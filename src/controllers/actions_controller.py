#!/usr/bin/env python3

"""
Actions Controller for IDAssist Actions Tab

Controller for managing built-in IDA Pro analysis actions.
Follows the same patterns as ExplainController and QueryController.
"""

from typing import Optional, Dict, Any, List
from ..qt_compat import QThread, Signal, Qt
from src.services.binary_context_service import BinaryContextService, ViewLevel
from src.services.actions_service import ActionsService
from src.services.settings_service import SettingsService
from src.services.llm_providers.provider_factory import LLMProviderFactory
from src.services.actions_tool_registry import ActionsToolRegistry
from src.services.models.action_models import ActionType, ActionProposal, ActionResult
from src.services.models.llm_models import ToolCall
from .actions_llm_thread import ActionsLLMThread, ActionsToolExecutorThread

from src.ida_compat import log, get_binary_hash, execute_on_main_thread

# IDA imports for view refresh
try:
    import ida_kernwin
    import ida_hexrays
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


class ActionsApplyThread(QThread):
    """Thread for applying actions in background to avoid UI thread conflicts"""

    action_applied = Signal(dict, object, bool)  # action_data, result, success
    apply_complete = Signal(int, int)  # applied_count, failed_count
    apply_error = Signal(str)  # error_message

    def __init__(self, actions_service, selected_actions):
        super().__init__()
        self.actions_service = actions_service
        self.selected_actions = selected_actions
        self._stop_requested = False

    def stop(self):
        """Request thread to stop"""
        self._stop_requested = True

    def run(self):
        """Apply actions in background thread"""
        try:
            applied_count = 0
            failed_count = 0

            for action_data in self.selected_actions:
                if self._stop_requested:
                    break

                try:
                    # Convert view data to ActionProposal
                    proposal = self._convert_view_data_to_proposal(action_data)
                    if not proposal:
                        log.log_error(f"Failed to convert action data: {action_data}")
                        failed_count += 1
                        self.action_applied.emit(action_data, None, False)
                        continue

                    # Apply the action
                    result = self.actions_service.apply_action(proposal)

                    if result.success:
                        applied_count += 1
                        log.log_info(f"Applied {proposal.action_type.value}: {result.message}")
                        self.action_applied.emit(action_data, result, True)
                    else:
                        failed_count += 1
                        log.log_error(f"Failed to apply {proposal.action_type.value}: {result.message}")
                        self.action_applied.emit(action_data, result, False)

                except Exception as e:
                    log.log_error(f"Error applying action: {e}")
                    failed_count += 1
                    self.action_applied.emit(action_data, None, False)

            self.apply_complete.emit(applied_count, failed_count)

        except Exception as e:
            log.log_error(f"Error in ActionsApplyThread: {e}")
            self.apply_error.emit(f"Apply thread failed: {e}")

    def _convert_view_data_to_proposal(self, action_data):
        """Convert view action data to ActionProposal (same logic as controller)"""
        try:
            from src.services.models.action_models import ActionType, ActionProposal

            action_name = action_data.get('action', '')
            description = action_data.get('description', '')

            # Map action names to types
            action_type_map = {
                'rename function': ActionType.RENAME_FUNCTION,
                'rename variable': ActionType.RENAME_VARIABLE,
                'retype variable': ActionType.RETYPE_VARIABLE,
                'auto create struct': ActionType.AUTO_CREATE_STRUCT,
            }

            action_type = action_type_map.get(action_name.lower())
            if not action_type:
                log.log_error(f"Unknown action type: {action_name}")
                return None

            # Parse the description to extract target and proposed value
            if ' -> ' in description:
                parts = description.split(' -> ', 1)
                target = parts[0].strip()
                proposed_value = parts[1].strip()
            else:
                target = description
                proposed_value = f"new_{description}"

            # Create proposal
            proposal = ActionProposal(
                action_type=action_type,
                target=target,
                current_value=target,
                proposed_value=proposed_value,
                confidence=0.8,
                rationale="User-selected action from table"
            )
            proposal.view_level = action_data.get('view_level')

            return proposal

        except Exception as e:
            log.log_error(f"Error converting action data to proposal in thread: {e}")
            return None


class ActionsController:
    """Controller for the Actions tab functionality"""

    def __init__(self, view):
        self.view = view

        # Initialize services - IDA doesn't need binary_view/view_frame
        self.context_service = BinaryContextService()
        self.settings_service = SettingsService()
        self.llm_factory = LLMProviderFactory()
        self.actions_service = ActionsService(self.context_service)

        # NEW: Actions tool registry for LLM tool calling
        self.actions_tool_registry = ActionsToolRegistry(self.context_service, self.actions_service)

        # State tracking
        self.analysis_active = False
        self.apply_active = False
        self.apply_thread = None

        # LLM thread management
        self.llm_thread = None
        self.tool_executor_thread = None

        # Populate available actions list
        self._populate_available_actions()

        # Connect view signals
        self.view.analyse_function_requested.connect(self.analyze_current_function)
        self.view.apply_actions_requested.connect(self.apply_selected_actions)
        self.view.clear_actions_requested.connect(self.clear_actions)

        log.log_info("ActionsController initialized with LLM tool calling support")

    def _populate_available_actions(self):
        """Populate the available actions list in the view."""
        actions = [
            ("Rename Function", "Suggest better function names based on analysis"),
            ("Rename Variable", "Suggest descriptive variable names"),
            ("Retype Variable", "Suggest more specific types for variables"),
            ("Auto Create Struct", "Suggest struct definitions for memory access patterns"),
        ]
        for name, desc in actions:
            self.view.add_available_action(name, desc)

    def analyze_current_function(self):
        """Analyze the current function using LLM + Actions tools"""
        try:
            # Check if this is a stop request
            if hasattr(self.view, 'analyse_function_button') and self.view.analyse_function_button.text() == "Stop":
                self.stop_analysis()
                return

            if self.analysis_active:
                log.log_warn("Analysis already in progress")
                return

            # Get selected action types from view
            selected_action_types = self._get_selected_action_types()
            if not selected_action_types:
                self._set_busy_state(False, "No action types selected")
                log.log_warn("No action types selected for analysis")
                return

            # Check for LLM provider
            active_provider = self.settings_service.get_active_llm_provider()
            if not active_provider:
                self._set_busy_state(False, "No LLM provider configured")
                log.log_warn("No LLM provider configured for Actions analysis")
                return

            self.analysis_active = True
            self._set_busy_state(True, "Analyzing function with AI tools...")
            log.log_info("Starting LLM-powered Actions analysis")

            # Get current context and code
            context = self.context_service.get_current_context()
            if context.get("error"):
                error_msg = f"Context Error: {context['error']}"
                log.log_error(error_msg)
                self._set_busy_state(False, "Context error")
                return

            # Get code at current view level
            current_offset = context["offset"]
            current_view_level = self.context_service.get_current_view_level()
            effective_view_level = current_view_level  # Track what actually worked
            code_data = self.context_service.get_code_at_level(current_offset, current_view_level)

            # Try fallback levels if current level fails
            if code_data.get("error"):
                log.log_warn(f"Current view level {current_view_level.value} failed, trying fallbacks")
                for level in [ViewLevel.PSEUDO_C, ViewLevel.ASM]:
                    if level != current_view_level:
                        code_data = self.context_service.get_code_at_level(current_offset, level)
                        if not code_data.get("error"):
                            effective_view_level = level  # Update to fallback level
                            log.log_info(f"Fallback level {level.value} succeeded")
                            break

            if code_data.get("error"):
                error_msg = f"Failed to get code: {code_data.get('error', 'Unknown error')}"
                log.log_error(error_msg)
                self._set_busy_state(False, "Code extraction failed")
                return

            # Track effective view level and propagate to tools
            self._last_analysis_view_level = effective_view_level.value
            self.actions_tool_registry.set_view_level(effective_view_level.value)
            log.log_info(f"Analysis view level: {effective_view_level.value}")

            # Clear the tool registry to get fresh suggestions for this analysis
            # (UI table keeps previous suggestions, registry gets new ones)
            self.actions_tool_registry.clear_suggestions()

            # Generate LLM prompt and query with selected action tools only
            self._query_llm_with_action_tools(context, code_data, active_provider, selected_action_types)

        except Exception as e:
            log.log_error(f"Error in analyze_current_function: {e}")
            self.analysis_active = False
            self._set_busy_state(False, "Analysis failed")

    def apply_selected_actions(self, selected_actions: List[Dict[str, Any]]):
        """Apply selected actions to the binary using background thread"""
        try:
            if not selected_actions:
                log.log_warn("No actions selected for application")
                return

            # Prevent multiple simultaneous apply operations
            if self.apply_active or (self.apply_thread and self.apply_thread.isRunning()):
                log.log_warn("Action application already in progress, ignoring request")
                return

            self.apply_active = True

            # Set busy state while applying actions
            self._set_busy_state(True, f"Applying {len(selected_actions)} actions...")

            # Mark selected actions as "Applying..." in the UI
            self._mark_actions_as_applying(selected_actions)

            log.log_info(f"Starting background thread to apply {len(selected_actions)} actions")

            # Create and start apply thread
            self.apply_thread = ActionsApplyThread(self.actions_service, selected_actions)

            # Connect thread signals
            self.apply_thread.action_applied.connect(self._on_action_applied_result)
            self.apply_thread.apply_complete.connect(self._on_apply_complete)
            self.apply_thread.apply_error.connect(self._on_apply_error)

            # Start the thread
            self.apply_thread.start()

        except Exception as e:
            log.log_error(f"Error starting apply actions thread: {e}")
            self.apply_active = False
            self._set_busy_state(False, "Apply failed")

    def clear_actions(self):
        """Clear all actions and reset the view"""
        try:
            # Stop any active analysis
            self.stop_analysis()

            # Clear both the tool registry and the view
            self.actions_tool_registry.clear_suggestions()
            if hasattr(self.view, 'clear_proposed_actions'):
                self.view.clear_proposed_actions()

            log.log_info("Actions cleared")

        except Exception as e:
            log.log_error(f"Error clearing actions: {e}")

    def stop_analysis(self):
        """Stop any active analysis or apply operation"""
        try:
            if self.analysis_active:
                log.log_info("Stopping active analysis")
                self.analysis_active = False
                self._set_busy_state(False, "Stopped")

            # Stop LLM thread if running
            if self.llm_thread and self.llm_thread.isRunning():
                log.log_info("Stopping active LLM thread")
                self.llm_thread.cancel()
                self.llm_thread.wait(3000)  # Wait up to 3 seconds
                self.llm_thread = None

            # Stop tool executor thread if running
            if self.tool_executor_thread and self.tool_executor_thread.isRunning():
                log.log_info("Stopping active tool executor thread")
                self.tool_executor_thread.wait(3000)
                self.tool_executor_thread = None

            # Also stop any active apply thread
            if self.apply_thread and self.apply_thread.isRunning():
                log.log_info("Stopping active apply thread")
                self.apply_thread.stop()
                self.apply_thread.wait(3000)  # Wait up to 3 seconds
                self.apply_thread = None
                self.apply_active = False

        except Exception as e:
            log.log_error(f"Error stopping analysis: {e}")

    def get_available_actions(self) -> List[Dict[str, Any]]:
        """Get available actions for the view"""
        try:
            return self.actions_service.get_available_actions()
        except Exception as e:
            log.log_error(f"Error getting available actions: {e}")
            return []

    # Context management methods
    def initialize_binary(self):
        """Initialize binary context (called when binary is loaded in IDA)"""
        try:
            binary_hash = get_binary_hash()
            if binary_hash:
                self.context_service.set_binary_hash(binary_hash)
                log.log_info(f"ActionsController: binary initialized with hash {binary_hash[:16]}...")
        except Exception as e:
            log.log_error(f"Error initializing binary: {e}")

    def set_current_offset(self, offset: int):
        """Update current offset in context service and view"""
        try:
            if self.context_service:
                self.context_service.set_current_offset(offset)
            self.view.set_current_offset(f"0x{offset:X}")
        except Exception as e:
            log.log_error(f"Error updating offset: {e}")

    # Helper methods
    def _get_selected_action_types(self) -> List[ActionType]:
        """Get selected action types from the view"""
        try:
            if hasattr(self.view, 'get_selected_available_actions'):
                selected_action_names = self.view.get_selected_available_actions()

                # Map action display names to ActionType enums
                action_name_map = {
                    'Rename Function': ActionType.RENAME_FUNCTION,
                    'Rename Variable': ActionType.RENAME_VARIABLE,
                    'Retype Variable': ActionType.RETYPE_VARIABLE,
                    'Auto Create Struct': ActionType.AUTO_CREATE_STRUCT,
                }

                selected_types = []
                for action_name in selected_action_names:
                    # Extract action name (handle "Action Name - Description" format)
                    clean_name = action_name.split(' - ')[0] if ' - ' in action_name else action_name
                    if clean_name in action_name_map:
                        selected_types.append(action_name_map[clean_name])
                    else:
                        log.log_warn(f"Unknown action type: {clean_name}")

                return selected_types

            return []

        except Exception as e:
            log.log_error(f"Error getting selected action types: {e}")
            return []

    def _populate_proposals_in_view(self, proposals: List[ActionProposal]):
        """Add new action proposals to the view (avoid duplicates)"""
        try:
            # Get existing proposals to check for duplicates
            existing_descriptions = set()
            if hasattr(self.view, 'get_selected_proposed_actions'):
                # Get all existing actions (selected and unselected)
                for row in range(self.view.proposed_actions_table.rowCount()):
                    desc_item = self.view.proposed_actions_table.item(row, 2)  # Description column
                    if desc_item:
                        existing_descriptions.add(desc_item.text())

            # Add each new proposal to the view (only if not duplicate)
            added_count = 0
            for proposal in proposals:
                if hasattr(self.view, 'add_proposed_action'):
                    # Format the action name and description
                    action_name = proposal.action_type.value.replace('_', ' ').title()
                    description = f"{proposal.target} -> {proposal.proposed_value}"

                    # Skip if this description already exists
                    if description in existing_descriptions:
                        log.log_debug(f"Skipping duplicate suggestion: {description}")
                        continue

                    status = "Ready" if proposal.confidence >= 0.5 else "Low Confidence"
                    confidence = f"{proposal.confidence:.2f}"

                    self.view.add_proposed_action(
                        action_name,
                        description,
                        status,
                        confidence
                    )
                    # Store view_level as hidden data on the description cell
                    row_idx = self.view.proposed_actions_table.rowCount() - 1
                    desc_item = self.view.proposed_actions_table.item(row_idx, 2)
                    if desc_item:
                        desc_item.setData(Qt.UserRole, proposal.view_level)
                    added_count += 1
                    existing_descriptions.add(description)  # Track this addition

            log.log_info(f"Added {added_count} new suggestions (filtered out duplicates)")

        except Exception as e:
            log.log_error(f"Error populating proposals in view: {e}")

    def _convert_view_data_to_proposal(self, action_data: Dict[str, Any]) -> Optional[ActionProposal]:
        """Convert view action data to ActionProposal"""
        try:
            action_name = action_data.get('action', '')
            description = action_data.get('description', '')

            # Map action names to types
            action_type_map = {
                'rename function': ActionType.RENAME_FUNCTION,
                'rename variable': ActionType.RENAME_VARIABLE,
                'retype variable': ActionType.RETYPE_VARIABLE,
                'auto create struct': ActionType.AUTO_CREATE_STRUCT,
            }

            action_type = action_type_map.get(action_name.lower())
            if not action_type:
                log.log_error(f"Unknown action type: {action_name}")
                return None

            # Parse the description to extract target and proposed value
            if ' -> ' in description:
                parts = description.split(' -> ', 1)
                target = parts[0].strip()
                proposed_value = parts[1].strip()
            else:
                target = description
                proposed_value = f"new_{description}"

            # Create proposal
            proposal = ActionProposal(
                action_type=action_type,
                target=target,
                current_value=target,
                proposed_value=proposed_value,
                confidence=0.8,
                rationale="User-selected action from table"
            )
            proposal.view_level = action_data.get('view_level')

            return proposal

        except Exception as e:
            log.log_error(f"Error converting action data to proposal: {e}")
            return None

    def _on_action_applied_result(self, action_data: Dict[str, Any], result, success: bool):
        """Handle action application result from background thread"""
        # This is called for each individual action that gets applied
        try:
            if hasattr(self.view, 'update_action_status'):
                status_info = {
                    'success': success,
                    'error': result.error if result and hasattr(result, 'error') else None
                }
                self.view.update_action_status(action_data, status_info)
                log.log_info(f"Updated UI status for action: {action_data.get('action', 'Unknown')}")

            action_name = action_data.get('action', 'Unknown')
            status_text = "Applied" if success else "Failed"
            log.log_info(f"Action {action_name}: {status_text}")

        except Exception as e:
            log.log_error(f"Error handling action applied result: {e}")

    def _on_apply_complete(self, applied_count: int, failed_count: int):
        """Handle completion of apply actions thread"""
        try:
            log.log_info(f"Action application completed: {applied_count} success, {failed_count} failed")

            # Refresh IDA views so changes are visible immediately
            if applied_count > 0:
                self._refresh_ida_views()

            # Clear busy state and apply flag
            self.apply_active = False
            self._set_busy_state(False, f"Applied {applied_count} actions")

        except Exception as e:
            log.log_error(f"Error handling apply completion: {e}")
        finally:
            self.apply_thread = None

    def _on_apply_error(self, error_message: str):
        """Handle error from apply actions thread"""
        log.log_error(f"Apply actions thread error: {error_message}")
        self.apply_active = False
        self._set_busy_state(False, "Apply failed")
        self.apply_thread = None

    def _set_busy_state(self, busy: bool, message: str = ""):
        """Set the busy state of the view"""
        try:
            if hasattr(self.view, 'set_busy_state'):
                self.view.set_busy_state(busy, message)
        except Exception as e:
            log.log_error(f"Error setting busy state: {e}")

    def _refresh_ida_views(self):
        """Refresh IDA disassembly and pseudocode views to reflect applied changes"""
        if not _IN_IDA:
            return

        def _do_refresh():
            try:
                # Refresh the active disassembly view
                ida_kernwin.refresh_idaview_anyway()

                # Refresh any open pseudocode (decompiler) views
                for suffix in "ABCDEFGH":
                    widget = ida_kernwin.find_widget(f"Pseudocode-{suffix}")
                    if widget:
                        vu = ida_hexrays.get_widget_vdui(widget)
                        if vu:
                            vu.refresh_view(True)
            except Exception as e:
                log.log_error(f"Error refreshing IDA views: {e}")

        execute_on_main_thread(_do_refresh)
        log.log_info("Refreshed IDA views")

    def _mark_actions_as_applying(self, selected_actions: List[Dict[str, Any]]):
        """Mark selected actions as 'Applying...' in the UI"""
        try:
            for action_data in selected_actions:
                status_info = {
                    'success': False,  # Temporary state
                    'applying': True
                }
                if hasattr(self.view, 'update_action_status'):
                    self.view.update_action_status(action_data, status_info)
        except Exception as e:
            log.log_error(f"Error marking actions as applying: {e}")

    # LLM Integration Methods
    def _query_llm_with_action_tools(self, context: dict, code_data: dict, provider_config: dict, selected_action_types: List[ActionType]):
        """Query LLM with selected Actions tools only"""
        try:
            # Generate analysis prompt
            prompt = self._generate_actions_analysis_prompt(context, code_data, selected_action_types)

            # Get only the selected action tool definitions
            action_tools = self._get_selected_tool_definitions(selected_action_types)
            log.log_info(f"Generated {len(action_tools)} selected action tool definitions for LLM")

            # Create and start LLM thread with tools
            messages = [{"role": "user", "content": prompt}]
            self.llm_thread = ActionsLLMThread(messages, provider_config, self.llm_factory, action_tools)

            # Connect LLM thread signals
            self.llm_thread.response_chunk.connect(self._on_llm_response_chunk)
            self.llm_thread.response_complete.connect(self._on_llm_response_complete)
            self.llm_thread.response_error.connect(self._on_llm_response_error)
            self.llm_thread.tool_calls_detected.connect(self._on_tool_calls_detected)
            self.llm_thread.stop_reason_received.connect(self._on_stop_reason_received)

            # Start the thread
            self.llm_thread.start()
            log.log_info("ActionsLLMThread started")

        except Exception as e:
            log.log_error(f"Error starting LLM query: {e}")
            self.analysis_active = False
            self._set_busy_state(False, "LLM query failed")

    def _get_selected_tool_definitions(self, selected_action_types: List[ActionType]) -> List[Dict[str, Any]]:
        """Get tool definitions for only the selected action types"""
        try:
            # Get all tool definitions
            all_tools = self.actions_tool_registry.get_tool_definitions()

            # Map action types to tool names
            action_type_to_tool_name = {
                ActionType.RENAME_FUNCTION: "rename_function",
                ActionType.RENAME_VARIABLE: "rename_variable",
                ActionType.RETYPE_VARIABLE: "retype_variable",
                ActionType.AUTO_CREATE_STRUCT: "create_struct"
            }

            # Filter tools based on selected action types
            selected_tool_names = {action_type_to_tool_name.get(action_type) for action_type in selected_action_types}
            selected_tool_names.discard(None)  # Remove any None values

            selected_tools = []
            for tool in all_tools:
                tool_name = tool.get("function", {}).get("name")
                if tool_name in selected_tool_names:
                    selected_tools.append(tool)

            log.log_info(f"Filtered to {len(selected_tools)} tools from {len(all_tools)} total tools")
            return selected_tools

        except Exception as e:
            log.log_error(f"Error filtering selected tools: {e}")
            return []

    def _generate_actions_analysis_prompt(self, context: dict, code_data: dict, selected_action_types: List[ActionType]) -> str:
        """Generate analysis prompt that encourages action tool usage"""
        try:
            # Get function details
            function_name = context.get('function_context', {}).get('name', 'Unknown')
            function_address = hex(context['offset'])

            # Format code content
            code_content = self._format_code_for_analysis(code_data)

            # Generate action-specific instructions based on selected types
            action_instructions = []
            if ActionType.RENAME_FUNCTION in selected_action_types:
                action_instructions.append("- **rename_function** - Use if the current name is generic (sub_, fcn_, etc.) or doesn't describe the function's purpose")
            if ActionType.RENAME_VARIABLE in selected_action_types:
                action_instructions.append("- **rename_variable** - Use for variables with generic names (var_, arg_, etc.) that could be more descriptive")
            if ActionType.RETYPE_VARIABLE in selected_action_types:
                action_instructions.append("- **retype_variable** - Use to suggest more specific types (void* -> char*, int -> size_t, etc.)")
            if ActionType.AUTO_CREATE_STRUCT in selected_action_types:
                action_instructions.append("- **create_struct** - Use if you see consistent memory offset patterns that suggest a data structure")

            instructions_text = "\n".join(action_instructions)

            # Generate comprehensive prompt
            prompt = f"""Analyze this IDA Pro function and suggest specific improvements using the available action tools.

FUNCTION DETAILS:
- Name: {function_name}
- Address: {function_address}
- Architecture: {context.get('architecture', 'Unknown')}

FUNCTION CODE:
{code_content}

INSTRUCTIONS:
Analyze this function and use the appropriate action tools to suggest improvements:

{instructions_text}

Focus on semantic understanding - what does this code actually DO? Base your suggestions on:
- API calls and their purposes
- String references and their context
- Control flow patterns
- Variable usage patterns
- Memory access patterns

Call the appropriate tools with your suggestions. Provide high confidence scores (0.7+) only for suggestions you're confident about based on clear evidence in the code."""

            return prompt

        except Exception as e:
            log.log_error(f"Error generating analysis prompt: {e}")
            return "Analyze this function and suggest improvements using the available action tools."

    def _format_code_for_analysis(self, code_data: dict) -> str:
        """Format code data for LLM analysis"""
        try:
            lines = code_data.get('lines', [])
            if not lines:
                return "[No code content available]"

            # Extract and format code lines
            formatted_lines = []
            for line in lines:
                if isinstance(line, dict):
                    # Handle line dictionaries with content
                    content = line.get('content', str(line))
                    formatted_lines.append(content)
                elif isinstance(line, str):
                    formatted_lines.append(line)
                else:
                    formatted_lines.append(str(line))

            return '\n'.join(formatted_lines)

        except Exception as e:
            log.log_error(f"Error formatting code for analysis: {e}")
            return "[Error formatting code content]"

    # LLM Thread Signal Handlers
    def _on_llm_response_chunk(self, chunk: str):
        """Handle LLM response chunk - for Actions tab we don't need to show streaming"""
        # Actions tab doesn't display streaming LLM response, just tool results
        pass

    def _on_llm_response_complete(self):
        """Handle LLM response completion"""
        log.log_info("LLM response completed")

        # Check if we got any suggestions from tool calls
        suggestion_count = self.actions_tool_registry.get_suggestion_count()
        if suggestion_count > 0:
            # Update UI with accumulated suggestions
            suggestions = self.actions_tool_registry.get_suggestions()
            self._populate_proposals_in_view(suggestions)

            self.analysis_active = False
            self._set_busy_state(False, f"Found {suggestion_count} suggestions")
            log.log_info(f"Analysis completed: {suggestion_count} suggestions generated")
        else:
            # No tools were called - LLM didn't find actionable improvements
            self.analysis_active = False
            self._set_busy_state(False, "No improvements suggested")
            log.log_info("Analysis completed: No actionable improvements found")

        # Clean up LLM thread
        if self.llm_thread:
            self.llm_thread.wait(1000)  # Wait for thread to finish
            self.llm_thread = None

    def _on_llm_response_error(self, error: str):
        """Handle LLM response error"""
        log.log_error(f"LLM query error: {error}")
        self.analysis_active = False
        self._set_busy_state(False, "LLM query failed")
        if self.llm_thread:
            self.llm_thread.wait(1000)
            self.llm_thread = None

    def _on_tool_calls_detected(self, tool_calls: List[ToolCall]):
        """Handle detected tool calls - execute Actions tools"""
        log.log_info(f"Detected {len(tool_calls)} tool calls from LLM")

        # Filter for Actions tools only (safety check)
        action_tool_calls = [tc for tc in tool_calls if self.actions_tool_registry.is_action_tool(tc.name)]

        if action_tool_calls:
            log.log_info(f"Executing {len(action_tool_calls)} action tool calls")

            # Create and start tool executor thread
            self.tool_executor_thread = ActionsToolExecutorThread(
                self.actions_tool_registry, action_tool_calls
            )

            # Connect tool executor signals
            self.tool_executor_thread.tool_execution_complete.connect(self._on_tool_execution_complete)
            self.tool_executor_thread.tool_execution_error.connect(self._on_tool_execution_error)

            # Start tool execution
            self.tool_executor_thread.start()
        else:
            log.log_warn("No valid action tool calls detected")

    def _on_stop_reason_received(self, reason: str):
        """Handle stop reason from LLM"""
        log.log_info(f"LLM stop reason: {reason}")

        if reason == "tool_calls":
            # Tool calls were detected, wait for tool execution to complete
            self._set_busy_state(True, "Executing action tools...")
        elif reason == "stop":
            # Normal completion without tool calls
            self._on_llm_response_complete()

    def _on_tool_execution_complete(self, tool_calls: List[ToolCall], tool_results: List):
        """Handle completion of tool execution"""
        log.log_info(f"Tool execution completed: {len(tool_results)} results")

        # Update UI with accumulated suggestions
        suggestions = self.actions_tool_registry.get_suggestions()
        self._populate_proposals_in_view(suggestions)

        # Update state
        self.analysis_active = False
        self._set_busy_state(False, f"Found {len(suggestions)} suggestions")

        # Clean up threads
        if self.tool_executor_thread:
            self.tool_executor_thread.wait(1000)
            self.tool_executor_thread = None
        if self.llm_thread:
            self.llm_thread.wait(1000)
            self.llm_thread = None

    def _on_tool_execution_error(self, error: str):
        """Handle tool execution error"""
        log.log_error(f"Tool execution error: {error}")
        self.analysis_active = False
        self._set_busy_state(False, "Tool execution failed")

        # Clean up threads
        if self.tool_executor_thread:
            self.tool_executor_thread.wait(1000)
            self.tool_executor_thread = None
        if self.llm_thread:
            self.llm_thread.wait(1000)
            self.llm_thread = None
