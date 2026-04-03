#!/usr/bin/env python3

from typing import Optional, Dict, Any, List
from datetime import datetime
import asyncio
from ..qt_compat import QThread, Signal, QTimer
from src.services.binary_context_service import BinaryContextService, ViewLevel
from src.services.llm_providers.provider_factory import LLMProviderFactory
from src.services.settings_service import SettingsService
from src.services.analysis_db_service import AnalysisDBService
from src.services.graphrag.graphrag_service import GraphRAGService
from src.services.rag_service import rag_service
from src.services.models.rag_models import SearchRequest, SearchType
from src.services.mcp_client_service import MCPClientService
from src.services.mcp_connection_manager import MCPConnectionManager
from src.services.mcp_tool_orchestrator import MCPToolOrchestrator
from src.services.models.llm_models import ToolCall, ToolResult
from src.services.rlhf_service import rlhf_service
from src.services.models.rlhf_models import RLHFFeedbackEntry
from src.services.streaming import StreamingMarkdownRenderer
from src.services.streaming.reasoning_filter import ReasoningFilter

from src.ida_compat import log, get_binary_hash


class ExplainController:
    """Controller for the Explain tab functionality"""

    def __init__(self, view):
        self.view = view
        self.context_service = BinaryContextService()
        self.settings_service = SettingsService()
        self.llm_factory = LLMProviderFactory()
        self.analysis_db = AnalysisDBService()
        self.graphrag_service = GraphRAGService.get_instance(self.analysis_db)

        # MCP integration components
        self.mcp_service = MCPClientService()
        self.mcp_connection_manager = MCPConnectionManager()
        self.mcp_orchestrator = MCPToolOrchestrator(self.mcp_service, self.context_service)

        # Query state tracking
        self.function_query_active = False
        self.line_query_active = False

        # Track current analysis context for edit/save
        self._current_analysis_address = None  # Function start address
        self._current_analysis_type = None  # "explain_function" or "explain_line"

        # MCP state tracking
        self.mcp_enabled = False
        self._tool_execution_active = False
        self._tool_call_attempts = {}
        self._tool_call_rounds = 0  # Track total rounds of tool calling

        # Conversation history tracking for tool calls
        self._conversation_history = []

        # RLHF context tracking
        self._current_rlhf_context = {
            'model_name': None,
            'prompt': None,
            'system': None,
            'response': None
        }

        # Streaming renderer and reasoning filter for responsive streaming
        self._streaming_renderer = StreamingMarkdownRenderer(
            update_callback=self._on_streaming_update
        )
        self._reasoning_filter = ReasoningFilter(
            on_content=self._streaming_renderer.on_chunk,
            on_thinking_start=self._on_thinking_start,
        )

        # Debounce timer for auto-load on cursor navigation
        self._autoload_timer = QTimer()
        self._autoload_timer.setSingleShot(True)
        self._autoload_timer.setInterval(500)  # 500ms debounce
        self._autoload_timer.timeout.connect(self._on_autoload_timer)
        self._pending_autoload_offset = None
        self._last_autoloaded_func_start = None

        # Connect view signals
        self._connect_signals()

    def _get_rag_context(self, code_content: str) -> str:
        """Get RAG context based on code content"""
        if not self.view.is_rag_enabled():
            return ""

        try:
            log.log_info("RAG enabled - performing hybrid search for additional context")

            # Create search request using the code content
            request = SearchRequest(
                query=code_content,
                search_type=SearchType.HYBRID,
                max_results=3,  # Limit to top 3 for prompt context
                similarity_threshold=0.3,  # Lower threshold for broader context
                include_metadata=True
            )

            # Perform RAG search
            results = rag_service.search(request)

            if not results:
                log.log_info("No RAG results found for code context")
                return ""

            log.log_info(f"Found {len(results)} RAG context results")

            # Format results for LLM context
            rag_context = "\n## Additional Reference Context\n"
            rag_context += "The following related documentation may provide helpful context:\n\n"

            for i, result in enumerate(results, 1):
                score_percent = int(result.score * 100)
                rag_context += f"### Reference {i} (Relevance: {score_percent}%)\n"
                rag_context += f"**Source:** {result.filename}, Chunk {result.chunk_id}\n"
                rag_context += f"**Content:** {result.snippet}\n\n"

            rag_context += "---\n"
            rag_context += "Please use this reference context to enhance your analysis, but focus primarily on the specific code provided.\n\n"

            return rag_context

        except Exception as e:
            log.log_error(f"Error getting RAG context: {e}")
            return ""

    def _connect_signals(self):
        """Connect view signals to controller methods"""
        self.view.explain_function_requested.connect(self.explain_function)
        self.view.explain_line_requested.connect(self.explain_line)
        self.view.stop_function_requested.connect(self.stop_function_query)
        self.view.stop_line_requested.connect(self.stop_line_query)
        self.view.clear_requested.connect(self.clear_explanation)
        self.view.edit_mode_changed.connect(self.on_edit_mode_changed)
        self.view.rag_enabled_changed.connect(self.on_rag_enabled_changed)
        self.view.mcp_enabled_changed.connect(self.on_mcp_enabled_changed)

    def initialize_binary(self):
        """Initialize binary context for IDA (replaces BinAssist set_binary_view)"""
        # Only calculate hash if not already cached
        # This ensures we calculate ONCE per binary file, not on every navigation
        if self.context_service.get_binary_hash() is None:
            # Calculate binary hash ONCE and cache it
            binary_hash = get_binary_hash()

            # Cache the hash in context service
            self.context_service.set_binary_hash(binary_hash)

    def set_current_offset(self, offset: int):
        """Update current offset in context service and view.

        Auto-load of cached analysis is debounced (500ms) and skipped
        entirely when the cursor stays within the same function.  This
        prevents a flood of redundant GraphRAG lookups while the user
        scrolls through the disassembly or pseudocode view.
        """
        self.context_service.set_current_offset(offset)
        self.view.set_current_offset(f"0x{offset:X}")

        # Skip auto-load entirely if we're still in the same function
        func_start = self._get_function_start_address(offset)
        if func_start is not None and func_start == self._last_autoloaded_func_start:
            return

        # Debounce: restart the timer on every new offset
        self._pending_autoload_offset = offset
        self._autoload_timer.start()

    def _on_autoload_timer(self):
        """Fired after the debounce interval — safe to auto-load now."""
        offset = self._pending_autoload_offset
        if offset is None:
            return

        # Track current function to avoid redundant reloads
        func_start = self._get_function_start_address(offset)
        self._last_autoloaded_func_start = func_start

        self._load_cached_analysis_for_offset(offset)
        self._load_cached_line_explanation_for_offset(offset)

    def explain_function(self):
        """Handle explain function request"""
        log.log_info("Explain function requested")

        # Check if already running
        if self.function_query_active:
            log.log_warn("Function query already active, ignoring request")
            return

        # Set query active state
        self._set_query_state("function", True)

        # Clear previous content immediately
        self.view.set_explanation_content("*Preparing function analysis...*")

        try:
            # Get current context
            context = self.context_service.get_current_context()

            if context.get("error"):
                error_msg = f"Context Error: {context['error']}"
                log.log_error(error_msg)
                self.view.set_explanation_content(f"**Error**: {error_msg}")
                self._set_query_state("function", False)
                return

            # Check if we have function context
            if not context.get("function_context"):
                error_msg = "No function found at current offset"
                log.log_warn(error_msg)
                self.view.set_explanation_content(f"**Error**: {error_msg}")
                self._set_query_state("function", False)
                return

            # Check for cached analysis first
            current_offset = context["offset"]
            binary_hash = self._get_current_binary_hash()
            function_start = self._get_function_start_address(current_offset)

            if binary_hash and function_start is not None:
                node = self.graphrag_service.get_node_by_address(
                    binary_hash, "FUNCTION", int(function_start)
                )
                if node and node.llm_summary and not node.is_stale:
                    log.log_info("Using cached GraphRAG function analysis")
                    self._current_analysis_address = function_start
                    self._current_analysis_type = "explain_function"
                    self.view.set_explanation_content(node.llm_summary)
                    self._update_security_panel_from_node(node)
                    self._set_query_state("function", False)
                    return

                cached_analysis = self.analysis_db.get_function_analysis(
                    binary_hash, function_start, "explain_function"
                )

                if cached_analysis and not self._should_refresh_cache(cached_analysis):
                    log.log_info("Using cached function analysis (legacy)")
                    self._current_analysis_address = function_start
                    self._current_analysis_type = "explain_function"
                    self.view.set_explanation_content(cached_analysis['response'])
                    if node:
                        self._update_security_panel_from_node(node)
                    else:
                        self.view.clear_security_info()
                    self._set_query_state("function", False)
                    return

            # Get function code at current view level
            current_view_level = self.context_service.get_current_view_level()

            log.log_info(f"Current view level detected: {current_view_level.value}")

            # Get code at the current view level
            code_data = self.context_service.get_code_at_level(current_offset, current_view_level)

            log.log_info(f"Code data result: error={code_data.get('error')}, lines_count={len(code_data.get('lines', []))}")

            # If current view level fails, fallback to available levels
            if code_data.get("error"):
                log.log_warn(f"Current view level {current_view_level.value} failed: {code_data.get('error')}, trying fallbacks")
                for level in [ViewLevel.PSEUDO_C, ViewLevel.ASM]:
                    if level != current_view_level:
                        log.log_info(f"Trying fallback level: {level.value}")
                        code_data = self.context_service.get_code_at_level(current_offset, level)
                        if not code_data.get("error"):
                            log.log_info(f"Fallback level {level.value} succeeded with {len(code_data.get('lines', []))} lines")
                            break
                        else:
                            log.log_warn(f"Fallback level {level.value} failed: {code_data.get('error')}")
            else:
                log.log_info(f"Current view level {current_view_level.value} succeeded")

            if not code_data or code_data.get("error"):
                error_msg = f"Failed to get code: {code_data.get('error', 'Unknown error')}"
                log.log_error(error_msg)
                self.view.set_explanation_content(f"**Error**: {error_msg}")
                return

            # Check if RAG and MCP are enabled
            rag_enabled = self.view.is_rag_enabled()
            mcp_enabled = self.view.is_mcp_enabled()

            # Get active LLM provider
            active_provider = self.settings_service.get_active_llm_provider()
            if not active_provider:
                # Fall back to static analysis
                explanation = self._format_function_explanation(context, code_data, include_llm_prompt=False)
                self.view.set_explanation_content(explanation)
                log.log_warn("No active LLM provider, showing static analysis")
                return

            # Generate LLM query
            llm_query = self._generate_llm_query(context, code_data, rag_enabled, mcp_enabled)

            # Track RLHF context for this query
            self._track_rlhf_context(active_provider['name'], llm_query, "Function analysis system")

            # Send to LLM and stream response
            self._query_llm_async(llm_query, active_provider)

            log.log_info("Function explanation sent to LLM")

            try:
                # In IDA, we use ida_funcs to get function info for GraphRAG indexing
                import ida_funcs
                func = ida_funcs.get_func(function_start)
                if func and binary_hash:
                    node = self.graphrag_service.index_function(
                        func, binary_hash
                    )
                    if node:
                        self._update_security_panel_from_node(node)
            except Exception as e:
                log.log_warn(f"Failed to index function for GraphRAG: {e}")

        except Exception as e:
            error_msg = f"Exception in explain_function: {str(e)}"
            log.log_error(error_msg)
            self.view.set_explanation_content(f"**Error**: {error_msg}")
            self._set_query_state("function", False)

    def explain_line(self):
        """Handle explain line request with per-line caching"""
        log.log_info("Explain line requested")

        # Check if already running
        if self.line_query_active:
            log.log_warn("Line query already active, ignoring request")
            return

        # Set query active state
        self._set_query_state("line", True)

        # Show preparing message in line panel
        self.view.set_line_explanation_content("*Preparing line analysis...*")

        try:
            # Get current context
            context = self.context_service.get_current_context()

            if context.get("error"):
                error_msg = f"Context Error: {context['error']}"
                log.log_error(error_msg)
                self.view.set_line_explanation_content(f"**Error**: {error_msg}")
                self._set_query_state("line", False)
                return

            current_offset = context["offset"]
            current_view_level = self.context_service.get_current_view_level()
            view_type = current_view_level.value

            # Check for per-line cached analysis first
            binary_hash = self._get_current_binary_hash()
            function_start = self._get_function_start_address(current_offset)

            if binary_hash:
                # Check new per-line cache (by line address and view type)
                cached_line = self.analysis_db.get_line_explanation(
                    binary_hash, current_offset, view_type
                )

                if cached_line and not self._should_refresh_cache(cached_line):
                    log.log_info(f"Using cached line explanation for 0x{current_offset:x} ({view_type})")
                    self._current_analysis_address = current_offset
                    self._current_analysis_type = "explain_line"
                    self.view.set_line_explanation_content(cached_line['explanation'])
                    self._set_query_state("line", False)
                    return

            # Get line with context using the new method
            line_with_context = self.context_service.get_line_with_context(
                current_offset, current_view_level, context_lines=5
            )

            if line_with_context.get("error"):
                error_msg = f"Failed to get line: {line_with_context['error']}"
                log.log_error(error_msg)
                self.view.set_line_explanation_content(f"**Error**: {error_msg}")
                self._set_query_state("line", False)
                return

            # Check if RAG and MCP are enabled
            rag_enabled = self.view.is_rag_enabled()
            mcp_enabled = self.view.is_mcp_enabled()

            # Get active LLM provider
            active_provider = self.settings_service.get_active_llm_provider()
            if not active_provider:
                # Fall back to static analysis
                explanation = self._format_line_explanation_with_context(context, line_with_context, include_llm_prompt=False)
                self.view.set_line_explanation_content(explanation)
                log.log_warn("No active LLM provider, showing static analysis")
                self._set_query_state("line", False)
                return

            # Generate enhanced LLM query for line analysis with context
            llm_query = self._generate_line_explanation_prompt(context, line_with_context, rag_enabled, mcp_enabled)

            # Track RLHF context for this query
            self._track_rlhf_context(active_provider['name'], llm_query, "Line analysis system")

            # Store line context for saving after completion
            self._pending_line_context = {
                'binary_hash': binary_hash,
                'function_start': function_start,
                'line_address': current_offset,
                'view_type': view_type,
                'line_content': line_with_context.get('current_line', {}).get('content', ''),
                'context_before': self._format_context_lines(line_with_context.get('lines_before', [])),
                'context_after': self._format_context_lines(line_with_context.get('lines_after', []))
            }

            # Send to LLM and stream response to line panel
            self._query_llm_async_for_line(llm_query, active_provider)

            log.log_info("Line explanation sent to LLM")

        except Exception as e:
            error_msg = f"Exception in explain_line: {str(e)}"
            log.log_error(error_msg)
            self.view.set_line_explanation_content(f"**Error**: {error_msg}")
            self._set_query_state("line", False)

    def clear_explanation(self):
        """Handle clear explanation request"""
        log.log_info("Clear explanation requested")

        # Delete cached analyses from database
        try:
            current_offset = self.context_service._current_offset
            binary_hash = self._get_current_binary_hash()
            function_start = self._get_function_start_address(current_offset)
            view_type = self.context_service.get_current_view_level().value

            if binary_hash and function_start is not None:
                # Delete function analysis
                deleted_function = self.analysis_db.delete_function_analysis(
                    binary_hash, function_start, "explain_function"
                )
                # Delete legacy line analysis (old format)
                deleted_line_legacy = self.analysis_db.delete_function_analysis(
                    binary_hash, function_start, "explain_line"
                )

                # Delete ALL line explanations for this function
                deleted_line_count = self.analysis_db.clear_line_explanations_for_function(
                    binary_hash, function_start
                )

                node = self.graphrag_service.get_node_by_address(
                    binary_hash, "FUNCTION", int(function_start)
                )
                if node:
                    node.llm_summary = None
                    node.user_edited = False
                    node.is_stale = True
                    self.graphrag_service.upsert_node(node)

                if deleted_function or deleted_line_legacy or deleted_line_count:
                    log.log_info(f"Deleted cached analysis for function at 0x{function_start:x}")
                else:
                    log.log_info("No cached analysis found to delete")
            else:
                log.log_warn("Cannot delete cached analysis - no function context available")

        except Exception as e:
            log.log_error(f"Failed to delete cached analysis: {e}")

        # Reset display to default content
        self._show_default_content()
        # Clear line explanation panel
        self.view.clear_line_explanation()
        self.view.clear_security_info()

    def on_edit_mode_changed(self, is_edit_mode: bool):
        """Handle edit mode change - save edited content when exiting edit mode"""
        log.log_info(f"Edit mode changed to: {is_edit_mode}")

        if not is_edit_mode:
            # Exiting edit mode (Save button clicked) - save the edited content
            self._save_edited_explanation()

    def _save_edited_explanation(self):
        """Save the edited explanation content to the database"""
        try:
            # Get the edited content from the view
            edited_content = self.view.get_explanation_content()
            if not edited_content:
                log.log_warn("No content to save")
                return

            # Check if we have valid analysis context
            binary_hash = self._get_current_binary_hash()
            if not binary_hash:
                log.log_warn("No binary hash available for saving edited explanation")
                return

            # Get analysis address - use tracked value or calculate from current offset
            analysis_address = self._current_analysis_address
            if not analysis_address:
                current_offset = self.context_service._current_offset
                if current_offset:
                    analysis_address = self._get_function_start_address(current_offset)

            if not analysis_address:
                log.log_warn("No analysis address available - cannot save edited explanation")
                return

            # Get analysis type - use tracked value or default to explain_function
            analysis_type = self._current_analysis_type or "explain_function"

            # Save the edited content to database
            metadata = {
                "view_level": self.context_service.get_current_view_level().value,
                "model": "user_edited",
                "offset": self.context_service._current_offset
            }

            self.analysis_db.save_function_analysis(
                binary_hash,
                analysis_address,
                analysis_type,
                edited_content,
                metadata
            )
            log.log_info(f"Saved edited {analysis_type} to database for address {hex(analysis_address)}")

            if analysis_type == "explain_function":
                node = self.graphrag_service.get_node_by_address(
                    binary_hash, "FUNCTION", int(analysis_address)
                )
                if node is None:
                    try:
                        import ida_funcs
                        func = ida_funcs.get_func(analysis_address)
                        if func:
                            node = self.graphrag_service.index_function(
                                func, binary_hash
                            )
                    except Exception:
                        pass
                if node:
                    node.llm_summary = edited_content
                    node.confidence = 0.95  # User-edited content has high confidence
                    node.user_edited = True
                    node.is_stale = False
                    self.graphrag_service.upsert_node(node)
                    self._update_security_panel_from_node(node)

            # Update tracked values for future edits
            self._current_analysis_address = analysis_address
            self._current_analysis_type = analysis_type

        except Exception as e:
            log.log_error(f"Failed to save edited explanation: {e}")

    def on_rag_enabled_changed(self, enabled: bool):
        """Handle RAG checkbox change"""
        log.log_info(f"RAG enabled changed to: {enabled}")
        # TODO: Update RAG settings in future LLM queries

    def on_mcp_enabled_changed(self, enabled: bool):
        """Handle MCP checkbox change"""
        self.mcp_enabled = enabled
        log.log_info(f"Explain MCP enabled changed to: {enabled}")

        if enabled:
            # Ensure MCP connections are established
            try:
                self.mcp_connection_manager.ensure_connections()
                log.log_info("MCP connections established for Explain tab")
            except Exception as e:
                log.log_error(f"Failed to establish MCP connections: {e}")
                self.view.set_mcp_enabled(False)  # Reset checkbox
                self.mcp_enabled = False

    def _get_current_mcp_tools(self) -> List[Dict[str, Any]]:
        """Get current MCP tools list if MCP is enabled"""
        if not self.mcp_enabled:
            return []

        try:
            self.mcp_connection_manager.ensure_connections()
            tools = self.mcp_connection_manager.get_available_tools_for_llm()
            log.log_info(f"MCP enabled with {len(tools)} tools available for Explain")
            return tools
        except Exception as e:
            log.log_error(f"Failed to get MCP tools: {e}")
            return []

    def _format_function_explanation(self, context: dict, code_data: dict, include_llm_prompt: bool = True) -> str:
        """Format function explanation as markdown"""
        func_ctx = context["function_context"]
        binary_info = context["binary_info"]

        if include_llm_prompt:
            explanation = ""
        else:
            explanation = "# Function Explanation\n\n"

        explanation += f"""## Function: {func_ctx['name']}
**Prototype**: `{func_ctx.get('prototype', 'unknown')}`
**Address**: {func_ctx['start']} - {func_ctx['end']}
**Size**: {func_ctx['size']} bytes
**Basic Blocks**: {func_ctx['basic_blocks']}
**Call Sites**: {func_ctx['call_sites']}

## Binary Context
**File**: {binary_info.get('filename', 'Unknown')}
**Architecture**: {binary_info.get('architecture', 'Unknown')}
**Platform**: {binary_info.get('platform', 'Unknown')}

## Code ({code_data['view_level']})
```
"""

        # Add code lines
        for line in code_data.get("lines", []):
            if isinstance(line, dict) and "content" in line:
                marker = ">>> " if line.get("is_current", False) else "    "
                address = line.get('address', '')
                content = line['content']

                # Only add colon if there's an address, otherwise just show content
                if address and address != "":
                    explanation += f"{marker}{address}: {content}\n"
                else:
                    explanation += f"{marker}{content}\n"

        explanation += "```\n\n"

        # Add callers/callees if available
        if func_ctx.get("callers"):
            explanation += f"**Callers**: {', '.join(func_ctx['callers'])}\n"
        if func_ctx.get("callees"):
            explanation += f"**Callees**: {', '.join(func_ctx['callees'])}\n"

        if not include_llm_prompt:
            # Add disclaimer for static analysis only
            explanation += """\n*This is a static analysis. Enable LLM integration for AI-powered explanations.*"""

        return explanation

    def _format_line_explanation(self, context: dict, line_data: dict, include_llm_prompt: bool = True) -> str:
        """Format line explanation as markdown"""
        binary_info = context["binary_info"]
        line = line_data.get("line", {})

        # Handle error case
        if line_data.get("error"):
            return f"""# Line Explanation

## Address: {line_data['address']}
**Error**: {line_data['error']}

*Unable to retrieve line information.*
"""

        if include_llm_prompt:
            explanation = f"""# Line Explanation

Analyze the specific instruction/line of code below. Provide a detailed explanation of what this instruction does, its purpose within the function context, potential side effects, and any security considerations. Focus on the technical details of this single instruction.

## Address: {line_data['address']}
**View Level**: {line_data['view_level']}
**Filename**: {binary_info.get('filename', 'Unknown')}
**Path**: {binary_info.get('filepath', 'Unknown')}
**Architecture**: {binary_info.get('architecture', 'Unknown')}

## Instruction
```
{line.get('content', 'No content available')}
```

"""
        else:
            explanation = f"""# Line Explanation

## Address: {line_data['address']}
**View Level**: {line_data['view_level']}
**Filename**: {binary_info.get('filename', 'Unknown')}
**Path**: {binary_info.get('filepath', 'Unknown')}
**Architecture**: {binary_info.get('architecture', 'Unknown')}

## Instruction
```
{line.get('content', 'No content available')}
```

"""

        # Add raw bytes if available
        if line.get("bytes"):
            explanation += f"**Raw Bytes**: `{line['bytes']}`\n\n"

        # Add function context if available
        func_ctx = line_data.get("context")
        if func_ctx:
            explanation += f"**Function**: {func_ctx['name']} ({func_ctx['start']} - {func_ctx['end']})\n"
            if func_ctx.get('prototype'):
                explanation += f"**Prototype**: `{func_ctx['prototype']}`\n"
            explanation += "\n"

        if not include_llm_prompt:
            explanation += "*This is a static analysis. Enable LLM integration for AI-powered explanations.*"

        return explanation

    def _generate_llm_query(self, context: dict, code_data: dict, rag_enabled: bool, mcp_enabled: bool) -> str:
        """Generate LLM query from context and code data"""
        # Get the formatted explanation content as the base prompt
        prompt = self._format_function_explanation(context, code_data, include_llm_prompt=True)

        # Add RAG context if enabled
        if rag_enabled:
            # Extract code content for RAG search
            code_lines = code_data.get('lines', [])
            if code_lines:
                # Extract content from line dictionaries
                code_content_lines = []
                for line in code_lines:
                    if isinstance(line, dict) and 'content' in line:
                        code_content_lines.append(line['content'])
                    elif isinstance(line, str):
                        code_content_lines.append(line)

                if code_content_lines:
                    code_content = '\n'.join(code_content_lines)
                    rag_context = self._get_rag_context(code_content)
                    if rag_context:
                        prompt += rag_context
                    else:
                        prompt += "\n\n**RAG Context**: No relevant documentation found for this code context."
                else:
                    prompt += "\n\n**RAG Context**: Unable to extract code content for documentation search."
            else:
                prompt += "\n\n**RAG Context**: Unable to search documentation (no code content available)."

        # Add MCP context if enabled
        if mcp_enabled:
            prompt += "\n\n**MCP Context**: Please leverage Model Context Protocol tools and resources for enhanced analysis."

        return prompt

    def _generate_line_llm_query(self, context: dict, line_data: dict, rag_enabled: bool, mcp_enabled: bool) -> str:
        """Generate LLM query for line analysis from context and line data"""
        # Get the formatted line explanation content as the base prompt
        prompt = self._format_line_explanation(context, line_data, include_llm_prompt=True)

        # Add RAG context if enabled
        if rag_enabled:
            # Extract line content for RAG search
            line_info = line_data.get('line', {})
            if line_info:
                # Extract content from line dictionary or use string directly
                if isinstance(line_info, dict) and 'content' in line_info:
                    line_content = line_info['content']
                elif isinstance(line_info, str):
                    line_content = line_info
                else:
                    line_content = str(line_info)

                if line_content and line_content.strip():
                    rag_context = self._get_rag_context(line_content)
                    if rag_context:
                        prompt += rag_context
                    else:
                        prompt += "\n\n**RAG Context**: No relevant documentation found for this instruction context."
                else:
                    prompt += "\n\n**RAG Context**: Unable to extract instruction content for documentation search."
            else:
                prompt += "\n\n**RAG Context**: Unable to search documentation (no instruction content available)."

        # Add MCP context if enabled
        if mcp_enabled:
            prompt += "\n\n**MCP Context**: Please leverage Model Context Protocol tools and resources for enhanced analysis."

        return prompt

    def _query_llm_async(self, query: str, provider_config: dict):
        """Send query to LLM and stream response back to view"""
        # Clear any previous response buffer and tool execution state
        if hasattr(self, '_llm_response_buffer'):
            delattr(self, '_llm_response_buffer')
        self._tool_execution_active = False
        self._tool_call_attempts.clear()
        self._tool_call_rounds = 0  # Reset round counter

        # Reset streaming state for new query
        self._reasoning_filter.reset()
        self._streaming_renderer.reset()
        self.view.explain_browser.reset_streaming()

        # Initialize conversation history with the user query
        self._conversation_history = [{"role": "user", "content": query}]

        # Show LLM processing state
        self.view.set_explanation_content("*Generating AI explanation...*")

        # Get MCP tools if enabled
        mcp_tools = self._get_current_mcp_tools()

        if mcp_tools or self.mcp_enabled:
            # Use enhanced thread with MCP support
            messages = [{"role": "user", "content": query}]
            self.llm_thread = ExplainLLMThread(messages, provider_config, self.llm_factory, mcp_tools)
            self.llm_thread.response_chunk.connect(self._on_llm_response_chunk)
            self.llm_thread.response_complete.connect(self._on_llm_response_complete)
            self.llm_thread.response_error.connect(self._on_llm_response_error)
            # Connect new signals for tool call detection
            self.llm_thread.tool_calls_detected.connect(self._on_tool_calls_detected)
            self.llm_thread.stop_reason_received.connect(self._on_stop_reason_received)
            self.llm_thread.start()
        else:
            # Use original thread for backward compatibility
            self.llm_thread = LLMQueryThread(query, provider_config, self.llm_factory)
            self.llm_thread.response_chunk.connect(self._on_llm_response_chunk)
            self.llm_thread.response_complete.connect(self._on_llm_response_complete)
            self.llm_thread.response_error.connect(self._on_llm_response_error)
            self.llm_thread.start()

    def _on_streaming_update(self, update) -> None:
        """Handle streaming renderer updates."""
        self.view.explain_browser.apply_render_update(update)
        markdown = self._streaming_renderer.get_full_markdown()
        self.view.explain_browser.set_markdown_source(markdown)

    def _on_thinking_start(self) -> None:
        """Show thinking indicator when <reasoning> detected."""
        self._streaming_renderer.on_chunk("*Thinking...*\n\n")

    def _on_llm_response_chunk(self, chunk: str):
        """Handle streaming response chunk from LLM"""
        # Initialize buffer if not exists
        if not hasattr(self, '_llm_response_buffer'):
            self._llm_response_buffer = ""

        self._llm_response_buffer += chunk

        # Feed chunk through reasoning filter (which feeds to streaming renderer)
        self._reasoning_filter.feed(chunk)

    def _on_llm_response_complete(self):
        """Handle completion of LLM response"""
        log.log_info("LLM response completed")

        # Complete streaming and get filtered content
        self._reasoning_filter.complete()
        self._streaming_renderer.on_stream_complete()
        filtered_content = self._streaming_renderer.get_full_markdown()

        # Re-render final content through markdown_to_html so feedback buttons appear
        self.view.set_explanation_content(filtered_content)

        # Reset streaming state for next query
        self._reasoning_filter.reset()
        self._streaming_renderer.reset()

        # Update RLHF context with final response
        if hasattr(self, '_llm_response_buffer') and self._llm_response_buffer:
            self._update_rlhf_response(self._llm_response_buffer)

        # Save response to database if we have the necessary context
        if hasattr(self, '_llm_response_buffer') and self._llm_response_buffer:
            try:
                binary_hash = self._get_current_binary_hash()
                current_offset = self.context_service._current_offset
                function_start = self._get_function_start_address(current_offset)

                if binary_hash and function_start is not None:
                    # Determine query type based on active query
                    query_type = "explain_function" if self.function_query_active else "explain_line"

                    # Track current analysis context for edit/save functionality
                    self._current_analysis_address = function_start
                    self._current_analysis_type = query_type

                    # Save analysis with metadata
                    metadata = {
                        "view_level": self.context_service.get_current_view_level().value,
                        "model": self._get_current_model_name(),
                        "offset": current_offset
                    }

                    # Save the actual LLM response buffer (not the view content which may be stale)
                    complete_content = self._llm_response_buffer
                    self.analysis_db.save_function_analysis(
                        binary_hash, function_start, query_type,
                        complete_content, metadata
                    )
                    log.log_info(f"Saved {query_type} analysis to database")

                    if query_type == "explain_function":
                        node = self.graphrag_service.get_node_by_address(
                            binary_hash, "FUNCTION", int(function_start)
                        )
                        if node is None:
                            try:
                                import ida_funcs
                                func = ida_funcs.get_func(function_start)
                                if func:
                                    node = self.graphrag_service.index_function(
                                        func, binary_hash
                                    )
                            except Exception:
                                pass
                        if node:
                            node.llm_summary = complete_content
                            node.confidence = 0.85  # LLM-generated summary confidence
                            node.is_stale = False
                            self.graphrag_service.upsert_node(node)
                            self._update_security_panel_from_node(node)

            except Exception as e:
                log.log_error(f"Failed to save analysis to database: {e}")

        if hasattr(self, '_llm_response_buffer'):
            delattr(self, '_llm_response_buffer')
        self._cleanup_llm_thread()

        # Reset query states
        if self.function_query_active:
            self._set_query_state("function", False)
        if self.line_query_active:
            self._set_query_state("line", False)

    def _on_llm_response_error(self, error: str):
        """Handle LLM response error"""
        log.log_error(f"LLM query failed: {error}")

        # Reset streaming state
        self._reasoning_filter.reset()
        self._streaming_renderer.reset()

        error_markdown = f"**Error:** {error}\n\n*Falling back to static analysis...*"
        self.view.set_explanation_content(error_markdown)

        if hasattr(self, '_llm_response_buffer'):
            delattr(self, '_llm_response_buffer')
        self._cleanup_llm_thread()

        # Reset query states
        if self.function_query_active:
            self._set_query_state("function", False)
        if self.line_query_active:
            self._set_query_state("line", False)

    def _on_tool_calls_detected(self, tool_calls: List[ToolCall]):
        """Handle tool calls detected from LLM response"""
        log.log_info(f"Tool calls detected: {len(tool_calls)} tools")

        # Check for loop detection
        if not self._should_allow_tool_execution(tool_calls):
            self._handle_tool_execution_error("Tool execution stopped to prevent infinite loop.")
            return

        # Mark tool execution as active
        self._tool_execution_active = True

        # Add assistant message with tool calls to conversation history
        self._add_assistant_with_tool_calls_to_history(tool_calls)

        # Create and display tool call messages
        self._create_tool_call_messages(tool_calls)

        # Execute tools
        self._execute_tools(tool_calls)

    def _on_stop_reason_received(self, reason: str):
        """Handle stop reason from LLM"""
        log.log_info(f"LLM stop reason: {reason}")
        # Could be used for additional logic based on why the LLM stopped

    def _should_allow_tool_execution(self, tool_calls: List[ToolCall]) -> bool:
        """Check if tool execution should proceed (includes loop detection)"""
        # Initialize tool call tracking if needed
        if not hasattr(self, '_tool_call_attempts'):
            self._tool_call_attempts = {}
        if not hasattr(self, '_tool_call_rounds'):
            self._tool_call_rounds = 0

        # Check global tool call round limit (prevent infinite continuation)
        self._tool_call_rounds += 1
        log.log_info(f"Tool call round: {self._tool_call_rounds} (limit: 5)")
        if self._tool_call_rounds > 5:  # Allow max 5 rounds of tool calling
            log.log_warn(f"Tool call round limit reached: {self._tool_call_rounds} rounds")
            return False

        # Check for potential infinite loops (same tool with same args)
        for tool_call in tool_calls:
            call_key = f"{tool_call.name}:{hash(str(tool_call.arguments))}"
            current_count = self._tool_call_attempts.get(call_key, 0) + 1
            self._tool_call_attempts[call_key] = current_count

            # Prevent more than 3 calls to the same tool with same args
            if current_count > 3:
                log.log_warn(f"Tool call loop detected: {tool_call.name} called {current_count} times")
                return False

        return True

    def _create_tool_call_messages(self, tool_calls: List[ToolCall]):
        """Create and display tool call messages"""
        current_content = self.view.get_explanation_content()

        for i, tool_call in enumerate(tool_calls):
            log.log_info(f"Tool call {i}: {tool_call.name} with args: {tool_call.arguments}")

            tool_display = f"\n\n### Tool Call: `{tool_call.name}`\n"
            if tool_call.arguments:
                import json
                args_str = json.dumps(tool_call.arguments, indent=2)
                tool_display += f"```json\n{args_str}\n```\n"
            tool_display += "*Executing tool...*\n"

            current_content += tool_display

        self.view.set_explanation_content(current_content)

    def _execute_tools(self, tool_calls: List[ToolCall]):
        """Execute tool calls using orchestrator"""
        try:
            # Create tool executor thread
            self.tool_executor_thread = ExplainToolExecutorThread(
                self.mcp_orchestrator,
                tool_calls,
                self.view.get_explanation_content()
            )

            # Connect signals for results
            self.tool_executor_thread.tool_execution_complete.connect(self._on_tool_execution_complete)
            self.tool_executor_thread.tool_execution_error.connect(self._handle_tool_execution_error)
            self.tool_executor_thread.start()

        except Exception as e:
            log.log_error(f"Error setting up tool execution: {e}")
            self._handle_tool_execution_error(f"Tool execution setup failed: {str(e)}")

    def _on_tool_execution_complete(self, tool_calls: List[ToolCall], results: List[ToolResult]):
        """Handle completion of tool execution"""
        log.log_info(f"Tool execution completed with {len(results)} results")

        # Add tool results to conversation history
        self._add_tool_results_to_history(tool_calls, results)

        # Display tool results
        self._display_tool_results(tool_calls, results)

        # Save tool execution to database
        current_analysis_type = "explain_function" if self.function_query_active else "explain_line"
        self._save_tool_execution_to_db(tool_calls, results, current_analysis_type)

        # Continue LLM conversation with tool results
        self._continue_llm_after_tools(tool_calls, results)

    def _handle_tool_execution_error(self, error_message: str):
        """Handle tool execution error"""
        log.log_error(f"Tool execution error: {error_message}")

        current_content = self.view.get_explanation_content()
        error_display = f"\n\n**Tool Execution Error:** {error_message}\n"
        self.view.set_explanation_content(current_content + error_display)

        # Mark tool execution as no longer active
        self._tool_execution_active = False

        # Complete the query since tools failed
        self._complete_query()

    def _display_tool_results(self, tool_calls: List[ToolCall], results: List[ToolResult]):
        """Display tool execution results with truncation for readability"""
        current_content = self.view.get_explanation_content()

        for i, (tool_call, result) in enumerate(zip(tool_calls, results)):
            result_display = f"\n### Tool Result: `{tool_call.name}`\n"
            if result.error:
                result_display += f"**Error:** {result.error}\n"
            else:
                # Apply truncation like Query tab for better readability
                content = result.content.strip() if result.content else ""
                if len(content) > 200:
                    # Truncate long results
                    truncated_content = content[:200] + "...\n\n[Tool result truncated for display]"
                    result_display += f"```\n{truncated_content}\n```\n"
                else:
                    result_display += f"```\n{content}\n```\n"
            current_content += result_display

        self.view.set_explanation_content(current_content)

    def _continue_llm_after_tools(self, tool_calls: List[ToolCall], results: List[ToolResult]):
        """Continue LLM conversation with tool results"""
        try:
            # Prepare continuation messages
            continuation_messages = self._prepare_continuation_messages(tool_calls, results)

            if continuation_messages:
                # Get current provider
                provider_config = self.settings_service.get_active_llm_provider()
                if not provider_config:
                    log.log_error("No active provider for continuation")
                    self._complete_query()
                    return

                # Start continuation thread
                self.continuation_thread = ExplainLLMThread(
                    messages=continuation_messages,
                    provider_config=provider_config,
                    llm_factory=self.llm_factory,
                    mcp_tools=self._get_current_mcp_tools()
                )

                # Connect continuation signals
                self.continuation_thread.response_chunk.connect(self._on_continuation_chunk)
                self.continuation_thread.tool_calls_detected.connect(self._on_tool_calls_detected)
                self.continuation_thread.response_complete.connect(self._on_continuation_complete)
                self.continuation_thread.response_error.connect(self._on_continuation_error)
                self.continuation_thread.start()
            else:
                # No continuation needed, complete query
                self._complete_query()

        except Exception as e:
            log.log_error(f"Error continuing LLM after tools: {e}")
            self._complete_query()

    def _prepare_continuation_messages(self, tool_calls: List[ToolCall], results: List[ToolResult]) -> List[Dict[str, Any]]:
        """
        Return the complete maintained conversation history for LLM continuation.
        This solves the tool call loop issue by maintaining cumulative conversation state.
        """
        try:
            # Return the complete conversation history that's been maintained
            # across all tool call rounds
            log.log_info(f"Returning maintained conversation history with {len(self._conversation_history)} messages")
            return self._conversation_history.copy()

        except Exception as e:
            log.log_error(f"Error preparing continuation messages: {e}")
            return []

    def _add_assistant_with_tool_calls_to_history(self, tool_calls: List[ToolCall]):
        """
        Add assistant message with tool calls to conversation history.
        This maintains cumulative conversation state.
        """
        try:
            # Get the current LLM response buffer (the assistant's response before tool calls)
            assistant_content = getattr(self, '_llm_response_buffer', "")
            if not assistant_content:
                # Fallback: extract assistant content from current view content
                current_content = self.view.get_explanation_content()
                # Try to extract the assistant's initial response before tool calls
                if "### Tool Call:" in current_content:
                    assistant_content = current_content.split("### Tool Call:")[0].strip()
                    # Remove any existing markdown headers/formatting to get just the content
                    lines = assistant_content.split('\n')
                    cleaned_lines = []
                    for line in lines:
                        if not line.startswith('#') and not line.startswith('*') and line.strip():
                            cleaned_lines.append(line)
                    assistant_content = '\n'.join(cleaned_lines).strip()

            # Build the assistant message with tool calls in Anthropic format
            # For Anthropic, tool calls are embedded in the content as tool_use blocks
            assistant_content_blocks = []

            # Add text content if any
            if assistant_content.strip():
                assistant_content_blocks.append({
                    "type": "text",
                    "text": assistant_content
                })

            # Add tool use blocks for each tool call
            for tool_call in tool_calls:
                tool_use_block = {
                    "type": "tool_use",
                    "id": tool_call.id,
                    "name": tool_call.name,
                    "input": tool_call.arguments if tool_call.arguments else {}
                }
                assistant_content_blocks.append(tool_use_block)

            # Create assistant message with content blocks
            assistant_message = {
                "role": "assistant",
                "content": assistant_content_blocks
            }

            # Add to conversation history
            self._conversation_history.append(assistant_message)
            log.log_info(f"Added assistant message with {len(tool_calls)} tool calls to conversation history")

        except Exception as e:
            log.log_error(f"Error adding assistant with tool calls to history: {e}")

    def _add_tool_results_to_history(self, tool_calls: List[ToolCall], results: List[ToolResult]):
        """
        Add tool results to conversation history.
        This maintains cumulative conversation state.
        """
        try:
            # Get active provider to format tool results properly
            active_provider = self.settings_service.get_active_llm_provider()
            if not active_provider:
                log.log_error("No active provider for formatting tool results")
                return

            provider = self.llm_factory.create_provider(active_provider)

            # Format tool results for the specific provider
            tool_result_contents = [r.content if not r.error else f"Error: {r.error}" for r in results]
            tool_result_messages = provider.format_tool_results_for_continuation(tool_calls, tool_result_contents)

            # Add all tool result messages to conversation history
            for message in tool_result_messages:
                self._conversation_history.append(message)

            log.log_info(f"Added {len(tool_result_messages)} tool result messages to conversation history")

        except Exception as e:
            log.log_error(f"Error adding tool results to history: {e}")

    def _on_continuation_chunk(self, chunk: str):
        """Handle continuation response chunk"""
        # Initialize continuation buffer and base content if needed
        if not hasattr(self, '_continuation_buffer'):
            self._continuation_buffer = ""
            # Store the base content (everything before continuation)
            self._base_content = self.view.get_explanation_content()
            if not self._base_content.endswith('\n'):
                self._base_content += '\n'
            self._base_content += "\n### LLM Continuation\n"

        # Accumulate chunk in buffer
        self._continuation_buffer += chunk

        # Efficiently update view: base content + continuation buffer
        # This avoids reading current content and doing string operations every time
        complete_content = self._base_content + self._continuation_buffer
        self.view.set_explanation_content(complete_content)

    def _on_continuation_complete(self):
        """Handle completion of continuation"""
        log.log_info("LLM continuation completed")

        # Add the continuation response to conversation history
        if hasattr(self, '_continuation_buffer') and self._continuation_buffer.strip():
            continuation_message = {
                "role": "assistant",
                "content": self._continuation_buffer.strip()
            }
            self._conversation_history.append(continuation_message)
            log.log_info("Added continuation response to conversation history")

        # Save final complete content to database (includes final LLM explanation)
        try:
            binary_hash = self._get_current_binary_hash()
            if binary_hash:
                context = self.context_service.get_current_context()
                if context and not context.get("error"):
                    address = context.get("offset", 0)

                    # Determine analysis type based on which query is active
                    analysis_type = "explain_function" if self.function_query_active else "explain_line"

                    if analysis_type == "explain_function":
                        function_start = self._get_function_start_address(address)
                        if function_start is not None:
                            address = function_start

                    # Save complete final content including the continuation response
                    complete_content = self.view.get_explanation_content()
                    self.analysis_db.save_function_analysis(binary_hash, address, analysis_type, complete_content)
                    log.log_info(f"Saved final {analysis_type} analysis with continuation response")
        except Exception as e:
            log.log_error(f"Error saving final analysis to database: {e}")

        # Clean up continuation state
        if hasattr(self, '_continuation_buffer'):
            delattr(self, '_continuation_buffer')
        if hasattr(self, '_base_content'):
            delattr(self, '_base_content')
        self._complete_query()

    def _on_continuation_error(self, error: str):
        """Handle continuation error"""
        log.log_error(f"LLM continuation error: {error}")
        self._complete_query()

    def _complete_query(self):
        """Complete the current query and clean up"""
        self._tool_execution_active = False
        self._tool_call_rounds = 0  # Reset round counter

        # Clean up continuation thread if it exists
        if hasattr(self, 'continuation_thread'):
            if self.continuation_thread.isRunning():
                self.continuation_thread.quit()
                self.continuation_thread.wait(5000)
            self.continuation_thread.deleteLater()
            delattr(self, 'continuation_thread')

        # Clean up tool executor thread if it exists
        if hasattr(self, 'tool_executor_thread'):
            if self.tool_executor_thread.isRunning():
                self.tool_executor_thread.quit()
                self.tool_executor_thread.wait(5000)
            self.tool_executor_thread.deleteLater()
            delattr(self, 'tool_executor_thread')

        # Set query states to inactive
        if self.function_query_active:
            self._set_query_state("function", False)
        if self.line_query_active:
            self._set_query_state("line", False)

    def _cleanup_llm_thread(self):
        """Safely cleanup the LLM thread"""
        if hasattr(self, 'llm_thread'):
            if self.llm_thread.isRunning():
                self.llm_thread.quit()
                self.llm_thread.wait(5000)  # Wait up to 5 seconds
            self.llm_thread.deleteLater()
            delattr(self, 'llm_thread')

    def stop_function_query(self):
        """Stop the current function query"""
        log.log_info("Stop function query requested")

        # Reset streaming state
        self._reasoning_filter.reset()
        self._streaming_renderer.reset()

        if self.function_query_active and hasattr(self, 'llm_thread'):
            self.llm_thread.cancel()
            self._cleanup_llm_thread()
        self._set_query_state("function", False)

    def stop_line_query(self):
        """Stop the current line query"""
        log.log_info("Stop line query requested")

        # Reset streaming state
        self._reasoning_filter.reset()
        self._streaming_renderer.reset()

        # Clean up line-specific LLM thread
        if self.line_query_active and hasattr(self, 'line_llm_thread'):
            self.line_llm_thread.cancel()
            self._cleanup_line_llm_thread()

        # Also clean up the regular llm_thread in case it was used
        if self.line_query_active and hasattr(self, 'llm_thread'):
            self.llm_thread.cancel()
            self._cleanup_llm_thread()

        # Clean up pending line context
        if hasattr(self, '_pending_line_context'):
            delattr(self, '_pending_line_context')
        if hasattr(self, '_line_response_buffer'):
            delattr(self, '_line_response_buffer')

        self._set_query_state("line", False)

    def _set_query_state(self, query_type: str, active: bool):
        """Update query state and notify view"""
        if query_type == "function":
            self.function_query_active = active
            self.view.set_function_query_running(active)
        elif query_type == "line":
            self.line_query_active = active
            self.view.set_line_query_running(active)

        log.log_info(f"{query_type.title()} query state: {'active' if active else 'inactive'}")

    # Database helper methods

    def _get_current_binary_hash(self) -> Optional[str]:
        """Get current binary hash from cached value"""
        return self.context_service.get_binary_hash()

    def _get_function_start_address(self, address: int) -> Optional[int]:
        """Get function start address for database key"""
        try:
            import ida_funcs
            func = ida_funcs.get_func(address)
            return func.start_ea if func else None
        except ImportError:
            return None

    def _should_refresh_cache(self, cached_analysis: dict) -> bool:
        """Determine if cached analysis should be refreshed"""
        # For now, always use cache. Future: check timestamps, model versions, etc.
        return False

    def _save_tool_execution_to_db(self, tool_calls: List[ToolCall], results: List[ToolResult], analysis_type: str):
        """Save tool execution to database"""
        try:
            binary_hash = self._get_current_binary_hash()
            if not binary_hash:
                log.log_warn("Cannot save tool execution: no binary hash available")
                return

            # Get current context for address
            context = self.context_service.get_current_context()
            address = context.get("offset", 0)

            if analysis_type == "explain_function":
                function_start = self._get_function_start_address(address)
                if function_start is not None:
                    address = function_start

            # Create markdown content with tool calls and results
            tool_markdown = self._format_tool_execution_as_markdown(tool_calls, results)

            # Save complete view content (includes all user queries, assistant responses, tool calls, and results)
            complete_content = self.view.get_explanation_content()
            self.analysis_db.save_function_analysis(binary_hash, address, analysis_type, complete_content)

            existing_analysis = self.analysis_db.get_function_analysis(binary_hash, address, analysis_type)
            if existing_analysis:
                log.log_info(f"Updated {analysis_type} analysis with tool execution results")
            else:
                log.log_info(f"Saved new {analysis_type} analysis with tool execution results")

        except Exception as e:
            log.log_error(f"Error saving tool execution to database: {e}")

    def _format_tool_execution_as_markdown(self, tool_calls: List[ToolCall], results: List[ToolResult]) -> str:
        """Format tool execution as markdown content"""
        markdown_content = "\n\n---\n\n## Tool Execution\n\n"

        for i, (tool_call, result) in enumerate(zip(tool_calls, results)):
            markdown_content += f"### Tool Call {i+1}: `{tool_call.name}`\n"

            # Add arguments if present
            if tool_call.arguments:
                import json
                args_str = json.dumps(tool_call.arguments, indent=2)
                markdown_content += f"**Arguments:**\n```json\n{args_str}\n```\n\n"

            # Add result
            markdown_content += "**Result:**\n"
            if result.error:
                markdown_content += f"**Error:** {result.error}\n\n"
            else:
                markdown_content += f"```\n{result.content}\n```\n\n"

        return markdown_content

    def _get_current_model_name(self) -> str:
        """Get current LLM model name for metadata"""
        active_provider = self.settings_service.get_active_llm_provider()
        return active_provider.get('model', 'unknown') if active_provider else 'unknown'

    def _load_cached_analysis_for_offset(self, offset: int):
        """Load and display any cached analysis for the given offset"""
        try:
            binary_hash = self._get_current_binary_hash()
            function_start = self._get_function_start_address(offset)

            if not binary_hash or function_start is None:
                # No binary context or not in a function - show default content
                self._show_default_content()
                self.view.clear_security_info()
                return

            node = self.graphrag_service.get_node_by_address(
                binary_hash, "FUNCTION", int(function_start)
            )
            if node and node.llm_summary and not node.is_stale:
                log.log_info(f"Auto-loaded GraphRAG analysis for offset 0x{offset:x}")
                self.view.set_explanation_content(node.llm_summary)
                self._update_security_panel_from_node(node)
                return

            # Check for cached function analysis first (more comprehensive)
            cached_function = self.analysis_db.get_function_analysis(
                binary_hash, function_start, "explain_function"
            )

            if cached_function:
                log.log_info(f"Auto-loaded cached function analysis for offset 0x{offset:x}")
                self.view.set_explanation_content(cached_function['response'])
                if node:
                    self._update_security_panel_from_node(node)
                else:
                    self.view.clear_security_info()
                return

            # Check for cached line analysis
            cached_line = self.analysis_db.get_function_analysis(
                binary_hash, function_start, "explain_line"
            )

            if cached_line:
                log.log_info(f"Auto-loaded cached line analysis for offset 0x{offset:x}")
                self.view.set_explanation_content(cached_line['response'])
                if node:
                    self._update_security_panel_from_node(node)
                else:
                    self.view.clear_security_info()
                return

            # No cached analysis found - show default content
            self._show_default_content()
            if node:
                self._update_security_panel_from_node(node)
            else:
                self.view.clear_security_info()

        except Exception as e:
            log.log_error(f"Failed to load cached analysis for offset 0x{offset:x}: {e}")
            self._show_default_content()
            self.view.clear_security_info()

    def _show_default_content(self):
        """Show default content when no cached analysis is available"""
        default_content = "No explanation available. Click 'Explain Function' or 'Explain Line' to generate content."
        self.view.set_explanation_content(default_content)

    def _load_cached_line_explanation_for_offset(self, offset: int):
        """Load and display cached line explanation if available"""
        try:
            binary_hash = self._get_current_binary_hash()
            if not binary_hash:
                self.view.clear_line_explanation()
                return

            view_type = self.context_service.get_current_view_level().value

            cached = self.analysis_db.get_line_explanation(binary_hash, offset, view_type)
            if cached:
                log.log_info(f"Auto-loaded cached line explanation for 0x{offset:x} ({view_type})")
                self.view.set_line_explanation_content(cached['explanation'])
            else:
                # No cached line explanation - hide the panel
                self.view.clear_line_explanation()

        except Exception as e:
            log.log_error(f"Failed to load cached line explanation for 0x{offset:x}: {e}")
            self.view.clear_line_explanation()

    def _query_llm_async_for_line(self, query: str, provider_config: dict):
        """Send query to LLM for line explanation and stream response to line panel"""
        # Clear any previous line response buffer
        if hasattr(self, '_line_response_buffer'):
            delattr(self, '_line_response_buffer')

        # Show LLM processing state in line panel
        self.view.set_line_explanation_content("*Generating AI explanation...*")

        # Get MCP tools if enabled
        mcp_tools = self._get_current_mcp_tools()

        if mcp_tools or self.mcp_enabled:
            # Use enhanced thread with MCP support
            messages = [{"role": "user", "content": query}]
            self.line_llm_thread = ExplainLLMThread(messages, provider_config, self.llm_factory, mcp_tools)
        else:
            # Use original thread
            self.line_llm_thread = LLMQueryThread(query, provider_config, self.llm_factory)

        # Connect signals for line-specific handling
        self.line_llm_thread.response_chunk.connect(self._on_line_llm_response_chunk)
        self.line_llm_thread.response_complete.connect(self._on_line_llm_response_complete)
        self.line_llm_thread.response_error.connect(self._on_line_llm_response_error)
        self.line_llm_thread.start()

    def _on_line_llm_response_chunk(self, chunk: str):
        """Handle streaming response chunk from LLM for line explanation"""
        # Initialize buffer if not exists
        if not hasattr(self, '_line_response_buffer'):
            self._line_response_buffer = ""

        self._line_response_buffer += chunk
        self.view.set_line_explanation_content(self._line_response_buffer)

    def _on_line_llm_response_complete(self):
        """Handle completion of LLM response for line explanation"""
        log.log_info("Line LLM response completed")

        # Update RLHF context with final response
        if hasattr(self, '_line_response_buffer') and self._line_response_buffer:
            self._update_rlhf_response(self._line_response_buffer)

        # Save response to new per-line cache
        if hasattr(self, '_line_response_buffer') and self._line_response_buffer:
            if hasattr(self, '_pending_line_context') and self._pending_line_context:
                try:
                    ctx = self._pending_line_context
                    metadata = {
                        "model": self._get_current_model_name(),
                        "timestamp": str(datetime.now())
                    }

                    self.analysis_db.save_line_explanation(
                        ctx['binary_hash'],
                        ctx['function_start'] or 0,
                        ctx['line_address'],
                        ctx['view_type'],
                        ctx['line_content'],
                        ctx['context_before'],
                        ctx['context_after'],
                        self._line_response_buffer,
                        metadata
                    )
                    log.log_info(f"Saved line explanation to database for 0x{ctx['line_address']:x}")
                except Exception as e:
                    log.log_error(f"Failed to save line explanation: {e}")

        # Cleanup
        if hasattr(self, '_line_response_buffer'):
            delattr(self, '_line_response_buffer')
        if hasattr(self, '_pending_line_context'):
            delattr(self, '_pending_line_context')
        self._cleanup_line_llm_thread()

        # Reset query state
        self._set_query_state("line", False)

    def _on_line_llm_response_error(self, error: str):
        """Handle LLM response error for line explanation"""
        log.log_error(f"Line LLM query failed: {error}")
        error_markdown = f"**Error:** {error}\n\n*Falling back to static analysis...*"
        self.view.set_line_explanation_content(error_markdown)

        if hasattr(self, '_line_response_buffer'):
            delattr(self, '_line_response_buffer')
        if hasattr(self, '_pending_line_context'):
            delattr(self, '_pending_line_context')
        self._cleanup_line_llm_thread()

        self._set_query_state("line", False)

    def _cleanup_line_llm_thread(self):
        """Safely cleanup the line LLM thread"""
        if hasattr(self, 'line_llm_thread'):
            if self.line_llm_thread.isRunning():
                self.line_llm_thread.quit()
                self.line_llm_thread.wait(5000)
            self.line_llm_thread.deleteLater()
            delattr(self, 'line_llm_thread')

    def _generate_line_explanation_prompt(self, context: dict, line_with_context: dict, rag_enabled: bool, mcp_enabled: bool) -> str:
        """Generate enhanced LLM prompt for line explanation with context lines"""
        binary_info = context.get("binary_info", {})
        func_ctx = line_with_context.get("function_context", {})
        current_line = line_with_context.get("current_line", {})
        lines_before = line_with_context.get("lines_before", [])
        lines_after = line_with_context.get("lines_after", [])

        prompt = f"""# Line Explanation Request

Analyze the specific instruction/line of code marked with >>> below. Provide a detailed explanation of what this instruction does, its purpose within the function context, potential side effects, and any security considerations.

## Binary Context
**File**: {binary_info.get('filename', 'Unknown')}
**Architecture**: {binary_info.get('architecture', 'Unknown')}
**Platform**: {binary_info.get('platform', 'Unknown')}

## Function Context
"""
        if func_ctx:
            prompt += f"""**Function**: {func_ctx.get('name', 'Unknown')}
**Prototype**: `{func_ctx.get('prototype', 'unknown')}`
**Address Range**: {func_ctx.get('start', '?')} - {func_ctx.get('end', '?')}

"""

        prompt += f"""## Code Context ({line_with_context.get('view_level', 'unknown')})
```
"""
        # Add context lines before
        for line in lines_before:
            if isinstance(line, dict):
                addr = line.get('address', '')
                content = line.get('content', '')
                if addr:
                    prompt += f"    {addr}: {content}\n"
                else:
                    prompt += f"    {content}\n"

        # Add current line with marker
        if isinstance(current_line, dict):
            addr = current_line.get('address', '')
            content = current_line.get('content', '')
            if addr:
                prompt += f">>> {addr}: {content}\n"
            else:
                prompt += f">>> {content}\n"

        # Add context lines after
        for line in lines_after:
            if isinstance(line, dict):
                addr = line.get('address', '')
                content = line.get('content', '')
                if addr:
                    prompt += f"    {addr}: {content}\n"
                else:
                    prompt += f"    {content}\n"

        prompt += "```\n\n"
        prompt += "Focus your analysis on the line marked with >>> above. Explain:\n"
        prompt += "1. What this instruction/statement does\n"
        prompt += "2. Its role in the surrounding code flow\n"
        prompt += "3. Any data transformations or state changes\n"
        prompt += "4. Potential security implications if applicable\n"

        # Add RAG context if enabled
        if rag_enabled:
            line_content = current_line.get('content', '') if isinstance(current_line, dict) else str(current_line)
            if line_content:
                rag_context = self._get_rag_context(line_content)
                if rag_context:
                    prompt += rag_context

        # Add MCP context if enabled
        if mcp_enabled:
            prompt += "\n\n**MCP Context**: Please leverage Model Context Protocol tools and resources for enhanced analysis."

        return prompt

    def _format_line_explanation_with_context(self, context: dict, line_with_context: dict, include_llm_prompt: bool = True) -> str:
        """Format line explanation with context as markdown (static analysis fallback)"""
        binary_info = context.get("binary_info", {})
        func_ctx = line_with_context.get("function_context", {})
        current_line = line_with_context.get("current_line", {})

        explanation = f"""# Line Explanation

## Address: {line_with_context.get('address', 'Unknown')}
**View Level**: {line_with_context.get('view_level', 'Unknown')}
**Filename**: {binary_info.get('filename', 'Unknown')}
**Architecture**: {binary_info.get('architecture', 'Unknown')}

## Instruction
```
{current_line.get('content', 'No content available') if isinstance(current_line, dict) else current_line}
```

"""
        if func_ctx:
            explanation += f"**Function**: {func_ctx.get('name', 'Unknown')} ({func_ctx.get('start', '?')} - {func_ctx.get('end', '?')})\n"
            if func_ctx.get('prototype'):
                explanation += f"**Prototype**: `{func_ctx['prototype']}`\n"

        if not include_llm_prompt:
            explanation += "\n*This is a static analysis. Enable LLM integration for AI-powered explanations.*"

        return explanation

    def _format_context_lines(self, lines: list) -> str:
        """Format context lines as a string for storage"""
        if not lines:
            return ""

        formatted = []
        for line in lines:
            if isinstance(line, dict):
                addr = line.get('address', '')
                content = line.get('content', '')
                if addr:
                    formatted.append(f"{addr}: {content}")
                else:
                    formatted.append(content)
            else:
                formatted.append(str(line))

        return "\n".join(formatted)

    def _update_security_panel_from_node(self, node):
        """Update the security panel based on a GraphRAG node."""
        if not node:
            self.view.clear_security_info()
            return
        self.view.update_security_info(
            node.risk_level,
            node.category,
            node.activity_profile,
            node.security_flags,
            node.network_apis,
            node.file_io_apis
        )

    # RLHF methods

    def _track_rlhf_context(self, model_name: str, prompt: str, system_message: str = ""):
        """Track current query context for RLHF feedback"""
        self._current_rlhf_context = {
            'model_name': model_name,
            'prompt': prompt,
            'system': system_message,
            'response': None  # Will be set when response is complete
        }

    def _update_rlhf_response(self, response: str):
        """Update the RLHF context with the completed response"""
        self._current_rlhf_context['response'] = response

    def handle_rlhf_feedback(self, is_upvote: bool):
        """Handle RLHF feedback submission"""
        try:
            # Debug the current context
            log.log_info(f"RLHF feedback requested: {'upvote' if is_upvote else 'downvote'}")

            # Check for incomplete context more specifically
            if not self._current_rlhf_context.get('model_name'):
                log.log_warn("RLHF feedback failed: No model name in context")
                return
            if not self._current_rlhf_context.get('prompt'):
                log.log_warn("RLHF feedback failed: No prompt in context")
                return
            if not self._current_rlhf_context.get('response'):
                log.log_warn("RLHF feedback failed: No response in context - query may not be complete yet")
                return

            # Get binary metadata
            metadata = self.context_service.get_binary_metadata_for_rlhf()
            metadata_json = RLHFFeedbackEntry.create_metadata_json(
                metadata['filename'], metadata['size'], metadata['sha256']
            )

            # Create feedback entry
            feedback_entry = RLHFFeedbackEntry(
                model_name=self._current_rlhf_context['model_name'],
                prompt=self._current_rlhf_context['prompt'],
                system=self._current_rlhf_context['system'],
                response=self._current_rlhf_context['response'],
                feedback=is_upvote,
                timestamp="",  # Will be set by service
                metadata=metadata_json
            )

            # Store feedback
            success = rlhf_service.store_feedback(feedback_entry)
            if success:
                feedback_type = "upvote" if is_upvote else "downvote"
                log.log_info(f"RLHF {feedback_type} feedback stored successfully")
            else:
                log.log_error("Failed to store RLHF feedback")

        except Exception as e:
            log.log_error(f"Error handling RLHF feedback: {e}")


class LLMQueryThread(QThread):
    """Thread for handling async LLM queries"""
    response_chunk = Signal(str)
    response_complete = Signal()
    response_error = Signal(str)

    def __init__(self, query: str, provider_config: dict, llm_factory):
        super().__init__()
        self.query = query
        self.provider_config = provider_config
        self.llm_factory = llm_factory
        self.cancelled = False

    def cancel(self):
        """Cancel the running query"""
        self.cancelled = True

    def run(self):
        """Execute LLM query in background thread"""
        try:
            # Run async query in new event loop
            asyncio.run(self._async_query())
        except Exception as e:
            if not self.cancelled:  # Don't emit error if cancelled
                self.response_error.emit(str(e))

    async def _async_query(self):
        """Execute async LLM query"""
        try:
            # Check for cancellation before starting
            if self.cancelled:
                return

            # Import required models
            from src.services.models.llm_models import ChatRequest, ChatMessage, MessageRole

            # Create provider instance
            provider = self.llm_factory.create_provider(self.provider_config)

            # Check for cancellation after provider creation
            if self.cancelled:
                return

            # Create chat request
            # Merge system prompt into user message content
            try:
                from src.services.settings_service import settings_service as _ss
                _sys_prompt = _ss.get_system_prompt()
                if _sys_prompt:
                    merged_query = _sys_prompt + '\n\n' + self.query
                else:
                    merged_query = self.query
            except Exception:
                merged_query = self.query
            messages = [ChatMessage(role=MessageRole.USER, content=merged_query)]
            request = ChatRequest(
                messages=messages,
                model=self.provider_config.get('model', ''),
                stream=True,
                max_tokens=self.provider_config.get('max_tokens', 4096)
            )

            # Execute streaming query with cancellation checks
            async for response in provider.chat_completion_stream(request):
                if self.cancelled:
                    break
                if response.content:
                    self.response_chunk.emit(response.content)

            # Only emit completion if not cancelled
            if not self.cancelled:
                self.response_complete.emit()

        except Exception as e:
            if not self.cancelled:
                self.response_error.emit(str(e))


class ExplainLLMThread(QThread):
    """Enhanced thread for Explain LLM queries with tool call support"""
    response_chunk = Signal(str)
    response_complete = Signal()
    response_error = Signal(str)
    tool_calls_detected = Signal(list)  # List[ToolCall]
    stop_reason_received = Signal(str)  # "stop", "tool_calls", etc.

    def __init__(self, messages: List[Dict[str, Any]], provider_config: dict, llm_factory, mcp_tools: List[Dict[str, Any]] = None):
        super().__init__()
        self.messages = messages
        self.provider_config = provider_config
        self.llm_factory = llm_factory
        self.mcp_tools = mcp_tools or []
        self.cancelled = False

    def cancel(self):
        """Cancel the running query"""
        self.cancelled = True

    def run(self):
        """Execute LLM query in background thread"""
        try:
            # Run async query in new event loop
            asyncio.run(self._async_query())
        except Exception as e:
            if not self.cancelled:  # Don't emit error if cancelled
                self.response_error.emit(str(e))

    async def _async_query(self):
        """Execute async LLM query with tool call detection"""
        try:
            # Check for cancellation before starting
            if self.cancelled:
                return

            # Import required models
            from src.services.models.llm_models import ChatRequest, ChatMessage, MessageRole

            # Create provider instance
            provider = self.llm_factory.create_provider(self.provider_config)

            # Check for cancellation after provider creation
            if self.cancelled:
                return

            # Convert messages to ChatMessage format
            chat_messages = []
            for msg in self.messages:
                if msg["role"] == "system":
                    chat_messages.append(ChatMessage(role=MessageRole.SYSTEM, content=msg["content"]))
                elif msg["role"] == "tool":
                    # Tool result message - preserve tool_call_id
                    chat_messages.append(ChatMessage(
                        role=MessageRole.TOOL,
                        content=msg["content"],
                        tool_call_id=msg.get("tool_call_id"),
                        name=msg.get("name")
                    ))
                else:
                    # User or assistant message
                    role = MessageRole.USER if msg["role"] == "user" else MessageRole.ASSISTANT
                    content = msg["content"]

                    # Handle tool calls in assistant messages
                    tool_calls = msg.get("tool_calls")
                    structured_tool_calls = []
                    if tool_calls:
                        from src.services.models.llm_models import ToolCall
                        for tc in tool_calls:
                            if isinstance(tc, dict):
                                # Convert dict to ToolCall object
                                structured_tool_calls.append(ToolCall(
                                    id=tc.get('id', ''),
                                    name=tc.get('name', ''),
                                    arguments=tc.get('arguments', {})
                                ))
                            else:
                                structured_tool_calls.append(tc)

                    chat_messages.append(ChatMessage(
                        role=role,
                        content=content,
                        tool_calls=structured_tool_calls if structured_tool_calls else None
                    ))

            # Create chat request with tools if available
            request = ChatRequest(
                messages=chat_messages,
                model=self.provider_config.get('model', ''),
                stream=True,
                max_tokens=self.provider_config.get('max_tokens', 4096),
                tools=self.mcp_tools if self.mcp_tools else None
            )

            # Execute streaming query with tool call detection
            response_content = ""
            detected_tool_calls = []
            finish_reason = None

            async for response in provider.chat_completion_stream(request):
                if self.cancelled:
                    break

                # Handle content chunks
                if response.content:
                    response_content += response.content
                    self.response_chunk.emit(response.content)

                # Handle tool calls
                if response.tool_calls:
                    detected_tool_calls.extend(response.tool_calls)

                # Handle finish reason
                if hasattr(response, 'finish_reason') and response.finish_reason:
                    finish_reason = response.finish_reason

            # Only emit completion signals if not cancelled
            if not self.cancelled:
                # Emit tool calls if detected
                if detected_tool_calls:
                    self.tool_calls_detected.emit(detected_tool_calls)
                    # DO NOT emit response_complete when tool calls are detected
                    # The completion will happen after tools are executed
                else:
                    # Only emit completion when no tool calls are detected
                    self.response_complete.emit()

                # Emit stop reason
                if finish_reason:
                    self.stop_reason_received.emit(finish_reason)

        except Exception as e:
            if not self.cancelled:
                self.response_error.emit(str(e))


class ExplainToolExecutorThread(QThread):
    """Thread for executing tool calls in Explain tab"""
    tool_execution_complete = Signal(list, list)  # tool_calls, results
    tool_execution_error = Signal(str)

    def __init__(self, orchestrator, tool_calls: List[ToolCall], current_content: str, parent=None):
        super().__init__(parent)
        self.orchestrator = orchestrator
        self.tool_calls = tool_calls
        self.current_content = current_content
        self.tool_results = []

    def run(self):
        """Run tool execution in thread"""
        try:
            log.log_info("ExplainToolExecutorThread starting")
            # Run async tool execution in new event loop
            asyncio.run(self._async_execute_tools())
        except Exception as e:
            log.log_error(f"Tool execution thread failed: {e}")
            self.tool_execution_error.emit(str(e))

    async def _async_execute_tools(self):
        """Execute tools asynchronously"""
        try:
            # Execute all tools at once using the orchestrator's batch method
            log.log_info(f"Executing {len(self.tool_calls)} tools")
            results = await self.orchestrator.execute_tool_calls(self.tool_calls)

            # Emit completion with results
            self.tool_execution_complete.emit(self.tool_calls, results)

        except Exception as e:
            log.log_error(f"Tool execution failed: {e}")
            # Create error results for all tool calls
            results = []
            for tool_call in self.tool_calls:
                from src.services.models.llm_models import ToolResult
                error_result = ToolResult(
                    tool_call_id=tool_call.id,
                    content="",
                    error=str(e)
                )
                results.append(error_result)

            # Still emit completion so the UI can show the errors
            self.tool_execution_complete.emit(self.tool_calls, results)
