#!/usr/bin/env python3

from typing import Optional, Dict, Any, List, Callable
import asyncio
import json
from ..qt_compat import QDateTime, QThread, QTimer, Signal, Qt, utc_timezone
from src.ida_compat import log
from src.services.binary_context_service import BinaryContextService, ViewLevel
from src.services.llm_providers.provider_factory import LLMProviderFactory
from src.services.settings_service import SettingsService
from src.services.analysis_db_service import AnalysisDBService
from src.services.rag_service import rag_service
from src.services.models.rag_models import SearchRequest, SearchType
from src.services.mcp_client_service import MCPClientService
from src.services.models.mcp_models import MCPToolExecutionRequest
from src.services.mcp_connection_manager import MCPConnectionManager
from src.services.mcp_tool_orchestrator import MCPToolOrchestrator
from src.services.models.llm_models import ToolCall, ToolResult
from src.services.internal_tools import set_document_chat_handler, DOCUMENT_CHAT_TOOL_NAME
from src.services.graphrag.graphrag_tools import GRAPHRAG_TOOL_NAMES
from src.services.rlhf_service import rlhf_service
from src.services.models.rlhf_models import RLHFFeedbackEntry
from src.controllers.chat_edit_manager import ChatEditManager
from src.services.streaming import StreamingMarkdownRenderer
from src.services.streaming.render_update import RenderUpdate
from src.services.streaming.reasoning_filter import ReasoningFilter
from src.services.models.transcript_models import ContextSnapshot, TranscriptEventKind
from src.services.transcript_service import TranscriptService
from src.services.transcript_renderer import TranscriptRenderer
from src.services.tool_approval_service import ToolApprovalService
from src.controllers.react_thread import ReActOrchestratorThread
from src.services.models.react_models import ReActConfig, ReActResult, ReActStatus


class LLMQueryThread(QThread):
    """Thread for handling async LLM queries with streaming and tool call detection"""
    response_chunk = Signal(str)
    response_complete = Signal()
    response_error = Signal(str)
    tool_calls_detected = Signal(list)  # List[ToolCall]
    stop_reason_received = Signal(str)  # "stop", "tool_calls", etc.
    
    def __init__(self, messages: List[Dict[str, Any]], provider_config: dict, llm_factory, mcp_tools: List[Dict[str, Any]] = None, native_message_callback: Callable = None):
        super().__init__()
        self.messages = messages
        self.provider_config = provider_config
        self.llm_factory = llm_factory
        self.mcp_tools = mcp_tools or []
        self.native_message_callback = native_message_callback
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
            
            # Convert messages to ChatMessage format while preserving all roles and structure
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

                    # Handle tool calls for assistant messages
                    tool_calls = None
                    if msg.get("tool_calls"):
                        from src.services.models.llm_models import ToolCall
                        tool_calls = []
                        for tc in msg["tool_calls"]:
                            if tc.get("type") == "function" and "function" in tc:
                                # Parse OpenAI format
                                func_data = tc["function"]
                                arguments = func_data.get("arguments", "{}")
                                if isinstance(arguments, str):
                                    try:
                                        arguments = json.loads(arguments)
                                    except:
                                        arguments = {}

                                tool_call = ToolCall(
                                    id=tc.get("id", ""),
                                    name=func_data.get("name", ""),
                                    arguments=arguments
                                )
                                tool_calls.append(tool_call)

                    # Preserve thinking_blocks and reasoning_content for LiteLLM Anthropic thinking
                    # These are stored in native_content to be used when preparing messages
                    native_content = None
                    if role == MessageRole.ASSISTANT:
                        if msg.get("thinking_blocks") or msg.get("reasoning_content"):
                            native_content = {
                                "thinking_blocks": msg.get("thinking_blocks"),
                                "reasoning_content": msg.get("reasoning_content")
                            }

                    chat_messages.append(ChatMessage(
                        role=role,
                        content=content,
                        tool_calls=tool_calls,
                        native_content=native_content
                    ))
            
            # Create chat request
            request = ChatRequest(
                messages=chat_messages, 
                model=self.provider_config.get('model', ''),
                stream=True,
                max_tokens=self.provider_config.get('max_tokens', 4096)
            )
            
            # Add tools if available and provider supports tools
            if self.mcp_tools and provider.supports_tools():
                request = provider.prepare_tool_enabled_request(request, self.mcp_tools)
            
            # DEBUG: Log the actual request messages being sent to LLM
            import json
            debug_messages = []
            for msg in request.messages:
                debug_msg = {
                    "role": msg.role.value,
                    "content": msg.content[:200] + "..." if len(str(msg.content)) > 200 else msg.content
                }
                if msg.tool_calls:
                    debug_msg["tool_calls"] = [
                        {"id": tc.id, "name": tc.name, "arguments": str(tc.arguments)[:100] + "..." if len(str(tc.arguments)) > 100 else tc.arguments}
                        for tc in msg.tool_calls
                    ]
                if msg.tool_call_id:
                    debug_msg["tool_call_id"] = msg.tool_call_id
                if msg.native_content:
                    debug_msg["has_native_content"] = True
                    if isinstance(msg.native_content, dict):
                        debug_msg["has_thinking_blocks"] = bool(msg.native_content.get("thinking_blocks"))
                        debug_msg["has_reasoning_content"] = bool(msg.native_content.get("reasoning_content"))
                debug_messages.append(debug_msg)

            log.log_info(f"🔍 LLM REQUEST DEBUG - Initial Query ({len(request.messages)} messages):")
            log.log_info(json.dumps(debug_messages, indent=2))
            
            # Execute streaming query with cancellation checks and tool call detection
            accumulated_tool_calls = []
            final_stop_reason = "stop"
            
            async for response in provider.chat_completion_stream(request, self.native_message_callback):
                if self.cancelled:
                    break
                
                # Handle content chunks
                if response.content:
                    self.response_chunk.emit(response.content)
                
                # Handle tool calls
                if response.tool_calls:
                    log.log_info(f"Received {len(response.tool_calls)} tool calls from LLM")
                    accumulated_tool_calls.extend(response.tool_calls)
                
                # Track stop reason
                if response.finish_reason:
                    final_stop_reason = response.finish_reason
            
            # Only emit signals if not cancelled
            if not self.cancelled:
                # Emit tool calls if detected
                if accumulated_tool_calls:
                    self.tool_calls_detected.emit(accumulated_tool_calls)
                
                # Emit stop reason
                self.stop_reason_received.emit(final_stop_reason)
                
                # Emit completion
                self.response_complete.emit()
            
        except Exception as e:
            if not self.cancelled:
                self.response_error.emit(str(e))


class LLMContinuationThread(QThread):
    """Thread for handling LLM continuation after tool execution with proper Qt signal handling"""
    continuation_chunk = Signal(str)        # Streaming response chunks
    continuation_complete = Signal(str)     # Final complete response
    continuation_error = Signal(str)        # Error signal
    additional_tools_detected = Signal(list)  # Additional tool calls detected
    
    def __init__(self, provider_factory, provider_config: dict, messages: List[Dict[str, Any]], 
                 mcp_tools: List[Dict[str, Any]] = None, native_message_callback: Callable = None, parent=None):
        super().__init__(parent)
        self.provider_factory = provider_factory
        self.provider_config = provider_config
        self.messages = messages
        self.mcp_tools = mcp_tools or []
        self.native_message_callback = native_message_callback
        self.continuation_buffer = ""
        self.accumulated_tool_calls = []
        
    def run(self):
        """Run LLM continuation in thread"""
        try:
            log.log_info("LLMContinuationThread starting")
            # Run async continuation
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self._continue_async())
            finally:
                loop.close()
                
        except Exception as e:
            log.log_error(f"LLM continuation thread error: {e}")
            import traceback
            log.log_error(f"Continuation thread traceback: {traceback.format_exc()}")
            self.continuation_error.emit(str(e))
    
    async def _continue_async(self):
        """Execute LLM continuation asynchronously"""
        try:
            # Import required models
            from src.services.models.llm_models import ChatRequest, ChatMessage, MessageRole
            
            # Create provider instance
            provider = self.provider_factory.create_provider(self.provider_config)
            
            # DEBUG: Log what messages we received for continuation
            import json
            log.log_info(f"🔍 CONTINUATION INPUT DEBUG - Received {len(self.messages)} messages:")
            for i, msg in enumerate(self.messages):
                debug_msg = dict(msg) if isinstance(msg, dict) else str(msg)
                if isinstance(debug_msg, dict) and 'content' in debug_msg and len(str(debug_msg['content'])) > 100:
                    debug_msg['content'] = str(debug_msg['content'])[:100] + "..."
                log.log_info(f"   Input Message {i}: {json.dumps(debug_msg, indent=2) if isinstance(debug_msg, dict) else debug_msg}")
            
            # Convert messages to ChatMessage format while preserving tool structure
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
                    
                    # Extract text content from structured messages
                    if isinstance(content, list):
                        text_parts = []
                        for part in content:
                            if isinstance(part, dict) and part.get('type') == 'text':
                                text_parts.append(part.get('text', ''))
                        content = ' '.join(text_parts) if text_parts else str(content)
                    
                    # Handle tool calls for assistant messages
                    tool_calls = None
                    if msg.get("tool_calls"):
                        from src.services.models.llm_models import ToolCall
                        tool_calls = []
                        for tc in msg["tool_calls"]:
                            if tc.get("type") == "function" and "function" in tc:
                                # Parse OpenAI format
                                func_data = tc["function"]
                                arguments = func_data.get("arguments", "{}")
                                if isinstance(arguments, str):
                                    try:
                                        arguments = json.loads(arguments)
                                    except:
                                        arguments = {}

                                tool_call = ToolCall(
                                    id=tc.get("id", ""),
                                    name=func_data.get("name", ""),
                                    arguments=arguments
                                )
                                tool_calls.append(tool_call)

                    # Preserve thinking_blocks and reasoning_content for LiteLLM Anthropic thinking
                    # These are stored in native_content to be used when preparing messages
                    native_content = None
                    if role == MessageRole.ASSISTANT:
                        if msg.get("thinking_blocks") or msg.get("reasoning_content"):
                            native_content = {
                                "thinking_blocks": msg.get("thinking_blocks"),
                                "reasoning_content": msg.get("reasoning_content")
                            }

                    chat_messages.append(ChatMessage(
                        role=role,
                        content=content,
                        tool_calls=tool_calls,
                        native_content=native_content
                    ))

            # Create continuation request
            request = ChatRequest(
                messages=chat_messages,
                model=self.provider_config.get('model', ''),
                stream=True,
                max_tokens=self.provider_config.get('max_tokens', 4096)
            )
            
            # Add tools if available and provider supports them
            if self.mcp_tools and provider.supports_tools():
                request = provider.prepare_tool_enabled_request(request, self.mcp_tools)
            
            # DEBUG: Log the actual continuation request messages being sent to LLM
            import json
            debug_messages = []
            for msg in request.messages:
                debug_msg = {
                    "role": msg.role.value,
                    "content": msg.content[:200] + "..." if len(str(msg.content)) > 200 else msg.content
                }
                if msg.tool_calls:
                    debug_msg["tool_calls"] = [
                        {"id": tc.id, "name": tc.name, "arguments": str(tc.arguments)[:100] + "..." if len(str(tc.arguments)) > 100 else tc.arguments}
                        for tc in msg.tool_calls
                    ]
                if msg.tool_call_id:
                    debug_msg["tool_call_id"] = msg.tool_call_id
                if msg.native_content:
                    debug_msg["has_native_content"] = True
                    if isinstance(msg.native_content, dict):
                        debug_msg["has_thinking_blocks"] = bool(msg.native_content.get("thinking_blocks"))
                        debug_msg["has_reasoning_content"] = bool(msg.native_content.get("reasoning_content"))
                debug_messages.append(debug_msg)

            log.log_info(f"🔍 LLM REQUEST DEBUG - Continuation ({len(request.messages)} messages):")
            log.log_info(json.dumps(debug_messages, indent=2))
            
            # Stream the continuation response
            log.log_info("Starting LLM continuation stream")
            response_count = 0
            empty_response_count = 0
            final_stop_reason = None
            
            async for response in provider.chat_completion_stream(request, self.native_message_callback):
                response_count += 1
                
                # Handle content chunks
                if response.content:
                    self.continuation_buffer += response.content
                    # Emit streaming chunk signal for real-time UI updates
                    self.continuation_chunk.emit(response.content)
                else:
                    empty_response_count += 1
                    # Only log every 50 empty responses to avoid spam
                    if empty_response_count % 50 == 0:
                        log.log_debug(f"Response {response_count} has no content ({empty_response_count} empty so far)")
                
                # Handle additional tool calls
                if response.tool_calls:
                    log.log_info(f"Additional tool calls detected: {len(response.tool_calls)}")
                    self.accumulated_tool_calls.extend(response.tool_calls)
                
                # Track stop reason
                if response.finish_reason:
                    final_stop_reason = response.finish_reason
            
            log.log_info(f"LLM continuation stream completed after {response_count} responses ({empty_response_count} empty), stop_reason: {final_stop_reason}")
            
            # Decide next action based on stop reason, supporting both Anthropic and OpenAI formats
            tool_reasons = ["tool_use", "tool_calls"]  # Anthropic and OpenAI formats
            completion_reasons = ["end_turn", "stop"]  # Anthropic and OpenAI formats
            
            if final_stop_reason in tool_reasons and self.accumulated_tool_calls:
                # More tools needed
                log.log_info(f"Emitting additional_tools_detected with {len(self.accumulated_tool_calls)} tools")
                self.additional_tools_detected.emit(self.accumulated_tool_calls)
            elif final_stop_reason in completion_reasons:
                # LLM is completely done
                log.log_info(f"Emitting continuation_complete with {len(self.continuation_buffer)} chars")
                self.continuation_complete.emit(self.continuation_buffer)
            elif self.accumulated_tool_calls:
                # Fallback: if we have tool calls but unclear stop reason
                log.log_info(f"Fallback: Emitting additional_tools_detected with {len(self.accumulated_tool_calls)} tools")
                self.additional_tools_detected.emit(self.accumulated_tool_calls)
            else:
                # No more tool calls and no clear stop reason - assume done
                log.log_info(f"Fallback: Emitting continuation_complete with {len(self.continuation_buffer)} chars")
                self.continuation_complete.emit(self.continuation_buffer)
                
        except Exception as e:
            log.log_error(f"Error in LLM continuation: {e}")
            self.continuation_error.emit(str(e))


class ToolExecutorThread(QThread):
    """Thread for handling async tool execution with proper Qt signal handling"""
    tool_execution_update = Signal(str)  # UI update signal
    tool_execution_error = Signal(str)   # Error signal
    tool_results_ready = Signal(list)    # Tool results signal - emitted for ALL results (success or failure)
    
    def __init__(self, orchestrator, tool_calls: List[ToolCall], response_buffer: str, parent=None):
        super().__init__(parent)
        self.orchestrator = orchestrator
        self.tool_calls = tool_calls
        self.response_buffer = response_buffer
        self.tool_results = []
        
    def run(self):
        """Run tool execution in thread"""
        try:
            log.log_info("ToolExecutorThread starting")
            # Run async tool execution
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                results = loop.run_until_complete(self._execute_tools_async())
                self.tool_results = results
                log.log_info(f"ToolExecutorThread completed, emitting results signal with {len(results)} results")
                # Emit results signal - this should trigger continuation
                self.tool_results_ready.emit(results)
            finally:
                loop.close()
                
        except Exception as e:
            log.log_error(f"Tool execution thread error: {e}")
            import traceback
            log.log_error(f"Tool execution traceback: {traceback.format_exc()}")
            self.tool_execution_error.emit(str(e))
    
    async def _execute_tools_async(self):
        """Execute tools asynchronously"""
        # Execute all tool calls
        results = await self.orchestrator.execute_tool_calls(self.tool_calls)
        
        # Update UI with tool execution results
        tool_summary = self.orchestrator.get_tool_execution_summary(self.tool_calls, results)
        current_response = self.response_buffer + "\n\n" + tool_summary
        
        # Emit UI update signal
        self.tool_execution_update.emit(current_response)
        
        # Log the results for debugging
        log.log_info(f"Tool execution completed with {len(results)} results")
        for i, result in enumerate(results):
            if result.error:
                log.log_info(f"Tool result {i}: ERROR - {result.error}")
            else:
                log.log_info(f"Tool result {i}: SUCCESS - {len(result.content)} chars")
        
        return results


_STREAM_ARG_UNSET = object()


class QueryController:
    CHAT_TYPE_METADATA_KEY = "chat_type"
    DOCUMENT_CHAT_METADATA_KEY = "is_document_chat"
    DEFAULT_DOCUMENT_DOC_TYPE = "notes"
    DEFAULT_CHAT_TYPE = "chat"
    CHAT_TYPE_OPTIONS = {"chat", "general", "malware_report", "vuln_analysis", "api_doc", "notes"}

    """Controller for the Query tab functionality"""
    
    def __init__(self, view):
        self.view = view
        self.context_service = BinaryContextService()
        self.settings_service = SettingsService()
        self.llm_factory = LLMProviderFactory()
        self.analysis_db = AnalysisDBService()
        self.mcp_service = MCPClientService()
        
        # MCP integration components
        self.mcp_connection_manager = MCPConnectionManager()
        self.mcp_orchestrator = MCPToolOrchestrator(self.mcp_service, self.context_service)
        
        # Chat editing
        self.chat_edit_manager = ChatEditManager()
        self.transcript_service = TranscriptService(self.analysis_db)
        self.transcript_renderer = TranscriptRenderer("IDAssist")
        self.tool_approval_service = ToolApprovalService(self.analysis_db, self.transcript_service)
        
        # Chat management
        self.chats = {}  # chat_id -> chat_data
        self.current_chat_id = None
        
        # RLHF context tracking
        self._current_rlhf_context = {
            'model_name': None,
            'prompt': None,
            'system': None,
            'response': None
        }
        self.next_chat_id = 1
        
        # LLM streaming state
        self.llm_thread = None
        self._llm_response_buffer = ""
        self._query_active = False
        self._current_query_binary_hash = None  # Cache binary hash during query
        self._active_stream_markdown = ""
        self._context_snapshot: Optional[ContextSnapshot] = None
        self._expanded_transcript_keys = set()
        self._transcript_render_scheduled = False
        self._queued_stream_markdown = None
        self._queued_stream_markdown_explicit = False
        self._stream_base_html = ""
        
        # Tool execution state
        self._tool_execution_active = False
        self._pending_tool_calls: List[ToolCall] = []
        self._tool_results: List[ToolResult] = []
        self._continuation_complete = False
        self._tool_call_attempts = {}  # Track tool call attempts for loop prevention
        self._awaiting_tool_approvals: List[ToolCall] = []
        self._synthetic_tool_results: Dict[str, ToolResult] = {}
        self._tool_correlation_ids: Dict[str, str] = {}
        self._denied_tool_calls: Dict[str, ToolCall] = {}

        # Streaming renderer and reasoning filter for responsive streaming
        self._streaming_renderer = StreamingMarkdownRenderer(
            update_callback=self._on_streaming_update
        )
        self._reasoning_filter = ReasoningFilter(
            on_content=self._streaming_renderer.on_chunk,
            on_thinking_start=self._on_thinking_start,
        )

        # ReAct (agentic mode) state
        self._react_thread: Optional[ReActOrchestratorThread] = None
        self._react_active = False
        self._react_streaming_final_answer = False
        self._last_todo_snapshot = ""
        self._last_react_tasks: List[Dict[str, str]] = []

        # Connect view signals
        self._connect_signals()
        self.transcript_service.add_listener(self._on_transcript_changed)
        self.tool_approval_service.set_state_listener(self._on_approval_state_changed)

        # Register document chat handler for internal tools
        set_document_chat_handler(self._create_document_chat)

    def initialize_binary(self):
        """Initialize binary context for IDA (called after binary is loaded)"""
        from src.ida_compat import get_binary_hash
        new_binary_hash = get_binary_hash()
        if not new_binary_hash:
            return

        current_binary_hash = self.context_service.get_binary_hash()
        if new_binary_hash != current_binary_hash:
            self.context_service.set_binary_hash(new_binary_hash)
            self.load_existing_chats()

    def _connect_signals(self):
        """Connect view signals to controller methods"""
        self.view.submit_query_requested.connect(self.submit_query)
        self.view.stop_query_requested.connect(self.stop_query)
        self.view.new_chat_requested.connect(self.new_chat)
        self.view.delete_chats_requested.connect(self.delete_chats)
        self.view.chat_selected.connect(self.chat_selected)
        self.view.chat_name_changed.connect(self.on_chat_name_changed)
        self.view.chat_type_changed.connect(self.on_chat_type_changed)
        self.view.edit_mode_changed.connect(self.on_edit_mode_changed)
        self.view.rag_enabled_changed.connect(self.on_rag_enabled_changed)
        self.view.mcp_enabled_changed.connect(self.on_mcp_enabled_changed)
        self.view.agentic_enabled_changed.connect(self.on_agentic_enabled_changed)
        self.view.accept_all_tools_changed.connect(self.on_accept_all_tools_changed)
        self.view.approval_decision_requested.connect(self.on_approval_decision_requested)
        self.view.transcript_link_clicked.connect(self.on_transcript_link_clicked)
        self.view.rlhf_feedback_requested.connect(self.handle_rlhf_feedback)

    def _is_document_chat(self, chat_id: Optional[int] = None) -> bool:
        if chat_id is None:
            chat_id = self.current_chat_id
        if chat_id is None:
            return False
        metadata = self._get_chat_metadata(chat_id)
        return bool(metadata.get(self.DOCUMENT_CHAT_METADATA_KEY))

    def _build_context_snapshot(self) -> ContextSnapshot:
        active_provider = self.settings_service.get_active_llm_provider() or {}
        provider_label = active_provider.get("name", "No provider")
        model_name = active_provider.get("model", "No model")
        message_count = 0
        if self.current_chat_id and self.current_chat_id in self.chats:
            message_count = len(self.chats[self.current_chat_id].get("messages", []))
        return ContextSnapshot(
            provider_label=provider_label,
            model_name=model_name,
            message_count=message_count,
            peak_message_count=message_count,
        )

    def _status_text(self) -> str:
        snapshot = self._context_snapshot or self._build_context_snapshot()
        token_text = "No active context window data"
        if snapshot.token_limit:
            token_text = (
                f"context {snapshot.token_count}/{snapshot.token_limit} tokens | "
                f"{snapshot.message_count} msgs"
            )
            if snapshot.peak_token_count or snapshot.peak_message_count:
                token_text += (
                    f" | peak {snapshot.peak_token_count} tokens / "
                    f"{snapshot.peak_message_count} msgs"
                )
            if snapshot.threshold:
                token_text += f" | threshold {snapshot.threshold}"
            if snapshot.compaction_summary:
                token_text += f" | compacted {snapshot.compaction_summary}"
        return f"Model: {snapshot.provider_label} / {snapshot.model_name} | {token_text}"

    def _refresh_status_strip(self):
        self.view.set_context_status(self._status_text())

    def _refresh_edit_button_state(self):
        if self._is_document_chat():
            self.view.set_edit_available(bool(self.current_chat_id))
            return
        binary_hash = self._current_query_binary_hash or self._get_current_binary_hash()
        available = False
        if binary_hash and self.current_chat_id:
            events = self.transcript_service.get_transcript_events(binary_hash, str(self.current_chat_id))
            available = any(event.event_kind == TranscriptEventKind.ASSISTANT_MESSAGE for event in events)
        self.view.set_edit_available(available)

    def _build_transcript_html(self, streaming_markdown: Optional[str] = None) -> Optional[str]:
        if not self.current_chat_id or self.current_chat_id not in self.chats:
            return None
        if self._is_document_chat():
            return None
        binary_hash = self._current_query_binary_hash or self._get_current_binary_hash()
        if not binary_hash:
            return None
        self.transcript_service.ensure_backfilled(binary_hash, str(self.current_chat_id), self.analysis_db)
        events = self.transcript_service.get_transcript_events(binary_hash, str(self.current_chat_id))
        title = self.chats[self.current_chat_id].get("name", f"Chat {self.current_chat_id}")
        return self.transcript_renderer.render(
            title,
            events,
            streaming_assistant_markdown=streaming_markdown,
            expanded_keys=self._expanded_transcript_keys,
            context_snapshot=self._context_snapshot or self._build_context_snapshot(),
        )

    def _apply_streaming_transcript_update(self, streaming_markdown: str, force_base_refresh: bool = False):
        if not self.current_chat_id or self._is_document_chat():
            self._render_transcript_view_now(streaming_markdown or None)
            return
        base_html = self._build_transcript_html(None)
        if not base_html:
            self._render_transcript_view_now(streaming_markdown or None)
            return
        if force_base_refresh or base_html != self._stream_base_html:
            self._stream_base_html = base_html
            self.view.begin_streaming(base_html)
        pending_html = self.transcript_renderer.render_streaming_assistant_card(streaming_markdown or "")
        self.view.apply_streaming_update(RenderUpdate.incremental("", pending_html))
        self._refresh_status_strip()
        self._refresh_edit_button_state()

    def _refresh_transcript_view(self, streaming_markdown=_STREAM_ARG_UNSET):
        active_render = self._query_active or self._react_active or self._tool_execution_active
        if streaming_markdown is not _STREAM_ARG_UNSET:
            self._queued_stream_markdown = streaming_markdown
            self._queued_stream_markdown_explicit = True
        if active_render:
            if not self._transcript_render_scheduled:
                self._transcript_render_scheduled = True
                QTimer.singleShot(16, self._flush_transcript_refresh)
            return

        resolved_streaming = (
            streaming_markdown if streaming_markdown is not _STREAM_ARG_UNSET
            else (self._active_stream_markdown or None)
        )
        self._render_transcript_view_now(resolved_streaming)

    def _flush_transcript_refresh(self):
        self._transcript_render_scheduled = False
        if self._queued_stream_markdown_explicit:
            resolved_streaming = self._queued_stream_markdown
        else:
            resolved_streaming = self._active_stream_markdown or None
        self._queued_stream_markdown = None
        self._queued_stream_markdown_explicit = False
        if (self._query_active or self._react_active or self._tool_execution_active) and resolved_streaming is not None:
            self._apply_streaming_transcript_update(resolved_streaming, force_base_refresh=True)
        else:
            self._render_transcript_view_now(resolved_streaming)

    def _render_transcript_view_now(self, streaming_markdown: Optional[str] = None):
        if not self.current_chat_id or self.current_chat_id not in self.chats:
            self.view.set_chat_content("No chat selected. Click 'New' to start a conversation.")
            self._refresh_status_strip()
            return

        if self._is_document_chat():
            chat = self.chats[self.current_chat_id]
            markdown_content = self._format_chat_as_markdown(chat)
            self.view.set_chat_content(markdown_content)
            self._refresh_status_strip()
            self._refresh_edit_button_state()
            return

        html = self._build_transcript_html(streaming_markdown)
        if not html:
            self.view.set_chat_content("No binary loaded.")
            self._refresh_status_strip()
            return
        self._stream_base_html = html if not streaming_markdown else self._stream_base_html
        self.view.set_chat_html(html)
        self._refresh_status_strip()
        self._refresh_edit_button_state()

    def _on_transcript_changed(self, binary_hash: str, chat_id: str):
        if not self.current_chat_id:
            return
        current_binary_hash = self._current_query_binary_hash or self._get_current_binary_hash()
        if binary_hash == current_binary_hash and str(self.current_chat_id) == str(chat_id):
            self._refresh_transcript_view(self._active_stream_markdown or None)

    def _on_approval_state_changed(self):
        pending = self.tool_approval_service.get_first_pending_for_chat(self.current_chat_id or -1)
        self.view.set_pending_approval(pending)
        self.view.set_accept_all_tools_checked(
            self.tool_approval_service.is_accept_all_tools_enabled(self.current_chat_id or -1)
            if self.current_chat_id else False
        )

    def on_accept_all_tools_changed(self, enabled: bool):
        if self.current_chat_id is None:
            self.new_chat()
        if self.current_chat_id is None:
            return
        self.tool_approval_service.set_accept_all_tools_enabled(self.current_chat_id, enabled)

    def on_approval_decision_requested(self, decision: str):
        if self.current_chat_id is None:
            return
        pending = self.tool_approval_service.get_first_pending_for_chat(self.current_chat_id)
        if not pending:
            self.view.set_pending_approval(None)
            return
        outcome = self.tool_approval_service.resolve_pending(pending.request_id, decision)
        if not outcome:
            return
        tool_call = self._denied_tool_calls.pop(pending.request_id, None)
        if tool_call and not outcome.approved:
            self._synthetic_tool_results[tool_call.id] = ToolResult(
                tool_call_id=tool_call.id,
                content="",
                error="User denied tool execution.",
            )
        self._continue_pending_tool_approvals()

    def on_transcript_link_clicked(self, href: str):
        if href.startswith("tool-expand:"):
            self._expanded_transcript_keys.add(href.split(":", 1)[1])
        elif href.startswith("tool-collapse:"):
            self._expanded_transcript_keys.discard(href.split(":", 1)[1])
        elif href.startswith("tasks-expand:"):
            self._expanded_transcript_keys.add(f"tasks:{href.split(':', 1)[1]}")
        elif href.startswith("tasks-collapse:"):
            self._expanded_transcript_keys.discard(f"tasks:{href.split(':', 1)[1]}")
        else:
            return
        self._refresh_transcript_view(self._active_stream_markdown or None)

    def _resolve_tool_source(self, tool_name: str) -> str:
        if tool_name == DOCUMENT_CHAT_TOOL_NAME:
            return "internal:document"
        if tool_name in GRAPHRAG_TOOL_NAMES:
            return "internal:graphrag"
        self.mcp_orchestrator._refresh_tool_cache()
        server_name = self.mcp_orchestrator._tool_server_map.get(tool_name)
        if server_name:
            return f"mcp:{server_name}"
        return "tool"

    def _parse_react_tasks(self, todos_formatted: str) -> List[Dict[str, str]]:
        tasks: List[Dict[str, str]] = []
        for raw_line in (todos_formatted or "").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("Summary:", "Progress:")):
                continue
            lowered = line.lower()
            status = "pending"
            task_text = line
            if lowered.startswith(("[x]", "done", "complete")):
                status = "completed"
            elif lowered.startswith(("[>]", "active", "in_progress", "in progress")):
                status = "in_progress"
            task_text = task_text.lstrip("-* ").replace("[x]", "", 1).replace("[ ]", "", 1).replace("[>]", "", 1).strip()
            tasks.append({"task": task_text, "status": status})
        return tasks

    def _todo_summary(self, tasks: List[Dict[str, str]]) -> str:
        total = len(tasks)
        completed = sum(1 for task in tasks if task.get("status") == "completed")
        active = sum(1 for task in tasks if task.get("status") == "in_progress")
        pending = max(0, total - completed - active)
        return f"Progress: {completed}/{total} complete | {active} active | {pending} pending"

    def _begin_tool_workflow(self, tool_calls: List[ToolCall]):
        if not self.current_chat_id:
            return
        binary_hash = self._current_query_binary_hash or self._get_current_binary_hash()
        if not binary_hash:
            return

        self._tool_execution_active = True
        self._pending_tool_calls = list(tool_calls)
        self._awaiting_tool_approvals = []
        self._synthetic_tool_results = {}
        self._denied_tool_calls = {}
        self._tool_correlation_ids = {}

        for tool_call in tool_calls:
            correlation_id = tool_call.id or f"tool-{len(self._tool_correlation_ids) + 1}"
            self._tool_correlation_ids[tool_call.id] = correlation_id
            tool_source = self._resolve_tool_source(tool_call.name)
            self.transcript_service.append_tool_requested(
                binary_hash,
                str(self.current_chat_id),
                correlation_id,
                tool_call.name,
                tool_source,
                tool_call.arguments or {},
            )
            approval = self.tool_approval_service.request_approval(
                self.current_chat_id,
                binary_hash,
                correlation_id,
                tool_call.name,
                tool_source,
                tool_call.arguments or {},
            )
            if approval:
                self._awaiting_tool_approvals.append(tool_call)
                self._denied_tool_calls[approval.request_id] = tool_call

        self._continue_pending_tool_approvals()

    def _continue_pending_tool_approvals(self):
        if self.current_chat_id is None:
            return
        pending = self.tool_approval_service.get_first_pending_for_chat(self.current_chat_id)
        self.view.set_pending_approval(pending)
        if pending:
            return

        approved_calls = [tc for tc in self._pending_tool_calls if tc.id not in self._synthetic_tool_results]
        if not approved_calls:
            ordered_results = [self._synthetic_tool_results[tc.id] for tc in self._pending_tool_calls if tc.id in self._synthetic_tool_results]
            self._on_tool_results_ready(ordered_results)
            return

        for tool_call in approved_calls:
            correlation_id = self._tool_correlation_ids.get(tool_call.id, tool_call.id)
            self.transcript_service.append_tool_started(
                self._current_query_binary_hash or self._get_current_binary_hash(),
                str(self.current_chat_id),
                correlation_id,
                tool_call.name,
                self._resolve_tool_source(tool_call.name),
            )
        self._tool_execution_active = True
        self._setup_tool_executor(approved_calls)
    
    def set_current_offset(self, offset: int):
        """Update current offset in context service and view"""
        self.context_service.set_current_offset(offset)
        self.view.set_current_offset(f"0x{offset:X}")
    
    def load_existing_chats(self):
        """Load existing chats from database on startup"""
        # CRITICAL FIX: Don't reload chats during active query/tool execution/react analysis
        if self._query_active or self._tool_execution_active or self._react_active:
            log.log_debug("Skipping chat reload during active query/tool execution/react analysis")
            return
        
        try:
            binary_hash = self._get_current_binary_hash()
            if not binary_hash:
                log.log_debug("No binary hash available, skipping chat history load")
                return

            log.log_info(f"Loading chats for binary hash: {binary_hash[:16]}...")

            # Clear existing chats first
            self.chats.clear()
            self.current_chat_id = None

            # Clear the view's history table
            self.view.history_table.setRowCount(0)
            
            # Temporarily disable sorting and itemChanged signals during bulk loading for better performance
            was_sorting_enabled = self.view.history_table.isSortingEnabled()
            self.view.history_table.setSortingEnabled(False)
            
            # Temporarily disconnect itemChanged signal to prevent false triggers during bulk loading
            try:
                self.view.history_table.itemChanged.disconnect()
                signals_disconnected = True
            except:
                signals_disconnected = False
            
            # Get all chats for this binary
            existing_chats = self.analysis_db.get_all_chats(binary_hash)

            log.log_info(f"Found {len(existing_chats)} chats in database for this binary")
            for chat in existing_chats:
                log.log_info(f"  Chat ID: {chat['chat_id']}, Hash: {chat.get('binary_hash', 'N/A')[:16]}...")

            if not existing_chats:
                log.log_debug("No existing chats found in database")
                
                # Reconnect itemChanged signal if it was disconnected
                if signals_disconnected:
                    self.view.history_table.itemChanged.connect(self.view.on_history_item_changed)
                
                # Re-enable sorting even when no chats exist
                if was_sorting_enabled:
                    self.view.history_table.setSortingEnabled(True)
                # Set default content since no chats exist
                self.view.set_chat_content("No chat selected. Click 'New' to start a conversation.")
                self._context_snapshot = self._build_context_snapshot()
                self._refresh_status_strip()
                self.view.set_accept_all_tools_enabled(bool(binary_hash))
                self.view.set_pending_approval(None)
                return
            
            log.log_info(f"Loading {len(existing_chats)} existing chats from database")
            
            # Load chat metadata for names
            chat_metadata = {}
            try:
                all_metadata = self.analysis_db.get_all_chat_metadata(binary_hash)
                for metadata in all_metadata:
                    chat_metadata[metadata['chat_id']] = metadata
            except Exception as e:
                log.log_warn(f"Failed to load chat metadata: {e}")
            
            # Load chats and add to view
            for chat_data in existing_chats:
                chat_id = int(chat_data['chat_id'])
                message_count = chat_data['message_count']
                first_message = chat_data['first_message']
                last_message = chat_data['last_message']
                
                # Get chat name from metadata, or use default
                metadata_record = chat_metadata.get(str(chat_id), {})
                chat_name = metadata_record.get('name', f"Chat {chat_id}")
                chat_metadata_payload = self._normalize_chat_metadata(metadata_record.get('metadata'))
                
                # Add chat entry to in-memory storage (messages will be loaded lazily)
                self.chats[chat_id] = {
                    "name": chat_name,
                    "messages": [],  # Will be loaded when chat is selected
                    "created": first_message,
                    "updated": last_message,
                    "metadata": chat_metadata_payload,
                }
                
                # Convert UTC timestamp to local time for display consistency
                display_timestamp = self._convert_utc_to_local_display(last_message)
                
                # Add to view's history table directly (without triggering signals)
                self._add_chat_to_history_direct(
                    chat_id,
                    chat_name,
                    display_timestamp,
                    chat_metadata_payload.get(self.CHAT_TYPE_METADATA_KEY, self.DEFAULT_CHAT_TYPE),
                )
                
                # Update next chat ID to avoid conflicts
                if chat_id >= self.next_chat_id:
                    self.next_chat_id = chat_id + 1
            
            # Reconnect itemChanged signal if it was disconnected
            if signals_disconnected:
                self.view.history_table.itemChanged.connect(self.view.on_history_item_changed)
            
            # Re-enable sorting and ensure proper order (newest first)
            if was_sorting_enabled:
                self.view.history_table.setSortingEnabled(True)
                self.view.history_table.sortByColumn(1, Qt.DescendingOrder)  # Sort by timestamp, descending
            
            log.log_info(f"Successfully loaded {len(existing_chats)} chats")
            self._context_snapshot = self._build_context_snapshot()
            self._refresh_status_strip()
            self.view.set_accept_all_tools_enabled(bool(binary_hash))
            
        except Exception as e:
            log.log_error(f"Failed to load existing chats: {e}")
            # Re-enable sorting and reconnect signals even on error
            try:
                if 'signals_disconnected' in locals() and signals_disconnected:
                    self.view.history_table.itemChanged.connect(self.view.on_history_item_changed)
                if 'was_sorting_enabled' in locals() and was_sorting_enabled:
                    self.view.history_table.setSortingEnabled(True)
            except:
                pass
    
    def _convert_utc_to_local_display(self, utc_timestamp: str) -> str:
        """Convert UTC timestamp from database to local display format"""
        try:
            # Parse the UTC timestamp and explicitly set it as UTC time
            qdt_utc = QDateTime.fromString(utc_timestamp, "yyyy-MM-dd hh:mm:ss")
            qdt_utc.setTimeZone(utc_timezone())  # This time is in UTC
            
            # Convert to local time zone  
            qdt_local = qdt_utc.toLocalTime()
            
            # Return in display format
            return qdt_local.toString("yyyy-MM-dd hh:mm:ss")
        except Exception as e:
            log.log_warn(f"Failed to convert timestamp {utc_timestamp}: {e}")
            # Fallback: return original timestamp
            return utc_timestamp
    
    def _add_chat_to_history_direct(self, chat_id: int, description: str, timestamp: str, chat_type: str):
        """Add chat to history table directly without triggering signals (for bulk loading)"""
        from ..qt_compat import QTableWidgetItem
        
        row_count = self.view.history_table.rowCount()
        self.view.history_table.insertRow(row_count)
        
        desc_item = QTableWidgetItem(description)
        desc_item.setData(Qt.UserRole, chat_id)  # Store chat ID
        timestamp_item = QTableWidgetItem(timestamp)
        timestamp_item.setFlags(timestamp_item.flags() & ~Qt.ItemIsEditable)  # Make timestamp read-only
        
        self.view.history_table.setItem(row_count, 0, desc_item)
        self.view.history_table.setItem(row_count, 1, timestamp_item)
        self.view.set_chat_type_cell(row_count, chat_id, chat_type)
    
    def _expand_macros(self, query_text: str) -> str:
        """Expand macros in the query text using current Binary Ninja context"""
        try:
            expanded_text = query_text
            
            # #func - current function code at current view level (like Explain tab)
            if '#func' in expanded_text:
                try:
                    context = self.context_service.get_current_context()
                    if context and context.get("offset"):
                        current_offset = context["offset"]
                        current_level = self.context_service.get_current_view_level()
                        code_data = self.context_service.get_code_at_level(current_offset, current_level)
                        
                        if code_data and not code_data.get("error") and code_data.get('lines'):
                            func_code = '\n'.join(line['content'] for line in code_data['lines'])
                            func_expansion = f"\n\n```\n{func_code}\n```\n\n"
                            expanded_text = expanded_text.replace('#func', func_expansion)
                            log.log_info(f"Expanded #func to {len(func_code)} characters of code")
                        else:
                            expanded_text = expanded_text.replace('#func', 'current function')
                            log.log_warn("Could not get function code for #func macro")
                    else:
                        expanded_text = expanded_text.replace('#func', 'current function')
                        log.log_warn("No context available for #func macro")
                except Exception as e:
                    log.log_error(f"Error expanding #func macro: {e}")
                    expanded_text = expanded_text.replace('#func', 'current function')
            
            # #line - current line context from BinaryContextService
            if '#line' in expanded_text:
                try:
                    context = self.context_service.get_current_context()
                    if context and context.get("offset"):
                        current_offset = context["offset"]
                        current_level = self.context_service.get_current_view_level()
                        line_context = self.context_service.get_line_context(current_offset, current_level)
                        
                        if line_context:
                            # Format with newlines and code fencing
                            line_expansion = f"\n\n```\n{line_context}\n```\n\n"
                            expanded_text = expanded_text.replace('#line', line_expansion)
                            log.log_info(f"Expanded #line to line context")
                        else:
                            expanded_text = expanded_text.replace('#line', 'current line')
                            log.log_warn("Could not get line context for #line macro")
                    else:
                        expanded_text = expanded_text.replace('#line', 'current line')
                        log.log_warn("No context available for #line macro")
                except Exception as e:
                    log.log_error(f"Error expanding #line macro: {e}")
                    expanded_text = expanded_text.replace('#line', 'current line')
            
            # #addr - current address from BinaryView
            if '#addr' in expanded_text:
                try:
                    context = self.context_service.get_current_context()
                    current_addr = context.get('current_address') if context else None
                    if current_addr is not None:
                        addr_str = f"0x{current_addr:x}"
                        expanded_text = expanded_text.replace('#addr', addr_str)
                        log.log_info(f"Expanded #addr to: {addr_str}")
                    else:
                        expanded_text = expanded_text.replace('#addr', '0x0')
                        log.log_warn("Could not get current address for #addr macro")
                except Exception as e:
                    log.log_error(f"Error expanding #addr macro: {e}")
                    expanded_text = expanded_text.replace('#addr', '0x0')
            
            # #range(start, end) - hexdump of specified address range
            import re
            range_pattern = r'#range\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)'
            range_matches = re.findall(range_pattern, expanded_text)
            
            for start_str, end_str in range_matches:
                try:
                    # Convert string addresses to integers (support both hex and decimal)
                    start_str = start_str.strip()
                    end_str = end_str.strip()
                    
                    # Auto-detect base and convert to int
                    if start_str.startswith('0x') or start_str.startswith('0X'):
                        start_addr = int(start_str, 16)
                    else:
                        try:
                            start_addr = int(start_str, 16)  # Try hex first
                        except ValueError:
                            start_addr = int(start_str, 10)  # Fall back to decimal
                    
                    if end_str.startswith('0x') or end_str.startswith('0X'):
                        end_addr = int(end_str, 16)
                    else:
                        try:
                            end_addr = int(end_str, 16)  # Try hex first
                        except ValueError:
                            end_addr = int(end_str, 10)  # Fall back to decimal
                    
                    # Calculate size and get hexdump
                    size = end_addr - start_addr
                    if size > 0:
                        hexdump_data = self.context_service.get_hexdump(start_addr, size)
                        if hexdump_data and not hexdump_data.get('error') and hexdump_data.get('lines'):
                            hexdump_lines = []
                            for line in hexdump_data['lines']:
                                # Format as traditional hexdump: address: hex_bytes  ascii
                                formatted_line = f"{line['address']}: {line['hex']}  {line['ascii']}"
                                hexdump_lines.append(formatted_line)
                            hexdump_text = '\n'.join(hexdump_lines)
                            # Format with newlines and code fencing
                            range_expansion = f"\n\n```\n{hexdump_text}\n```\n\n"
                            # Replace the specific #range(start, end) call
                            range_call = f"#range({start_str}, {end_str})"
                            expanded_text = expanded_text.replace(range_call, range_expansion)
                            log.log_info(f"Expanded #range({start_str}, {end_str}) to hexdump of 0x{start_addr:x}-0x{end_addr:x} ({size} bytes)")
                        else:
                            range_str = f"0x{start_addr:x}-0x{end_addr:x}"
                            range_call = f"#range({start_str}, {end_str})"
                            expanded_text = expanded_text.replace(range_call, range_str)
                            log.log_warn(f"Could not get hexdump for #range({start_str}, {end_str}), using address range")
                    else:
                        range_call = f"#range({start_str}, {end_str})"
                        expanded_text = expanded_text.replace(range_call, f"0x{start_addr:x}")
                        log.log_warn(f"Invalid range for #range({start_str}, {end_str}): end <= start")
                        
                except Exception as e:
                    log.log_error(f"Error expanding #range({start_str}, {end_str}) macro: {e}")
                    range_call = f"#range({start_str}, {end_str})"
                    expanded_text = expanded_text.replace(range_call, f"invalid range ({start_str}, {end_str})")
            
            if expanded_text != query_text:
                log.log_info("Macro expansion completed successfully")
            
            return expanded_text
            
        except Exception as e:
            log.log_error(f"Error during macro expansion: {e}")
            return query_text

    def submit_query(self, query_text: str):
        """Handle query submission with LLM integration"""
        log.log_info(f"Query submitted: {query_text[:50]}...")

        # Expand macros in the query text
        query_text = self._expand_macros(query_text)

        # Route to agentic mode if enabled
        if self.view.is_agentic_enabled():
            self._submit_agentic_query(query_text)
            return

        # Check if query is already active
        if self._query_active:
            log.log_warn("Query already active, ignoring request")
            return
        
        try:
            # Get active LLM provider first  
            active_provider = self.settings_service.get_active_llm_provider()
            if not active_provider:
                # Fall back to static response
                self._handle_no_llm_provider(query_text)
                return
            
            # Note: OAuth providers (openai_oauth, gemini_oauth) authenticate via the
            # Settings > Edit Provider > Authenticate button before use.
            
            # Ensure we have an active chat
            if self.current_chat_id is None:
                self.new_chat()
            
            # Set query active state and cache binary hash
            self._query_active = True
            self._current_query_binary_hash = self._get_current_binary_hash()
            self.view.set_query_running(True)
            self._active_stream_markdown = ""
            self._stream_base_html = ""
            self._context_snapshot = self._build_context_snapshot()
            self._refresh_status_strip()

            # Reset auto-scroll to follow new response by default
            self.view.enable_auto_scroll()
            
            # Add user query to chat immediately (both legacy and native formats)
            self._add_message_to_chat(self.current_chat_id, "user", query_text)
            
            # Save user query in native format for the active provider
            provider_type = active_provider.get('provider_type', 'anthropic_platform')
            self._save_user_message_native(query_text, provider_type)
            if self._current_query_binary_hash:
                self.transcript_service.append_user_message(
                    self._current_query_binary_hash,
                    str(self.current_chat_id),
                    query_text,
                )
            
            # Add placeholder for assistant response (don't save to database)
            self._add_message_to_chat(self.current_chat_id, "assistant", "*Thinking...*", save_to_db=False)
            self._refresh_transcript_view("")
            
            
            # Get current context and settings
            context = self.context_service.get_current_context()
            rag_enabled = self.view.is_rag_enabled()
            mcp_enabled = self.view.is_mcp_enabled()
            
            # Prepare conversation messages for LLM in provider's native format
            provider_type = active_provider.get('provider_type', 'anthropic_platform')
            messages = self._prepare_native_messages(query_text, context, rag_enabled, mcp_enabled, provider_type)
            
            # Track RLHF context for this query
            self._track_rlhf_context(active_provider['name'], query_text, messages)
            
            # Get MCP tools if enabled
            mcp_tools = []
            if mcp_enabled:
                # Try to connect to external MCP servers (non-fatal if it fails)
                self.mcp_connection_manager.ensure_connections()
                # Always get tools — includes internal tools even if no
                # external servers are connected
                mcp_tools = self.mcp_connection_manager.get_available_tools_for_llm()
                log.log_info(f"MCP enabled with {len(mcp_tools)} tools available")
            
            # Start LLM query thread
            self._start_llm_query(messages, active_provider, mcp_tools)
            
            log.log_info("Query sent to LLM")
            
        except Exception as e:
            error_msg = f"Exception in submit_query: {str(e)}"
            log.log_error(error_msg)
            
            # Add error message to chat
            if self.current_chat_id:
                self._update_last_assistant_message(f"**Error**: {str(e)}")
                self._update_chat_display()
            
            self._query_active = False
            self._current_query_binary_hash = None
            self.view.set_query_running(False)
    
    def stop_query(self):
        """Stop the current query"""
        log.log_info("Stop query requested")

        # Reset streaming state
        self._reasoning_filter.reset()
        self._streaming_renderer.reset()

        # Cancel ReAct if active
        if self._react_active and self._react_thread:
            self._react_thread.cancel()
            self._cleanup_react_thread()
            self._react_active = False

        # Cancel standard query if active
        if self._query_active and hasattr(self, 'llm_thread') and self.llm_thread:
            self.llm_thread.cancel()
            self._cleanup_llm_thread()
        if self.current_chat_id:
            self.tool_approval_service.cancel_pending_for_chat(self.current_chat_id)
        self._active_stream_markdown = ""
        self._stream_base_html = ""
        self._query_active = False
        self._current_query_binary_hash = None
        self.view.set_query_running(False)
        self._context_snapshot = self._build_context_snapshot()
        self._refresh_transcript_view()
    
    def new_chat(self):
        """Create a new chat session"""
        chat_id = self.next_chat_id
        self.next_chat_id += 1
        
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        chat_name = f"Chat {chat_id}"
        
        # Create chat data
        self.chats[chat_id] = {
            "name": chat_name,
            "messages": [],
            "created": timestamp,
            "updated": timestamp,
            "metadata": self._default_chat_metadata(),
        }
        
        # Save chat metadata to database
        binary_hash = self._get_current_binary_hash()
        if binary_hash:
            try:
                self.analysis_db.save_chat_metadata(
                    binary_hash,
                    str(chat_id),
                    chat_name,
                    metadata=self.chats[chat_id]["metadata"],
                )
            except Exception as e:
                log.log_warn(f"Failed to save initial chat metadata: {e}")
        
        # Add to view
        self.view.add_chat_to_history(
            chat_id,
            chat_name,
            timestamp,
            self.DEFAULT_CHAT_TYPE,
        )
        
        # Set as current chat
        self.current_chat_id = chat_id
        
        # Set initial content
        self._context_snapshot = self._build_context_snapshot()
        self._refresh_transcript_view()
        self.view.set_accept_all_tools_enabled(True)
        self.view.set_accept_all_tools_checked(False)
        self.view.set_pending_approval(None)
        
        log.log_info(f"New chat created: {chat_name}")

    def _create_document_chat(self, title: str, content: str) -> int:
        """Create a new chat populated with document content (called from tool thread).

        This is invoked by the ga_add_document internal tool. The chat
        appears in the sidebar without disrupting the current conversation.
        """
        chat_id = self.next_chat_id
        self.next_chat_id += 1

        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")

        # Create chat data with a single assistant message
        self.chats[chat_id] = {
            "name": title,
            "messages": [{
                "role": "assistant",
                "content": content,
                "timestamp": timestamp
            }],
            "created": timestamp,
            "updated": timestamp,
            "metadata": self._normalize_chat_metadata({
                self.CHAT_TYPE_METADATA_KEY: self.DEFAULT_DOCUMENT_DOC_TYPE,
                self.DOCUMENT_CHAT_METADATA_KEY: True,
            }),
        }

        # Persist to database
        binary_hash = self._current_query_binary_hash or self._get_current_binary_hash()
        if binary_hash:
            try:
                self._save_chat_metadata(chat_id, binary_hash=binary_hash)
                self.analysis_db.delete_native_chat(binary_hash, str(chat_id))
                self.analysis_db.save_edited_message(
                    binary_hash,
                    str(chat_id),
                    message_order=0,
                    role="assistant",
                    content=content,
                    provider_type="symgraph_document",
                )
            except Exception as e:
                log.log_error(f"Failed to persist document chat: {e}")

        # Update UI on the main thread (this may be called from a worker thread)
        from src.ida_compat import execute_on_main_thread

        def _ui_update():
            self.view.add_chat_to_history(
                chat_id,
                title,
                timestamp,
                self.DEFAULT_DOCUMENT_DOC_TYPE,
            )

        execute_on_main_thread(_ui_update)

        log.log_info(f"Document chat created: '{title}' (Chat {chat_id})")
        return chat_id

    def delete_chats(self, selected_rows: List[int]):
        """Delete selected chats"""
        if not selected_rows:
            log.log_warn("No chats selected for deletion")
            return

        # Guard against re-entrant calls (QMessageBox runs a nested event loop
        # that can process pending click events, causing this method to fire twice)
        if getattr(self, '_delete_in_progress', False):
            return
        self._delete_in_progress = True
        try:
            self._delete_chats_impl(selected_rows)
        finally:
            self._delete_in_progress = False

    def _delete_chats_impl(self, selected_rows: List[int]):
        """Internal implementation of chat deletion."""
        log.log_info(f"Deleting {len(selected_rows)} chats")

        # Get chat IDs from selected rows
        chat_ids_to_delete = []
        chat_names = []
        for row in selected_rows:
            try:
                item = self.view.history_table.item(row, 0)
                if item:
                    chat_id = item.data(Qt.UserRole)
                    chat_name = item.text()
                    if chat_id is not None:  # Check for None explicitly
                        chat_ids_to_delete.append(chat_id)
                        chat_names.append(chat_name)
            except Exception as e:
                log.log_error(f"Error getting chat ID from row {row}: {e}")
                continue

        if not chat_ids_to_delete:
            log.log_warn("No valid chat IDs found for deletion")
            return

        # Show confirmation dialog
        from ..qt_compat import QMessageBox
        chat_list = "\n".join([f"• {name}" for name in chat_names[:5]])  # Show first 5
        if len(chat_names) > 5:
            chat_list += f"\n• ... and {len(chat_names) - 5} more"

        reply = QMessageBox.question(
            self.view,
            "Confirm Chat Deletion",
            f"Are you sure you want to delete {len(chat_ids_to_delete)} chat(s)?\n\n{chat_list}\n\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            log.log_info("Chat deletion cancelled by user")
            return

        # Remove from chats dict and database
        binary_hash = self._get_current_binary_hash()
        for chat_id in chat_ids_to_delete:
            if chat_id in self.chats:
                del self.chats[chat_id]

            # Delete from database
            if binary_hash:
                try:
                    self.analysis_db.delete_chat(binary_hash, str(chat_id))
                    log.log_info(f"Deleted chat {chat_id} from legacy database")
                except Exception as e:
                    log.log_error(f"Failed to delete chat {chat_id} from legacy database: {e}")

                # Also delete native chat messages
                try:
                    self.analysis_db.delete_native_chat(binary_hash, str(chat_id))
                    log.log_info(f"Deleted native chat {chat_id} from database")
                except Exception as e:
                    log.log_error(f"Failed to delete native chat {chat_id} from database: {e}")

                # Also delete chat metadata
                try:
                    self.analysis_db.delete_chat_metadata(binary_hash, str(chat_id))
                    log.log_info(f"Deleted chat metadata {chat_id} from database")
                except Exception as e:
                    log.log_error(f"Failed to delete chat metadata {chat_id} from database: {e}")

            # Clear current chat if it was deleted
            if chat_id == self.current_chat_id:
                self.current_chat_id = None

        # Remove from view
        self.view.remove_selected_chats()

        # Set default content if no chats remain
        if not self.chats:
            self.view.set_chat_content("No chat selected. Click 'New' to start a conversation.")
    
    def chat_selected(self, chat_id: int):
        """Handle chat selection"""
        
        if chat_id in self.chats:
            self.current_chat_id = chat_id
            
            # Load chat history from database if not already loaded
            if not self.chats[chat_id]["messages"]:
                try:
                    binary_hash = self._get_current_binary_hash()
                    if binary_hash:
                        db_messages = self.analysis_db.get_chat_history(binary_hash, str(chat_id))
                        # Convert database messages to in-memory format
                        for db_msg in db_messages:
                            message = {
                                "role": db_msg["role"],
                                "content": db_msg["content"],
                                "timestamp": db_msg["created_at"]
                            }
                            self.chats[chat_id]["messages"].append(message)
                        
                except Exception as e:
                    log.log_error(f"Failed to load chat history from database: {e}")
            
            self._context_snapshot = self._build_context_snapshot()
            self._update_chat_display()
            self._on_approval_state_changed()
        else:
            log.log_warn(f"Chat ID {chat_id} not found")
    
    def on_chat_name_changed(self, chat_id: int, new_name: str):
        """Handle chat name change from table editing"""
        log.log_info(f"Chat name changed for {chat_id}: '{new_name}'")
        
        if chat_id not in self.chats:
            log.log_warn(f"Chat ID {chat_id} not found for name change")
            return
        
        # Update in-memory chat data
        old_name = self.chats[chat_id]["name"]
        self.chats[chat_id]["name"] = new_name
        
        # Save to database
        binary_hash = self._get_current_binary_hash()
        if binary_hash:
            try:
                self._save_chat_metadata(chat_id, binary_hash=binary_hash)
                log.log_info(f"Saved chat name change to database: '{old_name}' -> '{new_name}'")
            except Exception as e:
                log.log_error(f"Failed to save chat name change to database: {e}")
                # Revert the in-memory change if database save failed
                self.chats[chat_id]["name"] = old_name
                return
        
        # Update the chat content heading if this is the current chat
        if chat_id == self.current_chat_id:
            self._update_chat_display()
            log.log_info(f"Updated chat display with new heading: '{new_name}'")

    def on_chat_type_changed(self, chat_id: int, new_type: str):
        """Handle chat type changes from the Query history dropdown."""
        if chat_id not in self.chats:
            return

        metadata = self._get_chat_metadata(chat_id)
        resolved_type = new_type if new_type in self.CHAT_TYPE_OPTIONS else self.DEFAULT_CHAT_TYPE
        metadata[self.CHAT_TYPE_METADATA_KEY] = resolved_type
        metadata[self.DOCUMENT_CHAT_METADATA_KEY] = resolved_type != self.DEFAULT_CHAT_TYPE
        if metadata[self.DOCUMENT_CHAT_METADATA_KEY]:
            metadata["symgraph_doc_type"] = resolved_type
        self.chats[chat_id]["metadata"] = metadata
        self._save_chat_metadata(chat_id)
    
    def on_edit_mode_changed(self, is_edit_mode: bool):
        """Handle edit mode change."""
        if self._is_document_chat():
            if is_edit_mode:
                self._prepare_edit_mode()
            else:
                if self.current_chat_id:
                    try:
                        self._save_edited_chat_content_with_manager()
                    except Exception as e:
                        log.log_error(f"Failed to save edited chat: {e}")
            return

        if is_edit_mode:
            self._prepare_latest_assistant_edit_mode()
        else:
            self._save_latest_assistant_edit()

    def _prepare_latest_assistant_edit_mode(self):
        if not self.current_chat_id:
            return
        binary_hash = self._current_query_binary_hash or self._get_current_binary_hash()
        if not binary_hash:
            return
        events = self.transcript_service.get_transcript_events(binary_hash, str(self.current_chat_id))
        for event in reversed(events):
            if event.event_kind == TranscriptEventKind.ASSISTANT_MESSAGE:
                self.view.set_chat_content(event.content_text or "")
                return
        self.view.set_chat_content("")

    def _save_latest_assistant_edit(self):
        if not self.current_chat_id or self._is_document_chat():
            return
        binary_hash = self._current_query_binary_hash or self._get_current_binary_hash()
        if not binary_hash:
            return
        edited_content = self.view.get_chat_content()
        self.transcript_service.update_last_assistant_message(
            binary_hash,
            str(self.current_chat_id),
            edited_content,
        )
        self._refresh_transcript_view()

    def _prepare_edit_mode(self):
        """Prepare chat content for editing using ChatEditManager"""
        if not self.current_chat_id or self.current_chat_id not in self.chats:
            return

        try:
            chat_data = self.chats[self.current_chat_id]
            editable_content = self.chat_edit_manager.generate_editable_content(chat_data)
            self.view.set_chat_content(editable_content)
        except Exception as e:
            log.log_error(f"Failed to prepare edit mode: {e}")

    def _save_edited_chat_content_with_manager(self):
        """Save edited chat content to database"""
        if not self.current_chat_id:
            return

        try:
            edited_content = self.view.get_chat_content()
            if not edited_content:
                return

            binary_hash = self._get_current_binary_hash()
            if not binary_hash:
                log.log_warn("No binary hash available for saving edited content")
                return

            changes = self.chat_edit_manager.parse_edited_content(edited_content)

            if changes:
                messages_updated = self._apply_chat_changes(binary_hash, changes)
                if messages_updated:
                    self._reload_current_chat()
            else:
                # Fallback: Save the raw edited content directly
                self._save_edited_content_directly(binary_hash, edited_content)

        except Exception as e:
            log.log_error(f"Failed to save edited chat content: {e}")

    def _save_edited_content_directly(self, binary_hash: str, edited_content: str):
        """Fallback: Save edited content directly to database (native storage)"""
        try:
            chat_id_str = str(self.current_chat_id)
            chat_name = self.chats[self.current_chat_id].get("name", "Edited Chat")

            # Delete existing messages from native storage and save new content
            self.analysis_db.delete_native_chat(binary_hash, chat_id_str)
            self.analysis_db.save_edited_message(
                binary_hash, chat_id_str,
                message_order=0,
                role="edited",
                content=edited_content
            )
            self.analysis_db.save_chat_metadata(
                binary_hash,
                chat_id_str,
                chat_name,
                metadata=self._get_chat_metadata(self.current_chat_id),
            )

            # Update in-memory chat
            self.chats[self.current_chat_id]["messages"] = [{
                "role": "edited",
                "content": edited_content,
                "timestamp": "edited",
                "db_id": None
            }]
            self._update_chat_display()

        except Exception as e:
            log.log_error(f"Failed to save edited content directly: {e}")
    
    def _apply_chat_changes(self, binary_hash: str, changes) -> bool:
        """Apply detected changes to the database

        Parses ALL chunks from the edited content rather than relying on message_map,
        since a chat may have been previously saved as a single "edited" message.
        """
        try:
            from .chat_edit_manager import ChangeType

            messages_updated = False
            title_updated = False
            new_title = None

            for change in changes:
                if change.change_type == ChangeType.MODIFIED:
                    if getattr(change, 'role', None) == 'title':
                        title_updated = True
                        new_title = change.new_content
                    else:
                        messages_updated = True
                elif change.change_type == ChangeType.DELETED:
                    messages_updated = True
                elif change.change_type == ChangeType.ADDED:
                    if change.new_content:
                        messages_updated = True

            # Rebuild chat by parsing ALL chunks directly from the edited content
            if messages_updated:
                edited_content = self.view.get_chat_content()
                final_messages = self._extract_all_messages_from_edited_content(edited_content)

                # Delete existing chat from native storage and recreate
                self.analysis_db.delete_native_chat(binary_hash, str(self.current_chat_id))

                # Save all messages to native storage
                for i, message in enumerate(final_messages):
                    self.analysis_db.save_edited_message(
                        binary_hash, str(self.current_chat_id),
                        message_order=i,
                        role=message["role"],
                        content=message["content"]
                    )

                # Update in-memory chat
                self.chats[self.current_chat_id]["messages"] = final_messages

            # Handle title changes
            if title_updated and new_title:
                self.chats[self.current_chat_id]["name"] = new_title

                # Save updated title to database
                try:
                    self._save_chat_metadata(self.current_chat_id, binary_hash=binary_hash)
                except Exception as e:
                    log.log_error(f"Failed to save updated chat title: {e}")

                # Update the chat name in the history table
                try:
                    for row in range(self.view.history_table.rowCount()):
                        item = self.view.history_table.item(row, 0)
                        if item and item.data(Qt.UserRole) == self.current_chat_id:
                            item.setText(new_title)
                            break
                except Exception as e:
                    log.log_warn(f"Could not update chat name in history table: {e}")
            
            return messages_updated or title_updated
            
        except Exception as e:
            log.log_error(f"Failed to apply chat changes: {e}")
            return False

    def _extract_all_messages_from_edited_content(self, edited_content: str) -> list:
        """Extract all messages from edited markdown content.

        Parses chunk markers and content, rebuilding the message list from raw markdown.
        Works even when the original message_map only had 1 entry.
        """
        import re

        messages = []

        # Split content by chunk markers to get each section
        chunk_split_pattern = r'(<!-- CHUNK:[^>]+ -->)'
        parts = re.split(chunk_split_pattern, edited_content)

        # Process pairs of (chunk_marker, content)
        i = 0
        while i < len(parts):
            part = parts[i]

            # Check if this is a chunk marker
            chunk_match = re.match(r'<!-- CHUNK:([^>]+) -->', part.strip())
            if chunk_match and i + 1 < len(parts):
                chunk_content = parts[i + 1]

                # Parse the header to get role (format: ## Role (timestamp))
                header_match = re.match(r'\s*##?\s*(\w+)(?:\s*\([^)]*\))?', chunk_content)
                if header_match:
                    role_text = header_match.group(1).lower()

                    # Map role text to standard roles
                    if role_text == 'user':
                        role = 'user'
                    elif role_text in ('binassist', 'assistant'):
                        role = 'assistant'
                    elif role_text == 'edited':
                        role = 'edited'
                    elif role_text == 'error':
                        role = 'error'
                    else:
                        role = role_text

                    # Extract content after the header line
                    lines = chunk_content.split('\n')
                    content_lines = []
                    found_header = False
                    for line in lines:
                        if not found_header:
                            if re.match(r'\s*##?\s*\w+', line):
                                found_header = True
                            continue
                        content_lines.append(line)

                    content = '\n'.join(content_lines).strip()

                    # Remove trailing horizontal rules
                    while content.endswith('---'):
                        content = content[:-3].strip()

                    if content:
                        messages.append({
                            "role": role,
                            "content": content,
                            "timestamp": "edited",
                            "db_id": None
                        })

                i += 2  # Skip marker and content
            else:
                i += 1

        # If no chunks found, try header-based extraction as fallback
        if not messages:
            messages = self._extract_messages_by_headers(edited_content)

        return messages

    def _extract_messages_by_headers(self, content: str) -> list:
        """Fallback extraction using section headers when chunk markers fail."""
        import re

        messages = []

        # Find all headers like ## User (...), ## IDAssist (...), etc.
        header_pattern = r'^##\s+(User|IDAssist|Assistant|Edited|Error)(?:\s*\([^)]*\))?'

        lines = content.split('\n')
        current_role = None
        current_content = []

        for line in lines:
            header_match = re.match(header_pattern, line, re.IGNORECASE)
            if header_match:
                # Save previous message if exists
                if current_role and current_content:
                    msg_content = '\n'.join(current_content).strip()
                    if msg_content:
                        messages.append({
                            "role": current_role,
                            "content": msg_content,
                            "timestamp": "edited",
                            "db_id": None
                        })

                # Start new message
                role_text = header_match.group(1).lower()
                if role_text == 'binassist':
                    current_role = 'assistant'
                else:
                    current_role = role_text
                current_content = []
            elif line.startswith('# ') and not line.startswith('## '):
                # Skip title
                continue
            elif line.strip().startswith('<!-- CHUNK:'):
                # Skip chunk markers
                continue
            elif line.strip() == '---':
                # Skip horizontal rules
                continue
            elif current_role:
                current_content.append(line)

        # Don't forget the last message
        if current_role and current_content:
            msg_content = '\n'.join(current_content).strip()
            if msg_content:
                messages.append({
                    "role": current_role,
                    "content": msg_content,
                    "timestamp": "edited",
                    "db_id": None
                })

        return messages

    def _reload_current_chat(self):
        """Reload the current chat from database (native storage)"""
        if not self.current_chat_id:
            return

        try:
            binary_hash = self._get_current_binary_hash()
            if not binary_hash:
                return

            # Load fresh messages from native storage
            messages = self.analysis_db.get_display_messages(binary_hash, str(self.current_chat_id))

            # Convert to our format
            formatted_messages = []
            for msg in messages:
                formatted_messages.append({
                    "role": msg["role"],
                    "content": msg["content"],
                    "timestamp": msg.get("created_at", ""),
                    "db_id": msg.get("id"),
                    "message_type": msg.get("message_type", "standard"),
                    "provider_type": msg.get("provider_type", "unknown")
                })

            # Update in-memory chat and display
            self.chats[self.current_chat_id]["messages"] = formatted_messages
            self._update_chat_display()

        except Exception as e:
            log.log_error(f"Failed to reload current chat: {e}")

    def _default_chat_metadata(self) -> Dict[str, Any]:
        return self._normalize_chat_metadata({})

    def _normalize_chat_metadata(self, metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        normalized = dict(metadata or {})
        chat_type = normalized.get(self.CHAT_TYPE_METADATA_KEY)
        if chat_type == "protocol_spec":
            chat_type = "api_doc"
        if chat_type not in self.CHAT_TYPE_OPTIONS:
            if normalized.get(self.DOCUMENT_CHAT_METADATA_KEY):
                chat_type = normalized.get("symgraph_doc_type", self.DEFAULT_DOCUMENT_DOC_TYPE)
                if chat_type == "protocol_spec":
                    chat_type = "api_doc"
            else:
                chat_type = self.DEFAULT_CHAT_TYPE
        normalized[self.CHAT_TYPE_METADATA_KEY] = chat_type
        normalized[self.DOCUMENT_CHAT_METADATA_KEY] = chat_type != self.DEFAULT_CHAT_TYPE
        if normalized[self.DOCUMENT_CHAT_METADATA_KEY]:
            normalized["symgraph_doc_type"] = chat_type
        return normalized

    def _get_chat_metadata(self, chat_id: int) -> Dict[str, Any]:
        chat = self.chats.get(chat_id, {})
        metadata = chat.get("metadata")
        normalized = self._normalize_chat_metadata(metadata)
        if chat:
            chat["metadata"] = normalized
        return normalized

    def _save_chat_metadata(self, chat_id: int, binary_hash: Optional[str] = None):
        if chat_id not in self.chats:
            return
        binary_hash = binary_hash or self._current_query_binary_hash or self._get_current_binary_hash()
        if not binary_hash:
            return
        chat = self.chats[chat_id]
        self.analysis_db.save_chat_metadata(
            binary_hash,
            str(chat_id),
            chat.get("name", f"Chat {chat_id}"),
            metadata=self._get_chat_metadata(chat_id),
        )

    def _ensure_chat_messages_loaded(self, chat_id: int):
        if chat_id not in self.chats or self.chats[chat_id]["messages"]:
            return

        self._load_chat_from_native_storage(chat_id)
        if self.chats[chat_id]["messages"]:
            return

        try:
            binary_hash = self._get_current_binary_hash()
            if not binary_hash:
                return
            db_messages = self.analysis_db.get_chat_history(binary_hash, str(chat_id))
            for db_msg in db_messages:
                self.chats[chat_id]["messages"].append({
                    "role": db_msg["role"],
                    "content": db_msg["content"],
                    "timestamp": db_msg["created_at"],
                })
        except Exception as e:
            log.log_error(f"Failed to load chat history from database: {e}")

    def _find_chat_id_by_document_identity(self, document_identity_id: str) -> Optional[int]:
        if not document_identity_id:
            return None
        for chat_id, chat in self.chats.items():
            metadata = self._normalize_chat_metadata(chat.get("metadata"))
            if metadata.get("symgraph_document_identity_id") == document_identity_id:
                return chat_id
        return None

    def upsert_symgraph_document_chat(self, document) -> int:
        """Create or update a Query chat from a remote SymGraph document."""
        binary_hash = self._current_query_binary_hash or self._get_current_binary_hash()
        if not binary_hash:
            raise RuntimeError("No binary hash available for document import")

        existing_chat_id = self._find_chat_id_by_document_identity(document.document_identity_id)
        chat_id = existing_chat_id if existing_chat_id is not None else self.next_chat_id
        if existing_chat_id is None:
            self.next_chat_id += 1

        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        metadata = self._normalize_chat_metadata({
            self.CHAT_TYPE_METADATA_KEY: (document.doc_type or self.DEFAULT_DOCUMENT_DOC_TYPE),
            self.DOCUMENT_CHAT_METADATA_KEY: True,
            "symgraph_document_identity_id": document.document_identity_id,
            "symgraph_document_version": document.version,
            "symgraph_last_synced_at": timestamp,
            "symgraph_source_sha256": binary_hash,
        })
        chat_payload = {
            "name": document.title,
            "messages": [{
                "role": "assistant",
                "content": document.content,
                "timestamp": timestamp,
            }],
            "created": timestamp,
            "updated": timestamp,
            "metadata": metadata,
        }
        self.chats[chat_id] = chat_payload

        self.analysis_db.delete_native_chat(binary_hash, str(chat_id))
        self.analysis_db.save_edited_message(
            binary_hash,
            str(chat_id),
            message_order=0,
            role="assistant",
            content=document.content,
            provider_type="symgraph_document",
        )
        self._save_chat_metadata(chat_id, binary_hash=binary_hash)

        from src.ida_compat import execute_on_main_thread

        def _update_ui():
            display_timestamp = self._convert_utc_to_local_display(timestamp)
            updated_row = False
            for row in range(self.view.history_table.rowCount()):
                item = self.view.history_table.item(row, 0)
                if item and item.data(Qt.UserRole) == chat_id:
                    item.setText(document.title)
                    ts_item = self.view.history_table.item(row, 1)
                    if ts_item:
                        ts_item.setText(display_timestamp)
                    self.view.set_chat_type_cell(
                        row,
                        chat_id,
                        metadata.get(self.CHAT_TYPE_METADATA_KEY, self.DEFAULT_CHAT_TYPE),
                    )
                    updated_row = True
                    break
            if not updated_row:
                self.view.add_chat_to_history(
                    chat_id,
                    document.title,
                    display_timestamp,
                    metadata.get(self.CHAT_TYPE_METADATA_KEY, self.DEFAULT_CHAT_TYPE),
                )
            if self.current_chat_id == chat_id:
                self._update_chat_display()

        execute_on_main_thread(_update_ui)
        log.log_info(
            f"{'Updated' if existing_chat_id is not None else 'Imported'} SymGraph document chat "
            f"'{document.title}' (Chat {chat_id})"
        )
        return chat_id

    def list_document_push_candidates(self) -> List[Dict[str, Any]]:
        """Return marked document chats for SymGraph push preview."""
        candidates: List[Dict[str, Any]] = []
        for chat_id, chat in self.chats.items():
            metadata = self._get_chat_metadata(chat_id)
            chat_type = metadata.get(self.CHAT_TYPE_METADATA_KEY, self.DEFAULT_CHAT_TYPE)
            if chat_type == self.DEFAULT_CHAT_TYPE:
                continue

            markdown = self.serialize_document_chat(chat_id)
            title = chat.get("name", f"Chat {chat_id}")
            updated_at = chat.get("updated") or chat.get("created")
            candidates.append({
                "chat_id": chat_id,
                "title": title,
                "content": markdown,
                "size_bytes": len(markdown.encode("utf-8")),
                "updated_at": updated_at,
                "document_identity_id": metadata.get("symgraph_document_identity_id"),
                "version": metadata.get("symgraph_document_version"),
                "doc_type": chat_type,
            })

        candidates.sort(key=lambda item: item.get("updated_at") or "", reverse=True)
        return candidates

    def update_document_sync_metadata(
        self,
        chat_id: int,
        document_identity_id: str,
        version: Optional[int],
        doc_type: Optional[str],
    ):
        """Persist remote document linkage after a successful push."""
        if chat_id not in self.chats:
            return
        metadata = self._get_chat_metadata(chat_id)
        resolved_type = doc_type or metadata.get(
            self.CHAT_TYPE_METADATA_KEY,
            self.DEFAULT_DOCUMENT_DOC_TYPE,
        )
        metadata[self.CHAT_TYPE_METADATA_KEY] = resolved_type
        metadata[self.DOCUMENT_CHAT_METADATA_KEY] = resolved_type != self.DEFAULT_CHAT_TYPE
        metadata["symgraph_document_identity_id"] = document_identity_id
        metadata["symgraph_document_version"] = version
        metadata["symgraph_doc_type"] = resolved_type
        metadata["symgraph_last_synced_at"] = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.chats[chat_id]["metadata"] = metadata
        self._save_chat_metadata(chat_id)

    def serialize_document_chat(self, chat_id: int) -> str:
        """Serialize a document chat to Markdown for SymGraph push."""
        if chat_id not in self.chats:
            return ""
        self._ensure_chat_messages_loaded(chat_id)
        chat = self.chats[chat_id]
        messages = chat.get("messages", [])
        if len(messages) == 1 and messages[0].get("role") in ("assistant", "edited"):
            return messages[0].get("content", "")
        return self._format_chat_as_markdown(chat)

    def on_rag_enabled_changed(self, enabled: bool):
        """Handle RAG checkbox change"""
        log.log_info(f"RAG enabled changed to: {enabled}")
        # TODO: Update RAG settings for future queries
    
    def on_mcp_enabled_changed(self, enabled: bool):
        """Handle MCP checkbox change"""
        log.log_info(f"MCP enabled changed to: {enabled}")
        # TODO: Update MCP settings for future queries

    def on_agentic_enabled_changed(self, enabled: bool):
        """Handle Agentic mode checkbox change"""
        log.log_info(f"Agentic mode enabled changed to: {enabled}")
        # Agentic mode requires MCP to be enabled
        if enabled and not self.view.is_mcp_enabled():
            log.log_info("Enabling MCP for agentic mode")
            self.view.set_mcp_enabled(True)

    def _add_message_to_chat(self, chat_id: int, role: str, content: str, save_to_db: bool = True):
        """Add a message to the specified chat"""
        if chat_id not in self.chats:
            log.log_error(f"Chat ID {chat_id} not found in chats")
            return
        
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        message = {
            "role": role,
            "content": content,
            "timestamp": timestamp
        }
        
        self.chats[chat_id]["messages"].append(message)
        self.chats[chat_id]["updated"] = timestamp
        self._context_snapshot = self._build_context_snapshot()
        
        # Persist to database only if requested
        if save_to_db:
            try:
                binary_hash = self._current_query_binary_hash or self._get_current_binary_hash()
                if binary_hash:
                    message_order = len(self.chats[chat_id]["messages"]) - 1
                    self.analysis_db.save_chat_message(
                        binary_hash, str(chat_id), role, content, 
                        metadata={"message_order": message_order}
                    )
                else:
                    log.log_warn(f"No binary hash available for saving {role} message")
            except Exception as e:
                log.log_error(f"Failed to persist chat message: {e}")

    def _on_streaming_update(self, update) -> None:
        """Handle streaming renderer updates with incremental display."""
        if not self.current_chat_id or self.current_chat_id not in self.chats:
            return

        # Get filtered markdown and update assistant message in memory
        filtered_markdown = self._streaming_renderer.get_full_markdown()
        self._active_stream_markdown = filtered_markdown
        self._update_last_assistant_message(filtered_markdown)
        self._apply_streaming_transcript_update(filtered_markdown)

    def _on_thinking_start(self) -> None:
        """Show thinking indicator when <reasoning> detected."""
        self._streaming_renderer.on_chunk("*Thinking...*\n\n")

    def _update_chat_display(self):
        """Update the chat display with current chat content"""
        if not self.current_chat_id or self.current_chat_id not in self.chats:
            return

        if not self._is_document_chat():
            self._refresh_transcript_view(self._active_stream_markdown or None)
            return

        # Only load from native storage when not actively streaming
        # During streaming (standard or ReAct), use in-memory messages that are being updated
        if not self._query_active and not self._react_active:
            try:
                self._load_chat_from_native_storage(self.current_chat_id)
            except Exception as e:
                log.log_debug(f"Native storage load failed, using legacy: {e}")
        
        chat = self.chats[self.current_chat_id]
        markdown_content = self._format_chat_as_markdown(chat)
        self.view.set_chat_content(markdown_content)
    
    def _load_chat_from_native_storage(self, chat_id: int):
        """Load chat messages from native storage for display"""
        try:
            binary_hash = self._get_current_binary_hash()
            if not binary_hash:
                return
            
            # Get display-optimized messages from native storage
            display_messages = self.analysis_db.get_display_messages(binary_hash, str(chat_id))
            
            # Update in-memory chat with display messages
            if chat_id in self.chats:
                formatted_messages = []
                for msg in display_messages:
                    formatted_messages.append({
                        "role": msg["role"],
                        "content": msg["content"],
                        "timestamp": msg["created_at"],
                        "message_type": msg.get("message_type", "standard"),
                        "provider_type": msg.get("provider_type", "unknown")
                    })
                
                self.chats[chat_id]["messages"] = formatted_messages
                log.log_debug(f"Loaded {len(formatted_messages)} messages from native storage")
        
        except Exception as e:
            log.log_warn(f"Failed to load chat from native storage: {e}")
            # Will fall back to legacy loading
    
    def _format_chat_as_markdown(self, chat: Dict[str, Any]) -> str:
        """Format chat messages as markdown with horizontal rules between conversation pairs"""
        if not chat["messages"]:
            return f"# {chat['name']}\n\n*No messages yet. Enter your query below.*"
        
        content = f"# {chat['name']}\n\n"
        
        messages = chat["messages"]
        conversation_pair_count = 0
        
        for i, message in enumerate(messages):
            role = message["role"]
            text = message["content"] 
            timestamp = message["timestamp"]
            
            if role == "user":
                # Add horizontal rule before each new conversation pair (except the first)
                if conversation_pair_count > 0:
                    content += "---\n\n"
                
                content += f"## User ({timestamp})\n{text}\n\n"
                conversation_pair_count += 1
                
            elif role == "assistant":
                content += f"## IDAssist ({timestamp})\n{text}\n\n"
                
            elif role == "tool":
                content += f"### 🔧 Tool ({timestamp})\n{text}\n\n"
                
            elif role == "tool_call":
                content += f"### 🔧 Tool Call ({timestamp})\n{text}\n\n"
                
            elif role == "tool_response":
                content += f"### 📊 Tool Response ({timestamp})\n{text}\n\n"

            elif role == "tool_status":
                # Tool status messages: just success/failure indicators
                content += f"*{text}*\n\n"

            elif role == "error":
                content += f"## Error ({timestamp})\n**{text}**\n\n"

            elif role == "edited":
                # User-edited content is displayed as-is (already formatted)
                content += f"{text}\n\n"

        return content

    def _render_chat_history_for_streaming(self, chat: Dict[str, Any]) -> str:
        """Render chat history excluding last assistant message (which is streaming).

        Returns HTML that can be used as the static base for incremental streaming updates.
        """
        messages = chat.get("messages", [])

        # Exclude the last message if it's an assistant message (the streaming one)
        if messages and messages[-1]["role"] == "assistant":
            history_messages = messages[:-1]
        else:
            history_messages = messages

        # Create a temporary chat dict with just the history
        history_chat = {
            "name": chat.get("name", "Chat"),
            "messages": history_messages
        }

        # Format as markdown
        markdown_content = self._format_chat_as_markdown(history_chat)

        # Add the assistant header for the streaming message
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        markdown_content += f"## IDAssist ({timestamp})\n"

        # Convert to HTML using the view's markdown_to_html method
        return self.view.markdown_to_html(markdown_content)

    def _get_initial_chat_content(self) -> str:
        """Get initial content for new chat"""
        try:
            context = self.context_service.get_current_context()
            
            content = f"""# New Chat Started

## Current Context
**Offset**: {context.get('offset_hex', 'N/A')}  
**Filename**: {context.get('binary_info', {}).get('filename', 'Unknown')}  
**Path**: {context.get('binary_info', {}).get('filepath', 'Unknown')}  
**Architecture**: {context.get('binary_info', {}).get('architecture', 'Unknown')}  

"""
            
            func_ctx = context.get("function_context")
            if func_ctx:
                content += f"**Function**: {func_ctx['name']} ({func_ctx['start']} - {func_ctx['end']})\n\n"
            
            content += "*Enter your query below to start the conversation.*"
            
        except Exception as e:
            content = f"# New Chat Started\n\n*Error getting context: {str(e)}*\n\n*Enter your query below to start the conversation.*"
        
        return content
    
    def _format_query_with_context(self, query: str, context: Dict[str, Any], rag_enabled: bool, mcp_enabled: bool) -> str:
        """Format query with context information for LLM"""
        formatted = f"""Query: {query}

Context Information:
- Offset: {context.get('offset_hex', 'N/A')}
- Filename: {context.get('binary_info', {}).get('filename', 'Unknown')}
- Path: {context.get('binary_info', {}).get('filepath', 'Unknown')}
- Architecture: {context.get('binary_info', {}).get('architecture', 'Unknown')}
"""
        
        func_ctx = context.get("function_context")
        if func_ctx:
            formatted += f"- Function: {func_ctx['name']} ({func_ctx['start']} - {func_ctx['end']})\n"
        
        formatted += f"""
Settings:
- RAG Enabled: {rag_enabled}
- MCP Enabled: {mcp_enabled}
"""
        
        return formatted
    
    def _generate_mock_response(self, query: str, context: Dict[str, Any]) -> str:
        """Generate a mock response for testing (will be replaced with LLM)"""
        func_ctx = context.get("function_context")
        binary_info = context.get("binary_info", {})
        
        response = f"""I understand you're asking: "{query}"

Based on the current context:
- **Filename**: {binary_info.get('filename', 'Unknown')}
- **Path**: {binary_info.get('filepath', 'Unknown')}
- **Architecture**: {binary_info.get('architecture', 'Unknown')}
- **Current Offset**: {context.get('offset_hex', 'N/A')}
"""
        
        if func_ctx:
            response += f"- **Function**: {func_ctx['name']} (Size: {func_ctx['size']} bytes)\n"
        
        response += """
*This is a mock response. LLM integration will be implemented in a future update to provide intelligent analysis and answers to your reverse engineering questions.*

Some capabilities that will be available:
- Code analysis and explanation
- Vulnerability identification
- Algorithm recognition
- Decompilation assistance
- Binary comparison
- And much more!
"""
        
        return response
    
    # LLM Integration Methods
    
    def _handle_no_llm_provider(self, query_text: str):
        """Handle case where no LLM provider is configured"""
        response = f"""**No LLM provider configured**

To get AI-powered responses to your queries, please:
1. Go to Settings → LLM Providers
2. Add and configure an LLM provider (OpenAI, Anthropic, etc.)
3. Set it as the active provider

For now, here's some basic information about your query: "{query_text}"

Current context:
- Filename: {self.context_service.get_current_context().get('binary_info', {}).get('filename', 'Unknown')}
- Path: {self.context_service.get_current_context().get('binary_info', {}).get('filepath', 'Unknown')}
- Offset: {self.context_service.get_current_context().get('offset_hex', 'N/A')}
"""
        
        self._update_last_assistant_message(response, final_update=True)
        self._update_chat_display()
        self._query_active = False
        self._current_query_binary_hash = None
        self.view.set_query_running(False)
    
    def _prepare_llm_messages(self, query_text: str, context: Dict[str, Any], rag_enabled: bool, mcp_enabled: bool) -> List[Dict[str, Any]]:
        """Prepare conversation messages for LLM, including context and history (LEGACY - use _prepare_native_messages)"""
        messages = []
        
        # Add system message with context
        system_content = self._build_system_message(context, rag_enabled, mcp_enabled)
        messages.append({"role": "system", "content": system_content})
        
        # Add conversation history (excluding the current query and placeholder response)
        if self.current_chat_id in self.chats:
            chat_messages = self.chats[self.current_chat_id]["messages"]
            # Exclude the last 2 messages (current user query and placeholder assistant response)
            for msg in chat_messages[:-2]:
                if msg["role"] in ["user", "assistant"]:
                    messages.append({
                        "role": msg["role"], 
                        "content": msg["content"]
                    })
        
        # Add current user query with RAG/MCP enhancements
        enhanced_query = self._enhance_query_with_context(query_text, context, rag_enabled, mcp_enabled)
        messages.append({"role": "user", "content": enhanced_query})
        
        return messages
    
    def _prepare_native_messages(self, query_text: str, context: Dict[str, Any], 
                               rag_enabled: bool, mcp_enabled: bool, provider_type: str) -> List[Dict[str, Any]]:
        """Prepare conversation messages in provider's native format using stored history"""
        from src.services.message_format_service import get_message_format_service
        from src.services.models.provider_types import ProviderType
        
        try:
            provider_enum = ProviderType(provider_type)
        except ValueError:
            raise ValueError(f"Unsupported provider type: {provider_type}")
        
        format_service = get_message_format_service()
        messages = []
        
        # Add system message in provider's native format
        system_content = self._build_system_message(context, rag_enabled, mcp_enabled)
        system_message = format_service.create_system_message(system_content, provider_enum)
        messages.append(system_message)
        
        # Add conversation history from native storage
        # Note: This should already include the current user query if it was saved via _save_user_message_native()
        if self.current_chat_id:
            try:
                binary_hash = self._get_current_binary_hash()
                if binary_hash:
                    # Get native messages for this specific provider
                    native_messages = self.analysis_db.get_native_messages_for_provider(
                        binary_hash, str(self.current_chat_id), provider_type
                    )
                    messages.extend(native_messages)
                    
                    # Check if the last message is the current user query to avoid duplication
                    if native_messages:
                        last_message = native_messages[-1]
                        # Extract content from the native message to compare
                        _, last_content, _ = format_service.extract_display_info(last_message, provider_enum)
                        enhanced_query = self._enhance_query_with_context(query_text, context, rag_enabled, mcp_enabled)
                        
                        # If the last message matches our current query, don't add it again
                        if enhanced_query in last_content or last_content in enhanced_query:
                            log.log_debug("Current user query already in conversation history, skipping duplicate")
                            return messages
            except Exception as e:
                log.log_warn(f"Failed to load native conversation history: {e}")
                # Fallback to legacy method if native history not available
                return self._prepare_llm_messages(query_text, context, rag_enabled, mcp_enabled)
        
        # Add current user query in provider's native format (only if not already in history)
        enhanced_query = self._enhance_query_with_context(query_text, context, rag_enabled, mcp_enabled)
        user_message = format_service.create_user_message(enhanced_query, provider_enum)
        messages.append(user_message)
        
        return messages
    
    def _save_user_message_native(self, query_text: str, provider_type: str):
        """Save user message in provider's native format"""
        try:
            binary_hash = self._get_current_binary_hash()
            if not binary_hash or not self.current_chat_id:
                log.log_warn("Cannot save user message: missing binary hash or chat ID")
                return
            
            from src.services.message_format_service import get_message_format_service
            from src.services.models.provider_types import ProviderType
            
            provider_enum = ProviderType(provider_type)
            format_service = get_message_format_service()
            
            # Create native user message
            context = self.context_service.get_current_context()
            enhanced_query = self._enhance_query_with_context(
                query_text, context, self.view.is_rag_enabled(), self.view.is_mcp_enabled()
            )
            native_message = format_service.create_user_message(enhanced_query, provider_enum)
            
            # Save to database
            self.analysis_db.save_native_message(
                binary_hash, str(self.current_chat_id), native_message, provider_type
            )
            
            log.log_debug(f"Saved user message in {provider_type} native format")
            
        except Exception as e:
            log.log_error(f"Failed to save user message in native format: {e}")
    
    def _save_assistant_response_native(self, response_content: str, tool_calls: List = None, 
                                      provider_type: str = None, finish_reason: str = None):
        """Save assistant response in provider's native format"""
        try:
            binary_hash = self._get_current_binary_hash()
            if not binary_hash or not self.current_chat_id:
                log.log_warn("Cannot save assistant response: missing binary hash or chat ID")
                return
            
            if not provider_type:
                # Get provider type from active provider
                active_provider = self.settings_service.get_active_llm_provider()
                if not active_provider:
                    log.log_warn("Cannot save assistant response: no active provider")
                    return
                provider_type = active_provider.get('provider_type', 'anthropic_platform')
            
            from src.services.message_format_service import get_message_format_service
            from src.services.models.provider_types import ProviderType
            from src.services.models.llm_models import ChatMessage, MessageRole, ToolCall
            
            provider_enum = ProviderType(provider_type)
            format_service = get_message_format_service()
            
            # Convert tool calls to proper format if provided
            structured_tool_calls = []
            if tool_calls:
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
            
            # Create ChatMessage
            assistant_message = ChatMessage(
                role=MessageRole.ASSISTANT,
                content=response_content,
                tool_calls=structured_tool_calls if structured_tool_calls else None
            )
            
            # Convert to native format
            native_message = format_service.to_native_format(assistant_message, provider_enum)
            
            # Save to database
            self.analysis_db.save_native_message(
                binary_hash, str(self.current_chat_id), native_message, provider_type
            )
            
            log.log_debug(f"Saved assistant response in {provider_type} native format")
            
        except Exception as e:
            log.log_error(f"Failed to save assistant response in native format: {e}")
    
    def _save_tool_response_native(self, tool_call_id: str, response_content: str, provider_type: str):
        """Save tool response in provider's native format"""
        try:
            binary_hash = self._get_current_binary_hash()
            if not binary_hash or not self.current_chat_id:
                log.log_warn("Cannot save tool response: missing binary hash or chat ID")
                return
            
            from src.services.message_format_service import get_message_format_service
            from src.services.models.provider_types import ProviderType
            from src.services.models.llm_models import ChatMessage, MessageRole
            
            provider_enum = ProviderType(provider_type)
            format_service = get_message_format_service()
            
            # Create tool response message
            tool_message = ChatMessage(
                role=MessageRole.TOOL,
                content=response_content,
                tool_call_id=tool_call_id
            )
            
            # Convert to native format
            native_message = format_service.to_native_format(tool_message, provider_enum)
            
            # Save to database
            self.analysis_db.save_native_message(
                binary_hash, str(self.current_chat_id), native_message, provider_type
            )
            
            log.log_debug(f"Saved tool response in {provider_type} native format")
            
        except Exception as e:
            log.log_error(f"Failed to save tool response in native format: {e}")
    
    def _create_native_message_callback(self) -> Callable[[Dict[str, Any], Any], None]:
        """Create callback function for provider native message updates"""
        def callback(native_message: Dict[str, Any], provider_type) -> None:
            try:
                # Only save assistant messages via callback - user and tool messages saved elsewhere
                if native_message.get("role") == "assistant":
                    binary_hash = self._current_query_binary_hash or self._get_current_binary_hash()
                    if binary_hash and self.current_chat_id:
                        provider_type_str = provider_type.value if hasattr(provider_type, 'value') else str(provider_type)
                        self.analysis_db.save_native_message(
                            binary_hash, str(self.current_chat_id), native_message, provider_type_str
                        )
                        log.log_debug(f"Saved assistant native message via callback for {provider_type_str}")
                    else:
                        log.log_warn("Cannot save native message: missing binary hash or chat ID")
            except Exception as e:
                log.log_error(f"Error in native message callback: {e}")
        
        return callback
    
    def _build_system_message(self, context: Dict[str, Any], rag_enabled: bool, mcp_enabled: bool) -> str:
        """Build system message with current context"""
        binary_info = context.get('binary_info', {})
        func_ctx = context.get('function_context')
        
        system_msg = f"""You are IDAssist, an AI assistant specialized in reverse engineering and binary analysis.

Current Analysis Context:
- Filename: {binary_info.get('filename', 'Unknown')}
- Path: {binary_info.get('filepath', 'Unknown')}
- Architecture: {binary_info.get('architecture', 'Unknown')}
- Platform: {binary_info.get('platform', 'Unknown')}
- Current Offset: {context.get('offset_hex', 'N/A')}"""
        
        if func_ctx:
            system_msg += f"\n- Current Function: {func_ctx['name']} ({func_ctx['start']} - {func_ctx['end']})"
            system_msg += f"\n- Function Size: {func_ctx['size']} bytes"
        
        system_msg += f"""

Capabilities:
- RAG (Documentation Search): {'Enabled' if rag_enabled else 'Disabled'}
- MCP (External Tools): {'Enabled' if mcp_enabled else 'Disabled'}

Instructions:
- Provide detailed, technical analysis relevant to reverse engineering
- Focus on the current binary context when applicable
- Use clear, structured responses with code examples when helpful
- If asked about specific code, relate it to the current offset/function when relevant"""

        if mcp_enabled:
            system_msg += """

Tool Usage Guidelines:
- When asked to analyze functions, binaries, or code, use multiple tool calls to gather comprehensive information
- Start with basic tools like get_binary_status, then use specific analysis tools based on what you discover
- Don't stop after one tool call - use the results to determine what additional information is needed
- For function analysis, typically use: get_binary_status → get_function_pseudo_c → get_references, etc.
- Always explain your analysis based on the tool results you gather
- If a tool result suggests more investigation is needed, make additional tool calls
- Provide a comprehensive answer only after you've gathered sufficient context through tool calls
"""
        
        return system_msg
    
    def _enhance_query_with_context(self, query_text: str, context: Dict[str, Any], rag_enabled: bool, mcp_enabled: bool) -> str:
        """Enhance user query with additional context from RAG and MCP"""
        enhanced_query = query_text
        
        # Add RAG context if enabled
        if rag_enabled:
            rag_context = self._get_rag_context(query_text)
            if rag_context:
                enhanced_query += f"\n\n{rag_context}"
        
        # Add MCP context if enabled (tools will be available to LLM)
        if mcp_enabled:
            mcp_context = "Use the available tool calls as needed."
            if mcp_context:
                enhanced_query += f"\n\n{mcp_context}"
        
        return enhanced_query
    
    def _get_rag_context(self, query_text: str) -> str:
        """Get RAG context for the query"""
        try:
            request = SearchRequest(
                query=query_text,
                search_type=SearchType.HYBRID,
                max_results=3,
                similarity_threshold=0.3,
                include_metadata=True
            )
            
            results = rag_service.search(request)
            
            if not results:
                return ""
            
            rag_context = "## Additional Reference Context\n"
            rag_context += "The following documentation may be helpful:\n\n"
            
            for i, result in enumerate(results, 1):
                score_percent = int(result.score * 100)
                rag_context += f"### Reference {i} (Relevance: {score_percent}%)\n"
                rag_context += f"**Source:** {result.filename}\n"
                rag_context += f"**Content:** {result.snippet}\n\n"
            
            return rag_context
            
        except Exception as e:
            log.log_error(f"Error getting RAG context: {e}")
            return ""
    
    def _get_mcp_context(self) -> str:
        """Get MCP context (available tools)"""
        try:
            # Use connection manager to get available tools
            if not self.mcp_connection_manager.is_available():
                return ""
            
            tools = self.mcp_connection_manager.get_available_tools_for_llm()
            
            if not tools:
                return ""
            
            mcp_context = "## Available MCP Tools\n"
            mcp_context += "The following external tools are available for your assistance:\n\n"
            
            for tool in tools[:5]:  # Show first 5 tools
                tool_name = tool.get("function", {}).get("name", "Unknown")
                tool_desc = tool.get("function", {}).get("description", "No description")
                mcp_context += f"- **{tool_name}**: {tool_desc}\n"
            
            if len(tools) > 5:
                mcp_context += f"\n... and {len(tools) - 5} more tools available.\n"
            
            return mcp_context
            
        except Exception as e:
            log.log_error(f"Error getting MCP context: {e}")
            return ""
    
    def _start_llm_query(self, messages: List[Dict[str, Any]], provider_config: dict, mcp_tools: List[Dict[str, Any]] = None):
        """Start the LLM query thread with optional MCP tools"""
        # Clear previous response buffer and tool state
        self._llm_response_buffer = ""
        self._pending_tool_calls = []
        self._tool_results = []
        self._tool_execution_active = False
        self._continuation_complete = False
        self._tool_call_attempts = {}  # Reset tool call attempt tracking
        self._stream_base_html = ""

        # Reset streaming state for new query
        self._reasoning_filter.reset()
        self._streaming_renderer.reset()

        # Set up static chat history for incremental streaming updates
        if self.current_chat_id and self.current_chat_id in self.chats:
            self._active_stream_markdown = ""
            self._refresh_transcript_view("")

        # Create and start the LLM query thread
        native_callback = self._create_native_message_callback()
        self.llm_thread = LLMQueryThread(messages, provider_config, self.llm_factory, mcp_tools, native_callback)
        self.llm_thread.response_chunk.connect(self._on_llm_response_chunk)
        self.llm_thread.response_complete.connect(self._on_llm_response_complete)
        self.llm_thread.response_error.connect(self._on_llm_response_error)
        self.llm_thread.tool_calls_detected.connect(self._on_tool_calls_detected)
        self.llm_thread.stop_reason_received.connect(self._on_stop_reason_received)
        self.llm_thread.start()
    
    def _on_llm_response_chunk(self, chunk: str):
        """Handle streaming response chunk from LLM"""
        self._llm_response_buffer += chunk

        # Feed chunk through reasoning filter (which feeds to streaming renderer)
        self._reasoning_filter.feed(chunk)
    
    def _on_llm_response_complete(self):
        """Handle completion of LLM response"""
        log.log_info(f"LLM response complete called - tool_execution_active: {self._tool_execution_active}")
        log.log_info(f"LLM response buffer: {len(self._llm_response_buffer)} chars")
        log.log_info(f"Response content: '{self._llm_response_buffer[:200]}{'...' if len(self._llm_response_buffer) > 200 else ''}'")

        # Complete streaming and get filtered content
        self._reasoning_filter.complete()
        self._streaming_renderer.on_stream_complete()
        filtered_content = self._streaming_renderer.get_full_markdown()

        # Reset streaming state for next query
        self._reasoning_filter.reset()
        self._streaming_renderer.reset()

        # Only complete if no tool execution is active
        if not self._tool_execution_active:
            # Check if we have content in the response buffer OR if the assistant message was already updated during streaming
            has_content = bool(self._llm_response_buffer)

            # Check if the assistant message already has content from streaming
            if not has_content and self.current_chat_id in self.chats:
                messages = self.chats[self.current_chat_id]["messages"]
                if messages and messages[-1]["role"] == "assistant":
                    existing_content = messages[-1]["content"]
                    if existing_content and existing_content != "*Thinking...*":
                        has_content = True
                        # Use the existing content as our response buffer for RLHF and final update
                        self._llm_response_buffer = existing_content

            # Final update of the assistant message
            if has_content:
                log.log_info("Updating last assistant message with LLM response")
                self._update_last_assistant_message(self._llm_response_buffer, final_update=True)
                # Update RLHF context with final response
                self._update_rlhf_response(self._llm_response_buffer)
            else:
                log.log_debug("No LLM response content - this might be a tool-only response")

            # Rebuild full chat display after streaming completes
            # This ensures chat history + final assistant response are properly rendered
            self._active_stream_markdown = ""
            self._stream_base_html = ""
            self._update_chat_display()

            # Clean up
            self._cleanup_llm_thread()
            self._query_active = False
            self._current_query_binary_hash = None
            self.view.set_query_running(False)
        else:
            log.log_info("Tool execution active - not completing LLM response yet")
    
    def _on_llm_response_error(self, error: str):
        """Handle LLM response error"""
        log.log_error(f"LLM query failed: {error}")

        # Reset streaming state
        self._reasoning_filter.reset()
        self._streaming_renderer.reset()

        # Cancel any pending tool execution
        self._tool_execution_active = False

        error_response = f"**Error**: {error}\n\n*The LLM query failed. Please check your provider configuration and try again.*"
        self._update_last_assistant_message(error_response, final_update=True)
        self._active_stream_markdown = ""
        self._stream_base_html = ""
        self._update_chat_display()

        # Clean up
        self._cleanup_llm_thread()
        self._query_active = False
        self._current_query_binary_hash = None
        self.view.set_query_running(False)
    
    def _on_tool_calls_detected(self, tool_calls: List[ToolCall]):
        """Handle tool calls detected from LLM response or continuation"""
        # Check for loop detection (for all tool calls, not just additional ones)
        if not self._should_allow_tool_execution(tool_calls):
            # Stop execution and complete conversation
            if self.current_chat_id and self._current_query_binary_hash and not self._is_document_chat():
                self.transcript_service.append_iteration_notice(
                    self._current_query_binary_hash,
                    str(self.current_chat_id),
                    "Tool execution stopped to prevent an infinite loop.",
                    metadata={"phase": "loop_guard"},
                )
            else:
                self._add_message_to_chat(self.current_chat_id, "assistant", "**Note:** Tool execution stopped to prevent infinite loop.")
            self._cleanup_continuation_thread()
            self._tool_execution_active = False
            self._query_active = False
            self._current_query_binary_hash = None
            self.view.set_query_running(False)
            self._refresh_transcript_view()
            return
        
        # Determine if this is from continuation thread (additional tools) or initial LLM response
        is_additional_tools = hasattr(self, 'continuation_thread') and self.continuation_thread
        
        # For initial tool calls, check if execution is already active
        if self._tool_execution_active and not is_additional_tools:
            log.log_warn("Tool execution already active, ignoring new tool calls")
            return
        
        # If this is additional tool calls (continuation), clean up the continuation thread
        if is_additional_tools:
            self._cleanup_continuation_thread()
        
        # Store tool calls and mark execution as active
        self._pending_tool_calls = tool_calls

        # Update in-memory message (but don't save to DB - the native_message_callback
        # already saved the assistant message WITH tool_calls during streaming)
        if self._llm_response_buffer and not hasattr(self, '_initial_response_saved'):
            self._update_last_assistant_message(self._llm_response_buffer, final_update=False)
            self._initial_response_saved = True

        self._begin_tool_workflow(tool_calls)
    
    def _create_tool_call_messages(self, tool_calls: List[ToolCall]):
        """Create and add tool call messages to chat for display"""
        return
    
    def _setup_tool_executor(self, tool_calls: List[ToolCall]):
        """Create, configure, and start the tool executor thread"""
        self._tool_execution_active = True
        # Create tool executor thread (no parent since QueryController is not a QObject)
        self.tool_executor_thread = ToolExecutorThread(
            self.mcp_orchestrator,
            tool_calls,
            self._llm_response_buffer
        )
        
        # Connect signals
        self.tool_executor_thread.tool_execution_update.connect(self._on_tool_execution_update)
        self.tool_executor_thread.tool_execution_error.connect(self._handle_tool_execution_error_signal)
        # CRITICAL: tool_results_ready handles ALL results and continues conversation
        self.tool_executor_thread.tool_results_ready.connect(self._on_tool_results_ready)
        
        # Start thread
        self.tool_executor_thread.start()
    
    def _should_allow_tool_execution(self, tool_calls: List[ToolCall]) -> bool:
        """Check if tool execution should proceed (includes loop detection)"""
        # Initialize tool call tracking if needed
        if not hasattr(self, '_tool_call_attempts'):
            self._tool_call_attempts = {}
        
        # Check for potential infinite loops
        for tool_call in tool_calls:
            call_key = f"{tool_call.name}:{hash(str(tool_call.arguments))}"
            current_count = self._tool_call_attempts.get(call_key, 0) + 1
            self._tool_call_attempts[call_key] = current_count
            
            # Log attempt counts for visibility
            if current_count > 1:
                log.log_info(f"Tool call {tool_call.name} attempt #{current_count}")
            
            if current_count > 3:  # Max 3 attempts per unique tool call
                log.log_warn(f"Tool call loop detected for {tool_call.name}, stopping after {current_count-1} attempts")
                return False
        
        return True
    
    def _on_stop_reason_received(self, stop_reason: str):
        """Handle stop reason from LLM response.

        Note: This handler only logs the stop reason. Actual response completion
        is handled by the response_complete signal to avoid double-calls.
        """
        log.log_info(f"Stop reason received: {stop_reason}, tool_execution_active: {self._tool_execution_active}")

        if stop_reason == "end_turn":
            log.log_info("LLM finished with end_turn")
            # response_complete signal will handle completion
        elif stop_reason == "tool_use":
            log.log_info("LLM finished with tool_use - tools will be executed")
            # Tool execution is handled by the tool_calls_detected signal
        else:
            log.log_info(f"LLM finished with {stop_reason}")
            # response_complete signal will handle completion
    
    # Removed _execute_tools_async - tool execution now handled by ToolExecutorThread
    
    def _on_tool_execution_update(self, response_content: str):
        """Handle tool execution update - just refresh the display"""
        self._update_chat_display()
    
    # Removed _update_continuation_response_ui - handled by continuation thread signals
    
    def _handle_tool_execution_error(self, response_content: str):
        """Handle tool execution error (runs on main thread)"""
        try:
            if self.current_chat_id and self._current_query_binary_hash and not self._is_document_chat():
                self.transcript_service.append_iteration_notice(
                    self._current_query_binary_hash,
                    str(self.current_chat_id),
                    response_content,
                    metadata={"phase": "tool_error"},
                )
                self._refresh_transcript_view(self._active_stream_markdown or None)
            else:
                self._add_message_to_chat(self.current_chat_id, "error", response_content)
                self._update_chat_display()
            
            # Complete the response on error
            self._tool_execution_active = False
            self._query_active = False
            self._current_query_binary_hash = None
            self.view.set_query_running(False)
        except Exception as e:
            log.log_error(f"Error handling tool execution error: {e}")
    
    # Removed _complete_tool_conversation - handled by continuation thread signals
    
    # Removed _complete_tool_conversation_with_final_ui_update - handled by continuation thread signals
    
    def _handle_tool_execution_error_signal(self, error_msg: str):
        """Handle tool execution error from signal"""
        self._handle_tool_execution_error(f"**Tool Execution Error:** {error_msg}")
    
    def _on_tool_results_ready(self, results: List[ToolResult]):
        """Handle tool results ready signal - ALWAYS continue conversation"""
        self._tool_results = results
        result_map = {result.tool_call_id: result for result in results}
        result_map.update(self._synthetic_tool_results)
        ordered_results: List[ToolResult] = []
        binary_hash = self._current_query_binary_hash or self._get_current_binary_hash()
        for tool_call in self._pending_tool_calls:
            result = result_map.get(tool_call.id)
            if not result:
                result = ToolResult(
                    tool_call_id=tool_call.id,
                    content="",
                    error="No tool result returned.",
                )
            ordered_results.append(result)
            if binary_hash and self.current_chat_id:
                self.transcript_service.append_tool_completed(
                    binary_hash,
                    str(self.current_chat_id),
                    self._tool_correlation_ids.get(tool_call.id, tool_call.id),
                    tool_call.name,
                    self._resolve_tool_source(tool_call.name),
                    result.error or result.content or "",
                    success=not bool(result.error),
                )
        self._tool_results = ordered_results
        self._refresh_transcript_view(self._active_stream_markdown or None)
        
        # ALWAYS continue LLM conversation with results (success or failure)
        try:
            
            # Prepare conversation messages for continuation
            messages = self._prepare_continuation_messages(self._pending_tool_calls, ordered_results)
            
            # Get active provider and MCP tools
            active_provider = self.settings_service.get_active_llm_provider()
            if not active_provider:
                self._handle_tool_execution_error("**Error:** No active LLM provider")
                return
            
            mcp_tools = []
            if self.view.is_mcp_enabled():
                mcp_tools = self.mcp_connection_manager.get_available_tools_for_llm()
            
            # Create and start continuation thread
            native_callback = self._create_native_message_callback()
            self.continuation_thread = LLMContinuationThread(
                self.llm_factory,
                active_provider,
                messages,
                mcp_tools,
                native_callback
            )

            # Connect signals
            self.continuation_thread.continuation_chunk.connect(self._on_continuation_chunk)
            self.continuation_thread.continuation_complete.connect(self._on_continuation_complete)
            self.continuation_thread.continuation_error.connect(self._on_continuation_error)
            self.continuation_thread.additional_tools_detected.connect(self._on_tool_calls_detected)

            # CRITICAL: Reset the LLM response buffer for this NEW continuation
            # Each continuation should start fresh, not accumulate previous responses
            self._llm_response_buffer = ""

            # Reset streaming state for this new continuation
            self._reasoning_filter.reset()
            self._streaming_renderer.reset()

            # Start thread
            self.continuation_thread.start()
            
        except Exception as e:
            log.log_error(f"Error starting continuation thread: {e}")
            self._handle_tool_execution_error(f"**Error:** {str(e)}")
    
    def _prepare_continuation_messages(self, tool_calls: List[ToolCall], results: List[ToolResult]) -> List[Dict[str, Any]]:
        """Prepare messages for LLM continuation after tool execution"""
        import json
        try:
            # Get active provider to format tool results properly
            active_provider = self.settings_service.get_active_llm_provider()
            if not active_provider:
                return []
            
            provider = self.llm_factory.create_provider(active_provider)
            
            # Format tool results for the specific provider
            tool_messages = provider.format_tool_results_for_continuation(tool_calls, [r.content for r in results])
            
            # Save tool result messages to native storage
            try:
                binary_hash = self._get_current_binary_hash()
                if binary_hash and self.current_chat_id and tool_messages:
                    provider_type = active_provider.get('provider_type', 'anthropic_platform')
                    for tool_msg in tool_messages:
                        self.analysis_db.save_native_message(
                            binary_hash, str(self.current_chat_id), tool_msg, provider_type
                        )
                    log.log_debug(f"Saved {len(tool_messages)} tool result messages to native storage")
            except Exception as e:
                log.log_error(f"Failed to save tool result messages to native storage: {e}")
            
            # Prepare conversation history up to this point
            conversation_messages = []
            
            # Add system message
            context = self.context_service.get_current_context()
            system_content = self._build_system_message(context, self.view.is_rag_enabled(), self.view.is_mcp_enabled())
            conversation_messages.append({"role": "system", "content": system_content})
            
            # Add chat history from native storage
            try:
                binary_hash = self._get_current_binary_hash()
                if binary_hash and self.current_chat_id:
                    provider_type = active_provider.get('provider_type', 'anthropic_platform')
                    native_messages = self.analysis_db.get_native_messages_for_provider(
                        binary_hash, str(self.current_chat_id), provider_type
                    )

                    # Add native messages directly (they're already in provider format)
                    conversation_messages.extend(native_messages)
            except Exception as e:
                log.log_warn(f"Failed to load native messages for continuation: {e}")
                # Fallback to in-memory messages if native storage fails
                if self.current_chat_id in self.chats:
                    chat_messages = self.chats[self.current_chat_id]["messages"]
                    for msg in chat_messages[:-1]:  # Exclude current placeholder response
                        if msg["role"] in ["user", "assistant"]:
                            conversation_messages.append({
                                "role": msg["role"], 
                                "content": msg["content"]
                            })
            
            # NOTE: Assistant message with tool calls and tool results are now loaded from native storage above
            # No need to manually add them again - that would cause duplicates

            # Validate: ensure tool results have a preceding assistant message with tool_calls.
            # If the native_message_callback didn't fire (e.g. non-streaming fallback for
            # thinking+tools models), the assistant message may be missing from storage.
            has_assistant_with_tools = any(
                msg.get("role") == "assistant" and (
                    msg.get("tool_calls") or
                    (isinstance(msg.get("content"), list) and
                     any(isinstance(b, dict) and b.get("type") == "tool_use" for b in msg["content"]))
                )
                for msg in conversation_messages
            )
            has_tool_results = any(
                msg.get("role") == "tool" or
                (msg.get("role") == "user" and isinstance(msg.get("content"), list) and
                 any(isinstance(b, dict) and b.get("type") == "tool_result" for b in msg["content"]))
                for msg in conversation_messages
            )

            if has_tool_results and not has_assistant_with_tools and tool_calls:
                log.log_warn(
                    "Native storage missing assistant message with tool_calls. "
                    "Reconstructing to prevent API error."
                )
                assistant_tool_calls = []
                for tc in tool_calls:
                    args = tc.arguments if isinstance(tc.arguments, str) else json.dumps(tc.arguments)
                    assistant_tool_calls.append({
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.name, "arguments": args}
                    })
                # Insert before the first tool result message
                insert_idx = next(
                    (i for i, msg in enumerate(conversation_messages)
                     if msg.get("role") == "tool" or
                     (msg.get("role") == "user" and isinstance(msg.get("content"), list) and
                      any(isinstance(b, dict) and b.get("type") == "tool_result" for b in msg["content"]))),
                    len(conversation_messages)
                )
                conversation_messages.insert(insert_idx, {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": assistant_tool_calls
                })

            return conversation_messages
            
        except Exception as e:
            log.log_error(f"Error preparing continuation messages: {e}")
            return []
    
    def _on_continuation_chunk(self, chunk: str):
        """Handle streaming continuation chunk"""
        # Add the chunk directly to the main LLM response buffer (just like initial streaming)
        self._llm_response_buffer += chunk

        # Feed chunk through reasoning filter (which feeds to streaming renderer)
        self._reasoning_filter.feed(chunk)
    
    def _update_or_create_continuation_message(self, content: str):
        """Update existing assistant message or create new one for continuation"""
        if self.current_chat_id not in self.chats:
            return
        
        messages = self.chats[self.current_chat_id]["messages"]
        
        # Check if last message is assistant message we can update
        if messages and messages[-1]["role"] == "assistant":
            # Update existing assistant message
            messages[-1]["content"] = content
            messages[-1]["timestamp"] = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            self.chats[self.current_chat_id]["updated"] = messages[-1]["timestamp"]
        else:
            # Create new assistant message for continuation
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            new_message = {
                "role": "assistant",
                "content": content,
                "timestamp": timestamp
            }
            messages.append(new_message)
            self.chats[self.current_chat_id]["updated"] = timestamp
    
    def _on_continuation_complete(self, final_response: str):
        """Handle continuation completion - this means the LLM is truly done (no more tool calls)"""
        try:
            # Complete streaming and get filtered content
            self._reasoning_filter.complete()
            self._streaming_renderer.on_stream_complete()
            filtered_content = self._streaming_renderer.get_full_markdown()

            # Reset streaming state
            self._reasoning_filter.reset()
            self._streaming_renderer.reset()

            # Use final_response if buffer is empty (non-streaming fallback case)
            response_content = self._llm_response_buffer or final_response
            log.log_info(f"Continuation complete - buffer: {len(self._llm_response_buffer)} chars, final_response: {len(final_response)} chars")

            # Update or add assistant message with the final response
            if response_content:
                # Check if last message is already an assistant message we can update
                can_update = False
                if self.current_chat_id in self.chats:
                    messages = self.chats[self.current_chat_id]["messages"]
                    if messages and messages[-1]["role"] == "assistant":
                        can_update = True

                if can_update:
                    self._update_last_assistant_message(response_content, final_update=True)
                else:
                    # After tool execution, last message is tool_status - add new assistant message
                    log.log_info("Adding new assistant message after tool execution")
                    self._add_message_to_chat(self.current_chat_id, "assistant", response_content, save_to_db=True)

                self._update_rlhf_response(response_content)

            # Final display with full markdown rendering (not plain text)
            self._active_stream_markdown = ""
            self._stream_base_html = ""
            self._update_chat_display()

            # Clean up and end the query
            self._cleanup_continuation_thread()
            self._tool_execution_active = False
            self._query_active = False
            self._current_query_binary_hash = None
            self.view.set_query_running(False)

        except Exception as e:
            log.log_error(f"Error handling continuation completion: {e}")
    
    def _on_continuation_error(self, error: str):
        """Handle continuation error"""
        log.log_error(f"Continuation error: {error}")
        self._handle_tool_execution_error(f"**Continuation Error:** {error}")
    
    def _cleanup_continuation_thread(self):
        """Safely cleanup the continuation thread"""
        if hasattr(self, 'continuation_thread') and self.continuation_thread:
            if self.continuation_thread.isRunning():
                self.continuation_thread.quit()
                self.continuation_thread.wait(5000)  # Wait up to 5 seconds
            self.continuation_thread.deleteLater()
            self.continuation_thread = None
    
    # Removed _continue_llm_with_tool_results - using LLMContinuationThread instead
    
    def _cleanup_llm_thread(self):
        """Safely cleanup the LLM thread"""
        if hasattr(self, 'llm_thread') and self.llm_thread:
            if self.llm_thread.isRunning():
                self.llm_thread.quit()
                self.llm_thread.wait(5000)  # Wait up to 5 seconds
            self.llm_thread.deleteLater()
            self.llm_thread = None
        
        # Cleanup tool executor thread if exists
        if hasattr(self, 'tool_executor_thread') and self.tool_executor_thread:
            if self.tool_executor_thread.isRunning():
                self.tool_executor_thread.quit()
                self.tool_executor_thread.wait(5000)  # Wait up to 5 seconds
            self.tool_executor_thread.deleteLater()
            self.tool_executor_thread = None
        
        # Cleanup continuation thread if exists
        self._cleanup_continuation_thread()
        
        # Clear response buffer
        self._llm_response_buffer = ""
    
    def _update_last_assistant_message(self, content: str, final_update: bool = False):
        """Update the last assistant message in the current chat"""
        if self.current_chat_id not in self.chats:
            return
        
        messages = self.chats[self.current_chat_id]["messages"]
        if messages and messages[-1]["role"] == "assistant":
            old_length = len(messages[-1]["content"])
            messages[-1]["content"] = content
            messages[-1]["timestamp"] = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            self.chats[self.current_chat_id]["updated"] = messages[-1]["timestamp"]
            
            # Save to native format on final update
            if final_update:
                try:
                    self._active_stream_markdown = ""
                    self._stream_base_html = ""
                    # Get active provider type for native saving
                    active_provider = self.settings_service.get_active_llm_provider()
                    if active_provider:
                        provider_type = active_provider.get('provider_type', 'anthropic_platform')
                        self._save_assistant_response_native(content, provider_type=provider_type)
                    
                    # Also save to legacy format for backward compatibility
                    binary_hash = self._current_query_binary_hash
                    if binary_hash:
                        message_order = len(messages) - 1
                        self.analysis_db.save_chat_message(
                            binary_hash, str(self.current_chat_id), "assistant", content,
                            metadata={"message_order": message_order}
                        )
                    else:
                        log.log_warn("No binary hash available for persisting assistant message")
                    if binary_hash and not self._is_document_chat():
                        self.transcript_service.append_assistant_message(
                            binary_hash,
                            str(self.current_chat_id),
                            content,
                            metadata={"provider_type": provider_type if active_provider else None},
                        )
                except Exception as e:
                    log.log_error(f"Failed to persist updated assistant message: {e}")
        else:
            log.log_debug(f"_update_last_assistant_message: Last message is not assistant (messages={len(messages)}, last_role={messages[-1]['role'] if messages else 'none'})")
    
    # Database helper methods
    
    def _get_current_binary_hash(self) -> Optional[str]:
        """
        Get current binary hash from cached value.

        The hash is calculated ONCE in initialize_binary() and cached
        in the context service. This avoids recalculating the hash
        on every UI update.

        Returns:
            Cached binary hash, or None if not available
        """
        return self.context_service.get_binary_hash()
    
    # RLHF methods
    
    def _track_rlhf_context(self, model_name: str, prompt: str, messages: List[Dict[str, Any]]):
        """Track current query context for RLHF feedback"""
        # Extract system message if present
        system_message = ""
        for msg in messages:
            if msg.get('role') == 'system':
                system_message = msg.get('content', '')
                break
        
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
            #log.log_info(f"Current RLHF context: {self._current_rlhf_context}")
            
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

    # =========================================================================
    # ReAct (Agentic Mode) Methods
    # =========================================================================

    def _submit_agentic_query(self, query_text: str):
        """Handle agentic (ReAct) query submission"""
        log.log_info(f"Agentic query submitted: {query_text[:50]}...")

        # Check if query is already active
        if self._query_active or self._react_active:
            log.log_warn("Query already active, ignoring agentic request")
            return

        try:
            # Get active LLM provider
            active_provider = self.settings_service.get_active_llm_provider()
            if not active_provider:
                self._handle_no_llm_provider(query_text)
                return

            # Ensure we have an active chat
            if self.current_chat_id is None:
                self.new_chat()

            # Set active state
            self._react_active = True
            self._current_query_binary_hash = self._get_current_binary_hash()
            self.view.set_query_running(True)
            self._active_stream_markdown = ""
            self._stream_base_html = ""
            self._context_snapshot = self._build_context_snapshot()
            self._refresh_status_strip()

            # Reset auto-scroll to follow new response by default
            self.view.enable_auto_scroll()

            # Add user query to chat (both legacy and native formats)
            self._add_message_to_chat(self.current_chat_id, "user", query_text)

            # Save user query in native format for the active provider
            provider_type = active_provider.get('provider_type', 'anthropic_platform')
            self._save_user_message_native(query_text, provider_type)
            if self._current_query_binary_hash:
                self.transcript_service.append_user_message(
                    self._current_query_binary_hash,
                    str(self.current_chat_id),
                    query_text,
                )
                self.transcript_service.append_iteration_notice(
                    self._current_query_binary_hash,
                    str(self.current_chat_id),
                    f"Planning investigation steps for: {query_text}",
                    metadata={"phase": "planning"},
                )

            # Update display to show the initial user query and planning notice cards.
            self._refresh_transcript_view("")
            log.log_debug(f"Agentic query: Added user message and transcript planning notice to chat {self.current_chat_id}")

            # Get context and MCP tools
            context = self.context_service.get_current_context()
            initial_context = self._format_initial_context_for_react(context)

            # MCP tools are required for agentic mode
            self.mcp_connection_manager.ensure_connections()
            mcp_tools = self.mcp_connection_manager.get_available_tools_for_llm()
            log.log_info(f"Agentic mode with {len(mcp_tools)} tools available")

            # Create provider instance
            provider = self.llm_factory.create_provider(active_provider)

            # Create ReAct config
            config = ReActConfig(
                max_iterations=15,
                reflection_enabled=True
            )

            # Start ReAct thread
            self._start_react_analysis(query_text, initial_context, provider, mcp_tools, config)

        except Exception as e:
            error_msg = f"Exception in submit_agentic_query: {str(e)}"
            log.log_error(error_msg)
            self._handle_react_error(str(e))

    def _format_initial_context_for_react(self, context: Dict[str, Any]) -> str:
        """Format initial binary context for ReAct agent"""
        binary_info = context.get('binary_info', {})
        func_ctx = context.get('function_context')

        ctx_str = f"""Binary: {binary_info.get('filename', 'Unknown')}
Architecture: {binary_info.get('architecture', 'Unknown')}
Current Offset: {context.get('offset_hex', 'N/A')}"""

        if func_ctx:
            ctx_str += f"\nCurrent Function: {func_ctx['name']} ({func_ctx['start']} - {func_ctx['end']})"

        return ctx_str

    def _start_react_analysis(self, objective: str, initial_context: str,
                              provider, mcp_tools: List[Dict[str, Any]],
                              config: ReActConfig):
        """Start the ReAct analysis thread"""
        log.log_info("Starting ReAct analysis thread")

        # Reset streaming state for ReAct analysis
        self._reasoning_filter.reset()
        self._streaming_renderer.reset()
        self._llm_response_buffer = ""
        self._react_streaming_final_answer = False

        # Set up static chat history for incremental streaming updates
        if self.current_chat_id and self.current_chat_id in self.chats:
            self._active_stream_markdown = ""
            self._refresh_transcript_view("")

        # Create and configure thread
        self._react_thread = ReActOrchestratorThread(
            objective=objective,
            initial_context=initial_context,
            llm_provider=provider,
            mcp_orchestrator=self.mcp_orchestrator,
            mcp_tools=mcp_tools,
            config=config
        )

        # Connect signals
        self._react_thread.planning_complete.connect(self._on_react_planning_complete)
        self._react_thread.todos_updated.connect(self._on_react_todos_updated)
        self._react_thread.iteration_started.connect(self._on_react_iteration_started)
        self._react_thread.iteration_complete.connect(self._on_react_iteration_complete)
        self._react_thread.finding_discovered.connect(self._on_react_finding)
        self._react_thread.progress_update.connect(self._on_react_progress)
        self._react_thread.content_chunk.connect(self._on_react_content_chunk)
        self._react_thread.tool_event.connect(self._on_react_tool_event)
        self._react_thread.analysis_complete.connect(self._on_react_complete)
        self._react_thread.analysis_error.connect(self._on_react_error)

        # Start thread
        self._react_thread.start()
        log.log_info("ReAct analysis thread started")

    def _on_react_planning_complete(self, todos_formatted: str):
        """Handle planning phase completion"""
        log.log_debug(f"ReAct planning complete: {todos_formatted[:100]}...")
        self._last_todo_snapshot = todos_formatted
        self._last_react_tasks = self._parse_react_tasks(todos_formatted)
        if self.current_chat_id and self._current_query_binary_hash:
            self.transcript_service.append_todo_snapshot(
                self._current_query_binary_hash,
                str(self.current_chat_id),
                self._todo_summary(self._last_react_tasks),
                self._last_react_tasks,
            )

    def _on_react_todos_updated(self, todos_formatted: str):
        """Handle todo list updates"""
        log.log_debug(f"ReAct todos updated")
        self._last_todo_snapshot = todos_formatted
        self._last_react_tasks = self._parse_react_tasks(todos_formatted)
        if self.current_chat_id and self._current_query_binary_hash:
            self.transcript_service.append_todo_snapshot(
                self._current_query_binary_hash,
                str(self.current_chat_id),
                self._todo_summary(self._last_react_tasks),
                self._last_react_tasks,
            )

    def _on_react_iteration_started(self, iteration: int, current_todo: str):
        """Handle iteration start"""
        log.log_debug(f"ReAct iteration {iteration} started: {current_todo[:50]}...")
        if self.current_chat_id and self._current_query_binary_hash:
            self.transcript_service.append_iteration_notice(
                self._current_query_binary_hash,
                str(self.current_chat_id),
                current_todo,
                metadata={"iteration": iteration, "phase": "start"},
            )

    def _on_react_iteration_complete(self, iteration: int, summary: str):
        """Handle iteration completion"""
        log.log_debug(f"ReAct iteration {iteration} complete")
        if self.current_chat_id and self._current_query_binary_hash:
            self.transcript_service.append_iteration_notice(
                self._current_query_binary_hash,
                str(self.current_chat_id),
                summary or f"Iteration {iteration} complete",
                metadata={"iteration": iteration, "phase": "complete"},
            )

    def _on_react_finding(self, finding: str):
        """Handle new finding discovered"""
        log.log_debug(f"ReAct finding: {finding[:50]}...")
        if self.current_chat_id and self._current_query_binary_hash:
            self.transcript_service.append_finding(
                self._current_query_binary_hash,
                str(self.current_chat_id),
                finding,
            )

    def _on_react_progress(self, message: str, iteration: int):
        """Handle progress update"""
        log.log_debug(f"ReAct progress: {message} (iteration {iteration})")
        if "Synthesizing final answer" in message and not self._react_streaming_final_answer:
            self._llm_response_buffer = ""
            self._active_stream_markdown = ""
            self._stream_base_html = ""
            self._reasoning_filter.reset()
            self._streaming_renderer.reset()
            self._react_streaming_final_answer = True
            self._ensure_react_assistant_placeholder()
            self._refresh_transcript_view("")

    def _on_react_content_chunk(self, chunk: str):
        """Handle streaming content chunk from ReAct"""
        if not chunk or not self._react_streaming_final_answer:
            return

        self._llm_response_buffer += chunk

        # Feed chunk through reasoning filter (which feeds to streaming renderer)
        self._reasoning_filter.feed(chunk)

    def _on_react_tool_event(self, event: dict):
        if not self.current_chat_id or not self._current_query_binary_hash:
            return
        correlation_id = event.get("tool_call_id") or event.get("correlation_id") or event.get("tool_name", "tool")
        tool_name = event.get("tool_name", "tool")
        tool_source = self._resolve_tool_source(tool_name)
        phase = event.get("phase")
        if phase == "requested":
            self.transcript_service.append_tool_requested(
                self._current_query_binary_hash,
                str(self.current_chat_id),
                correlation_id,
                tool_name,
                tool_source,
                event.get("arguments") or {},
            )
        elif phase == "started":
            self.transcript_service.append_tool_started(
                self._current_query_binary_hash,
                str(self.current_chat_id),
                correlation_id,
                tool_name,
                tool_source,
            )
        elif phase in ("completed", "failed"):
            self.transcript_service.append_tool_completed(
                self._current_query_binary_hash,
                str(self.current_chat_id),
                correlation_id,
                tool_name,
                tool_source,
                event.get("content") or event.get("error") or "",
                success=phase == "completed",
            )

    def _on_react_complete(self, result: ReActResult):
        """Handle ReAct analysis completion"""
        log.log_info(f"ReAct complete: {result.status.value}, {result.iteration_count} iterations, {result.tool_call_count} tool calls")

        # Complete streaming and reset state
        self._reasoning_filter.complete()
        self._streaming_renderer.on_stream_complete()
        self._reasoning_filter.reset()
        self._streaming_renderer.reset()

        # Format final response with statistics
        status_emoji = "✅" if result.status == ReActStatus.SUCCESS else "⚠️"
        final_content = result.answer or self._llm_response_buffer

        # Persist the final synthesis as its own assistant turn.
        self._finalize_react_assistant_message(final_content)
        self._active_stream_markdown = ""
        self._stream_base_html = ""
        self._react_streaming_final_answer = False
        self._update_chat_display()

        # Cleanup
        self._cleanup_react_thread()
        self._react_active = False
        self._current_query_binary_hash = None
        self.view.set_query_running(False)

    def _on_react_error(self, error: str):
        """Handle ReAct analysis error"""
        self._handle_react_error(error)

    def _handle_react_error(self, error: str):
        """Handle ReAct error"""
        log.log_error(f"ReAct error: {error}")

        # Reset streaming state
        self._reasoning_filter.reset()
        self._streaming_renderer.reset()

        error_response = f"**Agentic Investigation Error:** {error}"
        self._finalize_react_assistant_message(error_response)
        self._active_stream_markdown = ""
        self._stream_base_html = ""
        self._react_streaming_final_answer = False
        self._update_chat_display()

        # Cleanup
        self._cleanup_react_thread()
        self._react_active = False
        self._current_query_binary_hash = None
        self.view.set_query_running(False)

    def _cleanup_react_thread(self):
        """Safely cleanup the ReAct thread"""
        if hasattr(self, '_react_thread') and self._react_thread:
            try:
                if self._react_thread.isRunning():
                    # Request cancellation and wait for thread to finish
                    self._react_thread.cancel()
                    self._react_thread.wait(3000)  # Wait up to 3 seconds
                # Just set to None, let Qt handle cleanup
                self._react_thread = None
            except Exception as e:
                log.log_error(f"Error during ReAct thread cleanup: {e}")
                self._react_thread = None
        log.log_debug("ReAct thread cleaned up")

    def _ensure_react_assistant_placeholder(self):
        if not self.current_chat_id or self.current_chat_id not in self.chats:
            return
        messages = self.chats[self.current_chat_id]["messages"]
        if not messages or messages[-1]["role"] != "assistant":
            self._add_message_to_chat(self.current_chat_id, "assistant", "", save_to_db=False)

    def _finalize_react_assistant_message(self, content: str):
        if not self.current_chat_id or self.current_chat_id not in self.chats:
            return
        self._ensure_react_assistant_placeholder()
        self._update_last_assistant_message(content, final_update=True)
