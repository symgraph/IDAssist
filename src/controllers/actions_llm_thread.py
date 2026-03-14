#!/usr/bin/env python3

"""
Actions LLM Thread

Background thread for Actions tab LLM queries with tool call support.
Follows the same patterns as ExplainLLMThread but specialized for Actions tools.
"""

import asyncio
from typing import List, Dict, Any
from ..qt_compat import QThread, Signal
from ..services.models.llm_models import ToolCall, ChatRequest, ChatMessage, MessageRole

from src.ida_compat import log


class ActionsLLMThread(QThread):
    """Thread for Actions LLM queries with action tool support"""

    # Signals for communication with controller
    response_chunk = Signal(str)
    response_complete = Signal()
    response_error = Signal(str)
    tool_calls_detected = Signal(list)  # List[ToolCall]
    stop_reason_received = Signal(str)  # "stop", "tool_calls", etc.

    def __init__(self, messages: List[Dict[str, Any]], provider_config: dict, llm_factory, action_tools: List[Dict[str, Any]] = None):
        super().__init__()
        self.messages = messages
        self.provider_config = provider_config
        self.llm_factory = llm_factory
        self.action_tools = action_tools or []
        self.cancelled = False

        log.log_info(f"ActionsLLMThread initialized with {len(self.action_tools)} action tools")

    def cancel(self):
        """Cancel the running query"""
        self.cancelled = True
        log.log_info("ActionsLLMThread cancellation requested")

    def run(self):
        """Execute LLM query in background thread"""
        try:
            log.log_info("ActionsLLMThread starting async query")
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self._async_query())
            finally:
                loop.close()
        except Exception as e:
            if not self.cancelled:  # Don't emit error if cancelled
                log.log_error(f"ActionsLLMThread error: {e}")
                self.response_error.emit(str(e))

    async def _async_query(self):
        """Execute async LLM query with action tool call detection"""
        try:
            # Check for cancellation before starting
            if self.cancelled:
                return

            # Create provider instance
            provider = self.llm_factory.create_provider(self.provider_config)
            log.log_info(f"Created LLM provider: {self.provider_config.get('name', 'Unknown')}")

            # Check for cancellation after provider creation
            if self.cancelled:
                return

            # Convert messages to ChatMessage format
            chat_messages = []
            for msg in self.messages:
                if msg["role"] == "system":
                    chat_messages.append(ChatMessage(role=MessageRole.SYSTEM, content=msg["content"]))
                elif msg["role"] == "user":
                    chat_messages.append(ChatMessage(role=MessageRole.USER, content=msg["content"]))
                elif msg["role"] == "assistant":
                    chat_messages.append(ChatMessage(role=MessageRole.ASSISTANT, content=msg["content"]))

            # Create chat request with action tools
            request = ChatRequest(
                messages=chat_messages,
                model=self.provider_config.get('model', ''),
                tools=self.action_tools if self.action_tools else None,
                stream=True,  # Enable streaming for better UX
                temperature=0.1,  # Lower temperature for more consistent action suggestions
                max_tokens=self.provider_config.get('max_tokens', 4096)
            )

            log.log_info(f"Sending chat request with {len(self.action_tools)} tools, streaming=True")

            # Execute streaming chat request
            full_response = ""
            detected_tool_calls = []

            # Store the async generator to properly close it if cancelled
            stream = provider.chat_completion_stream(request)
            try:
                async for chunk in stream:
                    # Check for cancellation during streaming
                    if self.cancelled:
                        log.log_info("ActionsLLMThread cancelled during streaming")
                        return

                    # Handle different chunk types
                    if hasattr(chunk, 'content') and chunk.content:
                        full_response += chunk.content
                        self.response_chunk.emit(chunk.content)

                    # Check for tool calls in the chunk
                    if hasattr(chunk, 'tool_calls') and chunk.tool_calls:
                        log.log_info(f"Detected {len(chunk.tool_calls)} tool calls in chunk")
                        detected_tool_calls.extend(chunk.tool_calls)

                    # Check for stop reason
                    if hasattr(chunk, 'stop_reason') and chunk.stop_reason:
                        log.log_info(f"Stop reason received: {chunk.stop_reason}")
                        self.stop_reason_received.emit(chunk.stop_reason)

                        # If stop reason is tool_calls, emit the detected tool calls
                        if chunk.stop_reason == "tool_calls" and detected_tool_calls:
                            log.log_info(f"Emitting {len(detected_tool_calls)} detected tool calls")
                            self.tool_calls_detected.emit(detected_tool_calls)
                            return  # Don't emit response_complete for tool calls

                # Check if we accumulated tool calls without explicit stop_reason
                if detected_tool_calls:
                    log.log_info(f"Emitting {len(detected_tool_calls)} accumulated tool calls")
                    self.tool_calls_detected.emit(detected_tool_calls)
                    return  # Don't emit response_complete for tool calls

                # If we got here, the response completed without tool calls
                if not self.cancelled:
                    log.log_info("ActionsLLMThread completed normally")
                    self.response_complete.emit()

            finally:
                # Always properly close the async stream
                try:
                    if hasattr(stream, 'aclose'):
                        await stream.aclose()
                except Exception as close_error:
                    log.log_debug(f"Error closing stream: {close_error}")

        except Exception as e:
            if not self.cancelled:
                log.log_error(f"Error in ActionsLLMThread async query: {e}")
                self.response_error.emit(f"LLM query failed: {str(e)}")


class ActionsToolExecutorThread(QThread):
    """Thread for executing action tool calls"""

    tool_execution_complete = Signal(list, list)  # tool_calls, results
    tool_execution_error = Signal(str)

    def __init__(self, tool_registry, tool_calls: List[ToolCall], parent=None):
        super().__init__(parent)
        self.tool_registry = tool_registry
        self.tool_calls = tool_calls
        self.tool_results = []

        log.log_info(f"ActionsToolExecutorThread initialized with {len(tool_calls)} tool calls")

    def run(self):
        """Execute action tool calls"""
        try:
            log.log_info("ActionsToolExecutorThread starting tool execution")

            # Execute each tool call
            for tool_call in self.tool_calls:
                log.log_info(f"Executing action tool: {tool_call.name}")

                # Execute the tool through our registry
                result = self.tool_registry.execute_tool(tool_call)
                self.tool_results.append(result)

                if result.success:
                    log.log_info(f"Tool {tool_call.name} executed successfully")
                else:
                    log.log_warn(f"Tool {tool_call.name} failed: {result.error}")

            log.log_info(f"ActionsToolExecutorThread completed: {len(self.tool_results)} results")
            self.tool_execution_complete.emit(self.tool_calls, self.tool_results)

        except Exception as e:
            log.log_error(f"ActionsToolExecutorThread error: {e}")
            self.tool_execution_error.emit(str(e))
