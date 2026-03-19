#!/usr/bin/env python3

"""
Message Format Service - SOA component for provider-native message format handling
Handles serialization, deserialization, and translation between provider formats
"""

import json
from typing import Dict, Any, List, Optional, Tuple
from abc import ABC, abstractmethod

from .models.llm_models import ChatMessage, MessageRole, ToolCall, ToolResult
from .models.provider_types import ProviderType

from src.ida_compat import log


class MessageFormatAdapter(ABC):
    """Abstract base class for provider-specific message format adapters"""

    @abstractmethod
    def to_native_format(self, message: ChatMessage) -> Dict[str, Any]:
        """Convert ChatMessage to provider's native format"""
        pass

    @abstractmethod
    def from_native_format(self, native_message: Dict[str, Any]) -> ChatMessage:
        """Convert provider's native format to ChatMessage"""
        pass

    @abstractmethod
    def extract_display_info(self, native_message: Dict[str, Any]) -> Tuple[str, str, str]:
        """Extract (role, content_text, message_type) for UI display"""
        pass

    @abstractmethod
    def get_provider_type(self) -> ProviderType:
        """Get the provider type this adapter handles"""
        pass


class AnthropicMessageAdapter(MessageFormatAdapter):
    """Message format adapter for Anthropic Claude API"""

    def to_native_format(self, message: ChatMessage) -> Dict[str, Any]:
        """Convert ChatMessage to Anthropic's native format"""
        native_msg = {
            "role": message.role.value
        }

        # Handle content based on message type
        if message.role == MessageRole.ASSISTANT and message.tool_calls:
            # Assistant message with tool calls - use content array format
            content = []

            # Add text content if present
            if message.content:
                content.append({
                    "type": "text",
                    "text": message.content
                })

            # Add tool use blocks
            for tool_call in message.tool_calls:
                content.append({
                    "type": "tool_use",
                    "id": tool_call.id,
                    "name": tool_call.name,
                    "input": tool_call.arguments
                })

            native_msg["content"] = content

        elif message.role == MessageRole.TOOL:
            # Tool result message
            native_msg["content"] = [
                {
                    "type": "tool_result",
                    "tool_use_id": message.tool_call_id,
                    "content": message.content
                }
            ]

        else:
            # Simple text message (user, system, or assistant without tools)
            native_msg["content"] = message.content

        return native_msg

    def from_native_format(self, native_message: Dict[str, Any]) -> ChatMessage:
        """Convert Anthropic's native format to ChatMessage"""
        role = MessageRole(native_message["role"])
        content = ""
        tool_calls = []
        tool_call_id = None

        msg_content = native_message.get("content", "")

        if isinstance(msg_content, list):
            # Handle content array format
            for block in msg_content:
                block_type = block.get("type", "")

                if block_type == "text":
                    content += block.get("text", "")

                elif block_type == "tool_use":
                    tool_call = ToolCall(
                        id=block.get("id", ""),
                        name=block.get("name", ""),
                        arguments=block.get("input", {})
                    )
                    tool_calls.append(tool_call)

                elif block_type == "tool_result":
                    content = block.get("content", "")
                    tool_call_id = block.get("tool_use_id")

        else:
            # Simple string content
            content = str(msg_content)

        return ChatMessage(
            role=role,
            content=content,
            tool_calls=tool_calls if tool_calls else None,
            tool_call_id=tool_call_id
        )

    def extract_display_info(self, native_message: Dict[str, Any]) -> Tuple[str, str, str]:
        """Extract display info from Anthropic native format"""
        role = native_message.get("role", "unknown")
        content_text = ""
        message_type = "standard"

        msg_content = native_message.get("content", "")

        if isinstance(msg_content, list):
            # Handle content array
            has_tool_use = False
            has_tool_result = False

            for block in msg_content:
                block_type = block.get("type", "")

                if block_type == "text":
                    content_text += block.get("text", "")
                elif block_type == "tool_use":
                    has_tool_use = True
                    tool_name = block.get("name", "unknown")
                    content_text += f"[Tool: {tool_name}] "
                elif block_type == "tool_result":
                    has_tool_result = True
                    content_text = block.get("content", "")

            if has_tool_use:
                message_type = "tool_call"
            elif has_tool_result:
                message_type = "tool_response"

        else:
            content_text = str(msg_content)

        return role, content_text, message_type

    def get_provider_type(self) -> ProviderType:
        return ProviderType.ANTHROPIC_PLATFORM


class OpenAIMessageAdapter(MessageFormatAdapter):
    """Message format adapter for OpenAI API"""

    def to_native_format(self, message: ChatMessage) -> Dict[str, Any]:
        """Convert ChatMessage to OpenAI's native format"""
        native_msg = {
            "role": message.role.value,
            "content": message.content
        }

        # Add tool calls if present
        if message.tool_calls:
            tool_calls_list = []
            for tool_call in message.tool_calls:
                # Ensure arguments are JSON string for OpenAI
                args = tool_call.arguments if isinstance(tool_call.arguments, str) else json.dumps(tool_call.arguments)

                tool_call_dict = {
                    "id": tool_call.id,
                    "type": "function",
                    "function": {
                        "name": tool_call.name,
                        "arguments": args
                    }
                }
                tool_calls_list.append(tool_call_dict)

            native_msg["tool_calls"] = tool_calls_list

        # Add tool call ID for tool responses
        if message.tool_call_id:
            native_msg["tool_call_id"] = message.tool_call_id

        return native_msg

    def from_native_format(self, native_message: Dict[str, Any]) -> ChatMessage:
        """Convert OpenAI's native format to ChatMessage"""
        role = MessageRole(native_message["role"])
        content = native_message.get("content", "")
        tool_calls = []
        tool_call_id = native_message.get("tool_call_id")

        # Parse tool calls if present
        if "tool_calls" in native_message:
            for tc in native_message["tool_calls"]:
                if tc.get("type") == "function":
                    function_data = tc.get("function", {})
                    arguments_str = function_data.get("arguments", "{}")

                    # Parse arguments JSON
                    try:
                        arguments = json.loads(arguments_str) if isinstance(arguments_str, str) else arguments_str
                    except json.JSONDecodeError:
                        log.log_warn(f"Failed to parse tool call arguments: {arguments_str}")
                        arguments = {}

                    tool_call = ToolCall(
                        id=tc.get("id", ""),
                        name=function_data.get("name", ""),
                        arguments=arguments
                    )
                    tool_calls.append(tool_call)

        return ChatMessage(
            role=role,
            content=content,
            tool_calls=tool_calls if tool_calls else None,
            tool_call_id=tool_call_id
        )

    def extract_display_info(self, native_message: Dict[str, Any]) -> Tuple[str, str, str]:
        """Extract display info from OpenAI native format"""
        role = native_message.get("role", "unknown")
        content_text = native_message.get("content", "")
        message_type = "standard"

        # Check for tool calls
        if "tool_calls" in native_message and native_message["tool_calls"]:
            message_type = "tool_call"
            # Add tool call summary to content
            tool_names = []
            for tc in native_message["tool_calls"]:
                if tc.get("type") == "function":
                    function_data = tc.get("function", {})
                    tool_names.append(function_data.get("name", "unknown"))

            if tool_names:
                content_text += f" [Tools: {', '.join(tool_names)}]"

        elif native_message.get("tool_call_id"):
            message_type = "tool_response"

        return role, content_text, message_type

    def get_provider_type(self) -> ProviderType:
        return ProviderType.OPENAI_PLATFORM


class LiteLLMMessageAdapter(OpenAIMessageAdapter):
    """Message format adapter for LiteLLM proxy - uses OpenAI format"""

    def get_provider_type(self) -> ProviderType:
        return ProviderType.LITELLM


class AnthropicCLIMessageAdapter(OpenAIMessageAdapter):
    """Message format adapter for Anthropic CLI (Claude Code) - uses OpenAI-like format"""

    def get_provider_type(self) -> ProviderType:
        return ProviderType.ANTHROPIC_CLI


class OllamaMessageAdapter(MessageFormatAdapter):
    """Message format adapter for Ollama API"""

    def to_native_format(self, message: ChatMessage) -> Dict[str, Any]:
        """Convert ChatMessage to Ollama's native format"""
        native_msg = {
            "role": message.role.value,
            "content": message.content
        }

        # Handle tool calls (Ollama may have limited support)
        if message.tool_calls:
            tool_calls_list = []
            for tool_call in message.tool_calls:
                tool_call_dict = {
                    "id": tool_call.id,
                    "name": tool_call.name,
                    "arguments": tool_call.arguments
                }
                tool_calls_list.append(tool_call_dict)

            native_msg["tool_calls"] = tool_calls_list

        # Handle tool responses - Ollama might use different format
        if message.role == MessageRole.TOOL:
            native_msg = {
                "role": "tool",
                "content": message.content
            }
            if message.tool_call_id:
                native_msg["tool_call_id"] = message.tool_call_id

        return native_msg

    def from_native_format(self, native_message: Dict[str, Any]) -> ChatMessage:
        """Convert Ollama's native format to ChatMessage"""
        role = MessageRole(native_message["role"])
        content = native_message.get("content", "")
        tool_calls = []
        tool_call_id = native_message.get("tool_call_id")

        # Parse tool calls if present
        if "tool_calls" in native_message:
            for tc in native_message["tool_calls"]:
                tool_call = ToolCall(
                    id=tc.get("id", ""),
                    name=tc.get("name", ""),
                    arguments=tc.get("arguments", {})
                )
                tool_calls.append(tool_call)

        return ChatMessage(
            role=role,
            content=content,
            tool_calls=tool_calls if tool_calls else None,
            tool_call_id=tool_call_id
        )

    def extract_display_info(self, native_message: Dict[str, Any]) -> Tuple[str, str, str]:
        """Extract display info from Ollama native format"""
        role = native_message.get("role", "unknown")
        content_text = native_message.get("content", "")
        message_type = "standard"

        # Check for tool calls
        if "tool_calls" in native_message and native_message["tool_calls"]:
            message_type = "tool_call"
            tool_names = [tc.get("name", "unknown") for tc in native_message["tool_calls"]]
            if tool_names:
                content_text += f" [Tools: {', '.join(tool_names)}]"

        elif native_message.get("tool_call_id"):
            message_type = "tool_response"

        return role, content_text, message_type

    def get_provider_type(self) -> ProviderType:
        return ProviderType.OLLAMA


class MessageFormatService:
    """
    Service for handling provider-native message formats
    Follows SOA pattern - encapsulates all message format operations
    """

    def __init__(self):
        """Initialize message format service with provider adapters"""
        openai_adapter = OpenAIMessageAdapter()
        anthropic_adapter = AnthropicMessageAdapter()
        self._adapters: Dict[ProviderType, MessageFormatAdapter] = {
            # Anthropic providers (alphabetically)
            ProviderType.ANTHROPIC_CLI: AnthropicCLIMessageAdapter(),
            ProviderType.ANTHROPIC_PLATFORM: anthropic_adapter,
            # Gemini providers (alphabetically)
            ProviderType.GEMINI_OAUTH: openai_adapter,  # Storage uses OpenAI format; provider handles Gemini-native conversion
            ProviderType.GEMINI_PLATFORM: openai_adapter,  # OpenAI-compatible API
            # Local/Proxy providers (alphabetically)
            ProviderType.LITELLM: LiteLLMMessageAdapter(),
            ProviderType.LMSTUDIO: openai_adapter,
            ProviderType.OLLAMA: OllamaMessageAdapter(),
            ProviderType.OPENWEBUI: openai_adapter,
            # OpenAI providers (alphabetically)
            ProviderType.OPENAI_OAUTH: openai_adapter,  # Responses API uses OpenAI-like format
            ProviderType.OPENAI_PLATFORM: openai_adapter,
            # xAI provider
            ProviderType.XAI_PLATFORM: openai_adapter,  # OpenAI-compatible API
        }

    def get_adapter(self, provider_type: ProviderType) -> MessageFormatAdapter:
        """Get the appropriate adapter for a provider type"""
        if provider_type not in self._adapters:
            raise ValueError(f"No adapter available for provider type: {provider_type}")
        return self._adapters[provider_type]

    def to_native_format(self, message: ChatMessage, provider_type: ProviderType) -> Dict[str, Any]:
        """Convert ChatMessage to provider's native format"""
        adapter = self.get_adapter(provider_type)
        return adapter.to_native_format(message)

    def from_native_format(self, native_message: Dict[str, Any], provider_type: ProviderType) -> ChatMessage:
        """Convert provider's native format to ChatMessage"""
        adapter = self.get_adapter(provider_type)
        return adapter.from_native_format(native_message)

    def extract_display_info(self, native_message: Dict[str, Any], provider_type: ProviderType) -> Tuple[str, str, str]:
        """Extract display info from native message format"""
        adapter = self.get_adapter(provider_type)
        return adapter.extract_display_info(native_message)

    def convert_between_providers(self, native_message: Dict[str, Any],
                                from_provider: ProviderType,
                                to_provider: ProviderType) -> Dict[str, Any]:
        """Convert message between different provider formats"""
        # Convert to internal format first
        internal_message = self.from_native_format(native_message, from_provider)

        # Convert to target provider format
        return self.to_native_format(internal_message, to_provider)

    def create_system_message(self, content: str, provider_type: ProviderType) -> Dict[str, Any]:
        """Create a system message in provider's native format"""
        system_msg = ChatMessage(role=MessageRole.SYSTEM, content=content)
        return self.to_native_format(system_msg, provider_type)

    def create_user_message(self, content: str, provider_type: ProviderType) -> Dict[str, Any]:
        """Create a user message in provider's native format"""
        user_msg = ChatMessage(role=MessageRole.USER, content=content)
        return self.to_native_format(user_msg, provider_type)

    def get_supported_providers(self) -> List[ProviderType]:
        """Get list of supported provider types"""
        return list(self._adapters.keys())


# Global service instance (singleton pattern)
_message_format_service = None

def get_message_format_service() -> MessageFormatService:
    """Get the global message format service instance"""
    global _message_format_service
    if _message_format_service is None:
        _message_format_service = MessageFormatService()
    return _message_format_service
