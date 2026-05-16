#!/usr/bin/env python3

"""Bedrock Provider - Implementation for AWS Bedrock Converse API."""

import json
import time
from typing import List, Dict, Any, AsyncGenerator, Optional, Callable

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
except ImportError:
    raise ImportError("boto3 package not available. Install with: pip install boto3")

from .base_provider import (
    BaseLLMProvider, APIProviderError, AuthenticationError,
    RateLimitError, NetworkError
)
from ..models.llm_models import (
    ChatRequest, ChatResponse, EmbeddingRequest, EmbeddingResponse,
    ChatMessage, MessageRole, ToolCall, Usage, ProviderCapabilities,
    ProviderModelDiscoveryResult
)
from ..models.provider_types import ProviderType
from ..models.reasoning_models import ReasoningConfig

from src.ida_compat import log


class BedrockProvider(BaseLLMProvider):
    """AWS Bedrock provider via the Converse / ConverseStream API.

    Authenticates via boto3's credential chain: environment variables,
    AWS credentials file, IAM role, or explicit access key/secret key.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize Bedrock provider."""
        super().__init__(config)

        self.aws_region = config.get('aws_region', 'us-east-1')
        self.aws_profile = config.get('aws_profile', '')
        self.aws_access_key_id = config.get('aws_access_key_id', '')
        self.aws_secret_access_key = config.get('aws_secret_access_key', '')

        self.validate_config()

        log.log_info(
            f"Bedrock provider initialized with region={self.aws_region}, "
            f"model={self.model}"
        )

    def validate_config(self):
        """Validate provider configuration - relaxed for Bedrock."""
        if not self.name:
            raise ValueError("Provider name is required")
        if not self.model:
            raise ValueError("Model is required")
        if not self.aws_region:
            raise ValueError("AWS region is required")

    def _create_client(self):
        """Create a boto3 bedrock-runtime client.

        Uses the configured credential chain: explicit keys take precedence,
        then named profile, then default boto3 chain.
        """
        session_kwargs = {}
        if self.aws_profile:
            session_kwargs['profile_name'] = self.aws_profile

        session = boto3.Session(**session_kwargs)

        client_kwargs = {
            'region_name': self.aws_region,
        }
        if self.aws_access_key_id and self.aws_secret_access_key:
            client_kwargs['aws_access_key_id'] = self.aws_access_key_id
            client_kwargs['aws_secret_access_key'] = self.aws_secret_access_key

        return session.client('bedrock-runtime', **client_kwargs)

    @staticmethod
    def _prepare_messages(messages: List[ChatMessage]):
        """Convert internal ChatMessage list to Bedrock Converse format.

        Bedrock Converse API expects:
            messages: [{"role": "user"|"assistant", "content": [{"text": "..."}]}]
            system: [{"text": "..."}] (separate from messages)
        """
        converse_messages = []
        system_content = None

        for msg in messages:
            if msg.role == MessageRole.SYSTEM:
                if msg.content:
                    system_content = [{"text": msg.content}]
                continue

            role = "user" if msg.role == MessageRole.USER else "assistant"

            content_blocks = []
            if msg.content:
                content_blocks.append({"text": msg.content})

            if msg.tool_calls:
                for tc in msg.tool_calls:
                    content_blocks.append({
                        "toolUse": {
                            "toolUseId": tc.id,
                            "name": tc.name,
                            "input": tc.arguments
                        }
                    })

            if msg.tool_call_id:
                content_blocks.append({
                    "toolResult": {
                        "toolUseId": msg.tool_call_id,
                        "content": [{"text": msg.content or ""}]
                    }
                })

            converse_messages.append({
                "role": role,
                "content": content_blocks
            })

        return converse_messages, system_content

    @staticmethod
    def _build_inference_config(request: ChatRequest) -> Dict[str, Any]:
        """Build inferenceConfig dict from ChatRequest."""
        config = {}
        if request.max_tokens:
            config['maxTokens'] = request.max_tokens
        if request.temperature is not None:
            config['temperature'] = request.temperature
        if request.top_p is not None:
            config['topP'] = request.top_p
        if request.stop:
            stops = request.stop if isinstance(request.stop, list) else [request.stop]
            config['stopSequences'] = stops
        return config

    @staticmethod
    def _build_tool_config(tools: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build Bedrock toolConfig from OpenAI-format tool definitions."""
        bedrock_tools = []
        for tool in tools:
            function_def = {
                "name": tool["function"]["name"],
                "description": tool["function"].get("description", ""),
            }
            if "parameters" in tool["function"]:
                function_def["parameters"] = tool["function"]["parameters"]

            bedrock_tools.append({
                "toolSpec": {
                    "name": function_def["name"],
                    "description": function_def["description"],
                    "inputSchema": {
                        "json": function_def.get("parameters", {"type": "object"})
                    }
                }
            })

        return {"tools": bedrock_tools}

    @staticmethod
    def _parse_converse_response(response: Dict[str, Any]) -> tuple:
        """Parse a Converse API response into content and tool_calls."""
        content = ""
        tool_calls = []

        output = response.get('output', {})
        message = output.get('message', {})
        content_blocks = message.get('content', [])

        for block in content_blocks:
            if 'text' in block:
                if content:
                    content += "\n"
                content += block['text']
            elif 'toolUse' in block:
                tool_use = block['toolUse']
                tc = ToolCall(
                    id=tool_use['toolUseId'],
                    name=tool_use['name'],
                    arguments=tool_use.get('input', {})
                )
                tool_calls.append(tc)

        stop_reason = response.get('stopReason', 'end_turn')
        finish_reason_map = {
            'end_turn': 'stop',
            'tool_use': 'tool_calls',
            'max_tokens': 'length',
            'content_filtered': 'content_filter',
            'stop_sequence': 'stop',
        }
        finish_reason = finish_reason_map.get(stop_reason, stop_reason)

        usage_info = response.get('usage', {})
        usage = Usage(
            prompt_tokens=usage_info.get('inputTokens', 0),
            completion_tokens=usage_info.get('outputTokens', 0),
            total_tokens=(
                usage_info.get('inputTokens', 0) +
                usage_info.get('outputTokens', 0)
            )
        )

        return content, tool_calls, finish_reason, usage

    async def chat_completion(
        self,
        request: ChatRequest,
        native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None
    ) -> ChatResponse:
        """Generate non-streaming chat completion with rate limit retry."""
        log.log_info(
            f"Bedrock chat completion for {self.model} "
            f"with {len(request.messages)} messages"
        )
        return await self._with_rate_limit_retry(
            self._chat_completion_impl, request, native_message_callback
        )

    async def _chat_completion_impl(
        self,
        request: ChatRequest,
        native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None
    ) -> ChatResponse:
        """Internal implementation of chat completion via Converse API."""
        try:
            messages, system_prompt = self._prepare_messages(request.messages)

            converse_kwargs = {
                'modelId': self.model,
                'messages': messages,
                'inferenceConfig': self._build_inference_config(request),
            }

            if system_prompt:
                converse_kwargs['system'] = system_prompt

            if request.tools:
                converse_kwargs['toolConfig'] = self._build_tool_config(request.tools)

            client = self._create_client()
            response = client.converse(**converse_kwargs)

            content, tool_calls, finish_reason, usage = self._parse_converse_response(response)

            if native_message_callback:
                native_message = {
                    "role": "assistant",
                    "content": content,
                    "tool_calls": [
                        {"id": tc.id, "name": tc.name, "arguments": tc.arguments}
                        for tc in tool_calls
                    ] if tool_calls else [],
                    "model": self.model,
                    "stopReason": response.get('stopReason', ''),
                }
                native_message_callback(native_message, self.get_provider_type())

            return ChatResponse(
                content=content,
                model=self.model,
                usage=usage,
                tool_calls=tool_calls if tool_calls else None,
                finish_reason=finish_reason,
            )

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            if error_code in ('AccessDeniedException', 'UnrecognizedClientException'):
                raise AuthenticationError(
                    f"AWS authentication failed: {error_message}"
                )
            elif error_code == 'ThrottlingException':
                raise RateLimitError(
                    f"AWS Bedrock throttling: {error_message}"
                )
            elif error_code == 'ModelTimeoutException':
                raise APIProviderError(
                    f"Model request timed out: {error_message}"
                )
            elif error_code == 'ModelNotReadyException':
                raise APIProviderError(
                    f"Model not ready: {error_message}"
                )
            raise APIProviderError(
                f"AWS Bedrock API error ({error_code}): {error_message}"
            )
        except BotoCoreError as e:
            raise NetworkError(f"AWS SDK error: {e}")
        except Exception as e:
            log.log_error(f"Chat completion failed: {e}")
            raise APIProviderError(
                f"Unexpected error during chat completion: {e}"
            )

    async def chat_completion_stream(
        self,
        request: ChatRequest,
        native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None
    ) -> AsyncGenerator[ChatResponse, None]:
        """Generate streaming chat completion with rate limit retry."""
        log.log_info(
            f"Bedrock streaming completion for {self.model} "
            f"with {len(request.messages)} messages"
        )
        async for response in self._with_rate_limit_retry_stream(
            self._chat_completion_stream_impl, request, native_message_callback
        ):
            yield response

    async def _chat_completion_stream_impl(
        self,
        request: ChatRequest,
        native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None
    ) -> AsyncGenerator[ChatResponse, None]:
        """Internal implementation of streaming via ConverseStream API."""
        accumulated_content = ""
        accumulated_tool_calls = []
        response_id = None
        response_model = self.model
        input_token_count = 0
        output_token_count = 0
        stop_reason = "stop"

        try:
            messages, system_prompt = self._prepare_messages(request.messages)

            converse_kwargs = {
                'modelId': self.model,
                'messages': messages,
                'inferenceConfig': self._build_inference_config(request),
            }

            if system_prompt:
                converse_kwargs['system'] = system_prompt

            if request.tools:
                converse_kwargs['toolConfig'] = self._build_tool_config(request.tools)

            client = self._create_client()
            streaming_response = client.converse_stream(**converse_kwargs)
            stream = streaming_response.get('stream', [])

            for event in stream:
                event_type = list(event.keys())[0] if event else None

                if event_type == 'messageStart':
                    msg = event['messageStart']
                    role = msg.get('role', 'assistant')
                    response_id = msg.get('messageId')

                elif event_type == 'contentBlockDelta':
                    delta = event['contentBlockDelta']
                    delta_obj = delta.get('delta', {})

                    if 'text' in delta_obj:
                        text = delta_obj['text']
                        accumulated_content += text
                        yield ChatResponse(
                            content=text,
                            model=response_model,
                            usage=Usage(0, 0, 0),
                            is_streaming=True,
                            finish_reason="incomplete",
                            response_id=response_id,
                        )

                    elif 'toolUse' in delta_obj:
                        pass

                elif event_type == 'contentBlockStart':
                    start = event['contentBlockStart']
                    start_obj = start.get('start', {})

                    if 'toolUse' in start_obj:
                        tool_use_start = start_obj['toolUse']
                        current_tool = ToolCall(
                            id=tool_use_start.get('toolUseId', ''),
                            name=tool_use_start.get('name', ''),
                            arguments={}
                        )
                        accumulated_tool_calls.append(current_tool)

                elif event_type == 'messageStop':
                    stop_data = event['messageStop']
                    stop_reason = stop_data.get('stopReason', 'end_turn')

                elif event_type == 'metadata':
                    metadata = event['metadata']
                    usage_info = metadata.get('usage', {})
                    input_token_count = usage_info.get('inputTokens', 0)
                    output_token_count = usage_info.get('outputTokens', 0)

            finish_reason_map = {
                'end_turn': 'stop',
                'tool_use': 'tool_calls',
                'max_tokens': 'length',
                'content_filtered': 'content_filter',
                'stop_sequence': 'stop',
            }
            mapped_stop_reason = finish_reason_map.get(stop_reason, stop_reason)

            usage = Usage(
                prompt_tokens=input_token_count,
                completion_tokens=output_token_count,
                total_tokens=input_token_count + output_token_count,
            )

            yield ChatResponse(
                content="",
                model=response_model,
                usage=usage,
                tool_calls=accumulated_tool_calls if accumulated_tool_calls else None,
                finish_reason=mapped_stop_reason,
                is_streaming=False,
                response_id=response_id,
            )

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            if error_code in ('AccessDeniedException', 'UnrecognizedClientException'):
                raise AuthenticationError(
                    f"AWS authentication failed: {error_message}"
                )
            elif error_code == 'ThrottlingException':
                raise RateLimitError(
                    f"AWS Bedrock throttling: {error_message}"
                )
            raise APIProviderError(
                f"AWS Bedrock API error ({error_code}): {error_message}"
            )
        except BotoCoreError as e:
            raise NetworkError(f"AWS SDK error: {e}")
        except Exception as e:
            log.log_error(f"Streaming chat completion failed: {e}")
            raise APIProviderError(
                f"Unexpected error during streaming: {e}"
            )

    async def generate_embeddings(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """Generate text embeddings via Bedrock.

        Not supported via Converse API. Use Amazon Titan models via
        InvokeModel for embeddings.
        """
        raise NotImplementedError(
            "Embeddings not supported via Bedrock Converse API. "
            "Use LiteLLM provider with Titan embedding models."
        )

    async def test_connection(self) -> bool:
        """Test connectivity by listing available foundation models."""
        try:
            session_kwargs = {}
            if self.aws_profile:
                session_kwargs['profile_name'] = self.aws_profile

            session = boto3.Session(**session_kwargs)
            client_kwargs = {'region_name': self.aws_region}
            if self.aws_access_key_id and self.aws_secret_access_key:
                client_kwargs['aws_access_key_id'] = self.aws_access_key_id
                client_kwargs['aws_secret_access_key'] = self.aws_secret_access_key

            client = session.client('bedrock', **client_kwargs)

            response = client.list_foundation_models(
                byInferenceType='ON_DEMAND'
            )

            model_summaries = response.get('modelSummaries', [])
            log.log_info(
                f"AWS Bedrock connection successful: "
                f"{len(model_summaries)} models available"
            )
            return True

        except ClientError as e:
            error_code = e.response['Error']['Code']
            log.log_error(
                f"AWS Bedrock connection failed ({error_code}): "
                f"{e.response['Error']['Message']}"
            )
            return False
        except BotoCoreError as e:
            log.log_error(f"AWS SDK connection failed: {e}")
            return False
        except Exception as e:
            log.log_error(f"Bedrock connection test failed: {e}")
            return False

    def get_capabilities(self) -> ProviderCapabilities:
        """Get provider capabilities for Bedrock Converse API."""
        return ProviderCapabilities(
            supports_chat=True,
            supports_streaming=True,
            supports_tools=True,
            supports_embeddings=False,
            supports_vision=False,
            supports_model_discovery=True,
            max_tokens=8192,
            models=[
                "anthropic.claude-sonnet-4-6",
                "anthropic.claude-haiku-4-5",
                "anthropic.claude-opus-4-5",
                "amazon.nova-pro-v1:0",
                "amazon.nova-lite-v1:0",
                "meta.llama3-3-70b-instruct-v1:0",
            ],
        )

    def get_provider_type(self) -> ProviderType:
        """Get provider type enum value."""
        return ProviderType.BEDROCK

    def prepare_tool_enabled_request(
        self,
        request: ChatRequest,
        tools: List[Dict[str, Any]]
    ) -> ChatRequest:
        """Prepare request with tool definitions enabled.

        Bedrock Converse API handles tools via toolConfig rather than
        embedding them in the message body.
        """
        if not self.supports_tools():
            return request

        tool_request = ChatRequest(
            messages=request.messages,
            model=request.model,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            top_p=request.top_p,
            stream=request.stream,
            tools=tools,
            tool_choice=request.tool_choice or "auto",
            stop=request.stop,
            presence_penalty=request.presence_penalty,
            frequency_penalty=request.frequency_penalty,
            user=request.user,
        )
        return tool_request

    def format_tool_results_for_continuation(
        self,
        tool_calls: List[ToolCall],
        tool_results: List[str]
    ) -> List[Dict[str, Any]]:
        """Format tool results for Bedrock Converse continuation."""
        messages = []
        for tool_call, result in zip(tool_calls, tool_results):
            messages.append({
                "role": "tool",
                "content": result,
                "tool_call_id": tool_call.id,
                "name": tool_call.name,
            })
        return messages


class BedrockProviderFactory:
    """Factory for creating Bedrock provider instances."""

    def create_provider(self, config: Dict[str, Any]) -> BedrockProvider:
        """Create Bedrock provider instance."""
        return BedrockProvider(config)

    def supports_provider_type(self, provider_type: ProviderType) -> bool:
        """Check if this factory supports the provider type."""
        return provider_type == ProviderType.BEDROCK
