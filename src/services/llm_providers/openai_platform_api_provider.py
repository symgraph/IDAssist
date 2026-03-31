#!/usr/bin/env python3

"""
OpenAI Provider - Implementation for OpenAI API
Adapted from reference implementation for BinAssist architecture
"""

import asyncio
import json
from typing import List, Dict, Any, AsyncGenerator, Optional, Callable

try:
    import openai
    from openai import OpenAI
except ImportError:
    raise ImportError("openai package not available. Install with: pip install openai")

from .base_provider import (
    BaseLLMProvider, APIProviderError, AuthenticationError,
    RateLimitError, NetworkError
)
from ..models.llm_models import (
    ChatRequest, ChatResponse, EmbeddingRequest, EmbeddingResponse,
    ChatMessage, MessageRole, ToolCall, ToolResult, Usage, ProviderCapabilities
)
from ..models.provider_types import ProviderType
from ..models.reasoning_models import ReasoningConfig

from src.ida_compat import log


class OpenAIPlatformApiProvider(BaseLLMProvider):
    """
    OpenAI API provider implementation.

    Supports chat completions, streaming, function calling, and embeddings.
    Includes special handling for o* reasoning models.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize OpenAI provider"""
        super().__init__(config)

        # Validate configuration
        self.validate_config()

        # Check if API key is required for this provider type
        provider_type = self.get_provider_type()
        if not self.api_key and ProviderType.requires_api_key(provider_type):
            raise ValueError(f"API key is required for {provider_type.value} provider")

        # Initialize OpenAI client
        try:
            # o* models need longer timeouts due to reasoning time
            timeout = 120.0
            if self._is_reasoning_model():
                timeout = max(timeout, 180.0)  # At least 3 minutes for o* models
                log.log_info(f"Using extended timeout of {timeout}s for o* model: {self.model}")

            # Handle base_url - use default if not specified or standard OpenAI URL
            base_url = None
            if self.url and self.url != 'https://api.openai.com/v1':
                base_url = self.url

            # For local providers that don't need API keys, use a placeholder
            api_key = self.api_key or "not-needed"

            # Handle TLS verification settings and create client
            if self.disable_tls:
                import httpx
                import ssl
                log.log_warn(f"TLS verification disabled for OpenAI provider '{self.name}'")

                # Create SSL context that doesn't verify certificates
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

                # Create httpx client with disabled verification
                http_client = httpx.Client(verify=False, timeout=timeout)

                self._client = OpenAI(
                    api_key=api_key,
                    base_url=base_url,
                    timeout=timeout,
                    max_retries=0,  # We handle retries ourselves
                    http_client=http_client
                )
            else:
                import httpx
                # Respect bypass_proxy setting (default True: ignore system proxy)
                _bypass_proxy = self.config.get('bypass_proxy', True)
                _http_client = httpx.Client(trust_env=not _bypass_proxy, timeout=timeout)
                if _bypass_proxy:
                    log.log_debug("OpenAI: Bypassing system proxy (trust_env=False)")
                self._client = OpenAI(
                    api_key=api_key,
                    base_url=base_url,
                    timeout=timeout,
                    max_retries=0,  # We handle retries ourselves
                    http_client=_http_client
                )

        except Exception as e:
            raise APIProviderError(f"Failed to initialize OpenAI client: {e}")

    def _is_reasoning_model(self) -> bool:
        """Check if the current model is an o* reasoning model."""
        model_name = self.model.lower()
        return (model_name.startswith("o1") or
                model_name.startswith("o2") or
                model_name.startswith("o3") or
                model_name.startswith("o4") or
                model_name.startswith("gpt-5"))

    def _prepare_messages(self, messages: List[ChatMessage]) -> List[Dict[str, Any]]:
        """Convert BinAssist ChatMessage objects to OpenAI message format."""
        openai_messages = []

        for msg in messages:
            openai_msg = {
                "role": msg.role.value,  # Convert enum to string
                "content": msg.content
            }

            # Add tool calls if present
            if hasattr(msg, 'tool_calls') and msg.tool_calls:
                tool_calls_list = []
                for tc in msg.tool_calls:
                    # Ensure arguments are JSON string
                    args = tc.arguments if isinstance(tc.arguments, str) else json.dumps(tc.arguments)

                    tool_call_dict = {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": args
                        }
                    }
                    tool_calls_list.append(tool_call_dict)

                openai_msg["tool_calls"] = tool_calls_list

            # Add tool call id and name if this is a tool response
            if hasattr(msg, 'tool_call_id') and msg.tool_call_id:
                openai_msg["tool_call_id"] = msg.tool_call_id
            if hasattr(msg, 'name') and msg.name:
                openai_msg["name"] = msg.name

            openai_messages.append(openai_msg)

        return openai_messages

    async def chat_completion(self, request: ChatRequest,
                            native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> ChatResponse:
        """Generate non-streaming chat completion with rate limit retry"""
        log.log_info(f"OpenAI chat completion for {self.model} with {len(request.messages)} messages")
        return await self._with_rate_limit_retry(self._chat_completion_impl, request, native_message_callback)

    async def _chat_completion_impl(self, request: ChatRequest,
                            native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> ChatResponse:
        """Internal implementation of chat completion"""
        try:
            # Convert messages to OpenAI format
            openai_messages = self._prepare_messages(request.messages)

            # Prepare completion kwargs
            completion_kwargs = {
                "model": self.model,
                "messages": openai_messages,
                "stream": False
            }

            # Handle different token field names based on model type
            if self._is_reasoning_model():
                completion_kwargs["max_completion_tokens"] = min(request.max_tokens or self.max_tokens, self.max_tokens)
                # o* models don't support temperature parameter
            else:
                completion_kwargs["max_tokens"] = min(request.max_tokens or self.max_tokens, self.max_tokens)

                # Check if reasoning/thinking is enabled
                reasoning_effort_str = self.config.get('reasoning_effort', 'none')
                thinking_enabled = reasoning_effort_str and reasoning_effort_str != 'none'

                # When thinking is enabled (e.g., Anthropic via LiteLLM), temperature must be 1
                if thinking_enabled:
                    completion_kwargs["temperature"] = 1
                    log.log_debug("OpenAI: Thinking/reasoning enabled, forcing temperature=1")
                elif request.temperature is not None:
                    completion_kwargs["temperature"] = request.temperature

            # Add reasoning effort if configured
            reasoning_effort_str = self.config.get('reasoning_effort', 'none')
            if reasoning_effort_str and reasoning_effort_str != 'none':
                reasoning_config = ReasoningConfig.from_string(reasoning_effort_str)
                effort = reasoning_config.get_openai_reasoning_effort()
                if effort:
                    completion_kwargs["reasoning_effort"] = effort
                    log.log_debug(f"OpenAI reasoning_effort set to: {effort}")

            # Add tools if present
            if request.tools:
                completion_kwargs["tools"] = request.tools

            # Make API call
            response = self._client.chat.completions.create(**completion_kwargs)

            if not response.choices:
                raise APIProviderError("No choices in OpenAI response")

            message = response.choices[0].message
            content = message.content or ""

            # Extract tool calls if present
            tool_calls = []
            if message.tool_calls:
                for tc in message.tool_calls:
                    try:
                        arguments = json.loads(tc.function.arguments) if tc.function.arguments else {}
                    except json.JSONDecodeError:
                        log.log_warn(f"Failed to parse tool call arguments: {tc.function.arguments}")
                        arguments = {}

                    tool_call = ToolCall(
                        id=tc.id,
                        name=tc.function.name,
                        arguments=arguments
                    )
                    tool_calls.append(tool_call)

            # Call native message callback with actual OpenAI response
            if native_message_callback:
                # Convert the actual OpenAI response to dict for storage
                choice = response.choices[0]
                native_message = {
                    "role": "assistant",
                    "content": choice.message.content,
                    "model": response.model,
                    "id": response.id,
                    "object": response.object,
                    "created": response.created,
                    "finish_reason": choice.finish_reason
                }

                # Add tool calls if present in original response
                if choice.message.tool_calls:
                    native_message["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": tc.type,
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        }
                        for tc in choice.message.tool_calls
                    ]

                # Add usage if available
                if response.usage:
                    native_message["usage"] = {
                        "prompt_tokens": response.usage.prompt_tokens,
                        "completion_tokens": response.usage.completion_tokens,
                        "total_tokens": response.usage.total_tokens
                    }

                native_message_callback(native_message, self.get_provider_type())

            # Calculate usage
            usage = None
            if response.usage:
                usage = Usage(
                    prompt_tokens=response.usage.prompt_tokens,
                    completion_tokens=response.usage.completion_tokens,
                    total_tokens=response.usage.total_tokens
                )

            return ChatResponse(
                content=content,
                model=self.model,
                usage=usage,
                tool_calls=tool_calls,
                finish_reason=response.choices[0].finish_reason or "stop"
            )

        except openai.AuthenticationError as e:
            log.log_error(f"Authentication error: {e}")
            raise AuthenticationError(f"OpenAI authentication failed: {e}")
        except openai.RateLimitError as e:
            log.log_error(f"Rate limit error: {e}")
            raise RateLimitError(f"OpenAI rate limit exceeded: {e}")
        except openai.APIConnectionError as e:
            import traceback
            log.log_error(f"Connection error: {e}")
            log.log_error(f"Connection error details: {type(e).__name__}")
            log.log_error(f"Connection error traceback: {traceback.format_exc()}")
            if hasattr(e, '__cause__') and e.__cause__:
                log.log_error(f"Underlying cause: {e.__cause__}")
            raise NetworkError(f"OpenAI connection failed: {e}")
        except openai.APIError as e:
            log.log_error(f"OpenAI API error: {e}")
            raise APIProviderError(f"OpenAI API error: {e}")
        except Exception as e:
            log.log_error(f"Chat completion failed: {e}")
            raise APIProviderError(f"Unexpected error during chat completion: {e}")

    async def chat_completion_stream(self, request: ChatRequest,
                                   native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> AsyncGenerator[ChatResponse, None]:
        """Generate streaming chat completion with rate limit retry"""
        log.log_info(f"OpenAI streaming completion for {self.model} with {len(request.messages)} messages")
        async for response in self._with_rate_limit_retry_stream(self._chat_completion_stream_impl, request, native_message_callback):
            yield response

    async def _chat_completion_stream_impl(self, request: ChatRequest,
                                   native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> AsyncGenerator[ChatResponse, None]:
        """Internal implementation of streaming chat completion"""
        try:
            # Convert messages to OpenAI format
            openai_messages = self._prepare_messages(request.messages)

            # Prepare completion kwargs
            completion_kwargs = {
                "model": self.model,
                "messages": openai_messages,
                "stream": True
            }

            # Handle different token field names based on model type
            if self._is_reasoning_model():
                completion_kwargs["max_completion_tokens"] = min(request.max_tokens or self.max_tokens, self.max_tokens)
                # o* models don't support temperature parameter
            else:
                completion_kwargs["max_tokens"] = min(request.max_tokens or self.max_tokens, self.max_tokens)

                # Check if reasoning/thinking is enabled
                reasoning_effort_str = self.config.get('reasoning_effort', 'none')
                thinking_enabled = reasoning_effort_str and reasoning_effort_str != 'none'

                # When thinking is enabled (e.g., Anthropic via LiteLLM), temperature must be 1
                if thinking_enabled:
                    completion_kwargs["temperature"] = 1
                    log.log_debug("OpenAI: Thinking/reasoning enabled, forcing temperature=1")
                elif request.temperature is not None:
                    completion_kwargs["temperature"] = request.temperature

            # Add reasoning effort if configured (streaming)
            reasoning_effort_str = self.config.get('reasoning_effort', 'none')
            if reasoning_effort_str and reasoning_effort_str != 'none':
                reasoning_config = ReasoningConfig.from_string(reasoning_effort_str)
                effort = reasoning_config.get_openai_reasoning_effort()
                if effort:
                    completion_kwargs["reasoning_effort"] = effort
                    log.log_debug(f"OpenAI streaming reasoning_effort set to: {effort}")

            # Add tools if present
            if request.tools:
                completion_kwargs["tools"] = request.tools

            # Make streaming API call
            import json as _json
            _req_dump = _json.dumps(completion_kwargs, default=str)
            _req_size = len(_req_dump)
            log.log_info(f"OpenAI stream request size: {_req_size} bytes, messages: {len(openai_messages)}, keys: {list(completion_kwargs.keys())}")
            log.log_debug(f"OpenAI stream request body (first 500): {_req_dump[:500]}")
            stream = self._client.chat.completions.create(**completion_kwargs)

            accumulated_content = ""
            accumulated_tool_calls = []
            building_tool_calls = {}  # tool_index -> partial tool data

            try:
                finished = False
                for chunk in stream:
                    if not chunk.choices or finished:
                        continue

                    choice = chunk.choices[0]
                    delta = choice.delta

                    # Handle content delta - yield immediately for responsive streaming
                    if delta.content is not None and delta.content:
                        accumulated_content += delta.content
                        yield ChatResponse(
                            content=delta.content,
                            model=self.model,
                            usage=Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
                            tool_calls=[],
                            finish_reason="",
                            is_streaming=True
                        )
                        # Yield control to event loop for responsive UI updates
                        await asyncio.sleep(0)

                    # Handle tool call deltas - properly accumulate across chunks
                    if delta.tool_calls:
                        for tc_delta in delta.tool_calls:
                            tool_index = tc_delta.index if hasattr(tc_delta, 'index') else 0

                            # Initialize tool call if not seen before
                            if tool_index not in building_tool_calls:
                                building_tool_calls[tool_index] = {
                                    'id': tc_delta.id or f"tool_call_{tool_index}",
                                    'name': '',
                                    'arguments': ''
                                }

                            # Update tool call data from delta
                            if tc_delta.id:
                                building_tool_calls[tool_index]['id'] = tc_delta.id

                            if tc_delta.function:
                                if tc_delta.function.name:
                                    building_tool_calls[tool_index]['name'] = tc_delta.function.name

                                if tc_delta.function.arguments:
                                    building_tool_calls[tool_index]['arguments'] += tc_delta.function.arguments

                    # Handle finish reason - only process the first one
                    if choice.finish_reason and not finished:
                        # Convert accumulated tool calls to ToolCall objects
                        final_tool_calls = []
                        for tool_index, tool_data in building_tool_calls.items():
                            log.log_info(f"Tool {tool_index}: name='{tool_data['name']}', args='{tool_data['arguments']}'")
                            if tool_data['name']:  # Only include tools with names
                                try:
                                    arguments = json.loads(tool_data['arguments']) if tool_data['arguments'] else {}
                                except json.JSONDecodeError:
                                    log.log_warn(f"Failed to parse tool call arguments: {tool_data['arguments']}")
                                    arguments = {}

                                tool_call = ToolCall(
                                    id=tool_data['id'],
                                    name=tool_data['name'],
                                    arguments=arguments
                                )
                                final_tool_calls.append(tool_call)

                        log.log_info(f"Created {len(final_tool_calls)} final tool calls")

                        # Call native message callback with complete streaming response
                        if native_message_callback:
                            # Reconstruct OpenAI format from streaming data
                            native_message = {
                                "role": "assistant",
                                "content": accumulated_content,
                                "model": self.model,
                                "finish_reason": choice.finish_reason,
                                "streaming": True  # Mark as reconstructed from streaming
                            }

                            # Add tool calls if present
                            if final_tool_calls:
                                native_message["tool_calls"] = [
                                    {
                                        "id": tc.id,
                                        "type": "function",
                                        "function": {
                                            "name": tc.name,
                                            "arguments": json.dumps(tc.arguments) if isinstance(tc.arguments, dict) else tc.arguments
                                        }
                                    }
                                    for tc in final_tool_calls
                                ]

                            native_message_callback(native_message, self.get_provider_type())

                        final_response = ChatResponse(
                            content="",  # Empty content since all content already sent as deltas
                            model=self.model,
                            usage=Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
                            tool_calls=final_tool_calls,
                            finish_reason=choice.finish_reason,
                            is_streaming=False  # Mark as final response
                        )
                        yield final_response
                        finished = True  # Mark as finished to ignore subsequent chunks
                        break

            except Exception as stream_error:
                log.log_error(f"Error iterating OpenAI stream: {stream_error}")
                raise NetworkError(f"Stream error: {stream_error}")

        except openai.AuthenticationError as e:
            log.log_error(f"Authentication error: {e}")
            raise AuthenticationError(f"OpenAI authentication failed: {e}")
        except openai.RateLimitError as e:
            log.log_error(f"Rate limit error: {e}")
            raise RateLimitError(f"OpenAI rate limit exceeded: {e}")
        except openai.APIConnectionError as e:
            import traceback
            log.log_error(f"Connection error: {e}")
            log.log_error(f"Connection error details: {type(e).__name__}")
            log.log_error(f"Connection error traceback: {traceback.format_exc()}")
            if hasattr(e, '__cause__') and e.__cause__:
                log.log_error(f"Underlying cause: {e.__cause__}")
            raise NetworkError(f"OpenAI connection failed: {e}")
        except openai.APIError as e:
            log.log_error(f"OpenAI API error: {e}")
            # Retry once on 502/503 transient errors
            if hasattr(e, 'status_code') and e.status_code in (502, 503, 529):
                log.log_info(f"Transient {e.status_code} error, retrying in 3s...")
                import asyncio as _asyncio
                await _asyncio.sleep(3)
                async for response in self._chat_completion_stream_impl(request, native_message_callback):
                    yield response
                return
            raise APIProviderError(f"OpenAI API error: {e}")
        except Exception as e:
            log.log_error(f"Streaming completion failed: {e}")
            raise APIProviderError(f"Unexpected error during streaming: {e}")

    async def generate_embeddings(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """Generate embeddings using OpenAI's embedding API"""
        log.log_info(f"OpenAI embeddings for {len(request.texts)} texts")

        try:
            # Use text-embedding-3-small as default model for embeddings
            embedding_model = getattr(self, 'embedding_model', 'text-embedding-3-small')

            response = self._client.embeddings.create(
                model=embedding_model,
                input=request.texts
            )

            # Extract embeddings
            embeddings = [data.embedding for data in response.data]

            # Calculate usage if available
            usage = None
            if hasattr(response, 'usage') and response.usage:
                usage = Usage(
                    prompt_tokens=response.usage.prompt_tokens,
                    completion_tokens=0,  # Embeddings don't have completion tokens
                    total_tokens=response.usage.total_tokens
                )

            return EmbeddingResponse(
                embeddings=embeddings,
                usage=usage
            )

        except openai.AuthenticationError as e:
            log.log_error(f"Authentication error getting embeddings: {e}")
            raise AuthenticationError(f"OpenAI authentication failed: {e}")
        except openai.RateLimitError as e:
            log.log_error(f"Rate limit error getting embeddings: {e}")
            raise RateLimitError(f"OpenAI rate limit exceeded: {e}")
        except openai.APIConnectionError as e:
            log.log_error(f"Connection error getting embeddings: {e}")
            raise NetworkError(f"OpenAI connection failed: {e}")
        except openai.APIError as e:
            log.log_error(f"OpenAI API error getting embeddings: {e}")
            raise APIProviderError(f"OpenAI API error: {e}")
        except Exception as e:
            log.log_error(f"Unexpected error getting embeddings: {e}")
            raise APIProviderError(f"Unexpected error getting embeddings: {e}")

    def get_capabilities(self) -> ProviderCapabilities:
        """Get provider capabilities"""
        return ProviderCapabilities(
            supports_chat=True,
            supports_streaming=True,
            supports_tools=True,
            supports_embeddings=True,
            supports_vision=False,
            max_tokens=self.max_tokens,
            models=[self.model] if self.model else []
        )

    def get_provider_type(self) -> ProviderType:
        """Get the provider type for this provider"""
        # Return the configured provider type (could be OPENAI, LMSTUDIO, or OPENWEBUI)
        provider_type_str = self.config.get('provider_type', 'openai_platform')
        if isinstance(provider_type_str, str):
            return ProviderType(provider_type_str)
        return provider_type_str

    def validate_config(self):
        """Validate provider configuration"""
        super().validate_config()

        # OpenAI-specific validation
        if not self.model:
            raise ValueError("Model is required for OpenAI provider")

    async def test_connection(self) -> bool:
        """Test connection to OpenAI API"""
        try:
            # Simple test with minimal parameters
            test_request = ChatRequest(
                messages=[ChatMessage(role=MessageRole.USER, content="Hi")],
                max_tokens=10,
                temperature=0.1
            )

            response = await self.chat_completion(test_request)
            return bool(response.content)

        except Exception as e:
            log.log_error(f"OpenAI connection test failed: {e}")
            return False

# Factory for OpenAI provider
from ..llm_providers.provider_factory import ProviderFactory
from ..models.provider_types import ProviderType

class OpenAIPlatformApiProviderFactory(ProviderFactory):
    """Factory for creating OpenAI Platform API provider instances"""

    def create_provider(self, config: Dict[str, Any]) -> OpenAIPlatformApiProvider:
        """Create OpenAI Platform API provider instance"""
        return OpenAIPlatformApiProvider(config)

    def supports_provider_type(self, provider_type: ProviderType) -> bool:
        """Check if this factory supports the provider type"""
        # OpenAI provider handles OpenAI-compatible APIs
        return provider_type in {
            ProviderType.OPENAI_PLATFORM,
            ProviderType.LMSTUDIO,
            ProviderType.OPENWEBUI,
            ProviderType.XAI_PLATFORM,
            ProviderType.GEMINI_PLATFORM,
        }
