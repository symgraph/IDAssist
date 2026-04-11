#!/usr/bin/env python3

"""
Base LLM Provider - Abstract interface for all LLM providers
Defines the contract that all providers must implement
"""

import asyncio
import random
from abc import ABC, abstractmethod
from typing import AsyncGenerator, List, Dict, Any, Optional, Callable
from ..models.llm_models import (
    ChatRequest, ChatResponse, EmbeddingRequest, EmbeddingResponse,
    ProviderCapabilities, ProviderModelDiscoveryResult, ToolCall, ToolResult
)
from ..models.provider_types import ProviderType

from src.ida_compat import log

DEFAULT_PROVIDER_TIMEOUT_SECONDS = 90.0


class BaseLLMProvider(ABC):
    """
    Abstract base class for all LLM providers.
    Defines the interface that all providers must implement.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize provider with configuration from settings service.

        Args:
            config: Provider configuration dictionary containing:
                - name: Provider name
                - model: Model identifier
                - url: API endpoint URL
                - api_key: API key (if required)
                - max_tokens: Maximum tokens per request
                - timeout: Request timeout in seconds
                - disable_tls: Whether to disable TLS verification
                - provider_type: Type of provider (from ProviderType enum)
        """
        self.config = config
        self.name = config.get('name', 'Unknown')
        self.model = config.get('model', '')
        self.url = config.get('url', '')
        self.api_key = config.get('api_key', '')
        self.max_tokens = config.get('max_tokens', 4096)
        self.timeout = self._normalize_timeout_seconds(
            config.get('timeout', DEFAULT_PROVIDER_TIMEOUT_SECONDS)
        )
        self.disable_tls = config.get('disable_tls', False)
        self.provider_type = config.get('provider_type', 'openai_platform')

        # Rate limit retry configuration
        self.rate_limit_max_retries = config.get('rate_limit_max_retries', 50)
        self.rate_limit_min_delay = config.get('rate_limit_min_delay', 10.0)  # seconds
        self.rate_limit_max_delay = config.get('rate_limit_max_delay', 30.0)  # seconds

    @staticmethod
    def _normalize_timeout_seconds(value: Any) -> float:
        """Normalize provider timeout configuration to a positive float."""
        try:
            timeout = float(value)
            if timeout > 0:
                return timeout
        except (TypeError, ValueError):
            pass
        return DEFAULT_PROVIDER_TIMEOUT_SECONDS

    def _persist_oauth_api_key(self, api_key: str) -> bool:
        """Persist an updated OAuth credential blob back to the provider settings row."""
        current_api_key = self.config.get('api_key', '')
        if not api_key or api_key == current_api_key:
            return False

        try:
            from ..settings_service import SettingsService

            settings_service = SettingsService()
            provider_id = self.config.get('id')
            updated = False

            if provider_id is not None:
                updated = settings_service.update_llm_provider(int(provider_id), api_key=api_key)

            if not updated and self.name:
                updated = settings_service.update_llm_provider_api_key_by_name(self.name, api_key)

            if not updated:
                log.log_warn(
                    f"Unable to persist refreshed OAuth credentials for provider '{self.name}': provider not found"
                )
                return False

            self.api_key = api_key
            self.config['api_key'] = api_key
            log.log_info(f"Persisted refreshed OAuth credentials for provider '{self.name}'")
            return True
        except Exception as e:
            log.log_warn(f"Failed to persist refreshed OAuth credentials for provider '{self.name}': {e}")
            return False

    # ===================================================================
    # Rate Limit Retry Mechanism
    # ===================================================================

    async def _with_rate_limit_retry(self, operation_callable, *args, **kwargs):
        """
        Wrapper that retries an async operation when rate limit errors occur.

        This method implements exponential backoff with random jitter for rate limit errors.
        It will retry up to rate_limit_max_retries times, waiting between
        rate_limit_min_delay and rate_limit_max_delay seconds between attempts.

        Args:
            operation_callable: Async callable to execute (e.g., self._chat_completion_impl)
            *args: Positional arguments to pass to operation_callable
            **kwargs: Keyword arguments to pass to operation_callable

        Returns:
            Result from operation_callable

        Raises:
            RateLimitError: If max retries exceeded
            Other exceptions: Propagated as-is from operation_callable
        """
        attempt = 0

        while attempt < self.rate_limit_max_retries:
            try:
                # Execute the operation
                result = await operation_callable(*args, **kwargs)
                return result

            except RateLimitError as e:
                attempt += 1

                if attempt >= self.rate_limit_max_retries:
                    log.log_error(
                        f"Rate limit retry exhausted after {attempt} attempts for {self.name}. "
                        f"Giving up on this request."
                    )
                    raise RateLimitError(
                        f"Rate limit exceeded after {attempt} retries: {e}"
                    )

                # Calculate random delay between min and max
                delay = random.uniform(self.rate_limit_min_delay, self.rate_limit_max_delay)

                log.log_warn(
                    f"Rate limit error on attempt {attempt}/{self.rate_limit_max_retries} "
                    f"for {self.name}. Retrying in {delay:.1f} seconds... Error: {e}"
                )

                # Wait before retrying
                await asyncio.sleep(delay)

            except Exception as e:
                # Non-rate-limit errors are propagated immediately
                raise

        # This should never be reached due to the raise in the loop, but just in case
        raise RateLimitError(f"Rate limit retry mechanism failed unexpectedly")

    async def _with_rate_limit_retry_stream(self, operation_callable, *args, **kwargs) -> AsyncGenerator:
        """
        Wrapper that retries a streaming async operation when rate limit errors occur.

        This method implements exponential backoff with random jitter for rate limit errors
        in streaming contexts. It will retry up to rate_limit_max_retries times.

        Args:
            operation_callable: Async generator callable to execute (e.g., self._chat_completion_stream_impl)
            *args: Positional arguments to pass to operation_callable
            **kwargs: Keyword arguments to pass to operation_callable

        Yields:
            Items from operation_callable async generator

        Raises:
            RateLimitError: If max retries exceeded
            Other exceptions: Propagated as-is from operation_callable
        """
        attempt = 0

        while attempt < self.rate_limit_max_retries:
            try:
                # Execute the streaming operation
                async for item in operation_callable(*args, **kwargs):
                    yield item

                # If we successfully complete the stream, we're done
                return

            except RateLimitError as e:
                attempt += 1

                if attempt >= self.rate_limit_max_retries:
                    log.log_error(
                        f"Rate limit retry exhausted after {attempt} attempts for {self.name}. "
                        f"Giving up on this streaming request."
                    )
                    raise RateLimitError(
                        f"Rate limit exceeded after {attempt} retries: {e}"
                    )

                # Calculate random delay between min and max
                delay = random.uniform(self.rate_limit_min_delay, self.rate_limit_max_delay)

                log.log_warn(
                    f"Rate limit error on streaming attempt {attempt}/{self.rate_limit_max_retries} "
                    f"for {self.name}. Retrying in {delay:.1f} seconds... Error: {e}"
                )

                # Wait before retrying
                await asyncio.sleep(delay)

            except Exception as e:
                # Non-rate-limit errors are propagated immediately
                raise

        # This should never be reached due to the raise in the loop, but just in case
        raise RateLimitError(f"Rate limit retry mechanism failed unexpectedly for streaming")

    @abstractmethod
    async def chat_completion(self, request: ChatRequest,
                            native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> ChatResponse:
        """
        Generate a chat completion (non-streaming).

        Args:
            request: Chat completion request
            native_message_callback: Optional callback for provider-native message updates
                                   Signature: callback(native_message: Dict[str, Any], provider_type: ProviderType)

        Returns:
            Chat completion response

        Raises:
            APIProviderError: On API errors
            AuthenticationError: On authentication failures
            RateLimitError: On rate limit exceeded
            NetworkError: On network issues
        """
        pass

    @abstractmethod
    async def chat_completion_stream(self, request: ChatRequest,
                                   native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> AsyncGenerator[ChatResponse, None]:
        """
        Generate a streaming chat completion.

        Args:
            request: Chat completion request (with stream=True)
            native_message_callback: Optional callback for provider-native message updates
                                   Signature: callback(native_message: Dict[str, Any], provider_type: ProviderType)

        Yields:
            Partial chat completion responses

        Raises:
            APIProviderError: On API errors
            AuthenticationError: On authentication failures
            RateLimitError: On rate limit exceeded
            NetworkError: On network issues
        """
        pass

    @abstractmethod
    async def generate_embeddings(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """
        Generate text embeddings.

        Args:
            request: Embedding generation request

        Returns:
            Embedding response with vectors

        Raises:
            APIProviderError: On API errors
            AuthenticationError: On authentication failures
            RateLimitError: On rate limit exceeded
            NetworkError: On network issues
            NotImplementedError: If provider doesn't support embeddings
        """
        pass

    @abstractmethod
    async def test_connection(self) -> bool:
        """
        Test connectivity to the provider.

        Returns:
            True if connection successful, False otherwise
        """
        pass

    @abstractmethod
    def get_capabilities(self) -> ProviderCapabilities:
        """
        Get provider capabilities and supported features.

        Returns:
            Provider capabilities object
        """
        pass

    async def discover_available_models(self) -> ProviderModelDiscoveryResult:
        """
        Discover available models for this provider.

        Providers with live model discovery support should override this method.
        """
        provider_type = self.get_provider_type()
        return ProviderModelDiscoveryResult.failure_result(
            f"Live model discovery is not supported for {provider_type.display_name}."
        )

    @abstractmethod
    def get_provider_type(self) -> ProviderType:
        """
        Get the provider type for this provider.

        Returns:
            ProviderType enum value
        """
        pass

    # ===================================================================
    # Tool Support Methods
    # ===================================================================

    def supports_tools(self) -> bool:
        """
        Check if this provider supports tool calling.

        Returns:
            True if provider supports tools, False otherwise
        """
        capabilities = self.get_capabilities()
        return capabilities.supports_tools

    def prepare_tool_enabled_request(self, request: ChatRequest, tools: List[Dict[str, Any]]) -> ChatRequest:
        """
        Prepare a chat request with tool definitions enabled.

        Args:
            request: Original chat request
            tools: List of tool definitions in OpenAI format

        Returns:
            Modified chat request with tools enabled

        Note:
            Default implementation adds tools to request. Providers can override
            for provider-specific tool formatting.
        """
        if not self.supports_tools():
            return request

        # Create a copy of the request with tools added
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
            user=request.user
        )

        return tool_request

    def parse_tool_calls(self, response: ChatResponse) -> List[ToolCall]:
        """
        Parse tool calls from a chat response.

        Args:
            response: Chat response that may contain tool calls

        Returns:
            List of parsed tool calls

        Note:
            Default implementation returns response.tool_calls if present.
            Providers can override for provider-specific parsing.
        """
        if response.tool_calls:
            return response.tool_calls
        return []

    def get_stop_reason(self, response: ChatResponse) -> str:
        """
        Get the stop reason from a chat response.

        Args:
            response: Chat response

        Returns:
            Stop reason string ("stop", "tool_calls", "length", etc.)
        """
        return response.finish_reason

    def format_tool_results_for_continuation(self, tool_calls: List[ToolCall], tool_results: List[str]) -> List[Dict[str, Any]]:
        """
        Format tool execution results for LLM conversation continuation.

        Args:
            tool_calls: Original tool calls from LLM
            tool_results: Results from tool execution

        Returns:
            List of message dictionaries for LLM continuation

        Note:
            Default implementation creates tool messages in OpenAI format.
            Providers can override for provider-specific formatting.
        """
        messages = []

        for tool_call, result in zip(tool_calls, tool_results):
            messages.append({
                "role": "tool",
                "content": result,
                "tool_call_id": tool_call.id,
                "name": tool_call.name
            })

        return messages

    def has_tool_capability_changed(self, tools: List[Dict[str, Any]]) -> bool:
        """
        Check if tool capability requirements have changed.

        Args:
            tools: List of tool definitions

        Returns:
            True if provider needs to update tool capabilities
        """
        # Default implementation: no capability changes needed
        return False

    # ===================================================================
    # Token Counting Methods
    # ===================================================================

    async def count_tokens(self, request: ChatRequest) -> int:
        """
        Count tokens for a potential chat request.

        This method estimates the token count for messages, system prompt,
        and tools before sending to the API. Providers should override
        with native token counting when available.

        Args:
            request: Chat request to count tokens for

        Returns:
            Estimated token count

        Note:
            Default implementation uses character-based approximation
            (~4 characters per token for English text). This is a rough
            estimate and providers should override with accurate counting.
        """
        total_chars = 0

        # Count message content
        for message in request.messages:
            if message.content:
                total_chars += len(message.content)

            # Count tool calls in message
            if message.tool_calls:
                for tc in message.tool_calls:
                    total_chars += len(tc.name or '')
                    total_chars += len(tc.arguments or '')

        # Count tools definitions (rough estimate)
        if request.tools:
            import json
            try:
                tools_str = json.dumps(request.tools)
                total_chars += len(tools_str)
            except (TypeError, ValueError):
                # Fallback: estimate 500 chars per tool
                total_chars += len(request.tools) * 500

        # Convert to tokens (~4 chars per token for English)
        estimated_tokens = total_chars // 4

        log.log_debug(f"Token estimate for {self.name}: ~{estimated_tokens} tokens ({total_chars} chars)")

        return estimated_tokens

    def estimate_tokens_for_text(self, text: str) -> int:
        """
        Estimate token count for a single text string.

        Args:
            text: Text to estimate tokens for

        Returns:
            Estimated token count
        """
        if not text:
            return 0
        # ~4 characters per token for English text
        return len(text) // 4

    def validate_config(self) -> bool:
        """
        Validate provider configuration.

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If configuration is invalid
        """
        if not self.name:
            raise ValueError("Provider name is required")
        if not self.model:
            raise ValueError("Model is required")
        if not self.url:
            raise ValueError("URL is required")

        return True

    def __str__(self) -> str:
        """String representation of provider"""
        return f"{self.__class__.__name__}(name='{self.name}', model='{self.model}')"

    def __repr__(self) -> str:
        """Detailed string representation"""
        return (f"{self.__class__.__name__}("
                f"name='{self.name}', "
                f"model='{self.model}', "
                f"url='{self.url}', "
                f"provider_type='{self.provider_type}')")


class LLMProviderError(Exception):
    """Base exception for LLM provider errors"""
    pass


class APIProviderError(LLMProviderError):
    """General API provider error"""
    pass


class AuthenticationError(LLMProviderError):
    """Authentication/authorization error"""
    pass


class RateLimitError(LLMProviderError):
    """Rate limit exceeded error"""
    pass


class NetworkError(LLMProviderError):
    """Network connectivity error"""
    pass
