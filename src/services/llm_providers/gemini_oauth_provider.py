#!/usr/bin/env python3

"""
Gemini OAuth Provider - OAuth authentication for Gemini CLI subscriptions

This provider uses OAuth authentication to access Google Gemini via the
Code Assist proxy (cloudcode-pa.googleapis.com). It uses the native Gemini
API format (contents/parts), NOT OpenAI-compatible format.

Key Features:
- OAuth authentication (no API key required)
- Automatic token refresh
- Native Gemini API format (contents[{role, parts[{text}]}])
- Code Assist proxy wrapping/unwrapping
- Streaming via ?alt=sse
- Function/tool calling support (Gemini format)
- Rate limiting with exponential backoff on 429
"""

import asyncio
import json
import random
import time
import uuid
from typing import List, Dict, Any, AsyncGenerator, Optional, Callable

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    aiohttp = None
    AIOHTTP_AVAILABLE = False

from .base_provider import (
    BaseLLMProvider, APIProviderError, AuthenticationError,
    RateLimitError, NetworkError
)
from ..models.llm_models import (
    ChatRequest, ChatResponse, EmbeddingRequest, EmbeddingResponse,
    ChatMessage, MessageRole, ToolCall, ToolResult, Usage, ProviderCapabilities,
    ProviderModelDiscoveryResult
)
from ..models.provider_types import ProviderType

from src.ida_compat import log


# ============================================================================
# Constants
# ============================================================================

CODE_ASSIST_ENDPOINT = "https://cloudcode-pa.googleapis.com"
CODE_ASSIST_API_VERSION = "v1internal"

# Synthetic thought signature used when the original is unavailable
SYNTHETIC_THOUGHT_SIGNATURE = "skip_thought_signature_validator"

# Rate limiting
MIN_REQUEST_INTERVAL_S = 2.0
MAX_RATE_LIMIT_BACKOFF_S = 60.0
INITIAL_RATE_LIMIT_BACKOFF_S = 5.0

DEFAULT_MODEL = "gemini-2.5-flash"

_CLI_VISIBLE_AUTO_MODELS = [
    "auto-gemini-3",
    "auto-gemini-2.5",
]

_CLI_VISIBLE_PREVIEW_MODELS = [
    "gemini-3.1-flash-lite-preview",
    "gemini-3.1-pro-preview",
    "gemini-3-pro-preview",
    "gemini-3-flash-preview",
]

_CLI_VISIBLE_STABLE_MODELS = [
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
]

_CLI_PREVIEW_MODELS = set(_CLI_VISIBLE_PREVIEW_MODELS + ["auto-gemini-3"])


class GeminiOAuthProvider(BaseLLMProvider):
    """
    Google Gemini OAuth Provider - Routes requests through the Code Assist proxy.

    Uses OAuth authentication for Google Gemini CLI subscriptions.
    All API requests go through cloudcode-pa.googleapis.com/v1internal:{action}.
    Uses native Gemini API format (contents/parts), NOT OpenAI-compatible.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize Gemini OAuth provider"""
        super().__init__(config)

        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp package required for Gemini OAuth provider")

        self._credentials = None
        self._last_request_time = 0.0

        # Generate session ID matching Gemini CLI format
        self._session_id = self._generate_session_id()

        # Parse OAuth credentials from api_key field (JSON format)
        api_key = config.get('api_key', '')
        if api_key:
            try:
                from .oauth_gemini_utils import parse_credentials_json
                self._credentials = parse_credentials_json(api_key)
                if self._credentials:
                    log.log_info("Loaded Gemini OAuth credentials from api_key field")
            except Exception as e:
                log.log_warn(f"Failed to parse Gemini OAuth credentials: {e}")

        if not self.model:
            self.model = DEFAULT_MODEL

        log.log_info(f"Gemini OAuth provider initialized with model: {self.model}")

    # =========================================================================
    # Token Management
    # =========================================================================

    def is_authenticated(self) -> bool:
        """Check if valid OAuth credentials exist"""
        return self._credentials is not None and bool(self._credentials.get("access_token"))

    async def _ensure_valid_token(self) -> str:
        """Ensure we have a valid access token, refreshing if needed"""
        if self._credentials is None:
            raise AuthenticationError(
                "Not authenticated. Please authenticate via Settings > Edit Provider > Authenticate."
            )

        from .oauth_gemini_utils import is_token_expired, refresh_access_token

        if is_token_expired(self._credentials):
            log.log_info("Gemini access token expired, refreshing...")

            refresh_token = self._credentials.get("refresh_token")
            if not refresh_token:
                raise AuthenticationError(
                    "No refresh token available. Please re-authenticate."
                )

            try:
                tokens = await refresh_access_token(refresh_token)

                expires_at = time.time() + tokens.get("expires_in", 3600)
                self._credentials["access_token"] = tokens["access_token"]
                if tokens.get("refresh_token"):
                    self._credentials["refresh_token"] = tokens["refresh_token"]
                self._credentials["expires_at"] = expires_at
                self._persist_oauth_api_key(json.dumps(self._credentials))

                log.log_info("Gemini access token refreshed successfully")

            except Exception as e:
                log.log_error(f"Gemini token refresh failed: {e}")
                self._credentials = None
                raise AuthenticationError(
                    "Session expired. Please re-authenticate via Settings > Edit Provider > Authenticate."
                )

        return self._credentials["access_token"]

    # =========================================================================
    # Request Headers & Rate Limiting
    # =========================================================================

    async def _get_headers(self) -> Dict[str, str]:
        """Get request headers with valid OAuth token"""
        access_token = await self._ensure_valid_token()

        import platform
        os_name = platform.system().lower()
        if "linux" in os_name:
            plat = "linux"
        elif "darwin" in os_name:
            plat = "darwin"
        elif "win" in os_name:
            plat = "win32"
        else:
            plat = os_name

        machine = platform.machine().lower()
        if machine in ("amd64", "x86_64"):
            arch = "x86_64"
        elif machine in ("aarch64", "arm64"):
            arch = "arm64"
        else:
            arch = machine

        return {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "User-Agent": f"GeminiCLI/1.0.0/{self.model} ({plat}; {arch})",
        }

    async def _enforce_rate_limit(self):
        """Enforce minimum interval between API requests"""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < MIN_REQUEST_INTERVAL_S and self._last_request_time > 0:
            wait = MIN_REQUEST_INTERVAL_S - elapsed
            log.log_debug(f"Rate limiting: waiting {wait:.1f}s before next request")
            await asyncio.sleep(wait)
        self._last_request_time = time.time()

    def _create_client_session(
        self,
        timeout: Optional["aiohttp.ClientTimeout"] = None,
    ) -> "aiohttp.ClientSession":
        """Create an aiohttp session honoring the provider's proxy settings."""
        bypass_proxy = self.config.get("bypass_proxy", False)
        if timeout is None:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
        return aiohttp.ClientSession(timeout=timeout, trust_env=not bypass_proxy)

    def _get_project_id(self) -> str:
        """Get the Code Assist project ID discovered during OAuth setup."""
        if not self._credentials:
            return ""
        project_id = self._credentials.get("project_id", "")
        return project_id.strip() if isinstance(project_id, str) else ""

    def _get_method_url(self, method: str) -> str:
        """Build a Code Assist RPC URL."""
        return f"{CODE_ASSIST_ENDPOINT}/{CODE_ASSIST_API_VERSION}:{method}"

    @staticmethod
    def _is_preview_model(model_id: str) -> bool:
        """Check whether a model ID is part of the preview catalog."""
        return model_id in _CLI_PREVIEW_MODELS or model_id.endswith("-preview")

    @classmethod
    def _has_preview_access_from_buckets(cls, buckets: List[Dict[str, Any]]) -> bool:
        """Infer preview access from Code Assist quota buckets."""
        for bucket in buckets:
            if not isinstance(bucket, dict):
                continue
            model_id = bucket.get("modelId")
            if isinstance(model_id, str) and cls._is_preview_model(model_id):
                return True
        return False

    @classmethod
    def _build_visible_catalog(cls, has_preview_access: bool) -> List[str]:
        """Build the Gemini CLI-style visible model catalog for the modal."""
        models: List[str] = []
        if has_preview_access:
            models.extend(_CLI_VISIBLE_AUTO_MODELS)
            models.extend(_CLI_VISIBLE_PREVIEW_MODELS)
        else:
            models.append("auto-gemini-2.5")
        models.extend(_CLI_VISIBLE_STABLE_MODELS)
        return models

    # =========================================================================
    # Message Translation - Gemini Native Format
    # =========================================================================

    def _translate_messages(self, messages: List[ChatMessage]) -> Dict[str, Any]:
        """
        Translate ChatMessage list to Gemini native format.
        Returns dict with 'contents' and optionally 'systemInstruction'.
        """
        result = {}
        contents = []

        for i, message in enumerate(messages):
            if message.role == MessageRole.SYSTEM:
                # System message -> systemInstruction (single, outside contents)
                if message.content:
                    result["systemInstruction"] = {
                        "parts": [{"text": message.content}]
                    }
                continue

            if message.role == MessageRole.USER:
                if message.content:
                    contents.append({
                        "role": "user",
                        "parts": [{"text": message.content}]
                    })
                continue

            if message.role == MessageRole.ASSISTANT:
                parts = []

                # Check for tool calls first
                if message.tool_calls:
                    for tc in message.tool_calls:
                        args = tc.arguments
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except json.JSONDecodeError:
                                args = {"input": args}

                        fc_part = {
                            "thoughtSignature": SYNTHETIC_THOUGHT_SIGNATURE,
                            "functionCall": {
                                "name": tc.name or "",
                                "args": args if isinstance(args, dict) else {}
                            }
                        }
                        parts.append(fc_part)

                    # Also add text if present
                    if message.content:
                        parts.append({"text": message.content})

                elif message.content:
                    parts.append({"text": message.content})

                if parts:
                    contents.append({"role": "model", "parts": parts})
                continue

            if message.role == MessageRole.TOOL:
                # Batch consecutive tool messages into a single user turn
                # with functionResponse parts
                tool_parts = []

                # Process this message
                func_name = self._lookup_function_name(messages, message.tool_call_id)
                fr = {
                    "functionResponse": {
                        "name": func_name,
                        "response": {
                            "output": message.content if message.content else "(no output)"
                        }
                    }
                }
                if message.tool_call_id:
                    fr["functionResponse"]["id"] = message.tool_call_id
                tool_parts.append(fr)

                # Look ahead for consecutive tool messages
                j = i + 1
                while j < len(messages) and messages[j].role == MessageRole.TOOL:
                    next_msg = messages[j]
                    fn = self._lookup_function_name(messages, next_msg.tool_call_id)
                    next_fr = {
                        "functionResponse": {
                            "name": fn,
                            "response": {
                                "output": next_msg.content if next_msg.content else "(no output)"
                            }
                        }
                    }
                    if next_msg.tool_call_id:
                        next_fr["functionResponse"]["id"] = next_msg.tool_call_id
                    tool_parts.append(next_fr)
                    j += 1

                if tool_parts:
                    contents.append({"role": "user", "parts": tool_parts})

        result["contents"] = contents
        return result

    def _lookup_function_name(self, messages: List[ChatMessage], tool_call_id: Optional[str]) -> str:
        """Look up function name for a tool call ID from previous assistant messages"""
        if not tool_call_id:
            return "function"

        for msg in messages:
            if msg.role != MessageRole.ASSISTANT or not msg.tool_calls:
                continue
            for tc in msg.tool_calls:
                if tc.id == tool_call_id:
                    return tc.name or "function"
        return "function"

    def _translate_tools(self, tools: Optional[List[Dict[str, Any]]]) -> Optional[List[Dict[str, Any]]]:
        """Translate OpenAI-format tools to Gemini format"""
        if not tools:
            return None

        declarations = []
        for tool in tools:
            if tool.get("type") != "function":
                continue
            function = tool.get("function", {})
            decl = {
                "name": function.get("name", ""),
                "description": function.get("description", ""),
            }
            parameters = function.get("parameters")
            if parameters:
                decl["parametersJsonSchema"] = parameters
            declarations.append(decl)

        if not declarations:
            return None

        return [{"functionDeclarations": declarations}]

    # =========================================================================
    # Request Wrapping / Response Unwrapping
    # =========================================================================

    def _wrap_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Wrap a Gemini API request in the Code Assist envelope"""
        payload["session_id"] = self._session_id

        project_id = ""
        if self._credentials:
            project_id = self._credentials.get("project_id", "")

        return {
            "model": self.model,
            "project": project_id,
            "user_prompt_id": str(uuid.uuid4()),
            "request": payload,
        }

    def _unwrap_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Unwrap a Code Assist response envelope"""
        if isinstance(data.get("response"), dict):
            return data["response"]
        return data

    # =========================================================================
    # Response Parsing
    # =========================================================================

    def _parse_gemini_response(self, response_data: Dict[str, Any]):
        """
        Parse Gemini response into text content, tool calls, and finish reason.
        Returns (text_content, tool_calls, finish_reason)
        """
        text_content = ""
        tool_calls = []
        finish_reason = "stop"

        candidates = response_data.get("candidates", [])
        if not candidates:
            return text_content, tool_calls, finish_reason

        first_candidate = candidates[0]
        content = first_candidate.get("content", {})
        parts = content.get("parts", [])

        for part in parts:
            if "text" in part:
                text_content += part["text"]

            if "functionCall" in part:
                func_call = part["functionCall"]
                tc = ToolCall(
                    id=f"call_{uuid.uuid4().hex[:24]}",
                    name=func_call.get("name", ""),
                    arguments=func_call.get("args", {})
                )
                tool_calls.append(tc)
                finish_reason = "tool_calls"

        # Only check Gemini finish reason if no function calls detected
        # (Gemini returns STOP even when making function calls)
        if not tool_calls and first_candidate.get("finishReason"):
            reason = first_candidate["finishReason"]
            if reason == "MAX_TOKENS":
                finish_reason = "length"
            elif reason == "STOP":
                finish_reason = "stop"

        return text_content, tool_calls, finish_reason

    # =========================================================================
    # Chat Completion
    # =========================================================================

    async def chat_completion(self, request: ChatRequest,
                            native_message_callback: Optional[Callable[[Dict, ProviderType], None]] = None) -> ChatResponse:
        """Generate non-streaming chat completion"""
        if not self.is_authenticated():
            raise AuthenticationError(
                "Not authenticated. Please go to Settings > Edit Provider > Authenticate "
                "to sign in with your Gemini CLI subscription."
            )

        return await self._with_rate_limit_retry(self._chat_completion_impl, request, native_message_callback)

    async def _chat_completion_impl(self, request: ChatRequest,
                            native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> ChatResponse:
        """Internal implementation of chat completion"""
        await self._enforce_rate_limit()

        headers = await self._get_headers()

        # Build request payload
        payload = self._build_request_payload(request)
        wrapped = self._wrap_request(payload)

        url = self._get_method_url("generateContent")

        async with self._create_client_session() as session:
            async with session.post(
                url,
                json=wrapped,
                headers=headers,
                ssl=not self.disable_tls,
            ) as response:
                if response.status == 401:
                    raise AuthenticationError("Authentication failed. Please re-authenticate.")
                if response.status == 429:
                    raise RateLimitError("Rate limit exceeded")
                if not response.ok:
                    text = await response.text()
                    raise APIProviderError(f"API error {response.status}: {text}")

                response_data = await response.json()

        response_data = self._unwrap_response(response_data)
        text_content, tool_calls, finish_reason = self._parse_gemini_response(response_data)

        usage = Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0)

        return ChatResponse(
            content=text_content,
            model=self.model,
            usage=usage,
            tool_calls=tool_calls if tool_calls else None,
            finish_reason=finish_reason,
        )

    # =========================================================================
    # Streaming Chat Completion
    # =========================================================================

    async def chat_completion_stream(self, request: ChatRequest,
                                   native_message_callback: Optional[Callable[[Dict, ProviderType], None]] = None) -> AsyncGenerator[ChatResponse, None]:
        """Generate streaming chat completion"""
        if not self.is_authenticated():
            raise AuthenticationError(
                "Not authenticated. Please go to Settings > Edit Provider > Authenticate "
                "to sign in with your Gemini CLI subscription."
            )

        async for response in self._with_rate_limit_retry_stream(self._chat_completion_stream_impl, request, native_message_callback):
            yield response

    async def _chat_completion_stream_impl(self, request: ChatRequest,
                                   native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None) -> AsyncGenerator[ChatResponse, None]:
        """Internal implementation of streaming chat completion"""
        await self._enforce_rate_limit()

        headers = await self._get_headers()

        payload = self._build_request_payload(request)
        wrapped = self._wrap_request(payload)

        # Streaming via ?alt=sse
        url = f"{self._get_method_url('streamGenerateContent')}?alt=sse"

        accumulated_content = ""
        tool_calls = []

        async with self._create_client_session() as session:
            async with session.post(
                url,
                json=wrapped,
                headers=headers,
                ssl=not self.disable_tls,
            ) as response:
                if response.status == 401:
                    raise AuthenticationError("Authentication failed. Please re-authenticate.")
                if response.status == 429:
                    raise RateLimitError("Rate limit exceeded")
                if not response.ok:
                    text = await response.text()
                    raise APIProviderError(f"API error {response.status}: {text}")

                # Parse SSE: multi-line data blocks separated by empty lines
                buffered_lines = []

                async for line in response.content:
                    line = line.decode('utf-8').rstrip('\n').rstrip('\r')

                    if line.startswith("data: "):
                        buffered_lines.append(line[6:].strip())
                    elif line == "" and buffered_lines:
                        # Empty line = end of SSE block
                        try:
                            json_str = "\n".join(buffered_lines)
                            event = json.loads(json_str)
                            unwrapped = self._unwrap_response(event)

                            candidates = unwrapped.get("candidates", [])
                            if candidates:
                                first_candidate = candidates[0]
                                content = first_candidate.get("content", {})
                                parts = content.get("parts", [])

                                for part in parts:
                                    if "text" in part and part["text"]:
                                        text_delta = part["text"]
                                        accumulated_content += text_delta
                                        yield ChatResponse(
                                            content=text_delta,
                                            model=self.model,
                                            usage=Usage(0, 0, 0),
                                            is_streaming=True,
                                            finish_reason="incomplete"
                                        )

                                    if "functionCall" in part:
                                        func_call = part["functionCall"]
                                        tc = ToolCall(
                                            id=f"call_{uuid.uuid4().hex[:24]}",
                                            name=func_call.get("name", ""),
                                            arguments=func_call.get("args", {})
                                        )
                                        tool_calls.append(tc)

                        except json.JSONDecodeError:
                            log.log_debug("Skipping malformed SSE event")
                        buffered_lines.clear()

        # Final response
        if accumulated_content or tool_calls:
            yield ChatResponse(
                content="",
                model=self.model,
                usage=Usage(0, 0, 0),
                tool_calls=tool_calls if tool_calls else None,
                is_streaming=False,
                finish_reason="tool_calls" if tool_calls else "stop",
            )

    # =========================================================================
    # Request Building
    # =========================================================================

    def _build_request_payload(self, request: ChatRequest) -> Dict[str, Any]:
        """Build request payload in Gemini native format"""
        translated = self._translate_messages(request.messages)
        payload = {}

        payload["contents"] = translated.get("contents", [])

        if "systemInstruction" in translated:
            payload["systemInstruction"] = translated["systemInstruction"]

        # Add tools if present
        if request.tools:
            gemini_tools = self._translate_tools(request.tools)
            if gemini_tools:
                payload["tools"] = gemini_tools
                payload["toolConfig"] = {
                    "functionCallingConfig": {"mode": "AUTO"}
                }

        # Generation config
        max_tokens = min(request.max_tokens, self.max_tokens)
        if max_tokens > 0:
            payload["generationConfig"] = {"maxOutputTokens": max_tokens}

        return payload

    # =========================================================================
    # Embeddings (not supported)
    # =========================================================================

    async def generate_embeddings(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """Embeddings not supported by Gemini OAuth API"""
        raise APIProviderError("Embeddings are not supported by the Gemini OAuth API")

    # =========================================================================
    # Provider Interface
    # =========================================================================

    async def test_connection(self) -> bool:
        """Test OAuth token validity with a minimal request"""
        try:
            if not self.is_authenticated():
                return False

            await self._ensure_valid_token()

            headers = await self._get_headers()

            payload = {
                "contents": [{"role": "user", "parts": [{"text": "Test message. Please respond with 'OK'."}]}],
                "generationConfig": {"maxOutputTokens": 1}
            }
            wrapped = self._wrap_request(payload)

            url = self._get_method_url("generateContent")

            async with self._create_client_session() as session:
                async with session.post(
                    url,
                    json=wrapped,
                    headers=headers,
                    ssl=not self.disable_tls,
                ) as response:
                    if response.status == 401:
                        return False
                    return response.ok

        except Exception as e:
            log.log_error(f"Gemini OAuth connection test failed: {e}")
            return False

    def get_capabilities(self) -> ProviderCapabilities:
        """Get provider capabilities"""
        return ProviderCapabilities(
            supports_chat=True,
            supports_streaming=True,
            supports_tools=True,
            supports_embeddings=False,
            supports_vision=False,
            supports_model_discovery=True,
            max_tokens=self.max_tokens,
            models=[]
        )

    async def discover_available_models(self) -> ProviderModelDiscoveryResult:
        """Discover Gemini OAuth models via Code Assist quota and CLI catalog rules."""
        try:
            headers = await self._get_headers()
            project_id = self._get_project_id()
            if not project_id:
                return ProviderModelDiscoveryResult.failure_result(
                    "Gemini OAuth is missing its Code Assist project ID. Please re-authenticate."
                )

            request_body = {"project": project_id}
            quota_endpoint = self._get_method_url("retrieveUserQuota")

            async with self._create_client_session() as session:
                async with session.post(
                    quota_endpoint,
                    json=request_body,
                    headers=headers,
                    ssl=not self.disable_tls,
                ) as response:
                    if response.status == 401:
                        return ProviderModelDiscoveryResult.failure_result(
                            "Authentication failed. Please re-authenticate."
                        )
                    if not response.ok:
                        text = await response.text()
                        return ProviderModelDiscoveryResult.failure_result(
                            f"API error {response.status}: {text}"
                        )
                    payload = await response.json(content_type=None)

            buckets = payload.get("buckets")
            if not isinstance(buckets, list) or not buckets:
                return ProviderModelDiscoveryResult.failure_result(
                    "No available Gemini Code Assist models were found for this account."
                )

            has_preview_access = self._has_preview_access_from_buckets(buckets)
            models = self._build_visible_catalog(has_preview_access)
            return ProviderModelDiscoveryResult.success_result(
                models,
                source_label="quota+catalog",
            )

        except AuthenticationError as e:
            return ProviderModelDiscoveryResult.failure_result(str(e))
        except Exception as e:
            log.log_error(f"Gemini OAuth model discovery failed: {e}")
            return ProviderModelDiscoveryResult.failure_result(
                f"Model discovery failed: {str(e)}"
            )

    def get_provider_type(self) -> ProviderType:
        """Get the provider type"""
        return ProviderType.GEMINI_OAUTH

    def validate_config(self) -> bool:
        """Validate provider configuration"""
        if not self.name:
            raise ValueError("Provider name is required")
        if not self.model:
            raise ValueError("Model is required")
        return True

    # =========================================================================
    # Utility
    # =========================================================================

    @staticmethod
    def _generate_session_id() -> str:
        """Generate session ID matching Gemini CLI format"""
        rand_id = random.randint(1_000_000_000_000_000, 9_999_999_999_999_999)
        return f"-{rand_id}"


# ============================================================================
# Provider Factory
# ============================================================================

from .provider_factory import ProviderFactory


class GeminiOAuthProviderFactory(ProviderFactory):
    """Factory for creating Gemini OAuth provider instances"""

    def create_provider(self, config: Dict[str, Any]) -> GeminiOAuthProvider:
        """Create Gemini OAuth provider instance"""
        return GeminiOAuthProvider(config)

    def supports_provider_type(self, provider_type: ProviderType) -> bool:
        """Check if this factory supports the provider type"""
        return provider_type == ProviderType.GEMINI_OAUTH
