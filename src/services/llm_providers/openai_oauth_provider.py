#!/usr/bin/env python3

"""
OpenAI Codex Provider - ChatGPT Pro/Plus OAuth authentication with Responses API

This provider enables using ChatGPT Pro/Plus subscriptions for API access
through the Codex Responses API endpoint, implementing the same protocol as
the official Codex CLI (codex-cli-rs).

CRITICAL Implementation Details:
- originator header MUST be "codex_cli_rs" (not "opencode")
- OpenAI-Beta header MUST include "responses=experimental"
- chatgpt-account-id header must be lowercase
- instructions MUST match the official Codex CLI prompt from GitHub
- stream MUST be true (API requires streaming)
- store MUST be false

Key Features:
- OAuth PKCE authentication with ChatGPT Pro/Plus
- OpenAI Responses API format translation
- Streaming support (required)
- Tool/function calling support
"""

import json
import time
from typing import AsyncGenerator, Dict, Any, List, Optional, Callable
from urllib.parse import urlencode

from .base_provider import (
    BaseLLMProvider,
    APIProviderError,
    AuthenticationError,
    RateLimitError,
    NetworkError,
    log
)
from ..models.llm_models import (
    ChatRequest, ChatResponse, ChatMessage, MessageRole,
    EmbeddingRequest, EmbeddingResponse,
    ProviderCapabilities, ProviderModelDiscoveryResult, ToolCall, Usage
)
from ..models.provider_types import ProviderType
from . import oauth_codex_utils as oauth

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


# API Configuration
CODEX_API_BASE_URL = "https://chatgpt.com/backend-api/codex"
CODEX_API_ENDPOINT = f"{CODEX_API_BASE_URL}/responses"
CODEX_MODELS_ENDPOINT = f"{CODEX_API_BASE_URL}/models"
# The client version format is "major.minor.point".
CODEX_MODELS_CLIENT_VERSION = "0.116.0"

# Official Codex CLI instructions (from openai/codex rust-v0.80.0)
# CRITICAL: The Codex API validates instructions match the official prompt.
# Custom instructions will be rejected with "Instructions are not valid".
CODEX_INSTRUCTIONS = """You are Codex, based on GPT-5. You are running as a coding agent in the Codex CLI on a user's computer.

## General

- When searching for text or files, prefer using `rg` or `rg --files` respectively because `rg` is much faster than alternatives like `grep`. (If the `rg` command is not found, then use alternatives.)

## Editing constraints

- Default to ASCII when editing or creating files. Only introduce non-ASCII or other Unicode characters when there is a clear justification and the file already uses them.
- Add succinct code comments that explain what is going on if code is not self-explanatory. You should not add comments like "Assigns the value to the variable", but a brief comment might be useful ahead of a complex code block that the user would otherwise have to spend time parsing out. Usage of these comments should be rare.
- Try to use apply_patch for single file edits, but it is fine to explore other options to make the edit if it does not work well. Do not use apply_patch for changes that are auto-generated (i.e. generating package.json or running a lint or format command like gofmt) or when scripting is more efficient (such as search and replacing a string across a codebase).
- You may be in a dirty git worktree.
    * NEVER revert existing changes you did not make unless explicitly requested, since these changes were made by the user.
    * If asked to make a commit or code edits and there are unrelated changes to your work or changes that you didn't make in those files, don't revert those changes.
    * If the changes are in files you've touched recently, you should read carefully and understand how you can work with the changes rather than reverting them.
    * If the changes are in unrelated files, just ignore them and don't revert them.
- Do not amend a commit unless explicitly requested to do so.
- While you are working, you might notice unexpected changes that you didn't make. If this happens, STOP IMMEDIATELY and ask the user how they would like to proceed.
- **NEVER** use destructive commands like `git reset --hard` or `git checkout --` unless specifically requested or approved by the user.

## Plan tool

When using the planning tool:
- Skip using the planning tool for straightforward tasks (roughly the easiest 25%).
- Do not make single-step plans.
- When you made a plan, update it after having performed one of the sub-tasks that you shared on the plan.

## Codex CLI harness, sandboxing, and approvals

The Codex CLI harness supports several different configurations for sandboxing and escalation approvals that the user can choose from.

Filesystem sandboxing defines which files can be read or written. The options for `sandbox_mode` are:
- **read-only**: The sandbox only permits reading files.
- **workspace-write**: The sandbox permits reading files, and editing files in `cwd` and `writable_roots`. Editing files in other directories requires approval.
- **danger-full-access**: No filesystem sandboxing - all commands are permitted.

Network sandboxing defines whether network can be accessed without approval. Options for `network_access` are:
- **restricted**: Requires approval
- **enabled**: No approval needed

Approvals are your mechanism to get user consent to run shell commands without the sandbox. Possible configuration options for `approval_policy` are
- **untrusted**: The harness will escalate most commands for user approval, apart from a limited allowlist of safe "read" commands.
- **on-failure**: The harness will allow all commands to run in the sandbox (if enabled), and failures will be escalated to the user for approval to run again without the sandbox.
- **on-request**: Commands will be run in the sandbox by default, and you can specify in your tool call if you want to escalate a command to run without sandboxing. (Note that this mode is not always available. If it is, you'll see parameters for it in the `shell` command description.)
- **never**: This is a non-interactive mode where you may NEVER ask the user for approval to run commands. Instead, you must always persist and work around constraints to solve the task for the user. You MUST do your utmost best to finish the task and validate your work before yielding. If this mode is paired with `danger-full-access`, take advantage of it to deliver the best outcome for the user. Further, in this mode, your default testing philosophy is overridden: Even if you don't see local patterns for testing, you may add tests and scripts to validate your work. Just remove them before yielding.

When you are running with `approval_policy == on-request`, and sandboxing enabled, here are scenarios where you'll need to request approval:
- You need to run a command that writes to a directory that requires it (e.g. running tests that write to /var)
- You need to run a GUI app (e.g., open/xdg-open/osascript) to open browsers or files.
- You are running sandboxed and need to run a command that requires network access (e.g. installing packages)
- If you run a command that is important to solving the user's query, but it fails because of sandboxing, rerun the command with approval. ALWAYS proceed to use the `sandbox_permissions` and `justification` parameters - do not message the user before requesting approval for the command.
- You are about to take a potentially destructive action such as an `rm` or `git reset` that the user did not explicitly ask for
- (for all of these, you should weigh alternative paths that do not require approval)

When `sandbox_mode` is set to read-only, you'll need to request approval for any command that isn't a read.

You will be told what filesystem sandboxing, network sandboxing, and approval mode are active in a developer or user message. If you are not told about this, assume that you are running with workspace-write, network sandboxing enabled, and approval on-failure.

Although they introduce friction to the user because your work is paused until the user responds, you should leverage them when necessary to accomplish important work. If the completing the task requires escalated permissions, Do not let these settings or the sandbox deter you from attempting to accomplish the user's task unless it is set to "never", in which case never ask for approvals.

When requesting approval to execute a command that will require escalated privileges:
  - Provide the `sandbox_permissions` parameter with the value `"require_escalated"`
  - Include a short, 1 sentence explanation for why you need escalated permissions in the justification parameter

## Special user requests

- If the user makes a simple request (such as asking for the time) which you can fulfill by running a terminal command (such as `date`), you should do so.
- If the user asks for a "review", default to a code review mindset: prioritise identifying bugs, risks, behavioural regressions, and missing tests. Findings must be the primary focus of the response - keep summaries or overviews brief and only after enumerating the issues. Present findings first (ordered by severity with file/line references), follow with open questions or assumptions, and offer a change-summary only as a secondary detail. If no findings are discovered, state that explicitly and mention any residual risks or testing gaps.

## Presenting your work and final message

You are producing plain text that will later be styled by the CLI. Follow these rules exactly. Formatting should make results easy to scan, but not feel mechanical. Use judgment to decide how much structure adds value.

- Default: be very concise; friendly coding teammate tone.
- Ask only when needed; suggest ideas; mirror the user's style.
- For substantial work, summarize clearly; follow final-answer formatting.
- Skip heavy formatting for simple confirmations.
- Don't dump large files you've written; reference paths only.
- No "save/copy this file" - User is on the same machine.
- Offer logical next steps (tests, commits, build) briefly; add verify steps if you couldn't do something.
- For code changes:
  * Lead with a quick explanation of the change, and then give more details on the context covering where and why a change was made. Do not start this explanation with "summary", just jump right in.
  * If there are natural next steps the user may want to take, suggest them at the end of your response. Do not make suggestions if there are no natural next steps.
  * When suggesting multiple options, use numeric lists for the suggestions so the user can quickly respond with a single number.
- The user does not command execution outputs. When asked to show the output of a command (e.g. `git show`), relay the important details in your answer or summarize the key lines so the user understands the result.

### Final answer structure and style guidelines

- Plain text; CLI handles styling. Use structure only when it helps scanability.
- Headers: optional; short Title Case (1-3 words) wrapped in **...**; no blank line before the first bullet; add only if they truly help.
- Bullets: use - ; merge related points; keep to one line when possible; 4-6 per list ordered by importance; keep phrasing consistent.
- Monospace: backticks for commands/paths/env vars/code ids and inline examples; use for literal keyword bullets; never combine with **.
- Code samples or multi-line snippets should be wrapped in fenced code blocks; include an info string as often as possible.
- Structure: group related bullets; order sections general -> specific -> supporting; for subsections, start with a bolded keyword bullet, then items; match complexity to the task.
- Tone: collaborative, concise, factual; present tense, active voice; self-contained; no "above/below"; parallel wording.
- Don'ts: no nested bullets/hierarchies; no ANSI codes; don't cram unrelated keywords; keep keyword lists short-wrap/reformat if long; avoid naming formatting styles in answers.
- Adaptation: code explanations -> precise, structured with code refs; simple tasks -> lead with outcome; big changes -> logical walkthrough + rationale + next actions; casual one-offs -> plain sentences, no headers/bullets.
- File References: When referencing files in your response, make sure to include the relevant start line and always follow the below rules:
  * Use inline code to make file paths clickable.
  * Each reference should have a stand alone path. Even if it's the same file.
  * Accepted: absolute, workspace-relative, a/ or b/ diff prefixes, or bare filename/suffix.
  * Line/column (1-based, optional): :line[:column] or #Lline[Ccolumn] (column defaults to 1).
  * Do not use URIs like file://, vscode://, or https://.
  * Do not provide range of lines
  * Examples: src/app.ts, src/app.ts:42, b/server/index.js#L10, C:\\repo\\project\\main.rs:12:5
"""


class OpenAIOAuthProvider(BaseLLMProvider):
    """
    OpenAI Codex provider using ChatGPT Pro/Plus OAuth authentication.

    Routes requests through the Codex Responses API endpoint, which uses
    a different format from the standard OpenAI Chat Completions API.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize provider with configuration.

        Args:
            config: Provider configuration including api_key (which contains
                   JSON-encoded OAuth credentials for this provider)
        """
        super().__init__(config)

        # OAuth state
        self._credentials: Optional[Dict[str, Any]] = None
        self._account_id: Optional[str] = None
        self._pending_pkce_verifier: Optional[str] = None
        self._pending_state: Optional[str] = None

        # Load credentials from api_key field (stored as JSON)
        self._load_credentials()

    def _load_credentials(self) -> None:
        """Load OAuth credentials from the api_key field."""
        if self.api_key:
            credentials = oauth.parse_credentials_json(self.api_key)
            if credentials:
                self._credentials = credentials
                self._account_id = credentials.get("account_id")
                log.log_debug(f"Loaded OAuth credentials for {self.name}")

    # ===================================================================
    # OAuth Authentication Methods
    # ===================================================================

    def start_authentication(self) -> str:
        """
        Start OAuth authentication by opening browser.

        Returns:
            The authorization URL that was opened
        """
        verifier, challenge = oauth.generate_pkce()
        state = oauth.generate_state()

        self._pending_pkce_verifier = verifier
        self._pending_state = state

        auth_url = oauth.open_auth_browser(challenge, state)
        log.log_info(f"Opened browser for OpenAI Codex OAuth authentication")

        return auth_url

    async def complete_authentication(self, auth_code: str) -> bool:
        """
        Complete OAuth authentication by exchanging code for tokens.

        Args:
            auth_code: Authorization code from the OAuth callback

        Returns:
            True if authentication successful

        Raises:
            AuthenticationError: If authentication fails
        """
        if not self._pending_pkce_verifier:
            raise AuthenticationError("No pending authentication. Call start_authentication() first.")

        try:
            # Exchange code for tokens
            tokens = await oauth.exchange_code_for_tokens(auth_code, self._pending_pkce_verifier)

            # Extract account ID for org subscriptions
            account_id = oauth.extract_account_id(tokens)

            # Store credentials
            self._credentials = {
                "access_token": tokens["access_token"],
                "refresh_token": tokens.get("refresh_token", ""),
                "expires_at": time.time() + tokens.get("expires_in", 3600),
                "account_id": account_id,
            }
            self._account_id = account_id

            # Update api_key field with credentials JSON
            self.api_key = oauth.create_credentials_json(tokens, account_id)
            self.config["api_key"] = self.api_key

            log.log_info(f"OpenAI Codex OAuth authentication successful")
            return True

        except Exception as e:
            log.log_error(f"OAuth authentication failed: {e}")
            raise AuthenticationError(f"OAuth authentication failed: {e}")
        finally:
            # Clear pending state
            self._pending_pkce_verifier = None
            self._pending_state = None

    async def _ensure_valid_token(self) -> str:
        """
        Ensure we have a valid access token, refreshing if needed.

        Returns:
            Valid access token

        Raises:
            AuthenticationError: If no valid credentials or refresh fails
        """
        if not self._credentials:
            raise AuthenticationError("Not authenticated. Please authenticate first.")

        # Check if token is expired (with 5-minute buffer)
        if oauth.is_token_expired(self._credentials, buffer_seconds=300):
            await self._refresh_tokens()

        return self._credentials["access_token"]

    async def _refresh_tokens(self) -> None:
        """
        Refresh the OAuth access token.

        Raises:
            AuthenticationError: If refresh fails
        """
        refresh_token = self._credentials.get("refresh_token")
        if not refresh_token:
            raise AuthenticationError("No refresh token available. Re-authentication required.")

        try:
            log.log_info("Refreshing OpenAI Codex access token...")
            tokens = await oauth.refresh_access_token(refresh_token)

            # Extract account ID (may be in new tokens)
            account_id = oauth.extract_account_id(tokens) or self._account_id

            # Update credentials
            self._credentials["access_token"] = tokens["access_token"]
            if "refresh_token" in tokens:
                self._credentials["refresh_token"] = tokens["refresh_token"]
            self._credentials["expires_at"] = time.time() + tokens.get("expires_in", 3600)
            self._credentials["account_id"] = account_id
            self._account_id = account_id

            self._persist_oauth_api_key(json.dumps(self._credentials))

            log.log_info("OpenAI Codex access token refreshed successfully")

        except Exception as e:
            log.log_error(f"Token refresh failed: {e}")
            raise AuthenticationError(f"Token refresh failed: {e}")

    def _get_headers(self, access_token: str) -> Dict[str, str]:
        """
        Build request headers for Codex API.

        CRITICAL: These headers must match what the official Codex CLI sends:
        - originator: "codex_cli_rs" (NOT "opencode")
        - OpenAI-Beta: "responses=experimental"
        - chatgpt-account-id: lowercase

        Args:
            access_token: OAuth access token

        Returns:
            Headers dictionary
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
            # CRITICAL: Codex-specific headers from codex-cli-rs
            "originator": "codex_cli_rs",  # MUST be codex_cli_rs, not opencode
            "OpenAI-Beta": "responses=experimental",  # Required for Responses API
            "accept": "text/event-stream",  # Accept streaming responses
        }

        # Add account ID header (lowercase!) for organization subscriptions
        if self._account_id:
            headers["chatgpt-account-id"] = self._account_id

        return headers

    def _get_model_discovery_headers(self, access_token: str) -> Dict[str, str]:
        """
        Build headers for Codex model discovery.

        The Codex app uses auth headers for the models endpoint, not the
        Responses API-specific headers required for `/responses`.
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
        }

        if self._account_id:
            headers["ChatGPT-Account-ID"] = self._account_id

        return headers

    def _get_api_base_url(self) -> str:
        """
        Resolve the effective Codex API base URL from the provider config.

        The modal passes unsaved URL edits in `self.url`. Respect those values
        so dialog-local testing does not silently fall back to the default
        ChatGPT backend URL.
        """
        configured_url = (self.url or "").strip().rstrip("/")
        if not configured_url:
            return CODEX_API_BASE_URL

        for suffix in ("/responses", "/models"):
            if configured_url.endswith(suffix):
                return configured_url[: -len(suffix)]

        return configured_url

    def _get_responses_endpoint(self) -> str:
        """Get the effective Responses API endpoint for this provider instance."""
        return f"{self._get_api_base_url()}/responses"

    def _get_models_endpoint(self) -> str:
        """Get the effective model discovery endpoint for this provider instance."""
        return f"{self._get_api_base_url()}/models"

    def _create_client_session(self, timeout: Optional["aiohttp.ClientTimeout"] = None) -> "aiohttp.ClientSession":
        """Create an aiohttp session honoring the provider's proxy settings."""
        bypass_proxy = self.config.get("bypass_proxy", False)
        if timeout is None:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
        return aiohttp.ClientSession(timeout=timeout, trust_env=not bypass_proxy)

    def _get_codex_client_version(self) -> Optional[str]:
        """
        Load the client version string used for Codex model discovery.

        Temporary test override for Codex model discovery.
        """
        return CODEX_MODELS_CLIENT_VERSION

    def _extract_model_ids(self, payload: Any) -> List[str]:
        """Extract model slugs from the Codex `/models` payload."""
        if not isinstance(payload, dict):
            return []

        models = payload.get("models")
        if not isinstance(models, list):
            return []

        ordered = []
        seen = set()
        for model in models:
            if not isinstance(model, dict):
                continue
            if model.get("supported_in_api") is False:
                continue

            slug = model.get("slug")
            if isinstance(slug, str) and slug and slug not in seen:
                seen.add(slug)
                ordered.append(slug)

        return ordered

    # ===================================================================
    # Message Translation Methods
    # ===================================================================

    def _translate_messages_to_input(self, messages: List[ChatMessage]) -> tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Translate ChatMessage list to OpenAI Responses API input format.

        The Codex API requires the official Codex CLI instructions verbatim,
        so system messages must NOT be appended to the instructions field.
        Instead, system messages are converted to developer messages in the input.

        Args:
            messages: List of ChatMessage objects

        Returns:
            Tuple of (input_items, instructions_text) - instructions is always None
        """
        input_items = []

        for msg in messages:
            if msg.role == MessageRole.SYSTEM:
                # System messages become developer messages in input
                input_items.append({
                    "role": "developer",
                    "content": [{"type": "input_text", "text": msg.content}]
                })

            elif msg.role == MessageRole.USER:
                # User messages use input_text content type
                input_items.append({
                    "role": "user",
                    "content": [{"type": "input_text", "text": msg.content}]
                })

            elif msg.role == MessageRole.ASSISTANT:
                if msg.tool_calls:
                    # Tool calls become separate function_call items
                    for tc in msg.tool_calls:
                        input_items.append({
                            "type": "function_call",
                            "call_id": tc.id,
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments) if isinstance(tc.arguments, dict) else tc.arguments
                        })
                elif msg.content:
                    # Regular assistant text uses output_text content type
                    input_items.append({
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": msg.content}]
                    })

            elif msg.role == MessageRole.TOOL:
                # Tool results become function_call_output items
                input_items.append({
                    "type": "function_call_output",
                    "call_id": msg.tool_call_id,
                    "output": msg.content
                })

        return input_items, None

    def _translate_tools_to_format(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Translate tool definitions to Responses API format.

        Args:
            tools: Tool definitions in OpenAI Chat Completions format

        Returns:
            Tool definitions in Responses API format
        """
        responses_tools = []

        for tool in tools:
            if tool.get("type") == "function":
                func = tool.get("function", {})
                responses_tools.append({
                    "type": "function",
                    "name": func.get("name", ""),
                    "description": func.get("description", ""),
                    "parameters": func.get("parameters", {}),
                    "strict": func.get("strict")
                })

        return responses_tools

    def _parse_response_content(self, response_data: Dict[str, Any]) -> tuple[str, List[ToolCall], str]:
        """
        Parse response content from Responses API format.

        Args:
            response_data: Response from API

        Returns:
            Tuple of (text_content, tool_calls, finish_reason)
        """
        text_content = ""
        tool_calls = []
        finish_reason = "stop"

        output = response_data.get("output", [])

        for item in output:
            item_type = item.get("type", "")

            if item_type == "message":
                # Extract text content from message
                content = item.get("content", [])
                for part in content:
                    if part.get("type") == "output_text":
                        text_content += part.get("text", "")

            elif item_type == "function_call":
                # Parse function call
                try:
                    arguments = item.get("arguments", "{}")
                    if isinstance(arguments, str):
                        arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {}

                tool_call = ToolCall(
                    id=item.get("call_id", item.get("id", "")),
                    name=item.get("name", ""),
                    arguments=arguments
                )
                tool_calls.append(tool_call)
                finish_reason = "tool_calls"

        # Check status for finish reason
        status = response_data.get("status", "completed")
        if status == "incomplete":
            finish_reason = response_data.get("incomplete_details", {}).get("reason", "length")

        return text_content, tool_calls, finish_reason

    async def _collect_streaming_response(self, response) -> Dict[str, Any]:
        """
        Collect a streaming SSE response into a complete response dict.

        The Codex API requires stream=true, so we must parse SSE events
        and collect the final response.

        Args:
            response: aiohttp response object

        Returns:
            Complete response data dict
        """
        final_response = {}

        async for line in response.content:
            line = line.decode('utf-8').strip()

            if not line:
                continue

            # SSE format: "data: {...}"
            if line.startswith("data: "):
                data_str = line[6:]

                if data_str == "[DONE]":
                    break

                try:
                    event_data = json.loads(data_str)
                except json.JSONDecodeError:
                    continue

                event_type = event_data.get("type", "")

                # Capture the final response
                if event_type in ("response.completed", "response.done"):
                    final_response = event_data.get("response", {})

        return final_response

    def _build_openai_native_message(
        self,
        content: str,
        tool_calls: Optional[List[ToolCall]],
        model: str,
        streaming: bool = True,
    ) -> Dict[str, Any]:
        """Build OpenAI-style native message for persistence."""
        native_message = {
            "role": "assistant",
            "content": content,
            "model": model,
            "streaming": streaming,
        }

        if tool_calls:
            native_tool_calls = []
            for tc in tool_calls:
                arguments = tc.arguments if isinstance(tc.arguments, str) else json.dumps(tc.arguments)
                native_tool_calls.append({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": arguments,
                    },
                })
            native_message["tool_calls"] = native_tool_calls

        return native_message

    # ===================================================================
    # Chat Completion Methods
    # ===================================================================

    async def chat_completion(
        self,
        request: ChatRequest,
        native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None
    ) -> ChatResponse:
        """
        Generate a chat completion (non-streaming).

        Args:
            request: Chat completion request
            native_message_callback: Optional callback for native messages

        Returns:
            Chat completion response
        """
        return await self._with_rate_limit_retry(
            self._chat_completion_impl, request, native_message_callback
        )

    async def _chat_completion_impl(
        self,
        request: ChatRequest,
        native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None
    ) -> ChatResponse:
        """Implementation of non-streaming chat completion."""
        if not AIOHTTP_AVAILABLE:
            raise APIProviderError("aiohttp package required. Install with: pip install aiohttp")

        access_token = await self._ensure_valid_token()
        headers = self._get_headers(access_token)

        # Translate messages (system messages become developer messages)
        input_items, _ = self._translate_messages_to_input(request.messages)

        # Use official Codex instructions verbatim
        instructions = CODEX_INSTRUCTIONS

        # Build request payload in Responses API format
        # CRITICAL: Codex API requires store=false AND stream=true
        payload = {
            "model": request.model or self.model,
            "input": input_items,
            "instructions": instructions,
            "store": False,
            "stream": True,  # REQUIRED by Codex API
        }

        # Add tools if present
        if request.tools:
            payload["tools"] = self._translate_tools_to_format(request.tools)

        # Debug logging (truncate instructions for readability)
        payload_debug = {k: (f"{v[:100]}..." if k == "instructions" and isinstance(v, str) and len(v) > 100 else v) for k, v in payload.items()}
        log.log_debug(f"Codex request payload: {json.dumps(payload_debug, indent=2)}")

        try:
            async with self._create_client_session() as session:
                async with session.post(
                    self._get_responses_endpoint(),
                    headers=headers,
                    json=payload,
                    ssl=not self.disable_tls
                ) as response:

                    if response.status == 401:
                        raise AuthenticationError("Authentication failed. Please re-authenticate.")
                    elif response.status == 429:
                        raise RateLimitError("Rate limit exceeded")
                    elif not response.ok:
                        error_text = await response.text()
                        raise APIProviderError(f"API error {response.status}: {error_text}")

                    # Collect streaming response (API requires stream=true)
                    response_data = await self._collect_streaming_response(response)

            # Parse response
            text_content, tool_calls, finish_reason = self._parse_response_content(response_data)

            # Build usage info
            usage_data = response_data.get("usage", {})
            usage = Usage(
                prompt_tokens=usage_data.get("input_tokens", 0),
                completion_tokens=usage_data.get("output_tokens", 0),
                total_tokens=usage_data.get("total_tokens", 0)
            )

            # Call native callback if provided (store OpenAI-style tool calls)
            if native_message_callback and (text_content or tool_calls):
                native_message = self._build_openai_native_message(
                    text_content,
                    tool_calls,
                    response_data.get("model", request.model or self.model),
                    streaming=False,
                )
                native_message_callback(native_message, self.get_provider_type())

            return ChatResponse(
                content=text_content,
                model=response_data.get("model", request.model or self.model),
                usage=usage,
                tool_calls=tool_calls if tool_calls else None,
                finish_reason=finish_reason,
                is_streaming=False,
                response_id=response_data.get("id")
            )

        except aiohttp.ClientError as e:
            raise NetworkError(f"Network error: {e}")

    async def chat_completion_stream(
        self,
        request: ChatRequest,
        native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None
    ) -> AsyncGenerator[ChatResponse, None]:
        """
        Generate a streaming chat completion.

        Args:
            request: Chat completion request
            native_message_callback: Optional callback for native messages

        Yields:
            Partial chat completion responses
        """
        async for chunk in self._with_rate_limit_retry_stream(
            self._chat_completion_stream_impl, request, native_message_callback
        ):
            yield chunk

    async def _chat_completion_stream_impl(
        self,
        request: ChatRequest,
        native_message_callback: Optional[Callable[[Dict[str, Any], ProviderType], None]] = None
    ) -> AsyncGenerator[ChatResponse, None]:
        """Implementation of streaming chat completion."""
        if not AIOHTTP_AVAILABLE:
            raise APIProviderError("aiohttp package required. Install with: pip install aiohttp")

        access_token = await self._ensure_valid_token()
        headers = self._get_headers(access_token)

        # Translate messages (system messages become developer messages)
        input_items, _ = self._translate_messages_to_input(request.messages)

        # Use official Codex instructions verbatim
        instructions = CODEX_INSTRUCTIONS

        # Build request payload
        # CRITICAL: Codex requires store=false and stream=true
        payload = {
            "model": request.model or self.model,
            "input": input_items,
            "instructions": instructions,
            "store": False,
            "stream": True,
        }

        if request.tools:
            payload["tools"] = self._translate_tools_to_format(request.tools)

        accumulated_content = ""
        accumulated_tool_calls: List[ToolCall] = []
        final_response_data: Dict[str, Any] = {}

        try:
            async with self._create_client_session() as session:
                async with session.post(
                    self._get_responses_endpoint(),
                    headers=headers,
                    json=payload,
                    ssl=not self.disable_tls
                ) as response:

                    if response.status == 401:
                        raise AuthenticationError("Authentication failed. Please re-authenticate.")
                    elif response.status == 429:
                        raise RateLimitError("Rate limit exceeded")
                    elif not response.ok:
                        error_text = await response.text()
                        raise APIProviderError(f"API error {response.status}: {error_text}")

                    # Parse SSE stream
                    async for line in response.content:
                        line = line.decode('utf-8').strip()

                        if not line:
                            continue

                        # SSE format: "data: {...}"
                        if line.startswith("data: "):
                            data_str = line[6:]

                            if data_str == "[DONE]":
                                break

                            try:
                                event_data = json.loads(data_str)
                            except json.JSONDecodeError:
                                continue

                            event_type = event_data.get("type", "")

                            # Handle different event types
                            if event_type == "response.output_text.delta":
                                # Text delta
                                delta_text = event_data.get("delta", "")
                                accumulated_content += delta_text

                                yield ChatResponse(
                                    content=delta_text,
                                    model=request.model or self.model,
                                    usage=Usage(0, 0, 0),
                                    is_streaming=True,
                                    finish_reason=""
                                )

                            elif event_type == "response.function_call_arguments.delta":
                                # Function call argument delta - accumulate
                                pass  # Will be captured in final response

                            elif event_type == "response.output_item.done":
                                # Output item complete
                                item = event_data.get("item", {})
                                if item.get("type") == "function_call":
                                    try:
                                        arguments = item.get("arguments", "{}")
                                        if isinstance(arguments, str):
                                            arguments = json.loads(arguments)
                                    except json.JSONDecodeError:
                                        arguments = {}

                                    tool_call = ToolCall(
                                        id=item.get("call_id", item.get("id", "")),
                                        name=item.get("name", ""),
                                        arguments=arguments
                                    )
                                    accumulated_tool_calls.append(tool_call)

                            elif event_type in ("response.completed", "response.done"):
                                # Final response
                                final_response_data = event_data.get("response", {})

                                if native_message_callback:
                                    native_message_callback(final_response_data, self.get_provider_type())

            # Persist native message with tool calls
            if native_message_callback and (accumulated_content or accumulated_tool_calls):
                native_message = self._build_openai_native_message(
                    accumulated_content,
                    accumulated_tool_calls if accumulated_tool_calls else None,
                    final_response_data.get("model", request.model or self.model),
                    streaming=True,
                )
                native_message_callback(native_message, self.get_provider_type())

            # Yield final response with complete data
            usage_data = final_response_data.get("usage", {})
            usage = Usage(
                prompt_tokens=usage_data.get("input_tokens", 0),
                completion_tokens=usage_data.get("output_tokens", 0),
                total_tokens=usage_data.get("total_tokens", 0)
            )

            finish_reason = "stop"
            if accumulated_tool_calls:
                finish_reason = "tool_calls"
            elif final_response_data.get("status") == "incomplete":
                finish_reason = final_response_data.get("incomplete_details", {}).get("reason", "length")

            yield ChatResponse(
                content="",  # Already streamed
                model=final_response_data.get("model", request.model or self.model),
                usage=usage,
                tool_calls=accumulated_tool_calls if accumulated_tool_calls else None,
                finish_reason=finish_reason,
                is_streaming=False,  # Final chunk
                response_id=final_response_data.get("id")
            )

        except aiohttp.ClientError as e:
            raise NetworkError(f"Network error: {e}")

    # ===================================================================
    # Tool Support Methods
    # ===================================================================

    def format_tool_results_for_continuation(
        self,
        tool_calls: List[ToolCall],
        tool_results: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Format tool results for conversation continuation.

        For Responses API, tool results should be added as ChatMessages with role="tool"
        which will be translated to function_call_output items.

        Args:
            tool_calls: Original tool calls
            tool_results: Execution results

        Returns:
            List of message dicts to add to conversation
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

    # ===================================================================
    # Required Abstract Methods
    # ===================================================================

    async def generate_embeddings(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """
        Generate embeddings (not supported by Codex).

        Raises:
            NotImplementedError: Codex does not support embeddings
        """
        raise NotImplementedError("OpenAI Codex does not support embeddings")

    async def test_connection(self) -> bool:
        """
        Test connection to the provider.

        Returns:
            True if connection successful
        """
        try:
            # Try a simple request
            request = ChatRequest(
                messages=[ChatMessage(role=MessageRole.USER, content="Test message. Please respond with 'OK'.")],
                model=self.model or "gpt-5.1-codex",
                max_tokens=10
            )

            response = await self.chat_completion(request)
            return bool(response.content or response.tool_calls)

        except Exception as e:
            log.log_error(f"Connection test failed: {e}")
            return False

    def get_capabilities(self) -> ProviderCapabilities:
        """Get provider capabilities."""
        return ProviderCapabilities(
            supports_chat=True,
            supports_streaming=True,
            supports_tools=True,
            supports_embeddings=False,
            supports_vision=True,  # Codex supports images
            supports_model_discovery=True,
            max_tokens=self.max_tokens,
            models=[]
        )

    async def discover_available_models(self) -> ProviderModelDiscoveryResult:
        """Discover models from the authenticated Codex models endpoint."""
        if not AIOHTTP_AVAILABLE:
            return ProviderModelDiscoveryResult.failure_result(
                "aiohttp package required. Install with: pip install aiohttp"
            )

        try:
            access_token = await self._ensure_valid_token()
            headers = self._get_model_discovery_headers(access_token)
            client_version = self._get_codex_client_version()
            endpoint = self._get_models_endpoint()
            if client_version:
                endpoint = f"{endpoint}?{urlencode({'client_version': client_version})}"

            async with self._create_client_session() as session:
                try:
                    async with session.get(endpoint, headers=headers, ssl=not self.disable_tls) as response:
                        if response.status == 401:
                            return ProviderModelDiscoveryResult.failure_result(
                                "Authentication failed. Please re-authenticate."
                            )
                        if response.status == 404:
                            return ProviderModelDiscoveryResult.failure_result(
                                "Codex model discovery endpoint not found."
                            )
                        if not response.ok:
                            body = await response.text()
                            return ProviderModelDiscoveryResult.failure_result(
                                f"API error {response.status}: {body}"
                            )

                        payload = await response.json(content_type=None)
                        models = self._extract_model_ids(payload)
                        if models:
                            return ProviderModelDiscoveryResult.success_result(models)

                        return ProviderModelDiscoveryResult.failure_result(
                            "No available models were found."
                        )
                except aiohttp.ClientError as e:
                    return ProviderModelDiscoveryResult.failure_result(
                        f"Network error: {str(e)}"
                    )

        except AuthenticationError as e:
            return ProviderModelDiscoveryResult.failure_result(str(e))
        except Exception as e:
            log.log_error(f"OpenAI OAuth model discovery failed: {e}")
            return ProviderModelDiscoveryResult.failure_result(
                f"Model discovery failed: {str(e)}"
            )

    def get_provider_type(self) -> ProviderType:
        """Get the provider type."""
        return ProviderType.OPENAI_OAUTH


class OpenAIOAuthProviderFactory:
    """Factory for creating OpenAIOAuthProvider instances."""

    def create_provider(self, config: Dict[str, Any]) -> OpenAIOAuthProvider:
        """
        Create an OpenAIOAuthProvider instance.

        Args:
            config: Provider configuration

        Returns:
            Configured provider instance
        """
        return OpenAIOAuthProvider(config)
