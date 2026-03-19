#!/usr/bin/env python3

"""
OAuth Worker - QThread-based worker for non-blocking OAuth authentication

This module provides QThread workers that run OAuth authentication flows
in a background thread, preventing the Qt main thread from blocking.

Usage:
    worker = OpenAIOAuthWorker()
    worker.authentication_complete.connect(on_success)
    worker.authentication_failed.connect(on_error)
    worker.start()
"""

import asyncio
from typing import Dict, Any, Optional

try:
    from ...qt_compat import QThread, Signal
    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False
    # Stub for type hints when Qt not available
    class QThread:
        pass
    class Signal:
        def __init__(self, *args): pass

from src.ida_compat import log


class OAuthWorkerBase(QThread):
    """
    Base class for OAuth authentication workers.

    Signals:
        authentication_complete(dict): Emitted with tokens on success
        authentication_failed(str): Emitted with error message on failure
        status_update(str): Emitted with status messages during authentication
    """

    authentication_complete = Signal(dict)
    authentication_failed = Signal(str)
    status_update = Signal(str)

    def __init__(self, timeout: int = 300, parent=None):
        """
        Initialize the OAuth worker.

        Args:
            timeout: Seconds to wait for authentication (default 5 minutes)
            parent: Optional parent QObject
        """
        if not QT_AVAILABLE:
            raise ImportError("Qt bindings required for OAuth worker")

        super().__init__(parent)
        self.timeout = timeout
        self._cancelled = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._server = None  # Reference to callback server for cancellation

    def cancel(self):
        """
        Request cancellation of the authentication.

        This will stop the callback server and cancel any pending async operations.
        """
        self._cancelled = True
        log.log_info("OAuth cancellation requested")

        # Stop the callback server if running - this will cancel the wait_for_callback future
        if self._server is not None and self._loop is not None:
            log.log_info("Cancelling OAuth - stopping callback server")
            try:
                # Schedule server stop on the event loop
                if self._loop.is_running():
                    future = asyncio.run_coroutine_threadsafe(self._server.stop(), self._loop)
                    # Wait briefly for it to complete
                    try:
                        future.result(timeout=2.0)
                    except Exception:
                        pass  # Best effort
            except Exception as e:
                log.log_warn(f"Error during OAuth cancellation: {e}")

    def run(self):
        """Run the OAuth authentication in a background thread."""
        raise NotImplementedError("Subclasses must implement run()")

    def _run_async(self, coro):
        """
        Run an async coroutine in this thread's event loop.

        Args:
            coro: Coroutine to run

        Returns:
            Result of the coroutine
        """
        # Create a new event loop for this thread
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            return self._loop.run_until_complete(coro)
        finally:
            self._loop.close()
            self._loop = None


class OpenAIOAuthWorker(OAuthWorkerBase):
    """
    Worker for OpenAI OAuth authentication with automatic callback.

    Runs the complete OAuth flow in a background thread:
    1. Starts callback server
    2. Opens browser
    3. Waits for callback
    4. Exchanges code for tokens
    """

    def run(self):
        """Run the OpenAI OAuth authentication."""
        try:
            from .oauth_codex_utils import (
                generate_pkce, generate_state, build_authorize_url,
                exchange_code_for_tokens, create_credentials_json, extract_account_id,
                OAUTH_CALLBACK_PATH, OAUTH_CALLBACK_PORTS
            )
            from .oauth_callback_server import OAuthCallbackServer
            import webbrowser

            self.status_update.emit("Starting authentication server...")
            log.log_info("OpenAI OAuth worker started")

            if self._cancelled:
                self.authentication_failed.emit("cancelled")
                return

            # Run the async authentication with cancellation support
            tokens = self._run_async(
                self._authenticate_openai(
                    generate_pkce, generate_state, build_authorize_url,
                    exchange_code_for_tokens, extract_account_id,
                    OAuthCallbackServer, webbrowser,
                    OAUTH_CALLBACK_PATH, OAUTH_CALLBACK_PORTS
                )
            )

            if self._cancelled:
                self.authentication_failed.emit("cancelled")
                return

            if tokens is None:
                # Cancelled during authentication
                self.authentication_failed.emit("cancelled")
                return

            # Check for OAuth errors in response
            if tokens.get("error"):
                error_msg = tokens.get('error_description', tokens['error'])
                log.log_error(f"OpenAI OAuth error: {error_msg}")
                self.authentication_failed.emit(error_msg)
                return

            # Create credentials JSON
            credentials_json = create_credentials_json(tokens, tokens.get('account_id'))

            log.log_info("OpenAI OAuth authentication completed successfully")
            self.authentication_complete.emit({
                'credentials_json': credentials_json,
                'tokens': tokens
            })

        except asyncio.TimeoutError:
            log.log_warn("OpenAI OAuth timeout")
            self.authentication_failed.emit("timeout")
        except asyncio.CancelledError:
            log.log_info("OpenAI OAuth cancelled")
            self.authentication_failed.emit("cancelled")
        except RuntimeError as e:
            log.log_warn(f"OpenAI OAuth server error: {e}")
            self.authentication_failed.emit(f"server_error:{e}")
        except Exception as e:
            log.log_error(f"OpenAI OAuth error: {e}")
            self.authentication_failed.emit(str(e))

    async def _authenticate_openai(self, generate_pkce, generate_state, build_authorize_url,
                                    exchange_code_for_tokens, extract_account_id,
                                    OAuthCallbackServer, webbrowser,
                                    callback_path, callback_ports):
        """
        Internal async method for OpenAI OAuth with cancellation support.

        By running this directly in the worker, we can store a reference to the server
        and stop it when cancel() is called.
        """
        # Generate PKCE codes and state
        verifier, challenge = generate_pkce()
        state = generate_state()

        # Create callback server and store reference for cancellation
        self._server = OAuthCallbackServer(
            callback_path=callback_path,
            ports=callback_ports,
            timeout=self.timeout,
            provider_name="ChatGPT Pro/Plus"
        )

        try:
            # Start server and get redirect URI
            redirect_uri, port = await self._server.start()
            log.log_info(f"OAuth callback server started on port {port}")

            if self._cancelled:
                return None

            # Build and open authorization URL
            auth_url = build_authorize_url(challenge, state, redirect_uri)
            log.log_info("Opening browser for OpenAI authentication")
            webbrowser.open(auth_url)

            # Wait for callback
            log.log_info("Waiting for OAuth callback...")
            self.status_update.emit("Waiting for authentication in browser...")
            callback_params = await self._server.wait_for_callback()

            if self._cancelled:
                return None

            # Validate state parameter
            received_state = callback_params.get('state', '')
            if received_state != state:
                log.log_warn("State mismatch in OAuth callback (CSRF protection)")

            # Extract authorization code
            code = callback_params.get('code')
            if not code:
                raise Exception("No authorization code in callback")

            log.log_info("Received authorization code, exchanging for tokens...")
            self.status_update.emit("Exchanging code for tokens...")

            # Exchange code for tokens
            tokens = await exchange_code_for_tokens(code, verifier, redirect_uri)

            # Extract account ID
            account_id = extract_account_id(tokens)
            if account_id:
                tokens['account_id'] = account_id
                log.log_info("Extracted ChatGPT account ID")
            else:
                log.log_warn("Could not extract account ID from tokens")

            return tokens

        finally:
            # Always stop the server
            self._server_stopping = True
            await self._server.stop()
            self._server = None
class GeminiOAuthWorker(OAuthWorkerBase):
    """
    Worker for Google Gemini OAuth authentication with automatic callback.

    Runs the complete OAuth flow in a background thread:
    1. Starts callback server
    2. Opens browser (NO PKCE for browser mode, just state)
    3. Waits for callback
    4. Exchanges code for tokens (with client_secret)
    5. Fetches user info and sets up Code Assist project
    """

    def run(self):
        """Run the Gemini OAuth authentication."""
        try:
            from .oauth_gemini_utils import (
                generate_state, build_browser_auth_url,
                exchange_code_for_tokens, fetch_user_info,
                setup_user, create_credentials_json,
                OAUTH_CALLBACK_PATH, OAUTH_CALLBACK_PORTS
            )
            from .oauth_callback_server import OAuthCallbackServer
            import webbrowser

            self.status_update.emit("Starting authentication server...")
            log.log_info("Gemini OAuth worker started")

            if self._cancelled:
                self.authentication_failed.emit("cancelled")
                return

            # Run the async authentication with cancellation support
            tokens = self._run_async(
                self._authenticate_gemini(
                    generate_state, build_browser_auth_url,
                    exchange_code_for_tokens, fetch_user_info,
                    setup_user, create_credentials_json,
                    OAuthCallbackServer, webbrowser,
                    OAUTH_CALLBACK_PATH, OAUTH_CALLBACK_PORTS
                )
            )

            if self._cancelled:
                self.authentication_failed.emit("cancelled")
                return

            if tokens is None:
                self.authentication_failed.emit("cancelled")
                return

            # Check for errors
            if isinstance(tokens, dict) and tokens.get("error"):
                error_msg = tokens.get('error_description', tokens['error'])
                log.log_error(f"Gemini OAuth error: {error_msg}")
                self.authentication_failed.emit(error_msg)
                return

            log.log_info("Gemini OAuth authentication completed successfully")
            self.authentication_complete.emit(tokens)

        except asyncio.TimeoutError:
            log.log_warn("Gemini OAuth timeout")
            self.authentication_failed.emit("timeout")
        except asyncio.CancelledError:
            log.log_info("Gemini OAuth cancelled")
            self.authentication_failed.emit("cancelled")
        except RuntimeError as e:
            log.log_warn(f"Gemini OAuth server error: {e}")
            self.authentication_failed.emit(f"server_error:{e}")
        except Exception as e:
            log.log_error(f"Gemini OAuth error: {e}")
            self.authentication_failed.emit(str(e))

    async def _authenticate_gemini(self, generate_state, build_browser_auth_url,
                                    exchange_code_for_tokens, fetch_user_info,
                                    setup_user, create_credentials_json,
                                    OAuthCallbackServer, webbrowser,
                                    callback_path, callback_ports):
        """
        Internal async method for Gemini OAuth with cancellation support.

        Browser mode: NO PKCE, just state parameter for CSRF protection.
        Token exchange includes client_secret (form-encoded).
        """
        # Generate state (NO PKCE for browser mode)
        state = generate_state()

        # Create callback server and store reference for cancellation
        self._server = OAuthCallbackServer(
            callback_path=callback_path,
            ports=callback_ports,
            timeout=self.timeout,
            provider_name="Google Gemini"
        )

        try:
            # Start server and get redirect URI
            redirect_uri, port = await self._server.start()
            log.log_info(f"OAuth callback server started on port {port}")

            if self._cancelled:
                return None

            # Build and open authorization URL (NO PKCE)
            auth_url = build_browser_auth_url(state, redirect_uri)
            log.log_info("Opening browser for Gemini authentication")
            webbrowser.open(auth_url)

            # Wait for callback
            log.log_info("Waiting for OAuth callback...")
            self.status_update.emit("Waiting for authentication in browser...")
            callback_params = await self._server.wait_for_callback()

            if self._cancelled:
                return None

            # Validate state parameter
            received_state = callback_params.get('state', '')
            if received_state != state:
                log.log_warn("State mismatch in Gemini OAuth callback (CSRF protection)")

            # Extract authorization code
            code = callback_params.get('code')
            if not code:
                raise Exception("No authorization code in callback")

            log.log_info("Received authorization code, exchanging for tokens...")
            self.status_update.emit("Exchanging code for tokens...")

            # Exchange code for tokens (NO code_verifier for browser mode)
            tokens = await exchange_code_for_tokens(code, redirect_uri)

            if tokens.get("error"):
                return tokens

            # Fetch user info
            self.status_update.emit("Setting up account...")
            email = await fetch_user_info(tokens["access_token"])

            # Setup Code Assist (project discovery)
            user_info = await setup_user(tokens["access_token"])

            # Create credentials JSON
            credentials_json = create_credentials_json(
                tokens,
                email=email,
                project_id=user_info.get("project_id", ""),
                tier=user_info.get("tier", ""),
                tier_name=user_info.get("tier_name", ""),
            )

            return {
                'credentials_json': credentials_json,
                'tokens': tokens,
                'email': email,
            }

        finally:
            # Always stop the server
            await self._server.stop()
            self._server = None
