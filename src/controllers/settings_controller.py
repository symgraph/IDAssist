#!/usr/bin/env python3

import asyncio
from ..qt_compat import (QMessageBox, QInputDialog, QDialog, QVBoxLayout, QHBoxLayout,
                         QLabel, QLineEdit, QPushButton, QCheckBox, QSpinBox, QComboBox,
                         QObject, QThread, Signal, exec_dialog)

from src.ida_compat import log

from ..services.settings_service import settings_service
from ..services.models.provider_types import ProviderType
from ..services.mcp_client_service import MCPClientService
from ..services.models.mcp_models import MCPServerConfig, MCPTestResult
from ..services import (
    get_service_registry, LLMService, ChatMessage, MessageRole,
    LLMProviderError, APIProviderError, AuthenticationError,
    RateLimitError, NetworkError
)
from ..services.symgraph_service import symgraph_service, SymGraphAuthError, SymGraphNetworkError, SymGraphAPIError
from ..views.settings_tab_view import SettingsTabView


class ProviderTestWorker(QThread):
    """Worker thread for testing provider connectivity"""

    test_completed = Signal(bool, str)

    def __init__(self, provider_config):
        super().__init__()
        self.provider_config = provider_config

    def run(self):
        """Run provider test in background thread"""
        provider_name = self.provider_config.get('name', 'Unknown')

        try:
            log.log_info(f"Testing provider '{provider_name}'...")

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                success, message = loop.run_until_complete(
                    asyncio.wait_for(self._test_provider(), timeout=15.0)
                )

                if success:
                    log.log_info(f"Provider test successful for '{provider_name}'")
                else:
                    log.log_warn(f"Provider test failed for '{provider_name}'")

                self.test_completed.emit(success, message)

            except asyncio.TimeoutError:
                log.log_warn(f"Provider test timeout for '{provider_name}' after 15 seconds")
                self.test_completed.emit(False, f"Test timeout after 15 seconds")

            except Exception as e:
                log.log_error(f"Provider test execution failed for '{provider_name}': {e}")
                self.test_completed.emit(False, f"Test execution error: {str(e)}")

            finally:
                try:
                    pending = asyncio.all_tasks(loop)
                    if pending:
                        for task in pending:
                            task.cancel()
                        loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True)
                        )
                except Exception as cleanup_error:
                    log.log_debug(f"Event loop cleanup warning: {cleanup_error}")
                finally:
                    loop.close()

        except Exception as e:
            log.log_error(f"Provider test setup failed for '{provider_name}': {e}")
            self.test_completed.emit(False, f"Test setup error: {str(e)}")

    async def _test_provider(self):
        """Async method to test provider connectivity"""
        provider_name = self.provider_config.get('name', 'Unknown')
        provider_type = self.provider_config.get('provider_type', 'unknown')

        registry = None
        llm_service = None

        try:
            registry = get_service_registry()
            if not registry.is_initialized():
                registry.initialize()

            llm_service = registry.get_llm_service()
            if not llm_service:
                return False, "LLM service not available"

            from ..services.llm_providers.provider_factory import get_provider_factory

            factory = get_provider_factory()
            test_provider = factory.create_provider(self.provider_config)

            if not test_provider:
                return False, f"Failed to create provider '{provider_name}'"

            test_messages = [
                ChatMessage(
                    role=MessageRole.USER,
                    content="This is a test, please respond with just the word: OK"
                )
            ]

            log.log_debug(f"Sending test request to {provider_type} provider...")

            from ..services.models.llm_models import ChatRequest
            test_request = ChatRequest(
                messages=test_messages,
                model=test_provider.model,
                max_tokens=test_provider.max_tokens,
                temperature=None
            )

            response = await test_provider.chat_completion(test_request)

            if response and response.content:
                content = response.content.strip()
                content_upper = content.upper()

                log.log_debug(f"Received response: '{content}'")

                if "OK" in content_upper:
                    return True, f"Test successful! Response: '{content}'"
                else:
                    return True, f"Provider responded but not as expected: '{content}'"
            else:
                log.log_warn(f"Empty or null response from provider")
                return False, "Provider returned empty response"

        except AuthenticationError as e:
            log.log_warn(f"Authentication error for {provider_name}: {e}")
            return False, f"Authentication failed: {str(e)}"
        except RateLimitError as e:
            log.log_warn(f"Rate limit error for {provider_name}: {e}")
            return False, f"Rate limit exceeded: {str(e)}"
        except NetworkError as e:
            log.log_warn(f"Network error for {provider_name}: {e}")
            return False, f"Network error: {str(e)}"
        except APIProviderError as e:
            log.log_warn(f"API provider error for {provider_name}: {e}")
            return False, f"Provider error: {str(e)}"
        except LLMProviderError as e:
            log.log_warn(f"LLM service error for {provider_name}: {e}")
            return False, f"LLM service error: {str(e)}"
        except Exception as e:
            log.log_error(f"Unexpected error for {provider_name}: {e}")
            return False, f"Unexpected error: {str(e)}"

        finally:
            pass


class MCPTestWorker(QThread):
    """Worker thread for testing MCP server connectivity"""

    test_completed = Signal(bool, str, dict)

    def __init__(self, mcp_server_config):
        super().__init__()
        self.server_config = mcp_server_config

    def run(self):
        """Run MCP test in background thread"""
        server_name = self.server_config.get('name', 'Unknown')

        try:
            log.log_info(f"Testing MCP server '{server_name}'...")

            transport_type = self.server_config.get('transport', 'sse')

            config = MCPServerConfig(
                name=self.server_config['name'],
                transport_type=transport_type,
                url=self.server_config['url'],
                enabled=self.server_config.get('enabled', True),
                timeout=30.0
            )

            mcp_service = MCPClientService()

            result = mcp_service.test_server_connection(config)

            if result.success:
                log.log_info(f"MCP server test successful for '{server_name}'")

                tools_text = f"{result.tools_count} tools" if result.tools_count > 0 else "no tools"
                resources_text = f"{result.resources_count} resources" if result.resources_count > 0 else "no resources"

                message = f"Connection successful!\n\nFound {tools_text} and {resources_text}."

                if result.tools_count > 0:
                    message += "\n\nAvailable tools:"
                    for i, tool in enumerate(result.tools[:5]):
                        message += f"\n- {tool['name']}: {tool['description'][:50]}{'...' if len(tool['description']) > 50 else ''}"
                    if result.tools_count > 5:
                        message += f"\n... and {result.tools_count - 5} more tools"

                self.test_completed.emit(True, message, result.to_dict())
            else:
                log.log_warn(f"MCP server test failed for '{server_name}'")
                error_message = f"Connection failed: {result.error}"

                if "404" in result.error or "not found" in result.error.lower():
                    error_message += "\n\nSuggestions:"
                    error_message += "\n- Try adding '/sse' to the URL (e.g., http://localhost:9090/sse)"
                    error_message += "\n- Check if the server is running and accessible"
                    error_message += "\n- Verify the server supports MCP over SSE"
                elif "connection refused" in result.error.lower():
                    error_message += "\n\nSuggestion: Check if the server is running on the specified port"

                self.test_completed.emit(False, error_message, {})

        except Exception as e:
            log.log_error(f"MCP server test execution failed for '{server_name}': {e}")
            error_message = f"Test execution error: {str(e)}"
            self.test_completed.emit(False, error_message, {})


class SymGraphTestWorker(QThread):
    """Worker thread for testing SymGraph API connectivity"""

    test_completed = Signal(bool, str)

    def __init__(self):
        super().__init__()

    def run(self):
        """Run SymGraph API test in background thread"""
        try:
            log.log_info("Testing SymGraph API connection...")

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                success, message = loop.run_until_complete(
                    asyncio.wait_for(self._test_symgraph(), timeout=15.0)
                )

                if success:
                    log.log_info("SymGraph API test successful")
                else:
                    log.log_warn("SymGraph API test failed")

                self.test_completed.emit(success, message)

            except asyncio.TimeoutError:
                log.log_warn("SymGraph API test timeout after 15 seconds")
                self.test_completed.emit(False, "Test timeout after 15 seconds")

            except Exception as e:
                log.log_error(f"SymGraph API test execution failed: {e}")
                self.test_completed.emit(False, f"Test execution error: {str(e)}")

            finally:
                try:
                    pending = asyncio.all_tasks(loop)
                    if pending:
                        for task in pending:
                            task.cancel()
                        loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True)
                        )
                except Exception as cleanup_error:
                    log.log_debug(f"Event loop cleanup warning: {cleanup_error}")
                finally:
                    loop.close()

        except Exception as e:
            log.log_error(f"SymGraph API test setup failed: {e}")
            self.test_completed.emit(False, f"Test setup error: {str(e)}")

    async def _test_symgraph(self):
        """Async method to test SymGraph API connectivity"""
        try:
            test_hash = "0000000000000000000000000000000000000000000000000000000000000000"
            await symgraph_service.check_binary_exists(test_hash)

            if symgraph_service.has_api_key:
                try:
                    await symgraph_service.get_symbols(test_hash)
                    return True, "API reachable, authentication successful"
                except SymGraphAuthError as e:
                    return False, f"API reachable but authentication failed: {str(e)}"
            else:
                return True, "API reachable (no API key configured)"

        except SymGraphNetworkError as e:
            return False, f"Network error: {str(e)}"
        except SymGraphAPIError as e:
            return False, f"API error: {str(e)}"
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"


class ProviderDialog(QDialog):
    """Dialog for adding/editing LLM providers"""

    def __init__(self, parent=None, provider_data=None):
        super().__init__(parent)
        self.provider_data = provider_data
        self._pending_pkce_verifier = None
        self.setup_ui()

        if provider_data:
            self.populate_fields()

    def setup_ui(self):
        self.setWindowTitle("LLM Provider" if not self.provider_data else f"Edit {self.provider_data.get('name', 'Provider')}")
        self.setModal(True)
        self.resize(450, 400)

        layout = QVBoxLayout()

        # Name
        layout.addWidget(QLabel("Name:"))
        self.name_edit = QLineEdit()
        layout.addWidget(self.name_edit)

        # Provider Type
        layout.addWidget(QLabel("Provider Type:"))
        self.provider_type_combo = QComboBox()
        for provider_type in ProviderType:
            self.provider_type_combo.addItem(provider_type.display_name, provider_type.value)

        self.provider_type_combo.currentTextChanged.connect(self.on_provider_type_changed)
        layout.addWidget(self.provider_type_combo)

        # Model
        layout.addWidget(QLabel("Model:"))
        self.model_edit = QLineEdit()
        layout.addWidget(self.model_edit)

        # URL
        layout.addWidget(QLabel("URL:"))
        self.url_edit = QLineEdit()
        layout.addWidget(self.url_edit)

        # Max Tokens
        layout.addWidget(QLabel("Max Tokens:"))
        self.max_tokens_spin = QSpinBox()
        self.max_tokens_spin.setRange(1, 100000)
        self.max_tokens_spin.setValue(4096)
        layout.addWidget(self.max_tokens_spin)

        # API Key / OAuth Token
        self.api_key_label = QLabel("API Key:")
        layout.addWidget(self.api_key_label)

        key_layout = QHBoxLayout()
        self.key_edit = QLineEdit()
        self.key_edit.setEchoMode(QLineEdit.Password)
        key_layout.addWidget(self.key_edit)

        self.authenticate_button = QPushButton("Authenticate")
        self.authenticate_button.setToolTip("Open browser to authenticate with Claude Pro/Max")
        self.authenticate_button.clicked.connect(self.on_authenticate_clicked)
        self.authenticate_button.setVisible(False)
        key_layout.addWidget(self.authenticate_button)

        layout.addLayout(key_layout)

        self.oauth_note_label = QLabel(
            "Click 'Authenticate' to sign in with your Claude Pro/Max subscription.\n"
            "The OAuth token will be stored as JSON in the field above."
        )
        self.oauth_note_label.setStyleSheet("color: #666; font-style: italic;")
        self.oauth_note_label.setWordWrap(True)
        layout.addWidget(self.oauth_note_label)
        self.oauth_note_label.setVisible(False)

        # Disable TLS
        self.disable_tls_check = QCheckBox("Disable TLS Verification")
        layout.addWidget(self.disable_tls_check)

        # Claude Code CLI note
        self.claude_code_note_label = QLabel(
            "Note: Requires `claude` CLI installed and authenticated.\n"
            "Install with: npm install -g @anthropic-ai/claude-code"
        )
        self.claude_code_note_label.setStyleSheet("color: #666; font-style: italic; margin-top: 10px;")
        self.claude_code_note_label.setWordWrap(True)
        layout.addWidget(self.claude_code_note_label)
        self.claude_code_note_label.setVisible(False)

        # LiteLLM metadata
        self.litellm_metadata_label = QLabel("LiteLLM Metadata:")
        self.litellm_metadata_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(self.litellm_metadata_label)

        self.model_family_label = QLabel("Model Family: Not detected")
        layout.addWidget(self.model_family_label)

        self.is_bedrock_label = QLabel("Bedrock Model: No")
        layout.addWidget(self.is_bedrock_label)

        self.litellm_metadata_label.setVisible(False)
        self.model_family_label.setVisible(False)
        self.is_bedrock_label.setVisible(False)

        self.model_edit.textChanged.connect(self.update_litellm_metadata)

        # Buttons
        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Cancel")

        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def populate_fields(self):
        """Populate fields with existing provider data"""
        if self.provider_data:
            self.name_edit.setText(self.provider_data.get('name', ''))

            provider_type_value = self.provider_data.get('provider_type', 'openai_platform')
            index = self.provider_type_combo.findData(provider_type_value)
            if index >= 0:
                self.provider_type_combo.setCurrentIndex(index)

            self.model_edit.setText(self.provider_data.get('model', ''))
            self.url_edit.setText(self.provider_data.get('url', ''))
            self.max_tokens_spin.setValue(self.provider_data.get('max_tokens', 4096))
            self.key_edit.setText(self.provider_data.get('api_key', ''))
            self.disable_tls_check.setChecked(self.provider_data.get('disable_tls', False))

    def get_provider_data(self):
        """Get the provider data from the form"""
        return {
            'name': self.name_edit.text().strip(),
            'provider_type': self.provider_type_combo.currentData(),
            'model': self.model_edit.text().strip(),
            'url': self.url_edit.text().strip(),
            'max_tokens': self.max_tokens_spin.value(),
            'api_key': self.key_edit.text(),
            'disable_tls': self.disable_tls_check.isChecked()
        }

    def on_provider_type_changed(self):
        """Handle provider type selection change"""
        current_data = self.provider_type_combo.currentData()
        if current_data:
            try:
                provider_type = ProviderType(current_data)

                if not self.url_edit.text() or self.url_edit.text() in [pt.default_url for pt in ProviderType]:
                    self.url_edit.setText(provider_type.default_url)

                if not self.model_edit.text():
                    default_models = provider_type.default_models
                    if default_models:
                        self.model_edit.setText(default_models[0])

                is_litellm = provider_type == ProviderType.LITELLM
                self.litellm_metadata_label.setVisible(is_litellm)
                self.model_family_label.setVisible(is_litellm)
                self.is_bedrock_label.setVisible(is_litellm)

                if is_litellm:
                    self.update_litellm_metadata()

                is_claude_code = provider_type == ProviderType.ANTHROPIC_CLI
                self.claude_code_note_label.setVisible(is_claude_code)

                is_anthropic_oauth = provider_type == ProviderType.ANTHROPIC_OAUTH
                is_codex_oauth = provider_type == ProviderType.OPENAI_OAUTH
                is_gemini_oauth = provider_type == ProviderType.GEMINI_OAUTH
                is_oauth = is_anthropic_oauth or is_codex_oauth or is_gemini_oauth
                self.authenticate_button.setVisible(is_oauth)
                self.oauth_note_label.setVisible(is_oauth)

                if is_anthropic_oauth:
                    self.api_key_label.setText("OAuth Token (JSON):")
                    self.key_edit.setEchoMode(QLineEdit.Normal)
                    self.key_edit.setPlaceholderText('Click "Authenticate" to sign in')
                    self.oauth_note_label.setText(
                        "Click 'Authenticate' to sign in with your Claude Pro/Max subscription.\n"
                        "The OAuth token will be stored as JSON in the field above."
                    )
                elif is_codex_oauth:
                    self.api_key_label.setText("OAuth Token (JSON):")
                    self.key_edit.setEchoMode(QLineEdit.Normal)
                    self.key_edit.setPlaceholderText('Click "Authenticate" to sign in with ChatGPT')
                    self.oauth_note_label.setText(
                        "Click 'Authenticate' to sign in with your ChatGPT Pro/Plus subscription.\n"
                        "After authorization, copy the code from the browser URL bar."
                    )
                elif is_gemini_oauth:
                    self.api_key_label.setText("OAuth Token (JSON):")
                    self.key_edit.setEchoMode(QLineEdit.Normal)
                    self.key_edit.setPlaceholderText('Click "Authenticate" to sign in with Google')
                    self.oauth_note_label.setText(
                        "Click 'Authenticate' to sign in with your Google account.\n"
                        "The OAuth token will be stored as JSON in the field above."
                    )
                else:
                    self.api_key_label.setText("API Key:")
                    self.key_edit.setEchoMode(QLineEdit.Password)
                    self.key_edit.setPlaceholderText('')

            except ValueError:
                pass

    def update_litellm_metadata(self):
        """Update LiteLLM metadata labels based on current model name"""
        current_provider_type = self.provider_type_combo.currentData()
        if current_provider_type != 'litellm':
            return

        model_name = self.model_edit.text().strip()
        if not model_name:
            self.model_family_label.setText("Model Family: Not detected")
            self.is_bedrock_label.setText("Bedrock Model: No")
            return

        model_family = self._detect_model_family(model_name)
        is_bedrock = model_name.lower().startswith('bedrock/') or model_name.lower().startswith('bedrock-')

        self.model_family_label.setText(f"Model Family: {model_family.title()}")
        self.is_bedrock_label.setText(f"Bedrock Model: {'Yes' if is_bedrock else 'No'}")

    def _detect_model_family(self, model: str) -> str:
        """Detect model family from model name"""
        model_lower = model.lower()

        if model_lower.startswith('bedrock/'):
            if 'anthropic' in model_lower or 'claude' in model_lower:
                return 'anthropic'
            elif 'amazon' in model_lower or 'nova' in model_lower:
                return 'amazon'
            elif 'meta' in model_lower or 'llama' in model_lower:
                return 'meta'
            elif 'cohere' in model_lower:
                return 'cohere'
            elif 'ai21' in model_lower:
                return 'ai21'

        if 'claude' in model_lower or 'anthropic' in model_lower:
            return 'anthropic'
        elif 'gpt' in model_lower or 'openai' in model_lower:
            return 'openai'
        elif 'gemini' in model_lower or 'google' in model_lower:
            return 'google'
        elif 'llama' in model_lower or 'meta' in model_lower:
            return 'meta'

        return 'unknown'

    def on_authenticate_clicked(self):
        """Handle OAuth authentication button click"""
        from ..qt_compat import QMessageBox

        current_data = self.provider_type_combo.currentData()
        try:
            provider_type = ProviderType(current_data)
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid provider type selected.")
            return

        is_codex = provider_type == ProviderType.OPENAI_OAUTH
        is_anthropic = provider_type == ProviderType.ANTHROPIC_OAUTH
        is_gemini = provider_type == ProviderType.GEMINI_OAUTH

        if is_codex:
            self._authenticate_codex()
        elif is_anthropic:
            self._authenticate_anthropic()
        elif is_gemini:
            self._authenticate_gemini()
        else:
            QMessageBox.warning(self, "Not Supported",
                "OAuth authentication is not supported for this provider type.")

    def _authenticate_anthropic(self):
        """Handle Anthropic OAuth authentication with automatic callback"""
        from ..qt_compat import QMessageBox, QProgressDialog, Qt

        try:
            from ..services.llm_providers.oauth_worker import AnthropicOAuthWorker

            log.log_info("Starting Anthropic OAuth authentication with automatic callback")

            self._oauth_auth_completed = False

            self._oauth_progress = QProgressDialog(
                "Waiting for authentication...\n\n"
                "Please complete sign-in in your browser.\n"
                "This dialog will close automatically when done.",
                "Use Manual Entry",
                0, 0,
                self
            )
            self._oauth_progress.setWindowTitle("Claude Authentication")
            self._oauth_progress.setWindowModality(Qt.WindowModal)
            self._oauth_progress.setMinimumDuration(0)
            self._oauth_progress.setMinimumWidth(400)

            self._oauth_worker = AnthropicOAuthWorker(timeout=300)
            self._oauth_worker.authentication_complete.connect(self._on_anthropic_auth_complete)
            self._oauth_worker.authentication_failed.connect(self._on_anthropic_auth_failed)
            self._oauth_worker.status_update.connect(
                lambda msg: self._oauth_progress.setLabelText(msg) if self._oauth_progress else None
            )

            def on_cancel():
                if getattr(self, '_oauth_auth_completed', False):
                    return
                if hasattr(self, '_oauth_worker') and self._oauth_worker:
                    self._oauth_worker.cancel()

            self._oauth_progress.canceled.connect(on_cancel)
            self._oauth_worker.finished.connect(self._oauth_worker.deleteLater)
            self._oauth_worker.start()
            self._oauth_progress.show()

        except ImportError as e:
            log.log_error(f"OAuth import error: {e}")
            self._authenticate_anthropic_manual()
        except Exception as e:
            log.log_error(f"OAuth authentication error: {e}")
            self._authenticate_anthropic_manual()

    def _on_anthropic_auth_complete(self, result: dict):
        """Handle successful Anthropic OAuth authentication"""
        from ..qt_compat import QMessageBox

        self._oauth_auth_completed = True

        if hasattr(self, '_oauth_progress') and self._oauth_progress:
            self._oauth_progress.close()
            self._oauth_progress = None

        credentials_json = result.get('credentials_json', '')
        self.key_edit.setText(credentials_json)

        log.log_info("OAuth authentication successful - token stored in API key field")
        QMessageBox.information(self, "Authentication Successful",
            "Successfully authenticated with Claude Pro/Max!\n\n"
            "The OAuth token has been stored. Click OK to save the provider.")

    def _on_anthropic_auth_failed(self, error: str):
        """Handle failed Anthropic OAuth authentication"""
        from ..qt_compat import QMessageBox

        self._oauth_auth_completed = True

        if hasattr(self, '_oauth_progress') and self._oauth_progress:
            self._oauth_progress.close()
            self._oauth_progress = None

        if error == "cancelled":
            log.log_info("User cancelled automatic OAuth, showing manual entry")
            self._authenticate_anthropic_manual()
            return
        elif error == "timeout":
            reply = QMessageBox.question(
                self, "Authentication Timeout",
                "The authentication request timed out.\n\n"
                "Would you like to try manual code entry instead?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                self._authenticate_anthropic_manual()
        else:
            log.log_info(f"Anthropic OAuth failed ({error}), falling back to manual entry")
            self._authenticate_anthropic_manual()

    def _authenticate_anthropic_manual(self):
        """Manual fallback for Anthropic OAuth authentication"""
        from ..qt_compat import QMessageBox, QInputDialog

        try:
            from ..services.llm_providers.oauth_utils import (
                generate_pkce, generate_state, open_auth_browser,
                exchange_code_for_tokens, create_credentials_json
            )

            verifier, challenge = generate_pkce()
            state = generate_state()
            self._pending_pkce_verifier = verifier
            self._pending_oauth_state = state

            auth_url = open_auth_browser(challenge, state)
            log.log_info(f"Opened browser for Anthropic OAuth authorization (manual mode)")

            code, ok = QInputDialog.getText(
                self, "OAuth Authentication (Manual)",
                "A browser window has been opened for Claude Pro/Max authentication.\n\n"
                "1. Sign in to your Anthropic account in the browser\n"
                "2. Authorize IDAssist to access your account\n"
                "3. Copy the authorization code shown in the browser\n"
                "4. Paste it below:\n\n"
                "Authorization Code:"
            )

            if not ok or not code.strip():
                log.log_info("OAuth authentication cancelled by user")
                QMessageBox.information(self, "Authentication Cancelled", "Authentication was cancelled.")
                return

            code_input = code.strip()
            if "#" in code_input:
                auth_code, returned_state = code_input.split("#", 1)
            else:
                auth_code = code_input
                returned_state = state

            log.log_info("Exchanging authorization code for tokens...")

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                tokens = loop.run_until_complete(
                    exchange_code_for_tokens(auth_code, verifier, returned_state)
                )
            finally:
                loop.close()

            if tokens.get("error"):
                error_msg = tokens.get('error_description', tokens['error'])
                log.log_error(f"OAuth token exchange failed: {error_msg}")
                QMessageBox.critical(self, "Authentication Failed", f"Token exchange failed: {error_msg}")
                return

            credentials_json = create_credentials_json(tokens)
            self.key_edit.setText(credentials_json)

            log.log_info("OAuth authentication successful - token stored in API key field")
            QMessageBox.information(self, "Authentication Successful",
                "Successfully authenticated with Claude Pro/Max!\n\n"
                "The OAuth token has been stored. Click OK to save the provider.")

        except ImportError as e:
            log.log_error(f"OAuth import error: {e}")
            QMessageBox.critical(self, "Missing Dependencies",
                f"OAuth authentication requires additional packages.\n\nError: {e}")
        except Exception as e:
            log.log_error(f"OAuth authentication error: {e}")
            QMessageBox.critical(self, "Authentication Error", f"An error occurred during authentication:\n\n{e}")

    def _authenticate_codex(self):
        """Handle OpenAI Codex (ChatGPT) OAuth authentication with automatic callback"""
        from ..qt_compat import QMessageBox, QProgressDialog, Qt

        try:
            from ..services.llm_providers.oauth_worker import OpenAIOAuthWorker

            log.log_info("Starting OpenAI OAuth authentication with automatic callback")

            self._oauth_auth_completed = False

            self._oauth_progress = QProgressDialog(
                "Waiting for authentication...\n\n"
                "Please complete sign-in in your browser.\n"
                "This dialog will close automatically when done.",
                "Use Manual Entry",
                0, 0,
                self
            )
            self._oauth_progress.setWindowTitle("OpenAI Authentication")
            self._oauth_progress.setWindowModality(Qt.WindowModal)
            self._oauth_progress.setMinimumDuration(0)
            self._oauth_progress.setMinimumWidth(400)

            self._oauth_worker = OpenAIOAuthWorker(timeout=300)
            self._oauth_worker.authentication_complete.connect(self._on_codex_auth_complete)
            self._oauth_worker.authentication_failed.connect(self._on_codex_auth_failed)
            self._oauth_worker.status_update.connect(
                lambda msg: self._oauth_progress.setLabelText(msg) if self._oauth_progress else None
            )

            def on_cancel():
                if getattr(self, '_oauth_auth_completed', False):
                    return
                if hasattr(self, '_oauth_worker') and self._oauth_worker:
                    self._oauth_worker.cancel()

            self._oauth_progress.canceled.connect(on_cancel)
            self._oauth_worker.finished.connect(self._oauth_worker.deleteLater)
            self._oauth_worker.start()
            self._oauth_progress.show()

        except ImportError as e:
            log.log_error(f"OAuth import error: {e}")
            self._authenticate_codex_manual()
        except Exception as e:
            log.log_error(f"OAuth authentication error: {e}")
            self._authenticate_codex_manual()

    def _on_codex_auth_complete(self, result: dict):
        """Handle successful OpenAI OAuth authentication"""
        from ..qt_compat import QMessageBox

        self._oauth_auth_completed = True

        if hasattr(self, '_oauth_progress') and self._oauth_progress:
            self._oauth_progress.close()
            self._oauth_progress = None

        credentials_json = result.get('credentials_json', '')
        self.key_edit.setText(credentials_json)

        log.log_info("OAuth authentication successful - token stored in API key field")
        QMessageBox.information(self, "Authentication Successful",
            "Successfully authenticated with ChatGPT Pro/Plus!\n\n"
            "The OAuth token has been stored. Click OK to save the provider.")

    def _on_codex_auth_failed(self, error: str):
        """Handle failed OpenAI OAuth authentication"""
        from ..qt_compat import QMessageBox

        self._oauth_auth_completed = True

        if hasattr(self, '_oauth_progress') and self._oauth_progress:
            self._oauth_progress.close()
            self._oauth_progress = None

        if error == "cancelled":
            log.log_info("User cancelled automatic OAuth, showing manual entry")
            self._authenticate_codex_manual()
            return
        elif error == "timeout":
            reply = QMessageBox.question(
                self, "Authentication Timeout",
                "The authentication request timed out.\n\n"
                "Would you like to try manual code entry instead?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                self._authenticate_codex_manual()
        elif error.startswith("server_error:"):
            log.log_info("Falling back to manual entry due to server error")
            self._authenticate_codex_manual()
        else:
            reply = QMessageBox.question(
                self, "Authentication Error",
                f"An error occurred during authentication:\n\n{error}\n\n"
                "Would you like to try manual code entry instead?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                self._authenticate_codex_manual()

    def _authenticate_codex_manual(self):
        """Manual fallback for OpenAI Codex OAuth authentication"""
        from ..qt_compat import QMessageBox, QInputDialog

        try:
            from ..services.llm_providers.oauth_codex_utils import (
                generate_pkce, generate_state, open_auth_browser,
                exchange_code_for_tokens, create_credentials_json,
                extract_account_id
            )

            verifier, challenge = generate_pkce()
            state = generate_state()
            self._pending_pkce_verifier = verifier

            auth_url = open_auth_browser(challenge, state)
            log.log_info(f"Opened browser for OpenAI Codex OAuth authorization (manual mode)")

            code, ok = QInputDialog.getText(
                self, "OAuth Authentication (Manual)",
                "A browser window has been opened for ChatGPT Pro/Plus authentication.\n\n"
                "1. Sign in to your OpenAI/ChatGPT account in the browser\n"
                "2. Authorize IDAssist to access your account\n"
                "3. After authorization, the browser will show an error page\n"
                "4. Look at the browser's URL bar\n"
                "5. Copy the ENTIRE URL or just the 'code' value\n"
                "6. Paste it below:\n\n"
                "Authorization Code or Full URL:"
            )

            if not ok or not code.strip():
                log.log_info("OAuth authentication cancelled by user")
                QMessageBox.information(self, "Authentication Cancelled", "Authentication was cancelled.")
                return

            code = code.strip()
            if code.startswith("http"):
                from urllib.parse import urlparse, parse_qs
                try:
                    parsed = urlparse(code)
                    params = parse_qs(parsed.query)
                    if "code" in params:
                        code = params["code"][0]
                        log.log_info("Extracted authorization code from URL")
                except Exception as e:
                    log.log_warn(f"Failed to parse URL, using input as-is: {e}")

            log.log_info("Exchanging authorization code for tokens...")

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                tokens = loop.run_until_complete(
                    exchange_code_for_tokens(code, verifier)
                )
            finally:
                loop.close()

            if tokens.get("error"):
                error_msg = tokens.get('error_description', tokens['error'])
                log.log_error(f"OAuth token exchange failed: {error_msg}")
                QMessageBox.critical(self, "Authentication Failed", f"Token exchange failed: {error_msg}")
                return

            account_id = extract_account_id(tokens)
            credentials_json = create_credentials_json(tokens, account_id)
            self.key_edit.setText(credentials_json)

            log.log_info("OAuth authentication successful - token stored in API key field")
            QMessageBox.information(self, "Authentication Successful",
                "Successfully authenticated with ChatGPT Pro/Plus!\n\n"
                "The OAuth token has been stored. Click OK to save the provider.")

        except ImportError as e:
            log.log_error(f"OAuth import error: {e}")
            QMessageBox.critical(self, "Missing Dependencies",
                f"OAuth authentication requires additional packages.\n\nError: {e}")
        except Exception as e:
            log.log_error(f"OAuth authentication error: {e}")
            QMessageBox.critical(self, "Authentication Error", f"An error occurred during authentication:\n\n{e}")

    def _authenticate_gemini(self):
        """Handle Google Gemini OAuth authentication with automatic callback"""
        from ..qt_compat import QMessageBox, QProgressDialog, Qt

        try:
            from ..services.llm_providers.oauth_worker import GeminiOAuthWorker

            log.log_info("Starting Gemini OAuth authentication with automatic callback")

            self._oauth_auth_completed = False

            self._oauth_progress = QProgressDialog(
                "Waiting for authentication...\n\n"
                "Please complete sign-in in your browser.\n"
                "This dialog will close automatically when done.",
                "Use Manual Entry",
                0, 0,
                self
            )
            self._oauth_progress.setWindowTitle("Google Gemini Authentication")
            self._oauth_progress.setWindowModality(Qt.WindowModal)
            self._oauth_progress.setMinimumDuration(0)
            self._oauth_progress.setMinimumWidth(400)

            self._oauth_worker = GeminiOAuthWorker(timeout=300)
            self._oauth_worker.authentication_complete.connect(self._on_gemini_auth_complete)
            self._oauth_worker.authentication_failed.connect(self._on_gemini_auth_failed)
            self._oauth_worker.status_update.connect(
                lambda msg: self._oauth_progress.setLabelText(msg) if self._oauth_progress else None
            )

            def on_cancel():
                if getattr(self, '_oauth_auth_completed', False):
                    return
                if hasattr(self, '_oauth_worker') and self._oauth_worker:
                    self._oauth_worker.cancel()

            self._oauth_progress.canceled.connect(on_cancel)
            self._oauth_worker.finished.connect(self._oauth_worker.deleteLater)

            self._oauth_worker.start()
            self._oauth_progress.show()

        except ImportError as e:
            log.log_error(f"OAuth import error: {e}")
            self._authenticate_gemini_manual()
        except Exception as e:
            log.log_error(f"OAuth authentication error: {e}")
            self._authenticate_gemini_manual()

    def _on_gemini_auth_complete(self, result: dict):
        """Handle successful Gemini OAuth authentication"""
        from ..qt_compat import QMessageBox

        self._oauth_auth_completed = True

        if hasattr(self, '_oauth_progress') and self._oauth_progress:
            self._oauth_progress.close()
            self._oauth_progress = None

        credentials_json = result.get('credentials_json', '')
        self.key_edit.setText(credentials_json)

        email = result.get('email', '')
        email_msg = f" ({email})" if email else ""

        log.log_info("Gemini OAuth authentication successful - token stored in API key field")
        QMessageBox.information(self, "Authentication Successful",
            f"Successfully authenticated with Google Gemini{email_msg}!\n\n"
            "The OAuth token has been stored. Click OK to save the provider.")

    def _on_gemini_auth_failed(self, error: str):
        """Handle failed Gemini OAuth authentication"""
        from ..qt_compat import QMessageBox

        self._oauth_auth_completed = True

        if hasattr(self, '_oauth_progress') and self._oauth_progress:
            self._oauth_progress.close()
            self._oauth_progress = None

        if error == "cancelled":
            log.log_info("User cancelled automatic OAuth, showing manual entry")
            self._authenticate_gemini_manual()
            return
        elif error == "timeout":
            reply = QMessageBox.question(
                self,
                "Authentication Timeout",
                "The authentication request timed out.\n\n"
                "Would you like to try manual code entry instead?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                self._authenticate_gemini_manual()
        elif error.startswith("server_error:"):
            log.log_info("Falling back to manual entry due to server error")
            self._authenticate_gemini_manual()
        else:
            reply = QMessageBox.question(
                self,
                "Authentication Error",
                f"An error occurred during authentication:\n\n{error}\n\n"
                "Would you like to try manual code entry instead?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                self._authenticate_gemini_manual()

    def _authenticate_gemini_manual(self):
        """Manual fallback for Gemini OAuth authentication using headless mode"""
        from ..qt_compat import QMessageBox, QInputDialog
        import asyncio

        try:
            from ..services.llm_providers.oauth_gemini_utils import (
                generate_pkce,
                generate_state,
                open_headless_auth_browser,
                exchange_code_for_tokens,
                fetch_user_info,
                setup_user,
                create_credentials_json,
                OAUTH_HEADLESS_REDIRECT_URI,
            )

            # Generate PKCE codes and state (headless mode uses PKCE)
            verifier, challenge = generate_pkce()
            state = generate_state()

            # Open browser for authorization (headless mode with PKCE)
            auth_url = open_headless_auth_browser(challenge, state)
            log.log_info("Opened browser for Gemini OAuth authorization (manual mode)")

            # Show dialog to get authorization code from user
            code, ok = QInputDialog.getText(
                self,
                "OAuth Authentication (Manual)",
                "A browser window has been opened for Google Gemini authentication.\n\n"
                "1. Sign in to your Google account in the browser\n"
                "2. Authorize IDAssist to access your account\n"
                "3. Copy the authorization code shown on the page\n"
                "4. Paste it below:\n\n"
                "Authorization Code:"
            )

            if not ok or not code.strip():
                log.log_info("OAuth authentication cancelled by user")
                QMessageBox.information(self, "Authentication Cancelled",
                    "Authentication was cancelled.")
                return

            auth_code = code.strip()

            # Exchange code for tokens (with PKCE verifier for headless mode)
            log.log_info("Exchanging authorization code for tokens...")

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                tokens = loop.run_until_complete(
                    exchange_code_for_tokens(auth_code, OAUTH_HEADLESS_REDIRECT_URI, verifier)
                )

                if tokens.get("error"):
                    error_msg = tokens.get('error_description', tokens['error'])
                    log.log_error(f"OAuth token exchange failed: {error_msg}")
                    QMessageBox.critical(self, "Authentication Failed",
                        f"Token exchange failed: {error_msg}")
                    return

                # Fetch user info and setup
                email = loop.run_until_complete(fetch_user_info(tokens["access_token"]))
                user_info = loop.run_until_complete(setup_user(tokens["access_token"]))
            finally:
                loop.close()

            # Create JSON credentials and store
            credentials_json = create_credentials_json(
                tokens,
                email=email,
                project_id=user_info.get("project_id", ""),
                tier=user_info.get("tier", ""),
                tier_name=user_info.get("tier_name", ""),
            )
            self.key_edit.setText(credentials_json)

            email_msg = f" ({email})" if email else ""
            log.log_info("Gemini OAuth authentication successful - token stored in API key field")
            QMessageBox.information(self, "Authentication Successful",
                f"Successfully authenticated with Google Gemini{email_msg}!\n\n"
                "The OAuth token has been stored. Click OK to save the provider.")

        except ImportError as e:
            log.log_error(f"OAuth import error: {e}")
            QMessageBox.critical(self, "Missing Dependencies",
                f"OAuth authentication requires additional packages.\n\nError: {e}")
        except Exception as e:
            log.log_error(f"OAuth authentication error: {e}")
            QMessageBox.critical(self, "Authentication Error",
                f"An error occurred during authentication:\n\n{e}")


class MCPProviderDialog(QDialog):
    """Dialog for adding/editing MCP providers"""

    def __init__(self, parent=None, provider_data=None):
        super().__init__(parent)
        self.provider_data = provider_data
        self.setup_ui()

        if provider_data:
            self.populate_fields()

    def setup_ui(self):
        self.setWindowTitle("MCP Provider" if not self.provider_data else f"Edit {self.provider_data.get('name', 'Provider')}")
        self.setModal(True)
        self.resize(400, 300)

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Name:"))
        self.name_edit = QLineEdit()
        layout.addWidget(self.name_edit)

        layout.addWidget(QLabel("URL:"))
        self.url_edit = QLineEdit()
        layout.addWidget(self.url_edit)

        layout.addWidget(QLabel("Transport:"))
        self.transport_combo = QComboBox()
        self.transport_combo.addItem("SSE (HTTP)", "sse")
        self.transport_combo.addItem("Streamable HTTP", "streamablehttp")
        layout.addWidget(self.transport_combo)

        self.transport_combo.currentTextChanged.connect(self.on_transport_changed)
        self.on_transport_changed()

        self.enabled_check = QCheckBox("Enabled")
        self.enabled_check.setChecked(True)
        layout.addWidget(self.enabled_check)

        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Cancel")

        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def on_transport_changed(self):
        """Handle transport type change"""
        transport_data = self.transport_combo.currentData()
        if transport_data == "sse":
            self.url_edit.setPlaceholderText("e.g., http://localhost:8000/sse")
        else:
            self.url_edit.setPlaceholderText("e.g., http://localhost:8000/mcp")

    def populate_fields(self):
        """Populate fields with existing provider data"""
        if self.provider_data:
            self.name_edit.setText(self.provider_data.get('name', ''))
            self.url_edit.setText(self.provider_data.get('url', ''))

            raw_transport = self.provider_data.get('transport', 'sse').lower().strip()
            # Normalize legacy transport values
            transport_map = {'http': 'streamablehttp', 'streamable_http': 'streamablehttp'}
            transport_value = transport_map.get(raw_transport, raw_transport)
            index = self.transport_combo.findData(transport_value)
            if index >= 0:
                self.transport_combo.setCurrentIndex(index)

            self.enabled_check.setChecked(self.provider_data.get('enabled', True))
            self.on_transport_changed()

    def get_provider_data(self):
        """Get the provider data from the form"""
        return {
            'name': self.name_edit.text().strip(),
            'url': self.url_edit.text().strip(),
            'transport': self.transport_combo.currentData(),
            'enabled': self.enabled_check.isChecked()
        }


class SettingsController(QObject):
    """Controller for managing settings between view and service layers"""

    def __init__(self, settings_view: SettingsTabView):
        super().__init__()
        self.view = settings_view
        self.service = settings_service
        self.mcp_service = MCPClientService()

        self.connect_signals()
        self.load_initial_data()

    def connect_signals(self):
        """Connect view signals to controller methods"""
        self.view.llm_provider_add_requested.connect(self.add_llm_provider)
        self.view.llm_provider_edit_requested.connect(self.edit_llm_provider)
        self.view.llm_provider_duplicate_requested.connect(self.duplicate_llm_provider)
        self.view.llm_provider_delete_requested.connect(self.delete_llm_provider)
        self.view.llm_provider_test_requested.connect(self.test_llm_provider)
        self.view.llm_active_provider_changed.connect(self.set_active_llm_provider)
        self.view.reasoning_effort_changed.connect(self.update_reasoning_effort)

        self.view.mcp_provider_add_requested.connect(self.add_mcp_provider)
        self.view.mcp_provider_edit_requested.connect(self.edit_mcp_provider)
        self.view.mcp_provider_duplicate_requested.connect(self.duplicate_mcp_provider)
        self.view.mcp_provider_delete_requested.connect(self.delete_mcp_provider)
        self.view.mcp_provider_test_requested.connect(self.test_mcp_provider)

        self.view.system_prompt_changed.connect(self.update_system_prompt)
        self.view.database_path_changed.connect(self.update_database_path)

        self.view.symgraph_api_url_changed.connect(self.update_symgraph_api_url)
        self.view.symgraph_api_key_changed.connect(self.update_symgraph_api_key)
        self.view.symgraph_test_requested.connect(self.test_symgraph)

        self.view.llm_test_cancel_requested.connect(self.cancel_llm_test)
        self.view.mcp_test_cancel_requested.connect(self.cancel_mcp_test)
        self.view.symgraph_test_cancel_requested.connect(self.cancel_symgraph_test)

    def load_initial_data(self):
        """Load initial data from service into view"""
        try:
            self.view.active_provider_combo.currentTextChanged.disconnect()

            self.view.llm_table.setRowCount(0)
            self.view.mcp_table.setRowCount(0)
            self.view.active_provider_combo.clear()

            llm_providers = self.service.get_llm_providers()
            for provider in llm_providers:
                self.view.add_llm_provider(
                    provider['name'], provider['model'],
                    provider.get('provider_type', 'openai_platform'),
                    provider['url'], provider['max_tokens'],
                    provider['api_key'], provider['disable_tls']
                )

            mcp_providers = self.service.get_mcp_providers()
            for provider in mcp_providers:
                self.view.add_mcp_provider(
                    provider['name'], provider['url'],
                    provider['enabled'], provider['transport']
                )

            active_provider = self.service.get_active_llm_provider()
            log.log_debug(f"Loading active provider: {active_provider}")
            if active_provider and self.view.active_provider_combo.count() > 0:
                provider_name = active_provider['name']
                index = self.view.active_provider_combo.findText(provider_name)
                log.log_debug(f"Looking for provider '{provider_name}', found at index: {index}")
                if index >= 0:
                    self.view.active_provider_combo.setCurrentIndex(index)
                    reasoning_effort = active_provider.get('reasoning_effort', 'none')
                    self.view.set_reasoning_effort(reasoning_effort)

            system_prompt = self.service.get_setting('system_prompt', '')
            self.view.system_prompt_text.setPlainText(system_prompt)

            self.view.analysis_db_path.setText(self.service.get_setting('analysis_db_path', ''))
            self.view.rlhf_db_path.setText(self.service.get_setting('rlhf_db_path', ''))
            self.view.rag_index_path.setText(self.service.get_setting('rag_index_path', ''))

            if hasattr(self.view, 'symgraph_url_field'):
                self.view.set_symgraph_api_url(self.service.get_symgraph_api_url())
                self.view.set_symgraph_api_key(self.service.get_symgraph_api_key())

        except Exception as e:
            self.show_error("Failed to load settings", str(e))
        finally:
            self.view.active_provider_combo.currentTextChanged.connect(self.set_active_llm_provider)

    def add_llm_provider(self):
        dialog = ProviderDialog(self.view)
        if exec_dialog(dialog) == QDialog.Accepted:
            try:
                data = dialog.get_provider_data()
                is_cli_provider = data.get('provider_type') == 'anthropic_cli'
                if not data['name'] or not data['model']:
                    self.show_error("Validation Error", "Name and Model are required fields.")
                    return
                if not is_cli_provider and not data['url']:
                    self.show_error("Validation Error", "URL is required for this provider type.")
                    return

                provider_id = self.service.add_llm_provider(
                    data['name'], data['model'], data['url'],
                    data['max_tokens'], data['api_key'], data['disable_tls'], data['provider_type']
                )

                providers = self.service.get_llm_providers()
                if len(providers) == 1:
                    self.service.set_active_llm_provider(data['name'])

                self.load_initial_data()
                self.show_info("Success", f"Added LLM provider '{data['name']}'")

            except ValueError as e:
                self.show_error("Provider Already Exists", str(e))
            except Exception as e:
                self.show_error("Failed to Add Provider", str(e))

    def edit_llm_provider(self, row):
        if row < 0 or row >= self.view.llm_table.rowCount():
            return
        try:
            providers = self.service.get_llm_providers()
            if row >= len(providers):
                return
            provider = providers[row]
            dialog = ProviderDialog(self.view, provider)

            if exec_dialog(dialog) == QDialog.Accepted:
                data = dialog.get_provider_data()
                is_cli_provider = data.get('provider_type') == 'anthropic_cli'
                if not data['name'] or not data['model']:
                    self.show_error("Validation Error", "Name and Model are required fields.")
                    return
                if not is_cli_provider and not data['url']:
                    self.show_error("Validation Error", "URL is required for this provider type.")
                    return

                self.service.update_llm_provider(provider['id'], **data)
                self.load_initial_data()
                self.show_info("Success", f"Updated LLM provider '{data['name']}'")

        except Exception as e:
            self.show_error("Failed to Update Provider", str(e))

    def duplicate_llm_provider(self, row):
        if row < 0 or row >= self.view.llm_table.rowCount():
            return
        try:
            providers = self.service.get_llm_providers()
            if row >= len(providers):
                return
            provider = providers[row]
            new_name = provider['name'] + " - Copy"
            self.service.add_llm_provider(
                new_name, provider['model'], provider['url'],
                provider['max_tokens'], provider['api_key'],
                provider['disable_tls'], provider.get('provider_type', 'openai_platform')
            )
            self.load_initial_data()
            self.show_info("Success", f"Duplicated LLM provider as '{new_name}'")
        except Exception as e:
            self.show_error("Failed to Duplicate Provider", str(e))

    def delete_llm_provider(self, row):
        if row < 0 or row >= self.view.llm_table.rowCount():
            return
        try:
            providers = self.service.get_llm_providers()
            if row >= len(providers):
                return
            provider = providers[row]

            reply = QMessageBox.question(
                self.view, "Confirm Deletion",
                f"Are you sure you want to delete the LLM provider '{provider['name']}'?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                self.service.delete_llm_provider(provider['id'])
                self.view.llm_table.removeRow(row)
                self.view.active_provider_combo.removeItem(row)
                self.show_info("Success", f"Deleted LLM provider '{provider['name']}'")

        except Exception as e:
            self.show_error("Failed to Delete Provider", str(e))

    def test_llm_provider(self, row):
        try:
            providers = self.service.get_llm_providers()
            if row >= len(providers):
                return
            provider = providers[row]

            provider_type = provider.get('provider_type', '')
            requires_key = provider_type not in ('ollama', 'anthropic_cli', 'anthropic_oauth', 'openai_oauth', 'gemini_oauth')
            if not provider.get('api_key') and requires_key:
                self.view.set_llm_test_status('failure',
                    f"Provider '{provider['name']}' has no API key configured.")
                return

            self.view.set_llm_test_enabled(False)
            self.view.set_llm_test_status('testing', f"Testing {provider['name']}...")

            self.test_worker = ProviderTestWorker(provider)
            self.test_worker.test_completed.connect(self.on_provider_test_completed)
            self.test_worker.finished.connect(self.test_worker.deleteLater)
            self.test_worker.start()

        except Exception as e:
            self.view.set_llm_test_enabled(True)
            self.view.set_llm_test_status('failure', f"Test failed: {str(e)}")

    def on_provider_test_completed(self, success, message):
        if self.view.llm_test_button.text() != "Cancel":
            return  # Already cancelled
        self.view.set_llm_test_enabled(True)
        if success:
            self.view.set_llm_test_status('success', message)
        else:
            self.view.set_llm_test_status('failure', message)

    def cancel_llm_test(self):
        if hasattr(self, 'test_worker') and self.test_worker and self.test_worker.isRunning():
            self.test_worker.requestInterruption()
            self.test_worker.quit()
            self.test_worker.wait(2000)
        self.view.set_llm_test_enabled(True)
        self.view.set_llm_test_status('failure', 'Test cancelled by user')

    def set_active_llm_provider(self, provider_name):
        log.log_debug(f"set_active_llm_provider called with: '{provider_name}'")
        if not provider_name:
            return
        try:
            self.view.active_provider_combo.currentTextChanged.disconnect()
            success = self.service.set_active_llm_provider(provider_name)
            provider = self.service.get_active_llm_provider()
            if provider:
                reasoning_effort = provider.get('reasoning_effort', 'none')
                self.view.set_reasoning_effort(reasoning_effort)
            self.view.active_provider_combo.currentTextChanged.connect(self.set_active_llm_provider)
        except Exception as e:
            log.log_error(f"Error setting active provider: {e}")
            try:
                self.view.active_provider_combo.currentTextChanged.connect(self.set_active_llm_provider)
            except:
                pass
            self.show_error("Failed to Set Active Provider", str(e))

    def update_reasoning_effort(self, reasoning_effort: str):
        try:
            provider = self.service.get_active_llm_provider()
            if not provider:
                return
            provider_id = provider.get('id')
            if provider_id:
                self.service.update_llm_provider(provider_id, reasoning_effort=reasoning_effort)
                log.log_info(f"Updated reasoning effort to '{reasoning_effort}' for provider: {provider.get('name')}")
        except Exception as e:
            log.log_error(f"Error updating reasoning effort: {e}")

    def add_mcp_provider(self):
        dialog = MCPProviderDialog(self.view)
        if exec_dialog(dialog) == QDialog.Accepted:
            try:
                data = dialog.get_provider_data()
                if not all([data['name'], data['url']]):
                    self.show_error("Validation Error", "Name and URL are required fields.")
                    return

                provider_id = self.service.add_mcp_provider(
                    data['name'], data['url'], data['enabled'], data['transport']
                )
                self.load_initial_data()
                self.show_info("Success", f"Added MCP provider '{data['name']}'")

            except ValueError as e:
                self.show_error("Provider Already Exists", str(e))
            except Exception as e:
                self.show_error("Failed to Add Provider", str(e))

    def edit_mcp_provider(self, row):
        if row < 0 or row >= self.view.mcp_table.rowCount():
            return
        try:
            providers = self.service.get_mcp_providers()
            if row >= len(providers):
                return
            provider = providers[row]
            dialog = MCPProviderDialog(self.view, provider)

            if exec_dialog(dialog) == QDialog.Accepted:
                data = dialog.get_provider_data()
                if not all([data['name'], data['url']]):
                    self.show_error("Validation Error", "Name and URL are required fields.")
                    return
                self.service.update_mcp_provider(provider['id'], **data)
                self.load_initial_data()
                self.show_info("Success", f"Updated MCP provider '{data['name']}'")

        except Exception as e:
            self.show_error("Failed to Update Provider", str(e))

    def duplicate_mcp_provider(self, row):
        if row < 0 or row >= self.view.mcp_table.rowCount():
            return
        try:
            providers = self.service.get_mcp_providers()
            if row >= len(providers):
                return
            provider = providers[row]
            new_name = provider['name'] + " - Copy"
            self.service.add_mcp_provider(
                new_name, provider['url'],
                provider.get('enabled', True), provider.get('transport', 'sse')
            )
            self.load_initial_data()
            self.show_info("Success", f"Duplicated MCP provider as '{new_name}'")
        except Exception as e:
            self.show_error("Failed to Duplicate Provider", str(e))

    def delete_mcp_provider(self, row):
        if row < 0 or row >= self.view.mcp_table.rowCount():
            return
        try:
            providers = self.service.get_mcp_providers()
            if row >= len(providers):
                return
            provider = providers[row]

            reply = QMessageBox.question(
                self.view, "Confirm Deletion",
                f"Are you sure you want to delete the MCP provider '{provider['name']}'?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                self.service.delete_mcp_provider(provider['id'])
                self.view.mcp_table.removeRow(row)
                self.show_info("Success", f"Deleted MCP provider '{provider['name']}'")

        except Exception as e:
            self.show_error("Failed to Delete Provider", str(e))

    def test_mcp_provider(self, row):
        try:
            providers = self.service.get_mcp_providers()
            if row >= len(providers):
                return
            provider = providers[row]

            if not provider.get('url'):
                self.view.set_mcp_test_status('failure',
                    f"Provider '{provider['name']}' has no URL configured.")
                return

            self.view.set_mcp_test_enabled(False)
            self.view.set_mcp_test_status('testing', f"Testing {provider['name']}...")

            self.mcp_test_worker = MCPTestWorker(provider)
            self.mcp_test_worker.test_completed.connect(self.on_mcp_test_completed)
            self.mcp_test_worker.finished.connect(self.mcp_test_worker.deleteLater)
            self.mcp_test_worker.start()

        except Exception as e:
            self.view.set_mcp_test_enabled(True)
            self.view.set_mcp_test_status('failure', f"Test failed: {str(e)}")

    def on_mcp_test_completed(self, success, message, test_data):
        if self.view.mcp_test_button.text() != "Cancel":
            return  # Already cancelled
        self.view.set_mcp_test_enabled(True)
        if success:
            self.view.set_mcp_test_status('success', message)
        else:
            self.view.set_mcp_test_status('failure', message)

    def cancel_mcp_test(self):
        if hasattr(self, 'mcp_test_worker') and self.mcp_test_worker and self.mcp_test_worker.isRunning():
            self.mcp_test_worker.requestInterruption()
            self.mcp_test_worker.quit()
            self.mcp_test_worker.wait(2000)
        self.view.set_mcp_test_enabled(True)
        self.view.set_mcp_test_status('failure', 'Test cancelled by user')

    def update_system_prompt(self, prompt_text):
        try:
            self.service.set_setting('system_prompt', prompt_text, 'system')
        except Exception as e:
            self.show_error("Failed to Update System Prompt", str(e))

    def update_database_path(self, path_type, path_value):
        try:
            setting_key = f"{path_type}_path"
            self.service.set_setting(setting_key, path_value, 'database')
        except Exception as e:
            self.show_error("Failed to Update Database Path", str(e))

    def update_symgraph_api_url(self, url):
        try:
            self.service.set_symgraph_api_url(url)
        except Exception as e:
            self.show_error("Failed to Update SymGraph API URL", str(e))

    def update_symgraph_api_key(self, key):
        try:
            self.service.set_symgraph_api_key(key)
        except Exception as e:
            self.show_error("Failed to Update SymGraph API Key", str(e))

    def test_symgraph(self):
        try:
            self.service.set_symgraph_api_url(self.view.symgraph_url_field.text().strip())
            self.service.set_symgraph_api_key(self.view.symgraph_key_field.text())

            self.view.set_symgraph_test_enabled(False)
            self.view.set_symgraph_test_status('testing', 'Testing SymGraph API connection...')

            self.symgraph_test_worker = SymGraphTestWorker()
            self.symgraph_test_worker.test_completed.connect(self.on_symgraph_test_completed)
            self.symgraph_test_worker.finished.connect(self.symgraph_test_worker.deleteLater)
            self.symgraph_test_worker.start()

        except Exception as e:
            self.show_error("Test Failed", str(e))
            self.view.set_symgraph_test_enabled(True)
            self.view.set_symgraph_test_status('failure', f'Test failed: {str(e)}')

    def on_symgraph_test_completed(self, success, message):
        if self.view.symgraph_test_button.text() != "Cancel":
            return  # Already cancelled
        self.view.set_symgraph_test_enabled(True)
        if success:
            self.view.set_symgraph_test_status('success', message)
        else:
            self.view.set_symgraph_test_status('failure', message)

    def cancel_symgraph_test(self):
        if hasattr(self, 'symgraph_test_worker') and self.symgraph_test_worker and self.symgraph_test_worker.isRunning():
            self.symgraph_test_worker.requestInterruption()
            self.symgraph_test_worker.quit()
            self.symgraph_test_worker.wait(2000)
        self.view.set_symgraph_test_enabled(True)
        self.view.set_symgraph_test_status('failure', 'Test cancelled by user')

    def show_error(self, title, message):
        QMessageBox.critical(self.view, title, message)

    def show_info(self, title, message):
        QMessageBox.information(self.view, title, message)
