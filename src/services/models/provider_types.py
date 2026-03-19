#!/usr/bin/env python3

"""
Provider Types Enum - Central definition of supported LLM provider types

Naming Convention:
- VENDOR_AUTHMETHOD where AUTHMETHOD is:
  - PLATFORM: Direct API key access to vendor's platform
  - OAUTH: OAuth-based subscription access (Pro/Plus/Max plans)
  - CLI: Command-line interface wrapper
- Local/Proxy providers keep simple names (OLLAMA, LITELLM, etc.)
"""

from enum import Enum


class ProviderType(Enum):
    """
    Enumeration of supported LLM provider types.
    Used throughout the plugin for type safety and consistency.

    Sorted alphabetically for consistency.
    """

    # Anthropic providers (alphabetically)
    ANTHROPIC_CLI = "anthropic_cli"           # Claude Code CLI wrapper
    ANTHROPIC_PLATFORM = "anthropic_platform" # Platform API (direct API key)

    # Local/Proxy providers (alphabetically)
    LITELLM = "litellm"                       # LiteLLM proxy
    LMSTUDIO = "lmstudio"                     # LM Studio (local)
    OLLAMA = "ollama"                         # Ollama (local)
    OPENWEBUI = "openwebui"                   # Open WebUI (local/proxy)

    # Gemini providers (alphabetically)
    GEMINI_OAUTH = "gemini_oauth"             # OAuth (Gemini CLI subscription)
    GEMINI_PLATFORM = "gemini_platform"       # Platform API (direct API key)

    # OpenAI providers (alphabetically)
    OPENAI_OAUTH = "openai_oauth"             # OAuth (ChatGPT Pro/Plus subscription)
    OPENAI_PLATFORM = "openai_platform"       # Platform API (direct API key)

    # X.ai providers
    XAI_PLATFORM = "xai_platform"             # Platform API (direct API key)

    @classmethod
    def get_display_names(cls) -> dict['ProviderType', str]:
        """Get human-readable display names for each provider type"""
        return {
            # Anthropic
            cls.ANTHROPIC_CLI: "Anthropic CLI (Claude Code)",
            cls.ANTHROPIC_PLATFORM: "Anthropic Platform API",
            # Gemini
            cls.GEMINI_OAUTH: "Gemini OAuth (Gemini CLI)",
            cls.GEMINI_PLATFORM: "Gemini Platform API",
            # Local/Proxy
            cls.LITELLM: "LiteLLM Proxy",
            cls.LMSTUDIO: "LM Studio",
            cls.OLLAMA: "Ollama",
            cls.OPENWEBUI: "Open WebUI",
            # OpenAI
            cls.OPENAI_OAUTH: "OpenAI OAuth (ChatGPT Pro/Plus)",
            cls.OPENAI_PLATFORM: "OpenAI Platform API",
            # X.ai
            cls.XAI_PLATFORM: "xAI Platform API",
        }

    @classmethod
    def get_default_urls(cls) -> dict['ProviderType', str]:
        """Get default API URLs for each provider type"""
        return {
            # Anthropic
            cls.ANTHROPIC_CLI: "",  # CLI-based, no URL needed
            cls.ANTHROPIC_PLATFORM: "https://api.anthropic.com",
            # Gemini
            cls.GEMINI_OAUTH: "https://cloudcode-pa.googleapis.com",
            cls.GEMINI_PLATFORM: "https://generativelanguage.googleapis.com/v1beta/openai/",
            # Local/Proxy
            cls.LITELLM: "http://localhost:4000",
            cls.LMSTUDIO: "http://localhost:1234/v1",
            cls.OLLAMA: "http://localhost:11434",
            cls.OPENWEBUI: "http://localhost:3000",
            # OpenAI
            cls.OPENAI_OAUTH: "https://chatgpt.com/backend-api/codex/responses",
            cls.OPENAI_PLATFORM: "https://api.openai.com/v1",
            # X.ai
            cls.XAI_PLATFORM: "https://api.x.ai/v1",
        }

    @classmethod
    def get_default_models(cls) -> dict['ProviderType', list[str]]:
        """Get default/popular models for each provider type"""
        return {
            # Anthropic
            cls.ANTHROPIC_CLI: [
                "sonnet", "opus", "haiku"  # CLI model shortcuts
            ],
            cls.ANTHROPIC_PLATFORM: [
                "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022",
                "claude-3-opus-20240229", "claude-3-sonnet-20240229"
            ],
            # Gemini
            cls.GEMINI_OAUTH: [
                "gemini-2.5-flash", "gemini-2.5-pro",
                "gemini-2.0-flash", "gemini-2.0-flash-lite"
            ],
            cls.GEMINI_PLATFORM: [
                "gemini-2.5-flash", "gemini-2.5-pro",
                "gemini-2.0-flash", "gemini-2.0-flash-lite"
            ],
            # Local/Proxy
            cls.LITELLM: [
                # LiteLLM proxies to various providers - models are dynamic
            ],
            cls.LMSTUDIO: [
                "microsoft/DialoGPT-medium", "microsoft/DialoGPT-large"
            ],
            cls.OLLAMA: [
                "llama3.1:8b", "llama3.1:70b", "codellama:7b", "mistral:7b",
                "phi3:mini", "qwen2:7b"
            ],
            cls.OPENWEBUI: [
                "gpt-4o", "claude-3-5-sonnet", "llama3.1:8b"
            ],
            # OpenAI
            cls.OPENAI_OAUTH: [
                "gpt-5.2-codex", "gpt-5.1-codex-max",
                "gpt-5.1-codex-mini", "gpt-5.2"
            ],
            cls.OPENAI_PLATFORM: [
                "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"
            ],
            # X.ai
            cls.XAI_PLATFORM: [
                "grok-3-mini", "grok-3"
            ],
        }

    @classmethod
    def supports_embeddings(cls, provider_type: 'ProviderType') -> bool:
        """Check if provider type supports embedding generation"""
        return provider_type in {
            cls.LITELLM,          # Can proxy embeddings
            cls.LMSTUDIO,         # Depends on loaded models
            cls.OLLAMA,           # Various embedding models
            cls.OPENWEBUI,        # Depends on connected providers
            cls.OPENAI_PLATFORM,  # text-embedding-3-small/large
        }

    @classmethod
    def supports_tool_calls(cls, provider_type: 'ProviderType') -> bool:
        """Check if provider type supports function/tool calling"""
        return provider_type in {
            cls.ANTHROPIC_CLI,       # Via CLI --allowedTools flag
            cls.ANTHROPIC_PLATFORM,  # Full tool calling support
            cls.GEMINI_OAUTH,        # Full tool calling support
            cls.GEMINI_PLATFORM,     # Full tool calling support
            cls.LITELLM,             # Proxies tool calls
            cls.LMSTUDIO,            # Limited support
            cls.OLLAMA,              # Limited support
            cls.OPENWEBUI,           # Depends on connected providers
            cls.OPENAI_OAUTH,        # Full tool calling via Responses API
            cls.OPENAI_PLATFORM,     # Full tool calling support
            cls.XAI_PLATFORM,        # Full tool calling support
        }

    @classmethod
    def supports_streaming(cls, provider_type: 'ProviderType') -> bool:
        """Check if provider type supports streaming responses"""
        return provider_type in {
            # Note: ANTHROPIC_CLI does NOT support true streaming
            cls.ANTHROPIC_PLATFORM,
            cls.GEMINI_OAUTH,
            cls.GEMINI_PLATFORM,
            cls.LITELLM,
            cls.LMSTUDIO,
            cls.OLLAMA,
            cls.OPENWEBUI,
            cls.OPENAI_OAUTH,
            cls.OPENAI_PLATFORM,
            cls.XAI_PLATFORM,
        }

    @classmethod
    def requires_api_key(cls, provider_type: 'ProviderType') -> bool:
        """Check if provider type requires an API key (vs OAuth or local)"""
        return provider_type in {
            cls.ANTHROPIC_PLATFORM,
            cls.GEMINI_PLATFORM,
            cls.OPENAI_PLATFORM,
            cls.XAI_PLATFORM,
        }

    @classmethod
    def uses_oauth(cls, provider_type: 'ProviderType') -> bool:
        """Check if provider type uses OAuth authentication"""
        return provider_type in {
            cls.GEMINI_OAUTH,
            cls.OPENAI_OAUTH,
        }

    @property
    def display_name(self) -> str:
        """Get human-readable display name for this provider type"""
        return self.get_display_names()[self]

    @property
    def default_url(self) -> str:
        """Get default API URL for this provider type"""
        return self.get_default_urls()[self]

    @property
    def default_models(self) -> list[str]:
        """Get default models for this provider type"""
        return self.get_default_models()[self]

    def __str__(self) -> str:
        """String representation uses the enum value"""
        return self.value
