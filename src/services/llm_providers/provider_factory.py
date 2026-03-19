#!/usr/bin/env python3

"""
Provider Factory - Factory pattern for creating LLM providers
Handles dynamic provider instantiation based on configuration
"""

from typing import Dict, Any, Optional
from abc import ABC, abstractmethod

from .base_provider import BaseLLMProvider, LLMProviderError
from ..models.provider_types import ProviderType


class ProviderFactory(ABC):
    """Abstract factory for creating LLM providers"""

    @abstractmethod
    def create_provider(self, config: Dict[str, Any]) -> BaseLLMProvider:
        """Create a provider instance from configuration"""
        pass

    @abstractmethod
    def supports_provider_type(self, provider_type: ProviderType) -> bool:
        """Check if this factory supports the given provider type"""
        pass


class LLMProviderFactory:
    """
    Main factory for creating LLM providers.

    Uses registry pattern to support multiple provider types.
    """

    def __init__(self):
        """Initialize factory with empty registry"""
        self._factories: Dict[ProviderType, ProviderFactory] = {}
        self._register_default_factories()

    def register_factory(self, provider_type: ProviderType, factory: ProviderFactory):
        """
        Register a provider factory for a specific type

        Args:
            provider_type: Type of provider this factory creates
            factory: Factory instance to register
        """
        self._factories[provider_type] = factory

    def create_provider(self, config: Dict[str, Any]) -> BaseLLMProvider:
        """
        Create provider instance from configuration

        Args:
            config: Provider configuration dictionary containing:
                - provider_type: Type of provider (ProviderType enum value)
                - name, model, url, api_key, etc.

        Returns:
            Initialized provider instance

        Raises:
            LLMProviderError: If provider type not supported or creation fails
        """
        # Extract and validate provider type
        provider_type_str = config.get('provider_type', 'openai_platform')

        try:
            if isinstance(provider_type_str, str):
                provider_type = ProviderType(provider_type_str)
            else:
                provider_type = provider_type_str
        except ValueError:
            raise LLMProviderError(f"Unsupported provider type: {provider_type_str}")

        # Find appropriate factory
        if provider_type not in self._factories:
            raise LLMProviderError(f"No factory registered for provider type: {provider_type}")

        factory = self._factories[provider_type]

        try:
            return factory.create_provider(config)
        except Exception as e:
            raise LLMProviderError(f"Failed to create provider: {e}") from e

    def get_supported_types(self) -> list[ProviderType]:
        """Get list of supported provider types"""
        return list(self._factories.keys())

    def is_supported(self, provider_type: ProviderType) -> bool:
        """Check if provider type is supported"""
        return provider_type in self._factories

    def _register_default_factories(self):
        """Register default provider factories"""
        # Import and register available provider factories

        # Anthropic Claude CLI provider
        try:
            from .anthropic_claude_cli_provider import AnthropicClaudeCliProviderFactory
            self.register_factory(
                ProviderType.ANTHROPIC_CLI,
                AnthropicClaudeCliProviderFactory()
            )
        except ImportError:
            pass  # Anthropic Claude CLI provider not available

        # Anthropic Platform API provider
        try:
            from .anthropic_platform_api_provider import AnthropicPlatformApiProviderFactory
            self.register_factory(
                ProviderType.ANTHROPIC_PLATFORM,
                AnthropicPlatformApiProviderFactory()
            )
        except ImportError:
            pass  # Anthropic Platform API provider not available

        # LiteLLM proxy provider
        try:
            self.register_factory(
                ProviderType.LITELLM,
                LiteLLMProviderFactory()
            )
        except ImportError:
            pass  # LiteLLM provider not available

        # Ollama provider (local)
        try:
            from .ollama_provider import OllamaProviderFactory
            self.register_factory(
                ProviderType.OLLAMA,
                OllamaProviderFactory()
            )
        except ImportError:
            pass  # Ollama provider not available

        # OpenAI OAuth provider (ChatGPT Pro/Plus subscription)
        try:
            from .openai_oauth_provider import OpenAIOAuthProviderFactory
            self.register_factory(
                ProviderType.OPENAI_OAUTH,
                OpenAIOAuthProviderFactory()
            )
        except ImportError:
            pass  # OpenAI OAuth provider not available

        # OpenAI Platform API provider (handles OpenAI, LM Studio, OpenWebUI, X.ai, Gemini Platform)
        try:
            from .openai_platform_api_provider import OpenAIPlatformApiProviderFactory
            openai_factory = OpenAIPlatformApiProviderFactory()
            self.register_factory(ProviderType.OPENAI_PLATFORM, openai_factory)
            self.register_factory(ProviderType.LMSTUDIO, openai_factory)
            self.register_factory(ProviderType.OPENWEBUI, openai_factory)
            self.register_factory(ProviderType.XAI_PLATFORM, openai_factory)
            self.register_factory(ProviderType.GEMINI_PLATFORM, openai_factory)
        except ImportError:
            pass  # OpenAI Platform API provider not available

        # Gemini OAuth provider (Gemini CLI subscription)
        try:
            from .gemini_oauth_provider import GeminiOAuthProviderFactory
            self.register_factory(
                ProviderType.GEMINI_OAUTH,
                GeminiOAuthProviderFactory()
            )
        except ImportError:
            pass  # Gemini OAuth provider not available


class AnthropicPlatformApiProviderFactory(ProviderFactory):
    """Factory for creating Anthropic Platform API providers"""

    def create_provider(self, config: Dict[str, Any]) -> BaseLLMProvider:
        """Create Anthropic Platform API provider instance"""
        from .anthropic_platform_api_provider import AnthropicPlatformApiProvider
        return AnthropicPlatformApiProvider(config)

    def supports_provider_type(self, provider_type: ProviderType) -> bool:
        """Check if this factory supports Anthropic Platform API providers"""
        return provider_type == ProviderType.ANTHROPIC_PLATFORM


class LiteLLMProviderFactory(ProviderFactory):
    """Factory for creating LiteLLM providers"""

    def create_provider(self, config: Dict[str, Any]) -> BaseLLMProvider:
        """Create LiteLLM provider instance"""
        from .litellm_provider import LiteLLMProvider
        return LiteLLMProvider(config)

    def supports_provider_type(self, provider_type: ProviderType) -> bool:
        """Check if this factory supports LiteLLM providers"""
        return provider_type == ProviderType.LITELLM


# Note: Provider factory classes are defined in their respective provider modules.
# Example: AnthropicPlatformApiProviderFactory is in anthropic_platform_api_provider.py


# Global factory instance
_provider_factory = None

def get_provider_factory() -> LLMProviderFactory:
    """Get the global provider factory instance"""
    global _provider_factory
    if _provider_factory is None:
        _provider_factory = LLMProviderFactory()
    return _provider_factory
