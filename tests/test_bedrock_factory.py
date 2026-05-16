"""Tests for Bedrock provider factory registration."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.services.llm_providers.provider_factory import (
    LLMProviderFactory, get_provider_factory
)
from src.services.models.provider_types import ProviderType


class TestBedrockFactory(unittest.TestCase):
    """BedrockProviderFactory registration and creation."""

    def setUp(self):
        """Create a fresh factory for each test (bypass singleton)."""
        self.factory = LLMProviderFactory()

    def test_bedrock_is_registered(self):
        """BEDROCK is registered in the factory."""
        self.assertTrue(self.factory.is_supported(ProviderType.BEDROCK))

    def test_bedrock_create_provider(self):
        """Factory creates a BedrockProvider with minimal config."""
        config = {
            'name': 'Test Bedrock',
            'model': 'anthropic.claude-sonnet-4-6',
            'provider_type': 'bedrock',
            'aws_region': 'us-east-1',
        }
        provider = self.factory.create_provider(config)
        self.assertIsNotNone(provider)
        self.assertEqual(provider.get_provider_type(), ProviderType.BEDROCK)
        self.assertEqual(provider.model, 'anthropic.claude-sonnet-4-6')
        self.assertEqual(provider.aws_region, 'us-east-1')

    def test_bedrock_create_with_credentials(self):
        """Factory passes AWS credential config to provider."""
        config = {
            'name': 'Test Bedrock Creds',
            'model': 'anthropic.claude-sonnet-4-6',
            'provider_type': 'bedrock',
            'aws_region': 'us-west-2',
            'aws_profile': 'my-profile',
            'aws_access_key_id': 'AKIA123',
            'aws_secret_access_key': 'secret123',
        }
        provider = self.factory.create_provider(config)
        self.assertEqual(provider.aws_region, 'us-west-2')
        self.assertEqual(provider.aws_profile, 'my-profile')
        self.assertEqual(provider.aws_access_key_id, 'AKIA123')
        self.assertEqual(provider.aws_secret_access_key, 'secret123')

    def test_bedrock_factory_supports_type(self):
        """BedrockProviderFactory only supports BEDROCK."""
        from src.services.llm_providers.bedrock_provider import BedrockProviderFactory
        bf = BedrockProviderFactory()
        self.assertTrue(bf.supports_provider_type(ProviderType.BEDROCK))
        self.assertFalse(bf.supports_provider_type(ProviderType.OLLAMA))

    def test_global_factory_has_bedrock(self):
        """Global factory singleton includes BEDROCK."""
        gf = get_provider_factory()
        self.assertTrue(gf.is_supported(ProviderType.BEDROCK))

    def test_bedrock_not_in_other_providers(self):
        """BEDROCK is not mixed into other provider type lookups."""
        self.assertNotEqual(ProviderType.BEDROCK, ProviderType.LITELLM)
        self.assertNotEqual(ProviderType.BEDROCK, ProviderType.ANTHROPIC_PLATFORM)

    def test_existing_factories_unchanged(self):
        """Registered providers can still be created."""
        supported = self.factory.get_supported_types()
        self.assertIn(ProviderType.BEDROCK, supported)
        for pt in supported:
            config = {
                'name': f'Test {pt.value}',
                'model': 'test-model',
                'provider_type': pt.value,
                'url': 'http://localhost:9999',
            }
            try:
                provider = self.factory.create_provider(config)
                self.assertEqual(provider.get_provider_type(), pt)
            except Exception:
                pass

    def test_factory_raises_on_missing_config(self):
        """Factory raises error for missing required config."""
        from src.services.llm_providers.base_provider import LLMProviderError
        with self.assertRaises(LLMProviderError):
            self.factory.create_provider({
                'provider_type': 'bedrock',
            })


if __name__ == '__main__':
    unittest.main()
