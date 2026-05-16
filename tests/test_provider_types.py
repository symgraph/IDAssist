"""Tests for ProviderType enum - verifies BEDROCK and existing providers."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.services.models.provider_types import ProviderType


class TestProviderTypeEnum(unittest.TestCase):
    """ProviderType enum integrity checks."""

    def test_bedrock_enum_exists(self):
        """BEDROCK enum value exists and has correct string value."""
        self.assertIn(ProviderType.BEDROCK, ProviderType)
        self.assertEqual(ProviderType.BEDROCK.value, "bedrock")

    def test_all_provider_types_have_display_names(self):
        """Every ProviderType has a display name."""
        for pt in ProviderType:
            names = ProviderType.get_display_names()
            self.assertIn(pt, names)
            self.assertTrue(len(names[pt]) > 0)

    def test_all_provider_types_have_default_urls(self):
        """Every ProviderType has a default URL (may be empty)."""
        for pt in ProviderType:
            urls = ProviderType.get_default_urls()
            self.assertIn(pt, urls)
            self.assertIsInstance(urls[pt], str)

    def test_all_provider_types_have_default_models(self):
        """Every ProviderType has a default models list."""
        for pt in ProviderType:
            models = ProviderType.get_default_models()
            self.assertIn(pt, models)
            self.assertIsInstance(models[pt], list)

    def test_bedrock_defaults(self):
        """BEDROCK defaults are sensible."""
        self.assertEqual(ProviderType.BEDROCK.default_url, "")
        self.assertIn("anthropic.claude-sonnet-4-6", ProviderType.BEDROCK.default_models)
        self.assertEqual(ProviderType.BEDROCK.display_name, "AWS Bedrock")

    def test_bedrock_capabilities(self):
        """BEDROCK supports chat, streaming, tools, not embeddings, not API key."""
        self.assertTrue(ProviderType.supports_tool_calls(ProviderType.BEDROCK))
        self.assertTrue(ProviderType.supports_streaming(ProviderType.BEDROCK))
        self.assertFalse(ProviderType.supports_embeddings(ProviderType.BEDROCK))
        self.assertFalse(ProviderType.requires_api_key(ProviderType.BEDROCK))
        self.assertFalse(ProviderType.uses_oauth(ProviderType.BEDROCK))

    def test_existing_providers_unchanged(self):
        """Existing providers still have expected capabilities."""
        self.assertTrue(ProviderType.supports_streaming(ProviderType.OPENAI_PLATFORM))
        self.assertTrue(ProviderType.supports_streaming(ProviderType.ANTHROPIC_PLATFORM))
        self.assertTrue(ProviderType.requires_api_key(ProviderType.OPENAI_PLATFORM))
        self.assertFalse(ProviderType.requires_api_key(ProviderType.OLLAMA))
        self.assertTrue(ProviderType.supports_embeddings(ProviderType.OLLAMA))
        self.assertTrue(ProviderType.uses_oauth(ProviderType.GEMINI_OAUTH))

    def test_provider_type_string_conversion(self):
        """ProviderType converts to/from string correctly."""
        self.assertEqual(str(ProviderType.BEDROCK), "bedrock")
        self.assertIs(ProviderType("bedrock"), ProviderType.BEDROCK)

    def test_no_duplicate_values(self):
        """No two enum members share the same value."""
        values = [pt.value for pt in ProviderType]
        self.assertEqual(len(values), len(set(values)))


if __name__ == '__main__':
    unittest.main()
