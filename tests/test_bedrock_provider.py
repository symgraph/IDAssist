"""Tests for BedrockProvider with mocked boto3."""

import sys
import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.services.models.llm_models import (
    ChatRequest, ChatMessage, MessageRole, Usage
)
from src.services.models.provider_types import ProviderType


BEDROCK_MODULE = 'src.services.llm_providers.bedrock_provider'
BASE_CONFIG = {
    'name': 'Test Bedrock',
    'model': 'anthropic.claude-sonnet-4-6',
    'provider_type': 'bedrock',
    'aws_region': 'us-east-1',
    'rate_limit_max_retries': 1,
    'rate_limit_min_delay': 0.01,
    'rate_limit_max_delay': 0.01,
}


class TestBedrockProviderChat(unittest.TestCase):
    """BedrockProvider chat completion with mocked Converse API."""

    def setUp(self):
        """Create a BedrockProvider with a mocked boto3 client."""
        self.config = dict(BASE_CONFIG)

        self.mock_converse_response = {
            'output': {
                'message': {
                    'role': 'assistant',
                    'content': [{'text': 'Hello from Bedrock!'}]
                }
            },
            'stopReason': 'end_turn',
            'usage': {
                'inputTokens': 10,
                'outputTokens': 5,
            },
        }

        self.mock_converse_stream_response = {
            'stream': [
                {'messageStart': {'role': 'assistant', 'messageId': 'msg-1'}},
                {'contentBlockDelta': {
                    'contentBlockIndex': 0,
                    'delta': {'text': 'Hello '}
                }},
                {'contentBlockDelta': {
                    'contentBlockIndex': 0,
                    'delta': {'text': 'from Bedrock!'}
                }},
                {'messageStop': {'stopReason': 'end_turn'}},
                {'metadata': {
                    'usage': {'inputTokens': 10, 'outputTokens': 5}
                }},
            ]
        }

        self.mock_list_models_response = {
            'modelSummaries': [
                {'modelId': 'anthropic.claude-sonnet-4-6', 'modelName': 'Claude Sonnet 4.6'},
                {'modelId': 'amazon.nova-pro-v1:0', 'modelName': 'Nova Pro'},
            ]
        }

    def _create_provider(self):
        """Import and create a BedrockProvider (lazy import after mock setup)."""
        from src.services.llm_providers.bedrock_provider import BedrockProvider
        return BedrockProvider(self.config)

    def _make_request(self, text="Hello"):
        """Create a simple ChatRequest."""
        return ChatRequest(
            messages=[ChatMessage(role=MessageRole.USER, content=text)],
            model=self.config['model'],
            max_tokens=100,
        )

    @patch(BEDROCK_MODULE + '.boto3')
    async def _do_chat(self, mock_boto3):
        """Helper to run a single chat completion."""
        mock_client = MagicMock()
        mock_client.converse.return_value = self.mock_converse_response
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        provider = self._create_provider()
        request = self._make_request()
        response = await provider.chat_completion(request)

        return response, mock_client

    def test_chat_completion_returns_content(self):
        """chat_completion returns text from mock Converse API."""
        import asyncio
        response, client = asyncio.run(self._do_chat())
        self.assertEqual(response.content, 'Hello from Bedrock!')
        self.assertEqual(response.finish_reason, 'stop')

    def test_chat_completion_returns_usage(self):
        """chat_completion returns usage tokens."""
        import asyncio
        response, client = asyncio.run(self._do_chat())
        self.assertEqual(response.usage.prompt_tokens, 10)
        self.assertEqual(response.usage.completion_tokens, 5)
        self.assertEqual(response.usage.total_tokens, 15)

    def test_chat_completion_calls_converse(self):
        """chat_completion calls client.converse() with correct args."""
        import asyncio
        response, client = asyncio.run(self._do_chat())
        client.converse.assert_called_once()
        call_kwargs = client.converse.call_args[1]
        self.assertEqual(call_kwargs['modelId'], 'anthropic.claude-sonnet-4-6')
        self.assertEqual(len(call_kwargs['messages']), 1)
        self.assertEqual(call_kwargs['messages'][0]['role'], 'user')

    @patch(BEDROCK_MODULE + '.boto3')
    def test_chat_completion_with_system_prompt(self, mock_boto3):
        """System message is sent in Converse 'system' field."""
        import asyncio

        mock_client = MagicMock()
        mock_client.converse.return_value = self.mock_converse_response
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        provider = self._create_provider()
        request = ChatRequest(
            messages=[
                ChatMessage(role=MessageRole.SYSTEM, content="You are a helpful assistant."),
                ChatMessage(role=MessageRole.USER, content="Hello"),
            ],
            model=self.config['model'],
        )
        asyncio.run(provider.chat_completion(request))

        call_kwargs = mock_client.converse.call_args[1]
        self.assertIn('system', call_kwargs)
        self.assertEqual(call_kwargs['system'][0]['text'], "You are a helpful assistant.")

    @patch(BEDROCK_MODULE + '.boto3')
    def test_chat_completion_stream_yields_chunks(self, mock_boto3):
        """Stream returns content chunks and final metadata."""
        import asyncio

        mock_client = MagicMock()
        mock_client.converse_stream.return_value = self.mock_converse_stream_response
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        provider = self._create_provider()
        request = self._make_request()

        async def consume():
            chunks = []
            async for chunk in provider.chat_completion_stream(request):
                chunks.append(chunk)
            return chunks

        chunks = asyncio.run(consume())

        self.assertGreaterEqual(len(chunks), 2)
        texts = [c.content for c in chunks if c.is_streaming]
        final_chunks = [c for c in chunks if not c.is_streaming]

        combined = ''.join(texts)
        self.assertIn('Hello', combined)
        self.assertIn('Bedrock', combined)

        self.assertEqual(len(final_chunks), 1)
        self.assertEqual(final_chunks[0].usage.total_tokens, 15)

    @patch(BEDROCK_MODULE + '.boto3')
    def test_test_connection_success(self, mock_boto3):
        """test_connection returns True when Bedrock API responds."""
        import asyncio

        mock_client = MagicMock()
        mock_client.list_foundation_models.return_value = self.mock_list_models_response
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        provider = self._create_provider()
        result = asyncio.run(provider.test_connection())
        self.assertTrue(result)

    @patch(BEDROCK_MODULE + '.boto3')
    def test_test_connection_failure(self, mock_boto3):
        """test_connection returns False on ClientError."""
        import asyncio
        from botocore.exceptions import ClientError

        error_response = {'Error': {'Code': 'AccessDeniedException', 'Message': 'Not authorized'}}
        mock_client = MagicMock()
        mock_client.list_foundation_models.side_effect = ClientError(error_response, 'list_foundation_models')
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        provider = self._create_provider()
        result = asyncio.run(provider.test_connection())
        self.assertFalse(result)

    @patch(BEDROCK_MODULE + '.boto3')
    def test_authentication_error(self, mock_boto3):
        """chat_completion raises AuthenticationError on access denied."""
        import asyncio
        from botocore.exceptions import ClientError
        from src.services.llm_providers.base_provider import AuthenticationError

        error_response = {'Error': {'Code': 'AccessDeniedException', 'Message': 'Not authorized'}}
        mock_client = MagicMock()
        mock_client.converse.side_effect = ClientError(error_response, 'converse')
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        provider = self._create_provider()
        request = self._make_request()

        with self.assertRaises(AuthenticationError):
            asyncio.run(provider.chat_completion(request))

    @patch(BEDROCK_MODULE + '.boto3')
    def test_rate_limit_error(self, mock_boto3):
        """chat_completion raises RateLimitError on throttling."""
        import asyncio
        from botocore.exceptions import ClientError
        from src.services.llm_providers.base_provider import RateLimitError

        error_response = {'Error': {'Code': 'ThrottlingException', 'Message': 'Rate exceeded'}}
        mock_client = MagicMock()
        mock_client.converse.side_effect = ClientError(error_response, 'converse')
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        provider = self._create_provider()
        request = self._make_request()

        with self.assertRaises(RateLimitError):
            asyncio.run(provider.chat_completion(request))

    def test_get_provider_type(self):
        """get_provider_type returns ProviderType.BEDROCK."""
        provider = self._create_provider()
        self.assertEqual(provider.get_provider_type(), ProviderType.BEDROCK)

    def test_get_capabilities(self):
        """get_capabilities returns expected capabilities."""
        provider = self._create_provider()
        caps = provider.get_capabilities()
        self.assertTrue(caps.supports_chat)
        self.assertTrue(caps.supports_streaming)
        self.assertTrue(caps.supports_tools)
        self.assertFalse(caps.supports_embeddings)

    def test_embeddings_not_supported(self):
        """generate_embeddings raises NotImplementedError."""
        provider = self._create_provider()
        from src.services.models.llm_models import EmbeddingRequest
        with self.assertRaises(NotImplementedError):
            import asyncio
            asyncio.run(provider.generate_embeddings(
                EmbeddingRequest(texts=["hello"])
            ))


if __name__ == '__main__':
    unittest.main()
