"""Tests for SettingsService AWS field persistence via integration with DB."""

import sys
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.services.migrations.add_aws_bedrock_config import migrate_add_aws_bedrock_config


def _create_base_table(conn):
    """Create llm_providers table with original schema."""
    conn.execute('''
        CREATE TABLE IF NOT EXISTS llm_providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            model TEXT NOT NULL,
            url TEXT NOT NULL,
            max_tokens INTEGER DEFAULT 4096,
            api_key TEXT,
            disable_tls BOOLEAN DEFAULT 0,
            provider_type TEXT DEFAULT 'openai_platform',
            is_active BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')


class TestSettingsServiceAWSFields(unittest.TestCase):
    """AWS provider fields via direct SQL (matches SettingsService API)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'settings.db')
        conn = sqlite3.connect(self.db_path)
        _create_base_table(conn)
        conn.commit()
        conn.close()
        migrate_add_aws_bedrock_config(self.db_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _add_provider(self, name, model, url, provider_type, **extra):
        """Simulate SettingsService.add_llm_provider via direct SQL."""
        fields = {
            'name': name, 'model': model, 'url': url,
            'provider_type': provider_type,
            'aws_region': extra.get('aws_region', ''),
            'aws_profile': extra.get('aws_profile', ''),
            'aws_access_key_id': extra.get('aws_access_key_id', ''),
            'aws_secret_access_key': extra.get('aws_secret_access_key', ''),
        }
        cols = ', '.join(fields.keys())
        placeholders = ', '.join(['?'] * len(fields))
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            f'INSERT INTO llm_providers ({cols}) VALUES ({placeholders})',
            list(fields.values())
        )
        provider_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return provider_id

    def _get_providers(self):
        """Simulate SettingsService.get_llm_providers via direct SQL."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, name, model, url, max_tokens, api_key, disable_tls,
                   provider_type, is_active, aws_region, aws_profile,
                   aws_access_key_id, aws_secret_access_key
            FROM llm_providers ORDER BY name
        ''')
        providers = []
        for row in cursor.fetchall():
            providers.append({
                'id': row[0], 'name': row[1], 'model': row[2],
                'url': row[3], 'max_tokens': row[4], 'api_key': row[5],
                'disable_tls': bool(row[6]), 'provider_type': row[7],
                'is_active': bool(row[8]), 'aws_region': row[9],
                'aws_profile': row[10], 'aws_access_key_id': row[11],
                'aws_secret_access_key': row[12],
            })
        conn.close()
        return providers

    def test_add_provider_with_aws_fields(self):
        """INSERT with AWS fields succeeds."""
        pid = self._add_provider(
            'Test AWS', 'anthropic.claude-sonnet-4-6', '',
            'bedrock', aws_region='us-west-2',
            aws_profile='my-profile', aws_access_key_id='AKIA123',
            aws_secret_access_key='secret456',
        )
        self.assertGreater(pid, 0)

    def test_get_provider_returns_aws_fields(self):
        """SELECT returns stored AWS fields."""
        self._add_provider(
            'Test AWS', 'anthropic.claude-sonnet-4-6', '',
            'bedrock', aws_region='us-west-2',
            aws_profile='my-profile', aws_access_key_id='AKIA123',
        )
        providers = self._get_providers()
        self.assertEqual(len(providers), 1)
        p = providers[0]
        self.assertEqual(p['aws_region'], 'us-west-2')
        self.assertEqual(p['aws_profile'], 'my-profile')
        self.assertEqual(p['aws_access_key_id'], 'AKIA123')

    def test_non_bedrock_has_empty_aws_fields(self):
        """Non-Bedrock providers have empty AWS fields."""
        self._add_provider('Ollama', 'llama3.1:8b', 'http://localhost:11434', 'ollama')
        providers = self._get_providers()
        p = providers[0]
        self.assertEqual(p['aws_region'], '')
        self.assertEqual(p['aws_profile'], '')

    def test_mixed_providers(self):
        """Bedrock and non-Bedrock coexist."""
        self._add_provider('Bedrock', 'anthropic.claude-sonnet-4-6', '', 'bedrock',
                          aws_region='us-east-1')
        self._add_provider('Ollama', 'llama3.1:8b', 'http://localhost:11434', 'ollama')
        providers = self._get_providers()
        self.assertEqual(len(providers), 2)
        bedrock = [p for p in providers if p['name'] == 'Bedrock'][0]
        ollama = [p for p in providers if p['name'] == 'Ollama'][0]
        self.assertEqual(bedrock['aws_region'], 'us-east-1')
        self.assertEqual(ollama['aws_region'], '')

    def test_update_aws_fields(self):
        """UPDATE modifies AWS fields correctly."""
        pid = self._add_provider('Bedrock', 'anthropic.claude-sonnet-4-6', '', 'bedrock',
                                aws_region='us-east-1')
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            'UPDATE llm_providers SET aws_region = ?, aws_profile = ? WHERE id = ?',
            ('eu-west-1', 'prod', pid)
        )
        conn.commit()
        conn.close()

        providers = self._get_providers()
        p = providers[0]
        self.assertEqual(p['aws_region'], 'eu-west-1')
        self.assertEqual(p['aws_profile'], 'prod')


if __name__ == '__main__':
    unittest.main()
