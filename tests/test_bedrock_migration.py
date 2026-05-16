"""Tests for AWS Bedrock DB migration - idempotent, adds columns correctly."""

import sys
import os
import sqlite3
import unittest
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.services.migrations.add_aws_bedrock_config import migrate_add_aws_bedrock_config


def _create_minimal_db(path):
    """Create a llm_providers table matching the pre-migration schema."""
    conn = sqlite3.connect(path)
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
    conn.execute('''
        INSERT INTO llm_providers (name, model, url, provider_type)
        VALUES ('test-ollama', 'llama3.1:8b', 'http://localhost:11434', 'ollama')
    ''')
    conn.execute('''
        INSERT INTO llm_providers (name, model, url, provider_type)
        VALUES ('test-openai', 'gpt-4o', 'https://api.openai.com/v1', 'openai_platform')
    ''')
    conn.commit()
    conn.close()


class TestBedrockMigration(unittest.TestCase):
    """AWS Bedrock migration is idempotent and adds correct columns."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'settings.db')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _get_columns(self):
        """Return set of column names in llm_providers table."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(llm_providers)")
        cols = {col[1] for col in cursor.fetchall()}
        conn.close()
        return cols

    def test_migration_adds_columns(self):
        """Migration adds all four AWS columns to existing table."""
        _create_minimal_db(self.db_path)
        migrate_add_aws_bedrock_config(self.db_path)
        cols = self._get_columns()
        for col in ('aws_region', 'aws_profile', 'aws_access_key_id', 'aws_secret_access_key'):
            self.assertIn(col, cols)

    def test_migration_is_idempotent(self):
        """Running migration twice does not error or duplicate columns."""
        _create_minimal_db(self.db_path)
        migrate_add_aws_bedrock_config(self.db_path)
        migrate_add_aws_bedrock_config(self.db_path)
        cols = self._get_columns()
        aws_cols = [c for c in cols if c.startswith('aws_')]
        self.assertEqual(len(aws_cols), 4)

    def test_existing_data_preserved(self):
        """Existing provider rows keep their data after migration."""
        _create_minimal_db(self.db_path)
        migrate_add_aws_bedrock_config(self.db_path)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name, model, provider_type FROM llm_providers ORDER BY name")
        rows = cursor.fetchall()
        conn.close()

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], 'test-ollama')
        self.assertEqual(rows[1][0], 'test-openai')

    def test_new_columns_have_default_values(self):
        """New AWS columns default to empty string."""
        _create_minimal_db(self.db_path)
        migrate_add_aws_bedrock_config(self.db_path)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT aws_region, aws_profile, aws_access_key_id, aws_secret_access_key
            FROM llm_providers WHERE name = 'test-ollama'
        ''')
        row = cursor.fetchone()
        conn.close()

        for val in row:
            self.assertEqual(val, '')

    def test_migration_on_empty_db(self):
        """Migration works on a database with no rows."""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE llm_providers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL
            )
        ''')
        conn.close()
        migrate_add_aws_bedrock_config(self.db_path)
        cols = self._get_columns()
        for col in ('aws_region', 'aws_profile', 'aws_access_key_id', 'aws_secret_access_key'):
            self.assertIn(col, cols)

    def test_migration_on_already_migrated_db(self):
        """Migration handles a table that already has AWS columns."""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE llm_providers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                aws_region TEXT DEFAULT '',
                aws_profile TEXT DEFAULT '',
                aws_access_key_id TEXT DEFAULT '',
                aws_secret_access_key TEXT DEFAULT ''
            )
        ''')
        conn.close()
        migrate_add_aws_bedrock_config(self.db_path)
        cols = self._get_columns()
        for col in ('aws_region', 'aws_profile', 'aws_access_key_id', 'aws_secret_access_key'):
            self.assertIn(col, cols)


if __name__ == '__main__':
    unittest.main()
