#!/usr/bin/env python3

"""
Database migration to add oauth_credentials table for OAuth-based providers.

This table stores OAuth access tokens, refresh tokens, and expiry times
for providers that use OAuth authentication (like Anthropic Experimental).
"""

import sqlite3

from src.ida_compat import log


def migrate_add_oauth_credentials(db_path: str) -> bool:
    """
    Add oauth_credentials table to the database.

    Table schema:
    - id: Auto-incrementing primary key
    - provider_name: Unique identifier for the provider (e.g., 'openai_oauth')
    - access_token: OAuth access token
    - refresh_token: OAuth refresh token for obtaining new access tokens
    - expires_at: Unix timestamp when access token expires
    - created_at: When credentials were first stored
    - updated_at: When credentials were last updated

    Args:
        db_path: Path to SQLite database file

    Returns:
        True if migration successful, False otherwise
    """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if table already exists
        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='oauth_credentials'
        """)

        if cursor.fetchone():
            log.log_debug("oauth_credentials table already exists, skipping migration")
            conn.close()
            return True

        # Create the table
        cursor.execute('''
            CREATE TABLE oauth_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_name TEXT UNIQUE NOT NULL,
                access_token TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                expires_at REAL NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create index for faster lookups by provider name
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_oauth_provider_name
            ON oauth_credentials(provider_name)
        ''')

        conn.commit()
        conn.close()

        log.log_info("Successfully created oauth_credentials table")
        return True

    except Exception as e:
        log.log_error(f"Failed to create oauth_credentials table: {e}")
        return False
