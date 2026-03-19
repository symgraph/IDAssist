#!/usr/bin/env python3

"""
Migration: Update provider_type values to new naming convention

This migration updates old provider_type string values in the llm_providers table
to the new rationalized naming convention:

Old Value              -> New Value
---------              -> ---------
anthropic              -> anthropic_platform
claude_code            -> anthropic_cli
openai                 -> openai_platform
openai_codex           -> openai_oauth

The new naming convention follows the pattern: VENDOR_AUTHMETHOD
- PLATFORM: Direct API key access to vendor's platform
- OAUTH: OAuth-based subscription access (Pro/Plus/Max plans)
- CLI: Command-line interface wrapper
"""

import sqlite3

from src.ida_compat import log


# Migration mapping: old_value -> new_value
PROVIDER_TYPE_MIGRATION_MAP = {
    # Old Anthropic names
    "anthropic": "anthropic_platform",
    "claude_code": "anthropic_cli",
    # Old OpenAI names
    "openai": "openai_platform",
    "openai_codex": "openai_oauth",
}


def migrate_provider_type_names(db_path: str) -> bool:
    """
    Update provider_type values to new naming convention.

    Args:
        db_path: Path to SQLite database file

    Returns:
        True if migration successful, False otherwise
    """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if llm_providers table exists
        cursor.execute('''
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='llm_providers'
        ''')

        if not cursor.fetchone():
            log.log_info("llm_providers table not found, skipping provider type name migration")
            conn.close()
            return True

        # Check if provider_type column exists
        cursor.execute("PRAGMA table_info(llm_providers)")
        columns = [col[1] for col in cursor.fetchall()]

        if 'provider_type' not in columns:
            log.log_info("provider_type column not found, skipping provider type name migration")
            conn.close()
            return True

        # Count how many rows need to be updated
        total_updated = 0

        for old_value, new_value in PROVIDER_TYPE_MIGRATION_MAP.items():
            cursor.execute('''
                UPDATE llm_providers
                SET provider_type = ?
                WHERE provider_type = ?
            ''', (new_value, old_value))

            rows_updated = cursor.rowcount
            if rows_updated > 0:
                log.log_info(f"Migrated {rows_updated} provider(s): '{old_value}' -> '{new_value}'")
                total_updated += rows_updated

        conn.commit()
        conn.close()

        if total_updated > 0:
            log.log_info(f"Provider type name migration completed: {total_updated} provider(s) updated")
        else:
            log.log_info("Provider type name migration: no providers needed updating")

        return True

    except Exception as e:
        log.log_error(f"Provider type name migration failed: {e}")
        return False


if __name__ == "__main__":
    # Test migration
    import os
    from src.ida_compat import get_user_data_dir

    db_path = os.path.join(get_user_data_dir(), 'settings.db')
    if os.path.exists(db_path):
        migrate_provider_type_names(db_path)
    else:
        log.log_error("Settings database not found")
