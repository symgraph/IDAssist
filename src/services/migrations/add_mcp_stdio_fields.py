#!/usr/bin/env python3

"""
Migration: Add stdio transport fields to mcp_providers table.
"""

import sqlite3

from src.ida_compat import log


def migrate_add_mcp_stdio_fields(db_path: str):
    """Add stdio-related columns to mcp_providers if they do not exist."""
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(mcp_providers)")
        columns = [col[1] for col in cursor.fetchall()]

        field_definitions = {
            'command': "ALTER TABLE mcp_providers ADD COLUMN command TEXT DEFAULT ''",
            'args': "ALTER TABLE mcp_providers ADD COLUMN args TEXT DEFAULT '[]'",
            'env': "ALTER TABLE mcp_providers ADD COLUMN env TEXT DEFAULT '{}'",
            'cwd': "ALTER TABLE mcp_providers ADD COLUMN cwd TEXT DEFAULT ''",
        }

        for column_name, statement in field_definitions.items():
            if column_name not in columns:
                cursor.execute(statement)
                conn.commit()
                log.log_info(f"Added {column_name} column to mcp_providers")
            else:
                log.log_debug(f"{column_name} column already exists on mcp_providers")

    except Exception as e:
        conn.rollback()
        log.log_error(f"mcp stdio fields migration failed: {e}")
        raise
    finally:
        conn.close()
