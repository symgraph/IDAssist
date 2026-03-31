#!/usr/bin/env python3

"""
Migration: Add bypass_proxy field to llm_providers table
"""

import sqlite3

from src.ida_compat import log


def migrate_add_bypass_proxy(db_path: str):
    """
    Add bypass_proxy field to llm_providers table.
    Default is True (bypass system proxy) to avoid 502 errors with local/intranet endpoints.
    """
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(llm_providers)")
        columns = [col[1] for col in cursor.fetchall()]

        if 'bypass_proxy' not in columns:
            cursor.execute('''
                ALTER TABLE llm_providers
                ADD COLUMN bypass_proxy BOOLEAN DEFAULT 1
            ''')
            conn.commit()
            log.log_info("Added bypass_proxy column to llm_providers")
        else:
            log.log_info("bypass_proxy column already exists, skipping migration")

    except Exception as e:
        conn.rollback()
        log.log_error(f"bypass_proxy migration failed: {e}")
        raise
    finally:
        conn.close()
