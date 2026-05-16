#!/usr/bin/env python3

"""Migration: Add AWS Bedrock configuration fields to llm_providers table."""

import sqlite3

from src.ida_compat import log


def migrate_add_aws_bedrock_config(db_path: str):
    """Add AWS Bedrock-specific columns to the llm_providers table.

    New fields:
    - aws_region: AWS region for Bedrock endpoint (e.g., us-east-1)
    - aws_profile: Named AWS profile from credentials file
    - aws_access_key_id: AWS access key (optional, uses boto3 chain otherwise)
    - aws_secret_access_key: AWS secret key (optional, uses boto3 chain otherwise)
    """
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(llm_providers)")
        columns = [col[1] for col in cursor.fetchall()]

        changes_made = False

        if 'aws_region' not in columns:
            cursor.execute('''
                ALTER TABLE llm_providers
                ADD COLUMN aws_region TEXT DEFAULT ''
            ''')
            log.log_info("Added aws_region column to llm_providers")
            changes_made = True

        if 'aws_profile' not in columns:
            cursor.execute('''
                ALTER TABLE llm_providers
                ADD COLUMN aws_profile TEXT DEFAULT ''
            ''')
            log.log_info("Added aws_profile column to llm_providers")
            changes_made = True

        if 'aws_access_key_id' not in columns:
            cursor.execute('''
                ALTER TABLE llm_providers
                ADD COLUMN aws_access_key_id TEXT DEFAULT ''
            ''')
            log.log_info("Added aws_access_key_id column to llm_providers")
            changes_made = True

        if 'aws_secret_access_key' not in columns:
            cursor.execute('''
                ALTER TABLE llm_providers
                ADD COLUMN aws_secret_access_key TEXT DEFAULT ''
            ''')
            log.log_info("Added aws_secret_access_key column to llm_providers")
            changes_made = True

        if changes_made:
            conn.commit()
            log.log_info("AWS Bedrock config migration completed successfully")
        else:
            log.log_info("AWS Bedrock columns already exist, skipping migration")

    except Exception as e:
        conn.rollback()
        log.log_error(f"AWS Bedrock migration failed: {e}")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    import os
    from src.ida_compat import get_user_data_dir

    db_path = os.path.join(get_user_data_dir(), 'settings.db')
    if os.path.exists(db_path):
        migrate_add_aws_bedrock_config(db_path)
    else:
        log.log_error("Settings database not found")
