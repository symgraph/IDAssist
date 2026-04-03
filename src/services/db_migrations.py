#!/usr/bin/env python3

import sqlite3
import os
import json
from typing import Dict, Any

from src.ida_compat import log


class DatabaseMigrations:
    """Database migration utilities for IDAssist services"""

    @staticmethod
    def get_schema_version(db_path: str) -> int:
        """Get current schema version"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='schema_version'
            ''')

            if not cursor.fetchone():
                conn.close()
                return 0

            cursor.execute('SELECT version FROM schema_version ORDER BY id DESC LIMIT 1')
            row = cursor.fetchone()
            version = row[0] if row else 0

            conn.close()
            return version

        except Exception as e:
            log.log_error(f"Failed to get schema version: {e}")
            return 0

    @staticmethod
    def set_schema_version(db_path: str, version: int) -> bool:
        """Set current schema version"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS schema_version (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version INTEGER NOT NULL,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                INSERT INTO schema_version (version) VALUES (?)
            ''', (version,))

            conn.commit()
            conn.close()

            log.log_info(f"Set schema version to {version}")
            return True

        except Exception as e:
            log.log_error(f"Failed to set schema version: {e}")
            return False

    @staticmethod
    def migrate_analysis_db(db_path: str) -> bool:
        """Apply all migrations to analysis database"""
        try:
            current_version = DatabaseMigrations.get_schema_version(db_path)

            migrations = [
                (1, DatabaseMigrations._migration_001_initial_schema),
                (2, DatabaseMigrations._migration_002_add_indexes),
                (3, DatabaseMigrations._migration_003_native_message_storage),
                (4, DatabaseMigrations._migration_004_graphrag_tables),
                (5, DatabaseMigrations._migration_005_graphrag_communities),
                (6, DatabaseMigrations._migration_006_graphrag_fts),
                (7, DatabaseMigrations._migration_007_llm_renames),
                (8, DatabaseMigrations._migration_008_chat_document_metadata),
                (9, DatabaseMigrations._migration_009_graph_node_code_fields),
            ]

            for version, migration_func in migrations:
                if current_version < version:
                    log.log_info(f"Applying migration {version}")
                    if migration_func(db_path):
                        DatabaseMigrations.set_schema_version(db_path, version)
                    else:
                        log.log_error(f"Migration {version} failed")
                        return False

            return True

        except Exception as e:
            log.log_error(f"Migration failed: {e}")
            return False

    @staticmethod
    def _migration_001_initial_schema(db_path: str) -> bool:
        """Migration 001: Initial schema creation"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            log.log_error(f"Migration 001 failed: {e}")
            return False

    @staticmethod
    def _migration_002_add_indexes(db_path: str) -> bool:
        """Migration 002: Add additional indexes for performance"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_bnanalysis_created_at ON BNAnalysis(created_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_bnchathistory_created_at ON BNChatHistory(created_at)')

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            log.log_error(f"Migration 002 failed: {e}")
            return False

    @staticmethod
    def _migration_003_native_message_storage(db_path: str) -> bool:
        """Migration 003: Add native message storage for provider-specific formats"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS BNChatMessages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    binary_hash TEXT NOT NULL,
                    chat_id TEXT NOT NULL,
                    message_order INTEGER NOT NULL,
                    provider_type TEXT NOT NULL,
                    native_message_data TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content_text TEXT,
                    message_type TEXT DEFAULT 'standard',
                    parent_message_id INTEGER,
                    conversation_thread_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(binary_hash, chat_id, message_order),
                    FOREIGN KEY(parent_message_id) REFERENCES BNChatMessages(id)
                )
            ''')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_chat_messages_lookup ON BNChatMessages(binary_hash, chat_id, message_order)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_chat_messages_provider ON BNChatMessages(provider_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_chat_messages_thread ON BNChatMessages(conversation_thread_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_chat_messages_parent ON BNChatMessages(parent_message_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_chat_messages_type ON BNChatMessages(message_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_chat_messages_role ON BNChatMessages(role)')

            # Migrate existing chat history from old format (best effort)
            try:
                cursor.execute('''
                    SELECT binary_hash, chat_id, message_order, role, content, metadata, created_at
                    FROM BNChatHistory
                    ORDER BY binary_hash, chat_id, message_order
                ''')

                old_messages = cursor.fetchall()
                migrated_count = 0

                for old_msg in old_messages:
                    binary_hash, chat_id, message_order, role, content, metadata, created_at = old_msg

                    native_message = {
                        "role": role,
                        "content": content
                    }

                    provider_type = "anthropic_platform"
                    message_type = "standard"
                    if role == "tool":
                        message_type = "tool_response"
                    elif "tool_calls" in content.lower() or "function" in content.lower():
                        message_type = "tool_call"

                    try:
                        cursor.execute('''
                            INSERT INTO BNChatMessages (
                                binary_hash, chat_id, message_order, provider_type,
                                native_message_data, role, content_text, message_type, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            binary_hash, chat_id, message_order, provider_type,
                            json.dumps(native_message), role, content, message_type, created_at
                        ))
                        migrated_count += 1
                    except Exception as e:
                        log.log_warn(f"Failed to migrate message {message_order} in chat {chat_id}: {e}")

                cursor.execute('ALTER TABLE BNChatHistory RENAME TO BNChatHistory_backup')
                log.log_info(f"Migration 003 completed: Migrated {migrated_count} messages to native format")
            except Exception:
                # Old table may not exist in fresh installs
                pass

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            log.log_error(f"Migration 003 failed: {e}")
            return False

    @staticmethod
    def _table_exists(cursor, name: str) -> bool:
        """Check if a table exists in the database."""
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (name,)
        )
        return cursor.fetchone() is not None

    @staticmethod
    def _get_columns(cursor, table_name: str) -> dict:
        """Get column names and types for a table."""
        cursor.execute(f"PRAGMA table_info({table_name})")
        return {row[1]: row[2].upper().split()[0] for row in cursor.fetchall()}

    @staticmethod
    def _rename_to_backup(cursor, table_name: str) -> str:
        """Rename a table to a backup name with _bak suffix."""
        if not DatabaseMigrations._table_exists(cursor, table_name):
            return None
        backup_name = f"{table_name}_bak"
        suffix = 1
        while DatabaseMigrations._table_exists(cursor, backup_name):
            backup_name = f"{table_name}_bak_{suffix}"
            suffix += 1
        cursor.execute(f"ALTER TABLE {table_name} RENAME TO {backup_name}")
        return backup_name

    @staticmethod
    def _migration_004_graphrag_tables(db_path: str) -> bool:
        """Migration 004: Create graph_nodes and graph_edges tables."""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            expected_nodes = {
                "id", "type", "address", "binary_id", "name", "signature", "decompiled_code", "disassembly", "raw_content",
                "llm_summary", "confidence", "embedding", "security_flags",
                "network_apis", "file_io_apis", "ip_addresses", "urls",
                "file_paths", "domains", "registry_keys", "category", "risk_level",
                "activity_profile", "analysis_depth", "created_at", "updated_at",
                "is_stale", "user_edited"
            }

            for legacy in ("GraphNodes", "GraphEdges"):
                if DatabaseMigrations._table_exists(cursor, legacy):
                    backup = DatabaseMigrations._rename_to_backup(cursor, legacy)
                    log.log_warn(f"Renamed legacy {legacy} to {backup}")

            if DatabaseMigrations._table_exists(cursor, "graph_nodes"):
                existing = set(DatabaseMigrations._get_columns(cursor, "graph_nodes").keys())
                if existing != expected_nodes:
                    backup = DatabaseMigrations._rename_to_backup(cursor, "graph_nodes")
                    log.log_warn(f"Incompatible graph_nodes table found, renamed to {backup}. Creating fresh table.")
                    if DatabaseMigrations._table_exists(cursor, "graph_edges"):
                        edge_backup = DatabaseMigrations._rename_to_backup(cursor, "graph_edges")
                        log.log_warn(f"Also renamed graph_edges to {edge_backup}")

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    address INTEGER,
                    binary_id TEXT NOT NULL,
                    name TEXT,
                    signature TEXT,
                    decompiled_code TEXT,
                    disassembly TEXT,
                    raw_content TEXT,
                    llm_summary TEXT,
                    confidence REAL DEFAULT 0.0,
                    embedding BLOB,
                    security_flags TEXT,
                    network_apis TEXT,
                    file_io_apis TEXT,
                    ip_addresses TEXT,
                    urls TEXT,
                    file_paths TEXT,
                    domains TEXT,
                    registry_keys TEXT,
                    category TEXT,
                    risk_level TEXT,
                    activity_profile TEXT,
                    analysis_depth INTEGER DEFAULT 0,
                    created_at INTEGER,
                    updated_at INTEGER,
                    is_stale INTEGER DEFAULT 0,
                    user_edited INTEGER DEFAULT 0
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS graph_edges (
                    id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    weight REAL DEFAULT 1.0,
                    metadata TEXT,
                    created_at INTEGER,
                    FOREIGN KEY(source_id) REFERENCES graph_nodes(id) ON DELETE CASCADE,
                    FOREIGN KEY(target_id) REFERENCES graph_nodes(id) ON DELETE CASCADE
                )
            ''')

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_nodes_address ON graph_nodes(address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_nodes_type ON graph_nodes(type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_nodes_binary ON graph_nodes(binary_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_nodes_name ON graph_nodes(name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_nodes_stale ON graph_nodes(binary_id, is_stale)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges(source_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges(target_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_edges_type ON graph_edges(type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_edges_source_type ON graph_edges(source_id, type)")

            conn.commit()
            conn.close()
            log.log_info("Migration 004: GraphRAG core tables created successfully")
            return True

        except Exception as e:
            log.log_warn(f"Migration 004 issue: {e}. Attempting recovery...")
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                for table in ("graph_nodes", "graph_edges"):
                    if DatabaseMigrations._table_exists(cursor, table):
                        DatabaseMigrations._rename_to_backup(cursor, table)
                conn.close()
                log.log_warn("Migration 004: Tables backed up. Please restart plugin.")
            except Exception as recovery_error:
                log.log_error(f"Migration 004 recovery failed: {recovery_error}")
            return True

    @staticmethod
    def _migration_005_graphrag_communities(db_path: str) -> bool:
        """Migration 005: Create community detection tables."""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            expected_communities = {
                "id", "level", "binary_id", "parent_community_id", "name",
                "summary", "member_count", "is_stale", "created_at", "updated_at"
            }

            for legacy in ("GraphCommunities", "CommunityMembers"):
                if DatabaseMigrations._table_exists(cursor, legacy):
                    backup = DatabaseMigrations._rename_to_backup(cursor, legacy)
                    log.log_warn(f"Renamed legacy {legacy} to {backup}")

            if DatabaseMigrations._table_exists(cursor, "graph_communities"):
                existing = set(DatabaseMigrations._get_columns(cursor, "graph_communities").keys())
                if existing != expected_communities:
                    backup = DatabaseMigrations._rename_to_backup(cursor, "graph_communities")
                    log.log_warn(f"Incompatible graph_communities table found, renamed to {backup}. Creating fresh table.")
                    if DatabaseMigrations._table_exists(cursor, "community_members"):
                        member_backup = DatabaseMigrations._rename_to_backup(cursor, "community_members")
                        log.log_warn(f"Also renamed community_members to {member_backup}")

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS graph_communities (
                    id TEXT PRIMARY KEY,
                    level INTEGER NOT NULL,
                    binary_id TEXT NOT NULL,
                    parent_community_id TEXT,
                    name TEXT,
                    summary TEXT,
                    member_count INTEGER DEFAULT 0,
                    is_stale INTEGER DEFAULT 1,
                    created_at INTEGER,
                    updated_at INTEGER,
                    FOREIGN KEY (parent_community_id) REFERENCES graph_communities(id) ON DELETE SET NULL
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS community_members (
                    community_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    membership_score REAL DEFAULT 1.0,
                    PRIMARY KEY (community_id, node_id),
                    FOREIGN KEY (community_id) REFERENCES graph_communities(id) ON DELETE CASCADE,
                    FOREIGN KEY (node_id) REFERENCES graph_nodes(id) ON DELETE CASCADE
                )
            ''')

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_communities_binary ON graph_communities(binary_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_communities_level ON graph_communities(level)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_communities_parent ON graph_communities(parent_community_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_community_members_node ON community_members(node_id)")

            conn.commit()
            conn.close()
            log.log_info("Migration 005: GraphRAG community tables created successfully")
            return True

        except Exception as e:
            log.log_warn(f"Migration 005 issue: {e}. Attempting recovery...")
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                for table in ("graph_communities", "community_members"):
                    if DatabaseMigrations._table_exists(cursor, table):
                        DatabaseMigrations._rename_to_backup(cursor, table)
                conn.close()
                log.log_warn("Migration 005: Tables backed up. Please restart plugin.")
            except Exception as recovery_error:
                log.log_error(f"Migration 005 recovery failed: {recovery_error}")
            return True

    @staticmethod
    def _migration_006_graphrag_fts(db_path: str) -> bool:
        """Migration 006: Create FTS5 full-text search for graph nodes."""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("DROP TRIGGER IF EXISTS graph_nodes_ai")
            cursor.execute("DROP TRIGGER IF EXISTS graph_nodes_ad")
            cursor.execute("DROP TRIGGER IF EXISTS graph_nodes_au")

            if DatabaseMigrations._table_exists(cursor, "GraphNodeFTS"):
                cursor.execute("DROP TABLE IF EXISTS GraphNodeFTS")
                log.log_info("Dropped legacy GraphNodeFTS table")

            if DatabaseMigrations._table_exists(cursor, "node_fts"):
                cursor.execute("PRAGMA table_info(node_fts)")
                existing_cols = [row[1] for row in cursor.fetchall()]
                expected_cols = ["id", "name", "signature", "llm_summary", "security_flags"]
                if set(existing_cols) != set(expected_cols):
                    cursor.execute("DROP TABLE IF EXISTS node_fts")
                    log.log_info("Dropped incompatible node_fts table for recreation")

            try:
                cursor.execute('''
                    CREATE VIRTUAL TABLE IF NOT EXISTS node_fts USING fts5(
                        id,
                        name,
                        signature,
                        llm_summary,
                        security_flags,
                        content='graph_nodes',
                        content_rowid='rowid'
                    )
                ''')

                cursor.execute('''
                    CREATE TRIGGER IF NOT EXISTS graph_nodes_ai AFTER INSERT ON graph_nodes BEGIN
                        INSERT INTO node_fts(rowid, id, name, signature, llm_summary, security_flags)
                        VALUES (new.rowid, new.id, new.name, new.signature, new.llm_summary, new.security_flags);
                    END
                ''')

                cursor.execute('''
                    CREATE TRIGGER IF NOT EXISTS graph_nodes_ad AFTER DELETE ON graph_nodes BEGIN
                        INSERT INTO node_fts(node_fts, rowid, id, name, signature, llm_summary, security_flags)
                        VALUES ('delete', old.rowid, old.id, old.name, old.signature, old.llm_summary, old.security_flags);
                    END
                ''')

                cursor.execute('''
                    CREATE TRIGGER IF NOT EXISTS graph_nodes_au AFTER UPDATE ON graph_nodes BEGIN
                        INSERT INTO node_fts(node_fts, rowid, id, name, signature, llm_summary, security_flags)
                        VALUES ('delete', old.rowid, old.id, old.name, old.signature, old.llm_summary, old.security_flags);
                        INSERT INTO node_fts(rowid, id, name, signature, llm_summary, security_flags)
                        VALUES (new.rowid, new.id, new.name, new.signature, new.llm_summary, new.security_flags);
                    END
                ''')

                log.log_info("Migration 006: FTS5 full-text search created successfully")

            except Exception as fts_error:
                log.log_warn(f"FTS5 not available, full-text search disabled: {fts_error}")

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            log.log_warn(f"Migration 006 issue: {e}. FTS5 may be unavailable.")
            return True

    @staticmethod
    def _migration_007_llm_renames(db_path: str) -> bool:
        """Migration 007: LLM renames tracking table"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS llm_renames (
                    binary_id TEXT NOT NULL,
                    address INTEGER NOT NULL,
                    symbol_type TEXT NOT NULL DEFAULT 'function',
                    new_name TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (binary_id, address, symbol_type)
                )
            ''')

            conn.commit()
            conn.close()
            log.log_info("Migration 007: llm_renames table created successfully")
            return True

        except Exception as e:
            log.log_error(f"Migration 007 failed: {e}")
            return False

    @staticmethod
    def _migration_008_chat_document_metadata(db_path: str) -> bool:
        """Migration 008: Add JSON metadata column for chat-level document sync state."""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            try:
                cursor.execute('ALTER TABLE BNChatMetadata ADD COLUMN metadata TEXT')
            except sqlite3.OperationalError as e:
                if 'duplicate column name' not in str(e).lower():
                    raise
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            log.log_error(f"Migration 008 failed: {e}")
            return False

    @staticmethod
    def _migration_009_graph_node_code_fields(db_path: str) -> bool:
        """Migration 009: Add first-class signature, decompiled code, and disassembly fields."""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            for statement in (
                'ALTER TABLE graph_nodes ADD COLUMN signature TEXT',
                'ALTER TABLE graph_nodes ADD COLUMN decompiled_code TEXT',
                'ALTER TABLE graph_nodes ADD COLUMN disassembly TEXT',
            ):
                try:
                    cursor.execute(statement)
                except sqlite3.OperationalError as e:
                    if 'duplicate column name' not in str(e).lower():
                        raise

            cursor.execute('''
                UPDATE graph_nodes
                SET decompiled_code = raw_content
                WHERE decompiled_code IS NULL AND raw_content IS NOT NULL
            ''')

            cursor.execute('''
                UPDATE graph_nodes
                SET raw_content = decompiled_code
                WHERE raw_content IS NULL AND decompiled_code IS NOT NULL
            ''')

            cursor.execute("DROP TRIGGER IF EXISTS graph_nodes_ai")
            cursor.execute("DROP TRIGGER IF EXISTS graph_nodes_ad")
            cursor.execute("DROP TRIGGER IF EXISTS graph_nodes_au")
            cursor.execute("DROP TABLE IF EXISTS node_fts")

            cursor.execute('''
                CREATE VIRTUAL TABLE IF NOT EXISTS node_fts USING fts5(
                    id,
                    name,
                    signature,
                    llm_summary,
                    security_flags,
                    content='graph_nodes',
                    content_rowid='rowid'
                )
            ''')

            cursor.execute('''
                CREATE TRIGGER IF NOT EXISTS graph_nodes_ai AFTER INSERT ON graph_nodes BEGIN
                    INSERT INTO node_fts(rowid, id, name, signature, llm_summary, security_flags)
                    VALUES (new.rowid, new.id, new.name, new.signature, new.llm_summary, new.security_flags);
                END
            ''')

            cursor.execute('''
                CREATE TRIGGER IF NOT EXISTS graph_nodes_ad AFTER DELETE ON graph_nodes BEGIN
                    INSERT INTO node_fts(node_fts, rowid, id, name, signature, llm_summary, security_flags)
                    VALUES ('delete', old.rowid, old.id, old.name, old.signature, old.llm_summary, old.security_flags);
                END
            ''')

            cursor.execute('''
                CREATE TRIGGER IF NOT EXISTS graph_nodes_au AFTER UPDATE ON graph_nodes BEGIN
                    INSERT INTO node_fts(node_fts, rowid, id, name, signature, llm_summary, security_flags)
                    VALUES ('delete', old.rowid, old.id, old.name, old.signature, old.llm_summary, old.security_flags);
                    INSERT INTO node_fts(rowid, id, name, signature, llm_summary, security_flags)
                    VALUES (new.rowid, new.id, new.name, new.signature, new.llm_summary, new.security_flags);
                END
            ''')

            cursor.execute('''
                INSERT INTO node_fts(rowid, id, name, signature, llm_summary, security_flags)
                SELECT rowid, id, name, signature, llm_summary, security_flags
                FROM graph_nodes
            ''')

            conn.commit()
            conn.close()
            log.log_info("Migration 009: Graph node code fields added successfully")
            return True
        except Exception as e:
            log.log_error(f"Migration 009 failed: {e}")
            return False


class DatabaseCleanup:
    """Database cleanup utilities"""

    @staticmethod
    def cleanup_expired_data(db_path: str) -> Dict[str, int]:
        """Clean up expired data from database"""
        stats = {"expired_contexts": 0, "old_chat_messages": 0}

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                DELETE FROM BNContext
                WHERE expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP
            ''')
            stats["expired_contexts"] = cursor.rowcount

            conn.commit()
            conn.close()

            if stats["expired_contexts"] > 0:
                log.log_info(f"Cleaned up {stats['expired_contexts']} expired context entries")

            return stats

        except Exception as e:
            log.log_error(f"Database cleanup failed: {e}")
            return stats

    @staticmethod
    def get_database_size_info(db_path: str) -> Dict[str, Any]:
        """Get database size and statistics"""
        info = {
            "file_size_mb": 0,
            "table_counts": {},
            "total_records": 0
        }

        try:
            if os.path.exists(db_path):
                info["file_size_mb"] = os.path.getsize(db_path) / (1024 * 1024)

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            tables = ["BNAnalysis", "BNContext", "BNChatHistory", "SystemPrompts"]
            for table in tables:
                try:
                    cursor.execute(f'SELECT COUNT(*) FROM {table}')
                    count = cursor.fetchone()[0]
                    info["table_counts"][table] = count
                    info["total_records"] += count
                except:
                    info["table_counts"][table] = 0

            conn.close()
            return info

        except Exception as e:
            log.log_error(f"Failed to get database info: {e}")
            return info

    @staticmethod
    def vacuum_database(db_path: str) -> bool:
        """Optimize database by running VACUUM"""
        try:
            conn = sqlite3.connect(db_path)
            conn.execute('VACUUM')
            conn.close()

            log.log_info("Database vacuumed successfully")
            return True

        except Exception as e:
            log.log_error(f"Database vacuum failed: {e}")
            return False
