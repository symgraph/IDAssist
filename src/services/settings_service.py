#!/usr/bin/env python3

import sqlite3
import threading
import json
import os
from typing import Any, Dict, List, Optional, Union

from src.ida_compat import log, get_user_data_dir


class SettingsService:
    """
    Thread-safe settings service for IDAssist plugin.
    Provides CRUD API for plugin configuration stored in SQLite database.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern implementation"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize the settings service"""
        if hasattr(self, '_initialized'):
            return

        self._initialized = True
        self._db_lock = threading.RLock()  # Reentrant lock for database operations
        self._db_path = None
        self._connection = None

        # Initialize database
        self._init_database()
        self._create_tables()
        self._run_migrations()
        self._populate_defaults()

    def _init_database(self):
        """Initialize SQLite database in IDA user directory"""
        try:
            idassist_dir = get_user_data_dir()

            self._db_path = os.path.join(idassist_dir, 'settings.db')

            # Test connection
            with self._db_lock:
                conn = sqlite3.connect(self._db_path, check_same_thread=False)
                conn.close()

        except Exception as e:
            raise RuntimeError(f"Failed to initialize settings database: {e}")

    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-safe database connection"""
        return sqlite3.connect(self._db_path, check_same_thread=False)

    def _create_tables(self):
        """Create database schema"""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()

                # Settings table for key-value pairs
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        type TEXT NOT NULL DEFAULT 'string',
                        category TEXT DEFAULT 'general',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # LLM Providers table
                cursor.execute('''
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

                # MCP Providers table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS mcp_providers (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        url TEXT NOT NULL,
                        enabled BOOLEAN DEFAULT 1,
                        transport TEXT DEFAULT 'streamablehttp',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_settings_category ON settings(category)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_llm_active ON llm_providers(is_active)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_mcp_enabled ON mcp_providers(enabled)')

                conn.commit()

            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Failed to create database schema: {e}")
            finally:
                conn.close()

    def _run_migrations(self):
        """Run database migrations"""
        try:
            from .migrations import (
                migrate_add_provider_type,
                migrate_add_reasoning_effort,
                migrate_add_litellm_configs,
                migrate_provider_type_names
            )
            from .migrations.add_oauth_credentials import migrate_add_oauth_credentials
            from .migrations.add_bypass_proxy import migrate_add_bypass_proxy
            migrate_add_provider_type(self._db_path)
            migrate_add_reasoning_effort(self._db_path)
            migrate_add_litellm_configs(self._db_path)
            migrate_add_oauth_credentials(self._db_path)
            migrate_provider_type_names(self._db_path)
            migrate_add_bypass_proxy(self._db_path)
        except Exception as e:
            # Migration failures shouldn't prevent plugin loading
            try:
                log.log_warn(f"Migration failed: {e}")
            except:
                log.log_warn(f"[IDAssist] Warning: Migration failed: {e}")

    def _populate_defaults(self):
        """Populate database with default settings"""
        data_dir = get_user_data_dir()
        defaults = {
            # System settings
            'system_prompt': {
                'value': 'You are an AI assistant specialized in binary analysis and reverse engineering. Help users understand code, identify patterns, and provide actionable insights for their reverse engineering tasks.',
                'type': 'string',
                'category': 'system'
            },

            # Database paths
            'analysis_db_path': {
                'value': os.path.join(data_dir, 'analysis.db'),
                'type': 'string',
                'category': 'database'
            },
            'rlhf_db_path': {
                'value': os.path.join(data_dir, 'rlhf.db'),
                'type': 'string',
                'category': 'database'
            },
            'rag_index_path': {
                'value': os.path.join(data_dir, 'rag_index'),
                'type': 'string',
                'category': 'database'
            },

            # UI settings
            'active_llm_provider': {
                'value': '',
                'type': 'string',
                'category': 'ui'
            },

            # SymGraph feature flag
            'symgraph_enabled': {
                'value': '0',
                'type': 'boolean',
                'category': 'symgraph'
            },

            # SymGraph settings
            'symgraph_api_url': {
                'value': 'https://api.SymGraph',
                'type': 'string',
                'category': 'symgraph'
            },
            'symgraph_api_key': {
                'value': '',
                'type': 'string',
                'category': 'symgraph'
            }
        }

        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()

                for key, config in defaults.items():
                    # Only insert if key doesn't exist
                    cursor.execute('SELECT 1 FROM settings WHERE key = ?', (key,))
                    if not cursor.fetchone():
                        cursor.execute('''
                            INSERT INTO settings (key, value, type, category)
                            VALUES (?, ?, ?, ?)
                        ''', (key, config['value'], config['type'], config['category']))

                conn.commit()

            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Failed to populate default settings: {e}")
            finally:
                conn.close()

    # CRUD Operations for Settings

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a setting value by key"""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('SELECT value, type FROM settings WHERE key = ?', (key,))
                result = cursor.fetchone()

                if result:
                    value, value_type = result
                    return self._deserialize_value(value, value_type)
                return default

            except Exception as e:
                raise RuntimeError(f"Failed to get setting '{key}': {e}")
            finally:
                conn.close()

    def set_setting(self, key: str, value: Any, category: str = 'general') -> bool:
        """Set a setting value"""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                value_str, value_type = self._serialize_value(value)

                cursor.execute('''
                    INSERT OR REPLACE INTO settings (key, value, type, category, updated_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (key, value_str, value_type, category))

                conn.commit()
                return True

            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Failed to set setting '{key}': {e}")
            finally:
                conn.close()

    def delete_setting(self, key: str) -> bool:
        """Delete a setting by key"""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM settings WHERE key = ?', (key,))
                deleted = cursor.rowcount > 0
                conn.commit()
                return deleted

            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Failed to delete setting '{key}': {e}")
            finally:
                conn.close()

    def get_settings_by_category(self, category: str) -> Dict[str, Any]:
        """Get all settings in a category"""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('SELECT key, value, type FROM settings WHERE category = ?', (category,))
                results = cursor.fetchall()

                settings = {}
                for key, value, value_type in results:
                    settings[key] = self._deserialize_value(value, value_type)

                return settings

            except Exception as e:
                raise RuntimeError(f"Failed to get settings for category '{category}': {e}")
            finally:
                conn.close()

    # LLM Provider Operations

    def _detect_model_family(self, model: str) -> str:
        """Detect underlying model family from model name for LiteLLM."""
        model_lower = model.lower()

        if model_lower.startswith('bedrock/'):
            if 'anthropic' in model_lower or 'claude' in model_lower:
                return 'anthropic'
            elif 'amazon' in model_lower or 'nova' in model_lower:
                return 'amazon'
            elif 'meta' in model_lower or 'llama' in model_lower:
                return 'meta'
            elif 'cohere' in model_lower:
                return 'cohere'
            elif 'ai21' in model_lower:
                return 'ai21'

        if 'claude' in model_lower or 'anthropic' in model_lower:
            return 'anthropic'
        elif 'gpt' in model_lower or 'openai' in model_lower:
            return 'openai'
        elif 'gemini' in model_lower or 'google' in model_lower:
            return 'google'
        elif 'llama' in model_lower or 'meta' in model_lower:
            return 'meta'

        return 'unknown'

    def _is_bedrock_model(self, model: str) -> bool:
        """Check if this is a Bedrock model"""
        return model.startswith('bedrock/')

    def add_llm_provider(self, name: str, model: str, url: str, max_tokens: int = 4096,
                        api_key: str = '', disable_tls: bool = False, provider_type: str = 'openai_platform',
                        reasoning_effort: str = 'none', bypass_proxy: bool = True) -> int:
        """Add a new LLM provider"""
        model_family = 'unknown'
        is_bedrock = False
        if provider_type == 'litellm':
            model_family = self._detect_model_family(model)
            is_bedrock = self._is_bedrock_model(model)

        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO llm_providers
                    (name, model, url, max_tokens, api_key, disable_tls, provider_type, reasoning_effort, model_family, is_bedrock, litellm_params, bypass_proxy)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (name, model, url, max_tokens, api_key, disable_tls, provider_type, reasoning_effort, model_family, is_bedrock, '{}', bypass_proxy))

                provider_id = cursor.lastrowid
                conn.commit()
                return provider_id

            except sqlite3.IntegrityError:
                raise ValueError(f"Provider '{name}' already exists")
            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Failed to add LLM provider: {e}")
            finally:
                conn.close()

    def get_llm_providers(self) -> List[Dict[str, Any]]:
        """Get all LLM providers"""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, name, model, url, max_tokens, api_key, disable_tls, provider_type, is_active, reasoning_effort, bypass_proxy
                    FROM llm_providers ORDER BY name
                ''')

                providers = []
                for row in cursor.fetchall():
                    providers.append({
                        'id': row[0],
                        'name': row[1],
                        'model': row[2],
                        'url': row[3],
                        'max_tokens': row[4],
                        'api_key': row[5],
                        'disable_tls': bool(row[6]),
                        'provider_type': row[7],
                        'is_active': bool(row[8]),
                        'reasoning_effort': row[9] if len(row) > 9 else 'none',
                        'bypass_proxy': bool(row[10]) if len(row) > 10 else True
                    })

                return providers

            except Exception as e:
                raise RuntimeError(f"Failed to get LLM providers: {e}")
            finally:
                conn.close()

    def update_llm_provider(self, provider_id: int, **kwargs) -> bool:
        """Update an LLM provider"""
        valid_fields = {'name', 'model', 'url', 'max_tokens', 'api_key', 'disable_tls', 'bypass_proxy',
                        'provider_type', 'is_active', 'reasoning_effort',
                        'model_family', 'is_bedrock', 'litellm_params'}
        update_fields = {k: v for k, v in kwargs.items() if k in valid_fields}

        if not update_fields:
            return False

        if 'provider_type' in update_fields or 'model' in update_fields:
            with self._db_lock:
                conn = self._get_connection()
                try:
                    cursor = conn.cursor()
                    cursor.execute('SELECT provider_type, model FROM llm_providers WHERE id = ?', (provider_id,))
                    row = cursor.fetchone()
                    if row:
                        current_provider_type, current_model = row
                        final_provider_type = update_fields.get('provider_type', current_provider_type)
                        final_model = update_fields.get('model', current_model)

                        if final_provider_type == 'litellm':
                            update_fields['model_family'] = self._detect_model_family(final_model)
                            update_fields['is_bedrock'] = self._is_bedrock_model(final_model)
                finally:
                    conn.close()

        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()

                set_clause = ', '.join([f"{field} = ?" for field in update_fields.keys()])
                values = list(update_fields.values()) + [provider_id]

                cursor.execute(f'''
                    UPDATE llm_providers SET {set_clause}, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', values)

                updated = cursor.rowcount > 0
                conn.commit()
                return updated

            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Failed to update LLM provider: {e}")
            finally:
                conn.close()

    def delete_llm_provider(self, provider_id: int) -> bool:
        """Delete an LLM provider"""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM llm_providers WHERE id = ?', (provider_id,))
                deleted = cursor.rowcount > 0
                conn.commit()
                return deleted

            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Failed to delete LLM provider: {e}")
            finally:
                conn.close()

    def set_active_llm_provider(self, provider_name: str) -> bool:
        """Set the active LLM provider"""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()

                # Deactivate all providers
                cursor.execute('UPDATE llm_providers SET is_active = 0')

                # Activate the specified provider
                cursor.execute('UPDATE llm_providers SET is_active = 1 WHERE name = ?', (provider_name,))

                # Update the setting in the same transaction
                value_str, value_type = self._serialize_value(provider_name)
                cursor.execute('''
                    INSERT OR REPLACE INTO settings (key, value, type, category, updated_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', ('active_llm_provider', value_str, value_type, 'ui'))

                conn.commit()
                return True

            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Failed to set active LLM provider: {e}")
            finally:
                conn.close()

    def get_active_llm_provider(self) -> Optional[Dict[str, Any]]:
        """Get the currently active LLM provider"""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()

                cursor.execute('''
                    SELECT id, name, model, url, max_tokens, api_key, disable_tls, provider_type, reasoning_effort
                    FROM llm_providers WHERE is_active = 1 LIMIT 1
                ''')

                row = cursor.fetchone()
                if row:
                    log.log_debug(f"Found active provider in database: {row[1]}")
                    return {
                        'id': row[0],
                        'name': row[1],
                        'model': row[2],
                        'url': row[3],
                        'max_tokens': row[4],
                        'api_key': row[5],
                        'disable_tls': bool(row[6]),
                        'provider_type': row[7],
                        'reasoning_effort': row[8] if len(row) > 8 else 'none'
                    }

                log.log_debug("No active provider in database, checking saved setting")

                cursor.execute('''
                    SELECT value FROM settings WHERE key = 'active_llm_provider' LIMIT 1
                ''')
                setting_row = cursor.fetchone()

                if setting_row:
                    saved_provider_name = setting_row[0]
                    log.log_debug(f"Found saved active provider setting: {saved_provider_name}")

                    cursor.execute('''
                        SELECT id, name, model, url, max_tokens, api_key, disable_tls, provider_type, reasoning_effort
                        FROM llm_providers WHERE name = ? LIMIT 1
                    ''', (saved_provider_name,))

                    provider_row = cursor.fetchone()
                    if provider_row:
                        log.log_debug(f"Restoring active provider: {saved_provider_name}")
                        cursor.execute('UPDATE llm_providers SET is_active = 1 WHERE name = ?', (saved_provider_name,))
                        conn.commit()

                        return {
                            'id': provider_row[0],
                            'name': provider_row[1],
                            'model': provider_row[2],
                            'url': provider_row[3],
                            'max_tokens': provider_row[4],
                            'api_key': provider_row[5],
                            'disable_tls': bool(provider_row[6]),
                            'provider_type': provider_row[7],
                            'reasoning_effort': provider_row[8] if len(provider_row) > 8 else 'none'
                        }
                    else:
                        log.log_warn(f"Saved provider '{saved_provider_name}' no longer exists in database")
                else:
                    log.log_debug("No saved active provider setting found")

                return None

            except Exception as e:
                raise RuntimeError(f"Failed to get active LLM provider: {e}")
            finally:
                conn.close()

    # MCP Provider Operations

    def add_mcp_provider(self, name: str, url: str, enabled: bool = True, transport: str = 'streamablehttp') -> int:
        """Add a new MCP provider"""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO mcp_providers (name, url, enabled, transport)
                    VALUES (?, ?, ?, ?)
                ''', (name, url, enabled, transport))

                provider_id = cursor.lastrowid
                conn.commit()
                return provider_id

            except sqlite3.IntegrityError:
                raise ValueError(f"MCP Provider '{name}' already exists")
            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Failed to add MCP provider: {e}")
            finally:
                conn.close()

    def get_mcp_providers(self) -> List[Dict[str, Any]]:
        """Get all MCP providers"""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, name, url, enabled, transport
                    FROM mcp_providers ORDER BY name
                ''')

                providers = []
                for row in cursor.fetchall():
                    providers.append({
                        'id': row[0],
                        'name': row[1],
                        'url': row[2],
                        'enabled': bool(row[3]),
                        'transport': row[4]
                    })

                return providers

            except Exception as e:
                raise RuntimeError(f"Failed to get MCP providers: {e}")
            finally:
                conn.close()

    def update_mcp_provider(self, provider_id: int, **kwargs) -> bool:
        """Update an MCP provider"""
        valid_fields = {'name', 'url', 'enabled', 'transport'}
        update_fields = {k: v for k, v in kwargs.items() if k in valid_fields}

        if not update_fields:
            return False

        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()

                set_clause = ', '.join([f"{field} = ?" for field in update_fields.keys()])
                values = list(update_fields.values()) + [provider_id]

                cursor.execute(f'''
                    UPDATE mcp_providers SET {set_clause}, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', values)

                updated = cursor.rowcount > 0
                conn.commit()
                return updated

            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Failed to update MCP provider: {e}")
            finally:
                conn.close()

    def delete_mcp_provider(self, provider_id: int) -> bool:
        """Delete an MCP provider"""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM mcp_providers WHERE id = ?', (provider_id,))
                deleted = cursor.rowcount > 0
                conn.commit()
                return deleted

            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Failed to delete MCP provider: {e}")
            finally:
                conn.close()

    # OAuth Credentials Operations

    def store_oauth_credentials(self, provider_name: str, access_token: str,
                                refresh_token: str, expires_at: float) -> bool:
        """Store OAuth credentials for a provider."""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO oauth_credentials
                    (provider_name, access_token, refresh_token, expires_at, updated_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (provider_name, access_token, refresh_token, expires_at))
                conn.commit()
                log.log_info(f"Stored OAuth credentials for provider: {provider_name}")
                return True
            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Failed to store OAuth credentials: {e}")
            finally:
                conn.close()

    def get_oauth_credentials(self, provider_name: str) -> Optional[Dict[str, Any]]:
        """Get OAuth credentials for a provider."""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT access_token, refresh_token, expires_at
                    FROM oauth_credentials WHERE provider_name = ?
                ''', (provider_name,))
                row = cursor.fetchone()
                if row:
                    return {
                        'access_token': row[0],
                        'refresh_token': row[1],
                        'expires_at': row[2]
                    }
                return None
            except Exception as e:
                log.log_error(f"Failed to get OAuth credentials: {e}")
                return None
            finally:
                conn.close()

    def clear_oauth_credentials(self, provider_name: str) -> bool:
        """Clear OAuth credentials for a provider."""
        with self._db_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM oauth_credentials WHERE provider_name = ?',
                              (provider_name,))
                deleted = cursor.rowcount > 0
                conn.commit()
                if deleted:
                    log.log_info(f"Cleared OAuth credentials for provider: {provider_name}")
                return deleted
            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Failed to clear OAuth credentials: {e}")
            finally:
                conn.close()

    def has_oauth_credentials(self, provider_name: str) -> bool:
        """Check if OAuth credentials exist for a provider."""
        credentials = self.get_oauth_credentials(provider_name)
        return credentials is not None and credentials.get('access_token')

    # Utility methods

    def _serialize_value(self, value: Any) -> tuple[str, str]:
        """Serialize a value for database storage"""
        if isinstance(value, bool):
            return str(int(value)), 'boolean'
        elif isinstance(value, int):
            return str(value), 'integer'
        elif isinstance(value, float):
            return str(value), 'float'
        elif isinstance(value, (dict, list)):
            return json.dumps(value), 'json'
        else:
            return str(value), 'string'

    def _deserialize_value(self, value: str, value_type: str) -> Any:
        """Deserialize a value from database storage"""
        try:
            if value_type == 'boolean':
                return bool(int(value))
            elif value_type == 'integer':
                return int(value)
            elif value_type == 'float':
                return float(value)
            elif value_type == 'json':
                return json.loads(value)
            else:
                return value
        except (ValueError, json.JSONDecodeError):
            return value

    # System Prompt Management

    def get_system_prompt(self) -> str:
        """Get current system prompt (delegates to AnalysisDB)"""
        try:
            from .analysis_db_service import analysis_db_service
            active_prompt = analysis_db_service.get_active_system_prompt()
            if active_prompt:
                return active_prompt

            return self.get_setting('system_prompt',
                'You are an AI assistant specialized in binary analysis and reverse engineering. Help users understand code, identify patterns, and provide actionable insights for their reverse engineering tasks.')
        except Exception as e:
            log.log_error(f"Failed to get system prompt: {e}")
            return 'You are an AI assistant specialized in binary analysis and reverse engineering.'

    def save_system_prompt(self, prompt: str, version: str = None) -> bool:
        """Save system prompt (delegates to AnalysisDB)"""
        try:
            from .analysis_db_service import analysis_db_service
            import datetime

            if not version:
                version = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

            prompt_id = analysis_db_service.save_system_prompt(prompt, version)
            analysis_db_service.set_active_system_prompt(version)
            self.set_setting('system_prompt', prompt, 'system')

            log.log_info(f"Saved system prompt version {version}")
            return True

        except Exception as e:
            log.log_error(f"Failed to save system prompt: {e}")
            return False

    # SymGraph Settings

    def is_symgraph_enabled(self) -> bool:
        """Check if the SymGraph feature is enabled"""
        return self.get_setting('symgraph_enabled', False)

    def get_symgraph_api_url(self) -> str:
        """Get the SymGraph API URL"""
        return self.get_setting('symgraph_api_url', 'https://api.SymGraph')

    def set_symgraph_api_url(self, url: str) -> bool:
        """Set the SymGraph API URL"""
        return self.set_setting('symgraph_api_url', url, 'symgraph')

    def get_symgraph_api_key(self) -> str:
        """Get the SymGraph API key"""
        return self.get_setting('symgraph_api_key', '')

    def set_symgraph_api_key(self, key: str) -> bool:
        """Set the SymGraph API key"""
        return self.set_setting('symgraph_api_key', key, 'symgraph')

    def has_symgraph_api_key(self) -> bool:
        """Check if a SymGraph API key is configured"""
        key = self.get_symgraph_api_key()
        return bool(key and key.strip())

    def close(self):
        """Close database connections (for cleanup)"""
        pass


# Global instance for easy access throughout the application
settings_service = SettingsService()
