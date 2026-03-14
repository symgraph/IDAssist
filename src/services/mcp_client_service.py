#!/usr/bin/env python3
"""
MCP Client Service for IDAssist.

This service provides a clean interface for MCP (Model Context Protocol) integration,
following the IDAssist SOA architecture patterns. Handles connection management,
tool discovery, and execution for multiple MCP servers.
"""

import asyncio
import concurrent.futures
import threading
import time
from typing import Dict, List, Optional, Any

try:
    import anyio
    ANYIO_AVAILABLE = True
except ImportError:
    ANYIO_AVAILABLE = False

from .settings_service import SettingsService
from .models.mcp_models import (
    MCPConfig, MCPServerConfig, MCPTool, MCPResource,
    MCPConnectionInfo, MCPConnectionStatus, MCPTestResult,
    MCPToolExecutionRequest, MCPToolExecutionResult
)
from .mcp_exceptions import (
    MCPError, MCPConnectionError, MCPToolError, MCPResourceError
)

from src.ida_compat import log


# Import MCP client implementation
try:
    from .mcp_client import MCPConnection
    MCP_CLIENT_AVAILABLE = True
except ImportError:
    log.log_warn("MCP client implementation not available")
    MCPConnection = None
    MCP_CLIENT_AVAILABLE = False


class MCPClientService:
    """
    MCP Client service providing clean interface for:
    - Connection lifecycle management
    - Tool discovery and execution
    - Settings integration
    - Health monitoring
    - Thread-safe operations
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
        """Initialize the MCP client service"""
        if hasattr(self, '_initialized'):
            return

        self._initialized = True
        self._settings_service = SettingsService()
        self._config: Optional[MCPConfig] = None
        self._connections: Dict[str, MCPConnectionInfo] = {}  # Cached tool/resource metadata
        self._connection_lock = threading.RLock()

        # Connection lifecycle state
        self._lifecycle_initialized = False
        self._lifecycle_lock = threading.Lock()

        log.log_info("MCP Client Service initialized")

    # ===================================================================
    # Configuration Management
    # ===================================================================

    def load_configuration(self) -> bool:
        """Load MCP configuration from settings."""
        try:
            log.log_info("Loading MCP configuration from settings")

            # Load servers from settings using get_mcp_providers()
            servers_data = self._settings_service.get_mcp_providers()
            log.log_info(f"Loaded {len(servers_data)} MCP servers from settings")

            # Convert to server configs
            server_configs = []
            for server_data in servers_data:
                try:
                    # Normalize transport value from settings DB
                    raw_transport = server_data.get('transport', 'sse').lower().strip()
                    transport_map = {
                        'http': 'streamablehttp',
                        'streamablehttp': 'streamablehttp',
                        'streamable_http': 'streamablehttp',
                        'sse': 'sse',
                    }
                    transport_type = transport_map.get(raw_transport, 'streamablehttp')

                    # Convert settings format to MCPServerConfig format
                    config_dict = {
                        'name': server_data['name'],
                        'transport_type': transport_type,
                        'enabled': server_data.get('enabled', True),
                        'url': server_data.get('url'),
                        'timeout': server_data.get('timeout', 30.0)
                    }

                    config = MCPServerConfig.from_dict(config_dict)
                    server_configs.append(config)
                except Exception as e:
                    log.log_error(f"Failed to load MCP server config: {e}")
                    continue

            # Create MCP config
            self._config = MCPConfig(servers=server_configs)

            log.log_info(f"Successfully loaded {len(server_configs)} MCP servers")
            return True

        except Exception as e:
            log.log_error(f"Failed to load MCP configuration: {e}")
            return False

    def save_configuration(self) -> bool:
        """Save current configuration to settings."""
        try:
            if self._config:
                servers_data = [server.to_dict() for server in self._config.servers]
                self._settings_service.set_json('mcp_servers', servers_data)
                log.log_info(f"Saved {len(servers_data)} MCP servers to settings")
                return True
            else:
                log.log_warn("No MCP config to save")
                return False
        except Exception as e:
            log.log_error(f"Failed to save MCP configuration: {e}")
            return False

    def get_configuration(self) -> Optional[MCPConfig]:
        """Get current MCP configuration."""
        return self._config

    def update_server_config(self, server_config: MCPServerConfig) -> bool:
        """Update or add a server configuration."""
        try:
            if not self._config:
                self._config = MCPConfig(servers=[])

            # Find existing server or add new one
            for i, existing in enumerate(self._config.servers):
                if existing.name == server_config.name:
                    self._config.servers[i] = server_config
                    log.log_info(f"Updated server config: {server_config.name}")
                    break
            else:
                self._config.servers.append(server_config)
                log.log_info(f"Added new server config: {server_config.name}")

            return self.save_configuration()

        except Exception as e:
            log.log_error(f"Failed to update server config: {e}")
            return False

    def remove_server_config(self, server_name: str) -> bool:
        """Remove a server configuration."""
        try:
            if not self._config:
                return False

            original_count = len(self._config.servers)
            self._config.servers = [s for s in self._config.servers if s.name != server_name]

            if len(self._config.servers) < original_count:
                log.log_info(f"Removed server config: {server_name}")
                return self.save_configuration()
            else:
                log.log_warn(f"Server config not found: {server_name}")
                return False

        except Exception as e:
            log.log_error(f"Failed to remove server config: {e}")
            return False

    # ===================================================================
    # Async-to-Sync Bridge (Main Thread Safe)
    # ===================================================================

    def _run_in_background_with_events(self, fn, timeout=30):
        """Run a callable in a background thread while pumping Qt/IDA events.

        MCP servers running inside IDA (like IDAssistMCP) call IDA APIs
        via execute_on_main_thread() / idaapi.execute_sync(MFF_FAST).
        If we block IDA's main thread with anyio.run() or future.result(),
        those callbacks deadlock.  By running the work in a ThreadPoolExecutor
        and pumping QApplication.processEvents() on the main thread while
        we wait, execute_sync callbacks get processed normally.
        """
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(fn)
            deadline = time.time() + timeout
            while not future.done() and time.time() < deadline:
                try:
                    from ..qt_compat import QApplication
                    app = QApplication.instance()
                    if app:
                        app.processEvents()
                except ImportError:
                    pass
                time.sleep(0.01)

            if future.done():
                return future.result(timeout=0)
            else:
                raise TimeoutError(f"Operation timed out after {timeout}s")

    # ===================================================================
    # Connection Testing (Synchronous Interface)
    # ===================================================================

    def test_server_connection(self, server_config: MCPServerConfig) -> MCPTestResult:
        """
        Test connection to an MCP server (synchronous).

        Args:
            server_config: Server configuration to test

        Returns:
            Test result with connection status and available tools/resources
        """
        if not MCP_CLIENT_AVAILABLE:
            return MCPTestResult.failure_result("MCP client implementation not available")

        log.log_info(f"Testing connection to MCP server: {server_config.name}")

        try:
            if not ANYIO_AVAILABLE:
                return MCPTestResult.failure_result("anyio not available")

            def run_test():
                return anyio.run(self._test_server_connection_async, server_config)

            return self._run_in_background_with_events(run_test, timeout=15)

        except Exception as e:
            log.log_error(f"Exception in test_server_connection: {e}")
            return MCPTestResult.failure_result(str(e))

    async def _test_server_connection_async(self, server_config: MCPServerConfig) -> MCPTestResult:
        """Test connection to MCP server asynchronously."""
        test_connection = None
        try:
            log.log_info(f"Creating test connection to {server_config.name}")

            # Cap internal timeout so the HTTP client and session.initialize()
            # don't hang for 30s if the server is unreachable
            from dataclasses import replace as dc_replace
            capped_config = dc_replace(server_config, timeout=10.0)
            test_connection = MCPConnection(capped_config)

            # Attempt connection with 10 second timeout
            try:
                success = await asyncio.wait_for(test_connection.connect(), timeout=10.0)
            except asyncio.TimeoutError:
                log.log_warn(f"Test connection timeout for {server_config.name} after 10 seconds")
                return MCPTestResult.failure_result("Connection test timed out after 10 seconds")

            if success:
                log.log_info(f"Test connection successful to {server_config.name}")

                # Get available tools and resources
                tools = list(test_connection.tools.values())
                resources = list(test_connection.resources.values())

                log.log_info(f"Found {len(tools)} tools and {len(resources)} resources")

                return MCPTestResult.success_result(tools, resources)
            else:
                log.log_warn(f"Test connection failed to {server_config.name}")
                return MCPTestResult.failure_result("Failed to connect to server")

        except asyncio.TimeoutError:
            # Catch timeout at outer level as well
            log.log_warn(f"Test connection timeout for {server_config.name}")
            return MCPTestResult.failure_result("Connection test timed out after 10 seconds")
        except Exception as e:
            log.log_error(f"Test connection error for {server_config.name}: {e}")
            return MCPTestResult.failure_result(str(e))
        finally:
            # Clean up test connection
            if test_connection:
                try:
                    await test_connection.disconnect()
                except Exception as cleanup_error:
                    pass  # Ignore cleanup errors

    # ===================================================================
    # Connection Management
    # ===================================================================

    def get_connection_status(self, server_name: str) -> MCPConnectionStatus:
        """Get connection status for a specific server."""
        with self._connection_lock:
            if server_name in self._connections:
                return self._connections[server_name].status
            return MCPConnectionStatus.DISCONNECTED

    def get_all_connection_statuses(self) -> Dict[str, MCPConnectionStatus]:
        """Get connection statuses for all configured servers."""
        with self._connection_lock:
            return {name: info.status for name, info in self._connections.items()}

    def initialize_connections(self) -> bool:
        """Initialize connections to all enabled servers."""
        with self._lifecycle_lock:
            if self._lifecycle_initialized:
                log.log_info("Connection lifecycle already initialized")
                return True

            if not MCP_CLIENT_AVAILABLE:
                log.log_error("Cannot initialize connections - MCP client not available")
                return False

            try:
                # Ensure configuration is loaded
                if not self._config:
                    if not self.load_configuration():
                        log.log_error("Cannot initialize - failed to load configuration")
                        return False

                if not ANYIO_AVAILABLE:
                    log.log_error("anyio not available for MCP connections")
                    return False

                def run_init():
                    return anyio.run(self._initialize_connections_async)

                result = self._run_in_background_with_events(run_init, timeout=30)

                self._lifecycle_initialized = result
                return result

            except Exception as e:
                log.log_error(f"Failed to initialize connections: {e}")
                return False

    async def _initialize_connections_async(self) -> bool:
        """Initialize connections asynchronously."""
        try:
            log.log_info("Starting async connection initialization")

            # Connect to all enabled servers
            enabled_servers = list(self._config.get_enabled_servers())

            if not enabled_servers:
                log.log_warn("No enabled MCP servers found in configuration")
                return False

            success_count = 0
            for server_config in enabled_servers:
                try:
                    result = await self._connect_server_async(server_config)
                    if result:
                        success_count += 1
                except Exception as e:
                    log.log_error(f"Failed to connect to {server_config.name}: {e}")

            log.log_info(f"Connected to {success_count}/{len(enabled_servers)} servers")

            if success_count == 0:
                log.log_error("No MCP servers connected successfully")
                return False

            log.log_info("Connection initialization completed successfully")
            return True

        except Exception as e:
            log.log_error(f"Async connection initialization failed: {e}")
            return False

    async def _connect_server_async(self, server_config: MCPServerConfig) -> bool:
        """Connect to a server, discover tools/resources, cache metadata, then disconnect.

        Uses the same connection pattern as _test_server_connection_async
        (which is proven to work via the Settings Test button).
        """
        connection = None
        try:
            log.log_info(f"Connecting to server: {server_config.name}")

            # Use a capped internal timeout so both the HTTP client and
            # session.initialize() inside MCPConnection fail fast (the
            # config default is 30s which can hang if the server is down).
            from dataclasses import replace as dc_replace
            capped_config = dc_replace(server_config, timeout=10.0)
            connection = MCPConnection(capped_config)

            # Same timeout as the working test_server_connection path
            try:
                success = await asyncio.wait_for(connection.connect(), timeout=10.0)
            except asyncio.TimeoutError:
                log.log_error(f"Connection to {server_config.name} timed out after 10s")
                return False

            if success:
                # connection.tools and connection.resources already contain
                # MCPTool and MCPResource objects from mcp_client._discover_*
                with self._connection_lock:
                    connection_info = MCPConnectionInfo(
                        server_config=server_config,
                        status=MCPConnectionStatus.CONNECTED,
                        tools=dict(connection.tools),
                        resources=dict(connection.resources),
                        error_message=None
                    )
                    self._connections[server_config.name] = connection_info

                log.log_info(f"Discovered {len(connection.tools)} tools from {server_config.name}")
                return True
            else:
                log.log_error(f"Failed to connect to {server_config.name}")
                return False

        except asyncio.TimeoutError:
            log.log_error(f"Connection to {server_config.name} timed out")
            return False
        except Exception as e:
            log.log_error(f"Error connecting to {server_config.name}: {e}")
            return False
        finally:
            if connection:
                try:
                    await connection.disconnect()
                except Exception:
                    pass

    # ===================================================================
    # Tool Discovery and Execution
    # ===================================================================

    def get_available_tools(self, server_filter: Optional[List[str]] = None) -> List[MCPTool]:
        """
        Get all available tools, optionally filtered by servers.

        Args:
            server_filter: Optional list of server names to include

        Returns:
            List of available MCP tools
        """
        tools = []

        with self._connection_lock:
            for connection_info in self._connections.values():
                if not connection_info.is_connected:
                    continue

                # Apply server filter if provided
                if server_filter and connection_info.server_config.name not in server_filter:
                    continue

                tools.extend(connection_info.tools.values())

        return tools

    def get_tools_for_llm(self, server_filter: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Get tools formatted for LLM integration in OpenAI format.

        Args:
            server_filter: Optional list of server names to include

        Returns:
            List of tool definitions in OpenAI format
        """
        tools = self.get_available_tools(server_filter)
        return [tool.to_llm_format() for tool in tools]

    def execute_tool(self, request: MCPToolExecutionRequest) -> MCPToolExecutionResult:
        """
        Execute an MCP tool (synchronous).

        Creates a fresh connection for each execution so that all async
        context managers are properly entered and exited within one
        anyio.run() / event-loop lifetime.

        Args:
            request: Tool execution request

        Returns:
            Tool execution result
        """
        start_time = time.time()

        try:
            log.log_info(f"Executing tool: {request.tool_name}")

            # Find which server owns this tool
            server_name = None
            with self._connection_lock:
                for conn_name, connection_info in self._connections.items():
                    if request.tool_name in connection_info.tools:
                        server_name = conn_name
                        break

            if not server_name:
                raise MCPToolError(f"Tool '{request.tool_name}' not found in any connected server")

            # Get server config for fresh connection
            server_config = self._config.get_server_by_name(server_name) if self._config else None
            if not server_config:
                raise MCPConnectionError(f"No config for server '{server_name}'")

            # Execute with a fresh connection in a background thread,
            # pumping Qt events so IDAssistMCP's execute_sync callbacks work
            if not ANYIO_AVAILABLE:
                raise MCPError("anyio not available")

            def run_tool():
                return anyio.run(self._execute_with_fresh_connection, server_config, request)

            result = self._run_in_background_with_events(run_tool, timeout=request.timeout)

            execution_time = time.time() - start_time
            log.log_info(f"Tool '{request.tool_name}' executed successfully in {execution_time:.2f}s")

            return MCPToolExecutionResult.success_result(
                result=result,
                execution_time=execution_time,
                server_name=server_name
            )

        except Exception as e:
            execution_time = time.time() - start_time
            log.log_error(f"Tool execution failed: {e}")

            return MCPToolExecutionResult.failure_result(
                error=str(e),
                execution_time=execution_time
            )

    # ===================================================================
    # Fresh Connection Execution
    # ===================================================================

    async def _execute_with_fresh_connection(self, server_config, request: MCPToolExecutionRequest) -> Any:
        """Execute tool with a fresh connection that is opened and closed in this call."""
        fresh_connection = None
        try:
            log.log_info(f"Connecting to {server_config.name} for tool {request.tool_name}")

            fresh_connection = MCPConnection(server_config)

            success = await fresh_connection.connect()
            if not success:
                raise MCPConnectionError(f"Failed to connect to {server_config.name}")

            result = await fresh_connection.call_tool(request.tool_name, request.arguments)
            log.log_info(f"Tool {request.tool_name} executed successfully")

            return result

        except Exception as e:
            log.log_error(f"Tool execution failed for {request.tool_name}: {e}")
            raise
        finally:
            if fresh_connection:
                try:
                    await fresh_connection.disconnect()
                except Exception:
                    pass

    def shutdown(self) -> None:
        """Shutdown the MCP client service and clear cached state."""
        log.log_info("Shutting down MCP client service")

        with self._connection_lock:
            self._connections.clear()

        self._lifecycle_initialized = False

        log.log_info("MCP client service shutdown complete")
