#!/usr/bin/env python3
"""
MCP Client implementation for IDAssist.

This module provides the core MCP (Model Context Protocol) client functionality
for connecting to and interacting with MCP servers using the official MCP Python SDK.
"""

import asyncio
import os
import sys
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
import json

from .models.mcp_models import MCPServerConfig, MCPTool, MCPResource
from .mcp_exceptions import MCPError, MCPConnectionError, MCPTimeoutError, MCPToolError, MCPResourceError

from src.ida_compat import log

MCP_SDK_IMPORT_ERROR = None
STDIO_IMPORT_ERROR = None

# Import MCP SDK
try:
    from mcp.client.session import ClientSession
    import mcp.types as types
    MCP_SDK_AVAILABLE = True
except Exception as e:
    MCP_SDK_IMPORT_ERROR = e
    log.log_warn(f"MCP SDK core imports unavailable: {e}")
    MCP_SDK_AVAILABLE = False
    ClientSession = None
    types = None

try:
    from mcp.client.sse import sse_client
    SSE_CLIENT_AVAILABLE = True
except Exception as e:
    log.log_warn(f"MCP SSE client not available: {e}")
    sse_client = None
    SSE_CLIENT_AVAILABLE = False

try:
    from mcp.client.streamable_http import streamablehttp_client
    STREAMABLEHTTP_CLIENT_AVAILABLE = True
except Exception as e:
    log.log_warn(f"MCP Streamable HTTP client not available: {e}")
    streamablehttp_client = None
    STREAMABLEHTTP_CLIENT_AVAILABLE = False

try:
    from mcp.client.stdio import stdio_client, StdioServerParameters
    STDIO_CLIENT_AVAILABLE = True
except Exception as e:
    STDIO_IMPORT_ERROR = e
    log.log_warn(f"MCP stdio client not available: {e}")
    stdio_client = None
    StdioServerParameters = None
    STDIO_CLIENT_AVAILABLE = False


class MCPConnection:
    """Manages connection to a single MCP server."""

    def __init__(self, config: MCPServerConfig):
        self.config = config
        self.connected = False
        self.session: Optional[ClientSession] = None
        self.read = None
        self.write = None
        self.tools: Dict[str, MCPTool] = {}
        self.resources: Dict[str, MCPResource] = {}
        self._sse_context = None
        self._streamablehttp_context = None
        self._stdio_context = None
        self._stdio_errlog = None

    async def connect(self) -> bool:
        """Connect to the MCP server."""
        if not MCP_SDK_AVAILABLE:
            detail = f" ({MCP_SDK_IMPORT_ERROR})" if MCP_SDK_IMPORT_ERROR else ""
            raise MCPError(f"MCP SDK core imports unavailable{detail}. Ensure 'mcp' is installed in IDA's Python environment.")

        try:
            if self.config.transport_type == "sse":
                await self._connect_sse()
            elif self.config.transport_type == "streamablehttp":
                await self._connect_streamablehttp()
            elif self.config.transport_type == "stdio":
                await self._connect_stdio()
            else:
                raise MCPError(f"Unsupported transport type: {self.config.transport_type}")

            self.connected = True
            await self._discover_capabilities()
            return True

        except Exception as e:
            # Clean up any partially-entered context managers so that
            # the async generators are closed inside the current task
            # (prevents "cancel scope in a different task" errors).
            await self._cleanup_contexts()
            log.log_error(f"Failed to connect to MCP server {self.config.name}: {e}")
            raise MCPConnectionError(f"Connection failed: {e}")

    async def _cleanup_contexts(self):
        """Exit any entered context managers (session, transport) safely."""
        if self.session:
            try:
                await self.session.__aexit__(None, None, None)
            except Exception:
                pass
            self.session = None

        if self._sse_context:
            try:
                await self._sse_context.__aexit__(None, None, None)
            except Exception:
                pass
            self._sse_context = None

        if self._streamablehttp_context:
            try:
                await self._streamablehttp_context.__aexit__(None, None, None)
            except Exception:
                pass
            self._streamablehttp_context = None

        if self._stdio_context:
            try:
                await self._stdio_context.__aexit__(None, None, None)
            except Exception:
                pass
            self._stdio_context = None

        if self._stdio_errlog:
            try:
                self._stdio_errlog.close()
            except Exception:
                pass
            self._stdio_errlog = None

        self.read = None
        self.write = None

    def _get_stdio_errlog(self):
        """Get a real file handle for stdio server stderr under IDA/Windows."""
        candidates = [getattr(sys, "__stderr__", None), getattr(sys, "stderr", None)]
        for candidate in candidates:
            if candidate and hasattr(candidate, "fileno"):
                try:
                    candidate.fileno()
                    return candidate
                except Exception:
                    pass

        self._stdio_errlog = open(os.devnull, "w", encoding="utf-8")
        return self._stdio_errlog

    async def _connect_sse(self):
        """Connect using SSE transport."""
        if not self.config.url:
            raise MCPError("URL not specified for SSE transport")

        if not SSE_CLIENT_AVAILABLE:
            raise MCPError("SSE client not available in MCP SDK. Try updating MCP: pip install --upgrade mcp")

        # Create SSE client connection
        self._sse_context = sse_client(self.config.url, timeout=self.config.timeout)
        self.read, self.write = await self._sse_context.__aenter__()

        # Create and initialize session
        self.session = ClientSession(self.read, self.write)
        await self.session.__aenter__()

        # Initialize with timeout
        try:
            await asyncio.wait_for(self.session.initialize(), timeout=self.config.timeout)
        except asyncio.TimeoutError:
            raise MCPError(f"Session initialization timed out after {self.config.timeout} seconds")

    async def _connect_streamablehttp(self):
        """Connect using Streamable HTTP transport."""
        if not self.config.url:
            raise MCPError("URL not specified for Streamable HTTP transport")

        if not STREAMABLEHTTP_CLIENT_AVAILABLE:
            raise MCPError("Streamable HTTP client not available in MCP SDK. Try updating MCP: pip install --upgrade mcp")

        # Create Streamable HTTP client connection
        self._streamablehttp_context = streamablehttp_client(self.config.url, timeout=self.config.timeout)
        # Streamable HTTP returns (read, write, session_id)
        self.read, self.write, _ = await self._streamablehttp_context.__aenter__()

        # Create and initialize session
        self.session = ClientSession(self.read, self.write)
        await self.session.__aenter__()

        # Initialize with timeout
        try:
            await asyncio.wait_for(self.session.initialize(), timeout=self.config.timeout)
        except asyncio.TimeoutError:
            raise MCPError(f"Session initialization timed out after {self.config.timeout} seconds")

    async def _connect_stdio(self):
        """Connect using stdio transport."""
        if not self.config.command:
            raise MCPError("Command not specified for stdio transport")

        if not STDIO_CLIENT_AVAILABLE:
            detail = f": {STDIO_IMPORT_ERROR}" if STDIO_IMPORT_ERROR else ""
            raise MCPError(
                "Stdio client not available in MCP SDK"
                f"{detail}. On Windows, install 'pywin32' in the same Python environment as IDA."
            )

        server_params = StdioServerParameters(
            command=self.config.command,
            args=self.config.args or [],
            env=self.config.env,
            cwd=self.config.cwd or None,
        )
        self._stdio_context = stdio_client(server_params, errlog=self._get_stdio_errlog())
        self.read, self.write = await self._stdio_context.__aenter__()

        self.session = ClientSession(self.read, self.write)
        await self.session.__aenter__()

        try:
            await asyncio.wait_for(self.session.initialize(), timeout=self.config.timeout)
        except asyncio.TimeoutError:
            raise MCPError(f"Session initialization timed out after {self.config.timeout} seconds")

    async def _discover_capabilities(self):
        """Discover server capabilities."""
        try:
            await self._discover_tools()
            await self._discover_resources()
        except Exception as e:
            log.log_error(f"Capability discovery failed: {e}")
            raise MCPError(f"Capability discovery failed: {e}")

    async def _discover_tools(self):
        """Discover available tools."""
        try:
            tools_result = await self.session.list_tools()

            for tool_info in tools_result.tools:
                tool_name = tool_info.name
                tool_desc = tool_info.description or "No description"

                # Handle schema format
                if tool_info.inputSchema:
                    if hasattr(tool_info.inputSchema, 'model_dump'):
                        schema = tool_info.inputSchema.model_dump()
                    else:
                        schema = tool_info.inputSchema
                else:
                    schema = {}

                tool = MCPTool(
                    name=tool_name,
                    description=tool_desc,
                    schema=schema,
                    server_name=self.config.name
                )
                self.tools[tool.name] = tool

        except Exception as e:
            log.log_error(f"Tool discovery failed for {self.config.name}: {e}")

    async def _discover_resources(self):
        """Discover available resources."""
        try:
            resources_result = await self.session.list_resources()

            for resource_info in resources_result.resources:
                resource = MCPResource(
                    uri=resource_info.uri,
                    name=resource_info.name or "",
                    description=resource_info.description,
                    mime_type=resource_info.mimeType,
                    server_name=self.config.name
                )
                self.resources[resource.uri] = resource

        except Exception as e:
            log.log_warn(f"Resource discovery failed: {e}")

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool on the server."""
        if tool_name not in self.tools:
            raise MCPToolError(f"Tool '{tool_name}' not found")

        if not self.session:
            raise MCPToolError("No active session for tool calling")

        try:
            result = await self.session.call_tool(
                name=tool_name,
                arguments=arguments or {}
            )

            # Extract content from result
            if hasattr(result, 'content') and result.content:
                content_parts = []
                for content_item in result.content:
                    if hasattr(content_item, 'text'):
                        content_parts.append(content_item.text)
                    else:
                        content_parts.append(str(content_item))

                if len(content_parts) == 1:
                    return content_parts[0]
                elif len(content_parts) > 1:
                    return '\n'.join(content_parts)
                else:
                    return "Tool executed successfully"
            else:
                return "Tool executed successfully"

        except Exception as e:
            log.log_error(f"Tool call failed: {e}")
            import traceback
            log.log_error(f"Full traceback: {traceback.format_exc()}")
            raise MCPToolError(f"Tool call failed: {e}")

    async def get_resource(self, uri: str) -> Any:
        """Get a resource from the server."""
        if uri not in self.resources:
            raise MCPResourceError(f"Resource '{uri}' not found")

        if not self.session:
            raise MCPResourceError("No active session for resource access")

        try:
            content, mime_type = await self.session.read_resource(uri)
            return {"content": content, "mime_type": mime_type}

        except Exception as e:
            log.log_error(f"Resource access failed: {e}")
            raise MCPResourceError(f"Resource access failed: {e}")

    async def disconnect(self):
        """Disconnect from the server and clean up all contexts."""
        try:
            await self._cleanup_contexts()
        except Exception as e:
            log.log_warn(f"Error during disconnect: {e}")
        finally:
            self.connected = False


class MCPClient:
    """Main MCP client for managing multiple server connections."""

    def __init__(self, server_configs: List[MCPServerConfig]):
        self.server_configs = server_configs
        self.connections: Dict[str, MCPConnection] = {}
        self.all_tools: Dict[str, MCPTool] = {}
        self.all_resources: Dict[str, MCPResource] = {}

    async def connect_all(self) -> Dict[str, bool]:
        """Connect to all configured servers."""
        results = {}

        for server_config in self.server_configs:
            if not server_config.enabled:
                continue

            try:
                connection = MCPConnection(server_config)
                success = await connection.connect()

                if success:
                    self.connections[server_config.name] = connection
                    self._merge_tools(connection.tools)
                    self._merge_resources(connection.resources)

                results[server_config.name] = success

            except Exception as e:
                log.log_error(f"Failed to connect to {server_config.name}: {e}")
                results[server_config.name] = False

        # Connection results logged above
        return results

    def _merge_tools(self, tools: Dict[str, MCPTool]):
        """Merge tools from a connection into the global tool registry."""
        for name, tool in tools.items():
            # Handle name conflicts by prefixing with server name
            if name in self.all_tools and self.all_tools[name].server_name != tool.server_name:
                prefixed_name = f"{tool.server_name}.{name}"
                self.all_tools[prefixed_name] = tool
            else:
                self.all_tools[name] = tool

    def _merge_resources(self, resources: Dict[str, MCPResource]):
        """Merge resources from a connection into the global resource registry."""
        self.all_resources.update(resources)

    def get_available_tools(self) -> Dict[str, MCPTool]:
        """Get all available tools across all connected servers."""
        return self.all_tools.copy()

    def get_available_resources(self) -> Dict[str, MCPResource]:
        """Get all available resources across all connected servers."""
        return self.all_resources.copy()

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool on the appropriate server."""
        if tool_name not in self.all_tools:
            raise MCPToolError(f"Tool '{tool_name}' not available")

        tool = self.all_tools[tool_name]
        server_name = tool.server_name

        if server_name not in self.connections:
            raise MCPConnectionError(f"Not connected to server '{server_name}'")

        connection = self.connections[server_name]
        return await connection.call_tool(tool_name, arguments)

    async def get_resource(self, uri: str) -> Any:
        """Get a resource from the appropriate server."""
        if uri not in self.all_resources:
            raise MCPResourceError(f"Resource '{uri}' not available")

        resource = self.all_resources[uri]
        server_name = resource.server_name

        if server_name not in self.connections:
            raise MCPConnectionError(f"Not connected to server '{server_name}'")

        connection = self.connections[server_name]
        return await connection.get_resource(uri)

    async def disconnect_all(self):
        """Disconnect from all servers."""
        for connection in self.connections.values():
            await connection.disconnect()
        self.connections.clear()
        self.all_tools.clear()
        self.all_resources.clear()
