"""
MCP data models for IDAssist.

This module provides clean, reusable data structures for MCP integration,
following the existing IDAssist model architecture patterns.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from enum import Enum


class MCPConnectionStatus(Enum):
    """Status of MCP server connection."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    FAILED = "failed"


class MCPTransportType(Enum):
    """MCP transport protocol types."""
    SSE = "sse"
    STREAMABLEHTTP = "streamablehttp"
    STDIO = "stdio"


@dataclass
class MCPServerConfig:
    """Configuration for an MCP server."""
    name: str
    transport_type: str
    enabled: bool = True
    timeout: float = 30.0

    # SSE and Streamable HTTP transport fields
    url: Optional[str] = None
    headers: Optional[Dict[str, str]] = None

    # Stdio transport fields
    command: Optional[str] = None
    args: Optional[List[str]] = None
    env: Optional[Dict[str, str]] = None
    cwd: Optional[str] = None

    def __post_init__(self):
        """Validate configuration after initialization."""
        if self.transport_type in ("sse", "streamablehttp") and not self.url:
            raise ValueError(f"{self.transport_type} transport requires url")
        if self.transport_type == "stdio" and not self.command:
            raise ValueError("stdio transport requires command")
        if self.args is None:
            self.args = []

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MCPServerConfig':
        """Create server config from dictionary."""
        return cls(
            name=data['name'],
            transport_type=data['transport_type'],
            enabled=data.get('enabled', True),
            timeout=data.get('timeout', 30.0),
            url=data.get('url'),
            headers=data.get('headers'),
            command=data.get('command'),
            args=data.get('args'),
            env=data.get('env'),
            cwd=data.get('cwd')
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert server config to dictionary."""
        return {
            'name': self.name,
            'transport_type': self.transport_type,
            'enabled': self.enabled,
            'timeout': self.timeout,
            'url': self.url,
            'headers': self.headers,
            'command': self.command,
            'args': self.args,
            'env': self.env,
            'cwd': self.cwd
        }


@dataclass
class MCPConfig:
    """Configuration for MCP client."""
    servers: List[MCPServerConfig]

    def get_enabled_servers(self) -> List[MCPServerConfig]:
        """Get list of enabled servers."""
        return [server for server in self.servers if server.enabled]

    def get_server_by_name(self, name: str) -> Optional[MCPServerConfig]:
        """Get server config by name."""
        for server in self.servers:
            if server.name == name:
                return server
        return None


@dataclass
class MCPTool:
    """Represents an MCP tool with formatting capabilities."""
    name: str
    description: str
    schema: Dict[str, Any]
    server_name: str

    def to_llm_format(self, prefix: str = "") -> Dict[str, Any]:
        """
        Convert to OpenAI tool format for LLM integration.

        Args:
            prefix: Prefix to add to tool name (default: no prefix)

        Returns:
            Tool definition in OpenAI format
        """
        return {
            "type": "function",
            "function": {
                "name": f"{prefix}{self.name}",
                "description": self.description,
                "parameters": self.schema
            }
        }

    def to_test_format(self) -> Dict[str, Any]:
        """
        Convert to test result format for UI display.

        Returns:
            Tool info for test results
        """
        return {
            "name": self.name,
            "description": self.description,
            "server": self.server_name
        }


@dataclass
class MCPResource:
    """Represents an MCP resource."""
    uri: str
    name: str
    description: Optional[str] = None
    mime_type: Optional[str] = None
    server_name: Optional[str] = None

    def to_test_format(self) -> Dict[str, Any]:
        """
        Convert to test result format for UI display.

        Returns:
            Resource info for test results
        """
        return {
            "uri": self.uri,
            "name": self.name,
            "description": self.description
        }


@dataclass
class MCPConnectionInfo:
    """Information about an MCP server connection."""
    server_config: MCPServerConfig
    status: MCPConnectionStatus
    tools: Dict[str, MCPTool]
    resources: Dict[str, MCPResource]
    error_message: Optional[str] = None

    @property
    def is_connected(self) -> bool:
        """Check if connection is active."""
        return self.status == MCPConnectionStatus.CONNECTED

    @property
    def tools_count(self) -> int:
        """Get number of available tools."""
        return len(self.tools)

    @property
    def resources_count(self) -> int:
        """Get number of available resources."""
        return len(self.resources)


@dataclass
class MCPTestResult:
    """Result of testing an MCP server connection."""
    success: bool
    tools_count: int = 0
    resources_count: int = 0
    tools: List[Dict[str, Any]] = None
    resources: List[Dict[str, Any]] = None
    error: Optional[str] = None

    def __post_init__(self):
        """Initialize lists if None."""
        if self.tools is None:
            self.tools = []
        if self.resources is None:
            self.resources = []

    @classmethod
    def success_result(cls, tools: List[MCPTool], resources: List[MCPResource]) -> 'MCPTestResult':
        """Create successful test result."""
        return cls(
            success=True,
            tools_count=len(tools),
            resources_count=len(resources),
            tools=[tool.to_test_format() for tool in tools],
            resources=[resource.to_test_format() for resource in resources]
        )

    @classmethod
    def failure_result(cls, error: str) -> 'MCPTestResult':
        """Create failed test result."""
        return cls(
            success=False,
            error=error
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API compatibility."""
        return {
            "success": self.success,
            "tools_count": self.tools_count,
            "resources_count": self.resources_count,
            "tools": self.tools,
            "resources": self.resources,
            "error": self.error
        }


@dataclass
class MCPToolExecutionRequest:
    """Request to execute an MCP tool."""
    tool_name: str
    arguments: Dict[str, Any]
    server_name: Optional[str] = None  # Auto-detect if not provided
    timeout: float = 60.0


@dataclass
class MCPToolExecutionResult:
    """Result of MCP tool execution."""
    success: bool
    result: Any = None
    error: Optional[str] = None
    execution_time: float = 0.0
    server_name: Optional[str] = None

    @classmethod
    def success_result(cls, result: Any, execution_time: float = 0.0, server_name: str = None) -> 'MCPToolExecutionResult':
        """Create successful execution result."""
        return cls(
            success=True,
            result=result,
            execution_time=execution_time,
            server_name=server_name
        )

    @classmethod
    def failure_result(cls, error: str, execution_time: float = 0.0, server_name: str = None) -> 'MCPToolExecutionResult':
        """Create failed execution result."""
        return cls(
            success=False,
            error=error,
            execution_time=execution_time,
            server_name=server_name
        )
