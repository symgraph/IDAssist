"""
SymGraph data models for IDAssist.

This module provides data structures for SymGraph API integration,
following the existing IDAssist model architecture patterns.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class ConflictAction(Enum):
    """Action type for conflict resolution during pull."""
    NEW = "new"           # Remote only, doesn't exist locally
    CONFLICT = "conflict" # Different values locally and remotely
    SAME = "same"         # Identical values locally and remotely
    LOCAL_ONLY = "local"  # Exists locally but not remotely


class PushScope(Enum):
    """Scope for push operations."""
    FULL_BINARY = "full"
    CURRENT_FUNCTION = "function"


class SymbolType(Enum):
    """Type of symbol."""
    FUNCTION = "function"
    VARIABLE = "variable"
    TYPE = "type"
    STRUCT = "struct"
    ENUM = "enum"
    COMMENT = "comment"


def _parse_address(value: Any) -> int:
    """Parse an address from API response (handles int, hex string, or None)."""
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        if value.startswith('0x') or value.startswith('0X'):
            try:
                return int(value, 16)
            except ValueError:
                return 0
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _parse_int(value: Any, default: int = 0) -> int:
    """Parse an integer from API responses safely."""
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


@dataclass
class BinaryStats:
    """Statistics for a binary in SymGraph."""
    symbol_count: int = 0
    function_count: int = 0
    graph_node_count: int = 0
    query_count: int = 0
    last_queried_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BinaryStats':
        """Create stats from API response dictionary.

        Handles both nested stats (in 'stats' key) and flat response formats.
        """
        # Check if stats are nested inside a 'stats' key
        stats_data = data.get('stats', data)

        # last_queried_at might be at top level even when stats are nested
        last_queried = data.get('last_queried_at') or stats_data.get('last_queried_at')

        return cls(
            symbol_count=stats_data.get('symbol_count', 0),
            function_count=stats_data.get('function_count', 0),
            graph_node_count=stats_data.get('graph_node_count', 0),
            query_count=stats_data.get('query_count', 0),
            last_queried_at=last_queried
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            'symbol_count': self.symbol_count,
            'function_count': self.function_count,
            'graph_node_count': self.graph_node_count,
            'query_count': self.query_count,
            'last_queried_at': self.last_queried_at
        }


@dataclass
class BinaryRevision:
    """Accessible binary revision metadata."""
    version: int
    created_at: Optional[str] = None
    visibility: Optional[str] = None
    is_latest: bool = False
    owner_username: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BinaryRevision':
        return cls(
            version=int(data.get('version', 0) or 0),
            created_at=data.get('created_at'),
            visibility=data.get('visibility'),
            is_latest=bool(data.get('is_latest', False)),
            owner_username=data.get('owner_username')
        )

    @property
    def display_label(self) -> str:
        suffix = " (Latest)" if self.is_latest else ""
        return f"v{self.version}{suffix}"


@dataclass
class Symbol:
    """A symbol from SymGraph."""
    address: int
    symbol_type: str
    name: Optional[str] = None
    data_type: Optional[str] = None
    content: Optional[str] = None  # For comments
    confidence: float = 0.0
    provenance: str = "unknown"
    metadata: Optional[Dict[str, Any]] = None  # For enum members, struct fields, etc.

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Symbol':
        """Create symbol from API response dictionary."""
        return cls(
            address=data.get('address', 0),
            symbol_type=data.get('symbol_type', 'function'),
            name=data.get('name'),
            data_type=data.get('data_type'),
            content=data.get('content'),
            confidence=data.get('confidence', 0.0),
            provenance=data.get('provenance', 'unknown'),
            metadata=data.get('metadata')
        )

    @property
    def display_name(self) -> Optional[str]:
        """Get display name: name for symbols, content for comments."""
        if self.name:
            return self.name
        if self.content:
            return self.content
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert symbol to dictionary."""
        result = {
            'address': self.address,
            'symbol_type': self.symbol_type,
            'confidence': self.confidence,
            'provenance': self.provenance
        }
        if self.name:
            result['name'] = self.name
        if self.data_type:
            result['data_type'] = self.data_type
        if self.content:
            result['content'] = self.content
        if self.metadata:
            result['metadata'] = self.metadata
        return result


@dataclass
class DocumentSummary:
    """Document summary metadata from SymGraph."""
    id: str
    document_identity_id: str
    version: int
    title: str
    doc_type: str
    content_size_bytes: int
    created_at: Optional[str] = None
    introduced_in_revision: Optional[int] = None
    removed_in_revision: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DocumentSummary':
        return cls(
            id=str(data.get('id', '')),
            document_identity_id=str(data.get('document_identity_id', '')),
            version=_parse_int(data.get('version'), 0),
            title=data.get('title', 'Untitled Document'),
            doc_type=data.get('doc_type', 'notes'),
            content_size_bytes=_parse_int(data.get('content_size_bytes'), 0),
            created_at=data.get('created_at'),
            introduced_in_revision=data.get('introduced_in_revision'),
            removed_in_revision=data.get('removed_in_revision'),
        )


@dataclass
class Document(DocumentSummary):
    """Full document payload including Markdown content."""
    content: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Document':
        return cls(
            id=str(data.get('id', '')),
            document_identity_id=str(data.get('document_identity_id', '')),
            version=_parse_int(data.get('version'), 0),
            title=data.get('title', 'Untitled Document'),
            doc_type=data.get('doc_type', 'notes'),
            content_size_bytes=_parse_int(data.get('content_size_bytes'), 0),
            created_at=data.get('created_at'),
            introduced_in_revision=data.get('introduced_in_revision'),
            removed_in_revision=data.get('removed_in_revision'),
            content=data.get('content', ''),
        )


@dataclass
class GraphNode:
    """A graph node from SymGraph."""
    id: Optional[str] = None
    address: int = 0
    node_type: str = "function"
    name: Optional[str] = None
    summary: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'GraphNode':
        """Create graph node from API response dictionary."""
        # Build properties from all available fields
        properties = data.get('properties', {})

        # Map API fields to properties if not already present
        if 'signature' in data and 'signature' not in properties:
            properties['signature'] = data.get('signature')
        if 'decompiled_code' in data and 'decompiled_code' not in properties:
            properties['decompiled_code'] = data.get('decompiled_code')
        if 'disassembly' in data and 'disassembly' not in properties:
            properties['disassembly'] = data.get('disassembly')
        if 'raw_content' in data and 'raw_content' not in properties:
            properties['raw_content'] = data.get('raw_content')
        if 'decompiled_code' not in properties and 'raw_content' in properties:
            properties['decompiled_code'] = properties.get('raw_content')
        if 'confidence' in data and 'confidence' not in properties:
            properties['confidence'] = data.get('confidence', 0.0)
        if 'security_flags' in data and 'security_flags' not in properties:
            properties['security_flags'] = data.get('security_flags', [])
        if 'network_apis' in data and 'network_apis' not in properties:
            properties['network_apis'] = data.get('network_apis', [])
        if 'file_io_apis' in data and 'file_io_apis' not in properties:
            properties['file_io_apis'] = data.get('file_io_apis', [])
        if 'ip_addresses' in data and 'ip_addresses' not in properties:
            properties['ip_addresses'] = data.get('ip_addresses', [])
        if 'urls' in data and 'urls' not in properties:
            properties['urls'] = data.get('urls', [])
        if 'file_paths' in data and 'file_paths' not in properties:
            properties['file_paths'] = data.get('file_paths', [])
        if 'domains' in data and 'domains' not in properties:
            properties['domains'] = data.get('domains', [])
        if 'registry_keys' in data and 'registry_keys' not in properties:
            properties['registry_keys'] = data.get('registry_keys', [])
        if 'risk_level' in data and 'risk_level' not in properties:
            properties['risk_level'] = data.get('risk_level')
        if 'activity_profile' in data and 'activity_profile' not in properties:
            properties['activity_profile'] = data.get('activity_profile')
        if 'analysis_depth' in data and 'analysis_depth' not in properties:
            properties['analysis_depth'] = data.get('analysis_depth', 0)

        return cls(
            id=data.get('id'),
            address=_parse_address(data.get('address')),
            node_type=data.get('node_type', 'function'),
            name=data.get('name'),
            summary=data.get('summary') or data.get('llm_summary'),
            properties=properties
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert graph node to dictionary."""
        result = {
            'address': self.address,
            'node_type': self.node_type
        }
        if self.id:
            result['id'] = self.id
        if self.name:
            result['name'] = self.name
        if self.summary:
            result['summary'] = self.summary
            result['llm_summary'] = self.summary
        if self.properties.get('signature'):
            result['signature'] = self.properties.get('signature')
        if self.properties.get('decompiled_code'):
            result['decompiled_code'] = self.properties.get('decompiled_code')
        if self.properties.get('disassembly'):
            result['disassembly'] = self.properties.get('disassembly')
        if self.properties.get('decompiled_code') or self.properties.get('raw_content'):
            result['raw_content'] = self.properties.get('decompiled_code') or self.properties.get('raw_content')
        if self.properties:
            result['properties'] = self.properties
        return result


@dataclass
class GraphEdge:
    """A graph edge from SymGraph."""
    source_address: int
    target_address: int
    source_name: Optional[str] = None
    target_name: Optional[str] = None
    edge_type: str = "calls"
    properties: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'GraphEdge':
        """Create graph edge from API response dictionary."""
        # Build properties from metadata if present
        properties = data.get('properties', {})
        if 'metadata' in data and data['metadata']:
            metadata = data['metadata']
            if isinstance(metadata, dict):
                for k, v in metadata.items():
                    if k not in properties:
                        properties[k] = v
        if 'weight' in data and 'weight' not in properties:
            properties['weight'] = data.get('weight', 1.0)

        return cls(
            source_address=_parse_address(data.get('source_address')),
            target_address=_parse_address(data.get('target_address')),
            source_name=data.get('source_name'),
            target_name=data.get('target_name'),
            edge_type=data.get('edge_type', 'calls'),
            properties=properties
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert graph edge to dictionary."""
        result = {
            'source_address': self.source_address,
            'target_address': self.target_address,
            'edge_type': self.edge_type
        }
        if self.source_name:
            result['source_name'] = self.source_name
        if self.target_name:
            result['target_name'] = self.target_name
        if self.properties:
            result['properties'] = self.properties
        return result


@dataclass
class ConflictEntry:
    """An entry in the conflict resolution table."""
    address: int
    local_name: Optional[str]
    remote_name: Optional[str]
    action: ConflictAction
    selected: bool
    remote_symbol: Optional[Symbol] = None
    local_symbol: Optional[Symbol] = None

    @classmethod
    def create_new(cls, address: int, remote_symbol: Symbol) -> 'ConflictEntry':
        """Create a NEW conflict entry (remote only)."""
        return cls(
            address=address,
            local_name=None,
            remote_name=remote_symbol.display_name,
            action=ConflictAction.NEW,
            selected=True,  # New items checked by default
            remote_symbol=remote_symbol
        )

    @classmethod
    def create_conflict(cls, address: int, local_name: str, remote_symbol: Symbol) -> 'ConflictEntry':
        """Create a CONFLICT entry (different values)."""
        return cls(
            address=address,
            local_name=local_name,
            remote_name=remote_symbol.display_name,
            action=ConflictAction.CONFLICT,
            selected=False,  # Conflicts unchecked by default
            remote_symbol=remote_symbol
        )

    @classmethod
    def create_same(cls, address: int, name: str, remote_symbol: Symbol) -> 'ConflictEntry':
        """Create a SAME entry (identical values)."""
        return cls(
            address=address,
            local_name=name,
            remote_name=name,
            action=ConflictAction.SAME,
            selected=False,  # Same items are visible but skipped by default
            remote_symbol=remote_symbol
        )

    def to_table_row(self) -> tuple:
        """Convert to table row data for UI display."""
        return (
            self.selected,
            f"0x{self.address:x}",
            self.local_name or "<none>",
            self.remote_name or "<none>",
            self.action.value.upper()
        )


@dataclass
class SymbolExport:
    """Exported symbol data from SymGraph."""
    binary_sha256: str
    symbols: List[Symbol]
    export_version: str = "1.0"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SymbolExport':
        """Create export from API response dictionary."""
        symbols = [Symbol.from_dict(s) for s in data.get('symbols', [])]
        return cls(
            binary_sha256=data.get('binary_sha256', ''),
            symbols=symbols,
            export_version=data.get('export_version', '1.0'),
            metadata=data.get('metadata', {})
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert export to dictionary."""
        return {
            'binary_sha256': self.binary_sha256,
            'symbols': [s.to_dict() for s in self.symbols],
            'export_version': self.export_version,
            'metadata': self.metadata
        }


@dataclass
class GraphExport:
    """Exported graph data from SymGraph."""
    binary_sha256: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    export_version: str = "1.0"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'GraphExport':
        """Create export from API response dictionary."""
        nodes = [GraphNode.from_dict(n) for n in data.get('nodes', [])]
        edges = [GraphEdge.from_dict(e) for e in data.get('edges', [])]

        # Handle both nested (API) and flat (legacy) binary_sha256 formats
        binary_sha256 = data.get('binary_sha256', '')
        if not binary_sha256 and 'binary' in data:
            binary_info = data['binary']
            if isinstance(binary_info, dict):
                binary_sha256 = binary_info.get('sha256', '')

        # Build metadata from available fields
        metadata = data.get('metadata', {})
        if 'exported_at' in data:
            metadata['exported_at'] = data['exported_at']

        return cls(
            binary_sha256=binary_sha256,
            nodes=nodes,
            edges=edges,
            export_version=data.get('version') or data.get('export_version', '1.0'),
            metadata=metadata
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert export to dictionary."""
        return {
            'binary_sha256': self.binary_sha256,
            'nodes': [n.to_dict() for n in self.nodes],
            'edges': [e.to_dict() for e in self.edges],
            'export_version': self.export_version,
            'metadata': self.metadata
        }


@dataclass
class QueryResult:
    """Result of a SymGraph query operation."""
    exists: bool
    stats: Optional[BinaryStats] = None
    revisions: List[BinaryRevision] = field(default_factory=list)
    latest_revision: Optional[int] = None
    selected_revision: Optional[int] = None
    error: Optional[str] = None

    @classmethod
    def found(
        cls,
        stats: Optional[BinaryStats] = None,
        revisions: Optional[List[BinaryRevision]] = None,
        latest_revision: Optional[int] = None,
        selected_revision: Optional[int] = None
    ) -> 'QueryResult':
        """Create a successful query result."""
        return cls(
            exists=True,
            stats=stats,
            revisions=revisions or [],
            latest_revision=latest_revision,
            selected_revision=selected_revision
        )

    @classmethod
    def not_found(cls) -> 'QueryResult':
        """Create a not-found query result."""
        return cls(exists=False)

    @classmethod
    def error_result(cls, error: str) -> 'QueryResult':
        """Create an error query result."""
        return cls(exists=False, error=error)


@dataclass
class PushResult:
    """Result of a SymGraph push operation."""
    success: bool
    symbols_pushed: int = 0
    nodes_pushed: int = 0
    edges_pushed: int = 0
    documents_pushed: int = 0
    document_results: List[Dict[str, Any]] = field(default_factory=list)
    binary_revision: Optional[int] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    requested_visibility: Optional[str] = None
    suggested_visibility: Optional[str] = None

    @classmethod
    def success_result(
        cls,
        symbols: int = 0,
        nodes: int = 0,
        edges: int = 0,
        documents: int = 0,
        document_results: Optional[List[Dict[str, Any]]] = None,
        binary_revision: Optional[int] = None
    ) -> 'PushResult':
        """Create a successful push result."""
        return cls(
            success=True,
            symbols_pushed=symbols,
            nodes_pushed=nodes,
            edges_pushed=edges,
            documents_pushed=documents,
            document_results=document_results or [],
            binary_revision=binary_revision
        )

    @classmethod
    def failure_result(
        cls,
        error: str,
        error_code: Optional[str] = None,
        requested_visibility: Optional[str] = None,
        suggested_visibility: Optional[str] = None
    ) -> 'PushResult':
        """Create a failed push result."""
        return cls(
            success=False,
            error=error,
            error_code=error_code,
            requested_visibility=requested_visibility,
            suggested_visibility=suggested_visibility
        )


@dataclass
class PullPreviewResult:
    """Result of a pull preview operation."""
    success: bool
    conflicts: List[ConflictEntry] = field(default_factory=list)
    error: Optional[str] = None

    @classmethod
    def success_result(cls, conflicts: List[ConflictEntry]) -> 'PullPreviewResult':
        """Create a successful pull preview result."""
        return cls(success=True, conflicts=conflicts)

    @classmethod
    def failure_result(cls, error: str) -> 'PullPreviewResult':
        """Create a failed pull preview result."""
        return cls(success=False, error=error)

    def get_sorted_conflicts(self) -> List[ConflictEntry]:
        """Get conflicts sorted with CONFLICT items first."""
        return sorted(
            self.conflicts,
            key=lambda x: (x.action != ConflictAction.CONFLICT, x.address)
        )
