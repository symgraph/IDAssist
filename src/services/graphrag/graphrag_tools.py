#!/usr/bin/env python3

"""
GraphRAG Tools for LLM Function Calling

Provides 9 graph tools (3 write + 6 read) that let the LLM interact with
the semantic knowledge graph during conversations. Write tools allow the
LLM to record vulnerabilities, add security flags, and create semantic
edges. Read tools provide structured access to graph data.

This module is platform-agnostic: binary_hash and analysis_db are passed
in by the caller (orchestrator), not resolved internally.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from .graph_store import GraphStore
from .query_engine import GraphRAGQueryEngine
from .models import GraphNode, EdgeType

logger = logging.getLogger(__name__)

# ============================================================
# Vulnerability type and severity enums
# ============================================================

VULNERABILITY_TYPES = frozenset({
    "BUFFER_OVERFLOW", "COMMAND_INJECTION", "FORMAT_STRING",
    "USE_AFTER_FREE", "INTEGER_OVERFLOW", "PATH_TRAVERSAL",
    "RACE_CONDITION", "MEMORY_LEAK", "NULL_DEREF",
    "INFO_DISCLOSURE", "AUTH_BYPASS", "CRYPTO_WEAKNESS", "OTHER",
})

SEVERITY_LEVELS = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

# Non-structural edge types that can be created by the LLM (uppercased for validation)
_ALLOWED_EDGE_TYPES = frozenset(
    m.value.upper() for m in EdgeType if not m.is_structural()
)

# ============================================================
# Tool definitions (9 tools)
# ============================================================

GRAPHRAG_TOOL_DEFINITIONS = [
    # --- Write tools (3) ---
    {
        "name": "ga_record_vulnerability",
        "description": (
            "Record a discovered vulnerability on a function in the knowledge graph. "
            "Adds vulnerability flags and propagates CALLS_VULNERABLE to callers."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Function address (hex string, e.g. '0x401000')",
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name (used if address not provided)",
                },
                "vulnerability_type": {
                    "type": "string",
                    "enum": sorted(VULNERABILITY_TYPES),
                    "description": "Type of vulnerability discovered",
                },
                "severity": {
                    "type": "string",
                    "enum": sorted(SEVERITY_LEVELS),
                    "description": "Severity level of the vulnerability",
                },
                "description": {
                    "type": "string",
                    "description": "Description of the vulnerability",
                },
                "evidence": {
                    "type": "string",
                    "description": "Evidence or reasoning for the vulnerability",
                },
            },
            "required": ["vulnerability_type", "severity", "description"],
        },
    },
    {
        "name": "ga_add_security_flag",
        "description": (
            "Add a custom security flag to a function node in the knowledge graph. "
            "Common flags: HANDLES_USER_INPUT, PARSES_NETWORK_DATA, CRYPTO_OPERATION, "
            "PRIVILEGE_CHECK, AUTHENTICATION, SENSITIVE_DATA, MEMORY_ALLOCATOR, ERROR_HANDLER."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Function address (hex string)",
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name (used if address not provided)",
                },
                "flag": {
                    "type": "string",
                    "description": "Security flag to add (e.g. 'HANDLES_USER_INPUT')",
                },
            },
            "required": ["flag"],
        },
    },
    {
        "name": "ga_create_edge",
        "description": (
            "Create a relationship edge between two functions in the knowledge graph. "
            "Allowed types — Semantic: SIMILAR_PURPOSE, RELATED_TO, DEPENDS_ON, IMPLEMENTS; "
            "Security: VULNERABLE_VIA, TAINT_FLOWS_TO, CALLS_VULNERABLE, NETWORK_SEND, NETWORK_RECV; "
            "Community: BELONGS_TO_COMMUNITY, SIBLING. "
            "Structural types (CONTAINS, CALLS, FLOWS_TO, REFERENCES, INHERITS) are NOT allowed."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "source_address": {
                    "type": "string",
                    "description": "Source function address (hex string)",
                },
                "source_name": {
                    "type": "string",
                    "description": "Source function name (used if address not provided)",
                },
                "target_address": {
                    "type": "string",
                    "description": "Target function address (hex string)",
                },
                "target_name": {
                    "type": "string",
                    "description": "Target function name (used if address not provided)",
                },
                "edge_type": {
                    "type": "string",
                    "enum": sorted(_ALLOWED_EDGE_TYPES),
                    "description": "Type of semantic relationship",
                },
                "confidence": {
                    "type": "number",
                    "description": "Confidence score (0.0-1.0, default 0.8)",
                },
                "reason": {
                    "type": "string",
                    "description": "Reason for creating this relationship",
                },
            },
            "required": ["edge_type"],
        },
    },
    # --- Read tools (6) ---
    {
        "name": "ga_get_semantic_analysis",
        "description": (
            "Get full semantic analysis for a function from the knowledge graph, "
            "including LLM summary, security flags, callers, callees, and raw code."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Function address (hex string)",
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name (used if address not provided)",
                },
            },
        },
    },
    {
        "name": "ga_search_semantic",
        "description": (
            "Full-text search on LLM summaries and function names in the knowledge graph."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results (default 20)",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "ga_get_call_context",
        "description": (
            "Get caller/callee context for a function with summaries and security flags."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Function address (hex string)",
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name (used if address not provided)",
                },
                "depth": {
                    "type": "integer",
                    "description": "Depth of call context (default 1)",
                },
                "direction": {
                    "type": "string",
                    "enum": ["callers", "callees", "both"],
                    "description": "Direction of call context (default 'both')",
                },
            },
        },
    },
    {
        "name": "ga_get_security_analysis",
        "description": (
            "Get security analysis for a function including security flags, "
            "taint paths, attack surface, and vulnerable callers."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Function address (hex string)",
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name (used if address not provided)",
                },
            },
        },
    },
    {
        "name": "ga_get_activity_analysis",
        "description": (
            "Get network/file activity profile for a function including network APIs, "
            "file I/O, IP addresses, URLs, file paths, domains, and registry keys."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Function address (hex string)",
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name (used if address not provided)",
                },
            },
        },
    },
    {
        "name": "ga_get_module_summary",
        "description": (
            "Get the community/module summary for a function, including the module's "
            "inferred purpose, member functions, and member count."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Function address (hex string)",
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name (used if address not provided)",
                },
            },
        },
    },
]

GRAPHRAG_TOOL_NAMES = frozenset(d["name"] for d in GRAPHRAG_TOOL_DEFINITIONS)


def get_graphrag_tools_for_llm(exclude_names=None) -> List[Dict[str, Any]]:
    """Return graphrag tool definitions in OpenAI tool-calling format.

    Args:
        exclude_names: set of tool names to skip (e.g. tools already
                       provided by an external MCP server).
    """
    exclude = exclude_names or set()
    tools = []
    for defn in GRAPHRAG_TOOL_DEFINITIONS:
        if defn["name"] in exclude:
            continue
        tools.append({
            "type": "function",
            "function": {
                "name": defn["name"],
                "description": defn["description"],
                "parameters": defn["schema"],
            },
        })
    return tools


def execute_graphrag_tool(
    name: str,
    arguments: Dict[str, Any],
    binary_hash: str,
    analysis_db,
) -> str:
    """Execute a graphrag tool and return the result as a JSON string.

    Args:
        name: Tool name (must be in GRAPHRAG_TOOL_NAMES).
        arguments: Tool arguments from the LLM.
        binary_hash: Hash of the current binary.
        analysis_db: AnalysisDBService instance.

    Returns:
        JSON string with the tool result.
    """
    handlers = {
        "ga_record_vulnerability": _record_vulnerability,
        "ga_add_security_flag": _add_security_flag,
        "ga_create_edge": _create_edge,
        "ga_get_semantic_analysis": _get_semantic_analysis,
        "ga_search_semantic": _search_semantic,
        "ga_get_call_context": _get_call_context,
        "ga_get_security_analysis": _get_security_analysis,
        "ga_get_activity_analysis": _get_activity_analysis,
        "ga_get_module_summary": _get_module_summary,
    }
    handler = handlers.get(name)
    if not handler:
        return json.dumps({"error": f"Unknown graphrag tool: {name}"})
    try:
        graph_store = GraphStore(analysis_db)
        result = handler(arguments, binary_hash, graph_store)
        return json.dumps(result, default=str)
    except Exception as e:
        logger.error("Error executing graphrag tool %s: %s", name, e)
        return json.dumps({"error": f"Error executing {name}: {str(e)}"})


# ============================================================
# Helper: resolve function node by address or name
# ============================================================

def _parse_address(addr_str: str) -> int:
    """Parse hex address string to integer."""
    addr_str = addr_str.strip()
    return int(addr_str, 16)


def _resolve_function(
    args: Dict[str, Any],
    binary_hash: str,
    graph_store: GraphStore,
    address_key: str = "address",
    name_key: str = "function_name",
) -> Optional[GraphNode]:
    """Resolve a function node by address or name from tool arguments."""
    address_str = args.get(address_key)
    if address_str:
        try:
            address = _parse_address(address_str)
            node = graph_store.get_node_by_address(binary_hash, "FUNCTION", address)
            if node:
                return node
        except (ValueError, TypeError):
            pass

    func_name = args.get(name_key)
    if func_name:
        results = graph_store.search_nodes(binary_hash, func_name, limit=1)
        if results:
            return results[0]

    return None


# ============================================================
# Write tool handlers
# ============================================================

def _record_vulnerability(
    args: Dict[str, Any],
    binary_hash: str,
    graph_store: GraphStore,
) -> Dict[str, Any]:
    """Record a discovered vulnerability on a function node."""
    vuln_type = args.get("vulnerability_type", "").upper()
    severity = args.get("severity", "").upper()
    description = args.get("description", "")

    if vuln_type not in VULNERABILITY_TYPES:
        return {"error": f"Invalid vulnerability type: {vuln_type}"}
    if severity not in SEVERITY_LEVELS:
        return {"error": f"Invalid severity: {severity}"}

    node = _resolve_function(args, binary_hash, graph_store)
    if not node:
        return {
            "error": "Function not found in knowledge graph",
            "hint": "The function must be indexed first via the Semantic Graph tab.",
        }

    # Add vulnerability flags (idempotent)
    flags_to_add = [
        f"VULN_{vuln_type}",
        f"SEVERITY_{severity}",
        "LLM_DISCOVERED_VULN",
    ]
    existing_flags = set(node.security_flags or [])
    for flag in flags_to_add:
        if flag not in existing_flags:
            existing_flags.add(flag)

    node.security_flags = sorted(existing_flags)

    # Append vulnerability note to llm_summary
    evidence = args.get("evidence", "")
    vuln_note = f"\n[VULNERABILITY: {vuln_type} ({severity})] {description}"
    if evidence:
        vuln_note += f" Evidence: {evidence}"
    if node.llm_summary:
        node.llm_summary += vuln_note
    else:
        node.llm_summary = vuln_note.strip()

    graph_store.upsert_node(node)

    # Propagate to callers
    callers = graph_store.get_callers(binary_hash, node.id, "calls")
    propagated_to = []
    for caller in callers:
        # Add CALLS_VULNERABLE edge
        if not graph_store.has_edge(caller.id, node.id, EdgeType.CALLS_VULNERABLE.value):
            graph_store.create_edge(
                caller.id, node.id, EdgeType.CALLS_VULNERABLE,
                binary_hash, weight=1.0,
                metadata=json.dumps({"vulnerability_type": vuln_type, "source": "llm_analysis"}),
            )

        # Add flags to caller
        caller_flags = set(caller.security_flags or [])
        new_flags = {f"CALLS_VULN_{vuln_type}", "CALLS_VULNERABLE_FUNCTION"}
        if not new_flags.issubset(caller_flags):
            caller_flags.update(new_flags)
            caller.security_flags = sorted(caller_flags)
            graph_store.upsert_node(caller)
            propagated_to.append(caller.name or f"sub_{caller.address:x}")

    return {
        "status": "recorded",
        "function_name": node.name or f"sub_{node.address:x}",
        "address": f"0x{node.address:x}",
        "vulnerability_type": vuln_type,
        "severity": severity,
        "flags_added": flags_to_add,
        "propagated_to_callers": propagated_to,
    }


def _add_security_flag(
    args: Dict[str, Any],
    binary_hash: str,
    graph_store: GraphStore,
) -> Dict[str, Any]:
    """Add a custom security flag to a function node."""
    flag = args.get("flag", "").strip().upper().replace(" ", "_")
    if not flag:
        return {"error": "Flag parameter is required"}

    node = _resolve_function(args, binary_hash, graph_store)
    if not node:
        return {
            "error": "Function not found in knowledge graph",
            "hint": "The function must be indexed first via the Semantic Graph tab.",
        }

    existing_flags = set(node.security_flags or [])
    if flag in existing_flags:
        return {
            "status": "already_exists",
            "function_name": node.name or f"sub_{node.address:x}",
            "address": f"0x{node.address:x}",
            "flag": flag,
        }

    existing_flags.add(flag)
    node.security_flags = sorted(existing_flags)
    graph_store.upsert_node(node)

    return {
        "status": "added",
        "function_name": node.name or f"sub_{node.address:x}",
        "address": f"0x{node.address:x}",
        "flag": flag,
        "all_flags": node.security_flags,
    }


def _create_edge(
    args: Dict[str, Any],
    binary_hash: str,
    graph_store: GraphStore,
) -> Dict[str, Any]:
    """Create a semantic relationship edge between two functions."""
    edge_type_str = args.get("edge_type", "").upper()
    if edge_type_str not in _ALLOWED_EDGE_TYPES:
        return {
            "error": f"Invalid edge type: {edge_type_str}. "
                     f"Allowed: {', '.join(sorted(_ALLOWED_EDGE_TYPES))}",
        }

    source = _resolve_function(
        args, binary_hash, graph_store,
        address_key="source_address", name_key="source_name",
    )
    if not source:
        return {"error": "Source function not found in knowledge graph"}

    target = _resolve_function(
        args, binary_hash, graph_store,
        address_key="target_address", name_key="target_name",
    )
    if not target:
        return {"error": "Target function not found in knowledge graph"}

    if source.id == target.id:
        return {"error": "Cannot create edge from a function to itself"}

    edge_type = EdgeType.from_string(edge_type_str.lower())
    if not edge_type:
        return {"error": f"Could not parse edge type: {edge_type_str}"}

    # Check idempotency
    if graph_store.has_edge(source.id, target.id, edge_type.value):
        return {
            "status": "already_exists",
            "source": source.name or f"sub_{source.address:x}",
            "target": target.name or f"sub_{target.address:x}",
            "edge_type": edge_type_str,
        }

    confidence = args.get("confidence", 0.8)
    reason = args.get("reason", "")
    metadata = json.dumps({
        "reason": reason,
        "source": "llm_analysis",
        "confidence": confidence,
    })

    graph_store.create_edge(
        source.id, target.id, edge_type, binary_hash,
        weight=confidence, metadata=metadata,
    )

    return {
        "status": "created",
        "source": source.name or f"sub_{source.address:x}",
        "source_address": f"0x{source.address:x}",
        "target": target.name or f"sub_{target.address:x}",
        "target_address": f"0x{target.address:x}",
        "edge_type": edge_type_str,
        "confidence": confidence,
        "reason": reason,
    }


# ============================================================
# Read tool handlers
# ============================================================

def _get_semantic_analysis(
    args: Dict[str, Any],
    binary_hash: str,
    graph_store: GraphStore,
) -> Dict[str, Any]:
    """Get full semantic analysis for a function."""
    address = _resolve_address(args, binary_hash, graph_store)
    if address is None:
        return {"error": "Function not found. Provide address or function_name."}

    engine = GraphRAGQueryEngine(graph_store, binary_hash)
    return engine.get_semantic_analysis(address)


def _search_semantic(
    args: Dict[str, Any],
    binary_hash: str,
    graph_store: GraphStore,
) -> Dict[str, Any]:
    """Full-text search on LLM summaries."""
    query = args.get("query", "")
    if not query:
        return {"error": "query parameter is required"}

    limit = args.get("limit", 20)
    engine = GraphRAGQueryEngine(graph_store, binary_hash)
    results = engine.search_semantic(query, limit)
    return {"query": query, "count": len(results), "results": results}


def _get_call_context(
    args: Dict[str, Any],
    binary_hash: str,
    graph_store: GraphStore,
) -> Dict[str, Any]:
    """Get caller/callee context for a function."""
    address = _resolve_address(args, binary_hash, graph_store)
    if address is None:
        return {"error": "Function not found. Provide address or function_name."}

    depth = args.get("depth", 1)
    direction = args.get("direction", "both")
    engine = GraphRAGQueryEngine(graph_store, binary_hash)
    return engine.get_call_context(address, depth, direction)


def _get_security_analysis(
    args: Dict[str, Any],
    binary_hash: str,
    graph_store: GraphStore,
) -> Dict[str, Any]:
    """Get security analysis for a function."""
    address = _resolve_address(args, binary_hash, graph_store)
    if address is None:
        return {"error": "Function not found. Provide address or function_name."}

    engine = GraphRAGQueryEngine(graph_store, binary_hash)
    return engine.get_security_analysis(address)


def _get_activity_analysis(
    args: Dict[str, Any],
    binary_hash: str,
    graph_store: GraphStore,
) -> Dict[str, Any]:
    """Get network/file activity profile for a function."""
    address = _resolve_address(args, binary_hash, graph_store)
    if address is None:
        return {"error": "Function not found. Provide address or function_name."}

    engine = GraphRAGQueryEngine(graph_store, binary_hash)
    return engine.get_activity_analysis(address)


def _get_module_summary(
    args: Dict[str, Any],
    binary_hash: str,
    graph_store: GraphStore,
) -> Dict[str, Any]:
    """Get the community/module summary for a function."""
    address = _resolve_address(args, binary_hash, graph_store)
    if address is None:
        return {"error": "Function not found. Provide address or function_name."}

    engine = GraphRAGQueryEngine(graph_store, binary_hash)
    return engine.get_module_summary(address)


# ============================================================
# Helper: resolve address from args (address or function_name)
# ============================================================

def _resolve_address(
    args: Dict[str, Any],
    binary_hash: str,
    graph_store: GraphStore,
) -> Optional[int]:
    """Resolve a function address from tool arguments."""
    address_str = args.get("address")
    if address_str:
        try:
            return _parse_address(address_str)
        except (ValueError, TypeError):
            pass

    func_name = args.get("function_name")
    if func_name:
        results = graph_store.search_nodes(binary_hash, func_name, limit=1)
        if results and results[0].address is not None:
            return results[0].address

    return None
