#!/usr/bin/env python3

from typing import Dict, List, Optional, Set

from .graph_store import GraphStore
from .models import GraphNode


class GraphRAGQueryEngine:
    def __init__(self, graph_store: GraphStore, binary_hash: str):
        self.graph_store = graph_store
        self.binary_hash = binary_hash

    def get_semantic_analysis(self, address: int) -> Dict[str, object]:
        node = self.graph_store.get_node_by_address(self.binary_hash, "FUNCTION", address)
        if not node:
            return {
                "name": "unknown",
                "address": f"0x{address:x}",
                "has_semantic_analysis": False,
                "has_structure_data": False,
                "message": "Function not found in graph.",
            }

        callers = [self._node_name(n) for n in self.graph_store.get_callers(self.binary_hash, node.id, "calls")]
        callees = [self._node_name(n) for n in self._get_callees(node.id)]
        has_semantic = bool(node.llm_summary)
        decompiled_code = node.get_decompiled_code()
        disassembly = node.disassembly
        has_structure = bool(decompiled_code or disassembly or callers or callees)

        summary = node.llm_summary or "(LLM analysis pending - structure data available below)"
        truncated_decompiled = self._truncate(decompiled_code, 2000) if decompiled_code else None
        truncated_disassembly = self._truncate(disassembly, 2000) if disassembly else None

        return {
            "name": self._node_name(node),
            "address": f"0x{node.address:x}",
            "signature": node.signature,
            "has_semantic_analysis": has_semantic,
            "has_structure_data": has_structure,
            "summary": summary,
            "security_flags": node.security_flags or [],
            "category": node.category or self._extract_category(node.llm_summary),
            "confidence": 0.8 if has_semantic else 0.0,
            "callers": callers,
            "callees": callees,
            "community": None,
            "decompiled_code": truncated_decompiled,
            "disassembly": truncated_disassembly,
            "raw_code": truncated_decompiled,
        }

    def search_semantic(self, query: str, limit: int) -> List[Dict[str, object]]:
        results = self.graph_store.search_nodes(self.binary_hash, query, limit)
        output = []
        for idx, node in enumerate(results, 1):
            output.append({
                "function_name": self._node_name(node),
                "address": f"0x{node.address:x}",
                "summary": self._truncate(node.llm_summary or "", 200),
                "score": None,
            })
        return output

    def get_similar_functions(self, address: int, limit: int) -> List[Dict[str, object]]:
        source = self.graph_store.get_node_by_address(self.binary_hash, "FUNCTION", address)
        if not source:
            return []

        results = []
        added: Set[int] = {source.id}

        callers = self.graph_store.get_callers(self.binary_hash, source.id, "calls")
        for caller in callers:
            for sibling in self._get_callees(caller.id):
                if sibling.id in added:
                    continue
                added.add(sibling.id)
                results.append(self._similar_entry(sibling, 0.7, "SHARED_CALLERS"))
                if len(results) >= limit:
                    break
            if len(results) >= limit:
                break

        if len(results) < limit:
            callees = self._get_callees(source.id)
            for callee in callees:
                for sibling in self.graph_store.get_callers(self.binary_hash, callee.id, "calls"):
                    if sibling.id in added:
                        continue
                    added.add(sibling.id)
                    results.append(self._similar_entry(sibling, 0.6, "SHARED_CALLEES"))
                    if len(results) >= limit:
                        break
                if len(results) >= limit:
                    break

        if len(results) < limit and source.llm_summary:
            keywords = self._extract_keywords(source.llm_summary)
            if keywords:
                query = " OR ".join(keywords)
                fts_results = self.graph_store.search_nodes(self.binary_hash, query, limit)
                for node in fts_results:
                    if node.id in added:
                        continue
                    added.add(node.id)
                    results.append(self._similar_entry(node, 0.5, "FTS_MATCH"))
                    if len(results) >= limit:
                        break

        results.sort(key=lambda entry: entry.get("score") or 0.0, reverse=True)
        return results[:limit]

    def get_call_context(self, address: int, depth: int, direction: str) -> Dict[str, object]:
        node = self.graph_store.get_node_by_address(self.binary_hash, "FUNCTION", address)
        if not node:
            return {
                "function": {
                    "function_name": "unknown",
                    "address": f"0x{address:x}",
                    "summary": "Function not found in graph",
                    "security_flags": [],
                },
                "callers": [],
                "callees": [],
            }

        callers = []
        callees = []
        direction = (direction or "both").lower()
        if direction in ("both", "callers"):
            callers = self._collect_context(node.id, depth, True)
        if direction in ("both", "callees"):
            callees = self._collect_context(node.id, depth, False)

        return {
            "function": {
                "function_name": self._node_name(node),
                "address": f"0x{node.address:x}",
                "summary": node.llm_summary or "",
                "security_flags": node.security_flags or [],
            },
            "callers": callers,
            "callees": callees,
        }

    def get_security_analysis(self, address: int) -> Dict[str, object]:
        node = self.graph_store.get_node_by_address(self.binary_hash, "FUNCTION", address)
        if not node:
            return {
                "scope": "function",
                "name": "unknown",
                "address": f"0x{address:x}",
                "security_flags": [],
                "taint_paths": [],
                "attack_surface": [],
                "vulnerable_callers": [],
            }

        vulnerable_callers = []
        for caller in self.graph_store.get_callers(self.binary_hash, node.id, "calls"):
            if caller.security_flags:
                vulnerable_callers.append(self._node_name(caller))

        return {
            "scope": "function",
            "name": self._node_name(node),
            "address": f"0x{node.address:x}",
            "security_flags": node.security_flags or [],
            "taint_paths": [],
            "attack_surface": [],
            "vulnerable_callers": vulnerable_callers,
        }

    def get_binary_security_analysis(self) -> Dict[str, object]:
        nodes = self.graph_store.get_nodes_by_type(self.binary_hash, "FUNCTION")
        all_flags = set()
        flagged_functions = []
        for node in nodes:
            if node.security_flags:
                all_flags.update(node.security_flags)
                flagged_functions.append(self._node_name(node))

        return {
            "scope": "binary",
            "name": self.binary_hash,
            "security_flags": sorted(all_flags),
            "taint_paths": [],
            "attack_surface": [],
            "vulnerable_callers": flagged_functions,
        }

    def get_activity_analysis(self, address: int) -> Dict[str, object]:
        node = self.graph_store.get_node_by_address(self.binary_hash, "FUNCTION", address)
        if not node:
            return {"error": "Function not found in graph"}

        has_activity = any([
            node.network_apis,
            node.file_io_apis,
            node.ip_addresses,
            node.urls,
            node.file_paths,
            node.domains,
            node.registry_keys,
        ])

        result: Dict[str, object] = {
            "function_name": self._node_name(node),
            "address": f"0x{node.address:x}",
            "has_activity": bool(has_activity),
            "activity_profile": node.activity_profile or "NONE",
            "risk_level": node.risk_level or "LOW",
        }

        if node.network_apis:
            result["network_apis"] = node.network_apis
        if node.file_io_apis:
            result["file_io_apis"] = node.file_io_apis
        if node.ip_addresses:
            result["ip_addresses"] = node.ip_addresses
        if node.urls:
            result["urls"] = node.urls
        if node.file_paths:
            result["file_paths"] = node.file_paths
        if node.domains:
            result["domains"] = node.domains
        if node.registry_keys:
            result["registry_keys"] = node.registry_keys

        return result

    def get_module_summary(self, address: int) -> Dict[str, object]:
        """Get the module/community summary for the function at the given address."""
        node = self.graph_store.get_node_by_address(self.binary_hash, "FUNCTION", address)
        if not node:
            return {
                "error": "Function not found in graph",
                "address": f"0x{address:x}",
            }

        community = self.graph_store.get_community_for_node(node.id)
        if not community:
            return {
                "message": "No community detected for this function. Run community detection first.",
                "function_name": self._node_name(node),
                "function_address": f"0x{address:x}",
            }

        members = self.graph_store.get_community_members(community["id"])
        member_list = []
        for member in members[:20]:
            member_list.append({
                "name": self._node_name(member),
                "address": f"0x{member.address:x}" if member.address else "unknown",
            })

        return {
            "community_id": community["id"],
            "community_name": community["name"],
            "inferred_purpose": community["summary"],
            "member_count": community["member_count"],
            "members": member_list,
            "function_name": self._node_name(node),
            "function_address": f"0x{address:x}",
        }

    def get_all_communities(self) -> List[Dict[str, object]]:
        """Get all communities for the binary."""
        communities = self.graph_store.get_communities(self.binary_hash)
        result = []
        for community in communities:
            result.append({
                "community_id": community["id"],
                "community_name": community["name"],
                "inferred_purpose": community["summary"],
                "member_count": community["member_count"],
            })
        return result

    def _collect_context(self, node_id: int, depth: int, callers: bool) -> List[Dict[str, object]]:
        results = []
        visited = set()
        frontier = [(node_id, 0)]
        max_depth = max(1, depth)
        while frontier:
            current, current_depth = frontier.pop(0)
            if current_depth >= max_depth:
                continue
            neighbors = (self.graph_store.get_callers(self.binary_hash, current, "calls")
                         if callers else self._get_callees(current))
            for neighbor in neighbors:
                if neighbor.id in visited:
                    continue
                visited.add(neighbor.id)
                results.append({
                    "depth": current_depth + 1,
                    "function_name": self._node_name(neighbor),
                    "address": f"0x{neighbor.address:x}",
                    "summary": self._truncate(neighbor.llm_summary or "", 200),
                    "security_flags": neighbor.security_flags or [],
                })
                frontier.append((neighbor.id, current_depth + 1))
        return results

    def _get_callees(self, node_id: int) -> List[GraphNode]:
        edges = self.graph_store.get_edges_for_node(self.binary_hash, node_id)
        results = []
        for edge in edges:
            if edge.source_id == node_id and edge.edge_type == "calls":
                node = self.graph_store.get_node_by_id(edge.target_id)
                if node:
                    results.append(node)
        return results

    @staticmethod
    def _node_name(node: GraphNode) -> str:
        return node.name or f"sub_{node.address:x}"

    @staticmethod
    def _truncate(text: Optional[str], max_length: int) -> Optional[str]:
        if text is None or len(text) <= max_length:
            return text
        return text[:max_length] + "..."

    @staticmethod
    def _extract_category(summary: Optional[str]) -> Optional[str]:
        if not summary:
            return None
        lower = summary.lower()
        if "crypto" in lower or "encrypt" in lower or "decrypt" in lower:
            return "crypto"
        if "network" in lower or "socket" in lower or "connect" in lower:
            return "network"
        if "auth" in lower or "login" in lower or "password" in lower:
            return "authentication"
        if "file" in lower or "read" in lower or "write" in lower:
            return "io_operations"
        if "init" in lower or "setup" in lower or "constructor" in lower:
            return "initialization"
        if "error" in lower or "exception" in lower or "handler" in lower:
            return "error_handling"
        return "utility"

    @staticmethod
    def _extract_keywords(summary: str) -> List[str]:
        if not summary:
            return []
        stop_words = {
            "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
            "have", "has", "had", "do", "does", "did", "will", "would", "could", "should",
            "may", "might", "must", "shall", "can", "this", "that", "these", "those", "and", "or",
            "but", "if", "then", "else", "when", "where", "which", "who", "what", "how", "why",
            "to", "from", "for", "with", "without", "in", "on", "at", "by", "of", "as", "it",
        }
        keywords = []
        for word in summary.lower().split():
            cleaned = "".join(ch for ch in word if ch.isalnum())
            if len(cleaned) > 3 and cleaned not in stop_words:
                keywords.append(cleaned)
            if len(keywords) >= 5:
                break
        return keywords

    @staticmethod
    def _similar_entry(node: GraphNode, score: float, reason: str) -> Dict[str, object]:
        return {
            "function_name": node.name or f"sub_{node.address:x}",
            "address": f"0x{node.address:x}",
            "summary": GraphRAGQueryEngine._truncate(node.llm_summary or "", 200),
            "score": score,
            "similarity_type": reason,
        }
