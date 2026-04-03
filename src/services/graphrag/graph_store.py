#!/usr/bin/env python3

import json
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from .models import GraphNode, GraphEdge, EdgeType
from ..analysis_db_service import AnalysisDBService

from src.ida_compat import log


# Default batch size for bulk operations
DEFAULT_BATCH_SIZE = 100


class GraphStore:
    """SQLite-backed storage for GraphRAG nodes and edges."""

    def __init__(self, analysis_db: Optional[AnalysisDBService] = None):
        self.analysis_db = analysis_db or AnalysisDBService()
        self._db_lock = self.analysis_db.get_db_lock()

        # Batch operation queues (thread-safe)
        self._batch_lock = threading.Lock()
        self._node_batch: List[GraphNode] = []
        self._edge_batch: List[Tuple[str, str, EdgeType, str]] = []  # (source_id, target_id, edge_type, binary_hash)

        # Node cache for deduplication during batch operations
        # Key: (binary_hash, address) -> node_id
        self._node_cache: Dict[Tuple[str, int], str] = {}
        self._node_cache_lock = threading.Lock()

    @staticmethod
    def _serialize_list(values: Optional[List[str]]) -> str:
        if not values:
            return "[]"
        return json.dumps(list(values))

    @staticmethod
    def _deserialize_list(value: Optional[str]) -> List[str]:
        if not value:
            return []
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []

    @staticmethod
    def _normalize_semantic_fields(category: Optional[str], security_flags: Optional[List[str]]) -> Tuple[Optional[str], List[str]]:
        normalized_category = category.strip().lower().replace(" ", "_") if isinstance(category, str) and category.strip() else None
        filtered_flags: List[str] = []
        for flag in security_flags or []:
            if not isinstance(flag, str):
                continue
            trimmed = flag.strip()
            if not trimmed or trimmed == "LLM_FLAGGED":
                continue
            if trimmed.startswith("CATEGORY_"):
                if normalized_category is None:
                    normalized_category = trimmed[len("CATEGORY_"):].lower()
                continue
            filtered_flags.append(trimmed)
        return normalized_category, filtered_flags

    @staticmethod
    def _now_ms() -> int:
        return int(time.time() * 1000)

    @staticmethod
    def _graph_node_select(prefix: str = "") -> str:
        qualifier = f"{prefix}." if prefix else ""
        return (
            f"{qualifier}id, {qualifier}binary_id, {qualifier}type, {qualifier}address, {qualifier}name, "
            f"{qualifier}signature, {qualifier}decompiled_code, {qualifier}disassembly, {qualifier}raw_content, "
            f"{qualifier}llm_summary, {qualifier}confidence, {qualifier}embedding, {qualifier}security_flags, "
            f"{qualifier}network_apis, {qualifier}file_io_apis, {qualifier}ip_addresses, {qualifier}urls, "
            f"{qualifier}file_paths, {qualifier}domains, {qualifier}registry_keys, {qualifier}category, {qualifier}risk_level, "
            f"{qualifier}activity_profile, {qualifier}analysis_depth, {qualifier}created_at, {qualifier}updated_at, "
            f"{qualifier}is_stale, {qualifier}user_edited"
        )

    def _row_to_node(self, row: Tuple[Any, ...]) -> GraphNode:
        category, security_flags = self._normalize_semantic_fields(row[20], self._deserialize_list(row[12]))
        return GraphNode(
            id=row[0],
            binary_hash=row[1],
            node_type=row[2],
            address=row[3],
            name=row[4],
            signature=row[5],
            decompiled_code=row[6] or row[8],
            disassembly=row[7],
            raw_code=row[6] or row[8],
            llm_summary=row[9],
            confidence=row[10] if row[10] is not None else 0.0,
            embedding=row[11],
            security_flags=security_flags,
            network_apis=self._deserialize_list(row[13]),
            file_io_apis=self._deserialize_list(row[14]),
            ip_addresses=self._deserialize_list(row[15]),
            urls=self._deserialize_list(row[16]),
            file_paths=self._deserialize_list(row[17]),
            domains=self._deserialize_list(row[18]),
            registry_keys=self._deserialize_list(row[19]),
            category=category,
            risk_level=row[21],
            activity_profile=row[22],
            analysis_depth=row[23] if row[23] is not None else 0,
            created_at=row[24],
            updated_at=row[25],
            is_stale=bool(row[26]),
            user_edited=bool(row[27]),
        )

    def get_node_by_address(self, binary_hash: str, node_type: str, address: int) -> Optional[GraphNode]:
        if not binary_hash:
            return None
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    f'''
                    SELECT {self._graph_node_select()}
                    FROM graph_nodes
                    WHERE binary_id = ? AND type = ? AND address = ?
                    ''',
                    (binary_hash, node_type, address),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return self._row_to_node(row)
            finally:
                conn.close()

    def get_node_by_id(self, node_id: str) -> Optional[GraphNode]:
        if not node_id:
            return None
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    f'''
                    SELECT {self._graph_node_select()}
                    FROM graph_nodes
                    WHERE id = ?
                    ''',
                    (str(node_id),),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return self._row_to_node(row)
            finally:
                conn.close()

    def upsert_node(self, node: GraphNode) -> GraphNode:
        if not node.binary_hash:
            raise ValueError("binary_hash is required for GraphNode upsert")
        if node.address is None:
            raise ValueError("address is required for GraphNode upsert")

        if not node.id:
            existing = self.get_node_by_address(node.binary_hash, node.node_type, node.address)
            node.id = existing.id if existing else str(uuid.uuid4())

        node.category, node.security_flags = self._normalize_semantic_fields(node.category, node.security_flags)

        now_ms = self._now_ms()
        security_flags = self._serialize_list(node.security_flags)
        network_apis = self._serialize_list(node.network_apis)
        file_io_apis = self._serialize_list(node.file_io_apis)
        ip_addresses = self._serialize_list(node.ip_addresses)
        urls = self._serialize_list(node.urls)
        file_paths = self._serialize_list(node.file_paths)
        domains = self._serialize_list(node.domains)
        registry_keys = self._serialize_list(node.registry_keys)

        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO graph_nodes (
                        id, type, address, binary_id, name, signature, decompiled_code, disassembly, raw_content, llm_summary,
                        confidence, embedding, security_flags, network_apis, file_io_apis,
                        ip_addresses, urls, file_paths, domains, registry_keys, category, risk_level,
                        activity_profile, analysis_depth, created_at, updated_at, is_stale,
                        user_edited
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        -- STRUCTURAL DATA: Always update from fresh extraction
                        type = excluded.type,
                        address = excluded.address,
                        binary_id = excluded.binary_id,
                        name = excluded.name,
                        signature = COALESCE(excluded.signature, graph_nodes.signature),
                        decompiled_code = COALESCE(excluded.decompiled_code, graph_nodes.decompiled_code),
                        disassembly = COALESCE(excluded.disassembly, graph_nodes.disassembly),
                        raw_content = COALESCE(excluded.raw_content, graph_nodes.raw_content),
                        security_flags = excluded.security_flags,
                        network_apis = excluded.network_apis,
                        file_io_apis = excluded.file_io_apis,
                        ip_addresses = excluded.ip_addresses,
                        urls = excluded.urls,
                        file_paths = excluded.file_paths,
                        domains = excluded.domains,
                        registry_keys = excluded.registry_keys,
                        category = excluded.category,
                        risk_level = excluded.risk_level,
                        activity_profile = excluded.activity_profile,
                        updated_at = excluded.updated_at,
                        is_stale = excluded.is_stale,
                        -- SEMANTIC DATA: Preserve existing, only update if explicitly set
                        llm_summary = COALESCE(excluded.llm_summary, graph_nodes.llm_summary),
                        confidence = CASE WHEN excluded.confidence > 0 THEN excluded.confidence ELSE graph_nodes.confidence END,
                        embedding = COALESCE(excluded.embedding, graph_nodes.embedding),
                        analysis_depth = CASE WHEN excluded.analysis_depth > 0 THEN excluded.analysis_depth ELSE graph_nodes.analysis_depth END,
                        -- USER DATA: Never reset during reindex
                        user_edited = graph_nodes.user_edited
                ''', (
                    node.id,
                    node.node_type,
                    node.address,
                    node.binary_hash,
                    node.name,
                    node.signature,
                    node.get_decompiled_code(),
                    node.disassembly,
                    node.get_decompiled_code(),
                    node.llm_summary,
                    node.confidence,
                    node.embedding,
                    security_flags,
                    network_apis,
                    file_io_apis,
                    ip_addresses,
                    urls,
                    file_paths,
                    domains,
                    registry_keys,
                    node.category,
                    node.risk_level,
                    node.activity_profile,
                    node.analysis_depth,
                    now_ms,
                    now_ms,
                    1 if node.is_stale else 0,
                    1 if node.user_edited else 0
                ))
                conn.commit()
                return node
            finally:
                conn.close()

    def update_node_name(self, binary_hash: str, address: int, new_name: str) -> bool:
        """Update just the name of a function node by address (lightweight).

        Only touches name and updated_at — preserves all other fields.
        The existing graph_nodes_au AFTER UPDATE trigger automatically updates FTS.

        Returns True if a row was updated, False if node not indexed yet.
        """
        if not binary_hash or address is None:
            return False
        now_ms = self._now_ms()
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE graph_nodes
                    SET name = ?, updated_at = ?
                    WHERE binary_id = ? AND type = 'FUNCTION' AND address = ?
                ''', (new_name, now_ms, binary_hash, address))
                conn.commit()
                return cursor.rowcount > 0
            finally:
                conn.close()

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        if not edge.binary_hash:
            raise ValueError("binary_hash is required for GraphEdge insert")
        if not edge.source_id or not edge.target_id or not edge.edge_type:
            raise ValueError("source_id, target_id, and edge_type are required for GraphEdge insert")

        # Convert EdgeType enum to string for storage
        edge_type_str = edge.get_edge_type_str()

        # Use deterministic edge ID based on (source_id, target_id, type)
        # This ensures idempotent edge insertion
        edge_id = f"{edge.source_id}:{edge.target_id}:{edge_type_str}"
        edge.id = edge_id

        now_ms = self._now_ms()
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                # Check if edge already exists by deterministic ID
                cursor.execute('SELECT 1 FROM graph_edges WHERE id = ? LIMIT 1', (edge_id,))
                if cursor.fetchone():
                    return edge  # Already exists
                cursor.execute('''
                    INSERT INTO graph_edges (
                        id, source_id, target_id, type, weight, metadata, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    edge_id,
                    edge.source_id,
                    edge.target_id,
                    edge_type_str,
                    edge.weight,
                    edge.metadata,
                    now_ms
                ))
                conn.commit()
                return edge
            finally:
                conn.close()

    def has_edge(self, source_id: str, target_id: str, edge_type: str) -> bool:
        """Check if an edge exists between two nodes."""
        if not source_id or not target_id or not edge_type:
            return False

        # Handle EdgeType enum
        if isinstance(edge_type, EdgeType):
            edge_type = edge_type.value

        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT 1 FROM graph_edges
                    WHERE source_id = ? AND target_id = ? AND type = ?
                    LIMIT 1
                ''', (source_id, target_id, edge_type))
                return cursor.fetchone() is not None
            finally:
                conn.close()

    def create_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        binary_hash: str,
        weight: float = 1.0,
        metadata: Optional[str] = None
    ) -> GraphEdge:
        """Convenience method to create and store an edge."""
        edge = GraphEdge(
            binary_hash=binary_hash,
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            weight=weight,
            metadata=metadata
        )
        return self.add_edge(edge)

    def get_callers(self, binary_hash: str, node_id: str, edge_type: str = "calls") -> List[GraphNode]:
        if not binary_hash or not node_id:
            return []
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                # Use DISTINCT to prevent duplicate nodes from duplicate edges
                cursor.execute(
                    f'''
                    SELECT DISTINCT {self._graph_node_select("n")}
                    FROM graph_edges e
                    JOIN graph_nodes n ON n.id = e.source_id
                    JOIN graph_nodes t ON t.id = e.target_id
                    WHERE t.id = ? AND e.type = ? AND n.binary_id = ? AND t.binary_id = ?
                    ''',
                    (str(node_id), edge_type, binary_hash, binary_hash),
                )
                rows = cursor.fetchall()
                callers = []
                seen_ids = set()  # Additional deduplication by node ID
                for row in rows:
                    caller_id = row[0]
                    if caller_id in seen_ids:
                        continue
                    seen_ids.add(caller_id)
                    callers.append(self._row_to_node(row))
                return callers
            finally:
                conn.close()

    def get_edges_for_node(self, binary_hash: str, node_id: str) -> List[GraphEdge]:
        if not binary_hash or not node_id:
            return []
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT e.id, e.source_id, e.target_id, e.type, e.weight, e.metadata, e.created_at
                    FROM graph_edges e
                    JOIN graph_nodes s ON s.id = e.source_id
                    JOIN graph_nodes t ON t.id = e.target_id
                    WHERE (e.source_id = ? OR e.target_id = ?)
                      AND s.binary_id = ? AND t.binary_id = ?
                ''', (str(node_id), str(node_id), binary_hash, binary_hash))
                rows = cursor.fetchall()
                edges = []
                seen_keys = set()  # Deduplicate by (source_id, target_id, type)
                for row in rows:
                    source_id, target_id, edge_type = row[1], row[2], row[3]
                    key = (source_id, target_id, edge_type)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    edges.append(GraphEdge(
                        id=row[0],
                        binary_hash=binary_hash,
                        source_id=source_id,
                        target_id=target_id,
                        edge_type=edge_type,
                        weight=row[4] if row[4] is not None else 1.0,
                        metadata=row[5],
                        created_at=row[6],
                    ))
                return edges
            finally:
                conn.close()

    def get_graph_stats(self, binary_hash: str) -> Dict[str, Any]:
        if not binary_hash:
            return {"nodes": 0, "edges": 0, "stale": 0, "last_indexed": None}
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM graph_nodes WHERE binary_id = ?', (binary_hash,))
                nodes = cursor.fetchone()[0]
                cursor.execute('''
                    SELECT COUNT(*)
                    FROM graph_edges e
                    JOIN graph_nodes s ON s.id = e.source_id
                    JOIN graph_nodes t ON t.id = e.target_id
                    WHERE s.binary_id = ? AND t.binary_id = ?
                ''', (binary_hash, binary_hash))
                edges = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM graph_nodes WHERE binary_id = ? AND is_stale = 1', (binary_hash,))
                stale = cursor.fetchone()[0]
                cursor.execute('SELECT MAX(updated_at) FROM graph_nodes WHERE binary_id = ?', (binary_hash,))
                last = cursor.fetchone()[0]
                return {"nodes": nodes, "edges": edges, "stale": stale, "last_indexed": last}
            finally:
                conn.close()

    def delete_graph(self, binary_hash: str) -> None:
        if not binary_hash:
            return
        # Clear caches for this binary
        self.clear_batch_caches(binary_hash)
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM graph_nodes WHERE binary_id = ?', (binary_hash,))
                conn.commit()
            finally:
                conn.close()

    # ==================== Batch Operations ====================

    def clear_batch_caches(self, binary_hash: Optional[str] = None) -> None:
        """Clear batch queues and node cache, optionally for a specific binary."""
        with self._batch_lock:
            if binary_hash:
                self._node_batch = [n for n in self._node_batch if n.binary_hash != binary_hash]
                self._edge_batch = [e for e in self._edge_batch if e[3] != binary_hash]
            else:
                self._node_batch.clear()
                self._edge_batch.clear()

        with self._node_cache_lock:
            if binary_hash:
                keys_to_remove = [k for k in self._node_cache if k[0] == binary_hash]
                for key in keys_to_remove:
                    del self._node_cache[key]
            else:
                self._node_cache.clear()

    def deduplicate_nodes(self, binary_hash: str) -> int:
        """
        Remove duplicate nodes, keeping only one per (binary_id, address).

        When duplicates exist, keeps the node with the most data (non-null llm_summary,
        or highest analysis_depth, or most recent updated_at).

        Returns:
            Number of duplicate nodes removed
        """
        if not binary_hash:
            return 0

        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                # Delete duplicates, keeping the "best" node per address
                # Priority: has llm_summary > higher analysis_depth > newer updated_at
                cursor.execute('''
                    DELETE FROM graph_nodes
                    WHERE id IN (
                        SELECT id FROM (
                            SELECT id,
                                ROW_NUMBER() OVER (
                                    PARTITION BY binary_id, address
                                    ORDER BY
                                        CASE WHEN llm_summary IS NOT NULL AND llm_summary != '' THEN 0 ELSE 1 END,
                                        analysis_depth DESC,
                                        updated_at DESC
                                ) as rn
                            FROM graph_nodes
                            WHERE binary_id = ?
                        ) WHERE rn > 1
                    )
                ''', (binary_hash,))
                deleted = cursor.rowcount
                conn.commit()
                return deleted
            finally:
                conn.close()

    def deduplicate_edges(self, binary_hash: str) -> int:
        """
        Remove duplicate edges, keeping only one per (source_id, target_id, type).

        Keeps the oldest edge (by created_at) when duplicates exist.

        Returns:
            Number of duplicate edges removed
        """
        if not binary_hash:
            return 0

        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                # Delete duplicate edges for nodes belonging to this binary
                # Keep the oldest edge per (source_id, target_id, type)
                cursor.execute('''
                    DELETE FROM graph_edges
                    WHERE id IN (
                        SELECT e.id FROM (
                            SELECT id,
                                ROW_NUMBER() OVER (
                                    PARTITION BY source_id, target_id, type
                                    ORDER BY created_at ASC
                                ) as rn
                            FROM graph_edges
                            WHERE source_id IN (
                                SELECT id FROM graph_nodes WHERE binary_id = ?
                            )
                        ) e WHERE e.rn > 1
                    )
                ''', (binary_hash,))
                deleted = cursor.rowcount
                conn.commit()
                return deleted
            finally:
                conn.close()

    def preload_node_cache(self, binary_hash: str) -> int:
        """
        Pre-load existing node IDs from the database into the cache.

        This ensures that queue_node_for_batch() will reuse existing node IDs
        during non-destructive reindexing, preventing duplicate nodes.

        Returns:
            Number of nodes loaded into cache
        """
        if not binary_hash:
            return 0

        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, address FROM graph_nodes
                    WHERE binary_id = ? AND type = 'FUNCTION'
                ''', (binary_hash,))
                rows = cursor.fetchall()

                with self._node_cache_lock:
                    for row in rows:
                        node_id, address = row
                        cache_key = (binary_hash, address)
                        self._node_cache[cache_key] = node_id

                return len(rows)
            finally:
                conn.close()

    def queue_node_for_batch(self, node: GraphNode) -> GraphNode:
        """
        Queue a node for batch insert. Returns the canonical node with assigned ID.

        If a node with the same (binary_hash, address) already exists in the cache,
        returns the existing node to ensure consistent IDs for edge creation.
        """
        if not node.binary_hash or node.address is None:
            raise ValueError("binary_hash and address are required for batch node")

        cache_key = (node.binary_hash, node.address)

        with self._node_cache_lock:
            # Check if we already have this node in cache - reuse existing ID
            if cache_key in self._node_cache:
                node.id = self._node_cache[cache_key]
            elif not node.id:
                # Assign new ID if not set
                node.id = str(uuid.uuid4())
                # Cache the node ID
                self._node_cache[cache_key] = node.id

        node.category, node.security_flags = self._normalize_semantic_fields(node.category, node.security_flags)

        # Always queue for batch insert/update (even existing nodes need is_stale updated)
        with self._batch_lock:
            self._node_batch.append(node)

            # Auto-flush if batch is large
            if len(self._node_batch) >= DEFAULT_BATCH_SIZE:
                self._flush_node_batch_internal()

        return node

    def queue_edge_for_batch(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        binary_hash: str
    ) -> None:
        """Queue an edge for batch insert."""
        if not source_id or not target_id or not edge_type or not binary_hash:
            return

        with self._batch_lock:
            self._edge_batch.append((source_id, target_id, edge_type, binary_hash))

            # Auto-flush if batch is large
            # IMPORTANT: Flush nodes first to satisfy foreign key constraints
            if len(self._edge_batch) >= DEFAULT_BATCH_SIZE:
                self._flush_node_batch_internal()
                self._flush_edge_batch_internal()

    def flush_all_batches(self) -> Tuple[int, int]:
        """
        Flush all pending nodes and edges to the database.
        Returns (nodes_flushed, edges_flushed).
        """
        nodes_flushed = 0
        edges_flushed = 0

        with self._batch_lock:
            nodes_flushed = self._flush_node_batch_internal()
            edges_flushed = self._flush_edge_batch_internal()

        return nodes_flushed, edges_flushed

    def _flush_node_batch_internal(self) -> int:
        """Flush pending nodes to DB. Must be called with _batch_lock held."""
        if not self._node_batch:
            return 0

        nodes_to_flush = self._node_batch[:]
        self._node_batch.clear()

        now_ms = self._now_ms()
        rows = []
        for node in nodes_to_flush:
            rows.append((
                node.id,
                node.node_type,
                node.address,
                node.binary_hash,
                node.name,
                node.signature,
                node.get_decompiled_code(),
                node.disassembly,
                node.get_decompiled_code(),
                node.llm_summary,
                node.confidence,
                node.embedding,
                self._serialize_list(node.security_flags),
                self._serialize_list(node.network_apis),
                self._serialize_list(node.file_io_apis),
                self._serialize_list(node.ip_addresses),
                self._serialize_list(node.urls),
                self._serialize_list(node.file_paths),
                self._serialize_list(node.domains),
                self._serialize_list(node.registry_keys),
                node.category,
                node.risk_level,
                node.activity_profile,
                node.analysis_depth,
                now_ms,
                now_ms,
                1 if node.is_stale else 0,
                1 if node.user_edited else 0
            ))

        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.executemany('''
                    INSERT INTO graph_nodes (
                        id, type, address, binary_id, name, signature, decompiled_code, disassembly, raw_content, llm_summary,
                        confidence, embedding, security_flags, network_apis, file_io_apis,
                        ip_addresses, urls, file_paths, domains, registry_keys, category, risk_level,
                        activity_profile, analysis_depth, created_at, updated_at, is_stale,
                        user_edited
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        -- STRUCTURAL DATA: Always update from fresh extraction
                        type = excluded.type,
                        address = excluded.address,
                        binary_id = excluded.binary_id,
                        name = excluded.name,
                        signature = COALESCE(excluded.signature, graph_nodes.signature),
                        decompiled_code = COALESCE(excluded.decompiled_code, graph_nodes.decompiled_code),
                        disassembly = COALESCE(excluded.disassembly, graph_nodes.disassembly),
                        raw_content = COALESCE(excluded.raw_content, graph_nodes.raw_content),
                        security_flags = excluded.security_flags,
                        network_apis = excluded.network_apis,
                        file_io_apis = excluded.file_io_apis,
                        ip_addresses = excluded.ip_addresses,
                        urls = excluded.urls,
                        file_paths = excluded.file_paths,
                        domains = excluded.domains,
                        registry_keys = excluded.registry_keys,
                        category = excluded.category,
                        risk_level = excluded.risk_level,
                        activity_profile = excluded.activity_profile,
                        updated_at = excluded.updated_at,
                        is_stale = excluded.is_stale,
                        -- SEMANTIC DATA: Preserve existing, only update if explicitly set
                        llm_summary = COALESCE(excluded.llm_summary, graph_nodes.llm_summary),
                        confidence = CASE WHEN excluded.confidence > 0 THEN excluded.confidence ELSE graph_nodes.confidence END,
                        embedding = COALESCE(excluded.embedding, graph_nodes.embedding),
                        analysis_depth = CASE WHEN excluded.analysis_depth > 0 THEN excluded.analysis_depth ELSE graph_nodes.analysis_depth END,
                        -- USER DATA: Never reset during reindex
                        user_edited = graph_nodes.user_edited
                ''', rows)
                conn.commit()
                return len(rows)
            except Exception as e:
                log.log_error(f"Batch node flush failed: {e}")
                return 0
            finally:
                conn.close()

    def _flush_edge_batch_internal(self) -> int:
        """Flush pending edges to DB. Must be called with _batch_lock held."""
        if not self._edge_batch:
            return 0

        edges_to_flush = self._edge_batch[:]
        self._edge_batch.clear()

        now_ms = self._now_ms()
        rows = []
        seen = set()  # Dedupe within batch

        for source_id, target_id, edge_type, binary_hash in edges_to_flush:
            edge_type_str = edge_type.value if isinstance(edge_type, EdgeType) else str(edge_type)
            key = (source_id, target_id, edge_type_str)
            if key in seen:
                continue
            seen.add(key)

            # Generate deterministic edge ID from source/target/type
            # This ensures INSERT OR REPLACE will update existing edges with same key
            edge_id = f"{source_id}:{target_id}:{edge_type_str}"

            rows.append((
                edge_id,
                source_id,
                target_id,
                edge_type_str,
                1.0,  # weight
                None,  # metadata
                now_ms
            ))

        if not rows:
            return 0

        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                # Use INSERT OR REPLACE with deterministic edge IDs to prevent duplicates
                cursor.executemany('''
                    INSERT OR REPLACE INTO graph_edges (
                        id, source_id, target_id, type, weight, metadata, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', rows)
                conn.commit()
                return len(rows)
            except Exception as e:
                log.log_error(f"Batch edge flush failed: {e}")
                return 0
            finally:
                conn.close()

    def get_cached_node_id(self, binary_hash: str, address: int) -> Optional[str]:
        """Get a node ID from cache if it exists."""
        with self._node_cache_lock:
            return self._node_cache.get((binary_hash, address))

    def search_nodes(self, binary_hash: str, query: str, limit: int = 10) -> List[GraphNode]:
        if not binary_hash or not query:
            return []

        query = query.strip()
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        f'''
                        SELECT {self._graph_node_select("n")}
                        FROM node_fts f
                        JOIN graph_nodes n ON n.id = f.id
                        WHERE n.binary_id = ? AND node_fts MATCH ?
                        LIMIT ?
                        ''',
                        (binary_hash, query, limit),
                    )
                except Exception:
                    cursor.execute(
                        f'''
                        SELECT {self._graph_node_select()}
                        FROM graph_nodes
                        WHERE binary_id = ? AND (name LIKE ? OR signature LIKE ? OR llm_summary LIKE ?)
                        LIMIT ?
                        ''',
                        (binary_hash, f"%{query}%", f"%{query}%", f"%{query}%", limit),
                    )

                rows = cursor.fetchall()
                results = []
                for row in rows:
                    results.append(self._row_to_node(row))
                return results
            finally:
                conn.close()

    def get_stale_nodes(self, binary_hash: str, limit: int = 0) -> List[GraphNode]:
        if not binary_hash:
            return []
        limit_value = limit if limit > 0 else 1000000
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    f'''
                    SELECT {self._graph_node_select()}
                    FROM graph_nodes
                    WHERE binary_id = ?
                      AND (is_stale = 1 OR llm_summary IS NULL OR llm_summary = '')
                    LIMIT ?
                    ''',
                    (binary_hash, limit_value),
                )
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    results.append(self._row_to_node(row))
                return results
            finally:
                conn.close()

    def get_nodes_by_type(self, binary_hash: str, node_type: str = "FUNCTION") -> List[GraphNode]:
        if not binary_hash:
            return []
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    f'''
                    SELECT {self._graph_node_select()}
                    FROM graph_nodes
                    WHERE binary_id = ? AND type = ?
                    ''',
                    (binary_hash, node_type),
                )
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    results.append(self._row_to_node(row))
                return results
            finally:
                conn.close()

    # ==================== Community Detection Methods ====================

    def get_edges_by_types(self, binary_hash: str, edge_types: List[str]) -> List[GraphEdge]:
        """Get all edges of specified types for a binary (for community detection)."""
        if not binary_hash or not edge_types:
            return []
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                placeholders = ','.join('?' * len(edge_types))
                cursor.execute(f'''
                    SELECT e.id, e.source_id, e.target_id, e.type, e.weight, e.metadata, e.created_at
                    FROM graph_edges e
                    JOIN graph_nodes s ON s.id = e.source_id
                    JOIN graph_nodes t ON t.id = e.target_id
                    WHERE s.binary_id = ? AND t.binary_id = ? AND e.type IN ({placeholders})
                ''', (binary_hash, binary_hash, *edge_types))
                rows = cursor.fetchall()
                edges = []
                for row in rows:
                    edges.append(GraphEdge(
                        id=row[0],
                        binary_hash=binary_hash,
                        source_id=row[1],
                        target_id=row[2],
                        edge_type=row[3],
                        weight=row[4] if row[4] is not None else 1.0,
                        metadata=row[5],
                        created_at=row[6],
                    ))
                return edges
            finally:
                conn.close()

    def communities_exist(self, binary_hash: str) -> bool:
        """Check if communities have been detected for a binary."""
        if not binary_hash:
            return False
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT COUNT(*) FROM graph_communities WHERE binary_id = ?',
                    (binary_hash,)
                )
                count = cursor.fetchone()[0]
                return count > 0
            finally:
                conn.close()

    def delete_communities(self, binary_hash: str) -> int:
        """Delete all communities for a binary (for re-detection). Returns count deleted."""
        if not binary_hash:
            return 0
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                # Get count before delete
                cursor.execute(
                    'SELECT COUNT(*) FROM graph_communities WHERE binary_id = ?',
                    (binary_hash,)
                )
                count = cursor.fetchone()[0]
                # Delete communities (CASCADE will delete community_members)
                cursor.execute(
                    'DELETE FROM graph_communities WHERE binary_id = ?',
                    (binary_hash,)
                )
                conn.commit()
                return count
            finally:
                conn.close()

    def save_community(self, binary_hash: str, community: Dict[str, Any]) -> str:
        """Save a community to the database. Returns community_id."""
        if not binary_hash:
            raise ValueError("binary_hash is required for community save")

        community_id = community.get('id') or str(uuid.uuid4())
        now_ms = self._now_ms()

        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO graph_communities (
                        id, level, binary_id, parent_community_id, name, summary,
                        member_count, is_stale, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        name = excluded.name,
                        summary = excluded.summary,
                        member_count = excluded.member_count,
                        is_stale = excluded.is_stale,
                        updated_at = excluded.updated_at
                ''', (
                    community_id,
                    community.get('level', 0),
                    binary_hash,
                    community.get('parent_community_id'),
                    community.get('name', 'Unknown Module'),
                    community.get('summary', ''),
                    community.get('member_count', 0),
                    1 if community.get('is_stale', False) else 0,
                    now_ms,
                    now_ms,
                ))
                conn.commit()
                return community_id
            finally:
                conn.close()

    def add_community_member(self, community_id: str, node_id: str, score: float = 1.0) -> None:
        """Add a node as a member of a community."""
        if not community_id or not node_id:
            return
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO community_members (community_id, node_id, membership_score)
                    VALUES (?, ?, ?)
                    ON CONFLICT(community_id, node_id) DO UPDATE SET
                        membership_score = excluded.membership_score
                ''', (community_id, node_id, score))
                conn.commit()
            finally:
                conn.close()

    def get_communities(self, binary_hash: str) -> List[Dict[str, Any]]:
        """Get all communities for a binary."""
        if not binary_hash:
            return []
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, level, binary_id, parent_community_id, name, summary,
                           member_count, is_stale, created_at, updated_at
                    FROM graph_communities
                    WHERE binary_id = ?
                    ORDER BY member_count DESC
                ''', (binary_hash,))
                rows = cursor.fetchall()
                communities = []
                for row in rows:
                    communities.append({
                        'id': row[0],
                        'level': row[1],
                        'binary_id': row[2],
                        'parent_community_id': row[3],
                        'name': row[4],
                        'summary': row[5],
                        'member_count': row[6],
                        'is_stale': bool(row[7]),
                        'created_at': row[8],
                        'updated_at': row[9],
                    })
                return communities
            finally:
                conn.close()

    def get_community_members(self, community_id: str) -> List[GraphNode]:
        """Get all member nodes of a community."""
        if not community_id:
            return []
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    f'''
                    SELECT {self._graph_node_select("n")}
                    FROM community_members cm
                    JOIN graph_nodes n ON n.id = cm.node_id
                    WHERE cm.community_id = ?
                    ORDER BY n.name
                    ''',
                    (community_id,),
                )
                rows = cursor.fetchall()
                members = []
                for row in rows:
                    members.append(self._row_to_node(row))
                return members
            finally:
                conn.close()

    def get_community_for_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get the community that contains a specific node."""
        if not node_id:
            return None
        with self._db_lock:
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT c.id, c.level, c.binary_id, c.parent_community_id, c.name,
                           c.summary, c.member_count, c.is_stale, c.created_at, c.updated_at
                    FROM community_members cm
                    JOIN graph_communities c ON c.id = cm.community_id
                    WHERE cm.node_id = ?
                    LIMIT 1
                ''', (node_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                return {
                    'id': row[0],
                    'level': row[1],
                    'binary_id': row[2],
                    'parent_community_id': row[3],
                    'name': row[4],
                    'summary': row[5],
                    'member_count': row[6],
                    'is_stale': bool(row[7]),
                    'created_at': row[8],
                    'updated_at': row[9],
                }
            finally:
                conn.close()
