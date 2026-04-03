#!/usr/bin/env python3

import asyncio
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, TYPE_CHECKING

from .security_feature_extractor import SecurityFeatureExtractor
from .graph_store import GraphStore
from .models import GraphNode
from ..binary_context_service import BinaryContextService, ViewLevel
from ..models.llm_models import ChatRequest, ChatMessage, MessageRole

if TYPE_CHECKING:
    from ..function_summary_service import FunctionSummaryService

from src.ida_compat import log


@dataclass
class ExtractionResult:
    summarized: int
    errors: int
    elapsed_ms: int


class SemanticExtractor:
    DEFAULT_BATCH_SIZE = 3
    DEFAULT_DELAY_MS = 500

    def __init__(self, provider, graph_store: GraphStore, binary_hash: str,
                 summary_service: Optional["FunctionSummaryService"] = None,
                 rag_enabled: bool = False, mcp_enabled: bool = False):
        self.provider = provider
        self.graph_store = graph_store
        self.binary_hash = binary_hash
        self.batch_size = self.DEFAULT_BATCH_SIZE
        self.delay_between_batches = self.DEFAULT_DELAY_MS / 1000.0
        self.cancelled = False
        self._context_service = BinaryContextService()
        self._security_extractor = SecurityFeatureExtractor()
        self._summary_service = summary_service
        self.rag_enabled = rag_enabled
        self.mcp_enabled = mcp_enabled

    def set_batch_config(self, batch_size: int, delay_ms: int) -> None:
        self.batch_size = max(1, batch_size)
        self.delay_between_batches = max(0, delay_ms) / 1000.0

    def cancel(self) -> None:
        self.cancelled = True

    async def summarize_stale_nodes(
        self,
        limit: int = 0,
        progress_callback: Optional[Callable[[int, int, int, int], None]] = None,
        force: bool = False,
    ) -> ExtractionResult:
        start = time.time()
        summarized = 0
        errors = 0

        # When force=True, get all FUNCTION nodes; otherwise, get only stale ones
        if force:
            nodes = self.graph_store.get_nodes_by_type(self.binary_hash, "FUNCTION")
            if limit > 0:
                nodes = nodes[:limit]
            log.log_info(f"Semantic analysis starting (FORCE): {len(nodes)} total nodes to process")
        else:
            nodes = self.graph_store.get_stale_nodes(self.binary_hash, limit)
            log.log_info(f"Semantic analysis starting: {len(nodes)} stale nodes to process")

        total = len(nodes)

        if total == 0:
            log.log_warn("No nodes found to process!")
            return ExtractionResult(0, 0, 0)

        processed = 0
        for idx, node in enumerate(nodes):
            if self.cancelled:
                break
            success = await self._summarize_node(node, force=force)
            processed += 1
            if success:
                summarized += 1
            else:
                errors += 1
            if progress_callback:
                progress_callback(processed, total, summarized, errors)

            if self.delay_between_batches > 0 and (idx + 1) % self.batch_size == 0:
                await asyncio.sleep(self.delay_between_batches)

        elapsed_ms = int((time.time() - start) * 1000)
        log.log_info(f"Semantic analysis complete: {summarized}/{total} summarized, {errors} errors")
        return ExtractionResult(summarized, errors, elapsed_ms)

    async def _summarize_node(self, node: GraphNode, force: bool = False) -> bool:
        if node is None or node.node_type != "FUNCTION":
            return False
        # Always skip user-edited nodes (user's manual edits should be preserved)
        if node.user_edited:
            return False
        if not node.get_decompiled_code():
            decompiled_code = self._get_decompiled_code(node.address)
            if decompiled_code:
                node.set_decompiled_code(decompiled_code)
            if not node.disassembly:
                node.disassembly = self._get_disassembly(node.address)
            if node.get_primary_code():
                self.graph_store.upsert_node(node)

        if not node.get_primary_code():
            log.log_warn(f"Skipping summary for {node.name or node.address}: missing raw code")
            return False

        self._refresh_security_features(node)

        # Use FunctionSummaryService if available (unified prompt with RAG/MCP support)
        # Fall back to legacy prompt if not available
        prompt = self._generate_prompt_for_node(node)
        if not prompt:
            log.log_warn(f"Failed to generate prompt for {node.name or node.address}")
            return False

        response = await self._call_llm(prompt)
        if not response:
            return False

        from .extraction_prompts import extract_category

        node.llm_summary = response.strip()
        node.category = extract_category(response) or None
        node.confidence = 0.85  # LLM-generated summary confidence
        node.is_stale = False
        node.user_edited = False
        self.graph_store.upsert_node(node)
        return True

    def _generate_prompt_for_node(self, node: GraphNode) -> Optional[str]:
        """
        Generate the LLM prompt for a node.

        Uses FunctionSummaryService if available for unified prompt format
        with RAG/MCP support. Falls back to legacy prompt if not available.
        """
        # Try using FunctionSummaryService first (unified path)
        if self._summary_service and node.address is not None:
            try:
                prompt = self._summary_service.generate_full_query(
                    node.address,
                    view_level=ViewLevel.PSEUDO_C,  # Use pseudocode (decompiler output)
                    rag_enabled=self.rag_enabled,
                    mcp_enabled=self.mcp_enabled
                )
                if prompt:
                    log.log_info(f"Using unified prompt for {node.name or hex(node.address)}")
                    return prompt
            except Exception as e:
                log.log_warn(f"FunctionSummaryService failed, falling back to legacy prompt: {e}")

        # Fallback to legacy prompt (without RAG/MCP)
        return self._generate_legacy_prompt(node)

    def _generate_legacy_prompt(self, node: GraphNode) -> Optional[str]:
        """Generate prompt using the legacy extraction_prompts format."""
        # Import here to avoid circular imports and maintain backward compatibility
        from .extraction_prompts import function_summary_prompt

        callers = self._get_callers(node.id)
        callees = self._get_callees(node.id)
        return function_summary_prompt(
            node.name or f"sub_{node.address:x}",
            node.get_decompiled_code() or node.disassembly or "",
            callers,
            callees,
        )

    def _refresh_security_features(self, node: GraphNode) -> None:
        if not self._security_extractor or node.address is None:
            return
        try:
            # In IDA, pass func_ea directly to extract_features
            features = self._security_extractor.extract_features(
                node.address,
                node.get_decompiled_code() or node.disassembly,
            )

            node.network_apis = self._merge_list(node.network_apis, features.network_apis)
            node.file_io_apis = self._merge_list(node.file_io_apis, features.file_io_apis)
            node.ip_addresses = self._merge_list(node.ip_addresses, features.ip_addresses)
            node.urls = self._merge_list(node.urls, features.urls)
            node.file_paths = self._merge_list(node.file_paths, features.file_paths)
            node.domains = self._merge_list(node.domains, features.domains)
            node.registry_keys = self._merge_list(node.registry_keys, features.registry_keys)

            node.activity_profile = features.get_activity_profile()
            node.risk_level = features.get_risk_level()

            new_flags = set(features.generate_security_flags())
            node.security_flags = sorted(set(node.security_flags or []).union(new_flags))

            self.graph_store.upsert_node(node)
        except Exception as exc:
            log.log_warn(f"Failed to refresh security features: {exc}")

    @staticmethod
    def _merge_list(existing, new_values):
        merged = set(existing or [])
        merged.update(new_values or [])
        return sorted(merged)

    async def _call_llm(self, prompt: str) -> Optional[str]:
        try:
            messages = [ChatMessage(role=MessageRole.USER, content=prompt)]
            request = ChatRequest(
                messages=messages,
                model=self.provider.model,
                stream=False,
                max_tokens=self.provider.max_tokens,
            )
            response = await self.provider.chat_completion(request)
            return response.content if response else None
        except Exception as exc:
            log.log_error(f"Semantic LLM call failed: {exc}")
            return None

    def _get_decompiled_code(self, address: Optional[int]) -> Optional[str]:
        if not address or not self._context_service:
            return None
        for level in (ViewLevel.PSEUDO_C,):
            result = self._context_service.get_code_at_level(address, level, context_lines=0)
            if result.get("error"):
                continue
            lines = result.get("lines") or []
            parts: List[str] = []
            for line in lines:
                if isinstance(line, dict):
                    content = line.get("content")
                else:
                    content = str(line)
                if content:
                    parts.append(content.rstrip())
            if parts:
                return "\n".join(parts).strip()
        return None

    def _get_disassembly(self, address: Optional[int]) -> Optional[str]:
        if not address or not self._context_service:
            return None
        result = self._context_service.get_code_at_level(address, ViewLevel.ASM, context_lines=0)
        if result.get("error"):
            return None
        parts: List[str] = []
        for line in result.get("lines") or []:
            if isinstance(line, dict):
                content = line.get("content")
            else:
                content = str(line)
            if content:
                parts.append(content.rstrip())
        return "\n".join(parts).strip() if parts else None

    def _get_callers(self, node_id: Optional[int]) -> List[str]:
        if not node_id:
            return []
        callers = self.graph_store.get_callers(self.binary_hash, node_id, "calls")
        results = []
        for node in callers:
            results.append(node.name or f"sub_{node.address:x}")
            if len(results) >= 5:
                break
        return results

    def _get_callees(self, node_id: Optional[int]) -> List[str]:
        if not node_id:
            return []
        edges = self.graph_store.get_edges_for_node(self.binary_hash, node_id)
        results = []
        for edge in edges:
            if edge.source_id == node_id and edge.edge_type == "calls":
                node = self.graph_store.get_node_by_id(edge.target_id)
                if node:
                    results.append(node.name or f"sub_{node.address:x}")
            if len(results) >= 5:
                break
        return results
