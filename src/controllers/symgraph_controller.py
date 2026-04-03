#!/usr/bin/env python3
"""
SymGraph Controller for IDAssist.

This controller manages the SymGraph tab functionality including
querying, pushing, and pulling symbols and graph data.
"""

import asyncio
import json
import webbrowser
from typing import Dict, List, Optional, Any, Callable
from ..qt_compat import QMessageBox, QThread, Signal, QObject

from src.services.analysis_db_service import analysis_db_service
from src.services.graphrag.graph_store import GraphStore
from src.services.graphrag.models import GraphNode as LocalGraphNode, GraphEdge as LocalGraphEdge, NodeType, EdgeType

from src.services.symgraph_service import (
    symgraph_service, SymGraphServiceError, SymGraphAuthError,
    SymGraphNetworkError, SymGraphAPIError, is_default_name
)
from src.services.models.symgraph_models import (
    BinaryStats, Symbol, ConflictEntry, ConflictAction,
    QueryResult, PushResult, PullPreviewResult, PushScope
)
from src.views.symgraph_tab_view import SymGraphTabView

from src.ida_compat import log, get_binary_hash, execute_on_main_thread

# IDA imports
try:
    import idaapi
    import idautils
    import ida_funcs
    import ida_name
    import ida_nalt
    import ida_typeinf
    import idc
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


class AsyncWorker(QThread):
    """Generic async worker thread for running coroutines."""

    finished = Signal(object)  # result
    error = Signal(str)  # error message

    def __init__(self, coro_func: Callable, *args, **kwargs):
        super().__init__()
        self.coro_func = coro_func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        """Execute the coroutine in a new event loop."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(self.coro_func(*self.args, **self.kwargs))
                self.finished.emit(result)
            finally:
                loop.close()
        except Exception as e:
            log.log_error(f"AsyncWorker error: {e}")
            self.error.emit(str(e))


class QueryWorker(QThread):
    """Worker thread for querying SymGraph."""

    query_complete = Signal(object)  # QueryResult
    query_error = Signal(str)

    def __init__(self, sha256: str):
        super().__init__()
        self.sha256 = sha256

    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(
                    symgraph_service.query_binary(self.sha256, include_versions=True)
                )
                self.query_complete.emit(result)
            finally:
                loop.close()
        except Exception as e:
            log.log_error(f"Query error: {e}")
            self.query_error.emit(str(e))


class PushWorker(QThread):
    """Worker thread for pushing to SymGraph."""

    push_complete = Signal(object)  # PushResult
    push_error = Signal(str)

    def __init__(
        self,
        sha256: str,
        symbols: List[Dict],
        documents: Optional[List[Dict]] = None,
        graph_data: Optional[Dict] = None,
        visibility: str = "public",
        fingerprints: Optional[List[Dict[str, str]]] = None
    ):
        super().__init__()
        self.sha256 = sha256
        self.symbols = symbols
        self.documents = documents or []
        self.graph_data = graph_data
        self.visibility = visibility
        self.fingerprints = fingerprints or []  # List of {'type': str, 'value': str}

    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                total_result = PushResult(success=True)
                target_revision = None

                if self.symbols or self.graph_data:
                    target_revision = loop.run_until_complete(
                        symgraph_service.create_binary_revision(
                            self.sha256,
                            visibility=self.visibility
                        )
                    )
                    total_result.binary_revision = target_revision

                # Push symbols in chunks if provided
                if self.symbols:
                    result = loop.run_until_complete(
                        symgraph_service.push_symbols_chunked(
                            self.sha256,
                            self.symbols,
                            target_revision=target_revision
                        )
                    )
                    total_result.symbols_pushed = result.symbols_pushed
                    total_result.binary_revision = result.binary_revision or total_result.binary_revision

                # Push graph in chunks if provided
                if self.graph_data and total_result.success:
                    result = loop.run_until_complete(
                        symgraph_service.import_graph_chunked(
                            self.sha256,
                            self.graph_data,
                            target_revision=target_revision
                        )
                    )
                    total_result.nodes_pushed = result.nodes_pushed
                    total_result.edges_pushed = result.edges_pushed
                    total_result.binary_revision = result.binary_revision or total_result.binary_revision

                if self.documents and total_result.success:
                    result = loop.run_until_complete(
                        symgraph_service.push_documents_bulk(
                            self.sha256,
                            self.documents,
                            base_version=target_revision
                        )
                    )
                    total_result.documents_pushed = result.documents_pushed
                    total_result.document_results = list(result.document_results)

                # Add fingerprints (for BuildID/PDB GUID matching)
                if self.fingerprints and total_result.success:
                    for fp in self.fingerprints:
                        try:
                            loop.run_until_complete(
                                symgraph_service.add_fingerprint(
                                    self.sha256, fp['type'], fp['value']
                                )
                            )
                        except Exception as e:
                            log.log_warn(f"Failed to add fingerprint {fp['type']}: {e}")
                            # Non-fatal, continue

                self.push_complete.emit(total_result)
            finally:
                loop.close()
        except SymGraphAPIError as e:
            self.push_complete.emit(
                PushResult.failure_result(
                    str(e),
                    error_code=e.error_code,
                    requested_visibility=e.details.get('requested_visibility'),
                    suggested_visibility=e.details.get('suggested_visibility')
                )
            )
        except SymGraphAuthError as e:
            self.push_error.emit(f"Authentication required: {e}")
        except SymGraphNetworkError as e:
            self.push_error.emit(f"Network error: {e}")
        except Exception as e:
            log.log_error(f"Push error: {e}")
            self.push_error.emit(str(e))


class PullPreviewWorker(QThread):
    """Worker thread for pulling symbols from SymGraph and building conflicts."""

    progress = Signal(str)  # status message
    preview_complete = Signal(list, object, object, list)  # conflicts, graph_export, graph_stats, documents
    preview_error = Signal(str)

    def __init__(self, sha256: str, pull_config: dict = None):
        super().__init__()
        self.sha256 = sha256
        self.pull_config = pull_config or {
            'symbol_types': ['function'],
            'min_confidence': 0.0,
            'include_graph': False
        }
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            symbol_types = self.pull_config.get('symbol_types', ['function'])
            min_confidence = self.pull_config.get('min_confidence', 0.0)
            version = self.pull_config.get('version')
            name_filter = (self.pull_config.get('name_filter') or '').strip().lower()

            # Step 1: Fetch remote symbols from API for each selected type
            all_remote_symbols = []
            remote_documents = []
            include_graph = bool(self.pull_config.get('include_graph', False))
            graph_export = None
            graph_stats = None
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                for sym_type in symbol_types:
                    if self._cancelled:
                        return

                    self.progress.emit(f"Fetching {sym_type} symbols...")
                    remote_symbols = loop.run_until_complete(
                        symgraph_service.get_symbols(self.sha256, symbol_type=sym_type, version=version)
                    )
                    if name_filter:
                        remote_symbols = [
                            symbol for symbol in remote_symbols
                            if name_filter in (symbol.display_name or '').lower()
                        ]
                    # Handle None or empty results safely
                    if remote_symbols:
                        all_remote_symbols.extend(remote_symbols)
                        log.log_info(f"Fetched {len(remote_symbols)} {sym_type} symbols from API")
                    else:
                        log.log_info(f"No {sym_type} symbols returned from API")

                self.progress.emit("Fetching documents...")
                remote_documents = loop.run_until_complete(
                    symgraph_service.list_documents(self.sha256, version=version)
                )
                if name_filter:
                    remote_documents = [
                        document for document in remote_documents
                        if name_filter in (document.title or "").lower()
                    ]

                if include_graph:
                    try:
                        self.progress.emit("Fetching graph data...")
                        graph_export = loop.run_until_complete(
                            symgraph_service.export_graph(self.sha256, version=version)
                        )
                        if graph_export:
                            graph_stats = self._get_graph_stats(graph_export)
                            log.log_info(
                                f"Fetched graph data: {graph_stats.get('nodes', 0)} nodes, {graph_stats.get('edges', 0)} edges"
                            )
                    except Exception as e:
                        log.log_warn(f"Graph export failed: {e}")
            finally:
                loop.close()

            if self._cancelled:
                return

            log.log_info(f"Total fetched: {len(all_remote_symbols)} symbols from API")

            if not all_remote_symbols:
                document_payloads = [
                    {
                        'document_identity_id': document.document_identity_id,
                        'title': document.title,
                        'size_bytes': document.content_size_bytes,
                        'updated_at': document.created_at,
                        'version': document.version,
                        'doc_type': document.doc_type,
                    }
                    for document in remote_documents
                ]
                self.preview_complete.emit([], graph_export, graph_stats, document_payloads)
                return

            # Step 2: Get local symbols from IDA
            self.progress.emit("Collecting local symbols...")
            local_symbols = self._get_local_symbol_map()

            if self._cancelled:
                return

            log.log_info(f"Found {len(local_symbols)} local symbols")

            # Step 3: Build conflict entries with confidence filtering
            self.progress.emit("Building conflict list...")
            conflicts = symgraph_service.build_conflict_entries(
                local_symbols, all_remote_symbols, min_confidence
            )

            if self._cancelled:
                return

            log.log_info(f"Built {len(conflicts)} conflict entries")
            document_payloads = [
                {
                    'document_identity_id': document.document_identity_id,
                    'title': document.title,
                    'size_bytes': document.content_size_bytes,
                    'updated_at': document.created_at,
                    'version': document.version,
                    'doc_type': document.doc_type,
                }
                for document in remote_documents
            ]
            self.preview_complete.emit(conflicts, graph_export, graph_stats, document_payloads)

        except SymGraphAuthError as e:
            self.preview_error.emit(f"Authentication required: {e}")
        except SymGraphNetworkError as e:
            self.preview_error.emit(f"Network error: {e}")
        except Exception as e:
            log.log_error(f"Pull preview error: {e}")
            self.preview_error.emit(str(e))

    def _get_local_symbol_map(self) -> Dict[int, str]:
        """Get a map of address -> name for local function symbols using IDA API."""
        local_symbols = {}

        if not _IN_IDA:
            return local_symbols

        try:
            def _collect():
                try:
                    for func_ea in idautils.Functions():
                        name = ida_funcs.get_func_name(func_ea)
                        if name:
                            local_symbols[func_ea] = name
                except Exception as inner:
                    log.log_error(f"Error getting local symbols: {inner}")
                return 1

            execute_on_main_thread(_collect)
        except Exception as e:
            log.log_error(f"Error getting local symbols: {e}")

        return local_symbols

    @staticmethod
    def _get_graph_stats(graph_export) -> Dict[str, int]:
        metadata = graph_export.metadata or {}
        communities = metadata.get("community_count")
        if communities is None:
            communities = len(metadata.get("communities", [])) if isinstance(metadata.get("communities"), list) else 0
        return {
            "nodes": len(graph_export.nodes),
            "edges": len(graph_export.edges),
            "communities": communities,
        }


class ApplySymbolsWorker(QThread):
    """Worker thread for applying symbols to IDA Pro."""

    progress = Signal(int, int, str)  # current, total, message
    apply_complete = Signal(int, int)  # applied, errors
    apply_cancelled = Signal(int)  # applied so far
    apply_error = Signal(str)

    def __init__(self, symbols: List, graph_export=None, merge_policy: str = None, binary_hash: str = None):
        super().__init__()
        self.symbols = symbols
        self.graph_export = graph_export
        self.merge_policy = merge_policy
        self.binary_hash = binary_hash
        self._cancelled = False

    def cancel(self):
        """Request cancellation of the apply operation."""
        self._cancelled = True

    def run(self):
        try:
            # Calculate total work items (nodes + edges + symbols)
            num_nodes = len(self.graph_export.nodes) if self.graph_export else 0
            num_edges = len(self.graph_export.edges) if self.graph_export else 0
            num_symbols = len(self.symbols)
            total = num_nodes + num_edges + num_symbols

            progress_count = 0
            applied = 0
            errors = 0

            # Phase 1: Merge graph data (with progress)
            if self.graph_export and self.binary_hash:
                progress_count = self._merge_graph_data(progress_count, total, num_nodes, num_edges)
                if self._cancelled:
                    self.apply_cancelled.emit(applied)
                    return

            # Phase 2: Apply symbols (with progress)
            for i, symbol in enumerate(self.symbols):
                if self._cancelled:
                    self.apply_cancelled.emit(applied)
                    return

                # Handle both Symbol objects and ConflictEntry objects
                if hasattr(symbol, 'remote_symbol'):
                    # It's a ConflictEntry
                    addr = symbol.address
                    remote_sym = symbol.remote_symbol
                    name = remote_sym.name if remote_sym else None
                    symbol_type = getattr(remote_sym, 'symbol_type', 'function') if remote_sym else 'function'
                    metadata = getattr(remote_sym, 'metadata', {}) if remote_sym else {}
                else:
                    # It's a Symbol object
                    addr = symbol.address
                    name = symbol.name
                    symbol_type = getattr(symbol, 'symbol_type', 'function')
                    metadata = getattr(symbol, 'metadata', {})

                if name:
                    try:
                        if symbol_type == 'variable':
                            # Variable application for IDA
                            symbol_data = {
                                'name': name,
                                'metadata': metadata
                            }
                            if self._apply_variable(addr, symbol_data):
                                applied += 1
                        else:
                            # Function/symbol application for IDA
                            self._apply_symbol(addr, name)
                            applied += 1
                    except Exception as e:
                        log.log_error(f"Error applying symbol at 0x{addr:x}: {e}")
                        errors += 1

                progress_count += 1
                self.progress.emit(progress_count, total,
                    f"Applying symbol {i + 1}/{num_symbols}...")

            self.apply_complete.emit(applied, errors)

        except Exception as e:
            log.log_error(f"Apply symbols error: {e}")
            self.apply_error.emit(str(e))

    def _apply_symbol(self, addr: int, name: str):
        """Apply a single symbol to IDA Pro using main thread execution."""
        def _do():
            ida_name.set_name(addr, name, ida_name.SN_CHECK)
        execute_on_main_thread(_do)
        log.log_debug(f"Renamed symbol at 0x{addr:x} to {name}")

    def _apply_variable(self, func_addr: int, symbol_data: dict) -> bool:
        """Apply a variable symbol to IDA Pro.

        Note: IDA variable renaming is more limited than Binary Ninja.
        We handle stack variables and register variables where possible.
        """
        if not _IN_IDA:
            return False

        target_name = symbol_data.get('name')
        metadata = symbol_data.get('metadata', {})
        storage_class = metadata.get('storage_class')

        if not target_name or not storage_class:
            return False

        try:
            func = ida_funcs.get_func(func_addr)
            if not func:
                return False

            if storage_class == 'stack':
                stack_offset = metadata.get('stack_offset')
                if stack_offset is not None:
                    def _do():
                        idc.set_member_name(
                            idc.get_frame_id(func_addr),
                            stack_offset,
                            target_name
                        )
                    execute_on_main_thread(_do)
                    log.log_debug(f"Renamed stack var at offset {stack_offset} to {target_name}")
                    return True

            elif storage_class == 'parameter':
                # Parameters in IDA are typically stack or register based
                param_idx = metadata.get('parameter_index')
                if param_idx is not None:
                    # Try to rename via Hex-Rays if available
                    try:
                        import ida_hexrays
                        cfunc = ida_hexrays.decompile(func_addr)
                        if cfunc and param_idx < len(cfunc.arguments):
                            lvar = cfunc.arguments[param_idx]
                            def _do():
                                lvar.name = target_name
                                cfunc.save_user_lvar_settings()
                            execute_on_main_thread(_do)
                            log.log_debug(f"Renamed parameter {param_idx} to {target_name}")
                            return True
                    except Exception:
                        pass

        except Exception as e:
            log.log_error(f"Error applying variable: {e}")

        return False

    def _merge_graph_data(self, progress_count: int, total: int, num_nodes: int, num_edges: int) -> int:
        """Merge graph data with progress updates.

        Returns the updated progress count after processing nodes and edges.
        """
        if not self.graph_export or not self.binary_hash:
            return progress_count

        graph_store = GraphStore(analysis_db_service)
        merge_policy = self.merge_policy or "upsert"

        if merge_policy == "replace":
            graph_store.delete_graph(self.binary_hash)
            graph_store.delete_communities(self.binary_hash)

        address_to_id: Dict[int, str] = {}
        endpoint_to_id: Dict[tuple, str] = {}
        name_to_id: Dict[str, str] = {}
        for i, node in enumerate(self.graph_export.nodes):
            if self._cancelled:
                return progress_count

            node_type_str = (node.node_type or "FUNCTION").upper()
            node_type = NodeType.from_string(node_type_str) or NodeType.FUNCTION
            existing = graph_store.get_node_by_address(self.binary_hash, node_type.value, node.address)

            if merge_policy == "prefer_local" and existing:
                address_to_id[node.address] = existing.id
                endpoint_to_id[self._graph_endpoint_key(node.address, node.name)] = existing.id
                if node.name:
                    name_to_id[node.name] = existing.id
            else:
                props = node.properties or {}
                node_id = existing.id if existing else node.id

                local_node = LocalGraphNode(
                    id=node_id,
                    binary_hash=self.binary_hash,
                    node_type=node_type,
                    address=node.address,
                    name=node.name,
                    signature=props.get("signature"),
                    decompiled_code=props.get("decompiled_code") or props.get("raw_code") or props.get("raw_content"),
                    disassembly=props.get("disassembly"),
                    raw_code=props.get("decompiled_code") or props.get("raw_code") or props.get("raw_content"),
                    llm_summary=node.summary or props.get("llm_summary"),
                    confidence=float(props.get("confidence", 0.0) or 0.0),
                    security_flags=self._coerce_list(props.get("security_flags")),
                    network_apis=self._coerce_list(props.get("network_apis")),
                    file_io_apis=self._coerce_list(props.get("file_io_apis")),
                    ip_addresses=self._coerce_list(props.get("ip_addresses")),
                    urls=self._coerce_list(props.get("urls")),
                    file_paths=self._coerce_list(props.get("file_paths")),
                    domains=self._coerce_list(props.get("domains")),
                    registry_keys=self._coerce_list(props.get("registry_keys")),
                    category=props.get("category"),
                    risk_level=props.get("risk_level"),
                    activity_profile=props.get("activity_profile"),
                    analysis_depth=int(props.get("analysis_depth", 0) or 0),
                    is_stale=bool(props.get("is_stale", False)),
                    user_edited=bool(props.get("user_edited", False))
                )
                graph_store.upsert_node(local_node)
                address_to_id[node.address] = local_node.id
                endpoint_to_id[self._graph_endpoint_key(node.address, node.name)] = local_node.id
                if node.name:
                    name_to_id[node.name] = local_node.id

            progress_count += 1
            self.progress.emit(progress_count, total,
                f"Merging node {i + 1}/{num_nodes}...")

        for i, edge in enumerate(self.graph_export.edges):
            if self._cancelled:
                return progress_count

            source_id = endpoint_to_id.get(self._graph_endpoint_key(edge.source_address, edge.source_name))
            if not source_id:
                source_id = address_to_id.get(edge.source_address)
            if not source_id and edge.source_address == 0 and edge.source_name:
                source_id = name_to_id.get(edge.source_name)

            target_id = endpoint_to_id.get(self._graph_endpoint_key(edge.target_address, edge.target_name))
            if not target_id:
                target_id = address_to_id.get(edge.target_address)
            if not target_id and edge.target_address == 0 and edge.target_name:
                target_id = name_to_id.get(edge.target_name)
            if not source_id or not target_id:
                progress_count += 1
                self.progress.emit(progress_count, total,
                    f"Merging edge {i + 1}/{num_edges}...")
                continue

            edge_type = EdgeType.from_string(edge.edge_type) or EdgeType.CALLS
            metadata = edge.properties or {}
            weight = float(metadata.get("weight", 1.0) or 1.0)
            metadata_json = json.dumps(metadata) if metadata else None

            graph_store.add_edge(LocalGraphEdge(
                binary_hash=self.binary_hash,
                source_id=source_id,
                target_id=target_id,
                edge_type=edge_type,
                weight=weight,
                metadata=metadata_json
            ))

            progress_count += 1
            self.progress.emit(progress_count, total,
                f"Merging edge {i + 1}/{num_edges}...")

        return progress_count

    @staticmethod
    def _coerce_list(value):
        return value if isinstance(value, list) else []

    @staticmethod
    def _graph_endpoint_key(address: Optional[int], name: Optional[str]) -> tuple:
        return (int(address or 0), name or None)


class SymGraphController(QObject):
    """Controller for the SymGraph tab functionality."""

    def __init__(self, view: SymGraphTabView, data=None, query_controller=None):
        super().__init__()
        self.view = view
        self.data = data       # IDAssist data object
        self.query_controller = query_controller

        # Worker threads
        self.query_worker = None
        self.push_worker = None
        self.pull_worker = None
        self.apply_worker = None
        self.document_apply_worker = None

        self._graph_export = None
        self._graph_stats = None
        self._pending_push_request = None
        self._push_preview_symbols: List[Dict[str, Any]] = []
        self._push_preview_documents: List[Dict[str, Any]] = []
        self._push_preview_graph_data: Optional[Dict[str, Any]] = None
        self._push_preview_graph_stats: Dict[str, int] = {}
        self._pending_push_documents: List[Dict[str, Any]] = []
        self._pending_apply_documents: List[Dict[str, Any]] = []
        self._pending_apply_summary: Dict[str, int] = {}

        # Connect view signals
        self._connect_signals()

        # Update binary info if available
        self._update_binary_info()

    def _connect_signals(self):
        """Connect view signals to controller methods."""
        self.view.query_requested.connect(self.handle_query)
        self.view.open_binary_requested.connect(self.handle_open_binary)
        self.view.push_preview_requested.connect(self.handle_push_preview)
        self.view.push_execute_requested.connect(self.handle_push)
        self.view.pull_preview_requested.connect(self.handle_pull_preview)
        self.view.apply_selected_requested.connect(self.handle_apply_selected)
        self.view.apply_all_new_requested.connect(self.handle_apply_all_new)

    def initialize_binary(self):
        """Initialize binary context (called when binary is loaded in IDA)"""
        self._update_binary_info()

    def _update_binary_info(self):
        """Update binary info display from current IDA database."""
        if _IN_IDA:
            try:
                name = ida_nalt.get_root_filename() or "Unknown"
                sha256 = self._get_sha256()
                local_metadata: Dict[str, Any] = {}
                try:
                    local_metadata['functions'] = len(list(idautils.Functions()))
                except Exception:
                    pass
                try:
                    if sha256:
                        graph_stats = GraphStore().get_graph_stats(sha256)
                        if graph_stats.get('node_count') is not None:
                            local_metadata['graph_nodes'] = graph_stats.get('node_count')
                        elif graph_stats.get('nodes') is not None:
                            local_metadata['graph_nodes'] = graph_stats.get('nodes')
                        if graph_stats.get('edge_count') is not None:
                            local_metadata['graph_edges'] = graph_stats.get('edge_count')
                        elif graph_stats.get('edges') is not None:
                            local_metadata['graph_edges'] = graph_stats.get('edges')
                except Exception:
                    pass
                self.view.set_binary_info(name, sha256, local_metadata=local_metadata or None)
            except Exception as e:
                log.log_error(f"Error getting binary info: {e}")
                self.view.set_binary_info("<error>", None, local_metadata=None)
        else:
            self.view.set_binary_info("<no binary loaded>", None, local_metadata=None)

    def _get_symbol_provenance(self, is_auto: bool, address: int, symbol_type: str) -> str:
        """Determine symbol provenance: decompiler, llm, or user."""
        if is_auto:
            return 'decompiler'
        try:
            from src.services.analysis_db_service import AnalysisDBService
            binary_hash = self._get_sha256()
            if binary_hash:
                db = AnalysisDBService()
                if db.is_llm_renamed(binary_hash, address, symbol_type):
                    return 'llm'
        except Exception:
            pass
        return 'user'

    def _get_sha256(self) -> Optional[str]:
        """Get SHA256 hash of the original binary."""
        return get_binary_hash() or None

    def handle_query(self):
        """Handle query request."""
        sha256 = self._get_sha256()
        if not sha256:
            self._show_error("No Binary", "No binary loaded or unable to compute hash.")
            return

        log.log_info(f"Querying SymGraph for: {sha256}")
        self.view.set_query_status("Checking...")
        self.view.hide_stats()
        self.view.set_open_binary_url(None)
        self.view.set_buttons_enabled(False)

        # Start query worker
        self.query_worker = QueryWorker(sha256)
        self.query_worker.query_complete.connect(self._on_query_complete)
        self.query_worker.query_error.connect(self._on_query_error)
        self.query_worker.finished.connect(lambda: self.view.set_buttons_enabled(True))
        self.query_worker.start()

    def _on_query_complete(self, result: QueryResult):
        """Handle query completion."""
        self.view.set_buttons_enabled(True)

        if result.error:
            self.view.set_query_status(f"Error: {result.error}", found=False)
            self.view.set_open_binary_url(None)
            return

        if result.exists:
            self.view.set_query_status("Found in SymGraph", found=True)
            self.view.set_open_binary_url(symgraph_service.get_binary_url(self._get_sha256()))
            if result.stats:
                self.view.set_stats(
                    symbols=result.stats.symbol_count,
                    functions=result.stats.function_count,
                    nodes=result.stats.graph_node_count,
                    last_updated=result.stats.last_queried_at,
                    revisions=result.revisions,
                    latest_revision=result.latest_revision,
                    selected_revision=result.selected_revision
                )
        else:
            self.view.set_query_status("Not found in SymGraph", found=False)
            self.view.set_open_binary_url(None)
            self.view.hide_stats()

    def _on_query_error(self, error_msg: str):
        """Handle query error."""
        self.view.set_buttons_enabled(True)
        self.view.set_query_status(f"Error: {error_msg}", found=False)
        self.view.set_open_binary_url(None)
        log.log_error(f"Query error: {error_msg}")

    def handle_open_binary(self):
        """Open the current binary in the SymGraph web UI."""
        url = self.view.get_open_binary_url()
        if url:
            webbrowser.open(url)

    def handle_push_preview(self):
        """Build a filtered local preview for pushing to SymGraph."""
        sha256 = self._get_sha256()
        if not sha256:
            self._show_error("No Binary", "No binary loaded or unable to compute hash.")
            return

        push_config = self.view.get_push_config()
        scope = push_config.get('scope', PushScope.CURRENT_FUNCTION.value)
        symbol_types = push_config.get('symbol_types', [])
        name_filter = (push_config.get('name_filter') or '').strip().lower()
        push_graph = bool(push_config.get('push_graph'))

        symbols_data = self._collect_local_symbols(scope)
        if not symbol_types:
            symbols_data = []
        else:
            symbols_data = [
                symbol for symbol in symbols_data
                if self._matches_push_type_filter(symbol, symbol_types)
            ]
        if name_filter:
            symbols_data = [
                symbol for symbol in symbols_data
                if name_filter in (symbol.get('name') or symbol.get('content') or '').lower()
            ]

        graph_data = self._collect_local_graph(scope) if push_graph else None
        graph_stats = {
            'nodes': len(graph_data.get('nodes', [])) if graph_data else 0,
            'edges': len(graph_data.get('edges', [])) if graph_data else 0,
        }
        documents = self.query_controller.list_document_push_candidates() if self.query_controller else []

        self._push_preview_symbols = symbols_data
        self._push_preview_documents = documents
        self._push_preview_graph_data = graph_data
        self._push_preview_graph_stats = graph_stats
        self.view.set_push_preview(
            symbols_data,
            graph_data=graph_data,
            graph_stats=graph_stats,
            documents=documents,
        )

        summary_parts = [f"{len(symbols_data)} symbols ready"]
        if documents:
            summary_parts.append(f"{len(documents)} documents")
        if graph_data:
            summary_parts.append(f"{graph_stats['nodes']} nodes")
            summary_parts.append(f"{graph_stats['edges']} edges")
        self.view.set_push_status("Preview ready: " + ", ".join(summary_parts), success=True)

    def handle_push(
        self,
        scope: Optional[str] = None,
        push_symbols: Optional[bool] = None,
        push_graph: Optional[bool] = None,
        visibility: Optional[str] = None
    ):
        """Execute the selected push preview."""
        sha256 = self._get_sha256()
        if not sha256:
            self._show_error("No Binary", "No binary loaded or unable to compute hash.")
            return

        if not symgraph_service.has_api_key:
            self._show_error("API Key Required",
                "Push requires a SymGraph API key.\n\n"
                "Add your API key in Settings > SymGraph")
            return

        push_config = self.view.get_push_config()
        scope = scope or push_config.get('scope', PushScope.CURRENT_FUNCTION.value)
        visibility = visibility or push_config.get('visibility', 'public')
        selected_symbols = self.view.get_selected_push_symbols()
        selected_documents = self.view.get_selected_push_documents()
        document_payloads = []
        for document in selected_documents:
            payload = {
                'title': document['title'],
                'doc_type': document.get('doc_type') or 'notes',
                'content': document['content'],
            }
            if document.get('document_identity_id'):
                payload['document_identity_id'] = document['document_identity_id']
            document_payloads.append(payload)
        use_graph = push_graph if push_graph is not None else bool(push_config.get('push_graph'))
        graph_data = self._push_preview_graph_data if use_graph else None

        if not selected_symbols and not selected_documents and not graph_data:
            self.view.set_push_status("Preview the push and select at least one row first", success=False)
            return

        log.log_info(
            f"Pushing to SymGraph: scope={scope}, symbols={len(selected_symbols)}, "
            f"documents={len(selected_documents)}, graph={graph_data is not None}, visibility={visibility}"
        )
        self.view.show_push_progress("Creating revision...")
        self.view.set_push_status("Pushing...", success=None)
        self.view.set_buttons_enabled(False)
        self.view.update_push_progress(5, 100, "Preparing selected items...")

        # Collect fingerprints for matching (BuildID for ELF, PDB GUID for PE)
        fingerprints = self._collect_fingerprints()
        self._pending_push_request = {
            'scope': scope,
            'push_symbols': bool(selected_symbols),
            'push_graph': graph_data is not None,
            'visibility': visibility
        }
        self._pending_push_documents = list(selected_documents)

        # Start push worker
        self.push_worker = PushWorker(
            sha256,
            selected_symbols,
            document_payloads,
            graph_data,
            visibility=visibility,
            fingerprints=fingerprints
        )
        self.push_worker.push_complete.connect(self._on_push_complete)
        self.push_worker.push_error.connect(self._on_push_error)
        self.push_worker.finished.connect(lambda: self.view.set_buttons_enabled(True))
        self.push_worker.start()

    def _on_push_complete(self, result: PushResult):
        """Handle push completion."""
        self.view.set_buttons_enabled(True)
        self.view.hide_push_progress()

        if result.success:
            msg_parts = []
            if result.symbols_pushed > 0:
                msg_parts.append(f"{result.symbols_pushed} symbols")
            if result.nodes_pushed > 0:
                msg_parts.append(f"{result.nodes_pushed} nodes")
            if result.edges_pushed > 0:
                msg_parts.append(f"{result.edges_pushed} edges")
            if result.documents_pushed > 0:
                msg_parts.append(f"{result.documents_pushed} documents")

            if self.query_controller and self._pending_push_documents and result.document_results:
                for document_request, result_item in zip(self._pending_push_documents, result.document_results):
                    document_identity_id = result_item.get('document_identity_id')
                    if not document_identity_id:
                        continue
                    self.query_controller.update_document_sync_metadata(
                        document_request.get('chat_id'),
                        document_identity_id=document_identity_id,
                        version=result_item.get('version'),
                        doc_type=document_request.get('doc_type'),
                    )

            msg = "Pushed: " + ", ".join(msg_parts) if msg_parts else "Push complete"
            if result.binary_revision:
                msg += f" to v{result.binary_revision}"
            self.view.set_push_status(msg, success=True)
        else:
            if (
                result.error_code == "visibility_quota_exceeded"
                and result.requested_visibility
                and result.requested_visibility != "public"
            ):
                self._handle_visibility_denial(result)
                return
            self.view.set_push_status(f"Failed: {result.error or 'Unknown error'}", success=False)
        self._pending_push_documents = []

    def _on_push_error(self, error_msg: str):
        """Handle push error."""
        self.view.set_buttons_enabled(True)
        self.view.hide_push_progress()
        self.view.set_push_status(f"Error: {error_msg}", success=False)
        self._pending_push_documents = []
        log.log_error(f"Push error: {error_msg}")

    def _handle_visibility_denial(self, result: PushResult):
        """Offer a retry as public when a private push is denied by tier limits."""
        self.view.set_buttons_enabled(True)

        suggested_visibility = result.suggested_visibility or "public"
        message = (
            f"{result.error or 'This visibility is not available for your account.'}\n\n"
            f"Retry this push as {suggested_visibility}?"
        )
        reply = QMessageBox.question(
            self.view,
            "Visibility Not Available",
            message,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )
        if reply == QMessageBox.Yes and self._pending_push_request:
            request = dict(self._pending_push_request)
            request['visibility'] = suggested_visibility
            self.handle_push(**request)
            return

        self.view.set_push_status(f"Failed: {result.error or 'Visibility denied'}", success=False)

    @staticmethod
    def _matches_push_type_filter(symbol: Dict[str, Any], selected_types: List[str]) -> bool:
        symbol_type = str(symbol.get('symbol_type') or '').lower()
        if symbol_type in selected_types:
            return True
        return symbol_type in ('type', 'enum', 'struct') and 'type' in selected_types

    def handle_pull_preview(self):
        """Handle pull preview request."""
        sha256 = self._get_sha256()
        if not sha256:
            self._show_error("No Binary", "No binary loaded or unable to compute hash.")
            return

        if not _IN_IDA:
            self._show_error("No Binary", "No IDA database available.")
            return

        if not symgraph_service.has_api_key:
            self._show_error("API Key Required",
                "Pull requires a SymGraph API key.\n\n"
                "Add your API key in Settings > SymGraph")
            return

        # If worker is running, cancel it
        if self.pull_worker and self.pull_worker.isRunning():
            self.pull_worker.cancel()
            self.view.set_pull_status("Stopping...", success=None)
            return

        # Get pull configuration from view
        pull_config = self.view.get_pull_config()
        symbol_types = pull_config.get('symbol_types', [])

        log.log_info(f"Fetching symbols from SymGraph: {sha256} (types: {symbol_types})")
        self._graph_export = None
        self._graph_stats = None
        self.view.clear_graph_preview_data()
        self.view.set_pull_status("Fetching...", success=None)
        self.view.clear_conflicts()
        self.view.set_buttons_enabled(False)
        self.view.set_pull_button_text("Stop")

        # Start pull preview worker (no binary view needed for IDA)
        self.pull_worker = PullPreviewWorker(sha256, pull_config)
        self.pull_worker.progress.connect(self._on_pull_preview_progress)
        self.pull_worker.preview_complete.connect(self._on_pull_preview_complete)
        self.pull_worker.preview_error.connect(self._on_pull_preview_error)
        self.pull_worker.finished.connect(self._on_pull_preview_finished)
        self.pull_worker.start()

    def _on_pull_preview_progress(self, status: str):
        """Handle pull preview progress update."""
        self.view.set_pull_status(status, success=None)

    def _on_pull_preview_complete(
        self,
        conflicts: List[ConflictEntry],
        graph_export=None,
        graph_stats=None,
        documents: Optional[List[Dict[str, Any]]] = None,
    ):
        """Handle pull preview completion."""
        if graph_export is not None and not graph_stats:
            graph_stats = PullPreviewWorker._get_graph_stats(graph_export)
        self._graph_export = graph_export
        self._graph_stats = graph_stats
        self.view.set_graph_preview_data(graph_export, graph_stats)
        self.view.populate_fetch_documents(documents or [])

        if not conflicts and not graph_export and not documents:
            self.view.set_pull_status("No symbols found", success=False)
            return

        # Populate the conflict resolution table
        self.view.populate_conflicts(conflicts)

        # Calculate counts for status message
        conflict_count = sum(1 for c in conflicts if c.action == ConflictAction.CONFLICT)
        new_count = sum(1 for c in conflicts if c.action == ConflictAction.NEW)
        same_count = sum(1 for c in conflicts if c.action == ConflictAction.SAME)

        status_msg = f"Found {len(conflicts)} symbols ({conflict_count} conflicts, {new_count} new, {same_count} same)"
        if documents:
            status_msg += f" | Documents: {len(documents)}"
        if graph_stats:
            status_msg += (
                f" | Graph: {graph_stats.get('nodes', 0)} nodes, "
                f"{graph_stats.get('edges', 0)} edges, {graph_stats.get('communities', 0)} communities"
            )

        if not conflicts and graph_export:
            status_msg = "No symbols found (graph data available)"
            if documents:
                status_msg += f" | Documents: {len(documents)}"
        elif not conflicts and documents:
            status_msg = f"No symbols found | Documents: {len(documents)}"

        self.view.set_pull_status(status_msg, success=True)

    def _on_pull_preview_finished(self):
        """Handle pull preview worker finished (cleanup)."""
        self.view.set_buttons_enabled(True)
        self.view.set_pull_button_text("Preview Fetch")

    def _on_pull_preview_error(self, error_msg: str):
        """Handle pull preview error."""
        self._graph_export = None
        self._graph_stats = None
        self.view.populate_fetch_documents([])
        self.view.clear_graph_preview_data()
        self.view.set_buttons_enabled(True)
        self.view.set_pull_status(f"Error: {error_msg}", success=False)
        log.log_error(f"Pull preview error: {error_msg}")

    def handle_apply_selected(self, addresses: List[int]):
        """Handle applying selected symbols."""
        selected_documents = self.view.get_selected_fetch_documents()

        # If worker is running, cancel it (check first to allow Stop button)
        if self.apply_worker and self.apply_worker.isRunning():
            self.apply_worker.cancel()
            self.view.set_pull_status("Stopping...", success=None)
            return

        if not addresses and not self._graph_export and not selected_documents:
            self.view.set_pull_status("No items selected", success=False)
            return

        if not _IN_IDA:
            self._show_error("No Binary", "No IDA database loaded.")
            return

        # Get the selected items (Symbol or ConflictEntry objects)
        selected_items = self.view.get_selected_conflicts()
        if not selected_items and not self._graph_export and not selected_documents:
            self.view.set_pull_status("No items selected", success=False)
            return

        if not selected_items and not self._graph_export and selected_documents:
            self._pending_apply_documents = list(selected_documents)
            self._pending_apply_summary = {'applied': 0, 'errors': 0}
            self._start_document_apply()
            return

        log.log_info(f"Applying {len(selected_items)} selected symbols in background")
        self.view.set_pull_status(f"Applying 0/{len(selected_items)}...", success=None)
        self.view.set_buttons_enabled(False)
        self.view.set_apply_button_text("Stop")
        self._pending_apply_documents = list(selected_documents)
        self._pending_apply_summary = {}

        # Start apply worker
        merge_policy = self.view.get_graph_merge_policy() if self._graph_export else "upsert"
        binary_hash = self._get_sha256() or ""
        self.apply_worker = ApplySymbolsWorker(
            selected_items,
            graph_export=self._graph_export,
            merge_policy=merge_policy,
            binary_hash=binary_hash
        )
        self.apply_worker.progress.connect(self._on_apply_progress)
        self.apply_worker.apply_complete.connect(self._on_apply_complete)
        self.apply_worker.apply_cancelled.connect(self._on_apply_cancelled)
        self.apply_worker.apply_error.connect(self._on_apply_error)
        self.apply_worker.finished.connect(self._on_apply_finished)
        self.apply_worker.start()

    def handle_apply_all_new(self):
        """Handle applying all NEW symbols (wizard shortcut)."""
        if not _IN_IDA:
            self._show_error("No Binary", "No IDA database loaded.")
            return

        # Get all NEW conflict entries
        new_items = self.view.get_all_new_conflicts()
        if not new_items and not self._graph_export:
            self.view.set_pull_status("No new items to apply", success=False)
            return

        log.log_info(f"Applying all {len(new_items)} new symbols")
        apply_message = f"Applying {len(new_items)} new symbols..."
        if not new_items and self._graph_export:
            apply_message = "Applying graph data..."
        self.view.show_applying_page(apply_message)
        self.view.set_buttons_enabled(False)

        # Start apply worker
        merge_policy = self.view.get_graph_merge_policy() if self._graph_export else "upsert"
        binary_hash = self._get_sha256() or ""
        self.apply_worker = ApplySymbolsWorker(
            new_items,
            graph_export=self._graph_export,
            merge_policy=merge_policy,
            binary_hash=binary_hash
        )
        self.apply_worker.progress.connect(self._on_wizard_apply_progress)
        self.apply_worker.apply_complete.connect(self._on_wizard_apply_complete)
        self.apply_worker.apply_cancelled.connect(self._on_wizard_apply_cancelled)
        self.apply_worker.apply_error.connect(self._on_apply_error)
        self.apply_worker.finished.connect(self._on_apply_finished)
        self.apply_worker.start()

    def _on_wizard_apply_progress(self, current: int, total: int, message: str):
        """Handle apply progress update for wizard mode."""
        self.view.update_apply_progress(current, total, message)

    def _on_wizard_apply_complete(self, applied: int, errors: int):
        """Handle apply completion for wizard mode."""
        self.view.show_complete_page(applied, errors)
        log.log_info(f"Applied {applied} symbols, {errors} errors")

    def _on_wizard_apply_cancelled(self, applied: int):
        """Handle apply cancellation for wizard mode."""
        self.view.show_complete_page(applied, 0)
        log.log_info(f"Apply cancelled after {applied} symbols")

    def _on_apply_progress(self, current: int, total: int, message: str):
        """Handle apply progress update."""
        self.view.set_pull_status(message, success=None)

    def _on_apply_complete(self, applied: int, errors: int):
        """Handle apply completion."""
        self._pending_apply_summary = {'applied': applied, 'errors': errors}
        if self._pending_apply_documents:
            self.view.set_pull_status("Applying documents...", success=None)
            self._start_document_apply()
            return
        if errors > 0:
            self.view.set_pull_status(f"Applied {applied} symbols ({errors} errors)", success=True)
        else:
            self.view.set_pull_status(f"Applied {applied} symbols", success=True)
        log.log_info(f"Applied {applied} symbols, {errors} errors")

    def _on_apply_cancelled(self, applied: int):
        """Handle apply cancellation."""
        self._pending_apply_documents = []
        self.view.set_pull_status(f"Stopped ({applied} symbols applied)", success=None)
        log.log_info(f"Apply cancelled after {applied} symbols")

    def _on_apply_error(self, error_msg: str):
        """Handle apply error."""
        self._pending_apply_documents = []
        self.view.set_pull_status(f"Error: {error_msg}", success=False)
        log.log_error(f"Apply error: {error_msg}")

    def _on_apply_finished(self):
        """Handle worker finished (cleanup)."""
        if self.document_apply_worker and self.document_apply_worker.isRunning():
            return
        self.view.set_buttons_enabled(True)
        self.view.set_apply_button_text("Apply Selected")

    def _start_document_apply(self):
        sha256 = self._get_sha256()
        if not sha256:
            self.view.set_pull_status("Unable to resolve binary hash for document import", success=False)
            return

        documents = list(self._pending_apply_documents)
        if not documents:
            summary = self._pending_apply_summary or {'applied': 0, 'errors': 0}
            if summary['errors'] > 0:
                self.view.set_pull_status(
                    f"Applied {summary['applied']} symbols ({summary['errors']} errors)",
                    success=True,
                )
            else:
                self.view.set_pull_status(f"Applied {summary['applied']} symbols", success=True)
            self.view.set_buttons_enabled(True)
            self.view.set_apply_button_text("Apply Selected")
            return

        self.view.set_buttons_enabled(False)
        self.view.set_apply_button_text("Apply Selected")
        self.document_apply_worker = AsyncWorker(self._fetch_documents_for_apply, sha256, documents)
        self.document_apply_worker.finished.connect(self._on_document_apply_complete)
        self.document_apply_worker.error.connect(self._on_document_apply_error)
        self.document_apply_worker.start()

    async def _fetch_documents_for_apply(self, sha256: str, documents: List[Dict[str, Any]]):
        fetched = []
        for document in documents:
            fetched_document = await symgraph_service.get_document(
                sha256,
                document['document_identity_id'],
                version=document.get('version'),
            )
            if fetched_document is not None:
                fetched.append(fetched_document)
        return fetched

    def _on_document_apply_complete(self, documents):
        imported = 0
        if self.query_controller:
            for document in documents or []:
                self.query_controller.upsert_symgraph_document_chat(document)
                imported += 1

        summary = self._pending_apply_summary or {'applied': 0, 'errors': 0}
        parts = []
        if summary.get('applied', 0) > 0:
            if summary.get('errors', 0) > 0:
                parts.append(f"{summary['applied']} symbols ({summary['errors']} errors)")
            else:
                parts.append(f"{summary['applied']} symbols")
        if imported > 0:
            parts.append(f"{imported} documents")
        self.view.set_pull_status(
            "Applied " + ", ".join(parts) if parts else "Applied documents",
            success=True,
        )
        self._pending_apply_documents = []
        self._pending_apply_summary = {}
        self.view.set_buttons_enabled(True)
        self.view.set_apply_button_text("Apply Selected")

    def _on_document_apply_error(self, error_msg: str):
        self._pending_apply_documents = []
        self._pending_apply_summary = {}
        self.view.set_buttons_enabled(True)
        self.view.set_apply_button_text("Apply Selected")
        self.view.set_pull_status(f"Error importing documents: {error_msg}", success=False)

    # === Helper methods for data collection ===

    def _collect_fingerprints(self) -> List[Dict[str, str]]:
        """
        Collect fingerprints from the binary for debug symbol matching.

        Returns:
            List of fingerprint dicts with 'type' and 'value' keys.
            - For ELF: BuildID (build_id)
            - For PE: PDB GUID (pdb_guid)
        """
        fingerprints = []

        if not _IN_IDA:
            return fingerprints

        try:
            # IDA doesn't expose binary format as easily, but we can check sections
            # For now, return empty - fingerprint extraction can be enhanced later
            pass

        except Exception as e:
            log.log_warn(f"Error collecting fingerprints: {e}")

        return fingerprints

    def _collect_local_symbols(self, scope: str) -> List[Dict[str, Any]]:
        """Collect all symbol types from IDA based on scope."""
        symbols = []

        if not _IN_IDA:
            return symbols

        try:
            if scope == PushScope.CURRENT_FUNCTION.value:
                # Get current function
                import ida_kernwin
                ea = ida_kernwin.get_screen_ea()
                func = ida_funcs.get_func(ea)
                if func:
                    symbols.append(self._function_to_symbol_dict(func))
                    # Also collect comments within this function
                    symbols.extend(self._collect_function_comments(func))
            else:
                # Full binary - collect all functions
                for func_ea in idautils.Functions():
                    name = ida_funcs.get_func_name(func_ea)
                    if not self._is_auto_generated_name(name):
                        func = ida_funcs.get_func(func_ea)
                        if func:
                            symbols.append(self._function_to_symbol_dict(func))

                # Comments
                symbols.extend(self._collect_comments())

        except Exception as e:
            log.log_error(f"Error collecting symbols: {e}")

        return symbols

    def _function_to_symbol_dict(self, func) -> Dict[str, Any]:
        """Convert an IDA function to a symbol dictionary."""
        func_name = ida_funcs.get_func_name(func.start_ea)
        is_auto = self._is_auto_generated_name(func_name)

        # Get function type/signature if available
        data_type = None
        try:
            tinfo = ida_typeinf.tinfo_t()
            if ida_typeinf.guess_tinfo(tinfo, func.start_ea):
                data_type = str(tinfo)
        except Exception:
            pass

        # Classify thunk/library functions as external (same logic as _ida_function_to_node_dict)
        is_external = bool(func.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK))
        symbol_type = 'external' if is_external else 'function'

        return {
            'address': f"0x{func.start_ea:x}",
            'symbol_type': symbol_type,
            'name': func_name,
            'data_type': data_type,
            'confidence': 0.5 if is_auto else 0.9,
            'provenance': self._get_symbol_provenance(is_auto, func.start_ea, symbol_type)
        }

    def _is_auto_generated_name(self, name: str) -> bool:
        """Check if a name is auto-generated by IDA or other tools.

        Includes IDA patterns: sub_*, nullsub_*, j_*, loc_*, unk_*
        as well as patterns from other tools (Ghidra, Binary Ninja, radare2).
        """
        if not name:
            return True

        # Use the shared is_default_name from symgraph_service
        if is_default_name(name):
            return True

        # Additional IDA-specific patterns
        ida_auto_prefixes = (
            'sub_', 'nullsub_', 'j_', 'loc_', 'unk_',
            'byte_', 'word_', 'dword_', 'qword_',
            'off_', 'seg_', 'asc_', 'stru_', 'algn_',
            'flt_', 'dbl_', 'tbyte_', 'xmmword_',
        )
        name_lower = name.lower()
        for prefix in ida_auto_prefixes:
            if name_lower.startswith(prefix):
                return True

        return False

    def _collect_comments(self) -> List[Dict[str, Any]]:
        """Collect address-level comments from IDA."""
        symbols = []
        try:
            for func_ea in idautils.Functions():
                func = ida_funcs.get_func(func_ea)
                if not func:
                    continue

                # Function-level comment (repeatable comment)
                func_cmt = ida_funcs.get_func_cmt(func, True)  # True = repeatable
                if not func_cmt:
                    func_cmt = ida_funcs.get_func_cmt(func, False)  # False = regular

                if func_cmt:
                    symbols.append({
                        'address': f"0x{func_ea:x}",
                        'symbol_type': 'comment',
                        'name': None,
                        'content': func_cmt,
                        'confidence': 1.0,
                        'provenance': 'user',
                        'metadata': {'type': 'function'}
                    })

        except Exception as e:
            log.log_error(f"Error collecting comments: {e}")
        return symbols

    def _collect_function_comments(self, func) -> List[Dict[str, Any]]:
        """Collect comments within a specific function."""
        symbols = []
        try:
            # Function-level comment
            func_cmt = ida_funcs.get_func_cmt(func, True)
            if not func_cmt:
                func_cmt = ida_funcs.get_func_cmt(func, False)

            if func_cmt:
                symbols.append({
                    'address': f"0x{func.start_ea:x}",
                    'symbol_type': 'comment',
                    'name': None,
                    'content': func_cmt,
                    'confidence': 1.0,
                    'provenance': 'user',
                    'metadata': {'type': 'function'}
                })

        except Exception as e:
            log.log_error(f"Error collecting function comments: {e}")
        return symbols

    def _collect_local_graph(self, scope: str) -> Optional[Dict[str, Any]]:
        """Collect graph data from local graph store or fallback to IDA."""
        if not _IN_IDA:
            return None

        try:
            nodes = []
            edges = []

            # Get binary hash for graph store queries
            binary_hash = self._get_sha256()
            if not binary_hash:
                return self._collect_minimal_graph(scope)

            # Try to read from local graph store first
            graph_store = GraphStore(analysis_db_service)

            if scope == PushScope.CURRENT_FUNCTION.value:
                import ida_kernwin
                ea = ida_kernwin.get_screen_ea()
                func = ida_funcs.get_func(ea)
                if func:
                    local_node = graph_store.get_node_by_address(
                        binary_hash, "FUNCTION", func.start_ea
                    ) or graph_store.get_node_by_address(
                        binary_hash, "THUNK", func.start_ea
                    ) or graph_store.get_node_by_address(
                        binary_hash, "EXTERNAL", func.start_ea
                    )
                    if local_node:
                        nodes.append(self._local_node_to_push_dict(local_node))
                        graph_edges = graph_store.get_edges_for_node(binary_hash, local_node.id)
                        for edge in graph_edges:
                            edge_dict = self._local_edge_to_push_dict(edge, graph_store)
                            if edge_dict:
                                edges.append(edge_dict)
                    else:
                        nodes.append(self._ida_function_to_node_dict(func))
            else:
                # Full binary scope
                local_nodes = graph_store.get_nodes_by_type(binary_hash, "FUNCTION") or []
                local_nodes += graph_store.get_nodes_by_type(binary_hash, "EXTERNAL") or []
                local_nodes += graph_store.get_nodes_by_type(binary_hash, "THUNK") or []

                if local_nodes:
                    node_id_to_node = {}
                    for local_node in local_nodes:
                        nodes.append(self._local_node_to_push_dict(local_node))
                        node_id_to_node[local_node.id] = local_node

                    all_edges = graph_store.get_edges_by_types(
                        binary_hash,
                        ["calls", "calls_vulnerable", "network_send", "network_recv",
                         "taint_flows_to", "similar_purpose", "references"]
                    )
                    for edge in all_edges:
                        edge_dict = self._local_edge_to_push_dict(edge, graph_store, node_id_to_node)
                        if edge_dict:
                            edges.append(edge_dict)
                else:
                    # Fallback: create minimal graph from IDA
                    for func_ea in idautils.Functions():
                        func = ida_funcs.get_func(func_ea)
                        if func:
                            nodes.append(self._ida_function_to_node_dict(func))

            if nodes:
                return {'nodes': nodes, 'edges': edges}

        except Exception as e:
            log.log_error(f"Error collecting graph: {e}")

        return None

    def _collect_minimal_graph(self, scope: str) -> Optional[Dict[str, Any]]:
        """Fallback: Collect minimal graph data directly from IDA."""
        if not _IN_IDA:
            return None

        try:
            nodes = []
            edges = []

            if scope == PushScope.CURRENT_FUNCTION.value:
                import ida_kernwin
                ea = ida_kernwin.get_screen_ea()
                func = ida_funcs.get_func(ea)
                if func:
                    nodes.append(self._ida_function_to_node_dict(func))
            else:
                for func_ea in idautils.Functions():
                    func = ida_funcs.get_func(func_ea)
                    if func:
                        nodes.append(self._ida_function_to_node_dict(func))

            if nodes:
                return {'nodes': nodes, 'edges': edges}

        except Exception as e:
            log.log_error(f"Error collecting minimal graph: {e}")

        return None

    def _ida_function_to_node_dict(self, func) -> Dict[str, Any]:
        """Convert an IDA function to a minimal graph node dictionary."""
        func_name = ida_funcs.get_func_name(func.start_ea)
        flags = func.flags
        node_type = 'function'
        if flags & ida_funcs.FUNC_THUNK:
            node_type = 'thunk'
        elif flags & ida_funcs.FUNC_LIB:
            node_type = 'external'
        return {
            'address': f"0x{func.start_ea:x}",
            'node_type': node_type,
            'name': func_name,
            'signature': None,
            'decompiled_code': None,
            'disassembly': None,
            'raw_content': None,
            'llm_summary': None,
            'confidence': 0.0,
            'provenance': 'decompiler',
            'is_stale': True,
            'user_edited': False
        }

    def _local_node_to_push_dict(self, node: LocalGraphNode) -> Dict[str, Any]:
        """Convert a local GraphNode to push format with all rich metadata."""
        confidence = node.confidence or 0.0
        if node.llm_summary and confidence == 0.0:
            confidence = 0.95 if node.user_edited else 0.85
            log.log_debug(f"Fixed up confidence for {node.name}: {confidence}")

        result = {
            'address': f"0x{node.address:x}" if node.address else "0x0",
            'node_type': node.get_node_type_str().lower(),
            'name': node.name,
            'signature': node.signature,
            'decompiled_code': node.get_decompiled_code(),
            'disassembly': node.disassembly,
            'raw_content': node.get_decompiled_code(),
            'llm_summary': node.llm_summary,
            'confidence': confidence,
            'provenance': 'user' if node.user_edited else ('llm' if node.llm_summary else 'decompiler'),
        }

        if node.security_flags:
            result['security_flags'] = list(node.security_flags)
        if node.network_apis:
            result['network_apis'] = list(node.network_apis)
        if node.file_io_apis:
            result['file_io_apis'] = list(node.file_io_apis)
        if node.ip_addresses:
            result['ip_addresses'] = list(node.ip_addresses)
        if node.urls:
            result['urls'] = list(node.urls)
        if node.file_paths:
            result['file_paths'] = list(node.file_paths)
        if node.domains:
            result['domains'] = list(node.domains)
        if node.registry_keys:
            result['registry_keys'] = list(node.registry_keys)
        if node.category:
            result['category'] = node.category

        if node.risk_level:
            result['risk_level'] = node.risk_level
        if node.activity_profile:
            result['activity_profile'] = node.activity_profile
        if node.analysis_depth:
            result['analysis_depth'] = node.analysis_depth

        result['is_stale'] = node.is_stale
        result['user_edited'] = node.user_edited

        return result

    def _local_edge_to_push_dict(
        self,
        edge: LocalGraphEdge,
        graph_store: GraphStore,
        node_id_to_node: Optional[Dict[str, LocalGraphNode]] = None
    ) -> Optional[Dict[str, Any]]:
        """Convert a local GraphEdge to push format with weight."""
        source_node: Optional[LocalGraphNode] = None
        target_node: Optional[LocalGraphNode] = None

        if node_id_to_node:
            source_node = node_id_to_node.get(edge.source_id)
            target_node = node_id_to_node.get(edge.target_id)
        else:
            source_node = graph_store.get_node_by_id(edge.source_id)
            target_node = graph_store.get_node_by_id(edge.target_id)

        if not source_node or not target_node:
            return None

        return {
            'source_address': f"0x{(source_node.address or 0):x}",
            'target_address': f"0x{(target_node.address or 0):x}",
            'source_name': source_node.name,
            'target_name': target_node.name,
            'edge_type': edge.get_edge_type_str(),
            'weight': edge.weight or 1.0
        }

    def _get_current_function(self):
        """Get the current function from IDA."""
        if not _IN_IDA:
            return None
        try:
            import ida_kernwin
            ea = ida_kernwin.get_screen_ea()
            return ida_funcs.get_func(ea)
        except Exception:
            return None

    # === Utility methods ===

    def _show_error(self, title: str, message: str):
        """Show error message dialog."""
        QMessageBox.critical(self.view, title, message)

    def _show_info(self, title: str, message: str):
        """Show info message dialog."""
        QMessageBox.information(self.view, title, message)

    def _show_warning(self, title: str, message: str):
        """Show warning message dialog."""
        QMessageBox.warning(self.view, title, message)
