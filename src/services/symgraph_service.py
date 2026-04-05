#!/usr/bin/env python3
"""
SymGraph API Client Service for IDAssist.

This service provides a clean interface for SymGraph API integration,
following the IDAssist SOA architecture patterns.
"""

import asyncio
import re
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, urlunparse

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from .settings_service import settings_service
from .models.symgraph_models import (
    BinaryStats, BinaryRevision, Symbol, GraphNode, GraphEdge,
    SymbolExport, GraphExport, QueryResult, PushResult,
    DocumentSummary, Document,
    PullPreviewResult, ConflictEntry, ConflictAction
)

from src.ida_compat import log


# Unified default name patterns for cross-tool compatibility (Binary Ninja, Ghidra, IDA, radare2)
# Used to detect auto-generated symbol names that should be filtered during merge
DEFAULT_NAME_PATTERNS = [
    # Functions
    re.compile(r'^sub_[0-9a-fA-F]+$'),         # Binary Ninja, IDA
    re.compile(r'^FUN_[0-9a-fA-F]+$'),         # Ghidra
    re.compile(r'^fcn\.[0-9a-fA-F]+$'),        # radare2
    re.compile(r'^func_[0-9a-fA-F]+$'),        # Generic
    re.compile(r'^j_.*$'),                      # Thunks
    # Data
    re.compile(r'^(data|DAT|byte|BYTE|dword|DWORD|qword|QWORD)_[0-9a-fA-F]+$', re.IGNORECASE),
    # Variables (Ghidra decompiler patterns)
    re.compile(r'^(var|local|uVar|iVar|lVar|pVar|cVar|bVar|sVar|auVar|puVar)_?\d*$'),
    # Parameters
    re.compile(r'^(arg|param)_?\d+$'),
    re.compile(r'^a[1-9]$'),                    # IDA-style numbered args
]


def is_default_name(name: str) -> bool:
    """Check if a symbol name matches auto-generated patterns from any disassembler."""
    if not name:
        return True
    return any(p.match(name) for p in DEFAULT_NAME_PATTERNS)


class SymGraphServiceError(Exception):
    """Base exception for SymGraph service errors."""
    pass


class SymGraphAuthError(SymGraphServiceError):
    """Authentication error - API key missing or invalid."""
    pass


class SymGraphNetworkError(SymGraphServiceError):
    """Network error - unable to reach SymGraph API."""
    pass


class SymGraphAPIError(SymGraphServiceError):
    """API error - server returned an error response."""
    def __init__(
        self,
        message: str,
        status_code: int = None,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}


class SymGraphService:
    """
    SymGraph API client service providing:
    - Binary existence checking (unauthenticated)
    - Binary stats retrieval (unauthenticated)
    - Symbol and graph data operations (authenticated)
    - Thread-safe operations
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern implementation."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize the SymGraph service."""
        if hasattr(self, '_initialized'):
            return

        self._initialized = True
        self._client_lock = threading.Lock()

        if not HTTPX_AVAILABLE:
            log.log_warn("httpx package not available - SymGraph integration disabled")

    @property
    def base_url(self) -> str:
        """Get the configured API base URL."""
        return settings_service.get_symgraph_api_url().rstrip('/')

    @property
    def web_url(self) -> str:
        """Get the configured web base URL derived from the SymGraph setting."""
        parsed = urlparse(self.base_url)
        netloc = parsed.netloc
        if netloc.startswith("api.") and parsed.path in ("", "/"):
            netloc = netloc[4:]

        path = (parsed.path or "").rstrip("/")
        if path.endswith("/api/v1"):
            path = path[:-7]
        elif path.endswith("/api"):
            path = path[:-4]

        return urlunparse((parsed.scheme, netloc, path or "", "", "", "")).rstrip("/")

    def get_binary_url(self, sha256: str) -> str:
        """Get the browser URL for a binary in the configured SymGraph instance."""
        return f"{self.web_url}/binaries/{sha256}"

    @property
    def api_key(self) -> Optional[str]:
        """Get the configured API key."""
        key = settings_service.get_symgraph_api_key()
        return key if key and key.strip() else None

    @property
    def has_api_key(self) -> bool:
        """Check if an API key is configured."""
        return settings_service.has_symgraph_api_key()

    def _get_headers(self, authenticated: bool = False) -> Dict[str, str]:
        """Get HTTP headers for requests."""
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'IDAssist-SymGraph/1.0'
        }
        if authenticated and self.api_key:
            headers['X-API-Key'] = self.api_key
        return headers

    def _check_httpx(self):
        """Check if httpx is available."""
        if not HTTPX_AVAILABLE:
            raise SymGraphServiceError("httpx package not installed. Install with: pip install httpx")

    def _check_auth(self):
        """Check if authentication is configured."""
        if not self.has_api_key:
            raise SymGraphAuthError("SymGraph API key not configured. Add your API key in Settings > SymGraph")

    def _is_private_network(self) -> bool:
        """Check if the API URL points to a private/internal network address."""
        try:
            parsed = urlparse(self.base_url)
            host = parsed.hostname or ''
            if host in ('localhost', '127.0.0.1', '::1'):
                return True
            # RFC 1918 private networks
            if re.match(r'^10\.', host):
                return True
            if re.match(r'^172\.(1[6-9]|2[0-9]|3[01])\.', host):
                return True
            if re.match(r'^192\.168\.', host):
                return True
        except Exception:
            pass
        return False

    def _client_kwargs(self, timeout: float = 30.0) -> dict:
        """Build common kwargs for httpx.AsyncClient."""
        kwargs = {'timeout': timeout}
        if self._is_private_network():
            kwargs['verify'] = False
        return kwargs

    def _parse_api_error(self, response) -> Tuple[str, Optional[str], Dict[str, Any]]:
        """Extract a normalized API error message and metadata from a response."""
        details: Dict[str, Any] = {}
        message = response.text.strip() or f"HTTP {response.status_code}"

        try:
            payload = response.json()
        except ValueError:
            payload = None

        if isinstance(payload, dict):
            details = payload
            message = payload.get('error') or payload.get('message') or message
            return message, payload.get('code'), details

        return message, None, details

    def _raise_api_error(self, action: str, response):
        """Raise a structured SymGraph API error."""
        message, error_code, details = self._parse_api_error(response)
        raise SymGraphAPIError(
            f"Error {action}: {message}",
            response.status_code,
            error_code=error_code,
            details=details
        )

    def _build_graph_export_payload(self, sha256: str, export_data: Dict[str, Any]) -> Dict[str, Any]:
        """Wrap local graph data in the GraphExport API payload shape."""
        metadata = dict(export_data.get('metadata') or {})
        communities = export_data.get('communities')
        if communities is None:
            communities = metadata.get('communities', [])
        community_members = export_data.get('community_members')
        if community_members is None:
            community_members = metadata.get('community_members', [])

        exported_at = metadata.get('exported_at')
        if not exported_at:
            exported_at = datetime.now(timezone.utc).isoformat()

        return {
            'version': export_data.get('version') or export_data.get('export_version') or '1.0',
            'exported_at': exported_at,
            'binary': {'sha256': sha256},
            'nodes': export_data.get('nodes', []),
            'edges': export_data.get('edges', []),
            'communities': communities or [],
            'community_members': community_members or []
        }

    # === Unauthenticated Operations ===

    async def check_binary_exists(self, sha256: str) -> bool:
        """
        Check if a binary exists in SymGraph (unauthenticated).

        Args:
            sha256: SHA256 hash of the binary

        Returns:
            True if binary exists, False otherwise
        """
        self._check_httpx()

        url = f"{self.base_url}/api/v1/binaries/{sha256}"
        log.log_debug(f"Checking binary existence: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(30.0)) as client:
                response = await client.head(url, headers=self._get_headers())

                if response.status_code == 200:
                    return True
                elif response.status_code == 404:
                    return False
                else:
                    log.log_warn(f"Unexpected status checking binary: {response.status_code}")
                    return False

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def get_binary_stats(self, sha256: str, version: Optional[int] = None) -> Optional[BinaryStats]:
        """
        Get binary statistics from SymGraph (unauthenticated).

        Args:
            sha256: SHA256 hash of the binary

        Returns:
            BinaryStats if binary exists, None otherwise
        """
        self._check_httpx()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/stats"
        if version is not None:
            url += f"?version={version}"
        log.log_debug(f"Getting binary stats: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(30.0)) as client:
                response = await client.get(url, headers=self._get_headers())

                if response.status_code == 200:
                    data = response.json()
                    return BinaryStats.from_dict(data)
                elif response.status_code == 404:
                    return None
                else:
                    log.log_warn(f"Error getting stats: {response.status_code}")
                    return None

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def list_binary_versions(self, sha256: str) -> List[BinaryRevision]:
        """List accessible binary revisions for a binary."""
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/versions"
        log.log_debug(f"Listing binary versions: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(30.0)) as client:
                response = await client.get(
                    url,
                    headers=self._get_headers(authenticated=True)
                )

                if response.status_code == 200:
                    data = response.json() or {}
                    revisions = data.get('revisions') if isinstance(data, dict) else []
                    if not isinstance(revisions, list):
                        return []
                    return [BinaryRevision.from_dict(item) for item in revisions]
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                elif response.status_code == 404:
                    return []
                else:
                    self._raise_api_error("listing binary versions", response)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def query_binary(
        self,
        sha256: str,
        version: Optional[int] = None,
        include_versions: bool = False
    ) -> QueryResult:
        """
        Query SymGraph for binary info (unauthenticated).

        Args:
            sha256: SHA256 hash of the binary

        Returns:
            QueryResult with exists status and stats
        """
        try:
            exists = await self.check_binary_exists(sha256)
            if not exists:
                return QueryResult.not_found()

            revisions: List[BinaryRevision] = []
            latest_revision: Optional[int] = None
            if include_versions and self.has_api_key:
                try:
                    revisions = await self.list_binary_versions(sha256)
                    latest_revision = revisions[0].version if revisions else None
                except SymGraphServiceError as e:
                    log.log_warn(f"Unable to list versions for {sha256[:16]}...: {e}")

            effective_version = version if version is not None else latest_revision
            stats = await self.get_binary_stats(sha256, version=effective_version)
            return QueryResult.found(
                stats=stats,
                revisions=revisions,
                latest_revision=latest_revision,
                selected_revision=effective_version
            )

        except SymGraphServiceError as e:
            return QueryResult.error_result(str(e))

    # === Authenticated Operations ===

    async def get_symbols(
        self,
        sha256: str,
        symbol_type: Optional[str] = None,
        version: Optional[int] = None
    ) -> List[Symbol]:
        """
        Get symbols for a binary (authenticated).

        Args:
            sha256: SHA256 hash of the binary
            symbol_type: Optional filter by symbol type (e.g., "function", "data", "type")

        Returns:
            List of Symbol objects
        """
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/symbols"
        params = []
        if symbol_type:
            params.append(f"type={symbol_type}")
        if version is not None:
            params.append(f"version={version}")
        if params:
            url += "?" + "&".join(params)
        log.log_debug(f"Getting symbols: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(60.0)) as client:
                response = await client.get(
                    url,
                    headers=self._get_headers(authenticated=True)
                )

                if response.status_code == 200:
                    data = response.json()
                    # Handle various response formats safely
                    if data is None:
                        return []
                    symbols_data = data.get('symbols', data) if isinstance(data, dict) else data
                    if symbols_data is None or not isinstance(symbols_data, list):
                        return []
                    return [Symbol.from_dict(s) for s in symbols_data]
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                elif response.status_code == 404:
                    return []
                else:
                    self._raise_api_error("getting symbols", response)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def list_documents(
        self,
        sha256: str,
        version: Optional[int] = None,
        page_size: int = 200
    ) -> List[DocumentSummary]:
        """List remote document summaries for a binary."""
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/documents?page=1&page_size={page_size}"
        if version is not None:
            url += f"&version={version}"
        log.log_debug(f"Listing documents: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(60.0)) as client:
                response = await client.get(
                    url,
                    headers=self._get_headers(authenticated=True)
                )

                if response.status_code == 200:
                    data = response.json() or {}
                    documents_data = data.get('documents', []) if isinstance(data, dict) else []
                    if not isinstance(documents_data, list):
                        return []
                    return [DocumentSummary.from_dict(item) for item in documents_data]
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                elif response.status_code == 404:
                    return []
                else:
                    self._raise_api_error("listing documents", response)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def get_document(
        self,
        sha256: str,
        document_identity_id: str,
        version: Optional[int] = None,
        binary_version: Optional[int] = None
    ) -> Optional[Document]:
        """Fetch a single document with full Markdown content."""
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/documents/{document_identity_id}"
        params = []
        if version is not None:
            params.append(f"version={version}")
        if binary_version is not None:
            params.append(f"binary_version={binary_version}")
        if params:
            url += "?" + "&".join(params)
        log.log_debug(f"Fetching document: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(60.0)) as client:
                response = await client.get(
                    url,
                    headers=self._get_headers(authenticated=True)
                )

                if response.status_code == 200:
                    return Document.from_dict(response.json() or {})
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                elif response.status_code == 404:
                    return None
                else:
                    self._raise_api_error("fetching document", response)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def create_binary_revision(
        self,
        sha256: str,
        visibility: str = "public",
        base_version: Optional[int] = None
    ) -> int:
        """Create a writable binary revision for a push session."""
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/versions"
        payload: Dict[str, Any] = {'visibility': visibility}
        if base_version is not None:
            payload['base_version'] = base_version

        log.log_debug(f"Creating binary revision for {sha256[:16]}... visibility={visibility}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(60.0)) as client:
                response = await client.post(
                    url,
                    headers=self._get_headers(authenticated=True),
                    json=payload
                )

                if response.status_code in (200, 201):
                    data = response.json()
                    revision = data.get('version')
                    if isinstance(revision, int) and revision > 0:
                        return revision
                    raise SymGraphAPIError("Created binary revision response did not include a version")
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                else:
                    self._raise_api_error("creating binary revision", response)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def update_binary_metadata(
        self,
        sha256: str,
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update top-level binary metadata for an existing SymGraph binary."""
        self._check_httpx()
        self._check_auth()

        payload: Dict[str, Any] = {}
        for key, value in (metadata or {}).items():
            if value is None:
                continue
            if isinstance(value, str):
                cleaned = value.strip()
                if not cleaned:
                    continue
                payload[key] = cleaned
                continue
            payload[key] = value

        if not payload:
            return {}

        url = f"{self.base_url}/api/v1/binaries/{sha256}"
        log.log_debug(f"Updating binary metadata for {sha256[:16]}... keys={sorted(payload.keys())}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(60.0)) as client:
                response = await client.patch(
                    url,
                    headers=self._get_headers(authenticated=True),
                    json=payload
                )

                if response.status_code == 200:
                    return response.json() if response.content else {}
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                else:
                    self._raise_api_error("updating binary metadata", response)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def push_symbols_bulk(
        self,
        sha256: str,
        symbols: List[Dict[str, Any]],
        target_revision: Optional[int] = None
    ) -> PushResult:
        """
        Push symbols to SymGraph in bulk (authenticated).

        Args:
            sha256: SHA256 hash of the binary
            symbols: List of symbol dictionaries

        Returns:
            PushResult indicating success/failure
        """
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/symbols/bulk"
        params = {}
        if target_revision is not None:
            params['target_revision'] = target_revision
        log.log_debug(f"Pushing {len(symbols)} symbols to: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(120.0)) as client:
                response = await client.post(
                    url,
                    headers=self._get_headers(authenticated=True),
                    params=params,
                    json={'symbols': symbols}
                )

                if response.status_code in (200, 201):
                    data = response.json()
                    return PushResult.success_result(
                        symbols=data.get('symbols_created', len(symbols)),
                        binary_revision=data.get('binary_revision')
                    )
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                else:
                    self._raise_api_error("pushing symbols", response)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def push_symbols_chunked(
        self,
        sha256: str,
        symbols: List[Dict[str, Any]],
        chunk_size: int = 500,
        target_revision: Optional[int] = None,
        visibility: str = "public"
    ) -> PushResult:
        """
        Push symbols in chunks to avoid timeouts on large payloads.

        Args:
            sha256: SHA256 hash of the binary
            symbols: List of symbol dictionaries
            chunk_size: Number of symbols per chunk (default 500)

        Returns:
            PushResult with aggregated counts
        """
        if not symbols:
            return PushResult.success_result()

        total_pushed = 0
        total = len(symbols)
        if target_revision is None:
            target_revision = await self.create_binary_revision(sha256, visibility=visibility)
        log.log_info(f"Pushing {total} symbols in chunks of {chunk_size}")

        for i in range(0, total, chunk_size):
            chunk = symbols[i:i + chunk_size]
            log.log_debug(f"Pushing symbol chunk {i // chunk_size + 1} ({len(chunk)} symbols)")
            result = await self.push_symbols_bulk(sha256, chunk, target_revision=target_revision)
            total_pushed += result.symbols_pushed

        log.log_info(f"Successfully pushed {total_pushed} symbols")
        return PushResult.success_result(symbols=total_pushed, binary_revision=target_revision)

    async def push_documents_bulk(
        self,
        sha256: str,
        documents: List[Dict[str, Any]],
        base_version: Optional[int] = None
    ) -> PushResult:
        """Push document chats to SymGraph using the bulk documents API."""
        self._check_httpx()
        self._check_auth()

        if not documents:
            return PushResult.success_result()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/documents/bulk"
        if base_version is not None:
            url += f"?base_version={base_version}"
        payload = {'documents': documents}
        log.log_debug(f"Pushing {len(documents)} documents to: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(120.0)) as client:
                response = await client.post(
                    url,
                    headers=self._get_headers(authenticated=True),
                    json=payload
                )

                if response.status_code in (200, 201):
                    data = response.json() or {}
                    summary = data.get('summary', {}) if isinstance(data, dict) else {}
                    pushed_count = (
                        int(summary.get('created', 0) or 0)
                        + int(summary.get('versioned', 0) or 0)
                    )
                    if pushed_count == 0 and isinstance(data, dict):
                        results = data.get('results', [])
                        if isinstance(results, list):
                            pushed_count = len([
                                item for item in results
                                if item.get('status') in ('created', 'versioned')
                            ])
                    results = data.get('results', []) if isinstance(data, dict) else []
                    return PushResult.success_result(
                        documents=pushed_count,
                        document_results=results if isinstance(results, list) else [],
                    )
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                else:
                    self._raise_api_error("pushing documents", response)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def export_symbols(self, sha256: str) -> Optional[SymbolExport]:
        """
        Export all symbols for a binary (authenticated).

        Args:
            sha256: SHA256 hash of the binary

        Returns:
            SymbolExport object or None if not found
        """
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/export"
        log.log_debug(f"Exporting symbols: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(120.0)) as client:
                response = await client.get(
                    url,
                    headers=self._get_headers(authenticated=True)
                )

                if response.status_code == 200:
                    data = response.json()
                    return SymbolExport.from_dict(data)
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                elif response.status_code == 404:
                    return None
                else:
                    raise SymGraphAPIError(f"Error exporting symbols: {response.status_code}", response.status_code)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def import_symbols(self, sha256: str, export_data: Dict[str, Any]) -> PushResult:
        """
        Import symbols to SymGraph (authenticated).

        Args:
            sha256: SHA256 hash of the binary
            export_data: Symbol export data dictionary

        Returns:
            PushResult indicating success/failure
        """
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/import"
        log.log_debug(f"Importing symbols to: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(120.0)) as client:
                response = await client.post(
                    url,
                    headers=self._get_headers(authenticated=True),
                    json=export_data
                )

                if response.status_code in (200, 201):
                    data = response.json()
                    return PushResult.success_result(
                        symbols=data.get('symbols_imported', 0)
                    )
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                else:
                    error_msg = response.text or f"HTTP {response.status_code}"
                    self._raise_api_error("importing symbols", response)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def export_graph(self, sha256: str, version: Optional[int] = None) -> Optional[GraphExport]:
        """
        Export graph data for a binary (authenticated).

        Args:
            sha256: SHA256 hash of the binary

        Returns:
            GraphExport object or None if not found
        """
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/graph/export"
        if version is not None:
            url += f"?version={version}"
        log.log_debug(f"Exporting graph: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(120.0)) as client:
                response = await client.get(
                    url,
                    headers=self._get_headers(authenticated=True)
                )

                if response.status_code == 200:
                    data = response.json()
                    return GraphExport.from_dict(data)
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                elif response.status_code == 404:
                    return None
                else:
                    self._raise_api_error("exporting graph", response)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def import_graph(
        self,
        sha256: str,
        export_data: Dict[str, Any],
        target_revision: Optional[int] = None
    ) -> PushResult:
        """
        Import graph data to SymGraph (authenticated).

        Args:
            sha256: SHA256 hash of the binary
            export_data: Graph export data dictionary

        Returns:
            PushResult indicating success/failure
        """
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/graph/import"
        params = {}
        if target_revision is not None:
            params['target_revision'] = target_revision
        payload = self._build_graph_export_payload(sha256, export_data)
        log.log_debug(f"Importing graph to: {url}")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(120.0)) as client:
                response = await client.post(
                    url,
                    headers=self._get_headers(authenticated=True),
                    params=params,
                    json=payload
                )

                if response.status_code in (200, 201):
                    data = response.json()
                    return PushResult.success_result(
                        nodes=data.get('nodes_imported', data.get('imported_nodes', 0)),
                        edges=data.get('edges_imported', data.get('imported_edges', 0)),
                        binary_revision=data.get('binary_revision')
                    )
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                else:
                    self._raise_api_error("importing graph", response)

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    async def import_graph_chunked(
        self,
        sha256: str,
        export_data: Dict[str, Any],
        chunk_size: int = 500,
        target_revision: Optional[int] = None,
        visibility: str = "public"
    ) -> PushResult:
        """
        Import graph data in chunks (nodes first, then edges) to avoid timeouts.

        Args:
            sha256: SHA256 hash of the binary
            export_data: Graph export data with 'nodes' and 'edges' lists
            chunk_size: Number of nodes/edges per chunk (default 500)

        Returns:
            PushResult with aggregated counts
        """
        nodes = export_data.get('nodes', [])
        edges = export_data.get('edges', [])

        if not nodes and not edges:
            return PushResult.success_result()

        total_nodes_pushed = 0
        total_edges_pushed = 0
        if target_revision is None:
            target_revision = await self.create_binary_revision(sha256, visibility=visibility)

        log.log_info(f"Pushing {len(nodes)} nodes and {len(edges)} edges in chunks of {chunk_size}")

        # Push nodes in chunks
        for i in range(0, len(nodes), chunk_size):
            chunk = nodes[i:i + chunk_size]
            log.log_debug(f"Pushing node chunk {i // chunk_size + 1} ({len(chunk)} nodes)")
            result = await self.import_graph(
                sha256,
                {'nodes': chunk, 'edges': [], 'version': export_data.get('version') or export_data.get('export_version')},
                target_revision=target_revision
            )
            total_nodes_pushed += result.nodes_pushed

        # Push edges in chunks
        for i in range(0, len(edges), chunk_size):
            chunk = edges[i:i + chunk_size]
            log.log_debug(f"Pushing edge chunk {i // chunk_size + 1} ({len(chunk)} edges)")
            result = await self.import_graph(
                sha256,
                {'nodes': [], 'edges': chunk, 'version': export_data.get('version') or export_data.get('export_version')},
                target_revision=target_revision
            )
            total_edges_pushed += result.edges_pushed

        log.log_info(f"Successfully pushed {total_nodes_pushed} nodes, {total_edges_pushed} edges")
        return PushResult.success_result(
            nodes=total_nodes_pushed,
            edges=total_edges_pushed,
            binary_revision=target_revision
        )

    # === Fingerprint Operations ===

    async def add_fingerprint(self, sha256: str, fp_type: str, fp_value: str) -> bool:
        """
        Add a fingerprint to a binary (authenticated).

        Args:
            sha256: SHA256 hash of the binary
            fp_type: Fingerprint type (e.g., "pdb_guid", "build_id")
            fp_value: Fingerprint value

        Returns:
            True if successful, False otherwise
        """
        self._check_httpx()
        self._check_auth()

        url = f"{self.base_url}/api/v1/binaries/{sha256}/fingerprints"
        log.log_debug(f"Adding fingerprint {fp_type}={fp_value} to {sha256[:16]}...")

        try:
            async with httpx.AsyncClient(**self._client_kwargs(30.0)) as client:
                response = await client.post(
                    url,
                    headers=self._get_headers(authenticated=True),
                    json={'type': fp_type, 'value': fp_value}
                )

                if response.status_code in (200, 201):
                    log.log_info(f"Added fingerprint: {fp_type}={fp_value}")
                    return True
                elif response.status_code == 401:
                    raise SymGraphAuthError("Invalid API key")
                elif response.status_code == 409:
                    # Fingerprint already exists - not an error
                    log.log_debug(f"Fingerprint already exists: {fp_type}={fp_value}")
                    return True
                else:
                    log.log_warn(f"Failed to add fingerprint: {response.status_code}")
                    return False

        except httpx.TimeoutException:
            raise SymGraphNetworkError(f"Timeout connecting to {self.base_url}")
        except httpx.RequestError as e:
            raise SymGraphNetworkError(f"Network error: {str(e)}")

    # === Helper Methods for Pull Preview ===

    def build_conflict_entries(
        self,
        local_symbols: Dict[int, str],
        remote_symbols: List[Symbol],
        min_confidence: float = 0.0
    ) -> List[ConflictEntry]:
        """
        Build conflict entries by comparing local and remote symbols.

        Args:
            local_symbols: Dict mapping address to local name
            remote_symbols: List of remote Symbol objects
            min_confidence: Minimum confidence threshold (0.0-1.0) for remote symbols

        Returns:
            List of ConflictEntry objects for the conflict resolution table
        """
        conflicts = []
        skipped_default = 0
        skipped_confidence = 0
        skipped_duplicate = 0

        # Deduplicate by address: keep the best symbol per address.
        # Prefer named symbols (function/variable) over comments,
        # and higher confidence over lower.
        best_by_address: Dict[int, Symbol] = {}
        for remote_sym in remote_symbols:
            display_name = remote_sym.display_name
            is_comment = remote_sym.symbol_type == 'comment'

            # Skip symbols with no useful display name
            if not display_name:
                skipped_default += 1
                continue

            # Skip non-comment symbols with default/auto-generated names
            if not is_comment and is_default_name(remote_sym.name):
                skipped_default += 1
                continue

            # Skip remote symbols below minimum confidence threshold
            if remote_sym.confidence < min_confidence:
                skipped_confidence += 1
                continue

            addr = remote_sym.address
            existing = best_by_address.get(addr)
            if existing is None:
                best_by_address[addr] = remote_sym
            else:
                existing_is_comment = existing.symbol_type == 'comment'
                if existing_is_comment and not is_comment:
                    best_by_address[addr] = remote_sym
                    skipped_duplicate += 1
                elif not existing_is_comment and is_comment:
                    skipped_duplicate += 1
                elif remote_sym.confidence > existing.confidence:
                    best_by_address[addr] = remote_sym
                    skipped_duplicate += 1
                else:
                    skipped_duplicate += 1

        for addr, remote_sym in best_by_address.items():
            local_name = local_symbols.get(addr)
            local_is_default = is_default_name(local_name) if local_name else True

            if local_name is None or local_is_default:
                # Remote only OR local has default name - NEW (safe to apply)
                conflicts.append(ConflictEntry.create_new(addr, remote_sym))
            elif local_name == remote_sym.display_name:
                # Same value - SAME
                conflicts.append(ConflictEntry.create_same(addr, local_name, remote_sym))
            else:
                # Different values (both user-defined) - CONFLICT
                conflicts.append(ConflictEntry.create_conflict(addr, local_name, remote_sym))

        if skipped_default > 0 or skipped_confidence > 0 or skipped_duplicate > 0:
            log.log_info(f"Filtered out {skipped_default} default names, {skipped_confidence} low confidence, {skipped_duplicate} duplicates")

        return conflicts


# Singleton instance
symgraph_service = SymGraphService()
