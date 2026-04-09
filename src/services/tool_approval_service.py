#!/usr/bin/env python3

import json
import threading
import uuid
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .models.transcript_models import ApprovalRequest

try:
    import binaryninja
    log = binaryninja.log.Logger(0, "BinAssist")
except ImportError:
    class MockLog:
        @staticmethod
        def log_info(msg): print(f"[BinAssist] INFO: {msg}")
        @staticmethod
        def log_warn(msg): print(f"[BinAssist] WARN: {msg}")
        @staticmethod
        def log_error(msg): print(f"[BinAssist] ERROR: {msg}")
    log = MockLog()


class ToolRiskTier:
    READ_ONLY = "read_only"
    MUTATING = "mutating"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


@dataclass
class ApprovalOutcome:
    approved: bool
    decision: str


class ToolApprovalService:
    TOOL_NAME_ALL = "*"
    DECISION_ALLOW_ONCE = "allow_once"
    DECISION_ALLOW_SESSION = "allow_session"
    DECISION_DENY = "deny"

    def __init__(self, analysis_db, transcript_service):
        self.analysis_db = analysis_db
        self.transcript_service = transcript_service
        self._pending_by_request: Dict[str, ApprovalRequest] = {}
        self._pending_by_chat: Dict[int, List[str]] = {}
        self._state_listener: Optional[Callable[[], None]] = None
        self._lock = threading.RLock()

    def set_state_listener(self, listener: Callable[[], None]):
        self._state_listener = listener

    def classify(self, tool_name: str, tool_source: str) -> str:
        normalized = (tool_name or "").lower()
        if "." in normalized:
            normalized = normalized.rsplit(".", 1)[-1]
        source = (tool_source or "").lower()
        if source.startswith("mcp:"):
            return ToolRiskTier.READ_ONLY if self._looks_read_only(normalized) else ToolRiskTier.UNKNOWN
        if any(token in normalized for token in ("push", "sync", "upload", "network", "http")):
            return ToolRiskTier.EXTERNAL
        if any(token in normalized for token in ("rename", "retype", "patch", "comment", "set", "create", "delete", "update")):
            return ToolRiskTier.MUTATING
        return ToolRiskTier.READ_ONLY if self._looks_read_only(normalized) else ToolRiskTier.UNKNOWN

    def request_approval(self, chat_id: int, binary_hash: str, correlation_id: str,
                         tool_name: str, tool_source: str, arguments: dict) -> Optional[ApprovalRequest]:
        if chat_id <= 0:
            return None
        risk_tier = self.classify(tool_name, tool_source)
        if risk_tier == ToolRiskTier.READ_ONLY:
            return None
        if self.has_session_grant(chat_id, tool_name):
            self.transcript_service.append_approval_decision(
                binary_hash, str(chat_id), correlation_id, None, tool_name,
                self.DECISION_ALLOW_SESSION, risk_tier, "session", tool_source
            )
            return None
        request_id = str(uuid.uuid4())
        args_preview = json.dumps(arguments or {}, indent=2)[:2000]
        approval = ApprovalRequest(
            request_id=request_id,
            chat_id=chat_id,
            binary_hash=binary_hash,
            correlation_id=correlation_id,
            tool_name=tool_name,
            tool_source=tool_source,
            risk_tier=risk_tier,
            args_preview=args_preview,
            args_data=arguments or {},
        )
        with self._lock:
            self._pending_by_request[request_id] = approval
            self._pending_by_chat.setdefault(chat_id, []).append(request_id)
        self.transcript_service.append_approval_requested(
            binary_hash, str(chat_id), correlation_id, request_id,
            tool_name, tool_source, risk_tier, arguments or {}
        )
        self._notify()
        return approval

    def resolve_pending(self, request_id: str, decision: str) -> Optional[ApprovalOutcome]:
        with self._lock:
            approval = self._pending_by_request.pop(request_id, None)
            if not approval:
                return None
            chat_pending = self._pending_by_chat.get(approval.chat_id, [])
            if request_id in chat_pending:
                chat_pending.remove(request_id)
            if not chat_pending and approval.chat_id in self._pending_by_chat:
                self._pending_by_chat.pop(approval.chat_id, None)
        normalized = decision if decision in (
            self.DECISION_ALLOW_ONCE, self.DECISION_ALLOW_SESSION, self.DECISION_DENY
        ) else self.DECISION_DENY
        if normalized == self.DECISION_ALLOW_SESSION:
            self.save_session_grant(approval.chat_id, approval.tool_name, approval.risk_tier)
        self.transcript_service.append_approval_decision(
            approval.binary_hash, str(approval.chat_id), approval.correlation_id, approval.request_id,
            approval.tool_name, normalized, approval.risk_tier,
            "session" if normalized == self.DECISION_ALLOW_SESSION else "once",
            approval.tool_source
        )
        self._notify()
        return ApprovalOutcome(approved=normalized != self.DECISION_DENY, decision=normalized)

    def cancel_pending_for_chat(self, chat_id: int):
        request_ids = list(self._pending_by_chat.get(chat_id, []))
        for request_id in request_ids:
            self.resolve_pending(request_id, self.DECISION_DENY)

    def get_first_pending_for_chat(self, chat_id: int) -> Optional[ApprovalRequest]:
        with self._lock:
            pending_ids = self._pending_by_chat.get(chat_id, [])
            for request_id in pending_ids:
                approval = self._pending_by_request.get(request_id)
                if approval:
                    return approval
        return None

    def has_session_grant(self, chat_id: int, tool_name: str) -> bool:
        query = """
            SELECT 1 FROM BNChatApprovalGrants
            WHERE chat_id = ? AND tool_name IN (?, ?) AND scope = 'session'
            LIMIT 1
        """
        with self.analysis_db.get_db_lock():
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(query, (str(chat_id), tool_name, self.TOOL_NAME_ALL))
                return cursor.fetchone() is not None
            finally:
                conn.close()

    def is_accept_all_tools_enabled(self, chat_id: int) -> bool:
        return self.has_session_grant(chat_id, self.TOOL_NAME_ALL)

    def set_accept_all_tools_enabled(self, chat_id: int, enabled: bool):
        if enabled:
            self.save_session_grant(chat_id, self.TOOL_NAME_ALL, ToolRiskTier.UNKNOWN)
        else:
            with self.analysis_db.get_db_lock():
                conn = self.analysis_db.get_connection()
                try:
                    conn.execute(
                        "DELETE FROM BNChatApprovalGrants WHERE chat_id = ? AND tool_name = ?",
                        (str(chat_id), self.TOOL_NAME_ALL),
                    )
                    conn.commit()
                finally:
                    conn.close()
        self._notify()

    def save_session_grant(self, chat_id: int, tool_name: str, risk_tier: str):
        with self.analysis_db.get_db_lock():
            conn = self.analysis_db.get_connection()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO BNChatApprovalGrants
                    (chat_id, tool_name, scope, risk_tier, created_at, updated_at)
                    VALUES (?, ?, 'session', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                    (str(chat_id), tool_name, risk_tier),
                )
                conn.commit()
            finally:
                conn.close()

    def _looks_read_only(self, tool_name: str) -> bool:
        return tool_name.startswith(("get", "list", "query", "lookup", "search", "fetch")) or any(
            token in tool_name for token in ("current", "graph", "semantic", "decomp", "disasm", "xref", "range")
        )

    def _notify(self):
        if self._state_listener:
            self._state_listener()

