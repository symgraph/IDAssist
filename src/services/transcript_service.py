#!/usr/bin/env python3

import json
import os
import uuid
from typing import Dict, List, Optional

from .models.transcript_models import ArtifactRef, ContextSnapshot, TranscriptEvent, TranscriptEventKind

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


class TranscriptService:
    LARGE_ARTIFACT_THRESHOLD = 4000

    def __init__(self, analysis_db):
        self.analysis_db = analysis_db
        self._listeners = []
        self._artifact_root = os.path.join(os.path.dirname(self.analysis_db._db_path), "transcript_artifacts")
        os.makedirs(self._artifact_root, exist_ok=True)

    def add_listener(self, listener):
        self._listeners.append(listener)

    def notify_changed(self, binary_hash: str, chat_id: str):
        for listener in self._listeners:
            try:
                listener(binary_hash, chat_id)
            except Exception as exc:
                log.log_warn(f"Transcript listener failed: {exc}")

    def ensure_backfilled(self, binary_hash: str, chat_id: str, analysis_db=None):
        if self.get_transcript_events(binary_hash, chat_id):
            return
        db = analysis_db or self.analysis_db
        native_messages = db.get_native_messages(binary_hash, chat_id)
        if not native_messages:
            legacy_messages = db.get_chat_history(binary_hash, chat_id)
            for message in legacy_messages:
                kind = TranscriptEventKind.USER_MESSAGE if message["role"] == "user" else TranscriptEventKind.ASSISTANT_MESSAGE
                if message["role"] not in ("user", "assistant"):
                    kind = TranscriptEventKind.SYSTEM_NOTICE
                self.append_event(
                    binary_hash, chat_id, kind, message.get("role"), message.get("content"),
                    created_at=message.get("created_at"),
                    source_message_id=message.get("id"),
                    source_message_order=message.get("message_order"),
                )
            return
        for message in native_messages:
            role = message.get("role")
            if role == "system":
                continue
            kind = {
                "user": TranscriptEventKind.USER_MESSAGE,
                "assistant": TranscriptEventKind.ASSISTANT_MESSAGE,
                "tool": TranscriptEventKind.TOOL_CALL_COMPLETED,
            }.get(role, TranscriptEventKind.SYSTEM_NOTICE)
            metadata = {
                "provider_type": message.get("provider_type"),
                "message_type": message.get("message_type"),
            }
            native_data = message.get("native_message_data") or {}
            if kind == TranscriptEventKind.ASSISTANT_MESSAGE and native_data.get("tool_calls"):
                metadata["tool_calls"] = native_data.get("tool_calls")
            self.append_event(
                binary_hash, chat_id, kind, role, message.get("content_text"), metadata=metadata,
                created_at=message.get("created_at"), source_message_id=message.get("id"),
                source_message_order=message.get("message_order"),
            )

    def get_transcript_events(self, binary_hash: str, chat_id: str) -> List[TranscriptEvent]:
        with self.analysis_db.get_db_lock():
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT id, event_index, event_kind, correlation_id, actor_role,
                           content_text, metadata, artifact_id, source_message_id,
                           source_message_order, created_at
                    FROM BNChatTranscriptEvents
                    WHERE binary_hash = ? AND chat_id = ?
                    ORDER BY event_index ASC, id ASC
                    """,
                    (binary_hash, str(chat_id)),
                )
                events = []
                for row in cursor.fetchall():
                    metadata = json.loads(row[6]) if row[6] else {}
                    artifact_ref = self.get_artifact(binary_hash, chat_id, row[7]) if row[7] else None
                    events.append(TranscriptEvent(
                        id=row[0],
                        binary_hash=binary_hash,
                        chat_id=str(chat_id),
                        event_index=row[1],
                        event_kind=TranscriptEventKind(row[2]),
                        correlation_id=row[3],
                        actor_role=row[4],
                        content_text=row[5],
                        metadata=metadata,
                        artifact_ref=artifact_ref,
                        source_message_id=row[8],
                        source_message_order=row[9],
                        created_at=row[10],
                    ))
                return events
            finally:
                conn.close()

    def append_event(self, binary_hash: str, chat_id: str, event_kind: TranscriptEventKind,
                     actor_role: Optional[str], content_text: Optional[str], correlation_id: Optional[str] = None,
                     metadata: Optional[Dict] = None, source_message_id: Optional[int] = None,
                     source_message_order: Optional[int] = None, created_at: Optional[str] = None) -> int:
        artifact_id = None
        content_value = content_text
        metadata_value = dict(metadata or {})
        if content_text and len(content_text) > self.LARGE_ARTIFACT_THRESHOLD and event_kind in (
            TranscriptEventKind.TOOL_CALL_COMPLETED, TranscriptEventKind.TOOL_CALL_FAILED
        ):
            artifact = self.save_artifact(binary_hash, chat_id, "text/plain", content_text)
            artifact_id = artifact.artifact_id
            metadata_value["artifact_preview"] = artifact.preview_text
            content_value = artifact.preview_text
        with self.analysis_db.get_db_lock():
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COALESCE(MAX(event_index), -1) + 1 FROM BNChatTranscriptEvents WHERE binary_hash = ? AND chat_id = ?",
                    (binary_hash, str(chat_id)),
                )
                event_index = cursor.fetchone()[0]
                if created_at:
                    cursor.execute(
                        """
                        INSERT INTO BNChatTranscriptEvents
                        (binary_hash, chat_id, event_index, event_kind, correlation_id, actor_role,
                         content_text, metadata, artifact_id, source_message_id, source_message_order, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            binary_hash, str(chat_id), event_index, event_kind.value, correlation_id, actor_role,
                            content_value, json.dumps(metadata_value) if metadata_value else None, artifact_id,
                            source_message_id, source_message_order, created_at,
                        ),
                    )
                else:
                    cursor.execute(
                        """
                        INSERT INTO BNChatTranscriptEvents
                        (binary_hash, chat_id, event_index, event_kind, correlation_id, actor_role,
                         content_text, metadata, artifact_id, source_message_id, source_message_order)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            binary_hash, str(chat_id), event_index, event_kind.value, correlation_id, actor_role,
                            content_value, json.dumps(metadata_value) if metadata_value else None, artifact_id,
                            source_message_id, source_message_order,
                        ),
                    )
                event_id = cursor.lastrowid
                conn.commit()
            finally:
                conn.close()
        self.notify_changed(binary_hash, str(chat_id))
        return event_id

    def update_last_assistant_message(self, binary_hash: str, chat_id: str, new_markdown: str):
        with self.analysis_db.get_db_lock():
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT id, source_message_id, source_message_order
                    FROM BNChatTranscriptEvents
                    WHERE binary_hash = ? AND chat_id = ? AND event_kind = ?
                    ORDER BY event_index DESC LIMIT 1
                    """,
                    (binary_hash, str(chat_id), TranscriptEventKind.ASSISTANT_MESSAGE.value),
                )
                row = cursor.fetchone()
                if not row:
                    return
                cursor.execute(
                    "UPDATE BNChatTranscriptEvents SET content_text = ? WHERE id = ?",
                    (new_markdown, row[0]),
                )
                source_message_id = row[1]
                if source_message_id is None:
                    cursor.execute(
                        """
                        SELECT id
                        FROM BNChatMessages
                        WHERE binary_hash = ? AND chat_id = ? AND role = 'assistant'
                        ORDER BY message_order DESC LIMIT 1
                        """,
                        (binary_hash, str(chat_id)),
                    )
                    native_row = cursor.fetchone()
                    source_message_id = native_row[0] if native_row else None
                if source_message_id is not None:
                    cursor.execute(
                        "UPDATE BNChatMessages SET content_text = ?, native_message_data = ? WHERE id = ?",
                        (new_markdown, json.dumps({"role": "assistant", "content": new_markdown}), source_message_id),
                    )
                conn.commit()
            finally:
                conn.close()
        self.notify_changed(binary_hash, str(chat_id))

    def append_user_message(self, binary_hash: str, chat_id: str, content: str,
                            source_message_id: Optional[int] = None, source_message_order: Optional[int] = None):
        return self.append_event(binary_hash, chat_id, TranscriptEventKind.USER_MESSAGE, "user", content,
                                 source_message_id=source_message_id, source_message_order=source_message_order)

    def append_assistant_message(self, binary_hash: str, chat_id: str, content: str,
                                 source_message_id: Optional[int] = None, source_message_order: Optional[int] = None,
                                 metadata: Optional[Dict] = None):
        return self.append_event(binary_hash, chat_id, TranscriptEventKind.ASSISTANT_MESSAGE, "assistant", content,
                                 metadata=metadata, source_message_id=source_message_id,
                                 source_message_order=source_message_order)

    def append_tool_requested(self, binary_hash: str, chat_id: str, correlation_id: str,
                              tool_name: str, tool_source: str, arguments: dict,
                              metadata_extra: Optional[Dict] = None):
        metadata = {"tool_name": tool_name, "tool_source": tool_source, "arguments": arguments}
        if metadata_extra:
            metadata.update(metadata_extra)
        return self.append_event(binary_hash, chat_id, TranscriptEventKind.TOOL_CALL_REQUESTED, "tool", None,
                                 correlation_id=correlation_id, metadata=metadata)

    def append_tool_started(self, binary_hash: str, chat_id: str, correlation_id: str,
                            tool_name: str, tool_source: str, metadata_extra: Optional[Dict] = None):
        metadata = {"tool_name": tool_name, "tool_source": tool_source}
        if metadata_extra:
            metadata.update(metadata_extra)
        return self.append_event(binary_hash, chat_id, TranscriptEventKind.TOOL_CALL_STARTED, "tool", None,
                                 correlation_id=correlation_id, metadata=metadata)

    def append_tool_completed(self, binary_hash: str, chat_id: str, correlation_id: str,
                              tool_name: str, tool_source: str, result_text: str, success: bool = True,
                              metadata_extra: Optional[Dict] = None):
        kind = TranscriptEventKind.TOOL_CALL_COMPLETED if success else TranscriptEventKind.TOOL_CALL_FAILED
        metadata = {"tool_name": tool_name, "tool_source": tool_source}
        if metadata_extra:
            metadata.update(metadata_extra)
        return self.append_event(binary_hash, chat_id, kind, "tool", result_text, correlation_id=correlation_id,
                                 metadata=metadata)

    def append_approval_requested(self, binary_hash: str, chat_id: str, correlation_id: str, request_id: str,
                                  tool_name: str, tool_source: str, risk_tier: str, arguments: dict):
        return self.append_event(binary_hash, chat_id, TranscriptEventKind.APPROVAL_REQUESTED, "system", None,
                                 correlation_id=correlation_id,
                                 metadata={"request_id": request_id, "tool_name": tool_name, "tool_source": tool_source,
                                           "risk_tier": risk_tier, "arguments": arguments})

    def append_approval_decision(self, binary_hash: str, chat_id: str, correlation_id: str,
                                 request_id: Optional[str], tool_name: str, decision: str,
                                 risk_tier: str, scope: str, tool_source: str):
        return self.append_event(binary_hash, chat_id, TranscriptEventKind.APPROVAL_DECISION, "system", decision,
                                 correlation_id=correlation_id,
                                 metadata={"request_id": request_id, "tool_name": tool_name, "tool_source": tool_source,
                                           "risk_tier": risk_tier, "scope": scope})

    def append_todo_snapshot(self, binary_hash: str, chat_id: str, summary: str, todos: list,
                             iteration: Optional[int] = None, counts: Optional[Dict] = None,
                             metadata_extra: Optional[Dict] = None):
        metadata = {"summary": summary, "todos": todos, "tasks": todos}
        if iteration is not None:
            metadata["iteration"] = iteration
        if counts:
            metadata.update(counts)
        if metadata_extra:
            metadata.update(metadata_extra)
        return self.append_event(binary_hash, chat_id, TranscriptEventKind.TODO_UPDATED, "agent", summary,
                                 metadata=metadata)

    def append_finding(self, binary_hash: str, chat_id: str, finding: str, iteration: Optional[int] = None,
                       metadata_extra: Optional[Dict] = None):
        metadata = {"iteration": iteration} if iteration is not None else {}
        if metadata_extra:
            metadata.update(metadata_extra)
        return self.append_event(binary_hash, chat_id, TranscriptEventKind.FINDING_ADDED, "agent", finding,
                                 metadata=metadata or None)

    def append_iteration_notice(self, binary_hash: str, chat_id: str, content: str,
                                metadata: Optional[Dict] = None, metadata_extra: Optional[Dict] = None):
        merged = dict(metadata or {})
        if metadata_extra:
            merged.update(metadata_extra)
        return self.append_event(binary_hash, chat_id, TranscriptEventKind.ITERATION_NOTICE, "agent", content,
                                 metadata=merged or None)

    def append_context_compacted(self, binary_hash: str, chat_id: str, summary: str, metadata: Dict):
        return self.append_event(binary_hash, chat_id, TranscriptEventKind.CONTEXT_COMPACTED, "system", summary,
                                 metadata=metadata)

    def append_document_snapshot(self, binary_hash: str, chat_id: str, content: str):
        return self.append_event(binary_hash, chat_id, TranscriptEventKind.DOCUMENT_SNAPSHOT, "assistant", content)

    def save_artifact(self, binary_hash: str, chat_id: str, mime_type: str, content: str) -> ArtifactRef:
        artifact_id = str(uuid.uuid4())
        chat_dir = os.path.join(self._artifact_root, binary_hash, str(chat_id))
        os.makedirs(chat_dir, exist_ok=True)
        file_path = os.path.join(chat_dir, f"{artifact_id}.txt")
        with open(file_path, "w", encoding="utf-8") as handle:
            handle.write(content)
        preview = content[:800]
        with self.analysis_db.get_db_lock():
            conn = self.analysis_db.get_connection()
            try:
                conn.execute(
                    """
                    INSERT INTO BNChatArtifacts
                    (artifact_id, binary_hash, chat_id, mime_type, file_path, preview_text)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (artifact_id, binary_hash, str(chat_id), mime_type, file_path, preview),
                )
                conn.commit()
            finally:
                conn.close()
        return ArtifactRef(artifact_id=artifact_id, file_path=file_path, preview_text=preview, mime_type=mime_type)

    def get_artifact(self, binary_hash: str, chat_id: str, artifact_id: str) -> Optional[ArtifactRef]:
        with self.analysis_db.get_db_lock():
            conn = self.analysis_db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT file_path, preview_text, mime_type
                    FROM BNChatArtifacts
                    WHERE artifact_id = ? AND binary_hash = ? AND chat_id = ?
                    """,
                    (artifact_id, binary_hash, str(chat_id)),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return ArtifactRef(artifact_id=artifact_id, file_path=row[0], preview_text=row[1], mime_type=row[2])
            finally:
                conn.close()

    def build_react_continuation_bridge(self, binary_hash: str, chat_id: str) -> Optional[Dict]:
        events = self.get_transcript_events(binary_hash, chat_id)
        if not events:
            return None

        final_event = None
        final_metadata = None
        for event in reversed(events):
            if event.event_kind != TranscriptEventKind.ASSISTANT_MESSAGE:
                continue
            metadata = event.metadata or {}
            if metadata.get("react_final"):
                final_event = event
                final_metadata = metadata
                break
        if not final_event or not final_metadata:
            return None

        react_run_id = final_metadata.get("react_run_id")
        if not react_run_id:
            return None

        objective = final_metadata.get("react_objective")
        status = final_metadata.get("react_status")
        findings: List[str] = []
        seen = set()
        latest_todo_metadata = None

        for event in events:
            metadata = event.metadata or {}
            if metadata.get("react_run_id") != react_run_id:
                continue
            if event.event_kind == TranscriptEventKind.FINDING_ADDED:
                finding = self._normalize_bridge_text(event.content_text, 320)
                if finding and finding not in seen:
                    seen.add(finding)
                    findings.append(finding)
            elif event.event_kind == TranscriptEventKind.TODO_UPDATED:
                latest_todo_metadata = metadata

        if len(findings) > 6:
            findings = findings[-6:]

        pending_count = int((latest_todo_metadata or {}).get("pending_count") or 0)
        active_count = int((latest_todo_metadata or {}).get("in_progress_count") or 0)
        active_todo = self._extract_active_todo(latest_todo_metadata or {})

        lines = ["## Prior ReAct Investigation Context", ""]
        if objective:
            lines.append(f"- Objective: {objective}")
        if status:
            lines.append(f"- Status: {status}")

        conclusion = self._normalize_bridge_text(final_event.content_text, 900)
        if conclusion:
            lines.extend(["", "Conclusion:", conclusion])

        if findings:
            lines.extend(["", "Key findings:"])
            lines.extend(f"- {finding}" for finding in findings)

        if (active_count > 0 or pending_count > 0) and active_todo:
            lines.extend(["", "Open investigation items:", f"- {active_todo}"])

        return {
            "react_run_id": react_run_id,
            "markdown": "\n".join(lines).strip(),
            "finding_count": len(findings),
            "pending_count": pending_count,
            "status": status,
        }

    @staticmethod
    def _normalize_bridge_text(value: Optional[str], max_chars: int) -> str:
        if not value:
            return ""
        normalized = value.replace("\r\n", "\n").replace("\r", "\n").strip()
        if len(normalized) > max_chars:
            normalized = normalized[: max(0, max_chars - 3)].rstrip() + "..."
        return normalized

    @staticmethod
    def _extract_active_todo(metadata: Dict) -> Optional[str]:
        todos = metadata.get("todos") or metadata.get("tasks") or []
        pending = None
        for todo in todos:
            if not isinstance(todo, dict):
                continue
            task = (todo.get("task") or "").strip()
            status = str(todo.get("status") or "").upper()
            if not task:
                continue
            if status == "IN_PROGRESS":
                return task
            if pending is None and status == "PENDING":
                pending = task
        return pending
