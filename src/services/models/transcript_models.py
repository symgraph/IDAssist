#!/usr/bin/env python3

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class TranscriptEventKind(str, Enum):
    USER_MESSAGE = "user_message"
    ASSISTANT_MESSAGE = "assistant_message"
    TOOL_CALL_REQUESTED = "tool_call_requested"
    TOOL_CALL_STARTED = "tool_call_started"
    TOOL_CALL_COMPLETED = "tool_call_completed"
    TOOL_CALL_FAILED = "tool_call_failed"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_DECISION = "approval_decision"
    TODO_UPDATED = "todo_updated"
    FINDING_ADDED = "finding_added"
    ITERATION_NOTICE = "iteration_notice"
    CONTEXT_COMPACTED = "context_compacted"
    SYSTEM_NOTICE = "system_notice"
    DOCUMENT_SNAPSHOT = "document_snapshot"


class ToolChoiceMode(str, Enum):
    AUTO = "auto"
    REQUIRED_INITIAL = "required_initial"

    def to_openai_tool_choice(self, messages: list) -> str:
        if self == ToolChoiceMode.AUTO:
            return "auto"
        for message in reversed(messages or []):
            role = getattr(message, "role", None)
            role_value = role.value if hasattr(role, "value") else role
            if role_value == "system":
                continue
            if role_value == "tool":
                return "auto"
            break
        return "required"


@dataclass
class ArtifactRef:
    artifact_id: str
    file_path: str
    preview_text: str
    mime_type: str = "text/plain"


@dataclass
class TranscriptEvent:
    id: int
    binary_hash: str
    chat_id: str
    event_index: int
    event_kind: TranscriptEventKind
    correlation_id: Optional[str]
    actor_role: Optional[str]
    content_text: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    artifact_ref: Optional[ArtifactRef] = None
    source_message_id: Optional[int] = None
    source_message_order: Optional[int] = None
    created_at: Optional[str] = None


@dataclass
class ApprovalRequest:
    request_id: str
    chat_id: int
    binary_hash: str
    correlation_id: str
    tool_name: str
    tool_source: str
    risk_tier: str
    args_preview: str
    args_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContextSnapshot:
    provider_label: str = "No provider"
    model_name: str = "No model"
    token_count: int = 0
    token_limit: int = 0
    peak_token_count: int = 0
    message_count: int = 0
    peak_message_count: int = 0
    threshold: int = 0
    compacted: bool = False
    compaction_summary: Optional[str] = None

