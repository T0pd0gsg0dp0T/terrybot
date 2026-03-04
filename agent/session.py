"""
agent/session.py — Per-user session isolation and history management.

Each session is keyed by a unique session_id (Telegram user ID or web UUID).
Sessions are fully isolated — no cross-session history leakage.
History is compacted to max_turns when it grows too large.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import Any, Optional

MessageRole = str  # "system" | "user" | "assistant" | "tool"

MAX_MESSAGE_CONTENT_BYTES = 100 * 1024  # 100KB per message — warn if exceeded


@dataclass
class Message:
    role: MessageRole
    content: str
    # Optional tool call metadata
    tool_call_id: Optional[str] = None
    tool_name: Optional[str] = None
    timestamp: float = field(default_factory=time.monotonic)

    def to_api_dict(self) -> dict[str, Any]:
        """Convert to OpenRouter/OpenAI message dict format."""
        d: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.role == "tool" and self.tool_call_id:
            d["tool_call_id"] = self.tool_call_id
        return d


@dataclass
class Session:
    session_id: str
    history: list[Message] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    canvas_updates: list[str] = field(default_factory=list)
    pending_command: Optional[str] = None

    def touch(self) -> None:
        self.last_active = time.time()

    def add_message(self, role: MessageRole, content: str, **kwargs: Any) -> Message:
        content_bytes = len(content.encode("utf-8"))
        if content_bytes > MAX_MESSAGE_CONTENT_BYTES:
            print(
                f"[session] Warning: large message ({content_bytes} bytes) added to "
                f"session {self.session_id!r} (role={role!r})",
                file=sys.stderr,
            )
        msg = Message(role=role, content=content, **kwargs)
        self.history.append(msg)
        self.touch()
        return msg

    def compact(self, max_turns: int) -> None:
        """
        Trim history to at most max_turns user+assistant pairs.
        Always keeps the most recent messages.
        A "turn" = one user message + one assistant message = 2 entries.
        """
        max_messages = max_turns * 2
        if len(self.history) > max_messages:
            self.history = self.history[-max_messages:]

    def push_canvas(self, html: str) -> None:
        """Queue an HTML update for the canvas panel."""
        self.canvas_updates.append(html)

    def pop_canvas_updates(self) -> list[str]:
        """Return and clear all pending canvas updates."""
        updates = self.canvas_updates[:]
        self.canvas_updates.clear()
        return updates

    def clear(self) -> None:
        """Reset session history (e.g., /reset command)."""
        self.history = []
        self.touch()

    def history_length(self) -> int:
        """Return count of messages in history."""
        return len(self.history)

    def get_messages_for_api(self) -> list[dict[str, Any]]:
        """Return history as list of API-format message dicts."""
        return [msg.to_api_dict() for msg in self.history]


class SessionStore:
    """
    Thread-safe (single-process async) session store.
    Each session_id gets its own isolated Session object.
    """

    def __init__(self, max_history_turns: int = 20) -> None:
        self._sessions: dict[str, Session] = {}
        self.max_history_turns = max_history_turns

    def get_or_create(self, session_id: str) -> Session:
        """Return existing session or create a new isolated one."""
        session_id = str(session_id)
        if session_id not in self._sessions:
            self._sessions[session_id] = Session(session_id=session_id)
        return self._sessions[session_id]

    def get(self, session_id: str) -> Optional[Session]:
        """Return session if it exists, else None."""
        return self._sessions.get(str(session_id))

    def reset(self, session_id: str) -> None:
        """Clear history for a session (keep session object)."""
        session = self.get(str(session_id))
        if session:
            session.clear()

    def delete(self, session_id: str) -> None:
        """Remove session entirely."""
        self._sessions.pop(str(session_id), None)

    def history_length(self, session_id: str) -> int:
        """Return number of messages in the session's history (0 if not found)."""
        session = self.get(str(session_id))
        return session.history_length() if session else 0

    def list_sessions(self) -> list[str]:
        """Return list of active session IDs."""
        return list(self._sessions.keys())

    def compact_all(self) -> None:
        """Compact all sessions to max_history_turns."""
        for session in self._sessions.values():
            session.compact(self.max_history_turns)
