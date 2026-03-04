"""
agent/session.py — Per-user session isolation and history management.

Each session is keyed by a unique session_id (Telegram user ID or web UUID).
Sessions are fully isolated — no cross-session history leakage.
History is compacted to max_turns when it grows too large.
"""

from __future__ import annotations

import sqlite3
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
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
    model: Optional[str] = None        # per-session model override (None = use global)

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

    def all_sessions(self) -> dict[str, "Session"]:
        """Return a snapshot of all sessions (used by dashboard)."""
        return dict(self._sessions)

    def flush(self, session_id: str) -> None:
        """No-op: in-memory store needs no persistence."""

    def compact_all(self) -> None:
        """Compact all sessions to max_history_turns."""
        for session in self._sessions.values():
            session.compact(self.max_history_turns)


class PersistentSessionStore:
    """
    SQLite-backed session store. Same interface as SessionStore.
    Sessions are loaded from DB on first access and flushed on every mutation.
    """

    DB_PATH = Path.home() / ".terrybot" / "sessions.db"

    def __init__(self, max_history_turns: int = 20) -> None:
        self.max_history_turns = max_history_turns
        self._cache: dict[str, Session] = {}
        self._db = self._open_db()

    def _open_db(self) -> sqlite3.Connection:
        self.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(str(self.DB_PATH), check_same_thread=False)
        db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                ts REAL NOT NULL
            )
        """)
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_sid ON messages(session_id, ts)"
        )
        db.execute("""
            CREATE TABLE IF NOT EXISTS session_meta (
                session_id TEXT PRIMARY KEY,
                model TEXT,
                pending_command TEXT
            )
        """)
        db.commit()
        return db

    def _load_from_db(self, session_id: str) -> Session:
        session = Session(session_id=session_id)
        rows = self._db.execute(
            "SELECT role, content FROM messages WHERE session_id=? ORDER BY ts",
            (session_id,),
        ).fetchall()
        for role, content in rows:
            session.history.append(Message(role=role, content=content))
        # Restore session metadata
        meta = self._db.execute(
            "SELECT model, pending_command FROM session_meta WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if meta:
            session.model = meta[0] or None
            session.pending_command = meta[1] or None
        return session

    def _flush(self, session_id: str) -> None:
        """Write-through: replace all rows for this session."""
        session = self._cache.get(session_id)
        if session is None:
            return
        # Persist messages
        self._db.execute("DELETE FROM messages WHERE session_id=?", (session_id,))
        now = time.time()
        self._db.executemany(
            "INSERT INTO messages (session_id, role, content, ts) VALUES (?, ?, ?, ?)",
            [
                (session_id, m.role, m.content, now + i * 1e-6)
                for i, m in enumerate(session.history)
            ],
        )
        # Persist session metadata (model override, pending command)
        self._db.execute(
            "INSERT OR REPLACE INTO session_meta (session_id, model, pending_command) "
            "VALUES (?, ?, ?)",
            (session_id, session.model, session.pending_command),
        )
        self._db.commit()

    def get_or_create(self, session_id: str) -> Session:
        session_id = str(session_id)
        if session_id not in self._cache:
            self._cache[session_id] = self._load_from_db(session_id)
        return self._cache[session_id]

    def get(self, session_id: str) -> Optional[Session]:
        session_id = str(session_id)
        if session_id not in self._cache:
            # Check DB to see if it exists
            row = self._db.execute(
                "SELECT 1 FROM messages WHERE session_id=? LIMIT 1", (session_id,)
            ).fetchone()
            if row is None:
                return None
            self._cache[session_id] = self._load_from_db(session_id)
        return self._cache.get(session_id)

    def reset(self, session_id: str) -> None:
        """Clear history for a session (keep session object)."""
        session = self.get(str(session_id))
        if session:
            session.clear()
            self._flush(str(session_id))

    def delete(self, session_id: str) -> None:
        """Remove session from cache and DB."""
        session_id = str(session_id)
        self._cache.pop(session_id, None)
        self._db.execute("DELETE FROM messages WHERE session_id=?", (session_id,))
        self._db.execute("DELETE FROM session_meta WHERE session_id=?", (session_id,))
        self._db.commit()

    def history_length(self, session_id: str) -> int:
        session = self.get(str(session_id))
        return session.history_length() if session else 0

    def list_sessions(self) -> list[str]:
        """Return list of session IDs with at least one message."""
        rows = self._db.execute(
            "SELECT DISTINCT session_id FROM messages"
        ).fetchall()
        # Merge with in-memory cache (may have sessions with empty history)
        db_ids = {row[0] for row in rows}
        cache_ids = set(self._cache.keys())
        return list(db_ids | cache_ids)

    def all_sessions(self) -> dict[str, "Session"]:
        """Return snapshot of all sessions — loads from DB any not yet in cache."""
        rows = self._db.execute(
            "SELECT DISTINCT session_id FROM messages"
        ).fetchall()
        for (sid,) in rows:
            if sid not in self._cache:
                self._cache[sid] = self._load_from_db(sid)
        return dict(self._cache)

    def flush(self, session_id: str) -> None:
        """Public flush: write session to SQLite."""
        self._flush(str(session_id))

    def compact_all(self) -> None:
        for session_id, session in self._cache.items():
            session.compact(self.max_history_turns)
            self._flush(session_id)
