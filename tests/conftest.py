"""
tests/conftest.py — Shared fixtures for Terrybot test suite.
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent.session import Session, SessionStore
from config import (
    AgentConfig,
    GmailConfig,
    LocationConfig,
    NotificationConfig,
    OpenRouterConfig,
    SchedulerConfig,
    Settings,
    TelegramConfig,
    WebConfig,
)


@pytest.fixture
def settings() -> Settings:
    """Minimal Settings object with test values."""
    return Settings(
        openrouter=OpenRouterConfig(api_key="test-key", model="anthropic/claude-sonnet-4-6"),
        telegram=TelegramConfig(bot_token="", allowed_user_ids=[]),
        web=WebConfig(host="127.0.0.1", port=8765, auth_token="test-web-token"),
        agent=AgentConfig(model="anthropic/claude-sonnet-4-6", max_history_turns=20, persist_sessions=False),
        scheduler=SchedulerConfig(jobs=[]),
        gmail=GmailConfig(enabled=False),
        notifications=NotificationConfig(enabled=False),
        location=LocationConfig(),
    )


@pytest.fixture
def tmp_terrybot(tmp_path, monkeypatch):
    """Redirect ~/.terrybot to a temp directory."""
    monkeypatch.setattr("agent.session.PersistentSessionStore.DB_PATH", tmp_path / "sessions.db")
    monkeypatch.setattr("security.auth.LOCKOUT_FILE", tmp_path / "lockouts.json")
    return tmp_path


@pytest.fixture
def session_store() -> SessionStore:
    return SessionStore(max_history_turns=10)


class FakeSessionStore:
    """Minimal in-memory session store for runner mocking."""

    def __init__(self):
        self._sessions: dict[str, Session] = {}

    def get_or_create(self, session_id: str) -> Session:
        if session_id not in self._sessions:
            self._sessions[session_id] = Session(session_id=session_id)
        return self._sessions[session_id]

    def get(self, session_id: str):
        return self._sessions.get(session_id)

    def reset(self, session_id: str):
        s = self.get(session_id)
        if s:
            s.clear()

    def delete(self, session_id: str):
        self._sessions.pop(session_id, None)

    def history_length(self, session_id: str) -> int:
        s = self.get(session_id)
        return s.history_length() if s else 0

    def list_sessions(self):
        return list(self._sessions.keys())


class FakeRunner:
    """Minimal LLMRunner stand-in for tool tests."""

    def __init__(self, settings):
        self._settings = settings
        self._sessions = FakeSessionStore()

    async def run_turn(self, session_id: str, message: str) -> str:
        return f"[fake response to: {message[:50]}]"

    def reset_session(self, session_id: str):
        self._sessions.delete(session_id)

    def delete_session(self, session_id: str):
        self._sessions.delete(session_id)

    def get_session_history_turns(self, session_id: str) -> int:
        return self._sessions.history_length(session_id) // 2


@pytest.fixture
def fake_runner(settings) -> FakeRunner:
    return FakeRunner(settings=settings)
