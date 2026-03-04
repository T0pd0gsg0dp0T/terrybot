"""
tests/test_tools.py — Tests for agent/tools.py built-in tools.
"""
from __future__ import annotations

from agent.context import ToolContext
from agent.tools import (
    _sessions_in_flight,
    get_datetime,
    load_note,
    save_note,
    sessions_send,
)


# ── get_datetime ───────────────────────────────────────────────────────────────

def test_get_datetime_returns_iso8601():
    result = get_datetime()
    # Basic ISO 8601 check — should contain 'T' and look like a timestamp
    assert "T" in result
    assert len(result) >= 19  # at least "YYYY-MM-DDTHH:MM:SS"


# ── save_note / load_note ──────────────────────────────────────────────────────

def test_save_and_load_note_round_trip(tmp_path, monkeypatch):
    """save_note then load_note should return the same content."""
    import crypto

    # Redirect the credential store to a temp dir
    monkeypatch.setattr(crypto, "TERRYBOT_DIR", tmp_path)
    monkeypatch.setattr(crypto, "CREDS_DIR", tmp_path / "creds")

    result = save_note("test_key", "hello world")
    assert "saved" in result.lower()

    loaded = load_note("test_key")
    assert loaded == "hello world"


def test_save_note_invalid_key():
    result = save_note("bad key!", "content")
    assert "error" in result.lower()


def test_load_note_missing_key(tmp_path, monkeypatch):
    import crypto
    monkeypatch.setattr(crypto, "TERRYBOT_DIR", tmp_path)
    monkeypatch.setattr(crypto, "CREDS_DIR", tmp_path / "creds")

    result = load_note("nonexistent_key")
    assert "no note" in result.lower() or "not found" in result.lower()


# ── fetch_url SSRF block ───────────────────────────────────────────────────────

async def test_fetch_url_blocks_loopback():
    from agent.tools import fetch_url
    result = await fetch_url("http://127.0.0.1/")
    assert "error" in result.lower() or "blocked" in result.lower() or "ssrf" in result.lower()


async def test_fetch_url_blocks_private_ip():
    from agent.tools import fetch_url
    result = await fetch_url("http://192.168.1.1/")
    assert "error" in result.lower() or "blocked" in result.lower() or "ssrf" in result.lower()


# ── sessions_send deadlock guard ───────────────────────────────────────────────

async def test_sessions_send_blocks_self_send(fake_runner, settings):
    ctx = ToolContext(session_id="alice", runner=fake_runner, settings=settings)
    result = await sessions_send(ctx, "alice", "hello self")
    assert "loop" in result.lower() or "cannot" in result.lower()


async def test_sessions_send_blocks_circular(fake_runner, settings):
    """Simulate A→B→A loop: when B tries to send back to A, in_flight should block it."""
    ctx_b = ToolContext(session_id="bob", runner=fake_runner, settings=settings)

    # Simulate being inside a send from alice — mark alice as in-flight
    token = _sessions_in_flight.set(frozenset({"alice"}))
    try:
        result = await sessions_send(ctx_b, "alice", "reply back to alice")
        assert "loop" in result.lower() or "cannot" in result.lower()
    finally:
        _sessions_in_flight.reset(token)


async def test_sessions_send_allows_normal_send(fake_runner, settings):
    ctx = ToolContext(session_id="alice", runner=fake_runner, settings=settings)
    result = await sessions_send(ctx, "bob", "hello bob")
    assert result  # got a response
