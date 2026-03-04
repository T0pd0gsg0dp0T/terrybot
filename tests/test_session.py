"""
tests/test_session.py — Tests for agent/session.py SessionStore and PersistentSessionStore.
"""
from __future__ import annotations

from agent.session import PersistentSessionStore, Session, SessionStore


# ── In-memory SessionStore ─────────────────────────────────────────────────────

def test_get_or_create_new():
    store = SessionStore(max_history_turns=10)
    session = store.get_or_create("alice")
    assert isinstance(session, Session)
    assert session.session_id == "alice"


def test_get_or_create_idempotent():
    store = SessionStore(max_history_turns=10)
    s1 = store.get_or_create("alice")
    s2 = store.get_or_create("alice")
    assert s1 is s2


def test_add_message():
    store = SessionStore(max_history_turns=10)
    session = store.get_or_create("bob")
    session.add_message("user", "hello")
    session.add_message("assistant", "hi there")
    assert len(session.history) == 2
    assert session.history[0].role == "user"
    assert session.history[1].role == "assistant"


def test_compact_trims_history():
    store = SessionStore(max_history_turns=2)
    session = store.get_or_create("carol")
    for i in range(6):
        session.add_message("user" if i % 2 == 0 else "assistant", f"msg{i}")
    session.compact(max_turns=2)
    assert len(session.history) <= 4  # 2 turns × 2 messages


def test_delete_removes_session():
    store = SessionStore(max_history_turns=10)
    store.get_or_create("dave")
    store.delete("dave")
    assert store.get("dave") is None


def test_all_sessions_returns_snapshot():
    store = SessionStore(max_history_turns=10)
    store.get_or_create("eve")
    store.get_or_create("frank")
    snap = store.all_sessions()
    assert "eve" in snap
    assert "frank" in snap


def test_flush_is_noop_for_memory_store():
    store = SessionStore(max_history_turns=10)
    store.get_or_create("grace")
    store.flush("grace")  # should not raise


# ── PersistentSessionStore ─────────────────────────────────────────────────────

def test_persistent_store_round_trip(tmp_path, monkeypatch):
    db_path = tmp_path / "sessions.db"
    monkeypatch.setattr(PersistentSessionStore, "DB_PATH", db_path)

    store = PersistentSessionStore(max_history_turns=10)
    session = store.get_or_create("user1")
    session.add_message("user", "hello persistent")
    store.flush("user1")  # use public API

    # Open a fresh store — should reload from DB
    store2 = PersistentSessionStore(max_history_turns=10)
    session2 = store2.get_or_create("user1")
    assert any(m.content == "hello persistent" for m in session2.history)


def test_persistent_store_all_sessions_includes_prior_run(tmp_path, monkeypatch):
    """all_sessions() should surface sessions from the DB, not just the current cache."""
    db_path = tmp_path / "sessions.db"
    monkeypatch.setattr(PersistentSessionStore, "DB_PATH", db_path)

    # First process: write a session to DB
    store1 = PersistentSessionStore(max_history_turns=10)
    s = store1.get_or_create("prior_run")
    s.add_message("user", "hi from last time")
    store1.flush("prior_run")

    # Second process: fresh store — cache is empty, but all_sessions should load from DB
    store2 = PersistentSessionStore(max_history_turns=10)
    snap = store2.all_sessions()
    assert "prior_run" in snap
    assert any(m.content == "hi from last time" for m in snap["prior_run"].history)


def test_persistent_store_model_and_pending_command_persisted(tmp_path, monkeypatch):
    """model override and pending_command should survive a store restart."""
    db_path = tmp_path / "sessions.db"
    monkeypatch.setattr(PersistentSessionStore, "DB_PATH", db_path)

    store = PersistentSessionStore(max_history_turns=10)
    session = store.get_or_create("meta_user")
    session.model = "openai/gpt-4o"
    session.pending_command = "ls -la"
    session.add_message("user", "test")
    store.flush("meta_user")

    # Reload from DB
    store2 = PersistentSessionStore(max_history_turns=10)
    session2 = store2.get_or_create("meta_user")
    assert session2.model == "openai/gpt-4o"
    assert session2.pending_command == "ls -la"


def test_persistent_store_delete_removes_meta(tmp_path, monkeypatch):
    """delete() should clean up session_meta rows too."""
    import sqlite3 as _sqlite3
    db_path = tmp_path / "sessions.db"
    monkeypatch.setattr(PersistentSessionStore, "DB_PATH", db_path)

    store = PersistentSessionStore(max_history_turns=10)
    session = store.get_or_create("to_delete")
    session.model = "anthropic/claude-haiku-4-5"
    session.add_message("user", "bye")
    store.flush("to_delete")
    store.delete("to_delete")

    conn = _sqlite3.connect(str(db_path))
    meta_count = conn.execute(
        "SELECT COUNT(*) FROM session_meta WHERE session_id='to_delete'"
    ).fetchone()[0]
    msg_count = conn.execute(
        "SELECT COUNT(*) FROM messages WHERE session_id='to_delete'"
    ).fetchone()[0]
    conn.close()
    assert meta_count == 0
    assert msg_count == 0


def test_persistent_store_get_finds_meta_only_session(tmp_path, monkeypatch):
    """get() should find a session that has metadata but no messages."""
    db_path = tmp_path / "sessions.db"
    monkeypatch.setattr(PersistentSessionStore, "DB_PATH", db_path)

    store = PersistentSessionStore(max_history_turns=10)
    session = store.get_or_create("meta_only")
    session.model = "openai/gpt-4o"
    store.flush("meta_only")

    # Fresh store — session is only in session_meta, not messages
    store2 = PersistentSessionStore(max_history_turns=10)
    found = store2.get("meta_only")
    assert found is not None
    assert found.model == "openai/gpt-4o"


def test_persistent_store_compact_prunes_db(tmp_path, monkeypatch):
    db_path = tmp_path / "sessions.db"
    monkeypatch.setattr(PersistentSessionStore, "DB_PATH", db_path)

    store = PersistentSessionStore(max_history_turns=2)
    session = store.get_or_create("user2")
    for i in range(6):
        session.add_message("user" if i % 2 == 0 else "assistant", f"msg{i}")
    session.compact(max_turns=2)
    store.flush("user2")

    # Verify DB has at most 4 rows for user2
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    count = conn.execute("SELECT COUNT(*) FROM messages WHERE session_id='user2'").fetchone()[0]
    conn.close()
    assert count <= 4
