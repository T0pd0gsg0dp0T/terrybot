"""
tests/test_auth.py — Tests for security/auth.py token verification and rate limiting.
"""
from __future__ import annotations

import json
import time

from security.auth import (
    LOCKOUT_THRESHOLD,
    RateLimiter,
    verify_token,
)


def make_rl(tmp_path, monkeypatch) -> RateLimiter:
    lockout_path = tmp_path / "lockouts.json"
    monkeypatch.setattr("security.auth.LOCKOUT_FILE", lockout_path)
    return RateLimiter()


def test_valid_token_passes(tmp_path, monkeypatch):
    rl = make_rl(tmp_path, monkeypatch)
    result = verify_token("my-secret", "my-secret", "127.0.0.1", rl)
    assert result.success


def test_invalid_token_fails(tmp_path, monkeypatch):
    rl = make_rl(tmp_path, monkeypatch)
    result = verify_token("wrong", "my-secret", "127.0.0.1", rl)
    assert not result.success
    assert rl._clients.get("127.0.0.1") is not None
    assert rl._clients["127.0.0.1"].fail_count == 1


def test_five_failures_trigger_lockout(tmp_path, monkeypatch):
    rl = make_rl(tmp_path, monkeypatch)
    for _ in range(LOCKOUT_THRESHOLD):
        verify_token("wrong", "real-token", "10.0.0.1", rl)
    locked, remaining = rl.is_locked_out("10.0.0.1")
    assert locked
    assert remaining > 0


def test_lockout_persists_across_restart(tmp_path, monkeypatch):
    lockout_path = tmp_path / "lockouts.json"
    monkeypatch.setattr("security.auth.LOCKOUT_FILE", lockout_path)

    rl1 = RateLimiter()
    for _ in range(LOCKOUT_THRESHOLD):
        verify_token("wrong", "real-token", "192.168.1.1", rl1)

    assert lockout_path.exists(), "lockouts.json should be written after lockout"

    # Simulate restart — new RateLimiter reads from file
    rl2 = RateLimiter()
    locked, remaining = rl2.is_locked_out("192.168.1.1")
    assert locked, "Lockout should persist across RateLimiter restart"
    assert remaining > 0


def test_failure_file_not_written_before_lockout_threshold(tmp_path, monkeypatch):
    """lockouts.json should only be written when a lockout is triggered, not on every failure."""
    lockout_path = tmp_path / "lockouts.json"
    monkeypatch.setattr("security.auth.LOCKOUT_FILE", lockout_path)

    rl = RateLimiter()
    # Fail once — below threshold
    verify_token("wrong", "real-token", "172.16.0.1", rl)
    assert not lockout_path.exists(), "lockouts.json should NOT be written before threshold"

    # Reach threshold — now the file should appear
    for _ in range(LOCKOUT_THRESHOLD - 1):
        verify_token("wrong", "real-token", "172.16.0.1", rl)
    assert lockout_path.exists(), "lockouts.json should be written when lockout is triggered"
