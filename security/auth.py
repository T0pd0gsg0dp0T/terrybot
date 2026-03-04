"""
security/auth.py — Timing-safe token authentication + rate limiter.

Policy:
  - 5 consecutive failures from a single IP → 15-minute lockout
  - Both tokens are HMAC-SHA256'd before comparison, normalizing length to 32
    bytes. This prevents timing oracles that leak token length.
  - Lockout state is in-memory (resets on process restart — acceptable for
    personal use on a single machine).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


LOCKOUT_THRESHOLD = 5          # failures before lockout
LOCKOUT_DURATION = 15 * 60    # seconds (15 minutes)

LOCKOUT_FILE = Path.home() / ".terrybot" / "lockouts.json"

# Static HMAC key for length-normalizing comparison. Not a secret —
# its purpose is to produce fixed-length (32-byte) digests so that
# secrets.compare_digest can't be used as a length oracle.
_COMPARE_KEY = b"terrybot-auth-compare-v1"

# Hard cap on token length processed by HMAC to prevent DoS via huge input.
# Generated tokens are 64 hex chars; 1024 is a generous ceiling.
_MAX_TOKEN_LEN = 1024


def _normalize_token(token: str) -> bytes:
    """
    HMAC-SHA256 a token to produce a fixed-length 32-byte digest.
    This makes secrets.compare_digest length-invariant: regardless of
    how long `token` is, the comparison is always over 32 bytes.
    Input is capped at _MAX_TOKEN_LEN to prevent HMAC DoS.
    """
    return hmac.new(_COMPARE_KEY, token[:_MAX_TOKEN_LEN].encode("utf-8"), hashlib.sha256).digest()


@dataclass
class _ClientState:
    fail_count: int = 0
    lockout_until: float = 0.0  # monotonic seconds


@dataclass
class AuthResult:
    success: bool
    reason: str = ""
    locked_out: bool = False
    lockout_remaining: float = 0.0  # seconds remaining if locked out


class RateLimiter:
    """Per-IP failure tracking with automatic lockout (persisted across restarts)."""

    def __init__(
        self,
        threshold: int = LOCKOUT_THRESHOLD,
        lockout_duration: float = LOCKOUT_DURATION,
    ) -> None:
        self._threshold = threshold
        self._lockout_duration = lockout_duration
        self._clients: dict[str, _ClientState] = {}
        self._load_lockouts()

    def _load_lockouts(self) -> None:
        """Restore any active lockouts from disk on startup."""
        if not LOCKOUT_FILE.exists():
            return
        try:
            data = json.loads(LOCKOUT_FILE.read_text())
            now_wall = time.time()
            now_mono = time.monotonic()
            for ip, wall_until in data.items():
                if wall_until > now_wall:  # still active
                    mono_until = now_mono + (wall_until - now_wall)
                    self._clients[ip] = _ClientState(
                        fail_count=LOCKOUT_THRESHOLD,
                        lockout_until=mono_until,
                    )
        except Exception:
            pass

    def _save_lockouts(self) -> None:
        """Persist active lockouts to disk."""
        now_wall = time.time()
        now_mono = time.monotonic()
        data: dict[str, float] = {}
        for ip, state in self._clients.items():
            if state.lockout_until > now_mono:
                wall_until = now_wall + (state.lockout_until - now_mono)
                data[ip] = wall_until
        try:
            LOCKOUT_FILE.parent.mkdir(parents=True, exist_ok=True)
            LOCKOUT_FILE.write_text(json.dumps(data))
            LOCKOUT_FILE.chmod(0o600)
        except Exception:
            pass

    def _state(self, client_ip: str) -> _ClientState:
        if client_ip not in self._clients:
            self._clients[client_ip] = _ClientState()
        return self._clients[client_ip]

    def is_locked_out(self, client_ip: str) -> tuple[bool, float]:
        """Return (locked, seconds_remaining)."""
        state = self._state(client_ip)
        now = time.monotonic()
        if state.lockout_until > now:
            return True, state.lockout_until - now
        return False, 0.0

    def record_failure(self, client_ip: str) -> None:
        state = self._state(client_ip)
        state.fail_count += 1
        if state.fail_count >= self._threshold:
            state.lockout_until = time.monotonic() + self._lockout_duration
            print(
                f"[auth] SECURITY: client locked out for {self._lockout_duration}s "
                f"after {state.fail_count} failed auth attempts",
                file=sys.stderr,
            )
            self._save_lockouts()  # persist only when a lockout is triggered

    def record_success(self, client_ip: str) -> None:
        """Reset failure counter on successful auth."""
        if client_ip in self._clients:
            self._clients[client_ip] = _ClientState()


# Module-level singleton shared across the web server
_rate_limiter = RateLimiter()


def verify_token(
    provided_token: str,
    stored_token: str,
    client_ip: str,
    rate_limiter: Optional[RateLimiter] = None,
) -> AuthResult:
    """
    Validate `provided_token` against `stored_token` in a timing-safe way.

    Both tokens are HMAC-SHA256'd to a fixed 32-byte length before comparison,
    making the comparison time independent of token length.

    Args:
        provided_token: Token submitted by the client.
        stored_token:   The expected token from the credential store.
        client_ip:      Client IP string for rate-limiting.
        rate_limiter:   Optional custom RateLimiter; defaults to module singleton.

    Returns:
        AuthResult with success status and reason.
    """
    rl = rate_limiter or _rate_limiter

    locked, remaining = rl.is_locked_out(client_ip)
    if locked:
        return AuthResult(
            success=False,
            reason="Too many failed attempts. Try again later.",
            locked_out=True,
            lockout_remaining=remaining,
        )

    # Always normalise to fixed length before compare — prevents length oracle.
    # We do this even for empty tokens so timing is consistent.
    provided_digest = _normalize_token(provided_token or "")
    stored_digest = _normalize_token(stored_token or "")

    # An empty stored_token means auth is not configured — always fail.
    if not stored_token:
        rl.record_failure(client_ip)
        print(f"[auth] Failed auth: stored token is not configured", file=sys.stderr)
        return AuthResult(success=False, reason="Invalid token.")

    match = secrets.compare_digest(provided_digest, stored_digest)

    if match:
        rl.record_success(client_ip)
        return AuthResult(success=True, reason="Authenticated.")
    else:
        rl.record_failure(client_ip)
        print(f"[auth] Failed auth: token mismatch", file=sys.stderr)
        return AuthResult(success=False, reason="Invalid token.")


def generate_auth_token(byte_length: int = 32) -> str:
    """Generate a cryptographically secure hex auth token."""
    return secrets.token_hex(byte_length)


def get_rate_limiter() -> RateLimiter:
    """Return the module-level rate limiter singleton."""
    return _rate_limiter
