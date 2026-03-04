"""
security/origin.py — WebSocket origin allowlist validator.

Prevents Cross-Site WebSocket Hijacking (CSWSH) by only allowing connections
from localhost origins. This is the fix for CVE-2026-25253 class vulnerabilities.

Allowed origins:
  - None / missing (direct connection, e.g., curl, native WebSocket clients)
  - http://localhost (any port)
  - http://127.0.0.1 (any port)
  - https://localhost (any port)   ← if serving over TLS locally
  - https://127.0.0.1 (any port)

Everything else is rejected with a 403.
"""

from __future__ import annotations

import re
import sys
from typing import Optional

# Allow http:// and https:// on localhost/127.0.0.1 with any port.
_ALLOWED_PATTERN = re.compile(
    r"^https?://(localhost|127\.0\.0\.1)(:\d{1,5})?$",
    re.IGNORECASE,
)


def validate_ws_origin(origin: Optional[str]) -> bool:
    """
    Return True if the WebSocket origin is permitted, False otherwise.

    Args:
        origin: The value of the HTTP `Origin` header, or None if absent.

    Returns:
        True if connection should be allowed, False if it should be rejected.
    """
    if origin is None:
        # No Origin header — direct/native client connection; allow
        return True

    origin = origin.strip()

    if _ALLOWED_PATTERN.match(origin):
        return True

    # Do NOT log the origin value — it is attacker-controlled and could
    # contain log-injection payloads (newlines, ANSI codes).
    print(
        "[origin] REJECTED WebSocket connection from non-localhost origin.",
        file=sys.stderr,
    )
    return False


def assert_ws_origin(origin: Optional[str]) -> None:
    """
    Raise ValueError if the origin is not permitted.
    Use in FastAPI WebSocket handlers where raising is cleaner than returning bool.
    """
    if not validate_ws_origin(origin):
        raise ValueError("WebSocket origin rejected: only localhost connections are permitted.")
