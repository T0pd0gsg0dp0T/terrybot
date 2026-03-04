"""
bot/delivery.py — Heartbeat/scheduler message delivery to live channels.

DeliveryManager routes outbound messages (from scheduler jobs or proactive
heartbeats) to whichever channel the target session is reachable on:
  - Active WebSocket connections: put on per-client asyncio.Queue (broadcast)
  - Telegram sessions (numeric IDs): via Telegram bot API
  - All others: buffered in memory until a web client connects

The web bot registers/unregisters its clients via register_web_client() and
unregister_web_client().  The Telegram callback is wired in at startup.
"""

from __future__ import annotations

import asyncio
import sys
from collections import defaultdict
from typing import Any, Callable, Coroutine, Optional


class DeliveryManager:
    """Routes scheduled/heartbeat messages to live channels."""

    def __init__(self) -> None:
        # All currently connected WebSocket client queues
        self._web_queues: list[asyncio.Queue] = []
        # Buffered messages for sessions with no active WebSocket
        self._pending: dict[str, list[str]] = defaultdict(list)
        # Optional Telegram send callback (wired in main.py)
        self._telegram_notify: Optional[Callable[[str, str], Coroutine[Any, Any, None]]] = None

    # ── Registration ──────────────────────────────────────────────────────────

    def set_telegram_notify(
        self,
        callback: Callable[[str, str], Coroutine[Any, Any, None]],
    ) -> None:
        """Set async callback for Telegram delivery: callback(session_id, text)."""
        self._telegram_notify = callback

    def register_web_client(self) -> asyncio.Queue:
        """Register a new WebSocket client. Returns its private delivery queue."""
        q: asyncio.Queue = asyncio.Queue()
        self._web_queues.append(q)
        return q

    def unregister_web_client(self, q: asyncio.Queue) -> None:
        """Remove a disconnected WebSocket client's queue."""
        try:
            self._web_queues.remove(q)
        except ValueError:
            pass

    # ── Delivery ─────────────────────────────────────────────────────────────

    async def deliver(self, session_id: str, message: str) -> None:
        """
        Deliver a message to a session.
        Tries Telegram for numeric IDs, then broadcasts to web, then buffers.
        """
        # Telegram: numeric session IDs (individual users or group IDs)
        if session_id.lstrip("-").isdigit() and self._telegram_notify:
            try:
                await self._telegram_notify(session_id, message)
                return
            except Exception as e:
                print(
                    f"[delivery] Telegram notify failed for {session_id!r}: {type(e).__name__}",
                    file=sys.stderr,
                )

        # Web broadcast: push to all connected clients
        if self._web_queues:
            payload = {"session_id": session_id, "message": message}
            for q in list(self._web_queues):
                try:
                    q.put_nowait(payload)
                except asyncio.QueueFull:
                    pass
            return

        # No active channel — buffer for later delivery
        self._pending[session_id].append(message)
        print(
            f"[delivery] Buffered message for offline session {session_id!r}",
            file=sys.stderr,
        )

    def flush_pending(self, session_id: str) -> list[str]:
        """Return and clear buffered messages for a session (called on web connect)."""
        return self._pending.pop(session_id, [])

    def flush_all_pending_to_web(self, q: asyncio.Queue) -> None:
        """Push all buffered messages to a newly connected WebSocket client."""
        for sid, messages in list(self._pending.items()):
            for msg in messages:
                try:
                    q.put_nowait({"session_id": sid, "message": msg})
                except asyncio.QueueFull:
                    break
        self._pending.clear()
