"""
tests/test_delivery.py — Tests for bot/delivery.py DeliveryManager.
"""
from __future__ import annotations

import asyncio

from bot.delivery import DeliveryManager, _PENDING_BUFFER_CAP


async def test_web_delivery_to_registered_queue():
    dm = DeliveryManager()
    q = dm.register_web_client()

    await dm.deliver("web_abc", "hello web")

    assert not q.empty()
    payload = q.get_nowait()
    assert payload["message"] == "hello web"
    assert payload["session_id"] == "web_abc"


async def test_offline_buffer_when_no_clients():
    dm = DeliveryManager()

    await dm.deliver("web_abc", "buffered message")

    # Nothing in any queue (no registered clients)
    assert "web_abc" in dm._pending
    assert "buffered message" in dm._pending["web_abc"]


async def test_flush_pending_on_reconnect():
    dm = DeliveryManager()

    # Buffer a message while offline
    await dm.deliver("web_abc", "you were away")
    assert dm._pending.get("web_abc")

    # Now client connects
    q = dm.register_web_client()
    dm.flush_all_pending_to_web(q)

    # Pending should be cleared and message should be in queue
    assert not dm._pending
    payload = q.get_nowait()
    assert payload["message"] == "you were away"


async def test_pending_buffer_cap_drops_oldest():
    """Buffer should not grow beyond _PENDING_BUFFER_CAP; oldest message is dropped."""
    dm = DeliveryManager()

    for i in range(_PENDING_BUFFER_CAP + 5):
        await dm.deliver("web_offline", f"msg{i}")

    buf = dm._pending["web_offline"]
    assert len(buf) == _PENDING_BUFFER_CAP
    # Oldest messages were dropped; most recent should be present
    assert buf[-1] == f"msg{_PENDING_BUFFER_CAP + 4}"
    assert "msg0" not in buf


async def test_telegram_notify_callback_called():
    dm = DeliveryManager()
    calls = []

    async def fake_notify(session_id, message):
        calls.append((session_id, message))

    dm.set_telegram_notify(fake_notify)
    await dm.deliver("123456789", "hi telegram")

    assert len(calls) == 1
    assert calls[0] == ("123456789", "hi telegram")
