"""
agent/browser.py — Playwright/Chromium singleton manager for Terrybot.

BrowserManager is a module-level singleton.
Per-session pages are isolated in _pages dict keyed by session_id.
Chromium is launched headless on first tool call (lazy init).
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any, Optional

MAX_BROWSER_PAGES = 10  # max concurrent open pages; oldest evicted when exceeded

# Guards the singleton lazy-init to prevent two concurrent first-callers
# from each launching a Chromium process.
_init_lock = asyncio.Lock()


class BrowserManager:
    """
    Singleton manager for a shared Playwright Chromium instance.
    Each session gets its own isolated Page; capped at MAX_BROWSER_PAGES.
    Page creation order is tracked for LRU eviction.
    """

    _instance: Optional["BrowserManager"] = None

    def __init__(self) -> None:
        self._playwright: Optional[Any] = None  # playwright.async_api.Playwright
        self._browser: Optional[Any] = None     # playwright.async_api.Browser
        self._pages: dict[str, Any] = {}
        self._page_order: list[str] = []  # insertion order for LRU eviction

    @classmethod
    async def get_instance(cls) -> "BrowserManager":
        """Return the singleton, initializing Playwright on first call."""
        async with _init_lock:
            if cls._instance is None:
                instance = cls()
                await instance._init()
                cls._instance = instance
        return cls._instance

    async def _init(self) -> None:
        """Launch Playwright and Chromium headless."""
        try:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(headless=True)
            print("[browser] Chromium launched (headless).", file=sys.stderr)
        except Exception as e:
            print(f"[browser] Failed to launch Chromium: {type(e).__name__}: {e}", file=sys.stderr)
            raise

    async def get_or_create_page(self, session_id: str) -> Any:
        """Return existing page for session, or create one (evicting oldest if at cap)."""
        if session_id not in self._pages:
            if self._browser is None:
                raise RuntimeError("Browser not initialized.")
            # Evict the oldest page if at capacity
            if len(self._pages) >= MAX_BROWSER_PAGES and self._page_order:
                oldest = self._page_order[0]
                await self.close_session_page(oldest)
                print(
                    f"[browser] Page cap reached — closed oldest session page {oldest!r}",
                    file=sys.stderr,
                )
            page = await self._browser.new_page()
            self._pages[session_id] = page
            self._page_order.append(session_id)
        return self._pages[session_id]

    async def close_session_page(self, session_id: str) -> None:
        """Close and remove the page for a session."""
        page = self._pages.pop(session_id, None)
        try:
            self._page_order.remove(session_id)
        except ValueError:
            pass
        if page is not None:
            try:
                await page.close()
            except Exception:
                pass

    async def close(self) -> None:
        """Close all pages and the browser."""
        for session_id in list(self._pages):
            await self.close_session_page(session_id)
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
        BrowserManager._instance = None


async def get_browser_manager() -> BrowserManager:
    """Module-level convenience function to get the singleton."""
    return await BrowserManager.get_instance()
