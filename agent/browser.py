"""
agent/browser.py — Playwright/Chromium singleton manager for Terrybot.

BrowserManager is a module-level singleton.
Per-session pages are isolated in _pages dict keyed by session_id.
Chromium is launched headless on first tool call (lazy init).
"""

from __future__ import annotations

import sys
from typing import Optional


class BrowserManager:
    """
    Singleton manager for a shared Playwright Chromium instance.
    Each session gets its own isolated Page.
    """

    _instance: Optional["BrowserManager"] = None

    def __init__(self) -> None:
        self._playwright = None
        self._browser = None
        self._pages: dict[str, object] = {}

    @classmethod
    async def get_instance(cls) -> "BrowserManager":
        """Return the singleton, initializing Playwright on first call."""
        if cls._instance is None:
            cls._instance = cls()
            await cls._instance._init()
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

    async def get_or_create_page(self, session_id: str):
        """Return existing page for session or create a new one."""
        if session_id not in self._pages:
            if self._browser is None:
                raise RuntimeError("Browser not initialized.")
            page = await self._browser.new_page()
            self._pages[session_id] = page
        return self._pages[session_id]

    async def close_session_page(self, session_id: str) -> None:
        """Close and remove the page for a session."""
        page = self._pages.pop(session_id, None)
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
