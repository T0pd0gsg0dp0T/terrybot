"""
bot/telegram_bot.py — Telegram channel handler for Terrybot.

Security:
  - Only responds to allowlisted Telegram user IDs (drop-silently policy)
  - Group mention-gating (only respond when @mentioned in groups)
  - Per-user rate limiting (20 requests/min)
  - No internal stack traces exposed to users
  - Responses split at 4096 chars (Telegram limit)
"""

from __future__ import annotations

import sys
import time
from collections import defaultdict
from typing import TYPE_CHECKING

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from agent.runner import LLMRunner
from agent.tools import execute_pending_command

if TYPE_CHECKING:
    from bot.delivery import DeliveryManager
    from config import Settings

TELEGRAM_MAX_MSG = 4096
RATE_LIMIT_REQUESTS = 20    # max requests
RATE_LIMIT_WINDOW = 60      # per N seconds


class _UserRateLimiter:
    """Simple sliding-window rate limiter for Telegram users."""

    def __init__(self, max_requests: int = RATE_LIMIT_REQUESTS, window: float = RATE_LIMIT_WINDOW) -> None:
        self._max = max_requests
        self._window = window
        self._timestamps: dict[int, list[float]] = defaultdict(list)

    def is_allowed(self, user_id: int) -> bool:
        now = time.monotonic()
        window_start = now - self._window
        # Evict expired timestamps, then check count
        valid = [t for t in self._timestamps[user_id] if t > window_start]
        self._timestamps[user_id] = valid
        if len(valid) >= self._max:
            return False
        self._timestamps[user_id].append(now)
        return True


def _split_message(text: str, max_len: int = TELEGRAM_MAX_MSG) -> list[str]:
    """Split long messages at paragraph boundaries where possible."""
    if len(text) <= max_len:
        return [text]
    parts: list[str] = []
    while text:
        if len(text) <= max_len:
            parts.append(text)
            break
        split_at = text.rfind("\n", 0, max_len)
        if split_at == -1:
            split_at = max_len
        parts.append(text[:split_at].rstrip())
        text = text[split_at:].lstrip()
    return parts


class TelegramBot:
    """Wraps python-telegram-bot Application with Terrybot security policies."""

    def __init__(self, settings: "Settings", runner: LLMRunner) -> None:
        self._settings = settings
        self._runner = runner
        self._allowed_ids: set[int] = set(settings.telegram.allowed_user_ids)
        self._allowed_group_ids: set[int] = set(settings.telegram.allowed_group_ids)
        self._rate_limiter = _UserRateLimiter()

    def _is_allowed(self, user_id: int) -> bool:
        return user_id in self._allowed_ids

    async def _handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Main message handler."""
        user = update.effective_user
        if user is None or update.message is None:
            return

        user_id = user.id
        chat = update.effective_chat
        if chat is None:
            return

        text = update.message.text or ""
        if not text.strip():
            return

        # Determine session_id and apply group vs DM gating
        is_group = chat.type in ("group", "supergroup")
        if is_group:
            if chat.id not in self._allowed_group_ids:
                return  # silent drop — unlisted group
            if self._settings.telegram.require_mention_in_groups:
                me = await context.bot.get_me()
                if f"@{me.username}" not in text:
                    return  # not mentioned — ignore
            session_id = f"group_{chat.id}"
        else:
            # DM — require allowlist
            if not self._is_allowed(user_id):
                print(f"[telegram] Rejected message from non-allowlisted user {user_id}", file=sys.stderr)
                return
            session_id = str(user_id)

        # Rate limit check (by user_id for both DMs and groups)
        if not self._rate_limiter.is_allowed(user_id):
            await update.message.reply_text("Too many requests. Please slow down.")
            return

        # --- Confirm/deny intercept for pending system_run commands ---
        session = self._runner._sessions.get(session_id)
        if session and session.pending_command:
            normalized = text.strip().lower()
            if normalized in ("confirm", "yes"):
                cmd = session.pending_command
                session.pending_command = None
                self._runner._sessions.flush(session_id)
                output = execute_pending_command(cmd)
                for chunk in _split_message(f"Output:\n{output}"):
                    await update.message.reply_text(chunk)
                return
            elif normalized in ("deny", "no", "cancel"):
                session.pending_command = None
                self._runner._sessions.flush(session_id)
                await update.message.reply_text("Command cancelled.")
                return
            else:
                await update.message.reply_text(
                    f"There is a pending command waiting for confirmation:\n"
                    f"`{session.pending_command}`\n"
                    "Reply 'confirm' to execute or 'deny' to cancel."
                )
                return

        # Typing indicator
        await context.bot.send_chat_action(
            chat_id=chat.id,
            action="typing",
        )

        try:
            response = await self._runner.run_turn(session_id, text)
        except Exception as e:
            print(f"[telegram] Error processing message from {user_id}: {type(e).__name__}", file=sys.stderr)
            await update.message.reply_text("Sorry, something went wrong. Please try again.")
            return

        for chunk in _split_message(response):
            await update.message.reply_text(chunk)

    async def _cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if user is None or not self._is_allowed(user.id):
            return
        await update.message.reply_text(  # type: ignore[union-attr]
            "Hi! I'm Terrybot, your personal AI assistant.\n\n"
            "Commands:\n"
            "  /reset — Clear conversation history\n"
            "  /compact — Summarize and compact history\n"
            "  /status — Show current configuration\n\n"
            "Just send me a message to get started."
        )

    async def _cmd_reset(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if user is None or not self._is_allowed(user.id):
            return
        self._runner.reset_session(str(user.id))
        await update.message.reply_text("Conversation history cleared. Starting fresh!")  # type: ignore[union-attr]

    async def _cmd_compact(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if user is None or not self._is_allowed(user.id):
            return
        result = await self._runner.compact_session(str(user.id))
        await update.message.reply_text(result)  # type: ignore[union-attr]

    async def _cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if user is None or not self._is_allowed(user.id):
            return
        session_id = str(user.id)
        turns = self._runner.get_session_history_turns(session_id)
        model = self._runner._model_for_session(session_id)
        await update.message.reply_text(  # type: ignore[union-attr]
            f"Model: {model}\n"
            f"History turns: {turns}\n"
            f"Max turns: {self._settings.agent.max_history_turns}"
        )

    def build_application(self) -> Application:
        """Build and configure the telegram Application."""
        token = self._settings.telegram.bot_token
        if not token:
            print("[telegram] ERROR: bot_token is not configured.", file=sys.stderr)
            raise ValueError("Telegram bot_token is required")

        app = Application.builder().token(token).build()

        app.add_handler(CommandHandler("start", self._cmd_start))
        app.add_handler(CommandHandler("reset", self._cmd_reset))
        app.add_handler(CommandHandler("compact", self._cmd_compact))
        app.add_handler(CommandHandler("status", self._cmd_status))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self._handle_message))

        return app

