"""
bot/gmail_channel.py — Gmail IMAP polling channel for Terrybot.

Polls a Gmail mailbox (or any IMAP server) on a schedule and injects
new emails as messages into a configured session.

Credentials:
  - Email address: terrybot.yaml gmail.email
  - Password/App Password: encrypted in ~/.terrybot/creds/gmail_password

For Gmail with 2FA, use an App Password:
  https://myaccount.google.com/apppasswords
"""

from __future__ import annotations

import asyncio
import email
import email.header
import imaplib
import sys
from typing import TYPE_CHECKING, Any, Callable, Coroutine, Optional

if TYPE_CHECKING:
    from agent.runner import LLMRunner
    from config import Settings

MAX_BODY_CHARS = 2000  # truncate email body before injecting into session


def _decode_header(raw: str | bytes | None) -> str:
    """Decode RFC 2047 encoded email header value."""
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    decoded = email.header.decode_header(raw)
    parts = []
    for part, charset in decoded:
        if isinstance(part, bytes):
            parts.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(part)
    return " ".join(parts)


def _extract_body(msg: email.message.Message) -> str:
    """Extract plain text body from an email.message.Message."""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if ct == "text/plain" and "attachment" not in cd:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    return payload.decode(charset, errors="replace")[:MAX_BODY_CHARS]
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")[:MAX_BODY_CHARS]
    return "(no plain-text body)"


class GmailChannel:
    """Polls IMAP for unseen emails and injects them into a Terrybot session."""

    def __init__(
        self,
        settings: "Settings",
        runner: "LLMRunner",
        notify_callback: Callable[[str, str], Coroutine[Any, Any, None]],
    ) -> None:
        self._cfg = settings.gmail
        self._runner = runner
        self._notify = notify_callback
        self._password: Optional[str] = None
        self._scheduler = None  # set in start()

    def _load_password(self) -> bool:
        """Load Gmail password from encrypted credential store."""
        try:
            from crypto import CredentialStore
            store = CredentialStore()
            self._password = store.load("gmail_password")
            return bool(self._password)
        except Exception as e:
            print(f"[gmail] Failed to load password: {type(e).__name__}", file=sys.stderr)
            return False

    def _fetch_unseen_emails(self) -> list[dict]:
        """
        Blocking IMAP fetch — runs in a thread via asyncio.to_thread().
        Returns a list of dicts with keys: sender, subject, body.
        """
        mail = imaplib.IMAP4_SSL(self._cfg.imap_host, self._cfg.imap_port)
        try:
            mail.login(self._cfg.email, self._password)
            mail.select(self._cfg.label)

            _, data = mail.search(None, "UNSEEN")
            uid_list = data[0].split() if data[0] else []
            uids = uid_list[-self._cfg.max_per_poll:]  # newest N

            results = []
            for uid in uids:
                _, msg_data = mail.fetch(uid, "(RFC822)")
                if not msg_data or not msg_data[0]:
                    continue
                raw = msg_data[0][1]
                if not isinstance(raw, bytes):
                    continue
                msg = email.message_from_bytes(raw)
                results.append({
                    "sender": _decode_header(msg.get("From")),
                    "subject": _decode_header(msg.get("Subject")),
                    "body": _extract_body(msg),
                })
            return results
        finally:
            try:
                mail.logout()
            except Exception:
                pass

    async def poll(self) -> None:
        """Fetch unseen emails and inject them as session messages."""
        if not self._cfg.enabled:
            return
        if not self._password and not self._load_password():
            print("[gmail] No password — skipping poll.", file=sys.stderr)
            return

        session_id = self._cfg.session_id
        if not session_id:
            print("[gmail] No session_id configured — skipping poll.", file=sys.stderr)
            return

        try:
            # Run blocking IMAP I/O in a thread so the event loop stays free
            emails = await asyncio.to_thread(self._fetch_unseen_emails)
        except imaplib.IMAP4.error as e:
            print(f"[gmail] IMAP error: {e}", file=sys.stderr)
            return
        except Exception as e:
            print(f"[gmail] Poll error: {type(e).__name__}: {e}", file=sys.stderr)
            return

        for item in emails:
            sender, subject, body = item["sender"], item["subject"], item["body"]
            injected = f"[EMAIL] From: {sender}\nSubject: {subject}\n\n{body}"
            print(f"[gmail] New email from {sender!r}: {subject!r}", file=sys.stderr)
            try:
                response = await self._runner.run_turn(session_id, injected)
                await self._notify(session_id, response)
            except Exception as e:
                print(f"[gmail] run_turn error: {type(e).__name__}: {e}", file=sys.stderr)

    def start(self, scheduler) -> None:
        """Register poll job with an existing APScheduler instance."""
        from apscheduler.triggers.interval import IntervalTrigger
        scheduler.add_job(
            self.poll,
            IntervalTrigger(seconds=self._cfg.poll_interval),
            id="gmail_poll",
            name="terrybot:gmail_poll",
            replace_existing=True,
        )
        print(
            f"[gmail] Polling {self._cfg.email!r} every {self._cfg.poll_interval}s",
            file=sys.stderr,
        )
