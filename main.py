#!/usr/bin/env python3
"""
main.py — Terrybot CLI entry point.

Usage:
  python main.py setup                    # Interactive setup wizard
  python main.py run [--telegram] [--web] [--both]
  python main.py audit                    # Security self-check
  python main.py reset-session [--user-id N]

All secrets are stored encrypted. Never put real credentials in terrybot.yaml.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import secrets
import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from config import Settings
    from agent.runner import LLMRunner


def _require_python() -> None:
    if sys.version_info < (3, 11):
        print(
            f"[main] Python 3.11+ required (got {sys.version_info.major}.{sys.version_info.minor})",
            file=sys.stderr,
        )
        sys.exit(1)


# ── Setup wizard ──────────────────────────────────────────────────────────────

def cmd_setup() -> None:
    """Interactive setup wizard — collect secrets, encrypt, store."""
    from crypto import CredentialStore

    print("=" * 56)
    print(" Terrybot Setup Wizard")
    print("=" * 56)
    print("This wizard will encrypt and store your credentials.")
    print("Credentials are stored in ~/.terrybot/creds/ (chmod 600).")
    print()

    store = CredentialStore()

    # OpenRouter API key
    print("1. OpenRouter API key")
    print("   Get yours at: https://openrouter.ai/keys")
    key = getpass.getpass("   API key (sk-or-...): ").strip()
    if key:
        store.store("openrouter_api_key", key)
        print("   ✓ OpenRouter API key stored.\n")
    else:
        print("   ⚠ Skipped (key left unchanged).\n")

    # Telegram bot token
    print("2. Telegram bot token")
    print("   Create a bot via @BotFather on Telegram.")
    token = getpass.getpass("   Bot token (123456:ABC...): ").strip()
    if token:
        store.store("telegram_bot_token", token)
        print("   ✓ Telegram bot token stored.\n")
    else:
        print("   ⚠ Skipped.\n")

    # Web auth token
    print("3. Web UI auth token")
    existing = store.exists("web_auth_token")
    if existing:
        regen = input("   A token already exists. Regenerate? [y/N]: ").strip().lower()
        if regen == "y":
            new_token = secrets.token_hex(32)
            store.store("web_auth_token", new_token)
            print(f"   ✓ New web auth token: {new_token}")
            print("   Save this — you'll need it to connect to the web UI.\n")
        else:
            print("   ⚠ Kept existing token.\n")
    else:
        new_token = secrets.token_hex(32)
        store.store("web_auth_token", new_token)
        print(f"   ✓ Web auth token generated: {new_token}")
        print("   Save this — you'll need it to connect to the web UI.\n")

    # Telegram allowed user IDs
    print("4. Telegram allowed user IDs")
    print("   Comma-separated list of Telegram user IDs that can use the bot.")
    print("   Get your ID from @userinfobot on Telegram.")
    ids_raw = input("   User IDs (e.g. 123456789,987654321): ").strip()

    # Write/update terrybot.yaml with non-secret settings
    _write_config_file(ids_raw)

    # Gmail App Password
    print("5. Gmail App Password (optional)")
    print("   Create at: https://myaccount.google.com/apppasswords")
    pw = getpass.getpass("   App Password (leave blank to skip): ").strip()
    if pw:
        store.store("gmail_app_password", pw)
        print("   ✓ Gmail App Password stored.\n")
    else:
        print("   ⚠ Skipped.\n")

    # Webhook HMAC secret
    print("6. Webhook HMAC secret (optional)")
    print("   If set, POST /webhook/{name} requires X-Hub-Signature-256 header.")
    print("   Leave blank to allow unauthenticated webhook calls (rate-limited only).")
    ws_raw = input("   Webhook secret (leave blank to generate one, 'skip' to disable): ").strip()
    if ws_raw.lower() == "skip":
        print("   ⚠ Webhook HMAC disabled — webhook endpoint has no signature check.\n")
    else:
        webhook_secret = ws_raw or secrets.token_hex(32)
        store.store("webhook_secret", webhook_secret)
        if ws_raw:
            print("   ✓ Webhook secret stored.\n")
        else:
            print(f"   ✓ Webhook secret generated: {webhook_secret}")
            print("   Add X-Hub-Signature-256 to webhook callers.\n")

    print()
    print("=" * 56)
    print(" Setup complete! Next steps:")
    print("  1. Review terrybot.yaml (model, port, etc.)")
    print("  2. python main.py audit      — verify security")
    print("  3. python main.py run --both — start bot + web UI")
    print("=" * 56)


def _write_config_file(ids_raw: str) -> None:
    """Write or update terrybot.yaml with validated user IDs and safe defaults."""
    import yaml
    from config import CONFIG_PATH

    # Parse user IDs
    user_ids: list[int] = []
    for part in ids_raw.split(","):
        part = part.strip()
        if part.isdigit():
            user_ids.append(int(part))

    # Load existing config if present
    existing: dict[str, Any] = {}
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open(encoding="utf-8") as f:
            existing = yaml.safe_load(f) or {}

    # Start with existing config so sections like scheduler/gmail/notifications/location
    # are preserved across re-runs of setup.
    config = existing.copy()

    # Update only the sections that setup manages (never overwrite secrets with blanks
    # if they were already in the file — they shouldn't be, but be defensive).
    config["openrouter"] = {
        "api_key": "",
        "model": existing.get("openrouter", {}).get("model", "anthropic/claude-sonnet-4-6"),
    }
    config["telegram"] = {
        "bot_token": "",
        "allowed_user_ids": user_ids or existing.get("telegram", {}).get("allowed_user_ids", []),
    }
    config["web"] = {
        "host": "127.0.0.1",
        "port": existing.get("web", {}).get("port", 8765),
        "auth_token": "",
    }
    config["agent"] = {
        "model": existing.get("agent", {}).get("model", "anthropic/claude-sonnet-4-6"),
        "max_history_turns": existing.get("agent", {}).get("max_history_turns", 20),
        "persist_sessions": existing.get("agent", {}).get("persist_sessions", True),
    }

    with CONFIG_PATH.open("w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    CONFIG_PATH.chmod(0o600)
    print(f"   ✓ Configuration written to {CONFIG_PATH} (chmod 600).")


# ── Audit ─────────────────────────────────────────────────────────────────────

def cmd_audit() -> None:
    """Run security self-check and print report."""
    from config import load_config
    from crypto import CredentialStore
    from security.audit import print_audit_report, run_audit

    settings = load_config()

    # Inject secrets from credential store (for audit completeness)
    store = CredentialStore()
    settings.openrouter.api_key = store.load("openrouter_api_key") or ""
    settings.telegram.bot_token = store.load("telegram_bot_token") or ""
    settings.web.auth_token = store.load("web_auth_token") or ""

    findings = run_audit(settings)
    ok = print_audit_report(findings)
    sys.exit(0 if ok else 1)


# ── Reset session ─────────────────────────────────────────────────────────────

def cmd_reset_session(user_id: int | None) -> None:
    """Clear session history for a user (or all sessions)."""
    # Sessions are in-memory, so this just informs the user
    if user_id is not None:
        print(f"[reset] Session for user {user_id} will be cleared on next bot startup.")
        print("  (Sessions are in-memory — restart the bot to clear all sessions.)")
    else:
        print("[reset] All sessions will be cleared on next bot startup.")
        print("  (Sessions are in-memory — restart the bot to clear them.)")
    sys.exit(0)


# ── Run ───────────────────────────────────────────────────────────────────────

def _load_settings_with_secrets() -> "Settings":
    """Load config and inject encrypted secrets."""
    from config import load_config
    from crypto import CredentialStore

    settings = load_config()
    store = CredentialStore()

    settings.openrouter.api_key = store.load("openrouter_api_key") or ""
    settings.telegram.bot_token = store.load("telegram_bot_token") or ""
    settings.web.auth_token = store.load("web_auth_token") or ""
    settings.web.webhook_secret = store.load("webhook_secret") or ""

    return settings


def cmd_run(telegram: bool, web: bool) -> None:
    """Start Terrybot channels after security audit."""
    from security.audit import audit_and_exit_on_critical

    settings = _load_settings_with_secrets()

    print("[main] Running startup security audit...")
    audit_and_exit_on_critical(settings)

    from agent.runner import LLMRunner
    from agent.session import PersistentSessionStore, SessionStore
    from agent.tools import prune_old_screenshots

    prune_old_screenshots()

    sessions: SessionStore | PersistentSessionStore
    if settings.agent.persist_sessions:
        sessions = PersistentSessionStore(max_history_turns=settings.agent.max_history_turns)
        print("[main] Using persistent (SQLite) session store.")
    else:
        sessions = SessionStore(max_history_turns=settings.agent.max_history_turns)
    runner = LLMRunner(settings=settings, sessions=sessions)

    try:
        if telegram and web:
            asyncio.run(_run_both(settings, runner))
        elif telegram:
            asyncio.run(_run_telegram(settings, runner))
        elif web:
            asyncio.run(_run_web(settings, runner))
        else:
            print("[main] No channel selected. Use --telegram, --web, or --both.", file=sys.stderr)
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n[main] Stopped.", file=sys.stderr)


async def _build_telegram_stack(settings: "Settings", runner: "LLMRunner") -> tuple[Any, Any, Any]:
    """
    Shared setup for any mode that uses Telegram.
    Returns (tg_app, delivery, scheduler) with the notify callback wired in.
    Also starts the Gmail channel if configured.
    """
    from bot.delivery import DeliveryManager
    from bot.scheduler import TerryScheduler
    from bot.telegram_bot import TelegramBot

    tg_bot = TelegramBot(settings=settings, runner=runner)
    tg_app = tg_bot.build_application()
    delivery = DeliveryManager()

    async def _tg_notify(session_id: str, response: str) -> None:
        try:
            if session_id.lstrip("-").isdigit():
                await tg_app.bot.send_message(chat_id=int(session_id), text=response[:4096])
            else:
                print(f"[scheduler] Session {session_id!r}: {response[:100]}", file=sys.stderr)
        except Exception as e:
            print(f"[scheduler] Notify failed for {session_id!r}: {type(e).__name__}", file=sys.stderr)

    delivery.set_telegram_notify(_tg_notify)
    scheduler = TerryScheduler(settings=settings, runner=runner, delivery=delivery)

    if settings.gmail.enabled and settings.gmail.email:
        from bot.gmail_channel import GmailChannel
        gmail = GmailChannel(settings=settings, runner=runner, notify_callback=delivery.deliver)
        gmail.start(scheduler.underlying)

    return tg_app, delivery, scheduler


async def _run_telegram(settings: "Settings", runner: "LLMRunner") -> None:
    tg_app, delivery, scheduler = await _build_telegram_stack(settings, runner)
    print("[main] Starting Telegram bot...")
    async with tg_app:
        await tg_app.start()
        if tg_app.updater:
            await tg_app.updater.start_polling(drop_pending_updates=True)
        scheduler.start()
        try:
            await asyncio.Event().wait()
        finally:
            scheduler.stop()
            if tg_app.updater:
                await tg_app.updater.stop()
            await tg_app.stop()
            await runner.aclose()


async def _run_web(settings: "Settings", runner: "LLMRunner") -> None:
    import uvicorn
    from bot.delivery import DeliveryManager
    from bot.scheduler import TerryScheduler
    from bot.web_bot import create_app

    delivery = DeliveryManager()
    scheduler = TerryScheduler(settings=settings, runner=runner, delivery=delivery)

    if settings.gmail.enabled and settings.gmail.email:
        from bot.gmail_channel import GmailChannel
        gmail = GmailChannel(settings=settings, runner=runner, notify_callback=delivery.deliver)
        gmail.start(scheduler.underlying)

    app = create_app(settings=settings, runner=runner, delivery=delivery, scheduler=scheduler)
    host = settings.web.host
    port = settings.web.port
    print(f"[main] Starting web UI at http://{host}:{port}")
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)

    scheduler.start()
    try:
        await server.serve()
    finally:
        scheduler.stop()
        await runner.aclose()


async def _run_both(settings: "Settings", runner: "LLMRunner") -> None:
    """Run Telegram and web UI concurrently."""
    import uvicorn
    from bot.web_bot import create_app

    tg_app, delivery, scheduler = await _build_telegram_stack(settings, runner)

    app = create_app(settings=settings, runner=runner, delivery=delivery, scheduler=scheduler)
    host = settings.web.host
    port = settings.web.port
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)

    print(f"[main] Starting web UI at http://{host}:{port}")
    print("[main] Starting Telegram bot...")

    async with tg_app:
        await tg_app.start()
        if tg_app.updater:
            await tg_app.updater.start_polling(drop_pending_updates=True)
        scheduler.start()
        try:
            await server.serve()
        finally:
            scheduler.stop()
            if tg_app.updater:
                await tg_app.updater.stop()
            await tg_app.stop()
            await runner.aclose()


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    _require_python()

    parser = argparse.ArgumentParser(
        description="Terrybot — Secure Personal AI Assistant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  setup                   Interactive credential setup wizard
  run                     Start Terrybot (use --telegram, --web, or --both)
  audit                   Run security self-check
  reset-session           Clear in-memory session history (restart required)

Examples:
  python main.py setup
  python main.py run --both
  python main.py run --telegram
  python main.py run --web
  python main.py audit
  python main.py reset-session --user-id 123456789
""",
    )

    subparsers = parser.add_subparsers(dest="command")

    # setup
    subparsers.add_parser("setup", help="Interactive setup wizard")

    # run
    run_parser = subparsers.add_parser("run", help="Start Terrybot channels")
    run_group = run_parser.add_mutually_exclusive_group()
    run_group.add_argument("--telegram", action="store_true", help="Start Telegram bot only")
    run_group.add_argument("--web", action="store_true", help="Start web UI only")
    run_group.add_argument("--both", action="store_true", help="Start both channels")

    # audit
    subparsers.add_parser("audit", help="Run security self-check")

    # reset-session
    reset_parser = subparsers.add_parser("reset-session", help="Clear session history")
    reset_parser.add_argument(
        "--user-id",
        type=int,
        metavar="N",
        help="Telegram user ID (numeric, omit for all)",
    )

    args = parser.parse_args()

    if args.command == "setup":
        cmd_setup()
    elif args.command == "run":
        telegram = args.telegram or args.both
        web = args.web or args.both
        cmd_run(telegram=telegram, web=web)
    elif args.command == "audit":
        cmd_audit()
    elif args.command == "reset-session":
        cmd_reset_session(args.user_id)  # already int | None after argparse
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
