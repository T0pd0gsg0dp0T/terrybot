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
import logging
import secrets
import sys
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from config import Settings
    from agent.runner import LLMRunner


def _require_python() -> None:
    if sys.version_info < (3, 11):
        logger.error(
            "Python 3.11+ required (got %d.%d)",
            sys.version_info.major,
            sys.version_info.minor,
        )
        sys.exit(1)


# ── Setup wizard ──────────────────────────────────────────────────────────────

def cmd_setup() -> None:
    """Interactive setup wizard — collect secrets, encrypt, store."""
    from logging_setup import setup_logging
    setup_logging()
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

    # Gmail
    print("5. Gmail (optional)")
    print("   Terrybot can poll your Gmail inbox and inject emails into a session.")
    gmail_email = input("   Gmail address (leave blank to skip): ").strip()
    if gmail_email:
        pw = getpass.getpass("   App Password (create at https://myaccount.google.com/apppasswords): ").strip()
        if pw:
            store.store("gmail_app_password", pw)
            print("   ✓ Gmail App Password stored.\n")
        else:
            print("   ⚠ App Password skipped — Gmail will not work until you re-run setup.\n")
    else:
        gmail_email = ""
        print("   ⚠ Skipped.\n")

    # Write/update terrybot.yaml with non-secret settings
    _write_config_file(ids_raw, gmail_email=gmail_email or None)

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


def _write_config_file(ids_raw: str, gmail_email: str | None = None) -> None:
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

    if gmail_email:
        existing_gmail = existing.get("gmail", {})
        config["gmail"] = {
            "enabled": existing_gmail.get("enabled", False),
            "email": gmail_email,
            "imap_host": existing_gmail.get("imap_host", "imap.gmail.com"),
            "imap_port": existing_gmail.get("imap_port", 993),
            "poll_interval": existing_gmail.get("poll_interval", 60),
            "session_id": existing_gmail.get("session_id", str(user_ids[0]) if user_ids else ""),
            "label": existing_gmail.get("label", "INBOX"),
            "max_per_poll": existing_gmail.get("max_per_poll", 5),
        }

    with CONFIG_PATH.open("w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    CONFIG_PATH.chmod(0o600)
    print(f"   ✓ Configuration written to {CONFIG_PATH} (chmod 600).")


# ── Show secret ───────────────────────────────────────────────────────────────

def cmd_show_secret(name: str) -> None:
    """Decrypt and print a stored credential to stdout."""
    from logging_setup import setup_logging
    setup_logging()
    from crypto import CredentialStore

    KNOWN = {
        "openrouter_api_key",
        "telegram_bot_token",
        "web_auth_token",
        "gmail_app_password",
        "webhook_secret",
    }
    if name not in KNOWN:
        print(f"Unknown secret '{name}'. Valid names: {', '.join(sorted(KNOWN))}")
        sys.exit(1)

    store = CredentialStore()
    value = store.load(name)
    if value is None:
        print(f"No secret stored for '{name}'.")
        sys.exit(1)
    print(value)


# ── Audit ─────────────────────────────────────────────────────────────────────

def cmd_audit() -> None:
    """Run security self-check and print report."""
    from logging_setup import setup_logging
    setup_logging()
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


def _apply_yaml_reload(live: "Settings") -> None:
    """
    Reload terrybot.yaml and copy non-secret, mutable fields into the live
    Settings object so changes take effect without a full restart.

    Secrets (api_key, bot_token, auth_token) are NOT reloaded — they are
    already in memory and only change via `python main.py setup`.

    Fields reloaded: openrouter.model, openrouter.fallback_models,
    agent.model, agent.max_history_turns, agent.allow_system_run,
    agent.session_ttl_days, agent.system_prompt,
    telegram.allowed_user_ids, telegram.allowed_group_ids,
    telegram.require_mention_in_groups.
    """
    from config import load_config
    try:
        fresh = load_config()
    except Exception as exc:
        logger.error("SIGHUP reload failed — config error: %s", exc)
        return

    live.openrouter.model = fresh.openrouter.model
    live.openrouter.fallback_models = fresh.openrouter.fallback_models
    live.agent.model = fresh.agent.model
    live.agent.max_history_turns = fresh.agent.max_history_turns
    live.agent.allow_system_run = fresh.agent.allow_system_run
    live.agent.session_ttl_days = fresh.agent.session_ttl_days
    live.agent.system_prompt = fresh.agent.system_prompt
    live.telegram.allowed_user_ids = fresh.telegram.allowed_user_ids
    live.telegram.allowed_group_ids = fresh.telegram.allowed_group_ids
    live.telegram.require_mention_in_groups = fresh.telegram.require_mention_in_groups
    logger.info("Config reloaded from terrybot.yaml (SIGHUP).")


def _validate_scheduler_config(settings: "Settings") -> None:
    """Validate all cron expressions in config; exit with code 1 if any are invalid."""
    from apscheduler.triggers.cron import CronTrigger
    errors = []
    for job in settings.scheduler.jobs:
        try:
            CronTrigger.from_crontab(job.cron, timezone=job.timezone or None)
        except Exception as e:
            errors.append(f"Job {job.id!r}: invalid cron {job.cron!r}: {e}")
    if errors:
        for msg in errors:
            logger.error("Config error: %s", msg)
        sys.exit(1)


def cmd_run(telegram: bool, web: bool) -> None:
    """Start Terrybot channels after security audit."""
    from logging_setup import setup_logging
    setup_logging()
    from security.audit import audit_and_exit_on_critical

    settings = _load_settings_with_secrets()

    logger.info("Running startup security audit...")
    audit_and_exit_on_critical(settings)
    _validate_scheduler_config(settings)

    from agent.runner import LLMRunner
    from agent.session import PersistentSessionStore, SessionStore
    from agent.tools import prune_old_screenshots

    prune_old_screenshots()

    sessions: SessionStore | PersistentSessionStore
    if settings.agent.persist_sessions:
        sessions = PersistentSessionStore(max_history_turns=settings.agent.max_history_turns)
        logger.info("Using persistent (SQLite) session store.")
    else:
        sessions = SessionStore(max_history_turns=settings.agent.max_history_turns)

    # Prune stale sessions and compact remaining ones at startup.
    ttl = settings.agent.session_ttl_days
    if ttl > 0:
        pruned = sessions.prune_expired_sessions(ttl)
        if pruned:
            logger.info("Pruned %d session(s) inactive for >%d days.", pruned, ttl)
    sessions.compact_all()

    runner = LLMRunner(settings=settings, sessions=sessions)

    try:
        if telegram and web:
            asyncio.run(_run_both(settings, runner))
        elif telegram:
            asyncio.run(_run_telegram(settings, runner))
        elif web:
            asyncio.run(_run_web(settings, runner))
        else:
            logger.error("No channel selected. Use --telegram, --web, or --both.")
            sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Stopped.")


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
                logger.info("Scheduler session %r: %s", session_id, response[:100])
        except Exception as e:
            logger.error("Scheduler notify failed for %r: %s", session_id, type(e).__name__)

    delivery.set_telegram_notify(_tg_notify)
    scheduler = TerryScheduler(settings=settings, runner=runner, delivery=delivery)

    if settings.gmail.enabled and settings.gmail.email:
        from bot.gmail_channel import GmailChannel
        gmail = GmailChannel(settings=settings, runner=runner, notify_callback=delivery.deliver)
        gmail.start(scheduler.underlying)

    return tg_app, delivery, scheduler


def _install_sighup_handler(settings: "Settings") -> None:
    """Register a SIGHUP handler that reloads non-secret config in-place.

    Only available on Unix. On Windows this is a no-op.
    Send with: kill -HUP <pid>
    """
    import signal
    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGHUP, _apply_yaml_reload, settings)
        logger.info("SIGHUP handler installed (send SIGHUP to reload config).")
    except (AttributeError, OSError):
        # Windows or environments without SIGHUP
        pass


async def _run_telegram(settings: "Settings", runner: "LLMRunner") -> None:
    tg_app, delivery, scheduler = await _build_telegram_stack(settings, runner)
    logger.info("Starting Telegram bot...")
    async with tg_app:
        await tg_app.start()
        if tg_app.updater:
            await tg_app.updater.start_polling(drop_pending_updates=True)
        scheduler.start()
        _install_sighup_handler(settings)
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
    logger.info("Starting web UI at http://%s:%d", host, port)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)

    scheduler.start()
    _install_sighup_handler(settings)
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

    logger.info("Starting web UI at http://%s:%d", host, port)
    logger.info("Starting Telegram bot...")

    async with tg_app:
        await tg_app.start()
        if tg_app.updater:
            await tg_app.updater.start_polling(drop_pending_updates=True)
        scheduler.start()
        _install_sighup_handler(settings)
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
    from logging_setup import setup_logging
    setup_logging()
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
  show-secret             Print a stored encrypted secret to stdout

Examples:
  python main.py setup
  python main.py run --both
  python main.py run --telegram
  python main.py run --web
  python main.py audit
  python main.py reset-session --user-id 123456789
  python main.py show-secret webhook_secret
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

    # show-secret
    show_parser = subparsers.add_parser("show-secret", help="Print a stored secret to stdout")
    show_parser.add_argument(
        "name",
        help="Secret name (openrouter_api_key, telegram_bot_token, web_auth_token, gmail_app_password, webhook_secret)",
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
    elif args.command == "show-secret":
        cmd_show_secret(args.name)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
