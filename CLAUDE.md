# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Runtime

Requires **Python 3.11+** (enforced at startup; `asyncio.timeout` is used). Use `python3.11` explicitly — system `python3` is 3.10.

```bash
# Install dependencies
pip install -r requirements.txt

# First-time setup (writes terrybot.yaml + encrypted credentials)
python3.11 main.py setup

# Security self-check (run before every start, also auto-runs on `run`)
python3.11 main.py audit

# Start both channels
python3.11 main.py run --both

# Start individual channels
python3.11 main.py run --telegram
python3.11 main.py run --web
```

## Architecture

### Request flow

```
Telegram message / WebSocket message
  → bot/ (allowlist, rate limit, auth)
  → agent/sanitize.py (strip control chars, escape tags, truncate, wrap in [USER_MSG])
  → agent/runner.py (tool-call loop, OpenRouter API via httpx)
  → agent/session.py (isolated per-session history, compact to max_turns)
  → agent/tools.py (dispatch_tool: get_datetime, fetch_url, save_note, load_note)
  → response back to channel
```

### Key design decisions

**Config + secrets split**: `terrybot.yaml` holds only non-secret settings (model, port, allowed user IDs). All secrets (`openrouter_api_key`, `telegram_bot_token`, `web_auth_token`) are stored encrypted in `~/.terrybot/creds/*.enc` via `crypto.py` (Fernet + HKDF-SHA256). They are injected into `Settings` at runtime in `main.py`; the YAML fields for them are intentionally left blank.

**Session isolation**: `agent/session.py` stores history in a plain dict keyed by `session_id`. Telegram sessions use `str(user_id)` (persistent across reconnects); web sessions use `web_<uuid>` (ephemeral, deleted on WebSocket disconnect). There is no shared state between sessions.

**Tool loop**: `runner.py` runs up to `MAX_TOOL_ITERATIONS = 5` tool-call iterations per turn, with a hard `RUN_TURN_TIMEOUT = 120s` via `asyncio.timeout`. The session always gets a paired assistant message in the `finally` block, even if an exception occurs.

**Adding a tool**: All tools are hardcoded — no plugin system. To add one:
1. Implement the function in `agent/tools.py`
2. Add its JSON schema to `TOOL_DEFINITIONS`
3. Add a dispatch branch in `dispatch_tool()`

**Web bot concurrent mode** (`--both`): `_run_both()` in `main.py` uses `async with tg_app:` from python-telegram-bot v21+. Do **not** call `initialize()`/`shutdown()` manually — the context manager handles them. The uvicorn server and telegram polling run in the same asyncio event loop.

### Security layers (in order)

| Layer | Where | What it does |
|---|---|---|
| Allowlist | `bot/telegram_bot.py` | Silently drops messages from non-listed Telegram user IDs |
| Origin check | `security/origin.py` | Rejects WebSocket connections from non-localhost origins (CSWSH) |
| Auth + rate limit | `security/auth.py` | HMAC-normalized token compare; 5 failures → 15-min IP lockout |
| Input sanitize | `agent/sanitize.py` | Strips null bytes/control chars, escapes `[USER_MSG]` tags, truncates at 4000 chars, wraps in tags |
| SSRF prevention | `agent/tools.py:_check_ssrf` | DNS-resolves hostname, blocks loopback/private/link-local/multicast IPs |
| CSP | `bot/web_bot.py` | SHA-256 hashes of inline `<style>`/`<script>` blocks; no `unsafe-inline` |
| File permissions | `crypto.py` | `~/.terrybot/` 700, `creds/` 700, `*.enc` files 600; aborts on violation |
| Startup audit | `security/audit.py` | Checks all of the above; exits with code 1 on CRITICAL findings |

### Config schema (`config.py`)

`TERRYBOT_CONFIG` env var overrides the default `terrybot.yaml` path. `web.host` is validated to loopback addresses only (`127.0.0.1`, `::1`, `localhost`); any other value is a Pydantic validation error. The `agent.model` field takes precedence over `openrouter.model` in `runner.py`.
