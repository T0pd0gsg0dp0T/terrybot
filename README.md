# Terrybot

A secure, self-hosted personal AI assistant with Telegram and local web UI channels. Runs on [OpenRouter](https://openrouter.ai) — bring your own API key and model.

```
Telegram message / WebSocket message
  → allowlist + rate limit + auth
  → input sanitization (strip control chars, escape tags, truncate, wrap)
  → LLM runner (OpenRouter API, model failover, tool-call loop)
  → per-session isolated history
  → tools (datetime, fetch, notes, browser, shell, cross-session messaging)
  → response back to channel
```

---

## Features

### Channels
| Channel | How to access |
|---------|--------------|
| **Telegram** | DMs to your bot; optional group support with `@mention` gating |
| **Web UI** | `http://127.0.0.1:8765` — split-pane chat + canvas panel |
| **Webhooks** | `POST /webhook/{name}` — trigger sessions from external services |

### Tools (15 hardcoded, no plugin system)

| Tool | Description |
|------|-------------|
| `get_datetime` | Current UTC time in ISO 8601 |
| `fetch_url` | HTTP GET with SSRF prevention, 8KB text output |
| `save_note` / `load_note` | Encrypted persistent notes (`~/.terrybot/creds/`) |
| `sessions_list` | List all active session IDs |
| `sessions_send` | Send a message to another live session, get its response |
| `canvas_push` | Push arbitrary HTML to the web UI canvas panel |
| `system_run` | Execute a shell command (opt-in + user confirmation required) |
| `browser_navigate` | Navigate headless Chromium to a URL |
| `browser_snapshot` | Get page innerText (8KB, for LLM to read) |
| `browser_screenshot` | Screenshot → pushed to canvas as base64 image |
| `browser_click` | Click element by CSS selector |
| `browser_type` | Type text into element |
| `browser_fill` | Fill input field |
| `browser_upload` | Set file on upload input (path must be under `~/.terrybot/`) |

### Other capabilities
- **Model failover** — primary model rate-limited (429/529)? Transparently retries with configured fallback models, same context preserved
- **`/compact`** — LLM summarises conversation history into one message, freeing context
- **Cron scheduler** — inject messages into sessions on a schedule (APScheduler), deliver via Telegram or log
- **A2UI canvas panel** — right-hand pane in web UI, updated by `canvas_push` / `browser_screenshot`; supports arbitrary HTML and base64 images
- **`system_run` with confirmation** — bot proposes shell command, user must reply `confirm` or `deny` before it runs

---

## Security

Security is layered, enforced at startup via `python3.11 main.py audit`.

| Layer | Location | What it does |
|-------|----------|-------------|
| Allowlist | `bot/telegram_bot.py` | Silently drops DMs from non-listed Telegram user IDs |
| Group gating | `bot/telegram_bot.py` | Only responds in groups when `@mentioned`; per-group ID allowlist |
| Origin check | `security/origin.py` | Rejects WebSocket connections from non-localhost origins (CSWSH) |
| Auth + rate limit | `security/auth.py` | HMAC token comparison; 5 failures → 15-min IP lockout |
| Input sanitisation | `agent/sanitize.py` | Strips null bytes/control chars, escapes `[USER_MSG]` tags, truncates at 4000 chars, wraps in tags |
| SSRF prevention | `agent/tools.py` | DNS-resolves hostname, blocks loopback/private/link-local/multicast IPs |
| Browser upload guard | `agent/tools.py` | `browser_upload` file path must be under `~/.terrybot/` |
| CSP | `bot/web_bot.py` | SHA-256 hashes of inline `<style>`/`<script>` blocks; `img-src data: blob:` for screenshots |
| File permissions | `crypto.py` | `~/.terrybot/` 700, `creds/` 700, `*.enc` 600; aborts on violation |
| Startup audit | `security/audit.py` | Checks all of the above; exits code 1 on CRITICAL findings |
| `system_run` opt-in | `config.py` + audit | Disabled by default; WARN in audit if enabled |

Secrets (`openrouter_api_key`, `telegram_bot_token`, `web_auth_token`) are stored encrypted with Fernet + HKDF-SHA256 in `~/.terrybot/creds/*.enc`. They are **never** read from `terrybot.yaml`.

---

## Requirements

- Python **3.11+** (uses `asyncio.timeout`)
- An [OpenRouter](https://openrouter.ai/keys) API key
- Telegram bot token from [@BotFather](https://t.me/BotFather) *(optional — only needed for the Telegram channel)*

---

## Installation

```bash
git clone https://github.com/T0pd0gsg0dp0T/terrybot
cd terrybot

pip install -r requirements.txt
playwright install chromium   # only needed for browser tools
```

---

## Setup

```bash
# 1. Interactive wizard — encrypts and stores all credentials
python3.11 main.py setup

# 2. Security self-check — must pass before starting
python3.11 main.py audit

# 3. Start
python3.11 main.py run --both      # Telegram + web UI
python3.11 main.py run --telegram  # Telegram only
python3.11 main.py run --web       # Web UI only
```

Web UI is available at `http://127.0.0.1:8765`. Enter the auth token printed during setup to connect.

---

## Configuration

Copy `terrybot.yaml.example` to `terrybot.yaml` and edit non-secret settings. **Never put real credentials in the YAML** — use `python3.11 main.py setup` instead.

```yaml
openrouter:
  model: "anthropic/claude-sonnet-4-6"
  fallback_models:               # tried in order on 429/529
    - "anthropic/claude-haiku-4-5"
    - "openai/gpt-4o-mini"

telegram:
  allowed_user_ids: [123456789]  # get yours from @userinfobot
  allowed_group_ids: []          # negative IDs for groups/supergroups
  require_mention_in_groups: true

web:
  host: "127.0.0.1"             # never change to 0.0.0.0
  port: 8765

agent:
  model: "anthropic/claude-sonnet-4-6"
  max_history_turns: 20
  allow_system_run: false        # set true to enable shell execution

scheduler:
  jobs:
    - id: "morning_brief"
      cron: "0 9 * * 1-5"       # 9am Mon-Fri
      session_id: "123456789"   # Telegram user ID
      message: "Give me a morning briefing."
```

---

## Commands

### Bot commands (Telegram + web UI)
| Command | What it does |
|---------|-------------|
| `/reset` | Clear conversation history |
| `/compact` | LLM-summarise history into one message |
| `/status` | Show model and history turn count *(Telegram only)* |
| `confirm` / `deny` | Confirm or cancel a pending `system_run` command |

### CLI
```bash
python3.11 main.py setup          # credential wizard
python3.11 main.py audit          # security self-check
python3.11 main.py run --both     # start both channels
python3.11 main.py reset-session  # inform about in-memory sessions (restart to clear)
```

---

## Webhook endpoint

External services can trigger sessions without auth:

```bash
curl -X POST http://127.0.0.1:8765/webhook/my-event \
  -H "Content-Type: application/json" \
  -d '{"session_id": "webhook_my-event", "content": "Summarise today'\''s news."}'
```

Rate-limited at 20 requests/min per IP. `content` is capped at 4000 characters.

---

## Architecture

### Request flow
```
user message
  → bot/{telegram_bot,web_bot}.py  (allowlist, auth, rate limit, confirm/deny gate)
  → agent/sanitize.py              (strip control chars, escape tags, truncate, wrap)
  → agent/runner.py                (tool-call loop, failover, asyncio.timeout=120s)
  → agent/session.py               (isolated history per session_id, compact on max_turns)
  → agent/tools.py                 (dispatch_tool with ToolContext)
  → agent/browser.py               (Playwright singleton, per-session pages)
  → response to channel / canvas update to web UI
```

### Session isolation
| Session type | ID format | Lifetime |
|---|---|---|
| Telegram DM | `str(user_id)` | Persistent across reconnects |
| Telegram group | `group_{chat_id}` | Persistent |
| Web UI | `web_{uuid4().hex}` | Ephemeral — deleted on WebSocket disconnect |
| Webhook | `webhook_{name}` or custom | Persistent until restart |
| Scheduler | Configured `session_id` | Persistent |

### Tool loop
`runner.py` runs up to `MAX_TOOL_ITERATIONS = 5` tool calls per turn, with a hard `RUN_TURN_TIMEOUT = 120s` via `asyncio.timeout`. Session history always gets a paired assistant message in the `finally` block, even on exception.

### Adding a tool
All tools are hardcoded — no plugin system.
1. Implement the function in `agent/tools.py`
2. Add its JSON schema to `TOOL_DEFINITIONS`
3. Add a dispatch branch in `dispatch_tool()`
4. If it needs session/runner access, accept `context: ToolContext` as first argument

---

## Project structure

```
terrybot/
├── main.py                  # CLI entry point
├── config.py                # Pydantic settings schema + YAML loader
├── crypto.py                # Fernet credential store
├── requirements.txt
├── terrybot.yaml.example
├── agent/
│   ├── browser.py           # Playwright singleton manager
│   ├── context.py           # ToolContext dataclass
│   ├── runner.py            # OpenRouter LLM runner + failover + compact
│   ├── sanitize.py          # Input sanitisation + system prompt
│   ├── session.py           # Per-session history + canvas queue
│   └── tools.py             # All 15 tool implementations + dispatcher
├── bot/
│   ├── scheduler.py         # APScheduler cron runner
│   ├── telegram_bot.py      # Telegram handler
│   └── web_bot.py           # FastAPI WebSocket UI + webhook endpoint
└── security/
    ├── audit.py             # Startup security self-check
    ├── auth.py              # Token verification + IP rate limiter
    └── origin.py            # WebSocket origin validation
```

---

## License

MIT
