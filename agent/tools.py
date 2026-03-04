"""
agent/tools.py — Hardcoded safe tools for Terrybot.

All tools are:
  - Explicitly enumerated (no plugin system, no dynamic loading)
  - Input-validated before execution
  - Output size-limited

Built-in tools (21):
  - get_datetime, fetch_url, save_note, load_note
  - sessions_list, sessions_send, canvas_push, system_run
  - browser_navigate, browser_snapshot, browser_screenshot
  - browser_click, browser_type, browser_fill, browser_upload
  - send_notification, get_location
  - set_session_model, get_session_model
  - propose_tool, list_pending_tools

User-approved tools are loaded from ~/.terrybot/approved_tools/ at startup
and appended to TOOL_DEFINITIONS and the dispatcher automatically.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone
from html.parser import HTMLParser
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlparse

import httpx

if TYPE_CHECKING:
    from agent.context import ToolContext

TERRYBOT_DIR = Path.home() / ".terrybot"
SCREENSHOTS_DIR = TERRYBOT_DIR / "screenshots"

MAX_FETCH_BYTES = 8 * 1024   # 8KB
MAX_NOTE_SIZE = 16 * 1024    # 16KB
MAX_SNAPSHOT_BYTES = 8 * 1024  # 8KB browser snapshot
DNS_TIMEOUT = 5.0            # seconds for SSRF hostname DNS resolution
SHELL_TIMEOUT = 30           # seconds for system_run subprocess

# Granular httpx timeouts: connect and read are budgeted separately so a
# slow-to-connect host can't eat the entire read-timeout budget.
_HTTPX_TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=2.0)


# ── Tool definitions (OpenAI function-calling schema) ─────────────────────────

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "get_datetime",
            "description": "Get the current date and time in ISO 8601 format (UTC).",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": (
                "Fetch the text content of a URL (HTTP/HTTPS only). "
                "Returns up to 8KB of cleaned text content."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to fetch (must be http:// or https://).",
                    }
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_note",
            "description": "Save a text note under a given key for later retrieval.",
            "parameters": {
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "Short alphanumeric key (e.g. 'shopping_list', 'todo').",
                    },
                    "content": {
                        "type": "string",
                        "description": "The note content to save.",
                    },
                },
                "required": ["key", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "load_note",
            "description": "Load a previously saved note by key.",
            "parameters": {
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "The key used when the note was saved.",
                    }
                },
                "required": ["key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sessions_list",
            "description": "List all active session IDs.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sessions_send",
            "description": "Send a message to another active session and return its response.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_session_id": {
                        "type": "string",
                        "description": "The session ID to send the message to.",
                    },
                    "message": {
                        "type": "string",
                        "description": "The message to send.",
                    },
                },
                "required": ["target_session_id", "message"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "canvas_push",
            "description": "Push HTML content to the web UI canvas panel.",
            "parameters": {
                "type": "object",
                "properties": {
                    "html": {
                        "type": "string",
                        "description": "HTML content to display in the canvas panel.",
                    }
                },
                "required": ["html"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "system_run",
            "description": (
                "Execute a shell command. Requires user confirmation before running. "
                "Must be enabled in config (agent.allow_system_run: true)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute.",
                    }
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_navigate",
            "description": "Navigate the browser to a URL. Returns the page title and current URL.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to navigate to (http:// or https:// only).",
                    }
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_snapshot",
            "description": "Get a simplified text snapshot of the current browser page (up to 8KB of innerText).",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_screenshot",
            "description": "Take a screenshot of the current browser page and push it to the canvas panel.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_click",
            "description": "Click an element on the current browser page by CSS selector.",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {
                        "type": "string",
                        "description": "CSS selector for the element to click.",
                    }
                },
                "required": ["selector"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_type",
            "description": "Type text into a focused element on the current browser page.",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {
                        "type": "string",
                        "description": "CSS selector for the element.",
                    },
                    "text": {
                        "type": "string",
                        "description": "Text to type.",
                    },
                },
                "required": ["selector", "text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_fill",
            "description": "Fill an input field on the current browser page.",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {
                        "type": "string",
                        "description": "CSS selector for the input field.",
                    },
                    "value": {
                        "type": "string",
                        "description": "Value to fill in.",
                    },
                },
                "required": ["selector", "value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_upload",
            "description": (
                "Set a file on an upload input. File path must be under ~/.terrybot/."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {
                        "type": "string",
                        "description": "CSS selector for the file input.",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the file (must be under ~/.terrybot/).",
                    },
                },
                "required": ["selector", "file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_notification",
            "description": "Send a desktop notification to the OS notification centre (Linux/macOS).",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Notification title."},
                    "message": {"type": "string", "description": "Notification body text."},
                },
                "required": ["title", "message"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_location",
            "description": (
                "Get the current location (city, country, latitude, longitude, timezone). "
                "Uses IP geolocation by default or a manually configured location."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "set_session_model",
            "description": (
                "Override the AI model for this session. "
                "Use an OpenRouter model ID, e.g. 'openai/gpt-4o' or 'anthropic/claude-haiku-4-5'. "
                "Pass empty string to revert to the global default."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "model": {
                        "type": "string",
                        "description": "OpenRouter model ID, or empty string to use global default.",
                    }
                },
                "required": ["model"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_session_model",
            "description": "Get the current AI model in use for this session.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "propose_tool",
            "description": (
                "Propose a new tool to add to Terrybot. "
                "Writes a Python implementation to ~/.terrybot/pending_tools/ for user review and approval. "
                "The tool becomes active only after the user approves it via /dashboard."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Tool name in snake_case (e.g. 'search_web'). 3-64 chars.",
                    },
                    "description": {
                        "type": "string",
                        "description": "Human-readable description of what the tool does.",
                    },
                    "schema": {
                        "type": "string",
                        "description": (
                            "JSON string of the OpenAI function-calling schema for this tool "
                            "(the 'function' object: name, description, parameters)."
                        ),
                    },
                    "implementation": {
                        "type": "string",
                        "description": (
                            "Complete Python implementation of the tool function. "
                            "Signature: async def <name>(context: ToolContext, **kwargs) -> str "
                            "or def <name>(**kwargs) -> str for simple sync tools."
                        ),
                    },
                },
                "required": ["name", "description", "schema", "implementation"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_pending_tools",
            "description": "List all pending tool proposals awaiting user approval.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]

# ── User-approved tools (loaded from ~/.terrybot/approved_tools/) ─────────────
# These are appended at module load. Populated by _load_user_tools() below.
_USER_TOOL_DEFINITIONS: list[dict] = []
_USER_TOOL_DISPATCH: dict[str, Any] = {}


def _load_user_tools() -> None:
    """Load approved tools from ~/.terrybot/approved_tools/ and register them."""
    global _USER_TOOL_DEFINITIONS, _USER_TOOL_DISPATCH
    try:
        from agent.tool_manager import load_approved_tools
        defs, dispatch = load_approved_tools()
        _USER_TOOL_DEFINITIONS = defs
        _USER_TOOL_DISPATCH = dispatch
        if defs:
            TOOL_DEFINITIONS.extend(defs)
    except Exception as e:
        print(f"[tools] Failed to load user tools: {type(e).__name__}: {e}", file=sys.stderr)


_load_user_tools()


# ── Tool implementations ──────────────────────────────────────────────────────

def get_datetime() -> str:
    """Return current UTC datetime in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


async def fetch_url(url: str) -> str:
    """
    Fetch URL content (async). Returns cleaned text, max 8KB.
    Validates scheme (http/https only) and resolves hostname to block SSRF.
    """
    # Validate URL scheme
    try:
        parsed = urlparse(url)
    except Exception:
        return "Error: Invalid URL."

    if parsed.scheme not in ("http", "https"):
        return f"Error: Only http:// and https:// URLs are allowed. Got: {parsed.scheme!r}"

    hostname = parsed.hostname or ""
    if not hostname:
        return "Error: URL has no hostname."

    # Block private/loopback via DNS resolution (SSRF prevention)
    ssrf_error = _check_ssrf(hostname)
    if ssrf_error:
        return ssrf_error

    try:
        # follow_redirects=False prevents SSRF-via-redirect:
        # a server at a "safe" host could redirect to 169.254.169.254 etc.
        # after our SSRF check has already passed. Redirects are reported
        # back to the LLM as a message so it can decide whether to follow.
        async with httpx.AsyncClient(timeout=_HTTPX_TIMEOUT, follow_redirects=False) as client:
            response = await client.get(url, headers={"User-Agent": "Terrybot/1.0"})

            if response.is_redirect:
                location = response.headers.get("location", "(no Location header)")
                return f"[URL redirects to: {location} — fetch that URL explicitly if needed]"

            response.raise_for_status()

            content_type = response.headers.get("content-type", "")
            raw = response.content[:MAX_FETCH_BYTES]

            if "text" in content_type or "json" in content_type:
                text = raw.decode("utf-8", errors="replace")
                return _clean_html(text)
            else:
                return f"[Binary content of type {content_type!r} — not displayable]"

    except httpx.HTTPStatusError as e:
        return f"Error: HTTP {e.response.status_code}"
    except httpx.RequestError as e:
        return f"Error: Could not connect: {type(e).__name__}"
    except Exception as e:
        return f"Error: Unexpected error: {type(e).__name__}"


def save_note(key: str, content: str) -> str:
    """Save an encrypted note. Key must be alphanumeric + underscores."""
    if not _valid_note_key(key):
        return "Error: Key must be alphanumeric with underscores only (max 64 chars)."
    if len(content) > MAX_NOTE_SIZE:
        return f"Error: Note content exceeds maximum size ({MAX_NOTE_SIZE} bytes)."

    try:
        from crypto import CredentialStore
        store = CredentialStore()
        store.store(f"note_{key}", content)
        return f"Note '{key}' saved successfully."
    except Exception as e:
        print(f"[tools] Error saving note '{key}': {type(e).__name__}", file=sys.stderr)
        return "Error: Could not save note."


def load_note(key: str) -> str:
    """Load an encrypted note by key."""
    if not _valid_note_key(key):
        return "Error: Key must be alphanumeric with underscores only (max 64 chars)."

    try:
        from crypto import CredentialStore
        store = CredentialStore()
        value = store.load(f"note_{key}")
        if value is None:
            return f"No note found with key '{key}'."
        return value
    except Exception as e:
        print(f"[tools] Error loading note '{key}': {type(e).__name__}", file=sys.stderr)
        return "Error: Could not load note."


def sessions_list(context: "ToolContext") -> str:
    """Return JSON list of active session IDs."""
    import json
    sessions = context.runner._sessions.list_sessions()
    return json.dumps(sessions)


async def sessions_send(context: "ToolContext", target_session_id: str, message: str) -> str:
    """Send a message to another session and return its response."""
    if target_session_id == context.session_id:
        return "Error: Cannot send to own session (infinite loop prevention)."
    if not target_session_id or not message:
        return "Error: target_session_id and message are required."
    message = message[:4000]
    response = await context.runner.run_turn(target_session_id, message)
    return response


def canvas_push(context: "ToolContext", html: str) -> str:
    """Push HTML to the canvas panel for this session."""
    session = context.runner._sessions.get(context.session_id)
    if session is None:
        return "Error: Session not found."
    session.push_canvas(html)
    return "Canvas updated."


def system_run(context: "ToolContext", command: str) -> str:
    """
    Queue a shell command for user confirmation.
    The actual execution happens in the bot handler after user confirms.
    """
    if not context.settings.agent.allow_system_run:
        return (
            "Error: system_run is disabled. "
            "Set agent.allow_system_run: true in terrybot.yaml to enable."
        )
    session = context.runner._sessions.get(context.session_id)
    if session is None:
        return "Error: Session not found."
    session.pending_command = command
    return (
        f"PENDING: Shell command requires user confirmation: `{command}`\n"
        "Reply 'confirm' to execute or 'deny' to cancel."
    )


def execute_pending_command(command: str) -> str:
    """Execute a confirmed shell command. Returns output (stdout+stderr, capped at 4000 chars)."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=SHELL_TIMEOUT,
            cwd=Path.home(),
        )
        output = (result.stdout + result.stderr).strip()[:4000]
        return output or "(no output)"
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {SHELL_TIMEOUT}s."
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"


# ── Browser tools ─────────────────────────────────────────────────────────────

async def browser_navigate(context: "ToolContext", url: str) -> str:
    """Navigate the browser to a URL (with SSRF check)."""
    try:
        parsed = urlparse(url)
    except Exception:
        return "Error: Invalid URL."

    if parsed.scheme not in ("http", "https"):
        return f"Error: Only http:// and https:// URLs are allowed."

    hostname = parsed.hostname or ""
    if not hostname:
        return "Error: URL has no hostname."

    ssrf_error = _check_ssrf(hostname)
    if ssrf_error:
        return ssrf_error

    try:
        from agent.browser import get_browser_manager
        mgr = await get_browser_manager()
        page = await mgr.get_or_create_page(context.session_id)
        await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        title = await page.title()
        current_url = page.url
        return f"Navigated to: {current_url}\nTitle: {title}"
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"


async def browser_snapshot(context: "ToolContext") -> str:
    """Get simplified innerText of the current page (up to 8KB)."""
    try:
        from agent.browser import get_browser_manager
        mgr = await get_browser_manager()
        page = await mgr.get_or_create_page(context.session_id)
        text = await page.evaluate("document.body ? document.body.innerText : ''")
        if not isinstance(text, str):
            text = str(text)
        return text[:MAX_SNAPSHOT_BYTES]
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"


async def browser_screenshot(context: "ToolContext") -> str:
    """Take a screenshot and push it to the canvas panel."""
    try:
        import base64
        from agent.browser import get_browser_manager
        mgr = await get_browser_manager()
        page = await mgr.get_or_create_page(context.session_id)

        SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
        import time
        filename = SCREENSHOTS_DIR / f"{context.session_id}_{int(time.time())}.png"
        png_bytes = await page.screenshot(full_page=False)
        filename.write_bytes(png_bytes)
        filename.chmod(0o600)

        b64 = base64.b64encode(png_bytes).decode()
        img_tag = f'<img src="data:image/png;base64,{b64}" style="max-width:100%;height:auto;" alt="Browser screenshot">'

        session = context.runner._sessions.get(context.session_id)
        if session:
            session.push_canvas(img_tag)

        return f"Screenshot pushed to canvas. Saved to {filename}."
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"


async def browser_click(context: "ToolContext", selector: str) -> str:
    """Click an element by CSS selector."""
    try:
        from agent.browser import get_browser_manager
        mgr = await get_browser_manager()
        page = await mgr.get_or_create_page(context.session_id)
        await page.click(selector, timeout=10000)
        return "Clicked."
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"


async def browser_type(context: "ToolContext", selector: str, text: str) -> str:
    """Type text into an element by CSS selector."""
    try:
        from agent.browser import get_browser_manager
        mgr = await get_browser_manager()
        page = await mgr.get_or_create_page(context.session_id)
        await page.type(selector, text, timeout=10000)
        return "Typed."
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"


async def browser_fill(context: "ToolContext", selector: str, value: str) -> str:
    """Fill an input field by CSS selector."""
    try:
        from agent.browser import get_browser_manager
        mgr = await get_browser_manager()
        page = await mgr.get_or_create_page(context.session_id)
        await page.fill(selector, value, timeout=10000)
        return "Filled."
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"


def send_notification(title: str, message: str) -> str:
    """Send an OS desktop notification."""
    from bot.notifications import send_os_notification
    return send_os_notification(title, message)


async def get_location(context: "ToolContext") -> str:
    """Return current location via IP geolocation or manual config."""
    import json
    cfg = context.settings.location

    if cfg.mode == "manual" and (cfg.city or cfg.latitude):
        return json.dumps({
            "mode": "manual",
            "city": cfg.city,
            "country": cfg.country,
            "latitude": cfg.latitude,
            "longitude": cfg.longitude,
            "timezone": cfg.timezone,
        })

    # IP geolocation via ipapi.co (free, no key required)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=8.0, write=3.0, pool=2.0)) as client:
            resp = await client.get(
                "https://ipapi.co/json/",
                headers={"User-Agent": "Terrybot/1.0"},
            )
            resp.raise_for_status()
            data = resp.json()
            return json.dumps({
                "mode": "ip",
                "ip": data.get("ip", ""),
                "city": data.get("city", ""),
                "region": data.get("region", ""),
                "country": data.get("country_name", ""),
                "country_code": data.get("country_code", ""),
                "latitude": data.get("latitude", 0),
                "longitude": data.get("longitude", 0),
                "timezone": data.get("timezone", ""),
                "org": data.get("org", ""),
            })
    except Exception as e:
        return f"Error: Could not fetch location: {type(e).__name__}: {e}"


def set_session_model(context: "ToolContext", model: str) -> str:
    """Set or clear the per-session model override."""
    session = context.runner._sessions.get(context.session_id)
    if session is None:
        return "Error: session not found."
    if not model or not model.strip():
        session.model = None
        return "Session model cleared — using global default."
    session.model = model.strip()
    return f"Session model set to '{session.model}'."


def get_session_model(context: "ToolContext") -> str:
    """Return the current model in use for this session."""
    session = context.runner._sessions.get(context.session_id)
    session_model = session.model if session else None
    global_model = context.settings.agent.model or context.settings.openrouter.model
    if session_model:
        return f"Session model: '{session_model}' (overriding global '{global_model}')"
    return f"Global model: '{global_model}' (no session override)"


def _propose_tool(name: str, description: str, schema: str, implementation: str) -> str:
    """Write a proposed tool to pending_tools for user review."""
    from agent.tool_manager import propose_tool as _pt
    return _pt(name, description, schema, implementation)


def _list_pending_tools() -> str:
    """List pending tool proposals."""
    import json
    from agent.tool_manager import list_pending
    pending = list_pending()
    if not pending:
        return "No pending tool proposals."
    summary = [{"name": t["name"], "lines": len(t["code"].splitlines())} for t in pending]
    return f"{len(pending)} pending tool(s):\n" + json.dumps(summary, indent=2)


async def browser_upload(context: "ToolContext", selector: str, file_path: str) -> str:
    """Set a file on an upload input. file_path must be under ~/.terrybot/."""
    resolved = Path(file_path).resolve()
    terrybot_resolved = TERRYBOT_DIR.resolve()
    if not str(resolved).startswith(str(terrybot_resolved)):
        return "Error: file_path must be under ~/.terrybot/."
    if not resolved.exists():
        return f"Error: File not found: {resolved}"

    try:
        from agent.browser import get_browser_manager
        mgr = await get_browser_manager()
        page = await mgr.get_or_create_page(context.session_id)
        await page.set_input_files(selector, str(resolved), timeout=10000)
        return "File set."
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"


# ── Tool dispatcher ───────────────────────────────────────────────────────────

async def dispatch_tool(
    name: str,
    arguments: dict[str, Any],
    context: Optional["ToolContext"] = None,
) -> str:
    """
    Dispatch a tool call by name with validated arguments.
    Returns the tool result as a string.
    """
    if name == "get_datetime":
        return get_datetime()

    elif name == "fetch_url":
        url = arguments.get("url", "")
        if not isinstance(url, str):
            return "Error: Missing or invalid 'url' argument."
        url = url.strip()
        if not url:
            return "Error: Missing or invalid 'url' argument."
        return await fetch_url(url)

    elif name == "save_note":
        key = arguments.get("key", "")
        content = arguments.get("content", "")
        if not isinstance(key, str) or not isinstance(content, str):
            return "Error: Invalid arguments."
        return save_note(key, content)

    elif name == "load_note":
        key = arguments.get("key", "")
        if not isinstance(key, str) or not key:
            return "Error: Missing 'key' argument."
        return load_note(key)

    elif name == "sessions_list":
        if context is None:
            return "Error: No context available."
        return sessions_list(context)

    elif name == "sessions_send":
        if context is None:
            return "Error: No context available."
        target = arguments.get("target_session_id", "")
        message = arguments.get("message", "")
        if not isinstance(target, str) or not isinstance(message, str):
            return "Error: Invalid arguments."
        return await sessions_send(context, target, message)

    elif name == "canvas_push":
        if context is None:
            return "Error: No context available."
        html = arguments.get("html", "")
        if not isinstance(html, str):
            return "Error: Invalid 'html' argument."
        return canvas_push(context, html)

    elif name == "system_run":
        if context is None:
            return "Error: No context available."
        command = arguments.get("command", "")
        if not isinstance(command, str) or not command.strip():
            return "Error: Missing 'command' argument."
        return system_run(context, command)

    elif name == "browser_navigate":
        if context is None:
            return "Error: No context available."
        url = arguments.get("url", "")
        if not isinstance(url, str) or not url.strip():
            return "Error: Missing 'url' argument."
        return await browser_navigate(context, url.strip())

    elif name == "browser_snapshot":
        if context is None:
            return "Error: No context available."
        return await browser_snapshot(context)

    elif name == "browser_screenshot":
        if context is None:
            return "Error: No context available."
        return await browser_screenshot(context)

    elif name == "browser_click":
        if context is None:
            return "Error: No context available."
        selector = arguments.get("selector", "")
        if not isinstance(selector, str) or not selector:
            return "Error: Missing 'selector' argument."
        return await browser_click(context, selector)

    elif name == "browser_type":
        if context is None:
            return "Error: No context available."
        selector = arguments.get("selector", "")
        text = arguments.get("text", "")
        if not isinstance(selector, str) or not isinstance(text, str):
            return "Error: Invalid arguments."
        return await browser_type(context, selector, text)

    elif name == "browser_fill":
        if context is None:
            return "Error: No context available."
        selector = arguments.get("selector", "")
        value = arguments.get("value", "")
        if not isinstance(selector, str) or not isinstance(value, str):
            return "Error: Invalid arguments."
        return await browser_fill(context, selector, value)

    elif name == "browser_upload":
        if context is None:
            return "Error: No context available."
        selector = arguments.get("selector", "")
        file_path = arguments.get("file_path", "")
        if not isinstance(selector, str) or not isinstance(file_path, str):
            return "Error: Invalid arguments."
        return await browser_upload(context, selector, file_path)

    elif name == "send_notification":
        title = arguments.get("title", "")
        message = arguments.get("message", "")
        if not isinstance(title, str) or not isinstance(message, str):
            return "Error: Invalid arguments."
        return send_notification(title.strip() or "Terrybot", message)

    elif name == "get_location":
        if context is None:
            return "Error: No context available."
        return await get_location(context)

    elif name == "set_session_model":
        if context is None:
            return "Error: No context available."
        model = arguments.get("model", "")
        if not isinstance(model, str):
            return "Error: 'model' must be a string."
        return set_session_model(context, model)

    elif name == "get_session_model":
        if context is None:
            return "Error: No context available."
        return get_session_model(context)

    elif name == "propose_tool":
        tool_name = arguments.get("name", "")
        description = arguments.get("description", "")
        schema = arguments.get("schema", "")
        implementation = arguments.get("implementation", "")
        for v in (tool_name, description, schema, implementation):
            if not isinstance(v, str):
                return "Error: All arguments must be strings."
        return _propose_tool(tool_name, description, schema, implementation)

    elif name == "list_pending_tools":
        return _list_pending_tools()

    else:
        # Check user-approved dynamic tools
        if name in _USER_TOOL_DISPATCH:
            func = _USER_TOOL_DISPATCH[name]
            import asyncio as _asyncio
            import inspect
            if inspect.iscoroutinefunction(func):
                if context is not None:
                    return await func(context, **arguments)
                return await func(**arguments)
            else:
                if context is not None:
                    try:
                        return func(context, **arguments)
                    except TypeError:
                        return func(**arguments)
                return func(**arguments)
        return f"Error: Unknown tool '{name}'."


# ── Helpers ───────────────────────────────────────────────────────────────────

def _valid_note_key(key: str) -> bool:
    """Key must be alphanumeric + underscores, max 64 chars."""
    return bool(key) and len(key) <= 64 and re.match(r"^[a-zA-Z0-9_]+$", key) is not None


class _HTMLStripper(HTMLParser):
    """HTML parser that extracts plain text, discarding scripts and styles."""

    def __init__(self) -> None:
        super().__init__()
        self._buf = StringIO()
        self._skip = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag.lower() in ("script", "style"):
            self._skip = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in ("script", "style"):
            self._skip = False
        elif not self._skip:
            # Add spacing around block-level elements
            if tag.lower() in ("p", "div", "br", "li", "h1", "h2", "h3", "h4", "h5", "h6"):
                self._buf.write("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self._buf.write(data)

    def get_text(self) -> str:
        return re.sub(r"\s+", " ", self._buf.getvalue()).strip()


def _clean_html(html: str) -> str:
    """Strip HTML using a proper parser (not regex). Collapse whitespace."""
    stripper = _HTMLStripper()
    try:
        stripper.feed(html)
        return stripper.get_text()
    except Exception:
        # Fallback: crude strip if parser chokes on malformed HTML
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


def _check_ssrf(hostname: str) -> str | None:
    """
    SSRF prevention: resolve hostname and check all resulting IPs.
    Returns an error string if blocked, or None if safe to connect.

    Blocks:
      - Loopback (127.0.0.0/8, ::1)
      - Private networks (RFC 1918 + RFC 4193)
      - Link-local (169.254.0.0/16, fe80::/10)
      - Multicast, reserved, unspecified addresses
      - Unresolvable hostnames (fail-closed)
    """
    # Quick string checks before DNS resolution
    if hostname.lower() == "localhost":
        return "Error: Fetching internal/private addresses is not allowed."

    try:
        ip = ipaddress.ip_address(hostname)
        return _check_ip_blocked(ip)
    except ValueError:
        pass  # Not a literal IP — proceed to DNS resolution

    # DNS resolution with timeout.
    # We use a thread + future rather than mutating socket.setdefaulttimeout(),
    # which is a global side-effect that would be unsafe under concurrent use.
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                socket.getaddrinfo, hostname, None, 0, socket.SOCK_STREAM
            )
            results = future.result(timeout=DNS_TIMEOUT)
    except concurrent.futures.TimeoutError:
        return "Error: DNS resolution timed out."
    except socket.gaierror:
        # Unresolvable hostname — fail closed (could be DNS rebinding or bad host)
        return "Error: Hostname could not be resolved."
    except Exception:
        return "Error: DNS resolution failed."

    if not results:
        return "Error: Hostname resolved to no addresses."

    for (_, _, _, _, sockaddr) in results:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return "Error: Invalid resolved IP address."

        blocked = _check_ip_blocked(ip)
        if blocked:
            return blocked

    return None  # All resolved IPs are safe


def _check_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return error string if IP is in a blocked range, else None."""
    if ip.is_loopback:
        return "Error: Fetching internal/private addresses is not allowed."
    if ip.is_private:
        return "Error: Fetching internal/private addresses is not allowed."
    if ip.is_link_local:
        return "Error: Fetching link-local addresses is not allowed."
    if ip.is_multicast:
        return "Error: Fetching multicast addresses is not allowed."
    if ip.is_reserved:
        return "Error: Fetching reserved addresses is not allowed."
    if ip.is_unspecified:
        return "Error: Fetching unspecified addresses is not allowed."
    return None
