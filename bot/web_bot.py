"""
bot/web_bot.py — FastAPI local web UI for Terrybot.

Security:
  - Bound to 127.0.0.1 only (enforced in audit.py)
  - WebSocket origin validation (CSWSH prevention)
  - Token auth with rate limiting (5 failures → 15-min lockout)
  - Inline HTML/JS, no CDN dependencies
  - CSP uses SHA-256 hashes for inline script/style (no unsafe-inline)
  - No stack traces in responses
"""

from __future__ import annotations

import base64
import hashlib
import re
import sys
import time
import uuid
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from agent.runner import LLMRunner
from agent.tools import execute_pending_command
from security.auth import get_rate_limiter, verify_token
from security.origin import validate_ws_origin

if TYPE_CHECKING:
    from config import Settings

WS_RATE_LIMIT_REQUESTS = 20   # max messages
WS_RATE_LIMIT_WINDOW = 60.0   # per N seconds
WEBHOOK_RATE_LIMIT_REQUESTS = 20  # per IP per minute


class _WSRateLimiter:
    """Simple per-session sliding-window rate limiter for WebSocket messages."""

    def __init__(self, max_requests: int = WS_RATE_LIMIT_REQUESTS, window: float = WS_RATE_LIMIT_WINDOW) -> None:
        self._max = max_requests
        self._window = window
        self._timestamps: list[float] = []

    def is_allowed(self) -> bool:
        now = time.monotonic()
        window_start = now - self._window
        self._timestamps = [t for t in self._timestamps if t > window_start]
        if len(self._timestamps) >= self._max:
            return False
        self._timestamps.append(now)
        return True


# ── Minimal inline HTML/JS UI — Split pane: chat left, canvas right ──────────
# No CDN, no external resources.
# CSP hashes for inline blocks are computed at module load below.

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terrybot</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #1a1a2e; color: #e0e0e0; height: 100vh; display: flex; flex-direction: column; }
  #header { background: #16213e; padding: 12px 16px; font-size: 1.1rem; font-weight: bold; border-bottom: 1px solid #0f3460; flex-shrink: 0; }
  #auth-panel { display: flex; flex-direction: column; align-items: center; justify-content: center; flex: 1; gap: 12px; }
  #auth-panel input { padding: 10px; width: 300px; border-radius: 6px; border: 1px solid #0f3460; background: #16213e; color: #e0e0e0; font-size: 1rem; }
  #auth-panel button { padding: 10px 24px; background: #0f3460; color: #e0e0e0; border: none; border-radius: 6px; cursor: pointer; font-size: 1rem; }
  #main-panel { display: none; flex: 1; overflow: hidden; flex-direction: row; }
  #chat-pane { display: flex; flex-direction: column; flex: 1; min-width: 0; border-right: 1px solid #0f3460; }
  #messages { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 10px; }
  .msg { max-width: 90%; padding: 10px 14px; border-radius: 12px; line-height: 1.5; white-space: pre-wrap; word-wrap: break-word; }
  .msg.user { background: #0f3460; align-self: flex-end; }
  .msg.assistant { background: #16213e; align-self: flex-start; border: 1px solid #0f3460; }
  .msg.system { background: #2a1a0e; align-self: center; font-size: 0.85rem; color: #aaa; }
  #input-row { display: flex; gap: 8px; padding: 12px 16px; background: #16213e; border-top: 1px solid #0f3460; flex-shrink: 0; }
  #msg-input { flex: 1; padding: 10px; border-radius: 6px; border: 1px solid #0f3460; background: #1a1a2e; color: #e0e0e0; font-size: 1rem; resize: none; }
  #send-btn { padding: 10px 18px; background: #0f3460; color: #e0e0e0; border: none; border-radius: 6px; cursor: pointer; }
  #send-btn:disabled { opacity: 0.5; cursor: default; }
  #auth-error { color: #ff6b6b; font-size: 0.9rem; display: none; }
  #canvas-pane { display: flex; flex-direction: column; flex: 1; min-width: 0; background: #12121f; }
  #canvas-header { background: #16213e; padding: 8px 16px; font-size: 0.9rem; border-bottom: 1px solid #0f3460; display: flex; align-items: center; justify-content: space-between; flex-shrink: 0; }
  #canvas-clear-btn { padding: 4px 12px; background: #2a1a0e; color: #e0e0e0; border: 1px solid #4a3a2e; border-radius: 4px; cursor: pointer; font-size: 0.85rem; }
  #canvas-content { flex: 1; overflow: auto; padding: 16px; }
</style>
</head>
<body>
<div id="header">Terrybot</div>

<div id="auth-panel">
  <div style="font-size:1.2rem;">Connect to Terrybot</div>
  <input type="password" id="token-input" placeholder="Auth token" autocomplete="off">
  <button onclick="connect()">Connect</button>
  <div id="auth-error">Authentication failed. Check your token.</div>
</div>

<div id="main-panel">
  <div id="chat-pane">
    <div id="messages"></div>
    <div id="input-row">
      <textarea id="msg-input" rows="2" placeholder="Type a message... (Enter to send, Shift+Enter for newline)"></textarea>
      <button id="send-btn" onclick="sendMessage()">Send</button>
    </div>
  </div>
  <div id="canvas-pane">
    <div id="canvas-header">
      <span>Canvas</span>
      <button id="canvas-clear-btn" onclick="clearCanvas()">Clear</button>
    </div>
    <div id="canvas-content"></div>
  </div>
</div>

<script>
let ws = null;
let authenticated = false;

function connect() {
  const token = document.getElementById('token-input').value.trim();
  if (!token) return;

  ws = new WebSocket('ws://' + location.host + '/ws');

  ws.onopen = () => {
    ws.send(JSON.stringify({type: 'auth', token: token}));
  };

  ws.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.type === 'auth_ok') {
      authenticated = true;
      document.getElementById('auth-panel').style.display = 'none';
      document.getElementById('main-panel').style.display = 'flex';
      addMessage('system', 'Connected to Terrybot.');
    } else if (data.type === 'auth_fail') {
      document.getElementById('auth-error').style.display = 'block';
      ws.close();
    } else if (data.type === 'message') {
      addMessage('assistant', data.content);
      document.getElementById('send-btn').disabled = false;
    } else if (data.type === 'error') {
      addMessage('system', 'Error: ' + data.content);
      document.getElementById('send-btn').disabled = false;
    } else if (data.type === 'canvas') {
      document.getElementById('canvas-content').innerHTML = data.html;
    }
  };

  ws.onerror = () => {
    addMessage('system', 'Connection error.');
    document.getElementById('send-btn').disabled = false;
  };

  ws.onclose = () => {
    if (authenticated) addMessage('system', 'Disconnected.');
  };
}

function sendMessage() {
  const input = document.getElementById('msg-input');
  const text = input.value.trim();
  if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;
  addMessage('user', text);
  ws.send(JSON.stringify({type: 'message', content: text}));
  input.value = '';
  document.getElementById('send-btn').disabled = true;
}

function addMessage(role, text) {
  const div = document.createElement('div');
  div.className = 'msg ' + role;
  div.textContent = text;
  const msgs = document.getElementById('messages');
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
}

function clearCanvas() {
  document.getElementById('canvas-content').innerHTML = '';
}

document.getElementById('msg-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

document.getElementById('token-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') connect();
});
</script>
</body>
</html>
"""


# ── CSP hash computation ──────────────────────────────────────────────────────
# Compute SHA-256 hashes of inline <style> and <script> blocks at module load.
# These are injected into the Content-Security-Policy header so we can
# allow exactly these blocks without 'unsafe-inline'.

def _csp_hash(content: str) -> str:
    """Return a CSP hash directive value for the given inline content."""
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return f"'sha256-{base64.b64encode(digest).decode()}'"


def _extract_inline_blocks(html: str, tag: str) -> list[str]:
    """Extract all inline content between <tag> and </tag> pairs."""
    return re.findall(rf"<{tag}[^>]*>(.*?)</{tag}>", html, re.DOTALL | re.IGNORECASE)


_style_blocks = _extract_inline_blocks(_HTML, "style")
_script_blocks = _extract_inline_blocks(_HTML, "script")

_STYLE_HASHES = " ".join(_csp_hash(b) for b in _style_blocks)
_SCRIPT_HASHES = " ".join(_csp_hash(b) for b in _script_blocks)


# ── Security headers middleware ───────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; "
            f"script-src 'self' {_SCRIPT_HASHES}; "
            f"style-src 'self' {_STYLE_HASHES}; "
            f"connect-src 'self' ws://127.0.0.1:* ws://localhost:* wss://127.0.0.1:* wss://localhost:*; "
            f"img-src 'self' data: blob:; "
            f"object-src 'none'; "
            f"base-uri 'none'; "
            f"form-action 'none';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


# ── FastAPI app factory ───────────────────────────────────────────────────────

def create_app(settings: "Settings", runner: LLMRunner) -> FastAPI:
    """Create and configure the FastAPI app."""

    app = FastAPI(
        title="Terrybot Web UI",
        docs_url=None,    # Disable Swagger UI
        redoc_url=None,   # Disable ReDoc
        openapi_url=None, # Disable OpenAPI schema
    )
    app.add_middleware(SecurityHeadersMiddleware)

    auth_token = settings.web.auth_token
    rate_limiter = get_rate_limiter()

    # Per-IP webhook rate limiter (reuses same sliding-window logic)
    _webhook_timestamps: dict[str, list[float]] = {}

    def _webhook_allowed(ip: str) -> bool:
        now = time.monotonic()
        window_start = now - 60.0
        ts = [t for t in _webhook_timestamps.get(ip, []) if t > window_start]
        _webhook_timestamps[ip] = ts
        if len(ts) >= WEBHOOK_RATE_LIMIT_REQUESTS:
            return False
        _webhook_timestamps[ip].append(now)
        return True

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        return HTMLResponse(content=_HTML)

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.post("/webhook/{name}")
    async def webhook(name: str, request: Request) -> JSONResponse:
        """
        External webhook endpoint. No web-auth required (designed for server-to-server).
        Rate-limited by IP (20 req/min).
        """
        client_ip = "unknown"
        if request.client:
            client_ip = request.client.host

        if not _webhook_allowed(client_ip):
            return JSONResponse({"error": "Rate limit exceeded."}, status_code=429)

        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

        if not isinstance(body, dict):
            return JSONResponse({"error": "Body must be a JSON object."}, status_code=400)

        session_id = body.get("session_id", f"webhook_{name}")
        content = body.get("content", f"Webhook triggered: {name}")

        if not isinstance(content, str):
            return JSONResponse({"error": "content must be a string."}, status_code=400)
        if not isinstance(session_id, str):
            return JSONResponse({"error": "session_id must be a string."}, status_code=400)

        content = content[:4000]

        try:
            response = await runner.run_turn(session_id, content)
            return JSONResponse({"response": response})
        except Exception as e:
            print(f"[web] Webhook error for {name!r}: {type(e).__name__}", file=sys.stderr)
            return JSONResponse({"error": "Internal error."}, status_code=500)

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        # Step 1: Validate WebSocket origin (CSWSH prevention)
        origin = websocket.headers.get("origin")
        if not validate_ws_origin(origin):
            await websocket.close(code=4403, reason="Origin not allowed")
            return

        await websocket.accept()

        # Determine client IP for rate limiting
        client_ip = "unknown"
        if websocket.client:
            client_ip = websocket.client.host

        # Step 2: Require auth as first message
        try:
            raw = await websocket.receive_json()
        except Exception:
            await websocket.send_json({"type": "auth_fail", "reason": "Invalid message"})
            await websocket.close()
            return

        if not isinstance(raw, dict) or raw.get("type") != "auth":
            await websocket.send_json({"type": "auth_fail", "reason": "Expected auth message"})
            await websocket.close()
            return

        provided_token = raw.get("token", "")
        if not isinstance(provided_token, str):
            provided_token = ""

        result = verify_token(provided_token, auth_token, client_ip, rate_limiter)

        if not result.success:
            reason = "Account temporarily locked." if result.locked_out else "Invalid token."
            await websocket.send_json({"type": "auth_fail", "reason": reason})
            await websocket.close()
            return

        await websocket.send_json({"type": "auth_ok"})

        # Step 3: Assign a per-web-session UUID (isolated from other sessions)
        session_id = f"web_{uuid.uuid4().hex}"
        ws_limiter = _WSRateLimiter()

        # Step 4: Chat loop
        try:
            while True:
                try:
                    msg = await websocket.receive_json()
                except Exception:
                    break

                if not isinstance(msg, dict):
                    continue

                if msg.get("type") == "message":
                    content = msg.get("content", "")
                    if not isinstance(content, str) or not content.strip():
                        continue

                    # Per-session message rate limit (20/min)
                    if not ws_limiter.is_allowed():
                        await websocket.send_json({"type": "error", "content": "Too many requests. Please slow down."})
                        continue

                    # /compact special command
                    if content.strip() == "/compact":
                        result_text = await runner.compact_session(session_id)
                        await websocket.send_json({"type": "message", "content": result_text})
                        continue

                    # Confirm/deny intercept for pending system_run commands
                    session = runner._sessions.get(session_id)
                    if session and session.pending_command:
                        normalized = content.strip().lower()
                        if normalized in ("confirm", "yes"):
                            cmd = session.pending_command
                            session.pending_command = None
                            output = execute_pending_command(cmd)
                            await websocket.send_json({"type": "message", "content": f"Output:\n{output}"})
                        elif normalized in ("deny", "no", "cancel"):
                            session.pending_command = None
                            await websocket.send_json({"type": "message", "content": "Command cancelled."})
                        else:
                            await websocket.send_json({
                                "type": "message",
                                "content": (
                                    f"Pending command awaiting confirmation:\n"
                                    f"`{session.pending_command}`\n"
                                    "Reply 'confirm' to execute or 'deny' to cancel."
                                ),
                            })
                        continue

                    try:
                        response = await runner.run_turn(session_id, content)

                        # Flush canvas updates before the message response
                        session = runner._sessions.get(session_id)
                        if session:
                            for html in session.pop_canvas_updates():
                                await websocket.send_json({"type": "canvas", "html": html})

                        await websocket.send_json({"type": "message", "content": response})
                    except Exception as e:
                        print(f"[web] Error in session {session_id}: {type(e).__name__}", file=sys.stderr)
                        await websocket.send_json({"type": "error", "content": "Something went wrong."})

        except WebSocketDisconnect:
            pass
        finally:
            # Clean up ephemeral web session via public API
            runner.delete_session(session_id)

    return app
