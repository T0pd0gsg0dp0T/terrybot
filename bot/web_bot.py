"""
bot/web_bot.py — FastAPI local web UI + dashboard for Terrybot.

Endpoints:
  GET  /              — Chat UI (WebSocket auth)
  GET  /dashboard     — Control dashboard (token query param)
  POST /dashboard/tools/{name}/approve
  POST /dashboard/tools/{name}/reject
  POST /dashboard/tools/{name}/remove-approved
  GET  /api/sessions  — JSON session list (dashboard API)
  GET  /api/jobs      — JSON scheduler job list
  GET  /api/pending   — JSON pending tool list
  GET  /api/approved  — JSON approved tool list
  POST /webhook/{name}— External trigger endpoint
  GET  /health

Security:
  - Bound to 127.0.0.1 only
  - WebSocket origin validation (CSWSH)
  - Token auth with rate limiting (5 failures → 15-min lockout)
  - Dashboard protected by same token via query param
  - CSP with SHA-256 hashes for inline blocks
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import re
import secrets
import sys
import time
import uuid
from typing import TYPE_CHECKING, Optional

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from agent.runner import LLMRunner
from agent.tools import execute_pending_command
from bot.delivery import DeliveryManager
from security.auth import _normalize_token, get_rate_limiter, verify_token
from security.origin import validate_ws_origin

if TYPE_CHECKING:
    from config import Settings
    from bot.scheduler import TerryScheduler

WS_RATE_LIMIT_REQUESTS = 20
WS_RATE_LIMIT_WINDOW = 60.0
WEBHOOK_RATE_LIMIT_REQUESTS = 20


class _WSRateLimiter:
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


# ── Main chat UI ──────────────────────────────────────────────────────────────

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terrybot</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #1a1a2e; color: #e0e0e0; height: 100vh; display: flex; flex-direction: column; }
  #header { background: #16213e; padding: 12px 16px; font-size: 1.1rem; font-weight: bold; border-bottom: 1px solid #0f3460; flex-shrink: 0; display: flex; justify-content: space-between; align-items: center; }
  #header a { color: #7ab3ef; font-size: 0.85rem; text-decoration: none; }
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
  .msg.heartbeat { background: #0e2a1a; align-self: flex-start; border: 1px solid #1a5c3a; font-size: 0.9rem; }
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
<div id="header">
  <span>Terrybot</span>
  <a id="dash-link" href="#" style="display:none">Dashboard</a>
</div>

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
let currentToken = '';

function connect() {
  const token = document.getElementById('token-input').value.trim();
  if (!token) return;
  currentToken = token;

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
      document.getElementById('dash-link').href = '/dashboard?token=' + encodeURIComponent(token);
      document.getElementById('dash-link').style.display = 'inline';
      addMessage('system', 'Connected to Terrybot.');
    } else if (data.type === 'auth_fail') {
      document.getElementById('auth-error').style.display = 'block';
      ws.close();
    } else if (data.type === 'message') {
      addMessage('assistant', data.content);
      document.getElementById('send-btn').disabled = false;
    } else if (data.type === 'heartbeat') {
      addMessage('heartbeat', '\u23F0 [' + (data.session_id || 'scheduler') + ']: ' + data.content);
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
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
});

document.getElementById('token-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') connect();
});
</script>
</body>
</html>
"""

# ── Dashboard UI ──────────────────────────────────────────────────────────────

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terrybot Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #1a1a2e; color: #e0e0e0; min-height: 100vh; }
  header { background: #16213e; padding: 12px 24px; border-bottom: 1px solid #0f3460; display: flex; justify-content: space-between; align-items: center; }
  header h1 { font-size: 1.1rem; }
  header a { color: #7ab3ef; text-decoration: none; font-size: 0.9rem; }
  .container { max-width: 1100px; margin: 0 auto; padding: 24px; display: grid; gap: 24px; }
  section { background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 20px; }
  h2 { font-size: 1rem; margin-bottom: 14px; color: #7ab3ef; text-transform: uppercase; letter-spacing: 0.05em; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  th { text-align: left; padding: 6px 10px; border-bottom: 1px solid #0f3460; color: #aaa; font-weight: normal; }
  td { padding: 6px 10px; border-bottom: 1px solid #0f3460; word-break: break-all; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.78rem; }
  .badge-ok { background: #0e2a1a; color: #4caf88; }
  .badge-warn { background: #2a2000; color: #f0c040; }
  .empty { color: #666; font-size: 0.9rem; padding: 8px 0; }
  pre { background: #12121f; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 0.78rem; line-height: 1.4; white-space: pre-wrap; word-break: break-all; max-height: 260px; overflow-y: auto; border: 1px solid #0f3460; margin: 10px 0; }
  .tool-card { border: 1px solid #0f3460; border-radius: 6px; padding: 14px; margin-bottom: 12px; }
  .tool-card h3 { font-size: 0.95rem; margin-bottom: 6px; }
  .btn { display: inline-block; padding: 6px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85rem; text-decoration: none; }
  .btn-approve { background: #0e3a1a; color: #4caf88; }
  .btn-reject  { background: #3a0e0e; color: #e07070; margin-left: 8px; }
  .btn-remove  { background: #3a2000; color: #e0a040; margin-left: 8px; }
  .btn:hover { opacity: 0.85; }
  form { display: inline; }
</style>
</head>
<body>
<header>
  <h1>Terrybot Dashboard</h1>
  <a href="/?token={token}">&#8592; Chat</a>
</header>
<div class="container">

  <section id="sessions">
    <h2>Active Sessions</h2>
    {sessions_html}
  </section>

  <section id="jobs">
    <h2>Scheduler Jobs</h2>
    {jobs_html}
  </section>

  <section id="pending">
    <h2>Pending Tool Proposals</h2>
    {pending_html}
  </section>

  <section id="approved">
    <h2>Approved Tools (loaded at startup)</h2>
    {approved_html}
  </section>

</div>
</body>
</html>
"""


def _csp_hash(content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return f"'sha256-{base64.b64encode(digest).decode()}'"


def _extract_inline_blocks(html: str, tag: str) -> list[str]:
    return re.findall(rf"<{tag}[^>]*>(.*?)</{tag}>", html, re.DOTALL | re.IGNORECASE)


_style_blocks = _extract_inline_blocks(_HTML, "style")
_script_blocks = _extract_inline_blocks(_HTML, "script")
_STYLE_HASHES = " ".join(_csp_hash(b) for b in _style_blocks)
_SCRIPT_HASHES = " ".join(_csp_hash(b) for b in _script_blocks)

_dash_style_blocks = _extract_inline_blocks(_DASHBOARD_HTML, "style")
_DASH_STYLE_HASHES = " ".join(_csp_hash(b) for b in _dash_style_blocks)


# ── Security headers middleware ───────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        path = request.url.path
        if path.startswith("/dashboard"):
            # Dashboard: no script needed, forms POST to same origin
            response.headers["Content-Security-Policy"] = (
                f"default-src 'self'; "
                f"style-src 'self' {_DASH_STYLE_HASHES}; "
                f"script-src 'none'; "
                f"img-src 'none'; object-src 'none'; base-uri 'none'; "
                f"form-action 'self';"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                f"default-src 'self'; "
                f"script-src 'self' {_SCRIPT_HASHES}; "
                f"style-src 'self' {_STYLE_HASHES}; "
                f"connect-src 'self' ws://127.0.0.1:* ws://localhost:* wss://127.0.0.1:* wss://localhost:*; "
                f"img-src 'self' data: blob:; "
                f"object-src 'none'; base-uri 'none'; form-action 'none';"
            )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


# ── Dashboard HTML helpers ────────────────────────────────────────────────────

def _html_escape(s: str) -> str:
    import html as _html
    return _html.escape(s, quote=True)


def _render_sessions(runner: LLMRunner) -> str:
    sessions = runner._sessions.all_sessions()
    if not sessions:
        return '<p class="empty">No active sessions.</p>'
    rows = ""
    for sid, s in sessions.items():
        model = s.model or "<em style='color:#666'>global</em>"
        rows += (
            f"<tr><td>{_html_escape(sid)}</td>"
            f"<td>{len(s.history)}</td>"
            f"<td>{model}</td>"
            f"<td>{_html_escape(s.pending_command or '')}</td></tr>"
        )
    return (
        "<table><tr><th>Session ID</th><th>Messages</th><th>Model</th><th>Pending cmd</th></tr>"
        + rows + "</table>"
    )


def _render_jobs(scheduler: "TerryScheduler | None") -> str:
    if scheduler is None:
        return '<p class="empty">Scheduler not running.</p>'
    jobs = scheduler.underlying.get_jobs()
    if not jobs:
        return '<p class="empty">No scheduled jobs.</p>'
    rows = ""
    for j in jobs:
        next_run = str(j.next_run_time)[:19] if j.next_run_time else "—"
        rows += f"<tr><td>{_html_escape(j.id)}</td><td>{_html_escape(j.name)}</td><td>{next_run}</td></tr>"
    return "<table><tr><th>ID</th><th>Name</th><th>Next run</th></tr>" + rows + "</table>"


def _render_pending(token: str, csrf_token: str = "") -> str:
    from agent.tool_manager import list_pending
    tools = list_pending()
    if not tools:
        return '<p class="empty">No pending proposals.</p>'
    html = ""
    csrf_input = f'<input type="hidden" name="csrf_token" value="{_html_escape(csrf_token)}">'
    for t in tools:
        name = _html_escape(t["name"])
        code = _html_escape(t["code"])
        html += (
            f'<div class="tool-card">'
            f'<h3>{name}</h3>'
            f'<pre>{code}</pre>'
            f'<form method="post" action="/dashboard/tools/{name}/approve?token={_html_escape(token)}" style="display:inline">'
            f'{csrf_input}<button class="btn btn-approve" type="submit">Approve</button></form>'
            f'<form method="post" action="/dashboard/tools/{name}/reject?token={_html_escape(token)}" style="display:inline">'
            f'{csrf_input}<button class="btn btn-reject" type="submit">Reject</button></form>'
            f'</div>'
        )
    return html


def _render_approved(token: str, csrf_token: str = "") -> str:
    from agent.tool_manager import list_approved
    tools = list_approved()
    if not tools:
        return '<p class="empty">No approved tools.</p>'
    html = ""
    csrf_input = f'<input type="hidden" name="csrf_token" value="{_html_escape(csrf_token)}">'
    for t in tools:
        name = _html_escape(t["name"])
        code = _html_escape(t["code"])
        html += (
            f'<div class="tool-card">'
            f'<h3><span class="badge badge-ok">active</span> {name}</h3>'
            f'<pre>{code}</pre>'
            f'<form method="post" action="/dashboard/tools/{name}/remove-approved?token={_html_escape(token)}" style="display:inline">'
            f'{csrf_input}<button class="btn btn-remove" type="submit">Remove</button></form>'
            f'</div>'
        )
    return html


# ── App factory ───────────────────────────────────────────────────────────────

def create_app(
    settings: "Settings",
    runner: LLMRunner,
    delivery: Optional[DeliveryManager] = None,
    scheduler: "TerryScheduler | None" = None,
) -> FastAPI:
    """Create and configure the FastAPI app."""

    if delivery is None:
        delivery = DeliveryManager()

    app = FastAPI(
        title="Terrybot Web UI",
        docs_url=None, redoc_url=None, openapi_url=None,
    )
    app.add_middleware(SecurityHeadersMiddleware)

    auth_token = settings.web.auth_token
    rate_limiter = get_rate_limiter()
    _csrf_token = secrets.token_hex(32)  # stable per process lifetime

    _webhook_timestamps: dict[str, list[float]] = {}

    def _webhook_allowed(ip: str) -> bool:
        now = time.monotonic()
        window_start = now - 60.0
        ts = [t for t in _webhook_timestamps.get(ip, []) if t > window_start]
        if ts:
            _webhook_timestamps[ip] = ts
        else:
            _webhook_timestamps.pop(ip, None)  # evict empty entry
        if len(ts) >= WEBHOOK_RATE_LIMIT_REQUESTS:
            return False
        _webhook_timestamps[ip].append(now)
        return True

    def _check_dashboard_token(request: Request) -> bool:
        provided = request.query_params.get("token", "")
        return bool(auth_token) and secrets.compare_digest(
            _normalize_token(provided), _normalize_token(auth_token)
        )

    # ── Static routes ─────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        return HTMLResponse(content=_HTML)

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    # ── Dashboard ─────────────────────────────────────────────────────────────

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        if not _check_dashboard_token(request):
            return HTMLResponse("Unauthorized", status_code=401)
        token = request.query_params.get("token", "")
        html = (
            _DASHBOARD_HTML
            .replace("{token}", _html_escape(token))
            .replace("{sessions_html}", _render_sessions(runner))
            .replace("{jobs_html}", _render_jobs(scheduler))
            .replace("{pending_html}", _render_pending(token, _csrf_token))
            .replace("{approved_html}", _render_approved(token, _csrf_token))
        )
        return HTMLResponse(content=html)

    @app.post("/dashboard/tools/{name}/approve")
    async def dashboard_approve(name: str, request: Request) -> HTMLResponse | RedirectResponse:
        if not _check_dashboard_token(request):
            return HTMLResponse("Unauthorized", status_code=401)
        form_data = await request.form()
        if form_data.get("csrf_token") != _csrf_token:
            return HTMLResponse("Forbidden", status_code=403)
        from agent.tool_manager import approve_tool
        approve_tool(name)
        token = request.query_params.get("token", "")
        return RedirectResponse(f"/dashboard?token={token}", status_code=303)

    @app.post("/dashboard/tools/{name}/reject")
    async def dashboard_reject(name: str, request: Request) -> HTMLResponse | RedirectResponse:
        if not _check_dashboard_token(request):
            return HTMLResponse("Unauthorized", status_code=401)
        form_data = await request.form()
        if form_data.get("csrf_token") != _csrf_token:
            return HTMLResponse("Forbidden", status_code=403)
        from agent.tool_manager import reject_tool
        reject_tool(name)
        token = request.query_params.get("token", "")
        return RedirectResponse(f"/dashboard?token={token}", status_code=303)

    @app.post("/dashboard/tools/{name}/remove-approved")
    async def dashboard_remove(name: str, request: Request) -> HTMLResponse | RedirectResponse:
        if not _check_dashboard_token(request):
            return HTMLResponse("Unauthorized", status_code=401)
        form_data = await request.form()
        if form_data.get("csrf_token") != _csrf_token:
            return HTMLResponse("Forbidden", status_code=403)
        from agent.tool_manager import remove_approved_tool
        remove_approved_tool(name)
        token = request.query_params.get("token", "")
        return RedirectResponse(f"/dashboard?token={token}", status_code=303)

    # ── Dashboard JSON APIs ───────────────────────────────────────────────────

    @app.get("/api/sessions")
    async def api_sessions(request: Request) -> JSONResponse:
        if not _check_dashboard_token(request):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        sessions = runner._sessions.all_sessions()
        return JSONResponse([
            {
                "id": sid,
                "messages": len(s.history),
                "model": s.model,
                "pending_command": s.pending_command,
                "last_active": s.last_active,
            }
            for sid, s in sessions.items()
        ])

    @app.get("/api/jobs")
    async def api_jobs(request: Request) -> JSONResponse:
        if not _check_dashboard_token(request):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        if scheduler is None:
            return JSONResponse([])
        return JSONResponse([
            {
                "id": j.id,
                "name": j.name,
                "next_run": str(j.next_run_time) if j.next_run_time else None,
            }
            for j in scheduler.underlying.get_jobs()
        ])

    @app.get("/api/pending")
    async def api_pending(request: Request) -> JSONResponse:
        if not _check_dashboard_token(request):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        from agent.tool_manager import list_pending
        return JSONResponse(list_pending())

    @app.get("/api/approved")
    async def api_approved(request: Request) -> JSONResponse:
        if not _check_dashboard_token(request):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        from agent.tool_manager import list_approved
        return JSONResponse(list_approved())

    # ── Webhook ───────────────────────────────────────────────────────────────

    @app.post("/webhook/{name}")
    async def webhook(name: str, request: Request) -> JSONResponse:
        client_ip = "unknown"
        if request.client:
            client_ip = request.client.host

        # HMAC signature check (optional — only if webhook_secret is configured)
        if settings.web.webhook_secret:
            sig_header = request.headers.get("X-Hub-Signature-256", "")
            raw_body = await request.body()
            expected = "sha256=" + _hmac.new(
                settings.web.webhook_secret.encode(), raw_body, hashlib.sha256
            ).hexdigest()
            if not secrets.compare_digest(sig_header.encode(), expected.encode()):
                return JSONResponse({"error": "Invalid signature"}, status_code=401)
        else:
            raw_body = await request.body()

        if not _webhook_allowed(client_ip):
            return JSONResponse({"error": "Rate limit exceeded."}, status_code=429)

        try:
            import json as _json
            body = _json.loads(raw_body)
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

    # ── WebSocket ─────────────────────────────────────────────────────────────

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        import asyncio

        origin = websocket.headers.get("origin")
        if not validate_ws_origin(origin):
            await websocket.close(code=4403, reason="Origin not allowed")
            return

        await websocket.accept()

        client_ip = "unknown"
        if websocket.client:
            client_ip = websocket.client.host

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

        session_id = f"web_{uuid.uuid4().hex}"
        ws_limiter = _WSRateLimiter()

        # Register with delivery manager for heartbeat messages
        delivery_q = delivery.register_web_client()
        # Flush any buffered messages to this client
        delivery.flush_all_pending_to_web(delivery_q)

        async def _delivery_pump() -> None:
            """Forward delivery queue messages to this WebSocket."""
            while True:
                payload = await delivery_q.get()
                try:
                    await websocket.send_json({
                        "type": "heartbeat",
                        "session_id": payload.get("session_id", ""),
                        "content": payload.get("message", ""),
                    })
                except Exception:
                    break

        pump_task = asyncio.ensure_future(_delivery_pump())

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

                    if not ws_limiter.is_allowed():
                        await websocket.send_json({"type": "error", "content": "Too many requests. Please slow down."})
                        continue

                    if content.strip() == "/compact":
                        result_text = await runner.compact_session(session_id)
                        await websocket.send_json({"type": "message", "content": result_text})
                        continue

                    if content.strip() == "/reset":
                        runner.reset_session(session_id)
                        await websocket.send_json({"type": "message", "content": "Conversation history cleared."})
                        continue

                    session = runner._sessions.get(session_id)
                    if session and session.pending_command:
                        normalized = content.strip().lower()
                        if normalized in ("confirm", "yes"):
                            cmd = session.pending_command
                            session.pending_command = None
                            runner._sessions.flush(session_id)
                            output = execute_pending_command(cmd)
                            await websocket.send_json({"type": "message", "content": f"Output:\n{output}"})
                        elif normalized in ("deny", "no", "cancel"):
                            session.pending_command = None
                            runner._sessions.flush(session_id)
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
            pump_task.cancel()
            await asyncio.gather(pump_task, return_exceptions=True)
            delivery.unregister_web_client(delivery_q)
            runner.delete_session(session_id)

    return app
