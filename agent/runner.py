"""
agent/runner.py — OpenRouter LLM runner for Terrybot.

Uses httpx for async requests. Handles tool calls in a loop.
All requests go to OpenRouter (per project CLAUDE.md requirement).
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import TYPE_CHECKING, Any, AsyncIterator, Optional

# asyncio.timeout() requires Python 3.11+. main.py enforces this at the CLI
# entry point, but guard here too so an accidental import on 3.10 fails fast
# with a clear message rather than an AttributeError deep inside run_turn().
if not hasattr(asyncio, "timeout"):
    raise RuntimeError(
        "Terrybot requires Python 3.11+ (asyncio.timeout not available). "
        f"Current: {sys.version_info.major}.{sys.version_info.minor}"
    )

import httpx

from agent.context import ToolContext
from agent.sanitize import SYSTEM_PROMPT, detect_injection_attempt, sanitize_user_input
from agent.session import SessionStore
from agent.tools import TOOL_DEFINITIONS, dispatch_tool

if TYPE_CHECKING:
    from config import Settings

OPENROUTER_BASE = "https://openrouter.ai/api/v1"
MAX_TOOL_ITERATIONS = 5    # prevent infinite tool-call loops
HTTP_TIMEOUT = 60.0        # per OpenRouter API call
RUN_TURN_TIMEOUT = 120.0   # global max per run_turn() call (covers tool loop)


class LLMRunner:
    """
    Manages LLM interactions via OpenRouter API.
    Handles tool-call loops, session history, and response delivery.
    """

    def __init__(self, settings: "Settings", sessions: SessionStore) -> None:
        self._settings = settings
        self._sessions = sessions

    # ── Public session management API ─────────────────────────────────────────
    # Use these instead of accessing _sessions directly.

    def reset_session(self, session_id: str) -> None:
        """Clear history for a session."""
        self._sessions.reset(session_id)

    def delete_session(self, session_id: str) -> None:
        """Remove a session entirely (e.g., on web disconnect)."""
        self._sessions.delete(session_id)

    def get_session_history_turns(self, session_id: str) -> int:
        """Return number of complete turns (user+assistant pairs) in session."""
        return self._sessions.history_length(session_id) // 2

    # ── LLM interaction ───────────────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._settings.openrouter.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/terrybot",
            "X-Title": "Terrybot",
        }

    def _model(self) -> str:
        return self._settings.agent.model or self._settings.openrouter.model

    def _model_for_session(self, session_id: str) -> str:
        """Return model to use: session override → global agent model → openrouter model."""
        session = self._sessions.get(session_id)
        if session and session.model:
            return session.model
        return self._model()

    def _fallback_models(self) -> list[str]:
        return self._settings.openrouter.fallback_models or []

    async def compact_session(self, session_id: str) -> str:
        """Summarize and compact session history to a single summary message."""
        session = self._sessions.get_or_create(session_id)
        if not session.history:
            return "Nothing to compact."

        history_text = "\n".join(
            f"{m.role}: {m.content[:200]}" for m in session.history
        )
        summary_msgs: list[dict[str, Any]] = [
            {"role": "system", "content": "Summarize this conversation in 2-3 sentences:"},
            {"role": "user", "content": history_text},
        ]
        data, _ = await self._call_openrouter(summary_msgs, model=self._model())
        if not data:
            return "Compact failed: could not reach AI service."

        choices = data.get("choices") or []
        if not choices:
            return "Compact failed: empty response."

        summary = choices[0].get("message", {}).get("content", "").strip()
        session.clear()
        session.add_message("assistant", f"[Conversation summary: {summary}]")
        return f"History compacted. Summary: {summary}"

    async def run_turn(
        self,
        session_id: str,
        user_text: str,
        stream_callback: Optional[Any] = None,
    ) -> str:
        """
        Process one user turn with a global timeout.

        Steps:
          1. Sanitize and detect injection
          2. Append to session history
          3. Call OpenRouter with tool-call loop (max RUN_TURN_TIMEOUT seconds total)
          4. Append assistant response to history
          5. Return final assistant text
        """
        try:
            async with asyncio.timeout(RUN_TURN_TIMEOUT):
                return await self._run_turn_inner(session_id, user_text, stream_callback)
        except asyncio.TimeoutError:
            print(
                f"[runner] run_turn timed out after {RUN_TURN_TIMEOUT}s for session {session_id!r}",
                file=sys.stderr,
            )
            # _run_turn_inner's finally block already added the assistant
            # message to session history, so just return the timeout message.
            return "Sorry, I took too long to respond. Please try again."

    async def _run_turn_inner(
        self,
        session_id: str,
        user_text: str,
        stream_callback: Optional[Any],
    ) -> str:
        # Detect prompt injection (log only — we always process)
        if detect_injection_attempt(user_text):
            print(
                f"[runner] Possible prompt injection attempt in session {session_id!r}",
                file=sys.stderr,
            )

        # Sanitize and tag user input
        sanitized = sanitize_user_input(user_text)

        # Get/create isolated session
        session = self._sessions.get_or_create(session_id)
        session.add_message("user", sanitized)

        # Compact history if needed
        session.compact(self._settings.agent.max_history_turns)

        # Build message list: system prompt + history
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT}
        ] + session.get_messages_for_api()

        # Build model failover list (session override takes precedence)
        primary = self._model_for_session(session_id)
        fallbacks = self._fallback_models()
        models = [primary] + fallbacks
        model_idx = 0

        # Tool-call loop — wrapped in try/finally so the session always gets
        # a paired assistant message even if an unexpected exception occurs.
        final_text = ""
        ctx = ToolContext(session_id=session_id, runner=self, settings=self._settings)
        try:
            for iteration in range(MAX_TOOL_ITERATIONS):
                response_data, rate_limited = await self._call_openrouter(
                    messages, model=models[model_idx]
                )

                # Model failover on rate limit
                if response_data is None and rate_limited and model_idx < len(models) - 1:
                    model_idx += 1
                    print(
                        f"[runner] Rate limited on {models[model_idx - 1]!r}, "
                        f"switching to {models[model_idx]!r}",
                        file=sys.stderr,
                    )
                    continue  # retry same iteration with next model

                if response_data is None:
                    final_text = "Sorry, I couldn't reach the AI service. Please try again."
                    break

                choices = response_data.get("choices") or []
                if not choices:
                    final_text = "Sorry, I received an empty response from the AI service. Please try again."
                    break
                choice = choices[0]
                message = choice.get("message", {})
                content = message.get("content") or ""
                tool_calls = message.get("tool_calls") or []

                if tool_calls:
                    # Append assistant message with tool calls
                    messages.append({"role": "assistant", "content": content, "tool_calls": tool_calls})

                    # Execute each tool call
                    for tc in tool_calls:
                        tool_name = tc.get("function", {}).get("name", "")
                        tool_args_raw = tc.get("function", {}).get("arguments", "{}")
                        tool_call_id = tc.get("id", "")

                        try:
                            tool_args = (
                                json.loads(tool_args_raw)
                                if isinstance(tool_args_raw, str)
                                else tool_args_raw
                            )
                            if not isinstance(tool_args, dict):
                                raise ValueError("tool args must be a dict")
                        except (json.JSONDecodeError, ValueError) as exc:
                            print(
                                f"[runner] Bad tool args for '{tool_name}': {exc} "
                                f"(raw={tool_args_raw!r:.100})",
                                file=sys.stderr,
                            )
                            tool_args = {}

                        tool_result = await dispatch_tool(tool_name, tool_args, context=ctx)

                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call_id,
                            "content": tool_result,
                        })

                    continue  # get next response after tool execution

                else:
                    # Final text response
                    final_text = content
                    if stream_callback and final_text:
                        await stream_callback(final_text)
                    break
            else:
                final_text = "Sorry, I reached the tool execution limit. Please try a simpler request."
        except asyncio.TimeoutError:
            if not final_text:
                final_text = "Sorry, I took too long to respond. Please try again."
            raise
        except Exception:
            if not final_text:
                final_text = "Sorry, something went wrong. Please try again."
            raise
        finally:
            # Always append assistant response so session history stays paired
            session.add_message("assistant", final_text)

        return final_text

    async def _call_openrouter(
        self,
        messages: list[dict[str, Any]],
        model: Optional[str] = None,
    ) -> tuple[Optional[dict[str, Any]], bool]:
        """
        POST to OpenRouter /chat/completions.
        Returns (parsed JSON response, is_rate_limited).
        On error returns (None, bool).
        """
        if model is None:
            model = self._model()

        payload = {
            "model": model,
            "messages": messages,
            "tools": TOOL_DEFINITIONS,
            "tool_choice": "auto",
            "max_tokens": 2048,
        }

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
                response = await client.post(
                    f"{OPENROUTER_BASE}/chat/completions",
                    json=payload,
                    headers=self._headers(),
                )
                response.raise_for_status()
                return response.json(), False

        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            body = e.response.text[:300].replace("\n", " ")
            print(
                f"[runner] OpenRouter HTTP {status}: {body}",
                file=sys.stderr,
            )
            is_rate_limited = status in (429, 529)
            return None, is_rate_limited
        except httpx.RequestError as e:
            print(f"[runner] OpenRouter connection error: {type(e).__name__}", file=sys.stderr)
            return None, False
        except Exception as e:
            print(f"[runner] Unexpected OpenRouter error: {type(e).__name__}", file=sys.stderr)
            return None, False

    async def run_turn_streaming(
        self,
        session_id: str,
        user_text: str,
    ) -> AsyncIterator[str]:
        """
        Streaming variant: yields the complete response after run_turn finishes.
        (A true streaming implementation would require SSE parsing from OpenRouter.)
        """
        result = await self.run_turn(session_id, user_text)
        if result:
            yield result
