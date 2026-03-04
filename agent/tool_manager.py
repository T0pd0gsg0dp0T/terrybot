"""
agent/tool_manager.py — Tool proposal, approval, and dynamic loading.

Self-improvement flow:
  1. Agent calls propose_tool() — writes draft to ~/.terrybot/pending_tools/<name>.py
  2. User reviews code in dashboard at /dashboard
  3. User approves via dashboard button or `/approve-tool <name>` command
  4. Tool is moved to ~/.terrybot/approved_tools/<name>.py
  5. On next startup (or via reload), approved tools are loaded into the dispatcher

Security model:
  - Agent proposes, human approves — no auto-execution of agent-written code
  - Approved tools live in ~/.terrybot/ (chmod 700 dir, 600 files)
  - audit.py warns when approved tools are present
  - Tools are loaded as regular Python modules (same trust level as user-edited code)
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

TERRYBOT_DIR = Path.home() / ".terrybot"
PENDING_DIR = TERRYBOT_DIR / "pending_tools"
APPROVED_DIR = TERRYBOT_DIR / "approved_tools"

_TOOL_TEMPLATE = '''"""
{name} — User-proposed tool for Terrybot.
Description: {description}
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent.context import ToolContext

# Tool JSON schema (added to TOOL_DEFINITIONS automatically)
TOOL_DEFINITION = {schema}


# Tool implementation
# Signature must match: async def {name}(context: ToolContext, **kwargs) -> str
# OR: def {name}(**kwargs) -> str   (for sync tools that don't need session access)
{implementation}
'''


def _safe_tool_name(name: str) -> bool:
    """Tool name must be snake_case alphanumeric, 3-64 chars."""
    return bool(name) and 3 <= len(name) <= 64 and bool(re.match(r"^[a-z][a-z0-9_]*$", name))


def _ensure_dirs() -> None:
    for d in (PENDING_DIR, APPROVED_DIR):
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o700)


def propose_tool(name: str, description: str, schema: str, implementation: str) -> str:
    """
    Write a proposed tool to ~/.terrybot/pending_tools/<name>.py for user review.
    Returns status message.
    """
    if not _safe_tool_name(name):
        return "Error: Tool name must be lowercase snake_case, 3-64 chars (e.g. 'search_web')."

    # Validate schema is valid JSON
    try:
        schema_parsed = json.loads(schema) if isinstance(schema, str) else schema
        schema_str = json.dumps(schema_parsed, indent=2)
    except (json.JSONDecodeError, TypeError):
        return "Error: schema must be valid JSON (OpenAI function-calling format)."

    if not implementation.strip():
        return "Error: implementation code cannot be empty."

    _ensure_dirs()

    pending_file = PENDING_DIR / f"{name}.py"
    code = _TOOL_TEMPLATE.format(
        name=name,
        description=description,
        schema=schema_str,
        implementation=implementation.strip(),
    )

    pending_file.write_text(code, encoding="utf-8")
    pending_file.chmod(0o600)

    return (
        f"Tool '{name}' proposed and saved for review.\n"
        f"Review at: {pending_file}\n"
        f"Approve via dashboard at /dashboard or command: /approve-tool {name}"
    )


def list_pending() -> list[dict[str, str]]:
    """Return list of pending tool proposals with name and preview."""
    if not PENDING_DIR.exists():
        return []
    tools = []
    for f in sorted(PENDING_DIR.glob("*.py")):
        try:
            code = f.read_text(encoding="utf-8")
            tools.append({"name": f.stem, "code": code, "path": str(f)})
        except Exception:
            pass
    return tools


def list_approved() -> list[dict[str, str]]:
    """Return list of approved tools."""
    if not APPROVED_DIR.exists():
        return []
    tools = []
    for f in sorted(APPROVED_DIR.glob("*.py")):
        try:
            code = f.read_text(encoding="utf-8")
            tools.append({"name": f.stem, "code": code, "path": str(f)})
        except Exception:
            pass
    return tools


def approve_tool(name: str) -> str:
    """Move a pending tool to approved_tools. Returns status."""
    if not _safe_tool_name(name):
        return "Error: Invalid tool name."
    _ensure_dirs()
    src = PENDING_DIR / f"{name}.py"
    dst = APPROVED_DIR / f"{name}.py"
    if not src.exists():
        return f"Error: No pending tool named '{name}'."
    code = src.read_text(encoding="utf-8")
    dst.write_text(code, encoding="utf-8")
    dst.chmod(0o600)
    src.unlink()
    return f"Tool '{name}' approved. Restart Terrybot (or call /reload-tools) to activate."


def reject_tool(name: str) -> str:
    """Delete a pending tool proposal. Returns status."""
    if not _safe_tool_name(name):
        return "Error: Invalid tool name."
    src = PENDING_DIR / f"{name}.py"
    if not src.exists():
        return f"Error: No pending tool named '{name}'."
    src.unlink()
    return f"Tool proposal '{name}' rejected and deleted."


def remove_approved_tool(name: str) -> str:
    """Delete an approved tool. Requires restart to take effect."""
    if not _safe_tool_name(name):
        return "Error: Invalid tool name."
    dst = APPROVED_DIR / f"{name}.py"
    if not dst.exists():
        return f"Error: No approved tool named '{name}'."
    dst.unlink()
    return f"Approved tool '{name}' removed. Restart Terrybot to deactivate."


def load_approved_tools() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Dynamically load all approved tools.
    Returns (tool_definitions, dispatch_dict).
    dispatch_dict maps tool_name -> callable.
    """
    if not APPROVED_DIR.exists():
        return [], {}

    definitions: list[dict[str, Any]] = []
    dispatch: dict[str, Any] = {}

    for tool_file in sorted(APPROVED_DIR.glob("*.py")):
        name = tool_file.stem
        try:
            spec = importlib.util.spec_from_file_location(f"user_tool_{name}", tool_file)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore[attr-defined]

            tool_def = getattr(module, "TOOL_DEFINITION", None)
            func = getattr(module, name, None) or getattr(module, "run", None)

            if tool_def is None:
                print(f"[tool_manager] {name}.py missing TOOL_DEFINITION — skipped", file=sys.stderr)
                continue
            if func is None or not callable(func):
                print(f"[tool_manager] {name}.py missing callable '{name}' or 'run' — skipped", file=sys.stderr)
                continue

            # Wrap in standard format
            definitions.append({"type": "function", "function": tool_def})
            dispatch[name] = func
            print(f"[tool_manager] Loaded approved tool: {name}", file=sys.stderr)

        except Exception as e:
            print(f"[tool_manager] Failed to load {tool_file.name}: {type(e).__name__}: {e}", file=sys.stderr)

    return definitions, dispatch
