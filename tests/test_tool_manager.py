"""
tests/test_tool_manager.py — Tests for agent/tool_manager.py.
"""
from __future__ import annotations

import json
import sys

import pytest

import agent.tool_manager as tm


@pytest.fixture(autouse=True)
def isolated_dirs(tmp_path, monkeypatch):
    """Redirect PENDING_DIR and APPROVED_DIR to tmp dirs."""
    pending = tmp_path / "pending_tools"
    approved = tmp_path / "approved_tools"
    pending.mkdir()
    approved.mkdir()
    monkeypatch.setattr(tm, "PENDING_DIR", pending)
    monkeypatch.setattr(tm, "APPROVED_DIR", approved)
    monkeypatch.setattr(tm, "TERRYBOT_DIR", tmp_path)


def _minimal_schema():
    return json.dumps({
        "name": "my_tool",
        "description": "A test tool",
        "parameters": {"type": "object", "properties": {}, "required": []},
    })


def test_propose_tool_writes_file():
    result = tm.propose_tool(
        name="my_tool",
        description="A test tool",
        schema=_minimal_schema(),
        implementation="async def my_tool(context, **kwargs):\n    return 'ok'",
    )
    assert "my_tool" in result
    assert (tm.PENDING_DIR / "my_tool.py").exists()


def test_load_approved_tools_finds_run_fallback(tmp_path):
    """If the module defines `run` instead of the tool name, it should still load."""
    code = '''
TOOL_DEFINITION = {
    "name": "my_tool",
    "description": "test",
    "parameters": {"type": "object", "properties": {}, "required": []},
}

async def run(context, **kwargs):
    return "hello from run"
'''
    tool_file = tm.APPROVED_DIR / "my_tool.py"
    tool_file.write_text(code)
    tool_file.chmod(0o600)

    defs, dispatch = tm.load_approved_tools()
    assert "my_tool" in dispatch
    assert callable(dispatch["my_tool"])


def test_approve_tool_moves_file():
    tm.propose_tool(
        name="good_tool",
        description="A good tool",
        schema=_minimal_schema().replace("my_tool", "good_tool"),
        implementation="async def good_tool(context, **kwargs):\n    return 'ok'",
    )
    result = tm.approve_tool("good_tool")
    assert "approved" in result.lower()
    assert (tm.APPROVED_DIR / "good_tool.py").exists()
    assert not (tm.PENDING_DIR / "good_tool.py").exists()


def test_reject_tool_deletes_pending():
    tm.propose_tool(
        name="bad_tool",
        description="A bad tool",
        schema=_minimal_schema().replace("my_tool", "bad_tool"),
        implementation="async def bad_tool(context, **kwargs):\n    return 'evil'",
    )
    result = tm.reject_tool("bad_tool")
    assert "rejected" in result.lower()
    assert not (tm.PENDING_DIR / "bad_tool.py").exists()


def test_remove_approved_tool_deletes_file():
    # First approve something
    code = '''
TOOL_DEFINITION = {"name": "rm_tool", "description": "", "parameters": {"type": "object", "properties": {}, "required": []}}
async def rm_tool(**kwargs): return "x"
'''
    f = tm.APPROVED_DIR / "rm_tool.py"
    f.write_text(code)
    f.chmod(0o600)

    result = tm.remove_approved_tool("rm_tool")
    assert "removed" in result.lower()
    assert not f.exists()
