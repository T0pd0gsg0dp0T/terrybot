"""
agent/context.py — ToolContext dataclass for passing runner/settings to tools.

Avoids circular imports between runner ↔ tools by using Any type hints.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ToolContext:
    """Context passed to tools that need session/runner/settings access."""
    session_id: str
    runner: Any   # LLMRunner at runtime; Any to avoid circular import
    settings: Any # Settings
