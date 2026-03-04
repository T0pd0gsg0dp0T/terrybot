"""
config.py — Pydantic settings schema + YAML loader for Terrybot.

Secrets (api_key, bot_token, auth_token) are loaded from the encrypted
credential store (crypto.py), not from the YAML file.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, field_validator, model_validator

CONFIG_PATH = Path(os.environ.get("TERRYBOT_CONFIG", "terrybot.yaml"))
EXAMPLE_PATH = Path("terrybot.yaml.example")


class OpenRouterConfig(BaseModel):
    api_key: str = ""          # Populated from encrypted store at runtime
    model: str = "anthropic/claude-sonnet-4-6"
    fallback_models: list[str] = []


class TelegramConfig(BaseModel):
    bot_token: str = ""        # Populated from encrypted store at runtime
    allowed_user_ids: list[int] = []
    allowed_group_ids: list[int] = []
    require_mention_in_groups: bool = True

    @field_validator("allowed_user_ids")
    @classmethod
    def at_least_one_user(cls, v: list[int]) -> list[int]:
        # Warn but don't fail — audit.py will flag this as WARN
        return v


class WebConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8765
    auth_token: str = ""       # Populated from encrypted store at runtime

    @field_validator("host")
    @classmethod
    def no_public_bind(cls, v: str) -> str:
        # Whitelist safe loopback addresses only. Block all variants that bind
        # to all interfaces: "0.0.0.0" (IPv4), "::" (IPv6), "" (uvicorn treats
        # as all interfaces), "::ffff:0.0.0.0" (IPv6-mapped IPv4 wildcard).
        _SAFE_HOSTS = {"127.0.0.1", "::1", "localhost"}
        if v not in _SAFE_HOSTS:
            raise ValueError(
                f"web.host must be one of {sorted(_SAFE_HOSTS)} for local-only access. "
                f"Got: {v!r}. Values like '0.0.0.0' or '::' expose the service to the network."
            )
        return v

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not (1024 <= v <= 65535):
            raise ValueError("web.port must be between 1024 and 65535")
        return v


class AgentConfig(BaseModel):
    model: str = "anthropic/claude-sonnet-4-6"
    max_history_turns: int = 20
    allow_system_run: bool = False

    @field_validator("max_history_turns")
    @classmethod
    def reasonable_history(cls, v: int) -> int:
        if v < 1 or v > 200:
            raise ValueError("agent.max_history_turns must be between 1 and 200")
        return v


class SchedulerJob(BaseModel):
    id: str
    cron: str           # e.g. "0 9 * * 1-5"
    session_id: str     # target session
    message: str        # message to inject


class SchedulerConfig(BaseModel):
    jobs: list[SchedulerJob] = []


class Settings(BaseModel):
    openrouter: OpenRouterConfig = OpenRouterConfig()
    telegram: TelegramConfig = TelegramConfig()
    web: WebConfig = WebConfig()
    agent: AgentConfig = AgentConfig()
    scheduler: SchedulerConfig = SchedulerConfig()


def load_config(path: Path = CONFIG_PATH) -> Settings:
    """Load and validate terrybot.yaml. Returns Settings with defaults if file absent."""
    if not path.exists():
        if EXAMPLE_PATH.exists():
            print(
                f"[config] No {path} found. Copy {EXAMPLE_PATH} to {path} and run "
                "`python main.py setup` to configure secrets.",
                file=sys.stderr,
            )
        return Settings()

    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    try:
        return Settings.model_validate(raw)
    except Exception as exc:
        print(f"[config] Configuration error in {path}: {exc}", file=sys.stderr)
        sys.exit(1)
