"""
security/audit.py — Startup security self-check for Terrybot.

Run via: python main.py audit

Checks:
  - ~/.terrybot/ permissions == 700              [CRITICAL]
  - ~/.terrybot/secret.key permissions == 600    [CRITICAL]
  - All .enc credential files permissions == 600 [CRITICAL]
  - web.host != "0.0.0.0"                        [CRITICAL]
  - openrouter.api_key loaded and non-empty       [CRITICAL]
  - telegram.allowed_user_ids is non-empty        [WARN]
  - Web port >= 1024                              [WARN]
  - Python >= 3.11                                [WARN]
"""

from __future__ import annotations

import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from config import Settings

TERRYBOT_DIR = Path.home() / ".terrybot"
CREDS_DIR = TERRYBOT_DIR / "creds"
SECRET_KEY_PATH = TERRYBOT_DIR / "secret.key"


@dataclass
class AuditFinding:
    severity: str   # "CRITICAL", "WARN", "OK"
    check: str
    detail: str


def run_audit(settings: "Settings") -> list[AuditFinding]:
    """Run all security checks. Returns list of findings."""
    findings: list[AuditFinding] = []

    # ── ~/.terrybot/ permissions ────────────────────────────────────────────
    if TERRYBOT_DIR.exists():
        mode = stat.S_IMODE(TERRYBOT_DIR.stat().st_mode)
        if mode == 0o700:
            findings.append(AuditFinding("OK", "~/.terrybot/ permissions", f"{oct(mode)} — correct"))
        else:
            findings.append(AuditFinding(
                "CRITICAL",
                "~/.terrybot/ permissions",
                f"Got {oct(mode)}, expected 0o700. Fix: chmod 700 {TERRYBOT_DIR}",
            ))
    else:
        findings.append(AuditFinding(
            "WARN",
            "~/.terrybot/ exists",
            "Directory not created yet — run `python main.py setup`",
        ))

    # ── secret.key permissions ───────────────────────────────────────────────
    if SECRET_KEY_PATH.exists():
        mode = stat.S_IMODE(SECRET_KEY_PATH.stat().st_mode)
        size = SECRET_KEY_PATH.stat().st_size
        if mode != 0o600:
            findings.append(AuditFinding(
                "CRITICAL",
                "secret.key permissions",
                f"Got {oct(mode)}, expected 0o600. Fix: chmod 600 {SECRET_KEY_PATH}",
            ))
        elif size < 32:
            findings.append(AuditFinding(
                "CRITICAL",
                "secret.key integrity",
                f"File is only {size} bytes (expected >= 32). Re-run setup.",
            ))
        else:
            findings.append(AuditFinding("OK", "secret.key", f"Permissions 0o600, size {size}B — correct"))
    else:
        findings.append(AuditFinding(
            "WARN",
            "secret.key exists",
            "Not created yet — run `python main.py setup`",
        ))

    # ── ~/.terrybot/creds/ directory permissions ─────────────────────────────
    if CREDS_DIR.exists():
        creds_mode = stat.S_IMODE(CREDS_DIR.stat().st_mode)
        if creds_mode == 0o700:
            findings.append(AuditFinding("OK", "~/.terrybot/creds/ permissions", f"{oct(creds_mode)} — correct"))
        else:
            findings.append(AuditFinding(
                "CRITICAL",
                "~/.terrybot/creds/ permissions",
                f"Got {oct(creds_mode)}, expected 0o700. Fix: chmod 700 {CREDS_DIR}",
            ))
    else:
        findings.append(AuditFinding(
            "WARN",
            "~/.terrybot/creds/ exists",
            "Directory not created yet — run `python main.py setup`",
        ))

    # ── .enc credential file permissions ────────────────────────────────────
    if CREDS_DIR.exists():
        enc_files = list(CREDS_DIR.glob("*.enc"))
        if not enc_files:
            findings.append(AuditFinding("WARN", "Credential files", "No .enc files found — run setup"))
        else:
            bad = []
            for f in enc_files:
                mode = stat.S_IMODE(f.stat().st_mode)
                if mode != 0o600:
                    bad.append(f"{f.name}: {oct(mode)}")
            if bad:
                findings.append(AuditFinding(
                    "CRITICAL",
                    "Credential file permissions",
                    "Wrong permissions: " + ", ".join(bad) + ". Fix: chmod 600 ~/.terrybot/creds/*.enc",
                ))
            else:
                findings.append(AuditFinding("OK", "Credential file permissions", "All .enc files are 0o600"))

    # ── web.host must be a safe loopback address ────────────────────────────
    _SAFE_HOSTS = {"127.0.0.1", "::1", "localhost"}
    if settings.web.host not in _SAFE_HOSTS:
        findings.append(AuditFinding(
            "CRITICAL",
            "web.host binding",
            f"host is {settings.web.host!r} — this may expose the service to the network! "
            f"Set to one of: {sorted(_SAFE_HOSTS)}",
        ))
    else:
        findings.append(AuditFinding("OK", "web.host binding", f"{settings.web.host} — localhost only"))

    # ── OpenRouter API key loaded ────────────────────────────────────────────
    if settings.openrouter.api_key:
        findings.append(AuditFinding("OK", "openrouter.api_key", "Loaded and non-empty"))
    else:
        findings.append(AuditFinding(
            "CRITICAL",
            "openrouter.api_key",
            "Not configured — run `python main.py setup`",
        ))

    # ── Telegram allowed_user_ids non-empty ─────────────────────────────────
    if settings.telegram.allowed_user_ids:
        findings.append(AuditFinding(
            "OK",
            "telegram.allowed_user_ids",
            f"{len(settings.telegram.allowed_user_ids)} user(s) configured",
        ))
    else:
        findings.append(AuditFinding(
            "WARN",
            "telegram.allowed_user_ids",
            "Empty — Telegram bot will reject all users",
        ))

    # ── Web port >= 1024 ────────────────────────────────────────────────────
    if settings.web.port >= 1024:
        findings.append(AuditFinding("OK", "web.port", f"{settings.web.port} — non-privileged port"))
    else:
        findings.append(AuditFinding(
            "WARN",
            "web.port",
            f"{settings.web.port} is a privileged port (<1024)",
        ))

    # ── Python version >= 3.11 ──────────────────────────────────────────────
    major, minor = sys.version_info.major, sys.version_info.minor
    if (major, minor) >= (3, 11):
        findings.append(AuditFinding("OK", "Python version", f"{major}.{minor}"))
    else:
        findings.append(AuditFinding(
            "WARN",
            "Python version",
            f"{major}.{minor} — Python 3.11+ recommended",
        ))

    # ── agent.allow_system_run ───────────────────────────────────────────────
    if settings.agent.allow_system_run:
        findings.append(AuditFinding(
            "WARN",
            "agent.allow_system_run",
            "Shell execution is ENABLED. Users can run arbitrary commands (with confirmation). "
            "Set agent.allow_system_run: false to disable.",
        ))
    else:
        findings.append(AuditFinding("OK", "agent.allow_system_run", "Shell execution disabled"))

    return findings


def print_audit_report(findings: list[AuditFinding]) -> bool:
    """Print audit report. Returns True if no CRITICAL issues found."""
    width = 60
    print("=" * width)
    print(" Terrybot Security Audit")
    print("=" * width)

    critical_count = 0
    warn_count = 0

    for f in findings:
        icon = {"CRITICAL": "✗", "WARN": "!", "OK": "✓"}.get(f.severity, "?")
        label = f"[{f.severity}]".ljust(10)
        print(f"  {icon} {label} {f.check}")
        if f.severity != "OK":
            print(f"             {f.detail}")
        if f.severity == "CRITICAL":
            critical_count += 1
        elif f.severity == "WARN":
            warn_count += 1

    print("-" * width)
    print(f"  Result: {critical_count} critical issue(s), {warn_count} warning(s)")
    print("=" * width)

    return critical_count == 0


def audit_and_exit_on_critical(settings: "Settings") -> None:
    """Run audit; exit with code 1 if any CRITICAL issues are found."""
    findings = run_audit(settings)
    ok = print_audit_report(findings)
    if not ok:
        print("\n[audit] Aborting startup due to critical security issues.", file=sys.stderr)
        sys.exit(1)
