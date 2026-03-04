"""
bot/notifications.py — OS desktop notification delivery.

Supports Linux (notify-send / libnotify) and macOS (osascript).
Gracefully no-ops on unsupported platforms.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys


def send_os_notification(title: str, message: str, icon: str = "dialog-information") -> str:
    """
    Send a desktop notification via the OS notification system.
    Returns a status string.
    """
    system = platform.system()
    title = title[:128].replace('"', "'")
    message = message[:256].replace('"', "'")

    try:
        if system == "Linux":
            if shutil.which("notify-send"):
                subprocess.run(
                    ["notify-send", "--icon", icon, "--app-name", "Terrybot", title, message],
                    timeout=5,
                    capture_output=True,
                )
                return "Notification sent (Linux/notify-send)."
            else:
                return "Error: notify-send not found. Install libnotify-bin."

        elif system == "Darwin":
            script = (
                f'display notification "{message}" '
                f'with title "Terrybot" '
                f'subtitle "{title}" '
                f'sound name "default"'
            )
            subprocess.run(
                ["osascript", "-e", script],
                timeout=5,
                capture_output=True,
            )
            return "Notification sent (macOS)."

        elif system == "Windows":
            # Basic fallback: print to stderr (avoid win10toast dependency)
            print(f"[notification] {title}: {message}", file=sys.stderr)
            return "Notification logged (Windows desktop notifications require win10toast)."

        else:
            return f"Error: Notifications not supported on {system!r}."

    except subprocess.TimeoutExpired:
        return "Error: Notification timed out."
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"
