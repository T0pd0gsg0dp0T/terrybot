"""
crypto.py — Fernet-based encrypted credential store for Terrybot.

Key derivation (corrected):
  - IKM  = local_secret (32 cryptographically random bytes from ~/.terrybot/secret.key)
  - Salt  = SHA-256(machine_id) — binds key to this machine; always 32 bytes
  - Info  = b"terrybot-v1:fernet-key" — domain separation
  - HKDF-SHA256 → 32 bytes → base64url → Fernet key

Design rationale:
  - No XOR: HKDF already handles combining inputs correctly via salt/IKM
  - Salt binding ensures credentials can't be decrypted on a different machine
  - local_secret is the primary entropy source (os.urandom(32))
  - Fallback when /etc/machine-id unavailable: persisted random ID (not hostname)

Storage:
  - ~/.terrybot/creds/<key>.enc  (chmod 600)
  - Decrypted values exist only in memory, never logged
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

TERRYBOT_DIR = Path.home() / ".terrybot"
CREDS_DIR = TERRYBOT_DIR / "creds"
SECRET_KEY_PATH = TERRYBOT_DIR / "secret.key"
FALLBACK_ID_PATH = TERRYBOT_DIR / "machine_id.fallback"
MACHINE_ID_PATH = Path("/etc/machine-id")


def _ensure_dirs() -> None:
    """Create ~/.terrybot/ and ~/.terrybot/creds/ with strict permissions."""
    TERRYBOT_DIR.mkdir(mode=0o700, exist_ok=True)
    TERRYBOT_DIR.chmod(0o700)
    CREDS_DIR.mkdir(mode=0o700, exist_ok=True)
    CREDS_DIR.chmod(0o700)


def _get_machine_id() -> bytes:
    """
    Read /etc/machine-id. If unavailable, use a persistent random fallback
    stored in ~/.terrybot/machine_id.fallback (chmod 600).

    Never uses hostname or other predictable values — the fallback is
    cryptographically random and machine-local, providing equivalent binding.
    """
    try:
        raw = MACHINE_ID_PATH.read_text().strip()
        if raw:
            return raw.encode()
    except OSError:
        pass

    # Create or load a persistent random fallback machine ID
    _ensure_dirs()
    if FALLBACK_ID_PATH.exists():
        _enforce_600(FALLBACK_ID_PATH)
        raw = FALLBACK_ID_PATH.read_text().strip()
        if raw:
            return raw.encode()

    # First run: generate and persist a random machine ID
    fallback = os.urandom(32).hex()
    FALLBACK_ID_PATH.write_text(fallback)
    FALLBACK_ID_PATH.chmod(0o600)
    print(
        "[crypto] /etc/machine-id unavailable; created random machine binding at "
        f"{FALLBACK_ID_PATH}",
        file=sys.stderr,
    )
    return fallback.encode()


def _get_or_create_local_secret() -> bytes:
    """Return the 32-byte local secret, creating it on first run (chmod 600)."""
    _ensure_dirs()
    if SECRET_KEY_PATH.exists():
        _enforce_600(SECRET_KEY_PATH)
        data = SECRET_KEY_PATH.read_bytes()
        if len(data) < 32:
            print(
                f"[crypto] CRITICAL: {SECRET_KEY_PATH} is corrupt (< 32 bytes). "
                "Delete it and re-run setup.",
                file=sys.stderr,
            )
            sys.exit(1)
        return data
    else:
        secret = os.urandom(32)
        SECRET_KEY_PATH.write_bytes(secret)
        SECRET_KEY_PATH.chmod(0o600)
        return secret


def _derive_fernet_key() -> bytes:
    """
    Derive a 32-byte Fernet key via HKDF-SHA256.

      IKM  = local_secret          (primary entropy: 32 random bytes)
      Salt = SHA-256(machine_id)   (machine binding; normalized to 32 bytes)
      Info = b"terrybot-v1:fernet-key"
    """
    machine_id = _get_machine_id()
    local_secret = _get_or_create_local_secret()

    # Normalize machine_id to 32 bytes via SHA-256 (consistent length regardless of source)
    salt = hashlib.sha256(machine_id).digest()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"terrybot-v1:fernet-key",
    )
    raw_key = hkdf.derive(local_secret)
    return base64.urlsafe_b64encode(raw_key)


def _enforce_600(path: Path) -> None:
    """Abort if a file's permissions are not exactly 600."""
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        print(
            f"[crypto] CRITICAL: {path} has permissions {oct(mode)}, expected 0o600. "
            "Fix with: chmod 600 " + str(path),
            file=sys.stderr,
        )
        sys.exit(1)


class CredentialStore:
    """Encrypted key-value store backed by Fernet symmetric encryption."""

    def __init__(self) -> None:
        _ensure_dirs()
        key = _derive_fernet_key()
        self._fernet = Fernet(key)

    def store(self, name: str, value: str) -> None:
        """Encrypt `value` and write to ~/.terrybot/creds/<name>.enc (chmod 600)."""
        if not name.isidentifier():
            raise ValueError(f"Credential name must be a valid identifier, got: {name!r}")
        _ensure_dirs()
        encrypted = self._fernet.encrypt(value.encode("utf-8"))
        path = CREDS_DIR / f"{name}.enc"
        path.write_bytes(encrypted)
        path.chmod(0o600)

    def load(self, name: str) -> str | None:
        """Decrypt and return credential value, or None if not stored."""
        path = CREDS_DIR / f"{name}.enc"
        if not path.exists():
            return None
        _enforce_600(path)
        try:
            decrypted = self._fernet.decrypt(path.read_bytes())
            return decrypted.decode("utf-8")
        except InvalidToken:
            # Wrong key or tampered ciphertext — CRITICAL
            print(
                f"[crypto] CRITICAL: Could not decrypt '{name}' — wrong key or tampered file. "
                "If you replaced secret.key or changed machines, you must re-run setup.",
                file=sys.stderr,
            )
            sys.exit(1)
        except UnicodeDecodeError:
            print(f"[crypto] Credential '{name}' decrypted but contains invalid UTF-8.", file=sys.stderr)
            return None

    def exists(self, name: str) -> bool:
        """Return True if credential `name` is stored."""
        return (CREDS_DIR / f"{name}.enc").exists()

    def delete(self, name: str) -> None:
        """Remove a stored credential."""
        path = CREDS_DIR / f"{name}.enc"
        if path.exists():
            path.unlink()

    def audit_permissions(self) -> list[str]:
        """Return list of permission violation messages (empty = all OK)."""
        issues: list[str] = []
        for enc_file in CREDS_DIR.glob("*.enc"):
            mode = stat.S_IMODE(enc_file.stat().st_mode)
            if mode != 0o600:
                issues.append(
                    f"CRITICAL: {enc_file} has permissions {oct(mode)}, expected 0o600"
                )
        dir_mode = stat.S_IMODE(TERRYBOT_DIR.stat().st_mode)
        if dir_mode != 0o700:
            issues.append(
                f"CRITICAL: {TERRYBOT_DIR} has permissions {oct(dir_mode)}, expected 0o700"
            )
        return issues
