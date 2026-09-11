"""Optional authentication gate for hosted deployments.

ReconMind is a localhost tool by default — auth stays **off** so learners have
zero friction. Set ``RECONMIND_AUTH=1`` (e.g. when hosting it) to require login
on every API route. Shared-workspace model: accounts are a gate only; everyone
who logs in shares the same ~/.reconmind (scans, keys, findings).

No third-party deps: passwords are hashed with stdlib ``hashlib.scrypt`` and a
per-user random salt; sessions are opaque server-side tokens in a signed cookie.

Security note: hosting an active scanner behind auth still exposes a powerful
tool — pair this with the scope allow-list (see scope.py) and run it behind
HTTPS (set ``RECONMIND_HTTPS=1`` so the session cookie is marked Secure).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from . import config

AUTH_FILE = config.DATA_DIR.parent / "auth.json"     # ~/.reconmind/auth.json (0600)
SETTINGS_FILE = config.DATA_DIR.parent / "settings.json"
SESSION_TTL = 7 * 24 * 3600                            # 7 days
COOKIE = "reconmind_session"

# token -> {"user": str, "exp": float}. In-memory: sessions drop on restart
# (users just log in again), which is fine for a self-hosted tool.
_SESSIONS: dict[str, dict] = {}


def _truthy(v: str) -> bool:
    return v.lower() in ("1", "true", "yes", "on")


def _settings() -> dict:
    try:
        return json.loads(SETTINGS_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def enabled() -> bool:
    """Auth is active when RECONMIND_AUTH is truthy OR it's been turned on and
    persisted in settings.json (so it survives restarts without the env var).
    An explicit RECONMIND_AUTH=0 wins, to allow a one-off local override."""
    env = os.environ.get("RECONMIND_AUTH", "")
    if env:
        return _truthy(env)
    return bool(_settings().get("auth"))


def set_enabled(on: bool) -> None:
    """Persist the auth on/off choice into settings.json (preserving other keys)."""
    s = _settings()
    s["auth"] = bool(on)
    try:
        SETTINGS_FILE.write_text(json.dumps(s, indent=2))
    except OSError:
        pass


def cookie_secure() -> bool:
    return _truthy(os.environ.get("RECONMIND_HTTPS", ""))


def _load() -> dict:
    try:
        return json.loads(AUTH_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {"users": {}}


def _save(d: dict) -> None:
    AUTH_FILE.write_text(json.dumps(d, indent=2))
    try:
        os.chmod(AUTH_FILE, 0o600)
    except OSError:
        pass


def user_count() -> int:
    return len(_load().get("users", {}))


def allow_registration() -> bool:
    """Bootstrap-safe default: allow registering the FIRST account only, then
    close it. Override with RECONMIND_ALLOW_REGISTER=1/0."""
    env = os.environ.get("RECONMIND_ALLOW_REGISTER", "").lower()
    if env in ("1", "true", "yes", "on"):
        return True
    if env in ("0", "false", "no", "off"):
        return False
    return user_count() == 0


def _hash(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1,
                          dklen=32).hex()


def _norm(username: str) -> str:
    return (username or "").strip().lower()


def register(username: str, password: str) -> tuple[bool, str]:
    username = _norm(username)
    if not username or not password:
        return False, "username and password are required"
    if len(username) > 64 or len(password) < 8:
        return False, "password must be at least 8 characters"
    if not allow_registration():
        return False, "registration is disabled — ask an admin to add your account"
    d = _load()
    users = d.setdefault("users", {})
    if username in users:
        return False, "that username is already taken"
    salt = secrets.token_bytes(16)
    users[username] = {"salt": salt.hex(), "hash": _hash(password, salt),
                       "created": time.time()}
    _save(d)
    return True, ""


def verify(username: str, password: str) -> bool:
    u = _load().get("users", {}).get(_norm(username))
    if not u:
        # Constant-ish time: still run a hash so timing doesn't reveal usernames.
        _hash(password, b"0" * 16)
        return False
    return hmac.compare_digest(_hash(password, bytes.fromhex(u["salt"])), u["hash"])


def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    _SESSIONS[token] = {"user": _norm(username), "exp": time.time() + SESSION_TTL}
    return token


def session_user(token: str | None) -> str | None:
    if not token:
        return None
    s = _SESSIONS.get(token)
    if not s:
        return None
    if s["exp"] < time.time():
        _SESSIONS.pop(token, None)
        return None
    return s["user"]


def destroy_session(token: str | None) -> None:
    if token:
        _SESSIONS.pop(token, None)
