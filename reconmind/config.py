"""Central configuration for ReconMind.

Everything a beginner might need to tweak lives here, with sane defaults so the
tool works out of the box. No config file is required to get started.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

# --- Paths --------------------------------------------------------------------

HOME = Path.home()

# Where scan results are stored (one folder per scan).
DATA_DIR = Path(os.environ.get("RECONMIND_DATA", HOME / ".reconmind" / "data"))

# External CLI tools are often installed here even when not on PATH.
# We prepend these so we always find Go-based tools (subfinder, httpx, ...).
# The list spans macOS, Linux and Windows; dirs that don't exist on this machine
# are filtered out in augment_path(), so listing all of them is harmless.
def _default_bin_dirs() -> list[str]:
    # Cross-platform: Go installs land in ~/go/bin on every OS (GOPATH default).
    dirs = [str(HOME / "go" / "bin")]
    if os.name == "nt":  # Windows
        dirs += [
            str(HOME / "scoop" / "shims"),               # scoop
            r"C:\ProgramData\chocolatey\bin",            # chocolatey
            str(HOME / "AppData" / "Local" / "Microsoft" / "WinGet" / "Links"),
        ]
    else:  # macOS + Linux
        dirs += [
            "/opt/homebrew/bin",                         # macOS (Apple Silicon)
            "/usr/local/bin",                            # macOS (Intel) / Linux
            str(HOME / ".local" / "bin"),                # pipx / user installs
            "/usr/bin", "/bin",
            "/snap/bin",                                 # Ubuntu snaps
            "/home/linuxbrew/.linuxbrew/bin",            # Linuxbrew
        ]
    return dirs


EXTRA_BIN_DIRS = _default_bin_dirs()


def augment_path() -> str:
    """Return a PATH string that includes common tool install dirs."""
    current = os.environ.get("PATH", "")
    parts = [p for p in EXTRA_BIN_DIRS if os.path.isdir(p)]
    return os.pathsep.join(parts + [current])


# Apply immediately on import so every subprocess inherits it.
os.environ["PATH"] = augment_path()


# --- Wordlists / resolvers ----------------------------------------------------

def _first_existing(*candidates: str | Path) -> str | None:
    for c in candidates:
        if c and Path(c).is_file():
            return str(c)
    return None


# Resolvers for mass DNS resolution. Drop a resolvers.txt in ~/.reconmind to use it.
RESOLVERS_FILE = _first_existing(
    os.environ.get("RECONMIND_RESOLVERS"),
    DATA_DIR.parent / "resolvers.txt",       # ~/.reconmind/resolvers.txt
)

# DNS bruteforce wordlist. Drop a wordlist.txt in ~/.reconmind for a real hunt;
# without one, active mode falls back to the tiny BUILTIN_SUBWORDS below.
WORDLIST_FILE = _first_existing(
    os.environ.get("RECONMIND_WORDLIST"),
    DATA_DIR.parent / "wordlist.txt",        # ~/.reconmind/wordlist.txt
)

FALLBACK_RESOLVERS = [
    "1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
    "1.0.0.1", "208.67.222.222", "208.67.220.220", "64.6.64.6",
]

# A tiny built-in bruteforce list so active mode does *something* useful even
# without a big wordlist. Real hunts should point RECONMIND_WORDLIST at a big one.
BUILTIN_SUBWORDS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp",
    "secure", "vpn", "api", "dev", "staging", "stage", "test", "portal", "admin",
    "cdn", "app", "apps", "mobile", "m", "beta", "internal", "intranet", "corp",
    "gateway", "gw", "proxy", "auth", "sso", "login", "dashboard", "monitor",
    "grafana", "kibana", "jenkins", "git", "gitlab", "jira", "confluence", "wiki",
    "docs", "support", "help", "status", "assets", "static", "img", "images",
    "media", "files", "download", "uploads", "s3", "storage", "backup", "db",
    "database", "sql", "redis", "cache", "queue", "kafka", "console", "manage",
    "qa", "uat", "sandbox", "demo", "old", "new", "v1", "v2", "api-dev",
    "api-staging", "internal-api", "graphql", "ws", "socket", "payment", "pay",
]


# --- Ollama (local LLM) -------------------------------------------------------

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
# Preferred models in order; we use the first one that is actually installed.
PREFERRED_MODELS = [
    os.environ.get("RECONMIND_MODEL", ""),
    "llama3.1",
    "llama3",
    "qwen2.5",
    "mistral",
    "gemma2",
]


# --- Server -------------------------------------------------------------------

HOST = os.environ.get("RECONMIND_HOST", "127.0.0.1")
PORT = int(os.environ.get("RECONMIND_PORT", "8710"))


def tool_path(name: str) -> str | None:
    """Return the absolute path to an external tool, or None if missing."""
    return shutil.which(name)


DATA_DIR.mkdir(parents=True, exist_ok=True)
