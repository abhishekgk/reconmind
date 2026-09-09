"""API-key management and automatic tool-config wiring.

Researchers add whatever paid/free API keys they can afford in the UI. On save we:
  1. store them (locally, chmod 600, never sent anywhere but the tool's own calls),
  2. regenerate subfinder's provider-config.yaml so subfinder immediately uses them,
  3. expose env-var overrides (GITHUB_TOKEN, SHODAN_API_KEY, ...) for other tools.

Every service is optional. More keys => more sources => more assets discovered.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from . import config

KEYS_FILE = config.DATA_DIR.parent / "keys.json"
SUBFINDER_CONFIG = config.DATA_DIR.parent / "subfinder-provider-config.yaml"


# Registry of supported services. Each spec declares:
#   id        - stable key used in storage/UI
#   label     - display name
#   fields    - one or more inputs (most services need a single "key")
#   get_url   - where a user can obtain a key (shown in UI)
#   note      - what it unlocks
#   subfinder - subfinder provider name (if it feeds subfinder)
#   sf_value  - template producing the subfinder value from the fields
#   env       - env vars to export for CLI tools, templated from fields
#   direct    - True if we also call this API directly in keyed_sources/network
KEY_SPECS: list[dict] = [
    {
        "id": "anthropic", "label": "Anthropic (Claude)",
        "fields": [{"name": "key", "label": "API Key (sk-ant-…)"}],
        "get_url": "https://console.anthropic.com/settings/keys",
        "note": "use Claude for far better, grounded LLM answers (replaces the local model)",
    },
    {
        "id": "virustotal", "label": "VirusTotal",
        "fields": [{"name": "key", "label": "API Key"}],
        "get_url": "https://www.virustotal.com/gui/my-apikey",
        "note": "passive subdomains", "subfinder": "virustotal",
        "sf_value": "{key}", "direct": True,
    },
    {
        "id": "securitytrails", "label": "SecurityTrails",
        "fields": [{"name": "key", "label": "API Key"}],
        "get_url": "https://securitytrails.com/app/account/credentials",
        "note": "passive subdomains + history", "subfinder": "securitytrails",
        "sf_value": "{key}", "direct": True,
    },
    {
        "id": "shodan", "label": "Shodan",
        "fields": [{"name": "key", "label": "API Key"}],
        "get_url": "https://account.shodan.io/",
        "note": "subdomains, IPs, open ports & services", "subfinder": "shodan",
        "sf_value": "{key}", "env": {"SHODAN_API_KEY": "{key}"}, "direct": True,
    },
    {
        "id": "censys", "label": "Censys",
        "fields": [{"name": "id", "label": "API ID"},
                   {"name": "secret", "label": "API Secret"}],
        "get_url": "https://search.censys.io/account/api",
        "note": "hosts & certificates", "subfinder": "censys",
        "sf_value": "{id}:{secret}",
    },
    {
        "id": "github", "label": "GitHub",
        "fields": [{"name": "token", "label": "Classic PAT — no scopes needed"}],
        "get_url": "https://github.com/settings/tokens/new",
        "note": "subdomains leaked in public code (use a classic token with NO scopes checked)",
        "subfinder": "github",
        "sf_value": "{token}", "env": {"GITHUB_TOKEN": "{token}"}, "direct": True,
    },
    {
        "id": "chaos", "label": "ProjectDiscovery Chaos",
        "fields": [{"name": "key", "label": "API Key"}],
        "get_url": "https://cloud.projectdiscovery.io/",
        "note": "bug-bounty subdomain dataset", "subfinder": "chaos",
        "sf_value": "{key}", "env": {"PDCP_API_KEY": "{key}"}, "direct": True,
    },
    {
        "id": "netlas", "label": "Netlas",
        "fields": [{"name": "key", "label": "API Key"}],
        "get_url": "https://app.netlas.io/", "note": "hosts & subdomains",
        "subfinder": "netlas", "sf_value": "{key}",
    },
    {
        "id": "leakix", "label": "LeakIX",
        "fields": [{"name": "key", "label": "API Key"}],
        "get_url": "https://leakix.net/", "note": "exposed services & subdomains",
        "subfinder": "leakix", "sf_value": "{key}",
    },
    {
        "id": "fullhunt", "label": "FullHunt",
        "fields": [{"name": "key", "label": "API Key"}],
        "get_url": "https://fullhunt.io/", "note": "attack-surface subdomains",
        "subfinder": "fullhunt", "sf_value": "{key}",
    },
    {
        "id": "binaryedge", "label": "BinaryEdge",
        "fields": [{"name": "key", "label": "API Key"}],
        "get_url": "https://app.binaryedge.io/account/api",
        "note": "internet scan data", "subfinder": "binaryedge", "sf_value": "{key}",
    },
    {
        "id": "bevigil", "label": "BeVigil",
        "fields": [{"name": "key", "label": "API Key"}],
        "get_url": "https://bevigil.com/osint-api",
        "note": "subdomains from mobile apps", "subfinder": "bevigil", "sf_value": "{key}",
    },
    {
        "id": "whoxy", "label": "Whoxy",
        "fields": [{"name": "key", "label": "API Key"}],
        "get_url": "https://www.whoxy.com/", "note": "reverse WHOIS -> related domains",
        "direct": True,
    },
]

SPEC_BY_ID = {s["id"]: s for s in KEY_SPECS}


def load_keys() -> dict[str, dict[str, str]]:
    if not KEYS_FILE.is_file():
        return {}
    try:
        return json.loads(KEYS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _has_all_fields(spec: dict, values: dict) -> bool:
    return all(values.get(f["name"], "").strip() for f in spec["fields"])


def save_keys(keys: dict[str, dict[str, str]],
              remove: list[str] | None = None) -> dict:
    """Merge new keys into the stored set and regenerate derived tool configs.

    Merge semantics: a service is updated only when *all* its fields are provided
    non-blank in this request. Services absent (or left blank) keep their existing
    stored value — so saving a new key never wipes previously saved ones. Pass
    service ids in `remove` to explicitly delete them.
    """
    stored = load_keys()

    for sid, values in (keys or {}).items():
        spec = SPEC_BY_ID.get(sid)
        if not spec or not isinstance(values, dict):
            continue
        vals = {f["name"]: str(values.get(f["name"], "")).strip() for f in spec["fields"]}
        if all(vals.values()):          # fully supplied -> add/replace
            stored[sid] = vals

    for sid in (remove or []):
        stored.pop(sid, None)

    # Write with restrictive permissions (secrets on disk).
    fd = os.open(KEYS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(stored, f, indent=2)

    write_subfinder_config(stored)
    return {"saved": sorted(stored), "subfinder_config": str(SUBFINDER_CONFIG)}


def write_subfinder_config(keys: dict[str, dict[str, str]]) -> None:
    """Render subfinder's YAML provider-config from configured keys.

    We avoid a YAML dependency; the format is simple key + list-of-strings.
    """
    lines: list[str] = []
    for spec in KEY_SPECS:
        provider = spec.get("subfinder")
        if not provider:
            continue
        vals = keys.get(spec["id"])
        if not vals or not _has_all_fields(spec, vals):
            continue
        value = spec["sf_value"].format(**vals)
        lines.append(f"{provider}:")
        lines.append(f"  - {value}")
    SUBFINDER_CONFIG.write_text("\n".join(lines) + ("\n" if lines else ""))


def env_overrides() -> dict[str, str]:
    """Env vars to inject into external tool subprocesses based on stored keys."""
    keys = load_keys()
    env: dict[str, str] = {}
    for spec in KEY_SPECS:
        if "env" not in spec:
            continue
        vals = keys.get(spec["id"])
        if not vals or not _has_all_fields(spec, vals):
            continue
        for var, tmpl in spec["env"].items():
            env[var] = tmpl.format(**vals)
    return env


def get_field(service_id: str, field: str = "key") -> str | None:
    """Fetch a single stored field value (used by direct API sources)."""
    vals = load_keys().get(service_id)
    if not vals:
        return None
    return vals.get(field) or None


def configured_ids() -> set[str]:
    keys = load_keys()
    return {sid for sid, v in keys.items()
            if _has_all_fields(SPEC_BY_ID[sid], v)} if keys else set()


def specs_for_ui() -> list[dict]:
    """Public spec list for the settings UI (never returns secret values)."""
    configured = configured_ids()
    return [
        {
            "id": s["id"], "label": s["label"], "fields": s["fields"],
            "get_url": s["get_url"], "note": s["note"],
            "feeds_subfinder": bool(s.get("subfinder")),
            "configured": s["id"] in configured,
        }
        for s in KEY_SPECS
    ]
