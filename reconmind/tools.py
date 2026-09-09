"""Detect which external recon tools are available on this machine.

ReconMind is an *orchestrator*: it drives best-in-class open-source tools rather
than reinventing them. This module tells the UI what's installed and gives
copy-paste install hints for what's missing, so a newcomer can bootstrap a full
toolkit without hunting through blog posts.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

from . import config


def _os() -> str:
    """Return 'windows', 'mac', or 'linux' for install-hint selection."""
    if os.name == "nt":
        return "windows"
    if sys.platform == "darwin":
        return "mac"
    return "linux"


def _hint(mac: str, linux: str, windows: str) -> str:
    """Pick the install command for the current OS."""
    return {"mac": mac, "linux": linux, "windows": windows}[_os()]


# Go-based tools install identically on every OS (Go must be installed).
def _go(pkg: str) -> str:
    return f"go install {pkg}@latest"


@dataclass
class Tool:
    name: str
    purpose: str
    install: str
    required: bool = False
    path: str | None = field(default=None)

    @property
    def available(self) -> bool:
        return self.path is not None


# The toolbox ReconMind knows how to use. Nothing here is required for passive
# enumeration (which also uses pure-Python HTTP sources), but more tools = more
# thorough results.
TOOLBOX: list[Tool] = [
    Tool("subfinder", "Passive subdomain enumeration (aggregates 30+ sources)",
         "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    Tool("assetfinder", "Passive subdomains from certspotter/crt.sh/etc.",
         "go install github.com/tomnomnom/assetfinder@latest"),
    Tool("findomain", "Fast keyless subdomain enumeration (Rust)",
         _hint(mac="brew install findomain",
               linux="curl -L https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -o f.zip && unzip f.zip && chmod +x findomain && sudo mv findomain /usr/local/bin/",
               windows="scoop install findomain   # or download findomain-windows.exe from the GitHub releases")),
    Tool("amass", "Deep passive/active enumeration (OWASP)",
         _hint(mac="brew install amass",
               linux="go install github.com/owasp-amass/amass/v4/...@master",
               windows="go install github.com/owasp-amass/amass/v4/...@master")),
    Tool("httpx", "Probe hosts to find which are live (ProjectDiscovery)",
         "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    Tool("dnsx", "Fast DNS resolver/toolkit",
         "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    Tool("puredns", "Mass DNS resolve + bruteforce wrapper around massdns",
         "go install github.com/d3mondev/puredns/v2@latest"),
    Tool("gau", "Fetch known URLs (wayback/commoncrawl/otx) to mine hostnames",
         "go install github.com/lc/gau/v2/cmd/gau@latest"),
    Tool("waybackurls", "Historical URLs from the Wayback Machine",
         "go install github.com/tomnomnom/waybackurls@latest"),
    Tool("naabu", "Port scan resolved IPs (open ports without a paid Shodan plan)",
         "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    Tool("katana", "Crawl sites + parse JavaScript for endpoints",
         "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    Tool("tlsx", "Pull hostnames from TLS certificates",
         "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest"),
    Tool("gowitness", "Screenshot live hosts for visual triage (needs Chrome)",
         "go install github.com/sensepost/gowitness@latest"),
    Tool("ollama", "Local LLM runtime for explanations (optional)",
         _hint(mac="brew install ollama   # then: ollama pull llama3.1",
               linux="curl -fsSL https://ollama.com/install.sh | sh   # then: ollama pull llama3.1",
               windows="winget install Ollama.Ollama   # then: ollama pull llama3.1")),
]


def scan_toolbox() -> list[Tool]:
    """Populate each tool's path from the (augmented) PATH."""
    for t in TOOLBOX:
        t.path = config.tool_path(t.name)
    return TOOLBOX


def available_names() -> set[str]:
    return {t.name for t in scan_toolbox() if t.available}


def summary() -> dict:
    tools = scan_toolbox()
    return {
        "tools": [
            {
                "name": t.name,
                "purpose": t.purpose,
                "install": t.install,
                "available": t.available,
                "path": t.path,
            }
            for t in tools
        ],
        "available_count": sum(1 for t in tools if t.available),
        "total": len(tools),
    }
