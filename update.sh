#!/usr/bin/env bash
# One-command update for ReconMind — pulls the latest code and refreshes deps.
# Safe to re-run anytime. Your ~/.reconmind data (scans, keys, findings) is
# untouched (it lives outside the repo).
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .git ]; then
  echo "This copy isn't a git clone, so there's nothing to pull."
  echo "Grab updates with:  git clone https://github.com/abhishekgk/reconmind"
  echo "(or re-download the latest ZIP from the GitHub page)."
  exit 1
fi

echo "==> Pulling latest…"
git pull --ff-only

if [ -d .venv ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
  echo "==> Refreshing Python deps…"
  python -m pip install -q --upgrade -r requirements.txt
fi

echo "==> Done. Restart ReconMind:  python run.py"
