# Contributing to ReconMind

Thanks for helping! ReconMind is built to be **small and readable** so newcomers can
add a source or tool in a few lines. Contributions of any size are welcome.

## Getting set up

```bash
git clone https://github.com/<your-username>/reconmind.git && cd reconmind
./install.sh            # or install.ps1 on Windows, or a manual venv
source .venv/bin/activate
python run.py
```

## Good first issues

- **Add a passive source** → `reconmind/recon/sources.py`. Each source is a small
  async function returning a set of hostnames; copy an existing one.
- **Add a tool wrapper** → `reconmind/recon/runners.py`, and register it in
  `reconmind/tools.py` so the Toolbox panel shows install hints for every OS.
- **Add an API-keyed source** → declare it in `reconmind/keys.py`'s `KEY_SPECS`
  (it auto-appears in the settings UI) and wire it in `recon/keyed_sources.py`.

See [`docs/ENHANCEMENTS.md`](docs/ENHANCEMENTS.md) for the prioritised backlog.

## Ground rules

- **Never commit secrets or scan data.** All user state lives in `~/.reconmind`;
  the `.gitignore` blocks `keys.json`, `data/`, wordlists, resolvers and `.env`.
  Double-check `git diff --staged` before every commit.
- **Keep external tools optional** — the keyless Python sources must always work.
- **Cross-platform**: no hardcoded paths; use `pathlib`/`os.name`, and add per-OS
  install hints (`tools._hint(...)`) for any new tool.
- **Teacher, not autopilot** — features should explain attack surface, not exploit it.
- Only scan assets you own or are authorised to test.

## Before opening a PR

- Byte-compile: `python -m compileall reconmind`
- Run a smoke scan: `python -m reconmind.cli example.com`
- Keep the change focused and the modules small.
