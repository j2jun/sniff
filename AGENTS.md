# AGENTS.md

Shared instructions for every coding agent (Codex reads this file; Claude Code reads it via CLAUDE.md).

## Project
Read-only macOS audit that shows what monitoring is present on a machine: EDR, MDM, DLP,
proxies/TLS inspection, employee-monitoring tools. It is a learning project in endpoint visibility.

## Commands
- Run: `python3 audit.py`
- Test: `python3 audit.py --test` (must print `ok` before any commit)

## Rules
- Inventory only. Never add code that disables, hides from, or evades security tooling.
- Python stdlib only. No new dependencies.
- Keep it one file until it genuinely hurts.
- Never commit secrets, `.env`, or real audit output from a work machine.
