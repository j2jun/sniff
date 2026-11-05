# sniff

**Sniff out malicious take-home assignments before they run.**

A widely shared 2026 story describes a crypto-exchange breach that started with a fake job
interview. The "assignment" quietly replaced a pyenv file, and that foothold led to a stolen
deploy token. The attack pattern is real and well documented: fake-recruiter malware hides in
install hooks, shell profiles, toolchain shims, and obfuscated blobs, all of which run before or
alongside the code you meant to run.

`sniff` reads a repo **without running anything** and tells you what it would touch.

```sh
python3 sniff.py ./assignment     # exit 1 if anything HIGH
python3 sniff.py --test           # self-check
```

```
HIGH   pipe-to-shell     install.sh:1  - downloads and runs code in one step
HIGH   toolchain-shim    fix_env.py:2  - touches pyenv/nvm/rbenv shims (the pyenv swap trick)
HIGH   npm-install-hook  package.json  - runs on npm install: 'node steal.js'
```

## What it checks
| Rule | Why |
|---|---|
| `pipe-to-shell` | `curl ... \| sh` runs code you never read |
| `shell-profile`, `toolchain-shim` | PATH hijack and persistence through `.zshrc` and `~/.pyenv/shims` |
| `persistence` | LaunchAgents, cron, and systemd entries survive reboots |
| `credential-path` | Reads `~/.ssh`, `~/.aws`, kube and docker configs, Keychain |
| `decode-exec`, `dynamic-exec`, `long-blob` | Obfuscated payloads |
| `npm-install-hook`, `setup-py`, `git-hook` | Code that runs on `npm install`, `pip install`, or `git commit` |
| `binary`, `hidden-unicode` | Prebuilt executables and Trojan Source characters |

A clean result doesn't make a repo safe. Next, run it in a sandbox: no network, no home
directory, no credentials.

```sh
docker run --rm -it --network none --read-only --tmpfs /tmp -v "$PWD/assignment:/work:ro" -w /work python:3.12-slim bash
```

## Agent setup
- `AGENTS.md`: the single source of agent instructions (Codex reads it natively)
- `CLAUDE.md`: imports `AGENTS.md` and adds Claude-only notes
- `.claude/settings.json`: shared Claude Code permissions (`settings.local.json` is gitignored)
- `.codex/config.toml`: project Codex sandbox and approval settings
