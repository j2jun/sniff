# sniff

**Sniff out malicious take-home assignments before they run.**

The [$6.3B Binance heist](https://www.bleepingcomputer.com/news/security/binance-says-fake-job-interview-led-to-63-billion-crypto-heist/)
(Oct 2026, attributed to North Korea's TraderTraitor group) started with a fake job interview. The
take-home "assignment" ran malicious setup code that swapped a pyenv component on a work laptop,
and that foothold led to a container deployment token and the wallet signing service. Fake-recruiter
malware hides in install hooks, shell profiles, toolchain shims, and obfuscated blobs, all of which
run before or alongside the code you meant to run.

`sniff` reads a repo **without running anything** and tells you what it would touch.

| | macOS | Linux | Windows |
|---|---|---|---|
| Scan | ✅ | ✅ | ✅ (use `python` instead of `python3`) |
| Sandbox (`run`) | ✅ Docker Desktop | ✅ Docker | ✅ Docker Desktop with Linux containers |

CI runs the self-check on all three operating systems, and proves the sandbox's isolation on Linux.

```sh
python3 sniff.py ./assignment     # scan; exit 1 if anything HIGH
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
| `shell-profile`, `toolchain-shim` | PATH hijack and persistence through `.zshrc`, the PowerShell `$PROFILE`, and pyenv shims |
| `persistence`, `windows-persistence` | LaunchAgents, cron, systemd, Run keys, scheduled tasks, and services survive reboots |
| `ps-download-exec`, `encoded-powershell` | `iwr ... \| iex` and `powershell -enc`: the Windows versions of `curl \| sh` |
| `credential-path` | Reads `~/.ssh`, `~/.aws`, kube and docker configs, Keychain, Windows Credential Manager, browser logins |
| `decode-exec`, `dynamic-exec`, `long-blob` | Obfuscated payloads |
| `npm-install-hook`, `setup-py`, `git-hook` | Code that runs on `npm install`, `pip install`, or `git commit` |
| `binary`, `hidden-unicode` | Prebuilt executables and Trojan Source characters |

A clean result doesn't make a repo safe, so run it in the sandbox next:

```sh
python3 sniff.py run ./assignment            # scan, then a shell in a locked-down container
python3 sniff.py run ./assignment make test  # or run one command
```

The container has no network, a read-only root filesystem, no capabilities, and no host home
directory or credentials. It runs as `nobody` with memory and process limits. Your repo is mounted
read-only and copied into a throwaway tmpfs, so nothing the code writes survives. CI proves these
properties on every push (`.github/sandbox-check.sh`). With no network, `pip install` won't work;
that's deliberate.

## Agent setup
- `AGENTS.md`: the single source of agent instructions (Codex reads it natively)
- `CLAUDE.md`: imports `AGENTS.md` and adds Claude-only notes
- `.claude/settings.json`: shared Claude Code permissions (`settings.local.json` is gitignored)
- `.codex/config.toml`: project Codex sandbox and approval settings
