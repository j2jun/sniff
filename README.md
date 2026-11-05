# endpoint-visibility-audit

"Don't use your work laptop to job hunt" is good advice, and this repo shows why. A managed
laptop can run EDR, MDM, DLP, a TLS-inspecting proxy, and employee-monitoring software. This
read-only script lists which of those are present on a Mac.

```sh
python3 audit.py          # audit this machine
python3 audit.py --test   # self-check
```

| Signal | What it means |
|---|---|
| EDR agent (Falcon, SentinelOne, Defender) | Process, file, and network telemetry goes to the security team |
| MDM enrollment (Jamf, Intune, Kandji) | IT can push profiles, certificates, and apps, and can wipe the device |
| Proxy / admin-trusted root CA | HTTPS can be decrypted and logged (TLS inspection) |
| DLP / insider risk (Code42, Forcepoint, Netskope) | File uploads, USB copies, and cloud syncs are flagged |
| Employee monitoring (Teramind, ActivTrak) | Screenshots, keystrokes, and app usage can be recorded |

No findings does **not** mean no monitoring. Network-side logging (DNS, firewall, CASB) is
invisible from the endpoint.

## Agent setup
- `AGENTS.md`: the single source of agent instructions (Codex reads it natively)
- `CLAUDE.md`: imports `AGENTS.md` and adds Claude-only notes
- `.claude/settings.json`: shared Claude Code permissions (`settings.local.json` is gitignored)
- `.codex/config.toml`: project Codex sandbox and approval settings
