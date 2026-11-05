"""Read-only macOS audit: what monitoring could your employer (or anyone) see on this Mac?

Inventory only. It never disables, hides, or tampers with anything.
Run: python3 audit.py        Self-check: python3 audit.py --test
"""
import os
import subprocess
import sys

# Substrings of app/daemon names -> (vendor, category). Lowercase.
# ponytail: name matching only; add bundle-ID/code-signature checks when false positives appear.
VENDORS = {
    "crowdstrike": ("CrowdStrike Falcon", "EDR"),
    "falcon": ("CrowdStrike Falcon", "EDR"),
    "sentinel": ("SentinelOne", "EDR"),
    "defender": ("Microsoft Defender", "EDR"),
    "cortex": ("Palo Alto Cortex XDR", "EDR"),
    "carbonblack": ("VMware Carbon Black", "EDR"),
    "tanium": ("Tanium", "EDR/asset mgmt"),
    "jamf": ("Jamf", "MDM"),
    "kandji": ("Kandji", "MDM"),
    "company portal": ("Microsoft Intune", "MDM"),
    "intune": ("Microsoft Intune", "MDM"),
    "zscaler": ("Zscaler", "Proxy/TLS inspection"),
    "netskope": ("Netskope", "Proxy/TLS inspection/DLP"),
    "forcepoint": ("Forcepoint", "DLP"),
    "code42": ("Code42 Incydr", "DLP/insider risk"),
    "teramind": ("Teramind", "Employee monitoring"),
    "activtrak": ("ActivTrak", "Employee monitoring"),
    "hubstaff": ("Hubstaff", "Employee monitoring"),
}

PLACES = ["/Applications", "/Library/LaunchDaemons", "/Library/LaunchAgents",
          "/Library/SystemExtensions"]


def match_vendors(names):
    """Return sorted unique (vendor, category, name) hits for the given file names."""
    hits = set()
    for name in names:
        low = name.lower()
        for key, (vendor, cat) in VENDORS.items():
            if key in low:
                hits.add((vendor, cat, name))
    return sorted(hits)


def sh(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"(unavailable: {e})"


def main():
    names = [n for p in PLACES if os.path.isdir(p) for n in os.listdir(p)]
    print("== Known monitoring software ==")
    for vendor, cat, name in match_vendors(names) or [("none found", "", "")]:
        print(f"  {vendor:24} {cat:28} {name}")
    print("\n== MDM enrollment ==\n" + sh("profiles", "status", "-type", "enrollment"))
    print("\n== Proxy settings (traffic routed through a gateway?) ==\n" + sh("scutil", "--proxy"))
    # Admin-trusted root CAs are how corporate TLS inspection reads "encrypted" HTTPS.
    print("\n== Admin-trusted root certificates (TLS inspection) ==\n"
          + sh("security", "dump-trust-settings", "-d"))
    print("\n== System extensions (EDR / network filters) ==\n" + sh("systemextensionsctl", "list"))


def test():
    hits = match_vendors(["Falcon.app", "Slack.app", "com.jamf.management.daemon.plist"])
    assert [h[0] for h in hits] == ["CrowdStrike Falcon", "Jamf"], hits
    assert match_vendors([]) == []
    print("ok")


if __name__ == "__main__":
    test() if "--test" in sys.argv else main()
