"""Generate Claude Code worker policies (passed with --settings) from one definition.
Absolute paths use the documented '//' prefix; file-tool access uses Read/Edit rules only (Write(path) rules do
not match). validate() is called by the runner before every launch and refuses malformed policies."""

import json
import os
import re
import sys
from pathlib import Path

H = str(Path.home())
P = str(Path(os.environ.get("ARCTURUS_ROOT", Path(__file__).resolve().parents[1])).resolve())
PROJ = f"{P}/projects"
CFG = json.loads(Path(f"{P}/runner/config.json").read_text())
PROJECTS = list(CFG["projects"])  # every registered project is denied to every other worker
BASE_PROTECTED = ["test/isolation.probe.test.js", "test/acceptance"]
CONTROL = [
    f"{P}/runner",
    f"{P}/runner-state",
    f"{P}/bin",
    f"{P}/tests",
    f"{P}/policy",
    f"{P}/paperclip-home",
    f"{P}/paperclip-app",
    f"{H}/arcturus",
    f"{H}/.ssh",
    f"{H}/.aws",
    f"{H}/.codex",
    f"{H}/.config",
]
SOURCE = Path(__file__).resolve().parents[1]
if Path(P) != SOURCE:
    CONTROL += [str(SOURCE / name) for name in ("runner", "bin", "tests", ".git")]
if Path(P) != Path(H) / "arcturus-pilot":
    CONTROL.append(f"{H}/arcturus-pilot")
CONTROL_FILES = [f"{H}/.claude.json", f"{H}/.netrc", f"{H}/.gitconfig"]


def rules_for(own, readable_projects, protected=()):
    """protected: the project's extra protected paths from config (beyond the probe and test/acceptance)."""
    extra = [r for r in protected if r not in BASE_PROTECTED]
    allow = [f"Edit(/{own}/**)", "Bash"]
    deny = [
        f"Read(/{own}/.env)",
        f"Read(/{own}/secrets/**)",
        f"Edit(/{own}/.git/config)",
        f"Edit(/{own}/.git/hooks/**)",
        f"Edit(/{own}/.claude/**)",
        f"Edit(/{own}/test/isolation.probe.test.js)",
        f"Edit(/{own}/test/acceptance/**)",
        *[f"Edit(/{own}/{r})" for r in extra],
        *[f"Edit(/{own}/{r}/**)" for r in extra],
        "Bash(git push*)",
        "Bash(curl*)",
        "Bash(wget*)",
        "WebFetch",
        "WebSearch",
        "SendMessage",
        "ListAgents",
    ]
    for p in PROJECTS:
        d = f"{PROJ}/{p}"
        if d == own:
            continue
        if p in readable_projects:
            deny += [f"Read(/{d}/.env)", f"Read(/{d}/secrets/**)"]
        else:
            deny += [f"Read(/{d}/**)"]
        deny += [f"Edit(/{d}/**)"]
    for c in CONTROL:
        deny += [f"Read(/{c}/**)", f"Edit(/{c}/**)"]
    for f in CONTROL_FILES:
        deny += [f"Read(/{f})", f"Edit(/{f})"]
    deny_read = (
        [d for d in CONTROL]
        + [f"{own}/.env", f"{own}/secrets"]
        + [f"{PROJ}/{p}" for p in PROJECTS if f"{PROJ}/{p}" != own and p not in readable_projects]
        + [f"{PROJ}/{p}/secrets" for p in readable_projects]
        + CONTROL_FILES
    )
    return {
        "permissions": {"allow": allow, "deny": deny},
        "sandbox": {
            "enabled": True,
            "failIfUnavailable": True,
            "allowUnsandboxedCommands": False,
            "network": {"allowedDomains": []},
            "filesystem": {
                "denyRead": sorted(set(deny_read)),
                "denyWrite": [
                    f"{own}/.git/config",
                    f"{own}/.git/hooks",
                    f"{own}/.claude",
                    f"{own}/test/isolation.probe.test.js",
                    f"{own}/test/acceptance",
                    *[f"{own}/{r}" for r in extra],
                ],
            },
        },
    }


def validate(policy_path):
    """Return a list of problems; empty means OK. Absolute paths in rules must start with '//'."""
    c = json.loads(Path(policy_path).read_text())
    probs = []
    for kind in ("allow", "deny"):
        for r in c["permissions"][kind]:
            m = re.fullmatch(r"(\w+)\((.*)\)", r)
            if not m:
                continue
            tool, arg = m.groups()
            if tool == "Write":
                probs.append(f"{r}: Write(path) rules never match; use Edit")
            if tool in ("Read", "Edit") and arg.startswith("/") and not arg.startswith("//"):
                probs.append(f"{r}: single-slash path is settings-relative, not absolute")
            if tool in ("Read", "Edit") and arg.startswith("//") and not arg[1:].startswith(H):
                probs.append(f"{r}: absolute path outside home is unexpected")
    sb = c.get("sandbox", {})
    if not (sb.get("enabled") and sb.get("failIfUnavailable") and sb.get("allowUnsandboxedCommands") is False):
        probs.append("sandbox must be enabled, failIfUnavailable, no unsandboxed retry")
    if sb.get("network", {}).get("allowedDomains"):
        probs.append("network allowlist must be empty")
    return probs


if __name__ == "__main__":
    # "readonly": untracked paths workers must not change either (e.g. a pinned node_modules); not Git-checked
    out = {
        n: rules_for(c["dir"], [], [*c.get("protected", ()), *c.get("readonly", ())])
        for n, c in CFG["projects"].items()
    }
    out["_lead"] = rules_for(f"{PROJ}/_lead", PROJECTS)
    for n, c in out.items():
        f = Path(P) / "policy" / f"{n}.json"
        f.write_text(json.dumps(c, indent=1))
        probs = validate(f)
        print(n, "OK" if not probs else probs)
    sys.exit(0)
