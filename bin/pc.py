"""Tiny wrapper around the pilot's pinned Paperclip CLI (board auth, local_trusted, isolated data dir)."""

import json
import os
import subprocess
import sys

P = os.path.realpath(os.environ.get("ARCTURUS_ROOT", os.path.dirname(os.path.dirname(__file__))))
X = f"{P}/paperclip-app/node_modules/.bin/paperclipai"
ENV = dict(
    os.environ,
    PATH=f"{P}/tools/node24/bin:{P}/tools/claude:" + os.environ["PATH"],
    PAPERCLIP_HOME=f"{P}/paperclip-home",
    PAPERCLIP_TELEMETRY_DISABLED="1",
    DO_NOT_TRACK="1",
)
for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CODEX_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"):
    ENV.pop(k, None)


def pc(*args, api_key=None, check=True):
    cmd = [X, *args, "--data-dir", f"{P}/paperclip-home", "--json"]
    if api_key:
        cmd += ["--api-key", api_key]
    r = subprocess.run(cmd, env=ENV, capture_output=True, text=True, cwd=f"{P}/paperclip-app")
    if check and r.returncode != 0:
        raise SystemExit(f"paperclipai {' '.join(args[:2])} failed: {r.stderr.strip()[:400]}")
    try:
        return json.loads(r.stdout) if r.stdout.strip() else None
    except json.JSONDecodeError:
        return {"_raw": r.stdout, "_err": r.stderr, "_code": r.returncode}


def company_id():
    return open(f"{P}/paperclip-home/pilot-company-id").read().strip()


def claude_agent(name, role, title, cwd, policy, turns, reports_to=None):
    p = {
        "name": name,
        "role": role,
        "title": title,
        "adapterType": "claude_local",
        "adapterConfig": {
            "engine": "cli",
            "command": f"{P}/tools/claude/claude",
            "dangerouslySkipPermissions": False,
            "cwd": cwd,
            "extraArgs": ["--settings", policy],
            "maxTurnsPerRun": turns,
            "timeoutSec": 1800,
            "graceSec": 20,
        },
        "runtimeConfig": {"heartbeat": {"enabled": False, "wakeOnDemand": True, "maxConcurrentRuns": 1}},
        "permissions": {"canCreateAgents": False, "canCreateSkills": False},
        "budgetMonthlyCents": 0,
    }
    if reports_to:
        p["reportsTo"] = reports_to
    return p


if __name__ == "__main__":
    print(json.dumps(pc(*sys.argv[1:]), indent=1)[:4000])


def api(method, path, body=None, token=None):
    """Direct HTTP call to the local Paperclip API. No token = board (local_trusted). Returns (status, json)."""
    import urllib.request
    import urllib.error

    port = int(os.environ.get("ARCTURUS_BOARD_PORT", "3100"))
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api{path}",
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"content-type": "application/json", **({"authorization": f"Bearer {token}"} if token else {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            t = r.read().decode()
            return r.status, (json.loads(t) if t else None)
    except urllib.error.HTTPError as e:
        t = e.read().decode()
        try:
            return e.code, json.loads(t)
        except Exception:
            return e.code, {"error": t[:200]}
