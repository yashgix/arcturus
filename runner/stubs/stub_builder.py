"""Gate stand-in for the Claude builder: same spawn/kill/state path, deterministic timing. Spawns a child
process so cancellation must kill a real process tree. Writes pids for the gate, commits one file, prints JSON."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ident, cycle = sys.argv[1], sys.argv[2]
ov = json.loads((Path.home() / "arcturus-pilot/runner/overrides.json").read_text())
secs = ov.get("sleep", {}).get(ident, 3)
child = subprocess.Popen(["/bin/sleep", str(secs + 30)])
pids = Path.home() / "arcturus-pilot/tests/out/stub-pids"
pids.mkdir(parents=True, exist_ok=True)
(pids / f"{ident}.json").write_text(json.dumps({"stub": os.getpid(), "child": child.pid}))
time.sleep(secs)
child.terminate()
Path(f"stub-{ident}-{cycle}.txt").write_text(f"stub change {ident} cycle {cycle}\n")
g = ["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=Stub", "-c", "user.email=stub@local"]
subprocess.run(g + ["add", "-A"], check=True)
subprocess.run(g + ["commit", "-q", "-m", f"{ident} stub cycle {cycle}"], check=True)
print(json.dumps({"result": f"stub build {ident} cycle {cycle}", "num_turns": 0, "total_cost_usd": 0}))
