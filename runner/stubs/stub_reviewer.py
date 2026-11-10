"""Gate stand-in for the Codex reviewer: scripted verdict per task and cycle (from overrides.json)."""

import json
import sys
from pathlib import Path

out, ident, cycle = sys.argv[1], sys.argv[2], int(sys.argv[3])
ov = json.loads((Path.home() / "arcturus-pilot/runner/overrides.json").read_text())
seq = ov.get("verdicts", {}).get(ident, ["approve"])
v = seq[min(cycle, len(seq) - 1)]
Path(out).write_text(
    json.dumps(
        {
            "verdict": v,
            "summary": f"scripted {v} for {ident} cycle {cycle}",
            "tests_run": "n/a (stub)",
            "findings": [] if v == "approve" else [{"severity": "medium", "file": "src", "issue": "scripted finding"}],
        }
    )
)
