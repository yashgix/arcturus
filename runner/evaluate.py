"""Run one investigation suite through the model broker under one signed grant.

The candidate replaykit runs as _arcexec in the sandbox with one loopback port and never holds a key. A trusted
replaykit (the verifier, pinned by tree hash in the grant) then rebuilds the whole report in the sandbox from the
broker's own transcript; its replay only succeeds if every packet the candidate sent is the one the verifier would
have sent. The run is valid only if the candidate's report is byte-identical to the verifier's, both match the
broker's record one to one, and nothing was left unfinished."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

import approve
from broker import Broker
from gateway import leaks
import grant as grants
import llm
import sandbox
from workflow import Stopped, Workflow

PROMPT = "replaykit/investigator/prompt.txt"
SCHEMA = "replaykit/investigator/action.schema.json"
CLEAN_ENV = {"PATH", "HOME", "LANG", "LC_CTYPE", "TMPDIR", "PWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING"}
COMPARED = ("packet_sha256", "kind", "action", "input_tokens", "output_tokens", "cost_microusd", "latency_ms")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def tree_sha256(root):
    """One hash over every file's path and bytes; links are refused."""
    root, hashed = Path(root), hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise Stopped(f"the verifier holds a link: {path}")
        if path.is_file():
            hashed.update(f"{path.relative_to(root)}\0{sha256(path.read_bytes())}\0".encode())
    return hashed.hexdigest()


def inputs(manifest):
    """The suite, its scenario, the prompt and the schema, read once from the verifier."""
    verifier = Path(manifest["verifier"])
    suite_raw = (verifier / manifest["suite"]).read_bytes()
    suite = json.loads(suite_raw)
    scenario_raw = ((verifier / manifest["suite"]).parent / suite["scenario"]).read_bytes()
    if sha256(scenario_raw) != suite["scenario_sha256"]:
        raise Stopped("the suite's scenario changed")
    scenario_id = json.loads(scenario_raw)["id"]
    return {
        "suite_raw": suite_raw,
        "prompt_raw": (verifier / PROMPT).read_bytes(),
        "schema_raw": (verifier / SCHEMA).read_bytes(),
        "limits": suite["limits"],
        "incidents": [
            f"{scenario_id}:{c['type']}:{c['service']}:{seed}" for c in suite["cases"] for seed in suite["seeds"]
        ],
    }


def pins(manifest, data):
    return {
        "suite_sha256": sha256(data["suite_raw"]),
        "prompt_sha256": sha256(data["prompt_raw"]),
        "schema_sha256": sha256(data["schema_raw"]),
        "verifier_sha256": tree_sha256(manifest["verifier"]),
    }


def audit(report, rows, models, incidents):
    """Every difference between a report's transcripts and the broker's record: same incidents in order, every model,
    turns 1..n without gaps or repeats, and the same recorded fields."""
    if [entry["id"] for entry in report["incidents"]] != list(incidents):
        return ["the report's incidents are not the suite's"]
    recorded = {(r["model"], r["incident"], r["turn"]): r for r in rows}
    problems, seen = [], set()
    for entry in report["incidents"]:
        for model in models:
            turns = entry["results"][model]["transcript"]
            if [t["turn"] for t in turns] != list(range(1, len(turns) + 1)):
                problems.append(f"{model} {entry['id']}: turns are not 1..{len(turns)}")
            for turn in turns:
                key = (model, entry["id"], turn["turn"])
                if key not in recorded:
                    problems.append(f"{key}: in the report, not in the broker transcript")
                    continue
                seen.add(key)
                problems += [f"{key}: {field} differs" for field in COMPARED if turn[field] != recorded[key][field]]
    problems += [f"{key}: in the broker transcript, not in the report" for key in sorted(set(recorded) - seen)]
    return problems


def recording(rows, models, incidents):
    """The broker's transcript in the shape the verifier's --replay reads."""
    turns = {(r["model"], r["incident"]): [] for r in rows}
    for row in sorted(rows, key=lambda r: r["turn"]):
        turns[(row["model"], row["incident"])].append({k: row[k] for k in ("turn", *COMPARED)})
    return {
        "incidents": [
            {"id": i, "results": {m: {"transcript": turns.get((m, i), [])} for m in models}} for i in incidents
        ]
    }


class Evaluation(Workflow):
    def __init__(self, root, connection=None, verify=True):
        super().__init__(root, connection, verify)
        self.workspace, self.verifier = Path(self.manifest["workspace"]), Path(self.manifest["verifier"])

    def checked_inputs(self):
        data = inputs(self.manifest)
        scope = self.grant["scope"]
        if scope["suite"] != self.manifest["suite"] or any(scope[k] != v for k, v in pins(self.manifest, data).items()):
            raise Stopped("the suite, prompt, schema or verifier changed since the grant was signed")
        given = (self.manifest["suite"], PROMPT, SCHEMA)
        if any((self.workspace / p).read_bytes() != (self.verifier / p).read_bytes() for p in given):
            raise Stopped("the candidate's given files differ from the verifier's")
        return data

    def job(self, name, cwd, read, out, args, port=None, env=None):
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(out),
            "TMPDIR": str(out),
            "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "en_US.UTF-8",
            **(env or {}),
        }
        argv = [self.manifest["python"], "-B", "-m", "replaykit", "investigate", self.manifest["suite"], *args]
        code, timed_out, strays = sandbox.run(
            argv,
            [cwd, *read],
            [out],
            environment,
            cwd,
            self.manifest["timeout_seconds"],
            self.root / f"{name}.stdout.txt",
            self.root / f"{name}.stderr.txt",
            port=port,
            deny_read=list(self.manifest["keys"].values()),
        )
        return {"exit": code, "timed_out": timed_out, "strays": strays}

    def investigate(self, data, keys):
        broker = Broker(
            self.ledger,
            self.manifest["company"]["id"],
            data["incidents"],
            data["limits"],
            data["prompt_raw"].decode(),
            json.loads(data["schema_raw"]),
            keys,
            self.connection,
            self.root / "broker-transcript.jsonl",
        )
        port = broker.start()
        try:
            out = self.root / "out"
            live = self.job(
                "investigate",
                self.workspace,
                [],
                out,
                ["--broker", f"http://127.0.0.1:{port}", "--out", str(out / "report.json")],
                port=port,
                env={"REPLAYKIT_BROKER_TOKEN": broker.token},
            )
        finally:
            broker.stop()
        if broker.stopped or broker.unfinished:  # fail closed: going on needs a new grant
            self.ledger.control("stop")
        return {
            **live,
            "broker_stopped": broker.stopped,
            "unfinished": broker.unfinished,
            "lanes_stopped": sorted(broker.lanes_stopped),
        }

    def rows(self):
        transcript = self.root / "broker-transcript.jsonl"
        return [json.loads(line) for line in transcript.read_text().splitlines()] if transcript.exists() else []

    def verify(self, data, rows):
        """The verifier's report, rebuilt from the broker's transcript alone."""
        given = self.root / "verify-in"
        given.mkdir()
        (given / "recorded.json").write_text(json.dumps(recording(rows, self.manifest["models"], data["incidents"])))
        out = self.root / "verify"
        result = self.job(
            "verify",
            self.verifier,
            [given],
            out,
            [
                "--replay",
                str(given / "recorded.json"),
                "--out",
                str(out / "report.json"),
                "--md",
                str(out / "report.md"),
            ],
        )
        return result, sandbox.read_job_file(out / "report.json")

    def check(self, data, live, keys):
        rows, models, incidents = self.rows(), self.manifest["models"], data["incidents"]
        candidate = sandbox.read_job_file(self.root / "out" / "report.json")
        verified, trusted = self.verify(data, rows)
        problems = [] if candidate else ["no candidate report"]
        problems += [] if trusted else ["no verifier report"]
        if candidate and leaks(candidate, list(keys.values())):
            problems.append("the candidate's report holds credential-like text")
        if candidate and trusted:
            problems += audit(json.loads(trusted), rows, models, incidents)
            problems += audit(json.loads(candidate), rows, models, incidents)
            problems += [] if candidate == trusted else ["the candidate's report differs from the verifier's"]
        if any(r["state"] == "reserved" for r in self.ledger.rows()):
            problems.append("a call is still reserved")
        clean = all(not j["timed_out"] and not j["strays"] and j["exit"] == 0 for j in (live, verified))
        return {
            "live": live,
            "verify": verified,
            "problems": problems,
            "calls": len(self.ledger.rows()),
            "committed_microusd": self.ledger.committed(),
            "valid": clean and not problems and not live["broker_stopped"] and not live["unfinished"],
        }

    def run(self):
        if set(os.environ) - CLEAN_ENV:
            raise Stopped(
                "start the runner with a clean environment: /usr/bin/env -i PATH=/usr/bin:/bin HOME=$HOME ..."
            )
        self.lock()
        if any((self.root / d).exists() for d in ("out", "verify", "verify-in")):
            raise Stopped("this run folder was already used; make a new one")
        self.gate()
        data = self.checked_inputs()  # after any pause, so the broker gets exactly the bytes that were checked
        for folder in ("out", "verify"):
            (self.root / folder).mkdir()
        keys = {llm.PRICES[m].provider: self.key(llm.PRICES[m].provider) for m in self.manifest["models"]}
        result = self.check(data, self.investigate(data, keys), keys)
        (self.root / "evaluation.json").write_text(json.dumps(result, indent=1))
        return result


def draft_grant(run_dir, ceiling, calls, hours):
    manifest = json.loads((Path(run_dir) / "run.json").read_text())
    company = manifest["company"]
    scope = {
        "companies": [company["name"]],
        "company_ids": [company["id"]],
        "operations": ["investigate"],
        "attempts_per_step": 1,
        "suite": manifest["suite"],
        **pins(manifest, inputs(manifest)),
        "lane_ceilings_microusd": {
            f"{company['id']}/{m}": round(usd * 1e6) for m, usd in manifest["lane_ceilings_usd"].items()
        },
    }
    return grants.write(run_dir, grants.draft("evaluate", scope, manifest["models"], ceiling, calls, hours))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run", type=Path)
    parser.add_argument("command", choices=("grant", "run", "pause", "resume", "stop", "revoke"))
    parser.add_argument("--ceiling", type=float)
    parser.add_argument("--calls", type=int)
    parser.add_argument("--hours", type=float, default=24)
    args = parser.parse_args(argv)
    try:
        if args.command == "grant":
            print(draft_grant(args.run, args.ceiling, args.calls, args.hours))
            return 0
        if args.command == "run":
            approve.ensure(args.run)
            print(json.dumps(Evaluation(args.run).run(), indent=1))
            return 0
        run = Evaluation(args.run, verify=False)
        run.ledger.control({"pause": "pause", "resume": "run", "stop": "stop", "revoke": "revoked"}[args.command])
        print(f"{run.grant['id']}: {run.ledger.state()}")
    except (grants.GrantError, ValueError, OSError, llm.SecurityStop, Stopped) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
