"""Internal process entry point for the authored offline engineering demo."""

import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import threading
import time

from api_review import decode, encode, mock_api_reviewer
from concurrent_runs import Scheduler
from workers import Dispatch, Limits, Result, Usage, Worker, WorkerFailure


def supervise(pipe, lease):
    os.fstat(lease)
    if os.getpgrp() != os.getpid() or select.select([pipe], [], [], 0)[0]:
        raise SystemExit("mock worker requires an active supervisor")

    def wait_for_parent():
        try:
            os.read(pipe, 1)
        finally:
            os.killpg(os.getpgrp(), signal.SIGKILL)

    threading.Thread(target=wait_for_parent, daemon=True).start()


def execute(schedule, job, node):
    item = schedule.job(job)
    if item is None or item["state"] != "running" or item["cancelled"]:
        raise SystemExit("mock task is no longer active")
    project, scenario = item["project"], item["scenario"]
    work = schedule.workspace(job)
    repo = work / "repo"
    runtime = work / "runtime"
    (runtime / "runner").mkdir(parents=True)
    config = {
        "projects": {project: {"dir": str(repo), "policy": "mock", "protected": ["test/acceptance"]}},
        "limits": {"max_reviews": 3, "max_repairs": 2},
    }
    (runtime / "runner/config.json").write_text(json.dumps(config))
    os.environ["ARCTURUS_ROOT"] = str(runtime)
    import arc

    repo.mkdir()
    arc.git(repo, "init", "-q", "-b", "main")
    arc.git(repo, "config", "user.name", "Arcturus Mock")
    arc.git(repo, "config", "user.email", "arcturus-mock@example.invalid")
    (repo / "src").mkdir()
    src = repo / "src/label.mjs"
    src.write_text("export const label = () => 'baseline';\n")
    contract = repo / arc.ACCEPTANCE_FILE
    contract.parent.mkdir(parents=True)
    contract.write_text(
        json.dumps(
            [
                {
                    "id": "label-positive",
                    "criterion": "T1.1",
                    "entry": "src/label.mjs",
                    "export": "label",
                    "args": [2],
                    "expected": f"{project}:2",
                }
            ]
        )
    )
    arc.git(repo, "add", "--all")
    arc.git(repo, "commit", "-qm", f"protected fixture for {project}")
    base = arc.git(repo, "rev-parse", "main")

    def acceptance(d, scratch, args, out, timeout, **kwargs):
        # This path runs only the authored fixture under Node's permission model.
        proof = kwargs["proof_input"]
        run = subprocess.run(
            [node, *args],
            cwd=d,
            timeout=timeout,
            input=proof,
            text=True,
            capture_output=True,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": str(scratch)},
        )
        Path(out).write_text(run.stdout + run.stderr)
        return run.returncode, run.stdout

    def mock_probe(d, out, nonce, keep, **kwargs):
        # Reduced real permission check. This receipt never represents the macOS host preflight.
        canaries = schedule.root / "project-canaries"
        peer_files = [str(path) for path in sorted(canaries.iterdir()) if path.name != project]
        if not peer_files or any(not Path(peer).is_file() for peer in peer_files):
            raise WorkerFailure("peer isolation canaries are missing")
        scratch = Path(d) / ".probe"
        scratch.mkdir()
        script = """
const fs = require('node:fs');
const [own, scratch, ...others] = process.argv.slice(1);
const deny = (operation) => {
    try { operation(); return 'allowed'; }
    catch (error) { return error.code; }
};
fs.readFileSync(own);
fs.writeFileSync(scratch, 'positive control');
const peers = others.map(file => ({
    read: deny(() => fs.readFileSync(file)),
    write: deny(() => fs.writeFileSync(file, 'unexpected write'))
}));
console.log(JSON.stringify(peers));
"""
        run = subprocess.run(
            [
                node,
                "--no-addons",
                "--permission",
                f"--allow-fs-read={d}",
                f"--allow-fs-write={scratch}",
                "-e",
                script,
                "--",
                str(Path(d) / "src/label.mjs"),
                str(scratch / "control"),
                *peer_files,
            ],
            cwd=d,
            timeout=kwargs.get("timeout", 10),
            text=True,
            capture_output=True,
            env={"PATH": "/usr/bin:/bin"},
        )
        Path(out).write_text(run.stdout + run.stderr)
        denied = {"read": "ERR_ACCESS_DENIED", "write": "ERR_ACCESS_DENIED"}
        if run.returncode or json.loads(run.stdout) != [denied] * len(peer_files):
            return False, ["mock Node peer read or write permission check failed"]
        Path(keep).write_text(
            json.dumps(
                {
                    "mode": "mock_node_permissions_only",
                    "nonce": nonce,
                    "own_read": "allowed",
                    "scratch_write": "allowed",
                    "peer_access": [denied] * len(peer_files),
                }
            )
        )
        return True, []

    arc.project_ids = lambda: {project: project}
    arc.validate_policy = lambda _: []
    arc.say = lambda *args: None
    arc.set_status = lambda *args: None
    arc.sandboxed_node = acceptance
    arc.run_probe = mock_probe
    identifier = f"MOCK-{job}"
    issue = {
        "id": identifier,
        "identifier": identifier,
        "projectId": project,
        "title": f"Label values for {project}",
        "description": "Prefix the project to each numeric value, including zero.",
    }
    spec = {"id": "T1", "owned_paths": ["src/"], "acceptance": ["Label each numeric value, including zero."]}

    def hold(phase):
        if not (work / f"hold-{phase}").exists():
            return False
        (work / f"{phase}-started").touch()
        while not (work / f"release-{phase}").exists():
            time.sleep(0.05)
        return True

    def build(request):
        if Path(request.workspace) != repo or request.project != project:
            raise WorkerFailure("mock builder received another workspace")
        bad = scenario == "repair" and not request.findings
        if request.findings and any(finding["file"] != "src/label.mjs" for finding in request.findings):
            raise WorkerFailure("unexpected mock repair target")
        if request.findings and not hold("repair"):
            time.sleep(0.5)  # make the fixture repair observable during the default demo
        expression = "value || 'missing'" if bad else "value"
        src.write_text(f"export const label = value => '{project}:' + ({expression});\n")
        arc.git(repo, "add", "src/label.mjs")
        arc.git(repo, "commit", "-qm", "repair zero handling" if request.findings else "implement labels")
        return Result(Usage(0, 0), {"exit": 0, "response": {"summary": "Updated the isolated label fixture."}})

    provider = "openai" if scenario == "repair" else "anthropic"
    model = f"mock-{provider}-review-v1"
    requests = 0

    def transport(body):
        nonlocal requests
        requests += 1
        (work / f"mock-request-{requests}.json").write_bytes(body)
        wire = decode(body)
        packet = json.loads(wire["messages"][-1]["content"])
        expected = f"'{project}:' + "
        if (
            packet["base"] != base
            or expected not in packet["diff"]
            or not packet["evidence"]
            or packet["criteria"] != dict(arc.criteria_of(spec))
        ):
            raise WorkerFailure("mock received incorrect candidate evidence")
        if requests == 1:
            hold("review")
        bad = "value || 'missing'" in packet["diff"]
        result = {
            "verdict": "changes_requested" if bad else "approve",
            "summary": "Reviewed label formatting.",
            "findings": [
                {
                    "severity": "medium",
                    "file": "src/label.mjs",
                    "issue": "Preserve zero instead of using a truthiness fallback.",
                }
            ]
            if bad
            else [],
            "tests_run": "Reviewed the runner's protected acceptance evidence.",
            "coverage": [
                {
                    "criterion": "T1.1",
                    "status": "unverified" if bad else "met",
                    "evidence": "Inspected the candidate's label expression and runner result.",
                }
            ],
        }
        response = encode(result).decode()
        if provider == "openai":
            return encode(
                {
                    "model": model,
                    "choices": [{"finish_reason": "stop", "message": {"content": response}}],
                    "usage": {"prompt_tokens": 128, "completion_tokens": 32, "total_tokens": 160},
                }
            )
        return encode(
            {
                "model": model,
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": response}],
                "usage": {"input_tokens": 128, "output_tokens": 32},
            }
        )

    def reserve(*args):
        return schedule.reserve(job, *args)

    dispatch = Dispatch(
        {
            "builder": Worker("fixture-builder", "mock", frozenset({"builder"}), frozenset({"edit"}), build),
            "api-review": mock_api_reviewer(provider, model, transport, reserve),
        },
        {"builder": "builder", "reviewer": "api-review"},
        Limits(seconds=45),
    )
    journal = arc.journal()
    status = arc.run_one(
        journal,
        issue,
        project,
        ctx={"spec": spec, "start": base, "dispatch": dispatch, "approval": "offline synthetic fixture only"},
    )
    task = journal["tasks"][identifier]
    if status == "ready" and (problems := arc.receipt_problems(journal, identifier)):
        raise WorkerFailure("invalid final fixture receipt: " + "; ".join(problems))
    if arc.git(repo, "rev-parse", "main") != base:
        raise WorkerFailure("fixture main moved")
    schedule.publish(
        job,
        {
            "status": status,
            "base": base,
            "candidate": task.get("candidate", {}).get("head"),
            "reason": task.get("reason"),
            "repairs": task.get("repairs", 0),
            "journal": str(arc.STATE / "journal.json"),
            "mock_only": True,
        },
    )


if __name__ == "__main__":
    root, job_id, parent_pipe, lease_fd, node_path = sys.argv[1:]
    supervise(int(parent_pipe), int(lease_fd))
    execute(Scheduler(root), int(job_id), node_path)
