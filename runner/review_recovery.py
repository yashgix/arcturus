"""Verify a rejected engineering review's original candidate without executing it."""

import re
import stat
import time

from api_review import LIVE_MODELS, MAX_REQUEST, decode, encode, trial_plan
from concurrent_runs import APPROVAL_TTL_SECONDS
from engineering import CONTRACT, PROTECTED, reviewer_context, sha, stored_manifest
from workers import WorkerFailure


COVERAGE_FAILURES = {
    "coverage does not list every acceptance criterion exactly once",
    "acceptance coverage is unverified",
    "approval requires verified, met coverage for every criterion",
}


def evidence_file(path):
    if path.resolve() != path or not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_nlink != 1:
        raise ValueError("unsafe recovery evidence path")
    with path.open("rb") as file:
        data = file.read(MAX_REQUEST + 1)
    if len(data) > MAX_REQUEST:
        raise ValueError("recovery evidence exceeds size limit")
    return data


def verified_source(schedule, job, candidate, arc):
    def require(condition):
        if not condition:
            raise ValueError("original engineering candidate or protected evidence failed verification")

    require(isinstance(candidate, str) and re.fullmatch(r"[0-9a-f]{40}", candidate))
    source = schedule.job(job)
    require(
        source
        and source["scenario"] == "engineering"
        and source["state"] == "blocked"
        and not source["cancelled"]
        and source["reason"] in COVERAGE_FAILURES
    )
    manifest = stored_manifest(schedule, job)
    project, base = manifest["project"], manifest["base"]
    require(source["project"] == project and manifest["providers"]["reviewer"]["provider"] == "openai")
    with schedule.connect() as db:
        rows = db.execute(
            "SELECT r.*, a.candidate, a.model, a.request_sha256, a.reserve_microusd, a.state "
            "FROM engineering_request r JOIN api_review a ON a.job=r.job AND a.session=r.session "
            "WHERE r.job=? AND a.provider='openai' ORDER BY r.staged DESC LIMIT 1",
            (job,),
        ).fetchall()
    require(len(rows) == 1)
    row = rows[0]
    old = decode(row["plan"].encode())
    old_digest = old.pop("plan_sha256")
    body = old["body_utf8"].encode()
    receipt = decode(row["receipt"].encode())
    task = f"ENG-{job}"
    require(
        row["state"] == "rejected"
        and row["candidate"] == candidate == old["candidate"]
        and old["source_job"] == job
        and old["task"] == task
        and old["project"] == project
        and old["provider"] == "openai"
        and old["model"] == row["model"] == manifest["providers"]["reviewer"]["model"]
        and old["engineering"]
        == {
            "session": row["session"],
            "role": "reviewer",
            "staged": row["staged"],
            "manifest_sha256": sha(encode(manifest)),
        }
        and old_digest == row["digest"] == sha(encode(old))
        and row["request_sha256"] == old["body_sha256"] == sha(body)
        and receipt["reason"] == source["reason"]
        and receipt["http_status"] == 200
        and receipt["state"] == "rejected"
        and receipt["reserve_microusd"] == row["reserve_microusd"]
        and row["staged"] <= row["approved"] <= row["consumed"] < old["expires_at"]
    )
    packet = decode(decode(body)["input"].encode())
    spec = {
        "id": "T1",
        "acceptance": manifest["acceptance"],
        "owned_paths": manifest["allowed_paths"],
        "goal": manifest["goal"],
    }
    criteria = dict(arc.criteria_of(spec))
    require(
        packet["criteria"] == criteria
        and packet["owned_paths"] == spec["owned_paths"]
        and packet["base"] == base
        and packet["candidate"] == candidate
        and packet["title"] == manifest["task"]
        and packet["description"] == manifest["goal"]
        and packet["task"] == task
        and packet["project"] == project
        and packet["mode"] == "supervised_api"
    )
    work = schedule.workspace(job)
    repo, state = work / "repo", work / "runtime/runner-state"
    require(repo.resolve() == repo and state.resolve() == state)
    arc.verify_git_metadata(repo)
    journal = decode(evidence_file(state / "journal.json"))["tasks"][task]
    require(
        journal["project"] == project
        and journal["start"] == base
        and journal["spec"] == spec
        and journal["stage"] == "blocked"
        and journal["reason"] == source["reason"]
        and journal["execution_approval"] == old["engineering"]["manifest_sha256"]
        and any(d["session"] == row["session"] and d["role"] == "reviewer" for d in journal["dispatches"])
    )
    require(
        arc.git(repo, "rev-parse", "HEAD") == arc.git(repo, "rev-parse", journal["branch"]) == candidate
        and arc.git(repo, "symbolic-ref", "--short", "HEAD") == journal["branch"]
        and arc.git(repo, "rev-parse", "main") == base
        and not arc.git_bytes(repo, "diff", "--cached", "--name-only", "-z", candidate)
    )
    entries = arc.changed_tree_paths(repo, base, candidate, spec["owned_paths"], [PROTECTED])
    arc.verify_checkout(repo, candidate, entries)
    require(
        arc.tree_inventory(entries) == packet["inventory"]
        and sha(arc.git_bytes(repo, "show", f"{base}:{CONTRACT}")) == manifest["protected_tests"][CONTRACT]
        and arc.git_bytes(
            repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--binary", "--full-index", base, candidate
        )
        == packet["diff"].encode()
    )
    logs = packet["evidence"]
    test_names = [name for name in logs if re.fullmatch(rf"{task}-[0-9a-f]{{8}}-tests\.txt", name)]
    require(len(test_names) == 1)
    test_name = test_names[0]
    prefix = test_name.removesuffix("-tests.txt")
    probe_name = prefix + "-probe.json"
    require(logs.keys() == {test_name, probe_name, prefix + "-probe.txt"})
    for name, item in logs.items():
        data = evidence_file(state / name)
        require(sha(data) == item["sha256"] and data == item["text"].encode())
    probe = decode(logs[probe_name]["text"].encode())
    require(
        probe["signalDenied"] is True
        and probe["forkDenied"] is True
        and all(
            isinstance(probe[k], list) and probe[k] and all(v is True for v in probe[k])
            for k in ("reads", "writes", "contractReads")
        )
    )
    cases = arc.read_acceptance(repo, base, criteria)
    proof = decode(logs[test_name]["text"].encode())
    require(
        proof["commit"] == candidate
        and proof["protected_base"] == base
        and proof["inventory"] == packet["inventory"]
        and encode(proof["checks"])
        == encode(
            [
                {
                    "id": case["id"],
                    "criterion": case["criterion"],
                    "ok": True,
                    "exit": 0,
                    "result": {"value": case["expected"]},
                }
                for case in cases
            ]
        )
    )
    return reviewer_context(arc, repo, packet, cases), old_digest


def prepare(schedule, job, candidate, expires_at, arc, *, require_current=True):
    schedule.require_initialized()
    if type(expires_at) is not int or (
        require_current and not expires_at - APPROVAL_TTL_SECONDS <= time.time() < expires_at
    ):
        raise ValueError("recovery plan requires an explicit expiry within the approval window")
    try:
        packet, old_digest = verified_source(schedule, job, candidate, arc)
    except (arc.Blocked, AttributeError, KeyError, OSError, TypeError, ValueError, WorkerFailure) as exc:
        raise ValueError("original engineering candidate or protected evidence failed verification") from exc
    return trial_plan(
        packet,
        "openai",
        LIVE_MODELS["openai"],
        project=packet["project"],
        source_job=job,
        expires_at=expires_at,
        recovery={"rejected_plan_sha256": old_digest, "supplemental_reserve": True},
    )
