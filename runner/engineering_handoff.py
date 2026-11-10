"""Read-only, verified engineering results for downstream coordinator workers."""

import json
from pathlib import Path

from api_review import decode, encode
from engineering import PROTECTED, sha, stored_manifest
from review_recovery import evidence_file
from workers import WorkerFailure


def ready_result(schedule, job):
    import arc

    item = schedule.job(job)
    if not item or item["state"] != "ready" or item["cancelled"]:
        raise ValueError("engineering handoff requires a READY job")
    try:
        checkpoint = json.loads(item["checkpoint"])
        if item["scenario"] == "api-review":
            return recovery_result(schedule, job, item, checkpoint, arc)
        if item["scenario"] != "engineering":
            raise ValueError
        manifest = stored_manifest(schedule, job)
        work = schedule.workspace(job)
        repo, state = work / "repo", work / "runtime/runner-state"
        task_id = f"ENG-{job}"
        journal = decode(evidence_file(state / "journal.json"))
        task = journal["tasks"][task_id]
        config = {"projects": {item["project"]: {"dir": str(repo), "protected": [PROTECTED]}}}
        files = arc.evidence_files(task, state=state, config=config)
        if (
            task["project"] != item["project"]
            or task["execution_approval"] != sha(encode(manifest))
            or repo.resolve() != repo
            or state.resolve() != state
            or any(
                Path(path).parent != state or sha(evidence_file(Path(path))) != task["evidence"][kind]
                for kind, path in files.items()
            )
        ):
            raise ValueError
        if arc.receipt_problems(journal, task_id, state=state, config=config):
            raise ValueError
        review = next(entry for entry in reversed(task["dispatches"]) if entry["role"] == "reviewer")
        with schedule.connect() as db:
            row = db.execute(
                "SELECT a.*, r.receipt, r.digest, r.plan, r.consumed FROM api_review a JOIN engineering_request r "
                "ON r.job=a.job AND r.session=a.session WHERE a.job=? AND a.session=?",
                (job, review["session"]),
            ).fetchone()
        candidate = task["candidate"]
        if (
            not row
            or row["candidate"] != candidate["head"]
            or row["state"] != "response_received"
            or row["candidate"] != checkpoint["candidate"]
            or review["status"] != "completed"
            or candidate["base"] != manifest["base"]
            or candidate["protected"] != manifest["protected_tests"]
            or row["consumed"] is None
            or any(row[key] != manifest["providers"]["reviewer"][key] for key in ("provider", "model"))
        ):
            raise ValueError
        plan = json.loads(row["plan"])
        if (
            plan.pop("plan_sha256") != row["digest"]
            or sha(encode(plan)) != row["digest"]
            or sha(plan["body_utf8"].encode()) != row["request_sha256"]
            or plan["candidate"] != row["candidate"]
        ):
            raise ValueError
        receipt = json.loads(row["receipt"])
        if row["provider"] == "deepseek" and (
            receipt.get("provider_fingerprint") != manifest["providers"]["reviewer"]["fingerprint"]
        ):
            raise ValueError
        proof = decode(evidence_file(Path(files["tests"])))
        return result(
            item,
            candidate["base"],
            candidate["head"],
            row,
            receipt,
            row["digest"],
            len(proof["checks"]),
            task["evidence"]["tests"],
            task["repairs"],
        )
    except (arc.Blocked, AttributeError, KeyError, OSError, StopIteration, TypeError, ValueError, WorkerFailure):
        raise ValueError("engineering candidate, tests, or independent review no longer verify") from None


def recovery_result(schedule, job, item, checkpoint, arc):
    approval = schedule.approval(job)
    stored = json.loads(approval["plan"])
    if "recovery" not in stored or approval["consumed"] is None:
        raise ValueError
    source = approval["source_job"]
    plan = schedule.prepare_recovery(source, stored["candidate"], stored["expires_at"], arc=arc, require_current=False)
    if (
        stored != plan
        or approval["plan_sha256"] != checkpoint["plan_sha256"]
        or approval["plan_sha256"] != plan["plan_sha256"]
        or plan["candidate"] != checkpoint["candidate"]
        or plan["project"] != item["project"]
        or checkpoint["source_job"] != source
        or checkpoint["rejected_plan_sha256"] != plan["recovery"]["rejected_plan_sha256"]
    ):
        raise ValueError
    packet = decode(decode(plan["body_utf8"].encode())["input"].encode())
    receipt = json.loads(approval["receipt"])
    outcome, review, _ = arc.validate_review(receipt["review"], packet["criteria"])
    if outcome != "approve" or any(row["status"] != "met" for row in review["coverage"]):
        raise ValueError
    with schedule.connect() as db:
        row = db.execute("SELECT * FROM api_review WHERE job=? AND session=?", (job, plan["plan_sha256"])).fetchone()
    if (
        not row
        or row["candidate"] != plan["candidate"]
        or row["request_sha256"] != plan["body_sha256"]
        or row["provider"] != plan["provider"]
        or row["model"] != plan["model"]
    ):
        raise ValueError
    (proof,) = (entry for name, entry in packet["evidence"].items() if name.endswith("-tests.txt"))
    return {
        **result(
            item,
            packet["base"],
            plan["candidate"],
            row,
            receipt,
            plan["plan_sha256"],
            len(packet["protected_case_inputs"]),
            proof["sha256"],
            None,
        ),
        "source_job": source,
    }


def result(item, base, candidate, row, receipt, plan_digest, passed, evidence_sha256, repairs):
    if (
        receipt["state"] != "response_received"
        or receipt["outcome"] != "approve"
        or row["state"] != receipt["state"]
        or row["reserve_microusd"] != receipt["reserve_microusd"]
    ):
        raise ValueError
    return {
        "version": 1,
        "kind": "engineering.ready",
        "job": item["id"],
        "project": item["project"],
        "base": base,
        "candidate": candidate,
        "repairs": repairs,
        "protected_tests": {"passed": passed, "evidence_sha256": evidence_sha256},
        "independent_review": {
            "provider": row["provider"],
            "model": row["model"],
            "request_sha256": row["request_sha256"],
            "plan_sha256": plan_digest,
            "reserve_microusd": receipt["reserve_microusd"],
            "estimated_microusd": receipt["estimated_microusd"],
            "actual_charge_microusd": receipt["actual_charge_microusd"],
        },
    }
