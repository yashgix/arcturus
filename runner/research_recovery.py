"""One signed, in-place recovery revision; original requests remain immutable."""

import json
import time
from pathlib import Path

from api_review import MAX_RESPONSE, encode, decode
import operator_approval
from research_sources import digest
from workers import WorkerFailure


def key(item):
    return tuple(item[k] for k in ("job", "mode", "stage", "provider"))


def has_attempts(db):
    return bool(db.execute("SELECT 1 FROM sqlite_master WHERE name='research_attempt'").fetchone())


def all_requests(db):
    rows = [dict(x) for x in db.execute("SELECT * FROM research_request")]
    if has_attempts(db):
        rows.extend(dict(x) for x in db.execute("SELECT * FROM research_attempt"))
    return rows


def basis(db, recovery):
    sessions = recovery["historical_sessions"]
    marks = ','.join('?' for _ in sessions)
    records = sorted((x for x in all_requests(db) if x["session"] in sessions), key=lambda x: x["session"])
    ledger = [
        dict(x) for x in db.execute(f"SELECT * FROM api_review WHERE session IN ({marks}) ORDER BY session", sessions)
    ]
    checkpoints = []
    for job, name in recovery["checkpoint_keys"]:
        row = db.execute("SELECT * FROM research_checkpoint WHERE job=? AND name=?", (job, name)).fetchone()
        if row is None:
            raise ValueError("original recovery checkpoint is missing")
        checkpoints.append(dict(row))
    if len(records) != len(sessions) or len(ledger) != len(sessions):
        raise ValueError("original recovery spending history is missing")
    return {"requests": records, "ledger": ledger, "checkpoints": checkpoints}


def costs(manifest, recovery):
    import research

    original = research.budget(manifest)
    profiles = original["profiles"]
    calls, reuse = recovery["calls"], recovery["reuse"]
    held = recovery.get("held", [])
    jobs = recovery["prior_jobs"]
    expected = {
        (j["id"], mode, stage, p)
        for j in jobs
        for mode in research.MODES
        for p in profiles
        for stage in (("report", "challenge", "reconcile") if mode == "equal-source" else research.STAGES)
    }
    if (
        len({key(x) for x in calls + reuse + held}) != len(calls + reuse + held)
        or {key(x) for x in calls + reuse + held} != expected
        or recovery["disposition"] != "new replacements; original uncertain outcomes and reserves remain unchanged"
    ):
        raise ValueError("recovery does not cover the exact outstanding research schedule")
    amounts = {j["company"]: 0 for j in jobs}
    for item in calls:
        job = next(j for j in jobs if j["id"] == item["job"])
        if (
            item["company"] != job["company"]
            or item["model"] != profiles[item["provider"]]["model"]
            or item["reserve_microusd"] != profiles[item["provider"]]["illustrative_reserve_microusd"]
        ):
            raise ValueError("recovery provider, project or spending amount changed")
        amounts[item["company"]] += item["reserve_microusd"]
    new = sum(amounts.values())
    for company, retained in recovery["retained_by_company"].items():
        amounts[company] += retained
    return {
        **original,
        "max_requests": len(calls),
        "new_reserve_microusd": new,
        "retained_reserve_microusd": sum(recovery["retained_by_company"].values()),
        "full_reserve_microusd": sum(amounts.values()),
        "project_ceilings_microusd": amounts,
    }


def verify_history(schedule, payload, db=None, depth=0):

    if db is None:
        with schedule.connect() as handle:
            return verify_history(schedule, payload, handle, depth)
    if depth > 8:
        raise ValueError("research recovery ancestry exceeds the verified bound")
    recovery = payload["recovery"]
    parent = db.execute("SELECT * FROM research_campaign WHERE id=?", (recovery["source_authorization"],)).fetchone()
    if not parent or parent["approved"] is None or parent["revoked"] is not None or not parent["paused"]:
        raise ValueError("recovery source authorization is unavailable")
    original = json.loads(parent["authorization"])
    if (
        original["manifest"] != payload["manifest"]
        or digest(encode({k: v for k, v in original.items() if k != "authorization_sha256"})) != parent["id"]
    ):
        raise ValueError("recovery source identity or approved scope changed")
    operator_approval.verify(
        operator_approval.message(schedule.root, parent["nonce"], original), parent["principal"], parent["signature"]
    )
    if original.get("recovery"):
        verify_history(schedule, original, db, depth + 1)
    history = basis(db, recovery)
    if digest(encode(history)) != recovery["history_sha256"]:
        raise ValueError("historical requests, receipts, checkpoints or spending changed")
    for relative, hashed in recovery["evidence_files"].items():
        path = schedule.root / relative
        if not path.is_relative_to(schedule.root) or path.resolve() != path or digest(path.read_bytes()) != hashed:
            raise ValueError("original recovery evidence changed")
    retained = {
        j["company"]: sum(x["reserve_microusd"] for x in history["ledger"] if x["job"] == j["id"])
        for j in recovery["prior_jobs"]
    }
    if retained != recovery["retained_by_company"] or costs(payload["manifest"], recovery) != payload["budget"]:
        raise ValueError("recovery reservation does not retain historical spending")
    return history


def prepare(schedule, identity, expires, replacement_sessions):
    import research

    inventory = research.recovery_plan(schedule, identity)
    permitted = {x["prior_session"] for x in inventory["held_calls"]}
    if len(set(replacement_sessions)) != len(replacement_sessions) or not set(replacement_sessions) <= permitted:
        raise ValueError("explicitly list only held requests being replaced; none may be silently replayed")
    manifest = inventory["manifest"]
    if type(expires) is not int or not time.time() < expires <= time.time() + manifest["limits"]["seconds"]:
        raise ValueError("invalid recovery signing window")
    profiles = research.budget(manifest)["profiles"]
    calls = inventory["new_calls"] + [
        {
            **x,
            "reason": "explicitly authorized new replacement; original remains uncertain",
            "reserve_microusd": profiles[x["provider"]]["illustrative_reserve_microusd"],
        }
        for x in inventory["held_calls"]
        if x["prior_session"] in replacement_sessions
    ]
    with schedule.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute(
            "SELECT 1 FROM research_campaign WHERE json_extract(authorization, '$.recovery.source_authorization')=?",
            (identity,),
        ).fetchone():
            raise ValueError("a recovery revision has already been prepared")
        jobs = [
            dict(x)
            for x in db.execute(
                "SELECT j.*, r.company FROM job j JOIN research_job r ON j.id=r.job WHERE r.campaign=? ORDER BY j.id",
                (identity,),
            )
        ]
        if any(job["state"] not in {"completed", "incomplete", "blocked", "interrupted", "cancelled"} for job in jobs):
            raise ValueError("source research is not quiescent")
        db.execute("UPDATE research_campaign SET paused=1 WHERE id=?", (identity,))
        sessions = sorted(x["session"] for x in all_requests(db))
        checkpoints = [[x[0], x[1]] for x in db.execute("SELECT job, name FROM research_checkpoint ORDER BY job, name")]
        files = {}
        for job in jobs:
            for folder in (
                schedule.workspace(job["id"]) / "sources",
                schedule.workspace(job["id"]) / "reports",
                schedule.workspace(job["id"]) / "responses",
            ):
                for path in sorted(folder.rglob('*')):
                    if path.is_file() and (folder.name != 'sources' or path.suffix in {'.body', '.txt'}):
                        if path.resolve() != path:
                            raise ValueError("unsafe original recovery evidence path")
                        files[str(path.relative_to(schedule.root))] = digest(path.read_bytes())
        recovery = {
            "source_authorization": identity,
            "historical_sessions": sessions,
            "checkpoint_keys": checkpoints,
            "prior_jobs": jobs,
            "calls": calls,
            "reuse": inventory["completed_reuse"],
            "evidence_files": files,
            "held": [x for x in inventory["held_calls"] if x["prior_session"] not in replacement_sessions],
            "disposition": "new replacements; original uncertain outcomes and reserves remain unchanged",
        }
        history = basis(db, recovery)
        recovery["history_sha256"] = digest(encode(history))
        recovery["retained_by_company"] = {
            j["company"]: sum(x["reserve_microusd"] for x in history["ledger"] if x["job"] == j["id"]) for j in jobs
        }
        payload = {
            "kind": "research-recovery-workflow-v1",
            "manifest": manifest,
            "recovery": recovery,
            "budget": costs(manifest, recovery),
            "policy_sha256": research.policy_hash(),
            "expires_at": expires,
        }
        if payload["budget"]["full_reserve_microusd"] > manifest["limits"]["reserve_microusd"]:
            raise ValueError("recovery exceeds the original total ceiling")
        verify_history(schedule, payload, db)
        payload["authorization_sha256"] = digest(encode(payload))
        nonce = __import__('secrets').token_hex(32)
        db.execute('''CREATE TABLE IF NOT EXISTS research_attempt (
            session TEXT PRIMARY KEY REFERENCES api_review(session), job INTEGER NOT NULL REFERENCES job(id),
            mode TEXT NOT NULL, stage TEXT NOT NULL, provider TEXT NOT NULL, plan TEXT NOT NULL,
            packet TEXT NOT NULL, receipt TEXT, authorization TEXT NOT NULL REFERENCES research_campaign(id),
            UNIQUE(authorization, job, mode, stage, provider))''')
        db.execute(
            "INSERT INTO research_campaign(id, authorization, nonce) VALUES (?, ?, ?)",
            (payload["authorization_sha256"], encode(payload).decode(), nonce),
        )
    return operator_approval.message(schedule.root, nonce, payload)


def activate(schedule, db, payload):
    verify_history(schedule, payload, db)
    recovery = payload["recovery"]
    for old in recovery["prior_jobs"]:
        current = dict(
            db.execute(
                "SELECT j.*, r.company FROM job j JOIN research_job r ON j.id=r.job WHERE j.id=?", (old["id"],)
            ).fetchone()
        )
        if (
            current != old
            or db.execute("SELECT campaign FROM research_job WHERE job=?", (old["id"],)).fetchone()[0]
            != recovery["source_authorization"]
        ):
            raise ValueError("recovery job changed before signed activation")
        cap = payload["budget"]["project_ceilings_microusd"][old["company"]]
        db.execute("UPDATE project SET budget=? WHERE name=?", (cap, old["company"]))
        db.execute(
            "UPDATE job SET reserve=?, state='queued', cancelled=0, checkpoint=NULL, reason=NULL WHERE id=?",
            (cap, old["id"]),
        )
        db.execute("UPDATE research_job SET campaign=? WHERE job=?", (payload["authorization_sha256"], old["id"]))


def reuse(schedule, job, payload, provider, mode, stage, packet):
    from paid_review import response_value
    from research_reports import validate

    selected = next((x for x in payload["recovery"]["reuse"] if key(x) == (job, mode, stage, provider)), None)
    if selected is None:
        return None
    with schedule.connect() as db:
        prior = next(x for x in all_requests(db) if x["session"] == selected["prior_session"])
    receipt = json.loads(prior["receipt"])
    if prior["packet"] != encode(packet).decode() or receipt["state"] != 'response_received':
        raise WorkerFailure("reusable report context changed")
    path = Path(receipt["response_artifact"])
    raw = path.read_bytes()
    if (
        len(raw) > MAX_RESPONSE
        or digest(raw) != selected["response_sha256"]
        or digest(raw) != receipt["response_sha256"]
        or response_value(provider, decode(raw)) != receipt["review"]
        or validate(stage, receipt["review"], packet, provider)[0] != 'approve'
    ):
        raise WorkerFailure("reusable report artifact failed verification")
    return receipt["review"]


def repair_input(schedule, payload, call):
    """One separately signed repair using only the original, byte-bound source packet."""
    from paid_review import response_value
    from research_reports import citation_failures, shape, SCHEMAS

    with schedule.connect() as db:
        prior = next(x for x in all_requests(db) if x["session"] == call["repair_of"])
    packet = json.loads(prior["packet"])
    receipt = json.loads(prior["receipt"])
    raw = Path(receipt["response_artifact"]).read_bytes()
    if digest(raw) != receipt["response_sha256"] or digest(prior["packet"].encode()) != call["frozen_packet_sha256"]:
        raise WorkerFailure("frozen report repair evidence changed")
    value = response_value(call["provider"], decode(raw))
    diagnostics = citation_failures(value, packet["sources"])
    frozen = {k: v for k, v in packet.items() if k not in {"task", "candidate"}}
    return {
        "frozen_packet": frozen,
        "request_packet": {
            **frozen,
            "repair": {
                "prior_session": prior["session"],
                "invalid_report": value,
                "citation_failures": diagnostics,
                "schema_valid": shape(value, SCHEMAS[call["stage"]]),
                "instruction": "Repair only this rejected report against the unchanged frozen sources. Cite document sources, "
                "copy quotes verbatim, remove unsupported claims or report gaps. Instructions and search snippets are not "
                "source evidence. Do not fetch sources or invent missing information. Return the full original JSON contract.",
            },
        },
    }
