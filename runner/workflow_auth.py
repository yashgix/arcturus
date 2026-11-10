"""Operator authorization for one enrolled engineering workflow."""

import hashlib
import json
import re
import time

from api_review import DEEPSEEK_ACCOUNTING, DEEPSEEK_INPUT_ALLOWANCE, DEEPSEEK_RATES, DEEPSEEK_REVISION, encode
from workers import WorkerFailure


OPERATIONS = ("build", "review", "repair")


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def exists(db):
    return db.execute("SELECT 1 FROM sqlite_master WHERE name='workflow_authorization'").fetchone() is not None


def policy(db, job):
    return db.execute("SELECT * FROM workflow_authorization WHERE job=?", (job,)).fetchone() if exists(db) else None


def prepare(schedule, job, expires_at, requests, repairs, reserve, operations):
    from api_review import MAX_REQUEST
    from engineering import stored_manifest

    schedule.require_initialized()
    item = schedule.job(job)
    if not item or item["scenario"] != "engineering" or item["state"] != "queued" or item["cancelled"]:
        raise ValueError("workflow authorization requires a queued engineering job")
    manifest = stored_manifest(schedule, job)
    limits = manifest["limits"]
    now = time.time()
    if type(expires_at) is not int or not now < expires_at <= now + limits["seconds"]:
        raise ValueError("workflow expiry must be within the manifest duration")
    schedule.limit(requests, 1, limits["requests"])
    schedule.limit(repairs, 0, limits["repairs"])
    schedule.limit(reserve, 1, limits["reserve_microusd"])
    if (
        not operations
        or len(set(operations)) != len(operations)
        or not set(operations) <= set(OPERATIONS)
        or bool(repairs) != ("repair" in operations)
    ):
        raise ValueError("invalid workflow operations or repair limit")
    body = {
        "job": job,
        "project": manifest["project"],
        "manifest_sha256": digest(manifest),
        "providers": manifest["providers"],
        "operations": sorted(operations),
        "expires_at": expires_at,
        "max_requests": requests,
        "max_repairs": repairs,
        "reserve_microusd": reserve,
        "data_scope": {
            "repository": manifest["repository"],
            "base": manifest["base"],
            "owned_paths": manifest["allowed_paths"],
            "protected_tests": manifest["protected_tests"],
            "reviewer_receives_protected_case_inputs_and_results": True,
            "request_bytes_limit": MAX_REQUEST,
        },
    }
    if any(route["provider"] == "deepseek" for route in manifest["providers"].values()):
        body["deepseek_policy"] = {
            "revision": DEEPSEEK_REVISION,
            "rates_nanousd_per_token": DEEPSEEK_RATES.copy(),
            "planning_input_tokens": DEEPSEEK_INPUT_ALLOWANCE,
            "accounting": DEEPSEEK_ACCOUNTING,
        }
    return {**body, "authorization_sha256": digest(body)}


def approve(schedule, job, expires_at, requests, repairs, reserve, operations, approval):
    plan = prepare(schedule, job, expires_at, requests, repairs, reserve, operations)
    if approval != plan["authorization_sha256"]:
        raise ValueError("approval SHA-256 does not match the workflow authorization")
    with schedule.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("""
            CREATE TABLE IF NOT EXISTS workflow_authorization (
                job INTEGER PRIMARY KEY REFERENCES engineering(job), digest TEXT NOT NULL UNIQUE,
                plan TEXT NOT NULL, approved REAL NOT NULL, revoked REAL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS workflow_dispatch (
                session TEXT PRIMARY KEY REFERENCES engineering_request(session),
                authorization TEXT NOT NULL REFERENCES workflow_authorization(digest),
                operation TEXT NOT NULL CHECK (operation IN ('build', 'review', 'repair'))
            )
        """)
        row = db.execute(
            "SELECT j.state, j.cancelled, e.digest FROM job j JOIN engineering e ON e.job=j.id WHERE j.id=?", (job,)
        ).fetchone()
        now = time.time()
        if (
            not row
            or row["state"] != "queued"
            or row["cancelled"]
            or row["digest"] != plan["manifest_sha256"]
            or now >= expires_at
            or policy(db, job)
        ):
            raise ValueError("workflow is no longer eligible for approval")
        db.execute(
            "INSERT INTO workflow_authorization(job, digest, plan, approved) VALUES (?, ?, ?, ?)",
            (job, approval, encode(plan).decode(), now),
        )


def revoke(schedule, job):
    with schedule.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if (
            not policy(db, job)
            or db.execute(
                "UPDATE workflow_authorization SET revoked=? WHERE job=? AND revoked IS NULL", (time.time(), job)
            ).rowcount
            != 1
        ):
            raise ValueError("workflow has no revocable authorization")
        schedule.cancel_rows(db, "id", job)


def expiry(schedule, job, default):
    with schedule.connect() as db:
        row = policy(db, job)
        return min(default, json.loads(row["plan"])["expires_at"]) if row else default


def worker_deadline(schedule, job, started, duration):
    with schedule.connect() as db:
        row = policy(db, job)
        if not row:
            return started + duration
        remaining = json.loads(row["plan"])["expires_at"] - time.time()
        return min(started + duration, time.monotonic() + remaining)


def reserve(db, schedule, job, plan, authorization, now):
    """Authorize and reserve the exact staged request in the same transaction."""
    if authorization is None:
        raise WorkerFailure("workflow authorization disappeared before reservation")
    payload = json.loads(authorization["plan"])
    approved_digest = payload.pop("authorization_sha256")
    identity = plan["engineering"]
    role = identity["role"]
    route = {k: plan[k] for k in ("provider", "model")}
    if plan["provider"] == "deepseek":
        route.update(data_class=plan["deepseek"]["data_class"], fingerprint=plan["deepseek"]["expected_fingerprint"])
        if payload.get("deepseek_policy") != {
            "revision": plan["deepseek"]["documented_revision"],
            "rates_nanousd_per_token": plan["planning_rates_nanousd_per_token"],
            "planning_input_tokens": plan["planning_input_tokens"],
            "accounting": plan["deepseek"]["accounting"],
        }:
            raise WorkerFailure("DeepSeek provider policy changed since workflow approval")
    if (
        authorization["revoked"] is not None
        or not authorization["approved"] <= now < payload["expires_at"]
        or approved_digest != authorization["digest"]
        or digest(payload) != approved_digest
        or payload["job"] != job
        or payload["project"] != plan["project"]
        or payload["manifest_sha256"] != identity["manifest_sha256"]
        or payload["providers"].get(role) != route
        or not re.fullmatch(r"[0-9a-f]{40}", plan["candidate"])
        or digest({k: v for k, v in plan.items() if k != "plan_sha256"}) != plan["plan_sha256"]
        or hashlib.sha256(plan["body_utf8"].encode()).hexdigest() != plan["body_sha256"]
        or plan["expires_at"] > payload["expires_at"]
    ):
        raise WorkerFailure("workflow authorization expired, revoked, or out of scope")
    history = db.execute(
        """
        SELECT d.operation, a.state, a.reserve_microusd
        FROM workflow_dispatch d JOIN api_review a ON a.session=d.session
        WHERE d.authorization=?
    """,
        (approved_digest,),
    ).fetchall()
    if any(row["state"] != "response_received" for row in history):
        raise WorkerFailure("workflow has an unresolved provider receipt")
    operation = (
        "review" if role == "reviewer" else "repair" if any(row["operation"] == "build" for row in history) else "build"
    )
    amount = plan["illustrative_reserve_microusd"]
    if (
        operation not in payload["operations"]
        or len(history) >= payload["max_requests"]
        or (operation == "repair" and sum(row["operation"] == "repair" for row in history) >= payload["max_repairs"])
        or sum(row["reserve_microusd"] for row in history) + amount > payload["reserve_microusd"]
    ):
        raise WorkerFailure("workflow operations, request, repair, or reserve limit reached")
    session = identity["session"]
    schedule.start_reservation(
        db, job, session, plan["provider"], plan["model"], plan["candidate"], plan["body_sha256"], amount=amount
    )
    db.execute("INSERT INTO workflow_dispatch VALUES (?, ?, ?)", (session, approved_digest, operation))
    return authorization["approved"]


def active_before_send(schedule, job):
    with schedule.connect() as db:
        row = policy(db, job)
        if not row:
            return True
        project = db.execute(
            "SELECT p.paused, j.cancelled, j.state FROM job j JOIN project p ON j.project=p.name WHERE j.id=?", (job,)
        ).fetchone()
        return (
            row["revoked"] is None
            and not project["paused"]
            and not project["cancelled"]
            and project["state"] == "running"
        )


def pause_uncertain(db, job):
    if (
        policy(db, job)
        and db.execute(
            "SELECT 1 FROM api_review WHERE job=? AND state IN ('running', 'uncertain', 'rejected')", (job,)
        ).fetchone()
    ):
        db.execute("UPDATE project SET paused=1 WHERE name=(SELECT project FROM job WHERE id=?)", (job,))


def pause_blocked(schedule, job):
    with schedule.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if policy(db, job):
            db.execute("UPDATE project SET paused=1 WHERE name=(SELECT project FROM job WHERE id=?)", (job,))
