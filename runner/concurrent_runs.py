#!/usr/bin/env python3
"""Supervised scheduling for fixtures and budget-authorized Arcturus API jobs."""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass

from api_review import LIVE_MODELS, MAX_REQUEST, REVIEW_TIMEOUT, TRIAL_MODEL, decode, encode, trial_plan
from workers import WorkerFailure
import operator_approval
import workflow_auth

SOURCE = Path(__file__).resolve().parent
SCENARIOS = ("repair", "clean")
POLL = 0.05
DEADLINE = 60
APPROVAL_TTL_SECONDS = 15 * 60


@dataclass
class Child:
    process: subprocess.Popen
    parent_pipe: int
    expires: float


class Scheduler:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.database = self.root / "schedule.sqlite"

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=5)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def limit(value, low, high):
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"limit must be between {low} and {high}")
        return value

    def initialize(self, slots, budget, projects):
        self.limit(slots, 1, 32)
        self.limit(budget, 0, 10**12)
        for name, (project_slots, cap) in projects.items():
            if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name):
                raise ValueError("invalid project name")
            self.limit(project_slots, 1, 32)
            self.limit(cap, 0, 10**12)
        self.root.mkdir(mode=0o700, exist_ok=True)
        if self.root.stat().st_uid != os.getuid() or self.root.stat().st_mode & 0o077 or any(self.root.iterdir()):
            raise ValueError("initialize in a fresh private directory")
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE settings (slots INTEGER NOT NULL, budget INTEGER NOT NULL);
                CREATE TABLE project (
                    name TEXT PRIMARY KEY, slots INTEGER NOT NULL, budget INTEGER NOT NULL,
                    paused INTEGER NOT NULL DEFAULT 0, last_start INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE job (
                    id INTEGER PRIMARY KEY, project TEXT NOT NULL REFERENCES project(name),
                    scenario TEXT NOT NULL, reserve INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'queued', cancelled INTEGER NOT NULL DEFAULT 0,
                    started REAL, finished REAL, checkpoint TEXT, reason TEXT
                );
                CREATE TABLE api_review (
                    session TEXT PRIMARY KEY, job INTEGER NOT NULL REFERENCES job(id),
                    provider TEXT NOT NULL, model TEXT NOT NULL, candidate TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL, reserve_microusd INTEGER NOT NULL,
                    state TEXT NOT NULL, started REAL NOT NULL, finished REAL
                );
            """)
            db.execute("INSERT INTO settings VALUES (?, ?)", (slots, budget))
            db.executemany(
                "INSERT INTO project(name, slots, budget) VALUES (?, ?, ?)",
                [(name, *limits) for name, limits in projects.items()],
            )
        canaries = self.root / "project-canaries"
        canaries.mkdir()
        for name in projects:
            (canaries / name).write_text(f"private fixture for {name}\n")

    def require_initialized(self):
        if not self.database.is_file() or self.database.is_symlink():
            raise ValueError("initialize the schedule first")
        if self.root.stat().st_uid != os.getuid() or self.root.stat().st_mode & 0o077:
            raise ValueError("schedule directory must remain private")

    def enqueue(self, project, scenario, reserve):
        self.require_initialized()
        self.limit(reserve, 1, 10**12)
        if scenario not in SCENARIOS:
            raise ValueError("only authored mock scenarios are supported")
        with self.connect() as db:
            return db.execute(
                "INSERT INTO job(project, scenario, reserve) VALUES (?, ?, ?)", (project, scenario, reserve)
            ).lastrowid

    def workspace(self, job):
        return self.root / f"task-{job}"

    def status(self):
        self.require_initialized()
        with self.connect() as db:
            db.execute("BEGIN")
            result = {}
            for table, order in (("settings", "slots"), ("project", "name"), ("job", "id"), ("api_review", "started")):
                result[table] = [dict(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY {order}")]
            for row in result["job"]:
                if row["checkpoint"] is not None:
                    row["checkpoint"] = json.loads(row["checkpoint"])
            if self.has_approvals(db):
                result["review_approval"] = [
                    dict(row)
                    for row in db.execute(
                        "SELECT job, source_job, provider, plan_sha256, plan, approved, consumed, receipt "
                        "FROM review_approval ORDER BY job"
                    )
                ]
                for row in result["review_approval"]:
                    row["expires_at"] = json.loads(row.pop("plan")).get("expires_at")
                    if row["receipt"] is not None:
                        row["receipt"] = json.loads(row["receipt"])
            if self.has_model_approval_requests(db):
                result["model_approval_requests"] = [
                    dict(row)
                    for row in db.execute(
                        "SELECT digest AS plan_sha256, project, json_extract(plan, '$.expires_at') AS expires_at, "
                        "cancelled, job, principal, signature_sha256 FROM model_approval_request ORDER BY rowid"
                    )
                ]
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='engineering_request'").fetchone():
                result["engineering_requests"] = [
                    dict(row)
                    for row in db.execute(
                        "SELECT job, session, digest, approved, consumed, receipt FROM engineering_request ORDER BY rowid"
                    )
                ]
                for row in result["engineering_requests"]:
                    if row["receipt"] is not None:
                        row["receipt"] = json.loads(row["receipt"])
            if workflow_auth.exists(db):
                result["workflow_authorizations"] = [
                    {**dict(row), "plan": json.loads(row["plan"])}
                    for row in db.execute("SELECT * FROM workflow_authorization ORDER BY job")
                ]
                result["workflow_dispatches"] = [
                    dict(row) for row in db.execute("SELECT * FROM workflow_dispatch ORDER BY rowid")
                ]
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='research_campaign'").fetchone():
                result["research_campaigns"] = [
                    dict(row)
                    for row in db.execute("SELECT id, principal, approved, revoked, paused FROM research_campaign")
                ]
                result["research_requests"] = [
                    dict(row)
                    for row in db.execute(
                        "SELECT session, job, mode, stage, provider, receipt FROM research_request ORDER BY rowid"
                    )
                ]
                if db.execute("SELECT 1 FROM sqlite_master WHERE name='research_attempt'").fetchone():
                    result["research_requests"].extend(
                        dict(row)
                        for row in db.execute(
                            "SELECT session, job, mode, stage, provider, receipt FROM research_attempt ORDER BY rowid"
                        )
                    )
                for row in result["research_requests"]:
                    if row["receipt"] is not None:
                        row["receipt"] = json.loads(row["receipt"])
            return result

    @staticmethod
    def has_approvals(db):
        return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='review_approval'").fetchone()

    def prepare_trial(self, job, provider="anthropic", model=TRIAL_MODEL):
        status = self.status()
        task = next((row for row in status["job"] if row["id"] == job), None)
        reviews = [row for row in status["api_review"] if row["job"] == job]
        if (
            not task
            or task["state"] != "ready"
            or task["scenario"] not in SCENARIOS
            or not reviews
            or not task["checkpoint"]["mock_only"]
        ):
            raise ValueError("trial requires a completed synthetic task with a final review")
        review = reviews[-1]
        with (self.workspace(job) / f"mock-request-{len(reviews)}.json").open("rb") as file:
            raw = file.read(MAX_REQUEST + 1)
        if (
            len(raw) > MAX_REQUEST
            or hashlib.sha256(raw).hexdigest() != review["request_sha256"]
            or review["state"] != "response_received"
        ):
            raise ValueError("mock request failed its integrity check")
        packet = decode(decode(raw)["messages"][-1]["content"].encode())
        if (
            packet["mode"] != "offline_mock"
            or packet["task"] != f"MOCK-{job}"
            or packet["candidate"] != review["candidate"]
            or packet["candidate"] != task["checkpoint"]["candidate"]
        ):
            raise ValueError("mock request does not match the ready candidate")
        return trial_plan(
            packet,
            provider,
            model,
            project=task["project"],
            source_job=job,
            expires_at=task["finished"] + APPROVAL_TTL_SECONDS,
        )

    def approve_review(self, source, provider, model, digest, *, recovery=None):
        plan = (
            self.prepare_trial(source, provider, model)
            if recovery is None
            else self.prepare_recovery(source, *recovery)
        )
        return self.queue_approved_plan(plan, digest, "api-review")

    def prepare_model(self, spec, expires_at):
        from model_tasks import prepare

        self.require_initialized()
        plan = prepare(spec, expires_at, APPROVAL_TTL_SECONDS)
        with self.connect() as db:
            if db.execute("SELECT 1 FROM project WHERE name=?", (plan["project"],)).fetchone() is None:
                raise ValueError("model task requires an enrolled project budget")
        return plan

    def approve_model(self, spec, expires_at, digest):
        return self.queue_approved_plan(self.prepare_model(spec, expires_at), digest, "api-task")

    @staticmethod
    def has_model_approval_requests(db):
        return db.execute("SELECT 1 FROM sqlite_master WHERE name='model_approval_request'").fetchone()

    def model_approval_request(self, spec, expires_at):
        plan = self.prepare_model(spec, expires_at)
        digest = plan["plan_sha256"]
        encoded = encode(plan).decode()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""
                CREATE TABLE IF NOT EXISTS model_approval_request (
                    digest TEXT PRIMARY KEY, project TEXT NOT NULL REFERENCES project(name),
                    nonce TEXT NOT NULL, plan TEXT NOT NULL, cancelled REAL,
                    job INTEGER UNIQUE REFERENCES job(id), principal TEXT, signature BLOB, signature_sha256 TEXT
                )
            """)
            if (
                time.time() >= expires_at
                or db.execute("SELECT paused FROM project WHERE name=?", (plan["project"],)).fetchone()[0]
            ):
                raise ValueError("model approval request expired or project is paused")
            if (
                self.has_approvals(db)
                and db.execute("SELECT 1 FROM review_approval WHERE plan_sha256=?", (digest,)).fetchone()
            ):
                raise ValueError("this exact plan was already queued")
            db.execute(
                "INSERT INTO model_approval_request(digest, project, nonce, plan) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(digest) DO NOTHING",
                (digest, plan["project"], secrets.token_hex(32), encoded),
            )
            row = db.execute("SELECT * FROM model_approval_request WHERE digest=?", (digest,)).fetchone()
            if row["cancelled"] is not None or row["job"] is not None or row["plan"] != encoded:
                raise ValueError("model approval request is cancelled, used or changed")
            return operator_approval.message(self.root, row["nonce"], plan)

    def cancel_model_approval(self, digest):
        self.require_initialized()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if (
                not self.has_model_approval_requests(db)
                or db.execute(
                    "UPDATE model_approval_request SET cancelled=? WHERE digest=? AND job IS NULL AND cancelled IS NULL",
                    (time.time(), digest),
                ).rowcount
                != 1
            ):
                raise ValueError("no pending model approval request; use job cancellation after enrollment")

    def approve_signed_model(self, digest, principal, signature):
        from model_tasks import restore

        self.require_initialized()
        with self.connect() as db:
            row = (
                db.execute("SELECT plan FROM model_approval_request WHERE digest=?", (digest,)).fetchone()
                if self.has_model_approval_requests(db)
                else None
            )
        if row is None:
            raise ValueError("unknown model approval request")
        stored = json.loads(row["plan"])
        plan, _ = restore(stored, APPROVAL_TTL_SECONDS)
        if plan != stored:
            raise ValueError("model approval request plan changed")
        return self.queue_approved_plan(plan, digest, "api-task", signer=(principal, signature))

    def queue_approved_plan(self, plan, digest, scenario, *, signer=None):
        if digest != plan["plan_sha256"]:
            raise ValueError("approval SHA-256 does not match the current exact plan")
        source = plan["source_job"]
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""
                CREATE TABLE IF NOT EXISTS review_approval (
                    job INTEGER PRIMARY KEY REFERENCES job(id), source_job INTEGER NOT NULL REFERENCES job(id),
                    provider TEXT NOT NULL, plan_sha256 TEXT NOT NULL UNIQUE, plan TEXT NOT NULL,
                    approved REAL NOT NULL, consumed REAL, receipt TEXT
                )
            """)
            if (
                plan.get("recovery") is not None
                and db.execute(
                    "SELECT 1 FROM review_approval WHERE source_job=? AND json_type(plan, '$.recovery')='object'",
                    (source,),
                ).fetchone()
            ):
                raise ValueError("a one-shot recovery was already approved for this engineering job")
            if (
                scenario == "api-task"
                and db.execute("SELECT 1 FROM review_approval WHERE plan_sha256=?", (digest,)).fetchone()
            ):
                raise ValueError("this exact plan was already queued")
            if scenario == "api-task":
                challenge = (
                    db.execute(
                        "SELECT r.*, p.paused FROM model_approval_request r "
                        "JOIN project p ON p.name=r.project WHERE r.digest=?",
                        (digest,),
                    ).fetchone()
                    if self.has_model_approval_requests(db)
                    else None
                )
                if signer is not None:
                    if (
                        challenge is None
                        or challenge["cancelled"] is not None
                        or challenge["job"] is not None
                        or challenge["paused"]
                        or challenge["plan"] != encode(plan).decode()
                    ):
                        raise ValueError("model approval request is unavailable, cancelled or changed")
                    principal, signature = signer
                    operator_approval.verify(
                        operator_approval.message(self.root, challenge["nonce"], plan), principal, signature
                    )
                elif challenge is not None or operator_approval.configured():
                    raise ValueError("model task requires a signed operator approval")
            approved = time.time()
            if not plan["expires_at"] - APPROVAL_TTL_SECONDS <= approved < plan["expires_at"]:
                raise ValueError("review plan has expired or is outside its approval window")
            job = db.execute(
                "INSERT INTO job(project, scenario, reserve) VALUES (?, ?, ?)",
                (plan["project"], scenario, plan["illustrative_reserve_microusd"]),
            ).lastrowid
            db.execute(
                "INSERT INTO review_approval(job, source_job, provider, plan_sha256, plan, approved) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (job, job if source is None else source, plan["provider"], digest, encode(plan).decode(), approved),
            )
            if signer is not None:
                db.execute(
                    "UPDATE model_approval_request SET job=?, principal=?, signature=?, signature_sha256=? "
                    "WHERE digest=?",
                    (job, principal, signature, operator_approval.signature_hash(signature), digest),
                )
            return job

    def prepare_recovery(self, source, candidate, expires_at, *, arc=None, require_current=True):
        if arc is None:
            import arc
        from review_recovery import prepare

        return prepare(self, source, candidate, expires_at, arc, require_current=require_current)

    def approval(self, job):
        with self.connect() as db:
            return db.execute("SELECT * FROM review_approval WHERE job=?", (job,)).fetchone()

    def consume_review(self, job, plan):
        """Fence a single POST and charge its reserve in the same durable transaction."""
        digest = plan["plan_sha256"]
        if (
            hashlib.sha256(encode({key: value for key, value in plan.items() if key != "plan_sha256"})).hexdigest()
            != digest
        ):
            raise WorkerFailure("one-shot approval unavailable or plan changed")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT a.*, j.project, j.scenario, j.reserve, source.finished AS source_finished "
                "FROM review_approval a JOIN job j ON j.id=a.job "
                "JOIN job source ON source.id=a.source_job WHERE a.job=?",
                (job,),
            ).fetchone()
            model_task = "model_task" in plan
            if (
                row is None
                or row["consumed"] is not None
                or row["plan_sha256"] != digest
                or row["source_job"] != (job if model_task else plan["source_job"])
                or row["provider"] != plan["provider"]
                or row["project"] != plan["project"]
                or row["scenario"] != ("api-task" if model_task else "api-review")
                or row["reserve"] != plan["illustrative_reserve_microusd"]
                or row["plan"] != encode(plan).decode()
            ):
                raise WorkerFailure("one-shot approval unavailable or plan changed")
            expires_at = plan.get("expires_at")
            finished = row["source_finished"]
            approved = row["approved"]
            if (
                type(approved) not in (int, float)
                or type(expires_at) not in (int, float)
                or (not model_task and type(finished) not in (int, float))
            ):
                raise WorkerFailure("missing or invalid approval expiry or timestamp")
            recovery = plan.get("recovery")
            if model_task:
                if not expires_at - APPROVAL_TTL_SECONDS <= approved < expires_at:
                    raise WorkerFailure("model task approval is outside its window")
                challenge = (
                    db.execute("SELECT * FROM model_approval_request WHERE digest=? OR job=?", (digest, job)).fetchone()
                    if self.has_model_approval_requests(db)
                    else None
                )
                if challenge is not None:
                    if (
                        challenge["job"] != job
                        or challenge["digest"] != digest
                        or challenge["cancelled"] is not None
                        or challenge["plan"] != row["plan"]
                        or not isinstance(challenge["signature"], bytes)
                        or challenge["signature_sha256"] != operator_approval.signature_hash(challenge["signature"])
                    ):
                        raise WorkerFailure("signed operator approval is unavailable or changed")
                    try:
                        operator_approval.verify(
                            operator_approval.message(self.root, challenge["nonce"], plan),
                            challenge["principal"],
                            challenge["signature"],
                        )
                    except ValueError as exc:
                        raise WorkerFailure(str(exc)) from exc
                elif operator_approval.configured():
                    raise WorkerFailure("model task requires a signed operator approval")
            elif recovery:
                if not finished <= approved or not expires_at - APPROVAL_TTL_SECONDS <= approved < expires_at:
                    raise WorkerFailure("missing or invalid recovery approval expiry or timestamp")
                # The exact approval authorizes this additional reserve. Increase both ceilings
                # only in the transaction that immediately reserves the full increment.
                db.execute("UPDATE settings SET budget=budget+?", (row["reserve"],))
                db.execute("UPDATE project SET budget=budget+? WHERE name=?", (row["reserve"], row["project"]))
            elif expires_at != finished + APPROVAL_TTL_SECONDS or not finished <= approved < expires_at:
                raise WorkerFailure("missing or invalid approval expiry or timestamp")
            self.start_reservation(
                db, job, digest, plan["provider"], plan["model"], plan["candidate"], plan["body_sha256"]
            )
            # Sample after acquiring the lock and staging the reserve. A boundary failure rolls it back.
            consumed = time.time()
            if not approved <= consumed < expires_at:
                raise WorkerFailure("one-shot approval expired or is outside its approval window")
            db.execute("UPDATE review_approval SET consumed=? WHERE job=?", (consumed, job))

    def settle_review(self, job, plan, receipt, checkpoint):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state, cancelled FROM job WHERE id=?", (job,)).fetchone()
            if row is None or row["state"] != "running" or row["cancelled"]:
                return
            if (
                db.execute(
                    "UPDATE api_review SET state=?, finished=? WHERE job=? AND session=? AND state='running'",
                    (receipt["state"], time.time(), job, plan["plan_sha256"]),
                ).rowcount
                != 1
            ):
                raise WorkerFailure("review settlement has no active reservation")
            db.execute("UPDATE review_approval SET receipt=? WHERE job=?", (encode(receipt).decode(), job))
            db.execute("UPDATE job SET checkpoint=? WHERE id=?", (encode(checkpoint).decode(), job))

    def control(self, action, target):
        self.require_initialized()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if action == "cancel":
                if db.execute("SELECT 1 FROM job WHERE id=?", (target,)).fetchone() is None:
                    raise ValueError("unknown task")
                self.cancel_rows(db, "id", target)
            elif action in {"pause", "resume", "stop"}:
                if db.execute("UPDATE project SET paused=? WHERE name=?", (action != "resume", target)).rowcount != 1:
                    raise ValueError("unknown project")
                if action == "stop":
                    self.cancel_rows(db, "project", target)
                    if self.has_model_approval_requests(db):
                        db.execute(
                            "UPDATE model_approval_request SET cancelled=? "
                            "WHERE project=? AND job IS NULL AND cancelled IS NULL",
                            (time.time(), target),
                        )
            else:
                raise ValueError("unknown control")

    @staticmethod
    def cancel_rows(db, column, target):
        db.execute(
            f"UPDATE job SET state='cancelled', cancelled=1, finished=?, reason='operator cancelled' "
            f"WHERE {column}=? AND state='queued'",
            (time.time(), target),
        )
        db.execute(f"UPDATE job SET cancelled=1 WHERE {column}=? AND state='running'", (target,))

    def claim(self, providers=()):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            paid = "j.scenario NOT IN ('api-review', 'api-task', 'engineering', 'research')"
            parameters = []
            slots = ",".join("?" for _ in providers)
            if providers and db.execute("SELECT 1 FROM sqlite_master WHERE name='engineering'").fetchone():
                paid += f""" OR (j.scenario='engineering' AND EXISTS (
                    SELECT 1 FROM engineering e WHERE e.job=j.id AND NOT EXISTS (
                        SELECT 1 FROM json_each(e.manifest, '$.providers') route
                        WHERE json_extract(route.value, '$.provider') NOT IN ({slots}))))"""
                parameters.extend(providers)
            if providers and self.has_approvals(db):
                paid += f""" OR (j.scenario IN ('api-review', 'api-task') AND EXISTS (
                    SELECT 1 FROM review_approval a WHERE a.job=j.id AND a.provider IN ({slots})))"""
                parameters.extend(providers)
            if providers and db.execute("SELECT 1 FROM sqlite_master WHERE name='research_campaign'").fetchone():
                paid += f""" OR (j.scenario='research' AND EXISTS (
                    SELECT 1 FROM research_job r JOIN research_campaign c ON c.id=r.campaign
                    WHERE r.job=j.id AND c.approved IS NOT NULL AND c.revoked IS NULL AND c.paused=0
                    AND NOT EXISTS (SELECT 1 FROM json_each(c.authorization, '$.manifest.providers') route
                                    WHERE route.key NOT IN ({slots}))))"""
                parameters.extend(providers)
            row = db.execute(
                f"""
                SELECT j.* FROM job j JOIN project p ON p.name=j.project
                WHERE j.state='queued' AND p.paused=0
                  AND ({paid})
                  AND (SELECT COUNT(*) FROM job WHERE state='running') < (SELECT slots FROM settings)
                  AND (SELECT COUNT(*) FROM job WHERE state='running' AND project=p.name) < p.slots
                ORDER BY p.last_start, j.id LIMIT 1
            """,
                parameters,
            ).fetchone()
            if row is not None:
                db.execute("UPDATE job SET state='running', started=? WHERE id=?", (time.time(), row["id"]))
                db.execute(
                    "UPDATE project SET last_start=(SELECT MAX(last_start)+1 FROM project) WHERE name=?",
                    (row["project"],),
                )
            return row

    def running(self):
        with self.connect() as db:
            return list(db.execute("SELECT * FROM job WHERE state='running' ORDER BY id"))

    def job(self, job):
        with self.connect() as db:
            return db.execute("SELECT * FROM job WHERE id=?", (job,)).fetchone()

    @contextmanager
    def reserve(self, job, session, provider, model, candidate, digest):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT scenario FROM job WHERE id=?", (job,)).fetchone()
            if row is None or row["scenario"] in {"api-review", "api-task", "engineering", "research"}:
                raise WorkerFailure("paid reservation requires one-shot approval")
            self.start_reservation(db, job, session, provider, model, candidate, digest)
        outcome = "failed"
        try:
            yield
            outcome = "response_received"
        finally:
            with self.connect() as db:
                db.execute(
                    "UPDATE api_review SET state=?, finished=? WHERE session=? AND state='running'",
                    (outcome, time.time(), session),
                )

    @staticmethod
    def start_reservation(db, job, session, provider, model, candidate, digest, *, amount=None):
        row = db.execute(
            """
                SELECT j.state, j.cancelled, j.scenario, j.reserve, p.paused, p.budget AS project_cap, s.budget AS global_cap,
                       (SELECT COALESCE(SUM(reserve_microusd), 0) FROM api_review) AS total,
                       (SELECT COALESCE(SUM(reserve_microusd), 0) FROM api_review WHERE job=j.id) AS job_total,
                       (SELECT COALESCE(SUM(a.reserve_microusd), 0) FROM api_review a
                        JOIN job other ON other.id=a.job WHERE other.project=j.project) AS project_total
                FROM job j JOIN project p ON p.name=j.project CROSS JOIN settings s WHERE j.id=?
            """,
            (job,),
        ).fetchone()
        if (
            row is None
            or row["state"] != "running"
            or row["cancelled"]
            or (row["scenario"] in {"api-task", "research"} and row["paused"])
        ):
            raise WorkerFailure("task no longer authorized to dispatch")
        reserve = row["reserve"] if amount is None else amount
        if amount is not None and row["job_total"] + reserve > row["reserve"]:
            raise WorkerFailure("engineering task API reserve ceiling reached")
        if row["total"] + reserve > row["global_cap"] or row["project_total"] + reserve > row["project_cap"]:
            raise WorkerFailure("global or project API reserve ceiling reached")
        db.execute(
            "INSERT INTO api_review VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?, NULL)",
            (session, job, provider, model, candidate, digest, reserve, time.time()),
        )

    def publish(self, job, result):
        with self.connect() as db:
            db.execute(
                "UPDATE job SET checkpoint=? WHERE id=? AND state='running' AND cancelled=0", (json.dumps(result), job)
            )

    def finish(self, job, missing_reason, *, accept_checkpoint=True):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM job WHERE id=? AND state='running'", (job,)).fetchone()
            if row is None:
                return
            checkpoint = json.loads(row["checkpoint"]) if accept_checkpoint and row["checkpoint"] else None
            if row["cancelled"]:
                state, reason = "cancelled", "operator cancelled"
                checkpoint = None
            elif checkpoint:
                state, reason = checkpoint["status"], checkpoint.get("reason")
            else:
                state, reason = "interrupted", missing_reason
            db.execute(
                "UPDATE job SET state=?, finished=?, reason=?, checkpoint=? WHERE id=?",
                (state, time.time(), reason, json.dumps(checkpoint) if checkpoint else None, job),
            )
            db.execute(
                "UPDATE api_review SET state='uncertain', finished=? WHERE job=? AND state='running'",
                (time.time(), job),
            )
            if row["scenario"] in {"api-review", "api-task"}:
                receipt = {
                    "state": "uncertain",
                    "reserve_microusd": row["reserve"],
                    "estimated_microusd": None,
                    "actual_charge_microusd": None,
                }
                db.execute(
                    "UPDATE review_approval SET receipt=? WHERE job=? AND consumed IS NOT NULL AND receipt IS NULL",
                    (encode(receipt).decode(), job),
                )
            elif row["scenario"] == "engineering":
                workflow_auth.pause_uncertain(db, job)
                for reservation in db.execute(
                    "SELECT session, reserve_microusd FROM api_review WHERE job=? AND state='uncertain'", (job,)
                ):
                    receipt = {
                        "state": "uncertain",
                        "reserve_microusd": reservation["reserve_microusd"],
                        "estimated_microusd": None,
                        "actual_charge_microusd": None,
                    }
                    db.execute(
                        "UPDATE engineering_request SET receipt=? WHERE session=? AND receipt IS NULL",
                        (encode(receipt).decode(), reservation["session"]),
                    )
            elif row["scenario"] == "research":
                import research

                research.finish(db, self, job, state)

    def launch(self, job, node, credential=None):
        research_job = self.job(job)["scenario"] == "research"
        if not research_job and (credential is None or isinstance(credential, dict)) and not node:
            raise WorkerFailure("an existing Node executable is required for engineering")
        started = time.monotonic()
        work = self.workspace(job)
        work.mkdir(mode=0o700, exist_ok=True)
        home = work / "home"
        home.mkdir(mode=0o700, exist_ok=research_job)
        with (work / "lease").open("a") as lease, (work / "output.log").open("ab" if research_job else "xb") as out:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            read, write = os.pipe()
            try:
                engineering = isinstance(credential, dict) and not research_job
                entry = (
                    "research.py"
                    if research_job
                    else "engineering.py"
                    if engineering
                    else "paid_review.py"
                    if credential is not None
                    else "mock_engineering.py"
                )
                env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(work)}
                if research_job:
                    import research

                    authorization = research.checked(self, research.campaign(self, job))
                    deadline = started + authorization["expires_at"] - time.time()
                    env["ARCTURUS_RESEARCH_KEYS"] = json.dumps(credential)
                elif engineering:
                    from engineering import stored_manifest

                    duration = stored_manifest(self, job)["limits"]["seconds"]
                    deadline = workflow_auth.worker_deadline(self, job, started, duration)
                    if time.monotonic() >= deadline:
                        raise WorkerFailure("engineering workflow authorization expired before launch")
                    env["ARCTURUS_ENGINEERING_KEYS"] = json.dumps(credential)
                elif credential is not None:
                    deadline = started + REVIEW_TIMEOUT
                    env["ARCTURUS_REVIEW_KEY_FILE"] = credential
                else:
                    deadline = started + DEADLINE
                proc = subprocess.Popen(
                    [
                        sys.executable,
                        "-B",
                        str(SOURCE / entry),
                        str(self.root),
                        str(job),
                        str(read),
                        str(lease.fileno()),
                        *([node] if credential is None or engineering else []),
                    ],
                    cwd=work,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=subprocess.STDOUT,
                    pass_fds=(read, lease.fileno()),
                    start_new_session=True,
                )
            except BaseException:
                os.close(write)
                raise
            finally:
                os.close(read)
        return Child(proc, write, deadline)

    def recover(self, job):
        # The lease is inherited at spawn. Never replay an active job or signal a stale PID.
        work = self.workspace(job)
        work.mkdir(mode=0o700, exist_ok=True)
        with (work / "lease").open("a") as lease:
            try:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            self.finish(job, "prior supervisor or worker exited before a final checkpoint")

    @staticmethod
    def kill(child):
        # This child is from this invocation. The child and its authored subprocesses share a group.
        try:
            os.killpg(child.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.process.wait(timeout=5)

    def run(self, node, stop, credentials=None):
        self.require_initialized()
        credentials = credentials or {}
        with (self.root / "controller.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("schedule already has a supervisor") from exc
            active = {}
            try:
                while not stop():
                    running = self.running()
                    for row in running:
                        job = row["id"]
                        child = active.get(job)
                        if child is None:
                            self.recover(job)
                            continue
                        cancelled = bool(row["cancelled"])
                        if row["scenario"] == "research":
                            import research

                            cancelled = cancelled or not research.active(self, job)
                        expired = time.monotonic() >= child.expires
                        if cancelled or expired:
                            if child.process.poll() is None:
                                self.kill(child)
                            reason = "worker timed out" if expired else "operator cancelled"
                            self.finish(job, reason, accept_checkpoint=False)
                        elif child.process.poll() is not None:
                            self.finish(
                                job,
                                "worker exited before a final checkpoint",
                                accept_checkpoint=child.process.returncode == 0,
                            )
                        else:
                            continue
                        os.close(active.pop(job).parent_pipe)
                    while not stop():
                        row = self.claim(credentials)
                        if row is None:
                            break
                        job = row["id"]
                        try:
                            if row["scenario"] in {"api-review", "api-task"}:
                                active[job] = self.launch(job, node, credentials[self.approval(job)["provider"]])
                            elif row["scenario"] in {"engineering", "research"}:
                                active[job] = self.launch(job, node, credentials)
                            else:
                                active[job] = self.launch(job, node)
                        except (OSError, ValueError, WorkerFailure):
                            self.finish(job, "could not launch the worker", accept_checkpoint=False)
                    if not self.running():
                        return
                    time.sleep(POLL)
            finally:
                for job, child in active.items():
                    # Closing the pipe also stops the child if the supervisor is killed here.
                    os.close(child.parent_pipe)
                    if child.process.poll() is None:
                        self.kill(child)
                    self.finish(job, "supervisor stopped before a final checkpoint")
                with self.connect() as db:
                    research_present = db.execute(
                        "SELECT 1 FROM sqlite_master WHERE name='research_campaign'"
                    ).fetchone()
                if research_present:
                    import research

                    research.export(self)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="dedicated private schedule directory")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--slots", type=int, default=2)
    init.add_argument("--a-slots", type=int, default=1)
    init.add_argument("--b-slots", type=int, default=1)
    init.add_argument("--budget", type=int, default=300)
    init.add_argument("--a-budget", type=int, default=200)
    init.add_argument("--b-budget", type=int, default=100)
    api_init = commands.add_parser("api-init")
    api_init.add_argument("project")
    api_init.add_argument("--reserve", type=int, required=True, help="project and global ceiling in microdollars")
    for command in ("model-plan", "approve-model", "model-approval-request"):
        model_task = commands.add_parser(command)
        model_task.add_argument("spec", type=Path)
        model_task.add_argument("--expires-at", type=int, required=True)
    signed = commands.add_parser("approve-signed-model")
    signed.add_argument("plan_sha256")
    signed.add_argument("--operator", required=True)
    signed.add_argument("--signature", type=Path, required=True)
    commands.add_parser("cancel-model-approval").add_argument("plan_sha256")
    commands.add_parser("status")
    research_init = commands.add_parser("research-init")
    research_init.add_argument("manifest", type=Path)
    research_init.add_argument("--expires-at", type=int, required=True)
    commands.add_parser("research-budget").add_argument("manifest", type=Path)
    research_approve = commands.add_parser("approve-research")
    research_approve.add_argument("authorization")
    research_approve.add_argument("--operator", required=True)
    research_approve.add_argument("--signature", type=Path, required=True)
    recovery = commands.add_parser("research-recovery-init")
    recovery.add_argument("authorization")
    recovery.add_argument("--expires-at", type=int, required=True)
    recovery.add_argument("--replace-uncertain", action="append", default=[])
    for command in ("research-resume", "revoke-research", "research-recovery-plan"):
        commands.add_parser(command).add_argument("authorization")
    engineering = commands.add_parser("engineering-init")
    engineering.add_argument("manifests", nargs=2, type=Path)
    request = commands.add_parser("engineering-request")
    request.add_argument("session")
    commands.add_parser("engineering-handoff").add_argument("job", type=int)
    preflight = commands.add_parser("engineering-preflight")
    preflight.add_argument("--node", default=shutil.which("node"))
    step = commands.add_parser("approve-step")
    step.add_argument("session")
    for command in ("workflow-plan", "approve-workflow"):
        workflow = commands.add_parser(command)
        workflow.add_argument("job", type=int)
        workflow.add_argument("--expires-at", type=int, required=True)
        workflow.add_argument("--requests", type=int, required=True)
        workflow.add_argument("--repairs", type=int, required=True)
        workflow.add_argument("--reserve", type=int, required=True, help="ceiling in microdollars")
        workflow.add_argument("--operations", nargs="+", choices=workflow_auth.OPERATIONS, required=True)
    commands.add_parser("revoke-workflow").add_argument("job", type=int)
    trial = commands.add_parser("trial-plan")
    trial.add_argument("task", type=int)
    trial.add_argument("--provider", choices=("anthropic", "openai"), default="anthropic")
    trial.add_argument("--model")
    recovery_plan = commands.add_parser("recovery-plan")
    recovery_plan.add_argument("task", type=int)
    recovery_plan.add_argument("candidate")
    recovery_plan.add_argument("--expires-at", required=True, type=int)
    recovery_approve = commands.add_parser("approve-recovery")
    recovery_approve.add_argument("task", type=int)
    recovery_approve.add_argument("candidate")
    recovery_approve.add_argument("--expires-at", required=True, type=int)
    approve = commands.add_parser("approve-review")
    approve.add_argument("task", type=int)
    approve.add_argument("--provider", choices=("anthropic", "openai"), required=True)
    approve.add_argument("--model", required=True)
    add = commands.add_parser("add")
    add.add_argument("project")
    add.add_argument("scenario", choices=SCENARIOS)
    add.add_argument("--reserve", type=int, default=100)
    run = commands.add_parser("run")
    run.add_argument("--node", default=shutil.which("node"))
    for provider in LIVE_MODELS:
        run.add_argument(f"--{provider}-key-file")
    for action in ("pause", "resume", "stop"):
        commands.add_parser(action).add_argument("project")
    commands.add_parser("cancel").add_argument("task", type=int)
    args = parser.parse_args()
    os.umask(0o077)
    scheduler = Scheduler(args.root)
    try:
        if args.command == "init":
            scheduler.initialize(
                args.slots,
                args.budget,
                {"project-a": (args.a_slots, args.a_budget), "project-b": (args.b_slots, args.b_budget)},
            )
            scheduler.enqueue("project-a", "repair", 100)
            scheduler.enqueue("project-b", "clean", 100)
        elif args.command == "api-init":
            scheduler.initialize(1, args.reserve, {args.project: (1, args.reserve)})
        elif args.command in {
            "research-budget",
            "research-init",
            "approve-research",
            "research-resume",
            "revoke-research",
            "research-recovery-plan",
            "research-recovery-init",
        }:
            import research

            if args.command == "research-budget":
                print(json.dumps(research.budget(decode(args.manifest.read_bytes(), maximum=MAX_REQUEST)), indent=2))
            elif args.command == "research-init":
                sys.stdout.buffer.write(
                    research.enroll(scheduler, decode(args.manifest.read_bytes(), maximum=MAX_REQUEST), args.expires_at)
                )
            elif args.command == "approve-research":
                research.approve(
                    scheduler, args.authorization, args.operator, operator_approval.read_signature(args.signature)
                )
                print("Research workflow signature verified and activated.")
            elif args.command == "research-recovery-init":
                from research_recovery import prepare

                sys.stdout.buffer.write(prepare(scheduler, args.authorization, args.expires_at, args.replace_uncertain))
            elif args.command == "research-recovery-plan":
                print(json.dumps(research.recovery_plan(scheduler, args.authorization), indent=2))
            elif args.command == "research-resume":
                research.resume(scheduler, args.authorization)
            else:
                research.revoke(scheduler, args.authorization)
        elif args.command == "model-approval-request":
            from model_tasks import read_spec

            sys.stdout.buffer.write(scheduler.model_approval_request(read_spec(args.spec), args.expires_at))
        elif args.command == "approve-signed-model":
            job = scheduler.approve_signed_model(
                args.plan_sha256, args.operator, operator_approval.read_signature(args.signature)
            )
            print(f"Queued model task {job}.")
        elif args.command == "cancel-model-approval":
            scheduler.cancel_model_approval(args.plan_sha256)
        elif args.command in {"model-plan", "approve-model"}:
            from model_tasks import read_spec

            spec = read_spec(args.spec)
            plan = scheduler.prepare_model(spec, args.expires_at)
            print(json.dumps(plan, indent=2))
            if args.command == "approve-model":
                if operator_approval.configured():
                    raise ValueError("model task requires a signed operator approval")
                if not sys.stdin.isatty():
                    raise ValueError("model task approval requires the trusted operator terminal")
                digest = plan["plan_sha256"]
                if input("Enter APPROVE and the SHA-256 from the plan you inspected: ") != f"APPROVE {digest}":
                    raise ValueError("exact model task approval was not supplied")
                print(f"Queued model task {scheduler.approve_model(spec, args.expires_at, digest)}.")
        elif args.command == "status":
            print(json.dumps(scheduler.status(), indent=2))
        elif args.command in {"engineering-init", "engineering-request", "engineering-preflight", "approve-step"}:
            from engineering import operator_command

            operator_command(scheduler, args)
        elif args.command == "engineering-handoff":
            from engineering_handoff import ready_result

            print(json.dumps(ready_result(scheduler, args.job), indent=2))
        elif args.command in {"workflow-plan", "approve-workflow"}:
            policy_args = (args.job, args.expires_at, args.requests, args.repairs, args.reserve, args.operations)
            plan = workflow_auth.prepare(scheduler, *policy_args)
            print(json.dumps(plan, indent=2))
            if args.command == "approve-workflow":
                if not sys.stdin.isatty():
                    raise ValueError("workflow approval requires the trusted operator terminal")
                confirmation = input("Enter APPROVE and the authorization SHA-256: ")
                digest = plan["authorization_sha256"]
                if confirmation != f"APPROVE {digest}":
                    raise ValueError("exact workflow approval was not supplied")
                workflow_auth.approve(scheduler, *policy_args, digest)
        elif args.command == "revoke-workflow":
            workflow_auth.revoke(scheduler, args.job)
        elif args.command == "trial-plan":
            if args.provider != "anthropic" and not args.model:
                raise ValueError("provide the exact model for this provider")
            print(json.dumps(scheduler.prepare_trial(args.task, args.provider, args.model or TRIAL_MODEL), indent=2))
        elif args.command == "recovery-plan":
            print(json.dumps(scheduler.prepare_recovery(args.task, args.candidate, args.expires_at), indent=2))
        elif args.command in {"approve-review", "approve-recovery"}:
            if not sys.stdin.isatty():
                raise ValueError("approval requires the trusted operator terminal")
            recovery = (args.candidate, args.expires_at) if args.command == "approve-recovery" else None
            if recovery is None:
                plan = scheduler.prepare_trial(args.task, args.provider, args.model)
            else:
                plan = scheduler.prepare_recovery(args.task, *recovery)
            digest = plan["plan_sha256"]
            print(
                f"One review for {plan['project']} {plan['candidate']} using {plan['model']}, "
                f"reserve {plan['illustrative_reserve_microusd']} microdollars. "
                f"Expires {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(plan['expires_at']))}."
            )
            if recovery is not None:
                print("This approval adds that exact reserve to the project and global ceilings on consumption.")
            if input("Enter APPROVE and the SHA-256 from the plan you inspected: ") != f"APPROVE {digest}":
                raise ValueError("exact one-shot approval was not supplied")
            print(
                f"Queued review job {scheduler.approve_review(args.task, plan['provider'], plan['model'], digest, recovery=recovery)}."
            )
        elif args.command == "add":
            print(scheduler.enqueue(args.project, args.scenario, args.reserve))
        elif args.command == "run":
            credentials = {
                provider: getattr(args, f"{provider}_key_file")
                for provider in LIVE_MODELS
                if getattr(args, f"{provider}_key_file") is not None
            }
            if credentials and not sys.stdin.isatty():
                raise ValueError("API dispatch requires the trusted operator terminal")
            stopped = False

            def stop(*_):
                nonlocal stopped
                stopped = True

            signal.signal(signal.SIGINT, stop)
            signal.signal(signal.SIGTERM, stop)
            node = str(Path(args.node).resolve(strict=True)) if args.node else None
            scheduler.run(node, lambda: stopped, credentials)
            return 130 if stopped else 0
        else:
            scheduler.control(args.command, args.task if args.command == "cancel" else args.project)
    except (EOFError, OSError, sqlite3.Error, ValueError, WorkerFailure) as exc:
        print(f"BLOCKED — {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
