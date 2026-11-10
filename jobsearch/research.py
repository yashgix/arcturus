"""Foreground, offline coordinator for durable application research."""

import argparse
import fcntl
import json
import os
import sqlite3
import sys
import time
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import date, time as local_time, timedelta
from html import escape
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfoNotFoundError

from .ashby import Ashby, decode, read_bounded
from .candidate import load_profile, model_facts
from .dashboard import publish
from .live import ALLOWED_BOARDS
from .ranking import Profile, ROLE_SCOPE, _hits, _sponsorship, rank
from .research_model import DeepSeek, InvalidOutput, InvalidReceipt, fixture_transport, validate_packet
from .schedule import Cadence
from .store import Store, digest, encoded, normalized, stamp, utcnow

DEFAULT_PROFILE = Path(__file__).with_name("live-profile.json")
LEASE_SECONDS = 90


def read(path):
    with path.open("rb") as stream:
        return decode(read_bounded(stream))


def settings(raw):
    limits = {
        "daily_requests": 100,
        "daily_microusd": 10_000_000,
        "request_microusd": 10_000_000,
        "max_attempts": 5,
        "poll_seconds": 3600,
        "tasks_per_tick": 25,
    }
    if not isinstance(raw, dict) or set(raw) != {"boards", "cadence", *limits}:
        raise ValueError("invalid research configuration keys")
    for key, maximum in limits.items():
        if type(raw[key]) is not int or not 1 <= raw[key] <= maximum:
            raise ValueError(f"invalid {key}")
    if raw["request_microusd"] > raw["daily_microusd"]:
        raise ValueError("per-request reserve exceeds the daily spend cap")
    boards = raw["boards"]
    if (
        not isinstance(boards, list)
        or not boards
        or any(not isinstance(slug, str) or slug not in ALLOWED_BOARDS for slug in boards)
        or len(set(boards)) != len(boards)
    ):
        raise ValueError("research boards must be explicitly allowlisted")
    cadence = dict(raw["cadence"])
    cadence["anchor"] = date.fromisoformat(cadence["anchor"])
    cadence["local_time"] = local_time.fromisoformat(cadence["local_time"])
    schedule = Cadence(**cadence)
    schedule.due_slot(utcnow())
    return {**raw, "cadence": schedule}


def context_for(row, candidate, evidence):
    posting = row["posting"]
    sources = [
        {
            "id": "posting",
            "kind": "posting",
            "url": posting["url"],
            "date": posting["published"],
            "excerpt": posting["description"][:8000],
        }
    ]
    support = evidence.get(f"{row['board']}/{row['external_id']}", [])
    if not isinstance(support, list) or len(support) > 6:
        raise ValueError("invalid supplemental evidence list")
    for entry in support:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"kind", "url", "date", "excerpt"}
            or any(not isinstance(value, str) for value in entry.values())
            or entry["kind"] not in {"company", "role", "verified_role_restriction", "historical_sponsorship"}
            or not entry["excerpt"].strip()
            or len(entry["excerpt"]) > 1000
            or len(entry["url"]) > 500
            or any(ord(char) < 32 for char in entry["url"])
        ):
            raise ValueError("invalid supplemental evidence")
        url = urlsplit(entry["url"])
        if url.scheme != "https" or not url.hostname or url.username is not None:
            raise ValueError("evidence requires an HTTPS source URL")
        evidence_date = date.fromisoformat(entry["date"]).isoformat()
        sources.append({**entry, "date": evidence_date, "id": f"evidence-{len(sources)}"})
    facts, variants = model_facts(candidate)
    location = candidate["locations"]
    matched = _hits(location["allowed_terms"], normalized(" / ".join([posting["location"], *posting["secondary"]])))
    return {
        "candidate": {
            "schema_version": candidate["schema_version"],
            "revision": candidate["revision"],
            "mode": candidate["mode"],
            "variants": variants,
        },
        "location_constraints": {**location, "matched_terms": matched},
        "board": row["board"],
        "external_id": row["external_id"],
        "title": posting["title"],
        "company": row["company"],
        "location": posting["location"],
        "workplace": posting["workplace"],
        "resume_facts": facts,
        "sources": sources,
        "posting_sponsorship": _sponsorship(posting["description"])[0],
    }


def state(db):
    return db.execute("SELECT state FROM research_control WHERE singleton=1").fetchone()[0]


def change_state(store, value):
    with store.write():
        store.db.execute("UPDATE research_control SET state=? WHERE singleton=1", (value,))


def initialize(path):
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ValueError("research initialization requires a fresh registry path") from exc
    os.close(descriptor)
    with closing(Store(path, live_registry=False)) as store, store.write():
        store._schema("research_schema.sql")


def open_registry(path):
    if not path.is_file():
        raise ValueError("initialize a dedicated research registry first")
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='research_control'").fetchone() is None:
            raise ValueError("initialize a dedicated research registry first")
    store = Store(path, live_registry=False)
    try:
        with store.write():
            store._schema("research_schema.sql")
            if not any(row["name"] == "deferred" for row in store.db.execute("PRAGMA table_info(research_tasks)")):
                store.db.execute(
                    "ALTER TABLE research_tasks ADD COLUMN deferred INTEGER NOT NULL DEFAULT 0 CHECK(deferred IN (0,1))"
                )
    except BaseException:
        store.close()
        raise
    return store


@contextmanager
def coordinator(path):
    with path.with_name(path.name + ".lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("a research coordinator already owns this registry") from exc
        yield


def discover(store, config, fixtures, now):
    slot = config["cadence"].due_slot(now)
    if slot is None:
        return
    adapter = Ashby([ALLOWED_BOARDS[slug] for slug in config["boards"]])
    for slug in config["boards"]:
        if state(store.db) != "running":
            break
        previous = store.db.execute(
            "SELECT status FROM attempts WHERE slot=? AND source='ashby' AND board=? ORDER BY id DESC LIMIT 1",
            (slot, slug),
        ).fetchone()
        if previous and previous[0] != "interrupted":
            continue
        token = store.begin(slot, "ashby", slug, now)
        if token is None:
            continue
        try:
            with (fixtures / f"{slug}.json").open("rb") as stream:
                jobs = adapter.fixture(slug, read_bounded(stream))
        except KeyboardInterrupt:
            interrupt_discovery(store, now, token)
            raise
        except (OSError, ValueError) as exc:
            if state(store.db) == "running":
                store.fail(token, type(exc).__name__, now)
            else:
                interrupt_discovery(store, now, token)
            continue
        # Use the supervised store's omission/quarantine rules for offline rehearsal.
        store.complete(
            token,
            ALLOWED_BOARDS[slug],
            jobs,
            now,
            live=True,
            observed_at=now,
            may_apply=lambda: state(store.db) == "running",
        )


def interrupt_discovery(store, now, token=None):
    # Startup calls this while holding the dedicated coordinator lock.
    with store.write():
        store.db.execute(
            """UPDATE attempts SET status='interrupted',finished=?,error='coordinator interrupted'
               WHERE status='running' AND (? IS NULL OR id=?)""",
            (stamp(now), token, token),
        )


def reconcile_queue(store, eligible_ids):
    with store.write():
        store.db.execute(
            """UPDATE research_tasks SET state='superseded',error='posting closed',deferred=0
               WHERE state='queued' AND EXISTS(
                   SELECT 1 FROM postings p WHERE p.job_id=research_tasks.job_id AND p.active=0)"""
        )
        queued = store.db.execute("SELECT DISTINCT job_id FROM research_tasks WHERE state='queued'").fetchall()
        for (job_id,) in queued:
            deferred = int(job_id not in eligible_ids)
            store.db.execute(
                "UPDATE research_tasks SET deferred=? WHERE job_id=? AND state='queued' AND deferred<>?",
                (deferred, job_id, deferred),
            )


def enqueue(store, candidates, candidate, evidence, now):
    contexts = {}
    with store.write():
        if state(store.db) != "running":
            return contexts
        for row in candidates:
            body_hash = digest(row["posting"])
            try:
                context = context_for(row, candidate, evidence)
            except (TypeError, ValueError):
                context = None
            version = digest([1, body_hash, context])
            store.db.execute(
                """INSERT OR IGNORE INTO research_tasks(job_id,version,posting_hash,state,due_at,error)
                   VALUES (?,?,?,?,?,?)""",
                (
                    row["id"],
                    version,
                    body_hash,
                    "queued" if context else "failed",
                    stamp(now),
                    None if context else "invalid supplemental evidence",
                ),
            )
            store.db.execute(
                """UPDATE research_tasks SET state='superseded'
                   WHERE job_id=? AND version<>? AND state='queued'""",
                (row["id"], version),
            )
            if context:
                store.db.execute(
                    """UPDATE research_tasks SET state='queued',deferred=0
                       WHERE job_id=? AND version=? AND state='superseded'""",
                    (row["id"], version),
                )
                task = store.db.execute(
                    "SELECT id FROM research_tasks WHERE job_id=? AND version=?",
                    (row["id"], version),
                ).fetchone()
                store.db.execute(
                    """INSERT INTO research_current(job_id,task_id) VALUES (?,?)
                       ON CONFLICT(job_id) DO UPDATE SET task_id=excluded.task_id""",
                    (row["id"], task[0]),
                )
                contexts[task[0]] = context
            else:
                store.db.execute("DELETE FROM research_current WHERE job_id=?", (row["id"],))
    return contexts


def recover(store, config, now):
    with store.write():
        for row in store.db.execute(
            "SELECT id,claim,attempts FROM research_tasks WHERE state='running' AND lease_until<=?",
            (stamp(now),),
        ).fetchall():
            store.db.execute("UPDATE research_attempts SET outcome='interrupted' WHERE id=?", (row["claim"],))
            retry(store.db, row["id"], row["attempts"], config, now, "interrupted attempt")


def retry(db, task_id, attempts, config, now, error):
    next_due = stamp(now + timedelta(seconds=30 * 2 ** (attempts - 1)))
    db.execute(
        """UPDATE research_tasks SET state=?,due_at=?,claim=NULL,lease_until=NULL,error=? WHERE id=?""",
        ("failed" if attempts >= config["max_attempts"] else "queued", next_due, error, task_id),
    )


def claim(store, task_id, config, now):
    with store.write():
        if state(store.db) != "running":
            return None
        row = store.db.execute(
            """SELECT attempts FROM research_tasks WHERE id=? AND state='queued'
               AND deferred=0 AND due_at<=? AND attempts<?
               AND EXISTS(SELECT 1 FROM research_current c WHERE c.task_id=research_tasks.id)""",
            (task_id, stamp(now), config["max_attempts"]),
        ).fetchone()
        if row is None:
            return None
        day = stamp(now)[:10]
        receipts = store.db.execute(
            """SELECT coalesce(charged_microusd,reserved_microusd)
               FROM research_attempts WHERE utc_day=?""",
            (day,),
        ).fetchall()
        count = len(receipts)
        spent = sum(amount for (amount,) in receipts)
        reserve = config["request_microusd"]
        if count >= config["daily_requests"] or spent + reserve > config["daily_microusd"]:
            return None
        token = store.db.execute(
            """INSERT INTO research_attempts(task_id,utc_day,started,reserved_microusd,outcome)
               VALUES (?,?,?,?,'running')""",
            (task_id, day, stamp(now), reserve),
        ).lastrowid
        store.db.execute(
            """UPDATE research_tasks SET state='running',claim=?,lease_until=?,attempts=attempts+1,error=NULL
               WHERE id=?""",
            (token, stamp(now + timedelta(seconds=LEASE_SECONDS)), task_id),
        )
        return token


def finish(store, task_id, token, config, now, *, packet=None, charge=None, error=None):
    with store.write():
        if charge is not None:
            store.db.execute(
                """UPDATE research_attempts SET charged_microusd=?
                   WHERE id=? AND task_id=? AND charged_microusd IS NULL""",
                (charge, token, task_id),
            )
        row = store.db.execute(
            """SELECT attempts FROM research_tasks WHERE id=? AND claim=? AND state='running'
               AND lease_until>?""",
            (task_id, token, stamp(now)),
        ).fetchone()
        if row is None:
            return
        store.db.execute(
            "UPDATE research_attempts SET outcome=? WHERE id=?",
            ("failed" if error else "ready", token),
        )
        if error:
            retry(store.db, task_id, row[0], config, now, error)
        else:
            store.db.execute(
                """UPDATE research_tasks SET state='ready',packet=?,claim=NULL,lease_until=NULL
                   WHERE id=?""",
                (encoded(packet), task_id),
            )


def tick(store, config, fixtures, profile, candidate, evidence, model, *, clock=utcnow):
    if state(store.db) != "running":
        return
    if candidate["mode"] != "synthetic":
        raise ValueError("this offline release accepts synthetic candidate profiles only")
    profile = replace(
        profile,
        locations=candidate["locations"]["allowed_terms"],
        require_location=candidate["locations"]["require_match"],
    )
    now = clock()
    recover(store, config, now)
    discover(store, config, fixtures, now)
    verified = {row["board"] for row in store.run_status() if row["source"] == "ashby" and row["status"] == "complete"}
    rows = [
        row
        for row in store.inbox()
        if row["active"]
        and not row["pending_absence"]
        and row["source"] == "ashby"
        and row["board"] in verified
        and row["board"] in config["boards"]
    ]
    selected, available = rank(rows, profile, now, sponsorship_informational=True)
    candidates = selected + available
    reconcile_queue(store, {row["id"] for row in candidates})
    contexts = enqueue(store, candidates, candidate, evidence, now)
    dispatched = 0
    for task_id, context in contexts.items():
        if dispatched >= config["tasks_per_tick"]:
            break
        token = claim(store, task_id, config, clock())
        if token is None:
            continue
        dispatched += 1
        charge = None
        packet = None
        error = "model or packet validation failed"
        try:
            result = model.generate(context)
            charge = result.charged_microusd
            if type(charge) is not int or not 0 <= charge <= 2**63 - 1:
                raise InvalidReceipt("invalid model cost")
            draft = validate_packet(result.content, context)
            packet = {
                "draft": draft,
                "sources": context["sources"],
                "candidate": context["candidate"],
                "title": context["title"],
                "company": context["company"],
                "location_constraints": context["location_constraints"],
                "fact_source_refs": {key: fact["source_refs"] for key, fact in context["resume_facts"].items()},
                "sponsorship": sponsorship(context),
            }
            json.dumps(packet, ensure_ascii=False).encode("utf-8")
            error = None
        except InvalidReceipt:
            error = "invalid model cost receipt"
        except InvalidOutput as exc:
            charge = exc.charged_microusd
        except Exception:
            pass
        if charge is not None and (type(charge) is not int or not 0 <= charge <= 2**63 - 1):
            error = "invalid model cost receipt"
            charge = None
        if error == "invalid model cost receipt" or (charge is not None and charge > config["request_microusd"]):
            change_state(store, "paused")
            error = "invalid model cost receipt"
        finish(store, task_id, token, config, clock(), charge=charge, packet=packet, error=error)
        if error == "invalid model cost receipt":
            break


def sponsorship(context):
    posting, *supplemental = context["sources"]
    restrictions = [source for source in supplemental if source["kind"] == "verified_role_restriction"]
    history = [source["id"] for source in supplemental if source["kind"] == "historical_sponsorship"]
    current_wording = [context["posting_sponsorship"]] + [
        _sponsorship(source["excerpt"])[0]
        for source in supplemental
        if source["kind"] in ("role", "company", "verified_role_restriction")
    ]
    incompatible = any(
        wording.endswith(" sponsorship wording") or wording in ("conflicting wording", "uncertain role eligibility")
        for wording in current_wording
    )
    applicable = bool(posting["date"]) and all(
        source["date"] >= posting["date"][:10]
        and ROLE_SCOPE.search(normalized(source["excerpt"]))
        and _sponsorship(source["excerpt"])[1]
        for source in restrictions
    )
    return {
        "current": "confirmed_restriction" if restrictions and applicable and not incompatible else "unknown",
        "restriction_sources": [source["id"] for source in restrictions],
        "historical_sources": history,
    }


def display_text(value):
    return escape(value.encode("utf-8", "replace").decode("utf-8"))


def report(path, output):
    if output.suffix != ".html" or output.resolve() == path.resolve():
        raise ValueError("report needs a separate .html file")
    uri = path.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as db:
        db.row_factory = sqlite3.Row
        db.text_factory = lambda data: data.decode("utf-8", errors="replace")
        db.execute("BEGIN")
        control = state(db)
        upgraded = db.execute("SELECT 1 FROM sqlite_master WHERE name='research_current'").fetchone()
        bucket = "CASE WHEN state='queued' AND deferred=1 THEN 'deferred' ELSE state END" if upgraded else "state"
        counts = dict(db.execute(f"SELECT {bucket} bucket,count(*) FROM research_tasks GROUP BY bucket"))
        current_task = "c.task_id" if upgraded else "NULL"
        current_join = "LEFT JOIN research_current c ON c.job_id=t.job_id" if upgraded else ""
        usage = {}
        for day, charged, reserved in db.execute(
            """SELECT utc_day,charged_microusd,reserved_microusd FROM research_attempts
               WHERE utc_day IN (SELECT DISTINCT utc_day FROM research_attempts ORDER BY utc_day DESC LIMIT 14)
               ORDER BY utc_day DESC"""
        ):
            daily = usage.setdefault(day, {"utc_day": day, "requests": 0, "charged": 0, "reserved": 0})
            daily["requests"] += 1
            if charged is None:
                daily["reserved"] += reserved
            else:
                daily["charged"] += charged
        attempts = db.execute(
            """SELECT source,board,slot,status,error FROM attempts ORDER BY id DESC LIMIT 20"""
        ).fetchall()
        errors = db.execute(
            "SELECT job_id,state,error,due_at FROM research_tasks WHERE error IS NOT NULL ORDER BY id DESC LIMIT 20"
        ).fetchall()
        db.create_function("posting_digest", 1, lambda body: digest(json.loads(body)), deterministic=True)
        packets = db.execute(
            f"""WITH drafts AS (
               SELECT t.id,t.posting_hash,t.packet,p.body,p.active,
                      p.source,p.board,p.external_id,
                      EXISTS(SELECT 1 FROM pending_absences a WHERE
                          (a.source,a.board,a.external_id)=(p.source,p.board,p.external_id)) pending,
                      (SELECT a.status FROM attempts a JOIN runs r USING(slot,source,board)
                       WHERE (a.source,a.board)=(p.source,p.board)
                       ORDER BY r.generation DESC,a.id DESC LIMIT 1) source_status,
                      {current_task} current_task
               FROM research_tasks t JOIN postings p ON p.job_id=t.job_id
               {current_join}
               WHERE t.state='ready'
               )
               SELECT packet, CASE WHEN active AND NOT pending AND source_status='complete'
                   AND id=current_task AND posting_hash=posting_digest(body) THEN 1 ELSE 0 END is_current
               FROM drafts ORDER BY is_current DESC,id DESC LIMIT 50"""
        ).fetchall()
    html = """<!doctype html>
<html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Arcturus research review</title>
<style>body{font:16px system-ui;max-width:68rem;margin:2rem auto;padding:0 1rem}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>
<h1>Arcturus research review</h1><p>Offline rehearsal. Candidate evidence is synthetic. Review all drafts.</p>
"""
    html += f"<p>Coordinator: {escape(control)}</p>"
    for title, data in (
        ("Queue", counts),
        ("Cost ledger (millionths of USD)", list(usage.values())),
        ("Discovery", [dict(r) for r in attempts]),
        ("Research errors", [dict(r) for r in errors]),
    ):
        html += f"<h2>{title}</h2><pre>{escape(json.dumps(data, indent=2))}</pre>"
    html += "<h2>Prepared opportunities</h2>"
    for item in packets:
        label = "Current posting · draft" if item["is_current"] else "Historical or unverified · draft"
        packet = json.loads(item["packet"])
        try:
            json.dumps(packet, ensure_ascii=False).encode("utf-8")
        except UnicodeError:
            label = "Stored draft contains invalid Unicode · review required"
        title = display_text(packet["title"])
        url = display_text(packet["sources"][0]["url"])
        scores = packet["draft"]
        sponsorship = display_text(packet["sponsorship"]["current"].replace("_", " "))
        html += (
            f'<article><h3><a href="{url}" rel="noreferrer">{title}</a> · '
            f"{display_text(packet['company'])}</h3><p>{label}</p>"
            f"<p>Technical fit {scores['technical_fit']['score']}/100 · "
            f"Seniority fit {scores['seniority_fit']['score']}/100 · H-1B {sponsorship}</p>"
            f"<pre>{escape(json.dumps(packet, indent=2))}</pre></article>"
        )
    publish(output, html + "</html>")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("init", "resume", "pause", "stop"):
        commands.add_parser(command)
    view = commands.add_parser("report")
    view.add_argument("--html", type=Path, required=True)
    run = commands.add_parser("run")
    for option in ("config", "fixtures", "candidate", "responses"):
        run.add_argument(f"--{option}", type=Path, required=True)
    run.add_argument("--evidence", type=Path)
    run.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    run.add_argument("--watch", action="store_true", help="poll offline fixtures in an attended terminal")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            initialize(args.db)
            return 0
        if args.command == "report":
            report(args.db, args.html)
            return 0
        with closing(open_registry(args.db)) as store:
            if args.command != "run":
                change_state(store, {"pause": "paused", "resume": "running", "stop": "stopped"}[args.command])
                return 0
            if args.watch and not sys.stdin.isatty():
                raise ValueError("offline watch requires an attended terminal")
            config = settings(read(args.config))
            candidate = load_profile(read(args.candidate))
            profile = Profile.load(read(args.profile))
            evidence = read(args.evidence) if args.evidence else {}
            responses = read(args.responses)
            if not isinstance(evidence, dict) or not isinstance(responses, dict):
                raise ValueError("evidence and responses must be JSON objects")
            model = DeepSeek("deepseek-chat", fixture_transport(responses))
            with coordinator(args.db.resolve()):
                interrupt_discovery(store, utcnow())
                while state(store.db) == "running":
                    tick(store, config, args.fixtures, profile, candidate, evidence, model)
                    if not args.watch:
                        break
                    next_poll = time.monotonic() + config["poll_seconds"]
                    while state(store.db) == "running":
                        remaining = next_poll - time.monotonic()
                        if remaining <= 0:
                            break
                        time.sleep(min(remaining, 1))
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, KeyError, TypeError, ValueError, sqlite3.Error, ZoneInfoNotFoundError) as exc:
        print(f"research: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
