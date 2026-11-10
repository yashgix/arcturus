"""Signed public-source research campaigns on the existing Arcturus scheduler."""

import copy
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import signal
import sys
import threading
import time

from api_review import (
    LIVE_MODELS,
    MAX_RESPONSE,
    RESEARCH_MAX_REQUEST,
    RESEARCH_TIMEOUT,
    encode,
    trial_plan,
)
import operator_approval
from research_reports import CATEGORIES, SCHEMAS, STAGES, SYSTEM, complete, render, validate, wire_schema
from research_sources import SEARCH_PATHS, Retriever, allowed_url, compact_sources, digest, packet_sources
from workers import Limits, Request, WorkerFailure

MODES = ("equal-source", "independent")
POLICY_FILES = (
    "research.py",
    "research_sources.py",
    "research_reports.py",
    "api_review.py",
    "paid_review.py",
    "concurrent_runs.py",
    "research_recovery.py",
    "operator_approval.py",
    "workers.py",
    "mock_engineering.py",
)


class ResearchQualityFailure(WorkerFailure):
    """A fully accounted response failed the local research contract, not a security gate."""


class ResearchHeld(WorkerFailure):
    """A stage is excluded by signed authority; no request may be sent."""


def policy_hash():
    return digest(encode({name: digest(Path(__file__).with_name(name).read_bytes()) for name in POLICY_FILES}))


def make_plan(manifest, company, provider, mode, stage, packet, expires, campaign):
    route = manifest["providers"][provider]
    packet = copy.deepcopy(packet)
    if "sources" in packet:
        packet["sources"] = compact_sources(packet["sources"])
    packet = {**packet, "task": "public-research", "candidate": digest(encode(packet))}
    return trial_plan(
        packet,
        provider,
        route["model"],
        project=company["id"],
        source_job=None,
        expires_at=expires,
        build_schema=wire_schema(SCHEMAS[stage], provider),
        build_system=SYSTEM,
        data_class="public",
        fingerprint=route.get("fingerprint"),
        research={
            "role": "planning" if stage in {"discover", "expand"} else "research",
            "campaign": campaign,
            "mode": mode,
            "stage": stage,
        },
    ), packet


def validate_manifest(manifest):
    if (
        not isinstance(manifest, dict)
        or manifest.keys() != {"version", "companies", "providers", "limits"}
        or manifest["version"] != 1
        or set(manifest["providers"]) != set(LIVE_MODELS)
    ):
        raise ValueError("research manifest requires version, companies, three providers and explicit limits")
    limits = manifest["limits"]
    if (
        limits.keys() != {"reserve_microusd", "seconds", "retrieval_requests_per_lane", "source_characters"}
        or any(type(n) is not int for n in limits.values())
        or not 1 <= limits["reserve_microusd"] <= 10**9
        or not 60 <= limits["seconds"] <= 86400
        or not 1 <= limits["retrieval_requests_per_lane"] <= 100
        or not 500 <= limits["source_characters"] <= 12000
    ):
        raise ValueError("invalid research spending, duration, retrieval or context limits")
    companies = manifest["companies"]
    if (
        not isinstance(companies, list)
        or not 1 <= len(companies) <= 10
        or len({company["id"] for company in companies}) != len(companies)
    ):
        raise ValueError("research requires distinct company projects")
    for company in companies:
        if (
            company.keys() != {"id", "name", "origins", "seeds"}
            or not re.fullmatch("[a-z][a-z0-9-]{0,31}", company["id"])
            or not isinstance(company["name"], str)
            or not 1 <= len(company["name"]) <= 100
            or not isinstance(company["origins"], dict)
            or not company["origins"]
            or not isinstance(company["seeds"], list)
            or not 1 <= len(company["seeds"]) <= 20
        ):
            raise ValueError("invalid company identity or public source scope")
        for host, prefixes in company["origins"].items():
            if (
                not isinstance(host, str)
                or not re.fullmatch(r"[a-z0-9.-]+", host)
                or not isinstance(prefixes, list)
                or not prefixes
                or any(not isinstance(p, str) or not p.startswith("/") for p in prefixes)
            ):
                raise ValueError("invalid explicit public origin paths")
        if not any(company["origins"].get(host) == [path] for host, path in SEARCH_PATHS.items()):
            raise ValueError("research requires the same credential-free public search surface")
        for seed in company["seeds"]:
            if seed.keys() != {"url", "category"} or seed["category"] not in CATEGORIES:
                raise ValueError("invalid classified research seed")
            allowed_url(seed["url"], company["origins"])
    profiles = {}
    for provider, route in manifest["providers"].items():
        if route.keys() != ({"model", "fingerprint"} if provider == "deepseek" else {"model"}):
            raise ValueError("provider route fields differ from the approved API contract")
        plan, _ = make_plan(
            manifest,
            companies[0],
            provider,
            "independent",
            "report",
            {},
            int(time.time()) + limits["seconds"],
            "cost-only",
        )
        profiles[provider] = {
            key: plan[key]
            for key in (
                "model",
                "planning_input_tokens",
                "max_output_tokens",
                "timeout_seconds",
                "planning_rates_nanousd_per_token",
                "illustrative_reserve_microusd",
            )
        }
    return profiles


def budget(manifest):
    profiles = validate_manifest(manifest)
    per_company = sum(row["illustrative_reserve_microusd"] * 8 for row in profiles.values())
    return {
        "profiles": profiles,
        "calls_per_provider_per_company": 8,
        "max_requests": len(manifest["companies"]) * 24,
        "per_company_reserve_microusd": per_company,
        "full_reserve_microusd": per_company * len(manifest["companies"]),
        "max_retrieval_requests": len(manifest["companies"]) * 10 * manifest["limits"]["retrieval_requests_per_lane"],
        "max_request_bytes": RESEARCH_MAX_REQUEST,
        "automatic_retries": 0,
        "input_budget_basis": "262144-token planning allowance for at most 192000 request bytes, including framing headroom; not a provider billing guarantee",
    }


def exists(db):
    return db.execute("SELECT 1 FROM sqlite_master WHERE name='research_campaign'").fetchone() is not None


def enroll(schedule, manifest, expires):
    costs = budget(manifest)
    if costs["full_reserve_microusd"] > manifest["limits"]["reserve_microusd"]:
        raise ValueError("complete research reservation exceeds the operator ceiling")
    now = time.time()
    if type(expires) is not int or not now < expires <= now + manifest["limits"]["seconds"]:
        raise ValueError("research authorization expiry exceeds the approved duration")
    schedule.initialize(
        min(3, len(manifest["companies"])),
        manifest["limits"]["reserve_microusd"],
        {company["id"]: (1, costs["per_company_reserve_microusd"]) for company in manifest["companies"]},
    )
    payload = {
        "kind": "research-workflow-v1",
        "manifest": manifest,
        "budget": costs,
        "policy_sha256": policy_hash(),
        "expires_at": expires,
    }
    payload["authorization_sha256"] = digest(encode(payload))
    nonce = secrets.token_hex(32)
    with schedule.connect() as db:
        db.executescript("""
            CREATE TABLE research_campaign (
                id TEXT PRIMARY KEY, authorization TEXT NOT NULL, nonce TEXT NOT NULL,
                principal TEXT, signature BLOB, approved REAL, revoked REAL, paused INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE research_job (
                job INTEGER PRIMARY KEY REFERENCES job(id), campaign TEXT NOT NULL REFERENCES research_campaign(id),
                company TEXT NOT NULL, UNIQUE(campaign, company)
            );
            CREATE TABLE research_request (
                session TEXT PRIMARY KEY REFERENCES api_review(session),
                job INTEGER NOT NULL REFERENCES job(id), mode TEXT NOT NULL, stage TEXT NOT NULL,
                provider TEXT NOT NULL, plan TEXT NOT NULL, packet TEXT NOT NULL, receipt TEXT,
                UNIQUE(job, mode, stage, provider)
            );
            CREATE TABLE research_checkpoint (
                job INTEGER NOT NULL REFERENCES job(id), name TEXT NOT NULL, data TEXT NOT NULL, sha256 TEXT NOT NULL,
                PRIMARY KEY(job, name)
            );
        """)
        identity = payload["authorization_sha256"]
        db.execute(
            "INSERT INTO research_campaign(id, authorization, nonce) VALUES (?, ?, ?)",
            (identity, encode(payload).decode(), nonce),
        )
        for company in manifest["companies"]:
            job = db.execute(
                "INSERT INTO job(project, scenario, reserve) VALUES (?, 'research', ?)",
                (company["id"], costs["per_company_reserve_microusd"]),
            ).lastrowid
            db.execute("INSERT INTO research_job VALUES (?, ?, ?)", (job, identity, company["id"]))
    return operator_approval.message(schedule.root, nonce, payload)


def campaign(schedule, job):
    with schedule.connect() as db:
        row = db.execute(
            "SELECT c.*, r.company FROM research_campaign c JOIN research_job r ON c.id=r.campaign WHERE r.job=?",
            (job,),
        ).fetchone()
    if row is None:
        raise WorkerFailure("research job has no workflow authorization")
    return row


def authorized_budget(payload):
    if "recovery" in payload:
        from research_recovery import costs

        return costs(payload["manifest"], payload["recovery"])
    return budget(payload["manifest"])


def checked(schedule, row):
    payload = json.loads(row["authorization"])
    original = {k: v for k, v in payload.items() if k != "authorization_sha256"}
    if (
        digest(encode(original)) != row["id"]
        or payload["authorization_sha256"] != row["id"]
        or payload["policy_sha256"] != policy_hash()
        or payload["budget"] != authorized_budget(payload)
        or payload["budget"]["full_reserve_microusd"] > payload["manifest"]["limits"]["reserve_microusd"]
        or row["approved"] is None
        or row["revoked"] is not None
        or row["paused"]
        or not row["approved"] <= time.time() < payload["expires_at"]
    ):
        raise WorkerFailure("research workflow expired, revoked, paused or changed")
    operator_approval.verify(
        operator_approval.message(schedule.root, row["nonce"], payload), row["principal"], row["signature"]
    )
    if "recovery" in payload:
        from research_recovery import verify_history

        verify_history(schedule, payload)
    return payload


def approve(schedule, identity, principal, signature):
    with schedule.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM research_campaign WHERE id=?", (identity,)).fetchone()
        if not row or row["approved"] is not None or row["revoked"] is not None:
            raise ValueError("research authorization unavailable or already consumed")
        payload = json.loads(row["authorization"])
        if (
            payload["authorization_sha256"] != identity
            or digest(encode({k: v for k, v in payload.items() if k != "authorization_sha256"})) != identity
            or payload["policy_sha256"] != policy_hash()
            or payload["budget"] != authorized_budget(payload)
            or payload["budget"]["full_reserve_microusd"] > payload["manifest"]["limits"]["reserve_microusd"]
            or not time.time() < payload["expires_at"]
        ):
            raise ValueError("research policy changed or authorization expired")
        operator_approval.verify(operator_approval.message(schedule.root, row["nonce"], payload), principal, signature)
        approved = time.time()
        if not approved < payload["expires_at"]:
            raise ValueError("research authorization expired during verification")
        if "recovery" in payload:
            from research_recovery import activate

            activate(schedule, db, payload)
            if not time.time() < payload["expires_at"]:
                raise ValueError("recovery expired during atomic activation")
        db.execute(
            "UPDATE research_campaign SET principal=?, signature=?, approved=? WHERE id=?",
            (principal, signature, approved, identity),
        )


def active(schedule, job):
    row = campaign(schedule, job)
    task = schedule.job(job)
    return bool(
        row["approved"] is not None
        and not row["paused"]
        and row["revoked"] is None
        and time.time() < json.loads(row["authorization"])["expires_at"]
        and not task["cancelled"]
        and task["state"] == "running"
    )


def checkpoint(schedule, job, name, action):
    with schedule.connect() as db:
        row = db.execute("SELECT * FROM research_checkpoint WHERE job=? AND name=?", (job, name)).fetchone()
    if row:
        if digest(row["data"].encode()) != row["sha256"]:
            raise WorkerFailure("research checkpoint integrity failed")
        return json.loads(row["data"])
    data = action()
    raw = encode(data)
    with schedule.connect() as db:
        db.execute("INSERT INTO research_checkpoint VALUES (?, ?, ?, ?)", (job, name, raw.decode(), digest(raw)))
    return data


def reserve(schedule, job, plan, packet):
    with schedule.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT c.*, r.company FROM research_campaign c JOIN research_job r ON c.id=r.campaign WHERE r.job=?",
            (job,),
        ).fetchone()
        authorization = checked(schedule, row)
        company = next(c for c in authorization["manifest"]["companies"] if c["id"] == row["company"])
        task = db.execute("SELECT project, scenario, reserve FROM job WHERE id=?", (job,)).fetchone()
        if (
            task is None
            or task["project"] != company["id"]
            or task["scenario"] != "research"
            or task["reserve"]
            != authorization["budget"]
            .get("project_ceilings_microusd", {})
            .get(company["id"], authorization["budget"]["per_company_reserve_microusd"])
            or db.execute("SELECT budget FROM settings").fetchone()[0]
            > authorization["manifest"]["limits"]["reserve_microusd"]
        ):
            raise WorkerFailure("research task ownership or approved spending ceiling changed")
        identity = plan["research"]
        rebuilt, _ = make_plan(
            authorization["manifest"],
            company,
            plan["provider"],
            identity["mode"],
            identity["stage"],
            {k: v for k, v in packet.items() if k not in {"candidate", "task"}},
            authorization["expires_at"],
            row["id"],
        )
        if (
            rebuilt != plan
            or identity["mode"] not in MODES
            or identity["stage"] not in STAGES
            or (identity["mode"] == "equal-source" and identity["stage"] in {"discover", "expand"})
        ):
            raise WorkerFailure("research request differs from the signed workflow")
        table = "research_attempt" if "recovery" in authorization else "research_request"
        if "recovery" in authorization:
            from research_recovery import key

            if (job, identity["mode"], identity["stage"], plan["provider"]) not in {
                key(x) for x in authorization["recovery"]["calls"]
            }:
                raise WorkerFailure("request is not in the exact recovery schedule")
            selected = next(
                x
                for x in authorization["recovery"]["calls"]
                if key(x) == (job, identity["mode"], identity["stage"], plan["provider"])
            )
            if selected.get("repair_of"):
                from research_recovery import repair_input

                frozen = repair_input(schedule, authorization, selected)
                expected, expected_packet = make_plan(
                    authorization["manifest"],
                    company,
                    plan["provider"],
                    identity["mode"],
                    identity["stage"],
                    frozen["request_packet"],
                    authorization["expires_at"],
                    row["id"],
                )
                if plan != expected or packet != expected_packet:
                    raise WorkerFailure("report repair differs from the original frozen evidence")
            count = db.execute("SELECT COUNT(*) FROM research_attempt WHERE authorization=?", (row["id"],)).fetchone()[
                0
            ]
        else:
            count = db.execute(
                "SELECT COUNT(*) FROM research_request r JOIN research_job j ON j.job=r.job WHERE j.campaign=?",
                (row["id"],),
            ).fetchone()[0]
        if count >= authorization["budget"]["max_requests"]:
            raise WorkerFailure("research workflow request ceiling reached")
        schedule.start_reservation(
            db,
            job,
            plan["plan_sha256"],
            plan["provider"],
            plan["model"],
            plan["candidate"],
            plan["body_sha256"],
            amount=plan["illustrative_reserve_microusd"],
        )
        values = (
            plan["plan_sha256"],
            job,
            identity["mode"],
            identity["stage"],
            plan["provider"],
            encode(plan).decode(),
            encode(packet).decode(),
        )
        if table == "research_attempt":
            db.execute("INSERT INTO research_attempt VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)", (*values, row["id"]))
        else:
            db.execute("INSERT INTO research_request VALUES (?, ?, ?, ?, ?, ?, ?, NULL)", values)
        # Acquiring locks and verifying signatures may cross the authorization boundary.
        if not time.time() < authorization["expires_at"]:
            raise WorkerFailure("research workflow expired before dispatch")


def ask(schedule, job, authorization, company, provider, mode, stage, packet, keys, connection):
    from paid_review import request_receipt, response_value
    from api_review import decode

    try:
        plan, packet = make_plan(
            authorization["manifest"],
            company,
            provider,
            mode,
            stage,
            packet,
            authorization["expires_at"],
            authorization["authorization_sha256"],
        )
    except ValueError as exc:
        raise WorkerFailure("research request violated context or provider limits; evidence retained") from exc
    recovery = "recovery" in authorization
    if recovery:
        from research_recovery import reuse, key, repair_input

        slot = (job, mode, stage, provider)
        if slot in {key(x) for x in authorization["recovery"].get("held", [])}:
            raise ResearchHeld(f"{mode}/{provider}/{stage}: uncertain request remains held")
        call = next((x for x in authorization["recovery"]["calls"] if key(x) == slot), None)
        if call and call.get("repair_of"):
            fixed = repair_input(schedule, authorization, call)
            original = {k: v for k, v in packet.items() if k not in {"task", "candidate"}}
            if original != fixed["frozen_packet"]:
                raise WorkerFailure("report repair source packet changed")
            plan, packet = make_plan(
                authorization["manifest"],
                company,
                provider,
                mode,
                stage,
                fixed["request_packet"],
                authorization["expires_at"],
                authorization["authorization_sha256"],
            )
        reused = reuse(schedule, job, authorization, provider, mode, stage, packet)
        if reused is not None:
            return reused
    table = "research_attempt" if recovery else "research_request"
    responses = schedule.workspace(job) / "responses"
    responses.mkdir(mode=0o700, exist_ok=True)
    response_path = responses / (plan["plan_sha256"] + ".json")
    with schedule.connect() as db:
        query = f"SELECT * FROM {table} WHERE job=? AND mode=? AND stage=? AND provider=?"
        args = (job, mode, stage, provider)
        if recovery:
            query += " AND authorization=?"
            args += (authorization["authorization_sha256"],)
        prior = db.execute(query, args).fetchone()
    if prior:
        if prior["plan"] != encode(plan).decode() or prior["packet"] != encode(packet).decode():
            raise WorkerFailure("research request context changed after its durable reservation")
        receipt = json.loads(prior["receipt"]) if prior["receipt"] else {}
        if receipt.get("state") != "response_received":
            raise WorkerFailure("uncertain or failed research request cannot be repeated")
        with response_path.open("rb") as file:
            raw = file.read(MAX_RESPONSE + 1)
        if (
            receipt.get("response_artifact") != str(response_path)
            or digest(raw) != receipt["response_sha256"]
            or response_value(provider, decode(raw)) != receipt["review"]
            or validate(stage, receipt["review"], packet, provider)[0] != "approve"
        ):
            raise WorkerFailure("settled research response artifact changed")
    else:
        request = Request(
            plan["plan_sha256"],
            company["id"],
            stage,
            "research",
            "",
            (),
            frozenset(),
            "",
            schedule.workspace(job) / "unused-output",
            (),
            (),
            plan["candidate"],
            Limits(requests=1, retries=0, seconds=RESEARCH_TIMEOUT),
        )
        timer = threading.Timer(RESEARCH_TIMEOUT, os.killpg, (os.getpgrp(), signal.SIGKILL))
        timer.daemon = True
        timer.start()
        try:
            receipt = request_receipt(
                schedule,
                job,
                plan,
                keys[provider],
                request,
                lambda value, _: validate(stage, value, packet, provider),
                None,
                None,
                connection,
                authorize=lambda: reserve(schedule, job, plan, packet),
                active=lambda: active(schedule, job) and bool(checked(schedule, campaign(schedule, job))),
                response_path=response_path,
            )
        finally:
            timer.cancel()
        with schedule.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(f"UPDATE {table} SET receipt=? WHERE session=?", (encode(receipt).decode(), plan["plan_sha256"]))
            db.execute(
                "UPDATE api_review SET state=?, finished=? WHERE session=?",
                (receipt["state"], time.time(), plan["plan_sha256"]),
            )
    folder = schedule.workspace(job) / "reports"
    if recovery:
        folder /= "recovery-" + authorization["authorization_sha256"]
    folder = folder / mode / provider
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    (folder / (stage + ".receipt.json")).write_bytes(encode(receipt))
    if receipt["state"] != "response_received":
        if receipt.get("failure_class") == "research_quality":
            raise ResearchQualityFailure(f"{mode}/{provider}/{stage}: invalid research response; reserve retained")
        raise WorkerFailure("research API response failed validation; reserve retained")
    value = receipt["review"]
    (folder / (stage + ".json")).write_bytes(encode(value))
    if stage in {"report", "reconcile"}:
        (folder / (stage + ".md")).write_text(render(value, packet["sources"]))
    return value


def collect(retriever, requests, queries=(), *, fresh=False):
    items = []
    for query in queries:
        result, links = retriever.search(query["query"], query["category"])
        items.append(result)
        requests = [*requests, *({"url": link, "category": query["category"]} for link in links[:3])]
    seen = set()
    for request in requests:
        identity = (request["url"], request["category"])
        if identity in seen:
            continue
        seen.add(identity)
        try:
            items.append(retriever.fetch(request["url"], request["category"], fresh=fresh))
        except ValueError:
            # Retain explicit scope denials without silently expanding signed source permissions.
            raise WorkerFailure("model requested an unapproved public source origin")
    return items


def execute(schedule, job, keys, *, connection=http.client.HTTPSConnection, source_connection=None):
    from research_sources import PublicHTTPS

    row = campaign(schedule, job)
    authorization = checked(schedule, row)
    manifest = authorization["manifest"]
    company = next(c for c in manifest["companies"] if c["id"] == row["company"])
    limits = manifest["limits"]
    work = schedule.workspace(job)
    sources = work / "sources"

    def retriever(lane):
        item = Retriever(
            sources / lane,
            company["origins"],
            limits["retrieval_requests_per_lane"],
            connection=source_connection or PublicHTTPS,
            active=lambda: active(schedule, job),
        )
        for captured in item.state["captures"]:
            item.read(captured)
        return item

    shared_retriever = retriever("equal-source")
    shared = checkpoint(
        schedule,
        job,
        "equal-source-seeds",
        lambda: collect(
            shared_retriever,
            company["seeds"],
            [{"query": company["name"] + " " + category, "category": category} for category in CATEGORIES],
        ),
    )
    all_results, disagreements, gaps, final_sources = {}, {}, [], {}
    for mode in MODES:
        reports, evidence = {}, {}
        for provider in LIVE_MODELS:
            try:
                checked(schedule, campaign(schedule, job))
                if mode == "equal-source":
                    items = shared
                else:
                    discovered = ask(
                        schedule,
                        job,
                        authorization,
                        company,
                        provider,
                        mode,
                        "discover",
                        {
                            "company": company["name"],
                            "seed_urls": company["seeds"],
                            "allowed_origins": company["origins"],
                            "categories": list(CATEGORIES),
                        },
                        keys,
                        connection,
                    )
                    lane = retriever(mode + "-" + provider)
                    items = checkpoint(
                        schedule,
                        job,
                        mode + "-" + provider,
                        lambda: collect(lane, discovered["requests"], discovered["queries"]),
                    )
                    gaps.extend(discovered["gaps"])
                    expanded = ask(
                        schedule,
                        job,
                        authorization,
                        company,
                        provider,
                        mode,
                        "expand",
                        {
                            "company": company["name"],
                            "seed_urls": company["seeds"],
                            "allowed_origins": company["origins"],
                            "sources": packet_sources(items, characters=limits["source_characters"]),
                            "categories": list(CATEGORIES),
                            "instruction": "Inspect retrieved content and links. Retrieve source code, issues, PRs, docs and public posts still missing before writing your report.",
                        },
                        keys,
                        connection,
                    )
                    extra = checkpoint(
                        schedule,
                        job,
                        mode + "-expand-" + provider,
                        lambda: collect(lane, expanded["requests"], expanded["queries"]),
                    )
                    items = [*items, *extra]
                    gaps.extend(expanded["gaps"])
                evidence[provider] = packet_sources(items, characters=limits["source_characters"])
                reports[provider] = ask(
                    schedule,
                    job,
                    authorization,
                    company,
                    provider,
                    mode,
                    "report",
                    {"company": company["name"], "sources": evidence[provider], "categories": list(CATEGORIES)},
                    keys,
                    connection,
                )
            except (ResearchQualityFailure, ResearchHeld) as exc:
                gaps.append(str(exc))
        if set(reports) != set(LIVE_MODELS):
            gaps.append(mode + ": peer challenges and final reconciliation await every valid independent report")
            all_results[mode] = {}
            final_sources[mode] = {key: value for batch in evidence.values() for key, value in batch.items()}
            disagreements[mode] = {
                "findings": [],
                "resolutions": {},
                "blocked": "missing valid initial reports",
                "available_initial_providers": sorted(reports),
            }
            continue
        # Initial reports are complete and persisted before any peer output is exposed.
        combined = {key: value for batch in evidence.values() for key, value in batch.items()}
        challenges, findings = {}, []
        for provider in LIVE_MODELS:
            try:
                peers = {peer: report for peer, report in reports.items() if peer != provider}
                result = ask(
                    schedule,
                    job,
                    authorization,
                    company,
                    provider,
                    mode,
                    "challenge",
                    {"company": company["name"], "peer_reports": peers, "sources": combined},
                    keys,
                    connection,
                )
                challenges[provider] = result
                findings.extend(
                    {**item, "id": provider + "-" + str(n), "challenger": provider}
                    for n, item in enumerate(result["findings"])
                )
                gaps.extend(result["gaps"])
            except (ResearchQualityFailure, ResearchHeld) as exc:
                gaps.append(str(exc))
        if set(challenges) != set(LIVE_MODELS):
            gaps.append(mode + ": final reconciliation awaits every independent peer challenge")
            all_results[mode] = {}
            final_sources[mode] = combined
            disagreements[mode] = {"findings": findings, "resolutions": {}, "blocked": "missing valid peer challenges"}
            continue
        verified = dict(combined)
        verified_ids = []
        for provider, challenge in challenges.items():
            lane = retriever(mode + "-verify-" + provider)
            requests = list(challenge["verify"])
            for finding in challenge["findings"]:
                for reference in finding["evidence"]:
                    source = combined[reference["source_id"]]
                    requests.append({"url": source["url"], "category": source["category"]})
            fresh = checkpoint(schedule, job, mode + "-verify-" + provider, lambda: collect(lane, requests, fresh=True))
            verified.update(packet_sources(fresh, characters=limits["source_characters"]))
            verified_ids.extend(item["id"] for item in fresh if not item["gap"])
        final = {}
        for provider in LIVE_MODELS:
            try:
                final[provider] = ask(
                    schedule,
                    job,
                    authorization,
                    company,
                    provider,
                    mode,
                    "reconcile",
                    {
                        "company": company["name"],
                        "own_report": reports[provider],
                        "findings": findings,
                        "sources": verified,
                        "verified_source_ids": verified_ids,
                    },
                    keys,
                    connection,
                )
            except (ResearchQualityFailure, ResearchHeld) as exc:
                gaps.append(str(exc))
        gaps.extend(source["gap"] for source in verified.values() if source["gap"])
        gaps.extend(
            "Only a source excerpt was model-visible: " + source["url"]
            for source in verified.values()
            if source["excerpted"] and source["kind"] == "document"
        )
        all_results[mode] = final
        final_sources[mode] = verified
        disagreements[mode] = {
            "findings": findings,
            "resolutions": {p: report["resolutions"] for p, report in final.items()},
        }
    status = (
        "completed"
        if not gaps
        and all(
            complete(report, final_sources[mode])
            for mode, reports in all_results.items()
            for report in reports.values()
        )
        else "incomplete"
    )
    summary = {
        "company": company["name"],
        "status": status,
        "gaps": sorted(set(gaps)),
        "recommendations": {
            mode: {p: r["recommendation"] for p, r in reports.items()} for mode, reports in all_results.items()
        },
        "ranked_projects": {
            mode: {
                p: sorted(
                    r["projects"],
                    key=lambda project: (
                        -sum(
                            project[k]
                            for k in (
                                "depth_score",
                                "originality_score",
                                "relevance_score",
                                "feasibility_score",
                                "hiring_impact_score",
                            )
                        )
                    ),
                )
                for p, r in reports.items()
            }
            for mode, reports in all_results.items()
        },
    }
    # Observable evidence metrics, separate from each model's self-assigned project scores.
    comparison = {
        mode: {
            provider: {
                "coverage_met": sum(item["status"] == "met" for item in report["coverage"]),
                "coverage_total": len(CATEGORIES),
                "explicit_gaps": report["gaps"],
                "cited_source_count": len(
                    {ref["source_id"] for claim in report["claims"] for ref in claim["evidence"]}
                ),
                "project_count": len(report["projects"]),
                "uncertain_resolutions": sum(item["status"] == "uncertain" for item in report["resolutions"]),
                "peer_assessments": [
                    item for item in disagreements[mode]["findings"] if item["target_provider"] == provider
                ],
                "note": "Citation matching verifies captured text, not factual entailment. Project scores are model judgments.",
            }
            for provider, report in reports.items()
        }
        for mode, reports in all_results.items()
    }
    (work / "model-quality-comparison.json").write_bytes(encode(comparison))
    (work / "disagreements.json").write_bytes(encode(disagreements))
    (work / "company-summary.json").write_bytes(encode(summary))
    schedule.publish(
        job,
        {
            "status": status,
            "reason": "explicit coverage gaps remain" if status == "incomplete" else None,
            "report": str(work / "company-summary.json"),
        },
    )


def finish(db, schedule, job, state):
    if state in {"completed", "incomplete"}:
        return
    row = db.execute("SELECT campaign FROM research_job WHERE job=?", (job,)).fetchone()
    db.execute("UPDATE research_campaign SET paused=1 WHERE id=?", (row["campaign"],))
    for item in db.execute(
        "SELECT session, reserve_microusd FROM api_review WHERE job=? AND state='uncertain'", (job,)
    ):
        receipt = {
            "state": "uncertain",
            "reserve_microusd": item["reserve_microusd"],
            "estimated_microusd": None,
            "actual_charge_microusd": None,
        }
        db.execute(
            "UPDATE research_request SET receipt=? WHERE session=? AND receipt IS NULL",
            (encode(receipt).decode(), item["session"]),
        )
        from research_recovery import has_attempts

        if has_attempts(db):
            db.execute(
                "UPDATE research_attempt SET receipt=? WHERE session=? AND receipt IS NULL",
                (encode(receipt).decode(), item["session"]),
            )


def recovery_plan(schedule, identity):
    """Read-only recovery inventory. Unknown paid outcomes are never replacement authority."""
    from api_review import decode
    from paid_review import response_value

    with schedule.connect() as db:
        row = db.execute("SELECT * FROM research_campaign WHERE id=?", (identity,)).fetchone()
        if not row or row["approved"] is None or row["revoked"] is not None:
            raise ValueError("recovery requires a previously signed, non-revoked campaign")
        original = json.loads(row["authorization"])
        if digest(encode({k: v for k, v in original.items() if k != "authorization_sha256"})) != identity:
            raise ValueError("original research authorization identity changed")
        operator_approval.verify(
            operator_approval.message(schedule.root, row["nonce"], original), row["principal"], row["signature"]
        )
        jobs = [
            dict(x)
            for x in db.execute(
                "SELECT j.*, r.company FROM job j JOIN research_job r ON r.job=j.id WHERE r.campaign=? ORDER BY j.id",
                (identity,),
            )
        ]
        if any(job["state"] not in {"completed", "incomplete", "blocked", "interrupted", "cancelled"} for job in jobs):
            raise ValueError("stop the supervisor before preparing recovery")
        from research_recovery import all_requests, verify_history

        if original.get("recovery"):
            verify_history(schedule, original, db)
        source_jobs = {job["id"] for job in jobs}
        records = [x for x in all_requests(db) if x["job"] in source_jobs]
        ancestry = {identity}
        ancestor = original
        while ancestor.get("recovery"):
            parent_id = ancestor["recovery"]["source_authorization"]
            if parent_id in ancestry:
                raise ValueError("cyclic research recovery ancestry")
            ancestry.add(parent_id)
            ancestor = json.loads(
                db.execute("SELECT authorization FROM research_campaign WHERE id=?", (parent_id,)).fetchone()[0]
            )
        ledger = [dict(x) for x in db.execute("SELECT * FROM api_review ORDER BY session")]
    job_ids = {job["id"] for job in jobs}
    recorded_sessions = {x["session"] for x in records}
    if any(x["job"] in job_ids and x["session"] not in recorded_sessions for x in ledger):
        raise ValueError("paid research reservation has no durable request record; delivery remains unknown")
    ledger_by_session = {x["session"]: x for x in ledger}
    records.sort(key=lambda x: (ledger_by_session[x["session"]]["started"], x["session"]))
    indexed = {(x["job"], x["mode"], x["stage"], x["provider"]): x for x in records}
    manifest = original["manifest"]
    profiles = budget(manifest)["profiles"]
    new_calls, reusable, held = [], [], []
    for job in jobs:
        for mode in MODES:
            for provider in LIVE_MODELS:
                for stage in ("report", "challenge", "reconcile") if mode == "equal-source" else STAGES:
                    item = {
                        "job": job["id"],
                        "company": job["company"],
                        "mode": mode,
                        "provider": provider,
                        "model": manifest["providers"][provider]["model"],
                        "stage": stage,
                    }
                    prior = indexed.get((job["id"], mode, stage, provider))
                    if prior:
                        plan = json.loads(prior["plan"])
                        packet = json.loads(prior["packet"])
                        receipt = json.loads(prior["receipt"]) if prior["receipt"] else {}
                        paid = ledger_by_session.get(prior["session"])
                        if (
                            not paid
                            or plan["plan_sha256"] != prior["session"]
                            or digest(encode({k: v for k, v in plan.items() if k != "plan_sha256"})) != prior["session"]
                            or digest(plan["body_utf8"].encode()) != plan["body_sha256"]
                            or plan["body_sha256"] != paid["request_sha256"]
                            or receipt.get("reserve_microusd") != paid["reserve_microusd"]
                            or receipt.get("state") != paid["state"]
                        ):
                            raise ValueError("historical research request or spending identity changed")
                        wire = decode(plan["body_utf8"].encode(), maximum=RESEARCH_MAX_REQUEST)
                        wire_packet = decode(
                            (wire["input"] if provider == "openai" else wire["messages"][-1]["content"]).encode(),
                            maximum=RESEARCH_MAX_REQUEST,
                        )
                        if (
                            paid["job"] != job["id"]
                            or paid["provider"] != provider
                            or paid["model"] != plan["model"]
                            or plan["model"] != item["model"]
                            or plan["provider"] != provider
                            or plan["project"] != job["company"]
                            or plan["candidate"] != paid["candidate"]
                            or packet != wire_packet
                            or packet["candidate"]
                            != digest(encode({k: v for k, v in packet.items() if k not in {"candidate", "task"}}))
                            or plan["research"]["campaign"] not in ancestry
                            or plan["research"]["mode"] != mode
                            or plan["research"]["stage"] != stage
                        ):
                            raise ValueError("historical research task, packet or provider binding changed")
                        item["prior_session"] = prior["session"]
                        state = receipt.get("state")
                        if state in {"response_received", "rejected"}:
                            expected = schedule.workspace(job["id"]) / "responses" / (prior["session"] + ".json")
                            if (
                                receipt.get("response_artifact") != str(expected)
                                or expected.resolve() != expected
                                or not expected.is_file()
                            ):
                                raise ValueError("historical response artifact is unavailable or unsafe")
                            raw = expected.read_bytes()
                            if len(raw) > MAX_RESPONSE or digest(raw) != receipt.get("response_sha256"):
                                raise ValueError("historical response artifact changed")
                            reply = decode(raw)
                            if state == "response_received":
                                if (
                                    response_value(provider, reply) != receipt["review"]
                                    or validate(stage, receipt["review"], packet, provider)[0] != "approve"
                                ):
                                    raise ValueError("completed research report failed revalidation")
                                reusable.append(
                                    {
                                        **item,
                                        "response_sha256": receipt["response_sha256"],
                                        "packet_sha256": digest(prior["packet"].encode()),
                                    }
                                )
                                continue
                            if (
                                stage in {"report", "reconcile"}
                                and receipt.get("http_status") == 200
                                and receipt.get("validation_error")
                                and receipt.get("usage")
                                and receipt.get("stop_reason") in {"end_turn", "completed", "stop"}
                            ):
                                rejected = response_value(provider, reply)
                                if validate(stage, rejected, packet, provider)[0] == "invalid":
                                    item.update(
                                        reason="invalid research report; one independently signed frozen-source repair",
                                        repair_of=prior["session"],
                                        frozen_packet_sha256=digest(prior["packet"].encode()),
                                    )
                                    item["reserve_microusd"] = profiles[provider]["illustrative_reserve_microusd"]
                                    new_calls.append(item)
                                    continue
                            if (
                                receipt.get("http_status") != 200
                                or receipt.get("stop_reason") != "max_tokens"
                                or reply.get("stop_reason") != "max_tokens"
                            ):
                                held.append({**item, "reason": "failed response needs separate investigation"})
                                continue
                            item["reason"] = "known truncated output; new signed replacement required"
                        else:
                            held.append(
                                {
                                    **item,
                                    "reason": "uncertain delivery/billing; no response artifact; never automatically replay",
                                }
                            )
                            continue
                    else:
                        item["reason"] = "never dispatched"
                    item["reserve_microusd"] = profiles[provider]["illustrative_reserve_microusd"]
                    new_calls.append(item)
    retained = sum(x["reserve_microusd"] for x in ledger)
    proposed = sum(x["reserve_microusd"] for x in new_calls)
    held_reserve = sum(profiles[x["provider"]]["illustrative_reserve_microusd"] for x in held)
    result = {
        "kind": "research-recovery-preflight-v1",
        "dispatch": "blocked",
        "source_authorization": identity,
        "schedule": str(schedule.root),
        "historical_records_sha256": digest(encode({"requests": records, "ledger": ledger, "jobs": jobs})),
        "policy_sha256": policy_hash(),
        "manifest": manifest,
        "completed_reuse": reusable,
        "new_calls": new_calls,
        "held_calls": held,
        "new_call_count": len(new_calls),
        "retained_reserve_microusd": retained,
        "new_reserve_microusd": proposed,
        "combined_reserve_microusd": retained + proposed,
        "conditional_full_completion_calls": len(new_calls) + len(held),
        "conditional_full_completion_reserve_microusd": retained + proposed + held_reserve,
        "ceiling_microusd": manifest["limits"]["reserve_microusd"],
        "automatic_retries": 0,
        "requires_fresh_signed_authorization": True,
        "ready_to_sign": False,
        "blockers": (
            ["resolve held delivery/billing outcomes with provider evidence before any replay"] if held else []
        )
        + ["changed policy requires a fresh recovery authorization; ordinary resume cannot change signed requests"],
    }
    if retained + proposed > result["ceiling_microusd"]:
        raise ValueError("recovery reservation exceeds the existing total research ceiling")
    result["plan_sha256"] = digest(encode(result))
    return result


def resume(schedule, identity):
    with schedule.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM research_campaign WHERE id=?", (identity,)).fetchone()
        if not row or row["revoked"] is not None:
            raise ValueError("research workflow is unavailable or permanently revoked")
        table = "research_attempt" if "recovery" in json.loads(row["authorization"]) else "research_request"
        unresolved = db.execute(
            f"SELECT 1 FROM {table} r JOIN research_job j ON j.job=r.job "
            "WHERE j.campaign=? AND (r.receipt IS NULL OR json_extract(r.receipt, '$.state') "
            "!= 'response_received')",
            (identity,),
        ).fetchone()
        if unresolved:
            raise ValueError("uncertain or rejected research spending cannot be replayed")
        checked(schedule, {**dict(row), "paused": 0})
        db.execute("UPDATE research_campaign SET paused=0 WHERE id=?", (identity,))
        db.execute(
            "UPDATE job SET state='queued', checkpoint=NULL, reason=NULL WHERE cancelled=0 "
            "AND state IN ('interrupted', 'blocked') AND id IN "
            "(SELECT job FROM research_job WHERE campaign=?)",
            (identity,),
        )


def revoke(schedule, identity):
    with schedule.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if (
            db.execute(
                "UPDATE research_campaign SET revoked=? WHERE id=? AND revoked IS NULL", (time.time(), identity)
            ).rowcount
            != 1
        ):
            raise ValueError("no revocable research authorization")
        for row in db.execute("SELECT job FROM research_job WHERE campaign=?", (identity,)):
            schedule.cancel_rows(db, "id", row["job"])


def export(schedule):
    state = schedule.status()
    jobs = [job for job in state["job"] if job["scenario"] == "research"]
    if not jobs:
        return
    result = {
        "status": "completed" if all(job["state"] == "completed" for job in jobs) else "incomplete",
        "jobs": jobs,
        "campaigns": state["research_campaigns"],
        "reserved_microusd": sum(
            row["reserve_microusd"] for row in state["api_review"] if row["job"] in {job["id"] for job in jobs}
        ),
        "actual_charge_microusd": None,
    }
    accounting = {"by_provider": {}, "by_company": {}}
    project_by_job = {job["id"]: job["project"] for job in jobs}
    receipts = {row["session"]: row.get("receipt") or {} for row in state["research_requests"]}
    for paid in state["api_review"]:
        if paid["job"] not in project_by_job:
            continue
        receipt = receipts.get(paid["session"], {})
        for group, name in (("by_provider", paid["provider"]), ("by_company", project_by_job[paid["job"]])):
            item = accounting[group].setdefault(
                name,
                {
                    "request_records": 0,
                    "retained_reserve_microusd": 0,
                    "known_estimated_microusd": 0,
                    "uncertain_outcomes": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "reasoning_tokens": 0,
                    "actual_charge_microusd": None,
                },
            )
            item["request_records"] += 1
            item["retained_reserve_microusd"] += paid["reserve_microusd"]
            item["known_estimated_microusd"] += receipt.get("estimated_microusd") or 0
            item["uncertain_outcomes"] += paid["state"] in {"uncertain", "running"}
            for field in ("input_tokens", "output_tokens", "reasoning_tokens"):
                item[field] += (receipt.get("usage") or {}).get(field, 0)
    result["accounting"] = accounting
    result["remaining_ledger_ceiling_microusd"] = state["settings"][0]["budget"] - result["reserved_microusd"]
    result["receipts"] = state["research_requests"]
    (schedule.root / "research-results.json").write_bytes(encode(result))
    lines = [
        "# Arcturus research campaign",
        "",
        result["status"].upper(),
        "",
        f"Retained reservation {result['reserved_microusd']} microdollars. Actual billing remains unreconciled.",
        "",
    ]
    for job in jobs:
        work = schedule.workspace(job["id"])
        lines += ["## " + job["project"], "", "Task state " + job["state"] + ".", ""]
        for filename in ("company-summary.json", "disagreements.json", "model-quality-comparison.json"):
            if (work / filename).exists():
                lines += ["- [" + filename + "](" + str(work / filename) + ")"]
        for mode in MODES:
            for provider in LIVE_MODELS:
                auth = json.loads(campaign(schedule, job["id"])["authorization"])
                folder = work / "reports"
                if "recovery" in auth:
                    folder /= "recovery-" + auth["authorization_sha256"]
                for stage in ("report", "reconcile"):
                    report = folder / mode / provider / (stage + ".md")
                    if stage == "report" and not report.exists():
                        report = work / "reports" / mode / provider / "report.md"
                    if report.exists():
                        lines += ["- [" + mode + " " + provider + " " + stage + "](" + str(report) + ")"]
        lines += [""]
    (schedule.root / "research-results.md").write_text("\n".join(lines) + "\n")


def main(connection=http.client.HTTPSConnection, source_connection=None):
    from concurrent_runs import Scheduler
    from mock_engineering import supervise

    root, job, pipe, lease = sys.argv[1:]
    supervise(int(pipe), int(lease))
    schedule = Scheduler(root)
    job = int(job)
    authorization = json.loads(campaign(schedule, job)["authorization"])
    seconds = max(1, authorization["expires_at"] - time.time())
    timer = threading.Timer(seconds, os.killpg, (os.getpgrp(), signal.SIGKILL))
    timer.daemon = True
    timer.start()
    try:
        keys = json.loads(os.environ.pop("ARCTURUS_RESEARCH_KEYS"))
        execute(schedule, job, keys, connection=connection, source_connection=source_connection)
    except Exception as exc:
        # Provider/network exception prose can contain credentials. Receipts keep safe diagnostics.
        reason = (
            str(exc) if isinstance(exc, WorkerFailure) else "research failed; inspect durable receipts and source gaps"
        )
        schedule.publish(job, {"status": "blocked", "reason": reason})
    finally:
        timer.cancel()


if __name__ == "__main__":
    main()
