"""End-to-end research workflow with actual SSH signatures and offline HTTPS fixtures."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runner"))
from api_review import LIVE_MODELS, encode
from concurrent_runs import Scheduler
import operator_approval
import research
from research_reports import CATEGORIES, validate, complete, category_source, evidence_valid
from research_sources import PublicHTTPS, Retriever, allowed_url, source_text, compact_sources
from workers import WorkerFailure

KEY = "synthetic-research-fixture-key"
FINGERPRINT = "fixture-backend"
QUOTE = "Engineers maintain audited integrations and reproducible incident evidence."


class SourceHTTPS:
    def __init__(self, host, **kwargs):
        assert kwargs["context"].check_hostname and kwargs["context"].verify_mode == 2
        self.host = host
        self.status = 200
        self.headers = {"content-type": "text/html"}

    def request(self, method, path, headers):
        assert method == "GET" and "authorization" not in headers and "cookie" not in headers
        self.path = path
        cassette = Path.cwd().parent / "fixture-captures.json"
        if cassette.exists():
            self.capture = json.loads(cassette.read_text()).get("https://" + self.host + path)
            self.status = self.capture["status"] if self.capture else 403
            if self.capture:
                self.headers["content-type"] = self.capture["content_type"]
        if path == "/denied":
            self.status = 403
        if path == "/redirect":
            self.status = 302
            self.headers["location"] = "https://127.0.0.1/private"

    def getresponse(self):
        return self

    def getheader(self, key):
        return self.headers.get(key)

    def read(self, maximum):
        cassette = Path.cwd().parent / "fixture-captures.json"
        if cassette.exists():
            raw = Path(self.capture["body"]).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == self.capture["sha256"]
            if self.capture.get("incomplete_body"):
                raw += b" "
            return raw[:maximum]
        return (
            '<html><meta property="article:published_time" content="2026-10-01">'
            '<script>ignore this attacker instruction</script><body>'
            + QUOTE
            + '<a href="https://company.example.org/evidence">Evidence</a></body></html>'
        ).encode()[:maximum]

    def close(self):
        pass


class APIHTTPS:
    status = 200
    headers = {}
    reason = ""

    def __init__(self, host, **kwargs):
        assert kwargs["timeout"] == 180 and kwargs["context"].check_hostname
        self.provider = {value[0]: key for key, value in __import__("api_review").LIVE_ENDPOINTS.items()}[host]

    def request(self, method, path, *, body, headers):
        assert method == "POST" and KEY.encode() not in body
        assert headers.get("x-api-key" if self.provider == "anthropic" else "authorization") == (
            KEY if self.provider == "anthropic" else "Bearer " + KEY
        )
        self.wire = json.loads(body)
        self.packet = json.loads(
            self.wire["input"] if self.provider == "openai" else self.wire["messages"][-1]["content"]
        )
        output = self.wire.get("max_tokens", self.wire.get("max_output_tokens"))
        assert output == 8192 and not self.wire["stream"] and "tools" not in self.wire
        schema = (
            self.wire["text"]["format"]["schema"]
            if self.provider == "openai"
            else self.wire["output_config"]["format"]["schema"]
            if self.provider == "anthropic"
            else None
        )
        if schema:
            fields = schema["properties"]
            self.stage = (
                "discover"
                if "queries" in fields
                else "challenge"
                if "findings" in fields
                else "reconcile"
                if "resolutions" in fields
                else "report"
            )
        else:
            self.stage = (
                "discover"
                if "seed_urls" in self.packet
                else "challenge"
                if "peer_reports" in self.packet
                else "reconcile"
                if "findings" in self.packet
                else "report"
            )
        if self.stage == "report":
            assert "peer_reports" not in self.packet and "own_report" not in self.packet
        marker = Path.cwd() / ("sent-" + hashlib.sha256(body).hexdigest())
        if marker.exists():
            permitted = Path.cwd().parent / "fixture-authorized-replacement"
            if not permitted.exists() or marker.name not in permitted.read_text().splitlines():
                self.duplicate()
            marker = marker.with_name(marker.name + "-replacement")
            if marker.exists():
                self.duplicate()
        marker.write_bytes(body)
        control = Path.cwd().parent / "fixture-mode"
        self.mode = control.read_text() if control.exists() else "ok"
        if self.mode == "crash":
            os._exit(19)
        if self.mode in {"hang", "deadline"}:
            time.sleep(60)

    def duplicate(self):
        raise AssertionError("a paid request was dispatched twice")

    def getresponse(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def close(self):
        pass

    def evidence(self, category=None, *, fresh=False):
        sources = self.packet.get("sources", {})
        ids = self.packet["verified_source_ids"] if fresh else list(sources)
        selected = next(
            key
            for key in ids
            if sources[key]["kind"] == "document"
            and not sources[key]["gap"]
            and source_text(sources, key).strip()
            and (category is None or category_source(sources[key], category))
        )
        quote = source_text(sources, selected)[:80] if (Path.cwd().parent / "fixture-captures.json").exists() else QUOTE
        return [{"source_id": selected, "quote": quote}]

    def report(self):
        projects = []
        for number in range(3):
            project = {
                key: "Evidence-grounded fixture analysis"
                for key in (
                    "problem",
                    "contribution",
                    "technical_depth",
                    "originality",
                    "company_relevance",
                    "feasibility",
                    "competing_implementations",
                    "hiring_impact",
                )
            }
            project.update(
                title=f"Contribution {number}",
                scope="flagship",
                evidence=self.evidence(),
                depth_score=4,
                originality_score=3,
                relevance_score=5,
                feasibility_score=4,
                hiring_impact_score=4,
            )
            projects.append(project)
        report = {
            "summary": "Captured source analysis.",
            "coverage": (
                []
                if (Path.cwd().parent / "fixture-captures.json").exists()
                else [
                    {
                        "category": category,
                        "status": "met",
                        "explanation": "Inspected fixture evidence.",
                        "evidence": self.evidence(category),
                    }
                    for category in CATEGORIES
                ]
            ),
            "claims": [
                {
                    "id": "claim-1",
                    "category": "company",
                    "kind": "fact",
                    "statement": QUOTE,
                    "evidence": self.evidence(),
                }
            ],
            "projects": projects,
            "recommendation": {
                "project_title": "Contribution 0",
                "scope": "flagship",
                "reasoning": "Substantial contribution justified by fixture evidence.",
                "evidence": self.evidence(),
            },
            "gaps": [],
        }
        if (Path.cwd().parent / "fixture-captures.json").exists():
            report["summary"] = "MOCK response for captured-source replay. No real model research was performed."
            report["coverage"] = [
                {
                    "category": category,
                    "status": "gap",
                    "explanation": "A mocked provider cannot certify substantive research coverage.",
                    "evidence": [],
                }
                for category in CATEGORIES
            ]
            report["gaps"] = ["Offline captured-source replay; genuine research conclusions remain unverified."]
            report["claims"][0].update(kind="inference", statement="MOCK citation-validation exercise only.")
        return report

    def read(self, maximum):
        if self.stage == "discover":
            known = {source["url"] for source in self.packet.get("sources", {}).values()}
            pending = [seed for seed in self.packet["seed_urls"] if seed["url"] not in known]
            value = {"queries": [], "requests": pending[:12], "gaps": []}
        elif self.stage == "challenge":
            value = {
                "challenged_providers": list(self.packet["peer_reports"]),
                "findings": [
                    {
                        "target_provider": p,
                        "target_kind": kind,
                        "target_id": identity,
                        "assessment": "supported",
                        "objection": "Recheck against primary evidence.",
                        "evidence": self.evidence(),
                    }
                    for p, report in self.packet["peer_reports"].items()
                    for kind, identity in [
                        ("claim", report["claims"][0]["id"]),
                        *[("project", project["title"]) for project in report["projects"]],
                        ("recommendation", "recommendation"),
                    ]
                ],
                "verify": [],
                "gaps": [],
            }
        else:
            value = self.report()
            if self.stage == "reconcile":
                value["resolutions"] = [
                    {
                        "finding_id": item["id"],
                        "status": "verified",
                        "explanation": "Rechecked a fresh primary-source capture.",
                        "evidence": self.evidence(fresh=True),
                    }
                    for item in self.packet["findings"]
                ]
        targeted_quality = (
            self.mode == "quality_first_equal"
            and self.provider == "anthropic"
            and self.packet.get("company") == "Fixture company 0"
            and any(x["kind"] == "search-results" for x in self.packet.get("sources", {}).values())
        )
        if (self.mode == "bad_citation" or targeted_quality) and self.stage == "report":
            value["claims"][0]["evidence"][0]["quote"] = "Invented quotation"
        if self.mode == "credential_echo" and self.stage == "report":
            value["summary"] = KEY
        if self.mode == "gap" and self.stage in {"report", "reconcile"}:
            value["coverage"][0].update(status="gap", evidence=[])
            value["gaps"] = ["The company architecture is not fully documented."]
        text = encode(value).decode()
        usage = {"input_tokens": 100, "output_tokens": 100}
        if self.provider == "anthropic":
            if self.mode == "truncated" and self.stage == "report":
                return encode(
                    {
                        "model": self.wire["model"],
                        "stop_reason": "max_tokens",
                        "content": [
                            {"type": "thinking", "thinking": "", "signature": "fixture"},
                            {"type": "text", "text": text[:80]},
                        ],
                        "usage": {
                            "input_tokens": 62559,
                            "output_tokens": 8192,
                            "output_tokens_details": {"thinking_tokens": 6148},
                        },
                    }
                )
            return encode(
                {
                    "model": self.wire["model"],
                    "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": text}],
                    "usage": usage,
                }
            )
        if self.provider == "openai":
            return encode(
                {
                    "model": self.wire["model"],
                    "status": "completed",
                    "service_tier": "default",
                    "output": [
                        {
                            "type": "message",
                            "role": "assistant",
                            "status": "completed",
                            "content": [{"type": "output_text", "text": text}],
                        }
                    ],
                    "usage": {
                        **usage,
                        "total_tokens": 200,
                        "input_tokens_details": {"cached_tokens": 0},
                        "output_tokens_details": {"reasoning_tokens": 0},
                    },
                }
            )
        return encode(
            {
                "model": self.wire["model"],
                "object": "chat.completion",
                "system_fingerprint": (
                    (Path.cwd().parent / "fixture-fingerprint").read_text().strip()
                    if (Path.cwd().parent / "fixture-fingerprint").exists()
                    else FINGERPRINT
                ),
                "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": text}}],
                "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 100,
                    "total_tokens": 200,
                    "prompt_cache_hit_tokens": 0,
                    "prompt_cache_miss_tokens": 100,
                },
            }
        )


def fixture_manifest(companies=1):
    return {
        "version": 1,
        "companies": [
            {
                "id": f"company-{n}",
                "name": f"Fixture company {n}",
                "origins": {
                    "company.example.org": ["/"],
                    "www.google.com": ["/search"],
                    "raw.githubusercontent.com": ["/"],
                    "api.github.com": ["/repos/"],
                },
                "seeds": [
                    {
                        "url": {
                            "source": "https://raw.githubusercontent.com/fixture/company/main/README.md",
                            "issues": "https://api.github.com/repos/fixture/company/issues?state=open",
                            "prs": "https://api.github.com/repos/fixture/company/pulls?state=open",
                            "posts": "https://company.example.org/blog/engineering",
                        }.get(category, "https://company.example.org/evidence"),
                        "category": category,
                    }
                    for category in CATEGORIES
                ],
            }
            for n in range(companies)
        ],
        "providers": {
            p: {"model": model, **({"fingerprint": FINGERPRINT} if p == "deepseek" else {})}
            for p, model in LIVE_MODELS.items()
        },
        "limits": {
            "reserve_microusd": 10_000_000,
            "seconds": 600,
            "retrieval_requests_per_lane": 100,
            "source_characters": 3000,
        },
    }


class ResearchWorkflow(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.signer = self.root / "fixture-signer"
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.signer)], check=True)
        self.signers = self.root / "fixture-allowed-signers"
        self.signers.write_text(
            'operator namespaces="arcturus-model-approval-v1" ' + self.signer.with_suffix(".pub").read_text()
        )
        trust = patch.object(operator_approval, "trusted_signers", return_value=self.signers)
        trust.start()
        self.addCleanup(trust.stop)
        private = self.root / "credentials"
        private.mkdir(mode=0o700)
        self.key = private / "fixture-key"
        self.key.write_text(KEY)
        self.key.chmod(0o600)
        self.queue = Scheduler(self.root / "schedule")

    def enroll(self, companies=1):
        self.payload = research.enroll(self.queue, fixture_manifest(companies), int(time.time()) + 590)
        self.authorization = json.loads(self.payload)["plan"]["authorization_sha256"]
        # Only the test worker uses this public fixture trust store.
        (self.queue.root / "fixture-allowed-signers").write_text(self.signers.read_text())
        self.signature = subprocess.run(
            ["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(self.signer), "-n", operator_approval.NAMESPACE],
            input=self.payload,
            capture_output=True,
            check=True,
        ).stdout

    def approve(self):
        research.approve(self.queue, self.authorization, "operator", self.signature)

    def run_fixture(self, stop=lambda: False):
        spawn = subprocess.Popen

        def inject(argv, **kwargs):
            if len(argv) > 2 and Path(argv[2]).name == "research.py":
                argv = [*argv[:2], str(Path(__file__).resolve()), *argv[3:]]
            return spawn(argv, **kwargs)

        with patch("concurrent_runs.subprocess.Popen", side_effect=inject):
            self.queue.run(None, stop, dict.fromkeys(LIVE_MODELS, str(self.key)))

    def test_signed_three_company_workflow_is_complete_and_independent(self):
        self.enroll(3)
        self.assertIsNone(self.queue.claim(tuple(LIVE_MODELS)))
        self.approve()
        self.run_fixture()
        state = self.queue.status()
        self.assertEqual([j["state"] for j in state["job"]], ["completed"] * 3)
        self.assertEqual(len(state["api_review"]), 72)
        self.assertEqual(sum(row["reserve_microusd"] for row in state["api_review"]), 9_053_808)
        self.assertTrue(all(r["receipt"]["state"] == "response_received" for r in state["research_requests"]))
        for row in state["research_requests"]:
            receipt = row["receipt"]
            raw = Path(receipt["response_artifact"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), receipt["response_sha256"])
            self.assertNotIn(KEY.encode(), raw)
        for job in state["job"]:
            work = self.queue.workspace(job["id"])
            self.assertTrue((work / "disagreements.json").exists())
            summary = json.loads((work / "company-summary.json").read_bytes())
            self.assertEqual(set(summary["recommendations"]), set(research.MODES))
            with self.queue.connect() as db:
                rows = list(
                    db.execute(
                        "SELECT provider, packet FROM research_request "
                        "WHERE job=? AND mode='equal-source' AND stage='report'",
                        (job["id"],),
                    )
                )
            self.assertEqual(len({json.loads(r["packet"])["candidate"] for r in rows}), 1)
            sources = work / "sources"
            self.assertTrue((sources / "independent-anthropic/index.json").is_file())
            self.assertTrue((sources / "independent-openai/index.json").is_file())
            self.assertTrue((sources / "independent-deepseek/index.json").is_file())
            with self.queue.connect() as db:
                for row in db.execute(
                    "SELECT provider, stage, packet FROM research_request WHERE job=? "
                    "AND mode='independent' AND stage IN ('discover', 'report')",
                    (job["id"],),
                ):
                    packet = json.loads(row["packet"])
                    if row["stage"] == "discover":
                        self.assertNotIn("sources", packet)
                        self.assertNotIn("peer_reports", packet)
                    else:
                        index = json.loads((sources / ("independent-" + row["provider"]) / "index.json").read_bytes())
                        own = {item["id"] for item in index["captures"]}
                        self.assertTrue(set(packet["sources"]) <= own)
                        self.assertNotIn("peer_reports", packet)
        before = self.queue.status()
        self.run_fixture()
        self.assertEqual(before, self.queue.status())

    def test_forgery_expiry_replay_and_policy_drift_fail_before_dispatch(self):
        self.enroll()
        with self.assertRaises(ValueError):
            research.approve(self.queue, self.authorization, "operator", b"APPROVE")
        with patch("research.time.time", return_value=time.time() + 1000), self.assertRaises(ValueError):
            self.approve()
        self.approve()
        with self.assertRaises(ValueError):
            self.approve()
        with patch("research.policy_hash", return_value="changed"), self.assertRaises(WorkerFailure):
            research.checked(self.queue, research.campaign(self.queue, 1))
        self.assertEqual(self.queue.status()["api_review"], [])

    def test_failed_citation_is_local_and_retains_reserve(self):
        self.enroll(3)
        self.approve()
        (self.queue.root / "fixture-mode").write_text("bad_citation")
        self.run_fixture()
        state = self.queue.status()
        self.assertFalse(state["research_campaigns"][0]["paused"])
        self.assertTrue(all(j["state"] == "incomplete" for j in state["job"]))
        self.assertGreater(len(state["api_review"]), 0)
        with self.assertRaisesRegex(ValueError, "cannot be replayed"):
            research.resume(self.queue, self.authorization)
        count = len(state["api_review"])
        self.run_fixture()
        self.assertEqual(len(self.queue.status()["api_review"]), count)

    def test_explicit_coverage_gap_finishes_incomplete(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("gap")
        self.run_fixture()
        self.assertEqual(self.queue.job(1)["state"], "incomplete")
        summary = json.loads((self.queue.workspace(1) / "company-summary.json").read_bytes())
        self.assertEqual(summary["status"], "incomplete")

    def test_crash_after_post_retains_uncertain_spending_and_blocks_replay(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("crash")
        self.run_fixture()
        state = self.queue.status()
        self.assertEqual(len(state["api_review"]), 1)
        self.assertEqual(state["api_review"][0]["state"], "uncertain")
        self.assertIsNone(state["research_requests"][0]["receipt"]["actual_charge_microusd"])
        with self.assertRaisesRegex(ValueError, "cannot be replayed"):
            research.resume(self.queue, self.authorization)

    def test_recovery_after_settled_checkpoint_reuses_response_without_post(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("settled-crash")
        self.run_fixture()
        self.assertEqual(len(self.queue.status()["api_review"]), 1)
        research.resume(self.queue, self.authorization)
        (self.queue.root / "fixture-mode").unlink()
        self.run_fixture()
        self.assertEqual(self.queue.job(1)["state"], "completed")
        self.assertEqual(len(self.queue.status()["api_review"]), 24)
        self.assertEqual(len(list(self.queue.workspace(1).glob("sent-*"))), 24)

    def test_revocation_cancels_inflight_and_releases_process_leases(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("hang")
        revoked = False

        def stop():
            nonlocal revoked
            if list(self.queue.workspace(1).glob("sent-*")) and not revoked:
                research.revoke(self.queue, self.authorization)
                revoked = True
            return False

        self.run_fixture(stop)
        self.assertEqual(self.queue.job(1)["state"], "cancelled")
        self.assertEqual(self.queue.status()["api_review"][0]["state"], "uncertain")
        with (self.queue.workspace(1) / "lease").open("a") as file:
            fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_budget_is_checked_without_lowering_scope(self):
        manifest = fixture_manifest(3)
        self.assertEqual(research.budget(manifest)["full_reserve_microusd"], 9_053_808)
        manifest["limits"]["reserve_microusd"] = 9_053_807
        with self.assertRaisesRegex(ValueError, "exceeds"):
            research.enroll(self.queue, manifest, int(time.time()) + 590)
        self.assertFalse(self.queue.database.exists())

    def test_unsigned_or_generic_reservations_cannot_dispatch_research(self):
        self.enroll()
        self.assertIsNone(self.queue.claim(tuple(LIVE_MODELS)))
        with self.assertRaises(WorkerFailure):
            with self.queue.reserve(1, "forged", "anthropic", LIVE_MODELS["anthropic"], "fake", "fake"):
                self.fail("research accepted a generic paid reservation")
        self.assertEqual(self.queue.status()["api_review"], [])

    def test_cross_schedule_signature_and_expiry_at_consumption_fail_closed(self):
        self.enroll()
        other = Scheduler(self.root / "other")
        manifest = fixture_manifest()
        expires = json.loads(self.payload)["plan"]["expires_at"]
        research.enroll(other, manifest, expires)
        with self.assertRaises(ValueError):
            research.approve(other, self.authorization, "operator", self.signature)
        self.approve()
        self.queue.claim(tuple(LIVE_MODELS))
        with patch("research.time.time", return_value=expires), self.assertRaises(WorkerFailure):
            research.checked(self.queue, research.campaign(self.queue, 1))
        self.assertEqual(self.queue.status()["api_review"], [])

    def test_reservation_stops_before_post_when_global_budget_is_exhausted(self):
        self.enroll()
        self.approve()
        with self.queue.connect() as db:
            db.execute("UPDATE settings SET budget=1")
        self.run_fixture()
        self.assertEqual(self.queue.job(1)["state"], "blocked")
        self.assertEqual(self.queue.status()["api_review"], [])
        self.assertEqual(list(self.queue.workspace(1).glob("sent-*")), [])

    def test_project_ownership_and_unapproved_budget_increases_block_dispatch(self):
        self.enroll(3)
        self.approve()
        job = self.queue.claim(tuple(LIVE_MODELS))["id"]
        authorization = research.checked(self.queue, research.campaign(self.queue, job))
        company = authorization["manifest"]["companies"][0]
        plan, packet = research.make_plan(
            authorization["manifest"],
            company,
            "anthropic",
            "equal-source",
            "report",
            {"company": company["name"], "sources": {}},
            authorization["expires_at"],
            self.authorization,
        )
        with self.queue.connect() as db:
            db.execute("UPDATE job SET project='company-1' WHERE id=1")
        with self.assertRaisesRegex(WorkerFailure, "ownership"):
            research.reserve(self.queue, job, plan, packet)
        with self.queue.connect() as db:
            db.execute("UPDATE job SET project='company-0' WHERE id=1")
            db.execute("UPDATE settings SET budget=11000000")
        with self.assertRaisesRegex(WorkerFailure, "ceiling"):
            research.reserve(self.queue, job, plan, packet)
        self.assertEqual(self.queue.status()["api_review"], [])

    def test_source_tampering_after_interruption_is_detected_before_another_post(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("settled-crash")
        self.run_fixture()
        research.resume(self.queue, self.authorization)
        (self.queue.root / "fixture-mode").unlink()
        body = next((self.queue.workspace(1) / "sources/equal-source").glob("*.body"))
        body.write_bytes(b"modified capture")
        self.run_fixture()
        self.assertEqual(self.queue.job(1)["state"], "blocked")
        self.assertEqual(len(self.queue.status()["api_review"]), 1)

    def test_raw_provider_credential_echo_is_never_saved(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("credential_echo")
        self.run_fixture()
        self.assertEqual(self.queue.job(1)["state"], "blocked")
        self.assertEqual(list((self.queue.workspace(1) / "responses").glob("*.json")), [])
        self.assertNotIn(KEY, str(self.queue.status()))

    def test_raw_response_tampering_blocks_recovery_without_another_post(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("settled-crash")
        self.run_fixture()
        research.resume(self.queue, self.authorization)
        (self.queue.root / "fixture-mode").unlink()
        response = next((self.queue.workspace(1) / "responses").glob("*.json"))
        response.write_bytes(b"{}")
        self.run_fixture()
        self.assertEqual(self.queue.job(1)["state"], "blocked")
        self.assertEqual(len(self.queue.status()["api_review"]), 1)

    def test_recovery_inventory_reuses_verified_report_without_modifying_any_evidence(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("settled-crash")
        self.run_fixture()
        before = self.queue.status()
        files = {p: p.read_bytes() for p in self.queue.workspace(1).rglob("*") if p.is_file()}
        plan = research.recovery_plan(self.queue, self.authorization)
        self.assertEqual(len(plan["completed_reuse"]), 1)
        self.assertEqual(plan["new_call_count"], 23)
        self.assertEqual(plan["held_calls"], [])
        self.assertEqual(plan["combined_reserve_microusd"], 3_017_936)
        self.assertEqual(plan["dispatch"], "blocked")
        self.assertFalse(plan["ready_to_sign"])
        self.assertEqual(before, self.queue.status())
        self.assertEqual(files, {p: p.read_bytes() for p in files})
        response = next((self.queue.workspace(1) / "responses").glob("*.json"))
        response.write_bytes(b"{}")
        with self.assertRaisesRegex(ValueError, "artifact changed"):
            research.recovery_plan(self.queue, self.authorization)

    def test_recovery_inventory_never_treats_an_orphan_paid_reservation_as_unsent(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("crash")
        self.run_fixture()
        with self.queue.connect() as db:
            db.execute("DELETE FROM research_request")
        with self.assertRaisesRegex(ValueError, "delivery remains unknown"):
            research.recovery_plan(self.queue, self.authorization)
        self.assertEqual(len(self.queue.status()["api_review"]), 1)

    def test_recovery_inventory_holds_uncertain_outcome_and_all_its_spending(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("crash")
        self.run_fixture()
        before = self.queue.status()
        plan = research.recovery_plan(self.queue, self.authorization)
        self.assertEqual(plan["new_call_count"], 23)
        self.assertEqual(len(plan["held_calls"]), 1)
        self.assertEqual(plan["retained_reserve_microusd"], 151552)
        self.assertNotIn(plan["held_calls"][0]["prior_session"], [x.get("prior_session") for x in plan["new_calls"]])
        self.assertEqual(before, self.queue.status())
        with self.assertRaisesRegex(ValueError, "cannot be replayed"):
            research.resume(self.queue, self.authorization)
        self.run_fixture()
        self.assertEqual(before, self.queue.status())

    def test_truncated_response_is_archived_and_needs_new_signed_replacement(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("truncated")
        self.run_fixture()
        state = self.queue.status()
        receipt = state["research_requests"][0]["receipt"]
        self.assertEqual(receipt["stop_reason"], "max_tokens")
        self.assertEqual(receipt["usage"]["reasoning_tokens"], 6148)
        self.assertEqual(receipt["state"], "rejected")
        self.assertEqual(state["job"][0]["state"], "blocked")
        plan = research.recovery_plan(self.queue, self.authorization)
        self.assertEqual(plan["new_call_count"], 24)
        self.assertEqual(plan["held_calls"], [])
        self.assertEqual(plan["combined_reserve_microusd"], 3_169_488)
        self.assertEqual(len([x for x in plan["new_calls"] if x.get("prior_session")]), 1)
        with self.assertRaisesRegex(ValueError, "cannot be replayed"):
            research.resume(self.queue, self.authorization)
        self.assertEqual(len(self.queue.status()["api_review"]), 1)

    def stage_revision(self):
        from research_recovery import prepare

        held = research.recovery_plan(self.queue, self.authorization)["held_calls"]
        payload = prepare(self.queue, self.authorization, int(time.time()) + 500, [x["prior_session"] for x in held])
        identity = json.loads(payload)["plan"]["authorization_sha256"]
        sig = subprocess.run(
            ["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(self.signer), "-n", operator_approval.NAMESPACE],
            input=payload,
            capture_output=True,
            check=True,
        ).stdout
        return payload, identity, sig

    def test_signed_recovery_reuses_completed_report_and_requeues_only_after_signature(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("settled-crash")
        self.run_fixture()
        before = self.queue.status()
        original = {p: p.read_bytes() for p in (self.queue.workspace(1) / "reports").rglob("*") if p.is_file()}
        payload, identity, sig = self.stage_revision()
        self.assertEqual(json.loads(payload)["plan"]["budget"]["max_requests"], 23)
        self.assertIsNone(self.queue.claim(tuple(LIVE_MODELS)))
        with self.assertRaises(ValueError):
            research.approve(self.queue, identity, "operator", b"forged")
        research.approve(self.queue, identity, "operator", sig)
        with self.assertRaises(ValueError):
            research.approve(self.queue, identity, "operator", sig)
        (self.queue.root / "fixture-mode").unlink()
        self.run_fixture()
        after = self.queue.status()
        self.assertEqual(after["job"][0]["state"], "completed")
        self.assertEqual(len(after["api_review"]), 24)
        self.assertEqual(before["research_requests"], after["research_requests"][:1])
        self.assertEqual(original, {p: p.read_bytes() for p in original})

    def test_signed_replacement_preserves_original_uncertain_record_and_reserve(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("crash")
        self.run_fixture()
        before = self.queue.status()
        from research_recovery import prepare

        with self.assertRaisesRegex(ValueError, "explicitly list"):
            prepare(self.queue, self.authorization, int(time.time()) + 500, ["not-a-held-session"])
        payload, identity, sig = self.stage_revision()
        self.assertEqual(json.loads(payload)["plan"]["budget"]["full_reserve_microusd"], 3_169_488)
        (self.queue.root / "fixture-authorized-replacement").write_text(
            '\n'.join(p.name for p in self.queue.workspace(1).glob('sent-*'))
        )
        research.approve(self.queue, identity, "operator", sig)
        (self.queue.root / "fixture-mode").unlink()
        self.run_fixture()
        after = self.queue.status()
        self.assertEqual(after["job"][0]["state"], "completed")
        self.assertEqual(len(after["api_review"]), 25)
        self.assertEqual(before["api_review"][0], after["api_review"][0])
        self.assertEqual(before["research_requests"][0], after["research_requests"][0])
        self.assertEqual(sum(x["reserve_microusd"] for x in after["api_review"]), 3_169_488)

    def test_recovery_expiry_and_historical_tampering_cannot_activate(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("settled-crash")
        self.run_fixture()
        payload, identity, sig = self.stage_revision()
        with (
            patch("research.time.time", return_value=json.loads(payload)["plan"]["expires_at"]),
            self.assertRaises(ValueError),
        ):
            research.approve(self.queue, identity, "operator", sig)
        body = next((self.queue.workspace(1) / 'sources/equal-source').glob('*.body'))
        body.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, "evidence changed"):
            research.approve(self.queue, identity, "operator", sig)
        self.assertIsNone(self.queue.claim(tuple(LIVE_MODELS)))
        self.assertEqual(len(self.queue.status()["api_review"]), 1)

    def test_quality_failure_does_not_cancel_other_companies_or_deepseek(self):
        self.enroll(3)
        self.approve()
        (self.queue.root / "fixture-mode").write_text("quality_first_equal")
        self.run_fixture()
        state = self.queue.status()
        self.assertEqual([x["state"] for x in state["job"]], ["incomplete", "completed", "completed"])
        self.assertFalse(state["research_campaigns"][0]["paused"])
        self.assertFalse(any(x["state"] == "uncertain" for x in state["api_review"]))
        self.assertEqual(len(state["api_review"]), 66)
        self.assertTrue(
            any(
                x["job"] == 1 and x["provider"] == "deepseek" and x["receipt"]["state"] == "response_received"
                for x in state["research_requests"]
            )
        )
        failed = [x for x in state["research_requests"] if x["receipt"]["state"] == "rejected"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["receipt"]["failure_class"], "research_quality")

    def test_signed_frozen_report_repair_reuses_sources_and_never_repeats_completed_work(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("quality_first_equal")
        self.run_fixture()
        before = self.queue.status()
        sources = {
            p: p.read_bytes() for p in (self.queue.workspace(1) / 'sources/equal-source').rglob('*') if p.is_file()
        }
        payload, identity, sig = self.stage_revision()
        auth = json.loads(payload)["plan"]
        self.assertEqual(auth["budget"]["max_requests"], 7)
        repairs = [x for x in auth["recovery"]["calls"] if x.get("repair_of")]
        self.assertEqual(len(repairs), 1)
        self.assertEqual(auth["budget"]["full_reserve_microusd"], 3_169_488)
        research.approve(self.queue, identity, "operator", sig)
        from research_recovery import repair_input

        claimed = self.queue.claim(tuple(LIVE_MODELS))
        frozen = repair_input(self.queue, auth, repairs[0])['request_packet']
        frozen['repair']['instruction'] += ' Unauthorized instruction replacement.'
        plan, packet = research.make_plan(
            auth['manifest'],
            auth['manifest']['companies'][0],
            'anthropic',
            'equal-source',
            'report',
            frozen,
            auth['expires_at'],
            identity,
        )
        with self.assertRaisesRegex(WorkerFailure, 'differs from the original frozen evidence'):
            research.reserve(self.queue, claimed['id'], plan, packet)
        with self.queue.connect() as db:
            db.execute("UPDATE job SET state='queued' WHERE id=?", (claimed['id'],))
        (self.queue.root / 'fixture-mode').write_text('settled-crash')
        self.run_fixture()
        self.assertEqual(sources, {p: p.read_bytes() for p in sources})
        self.assertEqual(len(self.queue.status()["api_review"]), 19)
        research.resume(self.queue, identity)
        (self.queue.root / 'fixture-mode').unlink()
        self.run_fixture()
        state = self.queue.status()
        self.assertEqual(state["job"][0]["state"], "completed")
        self.assertEqual(len(state["api_review"]), 25)
        self.assertEqual(before["research_requests"], state["research_requests"][:18])
        with self.queue.connect() as db:
            row = db.execute(
                "SELECT packet FROM research_attempt WHERE mode='equal-source' AND stage='report' AND provider='anthropic'"
            ).fetchone()
        packet = json.loads(row['packet'])
        self.assertIn('repair', packet)
        self.assertEqual(packet['repair']['prior_session'], repairs[0]['repair_of'])
        self.assertTrue(packet['repair']['citation_failures'])

    def test_unselected_uncertain_request_stays_held_while_deepseek_progresses(self):
        self.enroll()
        self.approve()
        (self.queue.root / 'fixture-mode').write_text('crash')
        self.run_fixture()
        before = self.queue.status()
        from research_recovery import prepare

        payload = prepare(self.queue, self.authorization, int(time.time()) + 500, [])
        auth = json.loads(payload)['plan']
        self.assertEqual(len(auth['recovery']['held']), 1)
        self.assertEqual(auth['budget']['max_requests'], 23)
        signature = subprocess.run(
            ['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(self.signer), '-n', operator_approval.NAMESPACE],
            input=payload,
            capture_output=True,
            check=True,
        ).stdout
        research.approve(self.queue, auth['authorization_sha256'], 'operator', signature)
        (self.queue.root / 'fixture-mode').unlink()
        self.run_fixture()
        after = self.queue.status()
        self.assertEqual(after['job'][0]['state'], 'incomplete')
        self.assertEqual(before['api_review'][0], after['api_review'][0])
        self.assertEqual(before['research_requests'][0], after['research_requests'][0])
        self.assertEqual(
            sum(
                x['provider'] == 'anthropic' and x['mode'] == 'equal-source' and x['stage'] == 'report'
                for x in after['research_requests']
            ),
            1,
        )
        self.assertTrue(
            any(
                x['provider'] == 'deepseek' and x['receipt']['state'] == 'response_received'
                for x in after['research_requests']
            )
        )
        self.assertFalse(after['research_campaigns'][-1]['paused'])

    def test_failed_signed_repair_is_not_retried_and_other_lanes_remain_available(self):
        self.enroll()
        self.approve()
        (self.queue.root / 'fixture-mode').write_text('quality_first_equal')
        self.run_fixture()
        payload, identity, sig = self.stage_revision()
        research.approve(self.queue, identity, 'operator', sig)
        self.run_fixture()
        state = self.queue.status()
        self.assertEqual(state['job'][0]['state'], 'incomplete')
        self.assertEqual(len(state['api_review']), 19)
        self.assertFalse(state['research_campaigns'][-1]['paused'])
        self.assertEqual(state['research_requests'][-1]['receipt']['failure_class'], 'research_quality')
        self.run_fixture()
        self.assertEqual(state, self.queue.status())

    def test_second_signed_revision_repairs_quality_failures_without_losing_prior_audit(self):
        self.enroll()
        self.approve()
        (self.queue.root / 'fixture-mode').write_text('settled-crash')
        self.run_fixture()
        payload, first, sig = self.stage_revision()
        research.approve(self.queue, first, 'operator', sig)
        (self.queue.root / 'fixture-mode').write_text('bad_citation')
        self.run_fixture()
        before = self.queue.status()
        self.assertEqual(before['job'][0]['state'], 'incomplete')
        self.authorization = first
        payload, second, sig = self.stage_revision()
        auth = json.loads(payload)['plan']
        self.assertTrue(any(x.get('repair_of') for x in auth['recovery']['calls']))
        research.approve(self.queue, second, 'operator', sig)
        (self.queue.root / 'fixture-mode').unlink()
        self.run_fixture()
        after = self.queue.status()
        self.assertEqual(after['job'][0]['state'], 'completed')
        self.assertEqual(before['api_review'], after['api_review'][: len(before['api_review'])])
        self.assertEqual(before['research_requests'], after['research_requests'][: len(before['research_requests'])])
        self.assertLess(sum(x['reserve_microusd'] for x in after['api_review']), 10000000)

    def test_total_request_deadline_keeps_uncertain_spending(self):
        self.enroll()
        self.approve()
        (self.queue.root / "fixture-mode").write_text("deadline")
        started = time.monotonic()
        self.run_fixture()
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(self.queue.status()["api_review"][0]["state"], "uncertain")


class PublicSources(unittest.TestCase):
    def test_evidence_never_fetches_yc_or_h1bdata_even_after_a_redirect(self):
        from evidence import AnyPublicHost

        origins = AnyPublicHost()
        for url in (
            "https://www.ycombinator.com/companies/axle/jobs",
            "https://workatastartup.com/jobs/1",
            "https://h1bdata.info/index.php?em=x",
        ):
            with self.assertRaises(ValueError):
                allowed_url(url, origins)
        for url in ("https://news.ycombinator.com/item?id=1", "https://axle.insure/careers"):
            self.assertEqual(allowed_url(url, origins), url)

    def test_research_thinking_is_explicitly_disabled_without_changing_evidence_or_reviewers(self):
        from api_review import trial_plan
        from research_reports import SCHEMAS

        manifest = fixture_manifest()
        company = manifest["companies"][0]
        for stage in research.STAGES:
            packet = {"company": company["name"], "sources": {}}
            plan, bounded = research.make_plan(
                manifest,
                company,
                "anthropic",
                "independent",
                stage,
                packet,
                int(time.time()) + 600,
                "fixture-authorization",
            )
            wire = json.loads(plan["body_utf8"])
            self.assertEqual(wire["thinking"], {"type": "disabled"})
            self.assertEqual(wire["output_config"]["effort"], "low")
            self.assertEqual(wire["max_tokens"], 8192)
            self.assertEqual(json.loads(wire["messages"][-1]["content"]), bounded)
            self.assertEqual(plan["illustrative_reserve_microusd"], 151552)
            self.assertEqual(packet, {"company": company["name"], "sources": {}})
        reviewer = trial_plan(
            {"task": "review", "candidate": "a" * 64, "criteria": {}},
            "anthropic",
            LIVE_MODELS["anthropic"],
            project=company["id"],
            source_job=None,
            expires_at=int(time.time()) + 600,
        )
        self.assertNotIn("thinking", json.loads(reviewer["body_utf8"]))
        self.assertEqual(SCHEMAS["report"]["properties"]["projects"]["minItems"], 3)

    def test_citation_diagnostics_reject_search_snippets_wrong_ids_and_instruction_quotes(self):
        from research_reports import citation_failures

        api, report = self.report_fixture()
        sources = api.packet['sources']
        valid = api.evidence('company')[0]
        self.assertEqual(citation_failures(valid, sources), [])
        discovery = {**sources[valid['source_id']], 'kind': 'search-results'}
        sources['search-only'] = discovery
        item = {'source_id': 'search-only', 'quote': valid['quote']}
        self.assertFalse(evidence_valid(item, sources))
        self.assertEqual(citation_failures(item, sources)[0]['reason'], 'discovery_is_not_primary_evidence')
        for quote in (
            'Propose at least three distinct engineering contributions.',
            QUOTE.replace('audited', 'unverified'),
        ):
            item = {'source_id': valid['source_id'], 'quote': quote}
            self.assertFalse(evidence_valid(item, sources))
            self.assertEqual(citation_failures(item, sources)[0]['reason'], 'quote_not_verbatim_in_selected_source')

    def report_fixture(self):
        api = object.__new__(APIHTTPS)
        with tempfile.TemporaryDirectory() as root:
            collector = Retriever(root, fixture_manifest()["companies"][0]["origins"], 20, connection=SourceHTTPS)
            items = [
                collector.fetch(seed["url"], seed["category"]) for seed in fixture_manifest()["companies"][0]["seeds"]
            ]
            from research_sources import packet_sources

            api.packet = {"sources": compact_sources(packet_sources(items))}
        return api, api.report()

    def test_company_only_citations_cannot_certify_all_categories(self):
        api, report = self.report_fixture()
        self.assertEqual(validate("report", report, api.packet, "anthropic")[0], "approve")
        company = api.evidence("company")
        for coverage in report["coverage"]:
            coverage["evidence"] = company
        self.assertEqual(validate("report", report, api.packet, "anthropic")[0], "invalid")
        company_sources = {
            key: source for key, source in api.packet["sources"].items() if source["category"] == "company"
        }
        self.assertFalse(complete(report, company_sources))

    def test_challenge_requires_every_peer_project_and_recommendation(self):
        api, report = self.report_fixture()
        packet = {**api.packet, "peer_reports": {p: report for p in ("openai", "deepseek")}}
        findings = [
            {
                "target_provider": p,
                "target_kind": kind,
                "target_id": identity,
                "assessment": "uncertain",
                "objection": "Verify against primary evidence.",
                "evidence": [],
            }
            for p in packet["peer_reports"]
            for kind, identity in [
                ("claim", "claim-1"),
                ("recommendation", "recommendation"),
                *[("project", project["title"]) for project in report["projects"]],
            ]
        ]
        value = {"challenged_providers": ["openai", "deepseek"], "findings": findings, "verify": [], "gaps": []}
        self.assertEqual(validate("challenge", value, packet, "anthropic")[0], "approve")
        for kind in ("project", "recommendation"):
            incomplete = {**value, "findings": [item for item in findings if item["target_kind"] != kind]}
            self.assertEqual(validate("challenge", incomplete, packet, "anthropic")[0], "invalid")

    def test_compaction_preserves_citations_and_detects_alias_tampering(self):
        api, report = self.report_fixture()
        sources = api.packet["sources"]
        self.assertTrue(any(source.get("text_ref") for source in sources.values()))
        self.assertEqual(compact_sources(sources), sources)
        self.assertTrue(all(QUOTE in source_text(sources, identity) for identity in sources))
        alias = next(source for source in sources.values() if source.get("text_ref"))
        alias["view_sha256"] = "0" * 64
        with self.assertRaises(WorkerFailure):
            source_text(sources, next(key for key, source in sources.items() if source is alias))

    def test_origin_paths_are_segment_bound_and_traversal_is_denied(self):
        origins = {"company.example.org": ["/companies/one"]}
        self.assertEqual(
            allowed_url("https://company.example.org/companies/one/jobs", origins),
            "https://company.example.org/companies/one/jobs",
        )
        for suffix in (
            "/companies/one-evil",
            "/companies/one/../two",
            "/companies/one/%2e%2e/two",
            "/companies/one/%252e%252e/two",
            "/companies/one/\\two",
        ):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                allowed_url("https://company.example.org" + suffix, origins)

    def test_fresh_verification_deduplicates_identical_requests(self):
        with tempfile.TemporaryDirectory() as root:
            retriever = Retriever(root, {"company.example.org": ["/"]}, 2, connection=SourceHTTPS)
            request = {"url": "https://company.example.org/evidence", "category": "docs"}
            captured = research.collect(retriever, [request, request, request], fresh=True)
            self.assertEqual(len(captured), 1)
            self.assertEqual(retriever.state["attempts"], 1)

    def test_sitemaps_are_navigation_and_xml_entities_are_denied(self):
        class XML(SourceHTTPS):
            def request(self, *args, **kwargs):
                super().request(*args, **kwargs)
                self.headers["content-type"] = "text/xml"

            def read(self, maximum):
                return (
                    b'<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>'
                    if self.path == "/unsafe"
                    else b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url>'
                    b'<loc>https://company.example.org/docs</loc></url></urlset>'
                )

        with tempfile.TemporaryDirectory() as root:
            retriever = Retriever(root, {"company.example.org": ["/"]}, 3, connection=XML)
            item = retriever.fetch("https://company.example.org/sitemap.xml", "docs")
            self.assertEqual(item["kind"], "navigation")
            self.assertEqual(item["links"], ["https://company.example.org/docs"])
            self.assertIsNotNone(retriever.fetch("https://company.example.org/unsafe", "docs")["gap"])

    def test_claude_wire_schema_preserves_strict_local_bounds(self):
        from research_reports import SCHEMAS, wire_schema

        schema = wire_schema(SCHEMAS["report"], "anthropic")
        self.assertEqual(schema["properties"]["projects"]["minItems"], 1)
        self.assertNotIn("maxItems", schema["properties"]["projects"])
        self.assertIn("minItems", schema["properties"]["projects"]["description"])
        self.assertEqual(SCHEMAS["report"]["properties"]["projects"]["minItems"], 3)
        self.assertNotIn("maxLength", schema["properties"]["summary"])
        self.assertEqual(wire_schema(SCHEMAS["report"], "openai"), SCHEMAS["report"])

    def test_capture_provenance_tamper_denials_and_gaps(self):
        with tempfile.TemporaryDirectory() as root:
            collector = Retriever(root, {"company.example.org": ["/"]}, 5, connection=SourceHTTPS)
            item = collector.fetch("https://company.example.org/evidence", "docs")
            self.assertIn(QUOTE, item["text"])
            self.assertNotIn("attacker", item["text"])
            self.assertEqual(item["published_at"], "2026-10-01")
            self.assertTrue(item["retrieved_at"])
            self.assertEqual(collector.fetch(item["url"], "docs")["id"], item["id"])
            for url in (
                "http://company.example.org/x",
                "https://127.0.0.1/x",
                "https://company.example.org.evil/x",
                "https://user:secret@company.example.org/x",
                "file:///etc/passwd",
            ):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    collector.fetch(url, "docs")
            self.assertIsNotNone(collector.fetch("https://company.example.org/denied", "posts")["gap"])
            self.assertIsNotNone(collector.fetch("https://company.example.org/redirect", "docs")["gap"])
            (Path(root) / (item["id"] + ".body")).write_bytes(b"changed")
            with self.assertRaisesRegex(WorkerFailure, "changed"):
                collector.read(item)

    def test_dns_rebinding_cannot_reach_private_addresses(self):
        connection = PublicHTTPS("company.example.org", context=__import__("ssl").create_default_context())
        for address in ("127.0.0.1", "169.254.169.254", "::1", "10.0.0.1"):
            answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]
            with (
                patch("research_sources.socket.getaddrinfo", return_value=answers),
                patch("research_sources.socket.create_connection") as connect,
                self.assertRaises(OSError),
            ):
                connection.connect()
            connect.assert_not_called()

    def test_retrieval_exhaustion_is_durable_and_google_redirects_are_only_discovery(self):
        with tempfile.TemporaryDirectory() as root:
            collector = Retriever(
                root, {"company.example.org": ["/"], "www.google.com": ["/search"]}, 1, connection=SourceHTTPS
            )
            item, links = collector.search("company docs", "docs")
            self.assertEqual(item["kind"], "search-results")
            self.assertEqual(links, ["https://company.example.org/evidence"])
            with self.assertRaisesRegex(WorkerFailure, "limit"):
                collector.fetch(links[0], "docs")
            restored = Retriever(root, collector.origins, 1, connection=SourceHTTPS)
            self.assertEqual(restored.state["attempts"], 1)


if __name__ == "__main__":
    if len(sys.argv) == 5:
        import operator_approval

        operator_approval.trusted_signers = lambda: Path(sys.argv[1]) / "fixture-allowed-signers"
        mode = Path(sys.argv[1]) / "fixture-mode"
        if mode.exists() and mode.read_text() == "deadline":
            research.RESEARCH_TIMEOUT = 1
        original = research.ask

        def crash_after_settlement(*args, **kwargs):
            result = original(*args, **kwargs)
            control = Path.cwd().parent / "fixture-mode"
            if control.exists() and control.read_text() == "settled-crash":
                os._exit(23)
            return result

        research.ask = crash_after_settlement
        research.main(APIHTTPS, SourceHTTPS)
    else:
        unittest.main()
