"""Run the production paid worker through the real queue with an injected offline HTTPS client."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runner"))
import concurrent_runs
import paid_review
from api_review import ANTHROPIC_VERSION, LIVE_MODELS, encode, read_review
from concurrent_runs import Scheduler
from workers import WorkerFailure

NODE = shutil.which("node")
FIXTURE_KEY = "offline-fixture-key"


class FakeHTTPS:
    def __init__(self, host, *, port, timeout, context):
        assert host in {"api.anthropic.com", "api.openai.com"} and port == 443 and timeout == 30
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        self.provider = "anthropic" if host == "api.anthropic.com" else "openai"
        self.work = Path.cwd()
        control = self.work / "fixture-response"
        self.mode = control.read_text() if control.exists() else "success"
        self.status = 302 if self.mode == "redirect" else 429 if self.mode == "rate" else 200
        self.headers = {"x-fixture": FIXTURE_KEY} if self.mode == "credential_header" else {}

    def request(self, method, path, *, body, headers):
        assert method == "POST"
        wire = json.loads(body)
        assert wire["model"] == LIVE_MODELS[self.provider]
        if self.provider == "anthropic":
            assert path == "/v1/messages" and headers["anthropic-version"] == ANTHROPIC_VERSION
            assert headers["x-api-key"] == "offline-fixture-key"
            assert wire["service_tier"] == "standard_only" and wire["inference_geo"] == "global"
            self.packet = json.loads(wire["messages"][0]["content"])
        else:
            assert path == "/v1/responses" and headers["authorization"] == "Bearer offline-fixture-key"
            assert wire["store"] is False and wire["text"]["format"]["strict"] is True
            self.packet = json.loads(wire["input"])
        with (self.work / "post-sha256").open("x") as file:
            file.write(hashlib.sha256(body).hexdigest())
        if self.mode == "crash":
            os._exit(17)
        if self.mode == "hang":
            time.sleep(60)

    def getresponse(self):
        if self.mode == "timeout":
            raise TimeoutError("fixture transport timed out")
        if self.mode == "credential_exception":
            raise RuntimeError(FIXTURE_KEY)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def close(self):
        pass

    def read(self, n):
        assert self.status == 200 and n == 64_001
        if self.mode == "oversize":
            return b"x" * n
        if self.mode == "malformed":
            return b'{"usage":' + b'9' * 5000 + b'}'
        status = "unverified" if self.mode == "unverified" else "met"
        verdict = {
            "verdict": "approve",
            "summary": self.packet["task"],
            "findings": [],
            "tests_run": "Inspected trusted evidence.",
            "coverage": {c: {"status": status, "evidence": "Checked the diff."} for c in self.packet["criteria"]},
        }
        if self.mode == "changes":
            verdict.update(
                verdict="changes_requested",
                findings=[{"severity": "high", "file": "src/label.mjs", "issue": "Repair this line."}],
            )
        if self.mode in {"credential_echo", "escaped_credential"}:
            verdict["summary"] = FIXTURE_KEY
        text = encode(verdict).decode()
        if self.mode == "escaped_credential":
            text = text.replace(FIXTURE_KEY, "".join(f"\\u{ord(c):04x}" for c in FIXTURE_KEY))
        model = "wrong-model" if self.mode == "drift" else LIVE_MODELS[self.provider]
        if self.provider == "anthropic":
            return encode(
                {
                    "model": model,
                    "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": text}],
                    "stop_details": {"type": "refusal"} if self.mode == "refusal" else None,
                    "usage": {
                        "input_tokens": 128,
                        "output_tokens": 32,
                        "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 32,
                        "inference_geo": "global",
                        "service_tier": "standard",
                        "speed": "standard",
                    },
                }
            )
        message = {
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text}],
        }
        return encode(
            {
                "model": model,
                "status": "completed",
                "service_tier": "default",
                "output": [message],
                "usage": {
                    "input_tokens": 128,
                    "output_tokens": 32,
                    "total_tokens": 160,
                    "input_tokens_details": {"cached_tokens": 32, "cache_write_tokens": 0},
                    "output_tokens_details": {"reasoning_tokens": 0},
                },
            }
        )


class Audit(unittest.TestCase):
    def test_exact_coverage_and_safe_validation_diagnostics(self):
        from types import SimpleNamespace
        from test_arc_unit import arc

        criteria = {"T1.1": "first", "T1.2": "second"}
        request = SimpleNamespace(criteria=tuple(criteria), owned_paths=("src/",))
        packet = {"task": "ENG-1", "candidate": "commit", "criteria": criteria}
        plan = concurrent_runs.trial_plan(
            packet, "openai", LIVE_MODELS["openai"], project="a", source_job=1, expires_at=time.time() + 60
        )
        format = json.loads(plan["body_utf8"])["text"]["format"]
        coverage = format["schema"]["properties"]["coverage"]
        self.assertTrue(format["strict"])
        self.assertFalse(coverage["additionalProperties"])
        self.assertEqual(set(coverage["required"]), set(coverage["properties"]))
        self.assertEqual(set(coverage["properties"]), set(criteria))
        met = {"status": "met", "evidence": "src/label.mjs preserves zero in the concatenation."}
        good = {
            "verdict": "approve",
            "summary": "Checked both criteria.",
            "tests_run": "Read runner proof.",
            "findings": [],
            "coverage": dict.fromkeys(criteria, met),
        }
        missing = {**good, "coverage": {"T1.1": met}}
        extra = {**good, "coverage": {**good["coverage"], "UNTRUSTED-ID": met}}
        duplicate = encode(good).decode().replace('"T1.2":', '"T1.1":')
        unverified = {
            **good,
            "coverage": {
                **good["coverage"],
                "T1.2": {"status": "unverified", "evidence": "The supplied cases omit this behavior."},
            },
        }
        empty_evidence = {**good, "coverage": {**good["coverage"], "T1.2": {**met, "evidence": " "}}}
        blocked = {
            **unverified,
            "verdict": "changes_requested",
            "findings": [
                {"severity": "high", "file": "criterion:T1.2", "issue": "Missing evidence for the boundary case."}
            ],
        }
        not_met = {
            **good,
            "verdict": "changes_requested",
            "coverage": {
                **good["coverage"],
                "T1.2": {"status": "not_met", "evidence": "The function drops a zero value."},
            },
        }

        for value, outcome, error in (
            (missing, None, "exactly once"),
            (extra, None, "exactly once"),
            (duplicate, None, "duplicate JSON key"),
            (empty_evidence, None, "needs criterion, status and evidence"),
            (unverified, None, "verified, met coverage"),
            (good, "approve", None),
            (blocked, "changes", None),
            (not_met, "changes", None),
        ):
            with self.subTest(outcome=outcome, error=error):
                message = {
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [
                        {"type": "output_text", "text": value if isinstance(value, str) else encode(value).decode()}
                    ],
                }
                reply = {
                    "model": LIVE_MODELS["openai"],
                    "status": "completed",
                    "service_tier": "default",
                    "output": [message],
                    "usage": {
                        "input_tokens": 128,
                        "output_tokens": 32,
                        "total_tokens": 160,
                        "input_tokens_details": {"cached_tokens": 0},
                        "output_tokens_details": {"reasoning_tokens": 0},
                    },
                }
                receipt = paid_review.audit(
                    200,
                    encode(reply),
                    plan,
                    request,
                    arc.validate_review,
                    arc.owns,
                    arc.canonical_path,
                    credential=FIXTURE_KEY,
                )
                self.assertEqual(receipt.get("outcome"), outcome)
                self.assertEqual(receipt["stop_reason"], "completed")
                if error:
                    self.assertIn(error, receipt["validation_error"])
                    self.assertNotIn("review", receipt)
                    self.assertNotIn("UNTRUSTED-ID", str(receipt))
                else:
                    self.assertEqual([row["criterion"] for row in receipt["review"]["coverage"]], list(criteria))
                self.assertEqual(receipt["estimated_microusd"], 88)
                self.assertIsNone(receipt["actual_charge_microusd"])
        for reason, expected in (("max_output_tokens", "max_output_tokens"), ("untrusted", "incomplete")):
            with self.subTest(reason=reason):
                reply.update(status="incomplete", incomplete_details={"reason": reason})
                receipt = paid_review.audit(
                    200,
                    encode(reply),
                    plan,
                    request,
                    arc.validate_review,
                    arc.owns,
                    arc.canonical_path,
                    credential=FIXTURE_KEY,
                )
                self.assertEqual(receipt["stop_reason"], expected)
                self.assertEqual(receipt["state"], "rejected")

    def test_valid_usage_is_preserved_for_unverified_coverage_and_refusal(self):
        from types import SimpleNamespace
        from test_arc_unit import arc

        packet = {"task": "MOCK-1", "candidate": "commit", "criteria": {"T1.1": "requirement"}}
        plan = concurrent_runs.trial_plan(
            packet, "anthropic", LIVE_MODELS["anthropic"], project="a", source_job=1, expires_at=time.time() + 60
        )
        request = SimpleNamespace(criteria=("T1.1",), owned_paths=("src/",))
        with tempfile.TemporaryDirectory() as folder:
            for mode in ("unverified", "refusal", "drift", "malformed", "oversize"):
                with self.subTest(mode=mode):
                    (Path(folder) / "fixture-response").write_text(mode)
                    with patch.object(Path, "cwd", return_value=Path(folder)):
                        status, raw = paid_review.send_once(plan, "offline-fixture-key", FakeHTTPS)
                    (Path(folder) / "post-sha256").unlink()
                    receipt = paid_review.audit(
                        status,
                        raw,
                        plan,
                        request,
                        arc.validate_review,
                        arc.owns,
                        arc.canonical_path,
                        credential=FIXTURE_KEY,
                    )
                    self.assertEqual(receipt["state"], "rejected")
                    self.assertIsNone(receipt["actual_charge_microusd"])
                    self.assertEqual(receipt["reserve_microusd"], 528_128)
                    self.assertEqual(receipt["estimated_microusd"], 160 if mode in {"unverified", "refusal"} else None)
            (Path(folder) / "fixture-response").write_text("rate")
            with patch.object(Path, "cwd", return_value=Path(folder)):
                self.assertEqual(paid_review.send_once(plan, "offline-fixture-key", FakeHTTPS), (429, b""))
                (Path(folder) / "post-sha256").unlink()
                (Path(folder) / "fixture-response").write_text("credential_header")
                with self.assertRaisesRegex(paid_review.CredentialEcho, "active credential"):
                    paid_review.send_once(plan, FIXTURE_KEY, FakeHTTPS)

    def test_deepseek_codec_is_offline(self):
        model = "deepseek-flash"
        usage = {
            "prompt_tokens": 8,
            "completion_tokens": 2,
            "total_tokens": 10,
            "prompt_cache_hit_tokens": 4,
            "prompt_cache_miss_tokens": 4,
        }
        raw = encode(
            {"model": model, "choices": [{"finish_reason": "stop", "message": {"content": "{}"}}], "usage": usage}
        )
        self.assertEqual(read_review("deepseek", model, raw, 64), ({}, 10))
        reasoning = {**usage, "completion_tokens_details": {"reasoning_tokens": 1}}
        raw = encode(
            {"model": model, "choices": [{"finish_reason": "stop", "message": {"content": "{}"}}], "usage": reasoning}
        )
        with self.assertRaisesRegex(WorkerFailure, "reserve retained"):
            read_review("deepseek", model, raw, 64)
        with self.assertRaisesRegex(ValueError, "synthetic or public"):
            concurrent_runs.trial_plan({}, "deepseek", model, project="a", source_job=1, expires_at=0)

    def test_expiry_rechecked_before_post(self):
        packet = {"task": "MOCK-1", "candidate": "commit", "criteria": {}}
        plan = concurrent_runs.trial_plan(
            packet, "anthropic", LIVE_MODELS["anthropic"], project="a", source_job=1, expires_at=time.time() + 60
        )
        with tempfile.TemporaryDirectory() as folder:
            with (
                patch.object(Path, "cwd", return_value=Path(folder)),
                patch.object(paid_review.time, "time", return_value=plan["expires_at"]),
            ):
                with self.assertRaises(paid_review.ApprovalExpired):
                    paid_review.send_once(plan, FIXTURE_KEY, FakeHTTPS)
            self.assertFalse((Path(folder) / "post-sha256").exists())


@unittest.skipUnless(NODE, "fixture build requires Node permission mode")
class PaidReview(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        self.queue = Scheduler(root / "queue")
        self.queue.initialize(2, 2_000_000, {"project-a": (1, 1_000_000), "project-b": (1, 1_000_000)})
        self.a = self.queue.enqueue("project-a", "repair", 100)
        self.b = self.queue.enqueue("project-b", "clean", 100)
        self.queue.run(NODE, lambda: False)
        self.assertEqual([self.queue.job(job)["state"] for job in (self.a, self.b)], ["ready", "ready"])
        private = root / "private"
        private.mkdir(mode=0o700)
        self.key = private / "fixture-key"
        self.key.write_text("offline-fixture-key\n")
        self.key.chmod(0o600)
        self.credentials = dict.fromkeys(LIVE_MODELS, str(self.key))

    def approve(self, source, provider, mode="success"):
        model = LIVE_MODELS[provider]
        plan = self.queue.prepare_trial(source, provider, model)
        job = self.queue.approve_review(source, provider, model, plan["plan_sha256"])
        work = self.queue.workspace(job)
        work.mkdir()
        (work / "fixture-response").write_text(mode)
        return job, plan

    def run_offline(self, deadline=30, stop=lambda: False):
        popen = subprocess.Popen

        def inject(argv, **kwargs):
            self.assertEqual(Path(argv[2]).name, "paid_review.py")
            return popen([*argv[:2], str(Path(__file__).resolve()), *argv[3:]], **kwargs)

        with (
            patch.object(concurrent_runs.subprocess, "Popen", side_effect=inject),
            patch.object(concurrent_runs, "REVIEW_TIMEOUT", deadline),
        ):
            self.queue.run(NODE, stop, self.credentials)

    def receipt(self, job):
        row = self.queue.approval(job)
        return json.loads(row["receipt"])

    def assert_credential_absent(self):
        status = subprocess.run(
            [sys.executable, "-B", str(concurrent_runs.SOURCE / "concurrent_runs.py"), str(self.queue.root), "status"],
            capture_output=True,
            timeout=5,
            check=True,
        )
        for channel in (status.stdout, status.stderr):
            self.assertFalse(FIXTURE_KEY.encode() in channel, "credential escaped into status output")
        for path in self.queue.root.rglob("*"):
            if path.is_file():
                self.assertFalse(FIXTURE_KEY.encode() in path.read_bytes(), f"credential persisted in {path.name}")

    def test_unix_epoch_approval_reproduction(self):
        job, _ = self.approve(self.b, "anthropic")
        with self.queue.connect() as db:
            db.execute("UPDATE review_approval SET approved=0 WHERE job=?", (job,))
        self.run_offline()
        self.assertFalse((self.queue.workspace(job) / "post-sha256").exists(), "Unix-epoch approval reached transport")
        self.assertEqual(self.queue.job(job)["state"], "blocked")
        self.assertIsNone(self.queue.approval(job)["consumed"])
        self.assertEqual(len(self.queue.status()["api_review"]), 3)

    def test_schema_valid_credential_echo_reproduction(self):
        a, _ = self.approve(self.a, "openai", "credential_echo")
        b, _ = self.approve(self.b, "anthropic", "credential_echo")
        self.run_offline()
        for job in (a, b):
            self.assertTrue((self.queue.workspace(job) / "post-sha256").exists())
            self.assertFalse(FIXTURE_KEY in self.queue.approval(job)["receipt"], "credential persisted in receipt")
            receipt = self.receipt(job)
            self.assertEqual(receipt["state"], "rejected")
            self.assertIn("active credential", receipt["reason"])
            self.assertNotIn("review", receipt)
            self.assertNotIn("response_sha256", receipt)
            self.assertIsNone(receipt["actual_charge_microusd"])
            self.assertEqual(receipt["reserve_microusd"], self.queue.job(job)["reserve"])
        self.assert_credential_absent()

    def test_json_escaped_echo_is_rejected_for_both_providers(self):
        a, _ = self.approve(self.a, "openai", "escaped_credential")
        b, _ = self.approve(self.b, "anthropic", "escaped_credential")
        self.run_offline()
        for job in (a, b):
            self.assertEqual(self.queue.job(job)["state"], "blocked")
            self.assertIn("active credential", self.receipt(job)["reason"])
        self.assert_credential_absent()

    def test_transport_exception_message_never_leaves_worker(self):
        a, _ = self.approve(self.a, "openai", "credential_exception")
        b, _ = self.approve(self.b, "anthropic", "credential_exception")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.run_offline()
        for job in (a, b):
            receipt = self.receipt(job)
            self.assertEqual(receipt["state"], "uncertain")
            self.assertEqual(receipt["reserve_microusd"], self.queue.job(job)["reserve"])
        for channel in (stdout.getvalue(), stderr.getvalue()):
            self.assertFalse(FIXTURE_KEY in channel, "credential escaped into supervisor output")
        self.assert_credential_absent()

    def test_expired_and_legacy_approvals_are_blocked_without_reserving(self):
        old_finish = time.time() - concurrent_runs.APPROVAL_TTL_SECONDS - 60
        with self.queue.connect() as db:
            db.execute("UPDATE job SET finished=? WHERE id=?", (old_finish, self.a))
        with patch.object(concurrent_runs.time, "time", return_value=old_finish + 1):
            a, expired = self.approve(self.a, "openai")
        self.assertEqual(self.queue.prepare_trial(self.a, "openai", expired["model"]), expired)
        with self.assertRaisesRegex(ValueError, "expired"):
            self.queue.approve_review(self.a, "openai", expired["model"], expired["plan_sha256"])

        b, legacy = self.approve(self.b, "anthropic")
        legacy.pop("expires_at")
        legacy.pop("plan_sha256")
        legacy["plan_sha256"] = hashlib.sha256(encode(legacy)).hexdigest()
        with self.queue.connect() as db:
            db.execute(
                "UPDATE review_approval SET plan=?, plan_sha256=? WHERE job=?",
                (encode(legacy).decode(), legacy["plan_sha256"], b),
            )
        with self.assertRaisesRegex(WorkerFailure, "missing or invalid approval expiry"):
            self.queue.consume_review(b, legacy)
        self.run_offline()
        for job in (a, b):
            self.assertEqual(self.queue.job(job)["state"], "blocked")
            self.assertIsNone(self.queue.approval(job)["consumed"])
            self.assertFalse((self.queue.workspace(job) / "post-sha256").exists())
        self.assertEqual(len(self.queue.status()["api_review"]), 3)

    def test_consume_at_expiry_rolls_back_and_rejects_cross_project_plan(self):
        a, plan_a = self.approve(self.a, "openai")
        b, plan_b = self.approve(self.b, "anthropic")
        self.queue.claim(self.credentials)
        self.queue.claim(self.credentials)
        with self.assertRaisesRegex(WorkerFailure, "plan changed"):
            self.queue.consume_review(a, plan_b)
        expiry = plan_a["expires_at"]
        with patch.object(concurrent_runs.time, "time", side_effect=[expiry - 0.01, expiry]):
            with self.assertRaisesRegex(WorkerFailure, "expired"):
                self.queue.consume_review(a, plan_a)
        self.assertIsNone(self.queue.approval(a)["consumed"])
        self.assertEqual(len(self.queue.status()["api_review"]), 3)
        self.queue.consume_review(b, plan_b)
        with self.assertRaisesRegex(WorkerFailure, "one-shot"):
            self.queue.consume_review(b, plan_b)

    def test_both_providers_dispatch_exact_approved_bytes_independently(self):
        a, openai = self.approve(self.a, "openai", "changes")
        b, anthropic = self.approve(self.b, "anthropic")
        self.queue.run(NODE, lambda: False)  # the default offline run cannot claim either paid job
        self.assertEqual([self.queue.job(job)["state"] for job in (a, b)], ["queued", "queued"])
        self.run_offline()
        self.assertEqual([self.queue.job(job)["state"] for job in (a, b)], ["changes_requested", "reviewed"])
        rows = self.queue.status()["job"]
        self.assertLess(rows[-2]["started"], rows[-1]["finished"])
        self.assertLess(rows[-1]["started"], rows[-2]["finished"])
        for job, plan, source in ((a, openai, self.a), (b, anthropic, self.b)):
            work = self.queue.workspace(job)
            self.assertEqual((work / "post-sha256").read_text(), plan["body_sha256"])
            receipt = self.receipt(job)
            self.assertEqual(receipt["review"]["summary"], f"MOCK-{source}")
            self.assertIsNone(receipt["actual_charge_microusd"])
            self.assertGreater(receipt["estimated_microusd"], 0)
            self.assertEqual(receipt["reserve_microusd"], plan["illustrative_reserve_microusd"])
            self.assertEqual(json.loads(self.queue.job(job)["checkpoint"])["candidate"], plan["candidate"])
            self.assertNotIn("offline-fixture-key", (work / "output.log").read_text())

    def test_timeout_and_crash_retain_reserves_and_never_retry(self):
        a, _ = self.approve(self.a, "openai", "crash")
        b, _ = self.approve(self.b, "anthropic", "timeout")
        self.run_offline()
        self.assertEqual([self.queue.job(job)["state"] for job in (a, b)], ["interrupted", "blocked"])
        for job in (a, b):
            self.assertEqual(self.receipt(job)["state"], "uncertain")
            self.assertIsNone(self.receipt(job)["estimated_microusd"])
            self.assertIsNotNone(self.queue.approval(job)["consumed"])
        before = self.queue.status()
        self.run_offline()
        self.assertEqual(self.queue.status(), before)

    def test_cancel_in_flight_does_not_block_peer_or_replay(self):
        a, _ = self.approve(self.a, "openai", "hang")
        b, _ = self.approve(self.b, "anthropic")
        cancelled = False

        def cancel_when_sent():
            nonlocal cancelled
            if not cancelled and (self.queue.workspace(a) / "post-sha256").exists():
                self.queue.control("cancel", a)
                cancelled = True
            return False

        self.run_offline(deadline=5, stop=cancel_when_sent)
        self.assertTrue(cancelled)
        self.assertEqual([self.queue.job(job)["state"] for job in (a, b)], ["cancelled", "reviewed"])
        self.assertEqual(self.receipt(a)["state"], "uncertain")

    def test_total_deadline_terminates_stalled_worker(self):
        job, _ = self.approve(self.b, "anthropic", "hang")
        started = time.monotonic()
        self.run_offline(deadline=3)
        self.assertLess(time.monotonic() - started, 8)
        self.assertEqual(self.queue.job(job)["reason"], "worker timed out")
        self.assertTrue((self.queue.workspace(job) / "post-sha256").exists())
        self.assertEqual(self.receipt(job)["state"], "uncertain")

    def test_redirect_does_not_dispatch_again_or_block_peer(self):
        a, _ = self.approve(self.a, "openai", "redirect")
        b, _ = self.approve(self.b, "anthropic")
        self.run_offline()
        self.assertEqual(self.receipt(a)["http_status"], 302)
        self.assertEqual(self.receipt(a)["state"], "rejected")
        self.assertEqual(self.queue.job(b)["state"], "reviewed")
        self.assertEqual(len(self.queue.status()["api_review"]), 5)

    def test_approval_digest_source_drift_and_budget_fail_before_key_or_post(self):
        model = LIVE_MODELS["anthropic"]
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.queue.approve_review(self.b, "anthropic", model, "0" * 64)
        a, _ = self.approve(self.a, "openai")
        b, _ = self.approve(self.b, "anthropic")
        (self.queue.workspace(self.a) / "repo/src/label.mjs").write_text("drift\n")
        with self.queue.connect() as db:
            db.execute("UPDATE project SET budget=100 WHERE name='project-b'")
        self.run_offline()
        for job in (a, b):
            self.assertEqual(self.queue.job(job)["state"], "blocked")
            self.assertIsNone(self.queue.approval(job)["consumed"])
            self.assertFalse((self.queue.workspace(job) / "post-sha256").exists())
        self.assertEqual(len(self.queue.status()["api_review"]), 3)

    def test_approval_cannot_be_enqueued_twice_or_consumed_twice(self):
        plan = self.queue.prepare_trial(self.b)
        piped = subprocess.run(
            [
                sys.executable,
                "-B",
                str(concurrent_runs.SOURCE / "concurrent_runs.py"),
                str(self.queue.root),
                "approve-review",
                str(self.b),
                "--provider",
                "anthropic",
                "--model",
                plan["model"],
            ],
            input=f"APPROVE {plan['plan_sha256']}\n",
            text=True,
            capture_output=True,
            timeout=5,
        )
        self.assertEqual(piped.returncode, 1)
        self.assertIn("trusted operator terminal", piped.stderr)
        job, plan = self.approve(self.b, "anthropic")
        with self.assertRaisesRegex(concurrent_runs.sqlite3.IntegrityError, "UNIQUE"):
            self.queue.approve_review(self.b, "anthropic", plan["model"], plan["plan_sha256"])
        self.assertEqual(self.queue.claim(self.credentials)["id"], job)
        with self.assertRaisesRegex(WorkerFailure, "plan changed"):
            self.queue.consume_review(job, {**plan, "body_utf8": plan["body_utf8"] + " "})

        def consume():
            try:
                self.queue.consume_review(job, plan)
                return True
            except WorkerFailure:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            attempts = [pool.submit(consume) for _ in range(2)]
            self.assertCountEqual([attempt.result() for attempt in attempts], [True, False])
        self.queue.recover(job)
        self.assertEqual(self.receipt(job)["state"], "uncertain")
        self.assertEqual(len(self.queue.status()["api_review"]), 4)

    def test_unsafe_key_never_reaches_http(self):
        job, _ = self.approve(self.b, "anthropic")
        self.key.chmod(0o644)
        self.run_offline()
        self.assertEqual(self.receipt(job)["state"], "not_sent")
        self.assertFalse((self.queue.workspace(job) / "post-sha256").exists())


if __name__ == "__main__":
    paid_review.main(FakeHTTPS)
