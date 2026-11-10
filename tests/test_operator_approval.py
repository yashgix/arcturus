import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runner"))

from concurrent_runs import Scheduler, main
from api_review import DEEPSEEK_PROBE_PROFILE, encode
import operator_approval as approval
import paid_review
from test_model_tasks import FakeHTTPS, KEY
from workers import WorkerFailure


class OperatorApproval(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name).resolve()
        self.queue = self.schedule("schedule")
        self.spec = {
            "project": "fixture",
            "provider": "deepseek",
            "model": "deepseek-flash",
            "role": "probe",
            "data_class": "synthetic",
        }
        self.expires = int(time.time()) + 120
        self.signer = self.new_signer("operator")
        self.signers = self.root / "allowed_signers"
        self.signers.write_text(
            'operator namespaces="arcturus-model-approval-v1" ' + self.signer.with_suffix(".pub").read_text()
        )
        trust = patch.object(approval, "trusted_signers", return_value=self.signers)
        trust.start()
        self.addCleanup(trust.stop)

    def schedule(self, name):
        queue = Scheduler(self.root / name)
        queue.initialize(1, 314_650, {"fixture": (1, 314_650)})
        return queue

    def new_signer(self, name):
        key = self.root / name
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        return key

    def sign(self, payload, *, signer=None, namespace=approval.NAMESPACE):
        return subprocess.run(
            ["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(signer or self.signer), "-n", namespace],
            input=payload,
            check=True,
            capture_output=True,
        ).stdout

    def request(self, queue=None):
        payload = (queue or self.queue).model_approval_request(self.spec, self.expires)
        plan = json.loads(payload)["plan"]
        return payload, plan, plan["plan_sha256"]

    def test_noninteractive_import_consumes_once_and_sends_exact_mock_request(self):
        self.spec["probe_profile"] = DEEPSEEK_PROBE_PROFILE
        payload, plan, digest = self.request()
        self.assertEqual(self.request()[0], payload)
        self.assertEqual(hashlib.sha256(plan["body_utf8"].encode()).hexdigest(), plan["body_sha256"])
        self.assertEqual((plan["max_requests"], plan["automatic_retries"], plan["timeout_seconds"]), (1, 0, 30))
        self.assertEqual(plan["illustrative_reserve_microusd"], 19_738)
        signature = self.sign(payload)
        sig_file = self.root / "approval.sig"
        sig_file.write_bytes(signature)
        argv = [
            "concurrent_runs.py",
            str(self.queue.root),
            "approve-signed-model",
            digest,
            "--operator",
            "operator",
            "--signature",
            str(sig_file),
        ]
        self.addCleanup(os.umask, os.umask(0o077))
        with patch("sys.argv", argv), patch("sys.stdin", io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(), 0)
        job = self.queue.claim(("deepseek",))["id"]
        # The fake connection uses the work directory as its one-request fence.
        work = self.queue.workspace(job)
        work.mkdir()
        key = self.root / "fixture-key"
        key.write_text(KEY + "\n")
        key.chmod(0o600)
        with contextlib.chdir(work):
            paid_review.execute_model(self.queue, job, str(key), FakeHTTPS)
        self.assertEqual((work / "sent").read_bytes(), plan["body_utf8"].encode())
        self.assertEqual(json.loads(self.queue.approval(job)["receipt"])["result"], {"ok": True})
        status = self.queue.status()
        signed = status["model_approval_requests"][0]
        self.assertEqual(
            (signed["principal"], signed["signature_sha256"]), ("operator", approval.signature_hash(signature))
        )
        self.assertIsNotNone(self.queue.approval(job)["consumed"])
        self.assertEqual(len(status["api_review"]), 1)
        with self.assertRaisesRegex(ValueError, "already queued"):
            self.queue.approve_signed_model(digest, "operator", signature)
        with self.assertRaises(WorkerFailure):
            self.queue.consume_review(job, plan)

    def test_forged_wrong_principal_and_wrong_namespace_are_rejected(self):
        payload, _, digest = self.request()
        for principal, signature in (
            ("operator", b"APPROVE " + digest.encode()),
            ("operator", self.sign(payload, signer=self.new_signer("agent"))),
            ("agent", self.sign(payload)),
            ("operator", self.sign(payload, namespace="unrelated")),
        ):
            with self.subTest(principal=principal), self.assertRaisesRegex(ValueError, "signature"):
                self.queue.approve_signed_model(digest, principal, signature)
        self.assertEqual(self.queue.status()["job"], [])

    def test_altered_plan_fields_hashes_and_cross_schedule_replay_fail(self):
        payload, _, digest = self.request()
        for field, replacement in (
            ("provider", "openai"),
            ("model", "other"),
            ("body_utf8", "{}"),
            ("body_sha256", "0" * 64),
            ("plan_sha256", "0" * 64),
            ("illustrative_reserve_microusd", 1),
            ("expires_at", self.expires + 1),
        ):
            altered = json.loads(payload)
            altered["plan"][field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "signature"):
                self.queue.approve_signed_model(digest, "operator", self.sign(encode(altered) + b"\n"))
        signature = self.sign(payload)
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.queue.approve_signed_model("0" * 64, "operator", signature)
        other = self.schedule("other")
        self.assertEqual(self.request(other)[2], digest)
        with self.assertRaisesRegex(ValueError, "signature"):
            other.approve_signed_model(digest, "operator", signature)

    def test_one_of_two_concurrent_imports_can_enroll(self):
        payload, _, digest = self.request()
        signature = self.sign(payload)

        def import_once():
            try:
                return self.queue.approve_signed_model(digest, "operator", signature)
            except ValueError as exc:
                return str(exc)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: import_once(), range(2)))
        self.assertCountEqual(results, [1, "this exact plan was already queued"])

    def test_expiry_before_import_and_before_consumption(self):
        payload, plan, digest = self.request()
        signature = self.sign(payload)
        with patch("concurrent_runs.time.time", return_value=self.expires):
            with self.assertRaisesRegex(ValueError, "expiry"):
                self.queue.approve_signed_model(digest, "operator", signature)
        job = self.queue.approve_signed_model(digest, "operator", signature)
        self.queue.claim(("deepseek",))
        with patch("concurrent_runs.time.time", return_value=self.expires):
            with self.assertRaisesRegex(WorkerFailure, "expired"):
                self.queue.consume_review(job, plan)
        self.assertIsNone(self.queue.approval(job)["consumed"])
        self.assertEqual(self.queue.status()["api_review"], [])

    def test_cancelled_approval_and_cancelled_job_never_reserve(self):
        payload, _, digest = self.request()
        signature = self.sign(payload)
        self.queue.cancel_model_approval(digest)
        with self.assertRaisesRegex(ValueError, "cancelled"):
            self.queue.approve_signed_model(digest, "operator", signature)
        with self.assertRaisesRegex(ValueError, "cancelled"):
            self.request()
        other = self.schedule("other")
        payload, plan, digest = self.request(other)
        other.control("stop", "fixture")
        other.control("resume", "fixture")
        with self.assertRaisesRegex(ValueError, "cancelled"):
            other.approve_signed_model(digest, "operator", self.sign(payload))
        self.expires += 1
        payload, plan, digest = self.request(other)
        job = other.approve_signed_model(digest, "operator", self.sign(payload))
        other.claim(("deepseek",))
        other.control("cancel", job)
        with self.assertRaises(WorkerFailure):
            other.consume_review(job, plan)
        self.assertEqual(other.status()["api_review"], [])

    def test_signed_mode_has_no_terminal_fallback_and_rechecks_current_trust(self):
        payload, plan, digest = self.request()
        with self.assertRaisesRegex(ValueError, "signed operator"):
            self.queue.approve_model(self.spec, self.expires, digest)
        with patch.object(approval, "configured", return_value=True):
            fresh = self.queue.prepare_model(self.spec, self.expires + 1)
            with self.assertRaisesRegex(ValueError, "signed operator"):
                self.queue.approve_model(self.spec, self.expires + 1, fresh["plan_sha256"])
        job = self.queue.approve_signed_model(digest, "operator", self.sign(payload))
        self.queue.claim(("deepseek",))
        self.signers.write_text("")
        with self.assertRaisesRegex(WorkerFailure, "signature"):
            self.queue.consume_review(job, plan)
        self.assertEqual(self.queue.status()["api_review"], [])

    def test_dispatch_rejects_replaced_signature_even_with_matching_audit_hash(self):
        payload, plan, digest = self.request()
        job = self.queue.approve_signed_model(digest, "operator", self.sign(payload))
        self.queue.claim(("deepseek",))
        forged = self.sign(payload, signer=self.new_signer("agent"))
        with self.queue.connect() as db:
            db.execute(
                "UPDATE model_approval_request SET signature=?, signature_sha256=? WHERE job=?",
                (forged, approval.signature_hash(forged), job),
            )
        with self.assertRaisesRegex(WorkerFailure, "signature"):
            self.queue.consume_review(job, plan)
        self.assertIsNone(self.queue.approval(job)["consumed"])
        self.assertEqual(self.queue.status()["api_review"], [])


class TrustStore(unittest.TestCase):
    def test_missing_and_user_writable_trust_store_fail_closed(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            path = Path(tmp).resolve() / "allowed_signers"
            with patch.object(approval, "SIGNERS", path):
                self.assertFalse(approval.configured())
                path.touch()
                self.assertTrue(approval.configured())
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    approval.trusted_signers()


if __name__ == "__main__":
    unittest.main()
