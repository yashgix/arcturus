"""Offline integration of the supervised queue and API review over the existing task loop."""

from contextlib import nullcontext
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
from threading import Barrier
import time
import unittest

from test_arc_unit import gitc
from api_review import encode, mock_api_reviewer, read_review, wire_request
from concurrent_runs import Scheduler, SOURCE
from workers import WorkerFailure

NODE = shutil.which("node")


class ApiReviewCodec(unittest.TestCase):
    def test_deepseek_codec_does_not_enable_dispatch(self):
        wire = wire_request("deepseek", "fixture-only", {"candidate": "abc"}, 64)
        self.assertEqual(wire["response_format"], {"type": "json_object"})
        self.assertEqual(wire["thinking"], {"type": "disabled"})

        def no_transport(_):
            self.fail("blocked DeepSeek transport was reached")

        with self.assertRaisesRegex(WorkerFailure, "approved API scheduler"):
            mock_api_reviewer("deepseek", "fixture-only", no_transport, nullcontext)

    def test_openai_rejects_model_drift_refusal_and_extreme_usage(self):
        def result(**overrides):
            return {
                "model": "pinned",
                "choices": [{"finish_reason": "stop", "message": {"content": "{}"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
            } | overrides

        self.assertEqual(read_review("openai", "pinned", encode(result()), 64), ({}, 12))
        variants = [
            result(model="alias"),
            result(usage={"prompt_tokens": True, "completion_tokens": 1, "total_tokens": 2}),
            result(usage={"prompt_tokens": 10, "completion_tokens": 65, "total_tokens": 75}),
            result(usage={"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 13}),
            result(choices=[{"finish_reason": "stop", "message": {"content": "{}", "refusal": "declined"}}]),
            result(choices=[{"finish_reason": "length", "message": {"content": "{}"}}]),
        ]
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(WorkerFailure):
                read_review("openai", "pinned", encode(variant), 64)
        for raw in (b'{"usage":' + b'9' * 5000 + b'}', b'{"model":"pinned","model":"pinned"}'):
            with self.assertRaises(WorkerFailure):
                read_review("openai", "pinned", raw, 64)

    def test_anthropic_counts_cache_tokens_and_rejects_tool_use(self):
        result = {
            "model": "pinned",
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "{}"}],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 2,
                "cache_read_input_tokens": 4,
                "cache_creation_input_tokens": 3,
            },
        }
        self.assertEqual(read_review("anthropic", "pinned", encode(result), 64), ({}, 19))
        result["content"].insert(0, {"type": "thinking", "thinking": "ignored"})
        self.assertEqual(read_review("anthropic", "pinned", encode(result), 64), ({}, 19))
        with self.assertRaises(WorkerFailure):
            read_review("anthropic", "pinned", encode(result | {"stop_reason": "tool_use"}), 64)


class QueueLimits(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.queue = Scheduler(tmp.name)
        self.queue.initialize(2, 200, {"a": (1, 100), "b": (2, 200)})

    def test_round_robin_and_project_and_global_slot_limits(self):
        a1, a2 = (self.queue.enqueue("a", "clean", 100) for _ in range(2))
        b1, b2 = (self.queue.enqueue("b", "clean", 100) for _ in range(2))
        self.assertEqual(self.queue.claim()["id"], a1)
        self.assertEqual(self.queue.claim()["id"], b1)
        self.assertIsNone(self.queue.claim())
        self.queue.finish(b1, "done")
        self.assertEqual(self.queue.claim()["id"], b2)
        self.queue.finish(a1, "done")
        self.assertEqual(self.queue.claim()["id"], a2)

    def test_reserves_enforce_both_caps_and_hold_on_failure(self):
        a = self.queue.enqueue("a", "clean", 100)
        b = self.queue.enqueue("b", "clean", 100)
        self.queue.claim()
        self.queue.claim()
        args = ("openai", "mock-model", "commit", "digest")
        with self.assertRaisesRegex(ValueError, "after dispatch"):
            with self.queue.reserve(a, "s1", *args):
                raise ValueError("after dispatch")
        with self.assertRaisesRegex(WorkerFailure, "ceiling"):
            with self.queue.reserve(a, "s2", *args):
                self.fail("project reserve exceeded")
        with self.queue.reserve(b, "s3", *args):
            pass
        with self.assertRaisesRegex(WorkerFailure, "ceiling"):
            with self.queue.reserve(b, "s4", *args):
                self.fail("global reserve exceeded")
        ledger = self.queue.status()["api_review"]
        self.assertEqual(
            [(r["session"], r["state"], r["reserve_microusd"]) for r in ledger],
            [("s1", "failed", 100), ("s3", "response_received", 100)],
        )

    def test_simultaneous_reservations_cannot_overbook_global_cap(self):
        ids = [self.queue.enqueue(project, "clean", 100 if project == "a" else 200) for project in ("a", "b")]
        self.queue.claim()
        self.queue.claim()
        start = Barrier(2, timeout=5)

        def reserve(job):
            start.wait()
            try:
                with self.queue.reserve(job, f"session-{job}", "openai", "mock", "commit", "digest"):
                    return True
            except WorkerFailure:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(pool.map(reserve, ids), [True, False])
        self.assertEqual(len(self.queue.status()["api_review"]), 1)


@unittest.skipUnless(NODE, "mock engineering requires an installed Node with permission mode")
class SupervisedConcurrentDemo(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.queue = Scheduler(self.root)
        self.queue.initialize(2, 300, {"project-a": (1, 200), "project-b": (1, 100)})
        self.a = self.queue.enqueue("project-a", "repair", 100)
        self.b = self.queue.enqueue("project-b", "clean", 100)
        self.a_work = self.queue.workspace(self.a)
        self.b_work = self.queue.workspace(self.b)
        self.a_work.mkdir()
        (self.a_work / "hold-review").touch()

    def supervise(self):
        proc = subprocess.Popen(
            [sys.executable, "-B", str(SOURCE / "concurrent_runs.py"), str(self.root), "run", "--node", NODE],
            stdin=subprocess.DEVNULL,
        )

        def cleanup():
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)

        self.addCleanup(cleanup)
        return proc

    def wait_until(self, predicate):
        end = time.monotonic() + 25
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(0.05)
        logs = {
            p.name: (p / "output.log").read_text() for p in (self.a_work, self.b_work) if (p / "output.log").is_file()
        }
        self.fail(f"expected state not reached: {self.queue.status()!r}, logs={logs!r}")

    def test_two_projects_overlap_and_findings_trigger_a_new_candidate(self):
        self.queue.control("pause", "project-b")
        (self.a_work / "hold-repair").touch()
        proc = self.supervise()
        self.wait_until(lambda: (self.a_work / "mock-request-1.json").exists())
        (self.a_work / "release-review").touch()
        self.wait_until(lambda: (self.a_work / "repair-started").exists())
        self.queue.control("resume", "project-b")
        self.wait_until(lambda: self.queue.job(self.b)["state"] == "ready")
        self.assertEqual(self.queue.job(self.a)["state"], "running")
        (self.a_work / "release-repair").touch()
        self.assertEqual(proc.wait(timeout=25), 0)
        status = self.queue.status()
        a, b = status["job"]
        self.assertEqual([(row["state"], row["checkpoint"]["repairs"]) for row in (a, b)], [("ready", 1), ("ready", 0)])
        first, repaired = [row for row in status["api_review"] if row["job"] == self.a]
        self.assertLess(first["started"], first["finished"])
        self.assertLess(first["finished"], b["started"])
        self.assertLess(b["finished"], repaired["started"])
        self.assertNotEqual(first["candidate"], repaired["candidate"])
        self.assertEqual(repaired["candidate"], a["checkpoint"]["candidate"])
        for job, work, peer in ((a, self.a_work, "project-b"), (b, self.b_work, "project-a")):
            receipt = job["checkpoint"]
            self.assertEqual(gitc(work / "repo", "rev-parse", "main"), receipt["base"])
            self.assertEqual(gitc(work / "repo", "rev-parse", "HEAD"), receipt["candidate"])
            (task,) = json.loads(Path(receipt["journal"]).read_text())["tasks"].values()
            reviews = [entry for entry in status["api_review"] if entry["job"] == job["id"]]
            self.assertEqual(
                [entry["session"] for entry in task["dispatches"] if entry["role"] == "reviewer"],
                [entry["session"] for entry in reviews],
            )
            if job["id"] == self.a:
                self.assertIn("Preserve zero", task["dispatches"][2]["findings"][0]["issue"])
                self.assertEqual(task["history"][0]["candidate"], first["candidate"])
            for n, review in enumerate(reviews, 1):
                body = (work / f"mock-request-{n}.json").read_bytes()
                self.assertEqual(hashlib.sha256(body).hexdigest(), review["request_sha256"])
                self.assertNotIn(peer.encode(), body)
                self.assertNotIn(str(work).encode(), body)
                packet = json.loads(json.loads(body)["messages"][-1]["content"])
                self.assertEqual(packet["candidate"], review["candidate"])
                for name, evidence in packet["evidence"].items():
                    self.assertEqual(hashlib.sha256(evidence["text"].encode()).hexdigest(), evidence["sha256"])
                    if name.endswith("-probe.json"):
                        self.assertEqual(
                            json.loads(evidence["text"])["peer_access"],
                            [{"read": "ERR_ACCESS_DENIED", "write": "ERR_ACCESS_DENIED"}],
                        )
        plan = self.queue.prepare_trial(self.b)
        self.assertEqual(plan["dispatch"], "blocked")
        self.assertEqual(plan["candidate"], b["checkpoint"]["candidate"])
        self.assertEqual(plan["body_sha256"], hashlib.sha256(plan["body_utf8"].encode()).hexdigest())
        self.assertEqual(plan["illustrative_reserve_microusd"], 528_128)
        self.assertIsNone(plan["actual_charge_microusd"])
        self.assertEqual(
            plan["plan_sha256"],
            hashlib.sha256(encode({key: value for key, value in plan.items() if key != "plan_sha256"})).hexdigest(),
        )
        self.assertEqual(len(self.queue.status()["api_review"]), 3)
        (self.b_work / "mock-request-1.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "integrity"):
            self.queue.prepare_trial(self.b)

    def test_supervisor_sigkill_preserves_inflight_reserve_and_resumes_queued_project(self):
        self.queue.control("pause", "project-b")
        proc = self.supervise()
        self.wait_until(lambda: (self.a_work / "mock-request-1.json").exists())
        (first,) = self.queue.status()["api_review"]
        self.assertEqual(first["state"], "running")
        proc.kill()
        self.assertEqual(proc.wait(timeout=5), -signal.SIGKILL)
        self.queue.control("resume", "project-b")
        self.assertEqual(self.supervise().wait(timeout=25), 0)
        status = self.queue.status()
        self.assertEqual([job["state"] for job in status["job"]], ["interrupted", "ready"])
        old, new = status["api_review"]
        self.assertEqual((old["session"], old["state"], old["reserve_microusd"]), (first["session"], "uncertain", 100))
        self.assertEqual((new["job"], new["state"]), (self.b, "response_received"))
        self.assertEqual(self.supervise().wait(timeout=10), 0)
        self.assertEqual(self.queue.status(), status)
        self.assertFalse((self.a_work / "mock-request-2.json").exists())

    def test_cancel_kills_active_review_and_keeps_other_project_available(self):
        proc = self.supervise()
        self.wait_until(lambda: (self.a_work / "mock-request-1.json").exists())
        self.queue.control("cancel", self.a)
        self.assertEqual(proc.wait(timeout=25), 0)
        status = self.queue.status()
        self.assertEqual([job["state"] for job in status["job"]], ["cancelled", "ready"])
        self.assertEqual([row["state"] for row in status["api_review"] if row["job"] == self.a], ["uncertain"])
        self.assertFalse((self.a_work / "mock-request-2.json").exists())
