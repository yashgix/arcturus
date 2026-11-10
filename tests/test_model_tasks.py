import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runner"))

from api_review import (
    DEEPSEEK_PROBE_INPUT_ALLOWANCE,
    DEEPSEEK_PROBE_MAX_BYTES,
    DEEPSEEK_PROBE_PROFILE,
    LIVE_MODELS,
    encode,
    trial_plan,
)
from concurrent_runs import Scheduler
import paid_review


KEY = "fixture-secret-for-api-routing"
FINGERPRINT = "fixture-fingerprint"


class FakeHTTPS:
    status = 200

    def __init__(self, host, *, port, timeout, context):
        self.provider = {"api.deepseek.com": "deepseek", "api.openai.com": "openai", "api.anthropic.com": "anthropic"}[
            host
        ]
        assert port == 443 and timeout == 30 and context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        self.mode = (Path.cwd() / "mode").read_text() if (Path.cwd() / "mode").exists() else "ok"

    def request(self, method, path, *, body, headers):
        assert (
            method == "POST"
            and path
            == {"deepseek": "/chat/completions", "anthropic": "/v1/messages", "openai": "/v1/responses"}[self.provider]
        )
        assert KEY.encode() not in body
        assert headers.get("x-api-key" if self.provider == "anthropic" else "authorization") == (
            KEY if self.provider == "anthropic" else f"Bearer {KEY}"
        )
        with (Path.cwd() / "sent").open("xb") as file:
            file.write(body)
        if self.mode == "transport":
            raise OSError(f"mock failure {KEY}")
        if self.mode == "cancel":
            time.sleep(60)
        self.wire = json.loads(body)
        payload = self.wire["input"] if self.provider == "openai" else self.wire["messages"][-1]["content"]
        self.role = json.loads(payload)["task"]
        assert "tools" not in self.wire and self.wire["stream"] is False
        if self.provider == "deepseek":
            assert self.wire["thinking"] == {"type": "disabled"}
            assert self.wire["response_format"] == {"type": "json_object"}
            assert self.wire["max_tokens"] == (64 if self.role == "probe" else 1536)
        if self.mode == "redirect":
            self.status = 302
        if self.mode == "limited":
            self.status = 429

    def getresponse(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def close(self):
        pass

    def read(self, _):
        assert self.mode not in {"redirect", "limited"}
        value = (
            {"ok": True}
            if self.role == "probe"
            else {"items": [{"text": "Fixture finding", "source_ids": ["source-a"]}]}
        )
        if self.mode == "citation":
            value["items"][0]["source_ids"] = ["unknown"]
        text = {"bad_json": "{", "duplicate": '{"ok":true,"ok":true}', "echo": json.dumps({"ok": KEY})}.get(
            self.mode, encode(value).decode()
        )
        model = self.wire["model"]
        if self.provider == "anthropic":
            return encode(
                {
                    "model": model,
                    "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": text}],
                    "usage": {"input_tokens": 128, "output_tokens": 16},
                }
            )
        if self.provider == "openai":
            return encode(
                {
                    "model": model,
                    "status": "completed",
                    "service_tier": "default",
                    "output": [
                        {
                            "type": "message",
                            "status": "completed",
                            "role": "assistant",
                            "content": [{"type": "output_text", "text": text}],
                        }
                    ],
                    "usage": {
                        "input_tokens": 128,
                        "output_tokens": 16,
                        "total_tokens": 144,
                        "input_tokens_details": {"cached_tokens": 0},
                        "output_tokens_details": {"reasoning_tokens": 0},
                    },
                }
            )
        usage = {
            "prompt_tokens": 128,
            "completion_tokens": 16,
            "total_tokens": 144,
            "prompt_cache_hit_tokens": 8,
            "prompt_cache_miss_tokens": 120,
            "prompt_tokens_details": {"cached_tokens": 8},
        }
        if self.mode == "unknown_usage":
            usage.pop("prompt_cache_miss_tokens")
        if self.mode == "reasoning":
            usage["completion_tokens_details"] = {"reasoning_tokens": "bad"}
        if self.mode == "over_limit":
            usage.update(completion_tokens=65, total_tokens=193)
        if self.mode == "input_over_limit":
            usage.update(prompt_tokens=65_537, prompt_cache_miss_tokens=65_529, total_tokens=65_553)
        reply = {
            "id": "88beaa90-17fd-45fc-939c-2ef75e2d913c",
            "object": "chat.completion",
            "model": "deepseek-retired" if self.mode == "alias" else model,
            "system_fingerprint": "drifted" if self.mode == "drift" else FINGERPRINT,
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "length" if self.mode == "truncated" else "stop",
                    "message": {"role": "assistant", "content": text},
                }
            ],
            "usage": usage,
        }
        if self.mode == "huge":
            return encode(reply).replace(b'"prompt_tokens":128', b'"prompt_tokens":' + b"9" * 5000)
        if self.mode == "missing_fingerprint":
            reply.pop("system_fingerprint")
        if self.mode == "invalid_fingerprint":
            reply["system_fingerprint"] = "../untrusted"
        return encode(reply)


class ModelTasks(unittest.TestCase):
    def setUp(self):
        trust = patch("operator_approval.configured", return_value=False)
        trust.start()
        self.addCleanup(trust.stop)
        scratch = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name).resolve()
        self.queue = Scheduler(root / "schedule")
        self.queue.initialize(3, 20_000_000, {"fixture": (3, 20_000_000), "poor": (1, 10)})
        private = root / "private"
        private.mkdir(mode=0o700)
        self.key = private / "fixture-key"
        self.key.write_text(KEY + "\n")
        self.key.chmod(0o600)
        self.expires = int(time.time()) + 120

    def spec(self, role="probe", provider="deepseek", **kwargs):
        spec = {
            "project": "fixture",
            "provider": provider,
            "model": LIVE_MODELS[provider],
            "role": role,
            "data_class": "synthetic",
        }
        if role != "probe":
            spec.update(goal="Review synthetic source", sources={"source-a": "Synthetic excerpt."})
            if provider == "deepseek":
                spec["fingerprint"] = FINGERPRINT
        return {**spec, **kwargs}

    def enqueue(self, spec, mode="ok", offset=0):
        expiry = self.expires + offset
        plan = self.queue.prepare_model(spec, expiry)
        job = self.queue.approve_model(spec, expiry, plan["plan_sha256"])
        folder = self.queue.workspace(job)
        folder.mkdir()
        (folder / "mode").write_text(mode)
        return job, plan

    def run_fixture(self, providers=("deepseek",), stop=lambda: False):
        spawn = subprocess.Popen

        def inject(argv, **kwargs):
            assert Path(argv[2]).name == "paid_review.py"
            return spawn([*argv[:2], str(Path(__file__).resolve()), *argv[3:]], **kwargs)

        with patch("concurrent_runs.subprocess.Popen", side_effect=inject):
            self.queue.run(None, stop, dict.fromkeys(providers, str(self.key)))

    def test_fixed_probe_requires_exact_approval_and_is_durable_without_node(self):
        spec = self.spec()
        plan = self.queue.prepare_model(spec, self.expires)
        self.assertEqual(plan["illustrative_reserve_microusd"], 314_650)
        self.assertIsNone(plan["deepseek"]["expected_fingerprint"])
        self.assertIsNone(self.queue.claim(("deepseek",)))
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.queue.approve_model(spec, self.expires, "0" * 64)
        job, _ = self.enqueue(spec)
        self.assertIsNone(self.queue.claim(("openai", "anthropic")))
        self.run_fixture()
        state = self.queue.status()
        self.run_fixture()
        self.assertEqual(state, self.queue.status())
        receipt = json.loads(self.queue.approval(job)["receipt"])
        self.assertEqual(self.queue.job(job)["state"], "completed")
        self.assertEqual(receipt["result"], {"ok": True})
        self.assertEqual(receipt["provider_fingerprint"], FINGERPRINT)
        self.assertEqual(receipt["reserve_microusd"], 314_650)
        self.assertEqual(receipt["estimated_microusd"], 56)
        self.assertIsNone(receipt["actual_charge_microusd"])
        self.assertNotIn(KEY, str(state))
        with self.assertRaisesRegex(ValueError, "already queued"):
            self.queue.approve_model(spec, self.expires, plan["plan_sha256"])

    def test_research_and_planning_routing_and_policy(self):
        for spec in (
            self.spec(data_class="private"),
            self.spec(sources={"extra": "secret"}),
            self.spec(provider="openai"),
            self.spec("research", fingerprint=None),
            self.spec("planning", model="unreviewed"),
        ):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                self.queue.prepare_model(spec, self.expires)
        jobs = [
            self.enqueue(self.spec(role, provider))[0]
            for role, provider in (("research", "deepseek"), ("planning", "anthropic"), ("research", "openai"))
        ]
        self.run_fixture(tuple(LIVE_MODELS))
        self.assertEqual([self.queue.job(job)["state"] for job in jobs], ["completed"] * 3)
        for job in jobs:
            result = json.loads(self.queue.approval(job)["receipt"])["result"]
            self.assertEqual(result["items"][0]["source_ids"], ["source-a"])

    def test_bounded_probe_fits_ten_cents_and_records_verified_fingerprint(self):
        self.queue = Scheduler(self.queue.root.parent / "bounded")
        self.queue.initialize(1, 100_000, {"fixture": (1, 100_000)})
        spec = self.spec(probe_profile=DEEPSEEK_PROBE_PROFILE)
        plan = self.queue.prepare_model(spec, self.expires)
        self.assertEqual(plan["illustrative_reserve_microusd"], 19_738)
        self.assertEqual(plan["planning_input_tokens"], DEEPSEEK_PROBE_INPUT_ALLOWANCE)
        self.assertEqual(
            (plan["max_output_tokens"], plan["timeout_seconds"], plan["automatic_retries"], plan["max_requests"]),
            (64, 30, 0, 1),
        )
        raw = plan["body_utf8"].encode()
        self.assertTrue(raw.isascii())
        self.assertLessEqual(len(raw), DEEPSEEK_PROBE_MAX_BYTES)
        self.assertIsNone(self.queue.claim(("deepseek",)))
        job, _ = self.enqueue(spec)
        self.run_fixture()
        receipt = json.loads(self.queue.approval(job)["receipt"])
        self.assertEqual(self.queue.job(job)["state"], "completed")
        self.assertEqual(receipt["result"], {"ok": True})
        self.assertEqual(receipt["provider_fingerprint"], FINGERPRINT)
        self.assertEqual(receipt["reserve_microusd"], 19_738)
        self.assertIsNone(receipt["actual_charge_microusd"])
        state = self.queue.status()
        self.run_fixture()
        self.assertEqual(self.queue.status(), state)
        self.assertEqual(len(state["api_review"]), 1)

    def test_bounded_probe_rejects_prompt_expansion_and_profile_misuse(self):
        for spec in (
            self.spec(probe_profile="unknown"),
            self.spec("research", probe_profile=DEEPSEEK_PROBE_PROFILE),
            self.spec(probe_profile=DEEPSEEK_PROBE_PROFILE, goal="Other input"),
        ):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                self.queue.prepare_model(spec, self.expires)
        plan = self.queue.prepare_model(self.spec(probe_profile=DEEPSEEK_PROBE_PROFILE), self.expires)
        wire = json.loads(plan["body_utf8"])
        packet = json.loads(wire["messages"][1]["content"])
        from model_tasks import PROBE_INSTRUCTIONS, PROBE_SCHEMA

        for changes in (
            {"packet": {**packet, "extra": "injected"}},
            {"build_system": PROBE_INSTRUCTIONS + " Additional instruction"},
            {"build_system": "x" * (DEEPSEEK_PROBE_MAX_BYTES + 1)},
            {"build_schema": {"type": "string"}},
        ):
            arguments = dict(
                packet=packet,
                provider="deepseek",
                model=LIVE_MODELS["deepseek"],
                project="fixture",
                source_job=None,
                expires_at=self.expires,
                build_system=PROBE_INSTRUCTIONS,
                build_schema=PROBE_SCHEMA,
                model_task=plan["model_task"],
                data_class="synthetic",
            )
            arguments.update(changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "fixed ASCII"):
                trial_plan(**arguments)

    def test_bounded_probe_budget_and_invalid_receipts_fail_closed(self):
        poor = Scheduler(self.queue.root.parent / "bounded-poor")
        poor.initialize(1, 19_737, {"fixture": (1, 100_000)})
        self.queue, original = poor, self.queue
        job, _ = self.enqueue(self.spec(probe_profile=DEEPSEEK_PROBE_PROFILE))
        self.run_fixture()
        self.assertEqual(self.queue.job(job)["state"], "blocked")
        self.assertFalse((self.queue.workspace(job) / "sent").exists())
        self.assertIsNone(self.queue.approval(job)["consumed"])
        self.queue = original
        jobs = [
            self.enqueue(self.spec(probe_profile=DEEPSEEK_PROBE_PROFILE), mode, offset)[0]
            for offset, mode in enumerate(
                ("input_over_limit", "missing_fingerprint", "invalid_fingerprint", "truncated", "transport")
            )
        ]
        self.run_fixture()
        for job in jobs:
            with self.subTest(job=job):
                self.assertEqual(self.queue.job(job)["state"], "blocked")
                receipt = json.loads(self.queue.approval(job)["receipt"])
                self.assertEqual(receipt["reserve_microusd"], 19_738)
                self.assertIsNone(receipt["actual_charge_microusd"])
                self.assertNotIn("result", receipt)

    def test_failed_outputs_and_accounting_retain_full_reserve(self):
        modes = (
            "bad_json",
            "duplicate",
            "unknown_usage",
            "reasoning",
            "over_limit",
            "truncated",
            "alias",
            "huge",
            "echo",
            "redirect",
            "limited",
            "transport",
        )
        jobs = [(mode, self.enqueue(self.spec(), mode, n)[0]) for n, mode in enumerate(modes)]
        drift, _ = self.enqueue(self.spec("research"), "drift")
        citation, _ = self.enqueue(self.spec("planning"), "citation")
        self.run_fixture()
        for mode, job in jobs + [("drift", drift), ("citation", citation)]:
            with self.subTest(mode=mode):
                receipt = json.loads(self.queue.approval(job)["receipt"])
                self.assertEqual(self.queue.job(job)["state"], "blocked")
                self.assertEqual(receipt["state"], "uncertain" if mode == "transport" else "rejected")
                self.assertEqual(receipt["reserve_microusd"], 314_650 if mode in modes else 316_416)
                self.assertIsNone(receipt["actual_charge_microusd"])
                self.assertNotIn(KEY, str(receipt))
                self.assertNotIn("result", receipt)
                if mode in {"truncated", "citation", "bad_json", "duplicate"}:
                    self.assertIsNotNone(receipt["estimated_microusd"])
                if mode == "reasoning":
                    self.assertEqual(len(receipt["usage"]), 5)
                    self.assertIsNone(receipt["estimated_microusd"])
                if mode == "over_limit":
                    self.assertEqual(receipt["usage"]["output_tokens"], 65)
                    self.assertIsNone(receipt["estimated_microusd"])

    def test_budget_and_inflight_cancel_fence_replay(self):
        poor, _ = self.enqueue(self.spec(project="poor"))
        job, _ = self.enqueue(self.spec(), "cancel")
        work = self.queue.workspace(job)

        def cancel():
            if (work / "sent").exists() and not self.queue.job(job)["cancelled"]:
                self.queue.control("cancel", job)
            return False

        self.run_fixture(stop=cancel)
        self.assertEqual(self.queue.job(poor)["state"], "blocked")
        self.assertFalse((self.queue.workspace(poor) / "sent").exists())
        self.assertIsNone(self.queue.approval(poor)["consumed"])
        self.assertEqual(self.queue.job(job)["state"], "cancelled")
        receipt = json.loads(self.queue.approval(job)["receipt"])
        self.assertEqual((receipt["state"], receipt["reserve_microusd"]), ("uncertain", 314_650))
        state = self.queue.status()
        self.run_fixture()
        self.assertEqual(self.queue.status(), state)

    def test_global_ceiling_and_changed_plan_are_fenced_before_post(self):
        self.queue = Scheduler(self.queue.root.parent / "global-cap")
        self.queue.initialize(1, 314_650, {"fixture": (1, 1_000_000), "other": (1, 1_000_000)})
        first, _ = self.enqueue(self.spec())
        changed, _ = self.enqueue(self.spec(), offset=1)
        other, _ = self.enqueue(self.spec(project="other"))
        with self.queue.connect() as db:
            db.execute(
                "UPDATE review_approval SET plan=json_set(plan, '$.model_task.data_class', 'public') WHERE job=?",
                (changed,),
            )
        self.run_fixture()
        self.assertEqual(
            [self.queue.job(job)["state"] for job in (first, changed, other)], ["completed", "blocked", "blocked"]
        )
        self.assertFalse((self.queue.workspace(changed) / "sent").exists())
        self.assertFalse((self.queue.workspace(other) / "sent").exists())
        self.assertEqual(len(self.queue.status()["api_review"]), 1)


if __name__ == "__main__":
    if len(sys.argv) == 5:
        with patch("operator_approval.configured", return_value=False):
            paid_review.main(FakeHTTPS)
    else:
        unittest.main()
