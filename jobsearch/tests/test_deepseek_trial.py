"""Offline contract and billing checks for the proposed DeepSeek trial."""

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from jobsearch import deepseek_trial as trial


def response(**changes):
    return json.dumps(
        {
            "model": "deepseek-flash",
            "choices": [{"finish_reason": "stop", "message": {"content": '{"ok":true}'}}],
            "usage": {
                "prompt_tokens": 101,
                "prompt_cache_hit_tokens": 1,
                "prompt_cache_miss_tokens": 100,
                "completion_tokens": 9,
                "total_tokens": 110,
            },
        }
        | changes
    ).encode()


class DeepSeekTrialTests(unittest.TestCase):
    def test_plan_is_blocked_and_rounds_peak_allowance_up(self):
        plan = trial.plan()
        self.assertEqual(plan["dispatch"], "blocked")
        self.assertIsNone(plan["immutable_model_id"])
        self.assertIsNone(plan["proposed_request"]["model"])
        self.assertEqual(plan["illustrative_reserve_microusd"], 314650)
        self.assertEqual(plan["timeout_seconds"], 30)
        self.assertEqual((plan["max_requests"], plan["automatic_retries"]), (1, 0))
        self.assertEqual(plan["proposed_request"]["max_tokens"], 64)
        self.assertEqual(plan["proposed_request"]["thinking"], {"type": "disabled"})

    def test_exact_token_usage_and_rate_estimates_are_not_actual_charge(self):
        receipt = trial.audit_response(200, response(actual_charge_nanousd=0))
        self.assertEqual(receipt["outcome"], "synthetic_output_valid_billing_unverified")
        self.assertEqual(receipt["usage"]["total_tokens"], 110)
        self.assertEqual(receipt["estimated_cost_nanousd"], {"off_peak": 20403, "peak": 40806})
        self.assertIsNone(receipt["actual_charge_nanousd"])
        self.assertEqual(receipt["retained_reserve_microusd"], trial.RESERVE_MICROUSD)

    def test_invalid_output_keeps_known_usage_and_excludes_response_text(self):
        for reason, content in (
            ("stop", "arbitrary sensitive prose"),
            ("length", '{"ok":true}'),
            ("stop", '{"ok":1}'),
            ("stop", "\ud800"),
        ):
            with self.subTest(reason=reason, content=content):
                receipt = trial.audit_response(
                    200,
                    response(
                        choices=[
                            {"finish_reason": reason, "message": {"content": content}},
                        ]
                    ),
                )
                self.assertEqual(receipt["outcome"], "invalid_response")
                self.assertEqual(receipt["usage"]["completion_tokens"], 9)
                self.assertEqual(receipt["estimated_cost_nanousd"]["peak"], 40806)
                self.assertNotIn("sensitive", json.dumps(receipt))

    def test_errors_and_malformed_bodies_keep_reserve(self):
        for status, body, outcome in (
            (None, b"", "transport_unverified"),
            (429, b'{"error":{"message":"secret"}}', "http_error"),
            (500, b"<html>", "http_error"),
            (200, b"{broken", "invalid_response"),
            (200, b"x" * (trial.MAX_OUTPUT + 1), "invalid_response"),
        ):
            with self.subTest(status=status, outcome=outcome):
                receipt = trial.audit_response(status, body)
                self.assertEqual(receipt["outcome"], outcome)
                self.assertIsNone(receipt["actual_charge_nanousd"])
                self.assertEqual(receipt["retained_reserve_microusd"], trial.RESERVE_MICROUSD)
                self.assertNotIn("secret", json.dumps(receipt))
        receipt = trial.audit_response(500, response())
        self.assertEqual(receipt["outcome"], "http_error")
        self.assertEqual(receipt["usage"]["total_tokens"], 110)

    def test_missing_inconsistent_or_wrong_model_usage_fails_closed(self):
        for usage in (
            None,
            {"total_tokens": 110},
            {
                "prompt_tokens": 101,
                "prompt_cache_hit_tokens": 0,
                "prompt_cache_miss_tokens": 100,
                "completion_tokens": 9,
                "total_tokens": 110,
            },
        ):
            with self.subTest(usage=usage):
                receipt = trial.audit_response(200, response(usage=usage))
                self.assertEqual(receipt["outcome"], "usage_unavailable")
                self.assertIsNone(receipt["estimated_cost_nanousd"])
        receipt = trial.audit_response(200, response(model="unapproved-model"))
        self.assertEqual(receipt["outcome"], "unexpected_model")
        self.assertEqual(receipt["usage"]["total_tokens"], 110)
        self.assertIsNone(receipt["estimated_cost_nanousd"])

    def test_out_of_bounds_usage_is_preserved_and_flagged(self):
        receipt = trial.audit_response(
            200,
            response(
                usage={
                    "prompt_tokens": 101,
                    "prompt_cache_hit_tokens": 1,
                    "prompt_cache_miss_tokens": 100,
                    "completion_tokens": 65,
                    "total_tokens": 166,
                }
            ),
        )
        self.assertEqual(receipt["outcome"], "token_bound_violation")
        self.assertEqual(receipt["usage"]["completion_tokens"], 65)
        self.assertEqual(receipt["dispatch"], "blocked")

    def test_malformed_optional_reasoning_preserves_all_core_usage(self):
        core = json.loads(response())["usage"]
        for details, field in (
            ({"reasoning_tokens": "nine"}, "usage.completion_tokens_details.reasoning_tokens"),
            ({"reasoning_tokens": True}, "usage.completion_tokens_details.reasoning_tokens"),
            ({"reasoning_tokens": 10}, "usage.completion_tokens_details.reasoning_tokens"),
            ({"reasoning_tokens": None}, "usage.completion_tokens_details.reasoning_tokens"),
            ([], "usage.completion_tokens_details"),
        ):
            with self.subTest(details=details):
                receipt = trial.audit_response(200, response(usage={**core, "completion_tokens_details": details}))
                self.assertEqual(receipt["outcome"], "invalid_response")
                self.assertEqual(receipt["usage"], core)
                self.assertEqual(receipt["usage_error"], field)
                self.assertEqual(receipt["estimated_cost_nanousd"]["peak"], 40806)
                self.assertIsNone(receipt["actual_charge_nanousd"])
                self.assertEqual(receipt["retained_reserve_microusd"], 314650)

    def test_extreme_usage_emits_serializable_cli_receipt(self):
        for digits in (4300, 5000):
            with self.subTest(digits=digits), TemporaryDirectory() as folder:
                # The first case can parse as an integer but overflow the JSON
                # integer digit limit when multiplied by a rate. The second
                # can hit the interpreter's limit during numeric parsing.
                number = b"9" * digits
                raw = (
                    b'{"model":"deepseek-flash","usage":{"prompt_tokens":'
                    + number
                    + b',"prompt_cache_hit_tokens":0,"prompt_cache_miss_tokens":'
                    + number
                    + b',"completion_tokens":0,"total_tokens":'
                    + number
                    + b"}}"
                )
                self.assertLess(len(raw), trial.MAX_OUTPUT)
                path = Path(folder) / "mock.json"
                path.write_bytes(raw)
                output = StringIO()
                with redirect_stdout(output):
                    self.assertEqual(trial.main(["audit", "--http-status", "200", "--response", str(path)]), 0)
                receipt = json.loads(output.getvalue())
                self.assertIn(receipt["outcome"], ("usage_unavailable", "invalid_response"))
                self.assertIsNone(receipt["usage"])
                self.assertIsNone(receipt["estimated_cost_nanousd"])
                self.assertIsNone(receipt["actual_charge_nanousd"])
                self.assertEqual(receipt["retained_reserve_microusd"], 314650)

    def test_usage_above_audit_bound_is_rejected_before_estimation(self):
        count = trial.MAX_AUDIT_COUNTER + 1
        receipt = trial.audit_response(
            200,
            response(
                usage={
                    "prompt_tokens": count,
                    "prompt_cache_hit_tokens": 0,
                    "prompt_cache_miss_tokens": count,
                    "completion_tokens": 0,
                    "total_tokens": count,
                }
            ),
        )
        self.assertEqual(receipt["outcome"], "usage_unavailable")
        self.assertEqual(receipt["usage_error"], "usage_counter_out_of_range")
        self.assertIsNone(receipt["estimated_cost_nanousd"])
        self.assertIsNone(receipt["actual_charge_nanousd"])
        self.assertEqual(receipt["retained_reserve_microusd"], 314650)
