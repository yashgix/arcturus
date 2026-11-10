"""Offline plan and receipt audit for the proposed one-request DeepSeek trial."""

import argparse
import json
import sys
from pathlib import Path

from .ashby import decode
from .research_model import MAX_OUTPUT

ENDPOINT = "https://api.deepseek.com/chat/completions"
API_ALIAS = "deepseek-flash"
DOCUMENTED_REVISION = "DeepSeek-V4.1-Flash-1017"
TIMEOUT_SECONDS = 30
MAX_COMPLETION_TOKENS = 64
# Planning allowance for the documented 1M-token context. The endpoint has
# no documented per-request input cap. This is not a provider spending limit.
PLANNING_PROMPT_TOKENS = 1_048_576
# The audit accepts headroom above the trial limits so ordinary overruns can
# still be reported. This separate bound limits arithmetic and JSON output.
MAX_AUDIT_COUNTER = 2 * PLANNING_PROMPT_TOKENS
# Nanodollars per token, in cache hit, cache miss, completion order.
PEAK_RATES = (6, 300, 1200)
OFF_PEAK_RATES = (3, 150, 600)
RESERVE_NANOUSD = PLANNING_PROMPT_TOKENS * PEAK_RATES[1] + MAX_COMPLETION_TOKENS * PEAK_RATES[2]
RESERVE_MICROUSD = (RESERVE_NANOUSD + 999) // 1000
USAGE_FIELDS = (
    "prompt_tokens",
    "prompt_cache_hit_tokens",
    "prompt_cache_miss_tokens",
    "completion_tokens",
    "total_tokens",
)


def plan():
    return {
        "dispatch": "blocked",
        "endpoint": ENDPOINT,
        "method": "POST",
        "immutable_model_id": None,
        "documented_alias": API_ALIAS,
        "documented_revision": DOCUMENTED_REVISION,
        "timeout_seconds": TIMEOUT_SECONDS,
        "automatic_retries": 0,
        "max_requests": 1,
        "planning_prompt_tokens": PLANNING_PROMPT_TOKENS,
        "illustrative_reserve_microusd": RESERVE_MICROUSD,
        "proposed_request": {
            "model": None,
            "messages": [
                {"role": "user", "content": 'Synthetic connectivity test. Reply with JSON {"ok":true}.'},
            ],
            "thinking": {"type": "disabled"},
            "max_tokens": MAX_COMPLETION_TOKENS,
            "stream": False,
            "response_format": {"type": "json_object"},
        },
    }


def _usage(envelope):
    usage = envelope.get("usage")
    if not isinstance(usage, dict):
        return None, None
    counts = {field: usage.get(field) for field in USAGE_FIELDS}
    if any(type(value) is not int for value in counts.values()):
        return None, None
    if any(not 0 <= value <= MAX_AUDIT_COUNTER for value in counts.values()):
        return None, "usage_counter_out_of_range"
    if (
        counts["prompt_tokens"] != counts["prompt_cache_hit_tokens"] + counts["prompt_cache_miss_tokens"]
        or counts["total_tokens"] != counts["prompt_tokens"] + counts["completion_tokens"]
    ):
        return None, None
    if "completion_tokens_details" in usage:
        details = usage["completion_tokens_details"]
        if not isinstance(details, dict):
            return counts, "usage.completion_tokens_details"
        if "reasoning_tokens" in details:
            reasoning = details["reasoning_tokens"]
            if type(reasoning) is not int or not 0 <= reasoning <= counts["completion_tokens"]:
                return counts, "usage.completion_tokens_details.reasoning_tokens"
            counts["reasoning_tokens"] = reasoning
    return counts, None


def audit_response(status, raw):
    """Return numeric metadata only. Do not retain provider prose or headers."""
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        raise ValueError("invalid HTTP status")
    receipt = {
        "http_status": status,
        "outcome": "invalid_response",
        "usage": None,
        "estimated_cost_nanousd": None,
        "actual_charge_nanousd": None,
        "retained_reserve_microusd": RESERVE_MICROUSD,
        "dispatch": "blocked",
    }
    if status is None:
        receipt["outcome"] = "transport_unverified"
        return receipt
    try:
        envelope = decode(raw) if len(raw) <= MAX_OUTPUT else None
    except ValueError:
        envelope = None
    if not isinstance(envelope, dict):
        if status != 200:
            receipt["outcome"] = "http_error"
        return receipt

    counts, usage_error = _usage(envelope)
    receipt["usage"] = counts
    if usage_error is not None:
        receipt["usage_error"] = usage_error
    known_alias = envelope.get("model") == API_ALIAS
    if counts is not None and known_alias:
        tokens = tuple(counts[key] for key in USAGE_FIELDS[1:4])
        receipt["estimated_cost_nanousd"] = {
            "off_peak": sum(count * rate for count, rate in zip(tokens, OFF_PEAK_RATES)),
            "peak": sum(count * rate for count, rate in zip(tokens, PEAK_RATES)),
        }
    if status != 200:
        receipt["outcome"] = "http_error"
    elif counts is None:
        receipt["outcome"] = "usage_unavailable"
    elif usage_error is not None:
        return receipt
    elif not known_alias:
        receipt["outcome"] = "unexpected_model"
    elif (
        counts["prompt_tokens"] > PLANNING_PROMPT_TOKENS
        or counts["completion_tokens"] > MAX_COMPLETION_TOKENS
        or counts.get("reasoning_tokens", 0)
    ):
        receipt["outcome"] = "token_bound_violation"
    else:
        try:
            (choice,) = envelope["choices"]
            if choice["finish_reason"] != "stop":
                return receipt
            answer = decode(choice["message"]["content"].encode("utf-8"))
            if isinstance(answer, dict) and set(answer) == {"ok"} and answer["ok"] is True:
                receipt["outcome"] = "synthetic_output_valid_billing_unverified"
        except (AttributeError, KeyError, TypeError, ValueError):
            pass
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("plan")
    audit = commands.add_parser("audit")
    audit.add_argument("--http-status", required=True, type=int)
    audit.add_argument("--response", required=True, type=Path, help="local mocked response")
    args = parser.parse_args(argv)
    if args.command == "plan":
        result = plan()
    else:
        try:
            with args.response.open("rb") as stream:
                result = audit_response(args.http_status, stream.read(MAX_OUTPUT + 1))
        except (OSError, ValueError):
            print("Offline audit input unavailable or invalid.", file=sys.stderr)
            return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
