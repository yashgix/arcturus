"""One granted, tool-free model call: build, send once, account, classify."""

from dataclasses import dataclass
import http.client
import re
import ssl

from api_review import ANTHROPIC_VERSION, LIVE_ENDPOINTS, decode, encode
from paid_review import contains_credential
import providers
from research_reports import shape

TIMEOUT = 600
MAX_RESPONSE = 4_000_000
MAX_BODY = 1_000_000
MAX_ERROR = 2000
# Headroom for prompt tokens a provider adds around the request (format grammar, role markers).
OVERHEAD_TOKENS = 8192


@dataclass(frozen=True)
class Price:
    """Nano-USD per token: input, cached input, output; optional (threshold, input, cached, output) long tier."""

    provider: str
    input: int
    cached: int
    output: int
    long: tuple = None

    def rates(self, prompt_tokens):
        if self.long and prompt_tokens > self.long[0]:
            return self.long[1:]
        return self.input, self.cached, self.output


# Checked 5 Nov 2026: platform.claude.com pricing, developers.openai.com pricing; DeepSeek per the pinned peak rates.
PRICES = {
    "claude-haiku-5-5": Price("anthropic", 100, 10, 500, (100_000, 500, 50, 2500)),
    "claude-sonnet-5-5": Price("anthropic", 2000, 100, 10000),
    "claude-opus-5-5": Price("anthropic", 4000, 200, 20000),
    "gpt-6-luna": Price("openai", 100, 10, 500, (272_000, 200, 20, 750)),
    "gpt-6-sol": Price("openai", 2000, 200, 10000, (272_000, 4000, 400, 15000)),
    "deepseek-flash": Price("deepseek", 300, 6, 1200),
    "deepseek-v4-pro": Price("deepseek", 1320, 44, 3960),
}


class SecurityStop(Exception):
    """Stops every lane: the provider identity or credential handling cannot be trusted."""


@dataclass
class Outcome:
    kind: str  # ok, truncated, invalid, refused, rejected, uncertain, overrun
    value: object = None
    reason: str = ""
    charge: int = None
    usage: dict = None
    response_id: str = None
    fingerprint: str = None


def microusd(nano):
    return -(-nano // 1000)


def reserve(model, body, max_output):
    # A token is at least one byte of request text, so byte length bounds the prompt.
    price = PRICES[model]
    prompt = len(body) + OVERHEAD_TOKENS
    rate_in, _, rate_out = price.rates(prompt)
    return microusd(prompt * rate_in + max_output * rate_out)


def post(provider, body, key, connection, endpoint=None, accept="application/json", maximum=MAX_RESPONSE):
    host, path = endpoint or LIVE_ENDPOINTS[provider]
    headers = {"content-type": "application/json", "accept": accept, "connection": "close"}
    if provider == "anthropic":
        headers.update({"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION})
    else:
        headers["authorization"] = f"Bearer {key}"
    client = connection(host, port=443, timeout=TIMEOUT, context=ssl.create_default_context())
    try:
        client.request("POST", path, body=body, headers=headers)
        with client.getresponse() as response:
            if any(key in str(value) for value in (response.reason, *dict(response.headers or {}).items())):
                raise SecurityStop("provider response echoed the credential")
            return response.status, response.read(maximum + 1 if response.status == 200 else MAX_ERROR)
    finally:
        client.close()


def same_model(answered, model):
    """The granted model itself or a dated snapshot of it; anything else is another model."""
    return (
        isinstance(answered, str)
        and re.fullmatch(re.escape(model) + r"(-\d{4}-\d{2}-\d{2}|-\d{8})?", answered) is not None
    )


def count(value):
    if type(value) is not int or value < 0:
        raise ValueError(f"usage count {value!r} is not a non-negative integer")
    return value


def checked(counts):
    """Usage counts after the invariants every provider's accounting must meet (cached above the prompt total shows
    up as negative fresh input)."""
    counts = {k: count(v) for k, v in counts.items()}
    if counts.get("reasoning", 0) > counts["output"]:
        raise ValueError("reasoning tokens exceed output tokens")
    return counts


def parse(provider, model, reply):
    """Return (stop, text, usage, response_id, fingerprint); raise ValueError if accounting is unverifiable."""
    if not same_model(reply.get("model"), model):
        raise SecurityStop(f"provider answered as {reply.get('model')!r}, not {model}")
    usage = reply["usage"]
    if provider == "anthropic":
        stop = reply["stop_reason"]
        text = "".join(block["text"] for block in reply["content"] if block["type"] == "text")
        counts = checked(
            {
                "input": count(usage["input_tokens"]) + count(usage.get("cache_creation_input_tokens", 0)),
                "cached": usage.get("cache_read_input_tokens", 0),
                "output": usage["output_tokens"],
            }
        )
        stop = {
            "end_turn": "ok",
            "max_tokens": "truncated",
            "model_context_window_exceeded": "truncated",
            "refusal": "refused",
        }.get(stop, stop)
        return stop, text, counts, reply.get("id"), None
    if provider == "openai":
        cached = count(usage["input_tokens_details"]["cached_tokens"])
        counts = checked(
            {
                "input": count(usage["input_tokens"]) - cached,
                "cached": cached,
                "output": usage["output_tokens"],
                "reasoning": usage["output_tokens_details"]["reasoning_tokens"],
            }
        )
        text = "".join(
            block.get("text", "")
            for item in reply["output"]
            if item["type"] == "message"
            for block in item["content"]
            if block["type"] == "output_text"
        )
        refused = any(
            block.get("type") == "refusal"
            for item in reply["output"]
            if item["type"] == "message"
            for block in item["content"]
        )
        stop = (
            "refused"
            if refused
            else "ok"
            if reply["status"] == "completed"
            else "truncated"
            if (reply.get("incomplete_details") or {}).get("reason") == "max_output_tokens"
            else reply["status"]
        )
        return stop, text, counts, reply.get("id"), None
    (choice,) = reply["choices"]
    hit = count(usage["prompt_cache_hit_tokens"])
    counts = checked(
        {
            "input": count(usage["prompt_tokens"]) - hit,
            "cached": hit,
            "output": usage["completion_tokens"],
            "reasoning": (usage.get("completion_tokens_details") or {}).get("reasoning_tokens", 0),
        }
    )
    stop = {"stop": "ok", "length": "truncated", "content_filter": "refused"}.get(
        choice["finish_reason"], choice["finish_reason"]
    )
    return stop, choice["message"].get("content") or "", counts, reply.get("id"), reply.get("system_fingerprint")


def cost(model, counts):
    rate_in, rate_cached, rate_out = PRICES[model].rates(counts["input"] + counts["cached"])
    return microusd(counts["input"] * rate_in + counts["cached"] * rate_cached + counts["output"] * rate_out)


def granted_shape(wire, model, settings, granted):
    """Spending-relevant invariants of any request body, whatever builds it."""
    if settings["max_output_tokens"] > granted["max_output_tokens"] or settings["effort"] != granted["effort"]:
        return "output limit or reasoning effort exceeds the grant"
    limit = wire.get("max_tokens", wire.get("max_output_tokens"))
    if wire.get("model") != model or limit != settings["max_output_tokens"]:
        return "request model or output limit differs from the grant"
    if wire.get("stream") or any(k in wire for k in ("tools", "tool_choice", "n", "background", "service_tier")):
        return "request asks for tools, streaming or a billing option outside the grant"
    return None


def holds(raw, known):
    return any(secret.encode() in raw for secret in known)


def call(
    ledger, lane, step, model, settings, system, packet, schema, key, connection=http.client.HTTPSConnection, known=()
):
    """One granted call. *known* lists every other credential the caller holds; an echo of any of them stops all."""
    provider = PRICES[model].provider
    known = (key, *known)
    wire = providers.request(model, settings, system, packet, schema)
    problem = granted_shape(wire, model, settings, ledger.grant["models"].get(model, settings))
    if problem:
        return Outcome("rejected", reason=problem)
    body = encode(wire)
    if len(body) > MAX_BODY:
        return Outcome("rejected", reason="request too large for one step; split it")
    amount = reserve(model, body, settings["max_output_tokens"])
    call_id = ledger.reserve(lane, step, model, amount)
    try:
        status, raw = post(provider, body, key, connection)
    except SecurityStop:
        ledger.settle(call_id, "uncertain", reason="credential echo")
        raise
    except (OSError, http.client.HTTPException) as exc:
        ledger.settle(call_id, "uncertain", reason=f"transport interrupted: {type(exc).__name__}")
        return Outcome("uncertain", reason="transport interrupted; reserve retained")
    if holds(raw, known):
        ledger.settle(call_id, "uncertain", reason="credential echo")
        raise SecurityStop("provider response echoed a credential")
    if status != 200:
        # Requests the provider refused up front are not billed; server errors may have been.
        known = 400 <= status < 500 and status not in (408, 409)
        detail = raw.decode(errors="replace")[:MAX_ERROR]
        ledger.settle(
            call_id,
            "rejected" if known else "uncertain",
            charge=0 if known else None,
            reason=f"HTTP {status} {detail}".strip(),
        )
        return Outcome("rejected" if known else "uncertain", reason=f"HTTP {status} {detail}".strip())
    try:
        reply = decode(raw, maximum=MAX_RESPONSE)
        if contains_credential(reply, key):
            raise SecurityStop("provider response echoed the credential")
        stop, text, counts, response_id, fingerprint = parse(provider, model, reply)
        charge = cost(model, counts)
        if charge > amount or counts["output"] > settings["max_output_tokens"]:
            ledger.settle(
                call_id,
                "received",
                charge=charge,
                usage=counts,
                response_id=response_id,
                reason="charge or output exceeded its reserve",
            )
            return Outcome("overrun", reason="charge or output exceeded its reserve", charge=charge, usage=counts)
    except SecurityStop:
        ledger.settle(call_id, "uncertain", reason="provider identity mismatch")
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        ledger.settle(call_id, "uncertain", reason=f"unverifiable accounting: {exc}")
        return Outcome("uncertain", reason="response accounting could not be verified; reserve retained")
    outcome = Outcome(
        stop if stop in ("ok", "truncated", "refused") else "invalid",
        charge=charge,
        usage=counts,
        response_id=response_id,
        fingerprint=fingerprint,
    )
    if outcome.kind == "ok":
        try:
            outcome.value = providers.json_object(text)
            if not shape(outcome.value, schema):
                raise ValueError("response does not match the step schema")
        except ValueError as exc:
            outcome.kind, outcome.reason = "invalid", str(exc)
    elif outcome.kind == "invalid":
        outcome.reason = f"provider stopped with {stop}"
    ledger.settle(
        call_id,
        "received" if outcome.kind == "ok" else outcome.kind,
        charge=charge,
        usage=counts,
        reason=outcome.reason or None,
        response_id=response_id,
    )
    return outcome
