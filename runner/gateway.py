"""Local Responses API gateway for a coding agent. Every upstream call is shape-checked, reserved against the grant
ledger first and settled from the provider's own usage; the agent only ever holds a one-session local token."""

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import secrets
import threading

from api_review import encode
import llm
from paid_review import contains_credential

UPSTREAM = {"deepseek": ("api.deepseek.com", "/responses")}
MAX_STREAM = 32_000_000
# What the agent may set; everything spending-relevant is overwritten from the grant.
ALLOWED = {
    "model",
    "input",
    "instructions",
    "tools",
    "tool_choice",
    "reasoning",
    "text",
    "stream",
    "parallel_tool_calls",
    "max_output_tokens",
    "store",
    "include",
    "prompt_cache_key",
}
NON_TEXT = {
    "input_image",
    "input_file",
    "input_audio",
    "web_search_call",
    "file_search_call",
    "computer_call",
    "item_reference",
}
# Credential shapes that must never leave the Mac, e.g. another process's environment read by an agent.
SECRET = re.compile(
    r"sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[abpr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----|[A-Z0-9_]*(?:TOKEN|SECRET|API_KEY|PASSWORD)=[^\s\"']{8,}"
)


class Refused(Exception):
    pass


def non_text(value):
    if isinstance(value, dict):
        return value.get("type") in NON_TEXT or any(non_text(v) for v in value.values())
    return isinstance(value, list) and any(non_text(v) for v in value)


def leaks(text, known):
    """True if outbound text holds a known key or anything shaped like a credential."""
    return any(key in text for key in known) or bool(SECRET.search(text))


def strings(value):
    """Every string in a JSON value, keys included, decoded as the provider will read it."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def packet_leaks(packet, known):
    """leaks() on a packet's decoded text: JSON escapes such as \\n must not join a name and the next line."""
    return leaks("\n".join(strings(json.loads(json.dumps(packet)))), known)


def admit(body, model, settings):
    """The exact body sent upstream, or Refused."""
    if not isinstance(body, dict) or body.get("model") != model:
        raise Refused("model is not the granted builder")
    if set(body) - ALLOWED:
        raise Refused(f"unsupported request fields {sorted(set(body) - ALLOWED)}")
    if any(not isinstance(t, dict) or t.get("type") != "function" for t in body.get("tools", [])):
        raise Refused("only local function tools are allowed")
    if non_text(body.get("input")):
        raise Refused("only text input is allowed")
    wire = {k: v for k, v in body.items() if k not in ("include", "prompt_cache_key", "store")}
    return {
        **wire,
        "max_output_tokens": settings["max_output_tokens"],
        "reasoning": {"effort": settings["effort"]},
        "store": False,
    }


def final_response(content_type, raw):
    """The terminal response object of a JSON body or an event stream."""
    if "text/event-stream" not in content_type:
        return json.loads(raw)
    final = None
    for line in raw.splitlines():
        if line.startswith(b"data: ") and line[6:].strip() != b"[DONE]":
            event = json.loads(line[6:])
            if event.get("type") in ("response.completed", "response.incomplete", "response.failed"):
                final = event["response"]
    if final is None:
        raise ValueError("stream ended without a final response")
    return final


class Gateway:
    def __init__(self, ledger, lane, prefix, model, settings, key, known, connection=http.client.HTTPSConnection):
        self.ledger, self.lane, self.prefix, self.model, self.settings = ledger, lane, prefix, model, settings
        self.key, self.known, self.connection = key, known, connection
        self.provider = llm.PRICES[model].provider
        self.token = secrets.token_urlsafe(32)
        self.lock, self.calls, self.stopped, self.error = threading.Lock(), 0, None, None
        self.server = None

    def forward(self, body):
        """(status, content type, payload) for one agent request. Any refusal stops the session for good."""
        with self.lock:
            if self.stopped:
                raise Refused(self.stopped)
            try:
                return self.send(body)
            except Exception as exc:
                self.stopped = str(exc) if isinstance(exc, (Refused, llm.SecurityStop)) else type(exc).__name__
                self.error = exc
                raise

    def send(self, body):
        wire = admit(body, self.model, self.settings)
        raw = encode(wire)
        if len(raw) > llm.MAX_BODY:
            raise Refused("request too large")
        if packet_leaks(wire, self.known):
            raise llm.SecurityStop("agent request holds credential-like text; nothing was sent")
        amount = llm.reserve(self.model, raw, self.settings["max_output_tokens"])
        self.calls += 1
        call = self.ledger.reserve(self.lane, f"{self.prefix}-{self.calls}", self.model, amount)
        accept = "text/event-stream" if wire.get("stream") else "application/json"
        try:
            status, payload = llm.post(
                self.provider, raw, self.key, self.connection, UPSTREAM[self.provider], accept, MAX_STREAM
            )
        except llm.SecurityStop:
            self.ledger.settle(call, "uncertain", reason="credential echo")
            raise
        except (OSError, http.client.HTTPException) as exc:
            self.ledger.settle(call, "uncertain", reason=f"transport interrupted: {type(exc).__name__}")
            raise Refused("upstream transport interrupted; reserve retained") from None
        if status != 200:
            known = 400 <= status < 500 and status not in (408, 409)
            self.ledger.settle(
                call, "rejected" if known else "uncertain", charge=0 if known else None, reason=f"HTTP {status}"
            )
            raise Refused(f"upstream HTTP {status}")
        try:
            if len(payload) > MAX_STREAM or self.key.encode() in payload:
                raise llm.SecurityStop("oversized response or credential echo")
            reply = final_response(accept, payload)
            if contains_credential(reply, self.key) or not str(reply.get("model", "")).startswith(self.model):
                raise llm.SecurityStop(f"provider answered as {reply.get('model')!r}")
            usage = reply["usage"]
            cached = usage["input_tokens_details"]["cached_tokens"]
            counts = {
                "input": usage["input_tokens"] - cached,
                "cached": cached,
                "output": usage["output_tokens"],
                "reasoning": usage.get("output_tokens_details", {}).get("reasoning_tokens", 0),
            }
            charge = llm.cost(self.model, counts)
        except llm.SecurityStop:
            self.ledger.settle(call, "uncertain", reason="provider identity or credential check failed")
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            self.ledger.settle(call, "uncertain", reason=f"unverifiable accounting: {exc}")
            raise Refused("response accounting could not be verified; reserve retained") from None
        over = charge > amount or counts["output"] > self.settings["max_output_tokens"]
        self.ledger.settle(
            call,
            "received",
            charge=charge,
            usage=counts,
            response_id=reply.get("id"),
            reason="charge exceeded its reserve" if over else None,
        )
        if over:
            raise Refused("charge exceeded its reserve")
        return 200, accept, payload

    def start(self):
        gateway = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    if self.path != "/responses" or self.headers.get("Authorization") != f"Bearer {gateway.token}":
                        raise Refused("unexpected route or local token")
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= llm.MAX_BODY:
                        raise Refused("request too large")
                    status, kind, payload = gateway.forward(json.loads(self.rfile.read(length)))
                except Exception as exc:
                    gateway.stopped = gateway.stopped or type(exc).__name__
                    status, kind = 400, "application/json"
                    payload = encode(
                        {
                            "error": {
                                "type": "arcturus_gateway_stop",
                                "message": "Arcturus gateway stopped this session. Do not retry.",
                            }
                        }
                    )
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self.server.server_address[1]

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
