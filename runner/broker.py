"""Model brokers for sandboxed code: one granted, tool-free model call per request.

The code runs as _arcexec with one loopback port and a one-run token; it never holds a key. Broker serves an
investigator: it fixes the system prompt and answer schema (pinned in the grant), checks every request against the
suite's incidents and limits on its own, reserves each call in the ledger before sending (llm.call), and records its
own transcript for the post-run audit. ExperimentBroker serves a project's experiment: the experiment writes its own
prompts, within the spec's models and caps, and a recorded run can be replayed without a provider. Any malformed
request stops the session for good: honest code never sends one."""

import hashlib
import hmac
import json
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import grant as grants
import llm
import providers
from api_review import encode
from gateway import SECRET, leaks
from research_reports import checkable

MAX_BODY = 300_000
MAX_PACKET = 250_000
STOP_WAIT = 30  # seconds stop waits for a cancelled call to end
REQUEST_KEYS = {"model", "incident", "turn", "packet"}
CALL_KEYS = {"model", "system", "input", "schema"}
MAX_SCHEMA = 20_000
MAX_RECORDING = 5_000_000
MAX_HANDLERS = 8
# An experiment call's output limit (at most the grant's) and per-read timeout: Flash writes about 215 tokens a
# second, so 16,000 tokens finish within 300 s.
EXPERIMENT_OUTPUT = 16_000
READ_SECONDS = 300
PACKET_KEYS = {"history", "now", "trigger"}
STOPPED = {
    "kind": "stopped",
    "action": None,
    "input_tokens": 0,
    "output_tokens": 0,
    "cost_microusd": 0,
    "latency_ms": 0,
}


class Refused(Exception):
    pass


def packet_sha256(packet):
    """The investigator's own packet hash: compact, sorted JSON."""
    return hashlib.sha256(json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class BoundedServer(ThreadingHTTPServer):
    """At most MAX_HANDLERS connections open at once; one more is closed unread."""

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.slots = threading.BoundedSemaphore(MAX_HANDLERS)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Broker:
    route = "/turn"
    server_class = ThreadingHTTPServer

    def __init__(self, ledger, company, incidents, limits, system, schema, keys, connection, transcript):
        self.ledger, self.company, self.incidents, self.limits = ledger, company, frozenset(incidents), limits
        self.system, self.schema, self.keys, self.connection = system, schema, keys, connection
        self.transcript = transcript
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.used = {}  # (model, incident) -> {"turn", "tokens", "ms"}
        self.lanes_stopped, self.stopped, self.calls, self.server = set(), None, 0, None
        self.closing = self.unfinished = self.security_stop = False
        self.on_security_stop = None  # called once, in its own thread, after a security stop
        self.active = self.socket = None  # the provider connection of the call in flight, and its socket
        self.clock = time.monotonic

    def forward(self, body):
        """The answer to one turn. Refused and SecurityStop end the session for good."""
        self.admit()
        try:
            if self.closing:
                self.stopped = self.stopped or "a turn arrived while the broker was closing"
            if self.stopped:
                raise Refused(self.stopped)
            try:
                return self.answer(body)
            except (Refused, llm.SecurityStop) as exc:
                self.stopped = str(exc)
                if isinstance(exc, llm.SecurityStop):
                    self.security_stop = True
                    self.ledger.control("stop")  # every lane, now
                    if self.on_security_stop:  # and the job itself, rather than at the end of its time limit
                        threading.Thread(target=self.on_security_stop, daemon=True).start()
                raise
        finally:
            self.lock.release()

    def admit(self):
        self.lock.acquire()

    def screen_answer(self, text):
        if leaks(text, list(self.keys.values())):
            raise llm.SecurityStop("a provider answer held credential-like text; it was not passed on")

    def settings(self, model):
        return dict(self.ledger.grant["models"][model])

    def check(self, body):
        if not isinstance(body, dict) or set(body) != REQUEST_KEYS:
            raise Refused(f"a turn has exactly the keys {sorted(REQUEST_KEYS)}")
        model, incident, n, packet = body["model"], body["incident"], body["turn"], body["packet"]
        if model not in self.ledger.grant["models"]:
            raise Refused("model is not in the grant")
        if incident not in self.incidents:
            raise Refused("incident is not in the pinned suite")
        if not isinstance(packet, dict) or set(packet) != PACKET_KEYS:
            raise Refused(f"a packet has exactly the keys {sorted(PACKET_KEYS)}")
        used = self.used.get((model, incident), {"turn": 0, "tokens": 0, "ms": 0})
        if type(n) is not int or n != used["turn"] + 1:
            raise Refused("turns must follow each other from 1")
        if n > self.limits["turns"] or used["tokens"] >= self.limits["tokens"] or used["ms"] >= self.limits["model_ms"]:
            raise Refused("the incident's turn, token or model-time limit is used up")
        raw = encode(packet)
        if len(raw) > MAX_PACKET:
            raise Refused("packet too large")
        if leaks(raw.decode(), list(self.keys.values())):
            raise llm.SecurityStop("packet holds credential-like text; nothing was sent")
        return model, incident, n, packet, used

    def answer(self, body):
        model, incident, n, packet, used = self.check(body)
        self.used[(model, incident)] = used = {**used, "turn": n}
        if model in self.lanes_stopped:
            self.record(model, incident, n, packet, dict(STOPPED), llm.Outcome("stopped", reason="lane stopped"))
            return dict(STOPPED)
        self.calls += 1
        start = self.clock()
        outcome, kind, usage = self.granted_call(
            f"{self.company}/{model}", f"investigate-{self.calls}", model, self.system, packet, self.schema
        )
        latency = round((self.clock() - start) * 1000)
        reply = {
            "kind": kind,
            "action": outcome.value if outcome.kind == "ok" else None,
            **usage,
            "latency_ms": latency,
        }
        used.update(tokens=used["tokens"] + reply["input_tokens"] + reply["output_tokens"], ms=used["ms"] + latency)
        self.record(model, incident, n, packet, reply, outcome)
        return reply

    def granted_call(self, lane, step, model, system, packet, schema):
        """One granted call: (outcome, kind, usage). An uncertain call stops its model for the rest of the run."""
        try:
            outcome = llm.call(
                self.ledger,
                lane,
                step,
                model,
                self.settings(model),
                system,
                packet,
                schema,
                self.keys[llm.PRICES[model].provider],
                self.connect,
                known=tuple(self.keys.values()),
            )
        except grants.GrantError as exc:
            raise Refused(f"grant refused the call: {exc}") from None
        finally:
            self.active = self.socket = None
        self.screen_answer(json.dumps([outcome.value, outcome.reason, outcome.response_id]))
        counts = outcome.usage or {"input": 0, "cached": 0, "output": 0}
        kind = "uncertain" if outcome.kind == "overrun" else outcome.kind
        if kind == "uncertain":
            self.lanes_stopped.add(model)
        usage = {
            "input_tokens": counts["input"] + counts["cached"],
            "output_tokens": counts["output"],
            "cost_microusd": outcome.charge or 0,
        }
        return outcome, kind if kind in ("ok", "truncated", "refused", "uncertain", "invalid") else "rejected", usage

    def connect(self, *args, **kwargs):
        """The provider connection for llm.call. Its socket is kept when it opens: http.client hands it to the
        response once headers arrive, so the connection alone no longer reaches it."""
        client = self.active = self.connection(*args, **kwargs)
        opened = getattr(client, "connect", None)
        if opened:

            def connect():
                opened()
                self.socket = client.sock
                if self.closing:
                    raise OSError("the broker is closing; nothing was sent")

            client.connect = connect
        return client

    def cancel(self):
        """Shut the socket of the call in flight: its read fails, so llm.call settles it uncertain with its reserve."""
        sock = self.socket
        if sock is not None:
            try:
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            except OSError:
                pass

    def record(self, model, incident, n, packet, reply, outcome):
        row = {
            "model": model,
            "incident": incident,
            "turn": n,
            "packet_sha256": packet_sha256(packet),
            **reply,
            "reason": outcome.reason or None,
            "response_id": outcome.response_id,
        }
        with open(self.transcript, "a") as file:
            file.write(json.dumps(row, sort_keys=True) + "\n")

    def start(self):
        broker = self

        class Handler(BaseHTTPRequestHandler):
            timeout = 30  # bounds reading a request

            def log_message(self, *_):
                pass

            def send_error(self, code, message=None, explain=None):
                # Unsupported methods and malformed HTTP land here; they end the session like any other refusal.
                self.refuse()

            def refuse(self):
                broker.stopped = broker.stopped or "unexpected request"
                self.send(
                    400,
                    {
                        "error": {
                            "type": "arcturus_broker_stop",
                            "message": "Arcturus broker stopped this session. Do not retry.",
                        }
                    },
                )

            def send(self, status, value):
                payload = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                self.refuse()

            def do_POST(self):
                expected = f"Bearer {broker.token}".encode()
                given = self.headers.get("Authorization", "").encode()
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if (
                        self.path != broker.route
                        or not hmac.compare_digest(given, expected)
                        or not 0 < length <= MAX_BODY
                    ):
                        raise Refused("unexpected route, token or size")
                    self.send(200, broker.forward(json.loads(self.rfile.read(length))))
                except Exception:
                    self.refuse()

        self.server = self.server_class(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self.server.server_address[1]

    def stop(self, wait=STOP_WAIT):
        """Close admission and the listener, cancel a call in flight and wait at most *wait* seconds for it to end.
        A cancelled or never-ending call makes the run unfinished; its reserve stays."""
        self.closing = True
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        deadline = time.monotonic() + wait
        while not self.lock.acquire(timeout=0.1):
            if self.active is not None:  # also retried while the call is still opening its connection
                self.unfinished = True
                self.cancel()
            if time.monotonic() >= deadline:
                self.unfinished = True
                return
        self.lock.release()


def keep_earlier(transcript):
    """A new recording starts empty; an interrupted earlier one stays as llm-calls.N.jsonl, the record of calls the
    ledger already charged."""
    if transcript.exists() and transcript.stat().st_size:
        n = 1 + sum(1 for _ in transcript.parent.glob(f"{transcript.stem}.*{transcript.suffix}"))
        transcript.rename(transcript.with_name(f"{transcript.stem}.{n}{transcript.suffix}"))
    transcript.write_text("")


class ExperimentBroker(Broker):
    """Calls an experiment declares in its spec ({"models", "max_calls", "max_usd"}), one at a time. The caps hold
    per spec, across sessions and restarts: they are counted from the ledger lane named after the spec's
    fingerprint. Recording, it appends every answered request to the transcript; replaying (from that transcript),
    it answers each request by its exact content, each recorded reply once, and never contacts a provider."""

    route = "/call"
    server_class = BoundedServer

    def __init__(
        self, ledger, company, fingerprint, declared, keys, connection, transcript, replay=False, budget_usd=0
    ):
        super().__init__(ledger, company, (), None, None, None, keys, connection, transcript)
        self.models, self.max_calls = frozenset(declared["models"]), declared["max_calls"]
        self.max_microusd = round(declared["max_usd"] * 1_000_000)
        self.lane = f"{company}/experiment-{fingerprint}"
        # New spending this session stays within what is left of the company's budget (each spec has its own caps).
        self.budget_microusd, self.spent_before = round(budget_usd * 1_000_000), ledger.committed(self.lane)
        self.recording, self.recorded = None, 0
        if replay:
            self.recording = {}
            for line in Path(transcript).read_text().splitlines():
                row = json.loads(line)
                self.recording.setdefault(row["request_sha256"], []).append(row["reply"])
        else:
            keep_earlier(Path(transcript))

    def admit(self):
        if not self.lock.acquire(blocking=False):
            self.stopped = self.stopped or "one call at a time"
            raise Refused("one call at a time")

    def settings(self, model):
        settings = super().settings(model)
        return {**settings, "max_output_tokens": min(EXPERIMENT_OUTPUT, settings["max_output_tokens"])}

    def check(self, body):
        if not isinstance(body, dict) or set(body) != CALL_KEYS:
            raise Refused(f"a call has exactly the keys {sorted(CALL_KEYS)}")
        model, system, packet, schema = body["model"], body["system"], body["input"], body["schema"]
        if model not in self.models or model not in self.ledger.grant["models"]:
            raise Refused("model is not both in the spec and in the grant")
        if not isinstance(system, str) or not isinstance(packet, dict):
            raise Refused("system is a string and input a JSON object")
        if not isinstance(schema, dict) or schema.get("type") != "object" or not checkable(schema):
            raise Refused("schema is an object schema the runner can check")
        if len(encode(schema)) > MAX_SCHEMA:
            raise Refused("schema too large")
        raw = encode(body)
        if len(raw) > MAX_PACKET:
            raise Refused("call too large")
        self.screen(raw.decode(), "call", "nothing was sent")
        return model, system, packet, schema, len(raw)

    def screen(self, text, what, outcome):
        """Experiment code and its answers are untrusted text: a real key in them stops every lane, text only shaped
        like a credential ends this session (else any experiment could halt the whole pipeline at will)."""
        if any(key in text for key in self.keys.values()):
            raise llm.SecurityStop(f"{what} holds a key; {outcome}")
        if SECRET.search(text):
            raise Refused(f"{what} holds credential-shaped text; {outcome}")

    def screen_answer(self, text):
        self.screen(text, "a provider answer", "it was not passed on")

    def answer(self, body):
        model, system, packet, schema, size = self.check(body)
        digest = packet_sha256(body)
        if self.recording is not None:
            if not self.recording.get(digest):
                raise Refused("call is not in the recording")
            return self.recording[digest].pop(0)
        if self.recorded + size > MAX_RECORDING:
            raise Refused("the recording is full")
        held = 0
        if model in self.lanes_stopped:
            reply = {"kind": "stopped", "value": None, "input_tokens": 0, "output_tokens": 0, "cost_microusd": 0}
        else:
            calls, estimate = self.within_caps(model, system, packet, schema)
            outcome, kind, usage = self.granted_call(
                self.lane, f"experiment-{calls + 1}", model, system, packet, schema
            )
            reply = {"kind": kind, "value": outcome.value if kind == "ok" else None, **usage}
            held = estimate if kind == "uncertain" and outcome.charge is None else 0
        line = (
            json.dumps(
                {"request_sha256": digest, "request": body, "reply": reply, "held_microusd": held}, sort_keys=True
            )
            + "\n"
        )
        with open(self.transcript, "a") as file:
            file.write(line)
        self.recorded += len(line.encode())
        return reply

    def within_caps(self, model, system, packet, schema):
        """(calls so far, next reserve) if the spec's caps allow one more call: the lane's calls, and its committed
        spend (uncertain calls at their full reserve) plus the next call's reserve, which is what llm.call takes."""
        calls = sum(row["lane"] == self.lane for row in self.ledger.rows())
        if calls >= self.max_calls:
            raise Refused("the spec's max_calls is used up")
        settings = self.settings(model)
        estimate = llm.reserve(
            model, encode(providers.request(model, settings, system, packet, schema)), settings["max_output_tokens"]
        )
        committed = self.ledger.committed(self.lane)
        if committed + estimate > self.max_microusd:
            raise Refused("the next call would pass the spec's max_usd")
        if committed - self.spent_before + estimate > self.budget_microusd:
            raise Refused("the next call would pass what is left of the company's budget")
        return calls, estimate

    def connect(self, *args, **kwargs):
        """The timeout bounds each socket read, not the whole call; the experiment's own time limit bounds that."""
        return super().connect(*args, **{**kwargs, "timeout": READ_SECONDS})
