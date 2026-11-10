"""Model broker for a sandboxed investigator: one granted, tool-free model call per turn.

The investigator runs as _arcexec with one loopback port and a one-run token; it never holds a key. The broker fixes
the system prompt and answer schema (pinned in the grant), checks every request against the suite's incidents and
limits on its own, reserves each call in the ledger before sending (llm.call), and records its own transcript for
the post-run audit. Any malformed request stops the session for good: an honest investigator never sends one."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import json
import secrets
import socket
import threading
import time

from api_review import encode
from gateway import leaks
import grant as grants
import llm

MAX_BODY = 300_000
MAX_PACKET = 250_000
STOP_WAIT = 30  # seconds stop waits for a cancelled call to end
REQUEST_KEYS = {"model", "incident", "turn", "packet"}
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


class Broker:
    def __init__(self, ledger, company, incidents, limits, system, schema, keys, connection, transcript):
        self.ledger, self.company, self.incidents, self.limits = ledger, company, frozenset(incidents), limits
        self.system, self.schema, self.keys, self.connection = system, schema, keys, connection
        self.transcript = transcript
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.used = {}  # (model, incident) -> {"turn", "tokens", "ms"}
        self.lanes_stopped, self.stopped, self.calls, self.server = set(), None, 0, None
        self.closing = self.unfinished = False
        self.active = self.socket = None  # the provider connection of the call in flight, and its socket
        self.clock = time.monotonic

    def forward(self, body):
        """The answer to one turn. Refused and SecurityStop end the session for good."""
        with self.lock:
            if self.closing:
                self.stopped = self.stopped or "a turn arrived while the broker was closing"
            if self.stopped:
                raise Refused(self.stopped)
            try:
                return self.answer(body)
            except (Refused, llm.SecurityStop) as exc:
                self.stopped = str(exc)
                raise

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
        try:
            outcome = llm.call(
                self.ledger,
                f"{self.company}/{model}",
                f"investigate-{self.calls}",
                model,
                dict(self.ledger.grant["models"][model]),
                self.system,
                packet,
                self.schema,
                self.keys[llm.PRICES[model].provider],
                self.connect,
                known=tuple(self.keys.values()),
            )
        except grants.GrantError as exc:
            raise Refused(f"grant refused the call: {exc}") from None
        finally:
            self.active = self.socket = None
        if leaks(json.dumps([outcome.value, outcome.reason, outcome.response_id]), list(self.keys.values())):
            raise llm.SecurityStop("a provider answer held credential-like text; it was not passed on")
        latency = round((self.clock() - start) * 1000)
        counts = outcome.usage or {"input": 0, "cached": 0, "output": 0}
        kind = "uncertain" if outcome.kind == "overrun" else outcome.kind
        reply = {
            "kind": kind if kind in ("ok", "truncated", "refused", "uncertain", "invalid") else "rejected",
            "action": outcome.value if outcome.kind == "ok" else None,
            "input_tokens": counts["input"] + counts["cached"],
            "output_tokens": counts["output"],
            "cost_microusd": outcome.charge or 0,
            "latency_ms": latency,
        }
        used.update(tokens=used["tokens"] + reply["input_tokens"] + reply["output_tokens"], ms=used["ms"] + latency)
        if kind == "uncertain":
            self.lanes_stopped.add(model)
        self.record(model, incident, n, packet, reply, outcome)
        return reply

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
                    if self.path != "/turn" or not hmac.compare_digest(given, expected) or not 0 < length <= MAX_BODY:
                        raise Refused("unexpected route, token or size")
                    self.send(200, broker.forward(json.loads(self.rfile.read(length))))
                except Exception:
                    self.refuse()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
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
