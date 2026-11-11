"""One signed grant per workflow: checkpointed model steps with bounded, feedback-driven attempts."""

import fcntl
import html
import json
from pathlib import Path
import threading
import time

import grant as grants
import llm
from paid_review import load_key
import providers

CONCISE = "Your last answer was cut off at the output limit. Keep every field shorter and give fewer points."
PROVIDER_SLOTS = 3


THINKING_ONLY = "cut off with the whole output limit spent on reasoning"


def thinking_only(usage, limit):
    """A cut-off at the full limit with no answer text: asking again, even "concisely", fails the same way."""
    return bool(usage) and usage["output"] >= limit and usage.get("reasoning", 0) >= usage["output"]


class Stopped(Exception):
    pass


class Truncated(Exception):
    pass


def mismatch(value, schema, path="$"):
    """First place a value breaks its schema, in words a model can act on."""
    kind = schema["type"]
    if kind == "object":
        if not isinstance(value, dict) or value.keys() != schema["properties"].keys():
            return f"{path} must have exactly the keys {sorted(schema['properties'])}"
        return next((m for k, s in schema["properties"].items() if (m := mismatch(value[k], s, f"{path}.{k}"))), None)
    if kind == "array":
        if not isinstance(value, list) or not schema["minItems"] <= len(value) <= schema["maxItems"]:
            return f"{path} must be a list of {schema['minItems']} to {schema['maxItems']} items"
        return next((m for n, v in enumerate(value) if (m := mismatch(v, schema["items"], f"{path}[{n}]"))), None)
    if kind == "integer":
        ok = type(value) is int and schema["minimum"] <= value <= schema["maximum"]
        return None if ok else f"{path} must be an integer from {schema['minimum']} to {schema['maximum']}"
    if not isinstance(value, str) or not value.strip():
        return f"{path} must be a non-empty string"
    if "enum" in schema:
        return None if value in schema["enum"] else f"{path} must be one of {schema['enum']}"
    return (
        None
        if len(value) <= schema["maxLength"]
        else f"{path} is {len(value)} characters; the limit is {schema['maxLength']}"
    )


class Workflow:
    """Grant, ledger, keys, status page and the step loop shared by every workflow kind."""

    system = ""
    concise = CONCISE
    step_output = {}
    splittable = ()

    def __init__(self, root, connection=None, verify=True):
        self.root = Path(root)
        self.manifest = json.loads((self.root / "run.json").read_text())
        self.grant = grants.verified(self.root) if verify else json.loads((self.root / "grant.json").read_text())
        self.ledger = grants.Ledger(self.root / "ledger.sqlite", self.grant)
        self.connection = connection or llm.http.client.HTTPSConnection
        self.slots = {p: threading.Semaphore(PROVIDER_SLOTS) for p in set(providers.PROVIDER.values())}
        self.status, self.status_lock = {}, threading.Lock()
        self.keys = {}

    def lock(self):
        # One runner per grant: recover() must never relabel another runner's in-flight calls.
        self.lockfile = open(self.root / "runner.lock", "w")
        try:
            fcntl.flock(self.lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Stopped("another runner is already using this grant") from None
        self.ledger.recover()

    def key(self, provider):
        if provider not in self.keys:
            self.keys[provider] = load_key(self.manifest["keys"][provider], self.root)
        return self.keys[provider]

    def lane(self, company, provider):
        path = self.root / "lanes" / company["id"] / provider
        path.mkdir(parents=True, exist_ok=True)
        return path

    def note(self, company, provider, message):
        with self.status_lock:
            self.status[f"{company['id']}/{provider}"] = {"message": message, "at": time.time()}
        write_status(self)

    def gate(self):
        while (state := self.ledger.state()) == "pause":
            time.sleep(5)
        if state != "run":
            raise Stopped(f"grant {state}")
        grants.verified(self.root)

    def cutoffs(self, company, provider, name, model):
        """The usage of this model's cut-off answers to this step: another model taking over starts fresh."""
        key = (f"{company['id']}/{provider}", name, model, "truncated")
        return [
            json.loads(r["usage"] or "{}")
            for r in self.ledger.rows()
            if (r["lane"], r["step"], r["model"], r["state"]) == key
        ]

    def step(self, company, provider, name, model, packet, schema, check):
        """One checkpointed step: bounded attempts with feedback; Truncated is left to the caller to split."""
        lane = self.lane(company, provider)
        done = lane / f"{name}.json"
        if done.exists():
            return json.loads(done.read_text())
        granted = self.grant["models"][model]["max_output_tokens"]
        settings = {
            **self.grant["models"][model],
            "max_output_tokens": min(self.step_output.get(name.split("-")[0], granted), granted),
        }
        feedback, log = None, []
        # The cut-off rule survives a restart: the ledger remembers answers that were cut off.
        earlier = self.cutoffs(company, provider, name, model)
        cutoffs = len(earlier)
        if cutoffs > 1:
            if name.startswith(self.splittable):
                raise Truncated(name)
            (lane / f"{name}.failed.json").write_text(json.dumps({"log": [], "last_problems": ["cut off twice"]}))
            return None
        if not name.startswith(self.splittable) and any(thinking_only(u, granted) for u in earlier):
            (lane / f"{name}.failed.json").write_text(json.dumps({"log": [], "last_problems": [THINKING_ONLY]}))
            return None
        if cutoffs:
            settings["max_output_tokens"], feedback = granted, [self.concise]
        # A step that already failed under the enforced output format retries with JSON by instruction.
        settings["json_by_instruction"] = (lane / f"{name}.failed.json").exists() or model in self.manifest.get(
            "json_by_instruction", []
        )
        for attempt in range(self.grant["scope"]["attempts_per_step"]):
            self.gate()
            self.note(company, provider, f"{name} attempt {attempt + 1} on {model}")
            request = packet if feedback is None else {**packet, "fix_these_problems_from_your_last_attempt": feedback}
            account = providers.PROVIDER[model.split("-")[0]]
            with self.slots[account]:
                outcome = llm.call(
                    self.ledger,
                    f"{company['id']}/{provider}",
                    name,
                    model,
                    settings,
                    self.system,
                    request,
                    schema,
                    self.key(account),
                    self.connection,
                )
            log.append(
                {
                    "attempt": attempt + 1,
                    "kind": outcome.kind,
                    "reason": outcome.reason,
                    "charge_microusd": outcome.charge,
                    "usage": outcome.usage,
                    "fingerprint": outcome.fingerprint,
                }
            )
            if outcome.kind == "ok":
                feedback = check(outcome.value)
                if not feedback:
                    done.write_text(json.dumps(outcome.value, indent=1))
                    (lane / f"{name}.log.json").write_text(json.dumps(log, indent=1))
                    return outcome.value
                feedback = feedback[:25]
            elif outcome.kind == "truncated":
                # Each retry must change the request; a second cut-off ends the step (or splits it).
                cutoffs += 1
                full = settings["max_output_tokens"] == granted
                if name.startswith(self.splittable) and (full or cutoffs > 1):
                    (lane / f"{name}.log.json").write_text(json.dumps(log, indent=1))
                    raise Truncated(name)
                if cutoffs > 1:
                    break
                if full and thinking_only(outcome.usage, granted):
                    feedback = [THINKING_ONLY]
                    break
                if full:
                    feedback = [self.concise]
                else:
                    settings["max_output_tokens"] = granted
            elif outcome.kind == "invalid":
                where = mismatch(outcome.value, schema) if outcome.value is not None else None
                if feedback == [where or outcome.reason]:
                    settings["json_by_instruction"] = True
                feedback = [where or outcome.reason]
                log[-1]["reason"] = feedback[0]
                if outcome.value is not None:
                    (lane / f"{name}.invalid-{attempt + 1}.json").write_text(json.dumps(outcome.value, indent=1))
            elif outcome.kind != "uncertain":
                break
        (lane / f"{name}.log.json").write_text(json.dumps(log, indent=1))
        (lane / f"{name}.failed.json").write_text(json.dumps({"log": log, "last_problems": feedback}, indent=1))
        return None


def write_status(run):
    rows = run.ledger.rows()
    with run.status_lock:
        status = dict(run.status)
    lines = "".join(
        f"<tr><td>{html.escape(k)}</td><td>{html.escape(v['message'])}</td>"
        f"<td>{time.strftime('%H:%M:%S', time.localtime(v['at']))}</td></tr>"
        for k, v in sorted(status.items())
    )
    known = sum(r["charge"] or 0 for r in rows if r["state"] != "uncertain")
    held = sum(r["reserve"] for r in rows if r["state"] in ("uncertain", "reserved"))
    page = (
        f"<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=10><title>Arcturus run</title>"
        f"<style>body{{font:14px system-ui;margin:2em}}td,th{{padding:4px 10px;border-bottom:1px solid #ddd}}</style>"
        f"<h1>{html.escape(run.grant['id'])}: {html.escape(run.ledger.state())}</h1>"
        f"<p>{len(rows)} calls, ${known / 1e6:.4f} known, ${held / 1e6:.4f} held for uncertain or in-flight calls, "
        f"ceiling ${run.grant['ceiling_microusd'] / 1e6:.2f}.</p>"
        f"<table><tr><th>Lane</th><th>Now</th><th>At</th></tr>{lines}</table>"
    )
    (run.root / "status.html").write_text(page)
