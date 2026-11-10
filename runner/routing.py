"""Which model runs each pipeline step: the first one in the step's list (routing.json) that is up, covered by the
grant if it is an API model, and, for a plan, still under Yash's reserve line. Usage is read live from the plans."""

import json
import os
from pathlib import Path
import threading
import time

import providers
import subscriptions

PLANS = {"max", "codex"}
STALE = 600


def read(path):
    return json.loads(Path(path).read_text()) if Path(path).exists() else None


def write_json(path, value):
    """Replace the file in one step, so a reader in another thread never sees half of it."""
    temporary = Path(f"{path}.{threading.get_ident()}.tmp")
    temporary.write_text(json.dumps(value, indent=1))
    os.replace(temporary, path)


def plan(model):
    """'max:opus' -> 'max'; 'codex' -> 'codex'; an API model -> None."""
    name = model.split(":")[0]
    return name if name in PLANS else None


def provider(model):
    """Who serves a model: a reviewer from the builder's own provider is no independent check."""
    return {"max": "anthropic", "codex": "openai"}.get(plan(model)) or providers.PROVIDER[model.split("-")[0]]


class Router:
    def __init__(self, root, granted=None):
        self.root = Path(root)
        self.granted = granted  # API models the grant covers; None means all (tests and drafting the grant)
        self.lock = threading.Lock()
        self.usage = read(self.root / "usage.json") or {}
        self.down = {}  # plan or model -> epoch seconds until which it is skipped
        self.good = None

    def config(self):
        """Read on every choice, so Yash's edits apply at once; a file saved half-edited keeps the last good one."""
        try:
            self.good = read(self.root / "routing.json")
        except ValueError:
            if self.good is None:
                raise
        return self.good

    def record(self, name, windows):
        if not windows:
            return
        with self.lock:
            self.usage[name] = {"windows": windows, "at": time.time()}
            write_json(self.root / "usage.json", self.usage)
            with open(self.root / "usage.jsonl", "a") as log:
                log.write(json.dumps({"plan": name, "at": time.time(), "windows": windows}) + "\n")

    def mark_down(self, name, until=None):
        with self.lock:
            self.down[name] = until or time.time() + 900

    def under_line(self, name):
        snapshot = self.usage.get(name)
        if name == "codex" and (not snapshot or time.time() - snapshot["at"] > STALE):
            self.record("codex", subscriptions.codex_snapshot())
            snapshot = self.usage.get(name)
        if not snapshot:
            return True  # Max reports its usage with its first answer, which then sets the record.
        lines = self.config()["reserve"][name]
        return all(
            w["used"] < lines[window] or (w.get("resets_at") or 0) < time.time()
            for window, w in snapshot["windows"].items()
            if window in lines
        )

    def available(self, model):
        name = plan(model) or model
        if self.down.get(name, 0) > time.time():
            return False
        if plan(model):
            return self.under_line(name)
        return self.granted is None or model in self.granted

    def candidates(self, step):
        return [m for m in self.config()["steps"].get(step, []) if self.available(m)]

    def api_models(self):
        return sorted({m for models in self.config()["steps"].values() for m in models if not plan(m)})
