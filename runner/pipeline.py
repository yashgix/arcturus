"""Arcturus pipeline: companies from the radar move through a persistent queue (research, decide project / fast /
skip, spec, build, test, review, repair, final review, outreach draft), several at once, under one grant.

  python3 -B runner/pipeline.py RUN admit --count 3        # take the best companies from the radar shortlist
  python3 -B runner/pipeline.py RUN grant --ceiling 12      # prints the approval; Touch ID when the run starts
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=$HOME USER=$USER python3 -B runner/pipeline.py RUN run
  python3 -B runner/pipeline.py RUN status|report|pause|resume|stop
  python3 -B runner/pipeline.py RUN override COMPANY project|fast|skip
  python3 -B runner/pipeline.py RUN revise COMPANY... --reason "why" [--rebuild]   # parked: revise the spec
  python3 -B runner/pipeline.py RUN retry COMPANY...                    # parked: continue from its checkpoints

Nothing is sent, applied for or published. routing.json in RUN is read before every step, so edits apply at once."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from fnmatch import fnmatch
import hashlib
import http.client
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

import approve
import build
import dossier
import evidence
import grant as grants
import llm
import pipeline_steps as steps
import research_sources
import real_data
from research_reports import shape
import routing
from routing import read, write_json
import sandbox
from workflow import Stopped, write_status

RUNNER = Path(__file__).resolve().parent
KEYS = {
    name: str(Path.home() / ".arcturus-api-credentials" / f"{name}.key") for name in ("anthropic", "openai", "deepseek")
}
OPERATIONS = [
    "extract",
    "dossier",
    "projects",
    "challenge",
    "decide",
    "capability",
    "data",
    "spec",
    "plan",
    "build",
    "repair",
    "review",
    "notes",
    "outreach",
]
# DeepSeek's builds need room to think (pipeline_steps.THINKING_ROOM), within llm's 600 s read: Flash writes about
# 215 tokens a second, V4 Pro about 135 (9 Nov probe). Every other model keeps its usual limit.
MODELS = {
    **dossier.DEFAULT_MODELS,
    "deepseek-flash": {**dossier.DEFAULT_MODELS["deepseek-flash"], "max_output_tokens": steps.THINKING_ROOM},
    "deepseek-v4-pro": {**dossier.DEFAULT_MODELS["deepseek-v4-pro"], "max_output_tokens": 64_000},
}
DONE = ("ready", "skipped", "parked")
CLEAN_ENV = build.CLEAN_ENV | {"USER", "LOGNAME"}  # Claude Code finds the Max login in the keychain by user
JOB_BOARDS = (
    "ashbyhq.com",
    "greenhouse.io",
    "lever.co",
    "ycombinator.com",
    "workable.com",
    "gem.com",
    "linkedin.com",
    "rippling.com",
    "recruitee.com",
    "pinpointhq.com",
    "applytojob.com",
    "github.com",
    "x.com",
    "twitter.com",
    "youtube.com",
    "google.com",
    "notion.so",
    "notion.site",
    "docs.google.com",
    "calendly.com",
)
# Job boards whose first path segment names the company's board (jobs.gem.com/ultra).
ORG_BOARDS = ("ashbyhq.com", "greenhouse.io", "lever.co", "gem.com", "workable.com", "rippling.com", "recruitee.com")
CAREER_PAGES = ("/", "/careers", "/jobs")
SAMPLE_SECONDS = 15
POLL_SECONDS = 5
CHOICES = ("project", "fast", "skip")
# sandbox.stop() checks right after killing, so a process still exiting can trip it; a short wait clears it.
SANDBOX_RACE = "could not stop the execution account's processes"
CLAIMS_REPAIR = 100  # the claims repair's step number, far above any final repair's
SANDBOX_RETRIES = 3
SANDBOX_WAIT = 30


class Queue:
    """One row per company: its state, the decision, and the last note. Survives crashes and restarts."""

    def __init__(self, root):
        self.db = sqlite3.connect(
            Path(root) / "queue.sqlite", timeout=30, isolation_level=None, check_same_thread=False
        )
        self.lock = threading.Lock()
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS companies (id TEXT PRIMARY KEY, rank INTEGER, state TEXT, "
            "decision TEXT, note TEXT, updated REAL)"
        )

    def add(self, company_id, rank):
        with self.lock:
            self.db.execute(
                "INSERT OR IGNORE INTO companies VALUES (?, ?, 'queued', NULL, '', ?)", (company_id, rank, time.time())
            )

    def set(self, company_id, state, note="", decision=None):
        with self.lock:
            self.db.execute(
                "UPDATE companies SET state=?, note=?, decision=COALESCE(?, decision), updated=? WHERE id=?",
                (state, note[:500], decision, time.time(), company_id),
            )

    def rows(self):
        with self.lock:
            cursor = self.db.execute("SELECT * FROM companies ORDER BY rank")
            names = [c[0] for c in cursor.description]
            return [dict(zip(names, row)) for row in cursor]

    def waiting(self):
        return [r for r in self.rows() if r["state"] not in DONE]


# Admission: the best company per shortlist score, startups only, each with a known website.


def domain(host):
    return ".".join(host.split(".")[-2:])


def own_hosts(text):
    hosts = re.findall(r"https?://(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})", text.lower())
    return [domain(h) for h in hosts if not h.endswith(JOB_BOARDS)]


def site_of(name, item, description, root):
    """The company's own site: named in its job post, else a search result whose domain carries its name."""
    token = re.sub(r"[^a-z0-9]", "", name.lower())[:12]
    named = lambda hosts: next((h for h in hosts if token and token in h.replace("-", "")), None)
    own = own_hosts(description + " " + item["url"])
    if named(own):
        return named(own)
    store = evidence.Store(root / "sources" / "_admission", evidence.AnyPublicHost(), 400)
    for query in (f"{name} official website", f"{name} company"):
        # Bing's RSS results; DuckDuckGo's HTML page answers automated clients with a 202 challenge.
        _, links = research_sources.Retriever.search(store, query, "discovery")
        site = named(own_hosts(" ".join(links)))
        if site and links_to_board(store, site, item["url"]):
            return site
    return None


def board_of(url):
    """The company's own board on a job site, such as jobs.gem.com/ultra; None for free-text posts."""
    parts = urlsplit(url)
    org = next(iter(s for s in parts.path.split("/") if s), "")
    return f"{parts.hostname}/{org}".lower() if (parts.hostname or "").endswith(ORG_BOARDS) and org else None


def links_to_board(store, site, url):
    """A searched site is the employer only if its own pages link to the posting's board (two companies can share
    a name: Ultra the robot maker is not takeultra.com)."""
    board = board_of(url)
    return bool(board) and any(
        board in link.lower()
        for path in CAREER_PAGES
        for link in store.fetch(f"https://{site}{path}", "admission")["links"]
    )


def clean_name(name):
    return re.sub(r"\s*\(.*?\)", "", name).strip()


def slug(name):
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40]


def shortlist(registry):
    sys.path.insert(0, str(RUNNER.parent))
    from jobsearch import shortlist as radar
    from jobsearch.store import Store

    store = Store(registry, live_registry=True)
    try:
        items = radar.candidates(store, radar.utcnow())
        bodies = {
            r[0]: json.loads(r[1])["description"]
            for r in store.db.execute("SELECT json_extract(body,'$.url'), body FROM postings WHERE active=1")
        }
    finally:
        store.close()
    return items, bodies


def admissible(item, taken):
    return (
        not item["large"]
        and item["visa"]["state"] != "explicit refusal"
        and item["tier"] != "older"
        and slug(item["company"]) not in taken
    )


def fixed_grant(root):
    grant = read(root / "grant.json")
    return grant is not None and "company_ids" in grant["scope"]


def earlier_companies(root):
    """Companies that other pipeline runs beside this one already took, whatever came of them."""
    runs = (p / "run.json" for p in root.parent.glob("pipeline-*") if p != root)
    return {c["id"] for path in runs if path.exists() for c in json.loads(path.read_text())["companies"]}


def admit(root, registry, count):
    if fixed_grant(root):
        raise ValueError("this run's grant names its companies; admit into a new run folder")
    manifest = json.loads((root / "run.json").read_text())
    taken = {c["id"] for c in manifest["companies"]} | earlier_companies(root)
    items, bodies = shortlist(registry)
    queue, added = Queue(root), 0
    for item in items:
        if added >= count:
            break
        name = clean_name(item["company"])
        if not admissible(item, taken):
            continue
        site = site_of(name, item, bodies.get(item["url"], ""), root)
        if not site:
            print(
                f"skipped {name}: no confirmed website (the post names none, and no searched site links to its "
                "job board); check by hand"
            )
            taken.add(slug(item["company"]))
            continue
        company = {
            "id": slug(item["company"]),
            "name": name,
            "site": site,
            "role": item["title"],
            "seeds": [{"url": item["url"], "category": "hiring"}],
            "source_dirs": [],
            "job": {k: item[k] for k in ("title", "url", "tier", "basis", "place", "yoe", "visa", "skills")},
        }
        manifest["companies"].append(company)
        taken.add(company["id"])
        queue.add(company["id"], len(manifest["companies"]))
        added += 1
        print(f"admitted {company['name']} ({site}): {item['title']}, score {item['score']}")
    write_json(root / "run.json", manifest)


# The Mac: sample memory, swap, load and our own processes; heavy steps wait while the machine is busy.


def sysctl(name):
    return subprocess.run(["/usr/sbin/sysctl", "-n", name], capture_output=True, text=True, check=False).stdout.strip()


def our_rss_mb():
    rows = [
        line.split()
        for line in subprocess.run(
            ["/bin/ps", "-A", "-o", "pid=,ppid=,rss=,user="], capture_output=True, text=True, check=False
        ).stdout.splitlines()
    ]
    children, mine, total = {}, {os.getpid()}, 0
    for pid, ppid, _, _ in (r for r in rows if len(r) == 4):
        children.setdefault(int(ppid), []).append(int(pid))
    stack = [os.getpid()]
    while stack:
        for child in children.get(stack.pop(), []):
            mine.add(child)
            stack.append(child)
    for pid, _, rss, user in (r for r in rows if len(r) == 4):
        if int(pid) in mine or user == "_arcexec":
            total += int(rss)
    return round(total / 1024)


def sample():
    swap = re.search(r"used = ([\d.]+)M", sysctl("vm.swapusage"))
    return {
        "at": time.time(),
        "free_memory_percent": int(sysctl("kern.memorystatus_level") or 0),
        "swap_used_mb": float(swap[1]) if swap else None,
        "load_1m": round(os.getloadavg()[0], 2),
        "cores": os.cpu_count(),
        "ours_rss_mb": our_rss_mb(),
    }


def room(limits, now):
    return (
        now["free_memory_percent"] >= limits["min_free_memory_percent"]
        and now["load_1m"] <= limits["max_load_per_core"] * now["cores"]
    )


class Machine(threading.Thread):
    def __init__(self, root, router):
        super().__init__(daemon=True)
        self.path, self.router, self.latest = Path(root) / "machine.jsonl", router, sample()
        self.stopped = threading.Event()

    def run(self):
        while not self.stopped.is_set():
            try:
                self.latest = sample()
                with open(self.path, "a") as log:
                    log.write(json.dumps(self.latest) + "\n")
            except (OSError, ValueError) as exc:  # one bad sample must not freeze every wait on a stale reading
                self.latest = {**self.latest, "error": str(exc)}
            self.stopped.wait(SAMPLE_SECONDS)

    def wait_for_room(self, note, gate=lambda: None):
        while not room(self.router.config()["machine"], self.latest):
            gate()
            note(
                f"waiting: Mac busy (free memory {self.latest['free_memory_percent']}%, load {self.latest['load_1m']})"
            )
            time.sleep(SAMPLE_SECONDS)


def in_window(window, now=None):
    """window ["23:00", "07:00"] (may wrap past midnight); None or empty means always."""
    if not window:
        return True
    local = time.localtime(now)
    clock = local.tm_hour * 60 + local.tm_min
    start, end = (minutes(t) for t in window)
    return start <= clock < end if start <= end else clock >= start or clock < end


def minutes(clock):
    parsed = time.strptime(clock, "%H:%M")  # refuses anything but HH:MM, e.g. "24:00"
    return parsed.tm_hour * 60 + parsed.tm_min


# One company, from wherever it stopped to ready, skipped or parked.


class Pipeline:
    def __init__(self, root, connection=None, verify=True):
        self.root = Path(root)
        self.steps = steps.Steps(root, connection, verify)
        self.router, self.connection = self.steps.router, connection
        self.queue = Queue(root)
        self.machine = Machine(root, self.router)
        self.manifest = json.loads((self.root / "run.json").read_text())
        self.slots, self.building, self.idle, self.last_build = threading.Lock(), 0, set(), 0.0

    def company(self, company_id):
        return next((c for c in self.manifest["companies"] if c["id"] == company_id), None)

    def scheduled(self):
        """Companies the queue holds that this run's company list and the signed grant both cover. A standing
        allowance covers the first max_companies by rank, finished ones included; the ledger refuses any more."""
        self.manifest = read(self.root / "run.json")
        scope = self.steps.grant["scope"]
        rows = [r for r in self.queue.rows() if self.company(r["id"])]
        granted = (
            set(scope["company_ids"]) if "company_ids" in scope else {r["id"] for r in rows[: scope["max_companies"]]}
        )
        return [r["id"] for r in rows if r["id"] in granted and r["state"] not in DONE]

    def can_build(self, config):
        """The Mac decides: a new build starts while measurements show room, at least build_ramp_seconds after the
        last one started so its load shows first, under the max_builds safety ceiling and in the build window."""
        return (
            self.building < config.get("max_builds", 6)
            and in_window(config.get("build_window"))
            and room(config["machine"], self.machine.latest)
            and time.time() - self.last_build >= config.get("build_ramp_seconds", 60)
        )

    @contextmanager
    def build_slot(self, company_id, note):
        """A company waiting here gives up its active place, so the others keep moving through research and drafts."""
        checked = 0
        while True:
            config = self.router.config()
            with self.slots:
                if self.can_build(config):
                    self.building += 1
                    self.last_build = time.time()
                    self.idle.discard(company_id)
                    break
                self.idle.add(company_id)
            if self.halted:
                raise Stopped(self.halted)
            if time.time() - checked > 60:
                self.steps.gate()
                checked = time.time()
            note(
                "waiting for room to build"
                if in_window(config.get("build_window"))
                else f"waiting for the build window {'-'.join(config['build_window'])}"
            )
            time.sleep(POLL_SECONDS)
        try:
            yield
        finally:
            with self.slots:
                self.building -= 1

    def override(self, company_id):
        return (read(self.root / "overrides.json") or {}).get(company_id)

    def advance(self, company_id):
        """Walk one company. A grant pause halts the scheduler; any other failure parks the company with its reason."""
        company = self.company(company_id)
        note = lambda message: self.steps.note(company, "pipeline", message)
        self.idle.discard(company_id)
        try:
            self.walk(company, note)
        except llm.SecurityStop as exc:
            self.steps.ledger.control("stop")
            self.queue.set(company_id, "parked", f"security stop: {exc}")
            self.halted = f"security stop: {exc}"
        except (Stopped, grants.GrantError) as exc:
            note(f"paused: {exc}")
            self.halted = str(exc)
        except Exception as exc:  # noqa: BLE001 (each company's failure is recorded; the rest go on)
            message = f"{type(exc).__name__}: {exc}"
            if SANDBOX_RACE in str(exc):
                message += f" (still running: {'; '.join(survivors()) or 'none by now'})"
                tries = self.retries[company_id] = self.retries.get(company_id, 0) + 1
                if tries <= SANDBOX_RETRIES:
                    note(f"{message}; retry {tries} after {SANDBOX_WAIT * tries} s")
                    time.sleep(SANDBOX_WAIT * tries)
                    return
            self.queue.set(company_id, "parked", message)
            note(f"parked: {message}")

    def walk(self, company, note):
        cid, state = company["id"], next(r for r in self.queue.rows() if r["id"] == company["id"])["state"]
        if state == "queued":
            note("research")
            if not self.steps.research(company):
                return self.queue.set(cid, "parked", "research produced no dossier")
            self.queue.set(cid, "researched")
        decision = self.steps.decide(company)
        if decision is None:
            return self.queue.set(cid, "parked", "no model could decide")
        choice = self.override(cid) or decision["decision"]
        lane = self.steps.lane(company, "pipeline")
        held = self.hold(company, decision, lane, note) if choice == "project" else []
        blocked = steps.first_blocked(held)
        if choice == "skip":
            return self.queue.set(cid, "skipped", "; ".join(decision["reasons"])[:500], choice)
        self.queue.set(cid, "decided", decision["reasons"][0], choice)
        note("application packet")
        packet = self.steps.packet(company)  # before any build: applying never waits for a project
        project = None
        if choice == "project" and blocked != 1:
            project = read(lane / "project.json") or self.project(company, decision, note, blocked)
        note("outreach draft")
        pitch = project and {"title": project["title"], "independently_reviewed": project["accepted"]}
        draft = self.steps.outreach(company, pitch)
        if packet:
            write_packet(lane / "packet.md", company, packet, draft)
        drafts = [name for name, done in (("outreach draft", draft), ("application packet", packet)) if done]
        parked = None if project else (read(lane / "project-status.json") or {}).get("reason")
        self.queue.set(
            cid,
            "ready",
            (" and ".join(drafts) or "no drafts")
            + " ready"
            + (f"; project parked: {parked}" if parked else "")
            + (
                f"; project held at milestone {blocked}, needs: {'; '.join(r['requirement'] for r in held)}"
                if held
                else ""
            ),
            choice,
        )
        note("ready")

    def hold(self, company, decision, lane, note):
        """The runner capabilities the decided project lacks, saved for the report. Selection is settled by then:
        the project stays exactly as decided and waits. A seeded spec has already passed the runner's checks."""
        held = []
        if not (lane / "seed.json").exists():
            note("capability check")
            held = steps.missing(self.steps.capability(company, decision))
        if not held:
            (lane / "held.json").unlink(missing_ok=True)
            return []
        write_json(lane / "held.json", held)
        note(
            f"project held from milestone {steps.first_blocked(held)}, the runner cannot yet: "
            f"{'; '.join(r['requirement'] for r in held)[:300]}"
        )
        return held

    def project(self, company, decision, note, blocked=None):
        """Spec, build and the quality gate, milestone by milestone, each continuing on the same code. A fault the
        reviewer shows from the spec's own words (a contradicting hidden test or spec) gets an automatic revision.
        It stops before milestone *blocked*, which the runner cannot build yet: partial, never an accepted project."""
        lane, cid = self.steps.lane(company, "pipeline"), company["id"]
        milestones = decision.get("milestones") or steps.WHOLE_IDEA
        limits = self.router.config()["recovery"]
        while True:
            progress = read(lane / "progress.json") or {"milestone": 1, "respecs": 0}
            if blocked and progress["milestone"] >= blocked:
                note(
                    f"milestone {progress['milestone'] - 1} of {len(milestones)} accepted; held before milestone "
                    f"{blocked}"
                )
                return None
            if progress.get("pending"):  # decided before any crash, made once: a restart never skips it
                revise(self.root, cid, progress["pending"])
                write_json(lane / "progress.json", progress := {**progress, "pending": None})
            last = progress["milestone"] >= len(milestones)
            kind, value = self.attempt(company, decision, note, last)
            if (
                kind == "respec"
                and progress["respecs"] < limits["respecs"]
                and self.budget_left(cid) >= limits["round_usd"]
            ):
                note(f"spec or test at fault; revising: {value[:200]}")
                write_json(
                    lane / "progress.json",
                    {**progress, "respecs": progress["respecs"] + 1, "pending": "auto: " + value},
                )
                continue
            if kind != "accepted":
                reason = value if kind == "parked" else f"final review: spec or test fault, revision used up: {value}"
                write_json(lane / "project-status.json", {"state": "parked", "reason": reason[:500], "at": time.time()})
                self.queue.set(cid, "parked", reason)
                note(f"project parked: {reason[:200]}")
                return None
            if last:
                write_json(lane / "project.json", value)
                return value
            k = progress["milestone"]
            write_json(lane / f"milestone-{k}.json", value)
            note(f"milestone {k} accepted; starting milestone {k + 1} of {len(milestones)}")
            write_json(
                lane / "progress.json",
                {
                    "milestone": k + 1,
                    "respecs": 0,
                    "pending": f"auto: milestone {k + 1} of {len(milestones)}: {milestones[k]}",
                },
            )

    def attempt(self, company, decision, note, last):
        """One spec, build and quality gate: ("accepted", summary), ("respec", evidence) or ("parked", reason)."""
        base = sandbox.AREA / f"pipeline-{self.root.name}" / company["id"]
        given = read(self.steps.lane(company, "pipeline") / "seed.json")
        if given:  # its spec, tests and stated data are the project's; a search would only find unused data
            listing = []
        else:
            note("real data")
            try:
                listing = self.steps.find_data(company, decision, base)
            except real_data.SearchFailed as exc:  # nothing saved: the next run searches again
                return "parked", f"real-data search failed, no host answered: {exc}"
        spec = self.steps.spec(company, decision, listing)
        if spec is None:
            return "parked", "no model could write the spec"
        config = self.router.config()
        revision = read(self.steps.lane(company, "pipeline") / "revise.json")
        keep_code = bool(revision) and not revision.get("rebuild")
        evidence = steps.company_evidence(self.steps.lane(company, "routed"), decision)
        manifest = steps.materialize(base, company, spec, self.manifest["keys"], config["repairs"], keep_code, evidence)
        if not build.test_ids(manifest["protected"]["dir"], manifest["protected"]["pattern"]):
            return "parked", "the spec's acceptance tests define no test"
        if given:
            manifest["frozen"] = given["frozen"]
            steps.seed_workspace(steps.ProjectBuild(self.root, {**manifest, "builder": None, "reviewer": None}), given)
        if listing or (base / "repo" / real_data.FOLDER).exists():  # after git exists, so it is ignored from the start
            steps.ProjectBuild(self.root, {**manifest, "builder": None, "reviewer": None}).prepare("json")
            real_data.place(base, base / "arms" / "json")
        with self.build_slot(company["id"], note):
            self.machine.wait_for_room(note, self.steps.gate)
            note("build")
            pb, builder = steps.build_project(self.root, manifest, self.router, self.connection)
            if pb is None:
                return "parked", "no builder finished"
            if changed := real_data.changed(base / "repo", listing):
                raise llm.SecurityStop(f"real data changed during the build: {changed[:3]}")
            result = self.finish(pb, note)
            if result is None:
                return "parked", "no final review came back"
            if result.get("respec"):
                return "respec", result["respec"]
            if changed := real_data.changed(base / "repo", listing):
                raise llm.SecurityStop(f"real data changed during the final repairs: {changed[:3]}")
            if not result.get("reviewed_commit"):
                reasons = [f["problem"][:120] for f in steps.blocking(result["review"])][:2] or ["required tests fail"]
                return "parked", "final review: " + "; ".join(reasons)
            notes = (
                (lambda metrics: self.write_notes(pb, company, decision, {**result, "metrics": metrics}, note))
                if last
                else (lambda metrics: None)
            )
            metrics = None
            if manifest["experiment_minutes"]:  # the notes are written first, so the results check covers them
                metrics, problem = self.results(pb, note, notes)
                if problem:
                    return "parked", problem[:300]
            else:
                notes(None)
            summary = {
                "title": decision["idea_title"],
                "repo": str(pb.workspace("json")),
                "builder": builder,
                "final_review": result["model"],
                "reviewed_commit": result["reviewed_commit"],
                "accepted": True,
                "acceptance_tests": result["hidden"],
                "project_tests": result["own"],
                "open_findings": len(steps.documented(result["review"])),
                "real_data": len(listing),
                "demo": steps.run_demo(pb),
                "metrics": metrics,
            }
        return "accepted", summary

    def results(self, pb, note, notes):
        """(metrics, None) once the experiment gives identical metrics twice and an independent check finds every
        claim made from them supported, interview notes included; else (None, why). Claims that go too far get one
        wording repair (README and docs only)."""
        env, runs = steps.experiment_environment(pb), []
        for n in (1, 2):
            note(f"experiment run {n} of 2")
            value, problems = steps.run_experiment(pb, env)
            if problems:
                return None, "experiment: " + "; ".join(problems)
            runs.append(value)
        if runs[0] != runs[1]:
            return None, "experiment not reproducible: " + ", ".join(k for k in runs[0] if runs[0][k] != runs[1][k])
        metrics = runs[0]
        pb.write_files(
            "json",
            {"files": [{"path": "results/metrics.json", "text": json.dumps(metrics, indent=1) + "\n"}]},
            "Experiment metrics, measured by the runner",
        )
        notes(metrics)
        for n in range(2):
            result = steps.results_review(pb, self.router, metrics, n)
            if result is None:
                return None, "no results review came back"
            if not steps.blocking(result["review"]):
                return metrics, None
            if n or not steps.docs_only(result["review"]) or not self.repair_claims(pb, result):
                break
        reasons = [f["problem"][:150] for f in steps.blocking(result["review"])][:2]
        return None, "results not supported: " + "; ".join(reasons)

    def repair_claims(self, pb, result):
        """One repair of README and docs only. The limit is checked on what changed, so a replayed answer is held to
        it too; anything else is undone."""
        before = result["commit"]
        fixer = steps.ProjectBuild(self.root, {**pb.manifest, "allowed": list(steps.RESULT_DOCS)}, self.connection)
        try:
            try:
                made = self.repair(fixer, CLAIMS_REPAIR - pb.manifest["repairs"] - 1, result) is not None
            except OSError:  # e.g. a saved answer that writes onto a folder: a failed repair, rolled back below
                made = False
            outside = [
                p
                for p in steps.changed_files(pb, before) + steps.uncommitted(pb)
                if not any(fnmatch(p, g) for g in steps.RESULT_DOCS)
            ]
        except BaseException:
            undo_claims(pb, before, "it stopped")
            raise
        if outside or not made:  # also a half-written answer that failed on a later file
            undo_claims(pb, before, f"it changed {', '.join(outside[:3])}" if outside else "it did not finish")
            return False
        return True

    def write_notes(self, pb, company, decision, result, note):
        note("interview notes")
        notes = self.steps.notes(company, decision, result, pb.spec)
        if notes:
            pb.write_files(
                "json",
                {"files": [{"path": "docs/INTERVIEW.md", "text": steps.interview_notes(notes)}]},
                "Interview notes",
            )

    def finish(self, pb, note):
        """The quality gate: required tests pass and nothing blocking is left; it never weakens. Each failed review
        gets the step its cause calls for, within the attempts and dollars routing.json's recovery allows:
        - code: a targeted repair, then a focused recheck. A repair that breaks tests that passed is undone and the
          next try goes to a stronger model; a blocker still there after a stronger model's repair ends it.
        - a hidden test or the spec at fault, shown from the spec's own words: returned for a spec revision.
        - mediums only: bounded repairs, then documented in docs/REVIEW.md."""
        limits = self.router.config()["recovery"]
        seen, escalated, stronger = set(), set(), False
        result = self.review(pb, 0, None, note)
        for n in range(limits["attempts"] + 1):
            if result is None:
                return None
            clean = result["tests_pass"] and not steps.blocking(result["review"])
            mediums = [f for f in steps.documented(result["review"]) if f["severity"] == "medium"]
            if clean and (not mediums or n >= limits["medium_repairs"]):
                return {**result, "reviewed_commit": steps.record_acceptance(pb, result)}
            fault = spec_fault(result["review"])
            if fault:
                return {**result, "respec": fault}
            keys = steps.blocking_keys(result["review"])
            if n == limits["attempts"] or keys & escalated or self.over_budget(pb.company["id"], limits, note):
                note(
                    "recovery used up"
                    + (
                        f": {sorted(keys & escalated)} still blocking after a stronger repair"
                        if keys & escalated
                        else ""
                    )
                )
                return result
            repeated = keys & seen
            seen |= keys
            model = self.stronger(pb) if repeated or stronger else None
            note(f"final repair {n + 1}" + (f" on {model}" if model else ""))
            used = self.repair(pb, n, result, model)
            if used is None:
                return result
            if used != pb.manifest["builder"]:
                escalated |= keys if stronger else repeated
            broken = self.broken(pb, result, n)
            stronger = bool(broken)
            if broken:
                steps.revert(pb, result["commit"], f"Undo repair {n + 1}: it broke tests that passed")
                note(f"repair {n + 1} broke or bent {len(broken)} tests ({', '.join(broken[:3])}); undone")
                continue
            result = self.review(pb, n + 1, result, note)
        return result

    def review(self, pb, n, previous, note):
        self.machine.wait_for_room(note, self.steps.gate)
        note(f"final review {n}" + (" (focused recheck)" if previous else ""))
        return steps.final_review(pb, self.router, f"final{n}", previous)

    def broken(self, pb, before, n):
        """Tests the repair broke, and failing tests it made pass or removed by editing their own file when no
        finding blamed that test: fixers never change a test just to get past it."""
        own, hidden = pb.test("json", f"repaired{n}")
        outcome = {**own, **hidden}
        passing = [k for k, v in outcome.items() if v == "ok"]
        blamed = {f["path"] for f in before["review"]["findings"] if f["cause"] == "test"}
        edited = {p for p in steps.changed_files(pb, before["commit"]) if p.startswith("tests/")} - blamed
        bent = [
            t
            for t in before["own"]["not_ok"]
            if outcome.get(t, "gone") in ("ok", "gone") and f"tests/{t.split('.')[0]}.py" in edited
        ]
        return steps.regressed(before, {"passing": passing}) + sorted(bent)

    def budget_left(self, company_id):
        _, known, held = spend(self.steps.ledger.rows(), company_id)
        return self.router.config()["recovery"]["company_usd"] - known - held

    def over_budget(self, company_id, limits, note):
        """The company's recovery budget is soft: room for one more round (a repair and its recheck, estimated) must
        be left, so it can be passed by that estimate's error. The grant's ceiling is the hard limit on every call."""
        if self.budget_left(company_id) >= limits["round_usd"]:
            return False
        note(
            f"recovery stops: under ${limits['round_usd']:.2f} left of the ${limits['company_usd']:.2f} soft "
            "company budget"
        )
        return True

    def stronger(self, pb):
        return next((m for m in self.router.candidates("escalate") if m != pb.manifest["builder"]), None)

    def repair(self, pb, n, result, model=None):
        """One final repair; returns the model that made it (as recorded, when replayed), or None if it failed."""
        problems = {
            "review_findings": build.serious(result["review"]),
            "hidden_acceptance_tests": result["hidden"],
            "your_tests": result["own"],
        }
        step = f"repair-{pb.manifest['repairs'] + 1 + n}"
        done = pb.lane(pb.company, "json") / f"{step}.json"
        if done.exists():  # replayed: whoever made it then, not whoever is up now
            model = (read(self.steps.lane(pb.company, "pipeline") / "models.json") or {}).get(step)
        if model:
            pb = steps.ProjectBuild(self.root, {**pb.manifest, "builder": model}, self.connection)
        replayed = done.exists()
        try:
            build.JsonBuilder(pb, "json").repair(pb.manifest["repairs"] + 1 + n, problems)
        except Stopped as exc:  # write_files refuses an unsafe path: the repair failed, the grant is fine
            if "unsafe path" not in str(exc):
                raise
            return None
        if not done.exists():
            return None
        if model and not replayed:
            self.steps.record_model(pb.company, step, model)
        return pb.manifest["builder"]

    def run(self):
        """Keep up to max_active companies in flight until the queue is done or the grant pauses the run."""
        self.steps.lock()
        self.machine.start()
        self.halted, self.retries, running = None, {}, {}
        with ThreadPoolExecutor(32) as pool:
            while True:
                running = {cid: f for cid, f in running.items() if not f.done()}
                waiting = [cid for cid in self.scheduled() if cid not in running]
                if not running and (self.halted or not waiting):
                    break
                if not self.halted:
                    with self.slots:
                        active = len(set(running) - self.idle)
                    for cid in waiting[: max(0, self.router.config()["max_active"] - active)]:
                        running[cid] = pool.submit(self.advance, cid)
                write_report(self)
                time.sleep(POLL_SECONDS)
        self.machine.stopped.set()
        self.steps.lockfile.close()
        write_report(self)


def spec_fault(review):
    """The reviewer's evidence when a blocker is the spec's fault or a hidden test's: the spec gets revised, the
    code is never bent to a test that contradicts it."""
    faults = [
        f
        for f in steps.blocking(review)
        if f["cause"] == "spec" or f["cause"] == "test" and "test_p_" in f["path"] + f["problem"]
    ]
    return " | ".join(f"{f['path']}: {f['problem']}" for f in faults)[:1500]


def survivors():
    """Execution-account processes still alive, by pid, age and command, for the morning page."""
    rows = subprocess.run(
        ["/bin/ps", "-U", "_arcexec", "-o", "pid=,etime=,command="], capture_output=True, text=True
    ).stdout.splitlines()
    return [
        " ".join(r.split())[:160]
        for r in rows
        if r.split(None, 2)[2:] and r.split(None, 2)[2] not in sandbox.SYSTEM_AGENTS
    ]


def write_packet(path, company, packet, draft):
    """The packet as Yash reads it: nothing in it is sent anywhere."""
    lines = [
        f"# {company['name']}: {company['job']['title']}",
        "",
        f"Post: {company['job']['url']}",
        f"Base resume: {packet['base_resume']} (in ~/.arcturus/resumes)",
        "",
        "## Requirements",
        "",
    ]
    lines += [f"- **{r['level']}** {r['requirement']}: {r['evidence']}" for r in packet["requirements"]]
    lines += ["", "## Lead bullets (exact text from your resumes)", ""] + [f"- {b}" for b in packet["lead_bullets"]]
    lines += ["", "## Skills lines", ""] + [f"- {k}" for k in packet["skills"]]
    lines += ["", "## Why this company", "", packet["why_company"], "", "## Confirm before using", ""]
    lines += [f"- {c}" for c in packet["confirm"]] or ["- Nothing flagged."]
    if draft:
        lines += [
            "",
            f"## Outreach draft ({draft['channel']}, to {draft['to']})",
            "",
            f"Subject: {draft['subject']}",
            "",
            draft["body"],
        ]
    path.write_text("\n".join(lines) + "\n")


# Report: one page for the morning.


def deepseek_balance(key):
    connection = http.client.HTTPSConnection("api.deepseek.com", timeout=30)
    try:
        connection.request("GET", "/user/balance", headers={"Authorization": f"Bearer {key}"})
        reply = json.loads(connection.getresponse().read(100_000))
        return {i["currency"]: i["total_balance"] for i in reply.get("balance_infos", [])}
    except (OSError, ValueError, KeyError, http.client.HTTPException):
        return None
    finally:
        connection.close()


def spend(rows, company_id):
    mine = [r for r in rows if r["lane"].split("/")[0] == company_id]
    known = sum(r["charge"] or 0 for r in mine if r["state"] != "uncertain")
    held = sum(r["reserve"] for r in mine if r["state"] in ("uncertain", "reserved"))
    return len(mine), known / 1e6, held / 1e6


def project_state(lane, row):
    """Where the company's project stands: ready, in progress, recovering, waiting for approval or dropped."""
    if (lane / "project.json").exists():
        return "ready"
    if gaps(lane):
        done = len(list(lane.glob("milestone-*.json")))
        return f"partial: {done} milestones accepted, held" if done else "held: runner capability missing"
    if row["decision"] in ("fast", "skip") or (lane / "project-status.json").exists():
        return "dropped"
    if (read(lane / "real-data.json") or {}).get("needs_approval"):
        return "waiting for approval"
    if row["decision"] == "project" and ((lane / "revisions.jsonl").exists() or "repair" in row["note"]):
        return "recovering"
    return "in progress"


def gaps(lane):
    """What the runner lacked for this lane's decided project at its last capability check."""
    return read(lane / "held.json") or []


def gap_lines(pipeline):
    """Each held project as decided, and what would let Arcturus build it: for Yash to approve or not."""
    lines = []
    for row in pipeline.queue.rows():
        company = pipeline.company(row["id"])
        lane = company and pipeline.steps.lane(company, "pipeline")
        if not lane or not (missing := gaps(lane)):
            continue
        decision = read(lane / "decide.json")
        lines.append(
            f"- **{company['name']}**: {decision['idea_title']} (stack: "
            f"{', '.join(decision.get('stack') or ['not stated'])})"
        )
        lines += [
            f"  - Milestone {k} accepted (part of the project, not the finished project): `{read(path)['repo']}`"
            for k, path in enumerate(sorted(lane.glob("milestone-*.json")), 1)
        ]
        lines += [
            f"  - Missing {r['requirement']} (milestones {', '.join(map(str, r.get('milestones') or [1]))}). "
            f"Smallest safe extension: {r['extension'].rstrip('.')}. Needs approval: {r['approvals']}"
            for r in missing
        ]
    if lines:
        lines.append("- Once the runner has what is missing: `pipeline.py RUN retry COMPANY` (the check runs again).")
    return lines or ["- None."]


def company_line(pipeline, row, rows):
    company = pipeline.company(row["id"]) or {"id": row["id"], "name": row["id"]}
    lane = pipeline.steps.lane(company, "pipeline")
    calls, known, held = spend(rows, row["id"])
    decision = read(lane / "decide.json") or {}
    title = decision.get("idea_title", "") if row["decision"] == "project" else ""
    draft = read(lane / "outreach.json") or {}
    models = read(lane / "models.json") or {}
    return (
        f"| {company['name']} | {decision.get('company_priority', '')} | {row['state']} | {row['decision'] or ''} "
        f"| {title} | {project_state(lane, row)} | {draft.get('channel', '')} {draft.get('to', '')} | "
        f"{', '.join(f'{k}: {v}' for k, v in models.items() if k != 'research')} | {calls} | ${known:.4f}"
        f"{f' (+${held:.4f} held)' if held else ''} | {row['note'][:120]} |"
    )


def rescued(lane):
    """A revision or retry by hand; the pipeline's own start with "auto:"."""
    path = lane / "revisions.jsonl"
    reasons = [json.loads(line)["reason"] for line in path.read_text().splitlines()] if path.exists() else []
    return any(not r.startswith("auto:") for r in reasons)


def measure_lines(pipeline, rows):
    """Completion with no rescue, each accepted project's value, cost and time, and the run's cost per project."""
    attempted, accepted, lines = 0, [], []
    for row in pipeline.queue.rows():
        company = pipeline.company(row["id"])
        lane = company and pipeline.steps.lane(company, "pipeline")
        if not company or row["decision"] != "project" or gaps(lane):
            continue
        attempted += 1
        if not (lane / "project.json").exists():
            continue
        decision, mine = read(lane / "decide.json"), [r for r in rows if r["lane"].split("/")[0] == row["id"]]
        hours = ((lane / "project.json").stat().st_mtime - min(r["started"] for r in mine)) / 3600 if mine else 0
        accepted.append(not rescued(lane))
        lines.append(
            f"- **{company['name']}**: impact {decision['impact']}/5, proves: "
            f"{decision.get('what_it_proves', 'not stated')[:200]}; ${spend(rows, row['id'])[1]:.2f}, "
            f"{hours:.1f} h{', rescued by hand' if rescued(lane) else ''}"
        )
    total = sum(r["charge"] or 0 for r in rows if r["state"] != "uncertain") / 1e6
    head = [
        f"- Accepted with no rescue: {sum(accepted)} of {attempted} projects started "
        f"({len(accepted)} accepted in all).",
        f"- Cost per accepted project: ${total / len(accepted):.2f}"
        if accepted
        else f"- Cost per accepted project: none accepted yet (${total:.2f} spent).",
    ]
    return head + lines


def trouble_lines(pipeline):
    """Good startups (priority 4-5) whose project is stuck: Yash hears about these."""
    lines = []
    for row in pipeline.queue.rows():
        company = pipeline.company(row["id"])
        if not company:
            continue
        lane = pipeline.steps.lane(company, "pipeline")
        decision, status = read(lane / "decide.json") or {}, read(lane / "project-status.json")
        if decision.get("company_priority", 0) >= 4 and (status or project_state(lane, row) == "recovering"):
            reason = status["reason"] if status else row["note"]
            lines.append(
                f"- **{company['name']}** (priority {decision['company_priority']}): {reason[:300]}. "
                "Drafts to apply directly are ready or coming; the project needs a new approach."
            )
    return lines or ["- None."]


def machine_peaks(root):
    path = Path(root) / "machine.jsonl"
    samples = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    if not samples:
        return "no samples yet"
    return (
        f"lowest free memory {min(s['free_memory_percent'] for s in samples)}%, highest load "
        f"{max(s['load_1m'] for s in samples)} on {samples[-1]['cores']} cores, our processes up to "
        f"{max(s['ours_rss_mb'] for s in samples)} MB, swap up to {max(s['swap_used_mb'] or 0 for s in samples)} "
        f"MB ({len(samples)} samples)"
    )


def spend_lines(rows):
    """Known charges per model, with cut-off answers and calls whose charge is unknown (their reserve is held)."""
    lines = []
    for model in sorted({r["model"] for r in rows}):
        mine = [r for r in rows if r["model"] == model]
        known = sum(r["charge"] or 0 for r in mine if r["state"] != "uncertain") / 1e6
        cut = [r for r in mine if r["state"] == "truncated"]
        uncertain = [r for r in mine if r["state"] == "uncertain"]
        lines.append(
            f"- {model}: {len(mine)} calls, ${known:.4f} known; {len(cut)} cut off "
            f"(${sum(r['charge'] or 0 for r in cut) / 1e6:.4f}); {len(uncertain)} uncertain "
            f"(${sum(r['reserve'] for r in uncertain) / 1e6:.4f} held)"
        )
    return lines or ["- No API calls."]


def ready_lines(pipeline):
    lines = []
    for row in pipeline.queue.rows():
        company = pipeline.company(row["id"])
        if row["state"] != "ready" or not company:
            continue
        lane = pipeline.steps.lane(company, "pipeline")
        project = read(lane / "project.json") or {}
        files = [f"project `{project['repo']}` (review notes `docs/REVIEW.md`)"] if project else []
        files += [f"`{lane / name}`" for name in ("packet.md", "outreach.json") if (lane / name).exists()]
        lines.append(f"- **{company['name']}** ({row['decision']}): {', '.join(files) or 'no drafts'}")
    return lines or ["- Nothing yet."]


def balances(root):
    path = Path(root) / "balance.jsonl"
    entries = []
    for line in path.read_text().splitlines() if path.exists() else []:
        try:
            entries.append(json.loads(line))
        except ValueError:  # a line cut short by a crash must not stop every report
            continue
    return (
        "; ".join(
            f"{e['when']} {time.strftime('%H:%M', time.localtime(e['at']))} {e['deepseek']}" for e in entries[-4:]
        )
        or "not read yet"
    )


def last_start(root):
    path = Path(root) / "last-start.txt"
    return path.read_text().strip() if path.exists() else "never"


def write_report(pipeline):
    rows = pipeline.steps.ledger.rows()
    lines = [
        "# Pipeline report",
        "",
        f"Updated {time.strftime('%Y-%m-%d %H:%M')}. Grant {pipeline.steps.grant['id']} "
        f"({pipeline.steps.ledger.state()}), ceiling ${pipeline.steps.grant['ceiling_microusd'] / 1e6:.2f}.",
        "",
        "| Company | Priority | State | Decision | Project | Project state | Outreach | Models | API calls "
        "| API spend | Note |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    lines += [company_line(pipeline, row, rows) for row in pipeline.queue.rows()]
    usage = read(pipeline.root / "usage.json") or {}
    halted = getattr(pipeline, "halted", None)
    lines += [
        "",
        f"Paused: {halted}" if halted else "Not paused.",
        f"Plans: {json.dumps({k: v['windows'] for k, v in usage.items()})}",
        f"Mac: {machine_peaks(pipeline.root)}",
        "",
        "## Spend by model",
        "",
    ] + spend_lines(rows)
    lines += ["", "## Good startups whose project is in trouble", ""] + trouble_lines(pipeline)
    lines += ["", "## Projects held for a runner capability (kept as decided)", ""] + gap_lines(pipeline)
    lines += ["", "## Measures", ""] + measure_lines(pipeline, rows)
    lines += ["", "## Ready for Yash (drafts only; nothing was sent)", ""] + ready_lines(pipeline)
    lines += ["", f"DeepSeek balance: {balances(pipeline.root)}", f"Last start: {last_start(pipeline.root)}"]
    if not steps.packet_sources(pipeline.root):
        lines.append("Application packets: off (no copied resume list or bullet bank in this run folder).")
    (pipeline.root / "report.md").write_text("\n".join(lines) + "\n")
    write_status(pipeline.steps)


# Commands.


def init(root):
    root.mkdir(parents=True, exist_ok=True)
    if not (root / "run.json").exists():
        (root / "run.json").write_text(
            json.dumps(
                {"companies": [], "keys": KEYS, "routing": {}, "json_by_instruction": ["claude-sonnet-5-5"]}, indent=1
            )
        )
    if not (root / "routing.json").exists():
        shutil.copy(RUNNER / "routing.json", root / "routing.json")


def draft_grant(root, ceiling, calls, hours, standing=None):
    """A grant for this run's companies, or with *standing* a standing allowance: any companies the queue admits,
    at most that many, so daily discovery can add them without a new signature."""
    if standing and (root / "ledger.sqlite").exists():
        raise ValueError(
            "the ledger counts every company this folder has paid for; put a new allowance in a new run folder"
        )
    manifest = json.loads((root / "run.json").read_text())
    steps.copy_packet_sources(root)
    models = {m: MODELS[m] for m in routing.Router(root).api_models()}
    companies = (
        {"max_companies": standing}
        if standing
        else {
            "companies": [c["name"] for c in manifest["companies"]],
            "company_ids": [c["id"] for c in manifest["companies"]],
        }
    )
    scope = {**companies, "attempts_per_step": 3, "operations": OPERATIONS}
    return grants.write(root, grants.draft("build", scope, models, ceiling, calls, hours))


def revise(root, company_id, reason, rebuild=False):
    """Send a parked project back through spec and build: the spec is revised, the research is kept, and the
    earlier rounds move to attempt-N so their checkpoints are not replayed. The code is kept and repaired, or with
    rebuild (a design change that repairs cannot make, such as removing files) set aside and built fresh."""
    lane = root / "lanes" / company_id / "json"
    n = 1 + sum(1 for p in lane.glob("attempt-*"))
    if rebuild:  # the code first: a failure here leaves the checkpoints where they were
        base = sandbox.AREA / f"pipeline-{root.name}" / company_id
        for name in ("repo", "arms"):
            if (base / name).exists():
                (base / f"attempt-{n}").mkdir(parents=True, exist_ok=True)
                (base / name).rename(base / f"attempt-{n}" / name)
    archive = lane / f"attempt-{n}"
    archive.mkdir()
    for path in lane.iterdir():
        if path.is_file() and (rebuild or not path.name.startswith(("plan", "build-"))):
            path.rename(archive / path.name)
    specs = root / "lanes" / company_id / "pipeline"
    if (specs / "spec-2.json").exists():  # the next revision starts from the latest spec, the first one kept
        if (specs / "spec.json").exists():  # gone only if a crash came between the two renames: safe to redo
            (specs / "spec.json").rename(specs / f"spec-before-attempt-{n}.json")
        (specs / "spec-2.json").rename(specs / "spec.json")
    write_json(specs / "revise.json", {"reason": reason, "at": time.time(), "rebuild": rebuild})
    (specs / "project-status.json").unlink(missing_ok=True)
    log_revision(specs, reason)
    Queue(root).set(company_id, "decided", f"revising: {reason[:200]}")


def undo_claims(pb, before, why):
    steps.discard_uncommitted(pb)
    steps.revert(pb, before, f"Undo the claims repair: {why}")


def seed(root, company_id, path):
    """A project Yash chose and specified by hand (path: JSON with title, why, data, spec, tests, repo, commit,
    package, environment, also_test_in, experiment_minutes, metrics). Its spec and hidden tests pass the same checks
    as a model's; the decide and spec steps then use them as written, and the build starts from the repo's commit.
    'data' states the data it uses, with source and license (or "none"), since no data search runs for it."""
    given = json.loads(Path(path).read_text())
    if not isinstance(given.get("data"), str) or not given["data"].strip():
        raise ValueError("state the data the project uses, with its source and license, or 'none' (field 'data')")
    tests = [
        {"name": "test_p_" + f.name.removeprefix("test_").removeprefix("p_"), "text": f.read_text()}
        for f in sorted(Path(given["tests"]).glob("test_*.py"))
    ]
    spec = {
        "package": given["package"],
        "environment": given["environment"],
        "also_test_in": given.get("also_test_in", []),
        "experiment_minutes": given.get("experiment_minutes", 0),
        "metrics": given.get("metrics", []),
        "spec_markdown": Path(given["spec"]).read_text() + fixed_section(given),
        "acceptance_tests": tests,
        "data_paths": given.get("data_paths", []),
    }
    if not shape(spec, steps.SCHEMAS["spec"]):
        raise ValueError("the given spec does not match the spec schema (fields, environments, limits)")
    if problems := steps.check_spec(spec):
        raise ValueError("the given spec does not pass the spec checks: " + "; ".join(problems))
    commit = git_show(given["repo"], given["commit"] + "^{commit}", None).strip()
    if leaked := hidden_in_repo(given, commit, tests):
        raise ValueError(f"the repository holds hidden tests, which builders would then see: {leaked[:3]}")
    lane = root / "lanes" / company_id / "pipeline"
    lane.mkdir(parents=True, exist_ok=True)
    answers = dict.fromkeys((*steps.FOUR, "portfolio_difference"), "Chosen by Yash; see the specification.")
    write_json(
        lane / "decide.json",
        {
            "decision": "project",
            "impact": 5,
            "company_priority": 5,
            "reasons": [given["why"]],
            "idea_title": given["title"],
            "scope": given["title"],
            "demo": "none",
            "alternatives": [],
            "real_data": given["data"],
            "milestones": [given["title"]],
            "stack": [f"Python, environment {given['environment']}"],
            **answers,
        },
    )
    write_json(lane / "spec.json", spec)
    frozen = {path: git_show(given["repo"], commit, path) for path in given.get("frozen", [])}
    write_json(lane / "seed.json", {"repo": str(Path(given["repo"]).resolve()), "commit": commit, "frozen": frozen})
    write_json(root / "overrides.json", {**(read(root / "overrides.json") or {}), company_id: "project"})
    Queue(root).set(company_id, "researched", "project given by hand")


def hidden_in_repo(given, commit, tests):
    """Files of the seed commit that are a hidden test (same content), or the tests folder inside the repo; a seed
    with links is refused outright."""
    repo, folder = Path(given["repo"]).resolve(), Path(given["tests"]).resolve()
    if folder.is_relative_to(repo):
        return [str(folder)]
    blobs = {
        hashlib.sha1(b"blob %d\0" % len(t["text"].encode()) + t["text"].encode()).hexdigest(): t["name"] for t in tests
    }
    rows = subprocess.run(
        ["/usr/bin/git", "-C", str(repo), "ls-tree", "-r", commit], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    if links := [r.split("\t", 1)[1] for r in rows if r.startswith("120000")]:
        raise ValueError(f"the seed holds links, which could redirect writes: {links[:3]}")
    return [blobs[r.split()[2]] for r in rows if r.split()[2] in blobs]


def fixed_section(given):
    if not given.get("frozen"):
        return ""
    return (
        "\n\n## Fixed files (kept by the runner)\n\nThese files are part of the given project and are restored "
        "before every commit, so never write them: " + ", ".join(f"`{p}`" for p in given["frozen"]) + ".\n"
    )


def git_show(repo, commit, path):
    """A file's text at a commit, or with no path the commit's full id."""
    args = ["show", f"{commit}:{path}"] if path else ["rev-parse", "--verify", commit]
    return subprocess.run(["/usr/bin/git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout


def log_revision(lane, reason):
    """Every revision and retry, so the report can tell the pipeline's own recovery ("auto: ...") from a rescue."""
    lane.mkdir(parents=True, exist_ok=True)
    with open(lane / "revisions.jsonl", "a") as log:
        log.write(json.dumps({"reason": reason, "at": time.time()}) + "\n")


def discover(root, registry, count):
    """The daily job: refresh the radar (free page reads), then admit the best new startups into the queue."""
    subprocess.run(
        [sys.executable, "-B", "-m", "jobsearch.radar", "run", "--registry", registry],
        cwd=RUNNER.parent,
        check=True,
        timeout=3 * 3600,
    )
    admit(root, registry, count)


LAUNCH_AGENTS = Path.home() / "Library" / "LaunchAgents"
AGENT = "com.arcturus.pipeline"


# The runner starts every hour, so new work never waits for a slot and a crashed runner resumes within the hour (a
# runner still going holds the lock, so a second start ends at once). No KeepAlive: launchd treats it as
# RunAtLoad, which would start paid work the moment the job is loaded, and it would restart a lasting fault forever.
JOBS = {"discover": [(7, 0)], "run": [(hour, 15) for hour in range(24)]}


def agent(root, name, argv, hours):
    """A user launchd job (never root): caffeinate keeps the Mac awake while it runs, in a clean environment."""
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(Path.home()),
        "USER": os.environ["USER"],
        "LOGNAME": os.environ["USER"],
        "TMPDIR": os.environ.get("TMPDIR") or os.confstr("CS_DARWIN_USER_TEMP_DIR"),
    }
    command = [
        "/usr/bin/caffeinate",
        "-i",
        "/usr/bin/env",
        "-i",
        *(f"{k}={v}" for k, v in env.items()),
        steps.PYTHON,
        "-B",
        str(RUNNER / "pipeline.py"),
        str(root),
        *argv,
    ]
    return {
        "Label": f"{AGENT}.{name}",
        "ProgramArguments": command,
        "WorkingDirectory": str(RUNNER.parent),
        "StartCalendarInterval": [{"Hour": h, "Minute": m} for h, m in hours],
        "StandardOutPath": str(root / f"{name}.log"),
        "StandardErrorPath": str(root / f"{name}.log"),
    }


def schedule(root, count):
    LAUNCH_AGENTS.mkdir(parents=True, exist_ok=True)
    for name, argv in (("discover", ["discover", "--count", str(count)]), ("run", ["run", "--scheduled"])):
        path = LAUNCH_AGENTS / f"{AGENT}.{name}.plist"
        subprocess.run(["/bin/launchctl", "bootout", f"gui/{os.getuid()}", str(path)], capture_output=True)
        path.write_bytes(plistlib.dumps(agent(root, name, argv, JOBS[name])))
        subprocess.run(["/bin/launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)], check=True)
        print(f"scheduled {path.name}")


def unschedule():
    for name in ("discover", "run"):
        path = LAUNCH_AGENTS / f"{AGENT}.{name}.plist"
        subprocess.run(["/bin/launchctl", "bootout", f"gui/{os.getuid()}", str(path)], capture_output=True)
        path.unlink(missing_ok=True)
        print(f"removed {path.name}")


def record_balance(root, balance, when):
    with open(root / "balance.jsonl", "a") as log:
        log.write(json.dumps({"at": time.time(), "when": when, "deepseek": balance}) + "\n")


def check_clean():
    if set(os.environ) - CLEAN_ENV:
        raise Stopped("start with a clean environment: /usr/bin/env -i PATH=/usr/bin:/bin HOME=$HOME USER=$USER ...")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run", type=Path)
    parser.add_argument(
        "command",
        choices=(
            "admit",
            "discover",
            "grant",
            "run",
            "status",
            "report",
            "pause",
            "resume",
            "stop",
            "revoke",
            "override",
            "revise",
            "retry",
            "schedule",
            "unschedule",
            "seed",
        ),
    )
    parser.add_argument(
        "--scheduled",
        action="store_true",
        help="run: from launchd; an unapproved grant or a runner already going ends quietly",
    )
    parser.add_argument("--standing", type=int, help="grant: a standing allowance for this many companies")
    parser.add_argument("--reason", default="")
    parser.add_argument("--rebuild", action="store_true", help="revise: set the code aside and build fresh")
    parser.add_argument("--file", type=Path, help="seed: the hand-written project's JSON")
    parser.add_argument("args", nargs="*")
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--registry", default=str(Path.home() / "arcturus-runs/radar/registry.sqlite"))
    parser.add_argument("--ceiling", type=float, default=12.0)
    parser.add_argument("--calls", type=int, default=800)
    parser.add_argument("--hours", type=float, default=24)
    args = parser.parse_args(argv)
    root = args.run.resolve()
    try:
        init(root)
        if args.command == "admit":
            admit(root, args.registry, args.count)
        elif args.command == "discover":
            discover(root, args.registry, args.count)
        elif args.command == "schedule":
            schedule(root, args.count)
        elif args.command == "unschedule":
            unschedule()
        elif args.command == "grant":
            print(draft_grant(root, args.ceiling, args.calls, args.hours, args.standing))
        elif args.command == "retry":
            for company in args.args:
                log_revision(root / "lanes" / company / "pipeline", "retry by hand")
                Queue(root).set(company, "decided", "retrying with its work kept")
        elif args.command == "revise":
            if not args.reason:
                raise ValueError("say why with --reason; the spec model reads it")
            for company in args.args:
                revise(root, company, args.reason, args.rebuild)
        elif args.command == "seed":
            seed(root, args.args[0], args.file)
        elif args.command == "override":
            company, choice = args.args
            if choice not in CHOICES:
                raise ValueError(f"override must be one of {', '.join(CHOICES)}")
            write_json(root / "overrides.json", {**(read(root / "overrides.json") or {}), company: choice})
        else:
            if args.command == "run":
                check_clean()
                if args.scheduled:
                    grants.verified(root)  # no approval page at night: Yash approves the grant beforehand
                else:
                    approve.ensure(root)
            pipeline = Pipeline(root, verify=args.command == "run")
            if args.command == "run":
                (root / "last-start.txt").write_text(f"{time.strftime('%Y-%m-%d %H:%M')} started\n")
                balance = deepseek_balance(pipeline.steps.key("deepseek"))
                record_balance(root, balance, "start")
                print(f"DeepSeek balance: {balance}")
                pipeline.run()
                record_balance(root, deepseek_balance(pipeline.steps.key("deepseek")), "end")
            elif args.command in ("pause", "resume", "stop", "revoke"):
                pipeline.steps.ledger.control(
                    {"pause": "pause", "resume": "run", "stop": "stop", "revoke": "revoked"}[args.command]
                )
            write_report(pipeline)
            print((root / "report.md").read_text())
    except (grants.GrantError, Stopped) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        if args.scheduled:  # nobody watches the launchd log: the morning page says why nothing ran
            (root / "last-start.txt").write_text(f"{time.strftime('%Y-%m-%d %H:%M')} not started: {exc}\n")
            if (root / "grant.json").exists():
                write_report(Pipeline(root, verify=False))
        return 1
    except (ValueError, OSError, llm.SecurityStop, subprocess.CalledProcessError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
