"""Two genuine scheduler workers with offline provider transports."""

import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runner"))
from api_review import LIVE_MODELS, encode, trial_plan
from concurrent_runs import Scheduler
import engineering
from engineering_handoff import ready_result
from workers import WorkerFailure
import workflow_auth

HOST_NODE = os.environ.get("ARCTURUS_HOST_NODE")
NODE = HOST_NODE or shutil.which("node")
SOURCE = Path(__file__).resolve()


class OfflineBoundary:
    """Authored fixtures exercise the Node oracle. This is not Seatbelt evidence."""

    def __init__(self, arc, schedule, repo, node, digest, credentials):
        self.arc, self.node = arc, node
        self.targets = (schedule.database, *sorted((schedule.root / "project-canaries").iterdir()))

    def run(self, d, scratch, args, out, timeout, hidden, proof_input):
        result = subprocess.run(
            [self.node, *args],
            cwd=d,
            input=proof_input,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": str(scratch)},
        )
        Path(out).write_text(result.stdout + result.stderr)
        return result.returncode, result.stdout

    def probe(self, snapshot, tag):
        script = """
const fs = require('node:fs');
for (const path of process.argv.slice(1)) {
  for (const probe of [() => fs.readFileSync(path), () => fs.openSync(path, 'r+')]) {
    try { probe(); process.exit(1); }
    catch (e) { if (e.code !== 'ERR_ACCESS_DENIED') process.exit(2); }
  }
}
"""
        result = subprocess.run(
            [
                self.node,
                "--no-addons",
                "--permission",
                f"--allow-fs-read={snapshot}",
                "-e",
                script,
                "--",
                *map(str, self.targets),
            ],
            cwd=snapshot,
            timeout=5,
            capture_output=True,
            env={"PATH": "/usr/bin:/bin"},
        )
        if result.returncode:
            raise WorkerFailure("Node fixture isolation controls failed")
        (self.arc.STATE / f"{tag}-probe.txt").write_text("Node permission fixture only\n")
        proof = {"mode": "mock_node_permissions_only"}
        if (self.arc.STATE.parent.parent / "force-coverage-failure").exists():
            # Simulate the archived proof shape for recovery validation without claiming host isolation.
            proof.update(reads=[True], writes=[True], contractReads=[True], signalDenied=True, forkDenied=True)
        (self.arc.STATE / f"{tag}-probe.json").write_bytes(encode(proof))


class FakeHTTPS:
    status = 200

    def __init__(self, host, *, port, timeout, context):
        self.provider = {"api.anthropic.com": "anthropic", "api.openai.com": "openai", "api.deepseek.com": "deepseek"}[
            host
        ]
        assert port == 443
        self.timeout = timeout
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED

    def request(self, method, path, *, body, headers):
        assert (
            method == "POST"
            and path
            == {
                "anthropic": "/v1/messages",
                "openai": "/v1/responses",
                "deepseek": "/chat/completions",
            }[self.provider]
        )
        anthropic = self.provider == "anthropic"
        assert headers.get("x-api-key" if anthropic else "authorization") == (
            "synthetic-engineering" if anthropic else "Bearer synthetic-engineering"
        )
        wire = json.loads(body)
        assert "tools" not in wire
        self.packet = json.loads(wire["input"] if self.provider == "openai" else wire["messages"][-1]["content"])
        packet = self.packet
        self.builder = "files" in packet
        assert self.timeout == (60 if self.builder else 30)
        project = packet["project"]
        peer = "project-b" if project == "project-a" else "project-a"
        assert peer.encode() not in body and b"schedule.sqlite" not in body and b"synthetic-engineering" not in body
        self.model = wire["model"]
        assert wire.get("max_tokens", wire.get("max_output_tokens")) == (3072 if self.builder else 1536)
        if self.provider == "deepseek":
            assert wire["thinking"] == {"type": "disabled"} and wire["response_format"] == {"type": "json_object"}
        if self.builder:
            if anthropic:
                assert wire["thinking"] == {"type": "disabled"} and wire["output_config"]["effort"] == "low"
            assert set(packet["files"]) == {"src/label.mjs"}
            if (Path.cwd() / "hang-builder").exists():
                (Path.cwd() / "builder-in-flight").touch()
                time.sleep(60)
            if (Path.cwd() / "hold-builder").exists():
                (Path.cwd() / "builder-in-flight").touch()
                while not (Path.cwd() / "release-builder").exists():
                    time.sleep(0.05)
            if packet["findings"]:
                assert packet["findings"][0]["file"] == "src/label.mjs"
                (Path.cwd() / "repair-in-flight").touch()
                while not (Path.cwd() / "release-repair").exists():
                    time.sleep(0.05)
        else:
            if self.provider == "openai":
                assert "thinking" not in wire and wire["text"]["format"]["strict"]
            assert packet["candidate"] and packet["evidence"] and packet["diff"]
            assert packet["approved_base_files"]["src/label.mjs"]["text"] == "export const label = () => 'baseline';\n"
            assert packet["protected_case_inputs"][0]["args"] == [2]
            tests = next(item for name, item in packet["evidence"].items() if name.endswith("-tests.txt"))
            proof = json.loads(tests["text"])
            assert proof["commit"] == packet["candidate"] and all(case["ok"] for case in proof["checks"])

    def getresponse(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def close(self):
        pass

    def read(self, _):
        p = self.packet
        if self.builder:
            bad = p["project"] == "project-a" and not p["findings"]
            expression = "value || 'missing'" if bad else "value"
            value = {
                "candidate": p["candidate"],
                "edits": [
                    {
                        "path": "src/label.mjs",
                        "before": p["files"]["src/label.mjs"]["before"],
                        "text": f"export const label = value => '{p['project']}:' + ({expression});\n",
                    }
                ],
            }
            truncated = (Path.cwd() / "truncate-builder").exists()
            text = "{" if (Path.cwd() / "malformed-builder").exists() else encode(value).decode()
            return self.envelope(text, 3072 if truncated else 1600, truncated)
        bad = "value || 'missing'" in p["diff"]
        value = {
            "verdict": "changes_requested" if bad else "approve",
            "summary": "Checked candidate",
            "tests_run": "Inspected runner evidence.",
            "findings": ([{"severity": "medium", "file": "src/label.mjs", "issue": "Preserve zero."}] if bad else []),
            "coverage": {
                "T1.1": {"status": "unverified" if bad else "met", "evidence": "Compared diff and runner proof."}
            },
        }
        if (Path.cwd() / "force-coverage-failure").exists():
            value["coverage"] = {}
        return self.envelope(encode(value).decode(), 32)

    def envelope(self, text, tokens, truncated=False):
        if self.provider == "anthropic":
            return encode(
                {
                    "model": self.model,
                    "stop_reason": "max_tokens" if truncated else "end_turn",
                    "content": [{"type": "text", "text": text}],
                    "usage": {"input_tokens": 128, "output_tokens": tokens},
                }
            )
        if self.provider == "deepseek":
            return encode(
                {
                    "model": self.model,
                    "object": "chat.completion",
                    "system_fingerprint": "fixture-fingerprint",
                    "choices": [
                        {
                            "index": 0,
                            "finish_reason": "length" if truncated else "stop",
                            "message": {"role": "assistant", "content": text},
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 128,
                        "completion_tokens": tokens,
                        "total_tokens": 128 + tokens,
                        "prompt_cache_hit_tokens": 8,
                        "prompt_cache_miss_tokens": 120,
                    },
                }
            )
        return encode(
            {
                "model": self.model,
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
                    "output_tokens": tokens,
                    "total_tokens": 128 + tokens,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens_details": {"reasoning_tokens": 0},
                },
            }
        )


class PatchChecks(unittest.TestCase):
    def test_builder_profile_has_its_own_approval_bytes_and_reserve(self):
        packet = {"task": "ENG-1", "candidate": "base"}
        params = {"project": "project-a", "source_job": 1, "expires_at": 1000}
        builder = trial_plan(
            packet,
            "anthropic",
            LIVE_MODELS["anthropic"],
            **params,
            build_schema=engineering.BUILDER_SCHEMA,
            engineering={"role": "builder"},
        )
        reviewer = trial_plan(packet, "anthropic", LIVE_MODELS["anthropic"], **params)
        self.assertEqual(
            (builder["max_output_tokens"], builder["timeout_seconds"], builder["illustrative_reserve_microusd"]),
            (3072, 60, 531_968),
        )
        self.assertEqual(
            (reviewer["max_output_tokens"], reviewer["timeout_seconds"], reviewer["illustrative_reserve_microusd"]),
            (1536, 30, 528_128),
        )
        self.assertNotIn("thinking", json.loads(reviewer["body_utf8"]))
        self.assertNotEqual(builder["body_sha256"], reviewer["body_sha256"])
        self.assertEqual(
            builder["plan_sha256"], engineering.sha(encode({k: v for k, v in builder.items() if k != "plan_sha256"}))
        )

    def test_rejects_stale_unowned_duplicate_and_path_aliases(self):
        packet = {"candidate": "head", "files": {"src/a.js": {"before": "blob"}}}
        good = {"path": "src/a.js", "before": "blob", "text": "export const a = 2;"}
        self.assertEqual(
            engineering.patch_edits({"candidate": "head", "edits": [good]}, packet),
            {"src/a.js": b"export const a = 2;"},
        )
        for patch in (
            {"candidate": "wrong", "edits": [good]},
            {"candidate": "head", "edits": [good, good]},
            *(
                {"candidate": "head", "edits": [{**good, **edit}]}
                for edit in (
                    {"path": "src/../test/acceptance/coordinator.json"},
                    {"path": "src/b.js"},
                    {"before": "different"},
                )
            ),
        ):
            with self.assertRaises(WorkerFailure):
                engineering.patch_edits(patch, packet)
        with self.assertRaisesRegex(WorkerFailure, "case aliases"):
            engineering.check_aliases(["src/Folder/a.js", "src/folder/b.js"])


@unittest.skipUnless(NODE, "probe controls require Node")
class BoundaryProbe(unittest.TestCase):
    def test_unsandboxed_probes_detect_signal_and_protected_answer_access(self):
        """Run the actual attack code against disposable files and a disposable child."""
        from test_arc_unit import arc

        class Unrestricted(engineering.Boundary):
            def run(self, d, scratch, args, out, timeout, hidden, proof_input):
                result = subprocess.run([self.runtime, *args], cwd=d, capture_output=True, text=True, timeout=timeout)
                self.stdout = result.stdout
                Path(out).write_text(result.stdout + result.stderr)
                return result.returncode, result.stdout

        with tempfile.TemporaryDirectory(dir="/tmp") as folder:
            root = Path(folder).resolve()
            snapshot = root / "snapshot"
            contract = snapshot / engineering.CONTRACT
            contract.parent.mkdir(parents=True)
            contract.write_text('[{"expected":"synthetic answer"}]')
            (snapshot / "read-control").write_text("synthetic")
            outside = root / "external-control"
            outside.write_text("synthetic")
            boundary = Unrestricted(SimpleNamespace(STATE=root, fresh_dir=arc.fresh_dir), NODE, [outside])
            with self.assertRaisesRegex(WorkerFailure, "effective Seatbelt boundary"):
                boundary.probe(snapshot, "unrestricted")
            proof = json.loads(boundary.stdout)
            self.assertFalse(proof["signalDenied"])
            self.assertEqual(proof["reads"], [False, False])
            self.assertEqual(proof["contractReads"], [False] * (len(engineering.tmp_aliases(contract)) + 1))
            self.assertFalse((root / "unrestricted-probe.json").exists())


@unittest.skipUnless(NODE, "fixture requires Node permissions")
class ConcurrentEngineering(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name).resolve()
        self.queue = Scheduler(self.root / "schedule")
        node_digest = engineering.sha(Path(NODE).read_bytes())
        self.manifests = []
        for project in ("project-a", "project-b"):
            repo = self.root / project
            repo.mkdir()

            def git(*args):
                return subprocess.check_output(
                    ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-C", str(repo), *args],
                    text=True,
                ).strip()

            git("init", "-q", "-b", "main")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            (repo / "src").mkdir()
            (repo / "src/label.mjs").write_text("export const label = () => 'baseline';\n")
            contract = repo / "test/acceptance/coordinator.json"
            contract.parent.mkdir(parents=True)
            contract.write_bytes(
                encode(
                    [
                        {
                            "id": "label",
                            "criterion": "T1.1",
                            "entry": "src/label.mjs",
                            "export": "label",
                            "args": [2],
                            "expected": f"{project}:2",
                        }
                    ]
                )
            )
            git("add", "--all")
            git("commit", "-qm", "fixture")
            self.manifests.append(
                {
                    "project": project,
                    "task": "label-values",
                    "repository": str(repo),
                    "base": git("rev-parse", "HEAD"),
                    "goal": "Preserve zero in the label.",
                    "allowed_paths": ["src/label.mjs"],
                    "acceptance": ["Prefix numeric values including zero."],
                    "protected_tests": {"test/acceptance/coordinator.json": engineering.sha(contract.read_bytes())},
                    "providers": {
                        role: {"provider": provider, "model": LIVE_MODELS[provider]}
                        for role, provider in (("builder", "anthropic"), ("reviewer", "openai"))
                    },
                    "limits": {
                        "concurrency": 1,
                        "seconds": 60,
                        "requests": 4,
                        "repairs": 1,
                        "retries": 0,
                        "reserve_microusd": 2_200_000,
                    },
                    "node_sha256": node_digest,
                }
            )
        engineering.enroll(self.queue, self.manifests)
        private = self.root / "private"
        private.mkdir(mode=0o700)
        key = private / "fixture-key"
        key.write_text("synthetic-engineering\n")
        key.chmod(0o600)
        self.credentials = dict.fromkeys(LIVE_MODELS, str(key))

    def run_fixture(self, on_tick=lambda: None, approve=True):
        spawn = subprocess.Popen

        def inject(argv, **kwargs):
            self.assertEqual(Path(argv[2]).name, "engineering.py")
            if HOST_NODE:
                kwargs["env"]["ARCTURUS_TEST_NATIVE_BOUNDARY"] = "1"
            return spawn([*argv[:2], str(SOURCE), *argv[3:]], **kwargs)

        def tick():
            if approve:
                for row in self.queue.status()["engineering_requests"]:
                    if row["approved"] is None and self.queue.job(row["job"])["state"] == "running":
                        engineering.approve_step(self.queue, row["session"], row["digest"])
            on_tick()
            return False

        with patch("concurrent_runs.subprocess.Popen", side_effect=inject):
            self.queue.run(str(Path(NODE).resolve()), tick, self.credentials)

    @unittest.skipUnless(HOST_NODE and sys.platform == "darwin", "requires opt-in normal Terminal Seatbelt")
    def test_effective_host_preflight(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(Path(engineering.__file__).with_name("concurrent_runs.py")),
                str(self.queue.root),
                "engineering-preflight",
                "--node",
                str(Path(NODE).resolve()),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        state = self.queue.status()
        self.assertEqual(state["engineering_requests"], [])
        self.assertEqual(state["api_review"], [])
        self.assertEqual([job["state"] for job in state["job"]], ["queued", "queued"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS effective engineering Seatbelt boundary", result.stdout)

    def test_two_projects_run_and_independent_review_routes_repair(self):
        observed = []

        def release():
            if (self.queue.workspace(1) / "repair-in-flight").exists() and self.queue.job(2)["state"] == "ready":
                observed.append(self.queue.job(1)["state"])
                (self.queue.workspace(1) / "release-repair").touch()

        self.run_fixture(release)
        state = self.queue.status()
        logs = [(self.queue.workspace(i) / "output.log").read_text() for i in (1, 2)]
        self.assertEqual([j["state"] for j in state["job"]], ["ready", "ready"], (state, logs))
        self.assertIn("running", observed)
        self.assertEqual([j["checkpoint"]["repairs"] for j in state["job"]], [1, 0])
        self.assertEqual(len(state["api_review"]), 6)
        for job in state["job"]:
            journal = json.loads(Path(job["checkpoint"]["journal"]).read_text())["tasks"][f"ENG-{job['id']}"]
            rows = [r for r in state["api_review"] if r["job"] == job["id"]]
            self.assertEqual([r["session"] for r in rows], [r["session"] for r in journal["dispatches"]])
            self.assertEqual(rows[-1]["candidate"], job["checkpoint"]["candidate"])
            repo = Path(self.manifests[job["id"] - 1]["repository"])
            self.assertEqual((repo / "src/label.mjs").read_text(), "export const label = () => 'baseline';\n")

    def test_workflow_routes_all_providers_with_distinct_review_and_build_roles(self):
        self.queue = Scheduler(self.root / "routed-schedule")
        anthropic = {"provider": "anthropic", "model": LIVE_MODELS["anthropic"]}
        openai = {"provider": "openai", "model": LIVE_MODELS["openai"]}
        deepseek = {
            "provider": "deepseek",
            "model": LIVE_MODELS["deepseek"],
            "data_class": "synthetic",
            "fingerprint": "fixture-fingerprint",
        }
        assignments = [{"builder": deepseek, "reviewer": anthropic}, {"builder": openai, "reviewer": deepseek}]
        engineering.enroll(
            self.queue, [{**manifest, "providers": routes} for manifest, routes in zip(self.manifests, assignments)]
        )
        self.assertIsNone(self.queue.claim(("anthropic", "openai")))
        self.authorize_workflow(1)
        self.authorize_workflow(2)

        def release():
            work = self.queue.workspace(1)
            if (work / "repair-in-flight").exists():
                (work / "release-repair").touch()

        self.run_fixture(release, approve=False)
        state = self.queue.status()
        self.assertEqual([job["state"] for job in state["job"]], ["ready", "ready"], state["job"])
        for job, expected in [(1, ["deepseek", "anthropic", "deepseek", "anthropic"]), (2, ["openai", "deepseek"])]:
            rows = [row for row in state["api_review"] if row["job"] == job]
            self.assertEqual([row["provider"] for row in rows], expected)
            self.assertEqual(ready_result(self.queue, job)["independent_review"]["provider"], expected[-1])

    def authorize_workflow(self, job, *, requests=4, repairs=1, reserve=2_200_000, operations=None):
        operations = operations or ["build", "review", "repair"]
        args = (job, int(time.time()) + 55, requests, repairs, reserve, operations)
        plan = workflow_auth.prepare(self.queue, *args)
        with self.assertRaisesRegex(ValueError, "does not match"):
            workflow_auth.approve(self.queue, *args, "0" * 64)
        workflow_auth.approve(self.queue, *args, plan["authorization_sha256"])
        return plan["authorization_sha256"]

    def test_workflow_authorization_advances_within_reserve_and_caps(self):
        first = self.authorize_workflow(1)
        second = self.authorize_workflow(2, requests=1, repairs=0, operations=["build", "review"])

        def release():
            if (self.queue.workspace(1) / "repair-in-flight").exists():
                (self.queue.workspace(1) / "release-repair").touch()

        self.run_fixture(release, approve=False)
        state = self.queue.status()
        self.assertEqual([j["state"] for j in state["job"]], ["ready", "blocked"])
        self.assertIn("limit reached", state["job"][1]["reason"])
        self.assertEqual([p["paused"] for p in state["project"]], [0, 1])
        rows = state["workflow_dispatches"]
        self.assertEqual(
            [r["operation"] for r in rows if r["authorization"] == first], ["build", "review", "repair", "review"]
        )
        self.assertEqual([r["operation"] for r in rows if r["authorization"] == second], ["build"])
        self.assertEqual({r["session"] for r in rows}, {r["session"] for r in state["api_review"]})
        self.assertEqual(sum(r["reserve_microusd"] for r in state["api_review"] if r["job"] == 1), 2_116_240)
        self.assertEqual(sum(r["consumed"] is None for r in state["engineering_requests"]), 1)
        handoff = ready_result(self.queue, 1)
        self.assertEqual(handoff["candidate"], state["job"][0]["checkpoint"]["candidate"])
        self.assertEqual(handoff["protected_tests"]["passed"], 1)
        self.assertEqual(handoff["independent_review"]["provider"], "openai")
        self.assertIsNone(handoff["independent_review"]["actual_charge_microusd"])
        with self.assertRaisesRegex(ValueError, "requires a READY"):
            ready_result(self.queue, 2)
        evidence = Path(json.loads(self.queue.job(1)["checkpoint"])["journal"]).parent
        for path in evidence.glob("ENG-*-review*.json"):
            path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "no longer verify"):
            ready_result(self.queue, 1)

    def test_workflow_revocation_during_transport_holds_reserve_and_fences_later_requests(self):
        self.authorize_workflow(1)
        self.queue.control("pause", "project-b")
        work = self.queue.workspace(1)
        work.mkdir()
        (work / "hang-builder").touch()

        def revoke():
            if not self.queue.job(1)["cancelled"] and (work / "builder-in-flight").exists():
                workflow_auth.revoke(self.queue, 1)

        self.run_fixture(revoke, approve=False)
        state = self.queue.status()
        self.assertEqual([j["state"] for j in state["job"]], ["cancelled", "queued"])
        (row,) = state["api_review"]
        self.assertEqual((row["state"], row["reserve_microusd"]), ("uncertain", 531_968))
        self.assertIsNotNone(state["workflow_authorizations"][0]["revoked"])
        self.assertEqual(state["project"][0]["paused"], 1)
        self.run_fixture(approve=False)
        self.assertEqual(self.queue.status(), state)

    def test_workflow_pause_holds_a_staged_review_until_resume(self):
        self.authorize_workflow(2, requests=2, repairs=0, operations=["build", "review"])
        self.queue.control("pause", "project-a")
        work = self.queue.workspace(2)
        work.mkdir()
        (work / "hold-builder").touch()
        observed = []

        def pause_then_resume():
            if not (work / "builder-in-flight").exists():
                return
            if not observed:
                self.queue.control("pause", "project-b")
                (work / "release-builder").touch()
                observed.append("paused")
            elif observed == ["paused"]:
                state = self.queue.status()
                if len(state["engineering_requests"]) == 2:
                    request = state["engineering_requests"][-1]
                    self.assertIsNone(request["consumed"])
                    self.assertEqual(len(state["api_review"]), 1)
                    self.queue.control("resume", "project-b")
                    observed.append("resumed")

        self.run_fixture(pause_then_resume, approve=False)
        self.assertEqual(observed, ["paused", "resumed"])
        self.assertEqual(self.queue.job(2)["state"], "ready")

    def test_cancel_uncertain_builder_then_restart_does_not_replay(self):
        work = self.queue.workspace(1)
        work.mkdir()
        (work / "hang-builder").touch()
        observed = []

        def cancel():
            if not observed and (work / "builder-in-flight").exists():
                self.queue.control("cancel", 1)
                observed.append(True)

        self.run_fixture(cancel)
        state = self.queue.status()
        self.assertEqual([j["state"] for j in state["job"]], ["cancelled", "ready"])
        first = next(r for r in state["api_review"] if r["job"] == 1)
        self.assertEqual(first["state"], "uncertain")
        self.assertGreater(first["reserve_microusd"], 0)
        self.run_fixture()
        self.assertEqual(self.queue.status(), state)

    def test_review_only_recovery_preserves_original_jobs_and_reserves(self):
        self.queue = Scheduler(self.root / "recovery-schedule")
        engineering.enroll(
            self.queue,
            [
                {
                    **manifest,
                    "limits": {
                        **manifest["limits"],
                        "requests": 2,
                        "repairs": 0,
                        "reserve_microusd": 1_058_120,
                    },
                }
                for manifest in self.manifests
            ],
        )
        for job in (1, 2):
            work = self.queue.workspace(job)
            work.mkdir()
            (work / "force-coverage-failure").touch()
        self.run_fixture()
        original = self.queue.status()
        self.assertEqual([job["state"] for job in original["job"]], ["blocked", "blocked"])
        self.assertEqual(
            original["settings"][0]["budget"], sum(row["reserve_microusd"] for row in original["api_review"])
        )
        expires = int(time.time()) + 120
        model = LIVE_MODELS["openai"]
        recoveries = []
        for source in (1, 2):
            candidate = next(
                row["candidate"]
                for row in original["api_review"]
                if row["job"] == source and row["provider"] == "openai"
            )
            with self.assertRaisesRegex(ValueError, "failed verification"):
                self.queue.prepare_recovery(source, "0" * 40, expires)
            plan = self.queue.prepare_recovery(source, candidate, expires)
            repo = self.queue.workspace(source) / "repo"
            label = repo / "src/label.mjs"
            committed = label.read_bytes()
            try:
                label.write_bytes(committed + b"\n")
                subprocess.run(["git", "-C", str(repo), "add", "--", "src/label.mjs"], check=True)
                label.write_bytes(committed)
                with self.assertRaisesRegex(ValueError, "failed verification"):
                    self.queue.prepare_recovery(source, candidate, expires)
            finally:
                label.write_bytes(committed)
                subprocess.run(["git", "-C", str(repo), "reset", "-q", candidate, "--", "src/label.mjs"], check=True)
            (test_log,) = (self.queue.workspace(source) / "runtime/runner-state").glob("ENG-*-tests.txt")
            saved = test_log.read_bytes()
            try:
                test_log.write_bytes(saved + b" ")
                with self.assertRaisesRegex(ValueError, "failed verification"):
                    self.queue.prepare_recovery(source, candidate, expires)
            finally:
                test_log.write_bytes(saved)
            with self.assertRaisesRegex(ValueError, "does not match"):
                self.queue.approve_review(source, "openai", model, "0" * 64, recovery=(candidate, expires))
            self.assertIsNone(self.queue.claim(("openai",)))
            job = self.queue.approve_review(source, "openai", model, plan["plan_sha256"], recovery=(candidate, expires))
            renewal = self.queue.prepare_recovery(source, candidate, expires + 1)
            with self.assertRaisesRegex(ValueError, "already approved"):
                self.queue.approve_review(
                    source, "openai", model, renewal["plan_sha256"], recovery=(candidate, expires + 1)
                )
            recoveries.append((job, plan))
            # Keep both reviews queued until both original approvals have been checked.
            self.queue.control("pause", plan["project"])
        self.assertEqual(self.queue.status()["settings"], original["settings"])
        for _, plan in recoveries:
            self.queue.control("resume", plan["project"])
        spawn = subprocess.Popen

        def inject(argv, **kwargs):
            self.assertEqual(Path(argv[2]).name, "paid_review.py")
            return spawn([*argv[:2], str(SOURCE), *argv[3:]], **kwargs)

        with patch("concurrent_runs.subprocess.Popen", side_effect=inject):
            self.queue.run(NODE, lambda: False, {"openai": self.credentials["openai"]})
            recovered = self.queue.status()
            self.queue.run(NODE, lambda: False, {"openai": self.credentials["openai"]})
        self.assertEqual(recovered, self.queue.status())
        self.assertEqual(recovered["job"][:2], original["job"])
        self.assertEqual(recovered["engineering_requests"], original["engineering_requests"])
        self.assertEqual(recovered["api_review"][:4], original["api_review"])
        self.assertEqual([job["state"] for job in recovered["job"][2:]], ["changes_requested", "ready"])
        self.assertEqual(recovered["settings"][0]["budget"] - original["settings"][0]["budget"], 2 * 526_152)
        for job, plan in recoveries:
            row = self.queue.job(job)
            self.assertEqual(json.loads(row["checkpoint"])["candidate"], plan["candidate"])
            self.assertEqual(json.loads(self.queue.approval(job)["receipt"])["stop_reason"], "completed")
        recovered_job, recovered_plan = recoveries[1]
        result = ready_result(self.queue, recovered_job)
        self.assertEqual((result["candidate"], result["source_job"]), (recovered_plan["candidate"], 2))
        with self.assertRaisesRegex(ValueError, "requires a READY"):
            ready_result(self.queue, recoveries[0][0])
        self.assertEqual([row["provider"] for row in recovered["api_review"][4:]], ["openai", "openai"])

    def test_truncated_and_malformed_builder_responses_never_apply(self):
        for job, marker in ((1, "truncate-builder"), (2, "malformed-builder")):
            work = self.queue.workspace(job)
            work.mkdir()
            (work / marker).touch()
        self.run_fixture()
        state = self.queue.status()
        self.assertEqual([job["state"] for job in state["job"]], ["blocked", "blocked"])
        self.assertEqual(len(state["api_review"]), 2)
        receipts = [row["receipt"] for row in sorted(state["engineering_requests"], key=lambda row: row["job"])]
        self.assertEqual(
            [(r["stop_reason"], r["reason"]) for r in receipts],
            [
                ("max_tokens", "Anthropic builder output truncated"),
                ("end_turn", "malformed Anthropic builder patch"),
            ],
        )
        for job, receipt in enumerate(receipts, 1):
            self.assertEqual(receipt["reserve_microusd"], 531_968)
            self.assertEqual(receipt["state"], "rejected")
            self.assertIsNone(receipt["actual_charge_microusd"])
            repo = self.queue.workspace(job) / "repo"
            head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            self.assertEqual(head, self.manifests[job - 1]["base"])

    def test_unapproved_steps_never_reserve_or_call_a_provider(self):
        checked = []

        def stop_unapproved():
            rows = self.queue.status()["engineering_requests"]
            if len(rows) != 2 or checked:
                return
            self.assertEqual(self.queue.status()["api_review"], [])
            with self.assertRaisesRegex(WorkerFailure, "eligible"):
                engineering.approve_step(self.queue, rows[0]["session"], rows[1]["digest"])
            self.queue.control("cancel", 1)
            self.queue.control("cancel", 2)
            checked.append(True)

        self.run_fixture(stop_unapproved, approve=False)
        self.assertTrue(checked)
        self.assertEqual(self.queue.status()["api_review"], [])
        self.assertTrue(all(row["consumed"] is None for row in self.queue.status()["engineering_requests"]))

    def test_project_cannot_borrow_a_peers_unspent_budget(self):
        self.queue = Scheduler(self.root / "bounded-schedule")
        first = self.manifests[0]
        first = {**first, "limits": {**first["limits"], "reserve_microusd": 531_968}}
        engineering.enroll(self.queue, [first, self.manifests[1]])
        self.run_fixture()
        state = self.queue.status()
        self.assertEqual([j["state"] for j in state["job"]], ["blocked", "ready"])
        self.assertIn("reserve ceiling", state["job"][0]["reason"])
        self.assertEqual([r["reserve_microusd"] for r in state["api_review"] if r["job"] == 1], [531_968])
        reviewer = [r for r in state["engineering_requests"] if r["job"] == 1][-1]
        self.assertIsNotNone(reviewer["approved"])
        self.assertIsNone(reviewer["consumed"])


if __name__ == "__main__":
    if len(sys.argv) == 5:
        import paid_review

        paid_review.main(FakeHTTPS)
    else:
        boundary = (
            engineering.host_boundary if os.environ.get("ARCTURUS_TEST_NATIVE_BOUNDARY") == "1" else OfflineBoundary
        )
        engineering.main(FakeHTTPS, boundary)
