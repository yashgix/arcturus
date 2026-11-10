"""Mock cross-provider demo through the real Arcturus task loop.

Run with python3 -m unittest discover -s tests -p test_coordinator_unit.py -v.
"""

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_arc_unit import GOOD, arc, gitc, good_probe, make_repo
from workers import Dispatch, Limits, Result, Usage, Worker, WorkerFailure


@unittest.skipUnless(shutil.which("node"), "demo needs Node for its protected acceptance test")
class CoordinatorCycle(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.repo = root / "project"
        state = root / "state"
        state.mkdir()
        make_repo(self.repo)
        (self.repo / "test/acceptance/a.test.js").unlink()
        (self.repo / arc.ACCEPTANCE_FILE).write_text(
            json.dumps(
                [
                    {
                        "id": "value",
                        "criterion": "T1.1",
                        "entry": "src/x.js",
                        "export": "atLeastTwo",
                        "args": [],
                        "expected": True,
                    }
                ]
            )
        )
        gitc(self.repo, "add", "-A")
        gitc(self.repo, "commit", "-qm", "protected contract")
        self.base = gitc(self.repo, "rev-parse", "main")
        self.issue = {
            "id": "task",
            "identifier": "ARC-1",
            "projectId": "p",
            "title": "Return three",
            "description": "Adjust the exported value.",
        }
        self.spec = {"id": "T1", "owned_paths": ["src/"], "acceptance": ["The exported value is three."]}
        self.j = {"tasks": {}, "own_comments": []}
        self.calls = []
        self.values = iter([2, 3, 4])
        self.reviews = iter(["changes_requested", "approve"])
        self.edited = "src/x.js"
        self.patch(
            STATE=state,
            GROUPS=state / "live-groups.json",
            CFG={"projects": {"demo": {"dir": str(self.repo), "policy": "mock", "protected": ["test/acceptance"]}}},
            project_ids=lambda: {"demo": "p"},
            validate_policy=lambda _: [],
            say=lambda *args: None,
            set_status=lambda *args: None,
            assert_quiescent=lambda: None,
            sandboxed_node=self.sandbox_fixture,
        )

    def patch(self, **kwargs):
        p = patch.multiple(arc, **kwargs)
        p.start()
        self.addCleanup(p.stop)

    def sandbox_fixture(
        self,
        repo,
        scratch,
        args,
        output,
        timeout,
        test=True,
        hidden=(),
        proof_input=None,
        node=None,
        *,
        scratch_noexec=False,
    ):
        # The desktop sandbox cannot nest sandbox-exec. Only this authored fixture runs directly.
        if args == ["test/isolation.probe.test.js"]:
            nonce = (scratch / "nonce").read_text()
            (scratch / "results-runner-test-sandbox-1.json").write_text(json.dumps(good_probe(nonce)))
            code, text = 0, "ℹ pass 1\nℹ fail 0\n"
        else:
            result = subprocess.run(
                [os.environ.get("ARCTURUS_TEST_NODE", "node"), *args],
                cwd=repo,
                input=proof_input,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={"PATH": "/usr/bin:/bin"} if proof_input is not None else None,
            )
            code, text = result.returncode, result.stdout if proof_input is not None else result.stdout + result.stderr
        Path(output).write_text(text)
        return code, text

    def build(self, request):
        self.calls.append(request)
        saved = arc.journal()["tasks"]["task"]["dispatches"][-1]
        self.assertEqual(saved["session"], request.session)
        self.assertEqual(saved["status"], "running")
        if self.edited != "src/x.js":
            (self.repo / self.edited).write_text("// unauthorized\n")
        else:
            value = next(self.values)
            (self.repo / self.edited).write_text(
                f"export const v = {value};\nexport const atLeastTwo = () => v >= 2;\n"
            )
        gitc(self.repo, "add", "-A")
        gitc(self.repo, "commit", "-qm", request.role)
        request.output.write_text('{"summary":"mock change"}')
        return Result(Usage(11, 0), {"exit": 0, "response": {"summary": "mock change"}})

    def review(self, request):
        self.calls.append(request)
        verdict = next(self.reviews)
        if verdict == "interrupt":
            raise KeyboardInterrupt
        if verdict == "malformed":
            request.output.write_text("{oops")
        else:
            changed = verdict in {"changes_requested", "contradiction", "unowned", "traversal"}
            findings = (
                [
                    {
                        "severity": "high",
                        "file": {"unowned": "package.json", "traversal": "src/../../outside"}.get(verdict, "src/x.js"),
                        "issue": "Return three instead of two.",
                    }
                ]
                if changed
                else []
            )
            output = {
                **GOOD,
                "verdict": "changes_requested" if verdict == "changes_requested" else "approve",
                "findings": findings,
                "coverage": [
                    {
                        "criterion": "T1.1",
                        "status": "not_met" if changed else "met",
                        "evidence": "Inspected source and runner log.",
                    }
                ],
            }
            request.output.write_text(json.dumps(output))
        return Result(Usage(7, 0), {"exit": 0})

    def execute(self, limits=Limits(), reversed_roles=False):
        roles = frozenset({"builder", "reviewer"})
        workers = {
            "one": Worker("mock-claude", "mock", roles, frozenset({"read"}), self.build),
            "two": Worker("mock-codex", "mock", roles, frozenset({"read"}), self.review),
        }
        if reversed_roles:
            workers["one"], workers["two"] = (
                Worker("mock-codex", "mock", roles, frozenset({"read"}), self.build),
                Worker("mock-claude", "mock", roles, frozenset({"read"}), self.review),
            )
        dispatcher = Dispatch(workers, {"builder": "one", "reviewer": "two"}, limits)
        with arc.lock():
            return arc.run_one(
                self.j, self.issue, "demo", ctx={"spec": self.spec, "approval": "mock operator", "dispatch": dispatcher}
            )

    def task(self):
        return arc.journal()["tasks"]["task"]

    def test_demo_automatic_handoff(self):
        self.assertEqual(self.execute(), "ready")
        record = self.task()
        self.assertEqual([r.role for r in self.calls], ["builder", "reviewer", "builder", "reviewer"])
        self.assertEqual(len({r.session for r in self.calls}), 4)
        self.assertIn("Return three", self.calls[2].findings[0]["issue"])
        self.assertEqual(self.calls[1].candidate, self.calls[2].candidate)
        self.assertEqual(record["repairs"], 1)
        self.assertEqual(record["dispatches"][2]["handoff_attempt"], record["history"][0]["attempt"])
        self.assertEqual(gitc(self.repo, "rev-parse", "main"), self.base)
        self.assertEqual(arc.receipt_problems(self.j, "task"), [])
        self.assertEqual(sum(d["usage"]["tokens"] for d in record["dispatches"]), 36)

    def test_repair_without_tree_change_does_not_get_another_review(self):
        original = self.build

        def empty_repair(request):
            if not request.findings:
                return original(request)
            self.calls.append(request)
            gitc(self.repo, "commit", "--allow-empty", "-qm", "no candidate change")
            return Result(Usage(0, 0), {"exit": 0, "response": {"summary": "No source change"}})

        self.build = empty_repair
        self.assertEqual(self.execute(), "blocked")
        self.assertEqual(self.task()["reason"], "repair did not change the candidate tree")
        self.assertEqual([request.role for request in self.calls], ["builder", "reviewer", "builder"])

    def test_roles_reverse_without_engine_change(self):
        self.assertEqual(self.execute(reversed_roles=True), "ready")
        self.assertEqual([d["provider"] for d in self.task()["dispatches"][:2]], ["mock-codex", "mock-claude"])

    def test_approve_with_blocking_finding_still_repairs(self):
        self.reviews = iter(["contradiction", "approve"])
        self.assertEqual(self.execute(), "ready")
        self.assertEqual(self.task()["repairs"], 1)

    def test_unowned_review_finding_escalates(self):
        self.reviews = iter(["unowned"])
        self.assertEqual(self.execute(), "blocked")
        self.assertEqual(len(self.calls), 2)
        self.assertIn("cannot be routed", self.task()["reason"])

    def test_malformed_review_cannot_approve_and_retry_is_bounded(self):
        self.reviews = iter(["malformed"] * 3)
        self.assertEqual(self.execute(Limits(retries=1)), "blocked")
        self.assertEqual([d["retry"] for d in self.task()["dispatches"]], [False, False, True])

    def test_two_automatic_repairs(self):
        self.reviews = iter(["changes_requested"] * 3)
        self.assertEqual(self.execute(), "blocked")
        self.assertEqual(self.task()["repairs"], 2)
        self.assertEqual(len(self.calls), 6)

    def test_request_budget_prevents_dispatch(self):
        self.assertEqual(self.execute(Limits(requests=1)), "blocked")
        self.assertEqual(len(self.calls), 1)

    def test_token_budget_rejects_result(self):
        self.assertEqual(self.execute(Limits(tokens=10)), "blocked")
        self.assertEqual(self.task()["dispatches"][0]["usage"]["tokens"], 11)
        self.assertIn("budget exceeded", self.task()["reason"])

    def test_estimated_spending_budget_rejects_result(self):
        original = self.build
        self.build = lambda request: Result(Usage(11, 2), original(request).payload)
        self.assertEqual(self.execute(Limits(estimated_usd=1)), "blocked")
        self.assertEqual(self.task()["dispatches"][0]["usage"]["estimated_usd"], 2)

    def test_duration_budget_prevents_dispatch(self):
        with patch("workers.time.time", side_effect=[100, 102]):
            # arc and workers share the time module. Journal/log setup itself uses strftime.
            self.assertEqual(self.execute(Limits(seconds=1)), "blocked")
        self.assertEqual(self.calls, [])

    def test_owned_path_check_stops_unauthorized_edit(self):
        self.edited = "package.json"
        self.assertEqual(self.execute(), "blocked")
        self.assertIn("unauthorized edits", self.task()["reason"])
        self.assertEqual(len(self.calls), 1)

    def test_protected_file_check_stops_unauthorized_edit(self):
        self.edited = arc.ACCEPTANCE_FILE
        self.assertEqual(self.execute(), "blocked")
        self.assertIn("protected acceptance", self.task()["reason"])
        self.assertEqual(len(self.calls), 1)

    def test_interruption_and_recovery_do_not_redispatch(self):
        self.reviews = iter(["interrupt"])
        with self.assertRaises(KeyboardInterrupt):
            self.execute()
        self.j = arc.journal()
        self.assertEqual(self.task()["dispatches"][-1]["status"], "running")
        arc.mark_interrupted(self.j)
        self.assertEqual(self.task()["stage"], "interrupted")
        self.assertEqual(self.task()["dispatches"][-1]["status"], "interrupted")
        with self.assertRaises(SystemExit):
            self.execute()
        self.assertEqual(len(self.calls), 2)

    def test_completed_task_cannot_dispatch_twice(self):
        self.assertEqual(self.execute(), "ready")
        self.j = arc.journal()
        with self.assertRaises(SystemExit):
            self.execute()
        self.assertEqual(len(self.calls), 4)

    def test_leading_space_git_path_is_distinct_from_owned_path(self):
        original = self.build

        def both_paths(request):
            result = original(request)
            disguised = self.repo / " src/x.js"
            disguised.parent.mkdir()
            disguised.write_text("export const v = 99;")
            gitc(self.repo, "add", "--", " src/x.js")
            gitc(self.repo, "commit", "-qm", "out of scope")
            raw = arc.git_bytes(self.repo, "diff", "--name-only", "-z", self.base, "HEAD")
            self.assertEqual(raw.split(b"\0")[:-1], [b" src/x.js", b"src/x.js"])
            return result

        self.build = both_paths
        self.assertEqual(self.execute(), "blocked")
        self.assertIn("b' src/x.js'", self.task()["reason"])
        self.assertEqual([r.role for r in self.calls], ["builder"])

    def test_reviewer_sees_tested_snapshot_even_if_builder_checkout_drifts(self):
        original = self.review

        def inspect(request):
            checkout_file = self.repo / "src/x.js"
            tested_file = Path(request.workspace) / "src/x.js"
            self.assertNotEqual(tested_file, checkout_file)
            expected = tested_file.read_bytes()
            checkout_file.write_text("export const v = -1;")
            self.assertEqual(tested_file.read_bytes(), expected)
            self.assertIn(b"v = 2", expected)
            self.assertFalse((Path(request.workspace) / ".git").exists())
            return original(request)

        self.review = inspect
        self.assertEqual(self.execute(), "blocked")
        self.assertIn("working copy differs", self.task()["reason"])
        self.assertEqual([r.role for r in self.calls], ["builder", "reviewer"])
        self.assertFalse(Path(self.calls[-1].workspace).exists())

    @unittest.skipUnless(shutil.which("cc") and os.uname().sysname == "Darwin", "requires the installed macOS compiler")
    def test_native_addon_cannot_forge_acceptance_completion(self):
        c_file = arc.STATE / "forge.c"
        c_file.write_text(r"""
#include <unistd.h>
__attribute__((constructor)) static void forge(void) {
    const char success[] = "{\"value\":true}";
    write(1, success, sizeof(success) - 1);
    _exit(0);
}
""")
        addon = self.repo / "src/forge.node"
        subprocess.run(["cc", "-dynamiclib", "-o", str(addon), str(c_file)], check=True, capture_output=True)
        source = self.repo / "src/x.js"
        source.write_text(
            "import {createRequire} from 'node:module';\n"
            "createRequire(import.meta.url)('./forge.node');\n"
            "export const atLeastTwo = () => false;"
        )
        node = os.environ.get("ARCTURUS_TEST_NODE", "node")
        old = subprocess.run(
            [node, "--input-type=module", "-e", "await import('./src/x.js')"],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(json.loads(old.stdout), {"value": True})
        gitc(self.repo, "add", "--", "src")
        gitc(self.repo, "commit", "-qm", "native acceptance forgery")
        head = gitc(self.repo, "rev-parse", "HEAD")
        checks, _, _ = arc.candidate_checks(self.repo, head, self.base, ["T1.1"], "addon")
        self.assertFalse(checks["ok"])
        proof = json.loads(Path(checks["log"]).read_text())
        self.assertEqual(proof["checks"][0]["id"], "value")
        self.assertNotEqual(proof["checks"][0]["exit"], 0)

    def test_hidden_worktree_edit_is_rejected(self):
        original = self.build

        def hide(request):
            result = original(request)
            gitc(self.repo, "update-index", "--assume-unchanged", "package.json")
            (self.repo / "package.json").write_text("{}")
            self.assertEqual(gitc(self.repo, "status", "--porcelain"), "")
            return result

        self.build = hide
        self.assertEqual(self.execute(), "blocked")
        self.assertIn("index flags", self.task()["reason"])
        self.assertEqual(len(self.calls), 1)

    def test_symlink_and_gitlink_are_rejected(self):
        (self.repo / "src/escape").symlink_to("../../outside")
        gitc(self.repo, "add", "src/escape")
        gitc(self.repo, "commit", "-qm", "symlink")
        with self.assertRaisesRegex(arc.Blocked, "symlink"):
            arc.candidate_tree(self.repo, "HEAD")
        gitc(self.repo, "rm", "-q", "src/escape")
        gitc(self.repo, "update-index", "--add", "--cacheinfo", f"160000,{self.base},src/gitlink")
        gitc(self.repo, "commit", "-qm", "gitlink")
        with self.assertRaisesRegex(arc.Blocked, "gitlink"):
            arc.candidate_tree(self.repo, "HEAD")

    def test_ignored_untracked_file_is_rejected(self):
        (self.repo / ".env").write_text("fake canary")
        self.assertEqual(gitc(self.repo, "status", "--porcelain"), "")
        self.assertEqual(self.execute(), "blocked")
        self.assertIn("untracked", self.task()["reason"])
        self.assertEqual(self.calls, [])

    def test_traversal_finding_does_not_reach_builder(self):
        self.reviews = iter(["traversal"])
        self.assertEqual(self.execute(), "blocked")
        self.assertIn("cannot be routed", self.task()["reason"])
        self.assertEqual([r.role for r in self.calls], ["builder", "reviewer"])

    def test_unauthorized_repair_does_not_reach_final_review(self):
        original = self.build

        def edit(request):
            if request.findings:
                self.edited = "package.json"
            return original(request)

        self.build = edit
        self.assertEqual(self.execute(), "blocked")
        self.assertIn("unauthorized edits", self.task()["reason"])
        self.assertEqual([r.role for r in self.calls], ["builder", "reviewer", "builder"])

    def test_protected_assertion_rejects_early_exit_even_with_forged_success(self):
        (self.repo / "src/x.js").write_text(
            'process.stdout.write(JSON.stringify({value:true})); process.exit(0);\n'
            'export const atLeastTwo = () => false;'
        )
        gitc(self.repo, "commit", "-qam", "early exit attack")
        legacy = self.repo / "legacy.test.mjs"
        legacy.write_text(
            "import assert from 'node:assert/strict';\n"
            "import {atLeastTwo} from './src/x.js';\nassert.equal(atLeastTwo(), true);"
        )
        node = os.environ.get("ARCTURUS_TEST_NODE", "node")
        version = subprocess.check_output([node, "--version"], text=True)
        result = subprocess.run([node, "--test", str(legacy)], capture_output=True, text=True, check=False)
        if version.startswith("v24."):
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        legacy.unlink()
        head = gitc(self.repo, "rev-parse", "HEAD")
        tests, probe_ok, _ = arc.candidate_checks(self.repo, head, self.base, ["T1.1"], "attack")
        proof = json.loads(Path(tests["log"]).read_text())
        self.assertTrue(probe_ok)
        self.assertFalse(tests["ok"])
        self.assertEqual(proof["commit"], head)
        self.assertEqual(proof["checks"][0]["ok"], False)
        self.assertEqual(proof["checks"][0]["exit"], 0)  # exit zero alone supplies no completion proof

    def test_missing_or_wrong_result_fails_independent_assertion(self):
        for code in ("export const atLeastTwo = () => undefined;", "export const atLeastTwo = () => false;"):
            with self.subTest(code=code):
                (self.repo / "src/x.js").write_text(code)
                gitc(self.repo, "commit", "-qam", "bad result")
                head = gitc(self.repo, "rev-parse", "HEAD")
                tests, _, _ = arc.candidate_checks(self.repo, head, self.base, ["T1.1"], "bad-result")
                self.assertFalse(tests["ok"])

    def test_board_gate_requires_latest_exact_human_approval(self):
        manifest = arc.STATE / "manifest.json"
        manifest.write_text("{}")
        proposal = {"spec": self.spec, "base": self.base}
        code = arc.plan_code(self.issue["id"], proposal)
        comments = [
            {"id": "1", "authorUserId": "local-board", "authorAgentId": "agent", "body": f"APPROVE PLAN {code}"}
        ]
        self.patch(
            by_identifier=lambda _: self.issue,
            builder_project=lambda *args: "demo",
            agents=lambda: {},
            coordinated_proposal=lambda *args: (proposal, object()),
            comments_all=lambda _: comments,
        )
        with (
            patch.dict(os.environ, {"ARCTURUS_BOARD_PORT": "3199"}),
            patch.object(arc, "run_one", side_effect=RuntimeError("dispatch reached")) as run,
        ):
            with redirect_stdout(io.StringIO()) as stdout:
                arc.cmd_coordinate("ARC-1", manifest, run=True)
            self.assertIn("NEEDS_APPROVAL", stdout.getvalue())
            comments.append({"id": "2", "authorUserId": "local-board", "body": f"APPROVE PLAN {code}"})
            comments.append({"id": "3", "authorUserId": "local-board", "body": f"REJECT PLAN {code}"})
            with redirect_stdout(io.StringIO()):
                arc.cmd_coordinate("ARC-1", manifest, run=True)
            run.assert_not_called()
            comments.append({"id": "4", "authorUserId": "local-board", "body": f"APPROVE PLAN {code}"})
            with self.assertRaisesRegex(RuntimeError, "dispatch reached"):
                arc.cmd_coordinate("ARC-1", manifest, run=True)
            self.assertEqual(run.call_args.kwargs["ctx"]["approval"], code)


class SubscriptionAdapters(unittest.TestCase):
    def test_adapters_normalize_usage_without_running_clis(self):
        from workers import Request

        workers = arc.subscription_workers({"policy": "isolated-policy.json"})
        request = Request(
            "session",
            "demo",
            "ARC-1",
            "builder",
            "/tmp/project",
            ("src/",),
            frozenset({"read"}),
            "prompt",
            Path("/tmp/unused.json"),
            ("T1.1",),
            (),
            "commit",
            Limits(seconds=20),
        )
        claude_output = {
            "structured_output": {"summary": "done"},
            "total_cost_usd": 0.02,
            "usage": {"input_tokens": 10, "output_tokens": 2, "cache_read_input_tokens": 3},
        }
        with patch.object(arc, "claude", return_value=(0, claude_output)) as run:
            self.assertEqual(workers["claude-code"].run(request).usage, Usage(15, 0.02))
            self.assertEqual(run.call_args.kwargs["session"], "session")
            self.assertEqual(run.call_args.kwargs["timeout"], 20)
        events = [{"type": "turn.completed", "usage": {"input_tokens": 4, "output_tokens": 3}}]
        with patch.object(arc, "codex_review", return_value=(0, events)) as run:
            self.assertEqual(workers["codex"].run(request).usage, Usage(7, 0))
            self.assertTrue(run.call_args.kwargs["telemetry"])


class ExecutionAuthorization(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=arc.STATE)
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        repo = root / "projects/demo"
        make_repo(repo, {"test/isolation.probe.test.js": "// protected\n"})
        (repo / "test/acceptance/a.test.js").unlink()
        (repo / arc.ACCEPTANCE_FILE).write_text(
            json.dumps(
                [{"id": "value", "criterion": "T1.1", "entry": "src/x.js", "export": "v", "args": [], "expected": 1}]
            )
        )
        gitc(repo, "add", "-A")
        gitc(repo, "commit", "-qm", "contract")
        self.issue = {
            "id": "id",
            "identifier": "ARC-1",
            "projectId": "p",
            "assigneeAgentId": "a",
            "title": "Task",
            "description": "Work",
        }
        state = root / "runner-state"
        state.mkdir()
        policy = root / "policy/demo.json"
        policy.parent.mkdir()
        protected = ["test/acceptance", "test/isolation.probe.test.js"]
        policy.write_text(json.dumps(arc.rules_for(str(repo), [], protected)))
        self.policy = policy
        self.config = {
            "dir": str(repo),
            "policy": str(policy),
            "protected": protected,
            "builder": "Demo",
            "coordinator": {"builder_model": "claude-pinned", "reviewer_model": "gpt-pinned"},
        }
        self.cli = root / "claude"
        self.cli.write_text("mock launcher identity")
        node = root / "node"
        (node / "bin").mkdir(parents=True)
        (node / "bin/node").write_text("mock runtime identity")
        (node / "bin/node").chmod(0o755)
        runtime_config = root / "runner/config.json"
        runtime_config.parent.mkdir()
        runtime_config.write_text("{}")
        self.runtime_config = runtime_config
        self.j = {"tasks": {}, "own_comments": []}
        self.comments = []
        patches = (
            patch.dict(os.environ, {"ARCTURUS_BOARD_PORT": "3199"}),
            patch.multiple(
                arc,
                ROOT=root,
                STATE=state,
                GROUPS=state / "groups.json",
                NODE=node,
                CLAUDE=str(self.cli),
                CODEX=str(self.cli),
                CFG={"projects": {"demo": self.config}, "lead": {"allowed_projects": ["demo"]}},
                company_id=lambda: "isolated",
                project_ids=lambda: {"demo": "p"},
                by_identifier=lambda _: self.issue,
                agents=lambda: {"Demo": {"id": "a"}},
                comments_all=lambda _: self.comments,
                assert_quiescent=lambda: None,
            ),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.manifest = {
            "acceptance": ["Value"],
            "owned_paths": ["src/"],
            "limits": {},
            "workers": {"builder": "claude-code", "reviewer": "codex"},
        }

    def proposal_context(self):
        proposal, dispatch = arc.coordinated_proposal(self.issue, "demo", self.manifest)
        code = arc.plan_code(self.issue["id"], proposal)
        self.comments[:] = [{"id": "1", "authorUserId": "local-board", "body": f"APPROVE PLAN {code}"}]
        return {
            "spec": proposal["spec"],
            "start": proposal["base"],
            "manifest": self.manifest,
            "dispatch": dispatch,
            "proposal": proposal,
            "approval": code,
        }

    def test_legacy_task_and_goal_routes_cannot_dispatch(self):
        out = arc.STATE / "unused"
        with patch.object(arc, "run_bounded") as launch:
            with self.assertRaisesRegex(SystemExit, "coordinator-managed"):
                arc.cmd_run("ARC-1")
            with self.assertRaisesRegex(arc.Blocked, "coordinator-managed"):
                arc.work_task(self.j, self.issue, "demo")
            with self.assertRaisesRegex(arc.Refused, "coordinator-managed"):
                arc.plan_goal(self.j, self.issue)
            with self.assertRaisesRegex(arc.Refused, "coordinator-managed"):
                arc.execute_plan(self.j, self.issue, [{"project": "demo"}], "")
            with patch.object(arc, "_proposed", return_value=("id", {"plan_base": {"demo": "head"}})):
                with self.assertRaisesRegex(arc.Refused, "coordinator-managed"):
                    arc.approve_plan(self.j, "unused")
            with patch.object(arc, "_goal", return_value=("id", {"plan_base": {"demo": "head"}})):
                with self.assertRaisesRegex(arc.Refused, "coordinator-managed"):
                    arc.resume_goal(self.j, "ARC-1")
            with self.assertRaisesRegex(arc.Blocked, "requires current"):
                arc.claude("prompt", self.config["policy"], self.config["dir"], out)
            with self.assertRaisesRegex(arc.Blocked, "requires current"):
                arc.codex_review("prompt", [self.config["dir"]], self.config["dir"], out)
            import bridge

            result, reason = bridge.coordinate(self.j, "start", [])
            self.assertIsNone(result)
            self.assertIn("coordinator-managed", reason)
            launch.assert_not_called()

    def test_live_dispatch_requires_the_latest_board_approval(self):
        ctx = self.proposal_context()
        arc.authorize_coordinated(self.j, self.issue, "demo", ctx)
        self.comments.clear()
        with patch.object(arc, "run_bounded") as launch:
            with self.assertRaisesRegex(arc.Blocked, "approval"):
                arc.work_task(self.j, self.issue, "demo", ctx=ctx)
            with self.assertRaisesRegex(WorkerFailure, "requires execution authorization"):
                ctx["dispatch"].dispatch(
                    "builder",
                    {
                        "spec": ctx["spec"],
                        "project": "demo",
                        "identifier": "ARC-1",
                        "dispatch_started": arc.time.time(),
                    },
                    lambda: None,
                    self.config["dir"],
                    "prompt",
                    arc.STATE / "unused",
                    ctx["start"],
                )
            launch.assert_not_called()

    def test_approved_launch_rejects_configuration_drift_at_dispatch(self):
        original_reviewer_argv = arc.codex_argv

        def changed_reviewer_profile(*args, **kwargs):
            return [
                arg.replace('default_permissions="arcreview"', 'default_permissions="changed"')
                for arg in original_reviewer_argv(*args, **kwargs)
            ]

        cases = {
            "reviewer profile": patch.object(arc, "codex_argv", side_effect=changed_reviewer_profile),
            "executable bytes": patch.object(arc, "CLAUDE", str(self.cli)),
            "builder model": patch.dict(self.config["coordinator"], {"builder_model": "changed"}),
            "reviewer model": patch.dict(self.config["coordinator"], {"reviewer_model": "changed"}),
            "timeout": patch.dict(arc.TIMEOUTS, {"review": 1}),
            "cleanup": patch.object(arc, "CANCEL_GRACE", (1, 1)),
        }
        for name, change in cases.items():
            with self.subTest(name=name):
                ctx = self.proposal_context()
                if name == "executable bytes":
                    self.cli.write_text("replaced launcher")
                with change, patch.object(arc, "run_bounded") as launch:
                    task = {
                        "spec": ctx["spec"],
                        "project": "demo",
                        "identifier": "ARC-1",
                        "dispatch_started": arc.time.time(),
                    }
                    with self.assertRaisesRegex(WorkerFailure, "configuration changed"):
                        arc.approved_dispatch(
                            self.j,
                            self.issue,
                            "demo",
                            ctx,
                            "builder",
                            task,
                            lambda: None,
                            self.config["dir"],
                            "prompt",
                            arc.STATE / "unused",
                            ctx["start"],
                        )
                    launch.assert_not_called()
        for changed_file in (self.policy, self.runtime_config):
            ctx = self.proposal_context()
            changed_file.write_text(changed_file.read_text() + "\n")
            with self.assertRaisesRegex(arc.Blocked, "configuration changed"):
                arc.authorize_coordinated(self.j, self.issue, "demo", ctx)

    def test_exact_approval_reaches_only_the_expected_launcher(self):
        ctx = self.proposal_context()
        task = {"spec": ctx["spec"], "project": "demo", "identifier": "ARC-1", "dispatch_started": arc.time.time()}
        response = {
            "structured_output": {"summary": "done"},
            "total_cost_usd": 0,
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        with patch.object(arc, "run_bounded", return_value=(0, json.dumps(response), "")) as launch:
            result = arc.approved_dispatch(
                self.j,
                self.issue,
                "demo",
                ctx,
                "builder",
                task,
                lambda: None,
                self.config["dir"],
                "prompt",
                arc.STATE / "unused",
                ctx["start"],
            )
        self.assertEqual(result["response"], {"summary": "done"})
        self.assertEqual(launch.call_args.args[0][-2:], ["--model", "claude-pinned"])

    def test_replacement_during_final_approval_read_never_reaches_spawn(self):
        ctx = self.proposal_context()
        task = {"spec": ctx["spec"], "project": "demo", "identifier": "ARC-1", "dispatch_started": arc.time.time()}
        reads = []

        def replace_on_last_read(_):
            reads.append(1)
            if len(reads) == 2:
                self.cli.write_text("unapproved launcher")
            return self.comments

        with (
            patch.object(arc, "comments_all", side_effect=replace_on_last_read),
            patch.object(arc, "run_bounded") as spawn,
        ):
            with self.assertRaisesRegex(WorkerFailure, "configuration changed"):
                arc.approved_dispatch(
                    self.j,
                    self.issue,
                    "demo",
                    ctx,
                    "builder",
                    task,
                    lambda: None,
                    self.config["dir"],
                    "prompt",
                    arc.STATE / "unused",
                    ctx["start"],
                )
        self.assertEqual(len(reads), 2)
        spawn.assert_not_called()

    def test_spawn_uses_pinned_bytes_if_original_changes_after_verification(self):
        ctx = self.proposal_context()
        task = {"spec": ctx["spec"], "project": "demo", "identifier": "ARC-1", "dispatch_started": arc.time.time()}
        response = {
            "structured_output": {"summary": "done"},
            "total_cost_usd": 0,
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        original = self.cli.read_bytes()

        def inspect(argv, *_args, **_kwargs):
            self.cli.write_bytes(b"unapproved launcher")
            pinned = Path(argv[0])
            self.assertNotEqual(pinned, self.cli)
            self.assertEqual(pinned.read_bytes(), original)
            settings = Path(argv[argv.index("--settings") + 1])
            self.assertEqual(settings.parent, pinned.parent)
            self.assertEqual(arc.sha_file(settings), ctx["proposal"]["policy"])
            return 0, json.dumps(response), ""

        with patch.object(arc, "run_bounded", side_effect=inspect):
            result = arc.approved_dispatch(
                self.j,
                self.issue,
                "demo",
                ctx,
                "builder",
                task,
                lambda: None,
                self.config["dir"],
                "prompt",
                arc.STATE / "unused",
                ctx["start"],
            )
        self.assertEqual(result["response"], {"summary": "done"})

    def test_reviewer_launcher_reads_only_the_bound_snapshot(self):
        ctx = self.proposal_context()
        task = {"spec": ctx["spec"], "project": "demo", "identifier": "ARC-1", "dispatch_started": arc.time.time()}
        repo = self.config["dir"]
        entries = arc.candidate_tree(repo, ctx["start"])
        proof = arc.STATE / "tests.json"
        proof.write_text(json.dumps({"commit": ctx["start"], "inventory": arc.tree_inventory(entries)}))
        evidence = {str(proof): arc.sha_file(proof)}
        event = {"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 1}}
        with (
            arc.candidate_snapshot(repo, entries) as snapshot,
            patch.object(arc, "run_bounded", return_value=(0, json.dumps(event), "")) as spawn,
        ):
            result = arc.approved_dispatch(
                self.j,
                self.issue,
                "demo",
                ctx,
                "reviewer",
                task,
                lambda: None,
                str(snapshot),
                "prompt",
                arc.STATE / "unused",
                ctx["start"],
                review_entries=entries,
                test_log=str(proof),
                test_evidence=evidence,
            )
            self.assertEqual(result["exit"], 0)
            argv = spawn.call_args.args[0]
            self.assertEqual(spawn.call_args.kwargs["cwd"], str(snapshot))
            profile = next(arg for arg in argv if arg.startswith("permissions.arcreview.filesystem="))
            self.assertIn(f'{json.dumps(str(snapshot))}={{"."="read"', profile)
            self.assertIn(f'{json.dumps(repo)}={{"."="deny"}}', profile)
            self.assertIn(f'{json.dumps(str(Path(argv[0]).parent))}={{"."="read"}}', profile)
            self.assertNotEqual(Path(argv[0]), self.cli)

    def test_snapshot_replacement_during_approval_read_never_reaches_reviewer(self):
        ctx = self.proposal_context()
        task = {"spec": ctx["spec"], "project": "demo", "identifier": "ARC-1", "dispatch_started": arc.time.time()}
        repo = self.config["dir"]
        entries = arc.candidate_tree(repo, ctx["start"])
        proof = arc.STATE / "tests.json"
        proof.write_text(json.dumps({"commit": ctx["start"], "inventory": arc.tree_inventory(entries)}))
        evidence = {str(proof): arc.sha_file(proof)}
        with arc.candidate_snapshot(repo, entries) as snapshot:
            reads = []

            def mutate_on_last_read(_):
                reads.append(1)
                if len(reads) == 2:
                    (snapshot / "src/x.js").write_text("replacement")
                return self.comments

            with (
                patch.object(arc, "comments_all", side_effect=mutate_on_last_read),
                patch.object(arc, "run_bounded") as spawn,
            ):
                with self.assertRaisesRegex(WorkerFailure, "working copy differs"):
                    arc.approved_dispatch(
                        self.j,
                        self.issue,
                        "demo",
                        ctx,
                        "reviewer",
                        task,
                        lambda: None,
                        str(snapshot),
                        "prompt",
                        arc.STATE / "unused",
                        ctx["start"],
                        review_entries=entries,
                        test_log=str(proof),
                        test_evidence=evidence,
                    )
            self.assertEqual(len(reads), 2)
            spawn.assert_not_called()

    def npm_fixture(self):
        root = self.cli.parent / "npm-package"
        files = {
            "cli.js": "#!/usr/bin/env node\n// approved entry",
            "package.json": json.dumps(
                {
                    "name": "@anthropic-ai/claude-code",
                    "version": "2.1.63",
                    "bin": {"claude": "cli.js"},
                    "type": "module",
                }
            ),
            "runtime.wasm": "approved asset",
            "node_modules/example/lib/addon.node": "approved dependency",
            "vendor/ripgrep/rg": "approved tool",
        }
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        (root / "vendor/ripgrep/rg").chmod(0o755)
        inventory = arc.STATE / "inventory.json"
        inventory.write_text(
            json.dumps(
                {
                    "platform": os.uname().sysname,
                    "machine": os.uname().machine,
                    "version": "2.1.63",
                    "entry": "cli.js",
                    "required_executables": ["vendor/ripgrep/rg"],
                    "files": {name: arc.sha_file(root / name) for name in files},
                }
            )
        )
        patcher = patch.multiple(arc, CLAUDE=str(root / "cli.js"), CLAUDE_NPM_INVENTORY=inventory)
        patcher.start()
        self.addCleanup(patcher.stop)
        return root, files

    def npm_dispatch(self, ctx):
        task = {"spec": ctx["spec"], "project": "demo", "identifier": "ARC-1", "dispatch_started": arc.time.time()}
        return arc.approved_dispatch(
            self.j,
            self.issue,
            "demo",
            ctx,
            "builder",
            task,
            lambda: None,
            self.config["dir"],
            "prompt",
            arc.STATE / "unused",
            ctx["start"],
        )

    def test_npm_runtime_rejects_missing_modified_and_unexpected_files(self):
        root, files = self.npm_fixture()
        ctx = self.proposal_context()
        asset = root / "runtime.wasm"
        with patch.object(arc, "run_bounded") as spawn:
            asset.unlink()
            with self.assertRaisesRegex(WorkerFailure, "missing.*runtime.wasm"):
                self.npm_dispatch(ctx)
            asset.write_text("modified")
            with self.assertRaisesRegex(WorkerFailure, "asset changed: runtime.wasm"):
                self.npm_dispatch(ctx)
            asset.write_text(files["runtime.wasm"])
            (root / "unexpected.json").touch()
            with self.assertRaisesRegex(WorkerFailure, "unexpected.*unexpected.json"):
                self.npm_dispatch(ctx)
            spawn.assert_not_called()

    def test_npm_runtime_rejects_asset_swap_while_pinning(self):
        root, _ = self.npm_fixture()
        ctx = self.proposal_context()
        copy = arc.copy_approved_file

        def replace(source, destination, expected, **kwargs):
            if destination.name == "runtime.wasm":
                (root / "runtime.wasm").write_text("changed after final approval read")
            return copy(source, destination, expected, **kwargs)

        with patch.object(arc, "copy_approved_file", side_effect=replace), patch.object(arc, "run_bounded") as spawn:
            with self.assertRaisesRegex(WorkerFailure, "artifact bytes changed"):
                self.npm_dispatch(ctx)
            spawn.assert_not_called()

    def test_npm_spawn_keeps_approved_package_after_installed_entry_replacement(self):
        root, files = self.npm_fixture()
        ctx = self.proposal_context()
        self.assertEqual(ctx["proposal"]["launch"]["claude_npm"]["version"], "2.1.63")
        response = {
            "structured_output": {"summary": "done"},
            "total_cost_usd": 0,
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }

        def inspect(argv, *_args, **_kwargs):
            (root / "cli.js").write_text("unapproved launcher")
            self.assertEqual(argv[1], "--no-global-search-paths")
            pinned_node, pinned_entry = Path(argv[0]), Path(argv[2])
            self.assertEqual(pinned_node.parent, pinned_entry.parent.parent)
            self.assertNotEqual(pinned_entry.parent, root)
            for name, content in files.items():
                self.assertEqual((pinned_entry.parent / name).read_text(), content)
            self.assertTrue((pinned_entry.parent / "vendor/ripgrep/rg").stat().st_mode & 0o100)
            return 0, json.dumps(response), ""

        with patch.object(arc, "run_bounded", side_effect=inspect):
            self.assertEqual(self.npm_dispatch(ctx)["response"], {"summary": "done"})

    def test_ripgrep_pcre2_missing_or_changed_source_blocks_dispatch(self):
        root, _ = self.npm_fixture()
        library = root.parent / "libpcre2-8.0.dylib"
        library.write_bytes(b"approved dependency")
        inventory = json.loads(arc.CLAUDE_NPM_INVENTORY.read_text())
        inventory["ripgrep_pcre2"] = {
            "executable": "vendor/ripgrep/rg",
            "library": str(library),
            "library_sha256": arc.sha_file(library),
            "signed_executable_sha256": "unused",
            "install_name_tool": "/usr/bin/true",
        }
        arc.CLAUDE_NPM_INVENTORY.write_text(json.dumps(inventory))
        ctx = self.proposal_context()
        with patch.object(arc, "run_bounded") as spawn:
            library.unlink()
            with self.assertRaisesRegex(WorkerFailure, "libpcre2"):
                self.npm_dispatch(ctx)
            library.write_bytes(b"replaced dependency")
            with self.assertRaisesRegex(WorkerFailure, "PCRE2 dependency changed"):
                self.npm_dispatch(ctx)
            spawn.assert_not_called()

    def test_final_launcher_rejects_arguments_that_differ_from_proposal(self):
        ctx = self.proposal_context()
        token = arc.LAUNCH_AUTHORITY.set(("builder", self.config["dir"], lambda: ctx["proposal"]))
        try:
            with patch.object(arc, "run_bounded") as launch:
                with self.assertRaisesRegex(arc.Blocked, "actual launch arguments"):
                    arc.claude(
                        "prompt",
                        self.policy,
                        self.config["dir"],
                        arc.STATE / "unused",
                        schema=arc.BUILD_SCHEMA,
                        session="session",
                        model="different",
                    )
                launch.assert_not_called()
        finally:
            arc.LAUNCH_AUTHORITY.reset(token)


class SpawnCleanup(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        state = Path(temp.name)
        patcher = patch.multiple(arc, STATE=state, GROUPS=state / "groups.json")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_signal_between_spawn_and_registration_reaps_worker(self):
        real_popen = subprocess.Popen
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=sig):
                launched = []

                def spawn(*args, **kwargs):
                    process = real_popen(*args, **kwargs)
                    launched.append(process)
                    os.kill(os.getpid(), sig)
                    return process

                with patch.object(arc.subprocess, "Popen", side_effect=spawn):
                    with self.assertRaises(KeyboardInterrupt):
                        arc.run_bounded(["/bin/sleep", "60"], 5)
                self.assertEqual(len(launched), 1)
                self.assertIsNotNone(launched[0].poll())
                self.assertFalse(arc._group_alive(launched[0].pid))
                self.assertEqual(arc._groups(), set())

    def test_failed_group_registration_reaps_worker(self):
        launched = []
        real_popen = subprocess.Popen

        def spawn(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            launched.append(process)
            return process

        with (
            patch.object(arc.subprocess, "Popen", side_effect=spawn),
            patch.object(arc, "_set_groups", side_effect=OSError("registration failed")),
        ):
            with self.assertRaisesRegex(OSError, "registration failed"):
                arc.run_bounded(["/bin/sleep", "60"], 5)
        self.assertIsNotNone(launched[0].poll())
        self.assertFalse(arc._group_alive(launched[0].pid))

    def test_stray_search_recognizes_actual_codex_argv(self):
        listing = (
            "990001 /opt/homebrew/bin/codex -a never exec --ignore-user-config --ephemeral -\n"
            f"990002 node {arc.STATE.resolve()}/launch-test/cli.js -p prompt\n"
        )
        with patch.object(arc.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, listing)):
            self.assertEqual(arc.stray_workers(), listing.splitlines())


class RipgrepDependency(unittest.TestCase):
    def test_signed_private_ripgrep_loads_only_bundled_pcre2_and_system_libraries(self):
        inventory = json.loads(arc.CLAUDE_NPM_INVENTORY.read_text())
        relocation = inventory["ripgrep_pcre2"]
        if (
            (os.uname().sysname, os.uname().machine) != (inventory["platform"], inventory["machine"])
            or not arc.CLAUDE
            or not Path(relocation["install_name_tool"]).is_file()
            or not Path(relocation["library"]).is_file()
        ):
            self.skipTest("requires the reviewed local Claude and macOS toolchain")
        runtime = arc.claude_npm_identity(arc.launch_file_identity(arc.CLAUDE))
        if runtime is None:
            self.skipTest("requires the reviewed Claude npm installation")
        relocation = runtime["ripgrep_pcre2"]
        with tempfile.TemporaryDirectory(dir=arc.STATE) as folder:
            bundle = Path(folder)
            exe = bundle / relocation["executable"]
            exe.parent.mkdir(parents=True)
            identity = runtime["files"][relocation["executable"]]
            arc.copy_approved_file(identity["resolved"], exe, identity, executable=True)
            arc.pin_ripgrep_pcre2(bundle, relocation)
            library = exe.with_name(relocation["bundle_library"])
            loads = subprocess.check_output(["/usr/bin/otool", "-L", exe], text=True)
            self.assertIn("@loader_path/" + library.name, loads)
            self.assertTrue(
                all(
                    line.strip().startswith(("/usr/lib/", "@loader_path/" + library.name))
                    for line in loads.splitlines()[1:]
                )
            )
            sample = bundle / "sample"
            sample.write_text("alpha42\n")
            result = subprocess.run(
                [exe, "-P", "(?<=alpha)42", sample],
                env={**arc.base_env(), "DYLD_PRINT_LIBRARIES": "1"},
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(result.stdout, "alpha42\n")
            self.assertIn(str(library.resolve()), result.stderr)
            self.assertNotIn("/opt/homebrew/", result.stderr)
            # dyld must fail when the private dependency is absent, even with Homebrew still available.
            library.unlink()
            failed = subprocess.run(
                [exe, "-P", "(?<=alpha)42", sample], env=arc.base_env(), capture_output=True, text=True
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("@loader_path/" + library.name, failed.stderr)
