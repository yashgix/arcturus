"""Deterministic regression tests for arc.py trust checks (no model calls, no Paperclip writes).
Run: python3 -m unittest -v tests/test_arc_unit.py"""

import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("arc", Path(__file__).resolve().parents[1] / "runner/arc.py")
arc = importlib.util.module_from_spec(spec)
sys.modules["arc"] = arc
spec.loader.exec_module(arc)  # bridge shares it

GOOD = {"verdict": "approve", "summary": "ok", "tests_run": "node --test", "findings": [], "coverage": []}


def write(p, obj, raw=None):
    Path(p).write_text(raw if raw is not None else json.dumps(obj))


class ReviewEvaluation(unittest.TestCase):  # review-21 P1
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.out = Path(self.d) / "r.json"
        self.t0 = time.time() - 1

    def test_clean_valid_approve_passes(self):
        write(self.out, GOOD)
        self.assertEqual(arc.evaluate_review(0, self.out, self.t0)[0], "approve")

    def test_nonzero_exit_with_valid_approve_json_fails(self):
        write(self.out, GOOD)
        self.assertEqual(arc.evaluate_review(1, self.out, self.t0)[0], "invalid")

    def test_timeout_after_output_fails(self):
        write(self.out, GOOD)
        self.assertEqual(arc.evaluate_review("timeout", self.out, self.t0)[0], "invalid")

    def test_missing_output_fails(self):
        self.assertEqual(arc.evaluate_review(0, self.out, self.t0)[0], "invalid")

    def test_stale_output_fails(self):
        write(self.out, GOOD)
        self.assertEqual(arc.evaluate_review(0, self.out, time.time() + 5)[0], "invalid")

    def test_malformed_json_fails(self):
        write(self.out, None, raw="{not json")
        self.assertEqual(arc.evaluate_review(0, self.out, self.t0)[0], "invalid")

    def test_wrong_schema_fails(self):
        write(self.out, {"verdict": "approve"})
        self.assertEqual(arc.evaluate_review(0, self.out, self.t0)[0], "invalid")
        write(self.out, {**GOOD, "verdict": "lgtm"})
        self.assertEqual(arc.evaluate_review(0, self.out, self.t0)[0], "invalid")
        write(self.out, {**GOOD, "extra": 1})
        self.assertEqual(arc.evaluate_review(0, self.out, self.t0)[0], "invalid")

    def test_approve_with_high_finding_is_not_approval(self):
        write(self.out, {**GOOD, "findings": [{"severity": "high", "file": "a", "issue": "bug"}]})
        self.assertEqual(arc.evaluate_review(0, self.out, self.t0)[0], "changes")

    def test_approve_with_low_finding_passes(self):
        write(self.out, {**GOOD, "findings": [{"severity": "low", "file": "a", "issue": "nit"}]})
        self.assertEqual(arc.evaluate_review(0, self.out, self.t0)[0], "approve")

    def test_changes_requested(self):
        write(
            self.out,
            {**GOOD, "verdict": "changes_requested", "findings": [{"severity": "medium", "file": "a", "issue": "x"}]},
        )
        self.assertEqual(arc.evaluate_review(0, self.out, self.t0)[0], "changes")


def good_probe(nonce):
    return {
        "nonce": nonce,
        "context": "runner-test-sandbox",
        "must_deny": {k: sorted(v)[0] for k, v in arc.EXPECTED.items()},
        "must_allow": {"read_own_source": "allowed", "write_inside_project": "allowed"},
        "sensitive_env_names": [],
    }


class ProbeOracle(unittest.TestCase):  # review-21 P2
    def setUp(self):
        self.d = tempfile.mkdtemp()
        (Path(self.d) / ".probe").mkdir()

    def put(self, r):
        (Path(self.d) / ".probe/results-runner-test-sandbox-1.json").write_text(json.dumps(r))

    def test_good_probe_passes(self):
        self.put(good_probe("n1"))
        self.assertTrue(arc.check_probe(self.d, "n1")[0])

    def test_missing_probe_fails(self):
        self.assertFalse(arc.check_probe(self.d, "n1")[0])

    def test_stale_nonce_fails(self):
        self.put(good_probe("old"))
        self.assertFalse(arc.check_probe(self.d, "n1")[0])

    def test_one_allowed_forbidden_access_fails(self):
        r = good_probe("n1")
        r["must_deny"]["other_project_secret"] = "allowed"
        self.put(r)
        ok, probs = arc.check_probe(self.d, "n1")
        self.assertFalse(ok)
        self.assertIn("other_project_secret", probs[0])

    def test_enoent_is_not_a_denial(self):
        r = good_probe("n1")
        r["must_deny"]["runner_state_sentinel"] = "denied:ENOENT"
        self.put(r)
        self.assertFalse(arc.check_probe(self.d, "n1")[0])

    def test_refused_connection_is_not_a_denial(self):
        r = good_probe("n1")
        r["must_deny"]["net_paperclip_api"] = "denied:ECONNREFUSED"
        self.put(r)
        self.assertFalse(arc.check_probe(self.d, "n1")[0])

    def test_missing_case_fails(self):
        r = good_probe("n1")
        del r["must_deny"]["write_git_config"]
        self.put(r)
        self.assertFalse(arc.check_probe(self.d, "n1")[0])

    def test_failed_positive_control_fails(self):
        r = good_probe("n1")
        r["must_allow"]["read_own_source"] = "denied:EPERM"
        self.put(r)
        self.assertFalse(arc.check_probe(self.d, "n1")[0])


class CandidateAndProtectedFiles(unittest.TestCase):  # review-21 P2/P3
    def setUp(self):
        self.d = tempfile.mkdtemp()
        g = lambda *a: subprocess.run(arc.GIT + list(a), cwd=self.d, check=True, capture_output=True)
        self.g = g
        g("init", "-q", "-b", "main")
        g("config", "user.name", "t")
        g("config", "user.email", "t@t")
        (Path(self.d) / "test/acceptance").mkdir(parents=True)
        (Path(self.d) / "test/acceptance/a.test.js").write_text("// oracle\n")
        (Path(self.d) / "src.js").write_text("v1\n")
        g("add", "-A")
        g("commit", "-qm", "base")
        g("checkout", "-q", "-b", "task/x")
        (Path(self.d) / "src.js").write_text("v2\n")
        g("commit", "-qam", "change")
        self.prot = ["test/acceptance"]

    def test_untouched_protected_passes(self):
        arc.assert_protected_untouched(self.d, "task/x", self.prot)

    def test_protected_change_on_branch_is_caught(self):
        (Path(self.d) / "test/acceptance/a.test.js").write_text("// weakened\n")
        self.g("commit", "-qam", "weaken")
        with self.assertRaises(arc.Blocked):
            arc.assert_protected_untouched(self.d, "task/x", self.prot)

    def test_protected_change_on_disk_is_caught(self):
        (Path(self.d) / "test/acceptance/a.test.js").write_text("// edited, uncommitted\n")
        with self.assertRaises(arc.Blocked):
            arc.assert_protected_untouched(self.d, "task/x", self.prot)

    def test_freeze_detects_source_change_after_freezing(self):
        before = arc.freeze(self.d, "task/x", self.prot)
        (Path(self.d) / "src.js").write_text("v3\n")
        self.assertNotEqual(arc.freeze(self.d, "task/x", self.prot), before)

    def test_freeze_detects_branch_ref_change(self):
        before = arc.freeze(self.d, "task/x", self.prot)
        (Path(self.d) / "src.js").write_text("v3\n")
        self.g("commit", "-qam", "later")
        self.assertNotEqual(arc.freeze(self.d, "task/x", self.prot), before)

    def test_freeze_detects_git_config_change(self):
        before = arc.freeze(self.d, "task/x", self.prot)
        self.g("config", "core.fsmonitor", "true")
        self.assertNotEqual(arc.freeze(self.d, "task/x", self.prot), before)


REAL_BY_IDENTIFIER = arc.by_identifier  # before any test world replaces it
REAL_REPAIR_TASK = arc.repair_task


def sub(k=1, project="alpha-habits", **kw):
    return {
        "id": f"T{k}",
        "project": project,
        "role": "backend",
        "title": "t",
        "description": "d",
        "acceptance": ["it works"],
        "depends_on": [],
        "owned_paths": [f"src/p{k}/"],
        "acceptance_tests": [],
        **kw,
    }


class PlanValidation(unittest.TestCase):
    def setUp(self):  # independent of which projects the live config allows
        cfg = copy.deepcopy(arc.CFG)
        cfg["lead"]["allowed_projects"] = ["alpha-habits", "beta-ratelimit"]
        old = arc.CFG
        arc.CFG = cfg
        self.addCleanup(setattr, arc, "CFG", old)

    def ok(self, *subs, files=None):
        return arc.validate_plan({"summary": "s", "subtasks": list(subs)}, files)

    def test_valid_plan(self):
        self.assertTrue(self.ok(sub())[0])

    def test_project_outside_goal_rejected(self):
        self.assertIsNone(self.ok(sub(project="_lead"))[0])

    def test_extra_or_missing_fields_rejected(self):
        self.assertIsNone(self.ok({**sub(), "cwd": "/"})[0])
        self.assertIsNone(self.ok({k: v for k, v in sub().items() if k != "owned_paths"})[0])

    def test_too_many_subtasks_rejected(self):
        self.assertIsNone(self.ok(*[sub(k) for k in range(1, 6)])[0])


class PlanMultiTask(unittest.TestCase):  # Phase 3A: several tasks per project with disjoint ownership and ordered deps
    setUp = PlanValidation.setUp
    ok = PlanValidation.ok

    def test_three_tasks_in_one_project_with_disjoint_paths_and_dependencies(self):
        subs, why = self.ok(
            sub(1, owned_paths=["src/api/", "src/shared/"]),
            sub(2, owned_paths=["src/web/"], depends_on=["T1"]),
            sub(
                3,
                role="integration",
                owned_paths=["src/serve.js", "README.md", "test/integration/"],
                depends_on=["T1", "T2"],
            ),
        )
        self.assertTrue(subs, why)

    def test_overlapping_owned_paths_in_one_project_rejected(self):
        for a, b in ((["src/"], ["src/web/"]), (["README.md"], ["README.md"]), (["src/web/"], ["src/web/main.js"])):
            subs, why = self.ok(sub(1, owned_paths=a), sub(2, owned_paths=b))
            self.assertIsNone(subs, (a, b))
            self.assertIn("overlaps", why)
        self.assertIsNone(self.ok(sub(1, owned_paths=["src/", "src/x.js"]))[0])  # within one task too
        self.assertTrue(
            self.ok(sub(1, owned_paths=["src/"]), sub(2, project="beta-ratelimit", owned_paths=["src/"]))[0]
        )

    def test_dependencies_must_name_earlier_tasks_and_ids_must_be_in_order(self):
        self.assertIsNone(self.ok(sub(1, depends_on=["T2"]), sub(2))[0])  # forward reference
        self.assertIsNone(self.ok(sub(1, depends_on=["T1"]))[0])  # itself
        self.assertIsNone(self.ok(sub(2))[0])  # ids T1, T2, ... in order
        self.assertIsNone(self.ok(sub(1), sub(2, depends_on=["T1", "T1"]))[0])

    def test_unsafe_or_protected_owned_paths_rejected(self):
        for bad in (
            ".git/",
            ".claude/settings.json",
            "test/acceptance/",
            "test/acceptance/x.test.js",
            "../beta/",
            "/Users/x/",
            "src/*.js",
            ".env",
            "secrets/",
            "",
            "test/isolation.probe.test.js",
        ):
            self.assertIsNone(self.ok(sub(1, owned_paths=[bad]))[0], bad)

    def test_acceptance_files_must_exist_on_main_and_be_assigned_once(self):
        files = {"alpha-habits": ["test/acceptance/api.test.js", "test/acceptance/web.test.js"]}
        self.assertTrue(self.ok(sub(1, acceptance_tests=["test/acceptance/api.test.js"]), files=files)[0])
        self.assertIsNone(self.ok(sub(1, acceptance_tests=["test/acceptance/nope.test.js"]), files=files)[0])
        self.assertIsNone(
            self.ok(
                sub(1, acceptance_tests=["test/acceptance/api.test.js"]),
                sub(2, acceptance_tests=["test/acceptance/api.test.js"]),
                files=files,
            )[0]
        )

    def test_criteria_are_a_bounded_list(self):
        self.assertIsNone(self.ok(sub(1, acceptance="one string"))[0])
        self.assertIsNone(self.ok(sub(1, acceptance=[]))[0])
        self.assertIsNone(self.ok(sub(1, acceptance=["x" * (arc.CRITERION_MAX + 1)]))[0])
        self.assertIsNone(self.ok(sub(1, acceptance=["c"] * (arc.MAX_CRITERIA + 1)))[0])
        self.assertEqual(arc.criteria_of(sub(3, acceptance=["a", "b"])), [("T3.1", "a"), ("T3.2", "b")])


class CoverageInReviews(unittest.TestCase):  # Phase 3A: each criterion linked to evidence, or explicitly unverified
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.out = Path(self.d) / "r.json"
        self.t0 = time.time() - 1

    def ev(self, cov, verdict="approve", crit=("T1.1", "T1.2")):
        write(self.out, {**GOOD, "verdict": verdict, "coverage": cov})
        return arc.evaluate_review(0, self.out, self.t0, crit)

    def c(self, i, st="met", e="test/a.test.js: 'works'"):
        return {"criterion": i, "status": st, "evidence": e}

    def test_complete_coverage_with_evidence_approves(self):
        self.assertEqual(self.ev([self.c("T1.1"), self.c("T1.2", "unverified", "needs a real browser")])[0], "approve")

    def test_missing_duplicate_or_unknown_criterion_is_invalid(self):
        for cov in (
            [self.c("T1.1")],
            [self.c("T1.1"), self.c("T1.1")],
            [self.c("T1.1"), self.c("T1.2"), self.c("T9.9")],
        ):
            self.assertEqual(self.ev(cov)[0], "invalid", cov)

    def test_entry_without_evidence_or_with_unknown_status_is_invalid(self):
        self.assertEqual(self.ev([self.c("T1.1", e=" "), self.c("T1.2")])[0], "invalid")
        self.assertEqual(self.ev([self.c("T1.1", st="partly"), self.c("T1.2")])[0], "invalid")

    def test_unmet_criterion_blocks_even_an_approve_verdict(self):
        outcome, rv, _ = self.ev([self.c("T1.1"), self.c("T1.2", "not_met", "no README section")])
        self.assertEqual(outcome, "changes")
        self.assertIn(
            {
                "severity": "medium",
                "file": "criterion:T1.2",
                "issue": "acceptance criterion T1.2 is not met: no README section",
            },
            rv["findings"],
        )

    def test_review_without_coverage_key_is_invalid(self):
        write(self.out, {k: v for k, v in GOOD.items() if k != "coverage"})
        self.assertEqual(arc.evaluate_review(0, self.out, self.t0, ())[0], "invalid")


# ======================= Phase 2A.1 regressions (review 23: A1-A6) =======================
import copy
import shutil
import subprocess as sp

PROBE_SRC = arc.ROOT / "projects/alpha-habits"


def gitc(d, *a):
    return sp.run(arc.GIT + list(a), cwd=d, check=True, capture_output=True, text=True).stdout.strip()


def make_repo(d, extra=None):
    Path(d).mkdir(parents=True, exist_ok=True)
    gitc(d, "init", "-q", "-b", "main")
    gitc(d, "config", "user.name", "t")
    gitc(d, "config", "user.email", "t@t")
    files = {
        "package.json": '{"type":"module"}\n',
        ".gitignore": ".probe/\n.tmp/\n.env\nsecrets/\n",
        "src/x.js": "export const v = 1;\n",
        "test/acceptance/a.test.js": "// oracle\n",
        **(extra or {}),
    }
    for rel, txt in files.items():
        (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
        (Path(d) / rel).write_text(txt)
    gitc(d, "add", "-A")
    gitc(d, "commit", "-qm", "base")


class ReviewSchemaTypes(unittest.TestCase):  # A4: complete local schema types
    def setUp(self):
        self.out = Path(tempfile.mkdtemp()) / "r.json"
        self.t0 = time.time() - 1

    def test_tests_run_must_be_string(self):
        write(self.out, {**GOOD, "tests_run": 5})
        self.assertEqual(arc.evaluate_review(0, self.out, self.t0)[0], "invalid")

    def test_finding_file_and_issue_must_be_strings(self):
        for bad in ({"severity": "low", "file": 1, "issue": "x"}, {"severity": "low", "file": "a", "issue": None}):
            write(self.out, {**GOOD, "findings": [bad]})
            self.assertEqual(arc.evaluate_review(0, self.out, self.t0)[0], "invalid")


class ProbeOracleExact(unittest.TestCase):  # A4: exact positive controls / cases, one result, right context
    def setUp(self):
        self.d = tempfile.mkdtemp()
        (Path(self.d) / ".probe").mkdir()

    def put(self, r, name="results-runner-test-sandbox-1.json"):
        (Path(self.d) / ".probe" / name).write_text(json.dumps(r))

    def test_extra_positive_control_fails(self):
        r = good_probe("n")
        r["must_allow"]["something_else"] = "allowed"
        self.put(r)
        self.assertFalse(arc.check_probe(self.d, "n")[0])

    def test_missing_positive_control_fails(self):
        r = good_probe("n")
        del r["must_allow"]["write_inside_project"]
        self.put(r)
        self.assertFalse(arc.check_probe(self.d, "n")[0])

    def test_extra_case_fails(self):
        r = good_probe("n")
        r["must_deny"]["made_up"] = "denied:EPERM"
        self.put(r)
        self.assertFalse(arc.check_probe(self.d, "n")[0])

    def test_two_result_files_fail(self):
        self.put(good_probe("n"))
        self.put(good_probe("n"), "results-runner-test-sandbox-2.json")
        self.assertFalse(arc.check_probe(self.d, "n")[0])

    def test_wrong_context_fails(self):
        r = good_probe("n")
        r["context"] = "claude-worker-sandbox"
        self.put(r)
        self.assertFalse(arc.check_probe(self.d, "n")[0])


class CheckoutIdentity(unittest.TestCase):  # A2: bind to the actual checked-out HEAD
    def setUp(self):
        self.d = tempfile.mkdtemp()
        make_repo(self.d)
        gitc(self.d, "checkout", "-q", "-b", "task/x")
        (Path(self.d) / "src/x.js").write_text("export const v = 2;\n")
        gitc(self.d, "commit", "-qam", "change")
        self.prot = ["test/acceptance"]

    def test_candidate_records_checkout(self):
        c = arc.freeze(self.d, "task/x", self.prot)
        self.assertEqual((c["checkout"], c["checkout_ref"]), (c["head"], "refs/heads/task/x"))
        arc.assert_checked_out(c, "task/x")

    def test_clean_checkout_switch_is_detected(self):
        before = arc.freeze(self.d, "task/x", self.prot)
        gitc(self.d, "checkout", "-q", "main")  # clean switch: branch, main, protected, config unchanged
        after = arc.freeze(self.d, "task/x", self.prot)
        self.assertEqual(
            {k: after[k] for k in ("base", "head", "tree", "protected", "fingerprint", "dirty")},
            {k: before[k] for k in ("base", "head", "tree", "protected", "fingerprint", "dirty")},
        )
        self.assertNotEqual(after, before)
        with self.assertRaises(arc.Blocked):
            arc.assert_checked_out(after, "task/x")

    def test_detached_head_at_same_commit_is_detected(self):
        before = arc.freeze(self.d, "task/x", self.prot)
        gitc(self.d, "checkout", "-q", "--detach", "task/x")
        after = arc.freeze(self.d, "task/x", self.prot)
        self.assertNotEqual(after, before)
        with self.assertRaises(arc.Blocked):
            arc.assert_checked_out(after, "task/x")


@unittest.skipUnless(
    Path("/usr/bin/sandbox-exec").exists() and (arc.NODE / "bin/node").exists(), "needs macOS sandbox + pilot node"
)
class TestFileSelection(unittest.TestCase):  # Salus setup: TypeScript tests must not be skipped when tasks are deferred
    NAMES = [
        "a.test.js",
        "b.test.ts",
        "c-test.mts",
        "d_test.cts",
        "test-e.ts",
        "test.ts",
        "test/sub/f.ts",
        "test/g.js",
        "src/h.spec.ts",
        "src/i.ts",
        "src/j.test.mjs",
        "notes.md",
    ]

    def test_runner_lists_exactly_the_files_node_runs_by_default(self):
        d = tempfile.mkdtemp(prefix="arc-glob-")
        make_repo(
            d,
            {
                n: f"import {{ test }} from 'node:test'; test({n!r}, () => {{}});\n"
                for n in self.NAMES
                if not n.endswith(".md")
            }
            | {"notes.md": "x\n"},
        )
        out = sp.run(
            [f"{arc.NODE}/bin/node", "--test", "--test-reporter=tap"], cwd=d, capture_output=True, text=True
        ).stdout
        ran = set(re.findall(r"^(?:not )?ok \d+ - (\S+)", out, re.M))  # a file that fails to load still ran
        listed = set(arc.test_files(d))
        self.assertEqual(listed, ran)
        self.assertIn("b.test.ts", listed)
        self.assertIn("test/sub/f.ts", listed)
        self.assertNotIn("src/i.ts", listed)
        shutil.rmtree(d, ignore_errors=True)


class SandboxedExecution(unittest.TestCase):  # A2 + A4: tests cannot change source/Git or plant probe results
    EVIL = r"""import { test } from 'node:test'; import fs from 'node:fs';
const tryW = (f) => { try { fs.writeFileSync(f, 'x'); return 'allowed'; } catch (e) { return 'denied:' + e.code; } };
test('evil', () => { console.log('EVIL ' + JSON.stringify({
  src: tryW('src/x.js'), git_head: tryW('.git/HEAD'), git_ref: tryW('.git/refs/heads/main'),
  probe_result: tryW('.probe/results-runner-test-sandbox-9.json'), tmp: tryW('.tmp/ok.txt') })); });
"""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="arc-sbx-")
        make_repo(
            self.d,
            {
                "test/isolation.probe.test.js": (PROBE_SRC / "test/isolation.probe.test.js").read_text(),
                "test/evil.test.js": self.EVIL,
            },
        )
        (Path(self.d) / "secrets").mkdir()
        (Path(self.d) / "secrets/canary.txt").write_text("canary")
        self.out = Path(tempfile.mkdtemp())
        self._s = arc.STATE, arc.GROUPS
        arc.STATE = self.out
        arc.GROUPS = self.out / "live-groups.json"

    def tearDown(self):
        arc.STATE, arc.GROUPS = self._s

    def test_project_tests_get_read_only_source_git_and_probe_folder(self):
        head = gitc(self.d, "rev-parse", "HEAD")
        (Path(self.d) / ".probe").mkdir(exist_ok=True)
        res = arc.run_tests(self.d, self.out / "t.txt")
        evil = json.loads(re.search(r"EVIL (\{.*\})", (self.out / "t.txt").read_text()).group(1))
        self.assertEqual(
            evil,
            {
                "src": "denied:EPERM",
                "git_head": "denied:EPERM",
                "git_ref": "denied:EPERM",
                "probe_result": "denied:EPERM",
                "tmp": "allowed",
            },
        )
        self.assertTrue(res["ok"], res)
        self.assertEqual(gitc(self.d, "rev-parse", "HEAD"), head)
        self.assertEqual(gitc(self.d, "status", "--porcelain"), "")

    def test_probe_runs_alone_and_planted_results_are_discarded(self):
        pd = Path(self.d) / ".probe"
        pd.mkdir(exist_ok=True)
        (pd / "results-runner-test-sandbox-1.json").write_text(json.dumps(good_probe("planted")))  # builder plants one
        ok, probs = arc.run_probe(self.d, self.out / "p.txt", "real-nonce", self.out / "keep.json")
        self.assertTrue(ok, probs)
        self.assertEqual(json.loads((self.out / "keep.json").read_text())["nonce"], "real-nonce")
        self.assertNotIn("EVIL", (self.out / "p.txt").read_text())  # only the probe file ran

    def test_symlinked_probe_folder_is_replaced_not_followed(self):
        target = Path(tempfile.mkdtemp())
        (target / "keepme").write_text("x")
        os.symlink(target, Path(self.d) / ".probe")
        ok, probs = arc.run_probe(self.d, self.out / "p.txt", "n2", self.out / "keep.json")
        self.assertTrue(ok, probs)
        self.assertTrue((target / "keepme").exists())
        self.assertFalse((Path(self.d) / ".probe").is_symlink())


class ProcessGroups(unittest.TestCase):  # A5 (partial): group kill and quiescence check
    def setUp(self):
        self.out = Path(tempfile.mkdtemp())
        self._s = arc.STATE, arc.GROUPS
        arc.STATE = self.out
        arc.GROUPS = self.out / "live-groups.json"

    def tearDown(self):
        arc.STATE, arc.GROUPS = self._s

    def alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def test_timeout_kills_descendants(self):
        pf = self.out / "pid"
        code, _, _ = arc.run_bounded(["/bin/sh", "-c", f"sleep 60 >/dev/null 2>&1 & echo $! > {pf}; sleep 60"], 1)
        self.assertEqual(code, "timeout")
        time.sleep(0.2)
        self.assertFalse(self.alive(int(pf.read_text())))
        self.assertEqual(json.loads(arc.GROUPS.read_text()), [])

    def test_stray_left_after_normal_exit_is_killed(self):
        pf = self.out / "pid"
        code, out, _ = arc.run_bounded(["/bin/sh", "-c", f"sleep 60 >/dev/null 2>&1 & echo $! > {pf}; echo done"], 10)
        self.assertEqual((code, out.strip()), (0, "done"))
        time.sleep(0.2)
        self.assertFalse(self.alive(int(pf.read_text())))
        self.assertIn("stray_processes_killed", (self.out / "events.jsonl").read_text())

    def test_live_group_from_earlier_run_blocks_start(self):
        p = sp.Popen(["sleep", "60"], start_new_session=True)
        try:
            arc._set_groups({p.pid})
            with self.assertRaises(SystemExit):
                arc.assert_quiescent()
        finally:
            p.kill()
            p.wait()
        arc.assert_quiescent()  # group gone -> quiescent again, record dropped
        self.assertEqual(json.loads(arc.GROUPS.read_text()), [])


def plan3(projects=("alpha-habits", "beta-ratelimit")):
    """A Phase 3A plan: one task per given project (T1, T2, ...), each owning src/ and examples/ there."""
    return {
        "summary": "s",
        "subtasks": [
            {
                "id": f"T{k}",
                "project": p,
                "role": "backend",
                "title": f"task {k}",
                "description": "d",
                "acceptance": [f"{p} criterion one", f"{p} criterion two"],
                "depends_on": [f"T{k - 1}"] if k > 1 else [],
                "owned_paths": ["src/", "examples/"],
                "acceptance_tests": [],
            }
            for k, p in enumerate(projects, 1)
        ],
    }


class World(unittest.TestCase):
    """Two throwaway project repos and a Phase 3A goal: one planned task per project (TA-1, TB-1, integrated) and one
    combined candidate per project (A-1, B-1: what Yash approves). Fake Paperclip, scripted reviewers, no model calls."""

    PROJ = ("alpha-habits", "beta-ratelimit")

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="arc-world-"))
        self.state = self.root / "state"
        self.state.mkdir()
        self.cfg = copy.deepcopy(arc.CFG)
        self.dirs = {}
        self.cfg["projects"] = {p: self.cfg["projects"][p] for p in self.PROJ}  # the test world, not the live config
        self.cfg["lead"]["allowed_projects"] = list(self.PROJ)
        for p in self.PROJ:
            d = self.root / p
            make_repo(d)
            self.dirs[p] = str(d)
            self.cfg["projects"][p]["dir"] = str(d)
            self.cfg["projects"][p]["protected"] = ["test/acceptance"]
        self.said, self.status, self.comments, self.reviews, self.repairs, self.calls = [], {}, {}, [], [], []
        self.issues = {}
        self.patch(
            STATE=self.state,
            GROUPS=self.state / "live-groups.json",
            CFG=self.cfg,
            say=lambda j, iid, text: (self.said.append((iid, text)), self.calls.append((iid, "comment"))),
            set_status=lambda iid, st: (self.status.__setitem__(iid, st), self.calls.append((iid, st))),
            by_identifier=lambda ident: self.issues[ident],
            api=self.fake_api,
            agents=lambda: {"Lead": {"id": "lead"}},
            codex_review=self.fake_review,
        )
        self.patch(repair_task=self.fake_repair)
        self.j = {"tasks": {}, "own_comments": []}
        self.goal = {"id": "g1", "identifier": "G-1", "title": "goal", "description": "", "assigneeAgentId": "lead"}
        self.issues["G-1"] = self.goal
        self.j["tasks"]["g1"] = {
            "identifier": "G-1",
            "kind": "goal",
            "stage": "delegated",
            "format": 3,
            "plan": plan3(self.PROJ),
            "children": [],
            "integration": [],
            "budget": {"max_reviews": 3, "max_repairs": 2},
        }
        for (n, p), tid in zip((("A-1", "alpha-habits"), ("B-1", "beta-ratelimit")), ("T1", "T2")):
            self.issues[n] = {"id": "id-" + n, "identifier": n, "parentId": "g1", "status": "in_review", "title": n}
            self.issues["T" + n] = {
                "id": "id-T" + n,
                "identifier": "T" + n,
                "parentId": "g1",
                "status": "in_review",
                "title": tid,
            }
            self.j["tasks"]["g1"]["integration"].append({"id": "id-" + n, "identifier": n, "project": p})
            self.j["tasks"]["g1"]["children"].append(
                {"id": "id-T" + n, "identifier": "T" + n, "project": p, "task": tid}
            )
            self.j["tasks"]["id-T" + n] = {
                "identifier": "T" + n,
                "project": p,
                "stage": "integrated",
                "reviews": 1,
                "repairs": 0,
                "history": [],
                "branch": f"task/t{n.lower()}",
            }
            self.ready(n, p)
        arc.save(self.j)

    def patch(self, **kw):
        for k, v in kw.items():
            old = getattr(arc, k)
            self.addCleanup(setattr, arc, k, old)
            setattr(arc, k, v)

    def fake_api(self, method, path, body=None):
        if method == "GET" and path.split("?")[0].endswith("/comments"):
            return 200, self.comments.get(path.split("/")[2], [])
        return 200, {}

    def ready(self, ident, proj, content="100", attempt="a1", kind="integration"):
        """Make child `ident` a real awaiting-approval candidate (commit, freeze, runner-owned evidence, code)."""
        d = self.dirs[proj]
        br = f"task/{ident.lower()}"
        iid = "id-" + ident
        if gitc(d, "branch", "--list", br):
            gitc(d, "checkout", "-q", br)
        else:
            gitc(d, "checkout", "-q", "-b", br)
        (Path(d) / "src/x.js").write_text(f"export const v = {content};\n")
        gitc(d, "commit", "-qam", f"{ident} {content}")
        cand = arc.freeze(d, br, ["test/acceptance"])
        tag = f"{ident}-{attempt}"
        (self.state / f"{tag}-tests.txt").write_text("ℹ pass 3\nℹ fail 0\n")
        (self.state / f"{tag}-probe.json").write_text(json.dumps(good_probe("n")))
        (self.state / f"{tag}-probe.txt").write_text("ℹ pass 1\nℹ fail 0\n")
        old = self.j["tasks"].get(iid, {})
        n = old.get("reviews", 0) + 1
        (self.state / f"{tag}-review{n}.json").write_text(json.dumps(GOOD))
        ev = {
            "tests": arc.sha_file(self.state / f"{tag}-tests.txt"),
            "probe": arc.sha_file(self.state / f"{tag}-probe.json"),
            "probe_log": arc.sha_file(self.state / f"{tag}-probe.txt"),
            "review": arc.sha_file(self.state / f"{tag}-review{n}.json"),
            "tag": tag,
            "review_n": n,
        }
        if kind == "integration":
            ev.pop("review")
            ev.pop("review_n")
        self.j["tasks"][iid] = {
            "identifier": ident,
            "project": proj,
            "branch": br,
            "reviews": n,
            "repairs": old.get("repairs", 0),
            "history": [],
            "attempt": attempt,
            "stage": "awaiting_approval",
            "candidate": cand,
            "evidence": ev,
            "code": arc.approval_code(iid, attempt, cand, ev),
            "tests": {"ok": True, "pass": 3, "fail": 0, "log": str(self.state / f"{tag}-tests.txt")},
            **({"kind": "integration", "chain": [cand["head"]], "http": None} if kind == "integration" else {}),
        }

    def final_checks_pass(self, fail_in=()):
        """Stand-in final tests/probe that write their evidence files like the real ones (fail for given projects)."""
        self.deferred = []

        def tests(d, out, defer=()):
            self.deferred.append(list(defer))
            bad = any(d == self.dirs[p] for p in fail_in)
            Path(out).write_text("ℹ pass 2\nℹ fail 1\n" if bad else "ℹ pass 3\nℹ fail 0\n")
            return {
                "ok": not bad,
                "pass": 2 if bad else 3,
                "fail": 1 if bad else 0,
                "exit": 1 if bad else 0,
                "log": str(out),
                "deferred": sorted(defer),
            }

        def probe(d, out, nonce, keep):
            Path(out).write_text("ℹ pass 1\nℹ fail 0\n")
            Path(keep).write_text(json.dumps(good_probe(nonce)))
            return True, []

        self.patch(run_tests=tests, run_probe=probe)

    def fake_review(self, prompt, dirs, cwd, out, criteria=()):
        """Scripted reviewer. A step is "crash", (outcome, findings) or (outcome, findings, {criterion: status})."""
        self.reviews.append(prompt)
        self.criteria_seen = getattr(self, "criteria_seen", []) + [list(criteria)]
        step = self.script.pop(0)
        if step == "crash":
            raise KeyboardInterrupt
        outcome, findings, cov = (list(step) + [{}])[:3]
        coverage = [
            {"criterion": c, "status": cov.get(c, "met"), "evidence": "test/x.test.js: shows it"} for c in criteria
        ]
        rv = {
            **GOOD,
            "verdict": "approve" if outcome == "approve" else "changes_requested",
            "findings": findings,
            "coverage": coverage,
        }
        Path(out).write_text(json.dumps(rv))
        if outcome == "invalid":
            return "invalid", None, "invalid"
        return arc.evaluate_review(0, out, time.time() - 5, criteria)  # the runner's own rules decide

    def fake_repair(self, j, goal, c, fs):
        """Stand-in for repair_task: the owning task is repaired and its project's combined candidate re-made."""
        self.repairs.append(c["identifier"])
        self.repair_findings = getattr(self, "repair_findings", []) + [fs]
        t = j["tasks"][c["id"]]
        t["repairs"] += 1
        t["reviews"] += 1
        integ = next(x for x in j["tasks"][goal["id"]]["integration"] if x["project"] == c["project"])
        self.j = j
        self.ready(
            integ["identifier"], c["project"], content=str(10 + len(self.repairs)), attempt=f"r{len(self.repairs)}"
        )
        arc.save(j)
        return "ready"

    def run_goal(self, script):
        self.script = list(script)
        arc.milestone_and_report(self.j, self.goal)
        return arc.journal()

    def gate(self):
        return arc.goal_gate(arc.journal(), "g1")

    def last_report(self):
        return [t for i, t in self.said if t.startswith("**Consolidated report")][-1]


HIGH_A = [{"severity": "high", "file": "alpha-habits/src/x.js", "issue": "bug"}]
HIGH_B = [{"severity": "high", "file": "beta-ratelimit/src/x.js", "issue": "bug"}]


class GoalGate(World):  # A1 + A3
    def test_complete_passing_goal_is_ready(self):
        j = self.run_goal([("approve", [])])
        self.assertEqual(self.gate(), [])
        self.assertTrue(j["tasks"]["g1"]["ready"])
        self.assertEqual(self.status["g1"], "in_review")
        self.assertIn("Ready for your decision", self.last_report())
        self.assertIn("A-1", self.reviews[0])
        self.assertIn("B-1", self.reviews[0])  # one review covers both
        self.assertEqual(self.criteria_seen[0], ["T1.1", "T1.2", "T2.1", "T2.2"])  # and every criterion

    def test_missing_child_means_no_milestone_review_and_not_ready(self):
        self.j["tasks"]["id-B-1"]["stage"] = "blocked"
        arc.save(self.j)
        self.script = []
        arc.milestone_and_report(self.j, self.goal)
        self.assertEqual(self.reviews, [])  # never reviews a partial set
        probs = self.gate()
        self.assertTrue(any("B-1" in p for p in probs))
        self.assertTrue(any("no integration review" in p for p in probs))
        self.assertEqual(self.status["g1"], "blocked")

    def test_child_change_after_milestone_approval_invalidates_gate(self):
        self.run_goal([("approve", [])])
        self.assertEqual(self.gate(), [])
        j = arc.journal()
        self.j = j
        self.ready("B-1", "beta-ratelimit", content="99", attempt="b2")
        arc.save(j)
        self.assertTrue(any("does not cover the current combined candidate" in p for p in self.gate()))

    def test_branch_moved_without_record_invalidates_gate(self):
        self.run_goal([("approve", [])])
        d = self.dirs["beta-ratelimit"]
        (Path(d) / "src/x.js").write_text("sneaky\n")
        gitc(d, "commit", "-qam", "sneak")
        self.assertTrue(any("B-1" in p and "moved" in p for p in self.gate()))

    def test_changed_evidence_invalidates_gate(self):
        self.run_goal([("approve", [])])
        t = arc.journal()["tasks"]["id-A-1"]
        Path(t["tests"]["log"]).write_text("ℹ pass 9\nℹ fail 0\n")
        self.assertTrue(any("tests evidence" in p for p in self.gate()))

    def test_escalation_with_approving_review_is_not_ready(self):
        self.run_goal([("approve", [])])
        j = arc.journal()
        j["tasks"]["g1"]["escalated"] = [{"task": "B-1", "findings": HIGH_B}]
        arc.save(j)
        self.assertTrue(any("unresolved escalation" in p for p in self.gate()))

    def test_every_invalid_invocation_consumes_budget(self):
        j = self.run_goal([("invalid", [])] * 5)
        g = j["tasks"]["g1"]
        self.assertEqual(len(self.reviews), 3)
        self.assertEqual(g["milestone_reviews"], 3)
        self.assertEqual([a["outcome"] for a in g["milestone_attempts"]], ["invalid"] * 3)
        self.assertEqual(len({a["out"] for a in g["milestone_attempts"]}), 3)  # per-attempt files kept
        self.assertTrue(self.gate())

    def test_crash_after_reservation_is_counted_and_never_retried(self):
        self.script = ["crash"]
        with self.assertRaises(KeyboardInterrupt):
            arc.milestone_and_report(self.j, self.goal)
        j = arc.journal()
        g = j["tasks"]["g1"]
        self.assertEqual((g["milestone_reviews"], g["milestone_attempts"][0]["outcome"]), (1, "launched"))
        arc.mark_interrupted(j)
        self.assertEqual(arc.journal()["tasks"]["g1"]["stage"], "interrupted")
        for _ in range(2):  # repeated restarts: refused, budget unchanged
            with self.assertRaises(SystemExit):
                arc.cmd_goal("G-1")
        self.assertEqual(arc.journal()["tasks"]["g1"]["milestone_reviews"], 1)
        self.assertEqual(len(self.reviews), 1)
        self.assertTrue(self.gate())

    def test_findings_route_back_and_rereview_covers_new_candidate(self):
        j = self.run_goal([("changes", HIGH_A), ("approve", [])])
        g = j["tasks"]["g1"]
        self.assertEqual(self.repairs, ["TA-1"])
        self.assertEqual((g["milestone_reviews"], g["milestone_repairs"]), (2, 1))
        self.assertEqual(
            g["milestone_attempts"][1]["manifest"]["children"]["A-1"]["code"], j["tasks"]["id-A-1"]["code"]
        )
        self.assertEqual(self.gate(), [])

    def test_exhausted_child_escalates_without_spending_or_changing_candidate(self):
        self.j["tasks"]["id-TB-1"]["repairs"] = 2
        arc.save(self.j)
        before = copy.deepcopy(self.j["tasks"]["id-B-1"])
        j = self.run_goal([("changes", HIGH_A + HIGH_B)])
        g = j["tasks"]["g1"]
        self.assertEqual(self.repairs, [])
        self.assertEqual(g["milestone_repairs"], 0)
        self.assertEqual(len(self.reviews), 1)
        self.assertEqual(j["tasks"]["id-B-1"], before)
        self.assertEqual(g["escalated"][0]["task"], "TB-1")
        self.assertTrue(any("unresolved escalation" in p for p in self.gate()))

    def test_unroutable_finding_escalates_without_spending(self):
        j = self.run_goal([("changes", [{"severity": "high", "file": "src/x.js", "issue": "which project?"}])])
        self.assertEqual((self.repairs, j["tasks"]["g1"]["milestone_repairs"]), ([], 0))
        self.assertTrue(self.gate())

    def test_legacy_receipt_cannot_pass(self):
        self.run_goal([("approve", [])])
        j = arc.journal()
        del j["tasks"]["id-A-1"]["candidate"]["v"]
        arc.save(j)
        self.assertTrue(any("predates the current format" in p for p in self.gate()))

    def test_review_without_manifest_cannot_pass(self):  # ARC-13 shape: legacy single milestone result
        j = self.j
        j["tasks"]["g1"].update(
            milestone={"outcome": "approve", "reason": "", "summary": "", "findings": []}, milestone_reviews=1
        )
        arc.save(j)
        self.assertTrue(any("no integration review of the current" in p for p in self.gate()))


class PlanningBase(World):  # found in the ARC-17 demo: Lead planned from unmerged task-branch checkouts
    def test_planner_sees_main_and_is_told_its_commit(self):
        seen = {}

        def fake_claude(prompt, policy, cwd, out, **kw):
            seen["branches"] = {p: gitc(d, "rev-parse", "--abbrev-ref", "HEAD") for p, d in self.dirs.items()}
            seen["prompt"] = prompt
            return 1, {}

        self.patch(claude=fake_claude, agents=lambda: {"Lead": {"id": "lead"}})
        self.issues["G-2"] = {**self.goal, "id": "g2", "identifier": "G-2"}
        arc.cmd_goal("G-2")  # alpha/beta start on task branches from setUp
        self.assertEqual(seen["branches"], {p: "main" for p in self.dirs})
        for d in self.dirs.values():
            self.assertIn(f"main {gitc(d, 'rev-parse', 'main')[:12]}", seen["prompt"])
        self.assertEqual(
            arc.journal()["tasks"]["g2"]["plan_base"], {p: gitc(d, "rev-parse", "main") for p, d in self.dirs.items()}
        )

    def test_dirty_project_refuses_before_any_record(self):
        (Path(self.dirs["beta-ratelimit"]) / "src/x.js").write_text("dirty\n")
        self.issues["G-2"] = {**self.goal, "id": "g2", "identifier": "G-2"}
        with self.assertRaises(SystemExit):
            arc.cmd_goal("G-2")
        self.assertNotIn("g2", arc.journal()["tasks"])


class ApprovalGate(World):  # A1: ordinary child approval cannot bypass the milestone gate
    def approve_comment(self, ident, code):
        self.comments["id-" + ident] = [{"id": "c1", "authorUserId": "local-board", "body": f"APPROVE {code}"}]

    def assert_nothing_merged(self):
        for p, d in self.dirs.items():
            self.assertEqual(gitc(d, "log", "--oneline", "main").count("\n"), 0, p)

    def test_child_approval_under_failed_milestone_is_refused(self):
        self.run_goal([("changes", HIGH_B)] + [("changes", HIGH_B)] * 2)
        j = arc.journal()
        self.approve_comment("A-1", j["tasks"]["id-A-1"]["code"])
        with self.assertRaises(SystemExit):
            arc.cmd_approve("A-1")
        self.assert_nothing_merged()
        self.assertEqual(arc.journal()["tasks"]["id-A-1"]["stage"], "awaiting_approval")
        self.assertIn("goal gate has not passed", self.said[-1][1])

    def test_cached_code_for_changed_child_is_refused(self):
        self.run_goal([("approve", [])])
        old = arc.journal()["tasks"]["id-B-1"]["code"]
        j = arc.journal()
        self.j = j
        self.ready("B-1", "beta-ratelimit", content="7", attempt="b9")
        arc.save(j)
        self.approve_comment("B-1", old)
        with self.assertRaises(SystemExit):
            arc.cmd_approve("B-1")
        self.assert_nothing_merged()

    def test_paperclip_status_must_be_in_review(self):
        self.run_goal([("approve", [])])
        self.issues["A-1"]["status"] = "cancelled"
        self.approve_comment("A-1", arc.journal()["tasks"]["id-A-1"]["code"])
        with self.assertRaises(SystemExit):
            arc.cmd_approve("A-1")
        self.assert_nothing_merged()

    def test_passing_gate_and_exact_code_merges_checked_out_candidate(self):
        self.final_checks_pass()
        self.run_goal([("approve", [])])
        t = arc.journal()["tasks"]["id-A-1"]
        gitc(self.dirs["alpha-habits"], "checkout", "-q", "main")  # approval checks the candidate out itself
        self.approve_comment("A-1", t["code"])
        arc.cmd_approve("A-1")
        j = arc.journal()
        self.assertEqual(j["tasks"]["id-A-1"]["stage"], "done")
        self.assertIn(t["candidate"]["head"], gitc(self.dirs["alpha-habits"], "rev-list", "main"))
        self.assertEqual(arc.goal_gate(j, "g1"), [])  # sibling still approvable afterwards
        self.assertEqual(
            [c for c in self.calls if c[0] == "id-A-1"][-1], ("id-A-1", "done")
        )  # A6: no comment after done

    def test_standalone_run_refuses_goal_child_and_existing_record(self):
        self.patch(agents=lambda: {"Alpha Builder": {"id": "ab"}})
        self.issues["A-1"]["assigneeAgentId"] = "ab"
        with self.assertRaises(SystemExit):
            arc.cmd_run("A-1")  # goal child
        self.issues["A-1"]["parentId"] = None
        j = arc.journal()
        j["tasks"]["g1"]["integration"] = [c for c in j["tasks"]["g1"]["integration"] if c["identifier"] != "A-1"]
        arc.save(j)
        with self.assertRaises(SystemExit):
            arc.cmd_run("A-1")  # existing run record: counters never reset


# ======================= Phase 2B prerequisites (review 24: R1, R2) =======================
class ProbeCompletion(unittest.TestCase):  # R2: valid JSON is not enough; the probe process must finish cleanly
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.out = Path(tempfile.mkdtemp())

    def run_with(self, code, text):
        def fake_node(d, scratch, args, out, timeout):
            nonce = (Path(scratch) / "nonce").read_text()
            (Path(scratch) / "results-runner-test-sandbox-1.json").write_text(json.dumps(good_probe(nonce)))
            Path(out).write_text(text)
            return code, text

        old = arc.sandboxed_node
        arc.sandboxed_node = fake_node
        self.addCleanup(setattr, arc, "sandboxed_node", old)
        return arc.run_probe(self.d, self.out / "p.txt", "n1", self.out / "keep.json")

    def test_clean_completion_passes(self):
        ok, probs = self.run_with(0, "ℹ pass 1\nℹ fail 0\n")
        self.assertTrue(ok, probs)
        self.assertTrue((self.out / "keep.json").exists())

    def test_nonzero_exit_after_valid_result_fails(self):
        ok, probs = self.run_with(1, "ℹ pass 1\nℹ fail 0\n")
        self.assertFalse(ok)
        self.assertIn("exited 1", probs[0])
        self.assertFalse((self.out / "keep.json").exists())

    def test_timeout_after_valid_result_fails(self):
        ok, probs = self.run_with("timeout", "TIMEOUT")
        self.assertFalse(ok)
        self.assertIn("timed out", probs[0])
        self.assertFalse((self.out / "keep.json").exists())

    def test_incomplete_output_after_valid_result_fails(self):
        for text in ("", "ℹ pass 0\nℹ fail 0\n", "ℹ pass 1\nℹ fail 1\n"):
            ok, probs = self.run_with(0, text)
            self.assertFalse(ok, text)
            self.assertIn("incomplete", probs[0])


class ReadyGoal(World):
    """World after a complete, approving milestone: both children await approval, the goal is in review."""

    def setUp(self):
        super().setUp()
        self.final_checks_pass()
        self.run_goal([("approve", [])])
        self.issues["G-1"]["status"] = "in_review"

    def approve(self, ident):
        code = arc.journal()["tasks"]["id-" + ident]["code"]
        self.comments["id-" + ident] = [
            {
                "id": "c-" + ident,
                "authorUserId": "local-board",
                "body": f"APPROVE {code}",
                "createdAt": "2026-10-31T00:00:00Z",
            }
        ]
        arc.cmd_approve(ident)

    def main_heads(self):
        return {p: gitc(d, "rev-parse", "main") for p, d in self.dirs.items()}

    def assert_refused(self, ident, before):
        with self.assertRaises(SystemExit):
            self.approve(ident)
        self.assertEqual(self.main_heads(), before)

    def cli_gate_exit(self, ident):
        with self.assertRaises(SystemExit) as cm:
            arc.cmd_gate(ident)
        return cm.exception.code


class WholeGoalRevalidation(ReadyGoal):  # R1: approval revalidates every child's actual Git state, pending and merged
    def test_changed_pending_sibling_config_blocks_cli_report_and_approval(self):
        before = self.main_heads()
        self.assertEqual(self.cli_gate_exit("A-1"), 0)
        gitc(self.dirs["beta-ratelimit"], "config", "core.fsmonitor", "true")  # refs and evidence unchanged
        self.assertTrue(any(p.startswith("B-1:") and "differs from the tested candidate" in p for p in self.gate()))
        self.assertEqual(self.cli_gate_exit("A-1"), 2)  # CLI agrees
        arc.report(arc.journal(), self.goal)
        self.assertIn("Needs your decision", self.last_report())  # report agrees
        self.assert_refused("A-1", before)  # approval agrees
        self.assertEqual(gitc(self.dirs["alpha-habits"], "rev-parse", "--abbrev-ref", "HEAD"), "task/a-1")  # restored

    def test_uncommitted_sibling_protected_or_source_change_blocks_approval(self):
        before = self.main_heads()
        for rel in ("test/acceptance/a.test.js", "src/x.js"):
            f = Path(self.dirs["beta-ratelimit"]) / rel
            old = f.read_text()
            f.write_text("// changed\n")
            self.assertTrue(any(p.startswith("B-1:") for p in self.gate()), rel)
            self.assert_refused("A-1", before)
            f.write_text(old)
        self.assertEqual(self.gate(), [])

    def test_changed_probe_log_evidence_blocks(self):
        t = arc.journal()["tasks"]["id-B-1"]
        Path(arc.evidence_files(t)["probe_log"]).write_text("ℹ pass 9\n")
        self.assertTrue(any("probe_log evidence" in p for p in self.gate()))

    def check_order(self, first, second):
        self.approve(first)
        self.assertEqual(self.gate(), [])  # merged child verified, sibling fine
        self.approve(second)
        j = arc.journal()
        for ident in (first, second):
            t = j["tasks"]["id-" + ident]
            self.assertEqual(t["stage"], "done")
            self.assertIn(t["candidate"]["head"], gitc(self.dirs[t["project"]], "rev-list", "main"))
        self.assertEqual(self.gate(), [])

    def test_approval_order_alpha_then_beta(self):
        self.check_order("A-1", "B-1")

    def test_approval_order_beta_then_alpha(self):
        self.check_order("B-1", "A-1")

    def test_stale_merged_child_blocks_sibling(self):
        self.approve("A-1")
        d = self.dirs["alpha-habits"]
        gitc(d, "reset", "-q", "--hard", arc.journal()["tasks"]["id-A-1"]["candidate"]["base"])  # merge undone
        self.assertTrue(any("A-1" in p and "no longer on main" in p for p in self.gate()))
        self.assert_refused("B-1", self.main_heads())

    def test_merged_child_changed_evidence_blocks_sibling(self):
        self.approve("A-1")
        t = arc.journal()["tasks"]["id-A-1"]
        for f in (t["final"]["tests"][0], arc.evidence_files(t)["probe_log"]):
            old = Path(f).read_text()
            Path(f).write_text("tampered")
            self.assertTrue(any(p.startswith("A-1:") and "evidence" in p for p in self.gate()), f)
            self.assert_refused("B-1", self.main_heads())
            Path(f).write_text(old)
        self.assertEqual(self.gate(), [])

    def test_merged_child_project_drift_blocks_sibling(self):
        self.approve("A-1")
        gitc(self.dirs["alpha-habits"], "config", "core.fsmonitor", "true")
        self.assertTrue(any(p.startswith("A-1:") and "after the merge" in p for p in self.gate()))
        self.assert_refused("B-1", self.main_heads())

    def test_done_without_merge_record_blocks(self):
        j = arc.journal()
        j["tasks"]["id-A-1"]["stage"] = "done"
        arc.save(j)
        self.assertTrue(any("without a merge record" in p for p in self.gate()))


class WholeGoalApproval(ReadyGoal):  # one code for the whole goal; never weaker than per-task approval
    def code(self):
        return arc.goal_code(arc.journal(), "g1")

    def test_exact_goal_code_merges_every_child(self):
        outcome = arc.approve_goal(arc.journal(), "G-1", self.code())
        self.assertEqual([(o["task"], o["result"]) for o in outcome], [("A-1", "merged"), ("B-1", "merged")])
        j = arc.journal()
        self.assertEqual(j["tasks"]["g1"]["stage"], "merged")
        self.assertEqual(self.status["g1"], "done")
        self.assertEqual(self.gate(), [])

    def test_wrong_or_child_code_is_refused(self):
        before = self.main_heads()
        for bad in ("0" * 12, arc.journal()["tasks"]["id-A-1"]["code"]):
            with self.assertRaises(arc.Refused):
                arc.approve_goal(arc.journal(), "G-1", bad)
        self.assertEqual(self.main_heads(), before)

    def test_code_issued_then_candidate_changed_is_refused(self):
        code = self.code()
        before = self.main_heads()
        d = self.dirs["beta-ratelimit"]
        (Path(d) / "src/x.js").write_text("changed\n")
        gitc(d, "commit", "-qam", "late")
        with self.assertRaises(arc.Refused):
            arc.approve_goal(arc.journal(), "G-1", code)
        self.assertEqual({p: h for p, h in self.main_heads().items()}, before)

    def test_failed_child_tests_mean_no_merge(self):
        code = self.code()
        j = arc.journal()
        j["tasks"]["id-B-1"]["stage"] = "blocked"
        arc.save(j)
        with self.assertRaises(arc.Refused):
            arc.approve_goal(arc.journal(), "G-1", code)
        self.assertEqual(gitc(self.dirs["alpha-habits"], "log", "--oneline", "main").count("\n"), 0)

    def test_failed_final_tests_roll_back_and_stop(self):
        self.final_checks_pass(fail_in=("beta-ratelimit",))
        before = self.main_heads()
        with self.assertRaises(arc.Refused) as cm:
            arc.approve_goal(arc.journal(), "G-1", self.code())
        self.assertEqual(
            [(o["task"], o["result"]) for o in cm.exception.outcome], [("A-1", "merged"), ("B-1", "failed")]
        )
        self.assertEqual(gitc(self.dirs["beta-ratelimit"], "rev-parse", "main"), before["beta-ratelimit"])
        j = arc.journal()
        self.assertEqual(j["tasks"]["id-B-1"]["stage"], "merge_rolled_back")
        self.assertEqual(j["tasks"]["g1"]["stage"], "partially_merged")
        with self.assertRaises(arc.Refused):  # no second attempt from chat
            arc.approve_goal(arc.journal(), "G-1", self.code())

    def test_second_goal_approval_is_refused(self):
        arc.approve_goal(arc.journal(), "G-1", self.code())
        with self.assertRaises(arc.Refused):
            arc.approve_goal(arc.journal(), "G-1", self.code())


# ======================= Phase 2B.1 (review 25: B1-B4, delivery packet) =======================
T_GATE = arc.goal_gate


class MergeOutcomes(ReadyGoal):  # B1: every project's real result, never "nothing merged" after a partial merge
    def code(self):
        return arc.goal_code(arc.journal(), "g1")

    def test_interruption_after_first_merge_is_uncertain_not_retried(self):
        real = arc.run_tests

        def tests(d, out):
            if d == self.dirs["beta-ratelimit"]:
                raise KeyboardInterrupt  # Ctrl-C after beta's merge, before its final checks
            return real(d, out)

        self.patch(run_tests=tests)
        with self.assertRaises(KeyboardInterrupt):
            arc.approve_goal(arc.journal(), "G-1", self.code())
        j = arc.journal()
        self.assertEqual((j["tasks"]["id-A-1"]["stage"], j["tasks"]["id-B-1"]["stage"]), ("done", "merging"))
        arc.mark_interrupted(j)
        j = arc.journal()
        self.assertEqual(
            (j["tasks"]["id-B-1"]["stage"], j["tasks"]["g1"]["stage"]), ("merge_uncertain", "merge_interrupted")
        )
        msg = [t for i, t in self.said if i == "g1"][-1]
        self.assertIn("Some projects may already be merged", msg)
        self.assertIn("merged as", msg)
        self.assertNotIn("Nothing was approved", msg)
        self.assertTrue(self.gate())
        with self.assertRaises(arc.Refused):
            arc.approve_goal(arc.journal(), "G-1", self.code())

    def test_unexpected_error_on_second_project_is_reported_uncertain(self):
        real = self.issues["B-1"]
        self.patch(
            by_identifier=lambda ident: (
                (_ for _ in ()).throw(RuntimeError("tracker down")) if ident == "B-1" else self.issues[ident]
            )
        )
        with self.assertRaises(arc.Refused) as cm:
            arc.approve_goal(arc.journal(), "G-1", self.code())
        self.assertEqual(
            [(o["task"], o["result"]) for o in cm.exception.outcome], [("A-1", "merged"), ("B-1", "uncertain")]
        )
        self.assertEqual(arc.journal()["tasks"]["g1"]["stage"], "merge_uncertain")
        msg = [t for i, t in self.said if i == "g1"][-1]
        self.assertIn("Some work IS merged", msg)
        self.assertIn("UNCERTAIN for B-1", msg)

    def failing_rollback(self, how):
        """Final checks fail in alpha after its merge, and the rollback of main then fails (`raise`) or silently
        does nothing (`noop`). Either way the runner cannot know main's state."""
        self.final_checks_pass(fail_in=("alpha-habits",))
        real = arc.git

        def git(d, *a):
            if a[:1] == ("reset",):
                if how == "raise":
                    raise arc.Blocked("git reset failed: disk full")
                return ""
            return real(d, *a)

        self.patch(git=git)

    def assert_uncertain_first_project(self, cm):
        self.assertEqual(
            [(o["task"], o["result"]) for o in cm.exception.outcome], [("A-1", "uncertain"), ("B-1", "not attempted")]
        )
        j = arc.journal()
        self.assertEqual(
            (j["tasks"]["g1"]["stage"], j["tasks"]["id-A-1"]["stage"]), ("merge_uncertain", "merge_uncertain")
        )
        msg = [t for i, t in self.said if i == "g1"][-1]
        self.assertIn("UNCERTAIN for A-1", msg)
        self.assertNotIn("Nothing was merged", msg)
        self.assertFalse(any("rolled back" in t for i, t in self.said if i == "id-A-1"))  # never claimed
        self.assertTrue(self.gate())
        _, full = arc.delivery_packet(j, self.issues["G-1"], self.gate())
        self.assertIn("Merge state is UNCERTAIN", full)
        self.assertNotIn("Nothing is merged", full)

    def test_first_project_rollback_failure_is_uncertain_not_nothing_merged(self):
        self.failing_rollback("raise")
        with self.assertRaises(arc.Refused) as cm:
            arc.approve_goal(arc.journal(), "G-1", self.code())
        self.assert_uncertain_first_project(cm)

    def test_rollback_that_silently_did_nothing_is_caught_and_uncertain(self):
        self.failing_rollback("noop")
        with self.assertRaises(arc.Refused) as cm:
            arc.approve_goal(arc.journal(), "G-1", self.code())
        self.assert_uncertain_first_project(cm)
        self.assertNotEqual(
            gitc(self.dirs["alpha-habits"], "rev-parse", "main"), arc.journal()["tasks"]["id-A-1"]["candidate"]["base"]
        )

    def test_merge_effects_claims_nothing_merged_only_when_proven(self):
        o = lambda *r: [{"task": f"T-{i}", "result": x} for i, x in enumerate(r)]
        self.assertEqual(arc.merge_effects(o("failed", "not attempted")), "Nothing was merged. ")
        self.assertIn("UNCERTAIN for T-0", arc.merge_effects(o("uncertain", "not attempted")))
        self.assertNotIn("Nothing", arc.merge_effects(o("uncertain", "not attempted")))
        self.assertIn("Some work IS merged", arc.merge_effects(o("merged", "uncertain")))

    def test_first_project_failure_reports_nothing_merged_and_rest_not_attempted(self):
        self.final_checks_pass(fail_in=("alpha-habits",))
        before = self.main_heads()
        with self.assertRaises(arc.Refused) as cm:
            arc.approve_goal(arc.journal(), "G-1", self.code())
        self.assertEqual([o["result"] for o in cm.exception.outcome], ["failed", "not attempted"])
        self.assertEqual(self.main_heads(), before)
        self.assertEqual(arc.journal()["tasks"]["g1"]["stage"], "merge_failed")

    def test_other_checkout_plus_drift_still_blocks(self):
        d = self.dirs["beta-ratelimit"]
        gitc(d, "checkout", "-q", "main")
        gitc(d, "config", "core.fsmonitor", "true")
        self.assertTrue(any(p.startswith("B-1:") for p in self.gate()))
        with self.assertRaises(arc.Refused):
            arc.approve_goal(arc.journal(), "G-1", self.code())
        self.assertEqual(gitc(d, "rev-parse", "--abbrev-ref", "HEAD"), "main")

    def test_disturbed_checkout_is_restored_and_verified_by_goal_approval(self):
        gitc(self.dirs["beta-ratelimit"], "checkout", "-q", "main")  # e.g. a later goal planned from main
        self.assertEqual(self.gate(), [])  # a clean other checkout doesn't block
        with self.assertRaises(arc.Refused):
            arc.approve_goal(arc.journal(), "G-1", "0" * 12)
        self.assertEqual(gitc(self.dirs["beta-ratelimit"], "rev-parse", "--abbrev-ref", "HEAD"), "main")  # untouched
        outcome = arc.approve_goal(arc.journal(), "G-1", self.code())
        self.assertEqual([o["result"] for o in outcome], ["merged", "merged"])


class CommittedDrift(ReadyGoal):  # B4: later commits on main invalidate a delivered child unless runner-recorded
    def approve(self, ident):
        WholeGoalRevalidation.approve(self, ident)

    def test_clean_descendant_revert_invalidates_delivered_child(self):
        self.approve("A-1")
        d = self.dirs["alpha-habits"]
        (Path(d) / "src/x.js").write_text("export const v = 1;\n")
        gitc(d, "commit", "-qam", "quiet revert")
        self.assertTrue(any(p.startswith("A-1:") and "did not record" in p for p in self.gate()))
        before = {p: gitc(x, "rev-parse", "main") for p, x in self.dirs.items()}
        with self.assertRaises(SystemExit):
            self.approve("B-1")
        self.assertEqual({p: gitc(x, "rev-parse", "main") for p, x in self.dirs.items()}, before)

    def test_runner_recorded_successor_merge_keeps_delivery_valid(self):
        self.approve("A-1")
        self.issues["A-9"] = {
            "id": "id-A-9",
            "identifier": "A-9",
            "parentId": None,
            "status": "in_review",
            "title": "A-9",
        }
        j = arc.journal()
        self.j = j
        self.ready("A-9", "alpha-habits", content="9", attempt="s1", kind=None)
        arc.save(j)
        arc.approve_task(arc.journal(), "A-9", arc.journal()["tasks"]["id-A-9"]["code"])
        self.assertEqual(self.gate(), [])


class FullTaskText(World):  # demo finding: Paperclip's list endpoint cuts descriptions at 1200 characters
    def test_issue_lookup_reads_the_issue_directly_not_the_list_copy(self):
        full = "D" * 1951 + "\n\nAcceptance: print the walkthrough"
        self.patch(
            issues=lambda: self.fail("the list must not be used for task text"),
            api=lambda m, path, body=None: (
                (200, {"id": "x", "identifier": "ARC-9", "description": full}) if path == "/issues/ARC-9" else (404, {})
            ),
        )
        self.assertEqual(REAL_BY_IDENTIFIER("ARC-9")["description"], full)

    def test_unreadable_or_wrong_issue_stops_instead_of_guessing(self):
        for reply in ((500, {}), (200, {"id": "y", "identifier": "ARC-8", "description": "other"}), (200, ["x"])):
            self.patch(api=lambda m, path, body=None, r=reply: r)
            with self.assertRaises(SystemExit):
                REAL_BY_IDENTIFIER("ARC-9")

    def test_runner_created_issue_must_still_have_exactly_the_text_it_was_given(self):
        body = "task text " * 200 + "SENTINEL-AFTER-1200"
        self.patch(
            api=lambda m, path, body_=None: (201, {**body_, "id": "x", "identifier": "ARC-9"}), company_id=lambda: "co"
        )
        arc.create_issue(self.j, {"title": "t", "description": body}, "k")
        self.patch(api=lambda m, path, body_=None: (200, {"id": "x", "identifier": "ARC-9", "description": body}))
        self.assertEqual(REAL_BY_IDENTIFIER("ARC-9")["description"], body)
        self.patch(
            api=lambda m, path, body_=None: (200, {"id": "x", "identifier": "ARC-9", "description": body[:1200]})
        )
        with self.assertRaises(SystemExit):
            REAL_BY_IDENTIFIER("ARC-9")

    def test_paperclip_storing_different_text_is_refused_at_creation(self):
        self.patch(
            api=lambda m, path, body_=None: (201, {**body_, "id": "x", "identifier": "ARC-9", "description": "cut"}),
            company_id=lambda: "co",
        )
        with self.assertRaises(arc.Refused):
            arc.create_issue(self.j, {"title": "t", "description": "long text"}, "k")

    def test_issue_list_is_paged_completely_and_fails_closed(self):
        rows = [{"id": f"i{n:04d}", "identifier": f"ARC-{n}"} for n in range(450)]

        def api(m, path, body=None):
            q = dict(x.split("=") for x in path.split("?")[1].split("&"))
            o, l = int(q["offset"]), int(q["limit"])
            return 200, rows[o : o + l]

        self.patch(api=api, company_id=lambda: "co")
        self.assertEqual([i["id"] for i in arc.issues()], [r["id"] for r in rows])
        self.patch(api=lambda m, path, body=None: (200, rows[: arc.PAGE]))  # a server that ignores offset
        with self.assertRaises(SystemExit):
            arc.issues()
        self.patch(api=lambda m, path, body=None: (200, rows))  # a server that ignores limit
        with self.assertRaises(SystemExit):
            arc.issues()

        def shifted(m, path, body=None):  # an issue moved while paging
            o = int(path.split("offset=")[1].split("&")[0])
            return 200, rows[max(0, o - 50) : o - 50 + arc.PAGE] if o else rows[: arc.PAGE]

        self.patch(api=shifted)
        with self.assertRaises(SystemExit):
            arc.issues()

    def test_comment_pages_are_merged_by_id_including_a_repeated_edge_comment(self):
        cs = [{"id": f"c{n:04d}", "body": str(n)} for n in range(450)]

        def api(m, path, body=None):
            q = dict(x.split("=") for x in path.split("?")[1].split("&"))
            start = 0
            if "after" in q:
                start = next(
                    k for k, c in enumerate(cs) if c["id"] == q["after"]
                )  # repeats the anchor (Paperclip ms bug)
            return 200, cs[start : start + int(q["limit"])]

        self.patch(api=api)
        self.assertEqual([c["id"] for c in arc.comments_all("x")], [c["id"] for c in cs])
        self.patch(api=lambda m, path, body=None: (200, cs[: arc.PAGE]))  # no progress: fail closed
        with self.assertRaises(SystemExit):
            arc.comments_all("x")
        self.patch(api=lambda m, path, body=None: (500, {}))
        with self.assertRaises(SystemExit):
            arc.comments_all("x")

    def test_integration_reviewer_sees_every_approved_acceptance_criterion(self):
        g = self.j["tasks"]["g1"]["plan"]["subtasks"]
        g[0]["acceptance"] = ["MUST print the walkthrough"]
        g[1]["acceptance"] = ["MUST keep README current"]
        arc.save(self.j)
        self.run_goal([("approve", [])])
        self.assertIn("T1.1: MUST print the walkthrough", self.reviews[0])
        self.assertIn("T2.1: MUST keep README current", self.reviews[0])
        self.assertIn("exactly one entry per criterion id", self.reviews[0])
        self.assertEqual(self.criteria_seen[0], ["T1.1", "T2.1"])

    def test_packet_shows_every_integration_attempt_and_the_correction(self):
        self.run_goal([("changes", HIGH_A), ("approve", [])])
        rep = self.last_report()
        self.assertIn("Attempt 1: **changes**", rep)
        self.assertIn("alpha-habits/src/x.js: bug", rep)
        self.assertIn("Attempt 2: **approve**", rep)
        self.assertIn("re-integrated", rep)
        story = arc.review_story(
            {
                "history": [
                    {"review": "changes", "findings": []},
                    {"review": "approve", "findings": []},
                    {"review": "approve", "findings": []},
                ]
            }
        )
        self.assertIn("Repair 1: the builder fixed the findings above", story)
        self.assertIn("Repair 2: the builder fixed the integration review's findings", story)


class DeliveryPacket(ReadyGoal):
    def test_packet_has_every_section_reviews_repairs_diff_preview_and_actions(self):
        d = self.dirs["alpha-habits"]
        (Path(d) / "examples").mkdir(exist_ok=True)
        (Path(d) / "examples/demo.mjs").write_text("console.log('demo 42')\n")
        gitc(d, "add", "-A")
        gitc(d, "commit", "-qm", "example")
        j = arc.journal()
        self.j = j
        self.ready("A-1", "alpha-habits", content="101", attempt="a2")
        j["tasks"]["id-TA-1"]["history"] = [
            {
                "attempt": "a1",
                "tests": {"pass": 3, "fail": 0},
                "review": "changes",
                "reason": "reviewer requested changes",
                "findings": [{"severity": "medium", "file": "src/x.js", "issue": "off by one"}],
            },
            {
                "attempt": "a2",
                "review": "ownership",
                "reason": "changed paths it does not own",
                "findings": [{"severity": "medium", "file": "README.md", "issue": "outside this task's owned paths"}],
            },
            {
                "attempt": "a3",
                "tests": {"pass": 4, "fail": 0},
                "review": "approve",
                "reason": "",
                "coverage": [{"criterion": "T1.1", "status": "met", "evidence": "t"}],
                "findings": [],
            },
        ]
        arc.save(j)
        self.script = [
            ("approve", [{"severity": "low", "file": "README.md", "issue": "could mention v"}], {"T2.2": "unverified"})
        ]
        arc.milestone_and_report(arc.journal(), self.goal)
        self.patch(sandboxed_node=lambda d, scratch, args, out, timeout, test=True: (0, "demo 42\n"))
        short, full = arc.delivery_packet(arc.journal(), self.goal, [])
        for part in (
            "delivery packet",
            "**Your decision**",
            "APPROVE GOAL G-1",
            "REJECT GOAL G-1",
            "**Goal (your words)**",
            "**Approved plan**",
            "T1 backend (alpha-habits): task 1",
            "**Verification status**",
            "pass 3, fail 0",
            "every forbidden access denied",
            "**Browser flow: not verified.**",
            "**Acceptance coverage**",
            "| T1.1: alpha-habits criterion one | T1 | met |",
            "| T2.2: beta-ratelimit criterion two | T2 | unverified |",
            "Not verified: T2.2",
            "**Tasks** (built one at a time",
            "| TA-1 | T1 | backend | `src/`, `examples/` | - |",
            "| TB-1 | T2 | backend | `src/`, `examples/` | T1 |",
            "**Integration**",
            "Review 1",
            "off by one",
            "Repair 1",
            "Runner ownership check",
            "Repair 2",
            "Review 2",
            "**approve**",
            "Integration review (the combined result)",
            "node examples/demo.mjs",
            "demo 42",
            "open low-severity note",
            "could mention v",
            "not proof of who typed them",
            "+export const v = 101;",
            "one at a time",
            "git -C",
        ):
            self.assertIn(part, short, part)
        self.assertIn("+export const v = 101;", full)
        self.assertIn("**Approved plan, in full**", full)
        self.assertIn("T2.2: beta-ratelimit criterion two", full)
        self.assertNotIn("Start the app", short)  # no server configured in this world

    def test_server_projects_get_start_stop_instructions_and_http_status(self):
        self.cfg["projects"]["alpha-habits"]["serve"] = {
            "entry": "src/serve.js",
            "port": 4199,
            "checks": "test/acceptance/http.json",
        }
        j = arc.journal()
        t = j["tasks"]["id-A-1"]
        tag = t["evidence"]["tag"]
        http = {
            "entry": "src/serve.js",
            "port": 4199,
            "started": True,
            "stopped": True,
            "passed": 1,
            "total": 2,
            "ok": False,
            "checks": [
                {"name": "home page", "ok": True, "status": 200, "why": ""},
                {"name": "traversal refused", "ok": False, "status": 200, "why": "status 200, expected [403, 404]"},
            ],
        }
        (self.state / f"{tag}-http.json").write_text(json.dumps(http))
        t["http"] = http
        t["evidence"]["http"] = arc.sha_file(self.state / f"{tag}-http.json")
        arc.save(j)
        probs = arc.goal_gate(arc.journal(), "g1")
        self.assertTrue(any("HTTP checks 1/2" in p for p in probs))  # a failing check blocks readiness
        short, _ = arc.delivery_packet(arc.journal(), self.goal, probs)
        for part in (
            "arc.py preview G-1",
            "http://127.0.0.1:4199",
            "**Stop:** Ctrl-C",
            "**1/2 passed**",
            "FAILED traversal refused: status 200",
            "**Browser flow: not verified.**",
        ):
            self.assertIn(part, short, part)
        self.assertNotIn("APPROVE GOAL", short)

    def test_legacy_goal_cannot_be_approved_under_the_new_rules(self):
        j = arc.journal()
        g = j["tasks"]["g1"]
        g["children"] = g.pop("integration")
        g.pop("format")
        arc.save(j)
        self.assertTrue(any("predates Phase 3A" in p for p in self.gate()))
        with self.assertRaises(arc.Refused):
            arc.approve_goal(arc.journal(), "G-1", arc.goal_code(arc.journal(), "g1"))

    def test_not_ready_packet_offers_no_approval_and_says_what_is_merged(self):
        WholeGoalRevalidation.approve(self, "A-1")
        j = arc.journal()
        j["tasks"]["id-B-1"]["stage"] = "blocked"
        arc.save(j)
        short, _ = arc.delivery_packet(arc.journal(), self.goal, arc.goal_gate(arc.journal(), "g1"))
        self.assertNotIn("APPROVE GOAL", short)
        self.assertIn("Some work is already merged", short)
        self.assertNotIn("Nothing is merged", short)
        self.assertIn("merged as", short)

    def test_overlapping_goal_is_named_and_merging_one_makes_the_other_stale(self):
        j = arc.journal()
        g2 = {
            "identifier": "G-2",
            "kind": "goal",
            "stage": "reported",
            "format": 3,
            "children": [],
            "integration": [{"id": "id-A-7", "identifier": "A-7", "project": "alpha-habits"}],
        }
        j["tasks"]["g2"] = g2
        self.j = j
        gitc(self.dirs["alpha-habits"], "checkout", "-q", "main")
        self.ready("A-7", "alpha-habits", content="7", attempt="o1")
        arc.save(j)
        gitc(self.dirs["alpha-habits"], "checkout", "-q", "task/a-1")
        self.patch(goal_gate=lambda j, k, real=arc.goal_gate: [] if k == "g2" else real(j, k))  # G-2 approvable
        self.assertIn("Overlaps with G-2", arc.delivery_packet(arc.journal(), self.goal, [])[0])
        self.patch(goal_gate=lambda j, k, real=arc.goal_gate: ["stale"] if k == "g2" else real(j, k))
        self.assertNotIn("Overlaps", arc.delivery_packet(arc.journal(), self.goal, [])[0])  # unapprovable: not listed
        self.patch(goal_gate=lambda j, k, real=arc.goal_gate: real(j, k) if k == "g1" else [])
        arc.approve_goal(arc.journal(), "G-1", arc.goal_code(arc.journal(), "g1"))
        self.assertTrue(any("moved" in p for p in T_GATE(arc.journal(), "g2")))  # stale, refused, not merged

    def test_long_diff_is_cut_in_the_comment_but_complete_in_the_file(self):
        d = self.dirs["beta-ratelimit"]
        gitc(d, "checkout", "-q", "task/b-1")
        (Path(d) / "src/big.js").write_text("".join(f"export const line{i} = {i};\n" for i in range(800)))
        gitc(d, "add", "-A")
        gitc(d, "commit", "-qm", "big")
        j = arc.journal()
        self.j = j
        self.ready("B-1", "beta-ratelimit", content="5", attempt="b3")
        arc.save(j)
        short, full = arc.delivery_packet(arc.journal(), self.goal, [])
        self.assertIn("cut here", short)
        self.assertIn("line799", full)
        self.assertNotIn("line799", short)


# ======================= Phase 3A: several coordinated tasks in one project =======================
SENTINEL = "SENTINEL-REQUIRED-AFTER-1200"


class MultiTask(World):
    """One project, three planned tasks (backend, frontend, integration): real branches, ownership checks, deferred
    acceptance files, integration merges and combined checks. Scripted builder and reviewers, no model calls."""

    def setUp(self):
        super().setUp()
        self.final_checks_pass()
        d = self.d = self.dirs["alpha-habits"]
        gitc(d, "checkout", "-q", "main")
        for rel in ("test/acceptance/api.test.js", "test/acceptance/web.test.js"):
            (Path(d) / rel).write_text("// oracle\n")
        gitc(d, "add", "-A")
        gitc(d, "commit", "-qm", "acceptance")
        self.k, self.prompts, self.attempts = 0, [], {}
        self.files = {
            "T-1": [{"src/api/a.js": "export const api = 1;\n"}],
            "T-2": [{"src/web/w.js": "export const w = 1;\n"}],
            "T-3": [{"README.md": "# app\n"}],
        }
        self.patch(
            api=self.api3,
            company_id=lambda: "co",
            project_ids=lambda: {"alpha-habits": "pa", "beta-ratelimit": "pb"},
            agents=lambda: {"Lead": {"id": "lead"}, "Alpha Builder": {"id": "ab"}},
            claude=self.builder,
            set_status=self.status3,
            repair_task=REAL_REPAIR_TASK,
        )
        self.subs = [
            sub(
                1,
                owned_paths=["src/api/"],
                acceptance=["API answers", "API validates"],
                description="D" * 1300 + SENTINEL,
                acceptance_tests=["test/acceptance/api.test.js"],
            ),
            sub(
                2,
                role="frontend",
                owned_paths=["src/web/"],
                depends_on=["T1"],
                acceptance=["page renders"],
                acceptance_tests=["test/acceptance/web.test.js"],
            ),
            sub(
                3,
                role="integration",
                owned_paths=["src/serve.js", "README.md"],
                depends_on=["T1", "T2"],
                acceptance=["README explains it"],
            ),
        ]
        self.goal3 = {
            "id": "g3",
            "identifier": "G-3",
            "title": "app",
            "description": "build it",
            "assigneeAgentId": "lead",
            "status": "in_review",
        }
        self.issues["G-3"] = self.goal3
        j = arc.journal()
        j["tasks"]["g3"] = {
            "identifier": "G-3",
            "kind": "goal",
            "format": 3,
            "stage": "plan_proposed",
            "plan_base": {"alpha-habits": gitc(d, "rev-parse", "main")},
            "budget": {"max_reviews": 3, "max_repairs": 2},
        }
        arc.save(j)

    def api3(self, method, path, body=None):
        if method == "POST" and path == "/companies/co/issues":
            if "integration of" in body["title"]:
                ident = "INT-1"
            else:
                self.k += 1
                ident = f"T-{self.k}"
            iss = {**body, "id": "id-" + ident, "identifier": ident}
            self.issues[ident] = iss
            return 201, iss
        return self.fake_api(method, path, body)

    def status3(self, iid, st):
        hit = next((i for i in self.issues.values() if i["id"] == iid), {})
        if st == "in_progress" and not (hit.get("assigneeAgentId") or hit.get("assigneeUserId")):
            raise SystemExit("could not set Paperclip status in_progress (HTTP 422); stopping")  # as Paperclip does
        self.status[iid] = st
        for i in self.issues.values():
            if i["id"] == iid:
                i["status"] = st

    def builder(self, prompt, policy, cwd, out, schema=None, **kw):
        ident = re.match(r"Task (\S+):", prompt).group(1)
        n = self.attempts.get(ident, 0)
        self.attempts[ident] = n + 1
        self.prompts.append((ident, prompt))
        for rel, txt in self.files[ident][min(n, len(self.files[ident]) - 1)].items():
            f = Path(cwd) / rel
            if txt is None:
                f.unlink()
            else:
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(txt)
        gitc(cwd, "add", "-A")
        if gitc(cwd, "status", "--porcelain"):
            gitc(cwd, "commit", "-qm", f"{ident} attempt {n + 1}")
        Path(out).write_text("{}")
        return 0, {}

    def run3(self, script):
        self.script = list(script)
        arc.execute_plan(arc.journal(), self.goal3, self.subs, "split into three")
        return arc.journal()

    def ids(self, j):
        return {c["identifier"]: c for c in j["tasks"]["g3"]["children"]}

    def test_three_tasks_run_in_order_each_from_the_integration_head_and_the_whole_is_checked(self):
        j = self.run3([("approve", [])] * 4)
        g = j["tasks"]["g3"]
        it = j["tasks"]["id-INT-1"]
        self.assertEqual([i for i, _ in self.prompts], ["T-1", "T-2", "T-3"])  # one writer at a time, in order
        self.assertEqual(len(it["chain"]), 4)  # base + three clean merges
        self.assertEqual(j["tasks"]["id-T-1"]["start"], g["plan_base"]["alpha-habits"])
        self.assertEqual(
            j["tasks"]["id-T-2"]["start"], j["tasks"]["id-T-1"]["integrated_as"]
        )  # each from the integrated result
        self.assertEqual(j["tasks"]["id-T-3"]["start"], j["tasks"]["id-T-2"]["integrated_as"])
        self.assertEqual(self.deferred, [["test/acceptance/web.test.js"], [], [], []])  # later task's file waits
        self.assertEqual(it["stage"], "awaiting_approval")
        self.assertEqual(it["candidate"]["head"], it["chain"][-1])
        self.assertEqual(gitc(self.d, "rev-parse", "integration/g-3^{tree}"), j["tasks"]["id-T-3"]["candidate"]["tree"])
        self.assertEqual(self.criteria_seen[-1], ["T1.1", "T1.2", "T2.1", "T3.1"])  # integration review: all
        self.assertEqual(self.criteria_seen[0], ["T1.1", "T1.2"])  # task review: its own
        self.assertEqual(arc.goal_gate(j, "g3"), [])
        self.assertEqual(j["reservations"]["alpha-habits"]["identifier"], "G-3")
        b1 = dict(self.prompts)["T-1"]
        for text in (
            SENTINEL,
            "T1.2: API validates",
            "You own only these paths: src/api/",
            "test/acceptance/web.test.js",
            "T2 frontend (alpha-habits)",
            "later",
        ):
            self.assertIn(text, b1, text)
        self.assertIn(SENTINEL, self.reviews[0])
        self.assertIn(SENTINEL, self.issues["T-1"]["description"])
        self.assertIn("already integrated", dict(self.prompts)["T-3"])
        outcome = arc.approve_goal(arc.journal(), "G-3", arc.goal_code(arc.journal(), "g3"))  # one merge of the whole
        self.assertEqual([(o["task"], o["result"]) for o in outcome], [("INT-1", "merged")])
        for rel in ("src/api/a.js", "src/web/w.js", "README.md"):
            self.assertIn(rel, gitc(self.d, "ls-tree", "-r", "--name-only", "main"))
        self.assertEqual(arc.journal()["reservations"], {})
        self.assertEqual(self.status["id-T-2"], "done")

    def stop_after_integration(self):
        """Run the plan but stop (as a refused Paperclip call did in ARC-38) right after the last task is integrated."""
        real = arc.check_and_review

        def stop(j, goal):
            j["tasks"]["id-INT-1"]["stage"] = "checking"
            arc.save(j)
            raise SystemExit("could not set Paperclip status in_progress (HTTP 422); stopping")

        self.patch(check_and_review=stop)
        j = arc.journal()
        g = j["tasks"]["g3"]  # the plan Yash approved (bridge path)
        g["proposal"] = {
            "subtasks": self.subs,
            "summary": "split into three",
            "base": dict(g["plan_base"]),
            "budget": {"max_reviews": 3, "max_repairs": 2},
        }
        g["plan_code"] = g["plan_approved"] = arc.plan_code("g3", g["proposal"])
        arc.save(j)
        with self.assertRaises(SystemExit):
            self.run3([("approve", [])] * 4)
        self.patch(check_and_review=real)
        j = arc.journal()
        arc.mark_interrupted(j)
        return arc.journal()

    def test_resume_finishes_a_goal_stopped_after_integration_without_rebuilding(self):
        j = self.stop_after_integration()
        self.assertEqual(j["tasks"]["id-INT-1"]["stage"], "interrupted")
        self.assertNotEqual(arc.goal_gate(j, "g3"), [])
        built = len(self.prompts)
        arc.resume_goal(arc.journal(), "G-3")
        j = arc.journal()
        self.assertEqual(len(self.prompts), built)  # no task rebuilt
        it = j["tasks"]["id-INT-1"]
        self.assertEqual(it["stage"], "awaiting_approval")
        self.assertEqual(it["candidate"]["head"], it["chain"][-1])
        self.assertEqual(self.criteria_seen[-1], ["T1.1", "T1.2", "T2.1", "T3.1"])  # integration review ran
        self.assertEqual(arc.goal_gate(j, "g3"), [])
        self.assertEqual(self.status["id-INT-1"], "in_review")

    def test_resume_refuses_a_moved_branch_a_task_not_integrated_or_a_finished_goal(self):
        self.stop_after_integration()
        gitc(self.d, "checkout", "-q", "integration/g-3")
        (Path(self.d) / "x.txt").write_text("x")
        gitc(self.d, "add", "-A")
        gitc(self.d, "commit", "-qm", "stray")
        with self.assertRaisesRegex(arc.Refused, "moved"):
            arc.resume_goal(arc.journal(), "G-3")
        gitc(self.d, "reset", "-q", "--hard", "HEAD~1")
        j = arc.journal()
        j["tasks"]["id-T-2"]["stage"] = "blocked"
        arc.save(j)
        with self.assertRaisesRegex(arc.Refused, "not integrated"):
            arc.resume_goal(arc.journal(), "G-3")
        j = arc.journal()
        j["tasks"]["id-T-2"]["stage"] = "integrated"
        arc.save(j)
        arc.resume_goal(arc.journal(), "G-3")
        with self.assertRaisesRegex(arc.Refused, "only a goal stopped after delegation"):
            arc.resume_goal(arc.journal(), "G-3")

    def assert_resume_refused(self, why):
        """Resume must refuse with `why`, before changing anything: no stage change, no checks, no review, no build."""
        j0 = arc.journal()
        built, reviewed = len(self.prompts), len(self.reviews)
        with self.assertRaises(arc.Refused) as e:
            arc.resume_goal(arc.journal(), "G-3")
        self.assertIn(why, str(e.exception))
        j = arc.journal()
        self.assertEqual(j["tasks"]["id-INT-1"]["stage"], "interrupted")
        self.assertEqual(j["tasks"]["g3"]["stage"], "delegated")
        self.assertEqual((len(self.prompts), len(self.reviews)), (built, reviewed))
        self.assertEqual(j["tasks"]["id-INT-1"].get("candidate"), j0["tasks"]["id-INT-1"].get("candidate"))

    def reseal(self, j, iid):
        """Make a tampered receipt internally consistent again (its code recomputed), as a careless or hostile edit could."""
        t = j["tasks"][iid]
        t["code"] = arc.approval_code(iid, t["attempt"], t["candidate"], t["evidence"])
        arc.save(j)

    def test_resume_refuses_missing_task_review_evidence(self):
        self.stop_after_integration()
        t = arc.journal()["tasks"]["id-T-1"]
        (arc.STATE / f"{t['evidence']['tag']}-review{t['evidence']['review_n']}.json").unlink()
        self.assert_resume_refused("T-1: review evidence missing or changed")

    def test_resume_refuses_changed_task_review_evidence(self):
        self.stop_after_integration()
        t = arc.journal()["tasks"]["id-T-2"]
        f = arc.STATE / f"{t['evidence']['tag']}-review{t['evidence']['review_n']}.json"
        f.write_text(f.read_text() + " ")
        self.assert_resume_refused("T-2: review evidence missing or changed")

    def test_resume_refuses_a_resealed_review_that_did_not_approve(self):
        j = self.stop_after_integration()
        t = j["tasks"]["id-T-2"]
        f = arc.STATE / f"{t['evidence']['tag']}-review{t['evidence']['review_n']}.json"
        rv = json.loads(f.read_text())
        rv["verdict"] = "changes_requested"
        f.write_text(json.dumps(rv))
        t["evidence"]["review"] = arc.sha_file(f)
        self.reseal(j, "id-T-2")
        self.assert_resume_refused("T-2: its retained task review is not an approval")

    def test_resume_refuses_an_invalid_receipt(self):
        j = self.stop_after_integration()
        j["tasks"]["id-T-3"]["candidate"]["tree"] = "0" * 40
        arc.save(j)
        self.assert_resume_refused("T-3: its receipt does not match its recorded code")

    def test_resume_refuses_incomplete_evidence(self):
        j = self.stop_after_integration()
        j["tasks"]["id-T-1"]["evidence"] = {}
        arc.save(j)
        self.assert_resume_refused("T-1: its receipt is missing or predates the current format")
        j = arc.journal()
        del j["tasks"]["id-T-2"]["evidence"]["tag"]
        self.reseal(j, "id-T-2")
        self.assert_resume_refused("T-2: its evidence record is incomplete")

    def test_resume_refuses_outdated_receipts(self):
        j = self.stop_after_integration()
        j["tasks"]["id-T-1"]["candidate"]["v"] = arc.RECEIPT - 1
        self.reseal(j, "id-T-1")
        self.assert_resume_refused("T-1: its receipt is missing or predates the current format")
        j = arc.journal()
        j["tasks"]["id-T-1"]["candidate"]["v"] = arc.RECEIPT
        j["tasks"]["id-T-1"]["candidate"]["base"] = "1" * 40
        self.reseal(j, "id-T-1")
        self.assert_resume_refused("T-1: it was tested against a main other than the approved baseline")
        j = arc.journal()
        j["tasks"]["id-T-1"]["candidate"]["base"] = j["tasks"]["g3"]["plan_base"]["alpha-habits"]
        self.reseal(j, "id-T-1")
        j["tasks"]["id-T-3"]["start"] = j["tasks"]["g3"]["plan_base"]["alpha-habits"]
        arc.save(j)
        self.assert_resume_refused("T-3: it was not built from the integration head before it")

    def test_resume_refuses_altered_merge_history(self):
        j = self.stop_after_integration()
        it = j["tasks"]["id-INT-1"]
        tree = gitc(self.d, "rev-parse", f"{it['chain'][-1]}^{{tree}}")  # same tree, but not a merge
        fake = gitc(self.d, "commit-tree", tree, "-p", it["chain"][-2], "-m", "squashed")
        gitc(self.d, "update-ref", "refs/heads/integration/g-3", fake)
        it["chain"][-1] = fake
        j["tasks"]["id-T-3"]["integrated_as"] = fake
        arc.save(j)
        self.assert_resume_refused("T-3: its integration merge is missing or not a merge")

    def test_resume_refuses_a_merge_of_something_other_than_the_reviewed_commit(self):
        j = self.stop_after_integration()
        it = j["tasks"]["id-INT-1"]
        tree = gitc(self.d, "rev-parse", f"{it['chain'][-1]}^{{tree}}")  # a real merge, same tree, wrong side
        fake = gitc(
            self.d,
            "commit-tree",
            tree,
            "-p",
            it["chain"][-2],
            "-p",
            j["tasks"]["id-T-1"]["candidate"]["head"],
            "-m",
            "m",
        )
        gitc(self.d, "update-ref", "refs/heads/integration/g-3", fake)
        it["chain"][-1] = fake
        j["tasks"]["id-T-3"]["integrated_as"] = fake
        arc.save(j)
        self.assert_resume_refused(
            "T-3: its integration merge is not the reviewed commit merged onto the head before it"
        )

    def test_resume_refuses_a_chain_that_does_not_match_the_tasks(self):
        j = self.stop_after_integration()
        it = j["tasks"]["id-INT-1"]
        it["chain"][1], it["chain"][2] = it["chain"][2], it["chain"][1]
        arc.save(j)
        self.assert_resume_refused("its recorded chain is not the approved base plus each task's merge")

    def test_resume_refuses_moved_main(self):
        self.stop_after_integration()
        gitc(self.d, "checkout", "-q", "main")
        (Path(self.d) / "late.txt").write_text("x")
        gitc(self.d, "add", "-A")
        gitc(self.d, "commit", "-qm", "late")
        gitc(self.d, "checkout", "-q", "integration/g-3")
        self.assert_resume_refused("alpha-habits: main moved from the approved baseline")

    def test_resume_refuses_wrong_reservation(self):
        j = self.stop_after_integration()
        j["reservations"]["alpha-habits"]["goal"] = "someone-else"
        arc.save(j)
        self.assert_resume_refused("alpha-habits is not reserved for G-3")

    def test_resume_refuses_a_plan_changed_after_approval(self):
        j = self.stop_after_integration()
        j["tasks"]["g3"]["proposal"]["subtasks"][0]["acceptance"].append("extra")
        arc.save(j)
        self.assert_resume_refused("the plan on record is not exactly the plan Yash approved")

    def test_resume_refuses_changed_config(self):
        self.stop_after_integration()
        gitc(self.d, "config", "core.hooksPath", "/tmp/elsewhere")
        self.assert_resume_refused("alpha-habits: config or protected files differ")

    def test_change_outside_owned_paths_is_found_and_sent_back(self):
        self.files["T-2"] = [{"src/web/w.js": "export const w = 1;\n", "README.md": "# mine\n"}, {"README.md": None}]
        j = self.run3([("approve", [])] * 4)
        t = j["tasks"]["id-T-2"]
        self.assertEqual([h["review"] for h in t["history"]], ["ownership", "approve"])
        self.assertEqual(t["repairs"], 1)
        self.assertEqual(t["history"][0]["findings"][0]["file"], "README.md")
        self.assertIn("outside this task's owned paths", [p for i, p in self.prompts if i == "T-2"][1])
        self.assertEqual(arc.goal_gate(j, "g3"), [])

    def test_failing_tests_go_back_to_the_builder_within_the_repair_budget(self):
        real = arc.run_tests

        def tests(d, out, defer=()):
            r = real(d, out, defer)
            if self.attempts.get("T-1") == 1:  # first build of T-1 fails in the runner's sandbox
                Path(out).write_text("not ok 1 - listens on a port\nEPERM listen\n")
                r.update(ok=False, fail=1)
            return r

        self.patch(run_tests=tests)
        self.files["T-1"].append({"src/api/a.js": "export const api = 2;\n"})
        j = self.run3([("approve", [])] * 4)
        t = j["tasks"]["id-T-1"]
        self.assertEqual([h["review"] for h in t["history"]], ["tests_failed", "approve"])
        self.assertEqual(t["repairs"], 1)
        self.assertIn("EPERM listen", [p for i, p in self.prompts if i == "T-1"][1])
        self.assertIn("no network at all", self.prompts[0][1])
        self.assertEqual(arc.goal_gate(j, "g3"), [])
        self.assertIn("Runner test run", arc.review_story(t))

    def test_integration_finding_goes_to_the_owning_task_which_repairs_from_the_combined_head(self):
        self.files["T-2"].append({"src/web/w.js": "export const w = 2;\n"})
        bad = [{"severity": "high", "file": "alpha-habits/src/web/w.js", "issue": "wrong field name"}]
        j = self.run3([("approve", [])] * 3 + [("changes", bad), ("approve", []), ("approve", [])])
        t2, it = j["tasks"]["id-T-2"], j["tasks"]["id-INT-1"]
        self.assertEqual([i for i, _ in self.prompts], ["T-1", "T-2", "T-3", "T-2"])  # routed to T2 only
        self.assertIn("wrong field name", self.prompts[-1][1])
        self.assertEqual(t2["start"], it["chain"][3])
        self.assertEqual(len(it["chain"]), 5)  # from the head after T3
        self.assertEqual(j["tasks"]["g3"]["milestone_repairs"], 1)
        self.assertEqual(arc.goal_gate(j, "g3"), [])
        self.assertIn("export const w = 2;", gitc(self.d, "show", "integration/g-3:src/web/w.js"))

    def test_unmet_criterion_goes_to_the_task_it_belongs_to(self):
        self.files["T-3"].append({"README.md": "# app\nHow it works.\n"})
        j = self.run3([("approve", [])] * 3 + [("approve", [], {"T3.1": "not_met"})] + [("approve", [])] * 2)
        self.assertEqual([i for i, _ in self.prompts][-1], "T-3")
        self.assertEqual(arc.goal_gate(j, "g3"), [])
        self.assertIn("criterion:T3.1", json.dumps(j["tasks"]["id-T-3"]["history"][-1]) + self.prompts[-1][1])

    def test_a_blocked_task_stops_the_goal_before_dependents_and_before_any_combined_review(self):
        self.files["T-1"] = [{}]  # builder produces nothing
        j = self.run3([])
        self.assertEqual([i for i, _ in self.prompts], ["T-1"])
        self.assertEqual(
            [j["tasks"]["id-" + i]["stage"] for i in ("T-1", "T-2", "T-3")], ["blocked", "not_started", "not_started"]
        )
        self.assertEqual(self.reviews, [])
        probs = arc.goal_gate(j, "g3")
        self.assertTrue(any("T-2 (T2) is not_started" in p for p in probs))
        self.assertTrue(any("no integration review" in p for p in probs))
        self.assertIn("Not ready because", self.last_report())

    def test_integration_refuses_unrecorded_commits_and_changed_trees_and_restores_the_branch(self):
        j = self.run3([("approve", [])] * 4)
        g = j["tasks"]["g3"]
        c2 = self.ids(j)["T-2"]
        gitc(self.d, "checkout", "-q", "integration/g-3")
        head = gitc(self.d, "rev-parse", "HEAD")
        (Path(self.d) / "src/web/w.js").write_text("sneaky\n")
        gitc(self.d, "commit", "-qam", "outside the runner")
        self.assertTrue(any("INT-1" in p for p in arc.goal_gate(arc.journal(), "g3")))  # combined candidate moved
        t2 = j["tasks"]["id-T-2"]
        t2.update(stage="awaiting_approval", start=gitc(self.d, "rev-parse", "HEAD"))
        with self.assertRaises(arc.Blocked):
            arc.integrate(j, g, c2)  # not a recorded head
        gitc(self.d, "reset", "-q", "--hard", head)
        t2["start"] = head
        t2["candidate"] = {**t2["candidate"], "tree": "0" * 40}
        with self.assertRaises(arc.Blocked) as cm:
            arc.integrate(j, g, c2)  # merge result is not the reviewed tree
        self.assertIn("restored", str(cm.exception))
        self.assertEqual(gitc(self.d, "rev-parse", "integration/g-3"), head)
        self.assertEqual(gitc(self.d, "status", "--porcelain"), "")

    def test_project_is_reserved_until_the_goal_is_rejected(self):
        self.run3([("approve", [])] * 4)
        self.issues["G-4"] = {**self.goal3, "id": "g4", "identifier": "G-4"}
        with self.assertRaises(SystemExit) as cm:
            arc.cmd_goal("G-4")
        self.assertIn("reserved by G-3", str(cm.exception))
        self.assertNotIn("g4", arc.journal()["tasks"])
        j = arc.journal()
        j["tasks"]["g5"] = {"identifier": "G-5", "kind": "goal"}
        with self.assertRaises(arc.Refused):
            arc.reserve(j, "g5", ["alpha-habits"])
        arc.reject_goal(arc.journal(), "G-3")
        self.assertEqual(arc.journal()["reservations"], {})
        self.assertEqual(self.status["id-INT-1"], "cancelled")

    def test_interrupted_integration_steps_are_never_resumed(self):
        j = arc.journal()
        j["tasks"]["x1"] = {"identifier": "T-9", "stage": "integrating"}
        j["tasks"]["x2"] = {"identifier": "INT-9", "kind": "integration", "stage": "checking"}
        arc.save(j)
        arc.mark_interrupted(j)
        self.assertEqual([arc.journal()["tasks"][k]["stage"] for k in ("x1", "x2")], ["interrupted", "interrupted"])


class CoverageGate(ReadyGoal):  # the gate, not only the reviewer, insists on every criterion
    def test_review_that_skips_a_criterion_or_leaves_one_unmet_is_not_ready(self):
        self.assertEqual(self.gate(), [])
        j = arc.journal()
        last = j["tasks"]["g1"]["milestone_attempts"][-1]
        last["coverage"] = [c for c in last["coverage"] if c["criterion"] != "T2.2"]
        arc.save(j)
        self.assertTrue(any("does not account for every acceptance criterion" in p for p in self.gate()))
        last["coverage"].append({"criterion": "T2.2", "status": "not_met", "evidence": "missing"})
        arc.save(j)
        self.assertIn("acceptance criterion T2.2 is not met", self.gate())


class Withdrawal(ReadyGoal):  # review 27: ARC-34 must stop being an approval option
    def test_withdrawn_goal_never_passes_and_cannot_be_merged(self):
        code = arc.goal_code(arc.journal(), "g1")
        before = self.main_heads()
        arc.withdraw_goal(arc.journal(), "G-1", "built from cut-off task text")
        self.assertEqual(self.gate(), ["withdrawn by Yash: built from cut-off task text"])
        with self.assertRaises(arc.Refused):
            arc.approve_goal(arc.journal(), "G-1", code)
        with self.assertRaises(SystemExit):
            WholeGoalRevalidation.approve(self, "A-1")  # nor any part of it
        self.assertEqual(self.main_heads(), before)
        self.assertEqual({self.status[k] for k in ("g1", "id-A-1", "id-B-1", "id-TA-1")}, {"cancelled"})
        self.assertTrue(gitc(self.dirs["alpha-habits"], "branch", "--list", "task/a-1"))  # kept for comparison
        arc.report(arc.journal(), self.goal)
        self.assertEqual(arc.journal()["tasks"]["g1"]["stage"], "withdrawn")
        self.assertNotIn("APPROVE GOAL", self.last_report())

    def test_merged_goal_cannot_be_withdrawn(self):
        arc.approve_goal(arc.journal(), "G-1", arc.goal_code(arc.journal(), "g1"))
        with self.assertRaises(arc.Refused):
            arc.withdraw_goal(arc.journal(), "G-1", "too late")


class HttpChecks(unittest.TestCase):  # the combined app's real server, sandboxed; failures must fail (review 27)
    SERVER = (
        "import http from 'node:http';\n"
        "http.createServer((req, res) => {\n"
        "  if (req.url === '/') { res.writeHead(200, {'content-type': 'text/html'}); res.end('<title>Hi</title>'); }\n"
        "  else if (req.url.includes('..')) { res.writeHead(200); res.end('LEAK'); }\n"
        "  else { res.writeHead(404); res.end('no'); }\n"
        "}).listen(Number(process.env.PORT), process.env.HOST);\n"
    )

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="arc-http-"))
        make_repo(self.d, {"src/serve.js": self.SERVER})
        cfg = copy.deepcopy(arc.CFG)
        cfg["projects"]["web"] = {"serve": {"entry": "src/serve.js", "port": 4197, "checks": "checks.json"}}
        old = arc.CFG
        arc.CFG = cfg
        self.addCleanup(setattr, arc, "CFG", old)
        st = Path(tempfile.mkdtemp())
        oldg = arc.GROUPS
        arc.GROUPS = st / "g.json"
        self.addCleanup(setattr, arc, "GROUPS", oldg)
        self.home = {
            "name": "home page",
            "path": "/",
            "status": 200,
            "contains": ["<title>Hi"],
            "content_type": "text/html",
        }

    def run_checks(self, checks):
        (self.d / "checks.json").write_text(json.dumps(checks))
        return arc.run_http_checks(str(self.d), "web", self.d / "out.json")

    def test_passing_checks_pass_and_the_server_is_stopped(self):
        r = self.run_checks([self.home, {"name": "missing", "path": "/nope", "status": 404}])
        self.assertTrue(r["ok"], r)
        self.assertEqual((r["passed"], r["total"]), (2, 2))
        self.assertTrue(r["stopped"])
        self.assertFalse(arc.port_open(4197))
        self.assertEqual(json.loads((self.d / "out.json").read_text())["ok"], True)

    def test_raw_traversal_path_reaches_the_server_and_a_wrong_answer_fails(self):
        r = self.run_checks(
            [
                self.home,
                {
                    "name": "traversal refused",
                    "path": "/../package.json",
                    "status": [403, 404],
                    "not_contains": ["LEAK"],
                },
            ]
        )
        self.assertFalse(r["ok"])
        self.assertEqual(r["passed"], 1)
        self.assertIn("status 200", r["checks"][1]["why"])
        self.assertIn("LEAK", r["checks"][1]["why"])

    def test_busy_port_or_broken_server_fails_closed(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 4197))
            s.listen()
            r = self.run_checks([self.home])
        self.assertFalse(r["ok"])
        self.assertFalse(r["started"])
        self.assertIn("already in use", r["why"])
        (self.d / "src/serve.js").write_text("process.exit(3)\n")
        r = self.run_checks([self.home])
        self.assertFalse(r["ok"])
        self.assertIn("did not start", r["why"])

    def test_server_cannot_reach_the_network_or_other_ports(self):
        (self.d / "src/serve.js").write_text(
            "import http from 'node:http'; import net from 'node:net';\n"
            "http.createServer((req, res) => { const s = net.connect(3100, '127.0.0.1');\n"
            "  s.on('connect', () => { res.end('REACHED'); s.destroy(); }); s.on('error', e => res.end('denied ' + e.code)); })\n"
            ".listen(Number(process.env.PORT), process.env.HOST);\n"
        )
        r = self.run_checks(
            [
                {
                    "name": "paperclip unreachable",
                    "path": "/",
                    "status": 200,
                    "contains": ["denied"],
                    "not_contains": ["REACHED"],
                }
            ]
        )
        self.assertTrue(r["ok"], r)


if __name__ == "__main__":
    unittest.main()
