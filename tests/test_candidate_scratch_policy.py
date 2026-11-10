"""Offline checks for the candidate scratch profile and loader evidence."""

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_arc_unit import arc
import host_bundle_preflight as preflight


class CandidateScratchPolicy(unittest.TestCase):
    def test_canonical_and_alias_subtrees_are_noexec_but_scratch_remains_writable(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder).resolve()
            scratch = work / 'scratch "data"'
            scratch.mkdir()
            alias = work / "scratch-alias"
            alias.symlink_to(scratch, target_is_directory=True)
            node = work / "pin/node"
            profile = arc.sandbox_profile(work, alias, runtime=str(node), scratch_noexec=True)
            canonical = f"(subpath {json.dumps(str(scratch))})"
            lexical = f"(subpath {json.dumps(str(alias))})"
            self.assertIn(f"(deny process-exec* file-map-executable {canonical} {lexical})", profile)
            self.assertIn(f'(allow file-write* {canonical} (literal "/dev/null"))', profile)
            self.assertIn(f"(allow file-read-data (literal {json.dumps(str(node))}))", profile)
            legacy = arc.sandbox_profile(work, alias)
            self.assertNotIn(f"(deny process-exec* file-map-executable {canonical}", legacy)
            self.assertIn('(deny file-read* file-map-executable (subpath "/opt/homebrew/opt/pcre2")', legacy)

    def test_strict_boundary_includes_canonical_and_aliased_approval_denials(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as folder:
            root = Path(folder).resolve()
            approval = root / "approvals"
            approval.mkdir()
            alias = root / "alias"
            alias.symlink_to(approval, target_is_directory=True)
            runtime = str(root / "pin/node")
            profile = arc.sandbox_profile(
                root / "snapshot",
                root / "snapshot/.tmp",
                hidden=(alias,),
                runtime=runtime,
                scratch_noexec=True,
                strict=True,
            )
            self.assertIn("(deny file-read-data)(allow file-read-data ", profile)
            self.assertIn('(allow file-read-data (literal "/"))', profile)
            self.assertNotIn('(subpath "/")', profile)
            self.assertIn("(deny signal)", profile)
            self.assertIn(
                f"(deny file-read* (subpath {json.dumps(str(alias))}) (subpath {json.dumps(str(approval))}))", profile
            )
            self.assertIn(
                f"(deny file-read-data (subpath {json.dumps(str(alias))}) (subpath {json.dumps(str(approval))}))",
                profile,
            )
            self.assertIn(f"(allow file-read-data (literal {json.dumps(runtime)}))", profile)

    def test_protected_node_launch_uses_pinned_runtime_and_scrubs_loader_overrides(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder).resolve()
            scratch = work / ".tmp"
            node = work / "pin/node"
            proof = '{"id":"A","nonce":"test"}'
            args = arc.acceptance_args(work)
            poison = {
                name: str(scratch)
                for name in ("DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS")
            }
            with (
                patch.dict(os.environ, poison),
                patch.object(arc, "run_bounded", return_value=(0, "result", "")) as run,
            ):
                arc.sandboxed_node(
                    work, scratch, args, work / "output", 3, test=False, proof_input=proof, node=str(node)
                )
            argv, timeout = run.call_args.args
            self.assertEqual((argv[3], timeout), (str(node), 3))
            self.assertIn("(deny process-exec* file-map-executable ", argv[2])
            self.assertIn("--no-addons", argv)
            self.assertEqual(run.call_args.kwargs["input"], proof)
            self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin", "TMPDIR": str(scratch)})

    def test_coordinated_probe_opts_in_without_changing_legacy_probe(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            with patch.object(arc, "sandboxed_node", return_value=(1, "")) as node:
                arc.run_probe(work, work / "probe.log", "nonce", work / "evidence.json", scratch_noexec=True)
                self.assertEqual(node.call_args.kwargs, {"scratch_noexec": True})
                arc.run_probe(work, work / "probe.log", "nonce", work / "evidence.json")
                self.assertEqual(node.call_args.kwargs, {})


class CandidateLoaderEvidence(unittest.TestCase):
    def test_read_only_positive_control_and_denied_scratch_aliases(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder).resolve()
            canaries = work / ".tmp/loader-canaries"
            canaries.mkdir(parents=True)
            for name in ("exec-canary", "inject-canary.dylib", "libpcre2.dylib"):
                (canaries / name).touch()
            trusted = work / "loader-control/rg-with-pcre2"
            expected_library = trusted / "libpcre2.dylib"
            alias = work / "loader-control/scratch-link"
            alias.parent.mkdir()
            alias.symlink_to(canaries, target_is_directory=True)
            calls = []

            def invoke(command, *, env, **kwargs):
                path = Path(command[0])
                calls.append((path, env))
                if path.name == "rg":
                    self.assertEqual(path, trusted / "rg")
                    return subprocess.CompletedProcess(
                        command, 0, "alpha42\n", f"dyld[1]: <image> {expected_library}\n"
                    )
                if path.name == "rg-missing-pcre2":
                    return subprocess.CompletedProcess(command, 1, "", "@loader_path/libpcre2.dylib missing")
                if path.parent.name == "loader-control":
                    if "DYLD_INSERT_LIBRARIES" not in env:
                        return subprocess.CompletedProcess(command, 0, "", preflight.EXEC_MARKER)
                    injected = Path(env["DYLD_INSERT_LIBRARIES"]).resolve()
                    return subprocess.CompletedProcess(command, 1, "", f"file system sandbox blocked {injected}")
                raise PermissionError(1, "Operation not permitted")

            output = io.StringIO()
            with redirect_stdout(output), patch.object(preflight.subprocess, "run", side_effect=invoke):
                self.assertTrue(
                    preflight.loader_matrix(
                        Path("/private/pin/rg"), Path("/private/pin/libpcre2.dylib"), work, "candidate"
                    )
                )
            self.assertIn("PASS authorized scratch write", output.getvalue())
            self.assertIn("PASS scratch executable via symlink", output.getvalue())
            self.assertIn("PASS scratch dylib via symlink", output.getvalue())
            overrides = {"DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES"}
            self.assertTrue(all(len(overrides & env.keys()) <= 1 for _, env in calls))
            self.assertTrue(overrides <= set().union(*(env.keys() for _, env in calls)))
