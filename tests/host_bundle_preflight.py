#!/usr/bin/env python3
"""Prepare or probe disposable host fixtures. See HOST-PREFLIGHT.md before running."""

from contextlib import ExitStack
import errno
import ipaddress
import json
import os
import pwd
from pathlib import Path
import select
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[1]
DENIED = {errno.EACCES, errno.EPERM}


def load_runner(root):
    if Path.home().resolve() != root / "synthetic-home":
        raise SystemExit("HOME must point to this fixture's synthetic-home")
    os.environ["ARCTURUS_ROOT"] = str(root)
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(REPO / "runner"), str(REPO / "bin")]
    import arc

    return arc


def stage(root):
    home = root / "synthetic-home"
    if (
        home.is_symlink()
        or not home.is_dir()
        or any(home.iterdir())
        or Path.home().resolve() != home
        or set(root.iterdir()) != {home}
    ):
        raise SystemExit("stage requires a fresh fixture with an empty synthetic HOME")
    own, foreign = (root / "projects" / name for name in ("builder", "foreign"))
    (root / "runner").mkdir()
    (root / "runner/config.json").write_text(
        json.dumps(
            {
                "projects": {p.name: {"dir": str(p)} for p in (own, foreign)},
                "limits": {},
            }
        )
    )
    pin = root / "runner-state/launch-fixture"
    snapshot = root / "runner-state/candidate-fixture"
    for path in (own, foreign, pin, snapshot, home / ".ssh", home / ".codex", home / ".aws"):
        path.mkdir(parents=True, exist_ok=True)
    arc = load_runner(root)
    # Generate after setting HOME so credential paths in this fixture refer only to synthetic files.
    (root / "builder.json").write_text(json.dumps(arc.rules_for(str(own), []), indent=2))
    runtime = arc.claude_npm_identity(arc.launch_file_identity(arc.CLAUDE))
    relocation = runtime["ripgrep_pcre2"]
    bundle = pin / "package"
    for relative, identity in runtime["files"].items():
        destination = bundle / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        arc.copy_approved_file(identity["resolved"], destination, identity, executable=bool(identity["mode"] & 0o111))
    arc.pin_ripgrep_pcre2(bundle, relocation)
    for source, name in ((arc.CODEX, "codex"), (os.environ["ARCTURUS_PREFLIGHT_NODE"], "node")):
        arc.copy_approved_file(source, pin / name, arc.launch_file_identity(source), executable=True)
    exe = bundle / relocation["executable"]
    library = exe.with_name(relocation["bundle_library"])
    for path in (own / "sample", snapshot / "sample"):
        path.write_text("alpha42\n")
    for path in (foreign / "private", home / ".ssh/canary", home / ".codex/canary", home / ".aws/canary"):
        path.write_text("synthetic")
    for path in (pin, pin.parent, bundle, library.parent):
        (path / "write-canary").write_text("synthetic")
        (path / "empty-canary").mkdir()
    argv = arc.codex_argv([str(snapshot)], str(snapshot), "<unused>", telemetry=True)
    configs = [value.replace("<pin>", str(pin)) for flag, value in zip(argv, argv[1:]) if flag == "-c"]
    (root / "reviewer-config.json").write_text(json.dumps(configs, indent=2))
    for name, work in (("builder", own), ("reviewer", snapshot)):
        (work / "replacement").write_text("synthetic")
    (snapshot / ".tmp").mkdir()
    write_candidate_profile(root, arc)
    (root / "fixture.json").write_text(
        json.dumps(
            {
                "executable": str(exe),
                "library": str(library),
                "source": relocation["library"],
                "resolved_source": relocation["library_identity"]["resolved"],
                "hashes": {str(path.relative_to(pin)): arc.sha_file(path) for path in pin.rglob("*") if path.is_file()},
            },
            indent=2,
        )
    )
    home_prefix = str(Path.home().resolve())
    selectors = " ".join(
        f"(subpath {json.dumps(str(Path(path).parent))})"
        for path in (relocation["library"], relocation["library_identity"]["resolved"])
    )
    (root / "loader.sbpl").write_text(
        f"(version 1)(allow default)(deny network*)(deny file-write*)(deny file-read* {selectors})"
        f"(deny file-read* (subpath {json.dumps(home_prefix)}))"
    )
    print("Runner child environment keys:", " ".join(sorted(arc.base_env())))
    print(root)


def write_candidate_profile(root, arc):
    snapshot = root / "runner-state/candidate-fixture"
    pin = root / "runner-state/launch-fixture"
    # Render the actual account-home boundary. Probe processes still get a synthetic HOME.
    try:
        os.environ["HOME"] = pwd.getpwuid(os.getuid()).pw_dir
        profile = arc.sandbox_profile(
            str(snapshot), str(snapshot / ".tmp"), runtime=str(pin / "node"), scratch_noexec=True
        )
    finally:
        os.environ["HOME"] = str(root / "synthetic-home")
    path = root / "candidate.sbpl"
    path.write_text(profile)
    return path


def loader_probe(root):
    data = json.loads((root / "fixture.json").read_text())
    sample = root / "runner-state/candidate-fixture/sample"
    profile = root / "loader.sbpl"
    for key in ("source", "resolved_source"):
        path = Path(data[key])
        if not path.is_file():
            raise SystemExit(f"INCONCLUSIVE original canary is missing: {path}")
        command = """import errno,sys
try: open(sys.argv[1], 'rb')
except PermissionError as e: sys.exit(0 if e.errno in (errno.EACCES,errno.EPERM) else 1)
else: sys.exit(1)
"""
        subprocess.run(
            ["/usr/bin/sandbox-exec", "-f", str(profile), sys.executable, "-c", command, str(path)],
            env={"PATH": "/usr/bin:/bin"},
            check=True,
        )
    command = [
        "/usr/bin/sandbox-exec",
        "-f",
        str(profile),
        "/usr/bin/env",
        "DYLD_PRINT_LIBRARIES=1",
        data["executable"],
        "-P",
        "(?<=alpha)42",
        str(sample),
    ]
    result = subprocess.run(command, env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, check=True)
    if result.stdout != "alpha42\n" or data["library"] not in result.stderr:
        raise SystemExit("FAIL pinned ripgrep output or dyld trace")
    print("PASS Homebrew denied and PCRE2 search loads private library")
    verify(root)


def use_controller_state(arc, root):
    arc.STATE = root / "controller-state"
    arc.STATE.mkdir(exist_ok=True)
    arc.GROUPS = arc.STATE / "live-groups.json"


def cleanup_controller(root, state, ready_fd, lifetime_fd, mode, profile):
    arc = load_runner(root)
    arc.STATE, arc.GROUPS = state, state / "live-groups.json"
    prefix = ["/usr/bin/sandbox-exec", "-f", profile] if profile else []
    # The descendant waits on a supervisor-owned pipe. Even if the controller dies before
    # registration, closing the only writer releases both the child and its waiting shell.
    command = [
        *prefix,
        "/bin/sh",
        "-c",
        '/bin/cat <&"$1" >/dev/null & child=$!; printf "%s %s\\n" "$$" "$child" >&"$2"; wait "$child"',
        "cleanup-fixture",
        str(lifetime_fd),
        str(ready_fd),
    ]
    try:
        code, _, err = arc.run_bounded(
            command, 3 if mode == "timeout" else 12, env=arc.base_env(), pass_fds=(ready_fd, lifetime_fd)
        )
    except KeyboardInterrupt:
        if mode == "timeout":
            raise
        print("caught cancellation")
        return
    if mode != "timeout" or code != "timeout":
        raise SystemExit(f"FAIL or INCONCLUSIVE cleanup: {code} {err}")
    print("caught timeout")


def registered_groups(state):
    registry = state / "live-groups.json"
    try:
        return set(json.loads(registry.read_text()))
    except FileNotFoundError:
        return set()


def wait_until_gone(pid, *, group=False):
    send = os.killpg if group else os.kill
    deadline = time.monotonic() + 2
    while True:
        try:
            send(pid, 0)
        except ProcessLookupError:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def supervise_cleanup(root, profile, mode):
    """Signal a disposable runner controller and verify its worker from the parent."""
    with tempfile.TemporaryDirectory(prefix="cleanup-", dir=root) as directory, ExitStack() as stack:
        state = Path(directory)
        ready_read, ready_write = os.pipe()
        lifetime_read, lifetime_write = os.pipe()
        ready_in = stack.enter_context(os.fdopen(ready_read, "rb", buffering=0))
        ready_out = stack.enter_context(os.fdopen(ready_write, "wb"))
        lifetime_in = stack.enter_context(os.fdopen(lifetime_read, "rb"))
        lifetime_out = stack.enter_context(os.fdopen(lifetime_write, "wb"))
        argv = [
            sys.executable,
            str(Path(__file__).resolve()),
            "cleanup-controller",
            str(root),
            str(state),
            str(ready_write),
            str(lifetime_read),
            mode,
            str(profile) if profile else "",
        ]
        env = {"HOME": str(root / "synthetic-home"), "PATH": os.environ["PATH"]}
        controller = subprocess.Popen(
            argv,
            env=env,
            start_new_session=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            pass_fds=(ready_write, lifetime_read),
        )
        group = None
        try:
            ready_out.close()
            lifetime_in.close()
            if not select.select([ready_in], [], [], 5)[0]:
                raise SystemExit("INCONCLUSIVE cleanup worker did not announce readiness")
            announcement = ready_in.read(128)
            if not announcement:
                _, err = controller.communicate(timeout=5)
                raise SystemExit(f"INCONCLUSIVE cleanup worker exited before readiness: {err.strip()}")
            reported_group, child = map(int, announcement.split())
            if (
                min(reported_group, child) <= 1
                or reported_group in {os.getpgrp(), controller.pid}
                or os.getpgid(child) != reported_group
                or os.getpgid(reported_group) != reported_group
            ):
                raise SystemExit("INCONCLUSIVE cleanup worker is outside its expected process group")
            group = reported_group
            deadline = time.monotonic() + 2
            while group not in registered_groups(state):
                if controller.poll() is not None or time.monotonic() >= deadline:
                    raise SystemExit("INCONCLUSIVE cleanup worker group was not registered")
                time.sleep(0.01)
            if mode != "timeout":
                controller.send_signal(signal.Signals[mode])
            out, err = controller.communicate(timeout=15)
            expected = "caught timeout" if mode == "timeout" else "caught cancellation"
            if controller.returncode or out.strip() != expected:
                raise SystemExit(f"FAIL cleanup controller {mode}: {controller.returncode} {err.strip()}")
            if registered_groups(state) or not wait_until_gone(group, group=True) or not wait_until_gone(child):
                raise SystemExit(f"FAIL cleanup {mode}: worker or registration survived")
            print(f"PASS cleanup {mode}")
        finally:
            # Preserve the failure result, then release the sentinel even if its PID was never reported.
            lifetime_out.close()
            if controller.poll() is None:
                controller.kill()
            controller.communicate(timeout=5)
            groups = {group} if group is not None else registered_groups(state)
            for worker_group in groups:
                if not wait_until_gone(worker_group, group=True):
                    try:
                        os.killpg(worker_group, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    if not wait_until_gone(worker_group, group=True):
                        raise SystemExit(f"FAIL fallback cleanup: group {worker_group} survived SIGKILL")


def cleanup_probe(root, profile):
    for mode in ("timeout", "SIGINT", "SIGTERM"):
        supervise_cleanup(root, profile, mode)


def probe(root, role, port):
    # The controller passes paths in argv so denied reads of fixture metadata cannot invalidate the probe.
    exe, library, source, resolved = map(Path, sys.argv[5:9])
    pin = root / "runner-state/launch-fixture"
    own = root / "projects/builder"
    snapshot = root / "runner-state/candidate-fixture"
    work = own if role == "builder" else snapshot
    if (
        not root.name.startswith(".host-preflight.")
        or Path(__file__).resolve().parent != work
        or not exe.is_relative_to(pin / "package")
        or library.parent != exe.parent
        or not all(path.is_relative_to("/opt/homebrew") for path in (source, resolved))
    ):
        raise SystemExit("refusing targets outside the synthetic fixture")

    def allowed(label, action):
        action()
        print(f"PASS {label}", flush=True)

    def denied(label, action):
        try:
            action()
        except OSError as exc:
            if exc.errno in DENIED:
                print(f"PASS {label} errno={exc.errno}", flush=True)
                return
            raise RuntimeError(f"INCONCLUSIVE {label}: errno={exc.errno}") from exc
        raise RuntimeError(f"FAIL {label}: unexpectedly succeeded")

    allowed("read own fixture", (work / "sample").read_bytes)
    if role in ("builder", "candidate"):
        scratch = own if role == "builder" else snapshot / ".tmp"
        allowed("write authorized scratch", lambda: (scratch / "write-positive").write_text("ok"))
    else:
        denied("write reviewer workspace", lambda: (work / "write-positive").touch())
    for path in (
        root / "projects/foreign/private",
        *(root / "synthetic-home" / d / "canary" for d in (".ssh", ".codex", ".aws")),
    ):
        denied(f"read {path.relative_to(root)}", path.read_bytes)
    for path in (library, exe):
        denied(f"open for write {path.name}", lambda p=path: os.close(os.open(p, os.O_WRONLY)))
        denied(f"replace {path.name}", lambda p=path: os.replace(work / "replacement", p))
        denied(f"rename {path.name}", lambda p=path: p.rename(p.with_suffix(".moved")))
        denied(f"unlink {path.name}", path.unlink)
    for directory in (library.parent, pin / "package", pin, pin.parent):
        denied(f"create under {directory}", lambda d=directory: (d / "created").mkdir())
        denied(f"write canary under {directory}", lambda d=directory: (d / "write-canary").write_text("changed"))
        denied(f"remove directory under {directory}", lambda d=directory: (d / "empty-canary").rmdir())
        denied(f"rename directory {directory}", lambda d=directory: d.rename(d.with_name(d.name + "-moved")))
    denied("subprocess open for write", lambda: child_denial(library))
    loader_ok = loader_matrix(exe, library, work, role)
    denied(
        "connect to live loopback listener", lambda: socket.create_connection(("127.0.0.1", port), timeout=2).close()
    )
    if len(sys.argv) > 9:
        address, lan_port = sys.argv[9:11]
        denied(
            "connect to live non-loopback listener",
            lambda: socket.create_connection((address, int(lan_port)), timeout=2).close(),
        )
    else:
        print("INCONCLUSIVE non-loopback listener not configured", flush=True)
    for path in (source, resolved):
        denied(f"read original PCRE2 {path}", path.read_bytes)
    if not loader_ok:
        raise SystemExit("loader matrix contains FAIL or INCONCLUSIVE results")


EXEC_MARKER = "ARCTURUS_EXEC_CANARY"
DYLIB_MARKER = "ARCTURUS_DYLIB_CANARY"


def loader_canaries(work, role):
    return (work / ".tmp" if role == "candidate" else work) / "loader-canaries"


def prepare_loader_canaries(root):
    arc = load_runner(root)
    verify(root)
    fixture = json.loads((root / "fixture.json").read_text())
    library = Path(fixture["library"])
    builder = root / "projects/builder"
    snapshot = root / "runner-state/candidate-fixture"
    destinations = {
        loader_canaries(builder, "builder"),
        loader_canaries(snapshot, "reviewer"),
        loader_canaries(snapshot, "candidate"),
        snapshot / "loader-control",
    }
    if any(path.exists() or path.is_symlink() for path in destinations):
        raise SystemExit("loader canaries already exist; use the existing canaries or stage a fresh fixture")
    with tempfile.TemporaryDirectory(prefix="loader-build-", dir=root) as temporary:
        build = Path(temporary)
        build_env = arc.base_env({"TMPDIR": str(build)})
        compiler = subprocess.check_output(["/usr/bin/xcrun", "--find", "clang"], text=True, env=build_env).strip()
        sdk = subprocess.check_output(
            ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True, env=build_env
        ).strip()
        source = build / "probe.c"
        for name, marker, declaration, options in (
            ("exec-canary", EXEC_MARKER, "int main(void)", []),
            (
                "inject-canary.dylib",
                DYLIB_MARKER,
                "__attribute__((constructor)) static void loaded(void)",
                ["-dynamiclib"],
            ),
        ):
            source.write_text(
                f'#include <unistd.h>\n{declaration} {{ const char s[] = "{marker}\\n"; '
                f'write(2, s, sizeof(s)-1); {"return 0;" if not options else ""} }}\n'
            )
            output = build / name
            subprocess.run(
                [compiler, "-isysroot", sdk, *options, str(source), "-o", str(output)], env=build_env, check=True
            )
            subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(output)], check=True)
        control = subprocess.run(
            [build / "exec-canary"],
            env={"PATH": "/usr/bin:/bin", "DYLD_INSERT_LIBRARIES": str(build / "inject-canary.dylib")},
            capture_output=True,
            text=True,
            check=True,
        )
        if EXEC_MARKER not in control.stderr or DYLIB_MARKER not in control.stderr:
            raise SystemExit("INCONCLUSIVE synthetic executable or dylib failed its positive control")
        for destination in destinations:
            destination.mkdir()
            for name in ("exec-canary", "inject-canary.dylib"):
                shutil.copy2(build / name, destination / name)
            if destination != snapshot / "loader-control":
                shutil.copy2(library, destination / library.name)
        # Only this disposable control lacks its adjacent PCRE2. The actual pin remains intact.
        shutil.copy2(Path(fixture["executable"]), snapshot / "loader-control/rg-missing-pcre2")
    print("PASS valid synthetic executable and dylib controls prepared")


def candidate_loader_control(root, fixture, arc, *, create=False):
    pin = root / "runner-state/launch-fixture"
    work = root / "runner-state/candidate-fixture"
    control = work / "loader-control"
    trusted = control / "rg-with-pcre2"
    alias = control / "scratch-link"
    scratch = loader_canaries(work, "candidate")
    if control.resolve() != control or trusted.resolve() != trusted:
        raise SystemExit("unsafe loader control directory")
    if create:
        if not all((scratch / name).is_file() for name in ("exec-canary", "inject-canary.dylib")):
            raise SystemExit("INCONCLUSIVE loader canaries missing; run prepare-loader-canaries")
        trusted.mkdir(exist_ok=True)
        if not alias.is_symlink() and not alias.exists():
            alias.symlink_to(scratch, target_is_directory=True)
    if not alias.is_symlink() or alias.resolve() != scratch:
        raise SystemExit("loader control scratch alias changed")
    # The real private directory stays outside candidate read scope. Exercise identical bytes
    # from the read-only snapshot and check against the private fixture's recorded hashes.
    for key in ("executable", "library"):
        source = Path(fixture[key])
        expected = fixture["hashes"][str(source.relative_to(pin))]
        target = trusted / source.name
        if create and not target.is_symlink() and not target.exists():
            shutil.copy2(source, target)
        if target.is_symlink() or not target.is_file() or arc.sha_file(target) != expected:
            raise SystemExit(f"FAIL read-only loader control {key} differs from the private pin")


def loader_matrix(exe, library, work, role):
    canaries = loader_canaries(work, role)
    if role == "candidate":
        trusted = work / "loader-control/rg-with-pcre2"
        exe, library = trusted / exe.name, trusted / library.name
        with tempfile.TemporaryDirectory(prefix="scratch-write-", dir=canaries.parent) as directory:
            (Path(directory) / "positive").write_text("ok")
        print("PASS authorized scratch write", flush=True)
    injected = canaries / "inject-canary.dylib"
    scratch_exe = canaries / "exec-canary"
    shadow = canaries / library.name
    if not all(path.is_file() for path in (injected, scratch_exe, shadow)):
        print("INCONCLUSIVE loader canaries missing; run prepare-loader-canaries", flush=True)
        return False

    def invoke(command, override=None):
        env = {"PATH": "/usr/bin:/bin", "DYLD_PRINT_LIBRARIES": "1"}
        if override:
            key, value = override
            env[key] = str(value)
        try:
            return subprocess.run(command, env=env, capture_output=True, text=True, timeout=5)
        except PermissionError as exc:
            if exc.errno not in DENIED:
                raise
            return None

    def mapped(result, path):
        spellings = {str(path), os.path.realpath(path)}
        return any(
            line.startswith("dyld[") and line.partition("> ")[2] in spellings for line in result.stderr.splitlines()
        )

    def mapping_denied(result, path):
        return any(spelling in result.stderr for spelling in {str(path), os.path.realpath(path)}) and any(
            message in result.stderr.lower()
            for message in ("operation not permitted", "permission denied", "file system sandbox blocked")
        )

    def report(label, status, detail):
        print(f"{status} {label}: {detail}", flush=True)
        return status == "PASS"

    clean = [exe, "-P", "(?<=alpha)42", work / "sample"]
    baseline = invoke(clean)
    ok = True
    if baseline is None:
        status = "INCONCLUSIVE" if role == "candidate" else "PASS"
        ok = report("pinned ripgrep", status, "direct execution denied")
    elif baseline.returncode or baseline.stdout != "alpha42\n" or not mapped(baseline, library):
        diagnostics = baseline.stderr.strip().splitlines()
        detail = diagnostics[-1] if diagnostics else "no dyld trace"
        ok = report("pinned ripgrep", "INCONCLUSIVE", f"clean launch did not prove the pinned mapping ({detail})")
    else:
        report("pinned ripgrep", "PASS", "clean launch mapped the private PCRE2")
        for key, value, target in (
            ("DYLD_LIBRARY_PATH", canaries, shadow),
            ("DYLD_FALLBACK_LIBRARY_PATH", canaries, shadow),
            ("DYLD_INSERT_LIBRARIES", injected, injected),
        ):
            result = invoke(clean, (key, value))
            if result is not None and (DYLIB_MARKER in result.stderr or mapped(result, target)):
                verdict = report(key, "FAIL", "alternate library loaded in the child")
            elif result is None or mapping_denied(result, target):
                verdict = report(key, "PASS", "launch or alternate mapping denied")
            elif result.returncode == 0 and result.stdout == "alpha42\n" and mapped(result, library):
                verdict = report(key, "PASS", "search used the private library")
            else:
                verdict = report(key, "INCONCLUSIVE", f"unexpected loader result ({result.returncode})")
            ok = verdict and ok

    executables = [("scratch executable", scratch_exe)]
    if role == "candidate":
        alias = work / "loader-control/scratch-link"
        executables.append(("scratch executable via symlink", alias / scratch_exe.name))
    for label, path in executables:
        result = invoke([path])
        if result is not None and EXEC_MARKER in result.stderr:
            verdict = report(label, "FAIL", "native scratch executable ran")
        elif result is None or mapping_denied(result, path):
            verdict = report(label, "PASS", "execution denied")
        else:
            verdict = report(label, "INCONCLUSIVE", "expected denial or marker missing")
        ok = verdict and ok

    if role == "candidate":
        missing = [work / "loader-control/rg-missing-pcre2", *clean[1:]]
        missing_result = invoke(missing)
        if missing_result is None:
            verdict = report("fallback with absent target", "PASS", "control execution denied")
        elif missing_result.returncode == 0 or library.name not in missing_result.stderr:
            verdict = report(
                "fallback with absent target", "INCONCLUSIVE", "missing-library control did not fail as expected"
            )
        else:
            result = invoke(missing, ("DYLD_FALLBACK_LIBRARY_PATH", canaries))
            if result is not None and mapped(result, shadow):
                verdict = report("fallback with absent target", "FAIL", "scratch PCRE2 mapped")
            elif result is None or mapping_denied(result, shadow):
                verdict = report("fallback with absent target", "PASS", "launch or scratch mapping denied")
            elif result.returncode != 0 and library.name in result.stderr:
                verdict = report(
                    "fallback with absent target", "PASS", "control still fails without its approved dependency"
                )
            else:
                verdict = report("fallback with absent target", "INCONCLUSIVE", "unexpected fallback result")
        ok = verdict and ok

        # This executable is outside writable scratch and proves mapping even if ripgrep itself is unreadable.
        control = work / "loader-control/exec-canary"
        control_result = invoke([control])
        if control_result is None or control_result.returncode or EXEC_MARKER not in control_result.stderr:
            return report("scratch dylib", "INCONCLUSIVE", "read-only control executable did not run")
        for label, path in (("scratch dylib", injected), ("scratch dylib via symlink", alias / injected.name)):
            result = invoke([control], ("DYLD_INSERT_LIBRARIES", path))
            if result is not None and (DYLIB_MARKER in result.stderr or mapped(result, path)):
                verdict = report(label, "FAIL", "valid dylib from writable scratch loaded")
            elif result is None or mapping_denied(result, path):
                verdict = report(label, "PASS", "injection denied")
            elif result.returncode == 0 and EXEC_MARKER in result.stderr:
                verdict = report(label, "PASS", "control ran without the injected marker")
            else:
                verdict = report(label, "INCONCLUSIVE", "expected denial or marker missing")
            ok = verdict and ok
    return ok


def run_candidate_loader_matrix(root):
    arc = load_runner(root)
    use_controller_state(arc, root)
    fixture = json.loads((root / "fixture.json").read_text())
    verify(root)
    candidate_loader_control(root, fixture, arc, create=True)
    profile = write_candidate_profile(root, arc)
    work = root / "runner-state/candidate-fixture"
    probe_file = work / "host-probe.py"
    probe_file.write_bytes(Path(__file__).read_bytes())
    command = [
        "/usr/bin/sandbox-exec",
        "-f",
        str(profile),
        sys.executable,
        str(probe_file),
        "probe-loader",
        str(root),
        fixture["executable"],
        fixture["library"],
    ]
    code, out, err = arc.run_bounded(command, 30, cwd=work, env=arc.base_env())
    print(out, end="")
    print(err, end="", file=sys.stderr)
    verify(root)
    candidate_loader_control(root, fixture, arc)
    if code != 0:
        if not out and "sandbox_apply:" in err:
            raise SystemExit("INCONCLUSIVE: Seatbelt did not start")
        raise SystemExit(f"candidate loader matrix contains FAIL or INCONCLUSIVE results ({code})")


def child_denial(path):
    command = "import os,sys; os.close(os.open(sys.argv[1], os.O_WRONLY))"
    try:
        subprocess.run([sys.executable, "-c", command, str(path)], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        if "PermissionError" in exc.stderr and any(f"[Errno {code}]" in exc.stderr for code in DENIED):
            raise PermissionError(errno.EPERM, "child denied") from exc
        raise


def run(root, role, profile):
    arc = load_runner(root)
    use_controller_state(arc, root)
    fixture = json.loads((root / "fixture.json").read_text())
    if role == "candidate":
        verify(root)
        candidate_loader_control(root, fixture, arc, create=True)
        if profile == root / "candidate.sbpl":
            profile = write_candidate_profile(root, arc)
    work = root / ("projects/builder" if role == "builder" else "runner-state/candidate-fixture")
    # The probe source must be readable by the sandbox. Keep the copy in the role's readable workspace.
    probe_file = work / "host-probe.py"
    probe_file.write_bytes(Path(__file__).read_bytes())
    with ExitStack() as sockets:

        def live_listener(address):
            listener = sockets.enter_context(socket.socket())
            listener.bind((address, 0))
            listener.listen()
            port = listener.getsockname()[1]
            with socket.create_connection((address, port), timeout=2), listener.accept()[0]:
                pass
            return str(port)

        port = live_listener("127.0.0.1")
        lan = os.environ.get("ARCTURUS_PREFLIGHT_LAN_IP")
        endpoints = []
        if lan:
            ip = ipaddress.IPv4Address(lan)
            if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
                raise SystemExit("LAN canary requires an assigned non-loopback IPv4 address")
            endpoints = [lan, live_listener(lan)]
        argv = [
            "/usr/bin/sandbox-exec",
            "-f",
            str(profile),
            sys.executable,
            str(probe_file),
            "probe",
            str(root),
            role,
            port,
            *(fixture[key] for key in ("executable", "library", "source", "resolved_source")),
            *endpoints,
        ]
        code, out, err = arc.run_bounded(argv, 30, cwd=work, env=arc.base_env())
    print(out, end="")
    print(err, end="", file=sys.stderr)
    if code != 0:
        raise SystemExit(f"{role}: FAIL or INCONCLUSIVE ({code})")
    verify(root)
    if role == "candidate":
        candidate_loader_control(root, fixture, arc)


def verify(root):
    import hashlib

    data = json.loads((root / "fixture.json").read_text())
    pin = root / "runner-state/launch-fixture"
    paths = list(pin.rglob("*"))
    if pin.is_symlink() or any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in paths):
        raise SystemExit("FAIL: unexpected private runtime entry")
    actual = {str(p.relative_to(pin)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
    if actual != data["hashes"]:
        raise SystemExit("FAIL: pinned file inventory or hashes changed")
    for key in ("executable", "library"):
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", data[key]], check=True)
        subprocess.run(["/usr/bin/otool", "-L", data[key]], check=True)
    print("PASS private hashes and signatures")


if __name__ == "__main__":
    action, raw_root = sys.argv[1:3]
    root = Path(raw_root).resolve(strict=True)
    if action not in {"probe", "probe-loader"} and (
        root.parent != REPO or not root.name.startswith(".host-preflight.")
    ):
        raise SystemExit("use a disposable .host-preflight.* directory directly under the isolated checkout")
    if action == "stage":
        if any(p.name != "synthetic-home" for p in root.iterdir()):
            raise SystemExit("stage requires a fresh fixture")
        stage(root)
    elif action == "run" and sys.argv[3] in {"builder", "reviewer", "candidate"}:
        run(root, sys.argv[3], Path(sys.argv[4]).resolve(strict=True))
    elif action == "probe":
        probe(root, sys.argv[3], int(sys.argv[4]))
    elif action == "probe-loader":
        work = root / "runner-state/candidate-fixture"
        exe, library = map(Path, sys.argv[3:5])
        if (
            not root.name.startswith(".host-preflight.")
            or Path(__file__).resolve().parent != work
            or not exe.is_relative_to(root / "runner-state/launch-fixture/package")
            or library.parent != exe.parent
        ):
            raise SystemExit("refusing targets outside the synthetic fixture")
        raise SystemExit(not loader_matrix(exe, library, work, "candidate"))
    elif action == "prepare-loader-canaries":
        prepare_loader_canaries(root)
    elif action == "loader-matrix":
        run_candidate_loader_matrix(root)
    elif action == "verify":
        verify(root)
    elif action == "loader":
        loader_probe(root)
    elif action == "cleanup":
        cleanup_probe(root, Path(sys.argv[3]).resolve(strict=True))
    elif action == "cleanup-controller":
        state, ready_fd, lifetime_fd, mode, profile = sys.argv[3:]
        state = Path(state).resolve(strict=True)
        if state.parent != root or not state.name.startswith("cleanup-"):
            raise SystemExit("invalid disposable cleanup state")
        cleanup_controller(root, state, int(ready_fd), int(lifetime_fd), mode, profile)
    else:
        raise SystemExit("invalid preflight action")
