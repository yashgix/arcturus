"""Builder agents and test runs execute as the separate _arcexec account (exec-user/), in its own launchd session,
under macOS Seatbelt: no network beyond one loopback port, no reads of the home folder or temp areas except the named
paths, writes only to the named paths, signals only to its own processes, and the known ways out of the sandbox
(Launch Services, Apple Events, keychain, sudo) refused. Job paths must live in the execution area. One job at a time,
under a lock: stopping a job stops every _arcexec process."""

import fcntl
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import time

PRIVATE = (
    "/Users",
    "/Volumes",
    "/private/tmp",
    "/private/var/tmp",
    "/private/var/folders",
    "/private/var/root",
    "/private/etc/arcturus-operator-private",
)
# Each of these can run code outside the sandbox or read credentials (Launch Services, Apple Events, keychain).
EXEC_DENIED = (
    "/usr/bin/open",
    "/usr/bin/osascript",
    "/usr/bin/security",
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/ssh",
    "/usr/bin/login",
    "/bin/launchctl",
    "/usr/bin/pbcopy",
    "/usr/bin/pbpaste",
)
SERVICES_DENIED = (
    "com.apple.coreservices.launchservicesd",
    "com.apple.lsd.mapdb",
    "com.apple.lsd.modifydb",
    "com.apple.coreservices.appleevents",
    "com.apple.SecurityServer",
    "com.apple.securityd.xpc",
    "com.apple.pasteboard.1",
)
AREA = Path("/Users/Shared/arcturus-exec")
MAX_JOB_FILE = 64 * 1024 * 1024
STOP_POLLS = 50
LAUNCHER = "/usr/local/libexec/arcturus-exec/run-as-exec"
START = ("/usr/bin/sudo", "-n", "/bin/launchctl", "asuser", "490", "/usr/bin/sudo", "-u", "_arcexec", LAUNCHER, "run")
STOP = ("/usr/bin/sudo", "-n", "-u", "_arcexec", LAUNCHER, "stop")
RIGHTS = (
    "list,add_file,search,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr,"
    "file_inherit,directory_inherit"
)
# Helpers launchd starts for every account that runs programs; not part of any job.
SYSTEM_AGENTS = {"/usr/sbin/distnoted agent", "/usr/sbin/cfprefsd agent"}
# Isolated mode, and the workspace goes last on sys.path after the runner's own imports, so code under test cannot
# replace json or unittest. It still shares the process and can forge outcomes and messages: callers keep only
# the kinds of ids they know, and messages stay local evidence.
RUNNER = r"""
import json, sys, unittest
start, pattern, out, workspace = sys.argv[1:5]
sys.path.append(workspace)
outcome = {}
def message(err, test):
    return unittest.TestResult._exc_info_to_string(Result(), err, test)[-1200:]
class Result(unittest.TestResult):
    def startTest(self, test):
        super().startTest(test)
        outcome.setdefault(test.id(), ["ok", ""])
    def failed(self, test, err):
        kind = "fail" if issubclass(err[0], AssertionError) else "error"
        outcome[test.id()] = [kind, message(err, test)]
    def addFailure(self, test, err):
        super().addFailure(test, err); self.failed(test, err)
    def addError(self, test, err):
        super().addError(test, err); self.failed(test, err)
    def addSubTest(self, test, sub, err):
        super().addSubTest(test, sub, err)
        if err is not None:
            self.failed(test, err)
try:
    suite = unittest.TestLoader().discover(start, pattern=pattern, top_level_dir=start)
    suite.run(Result())
except Exception as exc:
    outcome["<discovery>"] = ["error", f"{type(exc).__name__}: {exc}"[:1200]]
with open(out, "w") as file:
    json.dump(outcome, file)
"""


def selectors(paths):
    unique = dict.fromkeys(alias for p in paths for alias in (os.path.abspath(p), os.path.realpath(p)))
    return " ".join(f"(subpath {json.dumps(p)})" for p in unique)


def ancestors(paths):
    """The folders above each path, for metadata only: a venv's Python resolves its own path at start, and Node
    checks its output files."""
    folders = {str(f) for p in paths for q in (Path(p).absolute(), Path(p).resolve()) for f in q.parents}
    return " ".join(f"(literal {json.dumps(f)})" for f in sorted(folders))


def profile(read, write, port=None, deny_read=(), deny_write=(), outputs=()):
    network = f'(allow network-outbound (remote ip "localhost:{int(port)}"))' if port else ""
    literals = " ".join(f"(literal {json.dumps(p)})" for p in EXEC_DENIED)
    services = " ".join(f'(global-name "{s}")' for s in SERVICES_DENIED)
    hidden = f"(deny file-read* {selectors(deny_read)})" if deny_read else ""
    fixed = f"(deny file-write* {selectors(deny_write)})" if deny_write else ""
    return (
        f"(version 1)(allow default)(deny network*){network}"
        f'(deny file-write*)(allow file-write* {selectors(write)} (literal "/dev/null") (literal "/dev/tty")){fixed}'
        f"(deny file-read* {selectors(PRIVATE)})(allow file-read* {selectors([*read, *write])})"
        f"(allow file-read-metadata {ancestors([*read, *write])}"
        f"{''.join(f' (literal {json.dumps(str(Path(o).absolute()))})' for o in outputs)}){hidden}"
        f"(deny process-exec {literals})(deny mach-lookup {services})"
        "(deny signal)(allow signal (target pgrp))(allow signal (target children))"
    )


def share(read, write, cwd):
    """Let _arcexec pass through to every job path and write to the write paths; the runner keeps the right to
    delete what the job creates. Refuses any path outside the execution area."""
    paths = [Path(p).resolve() for p in (*read, *write, cwd)]
    outside = [str(p) for p in paths if not p.is_relative_to(AREA)]
    if outside:
        raise ValueError(f"job paths must be inside {AREA}: {outside}")
    for path in paths:
        for folder in (path, *path.parents):
            if folder == AREA or not folder.is_relative_to(AREA):
                break
            if folder.is_dir() and folder.stat().st_uid == os.getuid():
                subprocess.run(["/bin/chmod", "+a", "user:_arcexec allow search", str(folder)], check=True)
    owner = pwd.getpwuid(os.getuid()).pw_name
    for path in (Path(p).resolve() for p in write):
        for entry in (f"user:_arcexec allow {RIGHTS}", f"user:{owner} allow {RIGHTS},delete"):
            # Only the runner's own folders and single-link files: a planted symlink or hardlink must not pass
            # rights to its target. What the job creates inherits these entries.
            subprocess.run(
                [
                    "/usr/bin/find",
                    str(path),
                    "-user",
                    str(os.getuid()),
                    "(",
                    "-type",
                    "d",
                    "-o",
                    "(",
                    "-type",
                    "f",
                    "-links",
                    "1",
                    ")",
                    ")",
                    "-exec",
                    "/bin/chmod",
                    "+a",
                    entry,
                    "{}",
                    "+",
                ],
                check=True,
            )


def job_processes():
    rows = subprocess.run(["/bin/ps", "-U", "_arcexec", "-o", "pid=,command="], capture_output=True, text=True)
    return sorted(int(r.split()[0]) for r in rows.stdout.splitlines() if r.split(None, 1)[1] not in SYSTEM_AGENTS)


def stop():
    """Kill every _arcexec process; fail if any survives, so nothing of the job runs while rights are handed out."""
    subprocess.run(STOP, capture_output=True)
    for _ in range(STOP_POLLS):  # killed processes can take a moment to exit
        if not job_processes():
            return
        time.sleep(0.1)
    raise RuntimeError("could not stop the execution account's processes")


def create(path):
    """Open an output file for writing without following a link planted in its place."""
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644), "wb")


def run(argv, read, write, env, cwd, timeout, stdout, stderr, port=None, deny_read=(), deny_write=()):
    """Run argv as _arcexec in the sandbox with output to files outside the write paths; on timeout, stop it. Any job
    process still alive afterwards (e.g. a detached child) is killed. Returns (exit code, timed out, stray pids)."""
    if any(Path(f).resolve().is_relative_to(Path(w).resolve()) for f in (stdout, stderr) for w in write):
        raise ValueError("output files must be outside the job's write paths")
    with open(AREA / ".lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        stop()
        share(read, write, cwd)
        command = [
            *START,
            str(cwd),
            *(f"{k}={v}" for k, v in env.items()),
            "/usr/bin/sandbox-exec",
            "-p",
            profile(read, write, port, deny_read, deny_write, (stdout, stderr)),
            *argv,
        ]
        try:
            with create(stdout) as out, create(stderr) as err:
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True
                )
                timed_out = wait(process, timeout)
            leftovers = job_processes()
        finally:
            stop()
        process.wait(timeout=30)
    return process.returncode, timed_out, leftovers


def wait(process, timeout):
    """True if the job ran past its timeout and was terminated."""
    try:
        process.wait(timeout=timeout)
        return False
    except subprocess.TimeoutExpired:
        process.terminate()  # sudo passes SIGTERM on to the job
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        return True


def read_job_file(path, limit=MAX_JOB_FILE):
    """A file the job wrote, read without following links or blocking; None if it is missing, a link, not a regular
    file, not the job's own, or larger than limit bytes."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid == os.getuid() or info.st_nlink != 1:
            return None
        data = file.read(limit + 1)
    return None if len(data) > limit else data.decode("utf-8", "replace")


def run_tests(python, workspace, start, pattern, scratch, deny_read=(), timeout=300, read=(), extra_env=None):
    """Each test's outcome ("ok", "fail" or "error") with a short message, run with no network and no writes outside
    the scratch folder. read and extra_env: the project environment's read-only paths and variables."""
    scratch = Path(scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    out, errors = scratch / "outcome.json", scratch.with_name(f"{scratch.name}.stderr.txt")
    out.unlink(missing_ok=True)
    env = {
        **(extra_env or {}),
        "PATH": "/usr/bin:/bin",
        "HOME": str(scratch),
        "TMPDIR": str(scratch),
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "en_US.UTF-8",
        "MPLBACKEND": "Agg",
    }
    code, timed_out, _ = run(
        [python, "-I", "-B", "-c", RUNNER, str(start), pattern, str(out), str(workspace)],
        [workspace, start, *read],
        [scratch],
        env,
        workspace,
        timeout,
        scratch.with_name(f"{scratch.name}.stdout.txt"),
        errors,
        deny_read=deny_read,
    )
    outcome = read_job_file(out)
    if timed_out or outcome is None:
        reason = "timed out" if timed_out else f"exit {code}: {errors.read_text()[-800:]}"
        return {"<runner>": ["error", reason]}
    return json.loads(outcome)
