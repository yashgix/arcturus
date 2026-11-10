"""Isolation check for the _arcexec account, run as yashgx after setup.sh: python3 exec-user/isolation_check.py
Each probe runs as _arcexec, once with an allow-all profile (the account boundary alone) and, where it matters, with
the runner's real Seatbelt profile. Controls run the same probe as yashgx. Exit 1 if any check fails."""

import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "runner"))
import sandbox  # noqa: E402

LAUNCHER = "/usr/local/libexec/arcturus-exec/run-as-exec"
START = ["/usr/bin/sudo", "-n", "/bin/launchctl", "asuser", "490", "/usr/bin/sudo", "-u", "_arcexec", LAUNCHER]
AREA = Path("/Users/Shared/arcturus-exec")
PYTHON = "/opt/homebrew/bin/python3"
OPEN = "(version 1)(allow default)"
REFUSED = {"EPERM", "EACCES", "EINVAL", "ESRCH"}
EVIDENCE = Path.home() / "arcturus-runs" / "exec-isolation"
EXEC_RIGHTS = "list,add_file,search,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr"
OWNER_RIGHTS = EXEC_RIGHTS + ",delete,readsecurity"
INHERIT = "file_inherit,directory_inherit"
SYSTEM_AGENTS = {"/usr/sbin/distnoted agent", "/usr/sbin/cfprefsd agent"}

PROBE = r'''
import ctypes, errno, json, os, socket, subprocess, sys
def err(e): return errno.errorcode.get(e.errno, str(e.errno)) if isinstance(e, OSError) else type(e).__name__
def run(*argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        return p.returncode, p.stdout
    except OSError as e:
        return err(e), ""
cmd, args = sys.argv[1], sys.argv[2:]
try:
    if cmd == "read": open(args[0]).read(); print("ok")
    elif cmd == "list": os.listdir(args[0]); print("ok")
    elif cmd == "write": open(args[0], "w").write("x"); print("ok")
    elif cmd == "signal": os.kill(int(args[0]), 0); print("ok")
    elif cmd == "connect": socket.create_connection((args[0], int(args[1])), timeout=3).close(); print("ok")
    elif cmd == "groups": print(json.dumps(sorted(os.getgroups())))
    elif cmd == "env": print(json.dumps(sorted(os.environ)))
    elif cmd == "procargs":
        libc = ctypes.CDLL(None, use_errno=True)
        mib = (ctypes.c_int * 3)(1, 49, int(args[0]))  # CTL_KERN, KERN_PROCARGS2
        size = ctypes.c_size_t(1 << 20); buf = ctypes.create_string_buffer(size.value)
        if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0):
            print(errno.errorcode.get(ctypes.get_errno(), "error"))
        else:
            print("found" if args[1].encode() in buf.raw[:size.value] else "absent")
    elif cmd == "ps":
        code, out = run("/bin/ps", "-E", "-ww", "-o", "command=", "-p", args[0])
        print("found" if args[1] in out else f"absent rc={code}")
    elif cmd == "exec":
        code, out = run(*args); print(f"rc={code} bytes={len(out)}")
    elif cmd == "keychains":
        code, out = run("/usr/bin/security", "list-keychains"); print("home" if args[0] in out else f"none rc={code}")
    elif cmd == "linger":
        if os.fork() == 0:
            null = os.open(os.devnull, os.O_RDWR)
            for fd in (0, 1, 2): os.dup2(null, fd)
            os.setsid(); os.execv("/bin/sleep", ["sleep", "60"])
        print("ok")
except Exception as e:
    print(err(e))
'''


def sh(*argv, check=True):
    return subprocess.run(argv, capture_output=True, text=True, check=check)


class Job:
    def __init__(self):
        self.root = AREA / f"iso-{int(time.time())}"
        self.ws, self.scratch, self.other = self.root / "ws", self.root / "scratch", AREA / f"{self.root.name}-other"
        if not AREA.exists():
            AREA.mkdir(mode=0o700)
            sh("/bin/chmod", "+a", "user:_arcexec allow search", str(AREA))
        for path in (self.ws, self.scratch, self.other):
            path.mkdir(parents=True)
        sh("/bin/chmod", "+a", f"user:_arcexec allow {EXEC_RIGHTS},{INHERIT}", str(self.scratch))
        sh("/bin/chmod", "+a", f"user:{os.environ['USER']} allow {OWNER_RIGHTS},{INHERIT}", str(self.scratch))
        (self.ws / "probe.py").write_text(PROBE)
        (self.other / "secret.txt").write_text("other job")

    def as_exec(self, profile, *args):
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.scratch), "TMPDIR": str(self.scratch), "LANG": "en_US.UTF-8"}
        argv = [
            *START,
            "run",
            str(self.scratch),
            *[f"{k}={v}" for k, v in env.items()],
            "/usr/bin/sandbox-exec",
            "-p",
            profile,
            PYTHON,
            "-I",
            "-B",
            str(self.ws / "probe.py"),
            *args,
        ]
        return sh(*argv, check=False).stdout.strip() or "no output"

    def as_me(self, *args):
        return sh(PYTHON, "-I", "-B", str(self.ws / "probe.py"), *args, check=False).stdout.strip()

    def real_profile(self, port):
        return sandbox.profile([self.ws], [self.scratch], port)


def listener():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    return server, server.getsockname()[1]


def account_checks():
    record = sh("/usr/bin/dscl", ".", "-read", "/Users/_arcexec", "UserShell", "IsHidden", "NFSHomeDirectory").stdout
    token = sh("/usr/sbin/sysadminctl", "-secureTokenStatus", "_arcexec", check=False)
    groups = sh("/usr/bin/id", "-Gn", "_arcexec").stdout.split()
    return [
        (
            "account: no login shell, hidden, home /var/empty",
            " ".join(record.replace("dsAttrTypeNative:", "").split()),
            "IsHidden: 1 NFSHomeDirectory: /var/empty UserShell: /usr/bin/false",
        ),
        ("account: no secure token", "DISABLED" in token.stdout + token.stderr, True),
        ("account: not in staff or admin", sorted({"staff", "admin"} & set(groups)), []),
    ]


def isolation_checks(job, canary, marker, target, allowed, blocked):
    full = job.real_profile(allowed)
    home = str(Path.home())
    clipboard = int(job.as_me("exec", "/usr/bin/pbpaste").rsplit("=", 1)[1]) > 0
    return [
        ("control: yashgx reads the canary in ~/Projects", job.as_me("read", canary), "ok"),
        ("home: canary (world-readable file) not readable", job.as_exec(OPEN, "read", canary), REFUSED),
        (
            "home: a preferences file not readable",
            job.as_exec(OPEN, "read", f"{home}/Library/Preferences/.GlobalPreferences.plist"),
            REFUSED,
        ),
        ("home: home folder not listable", job.as_exec(OPEN, "list", home), REFUSED),
        ("control: yashgx sees the canary variable via sysctl", job.as_me("procargs", str(target), marker), "found"),
        (
            "processes: yashgx environment unreadable via sysctl",
            job.as_exec(OPEN, "procargs", str(target), marker),
            REFUSED,
        ),
        (
            "processes: yashgx environment unreadable via ps -E",
            job.as_exec(OPEN, "ps", str(target), marker)[:6],
            "absent",
        ),
        ("processes: cannot signal yashgx processes", job.as_exec(OPEN, "signal", str(target)), REFUSED),
        # macOS adds __CF_USER_TEXT_ENCODING (uid and text encoding) to every process.
        (
            "processes: environment is only what the runner passed",
            job.as_exec(OPEN, "env"),
            json.dumps(["HOME", "LANG", "PATH", "TMPDIR", "__CF_USER_TEXT_ENCODING"]),
        ),
        (
            "privilege: sudo refused",
            job.as_exec(OPEN, "exec", "/usr/bin/sudo", "-n", "true").split()[0],
            {"rc=1", "rc=EPERM"},
        ),
        ("credentials: no keychain from yashgx's home", job.as_exec(OPEN, "keychains", home)[:4], "none"),
        (
            "credentials: clipboard empty or unreadable"
            if clipboard
            else "credentials: clipboard (inconclusive: yours is empty)",
            job.as_exec(OPEN, "exec", "/usr/bin/pbpaste").endswith("bytes=0"),
            True,
        ),
        ("files: workspace not writable", job.as_exec(OPEN, "write", str(job.ws / "x")), REFUSED),
        ("files: scratch writable", job.as_exec(OPEN, "write", str(job.scratch / "x")), "ok"),
        (
            "sandbox: other job readable without Seatbelt (layer check)",
            job.as_exec(OPEN, "read", str(job.other / "secret.txt")),
            "ok",
        ),
        ("sandbox: other job not readable", job.as_exec(full, "read", str(job.other / "secret.txt")), REFUSED),
        ("sandbox: write outside scratch refused", job.as_exec(full, "write", "/Users/Shared/arcexec-x"), REFUSED),
        ("sandbox: allowed loopback port reachable", job.as_exec(full, "connect", "127.0.0.1", str(allowed)), "ok"),
        ("sandbox: other loopback port refused", job.as_exec(full, "connect", "127.0.0.1", str(blocked)), REFUSED),
        ("sandbox: internet refused", job.as_exec(full, "connect", "1.1.1.1", "443"), REFUSED),
        (
            "sandbox: osascript refused",
            job.as_exec(full, "exec", "/usr/bin/osascript", "-e", "return 1").split()[0][3:],
            REFUSED,
        ),
    ]


def job_processes():
    """_arcexec processes except the helpers launchd starts for every user."""
    rows = sh("/bin/ps", "-U", "_arcexec", "-o", "pid=,command=", check=False).stdout.splitlines()
    return [r.split()[0] for r in rows if r.split(None, 1)[1] not in SYSTEM_AGENTS]


def rule_checks():
    refused = lambda *argv: sh("/usr/bin/sudo", "-n", *argv, check=False).returncode != 0  # noqa: E731
    return [
        ("sudo rule: no other command as root", refused("/bin/launchctl", "asuser", "490", "/usr/bin/true"), True),
        (
            "sudo rule: launcher run only through the separate session",
            refused("-u", "_arcexec", LAUNCHER, "run", str(AREA)),
            True,
        ),
    ]


def stop_check(job):
    job.as_exec(OPEN, "linger")
    before = job_processes()
    sh("/usr/bin/sudo", "-n", "-u", "_arcexec", LAUNCHER, "stop", check=False)
    time.sleep(1)
    return [("stop: lingering process found, then killed", (bool(before), job_processes()), (True, []))]


def main():
    marker = secrets.token_hex(8)
    canary = Path.home() / "Projects" / f".arcturus-exec-canary-{marker}"
    canary.write_text("canary")
    canary.chmod(0o644)
    target = subprocess.Popen([PYTHON, "-c", "import time; time.sleep(300)"], env={"ARC_CANARY": marker})
    servers = [listener(), listener()]
    job = Job()
    try:
        checks = (
            account_checks()
            + isolation_checks(job, str(canary), marker, target.pid, servers[0][1], servers[1][1])
            + rule_checks()
            + stop_check(job)
        )
    finally:
        target.kill()
        canary.unlink()
        for server, _ in servers:
            server.close()
    sh("/bin/rm", "-rf", str(job.root), str(job.other))
    checks.append(("cleanup: runner removed the job's files", job.root.exists(), False))
    results = [
        {
            "check": name,
            "got": got,
            "expected": sorted(want) if isinstance(want, set) else want,
            "pass": got in want if isinstance(want, set) else got == want,
        }
        for name, got, want in checks
    ]
    for r in results:
        print(f"{'PASS' if r['pass'] else 'FAIL'}  {r['check']}" + ("" if r["pass"] else f"  (got {r['got']!r})"))
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / f"{time.strftime('%Y%m%dT%H%M%S')}.json").write_text(json.dumps(results, indent=1))
    failed = sum(not r["pass"] for r in results)
    print(f"{len(results) - failed}/{len(results)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
