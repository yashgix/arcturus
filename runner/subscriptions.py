"""Claude Max and Codex on ChatGPT Plus as headless workers, and both plans' usage: run one bounded, tool-free call,
and read how much of each plan's 5-hour and weekly allowance is used. No API key is ever in their environment, each
must report the plan login, and paid overage counts as a limit, so a plan call never bills anything. Codex runs with
every tool off (no shell, no file, web, image or agent tools; probed 9 Nov 2026), so it reads only its stdin."""

import glob
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

import llm

CLAUDE_GLOB = "~/.vscode/extensions/anthropic.claude-code-*-darwin-arm64/resources/native-binary/claude"
ANTHROPIC_TEAM = "Q6L2SF6YDW"
CODEX = "/opt/homebrew/bin/codex"
OPENAI_TEAM = "2DC432GLL2"
CODEX_MODEL = "gpt-6.1-sol"
CODEX_OFF = (
    "shell_tool",
    "unified_exec",
    "code_mode_host",
    "apps",
    "plugins",
    "multi_agent",
    "hooks",
    "browser_use",
    "computer_use",
    "image_generation",
    "view_image",
    "goals",
    "sleep_tool",
    "guardian_approval",
)
SAFE_ITEMS = {"agent_message", "reasoning", "todo_list", "error"}  # anything else is a tool
PLUS_LIMIT = re.compile(r"usage limit|rate limit|hit your limit", re.IGNORECASE)
CODEX_SESSIONS = Path.home() / ".codex" / "sessions"
TIMEOUT = 1800


class LimitReached(Exception):
    """The plan refused the call; *until* is when its window resets (epoch seconds) if known."""

    def __init__(self, message, until=None):
        super().__init__(message)
        self.until = until


class ToolUsed(RuntimeError):
    """Codex ran a tool although every tool was off: its confinement can't be trusted."""


def env():
    user = os.environ.get("USER") or Path.home().name
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(Path.home()),
        "USER": user,
        "LOGNAME": user,
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        "LANG": "en_US.UTF-8",
    }


def version(path):
    return tuple(int(n) for n in re.findall(r"claude-code-(\d+)\.(\d+)\.(\d+)", path)[0])


def signed_by(path, team):
    signed = subprocess.run(["/usr/bin/codesign", "-dv", path], capture_output=True, text=True, check=False).stderr
    if f"TeamIdentifier={team}" not in signed:
        raise PermissionError(f"{path} is not signed by team {team}")
    return path


def claude_binary():
    """The newest official binary from the VS Code extension, signed by Anthropic."""
    found = sorted(glob.glob(os.path.expanduser(CLAUDE_GLOB)), key=version)
    if not found:
        raise FileNotFoundError("no Claude Code binary from the VS Code extension")
    return signed_by(found[-1], ANTHROPIC_TEAM)


def codex_binary():
    return signed_by(os.path.realpath(CODEX), OPENAI_TEAM)


def bounded(argv, stdin, cwd, timeout=TIMEOUT):
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=env(),
        text=True,
        start_new_session=True,
    )
    try:
        out, err = process.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
        raise TimeoutError(f"{Path(argv[0]).name} ran past {timeout} s") from None
    return process.returncode, out, err


def max_windows(info):
    """Percent used per window from a rate_limit_event, e.g. {"five_hour": {"used": 30.0, ...}}."""
    windows = info.get("unifiedWindows", {})
    return {
        name: {"used": round(100 * w["utilization"], 1), "resets_at": w.get("resetsAt"), "status": w.get("status")}
        for name, w in windows.items()
        if isinstance(w, dict) and "utilization" in w
    }


def events(text):
    for line in text.splitlines():
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def claude_argv(instruction, schema, model):
    return [
        claude_binary(),
        "-p",
        instruction,
        "--output-format",
        "stream-json",
        "--verbose",
        "--tools",
        "",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--disable-slash-commands",
        "--setting-sources",
        "",
        "--no-session-persistence",
        "--model",
        model,
        "--json-schema",
        json.dumps(schema),
    ]


def read_claude(out):
    """(result event, usage windows) from the stream; refuses anything not billed to the plan."""
    windows, result = {}, None
    for event in events(out):
        if event.get("type") == "system" and event.get("subtype") == "init" and event.get("apiKeySource") != "none":
            raise llm.SecurityStop(f"Claude Code used {event.get('apiKeySource')!r}, not the Max login")
        if event.get("type") == "rate_limit_event":
            info = event.get("rate_limit_info", {})
            windows = max_windows(info) or windows
            if info.get("status") == "rejected" or info.get("isUsingOverage"):
                raise LimitReached("Max limit reached", info.get("resetsAt"))
        elif event.get("type") == "result":
            result = event
    if result is None:
        raise RuntimeError("Claude Code returned no result")
    if result.get("is_error"):
        raise RuntimeError(f"Claude Code failed: {str(result.get('result'))[:300]}")
    return result, windows


def claude(instruction, data, schema, model, cwd):
    """One tool-free answer from Claude on the Max plan. Returns (structured answer, usage windows, estimated cost)."""
    _, out, _ = bounded(claude_argv(instruction, schema, model), data, cwd)
    result, windows = read_claude(out)
    return result.get("structured_output"), windows, result.get("total_cost_usd")


def codex_argv(binary, schema_path, answer_path):
    argv = [
        binary,
        "exec",
        "--ignore-user-config",
        "--ignore-rules",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "-m",
        CODEX_MODEL,
        "-c",
        'model_reasoning_effort="high"',
        "-c",
        'web_search="disabled"',
        "-c",
        "include_apply_patch_tool=false",
        "--json",
        "--output-schema",
        str(schema_path),
        "-o",
        str(answer_path),
    ]
    for feature in CODEX_OFF:
        argv += ["--disable", feature]
    return argv + ["-"]


def read_codex(out):
    """(thread id, failure message) from Codex's event stream; any tool call raises ToolUsed. An error the turn
    recovers from (e.g. "Reconnecting... 1/5") is no failure."""
    thread, failure, completed = None, None, False
    for event in events(out):
        item = event.get("item")
        if isinstance(item, dict) and item.get("type") not in SAFE_ITEMS:
            raise ToolUsed(f"Codex used a tool: {item.get('type')}")
        kind = event.get("type")
        if kind == "thread.started":
            thread = event.get("thread_id")
        elif kind in ("error", "turn.failed"):
            failure = str(event.get("message") or (event.get("error") or {}).get("message"))
            completed = False
        elif kind == "turn.completed":
            completed = True
    return thread, None if completed else failure


def codex(instruction, data, schema):
    """One tool-free answer from Codex on the Plus plan. Returns (structured answer, usage windows). Not ephemeral:
    its session log is the only place Plus usage is recorded."""
    binary = codex_binary()
    with tempfile.TemporaryDirectory() as folder:
        work, schema_path, answer = Path(folder, "work"), Path(folder, "schema.json"), Path(folder, "answer.json")
        work.mkdir()
        _, out, err = bounded([binary, "login", "status"], "", work, 60)
        if "Logged in using ChatGPT" not in out + err:
            raise llm.SecurityStop("Codex is not on the ChatGPT Plus login")
        schema_path.write_text(json.dumps(schema))
        code, out, err = bounded(codex_argv(binary, schema_path, answer), instruction + "\n\n" + data, work)
        thread, failure = read_codex(out)
        windows = codex_snapshot(thread) if thread else {}
        if code != 0 or failure or not answer.exists():
            full = [w.get("resets_at") or 0 for w in windows.values() if w["used"] >= 100]
            if full or PLUS_LIMIT.search(failure or err[-2000:]):
                raise LimitReached("Plus limit reached", max(full, default=0) or None)
            raise RuntimeError(f"Codex failed: {(failure or err)[-300:]}")
        return json.loads(answer.read_text()), windows


def codex_snapshot(thread=None):
    """Plus usage from Codex's own session log: the given thread's, or the newest one recorded."""
    pattern = f"*{thread}.jsonl" if thread else "*.jsonl"
    files = sorted(CODEX_SESSIONS.glob(f"*/*/*/{pattern}"), key=lambda p: p.stat().st_mtime)
    for path in reversed(files[-20:]):
        limits = None
        for event in events(path.read_text(errors="replace")):
            found = event.get("payload", {}).get("rate_limits") if isinstance(event.get("payload"), dict) else None
            limits = found or limits
        if limits:
            return {
                name: {"used": float(limits[key]["used_percent"]), "resets_at": limits[key].get("resets_at")}
                for key, name in (("primary", "five_hour"), ("secondary", "seven_day"))
                if limits.get(key)
            }
    return {}
