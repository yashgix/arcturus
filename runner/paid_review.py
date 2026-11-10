"""Internal supervised entry point for one approved, tool-free review."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import sys
import threading
import time

from api_review import (
    ANTHROPIC_VERSION,
    BUILDER_TIMEOUT,
    DEEPSEEK_FINGERPRINT,
    LIVE_ENDPOINTS,
    RESEARCH_TIMEOUT,
    RESEARCH_MAX_REQUEST,
    MAX_REQUEST,
    MAX_RESPONSE,
    MAX_TOKENS,
    REVIEW_TIMEOUT,
    anthropic_text,
    decode,
    microusd,
)
from concurrent_runs import Scheduler
from mock_engineering import supervise
from workers import Limits, Request, Result, Usage, Worker, WorkerFailure


CREDENTIAL_ECHO = "provider response contained the active credential"
ANTHROPIC_STOP_REASONS = (
    "end_turn",
    "max_tokens",
    "stop_sequence",
    "tool_use",
    "pause_turn",
    "refusal",
    "model_context_window_exceeded",
)


class ApprovalExpired(WorkerFailure):
    pass


class CredentialEcho(WorkerFailure):
    pass


def load_key(filename, schedule_root):
    """Read a scoped credential only in the paid worker, via an anchored private file."""
    directory = fd = None
    try:
        path = Path(filename)
        if not path.is_absolute() or path != path.resolve(strict=True):
            raise ValueError
        if path.is_relative_to(schedule_root) or path.is_relative_to(Path(__file__).resolve().parents[1]):
            raise ValueError
        directory = os.open(path.parent, os.O_DIRECTORY | os.O_NOFOLLOW)
        parent = os.fstat(directory)
        if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise ValueError
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.getuid()
            or stat.S_IMODE(st.st_mode) not in (0o400, 0o600)
            or st.st_nlink != 1
            or not 1 <= st.st_size <= 1024
        ):
            raise ValueError
        data = os.read(fd, 1025)
        if len(data) != st.st_size:
            raise ValueError
        key = data.removesuffix(b"\n")
        if not re.fullmatch(rb"[!-~]{1,1024}", key):
            raise ValueError
        return key.decode("ascii")
    except (OSError, ValueError, RuntimeError) as exc:
        raise WorkerFailure("scoped credential file unavailable or unsafe") from exc
    finally:
        for handle in (fd, directory):
            if handle is not None:
                os.close(handle)


def send_once(plan, key, connection=http.client.HTTPSConnection):
    """One TLS POST. The scheduler bounds the entire process, including DNS and reads."""
    host, path = LIVE_ENDPOINTS[plan["provider"]]
    body = plan["body_utf8"].encode()
    timeout = (
        RESEARCH_TIMEOUT
        if "research" in plan
        else BUILDER_TIMEOUT
        if plan.get("engineering", {}).get("role") == "builder"
        else REVIEW_TIMEOUT
    )
    if (
        plan["endpoint"] != f"https://{host}{path}"
        or plan["method"] != "POST"
        or plan["automatic_retries"] != 0
        or plan["max_requests"] != 1
        or plan["timeout_seconds"] != timeout
        or len(body) > (RESEARCH_MAX_REQUEST if "research" in plan else MAX_REQUEST)
        or hashlib.sha256(body).hexdigest() != plan["body_sha256"]
    ):
        raise WorkerFailure("request does not match approved transport")
    headers = {"content-type": "application/json", "accept": "application/json", "connection": "close"}
    if plan["provider"] == "anthropic":
        if plan["anthropic_version"] != ANTHROPIC_VERSION:
            raise WorkerFailure("unexpected Anthropic API version")
        headers.update({"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION})
    else:
        headers["authorization"] = f"Bearer {key}"
    client = connection(host, port=443, timeout=timeout, context=ssl.create_default_context())
    try:
        if not time.time() < plan["expires_at"]:
            raise ApprovalExpired("one-shot approval expired before transport")
        client.request("POST", path, body=body, headers=headers)
        with client.getresponse() as response:
            response_headers = getattr(response, "headers", None)
            if key in (getattr(response, "reason", "") or "") or (
                response_headers is not None
                and any(key in name or key in value for name, value in response_headers.items())
            ):
                raise CredentialEcho(CREDENTIAL_ECHO)
            # http.client does not follow redirects and error prose may contain sensitive material.
            if response.status != 200:
                return response.status, b""
            return 200, response.read(MAX_RESPONSE + 1)
    finally:
        client.close()


def counter(value, maximum=MAX_TOKENS):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("invalid token count")
    return value


def usage_counts(provider, usage, reply, plan):
    output = counter(usage["output_tokens"], plan["max_output_tokens"])
    if provider == "anthropic":
        regular = counter(usage["input_tokens"])
        cached = counter(usage.get("cache_read_input_tokens", 0))
        written = counter(usage.get("cache_creation_input_tokens", 0))
        server = usage.get("server_tool_use")
        if (
            written
            or (server is not None and any(counter(n) for n in server.values()))
            or usage.get("inference_geo") not in (None, "global")
            or usage.get("service_tier") not in (None, "standard")
            or usage.get("speed") not in (None, "standard")
        ):
            raise ValueError("unexpected Anthropic billing metadata")
        inputs = regular + cached
        details = usage.get("output_tokens_details")
        reasoning = 0 if details is None else counter(details.get("thinking_tokens", 0), output)
    else:
        if reply.get("service_tier") != "default":
            raise ValueError("unexpected OpenAI service tier")
        inputs = counter(usage["input_tokens"])
        details = usage["input_tokens_details"]
        cached = counter(details["cached_tokens"], inputs)
        written = counter(details.get("cache_write_tokens", 0), inputs - cached)
        reasoning = counter(usage["output_tokens_details"]["reasoning_tokens"], output)
        if counter(usage["total_tokens"]) != inputs + output:
            raise ValueError("inconsistent OpenAI usage")
    counter(inputs, plan["planning_input_tokens"])
    return {
        "input_tokens": inputs,
        "output_tokens": output,
        "cached_input_tokens": cached,
        "cache_write_tokens": written,
        "reasoning_tokens": reasoning,
    }


def deepseek_usage(usage):
    inputs = counter(usage["prompt_tokens"])
    cached = counter(usage["prompt_cache_hit_tokens"], inputs)
    missed = counter(usage["prompt_cache_miss_tokens"], inputs)
    output = counter(usage["completion_tokens"])
    if cached + missed != inputs or counter(usage["total_tokens"]) != inputs + output:
        raise ValueError("inconsistent DeepSeek usage")
    return {
        "input_tokens": inputs,
        "output_tokens": output,
        "cached_input_tokens": cached,
        "cache_miss_input_tokens": missed,
        "total_tokens": inputs + output,
    }


def deepseek_text(reply):
    (choice,) = reply["choices"]
    message = choice["message"]
    if (
        reply["object"] != "chat.completion"
        or choice.get("index") != 0
        or choice["finish_reason"] != "stop"
        or message["role"] != "assistant"
        or any(message.get(key) for key in ("refusal", "tool_calls", "function_call", "reasoning_content"))
    ):
        raise ValueError("incomplete or unexpected DeepSeek output")
    return message["content"]


def response_value(provider, reply):
    text = {"anthropic": anthropic_text, "openai": openai_text, "deepseek": deepseek_text}[provider](reply)
    return decode(text.encode())


def openai_text(reply):
    if reply["status"] != "completed" or reply.get("error") or reply.get("incomplete_details"):
        raise ValueError("incomplete OpenAI response")
    *prefix, message = reply["output"]
    if (
        any(item["type"] != "reasoning" for item in prefix)
        or message["type"] != "message"
        or message["role"] != "assistant"
        or message["status"] != "completed"
    ):
        raise ValueError("unexpected OpenAI output")
    (block,) = message["content"]
    if block["type"] != "output_text":
        raise ValueError("unexpected OpenAI content")
    return block["text"]


def structured_review(value, criteria):
    """Normalize the paid wire format for Arc's shared reviewer validation."""
    if not isinstance(value, dict) or not isinstance(value.get("coverage"), dict):
        raise ValueError("coverage must be keyed by criterion ID")
    coverage = value["coverage"]
    if coverage.keys() != set(criteria):
        raise ValueError("coverage does not list every acceptance criterion exactly once")
    if any(not isinstance(row, dict) or row.keys() != {"status", "evidence"} for row in coverage.values()):
        raise ValueError("malformed coverage entry (each needs status and evidence)")
    return {**value, "coverage": [{"criterion": criterion, **coverage[criterion]} for criterion in criteria]}


def response_stop(provider, reply):
    if provider == "deepseek":
        choices = reply.get("choices")
        reason = (
            choices[0].get("finish_reason")
            if (isinstance(choices, list) and len(choices) == 1 and isinstance(choices[0], dict))
            else None
        )
        return (
            reason
            if reason in ("stop", "length", "content_filter", "tool_calls", "insufficient_system_resource")
            else None
        )
    if provider == "anthropic":
        reason = reply.get("stop_reason")
        return reason if reason in ANTHROPIC_STOP_REASONS else None
    status = reply.get("status")
    if status == "incomplete":
        details = reply.get("incomplete_details")
        reason = details.get("reason") if isinstance(details, dict) else None
        return reason if reason in ("max_output_tokens", "content_filter") else "incomplete"
    if status == "completed":
        output = reply.get("output")
        for item in output if isinstance(output, list) else ():
            content = item.get("content") if isinstance(item, dict) else None
            if isinstance(content, list) and any(
                isinstance(block, dict) and block.get("type") == "refusal" for block in content
            ):
                return "refusal"
        return "completed"
    return status if status in ("failed", "cancelled", "queued", "in_progress") else None


def contains_credential(value, credential):
    """Inspect JSON keys and values, including embedded JSON review text."""
    pending = [value]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value)
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            if credential in value:
                return True
            if "\\" in value and value.lstrip().startswith(("{", "[", '"')):
                try:
                    pending.append(decode(value.encode()))
                except (ValueError, RecursionError):
                    pass
    return False


def audit(status, raw, plan, request, validate, owns, canonical, *, credential):
    if type(status) is not int or not 100 <= status <= 599:
        status = None
    receipt = {
        "state": "rejected",
        "http_status": status,
        "reserve_microusd": plan["illustrative_reserve_microusd"],
        "estimated_microusd": None,
        "actual_charge_microusd": None,
    }
    if status != 200:
        receipt["reason"] = "provider HTTP error"
        return receipt
    if isinstance(raw, bytes) and credential.encode() in raw:
        return {**receipt, "reason": CREDENTIAL_ECHO}
    provider = plan["provider"]
    role = (plan.get("engineering") or plan.get("model_task") or plan.get("research") or {}).get("role", "reviewer")
    builder = role == "builder"
    reviewer = role == "reviewer"
    try:
        reply = decode(raw)
        if contains_credential(reply, credential):
            return {**receipt, "reason": CREDENTIAL_ECHO}
        receipt["response_sha256"] = hashlib.sha256(raw).hexdigest()
        stop_reason = response_stop(provider, reply)
        if stop_reason is not None:
            receipt["stop_reason"] = stop_reason
        if reply["model"] != plan["model"]:
            raise ValueError("unexpected model identity")
        rates = plan["planning_rates_nanousd_per_token"]
        if provider == "deepseek":
            fingerprint = reply.get("system_fingerprint")
            if not isinstance(fingerprint, str) or not DEEPSEEK_FINGERPRINT.fullmatch(fingerprint):
                raise ValueError("unusable DeepSeek fingerprint")
            receipt["provider_fingerprint"] = fingerprint
            expected = plan["deepseek"]["expected_fingerprint"]
            if expected is not None and fingerprint != expected:
                return {**receipt, "reason": "DeepSeek backend fingerprint changed; review profile before dispatch"}
            usage = reply["usage"]
            counts = deepseek_usage(usage)
            receipt["usage"] = counts
            details = usage.get("completion_tokens_details", {})
            prompt_details = usage.get("prompt_tokens_details", {})
            if (
                not isinstance(details, dict)
                or not isinstance(prompt_details, dict)
                or counter(details.get("reasoning_tokens", 0), counts["output_tokens"]) != 0
                or (
                    "cached_tokens" in prompt_details
                    and counter(prompt_details["cached_tokens"]) != counts["cached_input_tokens"]
                )
            ):
                raise ValueError("unexpected DeepSeek thinking or cache metadata")
            counts["reasoning_tokens"] = 0
            counter(counts["input_tokens"], plan["planning_input_tokens"])
            counter(counts["output_tokens"], plan["max_output_tokens"])
            estimate = (
                counts["cache_miss_input_tokens"] * rates["input"]
                + counts["cached_input_tokens"] * rates["cached_input"]
                + counts["output_tokens"] * rates["output"]
                + 999
            ) // 1000
        else:
            counts = usage_counts(provider, reply["usage"], reply, plan)
            estimate = microusd(counts["input_tokens"], counts["output_tokens"], rates)
        if estimate > plan["illustrative_reserve_microusd"]:
            raise ValueError("usage exceeds reserve")
        receipt.update(usage=counts, estimated_microusd=estimate)
        response_id = reply.get("id")
        prefix = {"anthropic": "msg_", "openai": "resp_", "deepseek": ""}[provider]
        if isinstance(response_id, str) and re.fullmatch(prefix + r"[A-Za-z0-9_-]{1,128}", response_id):
            receipt["provider_response_id"] = response_id
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
        receipt["reason"] = "unverifiable provider identity or accounting"
        return receipt
    if builder and provider == "anthropic":
        stop_reason = receipt.get("stop_reason")
        if stop_reason in ("max_tokens", "model_context_window_exceeded"):
            return {**receipt, "reason": "Anthropic builder output truncated"}
        if stop_reason is None:
            return {**receipt, "reason": "invalid Anthropic builder stop reason"}
        if stop_reason != "end_turn" or reply.get("stop_details") is not None:
            return {**receipt, "reason": "Anthropic builder response did not complete"}
    try:
        value = response_value(provider, reply)
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError) as exc:
        reason = (
            f"malformed {'Anthropic' if provider == 'anthropic' else provider} builder patch"
            if builder
            else "unusable provider output"
        )
        if not builder:
            receipt["validation_error"] = "duplicate JSON key" if exc.args == ("duplicate JSON key",) else reason
        return {**receipt, "reason": reason}
    if reviewer:
        try:
            value = structured_review(value, request.criteria)
        except ValueError as exc:
            return {**receipt, "reason": str(exc), "validation_error": str(exc)}
    try:
        outcome, review, reason = validate(value, request.criteria)
        if (
            reviewer
            and outcome != "invalid"
            and value["verdict"] == "approve"
            and any(row["status"] != "met" for row in review["coverage"])
        ):
            outcome, reason = "invalid", "approval requires verified, met coverage for every criterion"
        if reviewer and outcome == "changes":
            findings = [f for f in review["findings"] if f["severity"] in {"medium", "high"}] or review["findings"]
            if not findings or any(
                not f["issue"].strip()
                or (
                    f["file"] not in {f"criterion:{criterion}" for criterion in request.criteria}
                    and (not canonical(f["file"]) or not owns(request.owned_paths, f["file"]))
                )
                for f in findings
            ):
                outcome, reason = "invalid", "findings cannot be routed to the owned paths or criteria"
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
        outcome, review, reason = (
            "invalid",
            None,
            "malformed Anthropic builder patch" if builder else "unusable provider output",
        )
    if outcome == "invalid":
        if "research" in plan:
            receipt["failure_class"] = "research_quality"
        receipt["reason"] = reason
        if not builder:
            receipt["validation_error"] = reason
    else:
        receipt.update(state="response_received", outcome=outcome, review=review)
    return receipt


def verified_packet(schedule, plan, arc):
    source = schedule.workspace(plan["source_job"])
    repo, state = source / "repo", source / "runtime/runner-state"
    task_id, project = plan["task"], plan["project"]
    journal = json.loads((state / "journal.json").read_text())
    task = journal["tasks"][task_id]
    body = decode(plan["body_utf8"].encode())
    packet = decode((body["input"] if plan["provider"] == "openai" else body["messages"][0]["content"]).encode())
    # Scope evidence reads to this source task before calling the shared readiness gate.
    log = Path(task["tests"]["log"])
    if (
        task["project"] != project
        or task["stage"] != "awaiting_approval"
        or task["candidate"]["head"] != plan["candidate"]
        or packet["inventory"] != task["candidate"]["inventory"]
        or packet["base"] != task["start"]
        or repo.resolve() != repo
        or state.resolve() != state
        or log.resolve() != log
        or log.parent != state
        or not re.fullmatch(r"MOCK-\d+-[0-9a-f]{8}", task["evidence"]["tag"])
    ):
        raise WorkerFailure("source task or evidence drifted")
    config = {"projects": {project: {"dir": str(repo), "protected": ["test/acceptance"]}}}
    files = {kind: Path(path) for kind, path in arc.evidence_files(task, state=state, config=config).items()}
    if any(path.parent != state or path.is_symlink() for path in files.values()):
        raise WorkerFailure("source evidence is outside its task")
    bindings = {path.name: task["evidence"][kind] for kind, path in files.items() if kind != "review"}
    evidence = packet["evidence"]
    if {name: item["sha256"] for name, item in evidence.items()} != bindings or any(
        hashlib.sha256(item["text"].encode()).hexdigest() != item["sha256"] for item in evidence.values()
    ):
        raise WorkerFailure("request evidence does not match its source receipt")
    if arc.receipt_problems(journal, task_id, state=state, config=config):
        raise WorkerFailure("source candidate or evidence no longer passes the receipt gate")
    return packet


def request_receipt(
    schedule,
    job,
    plan,
    filename,
    request,
    validate,
    owns,
    canonical,
    connection,
    *,
    authorize=None,
    active=None,
    response_path=None,
):
    if authorize is None:
        schedule.consume_review(job, plan)
    else:
        authorize()
    receipt = {
        "state": "not_sent",
        "reserve_microusd": plan["illustrative_reserve_microusd"],
        "estimated_microusd": None,
        "actual_charge_microusd": None,
    }
    try:
        key = load_key(filename, schedule.root)
    except WorkerFailure:
        return {**receipt, "reason": "scoped credential file unavailable or unsafe"}
    if schedule.job(job)["cancelled"] or (active is not None and not active()):
        raise WorkerFailure("request cancelled before transport")
    try:
        status, raw = send_once(plan, key, connection)
    except ApprovalExpired:
        return {**receipt, "reason": "one-shot approval expired before transport"}
    except CredentialEcho:
        return {**receipt, "state": "rejected", "reason": CREDENTIAL_ECHO}
    except Exception:
        # Exception text can include provider bytes or request headers.
        return {**receipt, "state": "uncertain", "reason": "transport failed or timed out"}
    try:
        receipt = audit(status, raw, plan, request, validate, owns, canonical, credential=key)
        safe_response = False
        if response_path is not None and status == 200:
            try:
                safe_response = not contains_credential(decode(raw), key)
            except (ValueError, TypeError, RecursionError):
                pass
        if safe_response:
            with response_path.open("xb") as file:
                file.write(raw)
            receipt["response_artifact"] = str(response_path)
        return receipt
    except Exception:
        return {**receipt, "state": "rejected", "reason": "provider response could not be safely audited"}


def live_worker(schedule, job, plan, filename, arc, connection):
    def review(request):
        if (request.session, request.task, request.project, request.candidate, request.role) != (
            plan["plan_sha256"],
            plan["task"],
            plan["project"],
            plan["candidate"],
            "reviewer",
        ):
            raise WorkerFailure("review worker received a different task or candidate")
        receipt = request_receipt(
            schedule, job, plan, filename, request, arc.validate_review, arc.owns, arc.canonical_path, connection
        )
        counts = receipt.get("usage", {})
        tokens = counts.get("input_tokens", 0) + counts.get("output_tokens", 0)
        return Result(Usage(tokens, (receipt["estimated_microusd"] or 0) / 1_000_000), receipt)

    return Worker(plan["provider"], "api", frozenset({"reviewer"}), frozenset(), review, needs_review_packet=True)


def execute_model(schedule, job, filename, connection):
    from concurrent_runs import APPROVAL_TTL_SECONDS
    from model_tasks import restore, validate_output

    try:
        row, item = schedule.approval(job), schedule.job(job)
        if row is None or item["state"] != "running" or item["cancelled"] or row["consumed"] is not None:
            raise WorkerFailure("model task has no available approval")
        stored = json.loads(row["plan"])
        plan, packet = restore(stored, APPROVAL_TTL_SECONDS)
        if plan != stored or row["plan_sha256"] != plan["plan_sha256"]:
            raise WorkerFailure("approved model task or profile changed")
        role = plan["model_task"]["role"]
        request = Request(
            plan["plan_sha256"],
            plan["project"],
            plan["task"],
            role,
            "",
            (),
            frozenset(),
            "",
            schedule.workspace(job) / "result.json",
            (),
            (),
            plan["candidate"],
            Limits(requests=1, retries=0, seconds=REVIEW_TIMEOUT),
        )
        receipt = request_receipt(
            schedule,
            job,
            plan,
            filename,
            request,
            lambda value, _: validate_output(role, packet, value),
            None,
            None,
            connection,
        )
        if "review" in receipt:
            receipt["result"] = receipt.pop("review")
        checkpoint = {
            "status": "completed" if receipt["state"] == "response_received" else "blocked",
            "reason": receipt.get("reason"),
            "role": role,
            "plan_sha256": plan["plan_sha256"],
        }
        schedule.settle_review(job, plan, receipt, checkpoint)
    except (WorkerFailure, ValueError, OSError, KeyError, TypeError):
        row = schedule.approval(job)
        if row is not None and row["consumed"] is None:
            schedule.publish(job, {"status": "blocked", "reason": "model task, approval or budget failed validation"})


def execute(schedule, job, filename, arc, connection=http.client.HTTPSConnection):
    try:
        row, queued = schedule.approval(job), schedule.job(job)
        if row is None or row["consumed"] is not None or queued["state"] != "running" or queued["cancelled"]:
            raise WorkerFailure("paid review has no available approval")
        stored = json.loads(row["plan"])
        recovery = stored.get("recovery")
        if recovery:
            plan = schedule.prepare_recovery(row["source_job"], stored["candidate"], stored["expires_at"], arc=arc)
        else:
            plan = schedule.prepare_trial(row["source_job"], row["provider"], stored["model"])
        if plan != stored or plan["plan_sha256"] != row["plan_sha256"]:
            raise WorkerFailure("approved plan or source request changed")
        packet = (
            decode(decode(plan["body_utf8"].encode())["input"].encode())
            if recovery
            else verified_packet(schedule, plan, arc)
        )
        worker = live_worker(schedule, job, plan, filename, arc, connection)
        request = Request(
            plan["plan_sha256"],
            plan["project"],
            plan["task"],
            "reviewer",
            "",
            tuple(packet["owned_paths"]),
            frozenset(),
            "",
            schedule.workspace(job) / "review.json",
            tuple(packet["criteria"]),
            (),
            plan["candidate"],
            Limits(requests=1, retries=0, seconds=REVIEW_TIMEOUT),
            packet,
        )
        receipt = worker.run(request).payload
        status = {"approve": "reviewed", "changes": "changes_requested"}.get(receipt.get("outcome"), "blocked")
        checkpoint = {
            "status": status,
            "reason": receipt.get("reason"),
            "candidate": plan["candidate"],
            "source_job": plan["source_job"],
            "plan_sha256": plan["plan_sha256"],
        }
        if recovery:
            checkpoint["rejected_plan_sha256"] = recovery["rejected_plan_sha256"]
            if status == "reviewed":
                try:
                    if (
                        schedule.prepare_recovery(
                            row["source_job"], stored["candidate"], stored["expires_at"], arc=arc, require_current=False
                        )
                        != plan
                    ):
                        raise ValueError("recovery source changed")
                except ValueError:
                    checkpoint.update(status="blocked", reason="original candidate or protected evidence changed")
                else:
                    checkpoint["status"] = "ready"
        schedule.settle_review(job, plan, receipt, checkpoint)
    except (WorkerFailure, arc.Blocked, ValueError, OSError, KeyError, TypeError) as exc:
        # Any error after reservation is reconciled as uncertain by the supervisor.
        row = schedule.approval(job)
        if row is not None and row["consumed"] is None:
            reason = str(exc) if isinstance(exc, WorkerFailure) else "source evidence or approval could not be read"
            schedule.publish(job, {"status": "blocked", "reason": reason})


def main(connection=http.client.HTTPSConnection):
    root, job_id, pipe, lease = sys.argv[1:]
    supervise(int(pipe), int(lease))
    # Backstop the supervisor deadline if the supervisor is stalled in a local operation.
    deadline = threading.Timer(REVIEW_TIMEOUT, os.killpg, (os.getpgrp(), signal.SIGKILL))
    deadline.daemon = True
    deadline.start()
    try:
        schedule = Scheduler(root)
        if schedule.job(int(job_id))["scenario"] == "api-task":
            execute_model(schedule, int(job_id), os.environ.pop("ARCTURUS_REVIEW_KEY_FILE"), connection)
            return
        approval = schedule.approval(int(job_id))
        os.environ["ARCTURUS_ROOT"] = str(schedule.workspace(approval["source_job"]) / "runtime")
        import arc

        execute(schedule, int(job_id), os.environ.pop("ARCTURUS_REVIEW_KEY_FILE"), arc, connection)
    finally:
        deadline.cancel()


if __name__ == "__main__":
    main()
