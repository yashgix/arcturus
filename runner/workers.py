"""Trusted worker registration and per-task dispatch accounting."""

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Protocol
import time
import uuid


class WorkerFailure(Exception):
    pass


@dataclass(frozen=True)
class Limits:
    requests: int = 6
    tokens: int = 500_000
    estimated_usd: float = 20
    seconds: int = 7200
    retries: int = 2

    def __post_init__(self):
        for name in ("requests", "tokens", "seconds", "retries"):
            value = getattr(self, name)
            if type(value) is not int or value < (0 if name == "retries" else 1):
                raise ValueError(f"invalid {name} limit")
        if not valid_cost(self.estimated_usd):
            raise ValueError("invalid estimated spending limit")


def valid_cost(value):
    return type(value) in (int, float) and 0 <= value < float("inf")


@dataclass(frozen=True)
class Usage:
    tokens: int
    estimated_usd: float


@dataclass(frozen=True)
class Request:
    session: str
    project: str
    task: str
    role: str
    workspace: str
    owned_paths: tuple[str, ...]
    tools: frozenset[str]
    prompt: str
    output: Path
    criteria: tuple[str, ...]
    findings: tuple[dict, ...]
    candidate: str
    remaining: Limits
    review_packet: dict | None = None


@dataclass(frozen=True)
class Result:
    usage: Usage
    payload: dict


@dataclass(frozen=True)
class Worker:
    provider: str
    billing: str
    roles: frozenset[str]
    tools: frozenset[str]
    run: Callable[[Request], Result]
    needs_review_packet: bool = False


class ApiAdapter(Protocol):
    """OpenAI, Anthropic, Gemini, DeepSeek, etc. can implement this transport.

    A trusted wrapper must authorize billing, enforce remaining limits at request
    time, disable implicit retries, and translate the provider response to Result.
    Paid one-shot reviews use the supervised schedule's approval ledger.
    The engineering task dispatcher admits mock and subscription CLI workers.
    """

    def __call__(self, request: Request) -> Result: ...


class Dispatch:
    def __init__(self, registry, assignment, limits, *, api_dispatch=None):
        self.workers = {role: registry[key] for role, key in assignment.items()}
        if set(self.workers) != {"builder", "reviewer"}:
            raise WorkerFailure("engineering needs builder and reviewer assignments")
        for role, worker in self.workers.items():
            permitted = {"read", "exec"} | ({"edit"} if role == "builder" else set())
            if role not in worker.roles or not worker.tools <= permitted:
                raise WorkerFailure(f"invalid capabilities for {role}")
            if worker.billing not in {"mock", "subscription-cli"} and (
                worker.billing != "api" or api_dispatch is None or worker.tools
            ):
                raise WorkerFailure("paid API dispatch is disabled")
        if api_dispatch is not None and any(worker.billing != "api" for worker in self.workers.values()):
            raise WorkerFailure("API engineering requires two tool-free API workers")
        if self.workers["builder"].provider == self.workers["reviewer"].provider:
            raise WorkerFailure("engineering requires distinct builder and reviewer providers")
        self.limits = limits
        self.api_dispatch = api_dispatch

    @property
    def requires_approval(self):
        return any(worker.billing == "subscription-cli" for worker in self.workers.values())

    def remaining_seconds(self, task):
        seconds = int(self.limits.seconds - (time.time() - task["dispatch_started"]))
        if seconds <= 0:
            raise WorkerFailure("task duration budget exhausted")
        return seconds

    def dispatch(
        self,
        role,
        task,
        save,
        workspace,
        prompt,
        output,
        candidate,
        *,
        findings=(),
        criteria=(),
        retry=False,
        handoff=None,
        authorize=None,
        review_packet=None,
    ):
        worker = self.workers[role]
        ledger = task.setdefault("dispatches", [])
        if any(entry["status"] == "running" for entry in ledger):
            raise WorkerFailure("previous dispatch has an uncertain outcome")
        used_tokens = sum(entry.get("usage", {}).get("tokens", 0) for entry in ledger)
        used_cost = sum(entry.get("usage", {}).get("estimated_usd", 0) for entry in ledger)
        retries = sum(entry["retry"] for entry in ledger)
        left = self.limits
        seconds = self.remaining_seconds(task)
        if (
            len(ledger) >= left.requests
            or used_tokens >= left.tokens
            or used_cost > left.estimated_usd
            or (retry and retries >= left.retries)
        ):
            raise WorkerFailure("task dispatch budget exhausted (requests, tokens, spending, duration or retries)")
        remaining = Limits(
            left.requests - len(ledger),
            left.tokens - used_tokens,
            left.estimated_usd - used_cost,
            seconds,
            left.retries - retries - int(retry),
        )
        session = str(uuid.uuid4())
        owned = tuple(task["spec"]["owned_paths"])
        entry = {
            "session": session,
            "role": role,
            "provider": worker.provider,
            "billing": worker.billing,
            "status": "running",
            "retry": retry,
            "candidate": candidate,
            "workspace": workspace,
            "findings": list(findings),
            "handoff_attempt": handoff,
            "output": str(output),
            "tools": sorted(worker.tools),
            "owned_paths": list(owned),
        }
        ledger.append(entry)
        save()
        request = Request(
            session,
            task["project"],
            task["identifier"],
            role,
            workspace,
            owned,
            worker.tools,
            prompt,
            output,
            tuple(criteria),
            tuple(findings),
            candidate,
            remaining,
            review_packet,
        )
        try:
            if self.requires_approval:
                if authorize is None:
                    raise WorkerFailure("live dispatch requires execution authorization")
                authorize()
            result = self.api_dispatch(request) if worker.billing == "api" else worker.run(request)
            if (
                not isinstance(result, Result)
                or not isinstance(result.usage, Usage)
                or type(result.usage.tokens) is not int
                or result.usage.tokens < 0
                or not valid_cost(result.usage.estimated_usd)
                or not isinstance(result.payload, dict)
            ):
                raise WorkerFailure("malformed worker result or missing usage")
            entry["usage"] = asdict(result.usage)
            if (
                result.usage.tokens > remaining.tokens
                or result.usage.estimated_usd > remaining.estimated_usd
                or time.time() - task["dispatch_started"] >= left.seconds
            ):
                raise WorkerFailure("task dispatch budget exceeded (tokens, spending or duration)")
            entry["status"] = "completed"
            return result.payload
        except Exception as exc:
            entry.update(status="failed", reason=str(exc))
            raise WorkerFailure(str(exc)) from exc
        finally:
            save()
