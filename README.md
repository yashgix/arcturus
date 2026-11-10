# Arcturus

Arcturus is a secure multi-agent workstation that runs on my Mac. A workflow, written in code on a shared core,
breaks a job into checkpointed model steps; each step goes to a model chosen from an ordered list across
subscriptions and APIs, generated code runs in a locked-down sandbox, tests and an independent reviewer check the
result, failures get bounded repairs, and publishing, sending messages and other outside actions beyond the
approved workflow wait for a human. Every paid call
runs inside a spending grant that I approve once with Touch ID.

Four workflows run on that core today: spec-driven software builds, source-backed research, sandboxed evaluation of
AI agents, and an end-to-end job-search pipeline that combines the three. Giving it a goal in plain words and having
one main agent plan and delegate the work is the direction, not built yet.

**This repository is shared to show the work. It is not licensed for reuse.**

## What works today

| Workflow | What it does | Evidence |
|---|---|---|
| **Build** (`runner/build.py`) | Spec → model writes files → own and hidden acceptance tests in the sandbox → independent review → bounded repair | Tracebench milestones 1-2 (public history); 11 pipeline prototypes, 7-9 Nov 2026 |
| **Research** (`runner/dossier.py`) | Staged research from captured sources: quotes extracted and checked locally, findings cited, a second model challenges the ideas | Company dossiers for every pipeline run |
| **Evaluate** (`runner/evaluate.py`, `runner/broker.py`) | Runs an AI agent in the sandbox against a suite; a broker makes every model call; a pinned verifier replays the transcript and must reproduce the report byte for byte | [Tracebench](https://github.com/yashgix/tracebench): 12 incidents, three models, 220 calls, $0.22 |
| **Pipeline** (`runner/pipeline.py`) | A persistent queue that chains radar → research → decide → spec → build → review → drafts for several companies at once, unattended | Runs day and night since 8 Nov 2026 |

Honest status: every accepted build so far needed a final hand fix before an independent reviewer accepted it.
Full autonomy is the goal, not the current state. Builds run plain Python only; packages, local services, browser
tests, TypeScript and Docker are in development.

## Architecture

```
you ─── approve a grant (Touch ID / Face ID) ─── review drafts, decide every outside action
                 │
workflows    build · research · evaluate · pipeline (radar, decide, spec, notes, drafts)
                 │
core         workflow    checkpointed steps, bounded feedback-driven attempts
             llm.call    one granted, tool-free model call: build, send once, account, classify
             routing     ordered models per step across subscriptions and APIs, live usage, reserve lines
             grant       models, ceilings, calls, scope, expiry, hash of the enforcement code; local ledger
             approvals   passkey page; the grant is checked again on every use
             sandbox     separate macOS account, Seatbelt profile, no network, no keys
             real_data   runner-only retrieval of public datasets: listed hosts, caps, license, checksums
```

Details, the design decisions behind each piece and how to add a workflow: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Safety and control

- **Spending:** nothing paid runs without a grant. A grant names the models, a dollar ceiling, a call count, an expiry
  and either the companies or a maximum number of them, plus a hash of the enforcement code: change that code and
  the grant stops working. Every call is reserved in a local ledger before it is sent.
- **Approval:** I approve a grant once with a passkey on a local page (Touch ID on the Mac, or Face ID on my phone
  over my private Tailscale network). Inside it, routine steps, retries and repairs run without asking.
- **Isolation:** generated code runs as `_arcexec`, a hidden account that cannot enter my home folder, under a
  Seatbelt profile with no network, no keychain and no Apple Events. `exec-user/isolation_check.py` proves it with
  controls. API keys are read only by the runner; each answer is checked for an echo of the key used for that call
  before it is saved.
- **Review:** hidden acceptance tests never reach the model that writes the code. In the pipeline, the final reviewer
  is never from a provider that wrote the project's code, and a repair is undone if it breaks a test, or makes a
  failing test pass or removes it by editing a test file no finding blamed. Standalone builds use the reviewer the
  run names.
- **Outside actions:** Arcturus calls model APIs and public sources on its own. It never sends an email, submits an
  application, posts or deploys; it writes drafts and I act.
- **The Mac:** new builds start only while free memory and load stay within set limits.

## Configure

Models per step, reserve lines and concurrency live in `routing.json`, read before every step, so edits apply at
once:

```json
"reserve": {"max": {"five_hour": 80, "seven_day": 75}, "codex": {"five_hour": 80, "seven_day": 95}},
"steps": {
  "decide": ["max:opus", "claude-sonnet-5-5", "gpt-6-sol"],
  "build": ["deepseek-flash", "deepseek-v4-pro", "gpt-6-sol", "claude-sonnet-5-5"],
  "final_review": ["codex", "gpt-6-sol", "claude-sonnet-5-5"]
}
```

A build is a `run.json`: the spec, which paths the model may write, the hidden test folder with its hashes, the
builder and reviewer models, the number of repairs and a budget. Then:

```sh
python3 runner/build.py RUN grant --ceiling 4 --calls 300 --hours 24   # prints the approval; Touch ID
python3 runner/build.py RUN run --arms json                            # status in RUN/status.html
python3 runner/build.py RUN pause|resume|stop|revoke|report
```

## Built with Arcturus

Three projects, each showing a different part of the system. Each row says what Arcturus did and what a person did.

| Project | What it shows | How it was built | Verified outcome |
|---|---|---|---|
| [**Tracebench**](https://github.com/yashgix/tracebench) · [page](https://yashgix.github.io/tracebench/) | Model orchestration, benchmarking, controlled execution | Milestones 1-2 generated by the build loop (DeepSeek under a grant: the "Arcturus builder" commits), milestone 2 finished with labelled manual corrections; milestones 3-4 by Claude Code with Codex reviews. Every live model run went through `evaluate.py` and the broker | 12 incidents × 3 models, 220 calls, $0.22; each fix judged by hidden checks and a traffic replay; CI green |
| [**Salus Bridge**](https://github.com/yashgix/salus-bridge) · [page](https://yashgix.github.io/salus-bridge/artifact/) | Supervised multi-agent development, sandboxing, protected acceptance tests | Built through the first coordinator: a restricted builder agent on a local task board, with a protected type check and acceptance tests | A trusted execution boundary for agent tool calls (TypeScript): 10 of 10 safety invariants held, against 3 of 10 for a deliberately flawed integration (10 scenarios × 30 seeded runs) |
| [**Paradev CI Recovery**](https://yashgix.github.io/paradev-ci-recovery/) | Engineering inside an existing open-source codebase, independent review | Supervised workflow: Claude Code as lead developer, Codex attacking each milestone (15 NO-GO rounds before GO), tracked in Arcturus's shared records. Not built by the pipeline, which cannot yet do this kind of work on its own | Live on GitHub: failed CI to passing CI in under 3.5 minutes with one human review. Routing fix: 11 of 11 tests, 10 runs in a row, on Postgres. **Proposed contribution** on [issue #7522](https://github.com/ParadevAI/Paradev/issues/7522): pull request prepared, not opened or merged |

**See one run in full:** [docs/demo/](docs/demo/README.md) walks through Tracebench milestone 2 as it happened: the
plan, the build, the sandboxed tests, the gate refusing a near miss, the hand fix and the independent review, with
the run's own report and ledger as evidence.

**Earlier pipeline experiments.** Between 7 and 9 Nov the job-search pipeline built 11 small company-specific
prototypes unattended. All passed hidden acceptance tests and an independent review, and each needed a final hand
fix, but they looked alike (synthetic data, a score, a report), so none is published. That led to the four-question
gate and real-data retrieval; in the next run the pipeline chose stronger projects (a real Docker environment, a
browser worker, a FastAPI service) and held three of them because the sandbox could not yet run them. That gap is
the current work.

**How the pipeline works, as one example of a workflow:** it reads public job boards (Ashby, Greenhouse, Lever, Gem,
Workable, Recruitee, Rippling, Pinpoint, JazzHR), Hacker News job threads and VC portfolios; ranks by role, freshness
and visa sponsorship evidence; researches each company; decides with four questions whether a project is worth
building (why this company, why this project over the alternatives, why this implementation, what checkable result
it proves); builds and reviews it; and writes interview notes, an application packet and an outreach draft.

## Not built yet

- Builds in each project's own stack: Python packages, local services in tests, browser tests, TypeScript and
  multi-service Docker. Each counts only when a real example runs through the sandbox.
- Workflows defined in configuration; today a new workflow is a Python module on the core.
- Recovery that re-plans a weak idea or a broken environment, beyond code, test and spec repairs.
- Integrations with personal tools (email, calendar, notes, reminders) and one main agent as my single channel that
  delegates, has agents check each other and asks me only for decisions.
- A fast, tested setup for take-home assignments and live coding interviews.

## How it was built

With coding agents, which was also the point: to get fast at leading them. Codex wrote the first coordinator and
the first job search; Claude Code then took over as lead developer, with Codex as the independent reviewer and
ChatGPT for planning reviews. All of them coordinate through plain files (instructions, decisions, an add-only work
log), so any tool or account can pick up the work. I set the direction and approve every phase and outside action.

## Setup and tests

Needs macOS, Python 3.14 and `pip install ruff==0.17.4`. The grant tests sign with OpenSSH's `ssh-keygen`, which
macOS ships.

```sh
make lint            # ruff check and format check
make test            # portable suites, no setup needed
make test-sandbox    # also the build, evaluation and approval suites (execution account needed)
```

The execution account is a system change: read `exec-user/README.md` first. `setup.sh` is written for one owner
account (`OWNER` at its top) and needs `sudo`; `isolation_check.py` then creates the job area and proves the
boundary. Run `undo.sh` only to remove an install that `setup.sh` completed, with no Arcturus work running; it
refuses anything else, and if it stops partway, the steps it already finished are not rolled back. No test makes a paid call.

Live runs need API keys in `~/.arcturus-api-credentials/` and an approved grant. `pipeline.py RUN schedule` installs
two user launchd jobs (discovery daily at 07:00, the runner hourly, each kept awake with `caffeinate`), replacing any
earlier ones; `pipeline.py RUN unschedule` removes them.

## Repository layout

```
runner/      core (workflow, llm, routing, grant, approvals, sandbox, real data) and the workflows
jobsearch/   job radar: board readers, ranking, freshness, visa evidence, registry
exec-user/   setup, launcher, isolation check and undo for the execution account
bin/         two helpers of the first coordinator (runner/arc.py)
docs/        architecture, design decisions, and a real run as a demo with its evidence
tests/       unit and integration tests (fake models; no paid calls)
```

## Limits

- One person, one Mac (macOS Seatbelt, launchd, Touch ID). Not a framework or a hosted service.
- The approval page runs as my own user; same-user processes are trusted.
- Research reads only public sources; some (YC's own pages, LinkedIn) forbid automated reading and stay manual.
- `runner/arc.py`, `engineering.py` and `workers.py` come from a first coordinator built on Paperclip. The pipeline
  still uses parts of them; their own test suites need that pilot setup, which is not included.
