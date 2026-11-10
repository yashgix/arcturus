# Architecture

Arcturus has two layers: a small core that every workflow shares, and the workflows built on it. The core exists to
make three things true for any workflow: no model call happens outside an approved budget, generated code runs with
explicit file and network restrictions and without access to API keys, and a step that finished is reused after a restart instead of
being paid for again. (A crash after a call is paid but before its checkpoint is written can repeat that one call;
the ledger still counts both.)

## Core

| Module | Job | Why it is built this way |
|---|---|---|
| `workflow.py` | Base class: grant, ledger, keys, status page, and `step()`, one checkpointed model step with bounded attempts and feedback | A crash or restart resumes from the last finished step; an answer that fails its schema or check is retried with the problem named, a bounded number of times |
| `llm.py` | `call()`: one granted, tool-free request. Build it, reserve its cost, send once, account, classify the answer | Every provider goes through one function, so spending and credential checks can't be skipped by a new workflow |
| `providers.py` | Request shapes and answer decoding per provider | Kept outside the hashed enforcement code, so a format fix needs no new grant |
| `routing.py`, `subscriptions.py`, `routing.json` | An ordered model list per step (a configured preference); a subscription in the list is used while its live usage is under a reserve line, else the next entry | Uses plans I already pay for without exhausting them, and never stops on one provider's limit. Bulk steps list only APIs. The file is re-read before every step |
| `grant.py` | A signed grant (models, prices, dollar and call ceilings, scope, expiry, enforcement-code hash) and a SQLite ledger | One approval covers a whole run; the hash means weakening the checks voids the approval |
| `approve.py`, `passkey.py` | A local page that shows the grant in plain words and signs it with a passkey | Touch ID is faster and harder to misuse than a terminal signature; Face ID on the phone works over Tailscale only |
| `sandbox.py`, `exec-user/` | Runs code as `_arcexec` under Seatbelt: no network but one loopback port, no home folder, writes only to named paths | Native to macOS, no container overhead; containers come later for multi-service projects |
| `real_data.py` | Runner-only retrieval of public datasets from listed hosts, with caps, the license quoted and checksums | Projects get real data while builders stay offline |
| `gateway.py`, `broker.py` | Model access for an agent that runs inside the sandbox: the agent gets a loopback port and a one-run token, never a key | Lets a sandboxed agent think with a model while every call is still granted and logged |

## Workflows on the core

- **Build** (`build.py`): `run.json` names the spec, the paths the model may write, the files it must produce, the
  hidden test folder with hashes, the builder and reviewer models and the repairs allowed. Loop: generate files →
  own and hidden tests in the sandbox → independent review → bounded repair. Test output never leaves the Mac as
  text; the model learns only pass, fail and short messages. A second builder, an OpenCode agent inside the sandbox
  through the gateway, exists but the pipeline uses the first.
- **Research** (`dossier.py`, `evidence.py`, `research_sources.py`): each subject × provider lane extracts quotes from
  captured sources, verifies them locally, writes findings with citations, proposes ideas and has a second provider
  challenge them (a second model; routing decides whether it is another provider).
- **Evaluate** (`evaluate.py`, `broker.py`): an agent under test runs in the sandbox against a suite; the broker makes
  each model call; a verifier pinned by hash replays the broker's transcript and must rebuild the agent's report byte
  for byte, or the run is invalid.
- **Pipeline** (`pipeline.py`, `pipeline_steps.py`): a persistent SQLite queue that moves many subjects through
  research, decide, spec, build, review and drafts at once, with concurrency limited by free memory and load, a
  launchd schedule, and recovery by cause (code, test or spec) within attempts and a per-subject budget.

## Adding a workflow

A new workflow is a Python module, not configuration (yet):

1. A run folder holds `run.json` (the workflow's own settings) and the grant drafted for it (`grant.py`: models,
   ceilings, calls, operations). `Workflow(root)` loads both, verifies the approval and opens the ledger.
2. Subclass `workflow.Workflow`; set `system` (the fixed instructions) and call `self.step(subject, provider, name,
   model, packet, schema, check)` for each model step. `schema` is a JSON schema (the subset `workflow.mismatch`
   checks: types, objects with exactly the declared keys, enums, string lengths, item counts, number ranges); `check` returns problems to feed back on the next attempt.
3. `step()` takes an explicit model. To pick it from `routing.json` instead, use a `routing.Router` the way the
   pipeline's `Steps.ask` does: try each candidate for the step, fall back down the list.
4. Hold `self.lock()` for the run, and send anything that executes generated code through `sandbox.run` with explicit
   read and write paths.
5. Write tests with a fake connection (see `tests/test_dossier.py`); no test makes a paid call.

Lanes and the ledger are keyed by subject and provider. They are named "company" in the code because the first
workflows were about companies.

## Decisions worth knowing

- **One budget, not per-call prompts.** Approving each call stalls unattended work; no limit risks money. A grant
  with a ledger is both.
- **The pipeline's final reviewer comes from a provider that wrote none of the project's code.** Models from one
  family tend to miss the same things. Standalone builds use their configured reviewer; in-loop reviews do not
  carry this guarantee.
- **Hidden tests, protected by hash.** A builder that can see the acceptance tests can write to them.
- **Plain files for state.** Run folders hold `run.json`, the ledger, checkpoints and status pages; anyone can read
  what happened, and a restart needs nothing but the folder.
- **Measured before scaled.** Concurrency, prices and model choice were set from real runs (ledgers, a builder
  benchmark), not guessed.
