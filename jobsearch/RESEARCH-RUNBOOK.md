# Arcturus research MVP

This release is for offline rehearsal in a foreground terminal. It uses one dedicated SQLite registry, local Ashby fixtures, synthetic candidate evidence, and prerecorded model responses. The supervised discovery CLI remains a separate operator workflow. Research packets are drafts for review.

## Run the synthetic demo

From the repository root, choose a new path under the ignored runtime directory:

```sh
mkdir -p jobsearch/.runtime
research_db=jobsearch/.runtime/research-demo.sqlite
research_fixtures=jobsearch/fixtures/research
python3 -B -m jobsearch.research --db "$research_db" init
python3 -B -m jobsearch.research --db "$research_db" resume
python3 -B -m jobsearch.research --db "$research_db" run \
  --config "$research_fixtures/config.json" --fixtures "$research_fixtures" \
  --candidate "$research_fixtures/candidate.json" --responses "$research_fixtures/responses.json"
python3 -B -m jobsearch.research --db "$research_db" report --html jobsearch/.runtime/research-demo.html
```

Use a different registry filename to repeat a fresh demo. The supplied cadence begins November 3, 2026 in New York. One due observation of the synthetic Backend Engineer posting should produce one draft, technical fit 70, seniority fit 40, and zero actual model cost. A second tick in the same slot reuses the observation and completed packet. The sample posting URL is synthetic.

Add `--watch` to the run command for an attended offline polling session. Use `pause` or `stop` with the same `--db` from another terminal to stop claiming work and exit the poller. A local operation already in progress can finish. Ctrl-C exits the foreground process. To restart, use `resume` if paused or stopped, then run again with the same inputs and registry. `report` opens SQLite read-only and replaces the HTML atomically.

## Inputs and durable state

- The config chooses a subset of the supervised Ashby allowlist and a local calendar cadence. A due slot is persisted per board. The next tick after sleep uses the most recent due slot. Failed source reads are recorded and the next scheduled slot can try again. On startup the coordinator marks abandoned discovery attempts interrupted. An interrupted attempt can be retried in the same due slot. A Stop received during a source read prevents that snapshot from being applied. Local observations use the existing posting identity, history, absence confirmation and quarantine rules.
- The candidate schema is version 1. It has a revision, mode, local source references, resume variants referencing claim IDs, and explicit location constraints. Each claim includes verification state, technologies, metrics, and source reference IDs. Unverified or unreferenced claims are excluded from model inputs. The demo shows the shape with fictional SWE and AI variants. Source document names and locators stay in the input profile. This release executes synthetic mode only.
- The research queue is keyed by canonical job and input version. It uses a single foreground coordinator lock, transactional claims, a 90-second recovery lease, and exponential retry delays starting at 30 seconds. A restarted process recovers expired claims. An expired claim cannot publish a late result. A later posting or candidate version can create a separate packet. Queued work is deferred while the posting is unverified and superseded after confirmed closure. The current draft follows the version selected by the coordinator, including when a posting returns to an earlier version. Older registries acquire the new queue fields on the next writable coordinator command. The read-only report treats pre-upgrade packets as historical.
- The DeepSeek adapter builds and validates chat-completion messages through an injected transport. The CLI wires only a local fixture transport. Output references must resolve to supplied evidence and approved fact IDs. Scores for technical and seniority fit are separate. A draft can still make an unsupported inference despite valid citations, so review the referenced evidence.
- The daily UTC ledger reserves the configured maximum cost before each call and enforces both a request count and spending cap. Unknown or interrupted receipts retain the reserve for the day. An unusable model response still records its known charge. A malformed receipt pauses dispatch and retains the reserve. A valid charge above the reserve is recorded in full and also pauses dispatch. The demo caps are synthetic and expressed in millionths of a US dollar. Model errors use generic audit messages.
- Optional `--evidence PATH` accepts a JSON object keyed by `board/external_id`. Each value is a list of evidence records with `kind`, HTTPS `url`, ISO `date`, and `excerpt`. Supported kinds are `company`, `role`, `verified_role_restriction`, and `historical_sponsorship`. The operator attests attribution, date and role applicability. A confirmed restriction requires explicit, role-specific denial wording and evidence dated on or after the posting publication. Conflicting, qualified, or unclear current evidence leaves eligibility unknown and retains the sources. Current role-level support prevents an older denial from being marked confirmed. Historical evidence stays separate. Location matches are based on posting text and the profile constraints.

## Gates for live operation

1. Review the offline code, database recovery, and report. Authorize a narrow live discovery transport for approved boards and independently verify its deadline, cancellation, egress controls, stale snapshot protection, and safe handling of partial responses.
2. Populate and separately approve a candidate profile from the verified SWE and AI resumes and the candidate's own notes. Review evidence handling, outbound fields, retention, and which sources may be used for company and sponsorship research.
3. Verify the real DeepSeek contract, approved model, pricing, token limits, key storage, and usage reconciliation. Implement a narrowly scoped transport with a hard deadline and enforceable maximum charge. Rehearse ambiguous billing and provider failures before authorizing any call.
4. Approve a bounded foreground run on a disposable registry. Review output quality and cost receipts before a separate unattended scheduling decision. A scheduler, automatic external evidence collection, application submission, and outreach are outside this release.


## Minimum separately authorized DeepSeek trial

**NO-GO as of November 4, 2026.** DeepSeek documents two Chat Completions model IDs. Its changelog shows both IDs routing to updated revisions. The published revision names are not documented as accepted immutable request IDs. Chat Completions documents token usage and cache counters, with no authoritative per-request charge in the response. Public prices allow a rate calculation. They do not settle the actual charge on an account. [API contract](https://api-docs.deepseek.com/api/create-chat-completion/) · [Model changes](https://api-docs.deepseek.com/updates/) · [Pricing](https://api-docs.deepseek.com/quick_start/pricing/)

From the repository root, inspect the blocked plan and run the mocked checks:

```sh
python3 -B -m jobsearch.deepseek_trial plan
python3 -B -m unittest discover -s jobsearch/tests -p test_deepseek_trial.py -v
```

For a local mocked envelope, run `python3 -B -m jobsearch.deepseek_trial audit --http-status 200 --response /path/to/mock.json`. The audit outputs allowlisted counters and status fields. It preserves validated usage when the draft is invalid, computes exact integer estimates at both published rate tiers, and leaves actual charge unknown and the reserve held. It never echoes response text. The plan leaves the model field unset. Its **314,650 microdollar** illustrative reserve assumes 1,048,576 input tokens at the peak cache-miss rate and 64 output tokens at the peak output rate, rounded up. This allowance illustrates the ledger math. A live ceiling needs a documented enforceable token bound, a tariff verified for the approved model, and billing reconciliation. [Token accounting](https://api-docs.deepseek.com/quick_start/token_usage/) · [Pricing](https://api-docs.deepseek.com/quick_start/pricing/)

Before a separately authorized trial:

1. Obtain an accepted immutable model ID from DeepSeek. Verify the billing class, exact tariff, enforceable input bound including server-added tokens, and a way to reconcile the specific request to an authoritative charge. Keep the trial closed if any are unavailable.
2. Add a one-shot foreground transport for the fixed TLS endpoint `POST https://api.deepseek.com/chat/completions`. Reuse the supervised worker lifecycle with a 30-second total deadline and kill-and-reap on timeout or cancellation. Reject redirects and alternate hosts, bound the response, disable thinking and streaming, cap output at 64 tokens, and send the fixed synthetic prompt with no tools or resume inputs. Configure zero retries in both the worker and caller.
3. Recompute the ceiling using peak cache-miss input and peak output pricing for the verified token bounds. Show the endpoint, immutable model, caps, and exact ceiling for explicit operator approval. In a fresh disposable registry, durably reserve the full ceiling and consume the single dispatch permit before spawning. A crash or ambiguous receipt consumes the permit and retains the reserve.
4. Only after approval, supply the key to the foreground launcher through a protected process environment or no-echo prompt. Pass it only to the worker for the authorization header. Keep keys out of command arguments, shell history, requests shown to the operator, SQLite, and logs. Restrict worker output to validated numeric usage, the allowed response status, and approved receipt fields. Discard raw provider prose and headers.
5. Run once in a foreground terminal. Confirm worker exit and reconcile the recorded token counters, reported charge, and receipt even if the output fails validation. Treat missing usage or billing as unresolved, retain the full reservation, and stop. Do not retry the trial after an error, cancellation, or timeout.

The current CLI has no live launch command. The transport and durable one-shot authorization are the remaining implementation work once the provider gates above are met.
