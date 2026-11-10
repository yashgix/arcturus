# Arcturus Job Search Phase 1

A local, standard-library workflow for ingesting Ashby-format fixtures, maintaining a SQLite registry, and selecting opportunities from an explainable shortlist. Python 3.10+ with SQLite 3.25+ and the system time zone database is required.

## Try the fixture inbox

From the isolated repository root:

```sh
umask 077
mkdir -p jobsearch/.runtime
python3 -B -m jobsearch --db jobsearch/.runtime/demo.sqlite ingest --slot fixture-demo
python3 -B -m jobsearch --db jobsearch/.runtime/demo.sqlite ingest --slot fixture-demo
python3 -B -m jobsearch --db jobsearch/.runtime/demo.sqlite inbox --choose --html jobsearch/.runtime/inbox.html
```

Enter a shortlist number to save a selection or press Enter to exit. The HTML is a read-only local snapshot. Open it as a file or view [the included fixture preview](preview.html). Its posting URLs are synthetic. Explicit `select JOB_ID` and `deselect JOB_ID` commands are also available. `inbox --all` includes older qualifying jobs, still subject to the configured shortlist size. Previously selected jobs have their own section, including selected jobs that later close.

The checked-in board list and search profile are demonstrations. To experiment, copy them into the private runtime directory and pass `ingest --boards PATH --fixtures DIR` or place `--profile PATH` before `inbox`. The source directory expects one `SLUG.json` per board. Use a new slot for each intended snapshot, registering slots in acquisition order. Successful boards in a reused slot are skipped. Failed boards may be retried, and a retry retains its original position in the source order.

A manual invocation can also calculate its due slot with `ingest --cadence jobsearch/fixtures/cadence.json`. The example describes 09:00 America/New_York beginning November 4, 2026. The cadence accepts a time zone, local wall time, anchor date, and day interval. It catches up to the latest due slot after sleep. The first occurrence of a repeated local time wins, and a missing wall time shifts by the daylight-saving gap. There is no automatic trigger.

## Registry behavior

- Source identity is scoped by provider, board, and posting ID. Distinct simultaneously active IDs remain separate. Matching normalized company and posting text across boards produces possible-duplicate labels. A similar replacement can be recorded as a possible repost. Every source posting retains its own ID through closure and return. A selected original stays pinned to its specific posting and a replacement appears separately.
- Posting history records new, changed, missing, returned, and reposted listings. A complete empty fixture snapshot closes that board’s listings. Invalid or explicitly partial data preserves its previous state. Other boards can complete independently. SQLite applies source changes, history, and successful attempt status in one transaction.
- A slot receives a stable generation on first registration. A later retry cannot overwrite a newer successful generation. Attempt IDs fence concurrent writers within each slot. Replay does not extend freshness. New roles, material field changes, returns, and reposts do.
- Ranking uses title terms, title exclusions, skills, startup designation, explicit location matches, remote workplace, publication age, registry freshness, and sponsorship wording. Explicit H-1B, generic support, restrictions, ambiguity, and conflicting wording are separate signals. Generic sponsorship supplies no transfer evidence. The inbox displays the last known source publication date, first discovery, and last material edit separately. The first discovery date is the initial baseline for material change. Remote alone does not establish US eligibility.
- The event contract is a SQLite outbox. The `events` table has an increasing ID, canonical job ID, kind (`job.selected` or `job.deselected`), and UTC creation time. A selection, its source posting pin, and its event commit together. Schema v3 separates historically shared posting IDs in one transaction. Shared legacy IDs remain available for selection history and deselection, with future selections using the distinct posting IDs. Legacy selections with multiple possible original links are flagged for review and suppress the link until the operator deselects and selects the intended posting. A future consumer can read events after a persisted cursor and use the event ID for idempotency.
- The supervised CLI uses `Store.complete(..., live=True)` in a live-only registry. Losing at least half of the active IDs quarantines the whole snapshot and preserves the last successful state. The same missing IDs must be observed in a distinct, newer slot before closures apply. Retrying the quarantined slot does not confirm it, and a healthy verified snapshot clears the pending evidence. The fixture ingestion command accepts local data.


## Independent review

1. Confirm the branch and baseline with `git branch --show-current` and `git rev-parse HEAD`. Use `git --no-optional-locks status --short --untracked-files=all` and `git --no-optional-locks diff HEAD --exit-code` to check scope. The Phase 1 files are untracked. For a file-by-file patch, run `git diff --no-index -- /dev/null PATH` for each listed path. Exit code 1 denotes differences.
2. Run `python3 -B -m unittest discover -s jobsearch/tests -v`.
3. Exercise the demo twice against one slot and reopen the inbox. Select the same job twice using its ID. Inspect `jobs`, `postings`, `history`, `attempts`, `selections`, and `events` in the demo database. Confirm no extra job, attempt, or selection event appeared. Inspect `PRAGMA integrity_check` and `PRAGMA foreign_key_check`.
4. Review the fail-closed parsing, source allowlist, stale write fencing, identity heuristics, and event transaction. Exercise the supplied failure, real process-kill, concurrency, and publish tests. Verify selection is the only operator action and the HTML performs no background requests.
5. Review real board names and filters separately before granting live smoke-test authorization. Keep scheduling disabled pending independent review and a permitted live smoke test.

## Review limitations

- Source coverage is Ashby only. The network path requires explicit opt-in and its automated tests use offline substitutes. An opted-in call uses a short-lived worker with a bounded response. The parent terminates and reaps the worker on timeout and rejects late results, covering DNS, TLS, headers and body even when individual socket operations make progress. OS process creation and teardown can add latency outside the subprocess timeout. The worker is a timeout boundary. It does not provide an OS sandbox. Completeness of a well-formed feed with omitted records depends on the upstream provider.
- Exact normalized matching can miss paraphrased or relocated reposts. Similar sequential openings can be flagged as possible reposts while retaining separate IDs. No fuzzy matching or operator merge UI is included. The freshest active source representation supplies the displayed details. The report renders current database state on demand. Removing a board from the ingestion list does not expire its prior records. If publication fails after ingestion, rerun the inbox command to regenerate it.
- Role and H-1B heuristics are provisional. The profile contains illustrative role, seniority, location, and skill terms. The live profile is provisional and the supervised allowlist contains Navigate AI. A future scheduler and downstream event consumer require separate review.
- The network contract follows the [Ashby public posting API documentation](https://developers.ashbyhq.com/docs/public-job-posting-api). No live posting requests were used to build the preview or test suite.

## Supervised live discovery

After separate authorization for a single request, run this from an interactive terminal in the repository root:

```sh
python3 -B -m jobsearch --db jobsearch/.runtime/navigate-ai-supervised.sqlite discover-live --board navigate-ai
```

The database must be new or previously designated for live discovery. Use a separate path from the fixture registry. The command records an attempt, fetches once from the allowlisted Navigate AI Ashby endpoint, and previews the resulting changes on an in-memory copy. Type `apply` to record that observation within 120 seconds of the fetch. Use `--preview-ttl SECONDS` to set a window between 1 and 300 seconds. Expiration is checked after acquiring the database write lock. An expired preview leaves the existing attempt as an unapplied audit record and writes no snapshot data. Any other response cancels it. If an accepted or quarantined observation changes the preview before approval, the apply is refused. Each invocation is one foreground observation with its own slot.

After an applied observation, render the inbox offline:

```sh
python3 -B -m jobsearch --db jobsearch/.runtime/navigate-ai-supervised.sqlite inbox --html jobsearch/.runtime/navigate-ai-supervised.html
```

The live inbox defaults to the provisional `jobsearch/live-profile.json`. Supply `--profile PATH` before `inbox` to use another profile. Live ranking treats sponsorship as informational. Publication, first discovery, last successful observation, and material change appear separately in UTC. Initial discovery sets the baseline for material change. The freshness reason can reflect first discovery even for an older publication. The preview shows publication-only corrections, and a backwards publication correction preserves the separate high-water mark used to detect reposts. Successful fetch time and apply time are recorded separately.

A first miss retains the posting and marks it unverified. A subsequent independent, accepted observation must also omit it before closure. A snapshot omitting at least half the active IDs is quarantined as a whole. A newer valid observation with the same missing ID set can confirm the quarantine. A validated sighting clears a prior pending absence, including in a quarantined snapshot. Quarantined omissions do not create per-posting closure evidence. Failed or partial responses preserve listings and never confirm closure. A quarantined observation also fences older retries. Slot generations and recorded fetch times prevent observations from moving backwards.

The worker uses fixed HTTPS, rejects redirects, caps the response, and starts with an empty environment. The parent enforces a 15-second subprocess deadline, and the worker also arms a Unix alarm. The parent defers Ctrl-C and SIGTERM during spawn and cleanup, then terminates and reaps the worker before reporting an interruption. SIGKILL bypasses parent cleanup and can leave a running audit attempt or orphan a worker. The worker alarm provides a backstop once the worker has started far enough to arm it. Process creation and cleanup can extend wall time beyond the deadline. The child runs with the user's OS permissions. The in-memory preview copies the live database and requires memory proportional to its size. The workflow has no retry loop or scheduling entry point.

If the operator's saved response is present at `jobsearch/.runtime/navigate-ai-live.json`, the offline test suite uses it through a mocked fetch. Its replay and rendering checks skip on clean checkouts without that private runtime file.
