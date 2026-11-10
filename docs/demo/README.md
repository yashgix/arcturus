# A real run, step by step: Tracebench milestone 2 (6 Nov 2026)

One build loop run, start to finish, as it happened: what the agents did, what the gates caught, where a human
stepped in. The code it produced is public, so the outcome can be checked in
[Tracebench's history](https://github.com/yashgix/tracebench/commits/main).

Where each fact comes from:
- **[E]** the evidence files here, copied from the run without paths or ids: the acceptance criteria
  ([m2-acceptance.md](evidence/m2-acceptance.md)), the run's report ([m2-report.json](evidence/m2-report.json)) and
  its ledger ([m2-calls.json](evidence/m2-calls.json)); checksums in [SHA256SUMS](evidence/SHA256SUMS).
- **[C]** how the runner works: the code in this repository.
- **[H]** Tracebench's public commit history.
- **[R]** the project records written at the time; not in the evidence files.

**The task [H].** Extend the benchmark's first milestone (an incident simulator) with milestone 2: new fault types, a
suite runner and Markdown reports, from a written spec.

## 1. Acceptance fixed before any money was spent [E]
- 77 hidden acceptance tests (42 from milestone 1, 35 new) that the builder never sees.
- The tests were themselves tested: a reference solution passes 77 of 77, and they catch 20 of 20 planted bugs.
- A rehearsal with a fake model returning the reference went through the whole loop and was accepted.
- Accepted only if: every own test passes, hidden 77 of 77, a final review with no high or medium finding, the given
  fixtures untouched, and the suite's output identical on two runs.

## 2. One grant [E] [C]
Two models (DeepSeek Flash builds, DeepSeek V4 Pro reviews), a $2.00 ceiling and 40 calls; I approved the grant
before the run [R]. The runner reserves every call in the ledger before sending it and runs every test job as the execution account
with no network.

## 3. The run: 48.8 minutes, 17 calls, $1.245 [E]
| Minute | Step | What the ledger and report record |
|---|---|---|
| 0.0 | plan | Answer cut off at the output limit |
| 0.7 | plan | Answer invalid (failed its checks); the runner retries with the problems named [C] |
| 1.0 | plan | Answer received |
| 1.5-13.6 | build 1-8 | Eight build calls received |
| 13.6 | review 0 | First answer cut off, then received. Round 0: own tests 262/263, hidden 75/77; findings 1 high, 1 medium, 1 low |
| 32.5 | repair 1, review 1 | Round 1: own 262/263, hidden 75/77; findings 1 medium |
| 43.6 | repair 2, review 2 | Round 2: own 263/263, hidden 75/77; findings 1 high, 1 medium |
| 48.8 | end | Two repairs used. **Not accepted.** The gate held |

The report's inventory: 27 files (including the two given fixtures), 1,120 source lines and
2,792 test lines as the report counts them. Builder calls cost $0.37, reviewer calls $0.87.

What the failures were [R]: both hidden failures were Markdown layout, one where the generated rows broke milestone
1's format, one where the spec itself was unclear. The reviewer's medium finding, an "unhandled traceback" on invalid
UTF-8, was half right: the error was caught, but with the wrong message. Earlier that day this reviewer had found 2
of 3 defects planted in a seeded copy and missed deleted tests: one reason a build needs the hidden tests as well as
the review to be accepted.

## 4. Human decision [R] [H]
I chose a narrow, labelled fix instead of another paid round: clarify the unclear spec section, and fix the two
layout cases and the malformed-encoding message by hand. Claude Code made these fixes, outside the build loop and
with no paid calls. The builder's own result stays in the history as "final candidate as built (not accepted)"
(`d9c9334`); the fixes are separate commits titled "Manual correction" (`7df628b`, `227e379`). Claude Code re-ran
the tests as the execution account.

## 5. Independent review [R] [H]
Codex reviewed the milestone from the code and found two real problems the tests had missed: a scenario file was
hashed and then read again (so a file swapped in between would be evaluated under the old hash), and absolute
scenario paths were accepted. Claude Code fixed both, again outside the build loop, each with a regression test
(`1816277`, `2f34786`): own tests 267/267, hidden 77/77, suite output byte-identical to before. Codex then gave GO,
and Claude Code merged the milestone on my decision (`58752fa`).

## 6. What changed afterwards
- The in-loop reviewer here came from the builder's provider, and the outside review found what it missed [E] [R].
  Final reviews in the pipeline now never come from a provider that wrote the code [C].
- Cut-off answers were common in this run (plan, review) [E]. Output limits are now set per model, and a cut-off
  answer is never retried unchanged [C].

## What this shows, and what it doesn't
A summary of the sections above. It shows the loop working as designed: acceptance fixed and tested in advance,
metered calls, sandboxed tests,
retries, a gate that refused a near miss, and an outside reviewer catching what an in-loop one missed. It is not a
fully autonomous run: finishing the milestone took my decision, hand fixes by Claude Code and an independent review.
