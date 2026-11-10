# Milestone 2 acceptance criteria (excerpt)

Written on 6 Nov 2026 before the run (file last changed 12:24; first paid call 12:54). Copied word for word except local paths, helper file names and the grant id, which are removed.

## 2. Milestone 2 build
- Spec: the milestone 1 and 2 specs.
- Builder B (`deepseek-flash`, JSON whole files) extends the existing code (B's accepted milestone-1
  code plus the given `fixtures/` and `suites/`, which are outside the allowed paths). Reviewer `deepseek-v4-pro`,
  spec-by-spec prompt. At most 2 repairs. $2.00 ceiling, 40 calls. Option (b): every test job runs as `_arcexec`.
- Hidden tests: 77 (the 42 milestone-1 tests, one assertion updated for the new fault type, plus 35
  new). The reference passes 77/77 and its own 156 tests; 20 of 20 planted bugs are caught.
  Offline rehearsal with a fake DeepSeek returning the reference: accepted, 77/77, own
  156/156.
- **Accepted** when, on the final candidate: own tests all pass, hidden 77/77, and a final review with no high or
  medium findings. `fixtures/` and `suites/` unchanged. `python3 -m replaykit suite suites/shop-v1.json` gives the
  same bytes twice.
