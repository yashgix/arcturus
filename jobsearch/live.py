"""One foreground Ashby observation with an operator approval step."""

import json
import signal
import sys
from contextlib import closing
from datetime import timedelta
from uuid import uuid4

from .ashby import Ashby, Board
from .store import Store, utcnow

ALLOWED_BOARDS = {
    "navigate-ai": Board("navigate-ai", "Navigate AI", False),
    "pylon-labs": Board("pylon-labs", "Pylon", False),
    "braintrust": Board("braintrust", "Braintrust", False),
    "decagon": Board("decagon", "Decagon", False),
    "render": Board("render", "Render", False),
    "cognition": Board("cognition", "Cognition", False),
}
SOURCE = "ashby"
DEFAULT_PREVIEW_TTL = 120


def _interrupt(signum, frame):
    raise KeyboardInterrupt


def discover(path, slug, *, preview_ttl=DEFAULT_PREVIEW_TTL):
    board = ALLOWED_BOARDS.get(slug)
    if board is None:
        raise ValueError("board is outside the supervised allowlist")
    if not 1 <= preview_ttl <= 300:
        raise ValueError("preview lifetime must be between 1 and 300 seconds")
    if not sys.stdin.isatty():
        raise ValueError("live discovery requires an interactive terminal")
    previous_handler = signal.signal(signal.SIGTERM, _interrupt)
    try:
        with closing(Store(path, live_registry=True)) as store:
            slot = f"live-{uuid4().hex}"
            token = store.begin(slot, SOURCE, slug, utcnow())
            try:
                jobs = Ashby([board], network_enabled=True).fetch(slug)
                observed = utcnow()
                revision, outcome = preview(store, token, board, jobs, observed)
                if outcome in ("stale", "superseded"):
                    store.fail(token, "superseded preview", utcnow())
                    print("A newer observation exists. Preview discarded.", file=sys.stderr)
                    return 1
                expires = observed + timedelta(seconds=preview_ttl)
                print(f"Preview expires at {expires.isoformat()}.")
                if input("Type apply to record this observation: ").strip() != "apply":
                    store.fail(token, "operator cancelled", utcnow())
                    print("Cancelled. Listings preserved.")
                    return 0
                status = store.complete(
                    token,
                    board,
                    jobs,
                    utcnow(),
                    live=True,
                    expected_revision=revision,
                    observed_at=observed,
                    expires_at=expires,
                )
                print(f"{slug}: {status}")
                return 0 if status in ("complete", "quarantined") else 1
            except (EOFError, KeyboardInterrupt):
                store.fail(token, "operator interrupted", utcnow())
                print("Interrupted. Check source status for any committed result.", file=sys.stderr)
                return 130
            except (OSError, ValueError) as exc:
                store.fail(token, type(exc).__name__, utcnow())
                raise
    finally:
        signal.signal(signal.SIGTERM, previous_handler)


def preview(store, token, board, jobs, observed):
    """Simulate the exact transition on a consistent in-memory copy."""
    with closing(Store(":memory:")) as copy:
        store.db.backup(copy.db)
        revision = copy.observation_revision(SOURCE, board.slug)
        before = _posting_state(copy, board)
        status = copy.complete(token, board, jobs, observed, live=True, observed_at=observed)
        after = _posting_state(copy, board)
        print(f"{board.slug}: {len(jobs)} listed postings received. Proposed result: {status}.")
        if status == "quarantined":
            print("Large shrinkage. All listings will be retained pending confirmation.")
            present = {job["external_id"] for job in jobs}
            for external_id, row in before.items():
                if row["active"] and external_id not in present:
                    print(f"  missing: {json.loads(row['body'])['title']} [{external_id}]")
        kinds = {
            row["external_id"]: row["kind"]
            for row in copy.db.execute("SELECT kind,external_id FROM history WHERE attempt_id=?", (token,))
        }
        refreshed = 0
        for external_id, row in after.items():
            old = before.get(external_id)
            posting = json.loads(row["body"])
            title = posting["title"]
            if old is not None and row["last_seen"] != old["last_seen"]:
                refreshed += 1
            if external_id in kinds:
                print(f"  {kinds[external_id]}: {title} [{external_id}]")
            if old is not None:
                previous = json.loads(old["body"])
                changed = [key for key in sorted(posting) if posting[key] != previous.get(key)]
                for field in ("company", "startup"):
                    if row[field] != old[field]:
                        changed.append(field)
                if changed:
                    print(f"  fields changed: {title} [{external_id}]: {', '.join(changed)}")
                if "published" in changed:
                    print(
                        f"  publication changed: {title} [{external_id}]: "
                        f"{previous['published'] or 'unknown'} -> {posting['published'] or 'unknown'}"
                    )
                if row["publication_high_water"] != old["publication_high_water"]:
                    print(f"  publication high-water mark: {row['publication_high_water']}")
                if old["pending"] and not row["pending"] and row["active"]:
                    print(f"  pending absence cleared: {title} [{external_id}]")
            if row["pending"]:
                print(f"  retained, unverified: {title} [{external_id}]")
            if external_id in kinds or old is not None and row["body"] != old["body"]:
                print(
                    f"    published={posting['published'] or 'unknown'}, first discovered={row['first_seen']}, "
                    f"last observed={row['last_seen']}, material change={row['material_changed_at']}"
                )
        if refreshed:
            print(f"  last observation refreshed for {refreshed} existing postings at {observed.isoformat()}.")
        return revision, status


def _posting_state(store, board):
    return {
        row["external_id"]: row
        for row in store.db.execute(
            """SELECT p.*,j.first_seen,j.material_changed_at,a.generation IS NOT NULL pending
           FROM postings p JOIN jobs j ON p.job_id=j.id
           LEFT JOIN pending_absences a ON (a.source,a.board,a.external_id)=(p.source,p.board,p.external_id)
           WHERE p.source=? AND p.board=? ORDER BY p.external_id""",
            (SOURCE, board.slug),
        )
    }
