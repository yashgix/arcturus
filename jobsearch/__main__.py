"""CLI for fixture and supervised live discovery, shortlist and selection."""

import argparse
import sqlite3
import sys
from contextlib import closing
from datetime import date, time
from pathlib import Path
from zoneinfo import ZoneInfoNotFoundError

from . import dashboard
from .ashby import Ashby, Board, decode, read_bounded
from .live import ALLOWED_BOARDS, DEFAULT_PREVIEW_TTL, discover as discover_live
from .ranking import Profile, rank
from .schedule import Cadence
from .store import Store, utcnow

FIXTURES = Path(__file__).with_name("fixtures")


def config(path):
    with path.open("rb") as stream:
        return decode(read_bounded(stream))


def ingest(store, boards, fixture_dir, slot):
    adapter = Ashby(boards)
    failed = False
    for board in boards:
        token = store.begin(slot, "ashby", board.slug, utcnow())
        if token is None:
            continue
        try:
            with (fixture_dir / f"{board.slug}.json").open("rb") as stream:
                jobs = adapter.fixture(board.slug, read_bounded(stream))
        except (OSError, ValueError) as exc:
            store.fail(token, type(exc).__name__, utcnow())
            print(f"{board.slug}: fixture unreadable or invalid ({type(exc).__name__})", file=sys.stderr)
            failed = True
        else:
            status = store.complete(token, board, jobs, utcnow())
            if status == "superseded":
                print(f"{board.slug}: attempt superseded by another invocation", file=sys.stderr)
                failed = True
    return int(failed)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--profile", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    discover = commands.add_parser("ingest")
    slots = discover.add_mutually_exclusive_group(required=True)
    slots.add_argument("--slot")
    slots.add_argument("--cadence", type=Path, help="calculate the latest due slot for this invocation")
    discover.add_argument("--boards", type=Path, default=FIXTURES / "boards.json")
    discover.add_argument("--fixtures", type=Path, default=FIXTURES)
    live = commands.add_parser("discover-live", help="fetch once, preview and ask before applying")
    live.add_argument("--board", choices=sorted(ALLOWED_BOARDS), required=True)
    live.add_argument(
        "--preview-ttl",
        type=int,
        default=DEFAULT_PREVIEW_TTL,
        help="approval window in seconds after the fetch (1–300)",
    )
    inbox = commands.add_parser("inbox")
    inbox.add_argument("--all", action="store_true", help="include older qualifying jobs")
    inbox.add_argument("--choose", action="store_true", help="select one numbered job interactively")
    inbox.add_argument("--html", type=Path, help="write a local HTML preview")
    for action in ("select", "deselect"):
        commands.add_parser(action).add_argument("job_id")
    args = parser.parse_args(argv)
    try:
        if args.command == "discover-live":
            return discover_live(args.db, args.board, preview_ttl=args.preview_ttl)
        if args.command == "ingest":
            if args.cadence:
                settings = config(args.cadence)
                if not isinstance(settings, dict) or set(settings) != set(Cadence.__annotations__):
                    raise ValueError("invalid cadence keys")
                settings["anchor"] = date.fromisoformat(settings["anchor"])
                settings["local_time"] = time.fromisoformat(settings["local_time"])
                args.slot = Cadence(**settings).due_slot(utcnow())
                if args.slot is None:
                    print("No due slot.")
                    return 0
            raw = config(args.boards)
            if not isinstance(raw, list) or not raw or len(raw) > 100:
                raise ValueError("board list must contain 1–100 boards")
            boards = [Board(**item) for item in raw]
            if len({board.slug for board in boards}) != len(boards):
                raise ValueError("repeated board")
        if args.command == "inbox":
            if args.html and (args.html.suffix != ".html" or args.html.resolve() == args.db.resolve()):
                raise ValueError("HTML output needs a separate .html path")
        with closing(Store(args.db, live_registry=False if args.command == "ingest" else None)) as store:
            if args.command == "ingest":
                return ingest(store, boards, args.fixtures, args.slot)
            if args.command in ("select", "deselect"):
                changed = store.select(args.job_id, args.command == "select", utcnow())
                print("Selection saved." if changed else "Selection already recorded.")
                return 0
            default_profile = (
                FIXTURES.parent / "live-profile.json" if store.live_registry else FIXTURES / "profile.json"
            )
            profile = Profile.load(config(args.profile or default_profile))
            rank_options = dict(include_older=args.all, sponsorship_informational=store.live_registry)
            selected, available = rank(store.inbox(), profile, utcnow(), **rank_options)
            statuses = store.run_status()
            print(dashboard.terminal(selected, available, statuses))
            if args.choose and available:
                for index, item in enumerate(available, 1):
                    print(f"{index}. {item['posting']['title']} · {item['company']}")
                choice = input("Select a number or press Enter to exit: ").strip()
                if choice:
                    index = int(choice) - 1
                    if not 0 <= index < len(available):
                        raise ValueError("selection out of range")
                    item = available[index]
                    key = (item["source"], item["board"], item["external_id"])
                    store.select(item["id"], True, utcnow(), posting_key=key)
                    print("Selection saved.")
                    selected, available = rank(store.inbox(), profile, utcnow(), **rank_options)
            if args.html:
                dashboard.publish(args.html, dashboard.html(selected, available, statuses))
            return 0
    except (EOFError, OSError, TypeError, ValueError, sqlite3.Error, ZoneInfoNotFoundError) as exc:
        print(f"jobsearch: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
