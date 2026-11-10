"""Self-contained HTML preview and terminal inbox rendering."""

import os
from html import escape
from pathlib import Path
from tempfile import NamedTemporaryFile


def posting_dates(item):
    publication = item["posting"]["published"]
    return (
        f"Last published: {publication or 'unknown'} · "
        f"First discovered: {item['first_seen']} · "
        f"Last successfully observed: {item['last_seen']} · "
        f"Last material change: {item['material_changed_at']}"
    )


def listing_state(item, unverified_boards):
    if not item["active"]:
        return "Closed"
    if item["pending_absence"] or (item["source"], item["board"]) in unverified_boards:
        return "Retained · current status unverified"
    return ""


def unverified_sources(statuses):
    return {(row["source"], row["board"]) for row in statuses if row["status"] != "complete"}


def terminal(selected, available, statuses):
    unverified = unverified_sources(statuses)
    lines = ["Job inbox", ""]
    for label, items in (("Selected", selected), ("Shortlist", available)):
        lines.append(label)
        if not items:
            lines.append("  (empty)")
        for item in items:
            posting = item["posting"]
            state = listing_state(item, unverified)
            suffix = f" [{state}]" if state else ""
            link = "Selection needs review: original posting is unknown" if item["selection_review"] else posting["url"]
            lines.extend(
                [
                    f"  {posting['title']} · {item['company']} · {item['score']}{suffix}",
                    f"  {item['id']}  {link}",
                    f"  {posting_dates(item)}",
                    f"  {' | '.join(item['reasons'])}",
                    "",
                ]
            )
    lines.append("Source status")
    for row in statuses:
        lines.append(
            f"  {row['board']} · {row['slot']} · {row['status']} · "
            f"Last successful observation: {row['last_success'] or 'none'}"
            + (" · retained listings may be stale" if row["status"] != "complete" else "")
        )
    return "\n".join(lines)


def html(selected, available, statuses):
    unverified = unverified_sources(statuses)

    def section(title, items):
        cards = []
        for item in items:
            posting = item["posting"]
            state = listing_state(item, unverified)
            suffix = f" · {state}" if state else ""
            reasons = "".join(f"<li>{escape(reason)}</li>" for reason in item["reasons"])
            heading = escape(posting["title"])
            review = ""
            if item["selection_review"]:
                review = "<p>Selection needs review: original posting is unknown.</p>"
            else:
                heading = f'<a href="{escape(posting["url"], quote=True)}" rel="noreferrer">{heading}</a>'
            cards.append(
                f'<article><h3>{heading}</h3>{review}'
                f'<p>{escape(item["company"])} · {escape(posting["location"])} · {item["score"]}{suffix}</p>'
                f'<p>{escape(posting_dates(item))}</p><ul>{reasons}</ul><code>{escape(item["id"])}</code></article>'
            )
        return f"<section><h2>{title}</h2>{''.join(cards) or '<p>None</p>'}</section>"

    sources = "".join(
        f"<li>{escape(row['board'])} · {escape(row['slot'])} · {escape(row['status'])} "
        f"· Last successful observation: {escape(row['last_success'] or 'none')}"
        + (" · retained listings may be stale" if row["status"] != "complete" else "")
        + "</li>"
        for row in statuses
    )
    return (
        """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Arcturus job inbox</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;background:#f2f5f4;color:#162a26;max-width:58rem;margin:auto;padding:2rem 1rem}
h1{font-size:2.5rem;margin-bottom:0} h3{margin:0} a{color:#005d54} article{background:white;
border:1px solid #c8d7d2;border-radius:.75rem;padding:1rem;margin-bottom:1rem} code{overflow-wrap:anywhere}
</style>
<h1>Arcturus job inbox</h1><p>Rule-ranked local shortlist. Use the terminal inbox to save selections.</p>
"""
        + section("Selected", selected)
        + section("Shortlist", available)
        + (f"<section><h2>Source status</h2><ul>{sources}</ul></section></html>")
    )


def publish(path, content):
    path = Path(path)
    temporary = None
    try:
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
