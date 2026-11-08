"""drafter: the command line.

    drafter feeds fetch [FEED ...] [--since DATE] [--limit N]
    drafter feeds seed FEED --since DATE
    drafter feeds status
    drafter candidates refresh|list|add …
    drafter fill CVE … / drafter propose CVE …
    drafter web [--port N] [--origin URL]
    drafter decisions

Exit codes: 0 fine, 1 a feed failed or needs a look, 2 bad usage, 3 another run
holds the lock.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import logging
import os
import sqlite3
import sys
import time
import unicodedata
import urllib.parse
from pathlib import Path

from drafter import __version__, candidates, decisions, fill, thirdparty, timeutil
from drafter.feeds import CVE_ID, Context, all_feeds, by_name, nvd, run_feeds, run_one, seed_feed
from drafter.feeds.osv import Osv
from drafter.http import Fetcher
from drafter.status import needing_a_look, report
from drafter.store import Store, StoreError


def safe(text: object) -> str:
    """Printable on a terminal: no control or bidi characters from any source."""
    return "".join(
        ch if ch == " " or unicodedata.category(ch)[0] not in "CZ" else "?" for ch in str(text)
    )


def default_home() -> Path:
    if os.environ.get("DRAFTER_HOME"):
        return Path(os.environ["DRAFTER_HOME"])
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "pack-drafter"


def _date(text: str) -> dt.datetime:
    try:
        return dt.datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=dt.UTC)
    except ValueError:
        raise argparse.ArgumentTypeError("use YYYY-MM-DD") from None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="drafter", description="Compromise Checker pack drafter")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--home", type=Path, help="data folder (default: %(default)s)", default=default_home()
    )
    commands = parser.add_subparsers(dest="command", required=True)
    feeds = commands.add_parser("feeds", help="read the public feeds")
    actions = feeds.add_subparsers(dest="action", required=True)

    fetch = actions.add_parser("fetch", help="read what's new in each feed")
    fetch.add_argument("feeds", nargs="*", metavar="FEED", help="default: all")
    fetch.add_argument(
        "--since",
        type=_date,
        help="where a feed read for the first time starts (default: a day ago)",
    )
    fetch.add_argument(
        "--limit",
        type=int,
        default=500,
        help="records fetched one by one, per feed (default: %(default)s)",
    )

    seed = actions.add_parser("seed", help="fill an OSV feed's history from its archive")
    seed.add_argument("feed", metavar="FEED")
    seed.add_argument("--since", type=_date, required=True)

    actions.add_parser("status", help="how each feed is doing")

    cands = commands.add_parser("candidates", help="exploited threats the tool could judge")
    cand_actions = cands.add_subparsers(dest="action", required=True)
    for name, text in (
        ("refresh", "read the vendors' records for signalled CVEs"),
        ("list", "list the candidates"),
    ):
        sub = cand_actions.add_parser(name, help=text)
        window = sub.add_mutually_exclusive_group()
        window.add_argument(
            "--days",
            type=int,
            # refresh looks further back than the list, so older candidates are
            # still re-read weekly
            default=180 if name == "refresh" else 30,
            help="signalled in the last N days (default: %(default)s)",
        )
        window.add_argument("--since", type=_date, help="signalled on or after YYYY-MM-DD")
        if name == "refresh":
            sub.add_argument(
                "--limit",
                type=int,
                default=5000,
                help="vendor records fetched per run (default: %(default)s)",
            )
            sub.add_argument(
                "--reparse",
                action="store_true",
                help="re-read stored records with the current parsers; no fetching",
            )
        if name == "list":
            sub.add_argument(
                "--all", action="store_true", help="also list CVEs not on a supported release"
            )
    add = cand_actions.add_parser("add", help="add a threat by hand, by CVE number")
    add.add_argument("cve")
    add.add_argument("--note", required=True, help="where it came from")

    fill = commands.add_parser("fill", help="draft a pack's packages from vendor data (A.3)")
    fill.add_argument("cves", nargs="+", metavar="CVE")
    fill.add_argument(
        "--binaries",
        nargs="+",
        default=[],
        metavar="GLOB",
        help="the binaries that count for this threat, e.g. '*-fpm' 'libapache2-mod-php*'",
    )
    fill.add_argument("--compare", type=Path, help="a signed PACK.yaml to compare with")
    fill.add_argument(
        "--other-builds",
        choices=["cant_judge", "not_affected"],
        default="cant_judge",
        help="what a build no entry matches reads (default: %(default)s; not_affected"
        " only when the threat is in no build but those listed)",
    )
    fill.add_argument("--out", type=Path, help="write the draft here (default: print it)")
    fill.add_argument(
        "--thirdparty", type=Path, help="a proposals file from `drafter propose`, edited"
    )

    prop = commands.add_parser(
        "propose", help="propose third-party builds (Sury, Remi) for a person to confirm (A.3b)"
    )
    prop.add_argument("cves", nargs="+", metavar="CVE")
    prop.add_argument("--binaries", nargs="+", default=[], metavar="GLOB")
    prop.add_argument("--watch", metavar="CPE", help="the watched product, e.g. php:php")
    prop.add_argument("--out", type=Path, required=True, help="the proposals file to write")

    web = commands.add_parser("web", help="the candidate page, to approve or reject (A.4)")
    web.add_argument("--port", type=int, default=8089, help="on 127.0.0.1 (default: %(default)s)")
    web.add_argument(
        "--origin",
        default="https://packs.localhost:8443",
        help="the address the browser uses, through Caddy (default: %(default)s)",
    )
    web.add_argument(
        "--days", type=int, default=30, help="signalled in the last N days (default: %(default)s)"
    )
    commands.add_parser("decisions", help="every approve and reject, newest first (A.4)")
    return parser


class Locked(Exception):
    pass


def _lock(home: Path):
    handle = open(home / "lock", "w")  # held for the whole run
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise Locked from None
    return handle


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    home: Path = args.home
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    known = by_name()
    if args.command == "web":
        return _web(home, args)
    if args.command == "decisions":
        try:
            store = _reader(home / "drafter.sqlite3")
        except StoreError as exc:
            print(safe(exc), file=sys.stderr)
            return 1
        try:
            return _decisions(store)
        finally:
            store.close()
    if getattr(args, "action", None) in ("list", "status"):
        # Reading needs no lock (SQLite's write-ahead log), so status works mid-seed,
        # and opens read-only, so it never upgrades a store an older install writes.
        try:
            store = _reader(home / "drafter.sqlite3")
        except StoreError as exc:
            print(safe(exc), file=sys.stderr)
            return 1
        try:
            return _candidates_list(store, args) if args.action == "list" else _status(store)
        finally:
            store.close()
    try:
        lock = _lock(home)
    except Locked:
        print("another drafter run is going; try again when it ends", file=sys.stderr)
        return 3
    store = Store(home / "drafter.sqlite3")
    if store.migrated_from == 1:
        # Schema 2 keeps NVD's product names and descriptions; fill them for the
        # CVEs already stored, from the pages already kept (no fetching).
        filled = nvd.reparse_products(store)
        print(f"store upgraded to schema 2: NVD product names filled for {filled} CVE(s)")
    try:
        ctx = Context(
            store=store,
            fetcher=Fetcher(),
            sleep=time.sleep,
            nvd_api_key=os.environ.get("NVD_API_KEY") or None,
            workdir=home / "tmp",
        )
        if args.command == "candidates":
            return _candidates_write(ctx, args)
        if args.command == "fill":
            return _fill(ctx, args)
        if args.command == "propose":
            return _propose(ctx, args)
        if args.action == "fetch":
            unknown = [name for name in args.feeds if name not in known]
            if unknown:
                print(
                    f"unknown feed: {safe(', '.join(unknown))}; known: {', '.join(known)}",
                    file=sys.stderr,
                )
                return 2
            if args.limit < 1:
                print("--limit must be at least 1", file=sys.stderr)
                return 2
            ctx.since = args.since
            ctx.limit = args.limit
            feeds = [known[name] for name in args.feeds] if args.feeds else all_feeds()
            failed = False
            for outcome in run_feeds(ctx, feeds):
                if outcome.ok:
                    print(f"{outcome.feed}: {outcome.changed} new or changed")
                else:
                    failed = True
                    print(f"{outcome.feed}: FAILED: {safe(outcome.error)}")
            return 1 if failed else 0
        if args.action == "seed":
            feed = known.get(args.feed)
            if not isinstance(feed, Osv):
                osv = ", ".join(n for n, f in known.items() if isinstance(f, Osv))
                print(f"only OSV feeds have an archive to seed from: {osv}", file=sys.stderr)
                return 2

            outcome = seed_feed(ctx, feed, args.since, home / "tmp")
            if not outcome.ok:
                print(f"{feed.name}: seed FAILED: {safe(outcome.error)}", file=sys.stderr)
                return 1
            print(f"{feed.name}: {outcome.changed} records new or changed from the archive")
            return 0
        return 2
    finally:
        store.close()
        lock.close()


def _reader(path: Path) -> Store:
    if not path.exists():
        Store(path).close()  # a first look creates an empty store
    return Store(path, read_only=True)


def _window(args) -> str:
    if args.since:
        return timeutil.fmt(args.since)
    return timeutil.fmt(timeutil.now() - dt.timedelta(days=max(args.days, 1)))


def _candidates_list(store: Store, args) -> int:
    notes = needing_a_look(store, timeutil.now())
    since = _window(args)
    found = candidates.classify(store, since)
    by_cve = decisions.latest(decisions.history(store))
    listed = {c.cve for group in candidates.threats(found) for c in group.candidates}
    print(
        safe_lines(
            candidates.render(
                found,
                since,
                notes,
                show_all=args.all,
                decided=lambda threat: decisions.describe(decisions.state(threat, by_cve, listed)),
            )
        )
    )
    return 0


def _candidates_write(ctx: Context, args) -> int:
    if args.action == "add":
        cve = args.cve.strip().upper()
        if not CVE_ID.match(cve):
            print("a CVE number looks like CVE-2026-109618", file=sys.stderr)
            return 2
        note = " ".join(args.note.split())[:300]
        if not note:
            print("--note says where it came from", file=sys.stderr)
            return 2
        with ctx.store.transaction():
            # Adding again changes the note, never the date it was first added.
            ctx.store.db.execute(
                "INSERT INTO manual (cve, added_at, note) VALUES (?, ?, ?)"
                " ON CONFLICT(cve) DO UPDATE SET note = excluded.note",
                (cve, ctx.stamp(), note),
            )
        print(f"{cve} added; `drafter candidates refresh` reads its vendor records")
        return 0
    if args.reparse:
        print(f"vendor records re-read: {candidates.reparse(ctx.store)}")
        print(f"NVD products filled in: {nvd.reparse_products(ctx.store)}")
        return 0
    if args.limit < 1:
        print("--limit must be at least 1", file=sys.stderr)
        return 2
    outcome = run_one(ctx, candidates.VendorRecords(_window(args), args.limit))
    if outcome.ok:
        print(f"vendor records: {outcome.changed} read")
        return 0
    print(f"vendor records: FAILED: {safe(outcome.error)}")
    return 1


def _fill(ctx: Context, args) -> int:
    cves = sorted({c.strip().upper() for c in args.cves})
    bad = [c for c in cves if not CVE_ID.match(c)]
    if bad:
        print(f"not CVE numbers: {safe(', '.join(bad))}", file=sys.stderr)
        return 2
    extra, unconfirmed, problems = [], 0, []
    try:
        if args.thirdparty:
            extra, unconfirmed, problems = thirdparty.confirmed_entries(
                args.thirdparty.read_text(encoding="utf-8"), cves, ctx.store
            )
        draft = fill.build(ctx, cves, args.binaries, args.other_builds, extra, unconfirmed)
        draft.conflicts += problems
        for cve in thirdparty.unknown_cves(ctx, cves):
            draft.conflicts.append(
                f"{cve}: the store has no NVD or CISA row for it yet, so whether it touches a"
                " third-party build (thirdparty.toml) can't be told: check by hand, or fetch"
                " the feeds first"
            )
        if not args.thirdparty:
            for cpe in thirdparty.has_repositories(ctx, cves):
                draft.conflicts.append(
                    f"{cpe} has third-party builds (thirdparty.toml): run `drafter propose` and"
                    " pass --thirdparty. Until then they aren't named, and a host on one"
                    " reads not affected"
                )
    except (fill.FillError, thirdparty.ThirdPartyError) as exc:
        print(safe(exc), file=sys.stderr)
        return 2
    text = fill.render_yaml(draft)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"draft written to {safe(args.out)}")
    else:
        print(safe_lines(text))
    print(safe_lines(fill.render_report(draft)))
    if args.compare:
        print(safe_lines(fill.compare(draft, args.compare.read_text(encoding="utf-8"))))
    return 0


def _propose(ctx: Context, args) -> int:
    cves = sorted({c.strip().upper() for c in args.cves})
    if any(not CVE_ID.match(c) for c in cves):
        print("not CVE numbers", file=sys.stderr)
        return 2
    try:
        proposals, report, gaps = thirdparty.propose(ctx, cves, args.binaries, args.watch)
    except (fill.FillError, thirdparty.ThirdPartyError) as exc:
        print(safe(exc), file=sys.stderr)
        return 2
    run = thirdparty.record_run(ctx.store, cves, proposals, gaps, ctx.stamp())
    args.out.write_text(thirdparty.render(proposals, cves, gaps, run), encoding="utf-8")
    fixed = sum(1 for p in proposals if p.fixed)
    print(f"{len(proposals)} proposal(s), {fixed} with a fix, written to {safe(args.out)}")
    print("set confirm = true on each one you accept, then: drafter fill … --thirdparty FILE")
    for line in report:
        print(safe(f"  {line}"))
    for gap in gaps:
        print(safe(f"  GAP {gap} (in the file: fill will ask for it)"))
    return 0


def safe_lines(text: str) -> str:
    return "\n".join(safe(line) for line in text.split("\n"))


def _web(home: Path, args) -> int:
    from drafter import web  # Jinja2 is only needed here

    origin = args.origin.rstrip("/")
    parts = urllib.parse.urlsplit(origin)
    if parts.scheme not in ("http", "https") or not parts.netloc or parts.path:
        print("--origin is a scheme and host, like https://packs.localhost:8443", file=sys.stderr)
        return 2
    if not 0 < args.port < 65536 or not 0 < args.days <= 3650:
        print("--port is 1 to 65535 and --days 1 to 3650", file=sys.stderr)
        return 2
    site = web.Site(home=home, port=args.port, origin=origin, days=args.days)
    try:
        server = web.make_server(site)
    except (StoreError, OSError, sqlite3.Error) as exc:
        # sqlite3.Error: the store busy while it is upgraded (the hourly run).
        print(safe(exc), file=sys.stderr)
        return 1
    print(f"the candidate page: {origin} (listening on 127.0.0.1:{args.port})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _decisions(store: Store) -> int:
    decided = decisions.history(store)
    if not decided:
        print("no decisions yet: `drafter web` is where they are made")
    for d in decided:
        verdict = "approved" if d.verdict == "approve" else "rejected"
        print(
            safe(
                f"{d.decided_at[:16].replace('T', ' ')}  {verdict}  {', '.join(d.families) or '?'}"
                f"  {', '.join(d.cves)}  by {d.decided_by}: {d.reason}"
            )
        )
    return 0


def _status(store: Store) -> int:
    reports = report(store, [*all_feeds(), candidates.VendorRecords("", 0)], timeutil.now())
    width = max(len(r.feed) for r in reports)
    for r in reports:
        print(f"{r.feed:<{width}}  {r.state:<7}  {safe(r.detail)}")
    return 0 if all(r.ok for r in reports) else 1


if __name__ == "__main__":
    sys.exit(main())
