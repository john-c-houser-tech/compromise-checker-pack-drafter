"""drafter: the command line.

    drafter feeds fetch [FEED ...] [--since DATE] [--limit N]
    drafter feeds seed FEED --since DATE
    drafter feeds status
    drafter candidates refresh|list|add …
    drafter fill CVE … / drafter propose CVE …
    drafter draft CVE … [--out FILE] [--dry-run] / drafter spend
    drafter web [--port N] [--origin URL] [--packs DIR]
    drafter decisions

Exit codes: 0 fine, 1 a feed failed or needs a look, 2 bad usage, 3 another run
holds the lock.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import json
import logging
import os
import sqlite3
import sys
import time
import unicodedata
import urllib.parse
from pathlib import Path

from drafter import __version__, candidates, decisions, fill, thirdparty, timeutil, upgrade
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

    drafting = commands.add_parser(
        "draft", help="an AI draft of an approved threat's title, detections and remediation (A.5)"
    )
    drafting.add_argument("cves", nargs="+", metavar="CVE")
    drafting.add_argument("--out", type=Path, help="write the draft here (default: print it)")
    drafting.add_argument(
        "--dry-run",
        action="store_true",
        help="show what would be sent and its most possible cost; send nothing",
    )
    drafting.add_argument(
        "--past-tell-mark",
        action="store_true",
        help="go on past the $5 at which John asked to be told (only once he has said so)",
    )
    commands.add_parser("spend", help="every request sent to the AI, and the caps (A.5)")

    packing = commands.add_parser("pack", help="assemble an approved, drafted threat's pack (A.7)")
    pack_actions = packing.add_subparsers(dest="action", required=True)
    tmpl = pack_actions.add_parser("template", help="an assembly file to edit, from a draft")
    tmpl.add_argument("--draft", type=Path, required=True, help="the reviewed draft file")
    tmpl.add_argument("--packs", type=Path, required=True, help="a clone of the packs repository")
    tmpl.add_argument("--out", type=Path, help="write it here (default: print it)")
    writing = pack_actions.add_parser(
        "write", help="the pack, on a new branch of the packs clone, frozen for signing"
    )
    writing.add_argument("assembly", type=Path, help="the assembly file (TOML)")
    writing.add_argument(
        "--packs", type=Path, required=True, help="a clone of the packs repository"
    )
    checking = pack_actions.add_parser(
        "check", help="after signing: the frozen file, its signature, then the index"
    )
    checking.add_argument("id", help="the pack's id")
    checking.add_argument(
        "--packs", type=Path, required=True, help="a clone of the packs repository"
    )
    checking.add_argument(
        "--checker", default="checker", help="the checker's command (default: %(default)s)"
    )

    web = commands.add_parser("web", help="the candidate page, to approve or reject (A.4)")
    web.add_argument("--port", type=int, default=8089, help="on 127.0.0.1 (default: %(default)s)")
    web.add_argument(
        "--origin",
        default="https://packs.localhost:8443",
        help="the address the browser uses, through Caddy (default: %(default)s)",
    )
    web.add_argument(
        "--packs",
        type=Path,
        help="a local clone of compromise-checker-packs: threats its signed packs name"
        " read Covered",
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
    if (
        args.command in ("decisions", "spend")
        or (args.command == "draft" and getattr(args, "dry_run", False))
        or (args.command == "pack" and args.action in ("template", "check"))
    ):
        try:
            store = _reader(home / "drafter.sqlite3")
        except StoreError as exc:
            print(safe(exc), file=sys.stderr)
            return 1
        try:
            if args.command == "spend":
                return _spend(store)
            if args.command == "draft":
                return _draft_dry(store, args)
            if args.command == "pack":
                return _pack_read(store, args)
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
    if args.command == "draft":
        # No run lock: a draft writes only its own spending rows, each with the caps
        # checked in the same transaction, so the hourly run isn't held up for the
        # minute or two the AI takes (and a draft isn't turned away by it).
        return _draft_unlocked(home, args)
    try:
        lock = _lock(home)
    except Locked:
        print("another drafter run is going; try again when it ends", file=sys.stderr)
        return 3
    store = Store(home / "drafter.sqlite3")
    filled = upgrade.fill(store)  # the new columns, from the pages already kept
    if filled:
        print(filled)
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
        if args.command == "pack":
            return _pack_write(ctx, args)
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
    if args.packs is not None and not (args.packs / "index.yaml").is_file():
        print(f"--packs: no index.yaml in {safe(args.packs)}", file=sys.stderr)
        return 2
    site = web.Site(home=home, port=args.port, origin=origin, days=args.days, packs=args.packs)
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


def _draft_cves(args) -> list[str] | None:
    cves = sorted({c.strip().upper() for c in args.cves})
    bad = [c for c in cves if not CVE_ID.match(c)]
    if bad:
        print(f"not CVE numbers: {safe(', '.join(bad))}", file=sys.stderr)
        return None
    return cves


def _draft_dry(store: Store, args) -> int:
    from drafter import draft

    cves = _draft_cves(args)
    if cves is None:
        return 2
    try:
        decision = draft.approved(store, cves)
    except draft.DraftError as exc:
        print(safe(exc), file=sys.stderr)
        return 1
    found = draft.sources(store, list(decision.cves))
    messages = [{"role": "user", "content": draft.user_message(list(decision.cves), found)}]
    tokens = draft.estimate(draft.SYSTEM, messages)
    print(f"approved {decision.decided_at[:10]}: {', '.join(decision.cves)}")
    for s in found:
        print(safe(f"  source: {s.name} ({len(s.text)} characters, fetch {s.fetch_id})"))
    print(
        f"about {tokens} tokens in, by the rough estimate; at most"
        f" ${draft.worst_cost(tokens):.2f} for the first request (cap ${draft.PER_DRAFT_CAP:.2f}"
        f" a draft); ${draft.spent(store):.2f} spent of ${draft.TOTAL_CAP:.2f}. Nothing sent."
    )
    problem = None if found else "nothing fetched about these CVEs to draft from"
    try:
        draft.allow(store, draft.worst_cost(tokens), 0.0, args.past_tell_mark)
    except draft.DraftError as exc:
        problem = str(exc)
    if problem:
        print(safe(f"a real run would stop: {problem}"), file=sys.stderr)
        return 1
    return 0


def _draft_unlocked(home: Path, args) -> int:
    cves = _draft_cves(args)
    if cves is None:
        return 2
    if not os.environ.get("ANTHROPIC_API_KEY"):
        # Checked before anything is recorded: a request that can't be sent costs
        # nothing and mustn't count.
        print(
            'no API key: ANTHROPIC_API_KEY=$(op read "op://Personal/Anthropic API Key/notesPlain")'
            " drafter draft …",
            file=sys.stderr,
        )
        return 2
    if args.out is not None and (
        not args.out.parent.is_dir()
        or args.out.is_dir()
        or not os.access(args.out if args.out.exists() else args.out.parent, os.W_OK)
    ):
        print(f"--out: can't write a file at {safe(args.out)}", file=sys.stderr)
        return 2
    try:
        store = Store(home / "drafter.sqlite3")
    except (StoreError, sqlite3.Error) as exc:
        print(safe(exc), file=sys.stderr)
        return 1
    try:
        # Unlocked, so it waits for the hourly run's writes rather than failing
        # after an answer has been paid for. (A fill owed after a schema move is
        # left to the hourly run and the page, which hold their own.)
        store.db.execute("PRAGMA busy_timeout = 120000")
        return _draft(store, args, cves)
    finally:
        store.close()


def _draft(store: Store, args, cves: list[str]) -> int:
    import anthropic

    from drafter import draft

    client = anthropic.Anthropic(max_retries=0)
    try:
        made = draft.draft(
            store,
            cves,
            client,
            past_tell=args.past_tell_mark,
        )
    except draft.DraftError as exc:
        print(safe(exc), file=sys.stderr)
        return 1
    text = draft.render(made, timeutil.fmt(timeutil.now())[:16].replace("T", " ") + " UTC")
    written = False
    if args.out:
        try:
            args.out.write_text(text, encoding="utf-8")
            written = True
            print(f"draft written to {safe(args.out)}")
        except OSError as exc:
            print(f"--out couldn't be written ({safe(exc)}): here it is", file=sys.stderr)
    if not written:
        print(safe_lines(text))
    print(
        f"this draft: ${made.cost:.4f}; spent ${draft.spent(store):.2f} of ${draft.TOTAL_CAP:.2f}"
    )
    if not made.ok:
        print("NOT USABLE: the answer was refused (the reasons are in the draft)", file=sys.stderr)
        return 1
    return 0


def _pack_read(store: Store, args) -> int:
    from drafter import assemble

    try:
        if args.action == "template":
            text = assemble.template(store, args.draft, args.packs)
            if args.out:
                args.out.write_text(text, encoding="utf-8")
                print(f"assembly file written to {safe(args.out)}: fill in what it asks")
            else:
                print(safe_lines(text))
            return 0
        done = assemble.check(store, args.id, args.packs, checker=args.checker)
    except assemble.AssembleError as exc:
        print(safe_lines(str(exc)), file=sys.stderr)
        return 1
    print(safe(f"{done.path}: unchanged since it was frozen, signed by pack key"
               f" {done.key[:16]}…, trusted comment {done.comment!r}"))  # fmt: skip
    print(safe_lines(done.index_output))
    clone = safe(args.packs)
    print(
        f"Then: sign the index (minisign -S -s {assemble.PACK_KEY} -m {clone}/index.yaml),"
        f" and in {clone} commit packs/{safe(args.id)} with index.yaml and its signature,"
        " push the branch and open a pull request into dev. Don't touch a file after"
        " signing it."
    )
    return 0


def _pack_write(ctx: Context, args) -> int:
    from drafter import assemble

    try:
        a = assemble.read_assembly(args.assembly)
        done = assemble.write(ctx.store, ctx, a, args.packs, now=ctx.now)
    except (assemble.AssembleError, OSError) as exc:
        print(safe_lines(str(exc)), file=sys.stderr)
        return 1
    except draft_errors() as exc:
        print(safe_lines(str(exc)), file=sys.stderr)
        return 1
    print(safe_lines(done.report))
    if done.notes:
        print("CHECK BEFORE SIGNING: what the prose points people at, and where it came from:")
        for note in done.notes:
            print(safe(f"  {note}"))
    print(safe_lines(done.diff) if done.diff else "(a new pack: nothing to compare with)")
    print(safe(f"Written to {done.path}, read-only, on branch {done.branch}."))
    print(f"SHA-256: {done.sha256}")
    print("Read it, then sign it (a person, by hand):")
    print(safe(f"  {assemble.sign_command(done.path, a.id, a.version)}"))
    print(safe(f"Then: drafter pack check {a.id} --packs {args.packs}"))
    return 0


def draft_errors() -> tuple[type[Exception], ...]:
    from drafter import draft, fill

    return (draft.DraftError, fill.FillError)


def _spend(store: Store) -> int:
    from drafter import draft

    rows = draft.ledger(store)
    for r in rows:
        state = "" if r["settled"] else "  (never settled: counted at its most)"
        print(
            safe(
                f"{r['sent_at'][:16].replace('T', ' ')}  {', '.join(json.loads(r['cves']))}"
                f"  try {r['attempt']}  {r['stop_reason'] or '?'}  ${r['cost']:.4f}"
                f"  {r['request_id'] or ''}{state}"
            )
        )
    total = draft.spent(store)
    print(
        f"spent ${total:.2f} of ${draft.TOTAL_CAP:.2f}; at most ${draft.PER_DRAFT_CAP:.2f} a"
        f" draft; John is told at ${draft.TELL_AT:.2f} ({draft.MODEL}, D6)"
    )
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
                f"  {', '.join(d.cves)}  by {d.decided_by}: {d.reason or '(no reason given)'}"
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
