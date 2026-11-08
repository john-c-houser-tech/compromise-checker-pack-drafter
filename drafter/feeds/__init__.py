"""The feeds the drafter reads, and running them.

Each feed reads from fixed addresses, keeps every answer in the store, and moves
its saved position forward only after what it read is stored. A run that fails
partway keeps what it finished, so a closed laptop or a bad hour only delays it.
"""

from __future__ import annotations

import datetime as dt
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from drafter import timeutil
from drafter.http import Fetcher, FetchError
from drafter.store import FeedState, Store

log = logging.getLogger(__name__)

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,9}$")


class FeedError(Exception):
    """A feed's answer wasn't the shape the drafter reads. Never holds feed text."""


def cve_or_none(value: object) -> str | None:
    return value if isinstance(value, str) and CVE_ID.match(value) else None


@dataclass
class Context:
    store: Store
    fetcher: Fetcher
    now: Callable[[], dt.datetime] = timeutil.now
    sleep: Callable[[float], None] = lambda seconds: None
    since: dt.datetime | None = None  # where a feed with no saved position starts
    nvd_api_key: str | None = None
    limit: int = 500  # records fetched one by one, per feed per run
    workdir: Path | None = None  # room for an archive download; None: never download one

    def stamp(self) -> str:
        return timeutil.fmt(self.now())

    def fetch(self, feed: str, url: str, *, keep_body: bool = True, **kwargs):
        """Fetch, and record the answer before anything reads it: a failure, a
        "not modified" and an answer that won't parse all leave their trace.
        Returns (answer, fetch id)."""
        try:
            answer = self.fetcher.get(url, **kwargs)
        except FetchError as exc:
            self.record(feed, url, status=exc.status or 0, body=None)
            raise
        body = None if answer.not_modified else answer.body
        fetch_id = self.record(feed, url, status=answer.status, body=body, keep_body=keep_body)
        return answer, fetch_id

    def record(self, feed: str, url: str, *, status: int, body: bytes | None, **kwargs) -> int:
        with self.store.transaction():
            return self.store.record_fetch(
                feed=feed, url=url, fetched_at=self.stamp(), status=status, body=body, **kwargs
            )

    def start(self) -> dt.datetime:
        return self.since or (self.now() - dt.timedelta(days=1))


class Feed:
    name: str = ""
    title: str = ""
    quiet_after: dt.timedelta = dt.timedelta(days=7)

    def run(self, ctx: Context, state: FeedState) -> int:
        """Fetch what's new. Returns how many items were new or changed."""
        raise NotImplementedError


@dataclass
class Outcome:
    feed: str
    ok: bool
    changed: int = 0
    error: str | None = None
    notes: list[str] = field(default_factory=list)


def all_feeds() -> list[Feed]:
    from drafter.feeds import kev, nvd, osv, redhat, usn

    return [
        kev.Kev(),
        nvd.Nvd(),
        osv.Osv("Ubuntu"),
        osv.Osv("AlmaLinux"),
        osv.Osv("Rocky Linux"),
        usn.Usn(),
        redhat.RedHatCritical(),
    ]


def by_name() -> dict[str, Feed]:
    return {feed.name: feed for feed in all_feeds()}


def run_feeds(ctx: Context, feeds: list[Feed]) -> list[Outcome]:
    outcomes = []
    for feed in feeds:
        outcomes.append(run_one(ctx, feed))
    return outcomes


def run_one(ctx: Context, feed: Feed, work: Callable[[FeedState], int] | None = None) -> Outcome:
    """Run a feed (or `work`, such as a seed) with the same status accounting."""
    store = ctx.store
    state = store.state(feed.name)
    state.last_attempt = ctx.stamp()
    with store.transaction():
        store.save_state(state)
    try:
        changed = (work or (lambda s: feed.run(ctx, s)))(state)
    except (FetchError, FeedError, timeutil.TimeError) as exc:
        return _failed(ctx, feed, str(exc))
    except Exception as exc:  # a bug: record it, keep the other feeds going
        log.exception("feed %s", feed.name)
        return _failed(ctx, feed, f"internal error: {type(exc).__name__}")
    state.last_success = ctx.stamp()
    state.failures = 0
    state.last_error = None
    if changed:
        state.last_change = state.last_success
    with store.transaction():
        store.save_state(state)
    return Outcome(feed=feed.name, ok=True, changed=changed)


def _failed(ctx: Context, feed: Feed, message: str) -> Outcome:
    store = ctx.store
    if store.db.in_transaction:
        store.db.execute("ROLLBACK")
    state = store.state(feed.name)  # keeps whatever position the feed reached
    state.failures += 1
    state.last_error = message[:300]
    with store.transaction():
        store.save_state(state)
    return Outcome(feed=feed.name, ok=False, error=message)


def seed_feed(ctx: Context, feed, since: dt.datetime, workdir: Path) -> Outcome:
    """`drafter feeds seed`: an OSV archive read, with a fetch's status accounting."""

    def work(state: FeedState) -> int:
        kept = feed.seed(ctx, since, workdir)
        fresh = ctx.store.state(feed.name)  # what the seed saved
        state.position, state.floor = fresh.position, fresh.floor
        state.etag, state.last_modified = fresh.etag, fresh.last_modified
        return kept

    return run_one(ctx, feed, work)
