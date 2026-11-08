"""How each feed is doing: never read, failing, behind, quiet or fine."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from drafter import timeutil
from drafter.feeds import Feed
from drafter.store import Store

# No successful read for this long means the timer isn't running, or the laptop was off.
BEHIND_AFTER = dt.timedelta(days=1)


@dataclass
class FeedReport:
    feed: str
    title: str
    state: str  # never, failing, behind, quiet, ok
    detail: str
    last_success: str | None
    last_change: str | None

    @property
    def ok(self) -> bool:
        return self.state == "ok"


def _ago(now: dt.datetime, stamp: str | None) -> str:
    if not stamp:
        return "never"
    delta = now - timeutil.parse(stamp)
    if delta < dt.timedelta(hours=1):
        return f"{max(int(delta.total_seconds() // 60), 0)} min ago"
    if delta < dt.timedelta(days=2):
        return f"{int(delta.total_seconds() // 3600)} h ago"
    return f"{delta.days} days ago"


def report(store: Store, feeds: list[Feed], now: dt.datetime) -> list[FeedReport]:
    out = []
    for feed in feeds:
        state = store.state(feed.name)
        first = store.db.execute(
            "SELECT MIN(fetched_at) AS first FROM fetches WHERE feed = ?", (feed.name,)
        ).fetchone()["first"]
        if state.failures:
            kind = "failing"
            detail = f"{state.failures} failed run(s) in a row: {state.last_error}"
        elif not state.last_success:
            kind = "never"
            detail = "never read"
        elif now - timeutil.parse(state.last_success) > BEHIND_AFTER:
            kind = "behind"
            detail = f"last read {_ago(now, state.last_success)}"
        else:
            since = state.last_change or first
            if since and now - timeutil.parse(since) > feed.quiet_after:
                kind = "quiet"
                detail = (
                    f"nothing new for {(now - timeutil.parse(since)).days} days"
                    f" (usual: within {feed.quiet_after.days})"
                )
            else:
                kind = "ok"
                detail = f"read {_ago(now, state.last_success)}"
        out.append(
            FeedReport(
                feed=feed.name,
                title=feed.title,
                state=kind,
                detail=detail,
                last_success=state.last_success,
                last_change=state.last_change,
            )
        )
    return out
