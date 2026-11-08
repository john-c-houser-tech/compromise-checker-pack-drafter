"""Ubuntu Security Notices: the notice list, newest first, back to the saved position."""

from __future__ import annotations

import datetime as dt
import json
import re
import urllib.parse

from drafter import timeutil
from drafter.feeds import Context, Feed, FeedError, cve_or_none
from drafter.store import FeedState, dumps

BASE = "https://ubuntu.com/security/notices.json"
PAGE = 20
MAX_PAGES_PER_RUN = 200
LOOKBACK = dt.timedelta(days=3)
MAX_BYTES = 32 * 1024 * 1024
USN_ID = re.compile(r"^(USN|LSN)-\d{1,6}-\d{1,3}$")


class Usn(Feed):
    name = "usn"
    title = "Ubuntu Security Notices"
    quiet_after = dt.timedelta(days=4)

    def run(self, ctx: Context, state: FeedState) -> int:
        store = ctx.store
        # The list isn't strictly in publishing order, so a notice can appear after a
        # newer one was read: every run reads a few days back. Re-reads aren't changes.
        if state.position:
            cutoff = timeutil.fmt(timeutil.parse(state.position) - LOOKBACK)
        else:
            cutoff = timeutil.fmt(ctx.start())
        newest = state.position or cutoff
        changed = 0
        for page in range(MAX_PAGES_PER_RUN):
            url = (
                BASE
                + "?"
                + urllib.parse.urlencode({"limit": PAGE, "offset": page * PAGE, "order": "newest"})
            )
            answer, fetch_id = ctx.fetch(self.name, url, max_bytes=MAX_BYTES)
            total, entries, rows = parse(answer.body)
            fresh = [row for row in rows if row["published"] > cutoff]
            with store.transaction():
                for row in fresh:
                    changed += store.upsert("usn", {**row, "fetch_id": fetch_id}, ("id",))
            newest = max([newest, *(row["published"] for row in fresh)])
            # Stop on a page wholly older than the cutoff, not on the first old notice:
            # the list is only roughly in order, and the cutoff is days behind.
            reached_cutoff = bool(rows) and max(row["published"] for row in rows) <= cutoff
            if not entries or reached_cutoff or (page + 1) * PAGE >= total:
                break
        else:
            # More notices than one run reads: keep what was read and say so once,
            # rather than staying stuck at the same place every hour.
            with store.transaction():
                state.position = newest
                store.save_state(state)
            raise FeedError(
                f"more than {MAX_PAGES_PER_RUN * PAGE} notices to read; older ones skipped"
            )
        with store.transaction():
            state.position = newest
            store.save_state(state)
        return changed


def parse(body: bytes) -> tuple[int, int, list[dict]]:
    """(total notices, entries on this page, readable rows)."""
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise FeedError("notice list is not JSON") from None
    notices = data.get("notices") if isinstance(data, dict) else None
    total = data.get("total_results") if isinstance(data, dict) else None
    if not isinstance(notices, list) or not isinstance(total, int):
        raise FeedError("notice list has no notices or total")
    rows = []
    for notice in notices:
        if not isinstance(notice, dict):
            continue
        usn_id = notice.get("id")
        published = notice.get("published")
        if not isinstance(usn_id, str) or not USN_ID.match(usn_id):
            continue
        if not isinstance(published, str):
            continue
        try:
            published = timeutil.norm(published)
        except timeutil.TimeError:
            continue
        listed = notice.get("cves_ids")
        cves = [c for c in listed if cve_or_none(c)] if isinstance(listed, list) else []
        rows.append({"id": usn_id, "published": published, "cves": dumps(cves)})
    return total, len(notices), rows
