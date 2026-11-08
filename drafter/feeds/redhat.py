"""Red Hat's Security Data API: CVEs Red Hat rates Critical, its top severity (D3).

Asks for Critical CVEs made public since 30 days before the saved position, so a
CVE raised to Critical a few weeks after it went public is still seen. Red Hat's
CSAF/VEX files, with fixed builds, are read per threat in A.3, not here.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import urllib.parse

from drafter import timeutil
from drafter.feeds import Context, Feed, FeedError, cve_or_none
from drafter.store import FeedState, dumps

BASE = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
PAGE = 1000
MAX_PAGES = 20
LOOKBACK = dt.timedelta(days=30)
MAX_BYTES = 32 * 1024 * 1024
_PACKAGE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._+:~-]{0,200}\Z")


class RedHatCritical(Feed):
    name = "redhat"
    title = "Red Hat Security Data API (Critical)"
    quiet_after = dt.timedelta(days=21)

    def run(self, ctx: Context, state: FeedState) -> int:
        store = ctx.store
        after = (
            timeutil.parse(state.position) - LOOKBACK if state.position else ctx.start()
        ).date()
        changed = 0
        for page in range(1, MAX_PAGES + 1):
            url = (
                BASE
                + "?"
                + urllib.parse.urlencode(
                    {
                        "severity": "critical",
                        "after": after.isoformat(),
                        "per_page": PAGE,
                        "page": page,
                    }
                )
            )
            answer, fetch_id = ctx.fetch(self.name, url, max_bytes=MAX_BYTES)
            entries, rows = parse(answer.body)
            with store.transaction():
                for row in rows:
                    changed += store.upsert(
                        "redhat_critical", {**row, "fetch_id": fetch_id}, ("cve",)
                    )
            if entries < PAGE:
                break
        else:
            raise FeedError(f"more than {MAX_PAGES * PAGE} Critical CVEs; not all read")
        with store.transaction():
            state.position = ctx.stamp()
            store.save_state(state)
        return changed


def parse(body: bytes) -> tuple[int, list[dict]]:
    """(entries in the answer, readable Critical rows)."""
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise FeedError("Red Hat answer is not JSON") from None
    if not isinstance(data, list):
        raise FeedError("Red Hat answer is not a list")
    rows = []
    for entry in data:
        if not isinstance(entry, dict) or entry.get("severity") != "critical":
            continue
        cve = cve_or_none(entry.get("CVE"))
        if cve is None:
            continue
        public = entry.get("public_date")
        try:
            public = timeutil.norm(public) if isinstance(public, str) else None
        except timeutil.TimeError:
            public = None
        listed = entry.get("affected_packages")
        listed = listed if isinstance(listed, list) else []
        packages = [p for p in listed if isinstance(p, str) and _PACKAGE.match(p)]
        rows.append({"cve": cve, "public_date": public, "packages": dumps(packages)})
    return len(data), rows
