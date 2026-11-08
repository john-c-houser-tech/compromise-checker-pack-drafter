"""NVD's CVE API: every CVE changed since the saved position, for CISA's SSVC rating.

The API takes windows of at most 120 days and pages of up to 2,000 records.
Without an API key NVD allows about five requests in 30 seconds, so the feed
waits six seconds between requests (under a second with a key). The key, if any,
goes in a header, never in the address, so it never reaches the store.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import urllib.parse

from drafter import timeutil
from drafter.feeds import Context, Feed, FeedError, cve_or_none
from drafter.store import FeedState

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000
# NVD allows 120 days; a week keeps the saved position moving often on a long read.
WINDOW = dt.timedelta(days=7)
OVERLAP = dt.timedelta(minutes=15)  # NVD indexes changes with a short delay
MAX_PAGES_PER_RUN = 400
MAX_BYTES = 128 * 1024 * 1024


def _nvd_time(value: dt.datetime) -> str:
    value = value.astimezone(dt.UTC)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


class Nvd(Feed):
    name = "nvd"
    title = "NVD CVE API (CISA's SSVC rating)"
    quiet_after = dt.timedelta(days=1)

    def run(self, ctx: Context, state: FeedState) -> int:
        store = ctx.store
        start = timeutil.parse(state.position) - OVERLAP if state.position else ctx.start()
        now = ctx.now()
        headers = {"apiKey": ctx.nvd_api_key} if ctx.nvd_api_key else {}
        pause = 0.7 if ctx.nvd_api_key else 6.5  # a margin over NVD's 5 per 30 s
        requests = 0
        changed = 0
        while start < now:
            end = min(start + WINDOW, now)
            index = 0
            first_total = None
            while True:
                if requests >= MAX_PAGES_PER_RUN:
                    return changed  # the rest of this window waits for the next run
                if requests:
                    ctx.sleep(pause)
                url = (
                    BASE
                    + "?"
                    + urllib.parse.urlencode(
                        {
                            "lastModStartDate": _nvd_time(start),
                            "lastModEndDate": _nvd_time(end),
                            "resultsPerPage": PAGE,
                            "startIndex": index,
                        }
                    )
                )
                # NVD answers 403 when asked too fast: wait well past its 30 s window.
                answer, fetch_id = ctx.fetch(
                    self.name,
                    url,
                    headers=headers,
                    max_bytes=MAX_BYTES,
                    also_retry=frozenset({403}),
                    first_delay=35.0,
                )
                requests += 1
                total, entries, rows = parse(answer.body)
                with store.transaction():
                    for row in rows:
                        changed += _upsert_newer(store, {**row, "fetch_id": fetch_id})
                if first_total is None:
                    first_total = total
                if total < first_total:
                    # CVEs changed again mid-read left the window (only ever leave: the
                    # window's end is fixed) and the rest moved up, so this page started
                    # past some unread ones. Ask again from that many places back;
                    # re-reading is harmless.
                    index = max(0, index - (first_total - total))
                    first_total = total
                    continue
                index += entries
                if index >= total:
                    break
                if not entries:
                    raise FeedError("NVD page came back empty before the end")
            with store.transaction():
                state.position = timeutil.fmt(end)
                store.save_state(state)
            start = end
        return changed


def _upsert_newer(store, row: dict) -> int:
    old = store.db.execute("SELECT last_modified FROM nvd WHERE cve = ?", (row["cve"],)).fetchone()
    if old is not None and old["last_modified"] > row["last_modified"]:
        return 0  # an overlap page carrying an older copy
    return int(store.upsert("nvd", row, ("cve",)))


def parse(body: bytes) -> tuple[int, int, list[dict]]:
    """(total results, entries on this page, readable rows)."""
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise FeedError("NVD page is not JSON") from None
    if not isinstance(data, dict) or not isinstance(data.get("totalResults"), int):
        raise FeedError("NVD page has no total")
    entries = data.get("vulnerabilities")
    if not isinstance(entries, list):
        raise FeedError("NVD page has no vulnerabilities list")
    rows = []
    for entry in entries:
        cve = entry.get("cve") if isinstance(entry, dict) else None
        if not isinstance(cve, dict):
            continue
        cve_id = cve_or_none(cve.get("id"))
        modified = cve.get("lastModified")
        if cve_id is None or not isinstance(modified, str):
            continue
        try:
            modified = timeutil.norm(modified)
        except timeutil.TimeError:
            continue
        exploitation, ssvc_time = _ssvc(cve.get("metrics"))
        added = cve.get("cisaExploitAdd")
        rows.append(
            {
                "cve": cve_id,
                "last_modified": modified,
                "exploitation": exploitation,
                "ssvc_time": ssvc_time,
                "kev_added": added[:10] if isinstance(added, str) else None,
                "products": json.dumps(products(cve.get("configurations"))),
                "description": description(cve.get("descriptions")),
            }
        )
    return data["totalResults"], len(entries), rows


_CPE_PART = re.compile(r"^[a-z0-9][a-z0-9._\\/:~!-]{0,80}$")  # ":" only escaped, as "\\:"
MAX_PRODUCTS = 200  # a cut could drop a watched name, so the cap is only a guard


def products(configurations: object) -> list[str]:
    """The vendor:product of each CPE NVD marks vulnerable, such as php:php: what the
    third-party watch list (A.2) matches against."""
    found: set[str] = set()
    for config in configurations if isinstance(configurations, list) else []:
        nodes = config.get("nodes") if isinstance(config, dict) else None
        for node in nodes if isinstance(nodes, list) else []:
            matches = node.get("cpeMatch") if isinstance(node, dict) else None
            for match in matches if isinstance(matches, list) else []:
                if not isinstance(match, dict) or match.get("vulnerable") is not True:
                    continue
                parts = re.split(r"(?<!\\):", str(match.get("criteria", "")))  # not "\:"
                if len(parts) > 4 and parts[0] == "cpe" and parts[1] == "2.3":
                    vendor, product = parts[3].lower(), parts[4].lower()
                    if _CPE_PART.match(vendor) and _CPE_PART.match(product):
                        found.add(f"{vendor}:{product}")
    return sorted(found)[:MAX_PRODUCTS]


MAX_DESCRIPTION = 4000  # matched whole; never printed


def description(descriptions: object) -> str | None:
    """NVD's English description, cut short: there from the day a CVE appears, often
    days before NVD names its products. Untrusted text, matched and shown only."""
    for item in descriptions if isinstance(descriptions, list) else []:
        if isinstance(item, dict) and item.get("lang") == "en":
            value = item.get("value")
            if isinstance(value, str) and value.strip():
                return " ".join(value.split())[:MAX_DESCRIPTION]
    return None


def reparse_products(store) -> int:
    """Fill `products` and `description` for stored CVEs from the NVD pages already
    kept: no fetching."""
    count = 0
    pages = [r[0] for r in store.db.execute("SELECT DISTINCT fetch_id FROM nvd")]
    for fetch_id in pages:
        body = store.fetch_body(fetch_id)
        if body is None:
            continue
        try:
            _, _, rows = parse(body)
        except FeedError:
            continue
        with store.transaction():
            for row in rows:
                cursor = store.db.execute(
                    "UPDATE nvd SET products = ?, description = ? WHERE cve = ? AND fetch_id = ?",
                    (row["products"], row["description"], row["cve"], fetch_id),
                )
                count += cursor.rowcount
    return count


def _ssvc(metrics: object) -> tuple[str | None, str | None]:
    """CISA's SSVC "Exploitation" value: none, poc or active."""
    if not isinstance(metrics, dict):
        return None, None
    found: tuple[str | None, str | None] = (None, None)
    items = metrics.get("ssvcV203")
    for item in items if isinstance(items, list) else []:
        data = item.get("ssvcData") if isinstance(item, dict) else None
        if not isinstance(data, dict):
            continue
        options = data.get("options")
        for option in options if isinstance(options, list) else []:
            if not isinstance(option, dict):
                continue
            for key, value in option.items():
                if key.lower() == "exploitation" and isinstance(value, str):
                    stamp = data.get("timestamp")
                    try:
                        when = timeutil.norm(stamp) if isinstance(stamp, str) else None
                    except timeutil.TimeError:
                        when = None
                    value = value.strip().lower()[:20]
                    if found[0] != "active":  # active wins if CISA rated it twice
                        found = (value, when)
    return found
