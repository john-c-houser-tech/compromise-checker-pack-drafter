"""CISA's Known Exploited Vulnerabilities list: one file, fetched whole when it changes."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re

from drafter.feeds import Context, Feed, FeedError, cve_or_none
from drafter.store import FeedState

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_BYTES = 32 * 1024 * 1024
_DATE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")


def _real_date(text: str) -> bool:
    """YYYY-MM-DD and a day that exists: the candidate list reads it as a time."""
    if not _DATE.match(text):
        return False
    try:
        dt.date.fromisoformat(text)
    except ValueError:
        return False
    return True


def _text(value: object, limit: int = 300) -> str | None:
    return value[:limit] if isinstance(value, str) else None


class Kev(Feed):
    name = "kev"
    title = "CISA Known Exploited Vulnerabilities"
    quiet_after = dt.timedelta(days=14)

    def run(self, ctx: Context, state: FeedState) -> int:
        store = ctx.store
        answer, fetch_id = ctx.fetch(
            self.name, URL, etag=state.etag, last_modified=state.last_modified, max_bytes=MAX_BYTES
        )
        if answer.not_modified:
            return 0
        # The position holds the hash of the last list read in full, so a broken
        # copy that comes back unchanged is still read (and still fails) next time.
        if state.position == _sha(answer.body):
            # Same file under new headers: nothing new.
            with store.transaction():
                _headers(state, answer.headers)
                store.save_state(state)
            return 0
        rows = parse(answer.body)
        changed = 0
        with store.transaction():
            for row in rows:
                changed += store.upsert("kev", {**row, "fetch_id": fetch_id}, ("cve",))
            _headers(state, answer.headers)
            state.position = _sha(answer.body)
            store.save_state(state)
        return changed


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _headers(state: FeedState, headers: dict[str, str]) -> None:
    state.etag = _text(headers.get("etag"))
    state.last_modified = _text(headers.get("last-modified"))


def parse(body: bytes) -> list[dict]:
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise FeedError("KEV list is not JSON") from None
    entries = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise FeedError("KEV list has no vulnerabilities")
    rows = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cve = cve_or_none(entry.get("cveID"))
        added = entry.get("dateAdded")
        if cve is None or not isinstance(added, str) or not _real_date(added):
            continue
        rows.append(
            {
                "cve": cve,
                "date_added": added,
                "vendor": _text(entry.get("vendorProject")),
                "product": _text(entry.get("product")),
                "name": _text(entry.get("vulnerabilityName")),
            }
        )
    if not rows:
        raise FeedError("KEV list has no readable entries")
    return rows
