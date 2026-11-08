"""OSV's per-ecosystem data for Ubuntu, AlmaLinux and Rocky Linux.

Each ecosystem has a `modified_id.csv` (time, id; newest first). The feed reads it
when it changes, then fetches each record changed since its saved position, oldest
first, up to the per-run limit. The index keeps only its hash; each record keeps
its body. Ubuntu's records carry Ubuntu's own priority, used for D3.

For a long history (the 180-day test), `seed` reads the ecosystem's `all.zip` once.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import logging
import re
import urllib.parse
import zipfile
from pathlib import Path

from drafter import timeutil
from drafter.feeds import CVE_ID, Context, Feed, FeedError
from drafter.http import FetchError
from drafter.store import FeedState, dumps

log = logging.getLogger(__name__)

BASE = "https://osv-vulnerabilities.storage.googleapis.com"
OSV_ID = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{2,100}$")
MAX_INDEX_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_SEED_BYTES = 3 * 1024 * 1024 * 1024
CATCH_UP_AFTER = 1500  # records waiting; past this, read the archive instead


def _url(ecosystem: str, name: str) -> str:
    return f"{BASE}/{urllib.parse.quote(ecosystem)}/{urllib.parse.quote(name)}"


class Osv(Feed):
    def __init__(self, ecosystem: str):
        self.ecosystem = ecosystem
        self.name = "osv-" + ecosystem.lower().replace(" ", "")
        self.title = f"OSV: {ecosystem}"
        self.quiet_after = dt.timedelta(days=3 if ecosystem == "Ubuntu" else 10)

    def run(self, ctx: Context, state: FeedState) -> int:
        store = ctx.store
        state.floor = state.floor or timeutil.fmt(ctx.start())
        answer, _ = ctx.fetch(
            self.name,
            self.index_url,
            keep_body=False,
            etag=state.etag if state.position else None,
            last_modified=state.last_modified if state.position else None,
            max_bytes=MAX_INDEX_BYTES,
        )
        if answer.not_modified:
            return 0
        entries = parse_index(answer.body)
        with store.transaction():
            state.etag = state.last_modified = None  # set again once every change is read
            store.save_state(state)
        work = self._unhandled(store, entries, state.floor)
        changed = 0
        if len(work) > CATCH_UP_AFTER and self._may_catch_up(ctx):
            # A burst (Ubuntu rewrites thousands of records some days): one archive
            # download costs less than thousands of record fetches. Whatever the
            # archive lacks is still unhandled afterwards, and fetched one by one.
            try:
                changed += self.seed(ctx, timeutil.parse(work[0][0]), ctx.workdir, entries=entries)
            except (FetchError, FeedError) as exc:
                log.warning("%s: archive catch-up failed (%s); fetching records", self.name, exc)
            fresh = store.state(self.name)
            state.position, state.floor = fresh.position, fresh.floor
            work = self._unhandled(store, entries, state.floor)
        try:
            for modified, osv_id in work[: ctx.limit]:
                changed += self._fetch_record(ctx, modified, osv_id)
        finally:
            # Even if a fetch failed partway, the position covers what was handled.
            moved = self._advanced(store, entries, state.position or f"{state.floor}|")
            if store.db.in_transaction:
                store.db.execute("ROLLBACK")
            with store.transaction():
                state.position = moved
                store.save_state(state)
        with store.transaction():
            if len(work) <= ctx.limit:
                # Every change is read, so next time the index may answer "not modified".
                state.etag = (answer.headers.get("etag") or "")[:300] or None
                state.last_modified = (answer.headers.get("last-modified") or "")[:300] or None
            store.save_state(state)
        return changed

    @property
    def index_url(self) -> str:
        return _url(self.ecosystem, "modified_id.csv")

    @property
    def archive_url(self) -> str:
        return _url(self.ecosystem, "all.zip")

    def _seen(self, store, since: str) -> dict[str, str]:
        return dict(
            store.db.execute(
                "SELECT id, modified FROM osv_seen WHERE ecosystem = ? AND modified >= ?",
                (self.ecosystem, since),
            ).fetchall()
        )

    def _unhandled(self, store, entries: list[tuple[str, str]], floor: str) -> list:
        """Every index entry since the floor not yet handled at its listed version (or
        a newer one), oldest first. The whole index is compared each run, so a record
        that reaches the bucket late, or that an archive lacked, is never passed over."""
        seen = self._seen(store, floor)
        return sorted(
            (modified, osv_id)
            for modified, osv_id in entries
            if modified >= floor and not seen.get(osv_id, "") >= modified
        )

    def _fetch_record(self, ctx: Context, modified: str, osv_id: str) -> int:
        store = ctx.store
        url = _url(self.ecosystem, osv_id + ".json")
        try:
            record = ctx.fetcher.get(url, max_bytes=MAX_RECORD_BYTES)
        except FetchError as exc:
            if exc.status != 404:
                ctx.record(self.name, url, status=exc.status or 0, body=None)
                raise
            record = None  # withdrawn between the index and the fetch: note it, move on
        changed = 0
        with store.transaction():
            row = None
            if record is None:
                outcome = "withdrawn"
                fetch_id = store.record_fetch(
                    feed=self.name, url=url, fetched_at=ctx.stamp(), status=404, body=None
                )
            else:
                try:
                    row = parse_record(record.body, self.ecosystem)
                    outcome = "read"
                except FeedError as exc:
                    outcome = "unreadable"  # one bad record must not hold the feed up
                    log.warning("%s: %s: %s", self.name, osv_id, exc)
                fetch_id = store.record_fetch(
                    feed=self.name,
                    url=url,
                    fetched_at=ctx.stamp(),
                    status=record.status,
                    body=record.body,
                    keep_body=row is None or self.keep_body(store, row),
                )
                if row is not None:
                    changed = self._upsert(store, row, fetch_id)
            self._mark(store, osv_id, modified, outcome, fetch_id)
        return changed

    def _upsert(self, store, row: dict, fetch_id: int) -> int:
        """Never replace a stored record with an older copy (a lagging archive)."""
        old = store.db.execute(
            "SELECT modified FROM osv WHERE ecosystem = ? AND id = ?", (self.ecosystem, row["id"])
        ).fetchone()
        if old is not None and old["modified"] > row["modified"]:
            return 0
        return int(store.upsert("osv", {**row, "fetch_id": fetch_id}, ("ecosystem", "id")))

    def _mark(self, store, osv_id: str, modified: str, outcome: str, fetch_id: int) -> None:
        old = store.db.execute(
            "SELECT modified FROM osv_seen WHERE ecosystem = ? AND id = ?",
            (self.ecosystem, osv_id),
        ).fetchone()
        if old is not None and old["modified"] > modified:
            return
        store.upsert(
            "osv_seen",
            {
                "ecosystem": self.ecosystem,
                "id": osv_id,
                "modified": modified,
                "outcome": outcome,
                "fetch_id": fetch_id,
            },
            ("ecosystem", "id"),
        )

    def _may_catch_up(self, ctx: Context) -> bool:
        """Not without room to download, nor within a day of a failed archive read."""
        if ctx.workdir is None:
            return False
        failed = ctx.store.db.execute(
            "SELECT 1 FROM fetches WHERE url = ? AND status != 200 AND fetched_at >= ? LIMIT 1",
            (self.archive_url, timeutil.fmt(ctx.now() - dt.timedelta(days=1))),
        ).fetchone()
        return failed is None

    def keep_body(self, store, row: dict) -> bool:
        """Ubuntu's records run to half a megabyte each (every binary of every release),
        so their bodies are kept only when they are a sign of exploitation (D3).
        The hash and time are always kept; A.3 fetches fresh copies when it needs them.
        """
        if self.ecosystem != "Ubuntu" or row["ubuntu_priority"] == "critical":
            return True
        return store.signalled(json.loads(row["cves"]))

    def seed(
        self,
        ctx: Context,
        since: dt.datetime,
        workdir: Path,
        *,
        entries: list[tuple[str, str]] | None = None,
    ) -> int:
        """Read the ecosystem's all.zip once and keep the records changed since `since`.

        The position then moves only over index entries the archive actually held,
        in order, so an entry the archive lacks is still fetched by the next run.
        """
        store = ctx.store
        if entries is None:
            answer, _ = ctx.fetch(
                self.name, self.index_url, keep_body=False, max_bytes=MAX_INDEX_BYTES
            )
            entries = parse_index(answer.body)
        workdir.mkdir(parents=True, exist_ok=True)
        archive = workdir / f"{self.name}-all.zip"
        try:
            try:
                sha, size = ctx.fetcher.download(
                    self.archive_url, archive, max_bytes=MAX_SEED_BYTES
                )
            except FetchError as exc:
                ctx.record(self.name, self.archive_url, status=exc.status or 0, body=None)
                raise
            fetched_at = ctx.stamp()
            cutoff = timeutil.fmt(since)
            kept = 0
            with zipfile.ZipFile(archive) as bundle:
                ctx.record(
                    self.name, self.archive_url, status=200, body=None, sha256=sha, size=size
                )
                batch = []
                for info in bundle.infolist():
                    if info.is_dir() or not info.filename.endswith(".json"):
                        continue
                    if info.file_size > MAX_RECORD_BYTES:
                        continue
                    body = bundle.read(info)
                    try:
                        row = parse_record(body, self.ecosystem)
                    except FeedError:
                        continue
                    if row["modified"] < cutoff:
                        continue
                    batch.append((row, body))
                    if len(batch) >= 200:
                        kept += self._seed_batch(store, fetched_at, batch)
                        batch = []
                kept += self._seed_batch(store, fetched_at, batch)
        except zipfile.BadZipFile:
            ctx.record(self.name, self.archive_url, status=0, body=None)
            raise FeedError(f"{self.ecosystem} all.zip is not a zip archive") from None
        finally:
            archive.unlink(missing_ok=True)
        self._advance_over_handled(ctx, entries, since)
        return kept

    def _advance_over_handled(self, ctx: Context, entries, since: dt.datetime) -> None:
        store = ctx.store
        state = store.state(self.name)
        floor = min(state.floor or timeutil.fmt(since), timeutil.fmt(since))
        position = self._advanced(store, entries, state.position or f"{floor}|")
        with store.transaction():
            state.floor = floor
            state.position = position
            state.etag = state.last_modified = None
            store.save_state(state)

    def _advanced(self, store, entries, position: str) -> str:
        """The position moved forward over index entries already handled, in order,
        stopping at the first one that isn't (it is fetched next)."""
        seen = self._seen(store, position.split("|", 1)[0])
        for entry in sorted(e for e in entries if _key(e) > position):
            if not seen.get(entry[1], "") >= entry[0]:
                break
            position = _key(entry)
        return position

    def _seed_batch(self, store, fetched_at: str, batch: list) -> int:
        kept = 0
        with store.transaction():
            for row, body in batch:
                fetch_id = store.record_fetch(
                    feed=self.name,
                    url=f"{self.archive_url}#{row['id']}",
                    fetched_at=fetched_at,
                    status=200,
                    body=body,
                    keep_body=self.keep_body(store, row),
                )
                kept += self._upsert(store, row, fetch_id)
                self._mark(store, row["id"], row["modified"], "read", fetch_id)
        return kept


def _key(entry: tuple[str, str]) -> str:
    modified, osv_id = entry
    return f"{modified}|{osv_id}"


def parse_index(body: bytes) -> list[tuple[str, str]]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise FeedError("OSV index is not text") from None
    if text and not text.endswith("\n"):
        raise FeedError("OSV index cut off (no final line end)")
    entries = []
    for line in csv.reader(io.StringIO(text)):
        if len(line) != 2:
            continue
        stamp, osv_id = line
        if not OSV_ID.match(osv_id):
            continue
        try:
            entries.append((timeutil.norm(stamp), osv_id))
        except timeutil.TimeError:
            continue
    if text.strip() and not entries:
        raise FeedError("OSV index has no readable lines")
    return entries


def parse_record(body: bytes, ecosystem: str) -> dict:
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise FeedError("OSV record is not JSON") from None
    if not isinstance(data, dict):
        raise FeedError("OSV record is not an object")
    osv_id = data.get("id")
    modified = data.get("modified")
    if not isinstance(osv_id, str) or not OSV_ID.match(osv_id) or not isinstance(modified, str):
        raise FeedError("OSV record has no id or modified time")
    try:
        stamp = timeutil.norm(modified)
    except timeutil.TimeError:
        raise FeedError("OSV record has an unreadable time") from None
    cves = [osv_id.removeprefix("UBUNTU-")] if CVE_ID.match(osv_id.removeprefix("UBUNTU-")) else []
    for name in ("aliases", "upstream", "related"):
        values = data.get(name)
        if isinstance(values, list):
            cves.extend(v for v in values if isinstance(v, str) and CVE_ID.match(v))
    priority = None
    severity = data.get("severity")
    for item in severity if isinstance(severity, list) else []:
        if isinstance(item, dict) and item.get("type") == "Ubuntu":
            score = item.get("score")
            if isinstance(score, str):
                priority = score.strip().lower()[:20]
    return {
        "ecosystem": ecosystem,
        "id": osv_id,
        "modified": stamp,
        "cves": dumps(cves),
        "ubuntu_priority": priority,
    }
