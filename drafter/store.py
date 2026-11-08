"""The drafter's SQLite file: every answer fetched, and what was read from it.

Each fetch is kept with its address, time, status and sha256, so a draft can show
what it was built from. Record answers keep their body (gzipped); index answers
that only say what changed (OSV's modified_id.csv) keep the hash alone. A body is
stored once per feed: a later identical answer points at the first.
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import json
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = 5

_SCHEMA = """
CREATE TABLE fetches (
    id INTEGER PRIMARY KEY,
    feed TEXT NOT NULL,
    url TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    status INTEGER NOT NULL,
    sha256 TEXT,
    size INTEGER,
    body BLOB,                -- gzip; NULL when not kept or kept by an earlier fetch
    same_as INTEGER REFERENCES fetches(id)
);
CREATE INDEX fetches_feed_sha ON fetches(feed, sha256);

CREATE TABLE feed_state (
    feed TEXT PRIMARY KEY,
    position TEXT,            -- where the next run starts; meaning is per feed
    floor TEXT,               -- OSV: the oldest change this feed reads (its first start)
    etag TEXT,
    last_modified TEXT,
    last_attempt TEXT,
    last_success TEXT,
    last_change TEXT,         -- last run that found something new
    failures INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);

CREATE TABLE kev (
    cve TEXT PRIMARY KEY,
    date_added TEXT NOT NULL,
    vendor TEXT,
    product TEXT,
    name TEXT,
    fetch_id INTEGER NOT NULL REFERENCES fetches(id)
);

CREATE TABLE nvd (
    cve TEXT PRIMARY KEY,
    last_modified TEXT NOT NULL,
    exploitation TEXT,        -- CISA's SSVC "Exploitation" value, if any
    ssvc_time TEXT,
    kev_added TEXT,
    fetch_id INTEGER NOT NULL REFERENCES fetches(id)
);

CREATE TABLE osv (
    ecosystem TEXT NOT NULL,
    id TEXT NOT NULL,
    modified TEXT NOT NULL,
    cves TEXT NOT NULL,       -- JSON list
    ubuntu_priority TEXT,
    fetch_id INTEGER NOT NULL REFERENCES fetches(id),
    PRIMARY KEY (ecosystem, id)
);

-- Every OSV index entry handled, however it went: read, withdrawn (404) or
-- unreadable. Without it a withdrawn record would be queued again every run.
CREATE TABLE osv_seen (
    ecosystem TEXT NOT NULL,
    id TEXT NOT NULL,
    modified TEXT NOT NULL,   -- the version handled, as the index or archive gave it
    outcome TEXT NOT NULL,    -- read, withdrawn, unreadable
    fetch_id INTEGER NOT NULL REFERENCES fetches(id),
    PRIMARY KEY (ecosystem, id)
);

CREATE TABLE usn (
    id TEXT PRIMARY KEY,
    published TEXT NOT NULL,
    cves TEXT NOT NULL,       -- JSON list
    fetch_id INTEGER NOT NULL REFERENCES fetches(id)
);

CREATE TABLE redhat_critical (
    cve TEXT PRIMARY KEY,
    public_date TEXT,
    packages TEXT NOT NULL,   -- JSON list, as Red Hat gives them
    fetch_id INTEGER NOT NULL REFERENCES fetches(id)
);
"""


# Each step takes the store from the version before it to its own number.
_STEPS = {
    2: """
-- A.2: each signalled CVE's own vendor record, as the candidate list read it.
CREATE TABLE vendor_cve (
    cve TEXT NOT NULL,
    vendor TEXT NOT NULL,     -- ubuntu, redhat
    attempted_at TEXT NOT NULL,  -- the last try, whatever came of it
    error TEXT,               -- why the last try failed; NULL when it worked
    checked_at TEXT,          -- the last successful read; NULL: never read
    found INTEGER,            -- 0: the vendor doesn't track this CVE (404)
    published TEXT,           -- the vendor's own first publication of the CVE
    packages TEXT NOT NULL DEFAULT '[]',  -- JSON list of affected packages
    fetch_id INTEGER REFERENCES fetches(id),
    PRIMARY KEY (cve, vendor)
);

-- A.2: the vendor:product of each CPE NVD marks vulnerable (JSON list), for the
-- third-party watch list.
ALTER TABLE nvd ADD COLUMN products TEXT NOT NULL DEFAULT '[]';
-- ... and NVD's English description, there before the products are.
ALTER TABLE nvd ADD COLUMN description TEXT;

-- A.2: threats a person added by hand (PHP2Shell reached John before any feed).
CREATE TABLE manual (
    cve TEXT PRIMARY KEY,
    added_at TEXT NOT NULL,
    note TEXT NOT NULL
);
""",
    3: """
-- A.3b: what each `drafter propose` run proposed, so `drafter fill` can check a
-- proposals file against it (a block, its key and its binaries all edited away).
CREATE TABLE propose_run (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    cves TEXT NOT NULL,       -- JSON list, sorted
    token TEXT NOT NULL,      -- random, written into the file with the id
    proposals TEXT NOT NULL,  -- JSON {key: {"names": [...], "fixed": "…" or null}}
    gaps TEXT NOT NULL        -- JSON [keys]
);
""",
    4: """
-- A.4: a person's approve or reject of a threat, with the reason. Append-only: a
-- later decision on the same CVEs stands in front of an earlier one, which stays.
CREATE TABLE decision (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    decided_at TEXT NOT NULL,
    cves TEXT NOT NULL,       -- JSON list, sorted: the threat as the page showed it
    kind TEXT NOT NULL,       -- its section: judge or thirdparty
    families TEXT NOT NULL,   -- JSON list, the package families it was shown with
    verdict TEXT NOT NULL CHECK (verdict IN ('approve', 'reject')),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
    decided_by TEXT NOT NULL
);
CREATE TRIGGER decision_kept BEFORE UPDATE ON decision
BEGIN SELECT RAISE(ABORT, 'decisions are append-only'); END;
CREATE TRIGGER decision_not_removed BEFORE DELETE ON decision
BEGIN SELECT RAISE(ABORT, 'decisions are append-only'); END;
""",
    5: """
-- A.4b: what a card shows. The CVSS score shown for each CVE (JSON: version,
-- vector, score, source), and Red Hat's bug title and statement. Filled from the
-- pages already kept when the store moves up.
ALTER TABLE nvd ADD COLUMN cvss TEXT;
ALTER TABLE vendor_cve ADD COLUMN title TEXT;
ALTER TABLE vendor_cve ADD COLUMN statement TEXT;

-- A.4b: an approve may go without a reason (a reject still needs one), and each
-- decision keeps the signs of attacks it was made with ("kev:CVE-…", JSON), so a
-- sign that comes later brings a reject back; NULL for decisions made before.
-- SQLite can't change a CHECK, so the table is rebuilt with its rows and ids.
DROP TRIGGER decision_kept;
DROP TRIGGER decision_not_removed;
CREATE TABLE decision_5 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    decided_at TEXT NOT NULL,
    cves TEXT NOT NULL,
    kind TEXT NOT NULL,
    families TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('approve', 'reject')),
    reason TEXT NOT NULL CHECK (
        length(reason) <= 1000 AND (verdict = 'approve' OR length(reason) >= 1)
    ),
    decided_by TEXT NOT NULL,
    signs TEXT
);
INSERT INTO decision_5 (id, decided_at, cves, kind, families, verdict, reason, decided_by)
    SELECT id, decided_at, cves, kind, families, verdict, reason, decided_by FROM decision;
DROP TABLE decision;
ALTER TABLE decision_5 RENAME TO decision;
CREATE TRIGGER decision_kept BEFORE UPDATE ON decision
BEGIN SELECT RAISE(ABORT, 'decisions are append-only'); END;
CREATE TRIGGER decision_not_removed BEFORE DELETE ON decision
BEGIN SELECT RAISE(ABORT, 'decisions are append-only'); END;
""",
}


class StoreError(Exception):
    pass


@dataclass
class FeedState:
    feed: str
    position: str | None = None
    floor: str | None = None
    etag: str | None = None
    last_modified: str | None = None
    last_attempt: str | None = None
    last_success: str | None = None
    last_change: str | None = None
    failures: int = 0
    last_error: str | None = None


_STATE_FIELDS = (
    "position",
    "floor",
    "etag",
    "last_modified",
    "last_attempt",
    "last_success",
    "last_change",
    "failures",
    "last_error",
)


class Store:
    def __init__(self, path: Path, *, read_only: bool = False):
        """`read_only`: open without changing anything, schema included, so a reading
        command never upgrades a store that an older install still writes to."""
        self.path = Path(path)
        if read_only:
            # as_uri() escapes "#", "?" and "%" in the path, which a URI would read
            # as delimiters (and so lose mode=ro, or open another file).
            self.db = sqlite3.connect(
                f"{self.path.resolve().as_uri()}?mode=ro", uri=True, isolation_level=None
            )
            self.db.row_factory = sqlite3.Row
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            if version != SCHEMA_VERSION:
                self.db.close()
                raise StoreError(
                    f"store has schema {version}; this drafter reads {SCHEMA_VERSION}."
                    " A fetch with this drafter upgrades it (an older install then needs"
                    " installing again)"
                )
            return
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def close(self) -> None:
        self.db.close()

    migrated_from: int | None = None  # the schema this store had before this open moved it

    def _migrate(self) -> None:
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version == SCHEMA_VERSION:
            self._ensure_columns()
            return
        if version > SCHEMA_VERSION:
            raise StoreError(f"store has schema {version}; this drafter knows {SCHEMA_VERSION}")
        if version == 0:
            script = _SCHEMA + "".join(_STEPS[n] for n in sorted(_STEPS))
        else:
            script = "".join(_STEPS[n] for n in range(version + 1, SCHEMA_VERSION + 1))
        # executescript commits whatever is open, so the transaction is in the script.
        try:
            self.db.executescript(
                f"BEGIN IMMEDIATE;\n{script}\nPRAGMA user_version = {SCHEMA_VERSION};\nCOMMIT;"
            )
        except sqlite3.Error:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise
        self.migrated_from = version
        self._ensure_columns()  # a store from early in schema 2 lacks two columns

    def _ensure_columns(self) -> None:
        """Stores made while schema 2 was being built lack its last columns."""
        have = {row[1] for row in self.db.execute("PRAGMA table_info(nvd)")}
        missing = [
            sql
            for name, sql in (
                ("products", "ALTER TABLE nvd ADD COLUMN products TEXT NOT NULL DEFAULT '[]'"),
                ("description", "ALTER TABLE nvd ADD COLUMN description TEXT"),
            )
            if name not in have
        ]
        if missing:
            with self.transaction():
                for sql in missing:
                    self.db.execute(sql)
            self.migrated_from = 1  # so the caller fills them, as after an upgrade
        runs = {row[1] for row in self.db.execute("PRAGMA table_info(propose_run)")}
        if runs and "token" not in runs:
            # Early schema 3: its runs have no token, so none of them vouches for a file.
            with self.transaction():
                self.db.execute("ALTER TABLE propose_run ADD COLUMN token TEXT")
        vendor = {row[1] for row in self.db.execute("PRAGMA table_info(vendor_cve)")}
        if vendor and "attempted_at" not in vendor:
            # The early shape: its rows are vendor records `candidates refresh` reads
            # again, so the table is rebuilt rather than altered.
            create = _STEPS[2].split("CREATE TABLE vendor_cve", 1)[1].split(");", 1)[0]
            with self.transaction():
                self.db.execute("DROP TABLE vendor_cve")
                self.db.execute(f"CREATE TABLE vendor_cve{create});")

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield self.db
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        self.db.execute("COMMIT")

    # fetches

    def record_fetch(
        self,
        *,
        feed: str,
        url: str,
        fetched_at: str,
        status: int,
        body: bytes | None,
        keep_body: bool = True,
        sha256: str | None = None,
        size: int | None = None,
    ) -> int:
        """Keep one answer. Returns its fetch id. `sha256` and `size` describe an
        answer kept elsewhere (an archive streamed to disk); a body overrides them."""
        sha = hashlib.sha256(body).hexdigest() if body is not None else sha256
        size = len(body) if body is not None else size
        stored = None
        same_as = None
        if body is not None and keep_body:
            earlier = self.db.execute(
                "SELECT id FROM fetches WHERE feed = ? AND sha256 = ? AND body IS NOT NULL"
                " ORDER BY id LIMIT 1",
                (feed, sha),
            ).fetchone()
            if earlier:
                same_as = earlier["id"]
            else:
                stored = gzip.compress(body, mtime=0)
        cursor = self.db.execute(
            "INSERT INTO fetches (feed, url, fetched_at, status, sha256, size, body, same_as)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (feed, url, fetched_at, status, sha, size, stored, same_as),
        )
        return cursor.lastrowid

    def fetch_body(self, fetch_id: int) -> bytes | None:
        row = self.db.execute(
            "SELECT body, same_as FROM fetches WHERE id = ?", (fetch_id,)
        ).fetchone()
        if row is None:
            return None
        if row["body"] is not None:
            return gzip.decompress(row["body"])
        if row["same_as"] is not None:
            return self.fetch_body(row["same_as"])
        return None

    def last_sha(self, feed: str, url: str) -> str | None:
        row = self.db.execute(
            "SELECT sha256 FROM fetches WHERE feed = ? AND url = ? AND sha256 IS NOT NULL"
            " ORDER BY id DESC LIMIT 1",
            (feed, url),
        ).fetchone()
        return row["sha256"] if row else None

    # feed state

    def state(self, feed: str) -> FeedState:
        row = self.db.execute("SELECT * FROM feed_state WHERE feed = ?", (feed,)).fetchone()
        if row is None:
            return FeedState(feed=feed)
        return FeedState(**dict(row))

    def save_state(self, state: FeedState) -> None:
        values = [getattr(state, name) for name in _STATE_FIELDS]
        self.db.execute(
            f"INSERT INTO feed_state (feed, {', '.join(_STATE_FIELDS)})"  # noqa: S608 - fixed names
            f" VALUES (?, {', '.join('?' for _ in _STATE_FIELDS)})"
            " ON CONFLICT(feed) DO UPDATE SET "
            + ", ".join(f"{name} = excluded.{name}" for name in _STATE_FIELDS),
            (state.feed, *values),
        )

    # what was read

    def signalled(self, cves: list[str]) -> bool:
        """Is any of these CVEs on CISA's list, or rated actively exploited in NVD?"""
        if not cves:
            return False
        marks = ", ".join("?" for _ in cves)
        row = self.db.execute(
            f"SELECT 1 FROM kev WHERE cve IN ({marks})"  # noqa: S608 - placeholders only
            f" UNION SELECT 1 FROM nvd WHERE exploitation = 'active' AND cve IN ({marks})"
            " LIMIT 1",
            (*cves, *cves),
        ).fetchone()
        return row is not None

    def upsert(self, table: str, row: dict, key: tuple[str, ...]) -> bool:
        """Insert or replace one row. Returns True when it is new or changed."""
        if table not in {
            "kev",
            "nvd",
            "osv",
            "osv_seen",
            "usn",
            "redhat_critical",
            "vendor_cve",
            "manual",
        }:
            raise StoreError(f"unknown table {table}")
        where = " AND ".join(f"{k} = ?" for k in key)
        old = self.db.execute(
            f"SELECT * FROM {table} WHERE {where}",  # noqa: S608 - fixed names
            tuple(row[k] for k in key),
        ).fetchone()
        compare = {k: v for k, v in row.items() if k != "fetch_id"}
        if old is not None and all(old[k] == v for k, v in compare.items()):
            return False
        columns = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        self.db.execute(
            f"INSERT OR REPLACE INTO {table} ({columns}) VALUES ({marks})",  # noqa: S608 - fixed names
            tuple(row.values()),
        )
        return True


def dumps(items: list[str]) -> str:
    return json.dumps(sorted(set(items)))
