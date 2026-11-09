"""B.2: pages a person adds to an approved threat's sources (decision D9).

For pages nothing links to: a researcher's write-up, a CDN's first sighting, a
bulletin whose address no record gives. Any https site, since a person chooses
each one, with these safeguards:

- https only, on the default port, with no login in the address;
- every address the name resolves to must be public: never a private, loopback,
  link-local or reserved one; and the connection goes to the address that was
  checked, so a second lookup can't swap in another (DNS rebinding);
- each redirect is held to the same, at most five;
- fetched once, when added, never by the drafter on its own; kept as a fetch (feed
  `added`), with what happened kept even when it failed;
- at most 4 MiB, and only a page of words (HTML, plain text or JSON);
- in a draft, the same caps as every source, and data, never instructions; its own
  address is the only one it makes citable; and it is marked as added, by whom.

At most four a threat (D10 counts them against the 100,000 characters the pages
share, and keeps them longest).
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass

from drafter import linked, textcheck, timeutil
from drafter.http import USER_AGENT, FetchError, Response

FEED = "added"
MAX_ADDED = 4
MAX_BYTES = 4 * 1024 * 1024
MAX_REDIRECTS = 5
TIMEOUT = 20
KINDS = ("text/html", "application/xhtml+xml", "text/plain", "application/json")


# fetching from any site, safely


def check(url: str) -> tuple[str, str]:
    """(host, path with query) for an address that may be fetched; FetchError if not."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise FetchError("not an address that can be read") from None
    if parts.scheme != "https":
        raise FetchError("only https")
    if port not in (None, 443):
        raise FetchError("only the default port")
    if parts.username or parts.password:
        raise FetchError("no login in the address")
    host = (parts.hostname or "").lower()
    if not host or len(url) > 2_000:
        raise FetchError("not an address that can be read")
    return host, (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def public_address(host: str, resolve=socket.getaddrinfo) -> str:
    """The address to connect to: every address the name has must be public."""
    try:
        found = resolve(host, 443, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        raise FetchError("the name doesn't resolve") from None
    addresses = []
    for *_, sockaddr in found:
        ip = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        mapped = getattr(ip, "ipv4_mapped", None)
        if not (mapped or ip).is_global:
            raise FetchError("the name points at a private or reserved address")
        addresses.append(str(ip))
    if not addresses:
        raise FetchError("the name doesn't resolve")
    return addresses[0]


class _Pinned(http.client.HTTPSConnection):
    """TLS to `host`, with its certificate checked, over a connection to `ip`."""

    def __init__(self, host: str, ip: str, connect: Callable | None = None):
        super().__init__(host, 443, timeout=TIMEOUT, context=ssl.create_default_context())
        self._ip = ip
        self._make = connect or socket.create_connection

    def connect(self) -> None:
        sock = self._make((self._ip, 443), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def get(url: str, *, resolve=socket.getaddrinfo, connection: Callable = _Pinned) -> Response:
    """GET a page from any public https site (B.2's rules, above). `connection(host,
    ip)`: the connection, pinned to the address checked (a test's fake)."""
    for _ in range(MAX_REDIRECTS + 1):
        host, target = check(url)
        conn = connection(host, public_address(host, resolve))
        try:
            conn.request(
                "GET", target, headers={"User-Agent": USER_AGENT, "Accept": ", ".join(KINDS)}
            )
            answer = conn.getresponse()
            if answer.status in (301, 302, 303, 307, 308):
                where = answer.getheader("Location") or ""
                url = urllib.parse.urljoin(url, where)
                continue
            if answer.status != 200:
                raise FetchError(f"HTTP {answer.status}", status=answer.status)
            kind = (answer.getheader("Content-Type") or "").split(";")[0].strip().lower()
            if kind not in KINDS:
                raise FetchError(f"not a page of words ({kind[:60] or 'no type given'})")
            body = answer.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise FetchError("longer than 4 MiB")
            return Response(url=url, status=200, headers={"Content-Type": kind}, body=body)
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise FetchError(f"couldn't fetch it ({type(exc).__name__})", network=True) from None
        finally:
            conn.close()
    raise FetchError("too many redirects")


# reading what was kept


def text_of(body: bytes) -> str:
    """A kept page's words. The type isn't kept with the fetch, so it is read from
    the body: JSON, else HTML, else plain text."""
    head = body.lstrip()[:1]
    if head in (b"{", b"["):
        try:
            return linked._strings(json.loads(body))
        except (ValueError, RecursionError):
            pass
    sample = body[:4096].lower()
    if b"<html" in sample or b"<!doctype html" in sample or b"<body" in sample or b"<p" in sample:
        return linked.html_text(body)
    return body.decode("utf-8", "replace")


# the record


@dataclass(frozen=True)
class Added:
    id: int
    url: str
    added_by: str
    added_at: str
    fetch_id: int | None
    outcome: str  # "kept", or why not
    removed_at: str | None

    @property
    def kept(self) -> bool:
        return self.outcome == "kept" and self.removed_at is None and self.fetch_id is not None


def listed(store, decision_id: int) -> list[Added]:
    rows = store.db.execute(
        "SELECT id, url, added_by, added_at, fetch_id, outcome, removed_at FROM added_source"
        " WHERE decision_id = ? ORDER BY id",
        (decision_id,),
    ).fetchall()
    return [Added(*tuple(r)) for r in rows]


class AddError(Exception):
    pass


def add(store, decision_id: int, url: str, by: str, now, fetch=get) -> Added:
    """Fetch a page and add it to the approve's sources, or say why not. What
    happened is kept either way (a failure, as its outcome)."""
    url = url.strip()
    try:
        check(url)
    except FetchError as exc:
        raise AddError(f"{exc}") from None
    current = [a for a in listed(store, decision_id) if a.kept]
    if any(a.url == url for a in current):
        raise AddError("it is added already")
    if len(current) >= MAX_ADDED:
        raise AddError(f"at most {MAX_ADDED} added pages a threat; take one back first")
    when = timeutil.fmt(now())
    fetch_id, outcome = None, "kept"
    try:
        answer = fetch(url)
        if not text_of(answer.body).strip():
            raise FetchError("no words in it")
    except FetchError as exc:
        outcome = str(exc)[:200]
        with store.transaction():
            fetch_id = store.record_fetch(feed=FEED, url=url, fetched_at=when,
                                          status=exc.status or 0, body=None)  # fmt: skip
    else:
        with store.transaction():
            fetch_id = store.record_fetch(
                feed=FEED, url=url, fetched_at=when, status=200, body=answer.body
            )
    with store.transaction():
        cur = store.db.execute(
            "INSERT INTO added_source (decision_id, url, added_by, added_at, fetch_id, outcome)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (decision_id, url, by, when, fetch_id, outcome),
        )
    return Added(cur.lastrowid, url, by, when, fetch_id, outcome, None)


def take_back(store, decision_id: int, added_id: int, now) -> None:
    with store.transaction():
        done = store.db.execute(
            "UPDATE added_source SET removed_at = ? WHERE id = ? AND decision_id = ?"
            " AND removed_at IS NULL",
            (timeutil.fmt(now()), added_id, decision_id),
        ).rowcount
    if not done:
        raise AddError("not an added page of this threat")


def pages(store, decision_id: int) -> list[tuple[Added, str, str | None]]:
    """The kept pages: (the record, its words, its sha256)."""
    out = []
    for a in listed(store, decision_id):
        if not a.kept:
            continue
        body = store.fetch_body(a.fetch_id)
        row = store.db.execute("SELECT sha256 FROM fetches WHERE id = ?", (a.fetch_id,)).fetchone()
        if body is None or row is None:
            continue
        out.append((a, text_of(body), row["sha256"]))
    return out


# the addresses one hop further


def further(texts: list[str], have: set[str], limit: int = 15) -> list[str]:
    """Addresses the pages already read give, not read themselves: one click on the
    card adds one. The five kinds the drafter fetches by itself aren't offered."""
    seen: list[str] = []
    for text in texts:
        for url in textcheck._URL.findall(text):
            url = url.rstrip(".,;:)]}'\"")
            try:
                check(url)
            except FetchError:
                continue
            if url in have or url in seen or linked.links({url}):
                continue
            seen.append(url)
            if len(seen) >= limit:
                return seen
    return seen
