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
import re
import socket
import ssl
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass

from drafter import linked, textcheck, timeutil
from drafter.http import USER_AGENT, FetchError, Response

FEED = "added"
MAX_ADDED = 4
MAX_BYTES = 4 * 1024 * 1024
MAX_REDIRECTS = 5
TIMEOUT = 20  # each connect or read
DEADLINE = 60  # the whole fetch, redirects included
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


_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_COMPAT = ipaddress.ip_network("::/96")


def public(ip) -> bool:
    """Global and not multicast, looking through the IPv6 forms that carry an IPv4
    address (mapped ::ffff:, NAT64 64:ff9b::, compatible ::): Python calls some of
    those global whatever the address inside."""
    if ip.version == 6:
        inside = ip.ipv4_mapped
        if inside is None and (ip in _NAT64 or ip in _COMPAT):
            inside = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if inside is not None:
            return public(inside)
    return ip.is_global and not ip.is_multicast


def public_address(host: str, resolve=socket.getaddrinfo) -> str:
    """The address to connect to: every address the name has must be public."""
    try:
        found = resolve(host, 443, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        raise FetchError("the name doesn't resolve") from None
    addresses = []
    for *_, sockaddr in found:
        ip = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        if not public(ip):
            raise FetchError("the name points at a private or reserved address")
        addresses.append(str(ip))
    if not addresses:
        raise FetchError("the name doesn't resolve")
    return addresses[0]


class _Pinned(http.client.HTTPSConnection):
    """TLS to `host`, with its certificate checked, over a connection to `ip`."""

    def __init__(self, host: str, ip: str, connect: Callable | None = None, timeout=TIMEOUT):
        super().__init__(host, 443, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip
        self._make = connect or socket.create_connection

    def connect(self) -> None:
        sock = self._make((self._ip, 443), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def get(
    url: str, *, resolve=socket.getaddrinfo, connection: Callable = _Pinned, clock=time.monotonic
) -> Response:
    """GET a page from any public https site (B.2's rules, above). `connection(host,
    ip)`: the connection, pinned to the address checked (a test's fake)."""
    deadline = clock() + DEADLINE
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
                # The site's own words never go in a message: only a plain type name.
                said = kind if _TYPE.fullmatch(kind) else "an odd type"
                raise FetchError(f"not a page of words ({said or 'no type given'})")
            body = _read(conn, answer, deadline, clock)
            return Response(url=url, status=200, headers={"Content-Type": kind}, body=body)
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise FetchError(f"couldn't fetch it ({type(exc).__name__})", network=True) from None
        except (UnicodeError, ValueError):
            raise FetchError("not an address that can be read") from None
        finally:
            conn.close()
    raise FetchError("too many redirects")


_TYPE = re.compile(r"[a-z0-9.+-]{1,40}/[a-z0-9.+-]{1,40}")


def _read(conn, answer, deadline: float, clock) -> bytes:
    """The body, in pieces, within the size cap and the whole fetch's deadline: a
    server sending a byte every few seconds can't hold the page for long."""
    chunks, size = [], 0
    while True:
        left = deadline - clock()
        if left <= 0:
            raise FetchError("too slow")
        sock = getattr(conn, "sock", None)
        if sock is not None:
            sock.settimeout(min(TIMEOUT, left))
        piece = answer.read(min(65_536, MAX_BYTES + 1 - size))
        if not piece:
            return b"".join(chunks)
        chunks.append(piece)
        size += len(piece)
        if size > MAX_BYTES:
            raise FetchError("longer than 4 MiB")


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


def related(store, decision_id: int) -> list[int]:
    """This approve and every other approve of the same threat (a CVE in common):
    deciding again after a new sign of attacks keeps what a person added."""
    row = store.db.execute("SELECT cves FROM decision WHERE id = ?", (decision_id,)).fetchone()
    if row is None:
        return [decision_id]
    cves = set(json.loads(row["cves"]))
    ids = [
        r["id"]
        for r in store.db.execute("SELECT id, cves FROM decision WHERE verdict = 'approve'")
        if cves & set(json.loads(r["cves"]))
    ]
    return sorted(set(ids) | {decision_id})


def listed(store, decision_id: int) -> list[Added]:
    """The pages added to this threat's approves, this one and earlier ones."""
    ids = related(store, decision_id)
    rows = store.db.execute(
        "SELECT id, url, added_by, added_at, fetch_id, outcome, removed_at FROM added_source"  # noqa: S608 - ? marks only
        f" WHERE decision_id IN ({', '.join('?' for _ in ids)}) ORDER BY id",
        ids,
    ).fetchall()
    return [Added(*tuple(r)) for r in rows]


class AddError(Exception):
    pass


def add(store, decision_id: int, url: str, by: str, now, fetch=get, skip=frozenset()) -> Added:
    """Fetch a page and add it to the approve's sources, or say why not. What
    happened is kept either way (a failure, as its outcome). `skip`: the addresses
    the drafter reads already (the vendors' records and their linked pages)."""
    url = url.strip()
    try:
        check(url)
    except FetchError as exc:
        raise AddError(f"{exc}") from None
    if url in skip or url.rstrip("/") in skip:
        raise AddError("the drafter reads it already, from the vendors' records")
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
        # Again, inside the write: another add may have finished while this one fetched.
        current = [a for a in listed(store, decision_id) if a.kept]
        if outcome == "kept" and any(a.url == url for a in current):
            raise AddError("it is added already")
        if outcome == "kept" and len(current) >= MAX_ADDED:
            raise AddError(f"at most {MAX_ADDED} added pages a threat; take one back first")
        cur = store.db.execute(
            "INSERT INTO added_source (decision_id, url, added_by, added_at, fetch_id, outcome)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (decision_id, url, by, when, fetch_id, outcome),
        )
    return Added(cur.lastrowid, url, by, when, fetch_id, outcome, None)


def take_back(store, decision_id: int, added_id: int, now) -> None:
    ids = related(store, decision_id)
    with store.transaction():
        done = store.db.execute(
            "UPDATE added_source SET removed_at = ? WHERE id = ? AND removed_at IS NULL"  # noqa: S608
            f" AND decision_id IN ({', '.join('?' for _ in ids)})",
            (timeutil.fmt(now()), added_id, *ids),
        ).rowcount
    if not done:
        raise AddError("not an added page of this threat")


_TEXTS: dict[tuple[str, int], str] = {}  # a fetch's words, by store and fetch id


def kept_text(store, fetch_id: int, read=None) -> str | None:
    """A kept fetch's words, read once per process (a fetch never changes)."""
    key = (str(store.path), fetch_id)
    if key not in _TEXTS:
        body = store.fetch_body(fetch_id)
        if body is None:
            return None
        if len(_TEXTS) > 256:
            _TEXTS.clear()
        _TEXTS[key] = (read or text_of)(body)
    return _TEXTS[key]


def pages(store, decision_id: int) -> list[tuple[Added, str, str | None]]:
    """The kept pages: (the record, its words, its sha256)."""
    out = []
    for a in listed(store, decision_id):
        if not a.kept:
            continue
        text = kept_text(store, a.fetch_id)
        row = store.db.execute("SELECT sha256 FROM fetches WHERE id = ?", (a.fetch_id,)).fetchone()
        if text is None or row is None:
            continue
        out.append((a, text, row["sha256"]))
    return out


# the addresses one hop further


def further(texts: list[str], have: set[str], limit: int = 15) -> list[str]:
    """Addresses the pages already read give, not read themselves: one click on the
    card adds one. `have`: what is read already, by hand or by the drafter itself."""
    seen: list[str] = []
    for text in texts:
        for url in textcheck._URL.findall(text):
            url = url.rstrip(".,;:)]}'\"")
            try:
                check(url)
            except FetchError:
                continue
            if url in have or url.rstrip("/") in have or url in seen:
                continue
            seen.append(url)
            if len(seen) >= limit:
                return seen
    return seen
