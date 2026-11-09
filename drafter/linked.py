"""B.1: the pages the sources link to, fetched with a draft (decisions D8 and D10).

The vendor records, NVD and CISA's catalogue name their advisories but don't hold
them: PHP2Shell's mitigation was in PHP's own advisory, which Red Hat and NVD
linked and the drafter never read (A.9). Five kinds of page are fetched, and no
others (D8), in this order:

1. a project's GitHub security advisory, through GitHub's API (JSON);
2. a reviewed GitHub advisory, through GitHub's API (JSON);
3. a Red Hat security bulletin (its page's text);
4. an Ubuntu security notice, as Ubuntu's JSON;
5. a CISA alert (its page's text).

At most six a draft. Each is cut at the drafter's 20,000 characters for a source,
and together they share 100,000 (D10): past that, the last in this order are left
out, and the draft's header says so. A page that can't be fetched is left out too,
said the same way: a draft never stops for one.

Every answer is kept in the store as a fetch (feed `linked`), so the draft shows
what it read. One fetched in the last day is read again from the store, not the
web: a dry run and the draft after it read the same text. The pages are fetched
text: data, never instructions, like every other source.
"""

from __future__ import annotations

import datetime as dt
import html.parser
import json
import re
import sqlite3
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field

from drafter import timeutil
from drafter.http import FetchError

MAX_PAGES = 6  # D8
BUDGET = 100_000  # D10: characters, all the linked pages of one draft together
MAX_PAGE = 20_000  # as a source is cut (draft.MAX_SOURCE)
MAX_BYTES = 4 * 1024 * 1024
REUSE_FOR = dt.timedelta(days=1)
FEED = "linked"

_GHSA = r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}"
_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?"


@dataclass(frozen=True)
class Kind:
    name: str
    pattern: re.Pattern  # the whole of a link's host and path
    api: Callable[[re.Match], str] | None  # the address read instead, if not the link
    read: str  # "github", "usn" or "html"


KINDS = (
    Kind(
        "a project's advisory",
        re.compile(
            rf"github\.com/(?P<owner>{_NAME})/(?P<repo>{_NAME})/security/advisories/(?P<id>{_GHSA})",
            re.ASCII,
        ),
        lambda m: (
            f"https://api.github.com/repos/{m['owner']}/{m['repo']}/security-advisories/{m['id']}"
        ),
        "github",
    ),
    Kind(
        "a reviewed advisory",
        re.compile(rf"github\.com/advisories/(?P<id>{_GHSA})", re.ASCII),
        lambda m: f"https://api.github.com/advisories/{m['id']}",
        "github",
    ),
    Kind(
        "a Red Hat bulletin",
        re.compile(
            r"access\.redhat\.com/security/vulnerabilities/[A-Za-z0-9][A-Za-z0-9_-]{0,119}",
            re.ASCII,
        ),
        None,
        "html",
    ),
    Kind(
        "an Ubuntu notice",
        re.compile(r"ubuntu\.com/security/notices/(?P<id>USN-\d{1,6}-\d{1,3})", re.ASCII),
        lambda m: f"https://ubuntu.com/security/notices/{m['id']}.json",
        "usn",
    ),
    Kind(
        "a CISA alert",
        re.compile(
            r"(?:www\.)?cisa\.gov/(?P<path>news-events/alerts/\d{4}/\d{2}/\d{2}/[a-z0-9-]{1,200})",
            re.ASCII,
        ),
        lambda m: f"https://www.cisa.gov/{m['path']}",
        "html",
    ),
)


@dataclass(frozen=True)
class Link:
    kind: Kind
    url: str  # as the sources give it, without a query or fragment
    fetch: str  # the address read


def links(urls: set[str] | frozenset[str]) -> list[Link]:
    """The links of the five kinds, in D8's order, each page once: a GitHub advisory
    linked both as the project's and as a reviewed one is the project's. An address
    that can't be read (a port of 99999) is passed over, never a stop."""
    order = {k.name: i for i, k in enumerate(KINDS)}
    found: dict[str, Link] = {}
    for url in sorted(urls):
        try:
            parts = urllib.parse.urlsplit(url)
            if parts.scheme != "https" or parts.port not in (None, 443) or parts.username:
                continue
        except ValueError:
            continue
        host = (parts.hostname or "").lower()
        path = parts.path.rstrip("/")
        for kind in KINDS:
            m = kind.pattern.fullmatch(host + path)
            if m:
                link = Link(kind, f"https://{host}{path}", kind.api(m) if kind.api else "")
                if not link.fetch:
                    link = Link(kind, link.url, link.url)
                key = m["id"] if kind.read == "github" else link.fetch
                held = found.get(key)
                if held is None or order[kind.name] < order[held.kind.name]:
                    found[key] = link
                break
    return sorted(found.values(), key=rank)


def rank(link: Link) -> tuple[int, str]:
    """A link's place in D8's order."""
    return (next(i for i, k in enumerate(KINDS) if k.name == link.kind.name), link.url)


# reading a page


_SKIP = {"script", "style", "noscript", "svg", "nav", "header", "footer", "form", "button",
         "template", "iframe", "select", "aside"}  # fmt: skip
_BLOCK = {"p", "div", "li", "ul", "ol", "br", "tr", "table", "section", "article", "main",
          "h1", "h2", "h3", "h4", "h5", "h6", "pre", "blockquote", "dd", "dt"}  # fmt: skip
_VOID = {"br", "img", "hr", "input", "meta", "link", "source", "wbr", "area", "base", "col"}


class _Text(html.parser.HTMLParser):
    """A page's words, in <main> when it has one: no scripts, menus or forms."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.all: list[str] = []
        self.main: list[str] = []
        self._skip = 0
        self._in_main = 0
        self._stack: list[str] = []
        self._open: dict[str, int] = {}  # how many of each tag the stack holds

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in _VOID:
            if tag == "br":
                self._add("\n")
            return
        self._stack.append(tag)
        self._open[tag] = self._open.get(tag, 0) + 1
        if tag in _SKIP:
            self._skip += 1
        if tag == "main":
            self._in_main += 1
        if tag in _BLOCK:
            self._add("\n")

    def handle_endtag(self, tag: str) -> None:
        if not self._open.get(tag):
            return  # a stray end tag
        while self._stack:
            open_tag = self._stack.pop()
            self._open[open_tag] -= 1
            if open_tag in _SKIP:
                self._skip -= 1
            if open_tag == "main":
                self._in_main -= 1
            if open_tag in _BLOCK:
                self._add("\n")
            if open_tag == tag:
                break

    def handle_data(self, data: str) -> None:
        self._add(data)

    def _add(self, text: str) -> None:
        if self._skip:
            return
        self.all.append(text)
        if self._in_main:
            self.main.append(text)


def html_text(body: bytes) -> str:
    parser = _Text()
    parser.feed(body.decode("utf-8", "replace"))
    parser.close()
    words = "".join(parser.main) if "".join(parser.main).strip() else "".join(parser.all)
    lines = (" ".join(line.split()) for line in words.splitlines())
    out: list[str] = []
    for line in lines:
        if line and (not out or out[-1] != line):
            out.append(line)
    return "\n".join(out)


def _strings(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "\n".join(s for s in (_strings(v) for v in value) if s)
    if isinstance(value, dict):
        pairs = ((k, _strings(v)) for k, v in value.items())
        return "\n".join(f"{k}: {text}" for k, text in pairs if text)
    return str(value)


def github_text(body: bytes) -> str:
    """A GitHub advisory's words: its summary, description, dates and the version
    ranges it gives (the AI may not write versions; the ranges are read, not
    copied). Nothing about who reported it."""
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("not an advisory")
    parts = [
        f"Summary: {_strings(data.get('summary'))}",
        f"Identifiers: {_strings([data.get('ghsa_id'), data.get('cve_id')])}",
        f"Severity: {_strings(data.get('severity'))}",
        f"Published: {_strings(data.get('published_at'))}; updated:"
        f" {_strings(data.get('updated_at'))}",
    ]
    for v in data.get("vulnerabilities") or []:
        if isinstance(v, dict):
            package = v.get("package") if isinstance(v.get("package"), dict) else {}
            parts.append(
                f"Affected: {_strings(package.get('name'))}"
                f" {_strings(v.get('vulnerable_version_range'))};"
                f" patched: {_strings(v.get('patched_versions'))}"
            )
    parts.append(f"Description:\n{_strings(data.get('description'))}")
    refs = data.get("references")
    if refs:
        parts.append(f"References:\n{_strings(refs)}")
    return "\n".join(parts)


def usn_text(body: bytes) -> str:
    """An Ubuntu notice's words. Not its package list: a package list in a source
    would let the AI name packages (draft.check), and packages come from vendor
    data elsewhere."""
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("not a notice")
    return "\n".join(
        [
            f"Title: {_strings(data.get('title'))}",
            f"Published: {_strings(data.get('published'))}",
            f"CVEs: {_strings(data.get('cves_ids'))}",
            f"Summary: {_strings(data.get('summary'))}",
            f"Description:\n{_strings(data.get('description'))}",
            f"Instructions:\n{_strings(data.get('instructions'))}",
            f"References:\n{_strings(data.get('references'))}",
        ]
    )


READ = {"github": github_text, "usn": usn_text, "html": html_text}
_HEADERS = {"github": {"Accept": "application/vnd.github+json"}}


# fetching


@dataclass(frozen=True)
class Page:
    link: Link
    text: str  # as read, before any cut
    fetch_id: int
    sha256: str | None
    reused: bool


def _recent(ctx, address: str):
    """The last good answer for this address, if it is under a day old."""
    row = ctx.store.db.execute(
        "SELECT id, sha256, fetched_at FROM fetches WHERE feed = ? AND url = ? AND status = 200"
        " AND (body IS NOT NULL OR same_as IS NOT NULL) ORDER BY id DESC LIMIT 1",
        (FEED, address),
    ).fetchone()
    if row is None:
        return None
    try:
        when = timeutil.parse(row["fetched_at"])
    except ValueError:
        return None
    age = ctx.now() - when
    if age > REUSE_FOR or age < -dt.timedelta(minutes=5):
        return None  # old, or stamped in the future: not to be trusted as recent
    return row


def fetch(ctx, link: Link, row=None, *, offline: bool = False) -> Page:
    """Read one page, from the store if it was read in the last day (`row`, when the
    caller has looked already). Raises FetchError or ValueError (never with the
    page's own text). `offline`: never from the web."""
    row = row if row is not None else _recent(ctx, link.fetch)
    if row is None and offline:
        raise FetchError("not read in the last day")
    if row is not None:
        body, fetch_id, sha, reused = (
            ctx.store.fetch_body(row["id"]),
            row["id"],
            row["sha256"],
            True,
        )
    else:
        answer, fetch_id = ctx.fetch(
            FEED, link.fetch, headers=_HEADERS.get(link.kind.read), max_bytes=MAX_BYTES
        )
        if answer.not_modified or not answer.body:
            raise FetchError("an empty answer")
        if urllib.parse.urlsplit(answer.url).hostname != urllib.parse.urlsplit(link.fetch).hostname:
            # Kept as fetched, but never as a good answer: no later draft reuses it.
            with ctx.store.transaction():
                ctx.store.db.execute("UPDATE fetches SET status = 0 WHERE id = ?", (fetch_id,))
            raise FetchError("redirected off its site")
        body, sha, reused = answer.body, None, False
        sha = ctx.store.db.execute(
            "SELECT sha256 FROM fetches WHERE id = ?", (fetch_id,)
        ).fetchone()["sha256"]
    if body is None:
        raise FetchError("its answer isn't kept")
    try:
        text = READ[link.kind.read](body)
    except (ValueError, RecursionError, UnicodeDecodeError, AttributeError, TypeError):
        raise ValueError("its answer couldn't be read") from None
    if not text.strip():
        raise ValueError("no words in it")
    return Page(link, text, fetch_id, sha, reused)


@dataclass
class Gathered:
    pages: list[Page]
    left_out: list[str]  # each with why: over six, over the budget, couldn't be read
    pending: list[Link] = field(default_factory=list)  # offline: not read in the last day


def gather(
    ctx, urls: set[str] | frozenset[str], *, offline: bool = False, reserved: int = 0
) -> Gathered:
    """The linked pages for one draft, within D8's six and D10's budget. `offline`
    (a dry run, which records nothing): only pages read in the last day; the rest
    are `pending`, each counted at its most (MAX_PAGE) against the budget.
    `reserved`: the characters a person's added pages take of the budget (B.2)."""
    out = Gathered([], [])
    used = reserved
    for link in links(urls):
        if len(out.pages) + len(out.pending) >= MAX_PAGES:
            out.left_out.append(f"{link.url} ({link.kind.name}): over the {MAX_PAGES} a draft")
            continue
        try:
            row = _recent(ctx, link.fetch)
        except sqlite3.OperationalError:
            out.left_out.append(f"{link.url} ({link.kind.name}): the store was busy")
            continue
        if offline and row is None:
            if used + MAX_PAGE > BUDGET:
                out.left_out.append(
                    f"{link.url} ({link.kind.name}): over the {BUDGET:,} characters the linked"
                    " pages share"
                )
                continue
            used += MAX_PAGE
            out.pending.append(link)
            continue
        try:
            page = fetch(ctx, link, row, offline=offline)
        except (FetchError, ValueError) as exc:
            out.left_out.append(f"{link.url} ({link.kind.name}): {str(exc)[:120]}")
            continue
        except sqlite3.OperationalError:
            out.left_out.append(f"{link.url} ({link.kind.name}): the store was busy")
            continue
        size = min(len(page.text), MAX_PAGE)
        if used + size > BUDGET:
            out.left_out.append(
                f"{link.url} ({link.kind.name}): over the {BUDGET:,} characters the linked"
                " pages share"
            )
            continue
        used += size
        out.pages.append(page)
    return out
