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
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field

from drafter import textcheck, timeutil
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
            rf"github\.com/(?P<owner>{_NAME})/(?P<repo>{_NAME})/security/advisories/(?P<id>{_GHSA})"
        ),
        lambda m: (
            f"https://api.github.com/repos/{m['owner']}/{m['repo']}/security-advisories/{m['id']}"
        ),
        "github",
    ),
    Kind(
        "a reviewed advisory",
        re.compile(rf"github\.com/advisories/(?P<id>{_GHSA})"),
        lambda m: f"https://api.github.com/advisories/{m['id']}",
        "github",
    ),
    Kind(
        "a Red Hat bulletin",
        re.compile(r"access\.redhat\.com/security/vulnerabilities/[A-Za-z0-9._-]{1,120}"),
        None,
        "html",
    ),
    Kind(
        "an Ubuntu notice",
        re.compile(r"ubuntu\.com/security/notices/(?P<id>USN-\d{1,6}-\d{1,3})"),
        lambda m: f"https://ubuntu.com/security/notices/{m['id']}.json",
        "usn",
    ),
    Kind(
        "a CISA alert",
        re.compile(r"www\.cisa\.gov/news-events/alerts/\d{4}/\d{2}/\d{2}/[a-z0-9-]{1,200}"),
        None,
        "html",
    ),
)


@dataclass(frozen=True)
class Link:
    kind: Kind
    url: str  # as the sources give it, without a query or fragment
    fetch: str  # the address read


def links(urls: set[str] | frozenset[str]) -> list[Link]:
    """The links of the five kinds, in D8's order, each page once."""
    found: dict[str, Link] = {}
    for url in urls:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.port not in (None, 443) or parts.username:
            continue
        host = (parts.hostname or "").lower()
        path = parts.path.rstrip("/")
        for kind in KINDS:
            m = kind.pattern.fullmatch(host + path)
            if m:
                link = f"https://{host}{path}"
                address = kind.api(m) if kind.api else link
                found.setdefault(address, Link(kind, link, address))
                break
    order = {k.name: i for i, k in enumerate(KINDS)}
    return sorted(found.values(), key=lambda li: (order[li.kind.name], li.url))


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

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in _VOID:
            if tag == "br":
                self._add("\n")
            return
        self._stack.append(tag)
        if tag in _SKIP:
            self._skip += 1
        if tag == "main":
            self._in_main += 1
        if tag in _BLOCK:
            self._add("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag not in self._stack:
            return  # a stray end tag
        while self._stack:
            open_tag = self._stack.pop()
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
        return "\n".join(f"{k}: {_strings(v)}" for k, v in value.items() if _strings(v))
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


_READ = {"github": github_text, "usn": usn_text, "html": html_text}
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
    if ctx.now() - when > REUSE_FOR:
        return None
    return row


def fetch(ctx, link: Link) -> Page:
    """Read one page, from the store if it was read in the last day. Raises
    FetchError or ValueError (never with the page's own text)."""
    row = _recent(ctx, link.fetch)
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
        body, sha, reused = answer.body, None, False
        sha = ctx.store.db.execute(
            "SELECT sha256 FROM fetches WHERE id = ?", (fetch_id,)
        ).fetchone()["sha256"]
    if body is None:
        raise FetchError("its answer isn't kept")
    try:
        text = _READ[link.kind.read](body)
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


def gather(ctx, urls: set[str] | frozenset[str], *, offline: bool = False) -> Gathered:
    """The linked pages for one draft, within D8's six and D10's budget. `offline`
    (a dry run, which records nothing): only pages read in the last day; the rest
    are `pending`, each counted at its most (MAX_PAGE) against the budget."""
    out = Gathered([], [])
    used = 0
    for i, link in enumerate(links(urls)):
        if i >= MAX_PAGES:
            out.left_out.append(f"{link.url} ({link.kind.name}): over the {MAX_PAGES} a draft")
            continue
        if offline and _recent(ctx, link.fetch) is None:
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
            page = fetch(ctx, link)
        except (FetchError, ValueError) as exc:
            out.left_out.append(f"{link.url} ({link.kind.name}): {str(exc)[:120]}")
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


def known_urls(text: str) -> frozenset[str]:
    """The addresses a page's words give, in every form a reference may take."""
    found: set[str] = set()
    for url in textcheck._URL.findall(text):
        found |= textcheck.url_forms(url)
    return frozenset(found)
