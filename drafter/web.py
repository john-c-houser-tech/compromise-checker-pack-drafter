"""A.4: the candidate page, for approving or rejecting each threat with a reason.

    drafter web [--port 8089] [--origin https://packs.localhost:8443]

One person on one laptop (plan D7): it listens on 127.0.0.1 only, behind Caddy at
https://packs.localhost:8443, and has no login. Any site open in the same browser
can still send a form to it, so a decision is taken only with this page's own
origin, a token from this run of the server, and a Host it expects (which also
stops a hostile name being pointed at 127.0.0.1). Everything shown comes from the
feeds and is escaped; the page runs no scripts, and its policy allows none.
"""

from __future__ import annotations

import datetime as dt
import getpass
import hmac
import logging
import secrets
import sqlite3
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path

import jinja2

from drafter import __version__, candidates, decisions, timeutil
from drafter.status import needing_a_look
from drafter.store import Store, StoreError

log = logging.getLogger(__name__)

DEFAULT_PORT = 8089
DEFAULT_ORIGIN = "https://packs.localhost:8443"
MAX_BODY = 8 * 1024
# How far back the page reads, so a threat still to decide stays on it after its
# last sign is older than --days: as far back as `candidates refresh` keeps vendor
# records current (its default window).
OPEN_FOR = dt.timedelta(days=180)
# But never before the page's first window (John, 2026-11-07): threats from before
# the page existed are history, not a backlog to work through.
OPEN_SINCE = dt.datetime(2026, 10, 8, tzinfo=dt.UTC)
CSP = (
    "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self';"
    " form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)
STATIC = {
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
    "/fonts/atkinson-hyperlegible-latin-400-normal.woff2": (
        "fonts/atkinson-hyperlegible-latin-400-normal.woff2",
        "font/woff2",
    ),
    "/fonts/atkinson-hyperlegible-latin-700-normal.woff2": (
        "fonts/atkinson-hyperlegible-latin-700-normal.woff2",
        "font/woff2",
    ),
    "/fonts/OFL.txt": ("fonts/OFL.txt", "text/plain; charset=utf-8"),
}
SECTIONS = (
    ("judge", "Can judge", "Vendor packages on a supported release."),
    (
        "thirdparty",
        "Third-party builds",
        "Watched products (thirdparty.toml): the vendors' records can't say; settled at fill-in.",
    ),
    ("kernel", "Kernels", "The tool can't judge these yet (plan D2): a notice only."),
    ("setaside", "Set aside", "In setaside.toml, each with its reason."),
)


@dataclass
class Site:
    home: Path
    port: int = DEFAULT_PORT
    origin: str = DEFAULT_ORIGIN
    days: int = 30
    by: str = field(default_factory=getpass.getuser)
    token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    now: Callable[[], dt.datetime] = timeutil.now

    @property
    def store_path(self) -> Path:
        return self.home / "drafter.sqlite3"

    @property
    def hosts(self) -> set[str]:
        return {
            urllib.parse.urlsplit(self.origin).netloc,
            f"127.0.0.1:{self.port}",
            f"localhost:{self.port}",
        }

    @property
    def origins(self) -> set[str]:
        return {self.origin, f"http://127.0.0.1:{self.port}", f"http://localhost:{self.port}"}


_env = jinja2.Environment(
    loader=jinja2.PackageLoader("drafter", "templates"),
    autoescape=True,
    undefined=jinja2.StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)


def anchor(threat: candidates.Threat) -> str:
    return "t-" + min(c.cve for c in threat.candidates).lower()


def _card(
    threat: candidates.Threat,
    by_cve: dict[str, decisions.Decision],
    listed: set[str],
    older: bool,
) -> dict:
    cands = threat.candidates
    via, repos = [], []
    for cand in cands:
        via += [v for v in cand.watched_via if v not in via]
        repos += [r for r in cand.rebuilt_by if r not in repos]
    named = sorted(
        {p for cand in cands for p in cand.products}
        | {f"CISA: {cand.kev_name}" for cand in cands if cand.kev_name}
    )
    return {
        "anchor": anchor(threat),
        "kind": threat.kind,
        "first": threat.first[:10],
        "name": ", ".join(threat.families) or "?",
        "families": ",".join(threat.families),
        "cves": sorted(c.cve for c in cands),
        "signals": sorted({s.describe() for c in cands for s in c.signals}),
        "packages": candidates._releases([p for c in cands for p in c.packages]),
        "matched": via,
        "named": named,
        "repos": repos,
        "reasons": sorted({r for c in cands for r in c.reasons}),
        "decidable": threat.kind in decisions.DECIDABLE,
        "state": decisions.state(threat, by_cve, listed),
        "older": older,
    }


def view(site: Site, store: Store) -> dict:
    now = site.now()
    since = timeutil.fmt(now - dt.timedelta(days=site.days))
    # The window's threats exactly as `drafter candidates list` groups them, so a
    # decision reads the same in both.
    found = candidates.classify(store, since, now=now)
    recent = candidates.threats(found)
    decided = decisions.history(store)
    by_cve = decisions.latest(decided)
    # Then CVEs first signalled before the window that no decision has touched,
    # grouped among themselves only, so they never change the window's groups. They
    # stay (marked) until someone decides them, instead of dropping off unseen; a
    # CVE ever decided is settled once it leaves the window, so ageing alone never
    # reopens a decision.
    in_window = {c.cve for c in found}
    wide = timeutil.fmt(max(now - max(OPEN_FOR, dt.timedelta(days=site.days)), OPEN_SINCE))
    before = [
        c
        for c in candidates.classify(store, wide, now=now)
        if c.cve not in in_window and c.cve not in by_cve
    ]
    earlier = [g for g in candidates.threats(before) if g.kind in decisions.DECIDABLE]
    # As the command-line list counts it: the window's CVEs only.
    listed = {c.cve for g in recent for c in g.candidates}
    shown: list[candidates.Threat] = []  # the threats with a form on the page
    sections = []
    for kind, title, blurb in SECTIONS:
        cards = []
        for group, older in [(g, False) for g in recent] + [(g, True) for g in earlier]:
            if group.kind != kind:
                continue
            card = _card(group, by_cve, listed, older)
            cards.append(card)
            if card["decidable"]:
                shown.append(group)
        sections.append(
            {
                "kind": kind,
                "title": title,
                "blurb": blurb,
                "cards": cards,
                "cves": sum(len(c["cves"]) for c in cards),
                "open": sum(1 for c in cards if c["decidable"] and c["state"].open),
            }
        )
    return {
        "since": since[:10],
        "days": site.days,
        "notes": needing_a_look(store, now),
        "sections": sections,
        "unnamed": [c for c in found if c.kind == "unnamed"],
        "elsewhere": sum(1 for c in found if c.kind == "elsewhere"),
        "unread": [c.cve for c in found if c.kind == "unread"],
        "older": sum(1 for s in sections for card in s["cards"] if card["older"]),
        "history": decided,
        "groups": recent + earlier,
        "shown": shown,
    }


def page(site: Site, data: dict, *, error: str | None = None, kept: dict | None = None) -> str:
    return _env.get_template("page.html.j2").render(
        **{k: v for k, v in data.items() if k not in ("groups", "shown")},
        token=site.token,
        error=error,
        kept={"anchor": "", "reason": "", **(kept or {})},
        version=__version__,
    )


def find(groups: list[candidates.Threat], kind: str, cves: list[str], families: list[str]):
    """The threat the form was for, if it is still just as the page showed it."""
    wanted = sorted(cves)
    for group in groups:
        if (
            group.kind == kind
            and sorted(c.cve for c in group.candidates) == wanted
            and list(group.families) == families
        ):
            return group
    return None


def nearest(groups: list[candidates.Threat], cves: list[str]) -> str:
    """The anchor of the threat that now holds most of these CVEs, or ""."""
    best, most = "", 0
    for group in groups:
        shared = len({c.cve for c in group.candidates} & set(cves))
        if shared > most:
            best, most = anchor(group), shared
    return best


class Handler(BaseHTTPRequestHandler):
    site: Site  # set on the subclass `make_server` builds
    server_version = "drafter"
    sys_version = ""
    timeout = 15

    def log_message(self, format, *args):  # noqa: A002 (the base class's name)
        log.debug("%s %s", self.address_string(), format % args)

    def _send(self, status: int, body: bytes, kind: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        # Not no-referrer: a page with that policy sends `Origin: null` on its own
        # forms, which _refuse must turn away (sandboxed frames send it too).
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _text(self, status: int, text: str) -> None:
        self._send(status, text.encode() + b"\n", "text/plain; charset=utf-8")

    def _html(self, status: int, html: str) -> None:
        self._send(status, html.encode(), "text/html; charset=utf-8", {"Cache-Control": "no-store"})

    def _host_ok(self) -> bool:
        if self.headers.get("Host", "") in self.site.hosts:
            return True
        self._text(HTTPStatus.MISDIRECTED_REQUEST, "not a name this page answers to")
        return False

    def do_HEAD(self):  # noqa: N802
        self.do_GET()

    def do_GET(self):  # noqa: N802
        if not self._host_ok():
            return
        path = urllib.parse.urlsplit(self.path).path
        if path in STATIC:
            name, kind = STATIC[path]
            body = resources.files("drafter").joinpath("static", name).read_bytes()
            self._send(HTTPStatus.OK, body, kind, {"Cache-Control": "max-age=3600"})
            return
        if path != "/":
            self._text(HTTPStatus.NOT_FOUND, "not here")
            return
        try:
            store = Store(self.site.store_path, read_only=True)
        except (StoreError, sqlite3.Error) as exc:
            self._text(HTTPStatus.SERVICE_UNAVAILABLE, _unreadable(exc))
            return
        try:
            data = view(self.site, store)
        except sqlite3.Error as exc:
            self._text(HTTPStatus.SERVICE_UNAVAILABLE, f"the store can't be read now: {exc}")
            return
        finally:
            store.close()
        self._html(HTTPStatus.OK, page(self.site, data))

    def _refuse(self) -> str | None:
        """Why this POST isn't one of this page's own forms, or None."""
        origin = self.headers.get("Origin")
        if origin not in self.site.origins:
            return "a decision comes from this page's own form"
        if self.headers.get("Sec-Fetch-Site", "same-origin") != "same-origin":
            return "a decision comes from this page's own form"
        kind = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if kind != "application/x-www-form-urlencoded":
            return "a decision is a form"
        return None

    def do_POST(self):  # noqa: N802
        if not self._host_ok():
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._text(HTTPStatus.LENGTH_REQUIRED, "a form says how long it is")
            return
        if not 0 < length <= MAX_BODY:
            self._text(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too long for a decision")
            return
        # Read before any refusal, so the connection is left clean for Caddy.
        raw = self.rfile.read(length)
        if urllib.parse.urlsplit(self.path).path != "/decide":
            self._text(HTTPStatus.NOT_FOUND, "not here")
            return
        why = self._refuse()
        if why:
            self._text(HTTPStatus.FORBIDDEN, why)
            return
        try:
            form = urllib.parse.parse_qs(
                raw.decode("utf-8"),
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=10,
            )
        except (UnicodeDecodeError, ValueError):
            self._text(HTTPStatus.BAD_REQUEST, "the form couldn't be read")
            return
        fields = {name: values[0] for name, values in form.items() if len(values) == 1}
        if set(fields) != set(form) or not {
            "token",
            "kind",
            "cves",
            "families",
            "verdict",
            "reason",
        } <= set(fields):
            self._text(HTTPStatus.BAD_REQUEST, "the form is missing a field")
            return
        if not hmac.compare_digest(fields["token"].encode(), self.site.token.encode()):
            # A page from an earlier run of the server: its token has gone.
            self._text(
                HTTPStatus.FORBIDDEN,
                "the page is from an earlier run of the server; load it again and decide there",
            )
            return
        self._decide(fields)

    def _decide(self, fields: dict[str, str]) -> None:
        try:
            store = Store(self.site.store_path)
        except (StoreError, sqlite3.Error) as exc:
            self._text(HTTPStatus.SERVICE_UNAVAILABLE, _unreadable(exc))
            return
        try:
            try:
                data = view(self.site, store)
            except sqlite3.Error as exc:
                self._text(HTTPStatus.SERVICE_UNAVAILABLE, f"the store is busy; try again: {exc}")
                return
            cves = [c for c in fields["cves"].split(",") if c]
            families = [f for f in fields["families"].split(",") if f]
            threat = find(data["groups"], fields["kind"], cves, families)
            # Back in the box of a threat that has one, whatever happened to the CVEs.
            kept = {"anchor": nearest(data["shown"], cves), "reason": fields["reason"]}
            if threat is None:
                self._html(
                    HTTPStatus.CONFLICT,
                    page(
                        self.site,
                        data,
                        error="That threat changed since the page loaded (a CVE joined or"
                        " left it, its packages changed, or it moved section). Look at it"
                        " again below; "
                        + (
                            "your reason is kept in its box."
                            if kept["anchor"]
                            else "it has no form now, so here is your reason: "
                            + _quoted(fields["reason"])
                        ),
                        kept=kept,
                    ),
                )
                return
            try:
                decisions.record(
                    store,
                    threat,
                    fields["verdict"],
                    fields["reason"],
                    self.site.by,
                    timeutil.fmt(self.site.now()),
                )
            except decisions.DecisionError as exc:
                self._html(
                    HTTPStatus.BAD_REQUEST,
                    page(self.site, data, error=str(exc), kept=kept),
                )
                return
            except sqlite3.OperationalError as exc:
                self._html(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    page(
                        self.site,
                        data,
                        error=f"The store is busy (the hourly run?): {exc}. Nothing was"
                        " recorded; send it again in a moment.",
                        kept=kept,
                    ),
                )
                return
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", f"/#{anchor(threat)}")
            self.send_header("Content-Length", "0")
            self.end_headers()
        finally:
            store.close()


def _quoted(reason: str) -> str:
    """A refused reason as one line, whatever it is (the page escapes it)."""
    text = " ".join("".join(ch if ch.isprintable() else " " for ch in reason).split())
    return text[: decisions.MAX_REASON] or "(none)"


def _unreadable(exc: Exception) -> str:
    text = f"the store can't be opened: {exc}"
    if isinstance(exc, StoreError):
        text += (
            ". If the drafter was installed again, restart this page so it runs the same"
            " code: systemctl --user restart pack-drafter-web"
        )
    return text


class Server(ThreadingHTTPServer):
    # A thread per request, so one slow client can't hold up the rest; each request
    # opens its own Store.
    daemon_threads = True


def make_server(site: Site) -> Server:
    # The store is upgraded here, once, rather than by the first page load.
    Store(site.store_path).close()
    handler = type("SiteHandler", (Handler,), {"site": site})
    return Server(("127.0.0.1", site.port), handler)
