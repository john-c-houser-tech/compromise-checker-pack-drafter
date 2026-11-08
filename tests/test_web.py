"""A.4: decisions, and the candidate page with its guards."""

from __future__ import annotations

import http.client
import re
import sqlite3
import threading
import urllib.parse

import pytest

from drafter import candidates as c
from drafter import cli, decisions, web
from drafter.store import Store
from tests.conftest import NOW
from tests.test_candidates import _kev, _nvd, _pkg, _vendor

PHP = ("CVE-2026-109618", "CVE-2026-109619")
KERNEL = "CVE-2026-98432"
SINCE = "2026-10-01T00:00:00.000000Z"


def _seed(store):
    for cve in PHP:
        _nvd(store, cve, "2026-10-21T00:00:00.000000Z")
        _vendor(store, cve, "ubuntu", [_pkg("ubuntu:24.04", "php8.3")])
        _vendor(store, cve, "redhat", [_pkg("rhel:9", "php")])
    _nvd(store, KERNEL, "2026-10-15T00:00:00.000000Z")
    _vendor(store, KERNEL, "ubuntu", [_pkg("ubuntu:24.04", "linux-aws")])
    _vendor(store, KERNEL, "redhat", [], found=0)


def _threats(store):
    return c.threats(c.classify(store, SINCE, now=NOW))


def _php(store):
    return next(t for t in _threats(store) if t.kind == "judge")


# the record


def test_a_decision_is_kept_with_its_cves_and_reason(store):
    _seed(store)
    d = decisions.record(store, _php(store), "approve", "  PHP2Shell\n again ", "jch", "t1")
    assert d.cves == PHP and d.reason == "PHP2Shell again" and d.families == ("php",)
    [back] = decisions.history(store)
    assert back == d
    st = decisions.state(_php(store), decisions.latest([back]))
    assert st.word == "approve" and not st.open
    assert decisions.describe(st) == "approved t1: PHP2Shell again"


def test_decisions_are_append_only(store):
    _seed(store)
    decisions.record(store, _php(store), "reject", "no", "jch", "t1")
    for sql in ("UPDATE decision SET reason = 'yes'", "DELETE FROM decision"):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store.db.execute(sql)


def test_a_later_decision_stands_in_front(store):
    _seed(store)
    decisions.record(store, _php(store), "reject", "not yet", "jch", "t1")
    decisions.record(store, _php(store), "approve", "now it is", "jch", "t2")
    decided = decisions.history(store)
    assert [d.reason for d in decided] == ["now it is", "not yet"]
    assert decisions.state(_php(store), decisions.latest(decided)).word == "approve"


def test_a_cve_that_joins_later_asks_for_a_look_again(store):
    _nvd(store, PHP[0], "2026-10-21T00:00:00.000000Z")
    _vendor(store, PHP[0], "ubuntu", [_pkg("ubuntu:24.04", "php8.3")])
    _vendor(store, PHP[0], "redhat", [_pkg("rhel:9", "php")])
    decisions.record(store, _php(store), "approve", "yes", "jch", "t1")
    _nvd(store, PHP[1], "2026-10-23T00:00:00.000000Z")
    _vendor(store, PHP[1], "ubuntu", [_pkg("ubuntu:24.04", "php8.3")])
    _vendor(store, PHP[1], "redhat", [_pkg("rhel:9", "php")])
    st = decisions.state(_php(store), decisions.latest(decisions.history(store)))
    assert st.word == "again" and st.open and st.new == (PHP[1],)
    assert "CVE-2026-109619 came after it" in decisions.describe(st)


def test_cves_decided_apart_ask_for_a_look_again():
    one = decisions.Decision(1, "t1", (PHP[0],), "judge", ("php",), "approve", "a", "jch")
    two = decisions.Decision(2, "t2", (PHP[1],), "judge", ("php",), "approve", "b", "jch")
    threat = c.Threat("judge", ["php"], [c.Candidate(cve, [], "judge") for cve in PHP])
    st = decisions.state(threat, decisions.latest([two, one]))
    assert st.word == "again" and st.decision == two and st.apart == (PHP[0],)
    assert decisions.state(threat, {}).word == "undecided"


@pytest.mark.parametrize(
    ("verdict", "reason", "message"),
    [
        ("approve", " \n\t ", "a reason is needed"),
        ("approve", "x" * 1001, "1000 at most"),
        ("maybe", "fine", "approve or reject"),
    ],
)
def test_a_decision_needs_a_verdict_and_a_reason(store, verdict, reason, message):
    _seed(store)
    with pytest.raises(decisions.DecisionError, match=message):
        decisions.record(store, _php(store), verdict, reason, "jch", "t1")
    assert decisions.history(store) == []


def test_kernels_and_set_asides_are_not_decided_here(store):
    _seed(store)
    kernel = next(t for t in _threats(store) if t.kind == "kernel")
    with pytest.raises(decisions.DecisionError, match="kernel"):
        decisions.record(store, kernel, "approve", "x", "jch", "t1")


def test_reasons_lose_control_and_bidi_characters(store):
    _seed(store)
    d = decisions.record(store, _php(store), "approve", "ok\x1b[31m ‮good", "jch", "t1")
    assert d.reason == "ok [31m good"


def test_the_cli_list_and_decisions_show_them(tmp_path, capsys):
    s = Store(tmp_path / "drafter.sqlite3")
    _seed(s)
    decisions.record(s, _php(s), "reject", "a test\x1b", "jch", "2026-11-07T12:00:00Z")
    s.close()
    assert cli.main(["--home", str(tmp_path), "decisions"]) == 0
    out = capsys.readouterr().out
    assert "rejected  php  CVE-2026-109618, CVE-2026-109619  by jch: a test" in out
    assert "\x1b" not in out
    assert cli.main(["--home", str(tmp_path), "candidates", "list", "--days", "60"]) == 0
    out = capsys.readouterr().out
    assert "decision: rejected 2026-11-07: a test" in out


# the page


class Page:
    def __init__(self, site, server):
        self.site, self.server = site, server
        self.origin = f"http://127.0.0.1:{site.port}"

    def request(self, method, path="/", body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.site.port, timeout=5)
        sent = {"Host": f"127.0.0.1:{self.site.port}", **(headers or {})}
        conn.request(method, path, body=body, headers=sent)
        response = conn.getresponse()
        data = response.read().decode(errors="replace")
        conn.close()
        return response, data

    def form(self, **fields):
        base = {
            "token": self.site.token,
            "kind": "judge",
            "cves": ",".join(PHP),
            "verdict": "approve",
            "reason": "PHP2Shell",
        }
        return urllib.parse.urlencode({**base, **fields})

    def post(self, body, **headers):
        sent = {
            "Origin": self.origin,
            "Content-Type": "application/x-www-form-urlencoded",
            **headers,
        }
        return self.request("POST", "/decide", body, {k: v for k, v in sent.items() if v})


@pytest.fixture
def page(tmp_path):
    s = Store(tmp_path / "drafter.sqlite3")
    _seed(s)
    s.close()
    site = web.Site(home=tmp_path, port=0, by="jch", now=lambda: NOW, days=60)
    server = web.make_server(site)
    site.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True)
    thread.start()
    yield Page(site, server)
    server.shutdown()
    server.server_close()


def _stored(page):
    s = Store(page.site.store_path, read_only=True)
    try:
        return decisions.history(s)
    finally:
        s.close()


def test_the_page_lists_threats_with_their_forms(page):
    response, html = page.request("GET")
    assert response.status == 200
    assert response.getheader("Content-Security-Policy") == web.CSP
    assert response.getheader("X-Frame-Options") == "DENY"
    assert 'id="t-cve-2026-109618"' in html and "Undecided" in html
    assert html.count('action="/decide"') == 1  # the kernel gets no form
    assert f'value="{page.site.token}"' in html
    for path in web.STATIC:
        assert page.request("GET", path)[0].status == 200


def test_a_decision_is_made_and_shown(page):
    response, _ = page.post(page.form(reason="redo as the A.9 test"))
    assert response.status == 303
    assert response.getheader("Location") == "/#t-cve-2026-109618"
    [d] = _stored(page)
    assert (d.verdict, d.reason, d.decided_by, d.cves) == (
        "approve",
        "redo as the A.9 test",
        "jch",
        PHP,
    )
    _, html = page.request("GET")
    assert "Approved" in html and "redo as the A.9 test" in html and "Decide again" in html


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({"Origin": None}, 403),
        ({"Origin": "https://evil.example"}, 403),
        ({"Origin": "null"}, 403),
        ({"Sec-Fetch-Site": "cross-site"}, 403),
        ({"Sec-Fetch-Site": "same-site"}, 403),
        ({"Content-Type": "application/json"}, 403),
        ({"Content-Type": "text/plain"}, 403),
        ({"Host": "evil.example"}, 421),
        ({"Host": "packs.localhost:8443.evil.example"}, 421),
    ],
)
def test_a_form_from_anywhere_else_is_refused(page, headers, status):
    response, _ = page.post(page.form(), **headers)
    assert response.status == status
    assert _stored(page) == []


def test_the_page_answers_only_to_its_own_names(page):
    assert page.request("GET", headers={"Host": "rebound.example"})[0].status == 421
    response, _ = page.request("GET", headers={"Host": "packs.localhost:8443"})
    assert response.status == 200


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ("token=x&kind=judge&cves=CVE-2026-109618,CVE-2026-109619&verdict=approve&reason=r", 403),
        ("token=T&kind=judge&cves=CVE-2026-109618&verdict=approve&reason=r", 409),
        ("token=T&kind=kernel&cves=CVE-2026-98432&verdict=approve&reason=r", 400),
        ("token=T&kind=judge&cves=CVE-2026-109618,CVE-2026-109619&verdict=maybe&reason=r", 400),
        ("token=T&kind=judge&cves=CVE-2026-109618,CVE-2026-109619&verdict=approve&reason=+", 400),
        ("token=T&kind=judge&cves=CVE-2026-109618,CVE-2026-109619&verdict=approve", 400),
        (
            "token=T&kind=judge&cves=CVE-2026-109618,CVE-2026-109619&verdict=approve"
            "&verdict=reject&reason=r",
            400,
        ),
        ("token=T&a=1&&b", 400),
        ("token=T&reason=%ff", 400),
    ],
)
def test_odd_forms_are_refused(page, body, status):
    response, _ = page.post(body.replace("token=T", f"token={page.site.token}"))
    assert response.status == status
    assert _stored(page) == []


def test_a_refused_reason_stays_in_its_box(page):
    response, html = page.post(page.form(reason="x" * 1001))
    assert response.status == 400
    assert "1000 at most" in html
    box = re.search(r'id="r-t-cve-2026-109618"[^>]*>([^<]*)</textarea>', html)
    assert box and box.group(1) == "x" * 1001


def test_a_long_or_unsized_body_is_refused(page):
    big = page.form(reason="x" * (web.MAX_BODY + 1))
    assert page.post(big)[0].status == 413
    conn = http.client.HTTPConnection("127.0.0.1", page.site.port, timeout=5)
    conn.putrequest("POST", "/decide", skip_host=True)
    for name, value in (
        ("Host", f"127.0.0.1:{page.site.port}"),
        ("Origin", page.origin),
        ("Content-Type", "application/x-www-form-urlencoded"),
    ):
        conn.putheader(name, value)
    conn.endheaders()
    assert conn.getresponse().status == 411
    conn.close()


def test_feed_text_is_escaped(page):
    s = Store(page.site.store_path)
    _kev(s, PHP[0], "2026-10-26")
    s.db.execute("UPDATE kev SET vendor = '<script>alert(1)</script>' WHERE cve = ?", (PHP[0],))
    decisions.record(s, _php(s), "approve", '<img src=x onerror="alert(1)">', "jch", "t1")
    s.close()
    _, html = page.request("GET")
    assert "<script>alert" not in html and "<img src=x" not in html
    assert "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;" in html


def test_only_listed_files_are_served(page):
    for path in ("/../drafter.sqlite3", "/fonts/../style.css", "/static/style.css", "/x"):
        assert page.request("GET", path)[0].status == 404
