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
        ("reject", " \n\t ", "a reason is needed to reject"),
        ("reject", "", "a reason is needed to reject"),
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
            "families": "php",
            "verdict": "approve",
            "reason": "PHP2Shell",
        }
        merged = {**base, **fields}
        if "signs" not in merged:  # as the page shows them now, as a browser sends them
            merged["signs"] = self.signs(merged["cves"])
        return urllib.parse.urlencode(merged)

    def signs(self, cves):
        _, html = self.request("GET")
        found = re.search(
            rf'name="cves" value="{re.escape(cves)}">\s*<input type="hidden" name="families"'
            r' value="[^"]*">\s*<input type="hidden" name="signs" value="([^"]*)"',
            html,
        )
        return found[1] if found else ""

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


PS = "&signs=nvd:CVE-2026-109618,nvd:CVE-2026-109619"  # the PHP card's signs, as shown
BOTH = "&cves=CVE-2026-109618,CVE-2026-109619&families=php"


@pytest.mark.parametrize(
    ("body", "status"),
    [
        (f"token=x&kind=judge{BOTH}{PS}&verdict=approve&reason=r", 403),
        (
            "token=T&kind=judge&cves=CVE-2026-109618&families=php&signs=nvd:CVE-2026-109618"
            "&verdict=approve&reason=r",
            409,
        ),
        (f"token=T&kind=judge{BOTH}&signs=&verdict=approve&reason=r", 409),  # shown no signs
        (f"token=T&kind=judge{BOTH}&signs=nvd:CVE-2026-109618&verdict=approve&reason=r", 409),
        (
            "token=T&kind=kernel&cves=CVE-2026-98432&families=kernel&signs=nvd:CVE-2026-98432"
            "&verdict=approve&reason=r",
            400,
        ),
        (f"token=T&kind=judge{BOTH}{PS}&verdict=maybe&reason=r", 400),
        (f"token=T&kind=judge{BOTH}{PS}&verdict=reject&reason=+", 400),
        (f"token=T&kind=judge{BOTH}{PS}&verdict=approve", 400),  # no reason field at all
        (f"token=T&kind=judge{BOTH}&verdict=approve&reason=r", 400),  # no signs field
        (f"token=T&kind=judge{BOTH}{PS}&verdict=approve&verdict=reject&reason=r", 400),
        ("token=T&a=1&&b", 400),
        ("token=T&reason=%ff", 400),
    ],
)
def test_odd_forms_are_refused(page, body, status):
    response, _ = page.post(body.replace("token=T", f"token={page.site.token}"))
    assert response.status == status
    assert _stored(page) == []


def test_the_forms_signs_are_the_ones_the_page_shows(page):
    assert page.signs(",".join(PHP)) == PS.removeprefix("&signs=")
    assert page.post(page.form(signs=PS.removeprefix("&signs=")))[0].status == 303


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


# review fixes


def test_a_real_browser_sends_its_origin_on_the_pages_own_forms(page):
    # `no-referrer` makes a browser send `Origin: null`, which is refused.
    response, _ = page.request("GET")
    assert response.getheader("Referrer-Policy") == "same-origin"


def _move_php_to_thirdparty(store):
    for cve in PHP:
        _nvd(store, cve, "2026-10-21T00:00:00.000000Z", products=("php:php",))
        _vendor(store, cve, "ubuntu", [], found=0)
        _vendor(store, cve, "redhat", [], found=0)


def test_a_decision_made_in_another_section_asks_again(store):
    _seed(store)
    decisions.record(store, _php(store), "reject", "not ours", "jch", "t1")
    _move_php_to_thirdparty(store)
    threat = next(t for t in _threats(store) if t.kind == "thirdparty")
    st = decisions.state(threat, decisions.latest(decisions.history(store)))
    assert st.word == "again" and st.section == "judge"
    assert "made under Can judge" in decisions.describe(st)


def test_a_decision_shown_with_other_packages_asks_again(store):
    _seed(store)
    decisions.record(store, _php(store), "approve", "yes", "jch", "t1")
    for cve in PHP:
        _vendor(
            store, cve, "ubuntu", [_pkg("ubuntu:24.04", "php8.3"), _pkg("ubuntu:24.04", "apache2")]
        )
    threat = _php(store)
    st = decisions.state(threat, decisions.latest(decisions.history(store)))
    assert threat.families == ["apache", "php"]
    assert st.word == "again" and st.families == ("php",)
    assert "shown as php" in decisions.describe(st)


def test_a_split_asks_again_but_an_aged_off_cve_does_not():
    d = decisions.Decision(1, "t1", PHP, "judge", ("php",), "approve", "a", "jch")
    one = c.Threat("judge", ["php"], [c.Candidate(PHP[0], [], "judge")])
    st = decisions.state(one, decisions.latest([d]), listed={PHP[0], PHP[1]})
    assert st.word == "again" and st.moved == (PHP[1],)
    assert "now in another threat" in decisions.describe(st)
    assert decisions.state(one, decisions.latest([d]), listed={PHP[0]}).word == "approve"


@pytest.mark.parametrize("value", ["CVE-2026-109618\n", "CVE-2026-109618\r", " CVE-2026-109618"])
def test_a_cve_with_anything_around_it_is_not_a_cve(value):
    from drafter.feeds import cve_or_none

    assert cve_or_none(value) is None


def test_a_nine_digit_cve_can_be_decided(store):
    cve = "CVE-2026-123456789"
    _nvd(store, cve, "2026-10-21T00:00:00.000000Z")
    _vendor(store, cve, "ubuntu", [_pkg("ubuntu:24.04", "php8.3")])
    _vendor(store, cve, "redhat", [], found=0)
    d = decisions.record(store, _php(store), "approve", "yes", "jch", "t1")
    assert d.cves == (cve,)


def test_a_409_keeps_the_reason_where_the_threat_now_is(page):
    s = Store(page.site.store_path)
    early = "CVE-2026-100000"
    _nvd(s, early, "2026-10-22T00:00:00.000000Z")
    _vendor(s, early, "ubuntu", [_pkg("ubuntu:24.04", "php8.3")])
    _vendor(s, early, "redhat", [_pkg("rhel:9", "php")])
    s.close()
    response, html = page.post(page.form(reason="kept for later"))
    assert response.status == 409
    box = re.search(r'id="r-t-cve-2026-100000"[^>]*>([^<]*)</textarea>', html)
    assert box and box.group(1) == "kept for later"
    assert _stored(page) == []


def test_a_form_for_other_packages_than_now_is_refused(page):
    response, _ = page.post(page.form(families="apache2,php"))
    assert response.status == 409
    assert _stored(page) == []


def test_a_busy_store_keeps_the_reason(page, monkeypatch):
    def busy(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(decisions, "record", busy)
    response, html = page.post(page.form(reason="try me again"))
    assert response.status == 503
    assert "Nothing was recorded" in html and ">try me again</textarea>" in html


def test_a_store_that_cant_be_read_is_a_503_not_a_dropped_connection(page, monkeypatch):
    def broken(*args, **kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(web, "view", broken)
    assert page.request("GET")[0].status == 503
    assert page.post(page.form())[0].status == 503


def test_a_newer_store_says_to_restart_the_page(page):
    db = sqlite3.connect(page.site.store_path)
    db.execute("PRAGMA user_version = 99")
    db.close()
    response, text = page.request("GET")
    assert response.status == 503 and "systemctl --user restart pack-drafter-web" in text


def test_one_slow_client_does_not_hold_up_the_page(page):
    import socket

    slow = socket.create_connection(("127.0.0.1", page.site.port))
    slow.sendall(b"GET / HTTP/1.1\r\nHo")  # and nothing more
    try:
        conn = http.client.HTTPConnection("127.0.0.1", page.site.port, timeout=2)
        conn.request("GET", "/style.css", headers={"Host": f"127.0.0.1:{page.site.port}"})
        assert conn.getresponse().status == 200
        conn.close()
    finally:
        slow.close()


def test_web_refuses_odd_flags_and_a_busy_store(tmp_path, monkeypatch, capsys):
    home = ["--home", str(tmp_path), "web"]
    assert cli.main([*home, "--days", "0"]) == 2
    assert cli.main([*home, "--days", "999999999"]) == 2
    assert cli.main([*home, "--origin", "https://packs.localhost:8443/x"]) == 2

    def busy(site):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(web, "make_server", busy)
    assert cli.main(home) == 1
    assert "database is locked" in capsys.readouterr().err


def test_a_threat_still_to_decide_stays_after_its_window(page):
    page.site.days = 10  # PHP's last sign is 17 days old, the kernel's 23
    _, html = page.request("GET")
    assert 'id="t-cve-2026-109618"' in html and "Before the 10 days" in html
    assert "and 1 older still to decide" in html
    assert 'id="t-cve-2026-98432"' not in html  # a notice only: it goes
    assert page.post(page.form())[0].status == 303
    _, html = page.request("GET")
    assert 'id="t-cve-2026-109618"' not in html  # decided: it goes too
    assert "still to decide" not in html


def _nginx(store, cve, when):
    _nvd(store, cve, when)
    _vendor(store, cve, "ubuntu", [_pkg("ubuntu:24.04", "nginx")])
    _vendor(store, cve, "redhat", [_pkg("rhel:9", "nginx")])


def test_the_window_is_grouped_as_the_list_groups_it(page, capsys):
    # A before the window, B and C in it: the page must not let A pull B away from C.
    s = Store(page.site.store_path)
    for cve, when in (
        ("CVE-2026-2001", "2026-10-09T00:00:00.000000Z"),
        ("CVE-2026-2002", "2026-10-20T00:00:00.000000Z"),
        ("CVE-2026-2003", "2026-11-02T00:00:00.000000Z"),
    ):
        _nginx(s, cve, when)
    s.close()
    page.site.days = 20
    _, html = page.request("GET")
    assert 'value="CVE-2026-2002,CVE-2026-2003"' in html
    assert 'value="CVE-2026-2001"' in html and "Before the 20 days" in html
    body = page.form(cves="CVE-2026-2002,CVE-2026-2003", families="nginx", reason="both")
    assert page.post(body)[0].status == 303
    home = str(page.site.home)
    assert cli.main(["--home", home, "candidates", "list", "--days", "20"]) == 0
    out = capsys.readouterr().out
    assert "decision: approved 2026-11-07: both" in out


def test_a_later_sign_does_not_bring_a_decided_older_threat_back(page):
    s = Store(page.site.store_path)
    _kev(s, "CVE-2026-3001", "2026-10-10")  # first sign, before the window
    _nginx(s, "CVE-2026-3001", "2026-11-05T00:00:00.000000Z")  # NVD re-stamped
    s.close()
    page.site.days = 20
    _, html = page.request("GET")
    assert 'id="t-cve-2026-3001"' in html and "Before the 20 days" in html
    body = page.form(cves="CVE-2026-3001", families="nginx", reason="old news")
    assert page.post(body)[0].status == 303
    _, html = page.request("GET")
    assert 'id="t-cve-2026-3001"' not in html and "still to decide" not in html


@pytest.mark.parametrize("value", ["2026-02-30", "2026-11-02\n", "2026-1-02", "today"])
def test_kev_dates_that_cant_be_read_are_left_out(value):
    from drafter.feeds import kev

    assert not kev._real_date(value)
    assert kev._real_date("2026-11-02")


def test_a_reason_with_no_box_left_is_shown_in_the_message(page):
    # PHP's CVEs move to the kernel notice after the page loaded: no form holds them.
    s = Store(page.site.store_path)
    for cve in PHP:
        _vendor(s, cve, "ubuntu", [_pkg("ubuntu:24.04", "linux-aws")])
        _vendor(s, cve, "redhat", [], found=0)
    s.close()
    response, html = page.post(page.form(reason="keep this somewhere"))
    assert response.status == 409
    assert "here is your reason: keep this somewhere" in html


def test_a_decision_straddling_the_window_edge_stays_decided(page, capsys):
    s = Store(page.site.store_path)
    _nginx(s, "CVE-2026-4001", "2026-10-09T00:00:00.000000Z")
    _nginx(s, "CVE-2026-4002", "2026-10-15T00:00:00.000000Z")
    s.close()
    page.site.days = 30  # both in the window: one threat
    body = page.form(cves="CVE-2026-4001,CVE-2026-4002", families="nginx", reason="both ok")
    assert page.post(body)[0].status == 303
    page.site.days = 27  # 4001 has left the window, 4002 hasn't
    _, html = page.request("GET")
    assert 'id="t-cve-2026-4001"' not in html  # decided: not back as older
    card = html.split('id="t-cve-2026-4002"', 1)[1].split("</article>", 1)[0]
    assert "Approved" in card and "Look again" not in card
    home = str(page.site.home)
    assert cli.main(["--home", home, "candidates", "list", "--days", "27"]) == 0
    assert "decision: approved 2026-11-07: both ok" in capsys.readouterr().out


def test_a_stale_form_for_a_decided_older_threat_is_refused(page):
    s = Store(page.site.store_path)
    _nginx(s, "CVE-2026-5001", "2026-10-10T00:00:00.000000Z")
    s.close()
    page.site.days = 20
    body = page.form(cves="CVE-2026-5001", families="nginx", reason="yes")
    assert page.post(body)[0].status == 303
    stale = page.form(cves="CVE-2026-5001", families="nginx", verdict="reject", reason="no")
    assert page.post(stale)[0].status == 409
    assert [d.verdict for d in _stored(page)] == ["approve"]


@pytest.mark.parametrize("reason", ["   ", "x" * 1500, "a\x00b"])
def test_a_refused_form_with_any_reason_gets_its_page(page, reason):
    s = Store(page.site.store_path)
    for cve in PHP:
        _vendor(s, cve, "ubuntu", [_pkg("ubuntu:24.04", "linux-aws")])
        _vendor(s, cve, "redhat", [], found=0)
    s.close()
    response, html = page.post(page.form(reason=reason))
    assert response.status == 409 and "here is your reason:" in html
    if not reason.strip():
        assert "here is your reason: (none)" in html


def test_a_time_is_read_without_its_surrounding_space_and_only_then():
    from drafter import timeutil

    assert timeutil.parse("2026-11-02T00:00:00Z\n") == timeutil.parse("2026-11-02")
    with pytest.raises(timeutil.TimeError):
        timeutil.parse("2026-11-02T00:00:00Z\nX")


def test_nothing_before_the_pages_first_window_comes_back(page):
    s = Store(page.site.store_path)
    _nginx(s, "CVE-2026-7001", "2026-10-07T00:00:00.000000Z")  # the day before
    _nginx(s, "CVE-2026-7002", "2026-10-08T12:00:00.000000Z")  # its first day
    s.close()
    page.site.days = 20
    _, html = page.request("GET")
    assert 'id="t-cve-2026-7001"' not in html
    assert 'id="t-cve-2026-7002"' in html


def test_a_look_again_threat_is_settled_once_it_leaves_the_window(page):
    assert page.post(page.form(reason="yes"))[0].status == 303
    s = Store(page.site.store_path)
    for cve in PHP:
        _vendor(s, cve, "ubuntu", [_pkg("ubuntu:24.04", "php8.3"), _pkg("ubuntu:24.04", "apache2")])
    s.close()
    _, html = page.request("GET")
    assert "Look again" in html.split('id="t-cve-2026-109618"', 1)[1].split("</article>")[0]
    page.site.days = 10
    _, html = page.request("GET")
    assert 'id="t-cve-2026-109618"' not in html


# A.4b: what each card says, Covered, an approve without a reason, and attacks
# that come after a reject


def _rated_only(store, cve, when="2026-10-20T00:00:00.000000Z", package="dotnet8.0"):
    from tests.test_candidates import _rh

    _rh(store, cve, when)
    _nvd(store, cve, when, exploitation="none")
    _vendor(store, cve, "ubuntu", [])
    _vendor(store, cve, "redhat", [_pkg("rhel:9", package)])


DOTNET = "CVE-2026-70188"


def _card_html(html, cve):
    return html.split(f'id="t-{cve.lower()}"', 1)[1].split("</article>", 1)[0]


def _with(page, fn):
    s = Store(page.site.store_path)
    try:
        fn(s)
    finally:
        s.close()


def test_a_card_says_whether_it_is_attacked_and_what_it_is(page):
    def seed(s):
        _rated_only(s, DOTNET)
        s.db.execute(
            "UPDATE vendor_cve SET title = 'dotnet: smuggling', statement = ? WHERE cve = ?",
            ("Kestrel <script>alert(1)</script> is exposed.", DOTNET),
        )
        s.db.execute(
            "UPDATE nvd SET cvss = ? WHERE cve = ?",
            (
                '{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",'
                ' "score": 9.1, "source": "secure@microsoft.com"}',
                DOTNET,
            ),
        )

    _with(page, seed)
    _, html = page.request("GET")
    card = _card_html(html, DOTNET)
    assert "No sign of attacks" in card and "CISA says none (2026-10-20)" in card
    assert "Listed on Red Hat&#39;s Critical rating alone" in card
    assert "Red Hat: dotnet: smuggling" in card
    assert (
        "Over the network, no login, no user action (CVSS 3.1: 9.1, Microsoft&#39;s score)" in card
    )
    assert "Fixed on every listed release" in card
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in card and "<script" not in html
    php = _card_html(html, PHP[0])
    assert "Exploited" in php and "CISA says active (2026-10-21), for both" in php
    assert "Signals" not in php
    assert "Signals" in _card_html(html, KERNEL)  # a notice keeps its plain list


def test_an_approve_needs_no_reason_and_a_reject_does(page, capsys):
    response, html = page.post(page.form(verdict="reject", reason="  "))
    assert response.status == 400 and "a reason is needed to reject" in html
    assert page.post(page.form(reason=""))[0].status == 303
    [d] = _stored(page)
    assert (d.verdict, d.reason) == ("approve", "")
    _, html = page.request("GET")
    card = _card_html(html, PHP[0])
    assert "UTC by jch" in card and "no reason" not in card  # an approve needs none
    assert "<td>–</td>" in html
    assert cli.main(["--home", str(page.site.home), "decisions"]) == 0
    out = capsys.readouterr().out
    assert out.rstrip().endswith("by jch") and "no reason" not in out
    assert cli.main(["--home", str(page.site.home), "candidates", "list", "--days", "60"]) == 0
    assert "decision: approved 2026-11-07\n" in capsys.readouterr().out


def test_a_reject_comes_back_when_attacks_are_reported_after_it(page, capsys):
    _with(page, lambda s: _rated_only(s, DOTNET))
    body = page.form(cves=DOTNET, families="dotnet", verdict="reject", reason="no sign of attacks")
    assert page.post(body)[0].status == 303
    [d] = _stored(page)
    assert d.signs == ()
    _, html = page.request("GET")
    assert "pill-reject" in _card_html(html, DOTNET)
    _with(page, lambda s: _kev(s, DOTNET, "2026-11-07"))
    _, html = page.request("GET")
    card = _card_html(html, DOTNET)
    assert "Look again" in card and "Attacks reported since:</strong> on CISA&#39;s list" in card
    assert "2 to decide" in html  # it, and PHP
    home = str(page.site.home)
    assert cli.main(["--home", home, "candidates", "list", "--days", "60"]) == 0
    assert "attacks reported since: on CISA's list 2026-11-07" in capsys.readouterr().out
    # deciding again settles it, with the new sign kept
    assert page.post(page.form(cves=DOTNET, families="dotnet", reason=""))[0].status == 303
    assert _stored(page)[0].signs == (f"kev:{DOTNET}",)
    _, html = page.request("GET")
    card = _card_html(html, DOTNET)
    assert "pill-approve" in card and "Look again" not in card


def test_an_approve_or_a_restamped_sign_does_not_come_back(page):
    def seed(s):
        _rated_only(s, DOTNET)
        for cve in PHP:  # on CISA's list too, so a re-stamp doesn't move its first sign
            _kev(s, cve, "2026-10-21")

    _with(page, seed)
    body = page.form(cves=DOTNET, families="dotnet", reason="yes")
    assert page.post(body)[0].status == 303
    assert page.post(page.form(verdict="reject", reason="covered by hand"))[0].status == 303

    def later(s):
        _kev(s, DOTNET, "2026-11-07")  # after an approve: nothing to look at again
        _nvd(s, PHP[0], "2026-11-06T00:00:00.000000Z")  # CISA re-stamps PHP's rating

    _with(page, later)
    _, html = page.request("GET")
    dotnet = _card_html(html, DOTNET)
    assert "pill-approve" in dotnet and "Look again" not in dotnet
    php = _card_html(html, PHP[0])
    assert "Rejected" in php and "Look again" not in php


def test_a_reject_made_before_schema_5_is_not_brought_back(page):
    _with(page, lambda s: _rated_only(s, DOTNET))

    def old_reject(s):
        s.db.execute(
            "INSERT INTO decision (decided_at, cves, kind, families, verdict, reason,"
            " decided_by, signs) VALUES ('2026-11-01T00:00:00Z', ?, 'judge', '[\"dotnet\"]',"
            " 'reject', 'old', 'jch', NULL)",
            (f'["{DOTNET}"]',),
        )
        _kev(s, DOTNET, "2026-11-07")

    _with(page, old_reject)
    _, html = page.request("GET")
    card = _card_html(html, DOTNET)
    assert "pill-reject" in card and "Look again" not in card


def test_an_older_reject_comes_back_after_its_window(page):
    _with(page, lambda s: _rated_only(s, DOTNET, "2026-10-10T00:00:00.000000Z"))
    page.site.days = 20
    body = page.form(cves=DOTNET, families="dotnet", verdict="reject", reason="no attacks")
    assert page.post(body)[0].status == 303
    _, html = page.request("GET")
    assert f'id="t-{DOTNET.lower()}"' not in html  # settled once out of the window
    _with(page, lambda s: _kev(s, DOTNET, "2026-11-07"))
    _, html = page.request("GET")
    card = _card_html(html, DOTNET)
    assert "Before the 20 days" in card and "Look again" in card
    assert "and 1 older still to decide" in html


def _packs(tmp_path, pack_text=None):
    from tests.test_cards import PHP_PACK, _clone

    return _clone(
        tmp_path,
        '  - {id: "php2shell-2026-10", version: 1, sha256: "x"}\n',
        {"php2shell-2026-10": pack_text or PHP_PACK},
    )


def test_a_threat_a_signed_pack_names_reads_covered(page, tmp_path):
    page.site.packs = _packs(tmp_path)
    _, html = page.request("GET")
    card = _card_html(html, PHP[0])
    assert "Covered" in card and "Undecided" not in card
    assert "Signed pack <strong>php2shell-2026-10</strong> (version 1) names both CVEs" in card
    assert "<summary>Decide anyway</summary>" in card and 'action="/decide"' in card
    assert "to decide" not in html.split("</nav>")[0]
    # deciding anyway is an ordinary decision, and then shows as one
    assert (
        page.post(page.form(verdict="reject", reason="covered by the signed pack"))[0].status == 303
    )
    _, html = page.request("GET")
    card = _card_html(html, PHP[0])
    assert "Rejected" in card and "Covered" not in card and "Signed pack" in card


def test_a_pack_naming_some_of_the_cves_leaves_the_form_open(page, tmp_path):
    one = "id: php2shell-2026-10\nversion: 1\ncves: [CVE-2026-109618]\n"
    page.site.packs = _packs(tmp_path, one)
    _, html = page.request("GET")
    card = _card_html(html, PHP[0])
    assert "names CVE-2026-109618, not CVE-2026-109619" in card
    assert "Undecided" in card and "Decide anyway" not in card and "1 to decide" in html


def test_packs_that_cant_be_read_mark_nothing_covered(page, tmp_path):
    page.site.packs = _packs(tmp_path, "id: someone-else\nversion: 1\ncves: [CVE-2026-109618]\n")
    _, html = page.request("GET")
    assert "Signed packs couldn't be read" in html and "isn&#39;t the pack" in html
    assert "Undecided" in _card_html(html, PHP[0])
    page.site.packs = tmp_path / "gone"
    _, html = page.request("GET")
    assert "Signed packs couldn't be read" in html


def test_web_wants_a_clone_with_an_index(tmp_path, capsys):
    assert cli.main(["--home", str(tmp_path), "web", "--packs", str(tmp_path / "nope")]) == 2
    assert "no index.yaml" in capsys.readouterr().err


def test_a_form_from_a_page_that_didnt_show_a_new_sign_is_refused(page):
    _with(page, lambda s: _rated_only(s, DOTNET))
    body = page.form(cves=DOTNET, families="dotnet", verdict="reject", reason="no attacks")
    _with(page, lambda s: _kev(s, DOTNET, "2026-11-07"))  # the hourly run, meanwhile
    response, html = page.post(body)
    assert response.status == 409 and "attacks were reported" in html
    assert "no attacks</textarea>" in html  # the reason kept in its box
    assert _stored(page) == []
    body = page.form(cves=DOTNET, families="dotnet", verdict="reject", reason="still no")
    assert page.post(body)[0].status == 303
    assert _stored(page)[0].signs == (f"kev:{DOTNET}",)


def test_a_reject_made_knowing_of_attacks_isnt_brought_back_by_cisas_list(page):
    # PHP: CISA said active when it was rejected; CISA's list adding it is no news.
    assert page.post(page.form(verdict="reject", reason="GitLab, not Ruby"))[0].status == 303
    _with(page, lambda s: [_kev(s, cve, "2026-11-07") for cve in PHP])
    _, html = page.request("GET")
    card = _card_html(html, PHP[0])
    assert "pill-reject" in card and "Look again" not in card


def test_a_reject_comes_back_for_its_cve_that_had_no_sign(page):
    other = "CVE-2026-70189"

    def seed(s):
        _rated_only(s, DOTNET)
        _rated_only(s, other)
        _nvd(s, other, "2026-10-20T00:00:00.000000Z")  # this one: CISA says active

    _with(page, seed)
    cves = f"{DOTNET},{other}"
    body = page.form(cves=cves, families="dotnet", verdict="reject", reason="not on servers")
    assert page.post(body)[0].status == 303
    _with(page, lambda s: _kev(s, other, "2026-11-07"))
    _, html = page.request("GET")
    assert "Look again" not in _card_html(html, DOTNET)
    _with(page, lambda s: _kev(s, DOTNET, "2026-11-07"))
    _, html = page.request("GET")
    card = _card_html(html, DOTNET)
    assert "Look again" in card
    since = card.split("Attacks reported since:</strong>", 1)[1].split("<", 1)[0]
    assert DOTNET in since and other not in since


def test_packs_with_a_bad_date_say_so_and_the_page_still_works(page, tmp_path):
    page.site.packs = _packs(
        tmp_path, "id: php2shell-2026-10\nversion: 1\npublished: 2026-02-30\ncves: []\n"
    )
    response, html = page.request("GET")
    assert response.status == 200 and "Signed packs couldn't be read" in html
    assert page.post(page.form(reason="still works"))[0].status == 303


def test_a_refused_reject_on_a_folded_card_comes_back_open_and_named(page, tmp_path):
    page.site.packs = _packs(tmp_path)
    response, html = page.post(page.form(verdict="reject", reason=""))
    assert response.status == 400
    assert "Not recorded for php (CVE-2026-109618, CVE-2026-109619)" in html
    card = _card_html(html, PHP[0])
    assert "<details open><summary>Decide anyway</summary>" in card


def test_a_cve_that_joined_after_a_reject_isnt_an_attack_reported_since(page):
    later = "CVE-2026-70190"
    _with(page, lambda s: _rated_only(s, DOTNET))
    body = page.form(cves=DOTNET, families="dotnet", verdict="reject", reason="no attacks")
    assert page.post(body)[0].status == 303

    def join(s):
        _rated_only(s, later, "2026-10-25T00:00:00.000000Z")
        _kev(s, later, "2026-10-25")

    _with(page, join)
    _, html = page.request("GET")
    card = _card_html(html, DOTNET)
    assert "Look again" in card and f"Came after it:</strong> {later}" in card
    assert "Attacks reported since" not in card


def test_bidi_and_control_characters_in_fetched_text_dont_reach_the_page(page):
    flip = chr(0x202E)

    def seed(s):
        s.db.execute(
            "UPDATE nvd SET description = ? WHERE cve = ?",
            (f"A flaw{flip} in PHP\x1b[31m.", PHP[0]),
        )
        s.db.execute("UPDATE kev SET name = ? WHERE cve = ?", (f"PHP{flip}", PHP[0]))

    _with(page, lambda s: [_kev(s, cve, "2026-10-26") for cve in PHP])
    _with(page, seed)
    _, html = page.request("GET")
    card = _card_html(html, PHP[0])
    assert flip not in html and "\x1b" not in html
    assert "A flaw in PHP [31m." in card and "CISA: PHP</div>" in card


def test_a_reject_added_by_hand_comes_back_when_cisa_confirms_it(page):
    def seed(s):
        _rated_only(s, DOTNET)
        s.db.execute(
            "INSERT INTO manual (cve, added_at, note) VALUES (?, ?, 'heard of attacks')",
            (DOTNET, "2026-10-20T00:00:00.000000Z"),
        )

    _with(page, seed)
    body = page.form(cves=DOTNET, families="dotnet", verdict="reject", reason="rumour only")
    assert page.post(body)[0].status == 303
    assert _stored(page)[0].signs == (f"manual:{DOTNET}",)
    _with(page, lambda s: _kev(s, DOTNET, "2026-11-07"))
    _, html = page.request("GET")
    card = _card_html(html, DOTNET)
    assert "Look again" in card and "Attacks reported since:</strong> on CISA&#39;s list" in card
