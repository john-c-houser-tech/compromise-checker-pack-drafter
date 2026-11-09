"""B.2: pages a person adds (D9), through fakes: nothing here reaches a network."""

from __future__ import annotations

import socket
import sqlite3
import urllib.parse

import pytest

from drafter import added, decisions, draft, linked
from drafter.http import FetchError, Response
from drafter.store import Store
from tests import test_web
from tests.conftest import NOW
from tests.test_web import PHP, _php, _seed

page = test_web.page  # the web tests' running page, as a fixture here

SANSEC = "https://sansec.io/research/php2shell"
TIMELINE = b"<html><body><main><p>Details leaked on 2026-10-20.</p><p>See https://blog.cloudflare.com/php2shell-first-attacks and https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp.</p></main></body></html>"  # noqa: E501


def addrinfo(*ips):
    def resolve(host, port, type=None):  # noqa: A002 - socket's own name
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, type, 6, "", (ip, port))
                for ip in ips]  # fmt: skip

    return resolve


class FakeConn:
    """Answers in turn: (status, headers, body)."""

    def __init__(self, answers):
        self.answers, self.made = answers, []

    def __call__(self, host, ip):
        self.made.append((host, ip))
        return self

    def request(self, method, target, headers=None):
        self.target = target

    def getresponse(self):
        status, headers, body = self.answers.pop(0)

        class Answer:
            def getheader(self, name):
                return headers.get(name)

            def read(self, n):
                return body[:n]

        a = Answer()
        a.status = status
        return a

    def close(self):
        pass


PUBLIC = addrinfo("93.184.216.34")


# fetching from any site


@pytest.mark.parametrize(
    ("url", "why"),
    [
        ("http://sansec.io/x", "only https"),
        ("https://sansec.io:8443/x", "only the default port"),
        ("https://me:pw@sansec.io/x", "no login in the address"),
        ("https://sansec.io:99999/x", "not an address that can be read"),
        ("https://" + "a" * 2_100 + ".io/", "not an address that can be read"),
    ],
)
def test_only_plain_https_addresses(url, why):
    with pytest.raises(FetchError, match=why):
        added.check(url)


@pytest.mark.parametrize(
    "ips",
    [
        ("10.0.0.5",), ("127.0.0.1",), ("169.254.169.254",), ("192.168.1.1",), ("::1",),
        ("fc00::1",), ("fe80::1%2",), ("::ffff:10.0.0.1",), ("100.64.0.1",),
        ("93.184.216.34", "10.0.0.5"),  # one public, one private: refused
    ],
)  # fmt: skip
def test_a_name_with_any_private_address_is_refused(ips):
    with pytest.raises(FetchError, match="private or reserved"):
        added.public_address("x.example", addrinfo(*ips))


def test_the_connection_goes_to_the_address_checked():
    conn = FakeConn([(200, {"Content-Type": "text/html; charset=utf-8"}, TIMELINE)])
    got = added.get(SANSEC, resolve=PUBLIC, connection=conn)
    assert conn.made == [("sansec.io", "93.184.216.34")] and conn.target == "/research/php2shell"
    assert got.body == TIMELINE and got.url == SANSEC


def test_the_pinned_connection_dials_the_checked_address():
    dialled = []

    def dial(address, timeout):
        dialled.append(address)
        raise OSError("not here")

    with pytest.raises(OSError):
        added._Pinned("sansec.io", "93.184.216.34", dial).connect()
    assert dialled == [("93.184.216.34", 443)]


@pytest.mark.parametrize(
    ("answers", "resolves", "why"),
    [
        ([(302, {"Location": "http://sansec.io/x"}, b"")], [PUBLIC], "only https"),
        ([(301, {"Location": "https://internal.example/"}, b"")],
         [PUBLIC, addrinfo("10.1.2.3")], "private or reserved"),
        ([(200, {"Content-Type": "application/pdf"}, b"%PDF")], [PUBLIC], "not a page of words"),
        ([(200, {"Content-Type": "text/html"}, b"x" * (added.MAX_BYTES + 1))], [PUBLIC],
         "longer than 4 MiB"),
        ([(404, {}, b"")], [PUBLIC], "HTTP 404"),
        ([(302, {"Location": "/again"}, b"")] * 6, [PUBLIC] * 6, "too many redirects"),
    ],
)  # fmt: skip
def test_redirects_types_sizes_and_failures(answers, resolves, why):
    order = list(resolves)

    def resolve(host, port, type=None):  # noqa: A002
        return order.pop(0)(host, port, type)

    with pytest.raises(FetchError, match=why):
        added.get(SANSEC, resolve=resolve, connection=FakeConn(list(answers)))


def test_a_redirect_to_another_public_site_is_followed():
    conn = FakeConn([(302, {"Location": "https://www.sansec.io/r"}, b""),
                     (200, {"Content-Type": "text/plain"}, b"words")])  # fmt: skip
    got = added.get(SANSEC, resolve=PUBLIC, connection=conn)
    assert got.url == "https://www.sansec.io/r" and conn.made[1][0] == "www.sansec.io"


def test_a_kept_page_is_read_by_what_it_holds():
    assert added.text_of(TIMELINE).startswith("Details leaked on 2026-10-20.")
    assert added.text_of(b'{"summary": "s", "items": ["a"]}') == "summary: s\nitems: a"
    assert added.text_of(b"plain words") == "plain words"


# the record


@pytest.fixture
def approved(store):
    _seed(store)
    decisions.record(store, _php(store), "approve", "", "jch", "2026-11-09T01:00:00.000000Z")
    return decisions.history(store)[0]


def _ok(url):
    return Response(url=url, status=200, headers={"Content-Type": "text/html"}, body=TIMELINE)


def test_a_page_is_added_kept_and_taken_back(store, approved):
    a = added.add(store, approved.id, f" {SANSEC} ", "jch", lambda: NOW, fetch=_ok)
    assert a.kept and a.url == SANSEC
    row = store.db.execute("SELECT feed, url, status FROM fetches WHERE id = ?", (a.fetch_id,))
    assert tuple(row.fetchone()) == ("added", SANSEC, 200)
    with pytest.raises(added.AddError, match="added already"):
        added.add(store, approved.id, SANSEC, "jch", lambda: NOW, fetch=_ok)
    added.take_back(store, approved.id, a.id, lambda: NOW)
    assert not added.listed(store, approved.id)[0].kept
    with pytest.raises(added.AddError, match="not an added page"):
        added.take_back(store, approved.id, a.id, lambda: NOW)
    with pytest.raises(sqlite3.DatabaseError, match="kept"):
        store.db.execute("DELETE FROM added_source")
    with pytest.raises(sqlite3.DatabaseError, match="only ever taken back"):
        store.db.execute("UPDATE added_source SET url = 'https://x.example/'")


def test_a_page_that_cant_be_had_is_kept_as_a_failure(store, approved):
    def down(url):
        raise FetchError("HTTP 503", status=503)

    a = added.add(store, approved.id, SANSEC, "jch", lambda: NOW, fetch=down)
    assert not a.kept and a.outcome == "HTTP 503"
    assert (
        store.db.execute("SELECT status FROM fetches WHERE id = ?", (a.fetch_id,)).fetchone()[0]
        == 503
    )  # noqa: E501
    with pytest.raises(added.AddError, match="only https"):
        added.add(store, approved.id, "http://sansec.io/", "jch", lambda: NOW, fetch=_ok)


def test_four_at_most(store, approved):
    for i in range(4):
        added.add(store, approved.id, f"{SANSEC}/{i}", "jch", lambda: NOW, fetch=_ok)
    with pytest.raises(added.AddError, match="at most 4"):
        added.add(store, approved.id, f"{SANSEC}/9", "jch", lambda: NOW, fetch=_ok)


def test_addresses_one_hop_further_skip_the_read_and_the_five_kinds():
    texts = [
        added.text_of(TIMELINE) + " http://plain.example/ https://sansec.io/research/php2shell"
    ]
    assert added.further(texts, {SANSEC}) == ["https://blog.cloudflare.com/php2shell-first-attacks"]


# in a draft


def test_added_pages_go_in_the_draft_kept_longest_and_named(store, approved):
    a = added.add(store, approved.id, SANSEC, "jch", lambda: NOW, fetch=_ok)
    (source,) = draft.added_sources(store, approved.id)
    assert source.name == f"Added by jch {NOW.date()}: {SANSEC}" and source.added and source.linked
    assert source.urls == frozenset(textcheck_forms(SANSEC))  # only its own address
    big = [draft.linked_source(li, "y" * 20_000, 10 + i, None)
           for i, li in enumerate(linked.links({
               "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
               "https://access.redhat.com/security/vulnerabilities/RHSB-2026-013",
               "https://ubuntu.com/security/notices/USN-8948-1",
               "https://www.cisa.gov/news-events/alerts/2026/10/21/a"}))]  # fmt: skip
    vendor = [draft.Source("Red Hat, x", "words " * 4_000, 1, None, "u")]
    kept, over = draft.fit(list(PHP), vendor + [source] + big)
    assert source in kept and over  # linked pages went first
    assert a.fetch_id == source.fetch_id


def textcheck_forms(url):
    from drafter import textcheck

    return textcheck.url_forms(url)


def test_assembly_reads_an_added_page_back(store, approved):
    added.add(store, approved.id, SANSEC, "jch", lambda: NOW, fetch=_ok)
    (source,) = draft.added_sources(store, approved.id)
    sha = source.sha256
    header = f"# {source.name}: fetch {source.fetch_id}, sha256 {sha}, {source.url}\n"
    (back,) = draft.drafted_linked(store, header)
    assert (back.name, back.text, back.added) == (source.name, source.text, True)
    with pytest.raises(draft.DraftError, match="isn't kept as fetch"):
        draft.drafted_linked(store, header.replace(sha, "0" * 64))


# on the page


def _source_form(p, decision, **fields):
    base = {"token": p.site.token, "decision": str(decision), "anchor": "t-cve-2026-109618"}
    return urllib.parse.urlencode({**base, **fields})


def _post_source(p, body):
    sent = {"Origin": p.origin, "Content-Type": "application/x-www-form-urlencoded"}
    return p.request("POST", "/source", body, sent)


def test_an_approved_card_adds_a_page_and_takes_it_back(page):
    page.site.fetch_added = _ok
    response, _ = page.post(page.form())
    assert response.status == 303
    s = Store(page.site.store_path, read_only=True)
    decision = decisions.history(s)[0].id
    s.close()
    _, html = page.request("GET")
    assert 'action="/source"' in html and "Sources you added (0 of 4)" in html
    response, _ = _post_source(page, _source_form(page, decision, action="add", url=SANSEC))
    assert response.status == 303 and response.getheader("Location") == "/#t-cve-2026-109618"
    _, html = page.request("GET")
    assert "Sources you added (1 of 4)" in html and SANSEC in html
    # the timeline's own links, one hop further, are offered
    assert "https://blog.cloudflare.com/php2shell-first-attacks" in html
    s = Store(page.site.store_path, read_only=True)
    (a,) = added.listed(s, decision)
    s.close()
    response, _ = _post_source(page, _source_form(page, decision, action="remove", added=str(a.id)))
    assert response.status == 303
    _, html = page.request("GET")
    assert "Sources you added (0 of 4)" in html and "taken back" in html


def test_a_source_needs_the_current_approve_and_the_pages_token(page):
    page.site.fetch_added = _ok
    page.post(page.form())
    response, html = _post_source(page, _source_form(page, 999, action="add", url=SANSEC))
    assert response.status == 400 and "current approve only" in html
    response, _ = _post_source(page, _source_form(page, 1, action="add", url=SANSEC, token="old"))  # noqa: S106
    assert response.status == 403
    sent = {"Origin": "https://evil.example", "Content-Type": "application/x-www-form-urlencoded"}
    assert page.request("POST", "/source", _source_form(page, 1, action="add", url=SANSEC),
                        sent)[0].status == 403  # fmt: skip


def test_a_page_that_cant_be_read_is_said_on_the_card(page):
    def down(url):
        raise FetchError("the name points at a private or reserved address")

    page.site.fetch_added = down
    page.post(page.form())
    response, html = _post_source(page, _source_form(page, 1, action="add", url=SANSEC))
    assert response.status == 400 and "couldn&#39;t be read" in html and "private" in html


def test_an_added_page_is_sent_cited_and_in_the_header(tmp_path):
    from tests.test_draft import CVE, Provider, _answer, _cve, _threat, message

    s = Store(tmp_path / "drafter.sqlite3")
    _cve(s, CVE)
    decisions.record(s, _threat(s), "approve", "", "jch", "2026-11-09T01:00:00.000000Z")
    decision = decisions.history(s)[0]
    added.add(s, decision.id, SANSEC, "jch", lambda: NOW, fetch=_ok)
    by_hand = draft.added_sources(s, decision.id)
    p = Provider(lambda body: message(body, _answer(references=[SANSEC])))
    made = draft.draft(s, [CVE], p.client(), added=by_hand)
    sent = p.sent[0][1]["messages"][0]["content"]
    assert f"Added by jch {NOW.date()}: {SANSEC}" in sent and "leaked on 2026-10-20" in sent
    assert made.ok, made.checked.problems  # its own address is citable
    text = draft.render(made, "2026-11-09 10:00 UTC")
    assert f"# Added by jch {NOW.date()}: {SANSEC}: fetch" in text
    (back,) = draft.drafted_linked(s, text)
    assert back.added
    s.close()
