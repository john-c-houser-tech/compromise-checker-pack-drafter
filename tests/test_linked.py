"""B.1: the pages the sources link to (D8, D10), through a fake fetcher and a fake
Messages API: nothing here reaches a network or spends anything."""

from __future__ import annotations

import json

import pytest

from drafter import cli, draft, linked
from drafter.feeds import Context
from drafter.http import FetchError
from tests.conftest import Clock, FakeFetcher, ok
from tests.test_draft import CVE, GOOD, Provider, _answer, _cve, _threat, message

PHP_A = "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"
PHP_A_API = "https://api.github.com/repos/php/php-src/security-advisories/GHSA-6wmf-4rv5-p3rp"
REVIEWED = "https://github.com/advisories/GHSA-w8hw-w9fx-j79w"
RHSB = "https://access.redhat.com/security/vulnerabilities/RHSB-2026-013"
USN = "https://ubuntu.com/security/notices/USN-8948-1"
ALERT = "https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php"

ADVISORY = {
    "ghsa_id": "GHSA-6wmf-4rv5-p3rp",
    "cve_id": "CVE-2026-109619",
    "summary": "Use-after-free of stale request state",
    "severity": "critical",
    "published_at": "2026-10-21T13:34:13Z",
    "updated_at": "2026-10-22T08:00:00Z",
    "description": "Set session.upload_progress.enabled=0 and restart workers."
    " See https://www.php.net/archive/2026.php for the release.",
    "vulnerabilities": [
        {"package": {"name": "php"}, "vulnerable_version_range": "< 8.3.36",
         "patched_versions": "8.3.36"}
    ],
    "credits": [{"login": "someone"}],
}  # fmt: skip
NOTICE = {
    "title": "PHP vulnerabilities",
    "published": "2026-10-21T14:00:00",
    "cves_ids": ["CVE-2026-109618"],
    "summary": "Several security issues were fixed in PHP.",
    "description": "It was discovered that PHP mishandled memory.",
    "instructions": "In general, a standard system update will make all the changes.",
    "references": [],
    "release_packages": {"noble": [{"name": "php8.3-fpm", "version": "8.3.6-0ubuntu0.24.04.13"}]},
}
PAGE = b"""<html><head><title>t</title><script>var x = "never";</script></head><body>
<nav>Menu Home Alerts</nav><main><h1>Critical vulnerabilities in PHP</h1>
<p>Apply the patch &amp; restart. Monitor PHP workers starting shells.</p>
<p>Apply the patch &amp; restart. Monitor PHP workers starting shells.</p>
<ul><li>https://github.com/NCSC-NL/php2shell</li></ul></main><footer>Contact</footer></body></html>"""


@pytest.fixture
def approved_store(store):
    from drafter import decisions

    _cve(store, CVE)
    decisions.record(store, _threat(store), "approve", "", "jch", "2026-11-08T18:53:00Z")
    return store


@pytest.fixture
def ctx(store, fetcher):
    return Context(store=store, fetcher=fetcher, now=Clock())


# which links


def test_only_the_five_kinds_are_taken_in_d8s_order():
    urls = {
        ALERT, USN, RHSB, REVIEWED, PHP_A,
        PHP_A + "/",  # the same page twice
        PHP_A + "?tab=x#y",  # and again, with a query and a fragment
        "https://nvd.nist.gov/vuln/detail/CVE-2026-109618",
        "https://bugzilla.redhat.com/show_bug.cgi?id=2553995",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing",
        "https://www.php.net/",
        "https://github.com/google/brotli/releases",
        "https://access.redhat.com/security/cve/CVE-2026-109618",
        "https://ubuntu.com/security/CVE-2026-109618",
        "http://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",  # not https
        "https://github.com:8443/advisories/GHSA-w8hw-w9fx-j79w",  # another port
        "https://github.com/advisories/GHSA-aaaa-aaaa-aaaa",  # not GitHub's alphabet
    }  # fmt: skip
    found = linked.links(urls)
    assert [li.kind.name for li in found] == [
        "a project's advisory", "a reviewed advisory", "a Red Hat bulletin",
        "an Ubuntu notice", "a CISA alert",
    ]  # fmt: skip
    assert found[0].fetch == PHP_A_API and found[0].url == PHP_A
    assert found[1].fetch == "https://api.github.com/advisories/GHSA-w8hw-w9fx-j79w"
    assert found[3].fetch == USN + ".json"
    assert found[2].fetch == RHSB and found[4].fetch == ALERT


# reading a page


def test_a_page_is_read_as_its_main_words_only():
    text = linked.html_text(PAGE)
    assert text.splitlines()[0] == "Critical vulnerabilities in PHP"
    assert "Apply the patch & restart." in text and text.count("Apply the patch") == 1
    assert "never" not in text and "Menu" not in text and "Contact" not in text
    assert "https://github.com/NCSC-NL/php2shell" in text


def test_a_page_without_main_is_read_whole_less_its_menus():
    text = linked.html_text(b"<body><nav>Menu</nav><p>Patch now.</p><style>p{}</style></body>")
    assert text == "Patch now."


def test_an_advisory_gives_its_words_and_ranges_not_who_found_it():
    text = linked.github_text(json.dumps(ADVISORY).encode())
    assert "Summary: Use-after-free of stale request state" in text
    assert "session.upload_progress.enabled=0" in text and "patched: 8.3.36" in text
    assert "someone" not in text


def test_a_notice_gives_its_words_never_its_package_list():
    text = linked.usn_text(json.dumps(NOTICE).encode())
    assert "standard system update" in text and "php8.3-fpm" not in text


# fetching


def test_pages_are_fetched_kept_and_read_again_within_a_day(ctx, fetcher):
    fetcher.add(PHP_A_API, ok(ADVISORY, url=PHP_A_API))
    fetcher.add(ALERT, ok(PAGE, url=ALERT))
    got = linked.gather(ctx, {PHP_A, ALERT})
    assert [p.link.url for p in got.pages] == [PHP_A, ALERT] and not got.left_out
    assert fetcher.calls[0]["headers"] == {"Accept": "application/vnd.github+json"}
    rows = ctx.store.db.execute("SELECT feed, url, status FROM fetches").fetchall()
    assert [tuple(r) for r in rows] == [("linked", PHP_A_API, 200), ("linked", ALERT, 200)]
    again = linked.gather(ctx, {PHP_A, ALERT})
    assert len(fetcher.calls) == 2 and all(p.reused for p in again.pages)
    assert [p.fetch_id for p in again.pages] == [p.fetch_id for p in got.pages]
    ctx.now.advance(days=1, seconds=1)
    linked.gather(ctx, {PHP_A, ALERT})
    assert len(fetcher.calls) == 4


def test_a_page_that_cant_be_had_is_left_out_and_said(ctx, fetcher):
    fetcher.add(PHP_A_API, FetchError("HTTP 404", status=404))
    fetcher.add(USN + ".json", ok(b"<html>not json</html>", url=USN + ".json"))
    fetcher.add(ALERT, ok(PAGE, url=ALERT))
    got = linked.gather(ctx, {PHP_A, USN, ALERT})
    assert [p.link.url for p in got.pages] == [ALERT]
    assert got.left_out == [
        f"{PHP_A} (a project's advisory): HTTP 404",
        f"{USN} (an Ubuntu notice): its answer couldn't be read",
    ]
    # the failure is kept, as every fetch is
    assert (
        ctx.store.db.execute("SELECT status FROM fetches WHERE url = ?", (PHP_A_API,)).fetchone()[0]
        == 404
    )  # noqa: E501


def test_within_the_shared_budget_counting_each_page_as_sent(ctx, fetcher):
    alerts = [f"https://www.cisa.gov/news-events/alerts/2026/10/2{i}/a" for i in range(7)]
    for url in alerts[:6]:
        fetcher.add(url, ok(b"<p>" + b"x" * 18_000 + b"</p>", url=url))
    fetcher.add(alerts[6], ok(b"<p>short</p>", url=alerts[6]))
    got = linked.gather(ctx, set(alerts))
    # five of 18,000 make 90,000; a sixth doesn't fit the 100,000, the short one does
    assert [p.link.url for p in got.pages] == alerts[:5] + [alerts[6]]
    assert got.left_out == [
        f"{alerts[5]} (a CISA alert): over the 100,000 characters the linked pages share"
    ]
    # a page longer than 20,000 counts as 20,000, as it is sent cut
    fetcher.routes.clear()
    big = "https://www.cisa.gov/news-events/alerts/2026/11/01/b"
    fetcher.add(big, ok(b"<p>" + b"z" * 50_000 + b"</p>", url=big))
    assert len(linked.gather(ctx, {big} | set(alerts[:4])).pages) == 5


def test_six_pages_at_most_and_a_failure_doesnt_use_one(ctx, fetcher):
    alerts = [f"https://www.cisa.gov/news-events/alerts/2026/10/2{i}/a" for i in range(8)]
    fetcher.add(alerts[0], FetchError("HTTP 404", status=404))
    for url in alerts[1:]:
        fetcher.add(url, ok(b"<p>short</p>", url=url))
    got = linked.gather(ctx, set(alerts))
    assert [p.link.url for p in got.pages] == alerts[1:7]
    assert got.left_out == [
        f"{alerts[0]} (a CISA alert): HTTP 404",
        f"{alerts[7]} (a CISA alert): over the 6 a draft",
    ]
    assert len(fetcher.calls) == 7  # the one over six isn't fetched at all


def test_only_github_and_the_allowed_hosts_are_reached(ctx):
    from drafter.http import Refused, check_url

    assert check_url(PHP_A_API) == PHP_A_API
    with pytest.raises(Refused):
        check_url("https://github.com/NCSC-NL/php2shell")  # two hops: a person adds it (B.2)


# in a draft


def _gathered(ctx, fetcher, *urls):
    fetcher.add(PHP_A_API, ok(ADVISORY, url=PHP_A_API))
    fetcher.add(USN + ".json", ok(NOTICE, url=USN + ".json"))
    return linked.gather(ctx, set(urls))


def test_the_linked_pages_are_sent_cited_and_listed(approved_store, fetcher):
    ctx = Context(store=approved_store, fetcher=fetcher, now=Clock())
    gathered = _gathered(ctx, fetcher, PHP_A, USN)
    gathered.left_out.append(f"{RHSB} (a Red Hat bulletin): HTTP 404")
    answer = _answer(
        mitigations_yaml="- id: upload-progress-off\n  setting: {kind: php_ini, name:"
        " session.upload_progress.enabled}\n  expect: 'off'\n  default: 'on'\n"
        "  text: Turn off upload progress tracking and restart every worker.\n",
        references=[GOOD["references"][0], PHP_A],
    )
    p = Provider(lambda body: message(body, answer))
    made = draft.draft(approved_store, [CVE], p.client(), gathered=gathered)
    sent = p.sent[0][1]["messages"][0]["content"]
    assert f"Linked page, a project's advisory: {PHP_A}" in sent
    assert f"Address: {PHP_A}" in sent and "upload_progress" in sent
    assert made.ok, made.checked.problems  # the setting and the page are in a source now
    text = draft.render(made, "2026-11-09 10:00 UTC")
    assert f"Linked page, a project's advisory: {PHP_A}: fetch" in text
    assert f"# Linked or added pages not sent:\n#   {RHSB} (a Red Hat bulletin): HTTP 404" in text


def test_without_the_page_the_setting_is_still_refused(approved_store):
    answer = _answer(
        mitigations_yaml="- id: upload-progress-off\n  setting: {kind: php_ini, name:"
        " session.upload_progress.enabled}\n  expect: 'off'\n  default: 'on'\n  text: t\n"
    )
    made = draft.draft(approved_store, [CVE], Provider(lambda body: message(body, answer)).client())
    assert any("a setting no source gives" in p for p in made.checked.problems)


def test_a_linked_notice_doesnt_let_the_answer_name_a_package(approved_store, fetcher):
    ctx = Context(store=approved_store, fetcher=fetcher, now=Clock())
    notice = {**NOTICE, "description": "The dotnet8.0 runtime was updated."}
    fetcher.add(USN + ".json", ok(notice, url=USN + ".json"))
    gathered = linked.gather(ctx, {USN})
    answer = _answer(remediation=["Update dotnet8.0 now."])
    p = Provider(lambda body: message(body, answer), lambda body: message(body))
    made = draft.draft(approved_store, [CVE], p.client(), names={"dotnet8.0"}, gathered=gathered)
    assert "dotnet8.0 runtime" in p.sent[0][1]["messages"][0]["content"]  # it was sent
    assert "a package name in the answer: dotnet8.0" in p.sent[1][1]["messages"][2]["content"]
    assert made.ok  # the second answer (GOOD) names none


def test_the_cli_dry_run_fetches_nothing_and_counts_pages_at_their_most(
    tmp_path, capsys, monkeypatch
):
    from drafter import decisions
    from drafter.store import Store

    s = Store(tmp_path / "drafter.sqlite3")
    _cve(s, CVE)
    # Red Hat's record links PHP's advisory and a bulletin no one can fetch
    row = s.db.execute("SELECT fetch_id FROM vendor_cve WHERE vendor = 'redhat'").fetchone()
    record = json.loads(s.fetch_body(row[0]))
    record["references"] += [PHP_A, RHSB]
    s.db.execute("UPDATE fetches SET body = NULL, same_as = NULL WHERE id = ?", (row[0],))
    import gzip

    s.db.execute("UPDATE fetches SET body = ? WHERE id = ?",
                 (gzip.compress(json.dumps(record).encode()), row[0]))  # fmt: skip
    s.db.commit()
    decisions.record(s, _threat(s), "approve", "", "jch", "t1")
    s.close()
    fake = FakeFetcher()
    fake.add(PHP_A_API, ok(ADVISORY, url=PHP_A_API))
    monkeypatch.setattr(cli, "Fetcher", lambda: fake)
    assert cli.main(["--home", str(tmp_path), "draft", CVE, "--dry-run"]) == 0
    out = capsys.readouterr().out
    # read-only: nothing fetched, each page counted at its most
    assert not fake.calls
    assert f"the draft will fetch: {PHP_A} (a project's advisory), counted at its most" in out
    assert f"the draft will fetch: {RHSB} (a Red Hat bulletin)" in out  # both fit $0.75
    assert "Nothing sent." in out


def test_a_page_read_in_the_last_day_is_used_by_the_dry_run(ctx, fetcher):
    fetcher.add(PHP_A_API, ok(ADVISORY, url=PHP_A_API))
    linked.gather(ctx, {PHP_A})
    got = linked.gather(ctx, {PHP_A, ALERT}, offline=True)
    assert [p.link.url for p in got.pages] == [PHP_A] and got.pages[0].reused
    assert [li.url for li in got.pending] == [ALERT] and len(fetcher.calls) == 1


def test_an_address_that_cant_be_read_is_passed_over():
    found = linked.links({"https://example.com:99999/x", "https://a.example:abc/", PHP_A})
    assert [li.url for li in found] == [PHP_A]


def test_odd_addresses_are_not_pages_of_the_five_kinds():
    assert linked.links({
        "https://ubuntu.com/security/notices/USN-\u0663\u0664-1",  # Arabic-Indic digits
        "https://access.redhat.com/security/vulnerabilities/..",
        "https://access.redhat.com/security/vulnerabilities/.hidden",
    }) == []  # fmt: skip
    (alert,) = linked.links({"https://cisa.gov/news-events/alerts/2026/10/21/x"})
    assert alert.fetch == "https://www.cisa.gov/news-events/alerts/2026/10/21/x"


def test_one_advisory_linked_both_ways_takes_one_slot():
    twin = "https://github.com/advisories/GHSA-6wmf-4rv5-p3rp"
    (only,) = linked.links({twin, PHP_A})
    assert only.url == PHP_A and only.fetch == PHP_A_API


def test_a_redirect_off_the_pages_site_is_refused(ctx, fetcher):
    fetcher.add(ALERT, ok(PAGE, url="https://example.org/elsewhere"))
    got = linked.gather(ctx, {ALERT})
    assert got.pages == [] and got.left_out == [f"{ALERT} (a CISA alert): redirected off its site"]


def test_deeply_nested_json_is_read_quickly():
    import time

    deep: object = "x"
    for _ in range(40):  # one child a level: the old reader called itself twice on it
        deep = {"a": deep}
    started = time.monotonic()
    linked.github_text(
        json.dumps({"summary": "s", "description": "d", "references": [deep]}).encode()
    )
    assert time.monotonic() - started < 2


def test_a_fetch_stamped_in_the_future_isnt_recent(ctx, fetcher):
    fetcher.add(ALERT, ok(PAGE, url=ALERT))
    linked.gather(ctx, {ALERT})
    ctx.store.db.execute("UPDATE fetches SET fetched_at = '2030-01-01T00:00:00.000000Z'")
    linked.gather(ctx, {ALERT})
    assert len(fetcher.calls) == 2


def test_a_page_kept_as_a_pointer_to_an_earlier_one_is_read_again(ctx, fetcher):
    fetcher.add(ALERT, [ok(PAGE, url=ALERT), ok(PAGE, url=ALERT)])
    linked.gather(ctx, {ALERT})
    ctx.now.advance(days=2)
    linked.gather(ctx, {ALERT})  # the same body again: kept as same_as the first
    ctx.now.advance(hours=1)
    again = linked.gather(ctx, {ALERT})
    assert again.pages[0].reused and "Critical vulnerabilities in PHP" in again.pages[0].text


def test_a_busy_store_leaves_a_page_out_not_the_draft(ctx, monkeypatch):
    import sqlite3

    def busy(*a, **k):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(linked, "_recent", busy)
    got = linked.gather(ctx, {ALERT})
    assert got.left_out == [f"{ALERT} (a CISA alert): the store was busy"]


def test_a_linked_page_vouches_for_its_own_address_only(approved_store, fetcher):
    ctx = Context(store=approved_store, fetcher=fetcher, now=Clock())
    fetcher.add(PHP_A_API, ok(ADVISORY, url=PHP_A_API))
    gathered = linked.gather(ctx, {PHP_A})
    inside = "https://www.php.net/archive/2026.php"  # in the advisory's words
    answer = _answer(references=[PHP_A, inside])
    p = Provider(lambda body: message(body, answer), lambda body: message(body))
    draft.draft(approved_store, [CVE], p.client(), gathered=gathered)
    assert (
        f"a reference that isn't in the sources: {inside}" in p.sent[1][1]["messages"][2]["content"]
    )


def test_what_was_cut_off_a_page_counts_for_nothing():
    link = linked.links({ALERT})[0]
    source = draft.linked_source(link, "x" * 30_000 + " session.upload_progress.enabled", 1, None)
    assert len(source.text) <= draft.MAX_SOURCE and "upload_progress" not in source.said
    assert source.text.endswith("more characters not sent]")


def test_pages_are_left_out_from_the_end_until_the_cap_has_room():
    vendor = [draft.Source("Red Hat, x", "words " * 2_000, 1, None, "u")]
    pages = [
        draft.linked_source(li, "y" * 20_000, i, None)
        for i, li in enumerate(linked.links({PHP_A, RHSB, USN, ALERT}), start=10)
    ]
    kept, over = draft.fit([CVE], vendor + pages)
    assert kept[0] is vendor[0] and draft.room([CVE], kept)
    assert [s.name for s in kept[1:]] == [s.name for s in pages[: len(kept) - 1]]
    assert over and over[-1].startswith(f"a CISA alert: {ALERT}: over what the $0.75")
    # small pages all fit
    small = [draft.linked_source(li, "short", 2, None) for li in linked.links({PHP_A, USN})]
    assert draft.fit([CVE], vendor + small) == (vendor + small, [])


def test_assembly_reads_back_the_pages_the_draft_was_made_from(approved_store, fetcher):
    ctx = Context(store=approved_store, fetcher=fetcher, now=Clock())
    fetcher.add(PHP_A_API, ok(ADVISORY, url=PHP_A_API))
    gathered = linked.gather(ctx, {PHP_A})
    made = draft.draft(approved_store, [CVE], Provider().client(), gathered=gathered)
    text = draft.render(made, "2026-11-09 10:00 UTC")
    (back,) = draft.drafted_linked(approved_store, text)
    sent = next(s for s in made.found if s.linked)
    assert (back.name, back.text, back.urls) == (sent.name, sent.text, sent.urls)
    # a header pointing at another fetch is refused, not trusted
    other = text.replace(f"fetch {sent.fetch_id},", "fetch 1,")
    with pytest.raises(draft.DraftError, match="isn't kept as fetch 1"):
        draft.drafted_linked(approved_store, other)


def test_the_cli_draft_fetches_the_linked_pages_and_lists_them(tmp_path, capsys, monkeypatch):
    import gzip

    import anthropic

    from drafter import decisions
    from drafter.store import Store
    from tests.test_draft import KEY

    s = Store(tmp_path / "drafter.sqlite3")
    _cve(s, CVE)
    row = s.db.execute("SELECT fetch_id FROM vendor_cve WHERE vendor = 'redhat'").fetchone()
    record = json.loads(s.fetch_body(row[0]))
    record["references"] += [PHP_A]
    s.db.execute("UPDATE fetches SET body = ?, same_as = NULL WHERE id = ?",
                 (gzip.compress(json.dumps(record).encode()), row[0]))  # fmt: skip
    s.db.commit()
    decisions.record(s, _threat(s), "approve", "", "jch", "t1")
    s.close()
    fake = FakeFetcher()
    fake.add(PHP_A_API, ok(ADVISORY, url=PHP_A_API))
    monkeypatch.setattr(cli, "Fetcher", lambda: fake)
    p = Provider()
    client = p.client()
    monkeypatch.setattr(anthropic, "Anthropic", lambda **kw: client)
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    out = tmp_path / "x.draft.yaml"
    assert cli.main(["--home", str(tmp_path), "draft", CVE, "--out", str(out)]) == 0
    assert [c["url"] for c in fake.calls] == [PHP_A_API]
    assert "upload_progress" in p.sent[0][1]["messages"][0]["content"]
    assert f"Linked page, a project's advisory: {PHP_A}: fetch" in out.read_text()


def test_an_off_site_redirect_isnt_reused_later(ctx, fetcher):
    fetcher.add(ALERT, ok(PAGE, url="https://example.org/elsewhere"))
    linked.gather(ctx, {ALERT})
    fetcher.routes.clear()
    fetcher.add(ALERT, FetchError("HTTP 404", status=404))
    again = linked.gather(ctx, {ALERT})  # within the day: it must not come from the store
    assert again.pages == [] and len(fetcher.calls) == 2


def test_the_dry_run_leaves_out_what_the_draft_would(tmp_path, capsys, monkeypatch):
    # a pending project advisory and a cached notice: the notice is the one to go
    import gzip

    from drafter import decisions
    from drafter.store import Store

    s = Store(tmp_path / "drafter.sqlite3")
    _cve(s, CVE)
    row = s.db.execute("SELECT fetch_id FROM vendor_cve WHERE vendor = 'redhat'").fetchone()
    record = json.loads(s.fetch_body(row[0]))
    alerts = [f"https://www.cisa.gov/news-events/alerts/2026/10/2{i}/a" for i in range(3)]
    record["references"] += [PHP_A, *alerts]
    s.db.execute("UPDATE fetches SET body = ?, same_as = NULL WHERE id = ?",
                 (gzip.compress(json.dumps(record).encode()), row[0]))  # fmt: skip
    s.db.commit()
    decisions.record(s, _threat(s), "approve", "", "jch", "t1")
    fake = FakeFetcher()
    for url in alerts:
        fake.add(url, ok(b"<p>" + b"w" * 30_000 + b"</p>", url=url))
    linked.gather(
        Context(
            store=s,
            fetcher=fake,
            now=lambda: __import__("datetime").datetime.now(__import__("datetime").UTC),
        ),
        set(alerts),
    )  # the alerts are cached, the advisory isn't
    s.close()
    monkeypatch.setattr(cli, "Fetcher", lambda: FakeFetcher())
    monkeypatch.setattr(draft, "PER_DRAFT_CAP", 0.55)  # room for about two full pages
    assert cli.main(["--home", str(tmp_path), "draft", CVE, "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert f"the draft will fetch: {PHP_A} (a project's advisory)" in out
    assert f"not sent: a CISA alert: {alerts[2]}: over what the" in out
    assert f"not sent: a project's advisory: {PHP_A}" not in out
