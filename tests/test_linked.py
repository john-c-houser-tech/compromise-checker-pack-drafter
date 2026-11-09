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
    fetcher.add(PHP_A_API, ok(ADVISORY))
    fetcher.add(ALERT, ok(PAGE))
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
    fetcher.add(USN + ".json", ok(b"<html>not json</html>"))
    fetcher.add(ALERT, ok(PAGE))
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


def test_at_most_six_and_within_the_shared_budget(ctx, fetcher):
    alerts = [f"https://www.cisa.gov/news-events/alerts/2026/10/2{i}/a" for i in range(8)]
    for url in alerts:
        fetcher.add(url, ok(b"<p>" + b"x" * 30_000 + b"</p>"))  # each cut at 20,000
    got = linked.gather(ctx, set(alerts))
    # 20,000 counted for each: five fit in 100,000, the sixth doesn't, two are over six
    assert [p.link.url for p in got.pages] == alerts[:5]
    assert got.left_out == [
        f"{alerts[5]} (a CISA alert): over the 100,000 characters the linked pages share",
        f"{alerts[6]} (a CISA alert): over the 6 a draft",
        f"{alerts[7]} (a CISA alert): over the 6 a draft",
    ]
    assert len(fetcher.calls) == 6  # the two over six aren't fetched at all


def test_only_github_and_the_allowed_hosts_are_reached(ctx):
    from drafter.http import Refused, check_url

    assert check_url(PHP_A_API) == PHP_A_API
    with pytest.raises(Refused):
        check_url("https://github.com/NCSC-NL/php2shell")  # two hops: a person adds it (B.2)


# in a draft


def _gathered(ctx, fetcher, *urls):
    fetcher.add(PHP_A_API, ok(ADVISORY))
    fetcher.add(USN + ".json", ok(NOTICE))
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
    assert f"# Linked pages not sent (B.1):\n#   {RHSB} (a Red Hat bulletin): HTTP 404" in text


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
    fetcher.add(USN + ".json", ok(notice))
    gathered = linked.gather(ctx, {USN})
    answer = _answer(remediation=["Update dotnet8.0 now."])
    p = Provider(lambda body: message(body, answer), lambda body: message(body))
    made = draft.draft(approved_store, [CVE], p.client(), names={"dotnet8.0"}, gathered=gathered)
    assert "dotnet8.0 runtime" in p.sent[0][1]["messages"][0]["content"]  # it was sent
    assert "a package name in the answer: dotnet8.0" in p.sent[1][1]["messages"][2]["content"]
    assert made.ok  # the second answer (GOOD) names none


def test_the_cli_dry_run_fetches_the_linked_pages_and_sends_nothing(tmp_path, capsys, monkeypatch):
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
    fake.add(PHP_A_API, ok(ADVISORY))
    monkeypatch.setattr(cli, "Fetcher", lambda: fake)
    assert cli.main(["--home", str(tmp_path), "draft", CVE, "--dry-run"]) == 0
    out = capsys.readouterr().out
    # read-only: nothing fetched, each page counted at its most
    assert not fake.calls
    assert f"the draft will fetch: {PHP_A} (a project's advisory), counted at its most" in out
    assert f"the draft will fetch: {RHSB} (a Red Hat bulletin)" in out
    assert "Nothing sent." in out


def test_a_page_read_in_the_last_day_is_used_by_the_dry_run(ctx, fetcher):
    fetcher.add(PHP_A_API, ok(ADVISORY))
    linked.gather(ctx, {PHP_A})
    got = linked.gather(ctx, {PHP_A, ALERT}, offline=True)
    assert [p.link.url for p in got.pages] == [PHP_A] and got.pages[0].reused
    assert [li.url for li in got.pending] == [ALERT] and len(fetcher.calls) == 1
