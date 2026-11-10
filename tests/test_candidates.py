"""A.2: signals, vendor records, sorting and the list."""

from __future__ import annotations

import json
import sqlite3

import pytest

from drafter import candidates as c
from drafter import cli
from drafter.http import FetchError
from drafter.store import SCHEMA_VERSION, Store
from tests.conftest import ok

PHP = "CVE-2026-109618"


def _fid(store):
    return store.record_fetch(feed="t", url="u", fetched_at="t", status=200, body=None)


def _kev(store, cve, added):
    store.upsert(
        "kev",
        {
            "cve": cve,
            "date_added": added,
            "vendor": None,
            "product": None,
            "name": None,
            "fetch_id": _fid(store),
        },
        ("cve",),
    )


def _nvd(store, cve, ssvc, exploitation="active", products=("acme:thing",), description=None):
    store.upsert(
        "nvd",
        {
            "cve": cve,
            "last_modified": ssvc,
            "exploitation": exploitation,
            "ssvc_time": ssvc,
            "kev_added": None,
            "products": json.dumps(list(products)),
            "description": description,
            "fetch_id": _fid(store),
        },
        ("cve",),
    )


def _vendor(
    store,
    cve,
    vendor,
    packages,
    found=1,
    published=None,
    checked="2026-11-07T11:00:00.000000Z",
):
    store.upsert(
        "vendor_cve",
        {
            "cve": cve,
            "vendor": vendor,
            "attempted_at": checked,
            "error": None,
            "checked_at": checked,
            "found": found,
            "published": published,
            "packages": json.dumps(packages),
            "fetch_id": _fid(store),
        },
        ("cve", "vendor"),
    )


def _pkg(release, package, fixed=True, product=None):
    return {"release": release, "package": package, "fixed": fixed, "product": product}


SINCE = "2026-10-01T00:00:00.000000Z"

# signals


def test_signals_from_every_source_and_the_window(store):
    _kev(store, PHP, "2026-10-26")
    _nvd(store, PHP, "2026-10-21T00:00:00.000000Z")
    _nvd(store, "CVE-2026-0002", "2026-10-21T00:00:00.000000Z", exploitation="poc")
    _nvd(store, "CVE-2026-0003", "2026-09-01T00:00:00.000000Z")  # before the window
    store.upsert(
        "osv",
        {
            "ecosystem": "Ubuntu",
            "id": "UBUNTU-" + PHP,
            "modified": "2026-10-22T00:00:00.000000Z",
            "cves": "[]",
            "ubuntu_priority": "critical",
            "fetch_id": _fid(store),
        },
        ("ecosystem", "id"),
    )
    store.upsert(
        "osv",
        {
            "ecosystem": "Ubuntu",
            "id": "USN-8948-1",
            "modified": "2026-10-22T00:00:00.000000Z",
            "cves": "[]",
            "ubuntu_priority": "critical",
            "fetch_id": _fid(store),
        },
        ("ecosystem", "id"),
    )
    store.upsert(
        "redhat_critical",
        {
            "cve": "CVE-2026-0004",
            "public_date": "2026-10-03T00:00:00.000000Z",
            "packages": "[]",
            "fetch_id": _fid(store),
        },
        ("cve",),
    )
    store.upsert(
        "manual",
        {"cve": "CVE-2026-0005", "added_at": "2026-10-20T00:00:00.000000Z", "note": "a friend"},
        ("cve",),
    )
    found = c.signals(store, SINCE)
    assert sorted(found) == sorted([PHP, "CVE-2026-0004", "CVE-2026-0005"])
    assert [s.kind for s in found[PHP]] == ["nvd", "ubuntu", "kev"]  # oldest first


def test_ubuntu_signal_uses_ubuntus_own_publication_time(store):
    store.upsert(
        "osv",
        {
            "ecosystem": "Ubuntu",
            "id": "UBUNTU-" + PHP,
            "modified": "2026-11-06T00:00:00.000000Z",
            "cves": "[]",
            "ubuntu_priority": "critical",
            "fetch_id": _fid(store),
        },
        ("ecosystem", "id"),
    )
    _vendor(store, PHP, "ubuntu", [], published="2026-10-21T09:00:00.000000Z")
    assert c.signals(store, SINCE)[PHP][0].when == "2026-10-21T09:00:00.000000Z"


# the vendors' records


def test_parse_ubuntu_keeps_supported_shapes_and_drops_pro():
    record = {
        "id": "UBUNTU-" + PHP,
        "published": "2026-10-21T09:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "php8.3"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "8.3.6-0ubuntu0.24.04.9"}],
                    }
                ],
            },
            {
                "package": {"ecosystem": "Ubuntu:25.10", "name": "php8.4"},
                "ranges": [{"events": [{"introduced": "0"}]}],
            },
            {"package": {"ecosystem": "Ubuntu:Pro:18.04:LTS", "name": "php7.2"}},
            {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "bad name;"}},
            "junk",
        ],
    }
    published, packages = c.parse_ubuntu(json.dumps(record).encode())
    assert published == "2026-10-21T09:00:00.000000Z"
    assert packages == [
        {"release": "ubuntu:24.04", "package": "php8.3", "fixed": True},
        {"release": "ubuntu:25.10", "package": "php8.4", "fixed": False},
    ]


def test_parse_redhat_reads_base_add_ons_modules_and_unfixed():
    record = {
        "public_date": "2026-10-21T00:00:00Z",
        "affected_release": [
            {"package": "nginx-2:1.20.1-24.el9_7.3", "cpe": "cpe:/a:redhat:enterprise_linux:9"},
            {
                "package": "nginx:1.24-9080020260514160836.9",
                "cpe": "cpe:/a:redhat:enterprise_linux:9",
            },
            {
                "package": "nginx-2:1.26.3-1.el10_0.9",
                "cpe": "cpe:/o:redhat:enterprise_linux_eus:10.0",
            },
            {
                "package": "automation-controller-0:4.5.36-1.el9ap",
                "cpe": "cpe:/a:redhat:ansible_automation_platform:2.4::el9",
            },
            {
                "package": "nginx:1.24-8100020260514165201.489197e6",
                "cpe": "cpe:/a:redhat:enterprise_linux:8",
            },
        ],
        "package_state": [
            {
                "product_name": "Red Hat Enterprise Linux 9",
                "package_name": "php:8.4/php",
                "fix_state": "Affected",
                "cpe": "cpe:/a:redhat:enterprise_linux:9",
            },
            {
                "package_name": "insights-proxy/insights-proxy-container-rhel9",
                "fix_state": "Affected",
                "cpe": "cpe:/a:redhat:insights_proxy:1",
            },
            {"package_name": "php", "fix_state": "Not affected", "cpe": "cpe:/o:redhat:rhel_els:7"},
        ],
    }
    published, packages = c.parse_redhat(json.dumps(record).encode())
    assert published == "2026-10-21T00:00:00.000000Z"
    got = {(p["release"], p["package"], p["fixed"], p["product"]) for p in packages}
    assert got == {
        ("rhel:9", "nginx", True, "enterprise_linux"),
        ("rhel:10", "nginx", True, "enterprise_linux_eus"),
        ("rhel:9", "automation-controller", True, "ansible_automation_platform"),
        ("rhel:8", "nginx", True, "enterprise_linux"),
        ("rhel:9", "php", False, "enterprise_linux"),
    }


@pytest.mark.parametrize("body", [b"<html>", b"[]"])
def test_parse_refuses_wrong_shapes(body):
    with pytest.raises(c.FeedError):
        c.parse_redhat(body)
    with pytest.raises(c.FeedError):
        c.parse_ubuntu(body)


# refreshing


def test_refresh_reads_both_vendors_and_notes_404(ctx, fetcher, store):
    _nvd(store, PHP, "2026-11-06T00:00:00.000000Z")
    fetcher.add(
        c.UBUNTU_URL.format(cve=PHP),
        ok(
            {
                "id": "UBUNTU-" + PHP,
                "affected": [{"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "php8.3"}}],
            }
        ),
    )
    # Red Hat: not tracked (the fake answers 404)
    result = c.refresh(ctx, SINCE)
    assert (result.fetched, result.failed) == (2, 0)
    rows = {r["vendor"]: r for r in store.db.execute("SELECT * FROM vendor_cve")}
    assert rows["ubuntu"]["found"] == 1 and rows["redhat"]["found"] == 0
    statuses = [
        r[0]
        for r in store.db.execute(
            "SELECT status FROM fetches WHERE feed LIKE 'vendor-%' ORDER BY id"
        )
    ]
    assert sorted(statuses) == [200, 404]
    assert c.refresh(ctx, SINCE).fetched == 0  # fresh enough


def test_refresh_reads_again_when_old_or_newly_signalled(ctx, fetcher, store, clock):
    _nvd(store, PHP, "2026-11-06T00:00:00.000000Z")
    c.refresh(ctx, SINCE)
    clock.advance(days=1)
    assert c.refresh(ctx, SINCE).fetched == 2  # signalled in the last 30 days: daily
    _nvd(store, "CVE-2026-0007", "2026-10-01T00:00:00.000000Z")
    clock.advance(hours=1)
    assert c.refresh(ctx, SINCE).fetched == 2  # only the new one
    clock.advance(days=2)
    assert c.refresh(ctx, SINCE).fetched == 2  # PHP again; the older one waits a week


def test_refresh_stops_after_repeated_failures(ctx, fetcher, store, monkeypatch):
    monkeypatch.setattr(c, "STOP_AFTER_FAILURES", 3)
    for n in range(5):
        _nvd(store, f"CVE-2026-000{n}", "2026-11-06T00:00:00.000000Z")
    fetcher.add(lambda url: True, FetchError("HTTP 503", status=503))
    result = c.refresh(ctx, SINCE)
    assert result.stopped and result.failed == 3


# sorting


RULES = c.load_setaside()


def test_setaside_file_loads_and_needs_reasons():
    assert any(r.pattern == "webkit2gtk*" for r in RULES)
    with pytest.raises(ValueError, match="reason"):
        c.load_setaside('[[package]]\nname = "x"\n')


def _signalled(store, cve, when="2026-10-21T00:00:00.000000Z"):
    _nvd(store, cve, when)


def test_sorting_judge_kernel_setaside_elsewhere_unread(store):
    for cve in (
        "CVE-2026-1001",
        "CVE-2026-1002",
        "CVE-2026-1003",
        "CVE-2026-1004",
        "CVE-2026-1005",
        "CVE-2026-1006",
    ):
        _signalled(store, cve)
    _vendor(store, "CVE-2026-1001", "ubuntu", [_pkg("ubuntu:24.04", "php8.3")])
    _vendor(store, "CVE-2026-1001", "redhat", [_pkg("rhel:8", "php")])
    _vendor(store, "CVE-2026-1002", "ubuntu", [_pkg("ubuntu:24.04", "linux-aws")])
    _vendor(store, "CVE-2026-1002", "redhat", [_pkg("rhel:9", "kernel-rt")])
    _vendor(store, "CVE-2026-1003", "ubuntu", [], found=0)
    _vendor(store, "CVE-2026-1003", "redhat", [_pkg("rhel:9", "webkit2gtk3")])
    _vendor(store, "CVE-2026-1004", "ubuntu", [_pkg("ubuntu:20.04", "nginx")])
    _vendor(store, "CVE-2026-1004", "redhat", [], found=0)
    _vendor(store, "CVE-2026-1005", "ubuntu", [], found=0)  # Red Hat not read yet
    _vendor(store, "CVE-2026-1006", "ubuntu", [], found=0)
    _vendor(
        store,
        "CVE-2026-1006",
        "redhat",
        [_pkg("rhel:9", "automation-controller", product="ansible_automation_platform")],
    )
    kinds = {x.cve: x.kind for x in c.classify(store, SINCE, RULES)}
    assert kinds == {
        "CVE-2026-1001": "judge",
        "CVE-2026-1002": "kernel",
        "CVE-2026-1003": "setaside",
        "CVE-2026-1004": "elsewhere",
        "CVE-2026-1005": "unread",
        "CVE-2026-1006": "setaside",
    }


def test_a_judgeable_package_wins_over_kernel_and_setaside(store):
    _signalled(store, "CVE-2026-1001")
    _vendor(
        store,
        "CVE-2026-1001",
        "ubuntu",
        [_pkg("ubuntu:24.04", "linux"), _pkg("ubuntu:24.04", "brotli")],
    )
    _vendor(store, "CVE-2026-1001", "redhat", [_pkg("rhel:9", "firefox")])
    (only,) = c.classify(store, SINCE, RULES)
    assert only.kind == "judge" and only.families == ["brotli"]


def test_supported_releases():
    assert [
        c.supported(r)
        for r in (
            "ubuntu:22.04",
            "ubuntu:26.04",
            "ubuntu:25.10",  # interim, past its end of life
            "ubuntu:26.10",  # interim, in support
            "ubuntu:23.04",
            "ubuntu:20.04",
            "rhel:9",
            "rhel:10",
            "rhel:8",
        )
    ] == [True, True, False, True, False, False, True, True, False]


@pytest.mark.parametrize(
    "name, family",
    [
        ("php8.3", "php"),
        ("php", "php"),
        ("linux-aws-6.8", "kernel"),
        ("kernel-rt", "kernel"),
        ("linux-firmware", "linux-firmware"),
        ("linux", "kernel"),
        ("linux-signed-hwe-6.8", "kernel"),
        ("linux-oem-6.5", "kernel"),
        ("linux-atm", "linux-atm"),
        ("linux-base", "linux-base"),
        ("linuxptp", "linuxptp"),
        ("openjdk-17", "openjdk"),
        ("tomcat9", "tomcat"),
        ("python3.12", "python"),
    ],
)
def test_package_families(name, family):
    assert c.package_family(name) == family


def test_threats_group_same_family_within_two_weeks(store):
    _signalled(store, "CVE-2026-1001", "2026-10-21T00:00:00.000000Z")
    _signalled(store, "CVE-2026-1002", "2026-10-22T00:00:00.000000Z")
    _signalled(store, "CVE-2026-1003", "2026-11-20T00:00:00.000000Z")
    for cve, name in (
        ("CVE-2026-1001", "php8.3"),
        ("CVE-2026-1002", "php8.4"),
        ("CVE-2026-1003", "php8.3"),
    ):
        _vendor(store, cve, "ubuntu", [_pkg("ubuntu:24.04", name)])
        _vendor(store, cve, "redhat", [], found=0)
    groups = c.threats(c.classify(store, SINCE, RULES))
    assert [[x.cve for x in g.candidates] for g in groups] == [
        ["CVE-2026-1001", "CVE-2026-1002"],
        ["CVE-2026-1003"],
    ]


def test_render_names_sections_feeds_and_unread(store):
    _signalled(store, PHP)
    _vendor(store, PHP, "ubuntu", [_pkg("ubuntu:24.04", "php8.3")])
    _vendor(store, PHP, "redhat", [_pkg("rhel:9", "php", fixed=False)])
    _signalled(store, "CVE-2026-1005")
    text = c.render(c.classify(store, SINCE, RULES), SINCE, ["nvd: failing, HTTP 503"])
    assert "Feeds needing a look" in text and "nvd: failing" in text
    assert "Can judge: 1 threat(s), 1 CVE(s)" in text
    assert "rhel:9: php (no fix yet); ubuntu:24.04: php8.3 (fixed)" in text
    assert "Vendor records not read yet: 1 CVE(s)" in text


# the command line


def test_cli_add_by_hand_and_list(tmp_path, capsys):
    assert (
        cli.main(
            [
                "--home",
                str(tmp_path),
                "candidates",
                "add",
                "cve-2026-109618",
                "--note",
                "heard from a\x1b[31m friend",
            ]
        )
        == 0
    )
    db = sqlite3.connect(tmp_path / "drafter.sqlite3")
    assert db.execute("SELECT cve FROM manual").fetchone()[0] == PHP
    db.close()
    capsys.readouterr()
    assert cli.main(["--home", str(tmp_path), "candidates", "list"]) == 0
    out = capsys.readouterr().out
    assert "Vendor records not read yet: 1 CVE(s)" in out
    assert "\x1b" not in out


def test_cli_add_refuses_a_non_cve(tmp_path):
    assert cli.main(["--home", str(tmp_path), "candidates", "add", "PHP2Shell", "--note", "x"]) == 2


def test_store_moves_from_schema_1(tmp_path):
    path = tmp_path / "old.sqlite3"
    from drafter.store import _SCHEMA

    db = sqlite3.connect(path)
    db.executescript(_SCHEMA + "PRAGMA user_version = 1;")
    db.execute("INSERT INTO feed_state (feed, position) VALUES ('kev', 'x')")
    db.commit()
    db.close()
    s = Store(path)
    assert s.db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert s.state("kev").position == "x"
    s.db.execute("SELECT * FROM vendor_cve").fetchall()
    s.close()


# found in the 180-day history run (2026-11-07)


def _rh(store, cve, when="2026-10-21T00:00:00.000000Z"):
    store.upsert(
        "redhat_critical",
        {"cve": cve, "public_date": when, "packages": "[]", "fetch_id": _fid(store)},
        ("cve",),
    )


def test_red_hat_rating_speaks_only_for_red_hat_packages(store):
    _rh(store, "CVE-2026-2001")  # Red Hat Critical, only an Ubuntu universe package
    _nvd(store, "CVE-2026-2001", "2026-10-21T00:00:00.000000Z", exploitation="none")
    _vendor(store, "CVE-2026-2001", "ubuntu", [_pkg("ubuntu:24.04", "hugo")])
    _vendor(store, "CVE-2026-2001", "redhat", [_pkg("rhel:8", "hugo")])
    _rh(store, "CVE-2026-2002")  # Red Hat Critical on webkit (set aside) and Ubuntu nginx
    _vendor(store, "CVE-2026-2002", "ubuntu", [_pkg("ubuntu:24.04", "nginx")])
    _vendor(store, "CVE-2026-2002", "redhat", [_pkg("rhel:9", "webkit2gtk3")])
    _kev(store, "CVE-2026-2003", "2026-10-21")  # CISA's list speaks for every vendor
    _vendor(store, "CVE-2026-2003", "ubuntu", [_pkg("ubuntu:24.04", "hugo")])
    _vendor(store, "CVE-2026-2003", "redhat", [], found=0)
    _rh(store, "CVE-2026-2004")  # attacked, and Red Hat's rating with no RHEL package
    _kev(store, "CVE-2026-2004", "2026-10-21")
    _vendor(store, "CVE-2026-2004", "ubuntu", [_pkg("ubuntu:24.04", "hugo")])
    _vendor(store, "CVE-2026-2004", "redhat", [_pkg("rhel:8", "hugo")])
    found = {x.cve: x for x in c.classify(store, SINCE, RULES)}
    assert {cve: x.kind for cve, x in found.items()} == {
        "CVE-2026-2001": "rated",  # a rating alone puts nothing on the list
        "CVE-2026-2002": "rated",
        "CVE-2026-2003": "judge",
        "CVE-2026-2004": "judge",
    }
    assert [s.kind for s in found["CVE-2026-2004"].signals] == ["kev"]


def test_red_hat_container_images_are_not_host_packages():
    record = {
        "affected_release": [
            {
                "package": "openshift/ose-rhel-coreos-9:416.94.202605200242-0",
                "cpe": "cpe:/a:redhat:openshift:4.16::el9",
            },
            {"package": "kpatch-patch-5_14_0-427-0:1-1.el9_4", "cpe": "cpe:/o:redhat:rhel_eus:9.4"},
        ]
    }
    _, packages = c.parse_redhat(json.dumps(record).encode())
    assert [p["package"] for p in packages] == ["kpatch-patch-5_14_0-427"]
    assert c.package_family("kpatch-patch-5_14_0-427") == "kernel"


def test_reparse_reads_stored_bodies_again(store, ctx, fetcher):
    _nvd(store, PHP, "2026-11-06T00:00:00.000000Z")
    fetcher.add(
        c.REDHAT_URL.format(cve=PHP),
        ok(
            {
                "affected_release": [
                    {
                        "package": "php-0:8.3.36-1.el10_2",
                        "cpe": "cpe:/o:redhat:enterprise_linux:10.2",
                    }
                ]
            }
        ),
    )
    c.refresh(ctx, SINCE)
    store.db.execute("UPDATE vendor_cve SET packages = '[]' WHERE vendor = 'redhat'")
    assert c.reparse(store) == 1  # Ubuntu's was a 404: nothing to re-read
    packages = json.loads(
        store.db.execute("SELECT packages FROM vendor_cve WHERE vendor = 'redhat'").fetchone()[0]
    )
    assert packages[0]["package"] == "php"
    assert len([x for x in fetcher.calls]) == 2  # nothing fetched by the re-read


# agent review of PR #2


def test_old_cve_restamped_by_cisa_is_not_a_new_threat(store):
    _kev(store, "CVE-2022-30333", "2022-08-09")
    _nvd(store, "CVE-2022-30333", "2026-08-04T00:00:00.000000Z")  # CISA's batch re-stamp
    _nvd(store, PHP, "2026-10-21T00:00:00.000000Z")
    assert list(c.signals(store, SINCE)) == [PHP]


@pytest.mark.parametrize(
    "package, name",
    [
        ("nginx-2:1.20.1-24.el9_7.3", "nginx"),
        ("php8.4-0:8.4.27-1.el10_2", "php8.4"),
        ("redhat-ds:12-9020020260101.abc", "redhat-ds"),
        ("php:8.2-8100020261020140951.f7998665", "php"),
        ("openssl-3.0.7-27.el9", "openssl"),
        ("pki-servlet-engine", "pki-servlet-engine"),
        ("java-21-openjdk", "java-21-openjdk"),
        ("perl-Net-DNS", "perl-Net-DNS"),
        ("python-requests", "python-requests"),
        ("linux-firmware", "linux-firmware"),
        ("kpatch-patch-5_14_0-427-0:1-1.el9_4", "kpatch-patch-5_14_0-427"),
    ],
)
def test_red_hat_names_in_each_form(package, name):
    assert c._rh_name(package) == name


def test_fixed_in_one_stream_and_affected_in_another_stay_apart():
    record = {
        "affected_release": [
            {"package": "php-0:8.3.36-1.el9_7", "cpe": "cpe:/a:redhat:enterprise_linux:9"}
        ],
        "package_state": [
            {
                "package_name": "php:8.4/php",
                "fix_state": "Affected",
                "cpe": "cpe:/a:redhat:enterprise_linux:9",
            }
        ],
    }
    _, packages = c.parse_redhat(json.dumps(record).encode())
    assert [(p["package"], p["fixed"]) for p in packages] == [("php", False), ("php", True)]


def test_bad_records_are_recorded_and_go_to_the_back(ctx, fetcher, store, clock):
    for cve in ("CVE-2026-3001", "CVE-2026-3002"):
        _nvd(store, cve, "2026-11-06T00:00:00.000000Z")
    fetcher.add(
        c.REDHAT_URL.format(cve="CVE-2026-3001"), ok({"public_date": "9999-12-31T23:59:59-23:59"})
    )  # overflows, so it reads as no date
    fetcher.add(c.UBUNTU_URL.format(cve="CVE-2026-3001"), ok(b"[" * 100000))  # too deep
    result = c.refresh(ctx, SINCE)
    assert (result.fetched, result.failed) == (3, 1)
    rows = {(r["cve"], r["vendor"]): r for r in store.db.execute("SELECT * FROM vendor_cve")}
    assert rows[("CVE-2026-3001", "redhat")]["published"] is None
    bad = rows[("CVE-2026-3001", "ubuntu")]
    assert bad["checked_at"] is None and bad["error"]
    kinds = {x.cve: x.kind for x in c.classify(store, SINCE, RULES)}
    assert kinds["CVE-2026-3001"] == "unread"
    assert c.refresh(ctx, SINCE).fetched == 0  # failed tries wait an hour
    clock.advance(hours=1)
    _nvd(store, "CVE-2026-3003", "2026-11-07T00:00:00.000000Z")
    fetcher.calls.clear()
    c.refresh(ctx, SINCE)
    order = [call["url"].rsplit("/", 1)[1] for call in fetcher.calls]
    assert set(order[:2]) == {"UBUNTU-CVE-2026-3003.json", "CVE-2026-3003.json"}  # never read


def test_a_failed_reread_keeps_the_last_good_record(ctx, fetcher, store, clock):
    _nvd(store, PHP, "2026-11-06T00:00:00.000000Z")
    fetcher.add(
        c.REDHAT_URL.format(cve=PHP),
        [
            ok(
                {
                    "affected_release": [
                        {
                            "package": "php-0:8.3.36-1.el10_2",
                            "cpe": "cpe:/o:redhat:enterprise_linux:10.2",
                        }
                    ]
                }
            ),
            FetchError("HTTP 503", status=503),
        ],
    )
    c.refresh(ctx, SINCE)
    clock.advance(days=1)
    c.refresh(ctx, SINCE)
    row = store.db.execute("SELECT * FROM vendor_cve WHERE vendor = 'redhat'").fetchone()
    assert row["error"] == "HTTP 503" and json.loads(row["packages"])[0]["package"] == "php"


def test_a_new_sign_on_a_known_cve_rereads_it_at_once(ctx, fetcher, store, clock):
    _nvd(store, PHP, "2026-10-21T00:00:00.000000Z")
    c.refresh(ctx, SINCE)
    clock.advance(hours=2)
    assert c.refresh(ctx, SINCE).fetched == 0
    clock.advance(hours=1)
    store.upsert("manual", {"cve": PHP, "added_at": ctx.stamp(), "note": "x"}, ("cve",))
    assert c.refresh(ctx, SINCE).fetched == 2  # a sign newer than the last read


def test_older_candidates_are_reread_weekly(ctx, fetcher, store, clock):
    _nvd(store, PHP, "2026-08-01T00:00:00.000000Z")
    since = "2026-05-11T00:00:00.000000Z"
    c.refresh(ctx, since)
    clock.advance(days=6)
    assert c.refresh(ctx, since).fetched == 0
    clock.advance(days=1)
    assert c.refresh(ctx, since).fetched == 2


def test_kernel_threat_names_only_its_kernels(store):
    _signalled(store, "CVE-2026-46300")
    _vendor(store, "CVE-2026-46300", "ubuntu", [], found=0)
    _vendor(
        store,
        "CVE-2026-46300",
        "redhat",
        [_pkg("rhel:9", "kernel"), _pkg("rhel:9", "openshift", product="openshift")],
    )
    (only,) = c.classify(store, SINCE, RULES)
    assert only.kind == "kernel" and only.families == ["kernel"]


def test_unread_cves_are_listed_by_number(store):
    _signalled(store, "CVE-2026-1005")
    text = c.render(c.classify(store, SINCE, RULES), SINCE, [])
    assert "  CVE-2026-1005" in text


def test_hand_notes_show_cleaned(store, tmp_path, capsys, monkeypatch):
    home = tmp_path / "h"
    assert (
        cli.main(["--home", str(home), "candidates", "add", PHP, "--note", "from a friend\x1b[31m"])
        == 0
    )
    s = Store(home / "drafter.sqlite3")
    _vendor(s, PHP, "ubuntu", [_pkg("ubuntu:24.04", "php8.3")])
    _vendor(s, PHP, "redhat", [], found=0)
    s.close()
    capsys.readouterr()
    assert cli.main(["--home", str(home), "candidates", "list", "--days", "36500"]) == 0
    out = capsys.readouterr().out
    assert "added by hand" in out and "from a friend?[31m" in out and "\x1b" not in out


def test_adding_again_keeps_the_first_date(tmp_path):
    home = tmp_path / "h"
    cli.main(["--home", str(home), "candidates", "add", PHP, "--note", "first"])
    db = sqlite3.connect(home / "drafter.sqlite3")
    first = db.execute("SELECT added_at FROM manual").fetchone()[0]
    db.close()
    cli.main(["--home", str(home), "candidates", "add", PHP, "--note", "second"])
    db = sqlite3.connect(home / "drafter.sqlite3")
    assert db.execute("SELECT added_at, note FROM manual").fetchone() == (first, "second")
    db.close()


def test_reading_commands_never_upgrade_an_older_store(tmp_path, capsys):
    from drafter.store import _SCHEMA

    home = tmp_path / "h"
    home.mkdir()
    db = sqlite3.connect(home / "drafter.sqlite3")
    db.executescript(_SCHEMA + "PRAGMA user_version = 1;")
    db.close()
    for command in (["candidates", "list"], ["feeds", "status"]):
        assert cli.main(["--home", str(home), *command]) == 1
        assert "schema 1" in capsys.readouterr().err
    db = sqlite3.connect(home / "drafter.sqlite3")
    assert db.execute("PRAGMA user_version").fetchone()[0] == 1
    db.close()


def test_a_failing_refresh_shows_in_status(ctx, fetcher, store):
    from drafter.feeds import run_one
    from drafter.status import report

    _nvd(store, PHP, "2026-11-06T00:00:00.000000Z")
    fetcher.add(lambda url: True, FetchError("HTTP 503", status=503))
    outcome = run_one(ctx, c.VendorRecords(SINCE, 100))
    assert not outcome.ok and "2 vendor record(s) failed" in outcome.error
    (r,) = report(store, [c.VendorRecords("", 0)], ctx.now())
    assert r.state == "failing"


def test_unit_lets_a_failed_feed_read_go_on_to_the_refresh():
    from pathlib import Path

    unit = Path(__file__).parent.parent / "contrib/systemd/pack-drafter-feeds.service"
    starts = [line for line in unit.read_text().splitlines() if line.startswith("ExecStart=")]
    assert starts[0].startswith("ExecStart=-") and starts[0].endswith("feeds fetch")
    assert starts[1].endswith("candidates refresh") and not starts[1].startswith("ExecStart=-")


# Copilot round 1 on PR #2


def test_vendor_scope_keeps_older_signs_when_the_window_is_narrow(store):
    # CISA's list from long ago would make this "can judge" through its Ubuntu
    # package; a recent Red Hat rating alone would set it aside. The window picks
    # CVEs by their first sign, so a narrow window leaves it out, never re-sorted.
    _kev(store, "CVE-2026-4001", "2026-06-01")
    _rh(store, "CVE-2026-4001", "2026-10-21T00:00:00.000000Z")
    _vendor(store, "CVE-2026-4001", "ubuntu", [_pkg("ubuntu:24.04", "nginx")])
    _vendor(store, "CVE-2026-4001", "redhat", [_pkg("rhel:9", "webkit2gtk3")])
    wide = {x.cve: x.kind for x in c.classify(store, "2026-05-11T00:00:00.000000Z", RULES)}
    assert wide == {"CVE-2026-4001": "judge"}
    assert c.classify(store, SINCE, RULES) == []


# the third-party watch list (John, 2026-11-07)

WATCH = c.load_watch()


def test_watch_file_loads():
    (php,) = WATCH
    assert php.cpe == "php:php" and "PHP" in php.words and len(php.repositories) == 2
    with pytest.raises(ValueError, match="repositories"):
        c.load_watch('[[watch]]\ncpe = "x:y"\n')


def _no_vendor_packages(store, cve):
    _vendor(store, cve, "ubuntu", [], found=0)
    _vendor(store, cve, "redhat", [], found=0)


def test_a_watched_product_with_no_vendor_package_is_listed(store):
    # A bug only in PHP 8.4: no Ubuntu or Red Hat package is affected, Sury's is.
    _nvd(store, "CVE-2026-5001", "2026-10-21T00:00:00.000000Z", products=["php:php"])
    _no_vendor_packages(store, "CVE-2026-5001")
    (only,) = c.classify(store, SINCE, RULES, WATCH)
    assert only.kind == "thirdparty" and only.watched == ["php:php"]
    text = c.render([only], SINCE, [])
    assert "Third-party builds" in text and "rebuilt by: Sury" in text


def test_description_words_stand_in_until_nvd_names_products(store):
    text = "In PHP 8.4 before 8.4.28, a crafted multipart request can execute code."
    _nvd(store, "CVE-2026-5002", "2026-10-21T00:00:00.000000Z", products=[], description=text)
    _no_vendor_packages(store, "CVE-2026-5002")
    (only,) = c.classify(store, SINCE, RULES, WATCH)
    assert only.kind == "thirdparty" and "description mentions PHP" in only.watched_via[0]


@pytest.mark.parametrize(
    "text",
    [
        "The plugin's upload.php file allows arbitrary file upload.",  # a file name
        "A flaw in phpMyAdmin allows SQL injection.",  # another word
        "Graphite's php-like templating is unsafe.",
    ],
)
def test_description_words_match_whole_words_only(text):
    assert not WATCH[0].word_match(text)


def test_description_words_count_even_when_nvd_names_other_products(store):
    # PHP2Shell as NVD has it: products named are Palo Alto's, the text says PHP.
    text = "PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context."
    _nvd(
        store,
        "CVE-2026-5003",
        "2026-10-21T00:00:00.000000Z",
        products=["paloaltonetworks:pan-os"],
        description=text,
    )
    _no_vendor_packages(store, "CVE-2026-5003")
    (only,) = c.classify(store, SINCE, RULES, WATCH)
    assert only.kind == "thirdparty" and "description mentions PHP" in only.watched_via[0]


def test_a_vendor_rating_alone_does_not_make_a_third_party_threat(store):
    _rh(store, "CVE-2026-5004")
    _nvd(
        store,
        "CVE-2026-5004",
        "2026-10-21T00:00:00.000000Z",
        exploitation="none",
        products=["php:php"],
    )
    _no_vendor_packages(store, "CVE-2026-5004")
    (only,) = c.classify(store, SINCE, RULES, WATCH)
    assert only.kind == "rated"


def test_recent_cves_nvd_has_not_named_are_not_ruled_out(store):
    import datetime as dt

    _nvd(store, "CVE-2026-5005", "2026-10-21T00:00:00.000000Z", products=[])
    _no_vendor_packages(store, "CVE-2026-5005")
    soon = dt.datetime(2026, 11, 7, tzinfo=dt.UTC)
    (only,) = c.classify(store, SINCE, RULES, WATCH, now=soon)
    assert only.kind == "unnamed"
    assert "NVD names no product yet: 1 CVE(s)" in c.render([only], SINCE, [])
    later = dt.datetime(2026, 12, 1, tzinfo=dt.UTC)
    (only,) = c.classify(store, SINCE, RULES, WATCH, now=later)
    assert only.kind == "elsewhere"


def test_list_all_names_the_rest(store):
    _nvd(store, "CVE-2026-5006", "2026-10-21T00:00:00.000000Z", products=["google:chrome"])
    _no_vendor_packages(store, "CVE-2026-5006")
    found = c.classify(store, SINCE, RULES, WATCH)
    assert "CVE-2026-5006" not in c.render(found, SINCE, [])
    assert "CVE-2026-5006  google:chrome" in c.render(found, SINCE, [], show_all=True)


def test_nvd_products_and_description_from_a_page():
    from drafter.feeds import nvd

    page = {
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-5007",
                    "lastModified": "2026-11-07T10:00:00.000",
                    "descriptions": [
                        {"lang": "es", "value": "Hola"},
                        {"lang": "en", "value": "In  PHP\n x"},
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                                        },
                                        {
                                            "vulnerable": False,
                                            "criteria": "cpe:2.3:o:debian:debian_linux:12:*",
                                        },
                                        {"vulnerable": True, "criteria": "cpe:2.3:a:BAD;NAME:x:*"},
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ],
    }
    _, _, (row,) = nvd.parse(json.dumps(page).encode())
    assert json.loads(row["products"]) == ["php:php"]
    assert row["description"] == "In PHP x"


def test_a_vendor_rating_alone_is_not_left_open_either(store):
    import datetime as dt

    _rh(store, "CVE-2026-5008")  # Red Hat's own rating, and no RHEL package
    _no_vendor_packages(store, "CVE-2026-5008")
    soon = dt.datetime(2026, 11, 7, tzinfo=dt.UTC)
    (only,) = c.classify(store, SINCE, RULES, WATCH, now=soon)
    assert only.kind == "rated"


def test_a_rating_alone_is_counted_and_never_listed_or_read(store, ctx):
    # The scope rule (2026-11-10): packs are for attacks seen in the wild.
    _rh(store, "CVE-2026-6001")
    _vendor(store, "CVE-2026-6001", "ubuntu", [], found=0)
    _vendor(store, "CVE-2026-6001", "redhat", [_pkg("rhel:9", "dotnet8.0")])
    _rh(store, "CVE-2026-6002")  # its records never read: not "unread" either
    _kev(store, "CVE-2026-6003", "2026-10-21")
    _rh(store, "CVE-2026-6003")
    _vendor(store, "CVE-2026-6003", "ubuntu", [], found=0)
    _vendor(store, "CVE-2026-6003", "redhat", [_pkg("rhel:9", "dotnet8.0")])
    found = c.classify(store, SINCE, RULES, WATCH)
    assert {x.cve: x.kind for x in found} == {
        "CVE-2026-6001": "rated",
        "CVE-2026-6002": "rated",
        "CVE-2026-6003": "judge",
    }
    # same package family, same days: the rated CVE still doesn't join the threat
    (threat,) = c.threats(found)
    assert [x.cve for x in threat.candidates] == ["CVE-2026-6003"]
    text = c.render(found, SINCE, [])
    assert "CVE-2026-6001" not in text and "CVE-2026-6002" not in text
    assert "Rated critical by a vendor, no sign of an attack: 2 CVE(s), counted only" in text
    assert "Red Hat severity Critical" in text  # shown on the attacked one
    assert "not read yet" not in text


def test_refresh_reads_no_records_for_a_rating_alone(store, ctx):
    _rh(store, "CVE-2026-6001")
    assert c.refresh(ctx, SINCE).fetched == 0
    assert store.db.execute("SELECT count(*) FROM vendor_cve").fetchone()[0] == 0


def test_a_cve_rated_long_ago_and_attacked_now_is_new_now(store):
    _rh(store, "CVE-2026-6004", "2026-03-01T00:00:00.000000Z")  # long before the window
    assert c.signals(store, SINCE) == {}
    _kev(store, "CVE-2026-6004", "2026-10-21")
    _vendor(store, "CVE-2026-6004", "ubuntu", [], found=0)
    _vendor(store, "CVE-2026-6004", "redhat", [_pkg("rhel:9", "dotnet8.0")])
    (only,) = c.classify(store, SINCE, RULES, WATCH)
    assert only.kind == "judge" and only.first[:10] == "2026-10-21"
    assert [s.kind for s in only.signals] == ["redhat", "kev"]
    # and the other way: an old attack with a new rating stays history
    _kev(store, "CVE-2026-6005", "2026-03-01")
    _rh(store, "CVE-2026-6005")
    assert "CVE-2026-6005" not in c.signals(store, SINCE)


# focused review of the third-party commit


def test_cisas_own_names_reach_the_watch_list(store):
    # CISA writes "PHP Group" / "PHP"; NVD may have no row, or no CPE, yet.
    store.upsert(
        "kev",
        {
            "cve": "CVE-2026-6001",
            "date_added": "2026-10-21",
            "vendor": "PHP Group",
            "product": "PHP",
            "name": "PHP RCE",
            "fetch_id": _fid(store),
        },
        ("cve",),
    )
    _no_vendor_packages(store, "CVE-2026-6001")
    (only,) = c.classify(store, SINCE, RULES, WATCH)
    assert only.kind == "thirdparty" and "CISA's list names PHP Group PHP" in only.watched_via[0]


def test_a_cisa_name_does_not_rule_a_cve_out(store):
    import datetime as dt

    store.upsert(
        "kev",
        {
            "cve": "CVE-2026-6002",
            "date_added": "2026-11-06",
            "vendor": "SonicWall",
            "product": "SonicOS SSLVPN",
            "name": "x",
            "fetch_id": _fid(store),
        },
        ("cve",),
    )
    _nvd(store, "CVE-2026-6002", "2026-11-06T00:00:00.000000Z", exploitation="none", products=[])
    _no_vendor_packages(store, "CVE-2026-6002")
    soon = dt.datetime(2026, 11, 7, tzinfo=dt.UTC)
    (only,) = c.classify(store, SINCE, RULES, WATCH, now=soon)
    assert only.kind == "unnamed"
    assert "CISA: SonicWall SonicOS SSLVPN" in c.render([only], SINCE, [])


@pytest.mark.parametrize(
    "text, hit",
    [
        ("A flaw in PHP8.4 lets a request run code.", True),
        ("Exploited as PHP2Shell in October.", True),
        ("Util/PHP/eval-stdin.php in PHPUnit allows code execution.", True),  # "PHP/" is PHP
        ("PHPUnit before 4.8.28 allows code execution.", False),
    ],
)
def test_word_match_edges(text, hit):
    assert WATCH[0].word_match(text) is hit


def test_escaped_colons_in_cpe_names():
    from drafter.feeds.nvd import products

    config = [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:acme:tool\\:pro:1.0:*:*:*:*:*:*:*",
                        }
                    ]
                }
            ]
        }
    ]
    assert products(config) == ["acme:tool\\:pro"]


def _page(*cves):
    return json.dumps(
        {
            "totalResults": len(cves),
            "vulnerabilities": [
                {
                    "cve": {
                        "id": cve,
                        "lastModified": "2026-11-07T10:00:00.000",
                        "descriptions": [{"lang": "en", "value": f"About {cve} in PHP"}],
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
                for cve in cves
            ],
        }
    ).encode()


def test_reparse_products_fills_only_rows_from_their_page(store):
    from drafter.feeds.nvd import reparse_products

    first = store.record_fetch(
        feed="nvd",
        url="p1",
        fetched_at="t",
        status=200,
        body=_page("CVE-2026-7001", "CVE-2026-7002"),
    )
    again = store.record_fetch(
        feed="nvd",
        url="p2",
        fetched_at="t",
        status=200,
        body=_page("CVE-2026-7001", "CVE-2026-7002"),
    )  # same_as first
    newer = store.record_fetch(feed="nvd", url="p3", fetched_at="t", status=200, body=b"{}")
    for cve, fid in (("CVE-2026-7001", again), ("CVE-2026-7002", newer)):
        store.upsert(
            "nvd",
            {
                "cve": cve,
                "last_modified": "t",
                "exploitation": None,
                "ssvc_time": None,
                "kev_added": None,
                "fetch_id": fid,
            },
            ("cve",),
        )
    assert store.fetch_body(again) is not None and first
    assert reparse_products(store) == 1
    rows = dict(store.db.execute("SELECT cve, products FROM nvd").fetchall())
    assert json.loads(rows["CVE-2026-7001"]) == ["php:php"]
    assert json.loads(rows["CVE-2026-7002"]) == []  # its own page says nothing


def test_upgrade_from_schema_1_fills_nvd_names(tmp_path, capsys):
    from drafter.store import _SCHEMA

    home = tmp_path / "h"
    home.mkdir()
    db = sqlite3.connect(home / "drafter.sqlite3")
    db.executescript(_SCHEMA + "PRAGMA user_version = 1;")
    import gzip

    db.execute(
        "INSERT INTO fetches (id, feed, url, fetched_at, status, body)"
        " VALUES (1, 'nvd', 'p', 't', 200, ?)",
        (gzip.compress(_page(PHP)),),
    )
    db.execute("INSERT INTO nvd (cve, last_modified, fetch_id) VALUES (?, 't', 1)", (PHP,))
    db.commit()
    db.close()
    assert cli.main(["--home", str(home), "candidates", "add", PHP, "--note", "x"]) == 0
    assert "NVD rows for 1 CVE(s)" in capsys.readouterr().out
    s = Store(home / "drafter.sqlite3")
    row = s.db.execute("SELECT products, description FROM nvd").fetchone()
    assert json.loads(row[0]) == ["php:php"] and "PHP" in row[1]
    s.close()


def test_an_early_schema_2_store_gets_the_new_columns(tmp_path):
    from drafter import store as store_module

    path = tmp_path / "early.sqlite3"
    db = sqlite3.connect(path)
    early = store_module._STEPS[2].split("-- A.2: the vendor:product")[0]
    early += store_module._STEPS[2].split("ALTER TABLE nvd ADD COLUMN description TEXT;")[1]
    db.executescript(store_module._SCHEMA + early + "PRAGMA user_version = 2;")
    db.close()
    s = Store(path)
    cols = {r[1] for r in s.db.execute("PRAGMA table_info(nvd)")}
    assert {"products", "description"} <= cols and s.migrated_from == 1
    s.close()


def test_cli_list_all(tmp_path, capsys):
    home = tmp_path / "h"
    cli.main(["--home", str(home), "candidates", "add", "CVE-2026-8001", "--note", "x"])
    s = Store(home / "drafter.sqlite3")
    _nvd(
        s,
        "CVE-2026-8001",
        "2026-11-07T00:00:00.000000Z",
        exploitation="none",
        products=["google:chrome"],
    )
    _no_vendor_packages(s, "CVE-2026-8001")
    s.close()
    capsys.readouterr()
    cli.main(["--home", str(home), "candidates", "list", "--days", "36500"])
    assert "CVE-2026-8001" not in capsys.readouterr().out
    cli.main(["--home", str(home), "candidates", "list", "--days", "36500", "--all"])
    assert "CVE-2026-8001  google:chrome" in capsys.readouterr().out


# Copilot round 2 on PR #2


def test_cves_matched_different_ways_are_one_threat(store):
    _nvd(store, "CVE-2026-9001", "2026-10-21T00:00:00.000000Z", products=["php:php"])
    _nvd(
        store,
        "CVE-2026-9002",
        "2026-10-22T00:00:00.000000Z",
        products=[],
        description="In PHP 8.4 a request can run code.",
    )
    for cve in ("CVE-2026-9001", "CVE-2026-9002"):
        _no_vendor_packages(store, cve)
    groups = c.threats(c.classify(store, SINCE, RULES, WATCH))
    assert [[x.cve for x in g.candidates] for g in groups] == [["CVE-2026-9001", "CVE-2026-9002"]]
    text = c.render(c.classify(store, SINCE, RULES, WATCH), SINCE, [])
    assert "matched: NVD's description mentions PHP" in text


def test_read_only_open_survives_uri_characters_in_the_path(tmp_path):
    home = tmp_path / "copy#review?x"
    home.mkdir()
    Store(home / "drafter.sqlite3").close()
    s = Store(home / "drafter.sqlite3", read_only=True)
    with pytest.raises(sqlite3.OperationalError):
        s.db.execute("CREATE TABLE x (a)")  # really read-only
    s.close()
    assert not (tmp_path / "copy").exists()


def test_an_early_schema_2_store_still_gets_its_columns_on_the_way_up(tmp_path):
    from drafter import store as store_module

    path = tmp_path / "early2.sqlite3"
    db = sqlite3.connect(path)
    early = store_module._STEPS[2].split("-- A.2: the vendor:product")[0]
    early += store_module._STEPS[2].split("ALTER TABLE nvd ADD COLUMN description TEXT;")[1]
    db.executescript(store_module._SCHEMA + early + "PRAGMA user_version = 2;")
    db.close()
    s = Store(path)
    cols = {r[1] for r in s.db.execute("PRAGMA table_info(nvd)")}
    assert {"products", "description"} <= cols
    assert s.db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    s.db.execute("SELECT * FROM propose_run").fetchall()
    s.close()


def test_an_early_vendor_cve_table_is_rebuilt(tmp_path):
    path = tmp_path / "early.sqlite3"
    s = Store(path)
    s.db.execute("DROP TABLE vendor_cve")
    s.db.execute(
        "CREATE TABLE vendor_cve (cve TEXT NOT NULL, vendor TEXT NOT NULL, checked_at TEXT NOT"
        " NULL, found INTEGER NOT NULL, published TEXT, packages TEXT NOT NULL, fetch_id"
        " INTEGER NOT NULL, PRIMARY KEY (cve, vendor))"
    )
    s.close()
    s = Store(path)
    cols = {r[1] for r in s.db.execute("PRAGMA table_info(vendor_cve)")}
    assert {"attempted_at", "error"} <= cols
    s.close()


def test_an_early_propose_run_table_gets_its_token_column(tmp_path):
    from drafter import thirdparty as tp

    path = tmp_path / "early3.sqlite3"
    s = Store(path)
    s.db.execute("DROP TABLE propose_run")
    s.db.execute(
        "CREATE TABLE propose_run (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL,"
        " cves TEXT NOT NULL, proposals TEXT NOT NULL, gaps TEXT NOT NULL)"
    )
    s.db.execute("INSERT INTO propose_run VALUES (1, '2026-11-07T00:00:00Z', '[]', '{}', '[]')")
    s.close()
    s = Store(path)
    assert "token" in {r[1] for r in s.db.execute("PRAGMA table_info(propose_run)")}
    # The old run has no token, so a file without one isn't taken as its own.
    problems = tp._against_run(s, 1, None, {}, set(), None)
    assert any("isn't in this store" in p for p in problems)
    s.close()
