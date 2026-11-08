"""Each feed against made-up answers shaped like the real ones (checked 2026-11-07)."""

from __future__ import annotations

import datetime as dt
import json
import urllib.parse
import zipfile

import pytest

from drafter.feeds import FeedError, run_one, seed_feed
from drafter.feeds.kev import URL as KEV_URL
from drafter.feeds.kev import Kev
from drafter.feeds.nvd import Nvd
from drafter.feeds.osv import BASE as OSV_BASE
from drafter.feeds.osv import Osv
from drafter.feeds.redhat import RedHatCritical
from drafter.feeds.usn import Usn
from drafter.http import FetchError
from tests.conftest import NOT_MODIFIED, ok

# CISA's list


def _kev(*entries):
    return {
        "title": "KEV",
        "catalogVersion": "2026.11.06",
        "count": len(entries),
        "vulnerabilities": list(entries),
    }


def _kev_entry(cve="CVE-2026-109618", added="2026-10-26", **extra):
    return {
        "cveID": cve,
        "vendorProject": "PHP",
        "product": "PHP",
        "dateAdded": added,
        "vulnerabilityName": "PHP2Shell",
        **extra,
    }


def test_kev_first_read_keeps_entries_and_headers(ctx, fetcher, store):
    fetcher.add(KEV_URL, ok(_kev(_kev_entry()), headers={"etag": '"e1"', "last-modified": "Fri"}))
    outcome = run_one(ctx, Kev())
    assert outcome.ok and outcome.changed == 1
    row = store.db.execute("SELECT * FROM kev").fetchone()
    assert (row["cve"], row["date_added"], row["name"]) == (
        "CVE-2026-109618",
        "2026-10-26",
        "PHP2Shell",
    )
    state = store.state("kev")
    assert (state.etag, state.last_modified, state.failures) == ('"e1"', "Fri", 0)
    assert state.last_change == state.last_success


def test_kev_asks_conditionally_and_takes_not_modified(ctx, fetcher, store):
    fetcher.add(KEV_URL, [ok(_kev(_kev_entry()), headers={"etag": '"e1"'}), NOT_MODIFIED])
    run_one(ctx, Kev())
    outcome = run_one(ctx, Kev())
    assert outcome.changed == 0
    assert fetcher.calls[1]["etag"] == '"e1"'


def test_kev_same_file_new_headers_is_not_a_change(ctx, fetcher, store):
    body = _kev(_kev_entry())
    fetcher.add(KEV_URL, [ok(body, headers={"etag": '"e1"'}), ok(body, headers={"etag": '"e2"'})])
    run_one(ctx, Kev())
    assert run_one(ctx, Kev()).changed == 0
    assert store.state("kev").etag == '"e2"'
    # stored once
    bodies = store.db.execute("SELECT COUNT(*) FROM fetches WHERE body IS NOT NULL").fetchone()
    assert bodies[0] == 1


def test_kev_skips_unreadable_entries_and_trims_text(ctx, fetcher, store):
    fetcher.add(
        KEV_URL,
        ok(
            _kev(
                _kev_entry(cve="CVE-2026-1"),  # too short
                _kev_entry(cve="../../etc"),
                _kev_entry(added="last week"),
                "not an object",
                _kev_entry(cve="CVE-2026-2222", vulnerabilityName="x" * 5000),
            )
        ),
    )
    run_one(ctx, Kev())
    rows = store.db.execute("SELECT cve, length(name) AS n FROM kev").fetchall()
    assert [(r["cve"], r["n"]) for r in rows] == [("CVE-2026-2222", 300)]


@pytest.mark.parametrize("body", [b"<html>", b"[]", json.dumps({"vulnerabilities": []}).encode()])
def test_kev_wrong_shape_fails_and_says_so(ctx, fetcher, store, body):
    fetcher.add(KEV_URL, ok(body))
    outcome = run_one(ctx, Kev())
    assert not outcome.ok and "KEV" in outcome.error
    assert store.state("kev").failures == 1


# NVD


def _nvd_page(total, *cves):
    return {
        "resultsPerPage": len(cves),
        "startIndex": 0,
        "totalResults": total,
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [{"cve": c} for c in cves],
    }


def _nvd_cve(cve, modified="2026-11-07T10:00:00.000", exploitation=None, kev=None):
    record = {"id": cve, "lastModified": modified, "metrics": {}}
    if exploitation:
        record["metrics"]["ssvcV203"] = [
            {
                "source": "x",
                "ssvcData": {
                    "timestamp": "2026-10-21T00:00:00+00:00",
                    "id": cve,
                    "options": [{"exploitation": exploitation}, {"automatable": "no"}],
                },
            }
        ]
    if kev:
        record["cisaExploitAdd"] = kev
    return record


def _query(url):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))


def test_nvd_reads_ssvc_and_pages(ctx, fetcher, store, sleeps):
    fetcher.add(
        "https://services.nvd.nist.gov/",
        [
            ok(
                _nvd_page(
                    3,
                    _nvd_cve("CVE-2026-109618", exploitation="active", kev="2026-10-26"),
                    _nvd_cve("CVE-2026-0002", exploitation="poc"),
                )
            ),
            ok(_nvd_page(3, _nvd_cve("CVE-2026-0003"))),
        ],
    )
    outcome = run_one(ctx, Nvd())
    assert outcome.ok and outcome.changed == 3
    rows = {r["cve"]: r for r in store.db.execute("SELECT * FROM nvd")}
    assert rows["CVE-2026-109618"]["exploitation"] == "active"
    assert rows["CVE-2026-109618"]["ssvc_time"] == "2026-10-21T00:00:00.000000Z"
    assert rows["CVE-2026-109618"]["kev_added"] == "2026-10-26"
    assert rows["CVE-2026-0002"]["exploitation"] == "poc"
    assert rows["CVE-2026-0003"]["exploitation"] is None
    assert [_query(c["url"])["startIndex"] for c in fetcher.calls] == ["0", "2"]
    assert sleeps == [6.5]  # NVD's limit without a key, with a margin
    assert store.state("nvd").position == "2026-11-07T12:00:00.000000Z"


def test_nvd_key_goes_in_a_header_never_the_address(ctx, fetcher, store, sleeps):
    ctx.nvd_api_key = "k-123"
    fetcher.add("https://services.nvd.nist.gov/", [ok(_nvd_page(0)), ok(_nvd_page(0))])
    ctx.since = ctx.now() - dt.timedelta(days=10)
    run_one(ctx, Nvd())
    assert all(c["headers"] == {"apiKey": "k-123"} for c in fetcher.calls)
    assert not any("k-123" in c["url"] for c in fetcher.calls)
    urls = store.db.execute("SELECT url FROM fetches").fetchall()
    assert not any("k-123" in r["url"] for r in urls)
    assert sleeps == [0.7]


def test_nvd_splits_long_spans_into_windows(ctx, fetcher, store):
    ctx.since = ctx.now() - dt.timedelta(days=10)
    fetcher.add("https://services.nvd.nist.gov/", [ok(_nvd_page(0)), ok(_nvd_page(0))])
    run_one(ctx, Nvd())
    windows = [
        (_query(c["url"])["lastModStartDate"], _query(c["url"])["lastModEndDate"])
        for c in fetcher.calls
    ]
    assert windows == [
        ("2026-10-28T12:00:00.000Z", "2026-11-04T12:00:00.000Z"),
        ("2026-11-04T12:00:00.000Z", "2026-11-07T12:00:00.000Z"),
    ]


def test_nvd_next_run_starts_from_saved_position_with_overlap(ctx, fetcher, store, clock):
    fetcher.add("https://services.nvd.nist.gov/", [ok(_nvd_page(0)), ok(_nvd_page(0))])
    run_one(ctx, Nvd())
    clock.advance(hours=1)
    run_one(ctx, Nvd())
    second = _query(fetcher.calls[1]["url"])
    assert second["lastModStartDate"] == "2026-11-07T11:45:00.000Z"
    assert second["lastModEndDate"] == "2026-11-07T13:00:00.000Z"


def test_nvd_older_copy_from_overlap_does_not_overwrite(ctx, fetcher, store, clock):
    fetcher.add(
        "https://services.nvd.nist.gov/",
        [
            ok(
                _nvd_page(
                    1, _nvd_cve("CVE-2026-0001", "2026-11-07T11:00:00", exploitation="active")
                )
            ),
            ok(_nvd_page(1, _nvd_cve("CVE-2026-0001", "2026-11-07T10:00:00", exploitation="none"))),
        ],
    )
    run_one(ctx, Nvd())
    clock.advance(hours=1)
    assert run_one(ctx, Nvd()).changed == 0
    assert store.db.execute("SELECT exploitation FROM nvd").fetchone()[0] == "active"


def test_nvd_failure_partway_keeps_finished_windows(ctx, fetcher, store):
    ctx.since = ctx.now() - dt.timedelta(days=10)
    fetcher.add(
        "https://services.nvd.nist.gov/", [ok(_nvd_page(0)), FetchError("HTTP 503", status=503)]
    )
    outcome = run_one(ctx, Nvd())
    assert not outcome.ok
    state = store.state("nvd")
    assert state.position == "2026-11-04T12:00:00.000000Z" and state.failures == 1


def test_nvd_empty_page_before_the_end_is_an_error(ctx, fetcher):
    fetcher.add("https://services.nvd.nist.gov/", [ok(_nvd_page(5))])
    outcome = run_one(ctx, Nvd())
    assert not outcome.ok and "empty" in outcome.error


# OSV


def _osv_index(*lines):
    return "".join(f"{t},{i}\n" for t, i in lines).encode()


def _osv_record(osv_id, modified, *, priority=None, upstream=(), related=()):
    record = {
        "id": osv_id,
        "modified": modified,
        "upstream": list(upstream),
        "related": list(related),
        "affected": [],
    }
    if priority:
        record["severity"] = [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"},
            {"type": "Ubuntu", "score": priority},
        ]
    return record


def _osv_route(fetcher, ecosystem, index, records, *, headers=None):
    base = f"{OSV_BASE}/{urllib.parse.quote(ecosystem)}/"
    fetcher.add(
        base + "modified_id.csv",
        index if isinstance(index, list) else ok(index, headers=headers or {}),
    )
    for osv_id, record in records.items():
        fetcher.add(base + urllib.parse.quote(osv_id) + ".json", ok(record))


def test_osv_fetches_changes_oldest_first_and_keeps_position(ctx, fetcher, store):
    _osv_route(
        fetcher,
        "AlmaLinux",
        _osv_index(
            ("2026-11-07T11:00:00.123456789Z", "ALSA-2026:2"),
            ("2026-11-07T10:00:00Z", "ALSA-2026:1"),
            ("2026-11-01T10:00:00Z", "ALSA-2026:0"),  # before the start
        ),
        {
            "ALSA-2026:1": _osv_record(
                "ALSA-2026:1", "2026-11-07T10:00:00Z", related=["CVE-2026-0001"]
            ),
            "ALSA-2026:2": _osv_record(
                "ALSA-2026:2", "2026-11-07T11:00:00Z", related=["CVE-2026-0002", "not-a-cve"]
            ),
        },
        headers={"etag": '"i1"'},
    )
    outcome = run_one(ctx, Osv("AlmaLinux"))
    assert outcome.ok and outcome.changed == 2
    fetched = [c["url"].rsplit("/", 1)[1] for c in fetcher.calls[1:]]
    assert fetched == ["ALSA-2026%3A1.json", "ALSA-2026%3A2.json"]
    state = store.state("osv-almalinux")
    assert state.position == "2026-11-07T11:00:00.123456Z|ALSA-2026:2"
    assert state.etag == '"i1"'
    cves = store.db.execute("SELECT cves FROM osv WHERE id = 'ALSA-2026:2'").fetchone()[0]
    assert json.loads(cves) == ["CVE-2026-0002"]
    # the index keeps its hash only; records keep bodies
    index = store.db.execute(
        "SELECT body, sha256 FROM fetches WHERE url LIKE '%modified_id.csv'"
    ).fetchone()
    assert index["body"] is None and index["sha256"]


def test_osv_limit_leaves_the_rest_for_next_run(ctx, fetcher, store):
    ctx.limit = 1
    lines = [("2026-11-07T11:00:00Z", "ALSA-2026:2"), ("2026-11-07T10:00:00Z", "ALSA-2026:1")]
    records = {i: _osv_record(i, t) for t, i in lines}
    _osv_route(
        fetcher,
        "AlmaLinux",
        [
            ok(_osv_index(*lines), headers={"etag": '"i"'}),
            ok(_osv_index(*lines), headers={"etag": '"i"'}),
        ],
        records,
    )
    run_one(ctx, Osv("AlmaLinux"))
    state = store.state("osv-almalinux")
    assert state.position.endswith("|ALSA-2026:1")
    assert state.etag is None  # the index must be read again: changes are still waiting
    run_one(ctx, Osv("AlmaLinux"))
    assert store.state("osv-almalinux").position.endswith("|ALSA-2026:2")


def test_osv_withdrawn_record_is_noted_and_passed(ctx, fetcher, store):
    _osv_route(fetcher, "AlmaLinux", _osv_index(("2026-11-07T10:00:00Z", "ALSA-2026:9")), {})
    outcome = run_one(ctx, Osv("AlmaLinux"))
    assert outcome.ok
    assert store.state("osv-almalinux").position.endswith("|ALSA-2026:9")
    assert store.db.execute("SELECT status FROM fetches ORDER BY id DESC").fetchone()[0] == 404


def test_osv_ubuntu_keeps_bodies_only_for_signs_of_exploitation(ctx, fetcher, store):
    fid = store.record_fetch(feed="kev", url="u", fetched_at="t", status=200, body=b"x")
    store.upsert(
        "kev",
        {
            "cve": "CVE-2026-0003",
            "date_added": "2026-11-01",
            "vendor": None,
            "product": None,
            "name": None,
            "fetch_id": fid,
        },
        ("cve",),
    )
    _osv_route(
        fetcher,
        "Ubuntu",
        _osv_index(
            ("2026-11-07T10:00:01Z", "UBUNTU-CVE-2026-0001"),
            ("2026-11-07T10:00:02Z", "UBUNTU-CVE-2026-0002"),
            ("2026-11-07T10:00:03Z", "UBUNTU-CVE-2026-0003"),
        ),
        {
            "UBUNTU-CVE-2026-0001": _osv_record(
                "UBUNTU-CVE-2026-0001", "2026-11-07T10:00:01Z", priority="critical"
            ),
            "UBUNTU-CVE-2026-0002": _osv_record(
                "UBUNTU-CVE-2026-0002", "2026-11-07T10:00:02Z", priority="medium"
            ),
            "UBUNTU-CVE-2026-0003": _osv_record(
                "UBUNTU-CVE-2026-0003", "2026-11-07T10:00:03Z", priority="low"
            ),
        },
    )
    run_one(ctx, Osv("Ubuntu"))
    rows = store.db.execute(
        "SELECT o.id, o.ubuntu_priority, o.cves, f.body IS NOT NULL AS kept, f.sha256"
        " FROM osv o JOIN fetches f ON f.id = o.fetch_id ORDER BY o.id"
    ).fetchall()
    assert [(r["id"], r["ubuntu_priority"], r["kept"]) for r in rows] == [
        ("UBUNTU-CVE-2026-0001", "critical", 1),
        ("UBUNTU-CVE-2026-0002", "medium", 0),
        ("UBUNTU-CVE-2026-0003", "low", 1),  # on CISA's list
    ]
    assert all(r["sha256"] for r in rows)
    assert json.loads(rows[0]["cves"]) == ["CVE-2026-0001"]


def _zip(path, records):
    with zipfile.ZipFile(path, "w") as bundle:
        for record in records:
            bundle.writestr(record["id"].replace(":", "_") + ".json", json.dumps(record))
        bundle.writestr("README.txt", "not a record")
        bundle.writestr("broken.json", "{")
    return path


def test_osv_seed_keeps_records_since_and_sets_position(ctx, fetcher, store, tmp_path):
    archive = _zip(
        tmp_path / "all.zip",
        [
            _osv_record("ALSA-2026:1", "2026-05-01T00:00:00Z"),
            _osv_record("ALSA-2026:2", "2026-10-01T00:00:00Z"),
            _osv_record("ALSA-2026:3", "2026-11-06T00:00:00Z"),
        ],
    )
    fetcher.downloads[f"{OSV_BASE}/AlmaLinux/all.zip"] = archive
    _osv_route(
        fetcher,
        "AlmaLinux",
        _osv_index(
            ("2026-11-06T00:00:00Z", "ALSA-2026:3"),
            ("2026-10-01T00:00:00Z", "ALSA-2026:2"),
            ("2026-05-01T00:00:00Z", "ALSA-2026:1"),
        ),
        {},
    )
    kept = Osv("AlmaLinux").seed(ctx, dt.datetime(2026, 9, 1, tzinfo=dt.UTC), ctx.workdir)
    assert kept == 2
    ids = [r[0] for r in store.db.execute("SELECT id FROM osv ORDER BY id")]
    assert ids == ["ALSA-2026:2", "ALSA-2026:3"]
    assert store.state("osv-almalinux").position == "2026-11-06T00:00:00.000000Z|ALSA-2026:3"
    assert not list(ctx.workdir.iterdir())  # the archive is removed afterwards
    seed = store.db.execute("SELECT sha256, size FROM fetches WHERE url LIKE '%all.zip'")
    assert all(seed.fetchone())


def test_osv_bad_archive_fails_cleanly(ctx, fetcher, tmp_path):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip")
    fetcher.downloads[f"{OSV_BASE}/AlmaLinux/all.zip"] = bad
    _osv_route(fetcher, "AlmaLinux", _osv_index(("2026-11-06T00:00:00Z", "ALSA-2026:3")), {})
    with pytest.raises(FeedError, match="not a zip"):
        Osv("AlmaLinux").seed(ctx, dt.datetime(2026, 9, 1, tzinfo=dt.UTC), ctx.workdir)
    assert not list(ctx.workdir.iterdir())


def test_osv_burst_reads_the_archive_instead(ctx, fetcher, store, tmp_path, monkeypatch):
    monkeypatch.setattr("drafter.feeds.osv.CATCH_UP_AFTER", 2)
    lines = [(f"2026-11-07T10:00:0{n}Z", f"ALSA-2026:{n}") for n in range(1, 5)]
    _osv_route(fetcher, "AlmaLinux", _osv_index(*lines), {})
    fetcher.downloads[f"{OSV_BASE}/AlmaLinux/all.zip"] = _zip(
        tmp_path / "all.zip", [_osv_record(i, t) for t, i in lines]
    )
    outcome = run_one(ctx, Osv("AlmaLinux"))
    assert outcome.ok and outcome.changed == 4
    assert sum(1 for c in fetcher.calls if c.get("download")) == 1
    assert not any(c["url"].endswith(".json") for c in fetcher.calls)
    assert store.state("osv-almalinux").position.endswith("|ALSA-2026:4")


def test_osv_unsafe_ids_in_the_index_are_skipped(ctx, fetcher, store):
    _osv_route(
        fetcher,
        "AlmaLinux",
        _osv_index(
            ("2026-11-07T10:00:00Z", "../../secret"),
            ("2026-11-07T10:00:00Z", "ALSA 2026"),
            ("2026-11-07T10:00:01Z", "ALSA-2026:1"),
        ),
        {"ALSA-2026:1": _osv_record("ALSA-2026:1", "2026-11-07T10:00:01Z")},
    )
    run_one(ctx, Osv("AlmaLinux"))
    assert [c["url"].rsplit("/", 1)[1] for c in fetcher.calls[1:]] == ["ALSA-2026%3A1.json"]


def test_osv_names():
    assert [Osv(e).name for e in ("Ubuntu", "AlmaLinux", "Rocky Linux")] == [
        "osv-ubuntu",
        "osv-almalinux",
        "osv-rockylinux",
    ]


# Ubuntu Security Notices


def _usn_page(total, *notices):
    return {"notices": list(notices), "offset": 0, "limit": 20, "total_results": total}


def _notice(usn_id, published, cves=()):
    return {"id": usn_id, "published": published, "cves_ids": list(cves), "title": "t"}


def test_usn_reads_back_to_the_saved_position(ctx, fetcher, store, monkeypatch):
    monkeypatch.setattr("drafter.feeds.usn.PAGE", 2)
    fetcher.add(
        "https://ubuntu.com/security/notices.json",
        [
            ok(
                _usn_page(
                    10,
                    _notice("USN-8952-2", "2026-11-07T09:00:00.1"),
                    _notice("USN-8952-1", "2026-11-07T08:00:00", ["CVE-2026-0001", "bad"]),
                )
            ),
            ok(
                _usn_page(
                    10,
                    _notice("USN-8951-1", "2026-11-06T13:00:00"),
                    _notice("USN-8950-1", "2026-11-06T11:00:00"),  # before the start
                )
            ),
            ok(
                _usn_page(
                    10,
                    _notice("USN-8949-2", "2026-11-06T12:30:00"),  # out of order, still read
                    _notice("USN-8949-1", "2026-11-06T10:00:00"),
                )
            ),
            ok(_usn_page(10, _notice("USN-8948-1", "2026-11-05T10:00:00"))),
        ],
    )
    outcome = run_one(ctx, Usn())
    assert outcome.changed == 4
    assert len(fetcher.calls) == 4  # stops at the first page wholly before the start
    assert store.state("usn").position == "2026-11-07T09:00:00.100000Z"
    cves = store.db.execute("SELECT cves FROM usn WHERE id = 'USN-8952-1'").fetchone()[0]
    assert json.loads(cves) == ["CVE-2026-0001"]


def test_usn_backlog_keeps_what_was_read_and_says_so_once(ctx, fetcher, store, monkeypatch):
    monkeypatch.setattr("drafter.feeds.usn.PAGE", 1)
    monkeypatch.setattr("drafter.feeds.usn.MAX_PAGES_PER_RUN", 1)
    page = ok(_usn_page(10, _notice("USN-8952-2", "2026-11-07T09:00:00")))
    older = ok(_usn_page(10, _notice("USN-8000-1", "2026-11-01T00:00:00")))
    fetcher.add("https://ubuntu.com/security/notices.json", [page, older])
    outcome = run_one(ctx, Usn())
    assert not outcome.ok and "older ones skipped" in outcome.error
    assert store.state("usn").position == "2026-11-07T09:00:00.000000Z"
    assert run_one(ctx, Usn()).ok  # the next run reads only a few days back


def test_usn_late_notice_with_an_older_time_is_still_read(ctx, fetcher, store, clock):
    fetcher.add(
        "https://ubuntu.com/security/notices.json",
        [
            ok(_usn_page(1, _notice("USN-9003-1", "2026-11-07T11:00:00"))),
            ok(
                _usn_page(
                    2,
                    _notice("USN-9003-1", "2026-11-07T11:00:00"),
                    _notice("USN-8952-2", "2026-11-07T08:00:00"),  # listed late
                )
            ),
        ],
    )
    run_one(ctx, Usn())
    clock.advance(hours=1)
    assert run_one(ctx, Usn()).changed == 1
    ids = [r[0] for r in store.db.execute("SELECT id FROM usn ORDER BY id")]
    assert ids == ["USN-8952-2", "USN-9003-1"]


def test_usn_unreadable_time_skips_the_notice_only(ctx, fetcher, store):
    fetcher.add(
        "https://ubuntu.com/security/notices.json",
        ok(
            _usn_page(
                2,
                _notice("USN-9003-1", "soon"),
                _notice("USN-9002-1", "2026-11-07T10:00:00"),
            )
        ),
    )
    assert run_one(ctx, Usn()).changed == 1


# Red Hat


def test_redhat_reads_critical_with_lookback(ctx, fetcher, store, clock):
    fetcher.add(
        "https://access.redhat.com/",
        [
            ok(
                [
                    {
                        "CVE": "CVE-2026-115731",
                        "severity": "critical",
                        "public_date": "2026-11-03T20:40:10Z",
                        "affected_packages": ["openvox-agent-0:8.32.0-1.el9sat", "bad name; rm"],
                    },
                    {"CVE": "CVE-2026-0002", "severity": "important"},
                ]
            ),
            ok([]),
        ],
    )
    outcome = run_one(ctx, RedHatCritical())
    assert outcome.changed == 1
    row = store.db.execute("SELECT * FROM redhat_critical").fetchone()
    assert json.loads(row["packages"]) == ["openvox-agent-0:8.32.0-1.el9sat"]
    assert _query(fetcher.calls[0]["url"])["after"] == "2026-11-06"
    clock.advance(hours=1)
    run_one(ctx, RedHatCritical())
    assert _query(fetcher.calls[1]["url"])["after"] == "2026-10-08"  # 30 days back


def test_redhat_pages_until_a_short_page(ctx, fetcher, monkeypatch):
    monkeypatch.setattr("drafter.feeds.redhat.PAGE", 1)
    item = {"CVE": "CVE-2026-0001", "severity": "critical"}
    fetcher.add("https://access.redhat.com/", [ok([item]), ok([])])
    assert run_one(ctx, RedHatCritical()).ok
    assert [_query(c["url"])["page"] for c in fetcher.calls] == ["1", "2"]


def test_redhat_wrong_shape_fails(ctx, fetcher):
    fetcher.add("https://access.redhat.com/", ok({"error": "x"}))
    assert not run_one(ctx, RedHatCritical()).ok


def test_redhat_unreadable_entry_in_a_full_page_does_not_stop_paging(ctx, fetcher, monkeypatch):
    monkeypatch.setattr("drafter.feeds.redhat.PAGE", 2)
    good = {"CVE": "CVE-2026-0001", "severity": "critical"}
    fetcher.add("https://access.redhat.com/", [ok([good, {"CVE": "junk"}]), ok([])])
    assert run_one(ctx, RedHatCritical()).ok
    assert len(fetcher.calls) == 2


# review findings: NVD


def test_nvd_asks_again_when_results_shrink_mid_read(ctx, fetcher, store):
    # Page 1 holds A, B. Before page 2, A is changed again and leaves the window, so
    # C moves up to index 1 and the second page (from index 2) starts at D.
    fetcher.add(
        "https://services.nvd.nist.gov/",
        [
            ok(_nvd_page(4, _nvd_cve("CVE-2026-0001"), _nvd_cve("CVE-2026-0002"))),
            ok(_nvd_page(3, _nvd_cve("CVE-2026-0004"))),
            ok(_nvd_page(3, _nvd_cve("CVE-2026-0003"), _nvd_cve("CVE-2026-0004"))),
        ],
    )
    assert run_one(ctx, Nvd()).ok
    assert [_query(c["url"])["startIndex"] for c in fetcher.calls] == ["0", "2", "1"]
    cves = [r[0] for r in store.db.execute("SELECT cve FROM nvd ORDER BY cve")]
    assert "CVE-2026-0003" in cves


def test_nvd_unreadable_entries_skip_alone(ctx, fetcher, store):
    fetcher.add(
        "https://services.nvd.nist.gov/",
        [
            ok(_nvd_page(3, _nvd_cve("CVE-2026-0001", "never"), {"id": "junk"})),
            ok(_nvd_page(3, _nvd_cve("CVE-2026-0003"))),
        ],
    )
    outcome = run_one(ctx, Nvd())
    assert outcome.ok and outcome.changed == 1
    assert [_query(c["url"])["startIndex"] for c in fetcher.calls] == ["0", "2"]


def test_nvd_treats_403_as_slow_down(ctx, fetcher):
    fetcher.add("https://services.nvd.nist.gov/", ok(_nvd_page(0)))
    run_one(ctx, Nvd())
    assert fetcher.calls[0]["also_retry"] == frozenset({403})


# review findings: OSV


def test_osv_cut_off_index_fails_without_moving(ctx, fetcher, store):
    cut = _osv_index(("2026-11-07T10:00:00Z", "ALSA-2026:2"), ("2026-11-07T09:00:00Z", "ALSA-2"))
    _osv_route(fetcher, "AlmaLinux", cut[:-3], {})
    outcome = run_one(ctx, Osv("AlmaLinux"))
    assert not outcome.ok and "cut off" in outcome.error
    assert store.state("osv-almalinux").position is None


def test_osv_index_etag_waits_until_every_record_is_read(ctx, fetcher, store):
    lines = [("2026-11-07T10:00:00Z", "ALSA-2026:1"), ("2026-11-07T11:00:00Z", "ALSA-2026:2")]
    base = f"{OSV_BASE}/AlmaLinux/"
    fetcher.add(base + "modified_id.csv", ok(_osv_index(*lines), headers={"etag": '"i"'}))
    fetcher.add(base + "ALSA-2026%3A1.json", ok(_osv_record("ALSA-2026:1", lines[0][0])))
    fetcher.add(base + "ALSA-2026%3A2.json", FetchError("HTTP 503", status=503))
    assert not run_one(ctx, Osv("AlmaLinux")).ok
    state = store.state("osv-almalinux")
    assert state.etag is None  # so the next run reads the index again, not "not modified"
    assert state.position.endswith("|ALSA-2026:1")


def test_osv_unreadable_record_is_kept_and_passed(ctx, fetcher, store):
    _osv_route(
        fetcher,
        "AlmaLinux",
        _osv_index(
            ("2026-11-07T10:00:00Z", "ALSA-2026:1"), ("2026-11-07T11:00:00Z", "ALSA-2026:2")
        ),
        {
            "ALSA-2026:1": {"id": "ALSA-2026:1", "modified": "whenever"},
            "ALSA-2026:2": _osv_record("ALSA-2026:2", "2026-11-07T11:00:00Z"),
        },
    )
    outcome = run_one(ctx, Osv("AlmaLinux"))
    assert outcome.ok and outcome.changed == 1
    assert store.state("osv-almalinux").position.endswith("|ALSA-2026:2")
    kept = store.db.execute("SELECT COUNT(*) FROM fetches WHERE body IS NOT NULL").fetchone()[0]
    assert kept == 2  # the unreadable one is kept as evidence


def test_osv_late_record_behind_the_position_is_read(ctx, fetcher, store, clock):
    base = f"{OSV_BASE}/AlmaLinux/"
    first = _osv_index(("2026-11-07T11:00:00Z", "ALSA-2026:2"))
    later = _osv_index(
        ("2026-11-07T11:00:00Z", "ALSA-2026:2"), ("2026-11-07T10:00:00Z", "ALSA-2026:1")
    )
    fetcher.add(base + "modified_id.csv", [ok(first), ok(later), ok(later)])
    fetcher.add(base + "ALSA-2026%3A2.json", ok(_osv_record("ALSA-2026:2", "2026-11-07T11:00:00Z")))
    fetcher.add(base + "ALSA-2026%3A1.json", ok(_osv_record("ALSA-2026:1", "2026-11-07T10:00:00Z")))
    ctx.since = clock() - dt.timedelta(hours=2)
    run_one(ctx, Osv("AlmaLinux"))
    clock.advance(hours=1)
    assert run_one(ctx, Osv("AlmaLinux")).changed == 1
    assert store.state("osv-almalinux").position.endswith("|ALSA-2026:2")  # not moved back
    clock.advance(hours=1)
    assert run_one(ctx, Osv("AlmaLinux")).changed == 0
    assert sum(c["url"].endswith("ALSA-2026%3A1.json") for c in fetcher.calls) == 1


def test_osv_failed_catch_up_falls_back_and_waits_a_day(ctx, fetcher, store, monkeypatch, clock):
    monkeypatch.setattr("drafter.feeds.osv.CATCH_UP_AFTER", 1)
    lines = [(f"2026-11-07T10:00:0{n}Z", f"ALSA-2026:{n}") for n in range(1, 4)]
    records = {i: _osv_record(i, t) for t, i in lines}
    base = f"{OSV_BASE}/AlmaLinux/"
    fetcher.add(base + "modified_id.csv", [ok(_osv_index(*lines)), ok(_osv_index(*lines))])
    for osv_id, record in records.items():
        fetcher.add(base + urllib.parse.quote(osv_id) + ".json", ok(record))
    ctx.limit = 1
    # no archive offered: the download fails (404)
    assert run_one(ctx, Osv("AlmaLinux")).ok
    assert store.state("osv-almalinux").position.endswith("|ALSA-2026:1")
    clock.advance(hours=1)
    run_one(ctx, Osv("AlmaLinux"))
    downloads = sum(1 for c in fetcher.calls if c.get("download"))
    assert downloads == 1  # not tried again within a day
    assert store.state("osv-almalinux").position.endswith("|ALSA-2026:2")


def test_osv_seed_skips_a_record_with_a_bad_time(ctx, fetcher, store, tmp_path):
    archive = _zip(
        tmp_path / "all.zip",
        [
            {"id": "ALSA-2026:1", "modified": "whenever"},
            _osv_record("ALSA-2026:2", "2026-11-06T00:00:00Z"),
        ],
    )
    fetcher.downloads[f"{OSV_BASE}/AlmaLinux/all.zip"] = archive
    _osv_route(fetcher, "AlmaLinux", _osv_index(("2026-11-06T00:00:00Z", "ALSA-2026:2")), {})
    kept = Osv("AlmaLinux").seed(ctx, dt.datetime(2026, 9, 1, tzinfo=dt.UTC), ctx.workdir)
    assert kept == 1


# Copilot round 1


def test_every_answer_is_recorded_even_when_it_fails(ctx, fetcher, store):
    fetcher.add(
        KEV_URL, [ok(b"<html>broken</html>"), FetchError("HTTP 500", status=500), NOT_MODIFIED]
    )
    for _ in range(3):
        run_one(ctx, Kev())
    rows = store.db.execute("SELECT status, body IS NOT NULL AS kept FROM fetches ORDER BY id")
    assert [tuple(r) for r in rows] == [(200, 1), (500, 0), (304, 0)]


def test_kev_broken_file_that_comes_back_unchanged_still_fails(ctx, fetcher, store):
    broken = ok(b"<html>broken</html>")
    fetcher.add(KEV_URL, [broken, broken])
    assert not run_one(ctx, Kev()).ok
    assert not run_one(ctx, Kev()).ok
    assert store.state("kev").failures == 2


def test_osv_withdrawn_record_is_not_queued_again(ctx, fetcher, store, clock):
    ctx.limit = 1
    lines = [("2026-11-07T10:00:00Z", "ALSA-2026:1"), ("2026-11-07T11:00:00Z", "ALSA-2026:2")]
    base = f"{OSV_BASE}/AlmaLinux/"
    fetcher.add(base + "modified_id.csv", [ok(_osv_index(*lines)), ok(_osv_index(*lines))])
    fetcher.add(base + "ALSA-2026%3A2.json", ok(_osv_record("ALSA-2026:2", lines[1][0])))
    run_one(ctx, Osv("AlmaLinux"))  # ALSA-2026:1 is withdrawn (404)
    clock.advance(hours=1)
    run_one(ctx, Osv("AlmaLinux"))
    assert store.state("osv-almalinux").position.endswith("|ALSA-2026:2")
    seen = dict(store.db.execute("SELECT id, outcome FROM osv_seen").fetchall())
    assert seen == {"ALSA-2026:1": "withdrawn", "ALSA-2026:2": "read"}


def test_osv_catch_up_fetches_what_the_archive_lacks(ctx, fetcher, store, monkeypatch, tmp_path):
    monkeypatch.setattr("drafter.feeds.osv.CATCH_UP_AFTER", 1)
    lines = [(f"2026-11-07T10:00:0{n}Z", f"ALSA-2026:{n}") for n in range(1, 4)]
    base = f"{OSV_BASE}/AlmaLinux/"
    fetcher.add(base + "modified_id.csv", ok(_osv_index(*lines)))
    fetcher.add(base + "ALSA-2026%3A2.json", ok(_osv_record("ALSA-2026:2", lines[1][0])))
    # the archive has 1 and 3 but not 2
    fetcher.downloads[base + "all.zip"] = _zip(
        tmp_path / "all.zip", [_osv_record(i, t) for t, i in (lines[0], lines[2])]
    )
    outcome = run_one(ctx, Osv("AlmaLinux"))
    assert outcome.ok and outcome.changed == 3
    record_fetches = [c["url"] for c in fetcher.calls if c["url"].endswith(".json")]
    assert record_fetches == [base + "ALSA-2026%3A2.json"]
    assert store.state("osv-almalinux").position.endswith("|ALSA-2026:3")


def test_osv_catch_up_covers_late_entries(ctx, fetcher, store, monkeypatch, tmp_path, clock):
    base = f"{OSV_BASE}/AlmaLinux/"
    fetcher.add(
        base + "modified_id.csv",
        [
            ok(_osv_index(("2026-11-07T11:00:00Z", "ALSA-2026:9"))),
            ok(
                _osv_index(
                    ("2026-11-07T11:00:00Z", "ALSA-2026:9"),
                    ("2026-11-07T10:30:00Z", "ALSA-2026:8"),  # late
                    ("2026-11-07T12:00:01Z", "ALSA-2026:10"),
                    ("2026-11-07T12:00:02Z", "ALSA-2026:11"),
                )
            ),
        ],
    )
    fetcher.add(base + "ALSA-2026%3A9.json", ok(_osv_record("ALSA-2026:9", "2026-11-07T11:00:00Z")))
    ctx.since = clock() - dt.timedelta(hours=2)
    run_one(ctx, Osv("AlmaLinux"))
    monkeypatch.setattr("drafter.feeds.osv.CATCH_UP_AFTER", 1)
    fetcher.downloads[base + "all.zip"] = _zip(
        tmp_path / "all.zip",
        [
            _osv_record("ALSA-2026:8", "2026-11-07T10:30:00Z"),
            _osv_record("ALSA-2026:10", "2026-11-07T12:00:01Z"),
            _osv_record("ALSA-2026:11", "2026-11-07T12:00:02Z"),
        ],
    )
    clock.advance(hours=1)
    assert run_one(ctx, Osv("AlmaLinux")).changed == 3
    assert "ALSA-2026:8" in dict(store.db.execute("SELECT id, outcome FROM osv_seen").fetchall())


def test_osv_older_archive_copy_does_not_replace_a_newer_record(ctx, fetcher, store, tmp_path):
    base = f"{OSV_BASE}/Ubuntu/"
    newer = _osv_record("UBUNTU-CVE-2026-0001", "2026-11-07T10:00:00Z", priority="critical")
    _osv_route(
        fetcher,
        "Ubuntu",
        _osv_index(("2026-11-07T10:00:00Z", "UBUNTU-CVE-2026-0001")),
        {"UBUNTU-CVE-2026-0001": newer},
    )
    run_one(ctx, Osv("Ubuntu"))
    older = _osv_record("UBUNTU-CVE-2026-0001", "2026-11-01T10:00:00Z", priority="low")
    fetcher.downloads[base + "all.zip"] = _zip(tmp_path / "all.zip", [older])
    Osv("Ubuntu").seed(ctx, dt.datetime(2026, 10, 1, tzinfo=dt.UTC), ctx.workdir)
    row = store.db.execute("SELECT modified, ubuntu_priority FROM osv").fetchone()
    assert tuple(row) == ("2026-11-07T10:00:00.000000Z", "critical")


def test_osv_odd_severity_is_ignored_not_a_crash():
    record = {"id": "UBUNTU-CVE-2026-0001", "modified": "2026-11-07T10:00:00Z", "severity": 1}
    from drafter.feeds.osv import parse_record

    assert parse_record(json.dumps(record).encode(), "Ubuntu")["ubuntu_priority"] is None


def test_seed_counts_in_the_feed_status(ctx, fetcher, store, tmp_path):
    base = f"{OSV_BASE}/AlmaLinux/"
    _osv_route(fetcher, "AlmaLinux", _osv_index(("2026-11-06T00:00:00Z", "ALSA-2026:3")), {})
    fetcher.downloads[base + "all.zip"] = _zip(
        tmp_path / "all.zip", [_osv_record("ALSA-2026:3", "2026-11-06T00:00:00Z")]
    )
    assert seed_feed(ctx, Osv("AlmaLinux"), dt.datetime(2026, 9, 1, tzinfo=dt.UTC), ctx.workdir).ok
    state = store.state("osv-almalinux")
    assert state.last_success and state.position.endswith("|ALSA-2026:3")
    assert state.floor == "2026-09-01T00:00:00.000000Z"  # kept for later runs


# Copilot round 2


def test_osv_entry_far_behind_the_position_is_still_read(ctx, fetcher, store, clock):
    base = f"{OSV_BASE}/AlmaLinux/"
    ctx.since = clock() - dt.timedelta(days=10)
    newest = ("2026-11-07T11:00:00Z", "ALSA-2026:9")
    behind = ("2026-11-02T10:00:00Z", "ALSA-2026:1")  # five days behind, listed late
    fetcher.add(base + "modified_id.csv", [ok(_osv_index(newest)), ok(_osv_index(newest, behind))])
    fetcher.add(base + "ALSA-2026%3A9.json", ok(_osv_record("ALSA-2026:9", newest[0])))
    fetcher.add(base + "ALSA-2026%3A1.json", ok(_osv_record("ALSA-2026:1", behind[0])))
    run_one(ctx, Osv("AlmaLinux"))
    clock.advance(hours=1)
    assert run_one(ctx, Osv("AlmaLinux")).changed == 1
    assert store.state("osv-almalinux").position.endswith("|ALSA-2026:9")


def test_osv_newer_version_already_handled_counts_as_covered(ctx, fetcher, store, tmp_path):
    base = f"{OSV_BASE}/AlmaLinux/"
    # the archive is newer than the index it came with
    fetcher.add(
        base + "modified_id.csv", [ok(_osv_index(("2026-11-07T10:00:00Z", "ALSA-2026:1")))] * 2
    )
    fetcher.downloads[base + "all.zip"] = _zip(
        tmp_path / "all.zip", [_osv_record("ALSA-2026:1", "2026-11-07T11:00:00Z")]
    )
    Osv("AlmaLinux").seed(ctx, dt.datetime(2026, 11, 1, tzinfo=dt.UTC), ctx.workdir)
    assert store.state("osv-almalinux").position.endswith("|ALSA-2026:1")
    assert run_one(ctx, Osv("AlmaLinux")).ok
    assert not any(c["url"].endswith(".json") for c in fetcher.calls)


def test_nvd_odd_ssvc_shapes_are_ignored(ctx, fetcher, store):
    odd1 = {
        "id": "CVE-2026-0001",
        "lastModified": "2026-11-07T10:00:00",
        "metrics": {"ssvcV203": 1},
    }
    odd2 = {
        "id": "CVE-2026-0002",
        "lastModified": "2026-11-07T10:00:00",
        "metrics": {"ssvcV203": [{"ssvcData": {"options": 1}}]},
    }
    fetcher.add("https://services.nvd.nist.gov/", ok(_nvd_page(2, odd1, odd2)))
    outcome = run_one(ctx, Nvd())
    assert outcome.ok and outcome.changed == 2


def test_redhat_odd_package_list_is_treated_as_none(ctx, fetcher, store):
    fetcher.add(
        "https://access.redhat.com/",
        ok([{"CVE": "CVE-2026-0001", "severity": "critical", "affected_packages": 1}]),
    )
    assert run_one(ctx, RedHatCritical()).changed == 1
    assert store.db.execute("SELECT packages FROM redhat_critical").fetchone()[0] == "[]"


def test_usn_odd_cve_list_is_treated_as_none(ctx, fetcher, store):
    notice = {"id": "USN-9003-1", "published": "2026-11-07T10:00:00", "cves_ids": 1}
    fetcher.add("https://ubuntu.com/security/notices.json", ok(_usn_page(1, notice)))
    assert run_one(ctx, Usn()).changed == 1
