"""Running feeds, their status, and the command line."""

from __future__ import annotations

import fcntl

import pytest

from drafter import cli
from drafter.feeds import Feed, all_feeds, run_feeds, run_one
from drafter.feeds.kev import URL as KEV_URL
from drafter.feeds.kev import Kev
from drafter.http import FetchError
from drafter.status import report
from tests.conftest import ok


class _Broken(Feed):
    name = "broken"
    title = "Broken"

    def run(self, ctx, state):
        raise KeyError("bug")


def test_one_failing_feed_does_not_stop_the_others(ctx, fetcher, store):
    fetcher.add(KEV_URL, FetchError("HTTP 503", status=503))
    outcomes = run_feeds(ctx, [Kev(), _Broken()])
    assert [(o.feed, o.ok) for o in outcomes] == [("kev", False), ("broken", False)]
    assert outcomes[1].error == "internal error: KeyError"
    assert store.state("kev").failures == 1


def test_failures_count_up_and_clear(ctx, fetcher, store):
    fetcher.add(
        KEV_URL,
        [
            FetchError("HTTP 503", status=503),
            FetchError("HTTP 503", status=503),
            ok({"vulnerabilities": [{"cveID": "CVE-2026-1234", "dateAdded": "2026-11-01"}]}),
        ],
    )
    run_one(ctx, Kev())
    run_one(ctx, Kev())
    assert store.state("kev").failures == 2
    assert store.state("kev").last_error == "HTTP 503"
    run_one(ctx, Kev())
    state = store.state("kev")
    assert (state.failures, state.last_error) == (0, None)


def test_feed_names_are_unique_and_fixed():
    names = [f.name for f in all_feeds()]
    assert names == ["kev", "nvd", "osv-ubuntu", "osv-almalinux", "osv-rockylinux", "usn", "redhat"]


# status


def _states(store, now):
    return {r.feed: r.state for r in report(store, [Kev()], now)}


def test_status_never_ok_quiet_behind_failing(ctx, fetcher, store, clock):
    now = clock()
    assert _states(store, now) == {"kev": "never"}
    body = {"vulnerabilities": [{"cveID": "CVE-2026-1234", "dateAdded": "2026-11-01"}]}
    fetcher.add(KEV_URL, [ok(body), ok(body), ok(body), FetchError("HTTP 500", status=500)])
    run_one(ctx, Kev())
    assert _states(store, clock()) == {"kev": "ok"}
    clock.advance(days=15)  # read fine, nothing new for longer than usual
    run_one(ctx, Kev())
    assert _states(store, clock()) == {"kev": "quiet"}
    clock.advance(days=2)  # laptop shut
    assert _states(store, clock()) == {"kev": "behind"}
    run_one(ctx, Kev())
    run_one(ctx, Kev())
    reports = report(store, [Kev()], clock())
    assert reports[0].state == "failing" and "HTTP 500" in reports[0].detail


# the command line


def test_safe_strips_control_and_bidi_characters():
    hostile = "ok" + chr(0x1B) + "[31m" + chr(0x202E) + "evil" + chr(0x0A)
    assert cli.safe(hostile) == "ok?[31m?evil?"


def test_cli_unknown_feed(tmp_path, capsys):
    assert cli.main(["--home", str(tmp_path), "feeds", "fetch", "nope"]) == 2
    assert "unknown feed" in capsys.readouterr().err


def test_cli_seed_only_for_osv(tmp_path, capsys):
    assert cli.main(["--home", str(tmp_path), "feeds", "seed", "kev", "--since", "2026-05-01"]) == 2


def test_cli_status_before_any_run(tmp_path, capsys):
    home = tmp_path / "home"
    assert cli.main(["--home", str(home), "feeds", "status"]) == 1
    out = capsys.readouterr().out
    assert out.count("never read") == 8  # seven feeds and the vendor records
    assert (home / "drafter.sqlite3").exists()
    assert home.stat().st_mode & 0o777 == 0o700


def test_cli_second_run_waits_for_the_lock(tmp_path, capsys):
    with open(tmp_path / "lock", "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        assert cli.main(["--home", str(tmp_path), "feeds", "fetch", "kev"]) == 3
        # status only reads, so it still answers while a long seed holds the lock
        assert cli.main(["--home", str(tmp_path), "feeds", "status"]) == 1


def test_cli_bad_date(tmp_path):
    with pytest.raises(SystemExit):
        cli.main(["--home", str(tmp_path), "feeds", "fetch", "--since", "yesterday"])


def test_default_home(monkeypatch, tmp_path):
    monkeypatch.setenv("DRAFTER_HOME", str(tmp_path / "h"))
    assert cli.default_home() == tmp_path / "h"
    monkeypatch.delenv("DRAFTER_HOME")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "x"))
    assert cli.default_home() == tmp_path / "x" / "pack-drafter"
