"""Times, the address list, fetching and the store."""

from __future__ import annotations

import io
import sqlite3
import urllib.error
import urllib.request
from email.message import Message

import pytest

from drafter import timeutil
from drafter.http import Fetcher, FetchError, Refused, _AllowedRedirects, check_url
from drafter.store import SCHEMA_VERSION, Store, StoreError

# times


@pytest.mark.parametrize(
    "text, expected",
    [
        ("2026-11-07T01:58:36.964727875Z", "2026-11-07T01:58:36.964727Z"),  # OSV: nanoseconds
        ("2026-11-06T15:04:17.460907", "2026-11-06T15:04:17.460907Z"),  # Ubuntu: no zone
        ("2026-11-07T15:49:15+00:00", "2026-11-07T15:49:15.000000Z"),  # Red Hat
        ("2026-11-07T10:00:00-0700", "2026-11-07T17:00:00.000000Z"),
        ("2026-10-26", "2026-10-26T00:00:00.000000Z"),
        ("2026-11-07T10:15", "2026-11-07T10:15:00.000000Z"),
    ],
)
def test_times_read_from_each_feed(text, expected):
    assert timeutil.norm(text) == expected


@pytest.mark.parametrize("text", ["", "yesterday", "2026-13-01", "2026-11-07T25:00:00Z", 7])
def test_unreadable_times_refused(text):
    with pytest.raises(timeutil.TimeError):
        timeutil.parse(text)


def test_stored_times_sort_as_text():
    whole = timeutil.norm("2026-11-07T10:00:05Z")
    later = timeutil.norm("2026-11-07T10:00:05.1Z")
    assert whole < later


# the address list


@pytest.mark.parametrize(
    "url",
    [
        "http://www.cisa.gov/feed.json",
        "https://evil.example/feed.json",
        "https://www.cisa.gov.evil.example/feed.json",
        "https://www.cisa.gov:8443/feed.json",
        "https://user:pw@www.cisa.gov/feed.json",
        "file:///etc/passwd",
    ],
)
def test_addresses_off_the_list_refused(url):
    with pytest.raises(Refused):
        check_url(url)


def test_redirect_off_the_list_refused():
    handler = _AllowedRedirects()
    request = urllib.request.Request("https://www.cisa.gov/a")
    with pytest.raises(Refused):
        handler.redirect_request(request, None, 302, "Found", Message(), "https://evil.example/")


class _Answer(io.BytesIO):
    def __init__(self, body, status=200, url="https://www.cisa.gov/a", headers=None):
        super().__init__(body)
        self.status = status
        self._url = url
        msg = Message()
        for key, value in (headers or {}).items():
            msg[key] = value
        self.headers = msg

    def geturl(self):
        return self._url


class _Opener:
    def __init__(self, answers):
        self.answers = list(answers)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def _http_error(code, body=b"secret server text"):
    return urllib.error.HTTPError("https://www.cisa.gov/a", code, "x", Message(), io.BytesIO(body))


def test_not_modified_is_an_answer_not_an_error():
    fetcher = Fetcher(opener=_Opener([_http_error(304)]))
    answer = fetcher.get("https://www.cisa.gov/a", etag='"abc"')
    assert answer.not_modified


def test_conditional_headers_sent():
    opener = _Opener([_Answer(b"{}")])
    Fetcher(opener=opener).get("https://www.cisa.gov/a", etag='"e"', last_modified="Fri")
    request = opener.requests[0]
    assert request.get_header("If-none-match") == '"e"'
    assert request.get_header("If-modified-since") == "Fri"
    assert request.get_header("User-agent").startswith("compromise-checker-pack-drafter/")


def test_size_cap():
    fetcher = Fetcher(opener=_Opener([_Answer(b"x" * 101)]))
    with pytest.raises(FetchError, match="larger than 100"):
        fetcher.get("https://www.cisa.gov/a", max_bytes=100)


def test_passing_trouble_retried_with_growing_waits():
    sleeps = []
    opener = _Opener([_http_error(503), _http_error(429), _Answer(b"ok")])
    answer = Fetcher(opener=opener, sleep=sleeps.append).get("https://www.cisa.gov/a")
    assert answer.body == b"ok"
    assert sleeps == [5.0, 15.0]


def test_lasting_trouble_not_retried_and_server_text_not_echoed():
    opener = _Opener([_http_error(404)])
    with pytest.raises(FetchError) as caught:
        Fetcher(opener=opener, sleep=lambda s: None).get("https://www.cisa.gov/a")
    assert caught.value.status == 404
    assert "secret" not in str(caught.value)
    assert opener.answers == []


def test_network_trouble_retried_then_reported():
    error = urllib.error.URLError(TimeoutError("timed out"))
    opener = _Opener([error, error, error])
    with pytest.raises(FetchError, match="network: TimeoutError"):
        Fetcher(opener=opener, sleep=lambda s: None).get("https://www.cisa.gov/a")


def test_final_address_checked_after_redirects():
    opener = _Opener([_Answer(b"x", url="https://evil.example/")])
    with pytest.raises(Refused):
        Fetcher(opener=opener).get("https://www.cisa.gov/a")


def test_refused_address_never_opened():
    opener = _Opener([])
    with pytest.raises(Refused):
        Fetcher(opener=opener).get("https://evil.example/")
    assert opener.requests == []


def test_download_streams_with_cap(tmp_path):
    fetcher = Fetcher(opener=_Opener([_Answer(b"a" * 10)]))
    sha, size = fetcher.download("https://www.cisa.gov/a", tmp_path / "f", max_bytes=100)
    assert size == 10 and len(sha) == 64
    fetcher = Fetcher(opener=_Opener([_Answer(b"a" * 10)]))
    with pytest.raises(FetchError, match="larger"):
        fetcher.download("https://www.cisa.gov/a", tmp_path / "g", max_bytes=5)


# the store


def test_identical_bodies_stored_once(store):
    first = store.record_fetch(feed="f", url="u", fetched_at="t", status=200, body=b"same")
    second = store.record_fetch(feed="f", url="u", fetched_at="t2", status=200, body=b"same")
    rows = store.db.execute("SELECT id, body IS NOT NULL AS has, same_as FROM fetches").fetchall()
    assert [tuple(r) for r in rows] == [(first, 1, None), (second, 0, first)]
    assert store.fetch_body(second) == b"same"


def test_hash_kept_without_body(store):
    fetch_id = store.record_fetch(
        feed="f", url="u", fetched_at="t", status=200, body=b"big index", keep_body=False
    )
    row = store.db.execute("SELECT sha256, size, body FROM fetches WHERE id = ?", (fetch_id,))
    sha, size, body = row.fetchone()
    assert len(sha) == 64 and size == 9 and body is None
    assert store.fetch_body(fetch_id) is None


def test_upsert_reports_only_real_changes(store):
    fid = store.record_fetch(feed="kev", url="u", fetched_at="t", status=200, body=b"x")
    row = {
        "cve": "CVE-2026-1234",
        "date_added": "2026-11-01",
        "vendor": "V",
        "product": "P",
        "name": "N",
        "fetch_id": fid,
    }
    assert store.upsert("kev", row, ("cve",)) is True
    fid2 = store.record_fetch(feed="kev", url="u", fetched_at="t2", status=200, body=b"y")
    assert store.upsert("kev", {**row, "fetch_id": fid2}, ("cve",)) is False
    assert store.upsert("kev", {**row, "name": "M", "fetch_id": fid2}, ("cve",)) is True


def test_upsert_only_known_tables(store):
    with pytest.raises(StoreError):
        store.upsert("fetches; DROP TABLE kev", {"a": 1}, ("a",))


def test_newer_schema_refused(tmp_path):
    path = tmp_path / "d.sqlite3"
    db = sqlite3.connect(path)
    db.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    db.close()
    with pytest.raises(StoreError, match="schema"):
        Store(path)


def test_reopening_keeps_data(tmp_path):
    path = tmp_path / "d.sqlite3"
    s = Store(path)
    s.record_fetch(feed="f", url="u", fetched_at="t", status=200, body=b"x")
    s.close()
    s = Store(path)
    assert s.db.execute("SELECT COUNT(*) FROM fetches").fetchone()[0] == 1
    s.close()


def test_signalled(store):
    fid = store.record_fetch(feed="nvd", url="u", fetched_at="t", status=200, body=b"x")
    store.upsert(
        "nvd",
        {
            "cve": "CVE-2026-0001",
            "last_modified": "t",
            "exploitation": "active",
            "ssvc_time": None,
            "kev_added": None,
            "fetch_id": fid,
        },
        ("cve",),
    )
    store.upsert(
        "nvd",
        {
            "cve": "CVE-2026-0002",
            "last_modified": "t",
            "exploitation": "poc",
            "ssvc_time": None,
            "kev_added": None,
            "fetch_id": fid,
        },
        ("cve",),
    )
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
    assert store.signalled(["CVE-2026-0001"])
    assert not store.signalled(["CVE-2026-0002"])
    assert store.signalled(["CVE-2026-0009", "CVE-2026-0003"])
    assert not store.signalled([])


def test_transaction_rolls_back(store):
    with pytest.raises(RuntimeError), store.transaction():
        store.record_fetch(feed="f", url="u", fetched_at="t", status=200, body=b"x")
        raise RuntimeError
    assert store.db.execute("SELECT COUNT(*) FROM fetches").fetchone()[0] == 0


def test_cut_off_answer_is_an_error_and_retried():
    sleeps = []
    short = _Answer(b"x" * 50, headers={"Content-Length": "100"})
    whole = _Answer(b"x" * 100, headers={"Content-Length": "100"})
    answer = Fetcher(opener=_Opener([short, whole]), sleep=sleeps.append).get(
        "https://www.cisa.gov/a"
    )
    assert len(answer.body) == 100 and sleeps == [5.0]


def test_cut_off_download_is_an_error(tmp_path):
    short = _Answer(b"x" * 50, headers={"Content-Length": "100"})
    with pytest.raises(FetchError, match="cut off"):
        Fetcher(opener=_Opener([short])).download(
            "https://www.cisa.gov/a", tmp_path / "f", max_bytes=1000
        )


def test_extra_slow_down_statuses_retried_with_their_own_wait():
    sleeps = []
    opener = _Opener([_http_error(403), _Answer(b"ok")])
    fetcher = Fetcher(opener=opener, sleep=sleeps.append)
    assert (
        fetcher.get(
            "https://services.nvd.nist.gov/x", also_retry=frozenset({403}), first_delay=35.0
        ).body
        == b"ok"
    )
    assert sleeps == [35.0]
    with pytest.raises(FetchError):
        Fetcher(opener=_Opener([_http_error(403)])).get("https://services.nvd.nist.gov/x")


def test_api_key_not_carried_across_a_redirect():
    handler = _AllowedRedirects()
    request = urllib.request.Request(
        "https://services.nvd.nist.gov/a", headers={"apiKey": "k-1", "Accept": "*/*"}
    )
    new = handler.redirect_request(request, None, 302, "Found", Message(), "https://www.cisa.gov/b")
    assert "k-1" not in str(new.header_items())
    assert new.get_header("Accept") == "*/*"


def test_time_errors_hold_no_feed_text():
    with pytest.raises(timeutil.TimeError) as caught:
        timeutil.parse("<script>evil</script>")
    assert "evil" not in str(caught.value)
