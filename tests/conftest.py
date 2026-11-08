"""Shared test helpers: a fetcher that never touches the network, and a fixed clock."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from drafter.feeds import Context
from drafter.http import FetchError, Response, check_url
from drafter.store import Store

NOW = dt.datetime(2026, 11, 7, 12, 0, tzinfo=dt.UTC)


class FakeFetcher:
    """Answers from a list of (match, answer) routes. `match` is a prefix or a callable.

    An answer is a Response, an exception to raise, or a list used up in order.
    """

    def __init__(self):
        self.routes: list[tuple[str | Callable[[str], bool], object]] = []
        self.calls: list[dict] = []
        self.downloads: dict[str, Path] = {}

    def add(self, match, answer) -> None:
        self.routes.append((match, answer))

    def get(
        self,
        url,
        *,
        etag=None,
        last_modified=None,
        headers=None,
        max_bytes=0,
        also_retry=frozenset(),
        first_delay=5.0,
    ):
        check_url(url)
        self.calls.append(
            {
                "url": url,
                "etag": etag,
                "last_modified": last_modified,
                "headers": dict(headers or {}),
                "also_retry": also_retry,
            }
        )
        for match, answer in self.routes:
            hit = match(url) if callable(match) else url.startswith(match)
            if not hit:
                continue
            if isinstance(answer, list):
                if not answer:
                    raise AssertionError(f"no more answers for {url}")
                answer = answer.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer
        raise FetchError("HTTP 404", status=404)

    def download(self, url, dest, *, max_bytes):
        check_url(url)
        self.calls.append({"url": url, "download": True})
        source = self.downloads.get(url)
        if source is None:
            raise FetchError("HTTP 404", status=404)
        shutil.copyfile(source, dest)
        data = Path(dest).read_bytes()
        return hashlib.sha256(data).hexdigest(), len(data)


def ok(body, *, url="https://www.cisa.gov/x", headers=None, status=200) -> Response:
    if not isinstance(body, bytes):
        body = json.dumps(body).encode()
    return Response(url=url, status=status, headers=headers or {}, body=body)


NOT_MODIFIED = Response(url="https://www.cisa.gov/x", status=304)


class Clock:
    def __init__(self, start: dt.datetime = NOW):
        self.value = start

    def __call__(self) -> dt.datetime:
        return self.value

    def advance(self, **kwargs) -> None:
        self.value += dt.timedelta(**kwargs)


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "drafter.sqlite3")
    yield s
    s.close()


@pytest.fixture
def fetcher():
    return FakeFetcher()


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def sleeps():
    return []


@pytest.fixture
def ctx(store, fetcher, clock, sleeps, tmp_path):
    return Context(
        store=store,
        fetcher=fetcher,
        now=clock,
        sleep=sleeps.append,
        workdir=tmp_path / "work",
    )
