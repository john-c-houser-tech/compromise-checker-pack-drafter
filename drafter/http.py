"""Fetching from the fixed list of feed hosts.

HTTPS only, to the hosts below only (redirects included), with a size cap on
every answer. A feed's text is untrusted: nothing here echoes it into errors.
"""

from __future__ import annotations

import hashlib
import http.client
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

from drafter import __version__

# Every address the drafter reads lives on one of these hosts (docs/feeds.md).
ALLOWED_HOSTS = frozenset(
    {
        "www.cisa.gov",
        "services.nvd.nist.gov",
        "osv-vulnerabilities.storage.googleapis.com",
        "ubuntu.com",
        "access.redhat.com",
        "security.access.redhat.com",  # Red Hat's CSAF advisories (A.3)
        "api.launchpad.net",  # Sury's PPA publishing history (A.3b)
        "launchpad.net",  # Launchpad's file links, which redirect to its librarian
        "launchpadlibrarian.net",  # Sury's .changes files
        "rpms.remirepo.net",  # Remi's repository metadata (A.3b)
        "api.github.com",  # GitHub's security advisories, linked from the sources (B.1)
    }
)

USER_AGENT = f"compromise-checker-pack-drafter/{__version__}"
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
SECRET_HEADERS = frozenset({"apikey"})


class FetchError(Exception):
    """A fetch failed. The message never holds the feed's own text or a key."""

    def __init__(self, message: str, *, status: int | None = None, network: bool = False):
        super().__init__(message)
        self.status = status
        self.network = network


class Refused(FetchError):
    """The address isn't one the drafter may read. Never retried."""


@dataclass(frozen=True)
class Response:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def not_modified(self) -> bool:
        return self.status == 304


def check_url(url: str) -> str:
    """Refuse anything but https to an allowed host, on the default port."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise Refused("refused: not https")
    if parts.hostname not in ALLOWED_HOSTS or parts.port not in (None, 443):
        raise Refused("refused: host not on the feed list")
    if parts.username or parts.password:
        raise Refused("refused: address carries a login")
    return url


class _AllowedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(urllib.parse.urljoin(req.full_url, newurl))
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            # An API key is for the host it was sent to; never carry it along.
            for name in [h for h in new.headers if h.lower() in SECRET_HEADERS]:
                del new.headers[name]
        return new


def _opener() -> urllib.request.OpenerDirector:
    # build_opener would add plain-http and file handlers; only https is wanted.
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _AllowedRedirects(),
        urllib.request.HTTPErrorProcessor(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.UnknownHandler(),
    ):
        opener.add_handler(handler)
    return opener


class Fetcher:
    """GET with conditional headers, retries for passing trouble, and a size cap."""

    def __init__(
        self,
        *,
        opener: urllib.request.OpenerDirector | None = None,
        timeout: float = 60.0,
        attempts: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self._opener = opener or _opener()
        self._timeout = timeout
        self._attempts = attempts
        self._sleep = sleep

    def get(
        self,
        url: str,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
        headers: dict[str, str] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        also_retry: frozenset[int] = frozenset(),
        first_delay: float = 5.0,
    ) -> Response:
        """`also_retry`: statuses that mean "slow down" for this host (NVD's 403)."""
        check_url(url)
        sent = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if etag:
            sent["If-None-Match"] = etag
        if last_modified:
            sent["If-Modified-Since"] = last_modified
        sent.update(headers or {})
        delay = first_delay
        for attempt in range(1, self._attempts + 1):
            try:
                return self._once(url, sent, max_bytes)
            except Refused:
                raise
            except FetchError as exc:
                passing = exc.status in RETRY_STATUSES | also_retry or exc.network
                if not passing or attempt == self._attempts:
                    raise
            self._sleep(delay)
            delay *= 3
        raise AssertionError("unreachable")

    def _once(self, url: str, sent: dict[str, str], max_bytes: int) -> Response:
        request = urllib.request.Request(url, headers=sent, method="GET")  # noqa: S310 - https only, checked
        try:
            with self._opener.open(request, timeout=self._timeout) as answer:
                body = answer.read(max_bytes + 1)
                status = answer.status
                got = {k.lower(): v for k, v in answer.headers.items()}
                final = answer.geturl()
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                return Response(url=url, status=304)
            raise FetchError(f"HTTP {exc.code}", status=exc.code) from None
        except FetchError:
            raise
        except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise FetchError(f"network: {type(reason).__name__}", network=True) from None
        if len(body) > max_bytes:
            raise FetchError(f"answer larger than {max_bytes} bytes", status=status)
        _check_complete(got, len(body))
        check_url(final)
        return Response(url=final, status=status, headers=got, body=body)

    def download(self, url: str, dest, *, max_bytes: int) -> tuple[str, int]:
        """Stream a large answer (a seed archive) into `dest`: (sha256, size).

        One attempt; the caller removes `dest` if this raises.
        """
        check_url(url)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310 - https only, checked
        digest = hashlib.sha256()
        size = 0
        try:
            with (
                self._opener.open(request, timeout=self._timeout) as answer,
                open(dest, "wb") as out,
            ):
                check_url(answer.geturl())
                while chunk := answer.read(1024 * 1024):
                    size += len(chunk)
                    if size > max_bytes:
                        raise FetchError(f"answer larger than {max_bytes} bytes")
                    digest.update(chunk)
                    out.write(chunk)
                _check_complete({k.lower(): v for k, v in answer.headers.items()}, size)
        except urllib.error.HTTPError as exc:
            raise FetchError(f"HTTP {exc.code}", status=exc.code) from None
        except FetchError:
            raise
        except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise FetchError(f"network: {type(reason).__name__}", network=True) from None
        return digest.hexdigest(), size


def _check_complete(headers: dict[str, str], size: int) -> None:
    """A dropped connection gives a short body and no error: catch it by length."""
    declared = headers.get("content-length")
    if declared is None or headers.get("content-encoding"):
        return
    try:
        expected = int(declared)
    except ValueError:
        raise FetchError("answer has an unreadable length", network=True) from None
    if size != expected:
        raise FetchError(f"answer cut off ({size} of {expected} bytes)", network=True)
