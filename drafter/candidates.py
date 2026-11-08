"""A.2: which exploited threats touch packages Compromise Checker can judge.

A CVE is signalled (plan D3) when it is on CISA's list, rated "exploitation:
active" by CISA in NVD, rated critical by Ubuntu or Critical by Red Hat, or added
by hand. For each signalled CVE the drafter fetches Ubuntu's OSV record and Red
Hat's record once, and keeps them. A candidate is then sorted:

- judge: a package on a supported release (Ubuntu 22.04 and later, RHEL 9 and 10,
  which covers Rocky Linux and AlmaLinux) that isn't set aside;
- kernel: only kernels, which the tool can't judge until its Phase 6 (D2);
- set aside: only packages or products named in `setaside.toml`, with its reason;
- elsewhere: no package on a supported release (counted, not listed).

CVEs that hit the same package family within 14 days are one threat.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
import re
import tomllib
from dataclasses import dataclass, field
from importlib import resources

from drafter import timeutil
from drafter.feeds import CVE_ID, Context, Feed, FeedError
from drafter.http import FetchError, Refused
from drafter.store import Store

UBUNTU_URL = "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/UBUNTU-{cve}.json"
REDHAT_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"
MAX_BYTES = 32 * 1024 * 1024
GROUP_WITHIN = dt.timedelta(days=14)
RECENT = dt.timedelta(days=30)  # signalled this recently: vendor records re-read daily
STOP_AFTER_FAILURES = 20

SIGNAL_NAMES = {
    "kev": "on CISA's list",
    "nvd": "CISA rates exploitation active (NVD)",
    "ubuntu": "Ubuntu priority critical",
    "redhat": "Red Hat severity Critical",
    "manual": "added by hand",
}

_UBUNTU_RELEASE = re.compile(r"\AUbuntu:(\d{2})\.(\d{2})(?::LTS)?\Z")
_RH_CPE = re.compile(r"\Acpe:/[aoh]:redhat:([a-z0-9_]+)(?::([0-9][0-9.]*))?(?::.*)?\Z")
_RH_BASE = re.compile(r"\A(enterprise_linux(_eus)?|rhel_(eus|aus|e4s|tus|els|extras))\Z")
_RH_EL = re.compile(r"(?:::|\.)el(\d{1,2})")
_PACKAGE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._+-]{0,120}\Z")
# Red Hat's package_state values meaning "affected, no fixed build yet".
VENDOR_SIGNALS = ("ubuntu", "redhat")  # signal kinds that are a vendor's own rating
# Signs that someone is attacking it (A.4b): CISA's list, CISA's "active", or a
# person adding it by hand. A sign of these that comes after a reject brings it back.
ATTACK_SIGNALS = ("kev", "nvd", "manual")
_RH_UNFIXED = {"affected", "fix deferred", "will not fix", "under investigation"}


# set-asides


@dataclass(frozen=True)
class SetAside:
    kind: str  # package, product
    pattern: str
    reason: str


def load_setaside(text: str | None = None) -> list[SetAside]:
    if text is None:
        text = resources.files("drafter").joinpath("setaside.toml").read_text("utf-8")
    data = tomllib.loads(text)
    out = []
    for kind, key in (("package", "name"), ("product", "cpe")):
        for item in data.get(kind, []):
            pattern, reason = item.get(key), item.get("reason")
            if not isinstance(pattern, str) or not isinstance(reason, str) or not reason.strip():
                raise ValueError(f"setaside.toml: each [[{kind}]] needs {key} and a reason")
            out.append(SetAside(kind, pattern, reason.strip()))
    return out


def _set_aside(package: dict, rules: list[SetAside]) -> str | None:
    for rule in rules:
        if rule.kind == "package" and fnmatch.fnmatchcase(package["package"], rule.pattern):
            return rule.reason
        product = package.get("product")
        if rule.kind == "product" and product and fnmatch.fnmatchcase(product, rule.pattern):
            return rule.reason
    return None


# the third-party watch list


@dataclass(frozen=True)
class Watch:
    cpe: str  # vendor:product glob, as NVD names products
    repositories: tuple[str, ...]
    words: tuple[str, ...] = ()  # in NVD's description, before it names products

    def word_match(self, text: str) -> bool:
        # Whole words with their case; digits may follow (PHP8.4, PHP2Shell), letters
        # may not (PHPUnit), and a dot may not come before (upload.php).
        return any(
            re.search(rf"(?<![\w.]){re.escape(word)}(?![A-Za-z_])", text) for word in self.words
        )


def load_watch(text: str | None = None) -> list[Watch]:
    if text is None:
        text = resources.files("drafter").joinpath("thirdparty.toml").read_text("utf-8")
    out = []
    for item in tomllib.loads(text).get("watch", []):
        cpe, repos = item.get("cpe"), item.get("repositories")
        if not isinstance(cpe, str) or ":" not in cpe:
            raise ValueError("thirdparty.toml: each [[watch]] needs a cpe like php:php")
        if not isinstance(repos, list) or not repos or not all(isinstance(r, str) for r in repos):
            raise ValueError("thirdparty.toml: each [[watch]] needs its repositories")
        words = item.get("words", [])
        if not isinstance(words, list) or not all(isinstance(w, str) and w for w in words):
            raise ValueError("thirdparty.toml: words is a list of words")
        out.append(Watch(cpe.lower(), tuple(repos), tuple(words)))
    return out


def _watched(
    products: list[str], text: str | None, watch: list[Watch], kev_text: str | None = None
) -> tuple[list[str], list[str], list[str]]:
    """(watched products, repositories rebuilding them), from NVD's product names
    and, side by side, its description's words. NVD's names can be missing for days,
    or wrong: for PHP2Shell it named Palo Alto's PAN-OS, not php:php. A match on
    words alone is marked, so a person can tell it from a named product.

    Returns (watched names, how each was matched, repositories). The names are the
    watch list's own (php:php), so CVEs matched different ways still group."""
    matched, how, repos = set(), [], []
    for w in watch:
        if any(fnmatch.fnmatchcase(p, w.cpe) for p in products):
            via = None
        elif kev_text and w.word_match(kev_text):
            # CISA's own names ("PHP Group", "PHP"), there from the day it lists a CVE
            via = f"CISA's list names {kev_text}"
        elif text and w.word_match(text):
            via = f"NVD's description mentions {', '.join(w.words)}"
        else:
            continue
        matched.add(w.cpe)
        if via and via not in how:
            how.append(via)
        repos += [r for r in w.repositories if r not in repos]
    return sorted(matched), how, repos


# signals


@dataclass(frozen=True)
class Signal:
    kind: str
    when: str  # stored time form
    note: str = ""  # a person's note, for signs added by hand

    def describe(self) -> str:
        text = f"{SIGNAL_NAMES[self.kind]} {self.when[:10]}"
        return f"{text} ({self.note})" if self.note else text


def signals(store: Store, since: str) -> dict[str, list[Signal]]:
    """Every CVE first signalled on or after `since`, with all its signals, oldest
    first. Signals are gathered over the whole history and the window applies to
    the first one: CISA re-stamps old SSVC ratings in batches, and a CVE on its list
    since 2022 must not come back as a new threat."""
    found: dict[str, list[Signal]] = {}

    def add(cve: str, kind: str, when: str | None, note: str = "") -> None:
        if when and CVE_ID.match(cve):
            found.setdefault(cve, []).append(Signal(kind, when, note))

    db = store.db
    for cve, added in db.execute("SELECT cve, date_added FROM kev"):
        add(cve, "kev", f"{added}T00:00:00.000000Z")
    for cve, ssvc, modified in db.execute(
        "SELECT cve, ssvc_time, last_modified FROM nvd WHERE exploitation = 'active'"
    ):
        add(cve, "nvd", ssvc or modified)
    published = dict(
        db.execute(
            "SELECT cve, published FROM vendor_cve WHERE vendor = 'ubuntu' AND found = 1"
            " AND published IS NOT NULL"
        )
    )
    for osv_id, modified in db.execute(
        "SELECT id, modified FROM osv WHERE ecosystem = 'Ubuntu' AND ubuntu_priority = 'critical'"
        " AND id LIKE 'UBUNTU-CVE-%'"
    ):
        cve = osv_id.removeprefix("UBUNTU-")
        add(cve, "ubuntu", published.get(cve) or modified)
    for cve, public in db.execute("SELECT cve, public_date FROM redhat_critical"):
        add(cve, "redhat", public)
    for cve, added, note in db.execute("SELECT cve, added_at, note FROM manual"):
        add(cve, "manual", added, note)
    out = {}
    for cve, sigs in found.items():
        sigs.sort(key=lambda s: s.when)
        if sigs[0].when >= since:
            out[cve] = sigs
    return out


# the vendors' own records


def parse_ubuntu(body: bytes) -> tuple[str | None, list[dict]]:
    """Ubuntu's OSV record: (first published, packages on Ubuntu releases, Pro left out)."""
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise FeedError("Ubuntu record is not JSON") from None
    if not isinstance(data, dict):
        raise FeedError("Ubuntu record is not an object")
    published = _time_or_none(data.get("published"))
    packages = []
    affected = data.get("affected")
    for entry in affected if isinstance(affected, list) else []:
        package = entry.get("package") if isinstance(entry, dict) else None
        if not isinstance(package, dict):
            continue
        match = _UBUNTU_RELEASE.match(str(package.get("ecosystem", "")))
        name = package.get("name")
        if not match or not isinstance(name, str) or not _PACKAGE.match(name):
            continue
        ranges = entry.get("ranges")
        fixed = any(
            isinstance(event, dict) and event.get("fixed")
            for r in (ranges if isinstance(ranges, list) else [])
            if isinstance(r, dict) and isinstance(r.get("events"), list)
            for event in r["events"]
        )
        packages.append(
            {"release": f"ubuntu:{match[1]}.{match[2]}", "package": name, "fixed": fixed}
        )
    return published, _unique(packages)


_EPOCH = re.compile(r"\A(.+)-\d+\Z")
_NVR = re.compile(r"\A(.+)-[^-]+-[^-]*\.el\d+[^-]*\Z")


def _rh_name(package: str) -> str | None:
    """The package's name in each of Red Hat's forms:

    nginx-2:1.20.1-24.el9_7.3 (name-epoch:version-release) -> nginx
    redhat-ds:12-9020020260101.abc (a module stream)        -> redhat-ds
    openssl-3.0.7-27.el9 (no epoch)                        -> openssl
    pki-servlet-engine (a plain name, from package_state)  -> pki-servlet-engine
    """
    if ":" in package:
        head = package.split(":", 1)[0]
        epoch = _EPOCH.match(head)
        name = epoch[1] if epoch else head
    else:
        nvr = _NVR.match(package)
        name = nvr[1] if nvr else package
    return name if _PACKAGE.match(name) else None


def _rh_release(cpe: str, package: str) -> tuple[str | None, str | None]:
    """(release such as rhel:9, product such as enterprise_linux) from a CPE name."""
    match = _RH_CPE.match(cpe or "")
    if not match:
        return None, None
    product, version = match[1], match[2]
    if _RH_BASE.match(product) and version:
        return f"rhel:{version.split('.')[0]}", product
    el = _RH_EL.search(cpe) or _RH_EL.search(package)
    return (f"rhel:{el[1]}" if el else None), product


def parse_redhat(body: bytes) -> tuple[str | None, list[dict]]:
    """Red Hat's record: (made public, packages with a fixed build or still affected)."""
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise FeedError("Red Hat record is not JSON") from None
    if not isinstance(data, dict):
        raise FeedError("Red Hat record is not an object")
    packages = []
    released = data.get("affected_release")
    for entry in released if isinstance(released, list) else []:
        if not isinstance(entry, dict) or not isinstance(entry.get("package"), str):
            continue
        if "/" in entry["package"]:
            continue  # a container image (OpenShift's CoreOS, say), not a package on a host
        name = _rh_name(entry["package"])
        release, product = _rh_release(str(entry.get("cpe", "")), entry["package"])
        if name and release:
            packages.append(
                {"release": release, "package": name, "fixed": True, "product": product}
            )
    states = data.get("package_state")
    for entry in states if isinstance(states, list) else []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("fix_state", "")).strip().lower() not in _RH_UNFIXED:
            continue
        listed = entry.get("package_name")
        if not isinstance(listed, str):
            continue
        if "/" in listed:
            stream, _, rest = listed.partition("/")
            if ":" not in stream:
                continue  # a container image, not a package on a host
            listed = rest
        name = _rh_name(listed)
        release, product = _rh_release(str(entry.get("cpe", "")), listed)
        if name and release:
            packages.append(
                {"release": release, "package": name, "fixed": False, "product": product}
            )
    return _time_or_none(data.get("public_date")), _unique(packages)


MAX_TEXT = 4000  # Red Hat's title and statement, kept cut short; shown escaped


def _text_or_none(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join("".join(ch if ch.isprintable() else " " for ch in value).split())
    return text[:MAX_TEXT] or None


def redhat_text(body: bytes) -> tuple[str | None, str | None]:
    """Red Hat's own words on a CVE, for its card (A.4b): (bug title, statement).
    Untrusted text, kept and shown only."""
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    bug = data.get("bugzilla")
    title = _text_or_none(bug.get("description")) if isinstance(bug, dict) else None
    return title, _text_or_none(data.get("statement"))


def _time_or_none(value: object) -> str | None:
    try:
        return timeutil.norm(value) if isinstance(value, str) else None
    except timeutil.TimeError:
        return None


def _unique(packages: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for p in packages:
        # Fixed in one stream and still affected in another are two facts, kept apart.
        key = (p["release"], p["package"], p.get("product"), p["fixed"])
        seen.setdefault(key, dict(p))
    return sorted(
        seen.values(),
        key=lambda p: (p["release"], p["package"], p.get("product") or "", p["fixed"]),
    )


# refreshing the vendors' records


@dataclass
class Refresh:
    fetched: int = 0
    failed: int = 0
    stopped: bool = False


RETRY_FAILED_AFTER = dt.timedelta(hours=1)


def refresh(ctx: Context, since: str, *, limit: int = 5000) -> Refresh:
    """Fetch the vendor records that signalled CVEs lack, or that are getting old.

    Never-read records come first, then the longest since a try. A failed try is
    recorded with its time, so a record that keeps failing goes to the back of the
    queue instead of holding up the rest.
    """
    store = ctx.store
    now = ctx.now()
    result = Refresh()
    known = {
        (cve, vendor): (attempted, checked)
        for cve, vendor, attempted, checked in store.db.execute(
            "SELECT cve, vendor, attempted_at, checked_at FROM vendor_cve"
        )
    }
    todo = []
    for cve, sigs in signals(store, since).items():
        first = timeutil.parse(sigs[0].when)
        newest = sigs[-1].when
        every = dt.timedelta(days=1) if now - first <= RECENT else dt.timedelta(days=7)
        for vendor in ("ubuntu", "redhat"):
            attempted, checked = known.get((cve, vendor), (None, None))
            if attempted is None:
                due = True
            elif checked is None or checked < attempted:  # the last try failed
                due = now - timeutil.parse(attempted) >= RETRY_FAILED_AFTER
            else:
                due = checked < newest or now - timeutil.parse(checked) >= every
            if due:
                todo.append((attempted is not None, attempted or "", cve, vendor))
    failures_in_a_row = 0
    for _, _, cve, vendor in sorted(todo)[:limit]:
        try:
            _refresh_one(ctx, cve, vendor)
            result.fetched += 1
            failures_in_a_row = 0
        except Refused:
            raise
        except Exception as exc:  # untrusted input: one bad record must not stop the rest
            _record_failure(ctx, cve, vendor, exc)
            result.failed += 1
            failures_in_a_row += 1
            if failures_in_a_row >= STOP_AFTER_FAILURES:
                result.stopped = True
                break
    return result


class VendorRecords(Feed):
    """The refresh, run like a feed so `drafter feeds status` and the candidate list
    say when it fails, as they do for the feeds."""

    name = "vendor-records"
    title = "Vendor records for signalled CVEs"
    quiet_after = dt.timedelta(days=7)

    def __init__(self, since: str, limit: int):
        self.since, self.limit = since, limit

    def run(self, ctx: Context, state) -> int:
        result = refresh(ctx, self.since, limit=self.limit)
        if result.failed:
            stopped = ", stopped after repeated failures" if result.stopped else ""
            raise FeedError(f"{result.failed} vendor record(s) failed{stopped}")
        return result.fetched


def _record_failure(ctx: Context, cve: str, vendor: str, exc: Exception) -> None:
    store = ctx.store
    if store.db.in_transaction:
        store.db.execute("ROLLBACK")
    if isinstance(exc, FetchError | FeedError | timeutil.TimeError):
        message = str(exc)[:200]
    else:
        message = f"internal error: {type(exc).__name__}"
    with store.transaction():
        store.db.execute(
            "INSERT INTO vendor_cve (cve, vendor, attempted_at, error) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(cve, vendor) DO UPDATE SET attempted_at = excluded.attempted_at,"
            " error = excluded.error",
            (cve, vendor, ctx.stamp(), message),
        )


def reparse(store: Store) -> int:
    """Read every stored vendor record again with the current parsers, fetching
    nothing: after a parser change, the candidates match what the vendors said."""
    count = 0
    rows = store.db.execute(
        "SELECT cve, vendor, fetch_id FROM vendor_cve WHERE found = 1"
    ).fetchall()
    with store.transaction():
        for cve, vendor, fetch_id in rows:
            body = store.fetch_body(fetch_id)
            if body is None:
                continue
            parse = parse_ubuntu if vendor == "ubuntu" else parse_redhat
            try:
                published, packages = parse(body)
            except FeedError:
                continue
            title, statement = redhat_text(body) if vendor == "redhat" else (None, None)
            store.db.execute(
                "UPDATE vendor_cve SET published = ?, packages = ?, title = ?, statement = ?"
                " WHERE cve = ? AND vendor = ?",
                (published, json.dumps(packages), title, statement, cve, vendor),
            )
            count += 1
    return count


def _refresh_one(ctx: Context, cve: str, vendor: str) -> None:
    url = (UBUNTU_URL if vendor == "ubuntu" else REDHAT_URL).format(cve=cve)
    feed = f"vendor-{vendor}"
    try:
        answer, fetch_id = ctx.fetch(feed, url, max_bytes=MAX_BYTES)
    except FetchError as exc:
        if exc.status != 404:
            raise
        found, published, packages, title, statement = 0, None, [], None, None
        fetch_id = ctx.store.db.execute(
            "SELECT MAX(id) FROM fetches WHERE feed = ? AND url = ?", (feed, url)
        ).fetchone()[0]
    else:
        found = 1
        parse = parse_ubuntu if vendor == "ubuntu" else parse_redhat
        published, packages = parse(answer.body)
        title, statement = redhat_text(answer.body) if vendor == "redhat" else (None, None)
    with ctx.store.transaction():
        ctx.store.upsert(
            "vendor_cve",
            {
                "cve": cve,
                "vendor": vendor,
                "attempted_at": ctx.stamp(),
                "error": None,
                "checked_at": ctx.stamp(),
                "found": found,
                "published": published,
                "packages": json.dumps(packages),
                "title": title,
                "statement": statement,
                "fetch_id": fetch_id,
            },
            ("cve", "vendor"),
        )


# sorting candidates


# Ubuntu: LTS releases from 22.04, and the interim releases still in support
# (best effort, DESIGN.md). OSV keeps interim releases after their end of life, so
# they are named here, and this list changes when Ubuntu releases or retires one.
UBUNTU_INTERIM = frozenset({"26.10"})  # 25.10 reached end of life in July 2026
RHEL_MAJORS = frozenset({"9", "10"})  # Rocky Linux and AlmaLinux follow RHEL


def supported(release: str) -> bool:
    family, _, version = release.partition(":")
    if family == "ubuntu":
        lts = re.fullmatch(r"(\d{2})\.04", version) and int(version[:2]) % 2 == 0
        return bool(lts and version >= "22.04") or version in UBUNTU_INTERIM
    if family == "rhel":
        return version in RHEL_MAJORS
    return False


# Ubuntu's kernel source packages: `linux` and its flavours (linux-aws-6.8 and the
# like), as seen in its records on 2026-11-07. Other linux-* packages (linux-atm,
# linux-base, linux-firmware) are ordinary packages. A flavour missing here lands
# in "can judge", the safe way round: shown, not hidden as a notice.
_UBUNTU_KERNEL = re.compile(
    r"^linux(-(signed|meta|restricted-modules|restricted-signatures|unsigned))?"
    r"(-(allwinner|aws|azure|bluefield|dell|euclid|fips|gcp|gke|gkeop|hwe|ibm|intel|iot|kvm"
    r"|lowlatency|lts|mtk|nvidia|oem|oracle|raspi|realtime|riscv|snapdragon|starfive|vmware"
    r"|xilinx)([-.a-z0-9]*)?)?\Z"
)


def package_family(name: str) -> str:
    lowered = name.lower()
    if (
        lowered == "kernel"
        or lowered.startswith(("kernel-", "kpatch"))
        or _UBUNTU_KERNEL.match(lowered)
    ):
        return "kernel"
    family = re.sub(r"[\d.]+$", "", lowered).rstrip("-.")
    return family or lowered


@dataclass
class Candidate:
    cve: str
    signals: list[Signal]
    kind: str  # judge, thirdparty, kernel, setaside, unnamed, elsewhere, unread
    packages: list[dict] = field(default_factory=list)  # on supported releases
    reasons: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)  # NVD's vendor:product names
    watched: list[str] = field(default_factory=list)  # products on the watch list
    kev_name: str | None = None  # CISA's vendor and product, if it lists the CVE
    watched_via: list[str] = field(default_factory=list)  # how a watched name matched
    rebuilt_by: list[str] = field(default_factory=list)  # their repositories

    @property
    def first(self) -> str:
        return self.signals[0].when

    @property
    def families(self) -> list[str]:
        """The families that put the CVE in its section, and only those."""
        if self.kind == "thirdparty":
            return self.watched
        if self.kind == "judge":
            chosen = [p for p in self.packages if not p.get("set_aside") and not p.get("kernel")]
        elif self.kind == "kernel":
            chosen = [p for p in self.packages if p.get("kernel") and not p.get("set_aside")]
        else:
            chosen = self.packages
        return sorted({package_family(p["package"]) for p in chosen})


UNNAMED_FOR = dt.timedelta(days=30)


def classify(
    store: Store,
    since: str,
    rules: list[SetAside] | None = None,
    watch: list[Watch] | None = None,
    now: dt.datetime | None = None,
) -> list[Candidate]:
    now = now or timeutil.now()
    rules = load_setaside() if rules is None else rules
    watch = load_watch() if watch is None else watch
    sorted_out = _classify(store, since, rules)
    # Only the signalled CVEs' NVD rows, in batches: the table holds every CVE NVD
    # changed in the window (409,618 for 180 days).
    products, texts, kev_names = {}, {}, {}
    wanted = [cand.cve for cand in sorted_out]
    for start in range(0, len(wanted), 500):
        batch = wanted[start : start + 500]
        marks = ", ".join("?" for _ in batch)
        for cve, names, text in store.db.execute(
            f"SELECT cve, products, description FROM nvd WHERE cve IN ({marks})",  # noqa: S608
            batch,
        ):
            products[cve], texts[cve] = json.loads(names), text
        for cve, vendor, product in store.db.execute(
            f"SELECT cve, vendor, product FROM kev WHERE cve IN ({marks})",  # noqa: S608
            batch,
        ):
            kev_names[cve] = " ".join(x for x in (vendor, product) if x)
    for cand in sorted_out:
        # NVD's product names, and CISA's own names beside them (not instead: CISA
        # writes "PHP Group", NVD writes php:php).
        cand.products = products.get(cand.cve, [])
        cand.kev_name = kev_names.get(cand.cve) or None
        cand.watched, cand.watched_via, cand.rebuilt_by = _watched(
            cand.products, texts.get(cand.cve), watch, cand.kev_name
        )
        # A third-party build is judged on CISA's word or a person's, not on Ubuntu's
        # or Red Hat's rating of their own packages (D3's vendor scope).
        independent = any(sig.kind not in VENDOR_SIGNALS for sig in cand.signals)
        if cand.kind == "elsewhere" and cand.watched and independent:
            cand.kind = "thirdparty"
        elif (
            cand.kind == "elsewhere"
            and independent
            and not cand.products
            and now - timeutil.parse(cand.first) <= UNNAMED_FOR
        ):
            # Not ruled out: NVD often names the products days after a CVE appears.
            cand.kind = "unnamed"
    return sorted_out


def _classify(store: Store, since: str, rules: list[SetAside]) -> list[Candidate]:
    records: dict[str, dict[str, list[dict]]] = {}
    for cve, vendor, packages in store.db.execute(
        "SELECT cve, vendor, packages FROM vendor_cve WHERE checked_at IS NOT NULL"
    ):
        records.setdefault(cve, {})[vendor] = json.loads(packages)
    out = []
    signals_all = signals(store, since)
    for cve, sigs in signals_all.items():
        vendors = records.get(cve, {})
        if len(vendors) < 2:
            out.append(Candidate(cve, sigs, "unread"))
            continue
        by_vendor: dict[str, list[dict]] = {}
        for vendor, vendor_packages in vendors.items():
            for p in vendor_packages:
                if supported(p["release"]):
                    p = dict(p)
                    p["kernel"] = package_family(p["package"]) == "kernel"
                    p["set_aside"] = _set_aside(p, rules)
                    by_vendor.setdefault(vendor, []).append(p)
        # A vendor's own severity speaks for its own packages only: Red Hat rating a
        # CVE Critical says nothing about an Ubuntu universe package (D3).
        sigs = [s for s in sigs if s.kind not in VENDOR_SIGNALS or by_vendor.get(s.kind)]
        if not sigs or not by_vendor:
            out.append(Candidate(cve, sigs or signals_all[cve], "elsewhere"))
            continue
        if all(s.kind in VENDOR_SIGNALS for s in sigs):
            rating_vendors = {sig.kind for sig in sigs}
            packages = [p for vendor in rating_vendors for p in by_vendor[vendor]]
        else:
            packages = [p for vendor_packages in by_vendor.values() for p in vendor_packages]
        if any(not p["kernel"] and not p["set_aside"] for p in packages):
            kind = "judge"
        elif any(p["kernel"] and not p["set_aside"] for p in packages):
            kind = "kernel"
        else:
            kind = "setaside"
        reasons = sorted({p["set_aside"] for p in packages if p["set_aside"]})
        out.append(Candidate(cve, sigs, kind, packages, reasons))
    return sorted(out, key=lambda c: (c.first, c.cve))


@dataclass
class Threat:
    kind: str
    families: list[str]
    candidates: list[Candidate]

    @property
    def first(self) -> str:
        return min(c.first for c in self.candidates)


def threats(candidates: list[Candidate]) -> list[Threat]:
    """CVEs of one kind that hit the same package families within 14 days."""
    groups: list[Threat] = []
    for c in candidates:
        if c.kind in ("elsewhere", "unread", "unnamed"):
            continue
        families = c.families
        for group in groups:
            close = timeutil.parse(c.first) - timeutil.parse(group.first) <= GROUP_WITHIN
            if group.kind == c.kind and group.families == families and close:
                group.candidates.append(c)
                break
        else:
            groups.append(Threat(c.kind, families, [c]))
    return groups


# the list


def _releases(packages: list[dict]) -> str:
    by_release: dict[str, list[str]] = {}
    for p in packages:
        if p.get("set_aside") or p.get("kernel"):
            continue
        state = "fixed" if p["fixed"] else "no fix yet"
        by_release.setdefault(p["release"], []).append(f"{p['package']} ({state})")
    parts = []
    for release in sorted(by_release):
        names = sorted(set(by_release[release]))
        shown = ", ".join(names[:4]) + (f" and {len(names) - 4} more" if len(names) > 4 else "")
        parts.append(f"{release}: {shown}")
    return "; ".join(parts)


def render(
    candidates: list[Candidate],
    since: str,
    feed_notes: list[str],
    *,
    show_all: bool = False,
    decided=None,
) -> str:
    """`decided`: a threat's decision line (A.4), for the sections a person decides."""
    lines = []
    if feed_notes:
        lines.append("Feeds needing a look (the list may be missing threats):")
        lines += [f"  {note}" for note in feed_notes]
        lines.append("")
    lines.append(f"Threats signalled since {since[:10]}")
    groups = threats(candidates)
    sections = (
        ("judge", "Can judge"),
        (
            "thirdparty",
            "Third-party builds (thirdparty.toml): the vendors' records can't say;"
            " settled at fill-in",
        ),
        ("kernel", "Kernels: the tool can't judge these yet (plan D2), a notice only"),
        ("setaside", "Set aside (setaside.toml)"),
    )
    for kind, heading in sections:
        chosen = [g for g in groups if g.kind == kind]
        cves = sum(len(g.candidates) for g in chosen)
        lines.append("")
        lines.append(f"{heading}: {len(chosen)} threat(s), {cves} CVE(s)")
        for group in chosen:
            ids = ", ".join(c.cve for c in group.candidates)
            name = ", ".join(group.families) or "?"
            lines.append(f"  {group.first[:10]}  {name}  {ids}")
            if kind == "thirdparty":
                via = []
                for cand in group.candidates:
                    via += [v for v in cand.watched_via if v not in via]
                lines.append(f"      matched: {'; '.join(via) or 'NVD names the product'}")
            if decided is not None and kind in ("judge", "thirdparty"):
                lines.append(f"      decision: {decided(group)}")
            sigs = sorted({s.describe() for c in group.candidates for s in c.signals})
            lines.append(f"      signals: {'; '.join(sigs)}")
            if kind == "judge":
                packages = [p for c in group.candidates for p in c.packages]
                lines.append(f"      packages: {_releases(packages)}")
            if kind == "thirdparty":
                named = sorted(
                    {p for cand in group.candidates for p in cand.products}
                    | {f"CISA: {cand.kev_name}" for cand in group.candidates if cand.kev_name}
                )
                shown = ", ".join(named[:6]) + (
                    f" and {len(named) - 6} more" if len(named) > 6 else ""
                )
                lines.append(f"      named: {shown or 'no product yet'}")
            repos = []
            for cand in group.candidates:
                repos += [r for r in cand.rebuilt_by if r not in repos]
            if repos:
                label = "rebuilt by" if kind == "thirdparty" else "also rebuilt by"
                lines.append(f"      {label}: {'; '.join(repos)}")
            if kind == "setaside":
                reasons = sorted({r for c in group.candidates for r in c.reasons})
                lines.append(f"      why: {'; '.join(reasons)}")
    unnamed = [c for c in candidates if c.kind == "unnamed"]
    if unnamed:
        lines.append("")
        lines.append(
            f"No vendor package, and NVD names no product yet: {len(unnamed)} CVE(s) signalled"
            " in the last 30 days; not ruled out until NVD names one"
        )
        for cand in unnamed:
            sigs = "; ".join(s.describe() for s in cand.signals)
            name = f"  CISA: {cand.kev_name}" if cand.kev_name else ""
            lines.append(f"  {cand.first[:10]}  {cand.cve}{name}  {sigs}")
    elsewhere = sum(1 for c in candidates if c.kind == "elsewhere")
    unread = [c.cve for c in candidates if c.kind == "unread"]
    lines.append("")
    if show_all:
        lines.append(f"Not on a supported release: {elsewhere} CVE(s)")
        for cand in candidates:
            if cand.kind != "elsewhere":
                continue
            names = ", ".join(cand.products[:3]) or (
                f"CISA: {cand.kev_name}" if cand.kev_name else "no product named yet"
            )
            more = f" and {len(cand.products) - 3} more" if len(cand.products) > 3 else ""
            lines.append(f"  {cand.first[:10]}  {cand.cve}  {names}{more}")
    else:
        lines.append(
            f"Not on a supported release: {elsewhere} CVE(s), counted only (--all lists them)"
        )
    if unread:
        lines.append(
            f"Vendor records not read yet: {len(unread)} CVE(s); `drafter candidates refresh`"
            " reads them, and `drafter feeds status` says if it is failing"
        )
        for start in range(0, len(unread), 6):
            lines.append("  " + ", ".join(unread[start : start + 6]))
    return "\n".join(lines)
