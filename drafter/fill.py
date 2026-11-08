"""A.3a: a draft `packages` section from the vendors' own data.

For the CVEs of one threat and a person's binary filter (plan, 2026-11-07):

- Ubuntu: entries per supported release from Ubuntu's OSV record: its fixed
  version, binaries, and the USN it came from. Patterns cover every build the
  record lists as affected.
- RHEL 9 and 10: Red Hat's record names the advisories; each advisory's CSAF names
  the binary RPMs and exact builds. A stream Red Hat lists as affected with no fix,
  plain or module, gets `fixed: null`. Rocky Linux and AlmaLinux rebuilds fall
  under these entries.
- AlmaLinux's own builds (`.alma`), released ahead of Red Hat's, from its OSV
  records.

Fixed versions come from vendor data only. The `versions` patterns are derived by
the rules below, never typed by hand or by an AI. The expensive failure is a
vulnerable host read as fixed or not affected, so the patterns lean wide, and what
isn't drafted is listed in the report, never dropped quietly.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field

from drafter import candidates
from drafter.feeds import Context, FeedError
from drafter.http import FetchError

CSAF_URL = "https://security.access.redhat.com/data/csaf/v2/advisories/{year}/{name}.json"
ERRATA_URL = "https://access.redhat.com/errata/{advisory}"
USN_URL = "https://ubuntu.com/security/notices/{usn}"
UBUNTU_CVE_URL = "https://ubuntu.com/security/{cve}"
ALMA_OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/AlmaLinux/{id}.json"
ALMA_ERRATA_URL = "https://errata.almalinux.org/{major}/{id}.html"
MAX_CSAF_BYTES = 64 * 1024 * 1024
FAMILIES = ("ubuntu", "rhel")

_RHSA = re.compile(r"\ARH[SBE]A-(\d{4}):(\d{1,6})\Z")
_USN = re.compile(r"\AUSN-\d{1,6}-\d{1,3}\Z")
_ALSA = re.compile(r"\AALSA-\d{4}:[A-Z0-9]{1,8}\Z")
_NEVRA = re.compile(
    r"\A(?P<name>[A-Za-z0-9][A-Za-z0-9._+-]*)-(?:(?P<epoch>\d+):)?(?P<version>[^-:]+)-"
    r"(?P<release>[^-:]+)\.(?P<arch>x86_64|aarch64|ppc64le|s390x|noarch|i686|src)"
    r"(?:::(?P<stream>[A-Za-z0-9._+-]+:[A-Za-z0-9._+-]+))?\Z"
)
_EL = re.compile(r"(?:^|\.|\+|_)el(\d{1,2})")
# The checker's own shapes (checker/packs/format.py): what a pack may hold.
_PACKAGE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9+._-]{0,99}\Z")
_VERSION = re.compile(r"\A[A-Za-z0-9.+~:^_-]{1,100}\Z")
_URL = re.compile(r"\Ahttps://[A-Za-z0-9.-]+/[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]*\Z")


class FillError(ValueError):
    pass


@dataclass
class Entry:
    release: str
    binary_names: list[str]
    versions: str | None
    fixed: str | None
    source: str
    origin: str  # ubuntu, redhat, alma
    note: str = ""


OTHER_BUILDS = ("cant_judge", "not_affected")


@dataclass
class Draft:
    cves: list[str]
    binary_filter: list[str]
    # What a host gets when its build matches no entry. The checker's default is
    # not_affected; a draft says cant_judge unless a person decides otherwise, since
    # some vulnerable builds match no drafted entry (streams no vendor lists any
    # more, AlmaLinux's blog-only builds, third-party builds until A.3b).
    other_builds: str = "cant_judge"
    entries: list[Entry] = field(default_factory=list)
    filtered_out: dict[str, list[str]] = field(default_factory=dict)  # release -> binaries
    not_covered: list[str] = field(default_factory=list)
    guessed: list[str] = field(default_factory=list)  # entries whose binaries are a guess
    conflicts: list[str] = field(default_factory=list)  # for a person to settle
    missing: list[str] = field(default_factory=list)  # vendor records that weren't there
    alma_as_of: str | None = None  # when AlmaLinux's records were last read
    unconfirmed: int = 0  # third-party proposals nobody confirmed (A.3b)


def check_filter(filters: list[str]) -> None:
    for item in filters:
        scope, sep, glob = item.partition(":")
        if sep and scope not in FAMILIES:
            raise FillError(f"a filter's scope is ubuntu: or rhel:, not {scope!r}")
        if not (glob if sep else item):
            raise FillError("an empty filter")


def keep(binary: str, filters: list[str], family: str) -> bool:
    """A filter is a glob, or `ubuntu:GLOB` / `rhel:GLOB` for one family only:
    RHEL's php-cli holds php-cgi, Ubuntu's doesn't."""
    if not filters:
        return True
    for item in filters:
        scope, sep, glob = item.partition(":")
        if not sep:
            scope, glob = "", item
        if scope and scope != family:
            continue
        if fnmatch.fnmatchcase(binary, glob):
            return True
    return False


# Not "-dbg": RHEL's php-dbg is the phpdbg program, not symbols.
_DEBUG = re.compile(r"-(debuginfo|debugsource|dbgsym)\Z")


def _names(binaries: list[str]) -> list[str]:
    """Valid binary names, without debugging-symbol packages (php-fpm-debuginfo,
    php8.3-fpm-dbgsym): never a server's running code, and they'd crowd the
    checker's limit of 50 names an entry."""
    return sorted(
        {
            b
            for b in binaries
            if isinstance(b, str) and _PACKAGE.fullmatch(b) and not _DEBUG.search(b)
        }
    )


def _split(binaries: list[str], filters: list[str], release: str, draft: Draft) -> list[str]:
    family = release.split(":")[0]
    valid = _names(binaries)
    kept = [b for b in valid if keep(b, filters, family)]
    left = [b for b in valid if not keep(b, filters, family)]
    if left:
        have = draft.filtered_out.setdefault(release, [])
        have += [b for b in left if b not in have]
    return kept


def _clean(text: str, limit: int = 160) -> str:
    """Vendor text for a one-line comment: printable, no line breaks."""
    return "".join(ch if ch.isprintable() else "?" for ch in str(text))[:limit]


# versions patterns, by rule


_UBUNTU_REVISION = re.compile(r"^(?:\d+:)?([^-]+)-(\d+)ubuntu")


def ubuntu_shape(version: str) -> str:
    """The pattern for one of Ubuntu's own builds:

    8.3.6-0ubuntu0.24.04.13 -> 8.3.6-0ubuntu*  (every Ubuntu build on that base)
    8.3.4-1build1           -> 8.3.4-1build1   (no "ubuntu" mark: the exact string)

    Sury's builds write "+ubuntu" (8.1.2-1+ubuntu22.04.1+deb.sury.org+1), so
    neither shape reaches them, even on the same upstream version, where a match
    would compare as newer than Ubuntu's fix and read "fixed"."""
    match = _UBUNTU_REVISION.match(version)
    if match:
        return f"{match[1]}-{match[2]}ubuntu*"
    return version.split(":", 1)[-1]


# RHEL: a plain build's release ends .elN, .elN_M or .elN_M.P (M and P up to two
# digits). Written out, so AlmaLinux's own builds (.elN_M.alma.1) stay out: they
# have entries of their own, and in a plain match they'd read as older than the fix.
_PLAIN_TAILS = ("", "_?", "_??", "_?.?", "_?.??", "_??.?", "_??.??")


def rhel_plain_patterns(major: str) -> list[str]:
    """Every Red Hat, Rocky and AlmaLinux rebuild of a plain package on one release.
    One plain stream per name and release, so no version is pinned: a rebase
    (git 2.43 to 2.47) or a two-part version (tar 1.34) is still matched."""
    return [f"*.el{major}{tail}" for tail in _PLAIN_TAILS]


def rhel_module_pattern(stream: str | None, version: str | None, major: str) -> tuple[str, str]:
    """(pattern, note) for one module stream: keyed on the stream's name, which for
    most streams leads the version (php:8.2 -> 8.2.35, nodejs:20 -> 20.19.5).
    Red Hat and Rocky write module+elN, AlmaLinux module_elN; all end in an eight
    character hash, which AlmaLinux's own .alma builds don't."""
    name = (stream or "").split(":", 1)[-1]
    tail = f"module?el{major}*+????????"
    if name and version == name:
        return f"{name}-*{tail}", ""  # postgresql:16 at 16-1.module+el9…
    if name and (version is None or version.startswith(name + ".")):
        return f"{name}.*{tail}", ""
    # npm in nodejs:20 is 10.8.2, in nodejs:22 10.9.2: one pattern for both would
    # judge one stream's build against the other's fix. A person writes it.
    return "", f"stream {stream}: the version ({version}) doesn't start with the stream's name"


def rhel_fixed(epoch: str | None, version: str, release: str) -> str:
    """The fixed version as packs write it: a non-zero epoch kept (nginx is 2:), and
    for a module build no build number or hash (8.2.35-1.module+el9.8.0), which
    Rocky's and AlmaLinux's rebuilds of the same fix also reach."""
    if "module" in release:
        release = re.sub(r"(module[+_]el\d+(?:\.\d+)*)\+.*$", r"\1", release)
    head = f"{epoch}:" if epoch and epoch != "0" else ""
    return f"{head}{version}-{release}"


def alma_pattern(fixed: str, major: str) -> tuple[str, str]:
    """(pattern, note) for AlmaLinux's own builds, which only AlmaLinux writes `alma`
    into, so no other repository's build can match:

    2.34-125.el9_5.8.alma.1                        -> *.el9*alma*  (by release, as RHEL)
    8.1.32-1.module_el9.8.0+326+528679fc.alma.1    -> 8.1.*module?el9*alma*

    AlmaLinux's records don't name a module's stream, so a module build's is taken
    from its version's major.minor, and the note says so."""
    version, _, release = fixed.split(":", 1)[-1].partition("-")
    if "module" not in release:
        return f"*.el{major}*alma*", ""
    parts = version.split(".")
    stream = ".".join(parts[:2]) if len(parts) > 1 else parts[0]
    # 8.1.32-…: "8.1." leads; 10.11-… or 16-…: the whole version is the stream.
    joint = "." if len(parts) > 2 else "-"
    return (
        f"{stream}{joint}*module?el{major}*alma*",
        f"module stream guessed from the version ({stream}): AlmaLinux's record doesn't name it",
    )


def _drop_zero_epoch(version: str) -> str:
    head, sep, rest = version.partition(":")
    return rest if sep and head == "0" else version


# Ubuntu


def ubuntu_entries(record: dict, cve: str, filters: list[str], draft: Draft) -> list[Entry]:
    usns = [u for u in record.get("related") or [] if isinstance(u, str) and _USN.match(u)]
    source = USN_URL.format(usn=sorted(usns)[0]) if usns else UBUNTU_CVE_URL.format(cve=cve)
    out = []
    for affected in record.get("affected") or []:
        package = affected.get("package") if isinstance(affected, dict) else None
        if not isinstance(package, dict):
            continue
        ecosystem = str(package.get("ecosystem", ""))
        pro = re.match(r"^Ubuntu:Pro:(?:[A-Za-z-]+:)?(\d{2}\.\d{2})", ecosystem)
        if pro and candidates.supported(f"ubuntu:{pro[1]}"):
            draft.not_covered.append(
                f"ubuntu:{pro[1]} {_clean(ecosystem)}: {_clean(package.get('name'))}, an Ubuntu"
                " Pro build (the tool reads it as Ubuntu's own: check it by hand)"
            )
            continue
        match = re.match(r"\AUbuntu:(\d{2}\.\d{2})(?::LTS)?\Z", ecosystem)
        if not match or not candidates.supported(f"ubuntu:{match[1]}"):
            continue
        release = f"ubuntu:{match[1]}"
        fixed = None
        for r in affected.get("ranges") or []:
            for event in (r.get("events") if isinstance(r, dict) else None) or []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed = event["fixed"]
        if fixed is not None and not _VERSION.fullmatch(fixed):
            draft.conflicts.append(f"{release}: Ubuntu's fixed version is unreadable; left out")
            continue
        specific = affected.get("ecosystem_specific") or {}
        binaries = [
            b.get("binary_name")
            for b in (specific.get("binaries") if isinstance(specific, dict) else None) or []
            if isinstance(b, dict)
        ]
        names = _split(binaries, filters, release, draft)
        if not names:
            continue
        listed = [
            v
            for v in affected.get("versions") or []
            if isinstance(v, str) and _VERSION.fullmatch(v)
        ]
        shapes = sorted({ubuntu_shape(v) for v in [*listed, *([fixed] if fixed else [])]})
        if not shapes:
            shapes = [None]  # no version at all: every build, judged against the fix
        for shape in shapes:
            out.append(
                Entry(
                    release=release,
                    binary_names=names,
                    versions=shape,
                    fixed=fixed,
                    source=source,
                    origin="ubuntu",
                    note="" if fixed else "no fix from Ubuntu yet",
                )
            )
    return out


# Red Hat


def parse_csaf(body: bytes, cve: str) -> tuple[list[dict], int]:
    """(the binary builds a CSAF advisory says fix `cve`, product ids it couldn't
    read)."""
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise FeedError("CSAF advisory is not JSON") from None
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    fixed_ids: list[str] = []
    for vuln in vulns if isinstance(vulns, list) else []:
        if isinstance(vuln, dict) and vuln.get("cve") == cve:
            status = vuln.get("product_status") or {}
            fixed_ids += [p for p in status.get("fixed") or [] if isinstance(p, str)]
    builds, unread = [], 0
    for product_id in fixed_ids:
        # "AppStream-9.8.0.Z.MAIN.EUS:php-fpm-0:8.2.35-1.module+el9…x86_64::php:8.2"
        nevra = product_id.split(":", 1)[1] if ":" in product_id.split("::")[0] else product_id
        match = _NEVRA.match(nevra)
        if not match:
            unread += 1
            continue
        if match["arch"] == "src":
            continue
        builds.append(
            {
                "name": match["name"],
                "epoch": match["epoch"],
                "version": match["version"],
                "release": match["release"],
                "stream": match["stream"],
            }
        )
    return builds, unread


def redhat_entries(ctx: Context, record: dict, cve: str, filters: list[str], draft: Draft):
    out: list[Entry] = []
    csaf_cache: dict[str, tuple[list[dict], int]] = {}
    names_by: dict[tuple[str, str], list[str]] = {}  # (release, source package) -> binaries
    for released in record.get("affected_release") or []:
        if not isinstance(released, dict):
            continue
        cpe, advisory = str(released.get("cpe", "")), str(released.get("advisory", ""))
        package = str(released.get("package", ""))
        if "/" in package:
            continue  # a container image
        release, product = candidates._rh_release(cpe, package)
        if release is None or not candidates.supported(release):
            continue
        if product != "enterprise_linux":
            kind = (
                "an extended-support build"
                if product and product.startswith(("enterprise_linux_", "rhel_"))
                else f"a {_clean(product)} build"
            )
            draft.not_covered.append(
                f"{release} {_clean(product)}: {_clean(package)} ({_clean(advisory)}), {kind};"
                " hosts on it read as vulnerable"
            )
            continue
        match = _RHSA.match(advisory)
        if not match:
            draft.conflicts.append(f"{release}: {_clean(package)} has no readable advisory")
            continue
        url = CSAF_URL.format(year=match[1], name=advisory.lower().replace(":", "_"))
        if url not in csaf_cache:  # BaseOS and AppStream rows name the same advisory
            answer, _ = ctx.fetch("vendor-csaf", url, max_bytes=MAX_CSAF_BYTES)
            csaf_cache[url] = parse_csaf(answer.body, cve)
        major = release.split(":")[1]
        builds, unread = csaf_cache[url]
        if unread:
            draft.conflicts.append(f"{advisory}: {unread} product id(s) unreadable; left out")
        streams: dict[tuple, set] = {}
        other_el = 0
        for build in builds:
            el = _EL.search(build["release"])
            if not el or el[1] != major:
                other_el += 1
                continue
            key = (build["epoch"], build["version"], build["release"], build["stream"])
            streams.setdefault(key, set()).add(build["name"])
        if other_el:
            draft.not_covered.append(
                f"{advisory}: {other_el} build(s) for another RHEL release, left to that release"
            )
        source_package = candidates._rh_name(package) or package
        for (epoch, version, rel, stream), binaries in sorted(
            streams.items(), key=lambda kv: tuple(x or "" for x in kv[0])
        ):
            names = _split(sorted(binaries), filters, release, draft)
            if not names:
                continue  # another package the advisory also fixes (apcu, pecl)
            fixed = rhel_fixed(epoch, version, rel)
            if "module" in rel:
                pattern, note = rhel_module_pattern(stream, version, major)
                if not pattern:
                    draft.conflicts.append(
                        f"{release} {', '.join(names)} fixed {fixed} ({advisory}): {note};"
                        " write its versions pattern by hand"
                    )
                    continue
                patterns, notes = [pattern], f"stream {stream}" if stream else ""
            else:
                patterns, notes = rhel_plain_patterns(major), ""
            # Only names whose builds the pattern really matches may be lent to an
            # unfixed stream (npm in nodejs:22 is 10.9.x, never 22.*).
            have = names_by.setdefault((release, source_package), [])
            have += [n for n in names if n not in have]
            for pattern in patterns:
                out.append(
                    Entry(
                        release=release,
                        binary_names=names,
                        versions=pattern,
                        fixed=fixed,
                        source=ERRATA_URL.format(advisory=advisory),
                        origin="redhat",
                        note=_clean(notes),
                    )
                )
    # Streams Red Hat lists as affected with no fix yet: plain or module, never dropped.
    for state in record.get("package_state") or []:
        if not isinstance(state, dict):
            continue
        fix_state = str(state.get("fix_state", "")).strip()
        if fix_state.lower() not in candidates._RH_UNFIXED:
            continue
        listed = str(state.get("package_name", ""))
        stream_name, slash, rest = listed.partition("/")
        if slash and ":" not in stream_name:
            continue  # a container image
        module = stream_name.partition(":")[0] if slash else None
        package = rest if slash else listed
        release, product = candidates._rh_release(str(state.get("cpe", "")), listed)
        if release is None or not candidates.supported(release):
            continue
        if product != "enterprise_linux":
            draft.not_covered.append(
                f"{release} {_clean(product)}: {_clean(listed)} {_clean(fix_state)}, not drafted"
            )
            continue
        if not _PACKAGE.fullmatch(package):
            continue
        major = release.split(":")[1]
        key_package = module or package
        names = names_by.get((release, key_package))
        guess = None
        if not names:
            elsewhere = sorted((rel, n) for (rel, pkg), n in names_by.items() if pkg == key_package)
            if elsewhere:
                names = [n for n in elsewhere[0][1] if keep(n, filters, "rhel")]
                guess = f"binaries taken from {elsewhere[0][0]}'s fixed builds"
            else:
                # A source package's own name is often no binary at all (krb5 ships
                # krb5-libs): an entry naming it would match nothing on a host, and the
                # host would read "not affected". A person names the binaries.
                draft.conflicts.append(
                    f"{release} {_clean(listed)}: Red Hat lists it as {_clean(fix_state)} with no"
                    " fixed build anywhere to take binaries from; name its binaries by hand"
                )
                continue
        if module:
            pattern, note = rhel_module_pattern(stream_name, None, major)
            if not pattern or package != module:
                draft.conflicts.append(
                    f"{release} {_clean(listed)}: Red Hat lists it as {_clean(fix_state)}; the"
                    " stream's own versions don't say this package's, so write its pattern by hand"
                )
                continue
            patterns = [pattern]
        else:
            patterns, note = rhel_plain_patterns(major), ""
        what = f"Red Hat lists {_clean(listed)} as {_clean(fix_state)}"
        for pattern in patterns:
            out.append(
                Entry(
                    release=release,
                    binary_names=names,
                    versions=pattern,
                    fixed=None,
                    source=candidates.REDHAT_URL.format(cve=cve),
                    origin="redhat",
                    note=_clean("; ".join(x for x in (what, note, guess) if x)),
                )
            )
        if guess:
            draft.guessed.append(f"{release} {_clean(listed)}: {guess}")
    return out


# AlmaLinux's own builds


def alma_entries(ctx: Context, cve: str, filters: list[str], draft: Draft) -> list[Entry]:
    out = []
    rows = ctx.store.db.execute(
        "SELECT id FROM osv WHERE ecosystem = 'AlmaLinux' AND cves LIKE ?", (f'%"{cve}"%',)
    ).fetchall()
    for (osv_id,) in rows:
        if not _ALSA.match(osv_id):
            continue
        answer, _ = ctx.fetch("osv-almalinux", ALMA_OSV_URL.format(id=osv_id.replace(":", "%3A")))
        try:
            record = json.loads(answer.body)
        except (ValueError, UnicodeDecodeError, RecursionError):
            draft.conflicts.append(f"{osv_id}: unreadable; left out")
            continue
        by_fix: dict[tuple, list[str]] = {}
        for affected in record.get("affected") or [] if isinstance(record, dict) else []:
            package = affected.get("package") if isinstance(affected, dict) else None
            if not isinstance(package, dict):
                continue
            match = re.match(r"\AAlmaLinux:(\d+)\Z", str(package.get("ecosystem", "")))
            if not match or not candidates.supported(f"rhel:{match[1]}"):
                continue
            for r in affected.get("ranges") or []:
                for event in (r.get("events") if isinstance(r, dict) else None) or []:
                    fixed = event.get("fixed") if isinstance(event, dict) else None
                    if isinstance(fixed, str) and ".alma" in fixed and _VERSION.fullmatch(fixed):
                        # Kept whole: the pattern only reaches AlmaLinux's own builds,
                        # so the build number is what orders two of them.
                        key = (f"rhel:{match[1]}", _drop_zero_epoch(fixed))
                        by_fix.setdefault(key, []).append(package.get("name"))
        for (release, fixed), binaries in sorted(by_fix.items()):
            names = _split(binaries, filters, release, draft)
            if names:
                out.append(
                    Entry(
                        release=release,
                        binary_names=names,
                        versions=alma_pattern(fixed, release.split(":")[1])[0],
                        fixed=fixed,
                        source=ALMA_ERRATA_URL.format(
                            major=release.split(":")[1], id=osv_id.replace(":", "-")
                        ),
                        origin="alma",
                        note="; ".join(
                            x
                            for x in (
                                "AlmaLinux's own build",
                                alma_pattern(fixed, release.split(":")[1])[1],
                            )
                            if x
                        ),
                    )
                )
    return out


# the draft


def _record(ctx: Context, feed: str, url: str, draft: Draft, what: str) -> dict:
    try:
        answer, _ = ctx.fetch(feed, url, max_bytes=candidates.MAX_BYTES)
    except FetchError as exc:
        if exc.status != 404:
            raise
        draft.missing.append(what)
        return {}
    try:
        data = json.loads(answer.body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise FeedError(f"{feed}: record is not JSON") from None
    return data if isinstance(data, dict) else {}


def build(
    ctx: Context,
    cves: list[str],
    filters: list[str],
    other_builds: str = "cant_judge",
    thirdparty: list[Entry] | None = None,
    unconfirmed: int = 0,
) -> Draft:
    check_filter(filters)
    if other_builds not in OTHER_BUILDS:
        raise FillError(f"other_builds is one of {', '.join(OTHER_BUILDS)}")
    draft = Draft(cves=sorted(set(cves)), binary_filter=list(filters), other_builds=other_builds)
    for cve in draft.cves:
        ubuntu = _record(
            ctx,
            "vendor-ubuntu",
            candidates.UBUNTU_URL.format(cve=cve),
            draft,
            f"Ubuntu has no record for {cve} (it doesn't track it, or hasn't yet)",
        )
        redhat = _record(
            ctx,
            "vendor-redhat",
            candidates.REDHAT_URL.format(cve=cve),
            draft,
            f"Red Hat has no record for {cve} (it doesn't track it, or hasn't yet)",
        )
        draft.entries += (
            ubuntu_entries(ubuntu, cve, filters, draft)
            + redhat_entries(ctx, redhat, cve, filters, draft)
            + alma_entries(ctx, cve, filters, draft)
        )
    for cve in draft.cves:
        has_rhel = any(e.origin == "redhat" and e.fixed for e in draft.entries)
        listed = ctx.store.db.execute(
            "SELECT 1 FROM osv WHERE ecosystem = 'AlmaLinux' AND cves LIKE ? LIMIT 1",
            (f'%"{cve}"%',),
        ).fetchone()
        if has_rhel and not listed:
            draft.missing.append(
                f"AlmaLinux has no record for {cve} in the store: its own .alma builds"
                " (debranded glibc, openssh, systemd and others) match only AlmaLinux's"
                " entries, so check errata.almalinux.org"
            )
    draft.entries += thirdparty or []
    draft.unconfirmed = unconfirmed
    _merge(draft)
    alma = ctx.store.state("osv-almalinux")
    if alma.last_success:
        # The index's etag is saved only once every waiting record was read.
        caught_up = "caught up" if alma.etag or alma.last_modified else "with records still waiting"
        draft.alma_as_of = f"{alma.last_success}, {caught_up}"
    draft.not_covered = sorted(set(draft.not_covered))
    draft.guessed = sorted(set(draft.guessed))
    order = {"ubuntu": 0, "sury": 1, "redhat": 2, "alma": 3, "remi": 4, "byhand": 5}
    draft.entries.sort(key=lambda e: (order[e.origin], e.release, e.versions or "", e.fixed or ""))
    return draft


MAX_NAMES = 50  # the checker's limits (checker/packs/format.py)
MAX_ENTRIES = 100


def _merge(draft: Draft) -> None:
    """Fold identical entries (two CVEs, one fix), split entries over the checker's
    50 names, and report every clash the checker would refuse: one binary in two
    entries with the same release and pattern."""
    seen: set[tuple] = set()
    kept: list[Entry] = []
    for e in draft.entries:
        key = (e.release, tuple(e.binary_names), e.versions, e.fixed)
        if key in seen:
            continue
        seen.add(key)
        for start in range(0, len(e.binary_names), MAX_NAMES):
            kept.append(
                Entry(**{**e.__dict__, "binary_names": e.binary_names[start : start + MAX_NAMES]})
            )
    owner: dict[tuple, Entry] = {}
    clashes: dict[tuple, tuple[Entry, Entry, set, set]] = {}
    for e in kept:
        for name in e.binary_names:
            other = owner.setdefault((e.release, e.versions, name), e)
            if other is e:
                continue
            same = (
                e.release,
                tuple(other.binary_names),
                other.fixed,
                other.source,
                tuple(e.binary_names),
                e.fixed,
                e.source,
            )  # the pair, on every pattern
            pair = clashes.setdefault(same, (other, e, set(), set()))
            pair[2].add(name)
            pair[3].add(e.versions)
    for other, e, names, patterns in clashes.values():
        patterns = {p or "(any version)" for p in patterns}  # an entry with no pattern
        if other.fixed is None or e.fixed is None:
            advice = "keep fixed: null, since one CVE has no fix yet"
        elif other.fixed != e.fixed:
            advice = "each binary takes the later fix, in one entry"
        else:
            advice = "decide which entry they belong to (the same fix either way)"
        draft.conflicts.append(
            f"{e.release} {', '.join(sorted(names))} in two entries on"
            f" {len(patterns)} pattern(s) ({', '.join(sorted(patterns)[:2])}"
            f"{', …' if len(patterns) > 2 else ''}): fixed {other.fixed} ({other.source})"
            f" and {e.fixed} ({e.source}); {advice}. The checker refuses both."
        )
    if len(kept) > MAX_ENTRIES:
        draft.conflicts.append(
            f"{len(kept)} entries: the checker takes at most {MAX_ENTRIES}; narrow the filter"
            " or split the threat"
        )
    draft.entries = kept


def _q(text: str) -> str:
    return json.dumps(text)  # a YAML double-quoted scalar, escapes included


def render_yaml(draft: Draft) -> str:
    lines = [
        "# Drafted by the pack drafter from vendor data (A.3a). Not reviewed, not signed.",
        f"# CVEs: {', '.join(draft.cves)}",
        "# Binary filter: "
        + (_clean(", ".join(draft.binary_filter), 300) or "none (every binary; not filtered)"),
    ]
    if draft.other_builds == "cant_judge":
        lines.append('  # A build no entry matches reads "can\'t judge", never "not affected".')
    else:
        lines.append("  # A person decided the threat is only in the builds listed below.")
    lines += [f"  other_builds: {draft.other_builds}", "  packages:"]
    heading = {
        "ubuntu": "Ubuntu's own builds",
        "redhat": "RHEL, with Rocky Linux and AlmaLinux rebuilds",
        "alma": "AlmaLinux's own builds (debranded or early), matched only by AlmaLinux's",
        "sury": "Sury's PPA, confirmed by a person (A.3b)",
        "remi": "Remi's repository, confirmed by a person (A.3b)",
        "byhand": "Written by a person in the assembly file (A.7)",
    }
    last = None
    for e in draft.entries:
        if e.origin != last:
            lines.append(f"    # {heading[e.origin]}")
            last = e.origin
        if e.note:
            lines.append(f"    # {_clean(e.note)}")
        source = e.source if _URL.fullmatch(e.source) else "https://invalid.example/"
        lines.append(f"    - release: {_q(e.release)}")
        lines.append(f"      binary_names: [{', '.join(_q(n) for n in e.binary_names)}]")
        if e.versions is not None:
            lines.append(f"      versions: {_q(e.versions)}")
        lines.append(f"      fixed: {_q(e.fixed) if e.fixed else 'null'}")
        lines.append(f"      source: {_q(source)}")
    return "\n".join(lines) + "\n"


def render_report(draft: Draft) -> str:
    lines = [f"{len(draft.entries)} entries; other_builds: {draft.other_builds}"]
    if draft.other_builds == "not_affected":
        lines.append(
            '  a build no entry matches reads "not affected": only right if the threat'
            " is in no build but those listed"
        )
    if draft.missing:
        lines.append("Vendor records not there:")
        lines += [f"  {m}" for m in draft.missing]
    lines.append(
        f"AlmaLinux's own builds from records read {draft.alma_as_of or 'never'}"
        " (drafter feeds fetch osv-almalinux reads newer)"
    )
    if draft.conflicts:
        lines.append("Needs a person:")
        lines += [f"  {_clean(c, 300)}" for c in draft.conflicts]
    if draft.guessed:
        lines.append("Binaries guessed (check them):")
        lines += [f"  {g}" for g in draft.guessed]
    if draft.filtered_out:
        lines.append("Left out by the binary filter:")
        for release in sorted(draft.filtered_out):
            lines.append(f"  {release}: {', '.join(sorted(draft.filtered_out[release]))}")
    lines.append("Not covered here:")
    if any(e.origin in ("sury", "remi") for e in draft.entries) or draft.unconfirmed:
        lines.append(
            f"  {draft.unconfirmed} third-party proposal(s) not confirmed: their builds read"
            " can't judge"
        )
    else:
        lines.append(
            "  third-party repositories (Sury, Remi): `drafter propose` proposes them for a"
            " person to confirm"
        )
    lines.append(
        "  streams no vendor lists any more (php:8.1 on RHEL 9, say) and AlmaLinux's early"
        " builds announced only on its blog: hosts on them match no entry, so set"
        " other_builds: cant_judge when the threat is in every build"
    )
    lines += [f"  {item}" for item in draft.not_covered]
    return "\n".join(lines)


# comparing with a signed pack


def compare(draft: Draft, pack_text: str) -> str:
    """Against a signed pack's packages, matched on release, fixed version and
    binaries: the content that decides a host. Patterns are compared within each
    match, so a pattern drawn wider by rule shows as such, not as a missing entry."""
    import yaml  # only for reading packs

    pack = yaml.safe_load(pack_text) or {}
    signed = (pack.get("exposure") or {}).get("packages") or []

    def key(release, fixed, names):
        return (release, fixed or None, tuple(sorted(names or [])))

    theirs: dict[tuple, list] = {}
    for p in signed:
        theirs.setdefault(key(p.get("release"), p.get("fixed"), p.get("binary_names")), []).append(
            p
        )
    ours: dict[tuple, list] = {}
    for e in draft.entries:
        ours.setdefault(key(e.release, e.fixed, e.binary_names), []).append(e)
    lines = [f"Compared with {pack.get('id')} version {pack.get('version')}:"]
    same = 0
    for k in sorted(set(ours) & set(theirs), key=str):
        mine = sorted(e.versions or "(none)" for e in ours[k])
        signed_patterns = sorted(p.get("versions") or "(none)" for p in theirs[k])
        if mine == signed_patterns:
            same += 1
        else:
            lines.append(
                f"  patterns differ  {k[0]} fixed {k[1]} {list(k[2])}:"
                f" draft {mine} vs signed {signed_patterns}"
            )
    for k in sorted(set(ours) - set(theirs), key=str):
        lines.append(
            f"  draft only  {k[0]} fixed {k[1]} {list(k[2])}"
            f" {sorted(e.versions or '(none)' for e in ours[k])}"
        )
    for k in sorted(set(theirs) - set(ours), key=str):
        p = theirs[k][0]
        lines.append(
            f"  signed only  {k[0]} fixed {k[1]} {list(k[2])}"
            f" {sorted(x.get('versions') or '(none)' for x in theirs[k])}  ({p.get('source')})"
        )
    lines.insert(1, f"  {same} entries the same")
    return "\n".join(lines)
