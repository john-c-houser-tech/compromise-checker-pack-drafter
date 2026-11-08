"""A.3b: proposed entries for third-party builds, for a person to confirm (plan D4).

The vendors' records can't say whether a third-party build is affected, so the
drafter proposes, with the evidence it found, and a person confirms each one.

An unconfirmed proposal still becomes an entry: one that names its binaries under a
pattern no real version matches (`~unconfirmed`). The checker applies
`other_builds: cant_judge` only to binaries some entry on the release names; a
binary named nowhere isn't judged at all, and the host reads "not affected". Named
this way, the builds read "can't judge" until a person confirms the proposal.

- Sury (a Launchpad PPA): for each branch it publishes for a supported Ubuntu
  release, the newest upload's full `debian/changelog`. For every CVE of the threat,
  the oldest entry naming it is its fix; the branch's fix is the latest of those,
  and a CVE never named means no fix found.
- Remi (an RPM repository): per repository and branch, builds in changelog-date
  order; a build is fixed once every CVE has been named in its changelog or an
  earlier build's, or once its upstream version reaches the one Sury says fixed the
  branch (a hint given only by a "New upstream version" entry whose CVE lines aren't
  Debian patches). The metadata keeps only the latest builds and their last three
  changelog entries, so the oldest fixed build listed may be later than the first:
  hosts between the two read "vulnerable", the safe way round.

Where each repository is comes from `thirdparty.toml`, which John approves.
"""

from __future__ import annotations

import bz2
import fnmatch
import gzip
import io
import json
import lzma
import re
import tarfile
import tomllib
import urllib.parse
import xml.etree.ElementTree as ET  # noqa: S405 - fixed hosts, size-capped, expat limits
from dataclasses import dataclass, field

from drafter import candidates
from drafter.feeds import Context, FeedError
from drafter.fill import _PACKAGE, _URL, _VERSION, Entry, _names, keep
from drafter.http import FetchError

LAUNCHPAD = "https://api.launchpad.net/1.0"
SURY_SOURCE = "https://launchpad.net/~{owner}/+archive/ubuntu/{name}"
REMI_BASE = "https://rpms.remirepo.net/enterprise/{major}/{repo}/x86_64/"
MAX_METADATA_BYTES = 256 * 1024 * 1024  # decompressed
UNCONFIRMED = "~unconfirmed"  # a versions pattern no real version matches
SURY_PATTERN = "*+deb.sury.org*"
_REMI_PATTERN = re.compile(r"\d+(?:\.\d+)?\.\*remi\*")
_PPA = re.compile(r"[a-z0-9][a-z0-9+.-]{1,60}/[a-z0-9][a-z0-9+.-]{1,60}")
_REPO = re.compile(r"[a-z0-9][a-z0-9_-]{0,30}")
_CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,9}")
_UPDATE_TO = re.compile(r"[Uu]pdate to (\d+(?:\.\d+)+)")
_ENTRY = re.compile(r"^(\S+) \(([^()\s]+)\) [^;]*; urgency=", re.M)
_NEW_UPSTREAM = re.compile(r"[Nn]ew upstream (?:version|release)")
_PATCH_LINE = re.compile(r"d/patches|debian/patches|cherry-?pick|backport|patch", re.I)
_NEWS_LINE = re.compile(r"^\s*\+\s*[\[(]\s*CVE-\d")
_DIST = re.compile(r"\.(?:el\d|module)")  # where a Remi release's dist part starts
_NS = {
    "common": "http://linux.duke.edu/metadata/common",
    "other": "http://linux.duke.edu/metadata/other",
    "repo": "http://linux.duke.edu/metadata/repo",
}


class ThirdPartyError(ValueError):
    pass


@dataclass(frozen=True)
class Gap:
    """A branch or repository `propose` couldn't read. Its builds aren't named by any
    entry, so a host on one would read "not affected": `fill` says so."""

    key: str
    reason: str

    def __str__(self) -> str:
        return f"{self.key}: {self.reason}; not proposed"


@dataclass
class Proposal:
    key: str  # "sury ubuntu:24.04 php8.3", "remi rhel:9 safe 8.1"
    repository: str  # sury, remi
    release: str
    binary_names: list[str]
    versions: str
    fixed: str | None
    source: str
    evidence: list[str] = field(default_factory=list)
    note: str = ""
    confirm: bool = False


# the watch list's repositories


@dataclass(frozen=True)
class Repositories:
    cpe: str
    sury: dict | None
    remi: dict | None


def load_repositories(text: str | None = None) -> list[Repositories]:
    from importlib import resources

    if text is None:
        text = resources.files("drafter").joinpath("thirdparty.toml").read_text("utf-8")
    out = []
    for item in tomllib.loads(text).get("watch", []):
        sury, remi = item.get("sury"), item.get("remi")
        if sury is not None:
            if not isinstance(sury, dict) or not _PPA.fullmatch(str(sury.get("ppa", ""))):
                raise ThirdPartyError("thirdparty.toml: sury.ppa is owner/name")
            if not isinstance(sury.get("sources"), str):
                raise ThirdPartyError("thirdparty.toml: sury.sources is a glob")
        if remi is not None:
            repos = remi.get("repositories") if isinstance(remi, dict) else None
            packages = remi.get("packages") if isinstance(remi, dict) else None
            if not isinstance(repos, list) or not all(_REPO.fullmatch(str(r)) for r in repos):
                raise ThirdPartyError("thirdparty.toml: remi.repositories are names")
            if not isinstance(packages, list) or not packages:
                raise ThirdPartyError("thirdparty.toml: remi.packages are globs")
        out.append(Repositories(str(item.get("cpe")), sury, remi))
    return out


# versions


def upstream_key(version: str) -> tuple:
    """8.4.27 -> ((2, 8), (2, 4), (2, 27), (1, '')); 8.6.0~rc5 sorts before 8.6.0.
    Every part is a (kind, value) pair, so mixed lengths and letters compare."""
    version = version.split(":", 1)[-1].split("-", 1)[0]
    main, tilde, pre = version.partition("~")
    # A number (2, n) outranks the end of the version (1, ""), which outranks a
    # pre-release (0, "rc5"): 8.4.1.1 > 8.4.1 > 8.4.1~rc5.
    parts = tuple((2, int(p)) if p.isdigit() else (2, -1) for p in re.split(r"[.+]", main) if p)
    return parts + (((0, pre),) if tilde else ((1, ""),))


def branch_of(version: str) -> str:
    parts = version.split(":", 1)[-1].split("-", 1)[0].split("~")[0].split(".")
    return ".".join(parts[:2])


def _clean(text: str, limit: int = 200) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in text.strip())[:limit]


def _mentions(text: str, cves: set[str]) -> list[str]:
    """The changelog lines that name one of the CVEs, cleaned, at most three."""
    lines = [_clean(line) for line in text.splitlines() if set(_CVE_IN_TEXT.findall(line)) & cves]
    return lines[:3]


def _named(text: str, cves: set[str]) -> set[str]:
    return set(_CVE_IN_TEXT.findall(text)) & cves


# Sury, from Launchpad


def _launchpad(ctx: Context, url: str) -> dict:
    answer, _ = ctx.fetch("thirdparty-launchpad", url, max_bytes=16 * 1024 * 1024)
    try:
        data = json.loads(answer.body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise FeedError("Launchpad's answer is not JSON") from None
    if not isinstance(data, dict):
        raise FeedError("Launchpad's answer is not an object")
    return data


def _collection(ctx: Context, url: str, limit: int = 20) -> list[dict]:
    entries: list[dict] = []
    for _ in range(limit):
        data = _launchpad(ctx, url)
        listed = data.get("entries")
        entries += [e for e in listed if isinstance(e, dict)] if isinstance(listed, list) else []
        url = data.get("next_collection_link")
        if not isinstance(url, str) or not url.startswith(LAUNCHPAD + "/"):
            break
    return entries


def _series(ctx: Context) -> dict[str, str]:
    """Ubuntu release (24.04) -> Launchpad series link, supported releases only."""
    out = {}
    for entry in _collection(ctx, f"{LAUNCHPAD}/ubuntu/series"):
        version, link = entry.get("version"), entry.get("self_link")
        if isinstance(version, str) and isinstance(link, str) and link.startswith(LAUNCHPAD):
            if re.fullmatch(r"\d{2}\.\d{2}", version) and candidates.supported(f"ubuntu:{version}"):
                out[version] = link
    return out


def parse_debian_changelog(text: str) -> list[tuple[str, str]]:
    """[(version, the entry's text)], newest first."""
    heads = list(_ENTRY.finditer(text))
    out = []
    for n, head in enumerate(heads):
        end = heads[n + 1].start() if n + 1 < len(heads) else len(text)
        out.append((head.group(2), text[head.end() : end]))
    return out


def sury_fix(changelog: str, cves: set[str]):
    """(the Debian version that fixes every CVE, its entry, every entry naming one)
    from a changelog, or (None, None, entries) if some CVE is never named.

    Each CVE's fix is the oldest entry naming it; the branch is fixed at the latest
    of those. A later entry naming a CVE again ("incomplete fix", "revert") is shown
    in the evidence for the person to read."""
    entries = parse_debian_changelog(changelog)
    naming = [(v, body) for v, body in entries if _named(body, cves)]
    oldest: dict[str, tuple[int, str, str]] = {}  # cve -> (age, version, body)
    for age, (version, body) in enumerate(entries):  # 0 = newest
        for cve in _named(body, cves):
            if cve not in oldest or age > oldest[cve][0]:
                oldest[cve] = (age, version, body)
    if set(oldest) != cves:
        return None, None, naming
    age, version, body = min(oldest.values())  # the newest of the per-CVE fixes
    if len({a for a, _, _ in oldest.values()}) > 1:
        body = None  # the CVEs were fixed in different entries: no single upstream release
    return version, body, naming


def upstream_hint(version: str, body: str, cves: set[str]) -> str | None:
    """The upstream version that fixed a branch, given only by a "New upstream
    version" entry whose CVE lines aren't Debian patches: a backport (8.1.34-9) or a
    patch on top of a new release says nothing about other builds of that version."""
    if body is None or not _NEW_UPSTREAM.search(body):
        return None
    # Only Sury's NEWS bullets ("+ (CVE-…): …", "+ [CVE-…]: …") under a "New upstream
    # version" heading say the new release itself fixed it. Anything else ("Add
    # upstream fix for CVE-…", a bullet under "Backported from 8.3.37") may be a patch
    # on top, which other builds of that version lack.
    heading, naming = None, 0
    for line in body.splitlines():
        if re.match(r"^\s*\*", line):
            heading = line
        if not _named(line, cves):
            continue
        naming += 1
        if (
            not _NEWS_LINE.match(line)
            or _PATCH_LINE.search(line)
            or heading is None
            or not _NEW_UPSTREAM.search(heading)
            or _PATCH_LINE.search(heading)
        ):
            return None
    return version.split(":", 1)[-1].split("-", 1)[0] if naming else None


def sury_proposals(
    ctx: Context, config: dict, cves: set[str], filters: list[str], report: list[str]
) -> tuple[list[Proposal], dict[str, str]]:
    """(proposals, branch -> upstream version that fixed it)."""
    owner, name = config["ppa"].split("/")
    archive = f"{LAUNCHPAD}/~{owner}/+archive/ubuntu/{name}"
    source_url = SURY_SOURCE.format(owner=owner, name=name)
    proposals, fixed_upstream = [], {}
    for version, series in sorted(_series(ctx).items()):
        release = f"ubuntu:{version}"
        query = urllib.parse.urlencode(
            {
                "ws.op": "getPublishedSources",
                "distro_series": series,
                "status": "Published",
                "ws.size": 300,
            }
        )
        branches = sorted(
            {
                e.get("source_package_name")
                for e in _collection(ctx, f"{archive}?{query}")
                if isinstance(e.get("source_package_name"), str)
                and fnmatch.fnmatchcase(e["source_package_name"], config["sources"])
            }
        )
        if not branches:
            report.append(f"Sury: nothing published for {release}")
            continue
        for branch in branches:
            proposal, hint = _sury_branch(
                ctx, archive, series, release, branch, cves, filters, source_url, report
            )
            if proposal:
                proposals.append(proposal)
            if hint:
                fixed_upstream.setdefault(branch_of(hint), hint)
    return proposals, fixed_upstream


def _sury_branch(ctx, archive, series, release, branch, cves, filters, source_url, report):
    query = urllib.parse.urlencode(
        {
            "ws.op": "getPublishedSources",
            "source_name": branch,
            "exact_match": "true",
            "distro_series": series,
            "ws.size": 75,
        }
    )
    uploads = [
        e
        for e in _collection(ctx, f"{archive}?{query}", limit=2)
        if isinstance(e.get("source_package_version"), str)
        and _VERSION.fullmatch(e["source_package_version"])
        and isinstance(e.get("self_link"), str)
        and e["self_link"].startswith(LAUNCHPAD + "/")
    ]
    uploads.sort(key=lambda e: str(e.get("date_published") or e.get("date_created") or ""))
    key = f"sury {release} {branch}"
    if not uploads:
        report.append(Gap(key, "no uploads listed"))
        return None, None
    newest = uploads[-1]
    # The union over the newest three uploads: the newest may still be building, and
    # an older one may lack a binary the newest adds (-litespeed, added in 8.x.30-1).
    names, sources = [], []
    for upload in reversed(uploads[-3:]):
        found = _sury_binaries(ctx, upload, filters, release)
        if found:
            sources.append(upload["source_package_version"])
            names = sorted(set(names) | set(found))
    if not names:
        report.append(
            Gap(
                key,
                f"no binaries published for its newest uploads (to"
                f" {newest['source_package_version']}), or the filter keeps none",
            )
        )
        return None, None
    changelog = _debian_changelog(ctx, newest["self_link"])
    if changelog is None:
        report.append(
            f"Sury {release} {branch}: couldn't read its debian/changelog; proposed unconfirmed"
        )
        return _no_fix(
            key,
            "sury",
            release,
            names,
            SURY_PATTERN,
            source_url,
            ["its debian/changelog couldn't be read"],
            branch,
        ), None
    first_version, first_body, naming = sury_fix(changelog, cves)
    evidence = [f"{v}: {line}" for v, body in naming[:6] for line in _mentions(body, cves)]
    if first_version is None:
        never = sorted(cves - {c for _, body in naming for c in _named(body, cves)})
        return _no_fix(
            key,
            "sury",
            release,
            names,
            SURY_PATTERN,
            source_url,
            [
                f"no entry in {newest['source_package_version']}'s changelog names"
                f" {', '.join(never)}",
                *evidence,
            ],
            branch,
        ), None
    # The upload of that Debian version: Sury appends +ubuntuYY.MM.N+deb.sury.org+N.
    upload = next(
        (u for u in uploads if u["source_package_version"].split("+ubuntu", 1)[0] == first_version),
        None,
    )
    caveat = ""
    if upload is None:
        upload = next(
            (u for u in uploads if u["source_package_version"].startswith(first_version + "+")),
            newest,
        )
        caveat = (
            f"; no upload of {first_version} itself on {release}, so"
            f" {upload['source_package_version']} stands in"
        )
    version = upload["source_package_version"]
    when = str(upload.get("date_published") or "")[:10]
    if sources and sources[0] != newest["source_package_version"]:
        caveat += f"; binary names from {', '.join(sources)} (the newest has none published yet)"
    return Proposal(
        key=key,
        repository="sury",
        release=release,
        binary_names=names,
        versions=SURY_PATTERN,
        fixed=version,
        source=source_url,
        evidence=[f"fix: {first_version}, uploaded here as {version} ({when})", *evidence],
        note=f"{branch}: fixed once every CVE is named in its changelog" + caveat,
    ), upstream_hint(first_version, first_body, cves)


def _no_fix(key, repository, release, names, versions, source, evidence, branch) -> Proposal:
    return Proposal(
        key=key,
        repository=repository,
        release=release,
        binary_names=names,
        versions=versions,
        fixed=None,
        source=source,
        evidence=evidence,
        note=f"{branch}: no fix found. Confirm only if this branch is affected (every build"
        " then reads vulnerable); unconfirmed, its builds read can't judge. If the branch"
        " never had one of the CVEs, write the fix for the others into fixed by hand",
    )


def _debian_changelog(ctx: Context, upload_link: str) -> str | None:
    """debian/changelog from the upload's .debian.tar.*, read in memory."""
    try:
        answer, _ = ctx.fetch(
            "thirdparty-launchpad", f"{upload_link}?ws.op=sourceFileUrls", max_bytes=64 * 1024
        )
        urls = json.loads(answer.body)
    except (FetchError, ValueError, RecursionError):
        return None
    if not isinstance(urls, list):
        return None
    tarballs = [
        u for u in urls if isinstance(u, str) and re.search(r"\.debian\.tar\.(xz|gz|bz2)\Z", u)
    ]
    if not tarballs:
        return None
    try:
        got, _ = ctx.fetch("thirdparty-launchpad", tarballs[0], max_bytes=16 * 1024 * 1024)
        with tarfile.open(fileobj=io.BytesIO(got.body), mode="r:*") as tar:
            member = next(
                (
                    m
                    for m in tar.getmembers()
                    if m.isfile() and m.name in ("debian/changelog", "./debian/changelog")
                ),
                None,
            )
            if member is None or member.size > 8 * 1024 * 1024:
                return None
            handle = tar.extractfile(member)
            return handle.read().decode("utf-8", "replace") if handle else None
    except (FetchError, tarfile.TarError, OSError, EOFError, lzma.LZMAError):
        return None


def _sury_binaries(ctx, upload, filters, release) -> list[str]:
    query = urllib.parse.urlencode({"ws.op": "getPublishedBinaries", "ws.size": 300})
    try:
        entries = _collection(ctx, f"{upload['self_link']}?{query}", limit=5)
    except (FetchError, FeedError):
        return []  # this upload's list is missing: an older one may have it
    names = _names([e.get("binary_package_name") for e in entries])
    return [n for n in names if keep(n, filters, "ubuntu")]


# Remi, from its repository metadata


def _decompress(href: str, body: bytes) -> bytes:
    if href.endswith(".bz2"):
        out = bz2.BZ2Decompressor().decompress(body, MAX_METADATA_BYTES + 1)
    elif href.endswith(".xz"):
        out = lzma.LZMADecompressor().decompress(body, MAX_METADATA_BYTES + 1)
    elif href.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as handle:
            out = handle.read(MAX_METADATA_BYTES + 1)
    elif href.endswith(".xml"):
        out = body
    else:
        raise FeedError(
            f"repository metadata compressed in a way this drafter can't read ({href[-8:]})"
        )
    if len(out) > MAX_METADATA_BYTES:
        raise FeedError("repository metadata too large")
    return out


def _remi_metadata(ctx: Context, major: str, repo: str) -> tuple[list[dict], dict[str, list]]:
    base = REMI_BASE.format(major=major, repo=repo)
    answer, _ = ctx.fetch("thirdparty-remi", base + "repodata/repomd.xml", max_bytes=1024 * 1024)
    hrefs = {}
    for data in ET.fromstring(answer.body).findall("repo:data", _NS):  # noqa: S314
        location = data.find("repo:location", _NS)
        href = location.get("href") if location is not None else None
        if (
            data.get("type") in ("primary", "other")
            and href
            and re.fullmatch(r"repodata/[A-Za-z0-9._-]+", href)
        ):
            hrefs[data.get("type")] = href
    if set(hrefs) != {"primary", "other"}:
        raise FeedError(f"Remi {repo} for EL{major}: no primary or other metadata")
    blobs = {}
    for kind, href in hrefs.items():
        got, _ = ctx.fetch(
            "thirdparty-remi", base + href, max_bytes=64 * 1024 * 1024, keep_body=False
        )
        blobs[kind] = _decompress(href, got.body)
    packages = []
    for pkg in ET.fromstring(blobs["primary"]).findall("common:package", _NS):  # noqa: S314
        version = pkg.find("common:version", _NS)
        checksum = pkg.find("common:checksum", _NS)
        name = pkg.findtext("common:name", namespaces=_NS)
        arch = pkg.findtext("common:arch", namespaces=_NS)
        if version is None or checksum is None or not name or arch not in ("x86_64", "noarch"):
            continue
        packages.append(
            {
                "name": name,
                "epoch": version.get("epoch") or "0",
                "ver": version.get("ver") or "",
                "rel": version.get("rel") or "",
                "pkgid": checksum.text or "",
            }
        )
    changelogs: dict[str, list] = {}
    for pkg in ET.fromstring(blobs["other"]).findall("other:package", _NS):  # noqa: S314
        entries = []
        for c in pkg.findall("other:changelog", _NS):
            date = c.get("date") or "0"
            entries.append((int(date) if date.isdigit() else 0, c.text or ""))
        changelogs[pkg.get("pkgid") or ""] = entries
    return packages, changelogs


def remi_fixed(epoch: str, ver: str, rel: str) -> str:
    """The fixed version as an entry writes it: the release up to its dist part, so
    a fix in 6.1.el9.remi is 8.1.34-6.1, not 8.1.34-6 (which -6 would also reach)."""
    head = _DIST.split(rel, 1)[0]
    return f"{epoch + ':' if epoch not in ('', '0') else ''}{ver}-{head}"


def remi_proposals(
    ctx: Context,
    config: dict,
    cves: set[str],
    filters: list[str],
    fixed_upstream: dict[str, str],
    report: list[str],
) -> list[Proposal]:
    proposals = []
    for major in sorted(candidates.RHEL_MAJORS):
        release = f"rhel:{major}"
        for repo in config["repositories"]:
            try:
                packages, changelogs = _remi_metadata(ctx, major, repo)
            except (FetchError, FeedError, ET.ParseError) as exc:
                report.append(Gap(f"remi {release} {repo}", f"its metadata: {str(exc)[:120]}"))
                continue
            builds: dict[str, dict[tuple, dict]] = {}  # branch -> (ver, rel) -> build
            for p in packages:
                if not any(fnmatch.fnmatchcase(p["name"], g) for g in config["packages"]):
                    continue
                if not _PACKAGE.fullmatch(p["name"]) or not keep(p["name"], filters, "rhel"):
                    continue
                if "remi" not in p["rel"] or not _VERSION.fullmatch(f"{p['ver']}-{p['rel']}"):
                    continue
                build = builds.setdefault(branch_of(p["ver"]), {}).setdefault(
                    (p["ver"], p["rel"]), {"names": set(), "log": [], "epoch": p["epoch"]}
                )
                build["names"].add(p["name"])
                build["log"] = max(build["log"], changelogs.get(p["pkgid"], []), key=len)
            for branch in sorted(builds, key=upstream_key):
                proposals.append(
                    _remi_branch(release, repo, branch, builds[branch], cves, fixed_upstream, major)
                )
    return proposals


def _remi_branch(release, repo, branch, builds, cves, fixed_upstream, major) -> Proposal:
    def when(item):
        return max((d for d, _ in item[1]["log"]), default=0)

    ordered = sorted(builds.items(), key=when)  # oldest first, by changelog date
    names = sorted({n for _, b in ordered for n in b["names"]})
    hint = fixed_upstream.get(branch)
    seen: set[str] = set()
    fixed_build, evidence = None, []
    for (ver, rel), build in ordered:
        text = "\n".join(t for _, t in build["log"])
        seen |= _named(text, cves)
        lines = _mentions(text, cves)
        evidence += [f"{ver}-{rel}: {x}" for x in lines if f"{ver}-{rel}: {x}" not in evidence]
        if seen == cves:
            fixed_build = (ver, rel)
            break
        if hint and "~" not in ver and upstream_key(ver) >= upstream_key(hint):
            update = next((m for m in _UPDATE_TO.finditer(text) if m.group(1) == ver), None)
            said = f'its changelog says "{update.group(0)}"' if update else "by its version"
            fixed_build = (ver, rel)
            evidence.append(
                f"{ver}-{rel}: upstream {ver} reaches {hint}, the new upstream release"
                f" Sury's changelog gives as PHP {branch}'s fix ({said})"
            )
            break
    key = f"remi {release} {repo} {branch}"
    source = f"https://rpms.remirepo.net/enterprise/{major}/{repo}/x86_64/"
    pattern = f"{branch}.*remi*"
    if fixed_build is None:
        newest = ordered[-1][0]
        return _no_fix(
            key,
            "remi",
            release,
            names,
            pattern,
            source,
            [
                f"no build listed ({newest[0]}-{newest[1]} the newest) shows every CVE fixed"
                + (f"; Sury's changelog gives {hint} as PHP {branch}'s fix" if hint else ""),
                *evidence[:6],
            ],
            f"PHP {branch} ({repo})",
        )
    ver, rel = fixed_build
    return Proposal(
        key=key,
        repository="remi",
        release=release,
        binary_names=names,
        versions=pattern,
        fixed=remi_fixed(builds[fixed_build]["epoch"], ver, rel),
        source=source,
        evidence=evidence[:6],
        note=f"PHP {branch} ({repo}): the oldest build listed that has the fix (the"
        " repository keeps only its latest builds, so the first fix may be earlier)",
    )


# the proposals file


def _q(text: str) -> str:
    # A TOML basic string. ensure_ascii=False: JSON would write a character beyond
    # U+FFFF as a surrogate pair, which TOML refuses; control characters stay escaped.
    return json.dumps(text, ensure_ascii=False)


def render(
    proposals: list[Proposal],
    cves: list[str],
    gaps: list[Gap] | None = None,
    run: tuple[int, str] | None = None,
) -> str:
    gaps = gaps or []
    keys = [*(p.key for p in proposals), *(g.key for g in gaps)]
    lines = [
        "# Third-party builds proposed by the pack drafter (A.3b), for a person to confirm.",
        f"# CVEs: {', '.join(cves)}",
        "# Read each one's evidence; set confirm = true to draft it as proposed. An",
        "# unconfirmed one is drafted with a pattern no build matches, so its builds",
        "# read can't judge. `expected` lists every key; one gone, and every [[gap]],",
        "# is named by `drafter fill` as needing a person.",
        f"cves = [{', '.join(_q(c) for c in sorted(cves))}]",
        *([f"run = {int(run[0])}", f"run_token = {_q(run[1])}"] if run is not None else []),
        f"expected = [{', '.join(_q(k) for k in keys)}]",
        "",
    ]
    for g in gaps:
        lines += ["[[gap]]", f"key = {_q(g.key)}", f"reason = {_q(g.reason)}", ""]
    for p in proposals:
        fixed = f"fixed = {_q(p.fixed)}" if p.fixed else 'fixed = ""  # no fix'
        lines += [
            "[[proposal]]",
            f"key = {_q(p.key)}",
            f"confirm = {'true' if p.confirm else 'false'}",
            f"repository = {_q(p.repository)}",
            f"release = {_q(p.release)}",
            f"binary_names = [{', '.join(_q(n) for n in p.binary_names)}]",
            f"versions = {_q(p.versions)}",
            fixed,
            f"source = {_q(p.source)}",
            f"note = {_q(p.note)}",
            f"evidence = [{', '.join(_q(e) for e in p.evidence)}]",
            "",
        ]
    return "\n".join(lines)


_SURY_KEY = re.compile(r"sury (ubuntu:\d{2}\.\d{2}) ([a-z][a-z0-9+-]{0,30}?(\d+\.\d+))")
_REMI_KEY = re.compile(r"remi (rhel:\d{1,2}) ([a-z0-9_-]{1,30}) ((\d+\.\d+))")


def _check(item: dict) -> tuple[str, str, list[str], str, str, str]:
    key = str(item.get("key"))[:80]
    repository, release, names = (
        item.get("repository"),
        item.get("release"),
        item.get("binary_names"),
    )
    versions, fixed, source = item.get("versions"), item.get("fixed"), item.get("source")
    if repository not in ("sury", "remi"):
        raise ThirdPartyError(f"{key}: repository is sury or remi")
    shape = (_SURY_KEY if repository == "sury" else _REMI_KEY).fullmatch(key)
    if not shape or shape.group(1) != release or not candidates.supported(release):
        raise ThirdPartyError(
            f"{key}: the key and release don't agree, or the release isn't supported"
        )
    if (
        not isinstance(names, list)
        or not names
        or not all(isinstance(n, str) and _PACKAGE.fullmatch(n) for n in names)
    ):
        raise ThirdPartyError(f"{key}: binary_names are package names")
    # Only the patterns the drafter writes, for this branch: one that reached another
    # repository's or another branch's builds would judge them against this fix.
    if repository == "sury":
        branch, number = shape.group(2), shape.group(3)
        # The branch as a whole word in each name: php8.3-fpm, libphp8.3-embed, not
        # a key "php" that every branch's names would pass.
        token = re.compile(rf"(?:^|[-_.]|lib){re.escape(branch)}(?:$|[-_.])")
        ok = versions == SURY_PATTERN and all(token.search(n) for n in names)
        home = "https://launchpad.net/~"
    else:
        branch = number = shape.group(3)
        ok = versions == f"{branch}.*remi*"
        home = "https://rpms.remirepo.net/enterprise/"
    if not ok:
        raise ThirdPartyError(f"{key}: versions or binary_names reach beyond the branch {branch}")
    if not isinstance(fixed, str) or (
        fixed and not (_VERSION.fullmatch(fixed) and re.search(r"[^-]-[^-]+\Z", fixed))
    ):
        raise ThirdPartyError(f"{key}: fixed is a version with its revision, or empty for none")
    if fixed and branch_of(fixed) != number:
        # Another branch's fix would judge this branch's builds against it.
        raise ThirdPartyError(f"{key}: fixed {fixed} isn't a {number} version")
    if not isinstance(source, str) or not _URL.fullmatch(source) or not source.startswith(home):
        raise ThirdPartyError(f"{key}: source is {home}…")
    return key, repository, sorted(set(names)), release, versions, fixed


def confirmed_entries(
    text: str, cves: list[str] | None = None, store=None
) -> tuple[list[Entry], int, list[str]]:
    """(entries for every proposal, how many were unconfirmed, problems for a person).

    A confirmed proposal is drafted as proposed; an unconfirmed one names its
    binaries under a pattern no build matches, so they read "can't judge", not "not
    affected". Every field is checked: the file is a person's edit, and may have been
    anyone's. A file written for other CVEs is refused: its fixes may be older than
    this threat's. With the store, the file is also checked against the propose run
    it came from, so a proposal or binaries edited away show."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ThirdPartyError(f"proposals file isn't TOML: {exc}") from None
    problems: list[str] = []
    written_for = data.get("cves")
    if cves is not None:
        if written_for is None:
            problems.append(
                "the proposals file doesn't say which CVEs it was written for: check it is"
                " this threat's"
            )
        elif not isinstance(written_for, list) or sorted(map(str, written_for)) != sorted(cves):
            listed = written_for if isinstance(written_for, list) else [written_for]
            raise ThirdPartyError(
                "the proposals file was written for"
                f" {', '.join(map(str, listed))[:200]}, not"
                f" {', '.join(sorted(cves))}: propose again for this threat"
            )
    proposals = data.get("proposal", [])
    gap_items = data.get("gap", [])
    if not isinstance(proposals, list) or not all(isinstance(p, dict) for p in proposals):
        raise ThirdPartyError("proposals file: each [[proposal]] is a table")
    if not isinstance(gap_items, list) or not all(isinstance(g, dict) for g in gap_items):
        raise ThirdPartyError("proposals file: each [[gap]] is a table")
    entries, unconfirmed = [], 0
    present: dict[str, tuple[list[str], str]] = {}
    for item in proposals:
        key, repository, names, release, versions, fixed = _check(item)
        present[key] = (names, fixed)
        source = item["source"]
        if item.get("confirm") is True:
            entries.append(
                Entry(
                    release=release,
                    binary_names=names,
                    versions=versions,
                    fixed=fixed or None,
                    source=source,
                    origin=repository,
                    note=f"confirmed: {_clean(str(item.get('note', '')), 120)}",
                )
            )
        else:
            unconfirmed += 1
            # Its own pattern, so two unconfirmed branches naming php-fpm don't clash.
            slug = re.sub(r"[^A-Za-z0-9.+_-]", "", key.rsplit(" ", 1)[-1])[:40] or "x"
            entries.append(
                Entry(
                    release=release,
                    binary_names=names,
                    versions=f"{UNCONFIRMED}-{slug}",
                    fixed=None,
                    source=source,
                    origin=repository,
                    note=f"unconfirmed ({_clean(key, 60)}): named so its builds read can't judge",
                )
            )
    gap_keys = {str(g.get("key")) for g in gap_items}
    for gap in gap_items:
        problems.append(
            f"{_clean(str(gap.get('key')), 60)}: propose couldn't read it"
            f" ({_clean(str(gap.get('reason')), 120)}). Its builds aren't named, so a host on one"
            " reads not affected: write its proposal by hand, or propose again"
        )
    expected = data.get("expected")
    if not isinstance(expected, list):
        problems.append("the proposals file has no list of expected keys: check nothing was cut")
    else:
        for key in expected:
            if str(key) not in present and str(key) not in gap_keys:
                problems.append(
                    f"{_clean(str(key), 60)}: in the file's expected keys but its proposal is"
                    " gone. Its builds aren't named, so a host on one reads not affected"
                )
    if store is not None:
        problems += _against_run(
            store, data.get("run"), data.get("run_token"), present, gap_keys, cves
        )
    return entries, unconfirmed, problems


def record_run(
    store, cves: list[str], proposals: list[Proposal], gaps: list[Gap], when: str
) -> tuple[int, str]:
    """Keep what a propose run proposed, names and fixes; the file names the run by
    its id and a random token, so it can't be pointed at another run."""
    import secrets

    token = secrets.token_hex(16)
    proposed = {p.key: {"names": p.binary_names, "fixed": p.fixed} for p in proposals}
    with store.transaction():
        cursor = store.db.execute(
            "INSERT INTO propose_run (created_at, cves, token, proposals, gaps)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                when,
                json.dumps(sorted(cves)),
                token,
                json.dumps(proposed),
                json.dumps([g.key for g in gaps]),
            ),
        )
    return cursor.lastrowid, token


def _against_run(store, run, token, present, gap_keys: set[str], cves) -> list[str]:
    if isinstance(run, bool) or not isinstance(run, int) or not 0 < run < 2**62:
        return ["the proposals file names no propose run: it can't be checked against one"]
    row = store.db.execute(
        "SELECT cves, token, proposals, gaps FROM propose_run WHERE id = ?", (run,)
    ).fetchone()
    if row is None or row["token"] is None or row["token"] != token:
        return [
            f"propose run {run} isn't in this store with this file's token: the file came"
            " from elsewhere, or was pointed at another run; it is checked against itself"
            " only"
        ]
    problems = []
    if cves is not None and json.loads(row["cves"]) != sorted(cves):
        problems.append(f"propose run {run} was for other CVEs: propose again for this threat")
    for key, proposed in json.loads(row["proposals"]).items():
        names, fixed = proposed["names"], proposed["fixed"]
        if key not in present:
            if key not in gap_keys:
                problems.append(
                    f"{_clean(key, 60)}: proposed in run {run} but not in the file. Its builds"
                    " aren't named, so a host on one reads not affected"
                )
            continue
        here_names, here_fixed = present[key]
        if set(names) - set(here_names):
            gone = ", ".join(sorted(set(names) - set(here_names)))[:120]
            problems.append(
                f"{_clean(key, 60)}: binaries proposed in run {run} are gone from the file"
                f" ({gone}); a host with one reads not affected"
            )
        if (here_fixed or None) != fixed:
            problems.append(
                f"{_clean(key, 60)}: fixed edited by hand, from {fixed or 'none'} to"
                f" {_clean(here_fixed, 80) or 'none'}. Check it: an earlier fix would make"
                " vulnerable builds between the two read fixed"
            )
    return problems


def propose(ctx: Context, cves: list[str], filters: list[str], cpe: str | None = None):
    """(proposals, report lines) for the watched products these CVEs touch."""
    from drafter.fill import check_filter

    check_filter(filters)
    repositories = load_repositories()
    if cpe:
        chosen = [r for r in repositories if r.cpe == cpe]
    else:
        watched = watched_cpes(ctx, cves)
        chosen = [r for r in repositories if r.cpe in watched]
    if not chosen:
        raise ThirdPartyError(
            "no watched product for these CVEs (thirdparty.toml); name one with --watch"
        )
    wanted = set(cves)
    report, proposals = [], []
    for repo in chosen:
        fixed_upstream: dict[str, str] = {}
        if repo.sury:
            found, fixed_upstream = sury_proposals(ctx, repo.sury, wanted, filters, report)
            proposals += found
        if repo.remi:
            proposals += remi_proposals(ctx, repo.remi, wanted, filters, fixed_upstream, report)
    gaps = [g for g in report if isinstance(g, Gap)]
    notes = [str(r) for r in report if not isinstance(r, Gap)]
    return proposals, notes, gaps


def watched_cpes(ctx: Context, cves: list[str]) -> set[str]:
    watch = candidates.load_watch()
    found = set()
    for cve in cves:
        row = ctx.store.db.execute(
            "SELECT products, description FROM nvd WHERE cve = ?", (cve,)
        ).fetchone()
        kev = ctx.store.db.execute(
            "SELECT vendor, product FROM kev WHERE cve = ?", (cve,)
        ).fetchone()
        products = json.loads(row[0]) if row else []
        kev_name = " ".join(x for x in (kev or ()) if x) or None
        names, _, _ = candidates._watched(products, row[1] if row else None, watch, kev_name)
        found.update(names)
    return found


def unknown_cves(ctx: Context, cves: list[str]) -> list[str]:
    """CVEs the store has neither an NVD nor a CISA row for: whether they touch a
    watched product can't be told from here."""
    out = []
    for cve in cves:
        nvd = ctx.store.db.execute("SELECT 1 FROM nvd WHERE cve = ?", (cve,)).fetchone()
        kev = ctx.store.db.execute("SELECT 1 FROM kev WHERE cve = ?", (cve,)).fetchone()
        if not nvd and not kev:
            out.append(cve)
    return out


def has_repositories(ctx: Context, cves: list[str]) -> list[str]:
    """Watched products these CVEs touch whose third-party builds `propose` reads."""
    watched = watched_cpes(ctx, cves)
    return [r.cpe for r in load_repositories() if r.cpe in watched and (r.sury or r.remi)]
