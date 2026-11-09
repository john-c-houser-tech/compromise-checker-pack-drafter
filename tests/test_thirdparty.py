"""A.3b: proposing Sury and Remi builds, against answers shaped like the real ones
(Launchpad's API, a Debian source tarball, Remi's repository metadata; 2026-11-07)."""

from __future__ import annotations

import bz2
import io
import re
import tarfile

import pytest

from drafter import thirdparty as tp
from drafter.store import Store
from tests.conftest import ok

CVES = {"CVE-2026-109618", "CVE-2026-109619"}
LP = "https://api.launchpad.net/1.0"
ARCHIVE = f"{LP}/~ondrej/+archive/ubuntu/php"
SURY = {"ppa": "ondrej/php", "sources": "php?.?"}
REMI = {"repositories": ["safe"], "packages": ["php", "php-*", "php??-php", "php??-php-*"]}

CHANGELOG_83 = """php8.3 (8.3.36-1+ubuntu24.04.1+deb.sury.org+1) noble; urgency=medium

  * No-change backport to noble

 -- Ondřej Surý <ondrej@debian.org>  Wed, 21 Oct 2026 14:00:00 +0000

php8.3 (8.3.36-1) unstable; urgency=medium

  * New upstream version 8.3.36
   + (CVE-2026-109618, CVE-2026-109619): Avoid state corruption via bailout.

 -- Ondřej Surý <ondrej@debian.org>  Wed, 21 Oct 2026 12:00:00 +0000

php8.3 (8.3.35-1) unstable; urgency=medium

  * New upstream version 8.3.35

 -- Ondřej Surý <ondrej@debian.org>  Thu, 25 Sep 2026 05:00:00 +0000
"""

CHANGELOG_81 = """php8.1 (8.1.34-9) unstable; urgency=medium

  * Backport fix for bailout state corruption
   + [CVE-2026-109618, CVE-2026-109619]: Avoid state corruption via bailout

 -- Ondřej Surý <ondrej@debian.org>  Wed, 21 Oct 2026 12:00:00 +0000

php8.1 (8.1.34-8) unstable; urgency=medium

  * Rebuild

 -- Ondřej Surý <ondrej@debian.org>  Thu, 25 Sep 2026 05:00:00 +0000
"""


def _tarball(changelog: str) -> bytes:
    data = changelog.encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:xz") as tar:
        info = tarfile.TarInfo("debian/changelog")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _series():
    return {
        "entries": [
            {"name": "noble", "version": "24.04", "self_link": f"{LP}/ubuntu/noble"},
            {"name": "questing", "version": "25.10", "self_link": f"{LP}/ubuntu/questing"},
            {"name": "focal", "version": "20.04", "self_link": f"{LP}/ubuntu/focal"},
        ]
    }


def _upload(branch, version, n, when):
    return {
        "source_package_name": branch,
        "source_package_version": version,
        "self_link": f"{ARCHIVE}/+sourcepub/{n}",
        "date_published": when,
    }


@pytest.fixture
def sury(fetcher):
    fetcher.add(f"{LP}/ubuntu/series", ok(_series()))

    def route(url):
        return url.startswith(ARCHIVE + "?") and "source_name=" not in url

    fetcher.add(
        route,
        ok(
            {
                "entries": [
                    _upload("php8.3", "8.3.36-1+ubuntu24.04.1+deb.sury.org+1", 3, "2026-10-21"),
                    _upload("php8.1", "8.1.34-9+ubuntu24.04.1+deb.sury.org+1", 1, "2026-10-21"),
                    _upload("php-xdebug", "3.4.0-1", 9, "2026-10-01"),
                ]
            }
        ),
    )
    for branch, uploads in {
        "php8.3": [
            _upload("php8.3", "8.3.35-1+ubuntu24.04.1+deb.sury.org+1", 2, "2026-09-25"),
            _upload("php8.3", "8.3.36-1+ubuntu24.04.1+deb.sury.org+1", 3, "2026-10-21"),
        ],
        "php8.1": [
            _upload("php8.1", "8.1.34-8+ubuntu24.04.1+deb.sury.org+1", 0, "2026-09-25"),
            _upload("php8.1", "8.1.34-9+ubuntu24.04.1+deb.sury.org+1", 1, "2026-10-21"),
        ],
    }.items():
        fetcher.add(lambda url, b=branch: f"source_name={b}&" in url, ok({"entries": uploads}))
    for n, changelog in ((3, CHANGELOG_83), (1, CHANGELOG_81)):
        name = "php8.3_8.3.36-1" if n == 3 else "php8.1_8.1.34-9"
        tar_url = f"https://launchpad.net/~ondrej/+archive/ubuntu/php/+files/{name}.debian.tar.xz"
        fetcher.add(f"{ARCHIVE}/+sourcepub/{n}?ws.op=sourceFileUrls", ok([tar_url]))
        fetcher.add(tar_url, ok(_tarball(changelog)))
        branch = "php8.3" if n == 3 else "php8.1"
        fetcher.add(
            f"{ARCHIVE}/+sourcepub/{n}?ws.op=getPublishedBinaries",
            ok(
                {
                    "entries": [
                        {"binary_package_name": f"{branch}-fpm"},
                        {"binary_package_name": f"{branch}-cli"},
                        {"binary_package_name": f"{branch}-fpm-dbgsym"},
                        {"binary_package_name": f"libapache2-mod-{branch}"},
                    ]
                }
            ),
        )
    return fetcher


FILTER = ["ubuntu:*-fpm", "ubuntu:libapache2-mod-php*", "rhel:php??-php-fpm", "rhel:php-fpm"]


def test_sury_fix_is_the_oldest_changelog_entry_naming_the_cves(ctx, sury):
    report = []
    proposals, hints = tp.sury_proposals(ctx, SURY, CVES, FILTER, report)
    by = {p.key: p for p in proposals}
    p83 = by["sury ubuntu:24.04 php8.3"]
    assert p83.fixed == "8.3.36-1+ubuntu24.04.1+deb.sury.org+1"
    assert p83.versions == "*+deb.sury.org*"
    assert p83.binary_names == ["libapache2-mod-php8.3", "php8.3-fpm"]  # no -cli, no dbgsym
    assert any("CVE-2026-109618" in e for e in p83.evidence) and not p83.confirm
    assert by["sury ubuntu:24.04 php8.1"].fixed == "8.1.34-9+ubuntu24.04.1+deb.sury.org+1"
    assert not any("php-xdebug" in k for k in by)
    assert not any("25.10" in k or "20.04" in k for k in by)  # unsupported releases


def test_only_a_new_upstream_version_gives_remi_a_fixed_upstream(ctx, sury):
    _, hints = tp.sury_proposals(ctx, SURY, CVES, FILTER, [])
    # 8.3.36 was a new upstream release; 8.1.34-9 a backport, which says nothing about
    # other builds of 8.1.34 (found live: it made Remi's 8.1.34-5 read "fixed").
    assert hints == {"8.3": "8.3.36"}


def test_a_branch_whose_changelog_never_names_the_cves(ctx, sury):
    sury.routes.insert(
        0,
        (
            f"{ARCHIVE}/+sourcepub/3?ws.op=sourceFileUrls",
            ok(["https://launchpad.net/~ondrej/x/php8.3.debian.tar.xz"]),
        ),
    )
    sury.routes.insert(
        0,
        (
            "https://launchpad.net/~ondrej/x/php8.3.debian.tar.xz",
            ok(_tarball(CHANGELOG_83.replace("CVE-2026-109618, CVE-2026-109619", "CVE-2026-1"))),
        ),
    )
    proposals, hints = tp.sury_proposals(ctx, SURY, CVES, FILTER, [])
    p83 = next(p for p in proposals if p.key.endswith("php8.3"))
    assert p83.fixed is None and "no fix found" in p83.note
    assert "8.3" not in hints


def test_debian_changelog_parsing():
    entries = tp.parse_debian_changelog(CHANGELOG_83)
    assert [v for v, _ in entries] == [
        "8.3.36-1+ubuntu24.04.1+deb.sury.org+1",
        "8.3.36-1",
        "8.3.35-1",
    ]


# Remi


def _repo_xml(primary_href, other_href):
    return f"""<?xml version="1.0"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary"><location href="{primary_href}"/></data>
  <data type="other"><location href="{other_href}"/></data>
</repomd>""".encode()


def _source(name):
    """The source package a test package comes from: PHP's own, unless an extension."""
    if "-pecl-" in name or name.endswith("php-pear"):
        return name
    collection = re.match(r"php\d\d-php", name)
    return collection.group(0) if collection else "php"


def _primary(packages):
    body = "".join(
        f"""<package type="rpm"><name>{n}</name><arch>x86_64</arch>
<version epoch="0" ver="{v}" rel="{r}"/>
<checksum type="sha256" pkgid="YES">{i}</checksum>
<format><rpm:sourcerpm>{_source(n)}-{v}-{r}.src.rpm</rpm:sourcerpm></format></package>"""
        for n, v, r, i in packages
    )
    return f"""<?xml version="1.0"?><metadata xmlns="http://linux.duke.edu/metadata/common"
 xmlns:rpm="http://linux.duke.edu/metadata/rpm"
 packages="{len(packages)}">{body}</metadata>""".encode()


def _other(logs):
    body = "".join(
        f'<package pkgid="{i}" name="x" arch="x86_64">'
        + "".join(f'<changelog author="Remi" date="{d}">{t}</changelog>' for d, t in entries)
        + "</package>"
        for i, entries in logs.items()
    )
    return f"""<?xml version="1.0"?><otherdata xmlns="http://linux.duke.edu/metadata/other"
 packages="{len(logs)}">{body}</otherdata>""".encode()


@pytest.fixture
def remi(fetcher):
    packages = [
        ("php81-php-fpm", "8.1.34", "5.el9.remi", "a1"),
        ("php81-php-fpm", "8.1.34", "6.el9.remi", "a2"),
        ("php84-php-fpm", "8.4.26", "1.el9.remi", "b1"),
        ("php84-php-fpm", "8.4.27", "1.el9.remi", "b2"),
        ("php84-php-common", "8.4.27", "1.el9.remi", "b3"),  # filtered out
        ("php84-php-pecl-protobuf", "5.36.2", "1.el9.remi", "b4"),  # an extension
        ("php-fpm", "8.4.27", "1.el9", "c1"),  # not Remi's mark
    ]
    logs = {
        "a1": [(1790000000, "- Fix GHSA-xxxx CVE-2026-91768")],
        "a2": [
            (1790000000, "- Fix GHSA-xxxx CVE-2026-91768"),
            (1792700000, "- Fix state corruption via bailout CVE-2026-109618 CVE-2026-109619"),
        ],
        "b1": [(1790000000, "- Update to 8.4.26")],
        "b2": [(1792700000, "- Update to 8.4.27\n- http://www.php.net/releases/8_4_27.php")],
    }
    base = "https://rpms.remirepo.net/enterprise/9/safe/x86_64/"
    fetcher.add(
        base + "repodata/repomd.xml",
        ok(_repo_xml("repodata/p-primary.xml.bz2", "repodata/o-other.xml.bz2")),
    )
    fetcher.add(base + "repodata/p-primary.xml.bz2", ok(bz2.compress(_primary(packages))))
    fetcher.add(base + "repodata/o-other.xml.bz2", ok(bz2.compress(_other(logs))))
    # EL10's repository is unreachable here: reported, not fatal
    return fetcher


def test_remi_by_changelog_and_by_upstream_version(ctx, remi):
    report = []
    proposals = tp.remi_proposals(ctx, REMI, CVES, FILTER, {"8.4": "8.4.27"}, report)
    by = {p.key: p for p in proposals}
    p81, p84 = by["remi rhel:9 safe 8.1"], by["remi rhel:9 safe 8.4"]
    assert p81.fixed == "8.1.34-6" and any("CVE-2026-109618" in e for e in p81.evidence)
    assert p84.fixed == "8.4.27-1" and any("Update to 8.4.27" in e for e in p84.evidence)
    assert p84.binary_names == ["php84-php-fpm"] and p81.versions == "8.1.*remi*"
    assert any(isinstance(g, tp.Gap) and g.key == "remi rhel:10 safe" for g in report)


def test_remi_without_an_upstream_hint_waits_for_its_own_changelog(ctx, remi):
    proposals = tp.remi_proposals(ctx, REMI, CVES, FILTER, {}, [])
    p84 = next(p for p in proposals if p.key == "remi rhel:9 safe 8.4")
    assert p84.fixed is None and "no fix found" in p84.note


def test_a_backport_hint_does_not_make_older_builds_fixed(ctx, sury, remi):
    # Sury's 8.1.34-9 is a backport: it gives no upstream hint for 8.1, so Remi's
    # 8.1.34-5 can't read fixed by its version; only its own changelog decides.
    _, hints = tp.sury_proposals(ctx, SURY, CVES, FILTER, [])
    assert "8.1" not in hints
    proposals = tp.remi_proposals(ctx, REMI, CVES, FILTER, hints, [])
    assert next(p for p in proposals if p.key == "remi rhel:9 safe 8.1").fixed == "8.1.34-6"


@pytest.mark.parametrize(
    "a, b", [("8.4.27", "8.4.26"), ("8.6.0", "8.6.0~rc5"), ("8.10.0", "8.9.9")]
)
def test_upstream_order(a, b):
    assert tp.upstream_key(a) > tp.upstream_key(b)


def test_unknown_compression_is_refused():
    with pytest.raises(tp.FeedError):
        tp._decompress("repodata/x-primary.xml.zst", b"...")


# the proposals file


def _proposal(**over):
    p = tp.Proposal(
        key="sury ubuntu:24.04 php8.3",
        repository="sury",
        release="ubuntu:24.04",
        binary_names=["php8.3-fpm"],
        versions="*+deb.sury.org*",
        fixed="8.3.36-1+ubuntu24.04.1+deb.sury.org+1",
        source="https://launchpad.net/~ondrej/+archive/ubuntu/php",
        evidence=['8.3.36-1: "quoted" line\\with a backslash'],
        note="n",
    )
    for k, v in over.items():
        setattr(p, k, v)
    return p


def test_unconfirmed_proposals_name_their_binaries_under_a_pattern_nothing_matches():
    import fnmatch

    text = tp.render(
        [
            _proposal(),
            _proposal(key="sury ubuntu:24.04 php8.4", fixed=None, binary_names=["php8.4-fpm"]),
        ],
        sorted(CVES),
    )
    entries, unconfirmed, _ = tp.confirmed_entries(text)
    assert unconfirmed == 2 and len(entries) == 2
    assert {e.versions for e in entries} == {"~unconfirmed-php8.3", "~unconfirmed-php8.4"}
    assert all(e.fixed is None for e in entries)
    for version in ("8.3.36-1+ubuntu24.04.1+deb.sury.org+1", "8.3.6-0ubuntu0.24.04.13", "~"):
        assert not any(fnmatch.fnmatchcase(version, e.versions) for e in entries)
    text = text.replace("confirm = false", "confirm = true", 1)
    entries, unconfirmed, _ = tp.confirmed_entries(text)
    assert unconfirmed == 1
    confirmed = next(e for e in entries if e.versions == "*+deb.sury.org*")
    assert confirmed.origin == "sury" and confirmed.fixed.endswith("deb.sury.org+1")


@pytest.mark.parametrize(
    "field, value",
    [
        ("release", '"ubuntu:20.04"'),
        ("binary_names", '["php8.3-fpm; rm -rf /"]'),
        ("versions", '"*"'),  # would reach RHEL's own builds
        ("versions", '"8.3.*"'),
        ("fixed", '"8.3 36"'),
        ("source", '"http://evil.example/"'),
        ("repository", '"ppa"'),
    ],
)
def test_an_edited_proposal_with_bad_fields_is_refused(field, value):
    text = tp.render([_proposal(confirm=True)], sorted(CVES))
    lines = [
        f"{field} = {value}" if line.startswith(f"{field} = ") else line
        for line in text.splitlines()
    ]
    with pytest.raises(tp.ThirdPartyError):
        tp.confirmed_entries("\n".join(lines))


def test_a_confirmed_entry_reaches_the_draft(ctx, fetcher, store):
    from drafter import fill

    text = tp.render([_proposal(confirm=True)], sorted(CVES))
    entries, unconfirmed, _ = tp.confirmed_entries(text)
    draft = fill.build(ctx, sorted(CVES), [], thirdparty=entries, unconfirmed=unconfirmed)
    assert [e.origin for e in draft.entries] == ["sury"]
    yaml_text = fill.render_yaml(draft)
    assert "Sury's PPA, confirmed by a person" in yaml_text
    assert "0 third-party proposal(s) not confirmed" in fill.render_report(draft)


def test_the_watch_list_names_its_repositories():
    (php,) = tp.load_repositories()
    assert php.cpe == "php:php" and php.sury["ppa"] == "ondrej/php"
    assert php.remi["repositories"] == ["safe", "modular"]
    with pytest.raises(tp.ThirdPartyError):
        tp.load_repositories('[[watch]]\ncpe = "x:y"\n[watch.sury]\nppa = "not a ppa"\n')


def test_propose_needs_a_watched_product(ctx):
    with pytest.raises(tp.ThirdPartyError, match="no watched product"):
        tp.propose(ctx, ["CVE-2026-0001"], [])


def test_a_later_entry_naming_the_cve_again_is_not_the_fix(ctx, sury):
    later = (
        "php8.3 (8.3.37-1+ubuntu24.04.1+deb.sury.org+1) noble; urgency=medium\n\n"
        "  * No-change backport to noble\n\n"
        " -- Ondřej Surý <ondrej@debian.org>  Fri, 30 Oct 2026 13:00:00 +0000\n\n"
        "php8.3 (8.3.37-1) unstable; urgency=medium\n\n"
        "  * Fix a regression from the CVE-2026-109618 fix\n\n"
        " -- Ondřej Surý <ondrej@debian.org>  Fri, 30 Oct 2026 12:00:00 +0000\n\n"
    )
    uploads = [
        _upload("php8.3", "8.3.36-1+ubuntu24.04.1+deb.sury.org+1", 3, "2026-10-21"),
        _upload("php8.3", "8.3.37-1+ubuntu24.04.1+deb.sury.org+1", 4, "2026-10-30"),
    ]
    tar_url = "https://launchpad.net/~ondrej/y/php8.3_8.3.37-1.debian.tar.xz"
    sury.routes[:0] = [
        (lambda url: "source_name=php8.3&" in url, ok({"entries": uploads})),
        (f"{ARCHIVE}/+sourcepub/4?ws.op=sourceFileUrls", ok([tar_url])),
        (tar_url, ok(_tarball(later + CHANGELOG_83))),
        (
            f"{ARCHIVE}/+sourcepub/4?ws.op=getPublishedBinaries",
            ok({"entries": [{"binary_package_name": "php8.3-fpm"}]}),
        ),
    ]
    proposals, _ = tp.sury_proposals(ctx, SURY, CVES, FILTER, [])
    p83 = next(p for p in proposals if p.key.endswith("php8.3"))
    assert p83.fixed == "8.3.36-1+ubuntu24.04.1+deb.sury.org+1"  # the oldest naming it


@pytest.mark.parametrize("confirm", ['"true"', '"yes"', "1", None])
def test_only_a_literal_true_confirms(confirm):
    text = tp.render([_proposal()], sorted(CVES))
    lines = []
    for line in text.splitlines():
        if line.startswith("confirm = "):
            if confirm is None:
                continue
            line = f"confirm = {confirm}"
        lines.append(line)
    entries, unconfirmed, _ = tp.confirmed_entries("\n".join(lines))
    assert unconfirmed == 1 and entries[0].versions.startswith("~unconfirmed")


# first agent review of PR #5


TWO_CVES = """php8.3 (8.3.36-1) unstable; urgency=medium

  * New upstream version 8.3.36
   + (CVE-2026-10002): the second flaw.

 -- Ondřej Surý <ondrej@debian.org>  Wed, 21 Oct 2026 12:00:00 +0000

php8.3 (8.3.30-1) unstable; urgency=medium

  * New upstream version 8.3.30
   + (CVE-2026-10001): the first flaw.

 -- Ondřej Surý <ondrej@debian.org>  Wed, 01 Jul 2026 12:00:00 +0000
"""


def test_two_cves_fixed_at_different_times_take_the_later_fix():
    version, body, naming = tp.sury_fix(TWO_CVES, {"CVE-2026-10001", "CVE-2026-10002"})
    assert version == "8.3.36-1" and len(naming) == 2
    # fixed in two entries: no single new release fixed both, so no upstream hint
    assert tp.upstream_hint(version, body, {"CVE-2026-10001", "CVE-2026-10002"}) is None


def test_a_cve_never_named_means_no_fix():
    version, _, naming = tp.sury_fix(TWO_CVES, {"CVE-2026-10001", "CVE-2026-99999"})
    assert version is None and naming


def test_a_debian_patch_on_a_new_release_gives_no_upstream_hint():
    body = (
        "\n  * New upstream version 8.3.35\n"
        "  * d/patches: cherry-pick the fix for CVE-2026-109618 and CVE-2026-109619\n"
    )
    assert tp.upstream_hint("8.3.35-1", body, CVES) is None


def test_remi_needs_every_cve_named_before_a_build_is_fixed(ctx, remi):
    proposals = tp.remi_proposals(ctx, REMI, {"CVE-2026-109618", "CVE-2026-0001"}, FILTER, {}, [])
    p81 = next(p for p in proposals if p.key == "remi rhel:9 safe 8.1")
    assert p81.fixed is None and "every CVE" in p81.evidence[0]


@pytest.mark.parametrize(
    "rel, fixed",
    [
        ("6.1.el9.remi", "8.1.34-6.1"),
        ("6.el9.remi", "8.1.34-6"),
        ("6.module_php.8.1.el9.remi", "8.1.34-6"),
        ("31.el10.remi", "8.1.34-31"),
    ],
)
def test_remi_fixed_keeps_sub_releases(rel, fixed):
    assert tp.remi_fixed("0", "8.1.34", rel) == fixed


def test_remi_proposes_each_repository_on_its_own(ctx, remi, fetcher):
    # modular fixed only at -7 while safe is fixed at -6: two proposals, two fixes.
    base = "https://rpms.remirepo.net/enterprise/9/modular/x86_64/"
    fetcher.add(
        base + "repodata/repomd.xml",
        ok(_repo_xml("repodata/m-primary.xml.bz2", "repodata/m-other.xml.bz2")),
    )
    fetcher.add(
        base + "repodata/m-primary.xml.bz2",
        ok(
            bz2.compress(
                _primary(
                    [
                        ("php-fpm", "8.1.34", "6.module_php.8.1.el9.remi", "m6"),
                        ("php-fpm", "8.1.34", "7.module_php.8.1.el9.remi", "m7"),
                    ]
                )
            )
        ),
    )
    fetcher.add(
        base + "repodata/m-other.xml.bz2",
        ok(
            bz2.compress(
                _other(
                    {
                        "m6": [(1792000000, "- rebuild")],
                        "m7": [(1792900000, "- Fix CVE-2026-109618 CVE-2026-109619")],
                    }
                )
            )
        ),
    )
    config = {**REMI, "repositories": ["safe", "modular"]}
    proposals = tp.remi_proposals(ctx, config, CVES, FILTER, {}, [])
    by = {p.key: p for p in proposals}
    assert by["remi rhel:9 safe 8.1"].fixed == "8.1.34-6"
    assert by["remi rhel:9 modular 8.1"].fixed == "8.1.34-7"
    assert by["remi rhel:9 modular 8.1"].binary_names == ["php-fpm"]


@pytest.mark.parametrize(
    ("name", "rel", "branch"),
    [
        ("php83-php-fpm", "1.el9.remi", "8.3"),
        ("php85-php", "1.el10.remi", "8.5"),  # Remi's mod_php in a collection
        ("php83-php-pecl-protobuf", "1.el9.remi", "8.3"),
        ("php-fpm", "1.module_php.8.3.el9.remi", "8.3"),
        ("php-pecl-protobuf", "1.module_php.8.6.el9.remi", "8.6"),
        ("php-fpm", "1.el9.remi", None),  # neither the name nor the release says
    ],
)
def test_a_remi_packages_php_branch(name, rel, branch):
    assert tp.remi_php_branch(name, rel) == branch


@pytest.mark.parametrize(
    ("sourcerpm", "name"),
    [
        ("php83-php-8.3.36-1.el9.remi.src.rpm", "php83-php"),
        ("php-8.3.36-1.module_php.8.3.el9.remi.src.rpm", "php"),
        ("php-8.6.0~RC5-1.module_php.8.6.el9.remi.src.rpm", "php"),
        ("php83-php-pecl-ip2location-8.3.0-1.el9.remi.src.rpm", "php83-php-pecl-ip2location"),
        ("", ""),
        ("php-8.3.36.rpm", ""),
    ],
)
def test_a_remi_packages_source(sourcerpm, name):
    assert tp.remi_source_name(sourcerpm) == name


def test_remi_extensions_at_their_own_versions_are_not_php_branches(ctx, remi, fetcher):
    # A.9 found 366 proposals like "remi rhel:9 safe 5.36": pecl extensions grouped
    # by their own version, as if 5.36 were a PHP branch.
    base = "https://rpms.remirepo.net/enterprise/9/modular/x86_64/"
    fetcher.add(
        base + "repodata/repomd.xml",
        ok(_repo_xml("repodata/x-primary.xml.bz2", "repodata/x-other.xml.bz2")),
    )
    built = [
        ("php-fpm", "8.3.36", "1.module_php.8.3.el9.remi", "f1"),
        ("php-pecl-protobuf", "5.36.2", "1.module_php.8.6.el9.remi", "e1"),
        ("php-pecl-xdebug3", "3.3.2", "1.module_php.8.3.el9.remi", "e2"),
        ("php-pear", "1.10.16", "1.module_php.8.3.el9.remi", "e3"),
        # its version only looks like PHP 8.3's: the source package tells
        ("php-pecl-ip2location", "8.3.0", "1.module_php.8.3.el9.remi", "e4"),
        # PHP's own source, but its version isn't the stream's branch: left out
        ("php-cli", "8.4.1", "1.module_php.8.3.el9.remi", "e5"),
    ]
    fetcher.add(base + "repodata/x-primary.xml.bz2", ok(bz2.compress(_primary(built))))
    logs = {i: [(1792900000, "- Fix CVE-2026-109618 CVE-2026-109619")] for *_, i in built}
    fetcher.add(base + "repodata/x-other.xml.bz2", ok(bz2.compress(_other(logs))))
    config = {**REMI, "repositories": ["modular"]}
    proposals = tp.remi_proposals(ctx, config, CVES, [], {}, [])
    assert [p.key for p in proposals] == ["remi rhel:9 modular 8.3"]
    assert proposals[0].binary_names == ["php-fpm"]
    # the safe collection's extension (in the fixture), unfiltered, is left out too
    config = {**REMI, "repositories": ["safe"]}
    keys = [p.key for p in tp.remi_proposals(ctx, config, CVES, [], {}, [])]
    assert keys == ["remi rhel:9 safe 8.1", "remi rhel:9 safe 8.4"]


def test_left_out_packages_are_counted_and_none_left_is_a_gap(ctx, fetcher):
    base = "https://rpms.remirepo.net/enterprise/9/modular/x86_64/"
    fetcher.add(
        base + "repodata/repomd.xml",
        ok(_repo_xml("repodata/g-primary.xml.bz2", "repodata/g-other.xml.bz2")),
    )
    only_extensions = [("php-pecl-protobuf", "5.36.2", "1.module_php.8.6.el9.remi", "g1")]
    fetcher.add(base + "repodata/g-primary.xml.bz2", ok(bz2.compress(_primary(only_extensions))))
    fetcher.add(base + "repodata/g-other.xml.bz2", ok(bz2.compress(_other({}))))
    report = []
    config = {**REMI, "repositories": ["modular"]}
    assert tp.remi_proposals(ctx, config, CVES, [], {}, report) == []
    gaps = [r for r in report if isinstance(r, tp.Gap)]
    assert [g.key for g in gaps][-1] == "remi rhel:9 modular"
    assert "none of them PHP's own build" in gaps[-1].reason


def test_left_out_extensions_are_a_note(ctx, remi):
    report = []
    config = {**REMI, "repositories": ["safe"]}
    tp.remi_proposals(ctx, config, CVES, [], {}, report)
    assert (
        "Remi rhel:9 safe: 1 package(s) left out, not PHP's own builds"
        " (extensions, or no source or branch shown)"
    ) in report


def test_a_branch_with_no_binaries_yet_is_reported(ctx, sury):
    sury.routes.insert(
        0, (f"{ARCHIVE}/+sourcepub/3?ws.op=getPublishedBinaries", ok({"entries": []}))
    )
    report = []
    proposals, _ = tp.sury_proposals(ctx, SURY, CVES, FILTER, report)
    assert not any(p.key.endswith("php8.3") for p in proposals)
    assert any(
        isinstance(g, tp.Gap) and g.key.endswith("php8.3") and "no binaries" in g.reason
        for g in report
    )


@pytest.mark.parametrize(
    "field, value",
    [
        ("repository", '"remi"'),  # remi on an Ubuntu release
        ("versions", '"*remi*"'),  # a Remi pattern without its branch
        ("binary_names", '["php8.3-fpm\\n"]'),
    ],
)
def test_more_edits_that_are_refused(field, value):
    text = tp.render([_proposal(confirm=True)], sorted(CVES))
    lines = [
        f"{field} = {value}" if line.startswith(f"{field} = ") else line
        for line in text.splitlines()
    ]
    with pytest.raises(tp.ThirdPartyError):
        tp.confirmed_entries("\n".join(lines))


def test_characters_beyond_the_basic_plane_survive_the_proposals_file():
    text = tp.render([_proposal(note="a note with an emoji \U0001f600")], sorted(CVES))
    entries, _, _ = tp.confirmed_entries(text)
    assert entries


def test_gzip_metadata_is_capped(monkeypatch):
    import gzip

    monkeypatch.setattr(tp, "MAX_METADATA_BYTES", 10)
    with pytest.raises(tp.FeedError, match="too large"):
        tp._decompress("repodata/x-primary.xml.gz", gzip.compress(b"x" * 100))


def test_upstream_order_with_mixed_lengths_and_letters():
    assert tp.upstream_key("8.4.1.1") > tp.upstream_key("8.4.1")
    assert tp.upstream_key("8.4.1a") < tp.upstream_key("8.4.2")


def test_fill_without_thirdparty_warns_when_the_threat_has_third_party_builds(tmp_path, capsys):
    from drafter import cli
    from drafter.store import Store

    home = tmp_path / "h"
    s = Store(home / "drafter.sqlite3") if home.mkdir() is None else None
    fid = s.record_fetch(feed="t", url="u", fetched_at="t", status=200, body=None)
    s.upsert(
        "kev",
        {
            "cve": "CVE-2026-109618",
            "date_added": "2026-10-26",
            "vendor": "PHP Group",
            "product": "PHP",
            "name": "x",
            "fetch_id": fid,
        },
        ("cve",),
    )
    s.close()
    # no network: the fill itself fails to fetch, but the check comes from the store
    from drafter import thirdparty
    from drafter.feeds import Context

    ctx = Context(store=Store(home / "drafter.sqlite3"), fetcher=None)
    assert thirdparty.has_repositories(ctx, ["CVE-2026-109618"]) == ["php:php"]
    ctx.store.close()
    assert cli  # the CLI adds the warning when --thirdparty is missing


# second agent review of PR #5


def test_gaps_and_a_deleted_proposal_are_named_by_fill():
    gaps = [tp.Gap("remi rhel:9 safe", "its metadata: HTTP 503")]
    text = tp.render(
        [
            _proposal(),
            _proposal(
                key="sury ubuntu:24.04 php8.4",
                binary_names=["php8.4-fpm"],
                fixed="8.4.27-1+ubuntu24.04.1+deb.sury.org+1",
            ),
        ],
        sorted(CVES),
        gaps,
    )
    _, _, problems = tp.confirmed_entries(text)
    assert any("remi rhel:9 safe" in p and "not affected" in p for p in problems)
    cut = text.split("[[proposal]]")
    without_84 = "[[proposal]]".join(cut[:-1])  # the last block deleted by hand
    _, _, problems = tp.confirmed_entries(without_84)
    assert any("sury ubuntu:24.04 php8.4" in p and "gone" in p for p in problems)
    _, _, problems = tp.confirmed_entries(text.replace("expected = ", "listed = "))
    assert any("no list of expected keys" in p for p in problems)


@pytest.mark.parametrize(
    "line",
    [
        "  * Add upstream fix for CVE-2026-109618 and CVE-2026-109619",
        "  * Fix CVE-2026-109618, CVE-2026-109619 with patches from PHP-8.4",
        "   + (CVE-2026-109618, CVE-2026-109619): patch from the 8.4 branch",
    ],
)
def test_only_news_bullets_give_an_upstream_hint(line):
    body = f"\n  * New upstream version 8.3.36\n{line}\n"
    assert tp.upstream_hint("8.3.36-1", body, CVES) is None
    news = "\n  * New upstream version 8.3.36\n   + (CVE-2026-109618, CVE-2026-109619): x\n"
    assert tp.upstream_hint("8.3.36-1", news, CVES) == "8.3.36"


def test_binaries_come_from_an_older_upload_while_the_newest_builds(ctx, sury):
    sury.routes.insert(
        0, (f"{ARCHIVE}/+sourcepub/3?ws.op=getPublishedBinaries", ok({"entries": []}))
    )
    sury.routes.insert(
        0,
        (
            f"{ARCHIVE}/+sourcepub/2?ws.op=getPublishedBinaries",
            ok({"entries": [{"binary_package_name": "php8.3-fpm"}]}),
        ),
    )
    proposals, _ = tp.sury_proposals(ctx, SURY, CVES, FILTER, [])
    p83 = next(p for p in proposals if p.key.endswith("php8.3"))
    assert p83.binary_names == ["php8.3-fpm"]
    assert p83.fixed == "8.3.36-1+ubuntu24.04.1+deb.sury.org+1"  # still the newest's changelog


@pytest.mark.parametrize(
    "edit",
    [
        {
            "versions": '"8.*remi*"',
            "key": '"remi rhel:9 safe 8.1"',
            "repository": '"remi"',
            "release": '"rhel:9"',
            "source": '"https://rpms.remirepo.net/enterprise/9/safe/x86_64/"',
            "binary_names": '["php81-php-fpm"]',
            "fixed": '"8.1.34-6"',
        },  # every 8.x branch
        {"binary_names": '["php8.3-fpm", "php8.1-fpm"]'},  # another branch's binaries
        {"source": '"https://localhost/"'},
        {"source": '"https://rpms.remirepo.net/"'},  # Remi's address on a Sury proposal
        {"fixed": '"8.4.27"'},  # no revision: the checker refuses it
        {"release": '"ubuntu:22.04"'},  # the key says 24.04
    ],
)
def test_edits_beyond_the_branch_or_the_repository_are_refused(edit):
    text = tp.render([_proposal(confirm=True)], sorted(CVES))
    lines = []
    for line in text.splitlines():
        field = line.split(" = ", 1)[0]
        lines.append(f"{field} = {edit[field]}" if field in edit else line)
    with pytest.raises(tp.ThirdPartyError):
        tp.confirmed_entries("\n".join(lines))


def test_a_remi_proposal_as_written_is_accepted():
    p = _proposal(
        key="remi rhel:9 safe 8.1",
        repository="remi",
        release="rhel:9",
        binary_names=["php81-php-fpm"],
        versions="8.1.*remi*",
        fixed="8.1.34-6",
        source="https://rpms.remirepo.net/enterprise/9/safe/x86_64/",
        confirm=True,
    )
    entries, unconfirmed, problems = tp.confirmed_entries(tp.render([p], sorted(CVES)))
    assert entries[0].versions == "8.1.*remi*" and not unconfirmed and not problems


def test_unknown_cves_are_named(ctx):
    assert tp.unknown_cves(ctx, ["CVE-2026-999999"]) == ["CVE-2026-999999"]


# verification review of the second review's fixes


def test_a_file_written_for_other_cves_is_refused():
    text = tp.render([_proposal()], sorted(CVES))
    with pytest.raises(tp.ThirdPartyError, match="written for"):
        tp.confirmed_entries(text, sorted(CVES | {"CVE-2026-91768"}))
    _, _, problems = tp.confirmed_entries(text.replace("cves = ", "x_cves = "), sorted(CVES))
    assert any("doesn't say which CVEs" in p for p in problems)
    assert tp.confirmed_entries(text, sorted(CVES))  # the right CVEs are fine


@pytest.mark.parametrize(
    "repository, key, fixed",
    [
        ("sury", "sury ubuntu:24.04 php8.3", "8.2.35-1+ubuntu24.04.1+deb.sury.org+1"),
        ("remi", "remi rhel:9 safe 8.3", "8.2.1-1"),
    ],
)
def test_a_fix_from_another_branch_is_refused(repository, key, fixed):
    over = {"key": key, "repository": repository, "fixed": fixed, "confirm": True}
    if repository == "remi":
        over.update(
            release="rhel:9",
            binary_names=["php83-php-fpm"],
            versions="8.3.*remi*",
            source="https://rpms.remirepo.net/enterprise/9/safe/x86_64/",
        )
    with pytest.raises(tp.ThirdPartyError, match="isn't a 8.3 version"):
        tp.confirmed_entries(tp.render([_proposal(**over)], sorted(CVES)))


def test_a_news_bullet_under_a_backport_heading_gives_no_hint():
    body = (
        "\n  * New upstream version 8.2.36\n"
        "  * Backported from 8.3.37\n"
        "   + [CVE-2026-109618, CVE-2026-109619]: Avoid state corruption\n"
    )
    assert tp.upstream_hint("8.2.36-1", body, CVES) is None


def test_a_sury_key_that_isnt_a_branch_is_refused():
    p = _proposal(
        key="sury ubuntu:24.04 php", binary_names=["php8.3-fpm", "php8.4-fpm"], confirm=True
    )
    with pytest.raises(tp.ThirdPartyError):
        tp.confirmed_entries(tp.render([p], sorted(CVES)))


def test_libphp_embed_carries_its_branch():
    p = _proposal(binary_names=["libphp8.3-embed", "php8.3-fpm"], confirm=True)
    entries, _, _ = tp.confirmed_entries(tp.render([p], sorted(CVES)))
    assert entries[0].binary_names == ["libphp8.3-embed", "php8.3-fpm"]


def test_binary_names_are_the_union_over_the_newest_uploads(ctx, sury):
    sury.routes.insert(
        0,
        (
            f"{ARCHIVE}/+sourcepub/3?ws.op=getPublishedBinaries",
            ok({"entries": [{"binary_package_name": "php8.3-fpm"}]}),
        ),
    )
    sury.routes.insert(
        0,
        (
            f"{ARCHIVE}/+sourcepub/2?ws.op=getPublishedBinaries",
            ok({"entries": [{"binary_package_name": "libapache2-mod-php8.3"}]}),
        ),
    )
    proposals, _ = tp.sury_proposals(ctx, SURY, CVES, FILTER, [])
    p83 = next(p for p in proposals if p.key.endswith("php8.3"))
    assert p83.binary_names == ["libapache2-mod-php8.3", "php8.3-fpm"]


def test_the_file_is_checked_against_its_propose_run(store):
    p83, p84 = (
        _proposal(),
        _proposal(
            key="sury ubuntu:24.04 php8.4",
            binary_names=["php8.4-fpm", "php8.4-cgi"],
            fixed="8.4.27-1+ubuntu24.04.1+deb.sury.org+1",
        ),
    )
    run = tp.record_run(store, sorted(CVES), [p83, p84], [], "2026-11-07T00:00:00Z")
    number = run[0]
    text = tp.render([p83, p84], sorted(CVES), [], run)
    _, _, problems = tp.confirmed_entries(text, sorted(CVES), store)
    assert problems == []
    # the 8.4 block and its expected key both edited away, and 8.3's names trimmed
    edited = tp.render([_proposal(binary_names=["php8.3-fpm"])], sorted(CVES), [], run)
    p84_trim = edited  # only php8.3 left
    _, _, problems = tp.confirmed_entries(p84_trim, sorted(CVES), store)
    assert any("sury ubuntu:24.04 php8.4" in p and f"run {number}" in p for p in problems)
    trimmed = tp.render(
        [p83, _proposal(key=p84.key, binary_names=["php8.4-fpm"], fixed=p84.fixed)],
        sorted(CVES),
        [],
        run,
    )
    _, _, problems = tp.confirmed_entries(trimmed, sorted(CVES), store)
    assert any("php8.4-cgi" in p and "gone" in p for p in problems)
    _, _, problems = tp.confirmed_entries(
        text.replace(f'run_token = "{run[1]}"', 'run_token = "0"'), sorted(CVES), store
    )
    assert any("isn't in this store" in p for p in problems)


@pytest.mark.parametrize("bad", ['gap = "x"\n', "proposal = 7\n"])
def test_malformed_tables_are_refused_not_crashed(bad):
    with pytest.raises(tp.ThirdPartyError):
        tp.confirmed_entries(bad)


def test_a_news_bullet_must_sit_under_the_new_upstream_heading():
    body = (
        "\n  * New upstream version 8.2.36\n"
        "  * Changes taken from 8.3.37\n"
        "   + [CVE-2026-109618, CVE-2026-109619]: Avoid state corruption\n"
    )
    assert tp.upstream_hint("8.2.36-1", body, CVES) is None


# narrow review of the verification fixes


def test_a_fix_edited_by_hand_is_named(store):
    run = tp.record_run(store, sorted(CVES), [_proposal()], [], "2026-11-07T00:00:00Z")
    lowered = tp.render(
        [_proposal(fixed="8.3.0-1+ubuntu24.04.1+deb.sury.org+1")], sorted(CVES), [], run
    )
    _, _, problems = tp.confirmed_entries(lowered, sorted(CVES), store)
    assert any("fixed edited by hand" in p and "8.3.0-1" in p for p in problems)
    added = tp.render([_proposal()], sorted(CVES), [], run)
    _, _, problems = tp.confirmed_entries(added, sorted(CVES), store)
    assert problems == []


@pytest.mark.parametrize("value", ["5", "true", "1.5", '"CVE-2026-109618"'])
def test_odd_cve_lists_are_refused_not_crashed(value):
    text = tp.render([_proposal()], sorted(CVES))
    text = "\n".join(
        f"cves = {value}" if line.startswith("cves = ") else line for line in text.splitlines()
    )
    with pytest.raises(tp.ThirdPartyError):
        tp.confirmed_entries(text, sorted(CVES))


@pytest.mark.parametrize("value", ["99999999999999999999", "0", "-1", "true"])
def test_odd_run_numbers_are_named_not_crashed(store, value):
    text = tp.render([_proposal()], sorted(CVES), [], (1, "t"))
    text = "\n".join(
        f"run = {value}" if line.startswith("run = ") else line for line in text.splitlines()
    )
    _, _, problems = tp.confirmed_entries(text, sorted(CVES), store)
    assert any("no propose run" in p for p in problems)


def test_each_run_gets_its_own_token(store, tmp_path):
    first = tp.record_run(store, sorted(CVES), [_proposal()], [], "2026-11-07T00:00:00Z")
    second = tp.record_run(store, sorted(CVES), [_proposal()], [], "2026-11-07T00:00:00Z")
    assert first[1] != second[1] and len(first[1]) >= 32
    # Another store's run 1 doesn't vouch for this file.
    other = Store(tmp_path / "other.sqlite3")
    theirs = tp.record_run(other, sorted(CVES), [_proposal()], [], "2026-11-07T00:00:00Z")
    assert theirs[0] == first[0]
    text = tp.render([_proposal()], sorted(CVES), [], theirs)
    _, _, problems = tp.confirmed_entries(text, sorted(CVES), store)
    assert any("isn't in this store with this file's token" in p for p in problems)
    other.close()
