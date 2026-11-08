"""A.3a: drafting packages from vendor data, against records shaped like the real
ones for PHP2Shell (checked 2026-11-07)."""

from __future__ import annotations

import fnmatch
import json

import pytest
import yaml

from drafter import fill
from drafter.candidates import REDHAT_URL, UBUNTU_URL
from tests.conftest import ok

CVE = "CVE-2026-109618"
FILTER = [
    "ubuntu:*-fpm",
    "ubuntu:libapache2-mod-php*",
    "ubuntu:*-cgi",
    "ubuntu:*-litespeed",
    "rhel:php",
    "rhel:php-fpm",
    "rhel:php-cli",
    "rhel:php?.?",
    "rhel:php?.?-fpm",
    "rhel:php?.?-cli",
]
CSAF_BASE = "https://security.access.redhat.com/data/csaf/v2/advisories/2026/"
ALMA_URL = "https://osv-vulnerabilities.storage.googleapis.com/AlmaLinux/ALSA-2026%3AA014.json"


def _bins(*names, version="x"):
    return [{"binary_name": n, "binary_version": version} for n in names]


def _ubuntu_affected(ecosystem, name, fixed, binaries, versions=()):
    return {
        "package": {"ecosystem": ecosystem, "name": name},
        "versions": list(versions),
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
        "ecosystem_specific": {"binaries": _bins(*binaries)},
    }


UBUNTU = {
    "id": "UBUNTU-" + CVE,
    "related": ["USN-8948-2", "USN-8948-1"],
    "affected": [
        _ubuntu_affected(
            "Ubuntu:24.04:LTS",
            "php8.3",
            "8.3.6-0ubuntu0.24.04.13",
            ["php8.3-fpm", "libapache2-mod-php8.3", "php8.3-cgi", "php8.3-cli", "php8.3-common"],
            versions=["8.3.0-1", "8.3.4-1build1", "8.3.6-0ubuntu0.24.04.12"],
        ),
        _ubuntu_affected("Ubuntu:Pro:18.04:LTS", "php7.2", "7.2.24-0+esm1", ["php7.2-fpm"]),
        _ubuntu_affected("Ubuntu:25.10", "php8.4", "8.4.5-1ubuntu1.2", ["php8.4-fpm"]),  # EOL
    ],
}

REDHAT = {
    "affected_release": [
        {
            "package": "php-0:8.0.30-8.el9_8.1",
            "advisory": "RHSA-2026:87151",
            "cpe": "cpe:/a:redhat:enterprise_linux:9",
        },
        {
            "package": "php:8.2-9080020261020145734.9",
            "advisory": "RHSA-2026:87072",
            "cpe": "cpe:/a:redhat:enterprise_linux:9",
        },
        {
            "package": "php-0:8.0.30-3.el9_6.2",
            "advisory": "RHSA-2026:88720",
            "cpe": "cpe:/a:redhat:rhel_eus:9.6",
        },
        {
            "package": "php:8.2-8100020261020140951.f7998665",
            "advisory": "RHSA-2026:87073",
            "cpe": "cpe:/a:redhat:enterprise_linux:8",
        },
        {
            "package": "devspaces/udi-rhel9:1",
            "advisory": "RHSA-2026:90321",
            "cpe": "cpe:/a:redhat:openshift_devspaces:3.31::el9",
        },
    ],
    "package_state": [
        {
            "package_name": "php:8.4/php",
            "fix_state": "Affected",
            "cpe": "cpe:/a:redhat:enterprise_linux:9",
        },
        {"package_name": "php", "fix_state": "Not affected", "cpe": "cpe:/o:redhat:rhel_els:7"},
    ],
}


def _csaf(cve, *nevras, other_cve_only=()):
    prefix = "AppStream-9.8.0.Z.MAIN.EUS:"
    return {
        "document": {"tracking": {"id": "RHSA"}},
        "vulnerabilities": [
            {"cve": cve, "product_status": {"fixed": [prefix + n for n in nevras]}},
            {
                "cve": "CVE-2026-1",
                "product_status": {"fixed": [prefix + n for n in other_cve_only]},
            },
        ],
    }


CSAF_87151 = _csaf(
    CVE,
    "php-0:8.0.30-8.el9_8.1.src",
    "php-0:8.0.30-8.el9_8.1.x86_64",
    "php-fpm-0:8.0.30-8.el9_8.1.x86_64",
    "php-cli-0:8.0.30-8.el9_8.1.aarch64",
    "php-common-0:8.0.30-8.el9_8.1.x86_64",
    other_cve_only=("php-dbg-0:8.0.30-8.el9_8.1.x86_64",),
)
CSAF_87072 = _csaf(
    CVE,
    "php-0:8.2.35-1.module+el9.8.0+25111+a1450321.x86_64::php:8.2",
    "php-fpm-0:8.2.35-1.module+el9.8.0+25111+a1450321.x86_64::php:8.2",
    "php-cli-0:8.2.35-1.module+el9.8.0+25111+a1450321.x86_64::php:8.2",
    "apcu-panel-0:5.1.23-1.module+el9.7.0+24111+199d2cc4.noarch::php:8.2",
)

ALMA = {
    "id": "ALSA-2026:A014",
    "affected": [
        {
            "package": {"ecosystem": "AlmaLinux:9", "name": n},
            "ranges": [
                {
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "8.1.32-1.module_el9.8.0+326+528679fc.alma.1"},
                    ]
                }
            ],
        }
        for n in ("php", "php-fpm", "php-cli", "php-common")
    ],
}


def _alma_row(store, osv_id="ALSA-2026:A014", cve=CVE):
    fid = store.record_fetch(feed="t", url="u", fetched_at="t", status=200, body=None)
    store.upsert(
        "osv",
        {
            "ecosystem": "AlmaLinux",
            "id": osv_id,
            "modified": "t",
            "cves": json.dumps([cve]),
            "ubuntu_priority": None,
            "fetch_id": fid,
        },
        ("ecosystem", "id"),
    )


@pytest.fixture
def vendors(fetcher, store):
    fetcher.add(UBUNTU_URL.format(cve=CVE), ok(UBUNTU))
    fetcher.add(REDHAT_URL.format(cve=CVE), ok(REDHAT))
    fetcher.add(CSAF_BASE + "rhsa-2026_87151.json", ok(CSAF_87151))
    fetcher.add(CSAF_BASE + "rhsa-2026_87072.json", ok(CSAF_87072))
    fetcher.add(ALMA_URL, ok(ALMA))
    _alma_row(store)
    return fetcher


def _by(draft, release, versions):
    (entry,) = [e for e in draft.entries if e.release == release and e.versions == versions]
    return entry


# Ubuntu


def test_ubuntu_entries_cover_every_build_ubuntu_lists(ctx, vendors):
    draft = fill.build(ctx, [CVE], FILTER)
    mine = [e for e in draft.entries if e.release == "ubuntu:24.04"]
    assert sorted(e.versions for e in mine) == ["8.3.0-1", "8.3.4-1build1", "8.3.6-0ubuntu*"]
    for e in mine:
        assert e.binary_names == ["libapache2-mod-php8.3", "php8.3-cgi", "php8.3-fpm"]
        assert e.fixed == "8.3.6-0ubuntu0.24.04.13"
        assert e.source == "https://ubuntu.com/security/notices/USN-8948-1"
    assert not [x for x in draft.entries if x.release in ("ubuntu:18.04", "ubuntu:25.10")]
    assert draft.filtered_out["ubuntu:24.04"] == ["php8.3-cli", "php8.3-common"]


@pytest.mark.parametrize(
    "version, pattern",
    [
        ("8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu*"),
        ("8.1.2-1ubuntu2.28", "8.1.2-1ubuntu*"),
        ("1:7.4.3-4ubuntu2.24", "7.4.3-4ubuntu*"),
        ("8.3.4-1build1", "8.3.4-1build1"),
        ("8.3.0-1", "8.3.0-1"),
    ],
)
def test_ubuntu_shapes(version, pattern):
    assert fill.ubuntu_shape(version) == pattern


@pytest.mark.parametrize(
    "sury", ["8.1.2-1+ubuntu22.04.1+deb.sury.org+1", "8.3.6-0+ubuntu24.04.1+deb.sury.org+1"]
)
def test_ubuntu_shapes_never_reach_surys_builds(sury):
    # A Sury build on Ubuntu's upstream version would compare as newer than
    # Ubuntu's fix and read "fixed" (found by judging the draft with the checker).
    for version in ("8.1.2-1ubuntu2.28", "8.3.6-0ubuntu0.24.04.13", "8.3.6-0", "8.1.2-1"):
        assert not fnmatch.fnmatchcase(sury, fill.ubuntu_shape(version))


def test_ubuntu_pro_builds_are_reported(ctx, fetcher, store):
    fetcher.add(
        UBUNTU_URL.format(cve=CVE),
        ok(
            {
                "affected": [
                    _ubuntu_affected(
                        "Ubuntu:Pro:FIPS:22.04:LTS",
                        "openssl",
                        "3.0.2-0ubuntu1.10+Fips1",
                        ["openssl"],
                    )
                ]
            }
        ),
    )
    draft = fill.build(ctx, [CVE], [])
    assert any("Ubuntu Pro" in item for item in draft.not_covered)


# Red Hat


def test_rhel_plain_build_patterns_follow_the_release_not_the_version(ctx, vendors):
    draft = fill.build(ctx, [CVE], FILTER)
    patterns = sorted(e.versions for e in draft.entries if e.fixed == "8.0.30-8.el9_8.1")
    assert patterns == sorted(fill.rhel_plain_patterns("9"))
    e = _by(draft, "rhel:9", "*.el9")
    assert e.binary_names == ["php", "php-cli", "php-fpm"]
    assert e.source == "https://access.redhat.com/errata/RHSA-2026:87151"


def test_plain_patterns_reach_rebases_short_versions_and_two_digit_minors():
    plain = fill.rhel_plain_patterns("9")
    for version in (
        "2.43.5-2.el9_5",
        "1.34-7.el9",
        "590-5.el9",
        "8.0.30-9.el9_10",
        "8.0.30-1.el9_4.11",
        "8.0.30-8.el9_8.1",
    ):
        assert any(fnmatch.fnmatchcase(version, p) for p in plain), version
    for version in (
        "8.0.30-8.el9_8.alma.1",
        "8.2.35-1.module+el9.8.0+25111+a1450321",
        "7.4.33-31.module_php.7.4.el9.remi",
        "8.0.30-8.el10_1",
    ):
        assert not any(fnmatch.fnmatchcase(version, p) for p in plain), version


def test_rhel_module_build(ctx, vendors):
    draft = fill.build(ctx, [CVE], FILTER)
    e = _by(draft, "rhel:9", "8.2.*module?el9*+????????")
    assert e.fixed == "8.2.35-1.module+el9.8.0"
    assert e.binary_names == ["php", "php-cli", "php-fpm"]
    assert not [x for x in draft.entries if (x.versions or "").startswith("5.1.")]  # apcu


@pytest.mark.parametrize(
    "stream, version, pattern",
    [
        ("php:8.2", "8.2.35", "8.2.*module?el9*+????????"),
        ("nodejs:20", "20.19.5", "20.*module?el9*+????????"),
        ("container-tools:rhel8", "4.0.1", ""),  # a person writes it
    ],
)
def test_module_patterns_key_on_the_stream(stream, version, pattern):
    assert fill.rhel_module_pattern(stream, version, "9")[0] == pattern


def test_module_patterns_reach_rocky_and_alma_rebuilds_but_not_almas_own():
    pattern = fill.rhel_module_pattern("php:8.2", "8.2.35", "9")[0]
    for version in (
        "8.2.35-1.module+el9.8.0+40395+2f706e64",
        "8.2.13-1.module+el9.4.0+20027+be4b2d1a",
        "8.2.35-1.module_el9.8.0+330+fdc30075",
    ):
        assert fnmatch.fnmatchcase(version, pattern)
    assert not fnmatch.fnmatchcase("8.2.33-1.module_el9.8.0+320+aaaa1111.alma.1", pattern)


def test_rhel_affected_stream_with_no_fix(ctx, vendors):
    draft = fill.build(ctx, [CVE], FILTER)
    e = _by(draft, "rhel:9", "8.4.*module?el9*+????????")
    assert e.fixed is None and e.binary_names == ["php", "php-cli", "php-fpm"]
    assert "php:8.4" in e.note and not draft.guessed  # binaries from rhel:9's own builds


def test_a_plain_package_with_no_fix_is_never_dropped(ctx, fetcher, store):
    # Fixed on RHEL 10 (so its binaries are known), affected with no fix on RHEL 9.
    fetcher.add(
        REDHAT_URL.format(cve=CVE),
        ok(
            {
                "affected_release": [
                    {
                        "package": "libxml2-0:2.12.5-5.el10_1",
                        "advisory": "RHSA-2026:5",
                        "cpe": "cpe:/o:redhat:enterprise_linux:10.1",
                    }
                ],
                "package_state": [
                    {
                        "package_name": "libxml2",
                        "fix_state": "Affected",
                        "cpe": "cpe:/o:redhat:enterprise_linux:9",
                    }
                ],
            }
        ),
    )
    csaf = {
        "vulnerabilities": [
            {
                "cve": CVE,
                "product_status": {
                    "fixed": [
                        "BaseOS-10.1.Z:libxml2-0:2.12.5-5.el10_1.x86_64",
                        "BaseOS-10.1.Z:python3-libxml2-0:2.12.5-5.el10_1.x86_64",
                    ]
                },
            }
        ]
    }
    fetcher.add(CSAF_BASE + "rhsa-2026_5.json", ok(csaf))
    draft = fill.build(ctx, [CVE], [])
    nine = [e for e in draft.entries if e.release == "rhel:9"]
    assert {e.versions for e in nine} == set(fill.rhel_plain_patterns("9"))
    assert all(e.fixed is None for e in nine)
    assert nine[0].binary_names == ["libxml2", "python3-libxml2"]  # from rhel:10's builds
    assert any("rhel:10" in g for g in draft.guessed)


def test_no_binaries_to_borrow_goes_to_a_person_not_a_source_name(ctx, fetcher, store):
    # krb5 ships krb5-libs: an entry naming "krb5" would match nothing on a host,
    # which would then read "not affected" (found judging with the checker).
    fetcher.add(
        REDHAT_URL.format(cve=CVE),
        ok(
            {
                "package_state": [
                    {
                        "package_name": "krb5",
                        "fix_state": "Affected",
                        "cpe": "cpe:/o:redhat:enterprise_linux:10",
                    }
                ]
            }
        ),
    )
    draft = fill.build(ctx, [CVE], [])
    assert draft.entries == []
    assert any("krb5" in c and "name its binaries" in c for c in draft.conflicts)


def test_extended_support_and_other_products_and_older_releases(ctx, vendors):
    draft = fill.build(ctx, [CVE], FILTER)
    assert any("rhel_eus" in i and "extended-support" in i for i in draft.not_covered)
    assert not any("devspaces" in i for i in draft.not_covered)  # a container image
    assert not [e for e in draft.entries if e.release == "rhel:8"]


def test_csaf_builds_for_another_cve_are_left_out(ctx, vendors):
    draft = fill.build(ctx, [CVE], [])
    e = _by(draft, "rhel:9", "*.el9")
    assert "php-common" in e.binary_names
    assert "php-dbg" not in e.binary_names  # fixed by the advisory, but for another CVE


def test_epochs_are_kept():
    assert fill.rhel_fixed("2", "1.20.1", "24.el9_7.3") == "2:1.20.1-24.el9_7.3"
    assert fill.rhel_fixed("0", "8.0.30", "8.el9_8.1") == "8.0.30-8.el9_8.1"
    assert fill.rhel_fixed(None, "8.2.35", "1.module+el9.8.0+25111+a1450321") == (
        "8.2.35-1.module+el9.8.0"
    )


# AlmaLinux


def test_alma_own_build_kept_whole(ctx, vendors):
    draft = fill.build(ctx, [CVE], FILTER)
    e = _by(draft, "rhel:9", "8.1.*module?el9*alma*")
    assert e.fixed == "8.1.32-1.module_el9.8.0+326+528679fc.alma.1"
    assert "guessed from the version" in e.note
    assert e.binary_names == ["php", "php-cli", "php-fpm"]
    assert e.source == "https://errata.almalinux.org/9/ALSA-2026-A014.html"


# the filter, the output, the comparison


def test_no_filter_keeps_every_binary(ctx, vendors):
    draft = fill.build(ctx, [CVE], [])
    e = _by(draft, "ubuntu:24.04", "8.3.6-0ubuntu*")
    assert "php8.3-common" in e.binary_names and not draft.filtered_out
    assert "not filtered" in fill.render_yaml(draft)


def test_family_scoped_filters():
    assert fill.keep("php-cli", ["rhel:php-cli"], "rhel")
    assert not fill.keep("php-cli", ["rhel:php-cli"], "ubuntu")
    assert fill.keep("php8.3-fpm", ["*-fpm"], "ubuntu")


@pytest.mark.parametrize("bad", [["rhel9:php"], ["Ubuntu:php"], ["rhel:"]])
def test_filter_scopes_are_checked(ctx, bad):
    with pytest.raises(fill.FillError):
        fill.build(ctx, [CVE], bad)


def test_a_vendor_that_does_not_track_the_cve(ctx, fetcher, store):
    fetcher.add(REDHAT_URL.format(cve=CVE), ok({"affected_release": []}))
    draft = fill.build(ctx, [CVE], FILTER)  # Ubuntu answers 404
    assert draft.entries == []


def test_yaml_parses_and_report_names_its_parts(ctx, vendors):
    draft = fill.build(ctx, [CVE], FILTER)
    parsed = yaml.safe_load("exposure:\n" + fill.render_yaml(draft))["exposure"]["packages"]
    assert len(parsed) == len(draft.entries)
    assert {p["release"] for p in parsed} == {"ubuntu:24.04", "rhel:9"}
    report = fill.render_report(draft)
    assert "Left out by the binary filter" in report and "other_builds: cant_judge" in report


def test_hostile_vendor_text_cannot_shape_the_yaml(ctx, fetcher, store):
    names = ['php8.3-fpm\n    - release: "ubuntu:24.04"\n      versions: "*"', "php8.3-cgi"]
    evil = {
        "affected": [
            _ubuntu_affected("Ubuntu:24.04:LTS", "php8.3", "8.3.6-0ubuntu0.24.04.13", names)
        ]
    }
    fetcher.add(UBUNTU_URL.format(cve=CVE), ok(evil))
    fetcher.add(
        REDHAT_URL.format(cve=CVE),
        ok(
            {
                "package_state": [
                    {
                        "package_name": "php:8.4\n# x/php",
                        "fix_state": "Affected",
                        "cpe": "cpe:/a:redhat:enterprise_linux:9",
                    }
                ]
            }
        ),
    )
    draft = fill.build(ctx, [CVE], [])
    parsed = yaml.safe_load("exposure:\n" + fill.render_yaml(draft))["exposure"]["packages"]
    assert all(p.get("versions") != "*" for p in parsed)
    assert {tuple(p["binary_names"]) for p in parsed if p["release"] == "ubuntu:24.04"} == {
        ("php8.3-cgi",)
    }
    assert all("\n" not in e.note for e in draft.entries)


def test_two_fixes_for_the_same_builds_are_a_conflict(ctx, fetcher, store):
    for cve, fixed in (
        (CVE, "8.3.6-0ubuntu0.24.04.13"),
        ("CVE-2026-109619", "8.3.6-0ubuntu0.24.04.14"),
    ):
        fetcher.add(
            UBUNTU_URL.format(cve=cve),
            ok(
                {
                    "affected": [
                        _ubuntu_affected("Ubuntu:24.04:LTS", "php8.3", fixed, ["php8.3-fpm"])
                    ]
                }
            ),
        )
    draft = fill.build(ctx, [CVE, "CVE-2026-109619"], [])
    assert len(draft.entries) == 2 and len(draft.conflicts) == 1
    assert "each binary takes the later fix" in fill.render_report(draft)


def test_compare_with_a_signed_pack(ctx, vendors):
    draft = fill.build(ctx, [CVE], FILTER)
    sury = {
        "release": "ubuntu:24.04",
        "binary_names": ["php8.3-fpm"],
        "versions": "*+deb.sury.org*",
        "fixed": "8.3.36-1+ubuntu24.04.1+deb.sury.org+1",
        "source": "https://launchpad.net/~ondrej/+archive/ubuntu/php",
    }
    signed = {
        "id": "php2shell-2026-10",
        "version": 1,
        "exposure": {
            "packages": [
                {
                    "release": "ubuntu:24.04",
                    "binary_names": ["php8.3-fpm", "libapache2-mod-php8.3", "php8.3-cgi"],
                    "versions": "8.3.6-0*",
                    "fixed": "8.3.6-0ubuntu0.24.04.13",
                    "source": "https://ubuntu.com/security/notices/USN-8948-1",
                },
                sury,
                {**sury, "binary_names": ["php8.2-fpm"], "fixed": "8.2.35-1+ubuntu24.04.1"},
                {
                    "release": "rhel:9",
                    "binary_names": ["php", "php-fpm", "php-cli"],
                    "versions": "8.2.*module?el9*+????????",
                    "fixed": "8.2.35-1.module+el9.8.0",
                    "source": "https://access.redhat.com/errata/RHSA-2026:87072",
                },
            ]
        },
    }
    text = fill.compare(draft, yaml.safe_dump(signed))
    assert "1 entries the same" in text  # the module stream
    assert "patterns differ  ubuntu:24.04 fixed 8.3.6-0ubuntu0.24.04.13" in text
    assert text.count("signed only  ubuntu:24.04") == 2  # two Sury entries, kept apart
    assert "draft only  rhel:9 fixed 8.0.30-8.el9_8.1" in text


def test_cli_fill_refuses_non_cves_and_bad_scopes(tmp_path):
    from drafter import cli

    assert cli.main(["--home", str(tmp_path), "fill", "PHP2Shell"]) == 2
    assert cli.main(["--home", str(tmp_path), "fill", CVE, "--binaries", "rhel9:php"]) == 2


def test_drafts_say_cant_judge_for_builds_no_entry_matches(ctx, vendors):
    draft = fill.build(ctx, [CVE], FILTER)
    exposure = yaml.safe_load("exposure:\n" + fill.render_yaml(draft))["exposure"]
    assert exposure["other_builds"] == "cant_judge"
    loose = fill.build(ctx, [CVE], FILTER, "not_affected")
    assert (
        yaml.safe_load("exposure:\n" + fill.render_yaml(loose))["exposure"]["other_builds"]
        == "not_affected"
    )
    assert "only right if" in fill.render_report(loose)
    with pytest.raises(fill.FillError):
        fill.build(ctx, [CVE], FILTER, "maybe")


# second agent review of PR #3


@pytest.mark.parametrize(
    "fixed, vulnerable",
    [
        ("2.34-125.el9_5.8.alma.1", "2.34-125.el9_5.1.alma.1"),  # glibc: one dot
        ("252-32.el9_4.alma.1", "252-18.el9.alma.1"),  # systemd: no dot
        ("9.9p1-11.el9.alma.1", "8.7p1-38.el9.alma.1"),  # a rebase
    ],
)
def test_almas_own_plain_builds_are_matched_by_release(fixed, vulnerable):
    pattern, note = fill.alma_pattern(fixed, "9")
    assert pattern == "*.el9*alma*" and not note
    assert fnmatch.fnmatchcase(fixed, pattern) and fnmatch.fnmatchcase(vulnerable, pattern)
    for other in (
        "2.34-125.el9_5.8",
        "8.1.32-1.module_el9.8.0+326+528679fc.alma.1",
        "2.34-125.el10.alma.1",
    ):
        assert not fnmatch.fnmatchcase(other, pattern)


def test_a_module_stream_named_otherwise_goes_to_a_person(ctx, fetcher, store):
    fetcher.add(
        REDHAT_URL.format(cve=CVE),
        ok(
            {
                "affected_release": [
                    {
                        "package": "nodejs:20-9060020240101000000.1",
                        "advisory": "RHSA-2026:7",
                        "cpe": "cpe:/a:redhat:enterprise_linux:9",
                    }
                ]
            }
        ),
    )
    csaf = {
        "vulnerabilities": [
            {
                "cve": CVE,
                "product_status": {
                    "fixed": [
                        "AppStream-9.6:npm-1:10.8.2-1.20.19.5.1.module+el9.6.0+23001+8899aabb.x86_64::nodejs:20",
                        "AppStream-9.6:nodejs-1:20.19.5-1.module+el9.6.0+23001+8899aabb.x86_64::nodejs:20",
                    ]
                },
            }
        ]
    }
    fetcher.add(CSAF_BASE + "rhsa-2026_7.json", ok(csaf))
    draft = fill.build(ctx, [CVE], [])
    assert [e.binary_names for e in draft.entries] == [["nodejs"]]
    assert draft.entries[0].versions == "20.*module?el9*+????????"
    assert draft.entries[0].fixed == "1:20.19.5-1.module+el9.6.0"
    assert any("npm" in c and "by hand" in c for c in draft.conflicts)


def test_a_binary_in_two_entries_on_one_pattern_is_a_conflict(ctx, fetcher, store):
    fetcher.add(
        REDHAT_URL.format(cve=CVE),
        ok(
            {
                "affected_release": [
                    {
                        "package": "openssh-0:8.7p1-45.el9",
                        "advisory": "RHSA-2026:8",
                        "cpe": "cpe:/o:redhat:enterprise_linux:9",
                    },
                    {
                        "package": "openssh-0:8.7p1-46.el9",
                        "advisory": "RHSA-2026:9",
                        "cpe": "cpe:/o:redhat:enterprise_linux:9",
                    },
                ]
            }
        ),
    )
    for n, names in ((8, ["openssh-server"]), (9, ["openssh-server", "openssh-clients"])):
        rel = f"8.7p1-{37 + n}.el9"
        csaf = {
            "vulnerabilities": [
                {
                    "cve": CVE,
                    "product_status": {
                        "fixed": [f"BaseOS-9:{name}-0:{rel}.x86_64" for name in names]
                    },
                }
            ]
        }
        fetcher.add(CSAF_BASE + f"rhsa-2026_{n}.json", ok(csaf))
    draft = fill.build(ctx, [CVE], [])
    (clash,) = [c for c in draft.conflicts if "in two entries" in c]  # one line a pair
    assert "openssh-server" in clash and "on 7 pattern(s)" in clash
    assert "each binary takes the later fix" in clash


def test_debug_packages_are_left_out_and_long_lists_split(ctx, fetcher, store):
    names = [f"php8.3-ext{n}" for n in range(60)] + ["php8.3-fpm-dbgsym"]
    fetcher.add(
        UBUNTU_URL.format(cve=CVE),
        ok(
            {
                "affected": [
                    _ubuntu_affected("Ubuntu:24.04:LTS", "php8.3", "8.3.6-0ubuntu0.24.04.13", names)
                ]
            }
        ),
    )
    draft = fill.build(ctx, [CVE], [])
    assert [len(e.binary_names) for e in draft.entries] == [50, 10]
    assert all("dbgsym" not in n for e in draft.entries for n in e.binary_names)
    assert not draft.conflicts


def test_missing_vendor_records_and_alma_freshness_are_reported(ctx, fetcher, store):
    draft = fill.build(ctx, [CVE], [])  # both vendors answer 404
    report = fill.render_report(draft)
    assert "Ubuntu has no record for " + CVE in report
    assert "Red Hat has no record for " + CVE in report
    assert "AlmaLinux's own builds from records read never" in report


def test_each_csaf_advisory_is_read_once(ctx, vendors):
    record = json.loads(json.dumps(REDHAT))
    record["affected_release"].append(dict(record["affected_release"][0]))  # a BaseOS row too
    vendors.add(REDHAT_URL.format(cve=CVE), ok(record))
    vendors.routes.insert(0, vendors.routes.pop())
    fill.build(ctx, [CVE], FILTER)
    assert sum(c["url"].endswith("rhsa-2026_87151.json") for c in vendors.calls) == 1


def test_an_unfixed_stream_package_named_otherwise_goes_to_a_person(ctx, fetcher, store):
    # nodejs:20/npm: npm is 10.x, so a "20.*" pattern would never match it, and npm
    # would read "can't judge" at best. A person writes its pattern.
    fetcher.add(
        REDHAT_URL.format(cve=CVE),
        ok(
            {
                "affected_release": [
                    {
                        "package": "nodejs:22-9060020240101000000.1",
                        "advisory": "RHSA-2026:7",
                        "cpe": "cpe:/a:redhat:enterprise_linux:9",
                    }
                ],
                "package_state": [
                    {
                        "package_name": "nodejs:20/npm",
                        "fix_state": "Affected",
                        "cpe": "cpe:/a:redhat:enterprise_linux:9",
                    }
                ],
            }
        ),
    )
    csaf = {
        "vulnerabilities": [
            {
                "cve": CVE,
                "product_status": {
                    "fixed": [
                        "AppStream-9.6:nodejs-1:22.1.0-1.module+el9.6.0+23001+8899aabb.x86_64::nodejs:22"
                    ]
                },
            }
        ]
    }
    fetcher.add(CSAF_BASE + "rhsa-2026_7.json", ok(csaf))
    draft = fill.build(ctx, [CVE], [])
    assert [e.versions for e in draft.entries] == ["22.*module?el9*+????????"]
    assert any("nodejs:20/npm" in c and "don't say this package's" in c for c in draft.conflicts)


# verification review of the second review's fixes


def test_a_clash_with_an_unfixed_cve_says_keep_null(ctx, fetcher, store):
    fixes = ((CVE, {"fixed": "8.3.6-0ubuntu0.24.04.13"}), ("CVE-2026-109619", {}))
    for cve, event in fixes:
        affected = _ubuntu_affected("Ubuntu:24.04:LTS", "php8.3", "x", ["php8.3-fpm"])
        affected["ranges"] = [{"events": [{"introduced": "0"}, *([event] if event else [])]}]
        affected["versions"] = ["8.3.6-0ubuntu0.24.04.12"]
        fetcher.add(UBUNTU_URL.format(cve=cve), ok({"affected": [affected]}))
    draft = fill.build(ctx, [CVE, "CVE-2026-109619"], [])
    (clash,) = [c for c in draft.conflicts if "in two entries" in c]
    assert "keep fixed: null" in clash


def test_names_outside_a_streams_versions_are_never_lent(ctx, fetcher, store):
    # nodejs:22 is fixed for nodejs (22.x) but its npm is 10.9.x; nodejs:22 is also
    # listed affected (another build): npm must not be lent to a 22.* entry.
    fetcher.add(
        REDHAT_URL.format(cve=CVE),
        ok(
            {
                "affected_release": [
                    {
                        "package": "nodejs:22-9060020240101000000.1",
                        "advisory": "RHSA-2026:7",
                        "cpe": "cpe:/a:redhat:enterprise_linux:9",
                    }
                ],
                "package_state": [
                    {
                        "package_name": "nodejs:20/nodejs",
                        "fix_state": "Affected",
                        "cpe": "cpe:/a:redhat:enterprise_linux:9",
                    }
                ],
            }
        ),
    )
    csaf = {
        "vulnerabilities": [
            {
                "cve": CVE,
                "product_status": {
                    "fixed": [
                        "AppStream-9.6:nodejs-1:22.1.0-1.module+el9.6.0+23001+8899aabb.x86_64::nodejs:22",
                        "AppStream-9.6:npm-1:10.9.2-1.22.1.0.1.module+el9.6.0+23001+8899aabb.x86_64::nodejs:22",
                    ]
                },
            }
        ]
    }
    fetcher.add(CSAF_BASE + "rhsa-2026_7.json", ok(csaf))
    draft = fill.build(ctx, [CVE], [])
    assert all("npm" not in e.binary_names for e in draft.entries)
    unfixed = [e for e in draft.entries if e.fixed is None]
    assert unfixed and unfixed[0].binary_names == ["nodejs"]


def test_a_cve_alma_has_no_record_for_is_listed(ctx, vendors):
    draft = fill.build(ctx, [CVE, "CVE-2026-109619"], FILTER)
    assert any("AlmaLinux has no record for CVE-2026-109619" in m for m in draft.missing)
    assert not any("AlmaLinux has no record for " + CVE in m for m in draft.missing)


def test_php_dbg_is_a_program_and_stays(ctx, fetcher, store):
    assert fill._names(["php-dbg", "php-fpm-debuginfo", "php8.3-fpm-dbgsym"]) == ["php-dbg"]


@pytest.mark.parametrize(
    "stream, version, build",
    [("postgresql:16", "16", "16-1.module+el9.4.0+20000+abcdef12")],
)
def test_a_version_that_is_its_stream(stream, version, build):
    pattern = fill.rhel_module_pattern(stream, version, "9")[0]
    assert fnmatch.fnmatchcase(build, pattern)


@pytest.mark.parametrize(
    "fixed",
    [
        "10.11-2.module_el9.4.0+111+aaaabbbb.alma.1",
        "16-1.module_el9.4.0+222+ccccdddd.alma.1",
        "8.1.32-1.module_el9.8.0+326+528679fc.alma.1",
    ],
)
def test_almas_module_patterns_match_their_own_fix(fixed):
    assert fnmatch.fnmatchcase(fixed, fill.alma_pattern(fixed, "9")[0])


def test_alma_freshness_says_whether_it_caught_up(ctx, fetcher, store):
    from drafter.store import FeedState

    store.save_state(FeedState(feed="osv-almalinux", last_success="2026-11-07T12:00:00Z"))
    draft = fill.build(ctx, [CVE], [])
    assert "records still waiting" in fill.render_report(draft)
    store.save_state(
        FeedState(feed="osv-almalinux", last_success="2026-11-07T12:00:00Z", etag='"e"')
    )
    assert "caught up" in fill.render_report(fill.build(ctx, [CVE], []))
