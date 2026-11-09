# Fill-in (A.3)

`drafter fill` drafts a pack's `packages` section for one threat, from the vendors'
own data. A person gives the CVEs and a binary filter, then reviews the draft.
Nothing is signed or published here.

    drafter fill CVE-2026-109618 CVE-2026-109619 \
        --binaries 'ubuntu:*-fpm' 'ubuntu:libapache2-mod-php*' 'ubuntu:*-cgi' \
                   'ubuntu:*-litespeed' rhel:php rhel:php-fpm rhel:php-cli \
                   'rhel:php?.?' 'rhel:php?.?-fpm' 'rhel:php?.?-cli' \
        --out draft.yaml --compare ../compromise-checker-packs/packs/php2shell-2026-10/PACK.yaml

## The binary filter (John, 2026-11-07)

Which binaries count is a judgement about the threat. PHP2Shell names only the
web-serving SAPIs: Ubuntu's `php8.3-cli` doesn't count, but RHEL's `php-cli` does,
because `/usr/bin/php-cgi` is in it there. So the filter is a list of globs, each
for every family or for one: `ubuntu:GLOB`, `rhel:GLOB`. The report lists what it
left out, release by release, so a filter that is too tight shows. Without a
filter every binary is kept, and the draft says "not filtered".

## Builds no entry matches

A draft writes `other_builds: cant_judge`: a host whose build matches no entry
reads "can't judge", never "not affected" (the checker's default without the
setting). Some vulnerable builds always match no drafted entry: streams no vendor
lists any more, AlmaLinux's blog-only builds, and third-party builds until A.3b.
`--other-builds not_affected` is for a person who has checked that the threat is in
no build but those listed; the draft and the report then say so.

## Where each part comes from

| Part | Ubuntu | RHEL 9 and 10 | AlmaLinux's own builds |
|---|---|---|---|
| Record | OSV `UBUNTU-CVE-…` | Security Data API, then each advisory's CSAF | OSV `ALSA-…` whose fix ends `.alma…` |
| Binaries | the record's binary list | the CSAF's binary RPMs that fix this CVE | the record's packages |
| Fixed version | the record's fixed event | the CSAF build, no epoch; a module build without its build number and hash | the record's fixed event, shortened the same way |
| Source | the USN | Red Hat's errata page | AlmaLinux's errata page |

Rocky Linux and AlmaLinux rebuilds of Red Hat's fixes fall under the RHEL entries:
their versions match the same patterns and compare as fixed.

Ubuntu's record gives the **source** package's versions and fix, and each binary's
own fixed version (`binary_version`). They are usually the same; when a binary's
differs (dotnet8 `8.0.132-8.0.32-0ubuntu1~24.04.1` builds aspnetcore-runtime-8.0
`8.0.32-0ubuntu1~24.04.1`), its entries use the binary's: an installed package only
ever carries that, and the source's would make a patched host read vulnerable. The
listed versions are mapped the same way when the binary's fix is the source's after
its first hyphen; any other relation is for a person ("give them by hand"). A record
with no fix has nothing to map: a binary's version there is only its current build.

## The `versions` patterns, by rule

The expensive failure is a vulnerable host read as fixed or not affected, so the
patterns are drawn from the release and from the vendor's own list of affected
builds, never from the fixed version alone.

- **Ubuntu:** one pattern for each shape among the builds Ubuntu's record lists
  as affected, and the fix. A build with Ubuntu's mark gives `<upstream>-<base>ubuntu*`
  (`8.3.6-0ubuntu*`); one without it (`8.3.4-1build1`, `8.3.0-1`) is used exactly.
  Every build Ubuntu calls affected is matched. Sury's builds write `+ubuntu`
  (`8.1.2-1+ubuntu22.04.1+deb.sury.org+1`), so no Ubuntu pattern reaches them,
  even on the same upstream version, where the match would compare as newer than
  Ubuntu's fix and read "fixed".
- **RHEL, a plain build:** the release, not the version: `*.el9`, `*.el9_?`,
  `*.el9_??`, `*.el9_?.?`, `*.el9_?.??`, `*.el9_??.?`, `*.el9_??.??`. A package has
  one plain stream per release, so nothing is pinned: a rebase within the release
  (git 2.43 to 2.47), a two-part version (tar 1.34) and RHEL 9.10's `el9_10` are
  all matched, with Rocky's and AlmaLinux's rebuilds. The minors are written out so
  AlmaLinux's own `.alma` builds stay out: they have entries of their own, and in a
  plain match they would read as older than Red Hat's fix.
- **RHEL, a module build:** keyed on the stream from the CSAF (`::php:8.2` gives
  `8.2.*module?el9*+????????`, `::nodejs:20` gives `20.*…`). Red Hat and Rocky write
  `module+el9`, AlmaLinux `module_el9`; all end in an eight-character hash, which
  AlmaLinux's own builds don't. A build whose version doesn't start with its
  stream's name (npm 10.8.2 in nodejs:20, 10.9.2 in nodejs:22) isn't drafted: one
  pattern for both streams would judge one against the other's fix. It goes to
  "Needs a person", fixed or not.
- **No fix yet,** plain or module: the same patterns with `fixed: null`. Its
  binaries come from the same release's fixed builds, else another release's (the
  report flags that). With neither, nothing is drafted and a person names the
  binaries: a source package's own name is often no binary (krb5 ships
  `krb5-libs`), and an entry naming it would match nothing on a host, which would
  then read "not affected".
- **AlmaLinux's own builds:** only AlmaLinux writes `alma`, so a plain build goes
  by release, `*.el9*alma*`, as RHEL's do (glibc `2.34-125.el9_5.8.alma.1`,
  systemd `252-32.el9_4.alma.1`). A module build takes its stream from the
  version's major.minor (`8.1.*module?el9*alma*`), since AlmaLinux's records don't
  name it; the draft says so. The fixed version is kept whole: build numbers are
  what order two of AlmaLinux's builds.
- **Fixed versions** keep a non-zero epoch (nginx is `2:`); a Red Hat module fix
  drops its build number and hash, which Rocky's and AlmaLinux's rebuilds of it
  also reach.

## The checker's limits

Debugging-symbol packages (`-debuginfo`, `-debugsource`, `-dbgsym`, `-dbg`) are
never kept. An entry over the checker's 50 binary names is split; past its 100
entries, the report says to narrow the filter or split the threat. A binary in two
entries with the same release and pattern is a clash the checker refuses; the
report gives one line per pair of entries, with what to do: keep `fixed: null` when
one CVE has no fix yet, give the binary the later fix when the fixes differ, and
decide which entry it belongs to only when the fixes are the same.

## Not drafted, and listed as such

- Third-party repositories (Sury, Remi): `drafter propose` proposes them for a
  person to confirm, and `--thirdparty` adds the confirmed ones (`docs/thirdparty.md`).
- A vendor with no record for one of the CVEs (a 404): listed, since a threat
  drafted from the other CVE's fix alone could read a host between the two fixes
  as fixed.
- A CVE with Red Hat fixes but no AlmaLinux record in the store: listed, since
  AlmaLinux's debranded builds (glibc, openssh, systemd and others) match only
  AlmaLinux's entries.
- AlmaLinux's records come from the store, so the report says when they were last
  read and whether that read caught up.
- Red Hat's extended-support builds (EUS, E4S, AUS): listed by advisory; hosts on
  them read as vulnerable.
- Streams no vendor lists any more (php:8.1 on RHEL 9) and AlmaLinux's early
  builds announced only on its blog: hosts on them match no entry. Set
  `other_builds: cant_judge` when the threat is in every build, so they read
  "can't judge", never "not affected".

## History test: PHP2Shell (2026-11-07)

Two checks against the signed `php2shell-2026-10` version 1, with the filter
above.

**Content.** `--compare` matches entries on release, fixed version and binaries.
Every Ubuntu and RHEL fixed version and binary list from vendor data agrees with
the signed pack; the patterns differ, drawn wider by the rules above.

**Behaviour.** `scripts/judge.py` runs both through the checker's own matching code
on 90 installed versions (`tests/history/php2shell-cases.tsv`): every build Ubuntu's
record lists, the fixes, Rocky's and AlmaLinux's rebuilds, AlmaLinux's own early
builds, older and future RHEL builds, and Sury-shaped builds on Ubuntu's upstream
versions.

- 12 versions the draft is more cautious about: builds Ubuntu lists as affected
  that the signed pack's narrower patterns missed (`8.3.4-1build1`, `8.5.4-0ubuntu3`
  and others), and AlmaLinux's blog-only early builds (no entry, so "can't judge").
- 4 the draft is less cautious about, each explained:

| Version | Draft | Signed | Why |
|---|---|---|---|
| Sury `8.1.2-1+ubuntu22.04.1…` and `8.3.6-1+ubuntu24.04.1…` | can't judge | vulnerable | Sury's entries come in A.3b |
| RHEL `8.0.30-9.el9_10` (9.10, future) | fixed | can't judge | the draft is right: newer than the fix |
| RHEL php:8.1 module build | can't judge | vulnerable | Red Hat no longer lists the stream; the signed pack took it from AlmaLinux's blog |

Builds no entry matches get each pack's `other_builds` (both `cant_judge` here), but
only for binaries some entry names: a binary named nowhere isn't judged. These 90
cases are all binaries Ubuntu's or Red Hat's entries name; third-party branches
they don't name (Sury's `php8.3` on 22.04, Remi's `phpNN-php-*`) need
`drafter propose` (`docs/thirdparty.md`), and `drafter fill` says so.

The first pattern rules reproduced the signed pack's patterns exactly, and the
agent review showed why that was the wrong goal: pinned to the fixed build's
major.minor, they missed rebases, module streams that span minors, two-part
versions and RHEL 9.10, all reading "not affected". The rules were redrawn, and
judging with the checker then caught one more: a Sury build on Ubuntu's own upstream
version matched Ubuntu's pattern and read "fixed". Ubuntu's patterns are now
anchored on Ubuntu's mark.
