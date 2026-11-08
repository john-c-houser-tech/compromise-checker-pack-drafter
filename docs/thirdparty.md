# Third-party builds (A.3b)

Ubuntu's and Red Hat's records can't say whether a third-party build is affected.
So for a watched product (`drafter/thirdparty.toml`), the drafter proposes entries
with the evidence it found, and a person confirms each one (plan D4).

    drafter propose CVE-2026-109618 CVE-2026-109619 --binaries … --out proposals.toml
    # read proposals.toml; set confirm = true on each proposal you accept
    drafter fill CVE-2026-109618 CVE-2026-109619 --binaries … --thirdparty proposals.toml

A proposal nobody confirmed is drafted without its fix: its binaries are named under
a pattern no real version matches (`~unconfirmed-php8.3`), so its builds read
"can't judge". Naming them matters: the checker applies `other_builds: cant_judge`
only to binaries some entry on the release names, and a binary named nowhere isn't
judged at all, so the host reads "not affected". For the same reason `drafter
fill` without `--thirdparty` says, under "Needs a person", when the threat has
third-party builds `propose` would name. Only `confirm = true` counts, not
`"true"` or `"yes"`.

Nothing is dropped quietly. A branch or repository `propose` couldn't read (Sury's
newest uploads with no binaries yet, Remi's server failing) is written into the
file as a `[[gap]]`, and the file lists every key it expects. `drafter fill` names
every gap, and every expected proposal that has been deleted, under "Needs a
person": their builds aren't named, so a host on one would read "not affected".
`fill` also names a CVE the store has no NVD or CISA row for, since whether it
touches a third-party build can't be told.

The file says which CVEs it was written for (`cves`), and `fill` refuses it for any
other set: a file proposed for an older CVE would carry that CVE's fixes, and hosts
between them and this threat's fix would read fixed. Each `propose` run is also
recorded in the store (`run`, with a random `run_token` so a file from another
store's run of the same number isn't taken for this one's). `fill` names a
proposal, or binaries, edited out of the file even when its `expected` list was
edited to match, and a fixed version changed by hand: an earlier fix would make the
vulnerable builds between the two read fixed, so a person checks it. A file with no
run, or one this store doesn't hold, is checked against itself only, and `fill`
says so. A confirmed proposal is checked again before it is used: a supported release, package names, a fixed version or none, an https
source at the repository's own address, a key and release that agree, a pattern
exactly as the drafter writes it for that branch (`*+deb.sury.org*` with binary
names carrying the branch, `8.1.*remi*` for 8.1), and a fixed version with its
revision in the key's own branch (8.2's fix can't stand in for 8.3). That last check matters
because a pattern widened to `*` would reach Ubuntu's or Red Hat's own builds and
judge them against the third party's fix.

## Sury (a Launchpad PPA)

For each branch the PPA publishes for a supported Ubuntu release (`php5.6` to
`php8.6` on 22.04 and 24.04 today), the drafter reads the newest upload's full
`debian/changelog`. That file comes from its `.debian.tar.xz`, read in memory. For
each of the threat's CVEs, the oldest entry naming it is that CVE's fix; the
branch's fix is the latest of those, and a CVE never named means no fix found. The
proposal is Sury's upload of that version, with every entry naming a CVE as
evidence (so a later "incomplete fix" shows too):

    8.3.36-1 (uploaded here as 8.3.36-1+ubuntu24.04.1+deb.sury.org+1, 2026-10-21):
    + (CVE-2026-109618, CVE-2026-109619): Avoid state corruption via bailout.

The changelog, not the upload's `.changes` file: on 22.04 those only say
"No-change backport to jammy", and the first run, which used them, missed every
fix but one. A branch whose changelog never names the CVEs is proposed as "no fix
found" (`fixed` empty). Confirm it only if the branch is affected.

Pattern: `*+deb.sury.org*`, with the branch's own binary names (`php8.3-fpm`),
so branches don't overlap. Ubuntu's own patterns never reach Sury's builds (see
`docs/fill.md`).

## Remi (an RPM repository)

For each branch in the repositories `thirdparty.toml` names (`safe` for the
`phpNN-php-*` collections, `modular` for the `php:remi-N.N` modules), on RHEL 9 and
10, the drafter reads Remi's metadata (`primary` and `other`, bzip2). Remi's builds
are the ones whose release says `remi`. The oldest build listed that is fixed
becomes the proposal:

- Every CVE has been named in its changelog or an earlier build's (the branches
  Remi patches himself: 7.4, 8.0, 8.1), or
- Its upstream version reaches the one Sury's changelog gives as the fix, but only
  when every CVE was first named in one "New upstream version" entry, in Sury's
  NEWS bullets (`+ (CVE-…): …`), with no mention of a patch, cherry-pick or
  backport. "Add upstream fix for CVE-…" or "with patches from PHP-8.4" may be a
  patch on top of the release, which Remi's build of that version lacks. A backport (Sury's
  `8.1.34-9`) says nothing about other builds of 8.1.34. The first run took it as
  if it did, and Remi's `8.1.34-5` would have read fixed.

Each repository is proposed on its own (`safe` and `modular` can be fixed at
different builds). Fixed is the version and the release up to its dist part
(`8.4.27-1`, or `8.1.34-6.1` for a fix in `6.1.el9.remi`); the pattern is
`<branch>.*remi*`. Remi's metadata
keeps only the latest builds and their last three changelog entries, so the oldest
fixed build listed may be later than the first fix. Hosts between the two read
"vulnerable", the safe way round.

## History test: PHP2Shell (2026-11-07)

Judged by the checker's own `exposure.judge()` (`scripts/judge.py`), on 111 cases:

| Draft | "Not affected" where the signed pack says vulnerable | Less cautious |
|---|---|---|
| without `--thirdparty` (and warned) | 11 | 15 |
| with every proposal unconfirmed | 0: all "can't judge" | 15 |
| with every proposal confirmed | 0 | 2 (explained in `docs/fill.md`) |

An earlier `judge.py` imitated the checker instead of calling it, and missed that
`other_builds` applies only to named binaries; the first review of this PR found it.



`drafter propose` took 5.5 minutes and proposed 58 entries: 26 Sury (22.04 and
24.04, php5.6 to php8.6) and 32 Remi (RHEL 9 and 10, `safe` and `modular`, 7.4 to
8.6), 52 with a fix. The draft has 96 entries, near the checker's 100; the report
says so past it. With every one confirmed:

- **Content:** every fixed version matches the signed pack's. PHP 8.6's development builds are "no fix" under Sury's and
  Remi's patterns, where the signed pack writes `8.6.0~*`.
- **Behaviour,** judged with the checker (`scripts/judge.py`): every one of the 21
  Sury and Remi cases in `tests/history/php2shell-cases.tsv` (before the fix, the
  fix, later, epochs, release candidates, `safe` and modular) reads the same as in
  the signed pack. Across all 111 cases the draft is less cautious in two places,
  both explained in `docs/fill.md`: a future RHEL 9.10 build that really is fixed,
  and the php:8.1 stream Red Hat no longer lists.
