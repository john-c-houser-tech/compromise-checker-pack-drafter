# Candidates (A.2)

`drafter candidates list` answers one question: which exploited threats touch
packages Compromise Checker can judge?

## Signs of an attack (plan D3; the checker's scope, 2026-11-10)

A CVE comes onto the list when any of these is true:

| Sign | From | Time used |
|---|---|---|
| on CISA's list | `kev` | the day CISA added it |
| CISA rates it "exploitation: active" | `nvd` (CISA's SSVC rating) | CISA's rating time |
| added by hand | `drafter candidates add CVE-… --note "…"` | when it was added |

Adding by hand needs `--note`, saying where the report of attacks came from.

CISA's list alone is late: PHP2Shell's first attacks and fixes were on
2026-10-21, and it joined the list on 2026-10-26. CISA rated it "exploitation:
active" on 2026-10-21.

**A vendor's rating alone lists nothing.** Ubuntu's priority `critical`
(`osv-ubuntu`) and Red Hat's severity Critical (`redhat`) are still read, and are
shown on a CVE that has a sign of an attack. But a pack is for an attack seen in
the wild, and a rating says how bad a flaw could be, not that anyone is using it.
Until 2026-11-10 a rating was enough to list a CVE, and .NET, ca-certificates, Java
and edk2 all came in that way: none was being attacked, and none left anything on a
server to look for. Now such a CVE is **counted in one line** ("Rated critical by
a vendor, no sign of an attack"), its vendor records aren't read, and it joins no
threat, even one for the same package in the same days. If attacks are reported
later, it comes onto the list then.

## The vendors' own records

For each signalled CVE, `drafter candidates refresh` fetches Ubuntu's OSV record
(`UBUNTU-CVE-….json`) and Red Hat's record from its Security Data API, and keeps
both, like every other answer. A 404 means the vendor doesn't track the CVE, and
is kept too. It looks back 180 days: records are read again daily for CVEs first
signalled in the last 30 days, weekly for older ones, and at once when a new sign
arrives. Records for CVEs first signalled more than 180 days ago are no longer
read again, so a list reaching further back than that (`--since`) can show what
the vendors said then; `drafter candidates refresh --since …` brings them up to
date. A failed read is recorded with its time and tried again after an hour,
behind the records never read, so one record that keeps failing can't hold up the
rest. The hourly timer runs it after reading the feeds, and `drafter feeds status`
shows it as `vendor-records`.

A CVE counts from its first sign of an attack. Signs are gathered over the whole
history, because CISA re-stamps old SSVC ratings in batches: CVE-2022-30333, on
CISA's list since 2022, would otherwise show up as a threat from August 2026. A
vendor's rating doesn't start the clock: a CVE rated critical in March and
attacked in October is new in October.

## Sorting

Each signalled CVE lands in one place:

- **Can judge:** a package on a supported release that isn't set aside. Supported
  means Ubuntu's LTS releases from 22.04, the interim releases still in support
  (named in `drafter/candidates.py`, since OSV keeps retired ones), without Ubuntu
  Pro; and RHEL 9 and 10, which covers Rocky Linux and AlmaLinux. Red Hat
  packages count whatever their product, base RHEL or an add-on, unless the
  add-on is set aside.
- **Third-party builds:** no Ubuntu or Red Hat package is affected, but the CVE
  touches a product named in `drafter/thirdparty.toml`, which third-party
  repositories rebuild (PHP: Sury on Ubuntu, Remi on the RHEL family). A bug only
  in PHP 8.4 has no affected Ubuntu 24.04 package, yet Sury's `php8.4` is, as on
  nouriloop-prod. Whether each build is affected is settled at fill-in (A.3, D4),
  by a person confirming. A product matches on NVD's product names or, side by
  side, on words in NVD's description: NVD's names can be days late, or wrong
  (for PHP2Shell it named Palo Alto's PAN-OS, not `php:php`). A match on words
  alone is marked so. Over the 180 days it added 4 CVEs, all PHP add-ons for
  Magento and Joomla ("PHP object injection"): noise to read past, never a miss.
- **No vendor package, and NVD names no product yet:** signalled in the last 30
  days by CISA or by hand, listed by number, since NVD may not have named the
  products yet.
- **Kernels:** only kernel packages. The tool can't judge running kernels until
  its Phase 6 (plan D2), so these get a notice and no pack.
- **Set aside:** only packages or products named in `drafter/setaside.toml`, shown
  with the file's reason. John approves every change to that file.
- **Not on a supported release:** counted; `drafter candidates list --all` lists
  them by number with the products NVD names (mostly Chrome, Windows and
  appliances, and open-source software installed from upstream, such as Drupal).
- **Rated critical by a vendor, no sign of an attack:** counted only (above).
- **Vendor records not read yet:** listed by CVE number, with a reminder to
  refresh.

A vendor's own rating is shown only where it speaks: Red Hat rating a CVE Critical
says nothing about an Ubuntu universe package, so on a CVE with no Red Hat package
on a supported release its rating isn't shown, and likewise for Ubuntu.

Red Hat's container images (OpenShift's CoreOS, say) aren't packages on a host, so
they're left out; `kpatch-patch` (kernel live patches) counts as a kernel. On
Ubuntu, kernels are `linux` and its named flavours (`linux-aws-6.8`,
`linux-signed-hwe-6.8` and so on, listed in `drafter/candidates.py`); other
`linux-*` packages such as `linux-atm`, `linux-base` and `linux-firmware` are
ordinary packages. A new flavour missing from the list shows under "can judge",
not hidden as a notice.

CVEs of one kind that hit the same package families within 14 days are listed
as one threat, so PHP2Shell's two CVEs are one line.

After a parser change, `drafter candidates refresh --reparse` re-reads the stored
vendor records without fetching anything.

## What "network-facing" means here

D3 first counted a vendor's top severity for network-facing packages. CVSS can't
say which those are: Red Hat marks 245 of its 262 Critical CVEs in the 180 days to
2026-11-07 as network-reachable, browser engines included. So the rule became
(John, 2026-11-07): everything on a supported release counts, except a short
reviewed list of set-asides, shown with reasons. Since 2026-11-10 a rating lists
nothing at all (above); the set-asides still sort the CVEs that are attacked.

## After the scope rule (2026-11-10)

The same 180 days from 2026-05-11, on a copy of the real store, with only signs of
an attack listing a CVE:

| Section | Threats | CVEs |
|---|---|---|
| Can judge | 8 | 10 |
| Kernels (notice only) | 4 | 7 |
| Set aside | 1 | 1 |
| Third-party builds | 2 | 4 |
| Not on a supported release | | 156 |
| Rated critical by a vendor, no sign of an attack | | 324 |

About one threat a month and a half that the tool could judge, each of them
attacked. The 30 days to 2026-11-10 went from eight threats under "Can judge" to
four: PHP2Shell, Brotli, Ruby and OpenSSH stayed; .NET, ca-certificates, Java and
edk2 left.

## History test (2026-11-07, when a vendor's rating still listed a CVE)

The 180 days from 2026-05-11, on a copy of the real store: 578 CVEs signalled,
1,156 vendor records read in 5 minutes, none failed.

| Section | Threats | CVEs |
|---|---|---|
| Can judge | 19 | 24 |
| Kernels (notice only) | 8 | 49 |
| Set aside | 11 | 46 |
| Third-party builds | 2 | 4 |
| Not on a supported release | | 352 |

(Re-run after the review fixes. The first run counted 21, 8, 11 and 393: the
difference is mostly old CVEs that CISA re-stamped, which now count from their
first sign, and EOL Ubuntu 25.10.)

About three a month the tool could judge, against the plan's one and
a half from CISA's list alone. Every threat the plan measured is where it should
be: the six kernel CVEs under kernels; Tomcat (CVE-2026-34486), PHP2Shell and
Brotli under "can judge". PHP2Shell appears on 2026-10-21, five days before CISA's
list, and Brotli on 2026-10-23, four days before.

The very first run found three faults, fixed before the PR: Red Hat's rating was
counted for Ubuntu packages (64 threats instead of 21), container images were read
as packages, and kernel live patches weren't counted as kernels.

## Known limits

- A threat with no fix yet and no sign above never appears.
- Package families are guessed from names (`php8.3` is `php`, and `edk2` reads
  as `edk`). CVEs are grouped on the exact set of families, so a CVE touching
  `brotli` and `nodejs` is its own threat, apart from one touching `brotli` alone.
- Red Hat's "affected, no fix yet" comes from its package states; a package it
  hasn't assessed doesn't appear.
