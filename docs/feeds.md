# The feeds

The drafter reads seven feeds, Red Hat's advisories, two third-party repositories and the pages a draft's sources link to, from eleven hosts and no others: `www.cisa.gov`,
`services.nvd.nist.gov`, `osv-vulnerabilities.storage.googleapis.com`,
`ubuntu.com`, `access.redhat.com`, `security.access.redhat.com` (Red Hat's
CSAF advisories, read by `drafter fill`), and for `drafter propose`
`api.launchpad.net`, `launchpad.net`, `launchpadlibrarian.net` (Sury) and
`rpms.remirepo.net` (Remi), and for `drafter draft` `api.github.com` (GitHub's
security advisories, B.1). It refuses any other address, plain http,
and any redirect that leaves the list (`drafter/http.py`). The one exception is a
page a person adds on an approved card (B.2, D9): any public https site, by its own
rules (`docs/web.md`), fetched once when added and kept as feed `added`.

Every answer is kept in `drafter.sqlite3` with its address, time, status and
sha256, so a draft can show what it was built from. That includes failures, "not
modified" answers and answers that won't parse: each is recorded before anything
reads it. A body is stored once per feed: a later identical answer points at the
first.

| Feed | What it reads | Kept | Why |
|---|---|---|---|
| `kev` | CISA's Known Exploited Vulnerabilities list, whole, when it changes (`If-None-Match`) | every new version | on CISA's list (D3) |
| `nvd` | NVD's CVE API: every CVE changed since the saved position, in windows of 7 days and pages of 2,000 | every page | CISA's SSVC "exploitation: active" (D3) |
| `osv-ubuntu` | OSV's Ubuntu `modified_id.csv`, then each record not yet read at its listed version | hash of the index; record bodies only for signs of exploitation (below) | Ubuntu's priority, `critical` being its top (D3) |
| `osv-almalinux`, `osv-rockylinux` | the same for AlmaLinux and Rocky Linux | hash of the index; every record | fixed builds for A.3 |
| `usn` | Ubuntu Security Notices, newest first, back to the saved position | every page | notice ids and dates for A.3 |
| `redhat` | Red Hat's Security Data API: CVEs rated Critical, made public since 30 days before the last read | every page | Red Hat's top severity (D3) |

Not read here: Red Hat's CSAF/VEX files and the full records of non-critical
Ubuntu CVEs. A.3 fetches those per threat, when it needs them. A draft fetches the
advisories, bulletins, notices and alerts its sources link to (feed `linked`,
`docs/draft.md`).

## Ubuntu's records

Ubuntu's OSV records list every binary package of every release, Ubuntu Pro
included, so they average about 480 KB each. Some days Ubuntu rewrites thousands
of them (12,189 on 2026-11-06, 9,389 on 2026-10-17). So:

- A record's body is kept only when it is Ubuntu `critical`, or one of its CVEs is
  on CISA's list or rated active in NVD. The hash and time are always kept.
- When more than 1,500 records are waiting, the feed reads Ubuntu's `all.zip`
  (about 810 MB) once instead of fetching each record, which would cost several
  GB. Records the archive lacks, or holds in an older version, are then fetched
  one by one.

Ubuntu's own CVE listing API (`ubuntu.com/security/cves.json`) would give the
priority more cheaply, but it timed out or failed on three tries on 2026-11-07,
so the drafter doesn't depend on it.

## Saved positions

Each feed keeps where its next run starts: the end of the last NVD window read,
the newest notice seen, the time of the last Red Hat read. A feed moves its
position only after what it read is stored, so a run that fails partway keeps
what it finished, and a closed laptop only delays the next read. A feed read for
the first time starts a day back, or at `--since`.

Some feeds aren't strictly in order, so each run reads a little behind its
position: NVD 15 minutes, notices 3 days, Red Hat 30 days. Re-reading is never
counted as a change.

OSV is different. Each run compares the whole index with `osv_seen`, a record of
every index entry handled, whether it was read, withdrawn (404) or unreadable. It
works through every entry since the feed's first start that hasn't been handled
at its listed version. So a record that reaches the bucket late, or that an
archive lacked, is still read, however far behind it is. The saved position just
shows how far along the handled entries run without a gap.

## Is a feed all right?

`drafter feeds status` says, for each feed:

- `ok`: read recently, and something new came within the usual time.
- `failing`: the last run(s) failed, with how many and the error.
- `behind`: no successful read for over a day (the timer isn't running, or the
  laptop was off).
- `quiet`: read fine, but nothing new for longer than usual (CISA 14 days, NVD 1,
  Ubuntu OSV 3, AlmaLinux and Rocky 10, notices 4, Red Hat 21). Worth a look: a
  feed that changed its format can look like one with no news.
- `never`: not read yet.

It exits 1 unless every feed is `ok`.

## A long history

The candidate test in A.2 needs 180 days. NVD, notices and Red Hat reach back
with `--since`. For OSV, read the archive once. Read CISA's list and NVD first:
Ubuntu's bodies are kept only for signs of exploitation, and those come from
CISA's list and NVD.

    drafter feeds fetch kev nvd --since 2026-05-11
    drafter feeds seed osv-ubuntu --since 2026-05-11
    drafter feeds seed osv-almalinux --since 2026-05-11
    drafter feeds seed osv-rockylinux --since 2026-05-11
    drafter feeds fetch --since 2026-05-11
    drafter candidates refresh --since 2026-05-11

Without an NVD key, NVD's 180 days took 40 minutes on 2026-11-07 (409,618 CVEs
changed, about 220 pages, 6.5 seconds apart).

## Running it every hour (plan D7)

    mkdir -p -m 700 ~/.local/share/pack-drafter ~/.config/pack-drafter
    mkdir -p ~/.config/systemd/user
    uv venv -p 3.12 ~/.local/share/pack-drafter/venv
    uv pip install -p ~/.local/share/pack-drafter/venv .     # from the dev checkout
    cp contrib/systemd/pack-drafter-feeds.* ~/.config/systemd/user/
    systemctl --user daemon-reload
    systemctl --user enable --now pack-drafter-feeds.timer

The timer runs its own install, not a working checkout, so work on a branch never
changes what runs every hour. After each merge into `dev`, install again with the
`uv pip install` line above, and restart the candidate page if it runs
([`web.md`](web.md)). A newer drafter upgrades the store's schema when a
writing command (fetch, seed, refresh, add) opens it; reading commands (`feeds
status`, `candidates list`) open it read-only and never do. The hourly install then
refuses an upgraded store until it is installed again (`journalctl --user -u pack-drafter-feeds` says so). So try a branch on a
copy of the store (`sqlite3 drafter.sqlite3 ".backup /some/where/drafter.sqlite3"`,
then `DRAFTER_HOME=/some/where`). An NVD key, if you have one, goes in
`~/.config/pack-drafter/env` as `NVD_API_KEY=...` (mode 0600). It is sent in a
header only, never in an address, so it never reaches the store.

Data lives in `~/.local/share/pack-drafter/` (or `$DRAFTER_HOME`). Two runs never
overlap: a second one exits at once, with code 3.

## Not settled yet

- How much disk a year of hourly reads takes. The first runs kept about 1.5 MB per
  NVD page of 2,000 CVEs and 200 KB per new version of CISA's list. Measured over
  the first week; pruning old answers, if needed, comes with that measurement.
