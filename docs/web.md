# The candidate page (A.4)

`drafter web` serves the candidate list as a page, where a person approves or
rejects each threat. It runs no AI and drafts nothing: an approval is the go-ahead
a later stage (A.5) will need (it spends AI money, then a person's review and
signature), and a rejection says why not.

    drafter web [--port 8089] [--origin https://packs.localhost:8443] [--days 30]
                [--packs ~/Projects/compromise-checker-packs]
    drafter decisions          # every decision, newest first

## When to approve (A.4b, John, 2026-11-08)

Each card asks one question: would someone running Compromise Checker want a
pack for this? **Approve** when all of these hold:

- it's **exploited**: on CISA's list, or CISA says active;
- the attacked code is **in the packages listed**, not only in a product built on
  them (GitLab on Ruby, say);
- someone can **reach it on a server** the tool checks, from the network or with a
  login an attacker could plausibly get;
- no signed pack **covers it** already.

**Reject** otherwise, and say which test failed: "no sign of attacks", "GitLab,
not Ruby", "not a vulnerability (trust-store update)", "firmware, network boot
only". Whether a fix exists isn't one of the tests: a pack for an attacked threat
with no fix still tells an admin they're exposed.

## What each card says

For the two sections a person decides, from data the drafter already fetched
(nothing is fetched for the page, and nothing is summarised):

- **Attacks:** *Exploited* (on CISA's list, or CISA says active), *Added by hand*
  (with the note), or *No sign of attacks*, with CISA's own word for each CVE,
  "none" included, and the vendor rating that listed it otherwise.
- **What:** one line per CVE, CISA's name for it, else Red Hat's bug title.
- **Reach:** the CVSS vector in words (where from, what login, whether a user must
  act, hard to pull off, only under certain conditions), naming whose score it is:
  a score can belong to a product built on the package (GitLab's 10.0 on a Ruby
  card). NVD's own CVSS 3.1 first, then the reporting organisation's, then 3.0 the
  same way, then 4.0; CISA's scores added to others' CVEs come after all of those.
- **Ratings:** Red Hat's and Ubuntu's own, which put a CVE on the list (plan D3)
  but aren't evidence of attacks.
- **Fix:** the Packages line in one: fixed everywhere, nowhere, or which aren't.
- **What NVD and Red Hat say:** behind a fold, NVD's description and Red Hat's
  statement, each cut to about 600 characters, with a link to the whole record.
  Fetched text: escaped, like everything on the page, and without control or bidi
  characters (which could turn the page's own words around); read by a person only.
  The same words for several CVEs are shown once.
- **Pack** and **Covered:** with `--packs`, the page reads a local clone of
  compromise-checker-packs (`index.yaml`, then each listed `PACK.yaml`'s `cves`).
  A threat whose every CVE one signed pack names reads *Covered*: its form is
  folded behind "Decide anyway", and it isn't counted as still to decide. A pack
  naming only some of the CVEs is shown, and the form stays open. The index's
  signature isn't checked, since a wrong mark only folds a form, but each
  `PACK.yaml` must have the sha256 and version the index lists, so a pack edited
  in the clone (a draft, another branch) doesn't count. Anything odd in the clone
  (a pack missing or edited, an id that doesn't match, a path outside it, YAML
  anchors or aliases, which packs don't use, or nesting past 32 levels) marks
  nothing Covered and says so at the top. A pack naming no CVEs covers nothing.
  Once someone decides a Covered threat, it shows as decided.

Kernel and set-aside cards keep their plain list of signals.

## What it shows

The same sections as `drafter candidates list`, for the last 30 days: **Can
judge** and **Third-party builds** with a form each; **Kernels** (a notice only,
plan D2) and **Set aside** (changed in `setaside.toml`, not here) without one.
Below them, the CVEs that aren't threats here yet, and every decision made.

The window goes by each CVE's first sign, as the list's does. A threat no one has
decided stays on the page after its first sign leaves the window, marked "Before
the 30 days", until someone decides it. The page reads back 180 days (as far as
`candidates refresh` keeps vendor records current), and never before 2026-10-08,
its first window: threats from before the page existed are history, not a backlog.
These older CVEs are grouped among themselves only, so the window's threats are
grouped exactly as `drafter candidates list` groups them.

A CVE that was ever decided is settled once it leaves the window: its last
decision stands, so ageing alone never reopens one. That includes a threat that
read Look again (its packages or section changed) and wasn't decided again while
in the window. Decided threats and notices leave with their window.

Feeds that need a look are named at the top, since the list may then be missing
threats. `drafter candidates list` shows each threat's decision too (over its own
window, 30 days by default).

## Decisions

- **A reason to reject**, one line, at most 1,000 characters. An approve may go
  without one (A.4b): it rests on what the card showed, and a reject is the
  decision someone will ask about later. The store holds the rule too.
- **Append-only.** A decision is never changed or removed (the store refuses
  both). Deciding again adds a new decision that stands in front of the old one;
  both stay in the record.
- **Kept with what was shown.** The list groups CVEs into threats afresh on every
  run, so a decision keeps the CVEs, section and package families it was made on.
  A threat stands under a decision only while all three still match. It reads
  **Look again**, with its form back, if a CVE joined it, one of the decision's
  CVEs is now in another threat, its CVEs were decided apart, it moved section
  (third-party to vendor packages, say), or its package families changed. A CVE
  that has only aged off the list doesn't count.
- **A reject comes back if attacks are reported after it.** Each decision keeps
  the signs of attacks it was made with (on CISA's list, CISA's "active", added by
  hand), CVE by CVE. A reject reads **Look again** when one of its CVEs that had no
  sign of attacks gains one, or one only added by hand gains CISA's, even after the
  30 days (as far back as the page reads). A CVE CISA already called attacked
  doesn't come back when CISA lists it too: that's the same evidence, and the
  reject was made knowing it. A sign re-dated (CISA re-stamps its ratings in
  batches) isn't a new one. An approve doesn't come back this way, and nor does a
  reject made before schema 5, which didn't keep its signs. The form carries the
  signs its card showed, so a decision sent from a page loaded before a new sign
  arrived is refused (409) and the threat shown as it now stands, the reason kept
  in its box.
- **Checked against the list as it is now.** A form for a threat whose CVEs,
  section or package families changed since the page loaded is refused (409);
  the page shows the threat as it now stands, with the reason kept in its box.

## Safety

It is for one person on one laptop (plan D7): it listens on 127.0.0.1 only and has
no login. Any site open in the same browser could still send a form to it, so a
decision is taken only when:

- the `Origin` is the page's own (`--origin`, or 127.0.0.1 and localhost on its
  port), and `Sec-Fetch-Site`, when the browser sends it, says same-origin. (The
  page's referrer policy is `same-origin`, not `no-referrer`: with `no-referrer`
  a browser sends `Origin: null` on the page's own forms, and `null` is refused,
  since sandboxed frames on any site send it too);
- the form carries the token of this run of the server (restarting it means
  loading the page again);
- it is an ordinary form post of at most 8 KB; and
- the `Host` is one the page answers to, which also stops a hostile name being
  pointed at 127.0.0.1 to read the page.

One slow client can't hold up the page (a thread per request).
Everything shown comes from the feeds and is escaped. The page runs no scripts,
and its Content-Security-Policy allows none; it can't be framed.

## Running it

It runs from the same install as the hourly timer
([`feeds.md`](feeds.md), "Running it every hour"), so the two always agree on the
store's schema:

    cp contrib/systemd/pack-drafter-web.service ~/.config/systemd/user/
    systemctl --user daemon-reload
    systemctl --user enable --now pack-drafter-web.service

After each install, restart it (`systemctl --user restart pack-drafter-web`): it
keeps the code it started with. The first open after an install that moves the
store up a schema fills the new columns from the pages already kept (schema 5:
about a minute on a 180-day store), whether that is the page or the hourly run.
The move marks the fill as owed and the fill clears the mark, so one cut short is
done again by the next command or page start. And a Caddy block, like the other local services:

    packs.localhost:8443 {
    	bind 127.0.0.1 ::1
    	tls internal
    	reverse_proxy 127.0.0.1:8089
    }

Try a branch on a copy of the store, on another port:

    DRAFTER_HOME=/some/where .venv/bin/drafter web --port 8099 --origin http://127.0.0.1:8099

The page's fonts are Atkinson Hyperlegible, under the SIL Open Font Licence
([`drafter/static/fonts/OFL.txt`](../drafter/static/fonts/OFL.txt)).
