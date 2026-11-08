# The candidate page (A.4)

`drafter web` serves the candidate list as a page, where a person approves or
rejects each threat with a reason. It runs no AI and drafts nothing: an approval
is the go-ahead a later stage (A.5) will need, and a rejection says why not.

    drafter web [--port 8089] [--origin https://packs.localhost:8443] [--days 30]
    drafter decisions          # every decision, newest first

## What it shows

The same sections as `drafter candidates list`, for the last 30 days: **Can
judge** and **Third-party builds** with a form each; **Kernels** (a notice only,
plan D2) and **Set aside** (changed in `setaside.toml`, not here) without one.
Below them, the CVEs that aren't threats here yet, and every decision made.

The window goes by each CVE's first sign, as the list's does. A threat still to
decide (undecided, or Look again) stays on the page after its first sign leaves
the window, marked "Before the 30 days", until someone decides it: the page reads
back 180 days, as far as `candidates refresh` keeps vendor records current. These
older CVEs are grouped among themselves only, so the window's threats are grouped
exactly as `drafter candidates list` groups them. A CVE that was ever decided is
settled once it leaves the window, so ageing alone never reopens a decision;
decided threats and notices leave with their window.

Feeds that need a look are named at the top, since the list may then be missing
threats. `drafter candidates list` shows each threat's decision too (over its own
window, 30 days by default).

## Decisions

- **A reason every time**, for an approve as much as a reject: one line, at most
  1,000 characters.
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
keeps the code it started with. And a Caddy block, like the other local services:

    packs.localhost:8443 {
    	bind 127.0.0.1 ::1
    	tls internal
    	reverse_proxy 127.0.0.1:8089
    }

Try a branch on a copy of the store, on another port:

    DRAFTER_HOME=/some/where .venv/bin/drafter web --port 8099 --origin http://127.0.0.1:8099

The page's fonts are Atkinson Hyperlegible, under the SIL Open Font Licence
([`drafter/static/fonts/OFL.txt`](../drafter/static/fonts/OFL.txt)).
