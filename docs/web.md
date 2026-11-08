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

Feeds that need a look are named at the top, since the list may then be missing
threats. `drafter candidates list` shows each threat's decision too.

## Decisions

- **A reason every time**, for an approve as much as a reject: one line, at most
  1,000 characters.
- **Append-only.** A decision is never changed or removed (the store refuses
  both). Deciding again adds a new decision that stands in front of the old one;
  both stay in the record.
- **Kept with its CVEs.** The list groups CVEs into threats afresh on every run,
  so a decision keeps the CVEs it was made on. If a CVE joins a decided threat
  later, or its CVEs were decided apart, the threat reads **Look again** and gets
  its form back.
- **Checked against the list as it is now.** A form for a threat whose CVEs or
  section changed since the page loaded is refused (409), and the page shows the
  threat as it now stands.

## Safety

It is for one person on one laptop (plan D7): it listens on 127.0.0.1 only and has
no login. Any site open in the same browser could still send a form to it, so a
decision is taken only when:

- the `Origin` is the page's own (`--origin`, or 127.0.0.1 and localhost on its
  port), and `Sec-Fetch-Site`, when the browser sends it, says same-origin;
- the form carries the token of this run of the server (restarting it means
  loading the page again);
- it is an ordinary form post of at most 8 KB; and
- the `Host` is one the page answers to, which also stops a hostile name being
  pointed at 127.0.0.1 to read the page.

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
