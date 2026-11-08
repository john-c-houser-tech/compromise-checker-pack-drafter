# Compromise Checker pack drafter

Working name. This program helps a person write threat packs for
[Compromise Checker](https://github.com/john-c-houser-tech/compromise-checker).
It watches public feeds for exploited threats that touch packages the checker can
judge, fills in package versions from vendor data, and says plainly what it can't
fill in. A person approves every pack, and signs it by hand.

The drafter reads only public data. It holds no signing key, no GitHub token and
no evidence from anyone's machines, so it can't publish anything by itself.

**Status:** Stage 1 is built. A.1 reads the feeds
([`docs/feeds.md`](docs/feeds.md)), A.2 lists the candidates
([`docs/candidates.md`](docs/candidates.md)), A.3 drafts a threat's packages from
vendor data ([`docs/fill.md`](docs/fill.md)) and proposes third-party builds for a
person to confirm ([`docs/thirdparty.md`](docs/thirdparty.md)). In Stage 2, A.4 is
a page to approve or reject each threat, whose cards say whether it's attacked, what
it is, who can reach it and whether a signed pack covers it
([`docs/web.md`](docs/web.md)), and A.5 drafts an approved threat's title,
detections and remediation with an AI, within set caps, and A.6 holds what it
writes to the sources ([`docs/draft.md`](docs/draft.md)).
The plan is in
[`plans/pack-application-plan-2026-10-31.md`](plans/pack-application-plan-2026-10-31.md).

    uv venv -p 3.12 .venv && uv pip install -p .venv -e ".[dev]"
    .venv/bin/drafter feeds fetch
    .venv/bin/drafter feeds status
    .venv/bin/drafter candidates refresh
    .venv/bin/drafter candidates list [--all]
    .venv/bin/drafter propose CVE-… --binaries GLOB… --out proposals.toml
    .venv/bin/drafter fill CVE-… --binaries GLOB… [--thirdparty proposals.toml] [--compare PACK.yaml]
    .venv/bin/drafter web [--packs ../compromise-checker-packs]   # https://packs.localhost:8443, through Caddy
    .venv/bin/drafter decisions
    .venv/bin/drafter draft CVE-… [--dry-run] [--out FILE]   # ANTHROPIC_API_KEY set
    .venv/bin/drafter spend

## Licence

The program is licensed under the GNU Affero General Public License, version 3
(see [`LICENSE`](LICENSE)). The packs it helps write are data, published
separately in
[compromise-checker-packs](https://github.com/john-c-houser-tech/compromise-checker-packs)
under CC BY 4.0.

Copyright © 2026 NouriLoop LLC.
