# Proposal: sources beyond the vendor records (2026-11-09)

**Status: approved as written (John, 2026-11-09); D8, D9 and D10 decided the same day. Next: B.1.**

## The problem

A.9 (`plans/a9-php2shell-comparison-2026-11-09.md`) found that the drafter's AI
sees only NVD, CISA's catalog entry and the Red Hat and Ubuntu CVE records. Most
of what the regenerated PHP2Shell pack missed was on pages those records link to,
or on pages nobody linked:

- the upload-progress mitigation;
- how the flaw is reached, and which setups are exposed;
- what to look for in the logs;
- when the details leaked and when attacks began.

## What was within reach

PHP2Shell's eight sources link to 17 pages. The drafter fetched none of them.
Three of those pages hold most of what was missed:

| Page | Size as text | What it gives |
|---|---|---|
| PHP's advisory GHSA-6wmf-4rv5-p3rp (GitHub) | 12,400 characters | `session.upload_progress.enabled=0` blocks the shown route; `fatal_error_backtraces=0` on 8.5; mod_php exposed, FPM only through `PHP_VALUE`; look for fatal, parse and uncaught errors and "Maximum execution time exceeded" |
| PHP's advisory GHSA-w8hw-w9fx-j79w (GitHub) | 5,400 characters | the triggers (multipart requests without a declared length, unlimited part headers); `memory_limit=-1` is a partial mitigation; don't use RLIMIT_AS |
| CISA's alert of 2026-10-21 | 4,300 characters | patch internet-facing first; a WAF may help meanwhile; watch for PHP workers starting shells; links to NCSC-NL's php2shell repository, the PHP Foundation's post, NSA and five national CERT alerts |

These pages don't give the leak date or the first attacks (Sansec, Cloudflare).
Nothing the drafter holds links to those. Red Hat writes "see the security
bulletin" but gives no address for it.

## The proposal

### 1. Linked advisories, fetched with the draft

When it drafts, the drafter reads the addresses in the sources it already has.
It fetches only pages of these kinds:

| Kind | Addresses | How it's read |
|---|---|---|
| A project's security advisory | `github.com/OWNER/REPO/security/advisories/GHSA-…` | GitHub's API, as JSON |
| A reviewed advisory | `github.com/advisories/GHSA-…` | GitHub's API, as JSON |
| A vendor's security bulletin | `access.redhat.com/security/vulnerabilities/…` | page text |
| A vendor's security notice | `ubuntu.com/security/notices/USN-…` | page text |
| A CISA alert | `cisa.gov/news-events/alerts/…` | page text |

They're fetched in that order of priority, at most six per draft, and each is cut
at 20,000 characters, as sources are now. Each page is stored like every other
fetch, with its time and SHA-256, and listed in the draft's header beside the
others.

**Not fetched:** NVD and cve.org (already held); catalogue and directive pages;
bug trackers; home pages. Bug trackers are noisy and often half-private.

### 2. Sources a person adds

The approve card gets an "add a source" field, for pages nobody linked: a
researcher's write-up (Sansec), a CDN's first sighting (Cloudflare), a bulletin
whose address isn't given (Red Hat's RHSB). Rules for these:

- **Any host**, over https, but never a private or loopback address. Redirects
  must stay on https.
- **Fetched when added**, and shown as "added by jch" with its time.
- **The same caps** as every other source, and the same treatment as data.
- **Linked pages listed.** The card also lists the addresses found in fetched
  pages that weren't fetched: the two-hop links, such as NCSC-NL's repository
  from CISA's alert. One click adds one.

A person, not the drafter, decides to fetch from a site outside the list.

### 3. What changes downstream

- **The draft:** the new pages are sources like the others. The rule that their
  text is data, never instructions, applies unchanged.
- **The text checks (A.6):** a setting, command or address is accepted only if a
  source says it. With PHP's advisory fetched, `session.upload_progress.enabled`
  can become a mitigation; without it, it can't.
- **References** may cite the new pages.
- **Assembly:** `first_seen_in_wild` and an earlier window start can cite a
  source a person added. The assembly file names it.

## Cost (D6 is unchanged)

For PHP2Shell the three linked pages add about 22,000 characters. The drafter's
estimate of 2 characters a token is high, so that's at most 11,000 tokens, about
5 cents. The draft would then cost about $0.17 against $0.12 now.

The worst case is ten full pages (six linked, four added), 200,000 characters.
That could pass the $0.50 per-draft cap. So the new pages share a budget of
100,000 characters per draft. Past that, the lowest-priority pages are left out,
and the draft's header says which. The dry run shows all this before anything is
sent.

## What this won't fix

- **Detection weights.** The draft weighted worker-child at 20, where the signed
  pack has 100. That's prompt work: give the AI each built-in check's band and
  ask it to justify its ratio. It's a separate change.
- **Unlinked pages** stay a person's job, for example Sansec's timeline.
- **Exploit-specific detections** (PHP2Shell's crash and memory-error bursts)
  will still need research write-ups, which a person adds.

## Steps

- **B.1** Fetch the linked advisories: the allowed kinds, the GitHub API, HTML to
  text with the standard library, storage, the draft's input and header, the
  shared budget. Tests, two reviews, a PR.
- **B.2** Sources a person adds, and the two-hop links, on the card.
- **B.3** Run A.9 again: one PHP2Shell draft with the new sources, about $0.20,
  compared with the signed pack and with the first regeneration.

## Decisions for John (one at a time)

- **D8. Which kinds of page are fetched automatically? DECIDED (John, 2026-11-09):**
  the five above, and nothing else, until a run shows a need.
- **D9. Sources a person adds: from any https host, apart from private
  addresses? DECIDED (John, 2026-11-09): yes**, with the safeguards in section 2:
  https only, redirects staying on https, never a private or loopback address,
  fetched only when added, the same caps, data not instructions, marked as added.
- **D10. A shared budget of 100,000 characters for the new pages in each draft?
  DECIDED (John, 2026-11-09): yes**, so the $0.50 cap from D6 still holds. Past it,
  linked pages go first, from the end of D8's order; pages a person added are kept
  longest. The header names what was left out.
