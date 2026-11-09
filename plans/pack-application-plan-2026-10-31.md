# Pack application build plan — 2026-10-31

> **Status: 2026-11-09.** Stage 1 (A.1–A.3) built; A.4 and A.4b (the decision page) built; A.5 (AI drafts) built and used (seven drafts, $0.57); A.6 (text checks) built; A.7 (assembly) built, the first pack (brotli) assembled and signed; A.8 (proof) built (checker #157), and brotli proved, checked against the vendors' pages and published 2026-11-08; A.9 run 2026-11-09, compared in `plans/a9-php2shell-comparison-2026-11-09.md`. D1–D7 settled.
> Starts from the outline agreed on 2026-10-30, in Compromise Checker's
> `plans/phase4-build-plan-2026-10-30.md`, "After Phase 4: the pack application".

**Goal:** when an exploited threat touches packages Compromise Checker can
judge, a person hears about it quickly and gets a draft pack that is right about
versions, says plainly what it doesn't know, and takes far less than the hand
work PHP2Shell took. A person still approves it, and still signs it by hand.

The application stands apart from the tool. It reads only public data, and holds
no signing key and no customer evidence.

## What the feeds showed (checked 2026-10-31)

Measured before planning, against live feeds and the signed PHP2Shell pack.

**How often it would fire.** CISA's exploited list added 179 CVEs in the last 180
days. Ten have a fix on current Ubuntu (OSV) or RHEL 9/10 (Red Hat's API), which
makes nine threats:

| Threat | Added to the list | Can the tool judge it today? |
|---|---|---|
| Linux kernel: CVE-2022-0995, CVE-2026-53362, CVE-2025-39964, CVE-2026-53266, CVE-2025-39682, CVE-2026-46300 | Aug 26 to Oct 28 | **No**, not until the tool's Phase 6 (D2) |
| Apache Tomcat: CVE-2026-34486 | Aug 4 | Yes |
| PHP2Shell: CVE-2026-109618, CVE-2026-109619 | Oct 26 | Yes |
| Brotli: CVE-2026-111497 | Oct 27 | Yes, but a library inside many packages (dotnet, firefox, nodejs) |

So about one and a half threats a month, and six of the nine are kernels. The
count leaves out threats with no fix yet and anything the list never names.

**The list is late.** PHP2Shell's first attacks were on October 21 and the fixes
came out that day, but it joined the list on October 26. A watcher reading only
this list would have been five days behind.

**How much the vendors' data fills in.** The PHP2Shell pack has 72 package entries:

| Source | Entries | Structured data? |
|---|---|---|
| Ubuntu | 5 | Yes: USN JSON and OSV give fixed versions and binary package names |
| Red Hat | 12 | Yes: its API and CSAF, including module builds |
| AlmaLinux | 7 | Yes: OSV, `ALSA-` (Rocky too, `RLSA-`) |
| Sury PPA | 26 | Partly: Launchpad lists uploads, but nothing links an upload to a CVE |
| Remi | 22 | No: blog posts and the repository's listings |

Only a third of the entries can be filled in mechanically. The other two thirds
are third-party repositories, and those were why PHP2Shell mattered to
nouriloop-prod. The feeds also don't supply the `versions` globs, and those plus
the package lists are what the first vendor check of the hand draft found wrong.
"Versions from vendor data" holds for fixed versions, not for the whole package
section.

## Ground rules

- **The AI writes no version, package name or glob.** After it answers, those
  fields are replaced from vendor data, and an answer that contains them is
  refused.
- **Fetched text is untrusted**, as host text is to the advisor. The AI has no
  tools, and answers in a fixed structure.
- **What the AI writes reaches people**: an advisory could steer it into telling
  admins to run something. Remediation prose gets its own checks (A.6), and every
  field in the review screen says where it came from: vendor, AI or a person.
- **Nothing is spent before approval.** The AI drafts only threats a person
  approved.
- **No key and no GitHub token.** The application writes a file on a local branch.
  A compromised application can't publish anything.
- **Don't touch a file after signing it.** The file is frozen and its hash shown
  before signing, and the signature is checked before the hand-off finishes.
- **Every draft is validated by `checker.packs.format`**, the tool's own reader,
  pinned to a tool commit.
- **Reviews and proofs as in the tool:** agent review first, then Copilot; Linode
  runs need John's OK per PR.

## Pull requests

Each stage is useful alone, and there is a stop at the end of the first.

### Stage 1: watch and fill in (no AI, no web interface)

**A.1 Feeds.** Fetch CISA's list, NVD, OSV (Ubuntu, AlmaLinux, Rocky), Ubuntu's
notices and Red Hat's API, from a fixed list of addresses. Keep each answer with
its hash and time in SQLite, so a draft can show what it was built from. A feed
that fails or goes quiet says so.

**A.2 Candidates.** A threat becomes a candidate when it has a package on a
release the tool supports and a sign of exploitation (see D3). A person can also
add one by CVE number, since PHP2Shell reached John before any feed. Output is a
plain list on the command line. *Test against history:* the last 180 days must
give the nine threats above, and PHP2Shell before October 26.

**A.3 Fill-in.** Build the `packages` section from vendor data. Third-party
repositories come out as a named list of what isn't covered, and a threat in
every build of a package gets `other_builds: cant_judge` (D4). *Test against
history:* the Ubuntu, Red Hat and AlmaLinux entries against the signed PHP2Shell
pack, with every difference explained.

**Stop here and look.** John decides whether to go on, knowing the real number of
candidates and how far the fill-in got. If the answer is one real pack every two
months, the list and fill-in may be enough, without A.4 and A.5.

*Stopped and looked (2026-11-07):* first seen Oct 13 to Nov 6, 7 threats the
tool can judge, 1 kernel notice, 3 set aside, 1 waiting for NVD, 35 on no
supported release. Fill-in against the signed PHP2Shell pack: 2 cases less
cautious with every third-party proposal confirmed, both explained; none "not
affected" with none confirmed; 58 Sury and Remi proposals, 96 entries of the
100 allowed. **John: go on as far as A.4**; A.5 waits for its own go-ahead.

### Stage 2: approve and draft

*Binary filter (John, 2026-11-07):* which binaries count is a judgement about the
threat (PHP2Shell names only the web-serving SAPIs), so each draft takes a short
filter of globs from a person, applied to every vendor's binary list; what it
leaves out is listed release by release. Without a filter every binary is
included, marked "not filtered". A.3 comes in two PRs: A.3a (Ubuntu, Red Hat,
AlmaLinux from vendor data, `versions` patterns derived by rule, compared entry by
entry with the signed PHP2Shell pack) and A.3b (Sury and Remi, propose and
confirm).

**A.4 Web interface.** A small server-rendered page at
`https://packs.localhost:8443`: candidates, approve or reject with a reason, in an
append-only record.

*A.4b (John, 2026-11-08):* the first cards gave no basis to decide on (one titled
"ruby" was a GitLab flaw; four of seven had CISA saying "no exploitation"), and a
reason was asked for the wrong way round. Approved as proposed: a reason only to
reject; each card says whether it's attacked, what it is, who can reach it and
whether there's a fix, from data already fetched; threats a signed pack names read
Covered; a reject comes back if attacks are reported after it; the approve tests
written into `docs/web.md`.

**A.5 Drafting.** For an approved threat only: title, mitigations, detections and
remediation, from the fetched advisories. Answers are validated, retries bounded,
the cost recorded per draft and held to a cap (D6). Detections may only use what
the format allows. *Go-ahead: John, 2026-11-08; built as `drafter draft`
([`docs/draft.md`](../docs/draft.md)).*

**A.6 Text checks.** Refuse references that weren't among the fetched sources.
Flag commands, addresses and URLs in prose that no source contains. Test with
hostile advisories planted in each feed. *Go-ahead: John, 2026-11-08 ([`docs/draft.md`](../docs/draft.md), "Text
checks"): made-up ones refused, sourced ones listed for the signer, dangerous ones
refused wherever they came from.*

### Stage 3: release

**A.7 Hand-off.** Write `PACK.yaml` on a branch of a local packs clone, show what
changed since the last version, freeze it, and print the signing command. Then
check the signature and run `checker packs index`. *Go-ahead: John, 2026-11-08; built as `drafter pack
template|write|check` ([`docs/assemble.md`](../docs/assemble.md)): a person's assembly
file holds the id, window, weight, binary filter and `packages_from` (the Java case).*

*To settle before assembling (found 2026-11-08):* a threat whose fix is in another
package. Red Hat lists the Java packages for CVE-2026-91403 as "will not fix", because
RHEL is fixed by the ca-certificates update (CVE-2026-114406); `drafter fill` reads
that as "no fix", so a pack assembled from fill and the Java draft would show every
RHEL host with Java as vulnerable forever, updated or not. The ruby and edk2 threats
have no fix yet either, but one may still come. A person decides at assembly which
packages such a pack is judged from (here, perhaps ca-certificates), or whether it
needs a pack of its own.

**A.8 Proof.** A proof built from the pack's own entries (D5): the checker's
`tests/integration/pack_proof.py`, beside its other Linode proofs. Without `--go` it
prints the plan (one server per release the pack names; RHEL on Rocky, or Alma with
`--alma`) and creates nothing.

**A.9 A real one.** Regenerate PHP2Shell without looking at the signed pack and
compare the two: what was missed, what was wrong, how long it took. Then do the
first new threat for real, through review, proof and John's signature.

## Decisions to settle (one at a time)

- **D1. Which repository? DECIDED (John, 2026-10-31): its own**, not the packs
  repository as the outline said. The packs repository stays CC BY 4.0 signed data
  that sites pull from, with no code in it. Compromise Checker's Phase 4 plan is corrected.
  **Visibility and licence (John, 2026-11-07):** private on GitHub until the
  Stage 1 stop, then public under AGPL-3.0, like the checker (the drafter imports
  `checker.packs.format`). Packs it produces stay CC BY 4.0. No outside code
  without a contributor agreement; NouriLoop LLC holds the copyright.
- **D2. Kernels? DECIDED (John, 2026-10-31):** watch them from A.2 and mark them
  "the tool can't judge this yet". Kernel support goes into the tool as its Phase 6,
  after its web interface (Phase 5); design in the tool's DESIGN.md section 10.5.
  Until then kernel threats get a notice and no pack.
- **D3. What counts as a sign of exploitation? DECIDED (John, 2026-11-07):** any
  of CISA's exploited list, CISA's SSVC "exploitation: active" in NVD, or Ubuntu's
  or Red Hat's top severity on a network-facing package, plus adding by hand with
  a CVE number. Tuned against A.2's history test (CISA's list alone was five days
  late on PHP2Shell).
  **"Network-facing" (John, 2026-11-07): count everything, set aside a reviewed
  list.** Every package on a supported release counts, except those in a short
  file of set-asides, each with a reason (desktop-only such as `webkit2gtk3`, or
  add-on products the tool doesn't judge, such as Ansible Automation Platform).
  Set-aside threats still show in the candidate list under their own heading;
  John approves changes to the file. Measured first: CVSS "network" marks 245 of
  Red Hat's 262 Critical CVEs, so it filters nothing; of 52 Critical on RHEL 9/10,
  33 were `webkit2gtk3` and 10 Ansible Automation Platform. Ubuntu's 108 critical
  records were 106 kernels and PHP2Shell's two CVEs. Red Hat rated PHP2Shell
  Important, not Critical.
- **D4. Third-party repositories? DECIDED (John, 2026-11-07): propose and
  confirm, never filled in silently.** Sury: from Launchpad's upload list, the
  first upload carrying the fixed version, shown with its changelog entry for a
  person to confirm. Remi: the same if its repository metadata carries changelogs
  (checked at A.3, and John told which way it went), otherwise by hand. Anything
  not confirmed reads `cant_judge`, never "not affected".
  **Checked 2026-11-07: Remi gets propose-and-confirm too.** Every Remi repository
  publishes `other` metadata (RPM changelogs). Builds Remi patches himself (PHP
  7.4, 8.0, 8.1) name the CVE: 101 packages in `enterprise/9/modular` name
  CVE-2026-109618. Builds that track upstream (8.4 and so on) only say "Update to
  8.4.26" with a link to PHP's release notes, so they are proposed by upstream
  version, like Sury. The metadata keeps only the last three changelog entries per
  package, so an older fix is proposed from version numbers alone, with no
  changelog line to show.
- **D5. Proof for each generated pack? DECIDED (John, 2026-11-08):** PHP2Shell's
  proof was written by hand. A general one (install the last vulnerable and the first fixed
  build on one image per family, and check the verdicts), about a cent a server; each
  run with John's OK, under a Linode cap of $10 for this plan, stopping to tell John
  at $5.
- **D6. AI budget? DECIDED (John, 2026-11-08):** Claude Opus 5.5; at most $0.50 a
  draft and $10 for the plan, stopping to tell John at $5. **Per-draft cap raised to
  $0.75 (John, 2026-11-09)** for B.1's linked pages: under $0.50, with room for a
  second try, the drafter's high estimate let only about 40,000 characters of them in. Measured first on one
  brotli draft from the same input: Opus 5.5 $0.093, Sonnet 5.5 $0.044; Opus the more
  accurate (Sonnet gave NVD's score to CISA and cited another CVE's page).
- **D7. Where does it run? DECIDED (John, 2026-11-07), for now:** on the laptop,
  a systemd user timer about hourly, each feed read from a saved position so a
  closed laptop only delays it; no public login page. Reconsider if the tool gets
  take-up (a small Linode of its own, about $5 a month, would hear within the
  hour).

## Not proved or not known yet

- Ubuntu ESM and Pro releases are in OSV, but the tool's releases don't cover them.
- Red Hat's own advisories (`RHSA-`) didn't resolve under that id in OSV, so the
  plan reads Red Hat from its own API and CSAF.
- How much of the prose and detections an AI gets right is unmeasured until A.5.
  The tool's detections name events it can actually collect, so a threat with no
  sign in those events may correctly get none.
