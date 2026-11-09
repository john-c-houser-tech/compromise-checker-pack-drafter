# Proposal: detection weights a draft can justify (2026-11-09)

**Status: approved as written (John, 2026-11-09); D11 and D12 decided the same day. Next: C.1.**

## The problem

A.9 and B.3 found the drafts' detection weights far below the signed PHP2Shell
pack's: worker-child 20 where the signed pack has 100, new-script-hit 5 or absent
where it has 50. The cause isn't caution. The AI doesn't know how the checker uses
a weight.

**How the checker uses a weight** (its `docs/scoring.md`, "A threat pack's
detections"):
- A pack that names one of the checker's own checks can only **raise** that check's
  finding, while the detection counts, to the pack's ratio.
- The raise goes at most **one band above** the check's own band: low (1.5) to
  medium's 4, medium (4) to high's 20, high (20) to critical's 100.
- A weight **at or below the check's own band changes nothing**. A finding is never
  lowered.
- A pack's own rule (events or snapshot) weighs at most 20.

**What the drafter tells the AI:** only that a check's "findings then weigh up to
likelihood_ratio 100". It never sends each check's band, and nothing checks the
weights it picks. The B.3 draft against the bands:

| Detection | Check's band | B.3 weight | Effect | Signed pack |
|---|---|---|---|---|
| worker-child | high (20) | 20 | none | 100: raised to critical |
| new-script-hit | high (20) | (left out) | — | 50: raised |
| reverse-shell | high (20) | 20 | none | (not named) |
| web-shell (files.web) | high (20) | 8 | none | (not named) |
| scratch programs | high for programs, medium for scripts | 4 | none | (not named) |
| service segfault | medium if network-facing and repeated, else low | 2 | raises a low one to 2 | (own rule, php-crash 8) |
| error burst (web.errors) | low (1.5) | 2 | raises to 2 | 4: raised to medium |

So the B.3 draft raised almost nothing. The signed pack raised exactly the two signs
that mean PHP2Shell worked (a web worker starting a program, a new script answering
requests), and left the noisy ones near their bands.

## The proposal

1. **Send the AI each check's band** as the checker documents it (`docs/checks.md`
   at the pinned commit), with the rule above in plain words and the band table
   with its examples. The bands are kept in `drafter/vocabulary.py`, written once
   by `scripts/vocabulary.py` and read through by a person, since a few depend on
   what was found ("high for programs, medium for scripts"). A drift test checks
   them, as it does for the checks' titles.
2. **Say what a raise is for.** Raise a sign one band when it is what this threat's
   success looks like on a host exposed to it: a web worker starting a shell after a
   remote code execution in PHP. Leave common signs (crashes, error bursts, core
   dumps) at or near their band, since they happen on clean hosts too. Name a check
   at its band only to tie it to the exposure window, and say so.
3. **Ask for a reason for each weight.** The answer gets a `weights` list: one
   sentence for each detection on why that sign, on a host exposed to this threat,
   is that much more likely to mean compromise. The reasons go in the draft's
   header for the reviewer, not in the pack.
4. **Check the weights** (D11):
   - a weight above one band over the check's own: **refused** and sent back, since
     the checker would cut it without saying so;
   - a weight at or below the band: a **note** for the signer ("names web.errors at
     1.5, its band: it adds nothing to the score");
   - a check whose band depends on what was found is held to the higher band for
     the refusal and the lower one for the note.

**No examples from signed packs** go in the prompt. They would anchor every draft
(as the template's "(PHP2Shell: 5)" did) and spoil comparisons like A.9.

## Cost

The bands and the rule add about 4,000 characters to the instructions, under 1¢ a
draft by the drafter's high estimate. The reasons add a few hundred output tokens.
The caps (D6) are unchanged.

## Steps

- **C.1** The bands in the vocabulary (script, the pinned table, drift test), the
  prompt, the `weights` field and its header lines, the D11 checks. Tests, two
  reviews, a PR. Spends nothing.
- **C.2** One PHP2Shell draft (about $0.25 to $0.40, with John's OK), compared with
  the signed pack's weights and B.3's.

## Decisions for John (one at a time)

- **D11. A weight past one band over the check's own: refuse, or note? DECIDED
  (John, 2026-11-09): refuse**, and send it back once with the reason (the checker
  would cut it silently); only note one at or below the band.
- **D12. Where do the reasons go: the draft's header only, or into the pack too?
  DECIDED (John, 2026-11-09): the header only.** A pack carries what the checker reads, and the
  signer reads the reasons before signing.

## C.2: two drafts with the bands (2026-11-09)

The drafts are `drafts/php2shell-c2.draft.yaml` ($0.40 in two requests) and
`drafts/ruby-gitlab-c2.draft.yaml` ($0.11 in one). That makes $1.45 of $10 spent.

**PHP2Shell**, against B.3 (before C.1) and the signed pack:

| Detection | Band | B.3 | C.2 | Signed |
|---|---|---|---|---|
| worker-child (web.worker_child) | medium to high | 20 (no effect) | **50** | 100 |
| reverse-shell (process.reverse_shell) | high | 20 (no effect) | **50** | — |
| web-shell (files.web) | low to high | 8 (no effect) | 20 | — |
| new-script-hit (web.new_script_hit) | high | — | 20, kept at its band "to tie it to the window" | 50 |
| segfault (kernel.segfault) | low to medium | 2 | 2 | (own rule, 8) |
| error burst (web.errors) | low | 2 | 1.5, kept at its band | 4 |
| timeouts (own rule) | — | 2 | 2 | — |

**Ruby and GitLab** (no signed pack, so nothing to copy):
- worker-shell is raised to 40, "held below critical because GitLab legitimately runs child processes";
- reverse-shell is raised to 50;
- process.executable is held at 20;
- segfault and core dump stay at their bands (4).

**What C.1 changed:**
- The weights now do something. They raise the signs that mean the threat worked,
  past their band, and hold the noisy ones at or below theirs. B.3 raised almost
  nothing.
- Every weight comes with a reason, and the reasons are specific to the threat and
  the source: CISA names PHP workers starting shells as the sign to watch.
- The notes caught what a signer needs to know: worker-child's interpreter findings
  only reach 20, and new-script-hit and web.errors at their bands add nothing.

**Still different from the signed pack:**
- The draft raises less: worker-child 50 against 100, and new-script-hit left at
  20 against 50.
- It still has no exploit-specific crash rule (the signed pack's php-crash, at least
  6 in 10 minutes, at 8).

These are judgment calls the signer makes, and the reasons now show where they
differ.

**Seen twice, worth fixing:** the first PHP2Shell answer again gave php.ini
mitigations without PHP's default setting (`memory_limit`, `fatal_error_backtraces`),
which the format refuses. The retry costs about $0.15 each time. Fix it in the
instructions: a php_ini mitigation must give PHP's own default, and one the sources
don't give goes in remediation.
