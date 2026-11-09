# Proposal: detection weights a draft can justify (2026-11-09)

**Status: proposed, waiting for John.**

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

- **D11. A weight past one band over the check's own: refuse, or note?**
  Recommended: refuse it (the checker would cut it silently), and only note one at
  or below the band.
- **D12. Where do the reasons go: the draft's header only, or into the pack too?**
  Recommended: the header only. A pack carries what the checker reads, and the
  signer reads the reasons before signing.
