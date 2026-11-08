# AI drafts (A.5)

`drafter draft` asks an AI for the parts of a pack that vendor data can't fill: the
title, mitigations, detections, remediation and references, plus a list of what the
sources leave unknown. It drafts **approved threats only** (`drafter web`, A.4), and
a person reviews and signs everything it writes.

    drafter draft CVE-2026-111497 --dry-run      # what would be sent, and its most possible cost
    ANTHROPIC_API_KEY=$(op read "op://Personal/Anthropic API Key/notesPlain") \
        drafter draft CVE-2026-111497 --out brotli.draft.yaml
    drafter spend                                # every request sent, and the caps

Give the CVEs of one approve, all of them: a threat is drafted as it was approved.
Without `ANTHROPIC_API_KEY` set, nothing is sent or recorded. A draft doesn't take
the hourly run's lock (and leaves a fill owed after a schema move to the hourly run
and the page): it writes only its spending rows, each with the caps checked
in the same transaction as the row, so the hourly run and a draft never turn each
other away. `--dry-run` also says when a real run would stop (exit 1).
The packages section is not here: `drafter fill` writes it from vendor data (A.3),
and the two come together at the hand-off (A.7).

## What is sent

One request, with no tools, to Claude Opus 5.5 at effort high, answering in a fixed
JSON shape (structured output). It holds:

- **the instructions**: what to write and not write, the pack format as the checker
  documents it, and what the checker has for detections to name: its built-in checks
  (with their titles and variants), the event types and fields a pack's own rule can
  match (as `checker/events.py` writes them: sudo's details as tty, pwd and runas,
  sshd's invalid as invalid_user, a message's pid and the journal's own fields, and
  `program` on any event), and the snapshot sections it can read
  (`drafter/vocabulary.py`);
- **the sources**, as fetched and kept in the store: NVD's description and score,
  CISA's catalogue entry, and Red Hat's and Ubuntu's records, their words only (bug
  title, details, statement, mitigation, references), never their package lists.
  A source longer than 20,000 characters is cut, and says so where it is cut, and
  its `<`, `>` and `&` are escaped, so it can't close its block or pose as another.

The sources are fetched text, untrusted. The instructions say so, the model has no
tools to act with, and what comes back is checked before anyone reads it.

## What comes back is checked

An answer is refused when:

- it isn't the JSON asked for, or its mitigations or detections aren't YAML lists
  the checker's own reader takes (no anchors or aliases, no deep nesting, YAML 1.2);
- the checker's own pack format refuses it (`drafter/checkerformat`: the checker's
  `format.py` and `versions.py`, copied at a pinned commit; a test compares them with
  the checker's own when a checkout is beside this one);
- a detection names a check, variant, event type (exact, or a prefix ending in "."
  that some type starts with), event field or snapshot section the checker doesn't
  have at that commit (the checker would read it as a typo that never matches), or
  matches a snapshot item's fields (the drafter doesn't know each section's fields
  yet, so a snapshot rule matches the item's key only);
- a reference isn't, exactly, an address found in the sources' words (one copied
  with the `&amp;` it was sent as is read as the address);
- it holds a version outside a URL: three numbers however written (1.2.1, v1.2.1,
  1.2.1rc1, but not a four-number address such as 127.0.0.1), a version pattern
  (1.2.*, 8.0.x), or a vendor build (1.0.9-2ubuntu0.1); or any package name the
  vendors give for these CVEs, on any release, that carries a digit or a sign
  (dotnet8, openjdk-18, edk2-hwe), anywhere and in any case, unless the sources
  themselves use it as a word for the software (every source calls it EDK2). Two-number figures (a CVSS score of 9.8, .NET 8.0) aren't
  versions of a package here. Both are looked for in the answer as sent and as
  read, so a YAML escape (`1\x2E2\x2E1`) hides nothing.

An answer that breaks the reading itself is refused, never a crash: it has been
paid for, and its cost and text are kept. A refused answer goes back once with its
problems listed; the model's own turn is sent back unchanged. A second refusal ends
the draft: it is written marked NOT USABLE, with the reasons, and the answer as
comments only (a YAML reader finds nothing in it), and the command exits 1. A.6 will add text checks on
the prose (commands, addresses and URLs no source contains).

## Spending (D6, John, 2026-11-08)

Measured first: one brotli draft cost $0.093 on Opus 5.5 and $0.044 on Sonnet 5.5,
from the same input (about 8,500 tokens in, 3,000 out); Opus was the more accurate.

- **Model:** Claude Opus 5.5.
- **At most $0.50 a draft**, both requests together.
- **At most $10 for the plan**, and the drafter stops before a request that could
  take the total past **$5** and says so: John asked to be told then.
  `--past-tell-mark` goes on, once he has said so.

A request is sent only if its worst case fits both caps: input estimated at two
characters a token (high, on purpose), plus, for a second try, every token the first
answer used (its thinking is sent back and billed, though its text comes back empty), all of it billed as a cache write, and every
one of the 8,000 output tokens allowed used (the measured draft used 2,935, thinking
included; a lower allowance leaves room within $0.50 for a second try). An answer cut
off at the allowance (`max_tokens`) is recorded and reported, not tried again. Each request is recorded in the store before
it is sent, at that worst case, then settled with the real figures. A request that
got no answer (a timeout, a dropped connection) keeps its worst case, since it may
still have run, as does any other failure once the row is written; one the API
turned away (HTTP 4xx or 5xx), or that never reached it (no connection made: offline,
DNS), costs nothing. A store too busy to write the row stops the draft before
anything is sent; one too busy to settle it (after two minutes' wait) leaves the
row at its worst, which only overcounts, and the answer goes into the draft file,
which says so. An `--out` that can't be written is refused before anything is sent. The record
can't be deleted. `drafter spend` lists it.

If the model declines (a `refusal`), that is recorded and reported, and nothing else
is tried: another model could cost more than the caps were set for. Write that pack
by hand.

## The draft file

It starts with where everything came from: the CVEs and their approve, the model,
each request with its cost and request id, and each source with its fetch id and
sha256 in the store. Then the AI's list of what the sources leave unknown, as
comments, then the parts as YAML: `title`, `mitigations`, `detections`,
`remediation`, `references`. Every line of it is the AI's until a person has read it.
