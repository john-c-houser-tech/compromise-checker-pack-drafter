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
The packages section is not here: `drafter fill` writes it from vendor data (A.3),
and the two come together at the hand-off (A.7).

## What is sent

One request, with no tools, to Claude Opus 5.5 at effort high, answering in a fixed
JSON shape (structured output). It holds:

- **the instructions**: what to write and not write, the pack format as the checker
  documents it, and what the checker has for detections to name: its built-in checks
  (with their titles and variants), the event types and fields a pack's own rule can
  match, and the snapshot sections it can read (`drafter/vocabulary.py`);
- **the sources**, as fetched and kept in the store: NVD's description and score,
  CISA's catalogue entry, and Red Hat's and Ubuntu's records, their words only (bug
  title, details, statement, mitigation, references), never their package lists.
  A source longer than 20,000 characters is cut, and says so where it is cut.

The sources are fetched text, untrusted. The instructions say so, the model has no
tools to act with, and what comes back is checked before anyone reads it.

## What comes back is checked

An answer is refused when:

- it isn't the JSON asked for, or its mitigations or detections aren't YAML lists;
- the checker's own pack format refuses it (`drafter/checkerformat`: the checker's
  `format.py` and `versions.py`, copied at a pinned commit; a test compares them with
  the checker's own when a checkout is beside this one);
- a detection names a check, variant, event type, field or snapshot section the
  checker doesn't have at that commit (the checker would read it as a typo that
  never matches);
- a reference isn't a URL found in the sources;
- it holds a version (three numbers such as 1.2.1, or a vendor build such as
  1.0.9-2ubuntu0.1) outside a URL, or one of the threat's package names that carries
  a digit or a sign (dotnet8.0), anywhere. Two-number figures (a CVSS score of 9.8,
  .NET 8.0) aren't versions of a package here.

A refused answer goes back once with its problems listed; the model's own turn is
sent back unchanged. A second refusal ends the draft: it is written with the reasons
at the top, marked NOT USABLE, and the command exits 1. A.6 will add text checks on
the prose (commands, addresses and URLs no source contains).

## Spending (D6, John, 2026-11-08)

Measured first: one brotli draft cost $0.093 on Opus 5.5 and $0.044 on Sonnet 5.5,
from the same input (about 8,500 tokens in, 3,000 out); Opus was the more accurate.

- **Model:** Claude Opus 5.5.
- **At most $0.50 a draft**, both requests together.
- **At most $10 for the plan**, and at **$5** the drafter stops and says so: John asked
  to be told then. `--past-tell-mark` goes on, once he has said so.

A request is sent only if its worst case fits both caps: input estimated at two
characters a token (high, on purpose), all of it billed as a cache write, and every
one of the 8,000 output tokens allowed used (the measured draft used 2,935, thinking
included; a lower allowance leaves room within $0.50 for a second try). An answer cut
off at the allowance (`max_tokens`) is recorded and reported, not tried again. Each request is recorded in the store before
it is sent, at that worst case, then settled with the real figures. A request that
got no answer (a timeout, a dropped connection) keeps its worst case, since it may
still have run; one the API turned away (HTTP 4xx or 5xx) costs nothing. The record
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
