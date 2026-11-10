"""A.4: a person's approve or reject of each threat, kept append-only.

A threat is a group of CVEs the candidate list puts together, and its grouping can
change as CVEs arrive. So a decision keeps the CVEs it was made on, and a threat
reads as decided only while every one of its CVEs stands under that one decision.
A CVE that joined later, or CVEs decided apart, make it ask for a look again.

A reason is needed to reject, not to approve (A.4b): an approve rests on what the
card showed, a reject is the decision someone will ask about later. And a reject
keeps the signs of attacks it was made with, so a new one brings it back.

An approve says what the attack would leave on a server (the checker's scope,
2026-11-10: a pack is for an attack seen in the wild that leaves signs there), and
every CVE under it has a sign of an attack. An approve from before that rule which
covers a CVE with no such sign asks for a look again, and is never drafted from.
"""

from __future__ import annotations

import json
from collections.abc import Collection
from dataclasses import dataclass

from drafter.candidates import ATTACK_SIGNALS, Threat
from drafter.feeds import CVE_ID
from drafter.store import Store

DECIDABLE = ("judge", "thirdparty")  # kernels get a notice (D2); set-asides a file edit
SECTION_NAMES = {"judge": "Can judge", "thirdparty": "Third-party builds"}
VERDICTS = ("approve", "reject")
MAX_REASON = 1000
MAX_LEAVES = 500


class DecisionError(ValueError):
    pass


@dataclass(frozen=True)
class Decision:
    id: int
    decided_at: str
    cves: tuple[str, ...]
    kind: str
    families: tuple[str, ...]
    verdict: str
    reason: str
    decided_by: str
    # The signs of attacks it was made with ("kev:CVE-…"); None if made before
    # schema 5, when they weren't kept, and so never brought back by one.
    signs: tuple[str, ...] | None = None
    # An approve's answer to "what would it leave on a server?"; None for a reject,
    # and for an approve made before schema 9 asked.
    leaves: str | None = None


@dataclass(frozen=True)
class State:
    """Where a threat stands: undecided, approve, reject, or look again."""

    word: str  # undecided, approve, reject, again
    decision: Decision | None = None  # the one it stands under, or the latest it touched
    new: tuple[str, ...] = ()  # CVEs no decision covers
    apart: tuple[str, ...] = ()  # CVEs under another decision than `decision`
    moved: tuple[str, ...] = ()  # CVEs `decision` covered that are in another threat now
    section: str | None = None  # the section `decision` was made in, if not this one
    families: tuple[str, ...] | None = None  # what `decision` was shown, if not these
    attacked: tuple[str, ...] = ()  # signs of attacks since a reject, described
    unattacked: tuple[str, ...] = ()  # CVEs an approve covers with no sign of an attack

    @property
    def open(self) -> bool:
        return self.word in ("undecided", "again")


def clean_reason(text: str, verdict: str = "reject") -> str:
    """One line of printable text: runs of whitespace become one space. Needed to
    reject; an approve may go without."""
    text = " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())
    if not text and verdict != "approve":
        raise DecisionError("a reason is needed to reject: say which test it fails")
    if len(text) > MAX_REASON:
        raise DecisionError(f"the reason is {len(text)} characters; {MAX_REASON} at most")
    return text


def clean_leaves(text: str) -> str:
    """An approve's one line on what the attack would leave on a server."""
    text = " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())
    if not text:
        raise DecisionError(
            "to approve, say what the attack would leave on a server (a pack is for"
            " signs the checker can look for); if it leaves nothing, reject it"
        )
    if len(text) > MAX_LEAVES:
        raise DecisionError(f"what it leaves is {len(text)} characters; {MAX_LEAVES} at most")
    return text


def without_a_sign(cves: Collection[str], signs: Collection[str]) -> tuple[str, ...]:
    """The CVEs that none of these signs of attacks ("kev:CVE-…") is about."""
    have = {key.split(":", 1)[1] for key in signs}
    return tuple(sorted(cve for cve in cves if cve not in have))


def record(
    store: Store,
    threat: Threat,
    verdict: str,
    reason: str,
    by: str,
    when: str,
    *,
    leaves: str = "",
) -> Decision:
    """`leaves`: what the attack would leave on a server; needed to approve, and
    not kept with a reject."""
    if threat.kind not in DECIDABLE:
        raise DecisionError(f"a {threat.kind} threat isn't approved or rejected here")
    if verdict not in VERDICTS:
        raise DecisionError("the verdict is approve or reject")
    reason = clean_reason(reason, verdict)
    cves = tuple(sorted({c.cve for c in threat.candidates}))
    signs = tuple(sorted(attack_signs(threat)))
    if not cves or not all(CVE_ID.match(cve) for cve in cves):
        raise DecisionError("a threat is one or more CVE numbers")
    left = None
    if verdict == "approve":
        bare = without_a_sign(cves, signs)
        if bare:
            raise DecisionError(
                f"no sign of an attack on {', '.join(bare)}: a pack is for attacks seen in the wild"
            )
        left = clean_leaves(leaves)
    by = " ".join(by.split())[:100] or "?"
    with store.transaction():
        cur = store.db.execute(
            "INSERT INTO decision (decided_at, cves, kind, families, verdict, reason,"
            " decided_by, signs, leaves) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                when,
                json.dumps(list(cves)),
                threat.kind,
                json.dumps(list(threat.families)),
                verdict,
                reason,
                by,
                json.dumps(list(signs)),
                left,
            ),
        )
    return Decision(
        cur.lastrowid,
        when,
        cves,
        threat.kind,
        tuple(threat.families),
        verdict,
        reason,
        by,
        signs,
        left,
    )


def history(store: Store) -> list[Decision]:
    """Every decision, newest first."""
    rows = store.db.execute(
        "SELECT id, decided_at, cves, kind, families, verdict, reason, decided_by, signs,"
        " leaves"
        " FROM decision ORDER BY id DESC"
    ).fetchall()
    return [
        Decision(
            row["id"],
            row["decided_at"],
            tuple(json.loads(row["cves"])),
            row["kind"],
            tuple(json.loads(row["families"])),
            row["verdict"],
            row["reason"],
            row["decided_by"],
            None if row["signs"] is None else tuple(json.loads(row["signs"])),
            row["leaves"],
        )
        for row in rows
    ]


def latest(decided: list[Decision]) -> dict[str, Decision]:
    """Each CVE's latest decision (`decided` newest first, as `history` gives it)."""
    out: dict[str, Decision] = {}
    for decision in decided:
        for cve in decision.cves:
            out.setdefault(cve, decision)
    return out


def attack_signs(threat: Threat) -> dict[str, str]:
    """The threat's signs of attacks now: {"kev:CVE-…": "on CISA's list 2026-10-29 (CVE-…)"}."""
    return {
        f"{sig.kind}:{cand.cve}": f"{sig.describe()} ({cand.cve})"
        for cand in threat.candidates
        for sig in cand.signals
        if sig.kind in ATTACK_SIGNALS
    }


CISA_SIGNS = ("kev", "nvd")  # CISA's list and CISA's "active": one source of evidence


def attacked_since(decision: Decision, threat: Threat) -> tuple[str, ...]:
    """New signs of attacks on a reject's own CVEs, described. A sign is news when
    its CVE had none of its kind of evidence then: CISA listing a CVE it already
    called active is the same evidence, and the reject was made knowing it; but
    CISA confirming a CVE that was only added by hand is news. Only a reject comes
    back this way, and only one that kept its signs (schema 5 on). CVEs the reject
    didn't cover are another matter ("came after it")."""
    if decision.verdict != "reject" or decision.signs is None:
        return ()
    had_cisa = {k.split(":", 1)[1] for k in decision.signs if k.split(":", 1)[0] in CISA_SIGNS}
    had_any = {k.split(":", 1)[1] for k in decision.signs}
    out = []
    for key, text in sorted(attack_signs(threat).items()):
        kind, cve = key.split(":", 1)
        if cve not in decision.cves or key in decision.signs:
            continue
        if cve not in (had_cisa if kind in CISA_SIGNS else had_any):
            out.append(text)
    return tuple(out)


def unattacked_under(decision: Decision) -> tuple[str, ...]:
    """The CVEs an approve covers that had no sign of an attack when it was made:
    one from before the scope rule, when a vendor's rating listed a CVE. It isn't
    drafted from, and its threat asks for a look again. An approve from before
    schema 5 kept no signs, so it can't be told and is left alone."""
    if decision.verdict != "approve" or decision.signs is None:
        return ()
    return without_a_sign(decision.cves, decision.signs)


def shown_signs(threat: Threat) -> str:
    """The signs of attacks a card showed, as its form sends them back."""
    return ",".join(sorted(attack_signs(threat)))


def state(threat: Threat, by_cve: dict[str, Decision], listed: Collection[str] = ()) -> State:
    """A threat stands under a decision only if that decision was made on just
    these CVEs, in this section, shown with these package families. `listed`: the
    CVEs in any threat now, so one of the decision's CVEs that has since moved to
    another threat counts, and one that has aged off the list doesn't."""
    cves = sorted({c.cve for c in threat.candidates})
    under = {cve: by_cve[cve] for cve in cves if cve in by_cve}
    if not under:
        return State("undecided")
    newest = max(under.values(), key=lambda d: d.id)
    new = tuple(cve for cve in cves if cve not in under)
    apart = tuple(cve for cve, d in under.items() if d.id != newest.id)
    moved = tuple(cve for cve in newest.cves if cve not in cves and cve in listed)
    section = newest.kind if newest.kind != threat.kind else None
    families = newest.families if newest.families != tuple(threat.families) else None
    attacked = attacked_since(newest, threat)
    unattacked = unattacked_under(newest)
    if new or apart or moved or section or families is not None or attacked or unattacked:
        return State("again", newest, new, apart, moved, section, families, attacked, unattacked)
    return State(newest.verdict, newest)


def describe(st: State) -> str:
    """One line for the command-line list."""
    d = st.decision
    if st.word == "undecided" or d is None:
        return "undecided"
    said = f"{'approved' if d.verdict == 'approve' else 'rejected'} {d.decided_at[:10]}"
    if st.word != "again":
        said = f"{said}: {d.reason}" if d.reason else said
        return f"{said} (would leave: {d.leaves})" if d.leaves else said
    parts = []
    if st.new:
        parts.append(f"{', '.join(st.new)} came after it")
    if st.apart:
        parts.append(f"{', '.join(st.apart)} decided apart")
    if st.moved:
        parts.append(f"{', '.join(st.moved)} now in another threat")
    if st.section:
        parts.append(f"made under {SECTION_NAMES.get(st.section, st.section)}")
    if st.families is not None:
        parts.append(f"shown as {', '.join(st.families) or '?'}")
    if st.attacked:
        parts.append(f"attacks reported since: {', '.join(st.attacked)}")
    if st.unattacked:
        parts.append(f"it covers {', '.join(st.unattacked)}, with no sign of an attack")
    return f"look again: {said}, but {'; '.join(parts)}"
