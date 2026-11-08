"""A.4: a person's approve or reject of each threat, kept append-only.

A threat is a group of CVEs the candidate list puts together, and its grouping can
change as CVEs arrive. So a decision keeps the CVEs it was made on, and a threat
reads as decided only while every one of its CVEs stands under that one decision.
A CVE that joined later, or CVEs decided apart, make it ask for a look again.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from drafter.candidates import Threat
from drafter.store import Store

DECIDABLE = ("judge", "thirdparty")  # kernels get a notice (D2); set-asides a file edit
VERDICTS = ("approve", "reject")
MAX_REASON = 1000
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


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


@dataclass(frozen=True)
class State:
    """Where a threat stands: undecided, approve, reject, or look again."""

    word: str  # undecided, approve, reject, again
    decision: Decision | None = None  # the one it stands under, or the latest it touched
    new: tuple[str, ...] = ()  # CVEs no decision covers
    apart: tuple[str, ...] = ()  # CVEs under another decision than `decision`

    @property
    def open(self) -> bool:
        return self.word in ("undecided", "again")


def clean_reason(text: str) -> str:
    """One line of printable text: runs of whitespace become one space."""
    text = " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())
    if not text:
        raise DecisionError("a reason is needed, for an approve as much as a reject")
    if len(text) > MAX_REASON:
        raise DecisionError(f"the reason is {len(text)} characters; {MAX_REASON} at most")
    return text


def record(
    store: Store,
    threat: Threat,
    verdict: str,
    reason: str,
    by: str,
    when: str,
) -> Decision:
    if threat.kind not in DECIDABLE:
        raise DecisionError(f"a {threat.kind} threat isn't approved or rejected here")
    if verdict not in VERDICTS:
        raise DecisionError("the verdict is approve or reject")
    reason = clean_reason(reason)
    cves = tuple(sorted({c.cve for c in threat.candidates}))
    if not cves or not all(_CVE.match(cve) for cve in cves):
        raise DecisionError("a threat is one or more CVE numbers")
    by = " ".join(by.split())[:100] or "?"
    with store.transaction():
        cur = store.db.execute(
            "INSERT INTO decision (decided_at, cves, kind, families, verdict, reason,"
            " decided_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                when,
                json.dumps(list(cves)),
                threat.kind,
                json.dumps(list(threat.families)),
                verdict,
                reason,
                by,
            ),
        )
    return Decision(
        cur.lastrowid, when, cves, threat.kind, tuple(threat.families), verdict, reason, by
    )


def history(store: Store) -> list[Decision]:
    """Every decision, newest first."""
    rows = store.db.execute(
        "SELECT id, decided_at, cves, kind, families, verdict, reason, decided_by"
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


def state(threat: Threat, by_cve: dict[str, Decision]) -> State:
    cves = sorted({c.cve for c in threat.candidates})
    under = {cve: by_cve[cve] for cve in cves if cve in by_cve}
    if not under:
        return State("undecided")
    newest = max(under.values(), key=lambda d: d.id)
    new = tuple(cve for cve in cves if cve not in under)
    apart = tuple(cve for cve, d in under.items() if d.id != newest.id)
    if new or apart:
        return State("again", newest, new, apart)
    return State(newest.verdict, newest)


def describe(st: State) -> str:
    """One line for the command-line list."""
    d = st.decision
    if st.word == "undecided" or d is None:
        return "undecided"
    said = f"{'approved' if d.verdict == 'approve' else 'rejected'} {d.decided_at[:10]}"
    if st.word != "again":
        return f"{said}: {d.reason}"
    parts = []
    if st.new:
        parts.append(f"{', '.join(st.new)} came after it")
    if st.apart:
        parts.append(f"{', '.join(st.apart)} decided apart")
    return f"look again: {said}, but {'; '.join(parts)}"
