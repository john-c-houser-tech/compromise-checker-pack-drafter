"""A.4b: what a card says about its threat, so an approve or reject rests on the
card itself: is it being attacked, what is it, who can reach it, is there a fix.

Everything here comes from data already fetched (CISA's list, NVD, Red Hat's
records); nothing is fetched or summarised. The sources' own words are untrusted
text: the page escapes them, and a person reads them, never an AI.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from drafter.candidates import VENDOR_SIGNALS, Threat
from drafter.store import Store

WORDS_CUT = 600  # the sources' words, shown cut short with a link to the rest


@dataclass(frozen=True)
class Facts:
    """What the store holds about one CVE, for its card."""

    cve: str
    kev_added: str | None = None
    kev_name: str | None = None  # CISA's name for the vulnerability
    exploitation: str | None = None  # CISA's SSVC value: none, poc, active
    ssvc_time: str | None = None
    description: str | None = None  # NVD's
    cvss: dict | None = None
    rh_title: str | None = None  # Red Hat's bug title
    rh_statement: str | None = None


def facts(store: Store, cves: list[str]) -> dict[str, Facts]:
    rows: dict[str, dict] = {cve: {} for cve in cves}
    wanted = sorted(rows)
    for start in range(0, len(wanted), 500):
        batch = wanted[start : start + 500]
        marks = ", ".join("?" for _ in batch)
        for row in store.db.execute(
            f"SELECT cve, date_added, name FROM kev WHERE cve IN ({marks})",  # noqa: S608
            batch,
        ):
            rows[row[0]].update(kev_added=row[1], kev_name=row[2] or None)
        for row in store.db.execute(
            "SELECT cve, exploitation, ssvc_time, description, cvss FROM nvd"  # noqa: S608
            f" WHERE cve IN ({marks})",
            batch,
        ):
            rows[row[0]].update(
                exploitation=row[1],
                ssvc_time=row[2],
                description=row[3],
                cvss=_cvss(row[4]),
            )
        for row in store.db.execute(
            "SELECT cve, title, statement FROM vendor_cve"  # noqa: S608
            f" WHERE vendor = 'redhat' AND found = 1 AND cve IN ({marks})",
            batch,
        ):
            rows[row[0]].update(rh_title=row[1], rh_statement=row[2])
    for data in rows.values():
        for name in ("kev_name", "description", "rh_title", "rh_statement"):
            if name in data:
                data[name] = clean(data[name])
    return {cve: Facts(cve, **data) for cve, data in rows.items()}


def _cvss(text: str | None) -> dict | None:
    try:
        value = json.loads(text) if text else None
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _cves(threat: Threat) -> list[str]:
    return sorted({c.cve for c in threat.candidates})


def _all(n: int) -> str:
    return "both" if n == 2 else f"all {n}"


def _per_cve(texts: dict[str, str]) -> str:
    """One text if every CVE has the same, else each CVE with its own."""
    distinct = set(texts.values())
    if len(distinct) == 1:
        text = distinct.pop()
        return text if len(texts) == 1 else f"{text}, for {_all(len(texts))}"
    return ". ".join(f"{cve}: {text}" for cve, text in texts.items())


# is it being attacked?

_SSVC = {"active": "active", "none": "none", "poc": "proof of concept only"}
_RATINGS = {"redhat": "Red Hat's Critical rating", "ubuntu": "Ubuntu's critical priority"}


def attacks(threat: Threat, known: dict[str, Facts]) -> dict:
    """{"word": exploited | hand | none, "text": …}. Exploited: on CISA's list, or
    CISA says active. Added by hand: a person's note, shown as it is."""
    texts, exploited, by_hand = {}, False, []
    for cand in sorted(threat.candidates, key=lambda c: c.cve):
        f = known.get(cand.cve) or Facts(cand.cve)
        parts = []
        if f.kev_added:
            parts.append(f"on CISA's list since {f.kev_added[:10]}")
            exploited = True
        if f.exploitation:
            said = _SSVC.get(f.exploitation, f.exploitation)
            when = f" ({f.ssvc_time[:10]})" if f.ssvc_time else ""
            parts.append(f"CISA says {said}{when}")
            exploited = exploited or f.exploitation == "active"
        else:
            parts.append("CISA hasn't assessed it")
        texts[cand.cve] = "; ".join(parts)
        by_hand += [s.note for s in cand.signals if s.kind == "manual" and s.note]
    text = _per_cve(texts)
    if exploited:
        return {"word": "exploited", "text": text}
    if any(s.kind == "manual" for c in threat.candidates for s in c.signals):
        notes = "; ".join(dict.fromkeys(by_hand)) or "no note"
        return {"word": "hand", "text": f"{text}. Added by hand: {notes}"}
    # Not reached from the page since 2026-11-10 (a rating alone lists nothing):
    # kept so a threat built some other way still says what it rests on.
    kinds = sorted(
        {s.kind for c in threat.candidates for s in c.signals if s.kind in VENDOR_SIGNALS}
    )
    if kinds:
        text += f". Listed on {' and '.join(_RATINGS[k] for k in kinds)} alone"
    return {"word": "none", "text": text}


def ratings(threat: Threat, exploited: bool) -> str:
    cves = _cves(threat)
    names = {"redhat": "Red Hat Critical", "ubuntu": "Ubuntu priority critical"}
    parts = []
    for kind in ("redhat", "ubuntu"):
        rated = sorted({c.cve for c in threat.candidates for s in c.signals if s.kind == kind})
        if not rated:
            continue
        if len(cves) == 1:
            parts.append(names[kind])
        elif rated == cves:
            parts.append(f"{names[kind]} ({_all(len(cves))})")
        else:
            parts.append(f"{names[kind]} ({', '.join(rated)})")
    return "; ".join(parts) or ("none beyond CISA's" if exploited else "none")


# what is it?


def what(threat: Threat, known: dict[str, Facts]) -> list[tuple[str, str]]:
    """(CVE, a one-line name): CISA's, else Red Hat's bug title."""
    out = []
    for cve in _cves(threat):
        f = known.get(cve) or Facts(cve)
        if f.kev_name:
            out.append((cve, f"CISA: {f.kev_name}"))
        elif f.rh_title:
            out.append((cve, f"Red Hat: {f.rh_title}"))
        else:
            out.append((cve, "no name yet; NVD's description is below, if it has one"))
    return out


def clean(text: str | None) -> str | None:
    """Fetched text as one line of printable characters: no control or bidi
    characters, which could turn the page's own words around."""
    if text is None:
        return None
    return " ".join("".join(ch if ch.isprintable() else " " for ch in text).split()) or None


def _cut(text: str) -> str:
    if len(text) <= WORDS_CUT:
        return text
    head = text[:WORDS_CUT]
    space = head.rfind(" ")
    # At a space if there's one near the end; a long run with none (a URL) is cut.
    return (head[:space] if space >= WORDS_CUT - 100 else head) + " …"


def words(threat: Threat, known: dict[str, Facts]) -> list[dict]:
    """The sources' own words, each cut short, with a link to the whole record. The
    same words for several CVEs (Red Hat often writes one statement for both) are
    shown once, naming them all."""
    cves = _cves(threat)
    found: dict[tuple[str, str], list[str]] = {}
    for cve in cves:
        f = known.get(cve) or Facts(cve)
        for source, text in (("redhat", f.rh_statement), ("nvd", f.description)):
            if text:
                found.setdefault((source, text), []).append(cve)
    out = []
    for (source, text), named in sorted(
        found.items(), key=lambda kv: (kv[1][0], kv[0][0] != "redhat")
    ):
        tail = f", {' and '.join(named)}" if len(cves) > 1 else ""
        if source == "redhat":
            cite, link = f"Red Hat's statement{tail}", "https://access.redhat.com/security/cve/"
        else:
            cite, link = f"NVD{tail}", "https://nvd.nist.gov/vuln/detail/"
        out.append({"cite": cite, "text": _cut(text), "link": link + named[0]})
    return out


# who can reach it?

_AV = {
    "N": "over the network",
    "A": "from the same network",
    "L": "with local access",
    "P": "with physical access",
}
_PR = {"N": "no login", "L": "a low-privilege login", "H": "an admin login"}
_UI3 = {"N": "no user action", "R": "needs a user to act"}
_UI4 = {"N": "no user action", "P": "needs a user to act", "A": "needs a user to act"}
_WHO = {
    "nist.gov": "NVD",
    "redhat.com": "Red Hat",
    "microsoft.com": "Microsoft",
    "oracle.com": "Oracle",
    "gitlab.com": "GitLab",
    "php.net": "PHP",
    "google.com": "Google",
    "github.com": "GitHub",
    "mitre.org": "MITRE",
    "canonical.com": "Canonical",
    "ubuntu.com": "Canonical",
    "apache.org": "Apache",
    "cisa.dhs.gov": "CISA",
    "edk2.groups.io": "EDK2",
}


def reach_words(vector: str) -> str | None:
    """A CVSS vector in words: where from, what login, whether a user must act."""
    head, _, rest = vector.partition("/")
    metrics = dict(part.split(":", 1) for part in rest.split("/") if ":" in part)
    v4 = head == "CVSS:4.0"
    parts = [
        _AV.get(metrics.get("AV", "")),
        _PR.get(metrics.get("PR", "")),
        (_UI4 if v4 else _UI3).get(metrics.get("UI", "")),
    ]
    if metrics.get("AC") == "H":
        parts.append("hard to pull off")
    if v4 and metrics.get("AT") == "P":
        parts.append("only under certain conditions")
    parts = [p for p in parts if p]
    if not parts:
        return None
    text = ", ".join(parts)
    return text[0].upper() + text[1:]


# Organisations NVD names by an id rather than an address.
_WHO_IDS = {
    "134c704f-9b21-4f2e-91b3-4a467353bcc0": "CISA",
    "416baaa9-dc9f-4396-8d5f-8c081fb06d67": "kernel.org",
}


def whose(source: str) -> str:
    """Whose score: NVD's, or the organisation that reported it."""
    if source.lower() in _WHO_IDS:
        return f"{_WHO_IDS[source.lower()]}'s"
    domain = source.rpartition("@")[2].lower() if "@" in source else ""
    for known, name in _WHO.items():
        if domain == known or domain.endswith("." + known):
            return f"{name}'s"
    return f"{domain}'s" if domain else "the reporting organisation's"


def reach(threat: Threat, known: dict[str, Facts]) -> list[tuple[str, str]]:
    """(the CVEs it is for, or "" when it is for all, the reach in words)."""
    groups: dict[tuple, list[tuple[str, float]]] = {}
    unscored = []
    for cve in _cves(threat):
        score = (known.get(cve) or Facts(cve)).cvss
        said = (
            reach_words(score["vector"]) if score and isinstance(score.get("vector"), str) else None
        )
        if not said or not isinstance(score.get("score"), int | float):
            unscored.append(cve)
            continue
        key = (said, str(score.get("version", "")), whose(str(score.get("source", ""))))
        groups.setdefault(key, []).append((cve, float(score["score"])))
    lines = []
    for (said, version, who), scored in groups.items():
        numbers = " and ".join(f"{s:.1f}" for _, s in scored)
        plural = "scores" if len(scored) > 1 else "score"
        lines.append(
            (", ".join(c for c, _ in scored), f"{said} (CVSS {version}: {numbers}, {who} {plural})")
        )
    if unscored:
        lines.append((", ".join(unscored), "no CVSS score yet"))
    if len(lines) == 1:
        return [("", lines[0][1])]
    return lines


# is there a fix?


def fix(packages: list[dict]) -> str | None:
    """The Packages line in one: fixed everywhere, nowhere, or which aren't."""
    entries = sorted(
        {
            (p["release"], p["package"], bool(p["fixed"]))
            for p in packages
            if not p.get("set_aside") and not p.get("kernel")
        }
    )
    if not entries:
        return None
    unfixed = [(r, n) for r, n, fixed in entries if not fixed]
    if not unfixed:
        return "Fixed on every listed release"
    if len(unfixed) == len(entries):
        return "No fix yet on any listed release"
    fixed = {(r, n) for r, n, f in entries if f}
    by_release: dict[str, list[str]] = {}
    for release, name in unfixed:
        label = f"{name} (one stream)" if (release, name) in fixed else name
        by_release.setdefault(release, []).append(label)
    parts = [f"{' and '.join(names)} on {release}" for release, names in by_release.items()]
    done = len(entries) - len(unfixed)
    return f"Fixed for {done} of {len(entries)}; no fix yet: {', '.join(parts)}"
