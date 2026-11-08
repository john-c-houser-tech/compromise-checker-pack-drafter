"""A.7: one pack, assembled for signing, in a clone of the packs repository.

A pack comes from three things: the AI's draft of the prose, read and accepted by a
person (A.5, A.6); the packages, from vendor data (`drafter fill`, A.3); and what only
a person decides, in an assembly file (TOML): the pack's id and version, when the
threat became usable, how much exposure weighs, which binaries count, and whose
vendor data the packages come from (a threat fixed in another package's update is
judged from that package's).

    drafter pack template CVE… --draft FILE --packs CLONE   # an assembly file to edit
    drafter pack write ASSEMBLY.toml --packs CLONE          # the pack, frozen, for signing
    drafter pack check ID --packs CLONE                      # after signing: signature, index

`write` reads the result exactly as the checker does (drafter.checkerformat), puts
it at packs/ID/PACK.yaml on a new branch of the clone, makes it read-only, records
its SHA-256, shows what changed since the last version, and prints the signing
command. `check` refuses a file changed since then, checks the signature against the
clone's keys.yaml with minisign, and writes the index with the checker's own
`checker packs index`. Nothing here holds a key, signs, commits or pushes: signing
is by hand, and the pull request is a person's.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import datetime as dt
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import tomllib
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from drafter import draft as drafting
from drafter import fill, textcheck, timeutil
from drafter.checkerformat import format as packformat
from drafter.feeds import CVE_ID
from drafter.store import Store

PACK_KEY = "~/nouriloop-keys/pack.key"  # where John keeps it; never read here
_ID = re.compile(r"\A[a-z0-9][a-z0-9-]{0,62}\Z")  # the checker's pack id
_GIT_TIMEOUT = 60


class AssembleError(Exception):
    pass


# the assembly file


@dataclass
class Assembly:
    id: str
    version: int
    draft: Path
    reviewed_by: str
    window_start: dt.datetime
    likelihood_ratio: float
    binaries: list[str]
    # Per family (ubuntu, rhel): CVEs whose vendor data stand in for the pack's own on
    # that family's releases, with the person's reason (the Java case: RHEL is fixed by
    # the ca-certificates update, while Ubuntu's own records for the CVE still count).
    packages_from: dict[str, list[str]] | None = None
    packages_from_reason: str = ""
    by_hand: list[fill.Entry] = field(default_factory=list)  # a person's own entries
    # Each gap the vendor data leaves that a person accepts: (the start of its line, why).
    accepted: list[tuple[str, str]] = field(default_factory=list)
    first_seen_in_wild: dt.datetime | None = None
    window_end: dt.datetime | None = None
    other_builds: str = "cant_judge"
    thirdparty: Path | None = None
    stale_code: list[str] | None = None
    text: str = ""


def _when(value: Any, name: str) -> dt.datetime:
    if isinstance(value, dt.datetime):
        when = value if value.tzinfo else value.replace(tzinfo=dt.UTC)
    elif isinstance(value, dt.date):
        when = dt.datetime(value.year, value.month, value.day, tzinfo=dt.UTC)
    else:
        raise AssembleError(f"{name} is a date or time, like 2026-10-22T00:00:00Z")
    return when.astimezone(dt.UTC)


FAMILIES = {"ubuntu": ("ubuntu", "sury"), "rhel": ("redhat", "alma", "remi")}  # by fill origin
_VENDOR_OF = {"ubuntu": "ubuntu", "rhel": "redhat"}


def _printable(text: str, name: str) -> str:
    """Text that goes into the signed pack's comments: one line, nothing hidden."""
    if any(not ch.isprintable() or unicodedata.category(ch) == "Cf" for ch in text):
        raise AssembleError(f"{name} holds a hidden or control character")
    return text


def _by_hand(item: Any) -> fill.Entry:
    """A package entry a person writes: what the vendor data couldn't (a release Red
    Hat calls affected with no fixed build to take binary names from, say)."""
    keys = {"release", "binary_names", "versions", "fixed", "source", "note"}
    if not isinstance(item, dict) or set(item) - keys or not {"release", "binary_names",
                                                               "source"} <= set(item):  # fmt: skip
        raise AssembleError(
            "exposure.by_hand: each entry has release, binary_names and source, and may have"
            " versions, fixed (none: no fix yet) and note"
        )
    release = item["release"]
    if not isinstance(release, str) or not re.fullmatch(r"(ubuntu|rhel):[\d.]+", release):
        raise AssembleError(f"exposure.by_hand: release like ubuntu:24.04 or rhel:9: {release!r}")
    names = item["binary_names"]
    if not isinstance(names, list) or not names or not all(isinstance(n, str) for n in names):
        raise AssembleError("exposure.by_hand: binary_names is a list of names")
    for key in ("versions", "fixed", "source", "note"):
        if key in item and not isinstance(item[key], str):
            raise AssembleError(f"exposure.by_hand: {key} is text")
    note = _printable(" ".join(str(item.get("note", "")).split()), "by_hand note")
    return fill.Entry(
        release,
        list(names),
        item.get("versions"),
        item.get("fixed"),
        item["source"],
        "byhand",
        f"added by a person{': ' + note if note else ''}",
    )


def read_assembly(path: Path) -> Assembly:
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise AssembleError(f"{path}: not TOML: {exc}") from None
    exposure = data.get("exposure")
    if not isinstance(exposure, dict):
        raise AssembleError("the assembly file has no [exposure] table")
    known_top = {"id", "version", "draft", "reviewed_by", "exposure"}
    known_exp = {
        "window_start", "first_seen_in_wild", "window_end", "likelihood_ratio", "binaries",
        "packages_from", "packages_from_reason", "other_builds", "thirdparty", "stale_code",
        "by_hand", "accept",
    }  # fmt: skip
    odd = sorted(set(data) - known_top) + sorted(f"exposure.{k}" for k in set(exposure) - known_exp)
    if odd:
        raise AssembleError(f"not something an assembly file says: {', '.join(odd)}")
    pack_id = data.get("id")
    if not isinstance(pack_id, str) or not _ID.match(pack_id):
        raise AssembleError("id: lower-case letters, digits and hyphens, like brotli-2026-10")
    version = data.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise AssembleError("version is a whole number from 1")
    reviewed = data.get("reviewed_by")
    if not isinstance(reviewed, str) or not reviewed.strip():
        raise AssembleError("reviewed_by: who read the draft and stands by it")
    draft_path = data.get("draft")
    if not isinstance(draft_path, str) or not draft_path:
        raise AssembleError("draft: the reviewed draft file")
    lr = exposure.get("likelihood_ratio")
    if isinstance(lr, bool) or not isinstance(lr, int | float):
        raise AssembleError("exposure.likelihood_ratio: how much exposure weighs (more than 1)")
    binaries = exposure.get("binaries")
    if not isinstance(binaries, list) or not all(isinstance(b, str) for b in binaries):
        raise AssembleError("exposure.binaries: the binary filter, a list of globs ([] for none)")
    packages_from = exposure.get("packages_from")
    if packages_from is not None and (
        not isinstance(packages_from, dict)
        or not packages_from
        or set(packages_from) - set(FAMILIES)
        or not all(
            isinstance(v, list) and v and all(isinstance(c, str) and CVE_ID.match(c) for c in v)
            for v in packages_from.values()
        )
    ):
        raise AssembleError(
            "exposure.packages_from: per family, the CVEs whose vendor data stand in,"
            ' like {rhel = ["CVE-2026-114406"]}'
        )
    reason = exposure.get("packages_from_reason", "")
    if packages_from and (not isinstance(reason, str) or not reason.strip()):
        raise AssembleError(
            "exposure.packages_from_reason: why, in a sentence (it goes in the pack)"
        )
    stale = exposure.get("stale_code")
    if stale is not None and (
        not isinstance(stale, list) or not all(isinstance(p, str) for p in stale)
    ):
        raise AssembleError('exposure.stale_code: program globs to restart, like ["php-fpm*"]')
    third = exposure.get("thirdparty")
    if third is not None and not isinstance(third, str):
        raise AssembleError("exposure.thirdparty: a proposals file from `drafter propose`")
    other = exposure.get("other_builds", "cant_judge")
    if other not in fill.OTHER_BUILDS:
        raise AssembleError(f"exposure.other_builds is one of {', '.join(fill.OTHER_BUILDS)}")
    by_hand = []
    for item in exposure.get("by_hand") or []:
        by_hand.append(_by_hand(item))
    accepted = []
    for item in exposure.get("accept") or []:
        if (
            not isinstance(item, dict)
            or set(item) != {"gap", "reason"}
            or not all(isinstance(v, str) and v.strip() for v in item.values())
        ):
            raise AssembleError(
                'exposure.accept: each is {gap = "the start of the gap\'s line", reason = "why"}'
            )
        accepted.append(
            (" ".join(item["gap"].split()), _printable(" ".join(item["reason"].split()), "reason"))
        )
    if "window_start" not in exposure:
        raise AssembleError("exposure.window_start: when the threat became usable")
    return Assembly(
        id=pack_id,
        version=version,
        draft=Path(os.path.expanduser(draft_path)),
        reviewed_by=_printable(" ".join(reviewed.split()), "reviewed_by"),
        window_start=_when(exposure["window_start"], "exposure.window_start"),
        likelihood_ratio=float(lr),
        binaries=list(binaries),
        packages_from=(
            {f: sorted(set(c)) for f, c in packages_from.items()} if packages_from else None
        ),
        packages_from_reason=_printable(" ".join(str(reason).split()), "packages_from_reason"),
        by_hand=by_hand,
        accepted=accepted,
        first_seen_in_wild=(
            _when(exposure["first_seen_in_wild"], "exposure.first_seen_in_wild")
            if "first_seen_in_wild" in exposure
            else None
        ),
        window_end=(
            _when(exposure["window_end"], "exposure.window_end")
            if "window_end" in exposure
            else None
        ),
        other_builds=other,
        thirdparty=Path(os.path.expanduser(third)) if third else None,
        stale_code=list(stale) if stale else None,
        text=text,
    )


# the reviewed draft


@dataclass
class Reviewed:
    cves: list[str]
    parts: dict[str, Any]  # title, mitigations, detections, remediation, references
    sha256: str
    decision_id: int | None = None  # the approve it was drafted under


_CVES_LINE = re.compile(
    r"^# CVEs: ((?:CVE-\d{4}-\d{4,9}(?:, )?)+)(?: \(approved [^,]*, decision (\d+)\))?", re.M
)
PARTS = ("title", "mitigations", "detections", "remediation", "references")


def read_draft(path: Path) -> Reviewed:
    """A draft file as a person left it: an AI draft, not refused, its parts read
    the way the checker reads a pack."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise AssembleError(f"draft: {exc}") from None
    text = data.decode("utf-8", errors="replace")
    if not text.startswith("# AI DRAFT"):
        raise AssembleError(f"{path} isn't a draft from `drafter draft`")
    if "\n# NOT USABLE" in text:
        raise AssembleError(f"{path} is a refused draft: draft the threat again")
    found = _CVES_LINE.search(text)
    if not found:
        raise AssembleError(f"{path} doesn't say which CVEs it drafts")
    try:
        parts = packformat.load(data)
    except packformat.PackError as exc:
        raise AssembleError(f"{path}: {exc}") from None
    want = set(PARTS)
    if not isinstance(parts, dict) or set(parts) != want:
        raise AssembleError(f"{path} should hold just: {', '.join(sorted(want))}")
    return Reviewed(
        found.group(1).split(", "),
        parts,
        hashlib.sha256(data).hexdigest(),
        int(found.group(2)) if found.group(2) else None,
    )


def edited(store: Store, reviewed: Reviewed, decision_id: int) -> list[str] | None:
    """The parts a person changed from the AI's last accepted answer for this approve,
    or None if no such answer is on record."""
    row = store.db.execute(
        "SELECT answer FROM ai_request WHERE decision_id = ? AND settled = 1"
        " AND problems = '[]' AND answer IS NOT NULL ORDER BY id DESC LIMIT 1",
        (decision_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        answer = json.loads(row[0])
        ai = {
            "title": answer["title"],
            "mitigations": packformat.load(str(answer["mitigations_yaml"]).encode()) or [],
            "detections": packformat.load(str(answer["detections_yaml"]).encode()) or [],
            "remediation": answer["remediation"],
            "references": answer["references"],
        }
    except (ValueError, KeyError, TypeError, packformat.PackError):
        return None
    return [k for k in PARTS if _plain(ai[k]) != _plain(reviewed.parts[k])]


def _plain(value: Any) -> Any:
    """For comparing what the AI wrote with the draft file: YAML's own types aside."""
    return json.loads(json.dumps(value, default=str))


# the packs clone


def _git(clone: Path, *args: str) -> str:
    try:
        done = subprocess.run(  # noqa: S603 - git, with fixed arguments
            ["git", "-C", str(clone), *args],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            check=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},  # a read-only fetch never asks
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AssembleError(f"git: {exc}") from None
    if done.returncode != 0:
        raise AssembleError(f"git {' '.join(args)}: {done.stderr.strip()[:300]}")
    return done.stdout


def listed_version(clone: Path, pack_id: str) -> int | None:
    """The version the clone's index lists for a pack, or None."""
    try:
        index = packformat.load((clone / "index.yaml").read_bytes())
    except (OSError, packformat.PackError) as exc:
        raise AssembleError(f"{clone}/index.yaml can't be read: {exc}") from None
    for entry in (index or {}).get("packs") or []:
        if isinstance(entry, dict) and entry.get("id") == pack_id:
            version = entry.get("version")
            return version if isinstance(version, int) else None
    return None


BASE_BRANCH = "dev"  # pack pull requests go into dev (John merges)


def _clone(path: Path) -> Path:
    clone = Path(os.path.expanduser(path)).resolve()
    if not (clone / "index.yaml").is_file() or not (clone / "keys.yaml").is_file():
        raise AssembleError(f"{clone} isn't a clone of the packs repository (no index.yaml)")
    if _git(clone, "status", "--porcelain").strip():
        raise AssembleError(f"{clone} has changes not committed: start from a clean clone")
    branch = _git(clone, "branch", "--show-current").strip()
    if branch != BASE_BRANCH:
        raise AssembleError(
            f"{clone} is on {branch or 'no branch'}: a pack starts from {BASE_BRANCH}, pulled"
            f" (git switch {BASE_BRANCH} && git pull)"
        )
    return clone


def withdrawn(clone: Path) -> set[str]:
    try:
        index = packformat.load((clone / "index.yaml").read_bytes())
    except (OSError, packformat.PackError) as exc:
        raise AssembleError(f"{clone}/index.yaml can't be read: {exc}") from None
    out = set()
    for item in (index or {}).get("withdrawn") or []:
        out.add(item.get("id") if isinstance(item, dict) else item)
    return out


# writing the pack


@dataclass
class Written:
    path: Path
    sha256: str
    branch: str
    diff: str
    report: str
    notes: list[str]
    base: str = ""
    replaced: list[str] = field(default_factory=list)  # packages_from, said plainly
    needs_a_person: list[str] = field(default_factory=list)
    edits: list[str] | None = None  # parts changed from the AI's answer; None: unknown


def _yaml(value: Any) -> str:
    return yaml.safe_dump(value, sort_keys=False, allow_unicode=False, width=88)


def _iso(when: dt.datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def compose(
    a: Assembly,
    reviewed: Reviewed,
    filled: fill.Draft,
    published: dt.date,
    edits: list[str] | None = None,
) -> str:
    """The pack's text: where each part came from, as comments, then the pack."""
    if edits is None:
        how = "an AI draft (no accepted AI answer on record to compare it with)"
    elif edits:
        how = f"an AI draft, edited by a person ({', '.join(edits)})"
    else:
        how = "an AI draft, unedited"
    lines = [
        f"# {reviewed.parts['title']}"[:200],
        "# Assembled by the pack drafter (A.7). Where each part came from:",
        f"#   prose (title, mitigations, detections, remediation, references): {how},"
        f" read and accepted by {a.reviewed_by} (draft sha256 {reviewed.sha256[:16]})",
        f"#   packages: vendor data for {', '.join(reviewed.cves)} (`drafter fill`)",
    ]
    for family, cves in (a.packages_from or {}).items():
        lines.append(
            f"#     except {family}: from {', '.join(cves)} instead, because"
            f" {a.packages_from_reason}"[:400]
        )
    lines += [
        "#   id, version, window, weight, binary filter: the person's assembly file",
        "format: 1",
        f"id: {a.id}",
        f"version: {a.version}",
        _yaml({"title": reviewed.parts["title"]}).rstrip("\n"),
        f"published: {published.isoformat()}",
        f"cves: [{', '.join(reviewed.cves)}]",
        "exposure:",
        f"  window_start: {_iso(a.window_start)}",
    ]
    if a.first_seen_in_wild:
        lines.append(f"  first_seen_in_wild: {_iso(a.first_seen_in_wild)}")
    if a.window_end:
        lines.append(f"  window_end: {_iso(a.window_end)}")
    lr = a.likelihood_ratio
    lines.append(f"  likelihood_ratio: {int(lr) if lr.is_integer() else repr(lr)}")
    # fill's own header (unreviewed, unsigned) is for its draft, not this pack
    lines += [ln for ln in fill.render_yaml(filled).rstrip("\n").splitlines() if ln.startswith(" ")]
    if a.stale_code:
        lines.append(f"  stale_code: {{programs: {json.dumps(a.stale_code)}}}")
    for key in ("mitigations", "detections", "remediation", "references"):
        lines += _yaml({key: reviewed.parts[key]}).rstrip("\n").splitlines()
    return "\n".join(lines) + "\n"


def check_text(text: str, reviewed: Reviewed, found: list[drafting.Source]) -> list[str]:
    """What stops a pack: the checker's reading, its vocabulary, and the dangers A.6
    refuses (a person's edits too: a pack never needs one). Returns notes for the
    signer: literals in the prose no source gives (a person may have added them)."""
    try:
        packformat.read(text.encode("utf-8"))
    except packformat.PackError as exc:
        raise AssembleError(f"the checker wouldn't read the pack:\n{exc}") from None
    problems = drafting._vocabulary_problems(reviewed.parts.get("detections") or [])
    prose = drafting._prose(
        {"title": reviewed.parts["title"], "remediation": reviewed.parts["remediation"]},
        reviewed.parts.get("mitigations") or [],
        reviewed.parts.get("detections") or [],
    )
    problems += [f"never in a pack: {d}" for d in textcheck.dangers(prose)]
    if problems:
        raise AssembleError("the pack can't be assembled:\n" + "\n".join(problems))
    sources = [(s.name, s.said) for s in found]
    notes = []
    said = "\n".join(textcheck.plain(t).lower() for _, t in sources)
    for m in reviewed.parts.get("mitigations") or []:
        name = (m.get("setting") or {}).get("name") if isinstance(m, dict) else None
        if isinstance(name, str) and not re.search(
            rf"(?<![\w.-]){re.escape(name.lower())}(?![\w-]|\.\w)", said
        ):
            notes.append(f"setting {name!r}: in no source (a person's own?)")
    for finding in textcheck.look_up(textcheck.literals(prose), sources):
        lit = finding.literal
        if finding.sources:
            notes.append(f"{lit.kind} {lit.text!r}: from {'; '.join(finding.sources)}")
        else:
            notes.append(f"{lit.kind} {lit.text!r}: in no source (a person's own?)")
    return notes


def _family(entry: fill.Entry) -> str:
    if entry.origin == "byhand":
        return entry.release.split(":", 1)[0]
    return next(f for f, origins in FAMILIES.items() if entry.origin in origins)


VENDOR_ORIGINS = ("ubuntu", "redhat", "alma")  # what packages_from replaces; not Sury/Remi
_LIMIT = re.compile(r"^\d+ entries: the checker takes at most")


def _gap_family(line: str) -> str | None:
    """Which family a fill note is about, or None for both."""
    if line.startswith("rhel:") or "Red Hat" in line or "AlmaLinux" in line or "RHEL" in line:
        return "rhel"
    if line.startswith("ubuntu:") or "Ubuntu" in line:
        return "ubuntu"
    return None


def _packages(
    store: Store, ctx: Any, a: Assembly, reviewed: Reviewed
) -> tuple[fill.Draft, list[str]]:
    """The packages: the pack's own CVEs' vendor data, with a family's vendor entries
    replaced by another CVE's where the person says so (and said plainly). What the
    vendor data couldn't settle follows the entries: a replaced family's gaps go with
    them, the stand-in's come in."""
    from drafter import thirdparty

    extra, unconfirmed, problems = [], 0, []
    if a.thirdparty:
        extra, unconfirmed, problems = thirdparty.confirmed_entries(
            a.thirdparty.read_text(encoding="utf-8"), reviewed.cves, store
        )
    try:
        filled = fill.build(ctx, reviewed.cves, a.binaries, a.other_builds, extra, unconfirmed)
    except fill.FillError as exc:
        raise AssembleError(f"fill: {exc}") from None
    filled.conflicts += problems
    replaced = []
    for family, cves in (a.packages_from or {}).items():
        vendor = _VENDOR_OF[family]
        marks = ", ".join("?" for _ in cves)
        have = {
            r[0]
            for r in store.db.execute(
                f"SELECT cve FROM vendor_cve WHERE vendor = ? AND found = 1 AND cve IN ({marks})",  # noqa: S608
                [vendor, *cves],
            )
        }
        missing = [c for c in cves if c not in have]
        if missing:
            raise AssembleError(
                f"packages_from {family}: {vendor} has no record in the store for"
                f" {', '.join(missing)}: check the CVE number"
            )
        try:
            other = fill.build(ctx, cves, a.binaries, a.other_builds)
        except fill.FillError as exc:
            raise AssembleError(f"fill ({', '.join(cves)}): {exc}") from None

        def replaceable(e: fill.Entry, family: str = family) -> bool:
            return e.origin in VENDOR_ORIGINS and _family(e) == family

        own = [e for e in filled.entries if replaceable(e)]
        theirs = [e for e in other.entries if replaceable(e)]
        if not theirs:
            raise AssembleError(
                f"packages_from {family}: {', '.join(cves)} gives no {family} entries with this"
                f" binary filter: add its binaries (like {family}:ca-certificates)"
            )
        filled.entries = [e for e in filled.entries if not replaceable(e)] + theirs
        tag = ", ".join(cves)

        def ours(line: str, family: str = family) -> bool:
            return _gap_family(line) == family

        filled.conflicts = [c for c in filled.conflicts if not ours(c)] + [
            f"{tag}: {c}" for c in other.conflicts if ours(c)
        ]
        filled.missing = [m for m in filled.missing if not ours(m)] + [
            f"{tag}: {m}" for m in other.missing if ours(m)
        ]
        filled.not_covered += [f"{tag}: {n}" for n in other.not_covered if ours(n)]
        filled.guessed += [f"{tag}: {g}" for g in other.guessed]
        for release, names in other.filtered_out.items():
            if release.startswith(f"{family}:"):
                filled.filtered_out[release] = sorted(set(names))
        names = sorted({n for e in theirs for n in e.binary_names})
        dropped = sorted({n for e in own for n in e.binary_names})
        replaced.append(
            f"{family}: {len(theirs)} entries from {tag} ({', '.join(names)[:200]})"
            f" stand in for the pack's own {len(own)} ({', '.join(dropped)[:200] or 'none'}),"
            f" because {a.packages_from_reason}"
        )
    filled.entries += a.by_hand
    # Clashes and the entry limit, once, on what the pack will hold.
    filled.conflicts = [c for c in filled.conflicts if not _LIMIT.match(c)]
    fill._merge(filled)
    filled.conflicts = list(dict.fromkeys(filled.conflicts))  # each once
    if ctx is not None:
        if not a.thirdparty:
            for cpe in thirdparty.has_repositories(ctx, reviewed.cves):
                filled.conflicts.append(
                    f"{cpe} has third-party builds (thirdparty.toml): without a confirmed"
                    " proposals file (thirdparty, from `drafter propose`) a host on one reads"
                    " not affected"
                )
        for cve in thirdparty.unknown_cves(ctx, reviewed.cves):
            filled.conflicts.append(
                f"{cve}: no NVD or CISA row in the store, so whether it touches a third-party"
                " build can't be told"
            )
    order = {"ubuntu": 0, "sury": 1, "redhat": 2, "alma": 3, "remi": 4, "byhand": 5}
    filled.entries.sort(key=lambda e: (order[e.origin], e.release, e.versions or "", e.fixed or ""))
    return filled, replaced


def _gaps(conflicts: list[str], accepted: list[tuple[str, str]]) -> tuple[list[str], list[str]]:
    """What the vendor data couldn't settle must each be accepted by name: one
    sentence for all of them would also cover new ones in a later version. An
    acceptance that matches no gap any more is refused, for the same reason.
    Returns (the gaps, each accepted one with its reason)."""
    open_gaps = [c for c in conflicts if not any(c.startswith(g) for g, _ in accepted)]
    stale = [g for g, _ in accepted if not any(c.startswith(g) for c in conflicts)]
    if stale:
        raise AssembleError(
            "accepted gaps that aren't there any more (take them out of the assembly file):\n  "
            + "\n  ".join(stale)
        )
    if open_gaps:
        raise AssembleError(
            "the vendor data leaves these for a person; settle each (by_hand entries, the"
            " binary filter, packages_from) or accept it by name, with a reason"
            ' (accept = [{gap = "…", reason = "…"}]):\n  ' + "\n  ".join(open_gaps)
        )
    settled = [
        f"{c} (accepted: {next(r for g, r in accepted if c.startswith(g))})" for c in conflicts
    ]
    return conflicts, settled


PLACEHOLDER = "https://invalid.example/"


def _current(clone: Path) -> str:
    """Whether dev is GitHub's dev, as far as a fetch can tell (no token: read only)."""
    try:
        _git(clone, "fetch", "--quiet", "origin", BASE_BRANCH)
    except AssembleError as exc:
        return f"couldn't check {BASE_BRANCH} is current ({exc})"
    behind = _git(clone, "rev-list", "--count", "HEAD..FETCH_HEAD").strip()
    if behind != "0":
        raise AssembleError(
            f"{clone} is {behind} commit(s) behind origin/{BASE_BRANCH}: git pull first"
        )
    return ""


def _undo(clone: Path, branch: str, target: Path, existed: bool) -> str:
    """A write that failed part-way: back to dev, without the branch, the file or a
    new pack's folder (the checker's index refuses a folder without a pack). Returns
    what couldn't be undone, or ""."""
    problems = []
    try:
        if target.exists():
            target.chmod(0o644)
        if existed:
            _git(clone, "checkout", "--", ".")
        else:
            target.unlink(missing_ok=True)
            with contextlib.suppress(OSError):
                target.parent.rmdir()  # only if empty
    except (AssembleError, OSError) as exc:
        problems.append(str(exc))
    for args in (("switch", BASE_BRANCH), ("branch", "-D", branch)):
        try:
            _git(clone, *args)
        except AssembleError as exc:
            if "not found" not in str(exc):
                problems.append(str(exc))
    return "; ".join(problems)


def _reference_notes(references: list, found: list[drafting.Source]) -> list[str]:
    known = frozenset().union(*(s.urls for s in found)) if found else frozenset()
    notes = []
    for url in references if isinstance(references, list) else []:
        if not isinstance(url, str):
            continue
        if url not in known:
            notes.append(f"reference {url}: in no source (a person's own?)")
        elif not textcheck.known_site(url):
            notes.append(f"reference on {textcheck.site(url)}, not a usual advisory site: {url}")
    return notes


def write(
    store: Store,
    ctx: Any,
    a: Assembly,
    clone_path: Path,
    *,
    now=timeutil.now,
) -> Written:
    clone = _clone(clone_path)
    reviewed = read_draft(a.draft)
    decision = drafting.approved(store, reviewed.cves)
    if reviewed.decision_id is not None and reviewed.decision_id != decision.id:
        raise AssembleError(
            f"the draft was made under decision {reviewed.decision_id}; the threat was decided"
            f" again since (decision {decision.id}): draft it again"
        )
    if a.id in withdrawn(clone):
        raise AssembleError(f"{a.id} was withdrawn: a pack after it takes a new id")
    listed = listed_version(clone, a.id)
    expected = (listed or 0) + 1
    if a.version != expected:
        raise AssembleError(
            f"version {a.version}: the index lists {a.id} at {listed}, so this is {expected}"
            if listed
            else f"version {a.version}: {a.id} is a new pack, so this is version 1"
        )
    target = clone / "packs" / a.id / "PACK.yaml"
    if listed is None and target.exists():
        raise AssembleError(f"{target} is there but the index doesn't list it: settle that first")
    filled, replaced = _packages(store, ctx, a, reviewed)
    if not filled.entries:
        raise AssembleError("the vendor data gave no packages for this pack: check binaries")
    gaps, settled = _gaps(filled.conflicts, a.accepted)
    current = _current(clone)
    edits = edited(store, reviewed, decision.id)
    text = compose(a, reviewed, filled, now().date(), edits)
    if PLACEHOLDER in text:
        raise AssembleError(
            "an entry's source isn't an address the pack can carry (fill wrote"
            f" {PLACEHOLDER}): give it by hand"
        )
    found = drafting.sources(store, reviewed.cves)
    notes = check_text(text, reviewed, found) + _reference_notes(
        reviewed.parts["references"], found
    )
    old = ""
    if listed is not None:
        old = _git(clone, "show", f"HEAD:packs/{a.id}/PACK.yaml")
    base = _git(clone, "rev-parse", "--short", "HEAD").strip()
    branch = f"pack/{a.id}-v{a.version}"
    try:
        _git(clone, "switch", "-c", branch)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target.chmod(0o644)
        target.write_text(text, encoding="utf-8")
        target.chmod(0o444)  # frozen: nothing is to touch it between here and signing
        sha = hashlib.sha256(target.read_bytes()).hexdigest()  # as it is on disk
        with store.transaction():
            store.db.execute(
                "INSERT INTO pack_assembly (assembled_at, pack_id, version, path, sha256, cves,"
                " decision_id, draft_sha256, reviewed_by, assembly) VALUES (?, ?, ?, ?, ?, ?, ?,"
                " ?, ?, ?)",
                (timeutil.fmt(now()), a.id, a.version, str(target), sha,
                 json.dumps(reviewed.cves), decision.id, reviewed.sha256, a.reviewed_by, a.text),
            )  # fmt: skip
    except BaseException as exc:
        left = _undo(clone, branch, target, listed is not None)
        if left:
            raise AssembleError(
                f"{type(exc).__name__}: {exc}; and the clone couldn't all be put back ({left}):"
                " check it by hand"
            ) from exc
        raise
    diff = "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            text.splitlines(keepends=True),
            f"{a.id} version {listed}" if listed else "/dev/null",
            f"{a.id} version {a.version}",
        )
    )
    return Written(
        target,
        sha,
        branch,
        diff,
        fill.render_report(filled),
        notes,
        base=f"{BASE_BRANCH} at {base}",
        replaced=replaced,
        needs_a_person=settled + list(filled.missing) + ([current] if current else []),
        edits=edits,
    )


def sign_command(w_path: Path, pack_id: str, version: int) -> str:
    return f'minisign -S -s {PACK_KEY} -m {w_path} -t "{pack_id} version {version}"'


# after signing


@dataclass
class Checked:
    path: Path
    key: str
    comment: str
    index_output: str
    index: str = "written"  # written now; unsigned (written before, not signed); signed


def _latest(store: Store, pack_id: str) -> dict:
    row = store.db.execute(
        "SELECT * FROM pack_assembly WHERE pack_id = ? ORDER BY id DESC LIMIT 1", (pack_id,)
    ).fetchone()
    if row is None:
        raise AssembleError(f"no pack {pack_id} assembled here: `drafter pack write` first")
    return dict(row)


def _pack_keys(clone: Path) -> list[str]:
    try:
        keys = packformat.load((clone / "keys.yaml").read_bytes())
    except (OSError, packformat.PackError) as exc:
        raise AssembleError(f"keys.yaml can't be read: {exc}") from None
    found = []
    for key in (keys or {}).get("pack_keys") or []:
        if isinstance(key, dict) and isinstance(key.get("public_key"), str):
            found.append(key["public_key"])
    if not found:
        raise AssembleError("keys.yaml lists no pack keys")
    return found


def key_id(public_key: str) -> str:
    """minisign's id for a public key (as `minisign -V` and the key list show it)."""
    try:
        raw = base64.b64decode(public_key, validate=True)
    except (ValueError, binascii.Error):
        return "?"
    return raw[2:10][::-1].hex().upper() if len(raw) == 42 else "?"


def verify(path: Path, keys: list[str], minisign: str = "minisign") -> tuple[str, str]:
    """(the key that signed it, the trusted comment), by minisign itself."""
    if shutil.which(minisign) is None:
        raise AssembleError("minisign isn't installed: it checks the signature")
    if not Path(f"{path}.minisig").is_file():
        raise AssembleError(f"no {path.name}.minisig beside it: sign it first")
    try:
        lines = Path(f"{path}.minisig").read_text(encoding="utf-8").splitlines()
        algorithm = base64.b64decode(lines[1], validate=True)[:2]
    except (OSError, IndexError, ValueError, binascii.Error):
        algorithm = b""
    if algorithm != b"ED":
        raise AssembleError(
            f"{path.name}.minisig isn't a prehashed signature (minisign's default since 0.10):"
            " the checker refuses legacy ones; sign again without -l"
        )
    for key in keys:
        try:
            done = subprocess.run(  # noqa: S603 - minisign, with fixed arguments
                [minisign, "-V", "-P", key, "-m", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AssembleError(f"minisign: {exc}") from None
        if done.returncode == 0:
            comment = ""
            for line in done.stdout.splitlines():
                if line.startswith("Trusted comment: "):
                    comment = line.removeprefix("Trusted comment: ").strip()
            return key, comment
    raise AssembleError(f"{path.name}.minisig isn't a good signature by any pack key in keys.yaml")


def _indexed(clone: Path, pack_id: str, version: int, sha: str) -> bool:
    """Does the clone's index already list this very pack (written for it before)?"""
    try:
        index = packformat.load((clone / "index.yaml").read_bytes())
    except (OSError, packformat.PackError):
        return False
    return any(
        isinstance(e, dict)
        and e.get("id") == pack_id
        and e.get("version") == version
        and str(e.get("sha256", "")).lower() == sha
        for e in (index or {}).get("packs") or []
    )


def check(
    store: Store,
    pack_id: str,
    clone_path: Path,
    *,
    checker: str = "checker",
    minisign: str = "minisign",
) -> Checked:
    """The frozen file and its signature; then the index, written once: run again
    after signing the index, it checks that signature instead of writing it anew
    (which would undo the signing)."""
    clone = Path(os.path.expanduser(clone_path)).resolve()
    row = _latest(store, pack_id)
    path = Path(row["path"])
    if not path.is_relative_to(clone):
        raise AssembleError(f"{pack_id} was assembled into {path}, not into {clone}")
    try:
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise AssembleError(f"{path}: {exc}") from None
    if sha != row["sha256"]:
        raise AssembleError(
            f"{path} changed after it was frozen (sha256 {sha[:16]}, was {row['sha256'][:16]}):"
            " never edit a pack after it is written; to start again, delete its branch and"
            " folder in the clone and run `drafter pack write` again"
        )
    if not Path(f"{path}.minisig").is_file():
        raise AssembleError(f"no {path.name}.minisig beside it: sign it first")
    keys = _pack_keys(clone)
    key, comment = verify(path, keys, minisign)
    wanted = f"{pack_id} version {row['version']}"
    if comment != wanted:
        raise AssembleError(f"the signature's trusted comment is {comment!r}, not {wanted!r}")
    index = clone / "index.yaml"
    if _indexed(clone, pack_id, row["version"], sha):
        try:
            verify(index, keys, minisign)
        except AssembleError:
            return Checked(path, key, comment, "", index="unsigned")
        return Checked(path, key, comment, "", index="signed")
    if shutil.which(checker) is None:
        raise AssembleError(
            f"the checker ({checker}) isn't installed or on PATH: give --checker"
            " /path/to/checker; it writes the index"
        )
    try:
        done = subprocess.run(  # noqa: S603 - the checker, with fixed arguments
            [checker, "packs", "index", str(clone)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AssembleError(f"checker packs index: {exc}") from None
    output = (done.stdout + done.stderr).strip()
    if done.returncode != 0:
        raise AssembleError(f"checker packs index refused:\n{output}")
    return Checked(path, key, comment, output)


# a template


def template(store: Store, draft_path: Path, clone_path: Path) -> str:
    """An assembly file to edit, with what the store suggests."""
    reviewed = read_draft(Path(os.path.expanduser(draft_path)))
    decision = drafting.approved(store, reviewed.cves)
    clone = Path(os.path.expanduser(clone_path)).resolve()
    family = (decision.families or ("threat",))[0]
    signs = drafting.sources(store, reviewed.cves)
    first = min(
        (
            r[0]
            for r in store.db.execute(
                f"SELECT published FROM vendor_cve WHERE published IS NOT NULL AND cve IN"  # noqa: S608
                f" ({', '.join('?' for _ in reviewed.cves)})",
                reviewed.cves,
            )
        ),
        default=None,
    )
    kev = store.db.execute(
        f"SELECT MIN(date_added) FROM kev WHERE cve IN ({', '.join('?' for _ in reviewed.cves)})",  # noqa: S608
        reviewed.cves,
    ).fetchone()[0]
    month = (first or decision.decided_at)[:7]
    pack_id = re.sub(r"[^a-z0-9-]", "-", f"{family}-{month}".lower()).strip("-")
    listed = listed_version(clone, pack_id) if (clone / "index.yaml").is_file() else None
    start = (first or decision.decided_at)[:10]
    lines = [
        f"# Assembly for {', '.join(reviewed.cves)} (approved {decision.decided_at[:10]}).",
        "# Every value is a person's choice; the store's suggestions are filled in.",
        f'id = "{pack_id}"',
        f"version = {(listed or 0) + 1}",
        f"draft = {json.dumps(reviewed_path(draft_path))}",
        'reviewed_by = ""  # who read the draft, edited it as needed, and stands by it',
        "",
        "[exposure]",
        f"# The vendors' first public word on it: {first or 'not in the store'}.",
        f"window_start = {start}T00:00:00Z",
        f"# CISA listed it on {kev}; a first sighting in the wild needs a source of its own."
        if kev
        else "# No sign of attacks in the wild in the store.",
        "# first_seen_in_wild = 2026-10-21T00:00:00Z",
        "# How much exposure weighs, more than 1 and at most 10 (PHP2Shell: 5).",
        "likelihood_ratio = 0",
        "# Which binaries count (drafter fill --binaries; [] keeps every one, often over the",
        "# checker's 100 entries): `drafter fill CVE…` lists them.",
        "binaries = []",
        'other_builds = "cant_judge"',
        "# What the vendor data can't settle stops the write: settle it, or accept each by name:",
        '# accept = [{gap = "rhel:9 edk2", reason = "…"}]',
        "# A family whose releases are fixed in another CVE's update, judged from its data:",
        '# packages_from = {rhel = ["CVE-…"]}',
        '# packages_from_reason = "RHEL is fixed by the ca-certificates update"',
        '# thirdparty = "proposals.toml"',
        '# stale_code = ["program*"]  # programs to restart after the fix',
        f"# {len(signs)} source(s) about these CVEs in the store.",
    ]
    return "\n".join(lines) + "\n"


def reviewed_path(path: Path | str) -> str:
    return str(Path(os.path.expanduser(str(path))).resolve())
