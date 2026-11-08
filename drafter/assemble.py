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

import datetime as dt
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass
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
    packages_from: list[str] | None = None  # CVEs whose vendor data: default the pack's
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
        "packages_from", "other_builds", "thirdparty", "stale_code",
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
        not isinstance(packages_from, list)
        or not packages_from
        or not all(isinstance(c, str) and CVE_ID.match(c) for c in packages_from)
    ):
        raise AssembleError("exposure.packages_from: CVE numbers whose vendor data to use")
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
    if "window_start" not in exposure:
        raise AssembleError("exposure.window_start: when the threat became usable")
    return Assembly(
        id=pack_id,
        version=version,
        draft=Path(os.path.expanduser(draft_path)),
        reviewed_by=" ".join(reviewed.split()),
        window_start=_when(exposure["window_start"], "exposure.window_start"),
        likelihood_ratio=float(lr),
        binaries=list(binaries),
        packages_from=sorted(set(packages_from)) if packages_from else None,
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


_CVES_LINE = re.compile(r"^# CVEs: ((?:CVE-\d{4}-\d{4,9}(?:, )?)+)", re.M)


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
    want = {"title", "mitigations", "detections", "remediation", "references"}
    if not isinstance(parts, dict) or set(parts) != want:
        raise AssembleError(f"{path} should hold just: {', '.join(sorted(want))}")
    return Reviewed(found.group(1).split(", "), parts, hashlib.sha256(data).hexdigest())


# the packs clone


def _git(clone: Path, *args: str) -> str:
    try:
        done = subprocess.run(  # noqa: S603 - git, with fixed arguments
            ["git", "-C", str(clone), *args],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            check=False,
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


def _clone(path: Path) -> Path:
    clone = Path(os.path.expanduser(path)).resolve()
    if not (clone / "index.yaml").is_file() or not (clone / "keys.yaml").is_file():
        raise AssembleError(f"{clone} isn't a clone of the packs repository (no index.yaml)")
    if _git(clone, "status", "--porcelain").strip():
        raise AssembleError(f"{clone} has changes not committed: start from a clean clone")
    return clone


# writing the pack


@dataclass
class Written:
    path: Path
    sha256: str
    branch: str
    diff: str
    report: str
    notes: list[str]


def _yaml(value: Any) -> str:
    return yaml.safe_dump(value, sort_keys=False, allow_unicode=False, width=88)


def _iso(when: dt.datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def compose(a: Assembly, reviewed: Reviewed, filled: fill.Draft, published: dt.date) -> str:
    """The pack's text: where each part came from, as comments, then the pack."""
    from_cves = a.packages_from or reviewed.cves
    lines = [
        f"# {reviewed.parts['title']}"[:200],
        "# Assembled by the pack drafter (A.7). Where each part came from:",
        f"#   prose (title, mitigations, detections, remediation, references): an AI draft,"
        f" read and accepted by {a.reviewed_by} (draft sha256 {reviewed.sha256[:16]})",
        f"#   packages: vendor data for {', '.join(from_cves)} (`drafter fill`)",
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
    lines.append(f"  likelihood_ratio: {a.likelihood_ratio:g}")
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
    for finding in textcheck.look_up(textcheck.literals(prose), sources):
        lit = finding.literal
        if finding.sources:
            notes.append(f"{lit.kind} {lit.text!r}: from {'; '.join(finding.sources)}")
        else:
            notes.append(f"{lit.kind} {lit.text!r}: in no source (a person's own?)")
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
    extra, unconfirmed, problems = [], 0, []
    if a.thirdparty:
        from drafter import thirdparty

        extra, unconfirmed, problems = thirdparty.confirmed_entries(
            a.thirdparty.read_text(encoding="utf-8"), reviewed.cves, store
        )
    try:
        filled = fill.build(
            ctx, a.packages_from or reviewed.cves, a.binaries, a.other_builds, extra, unconfirmed
        )
    except fill.FillError as exc:
        raise AssembleError(f"fill: {exc}") from None
    filled.conflicts += problems
    if not filled.entries:
        raise AssembleError("the vendor data gave no packages for this pack: check binaries")
    published = now().date()
    text = compose(a, reviewed, filled, published)
    notes = check_text(text, reviewed, drafting.sources(store, reviewed.cves))
    old = ""
    if listed is not None:
        old = _git(clone, "show", f"HEAD:packs/{a.id}/PACK.yaml")
    branch = f"pack/{a.id}-v{a.version}"
    _git(clone, "switch", "-c", branch)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.chmod(0o644)
    target.write_text(text, encoding="utf-8")
    target.chmod(0o444)  # frozen: nothing is to touch it between here and signing
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    with store.transaction():
        store.db.execute(
            "INSERT INTO pack_assembly (assembled_at, pack_id, version, path, sha256, cves,"
            " decision_id, draft_sha256, reviewed_by, assembly) VALUES (?, ?, ?, ?, ?, ?, ?, ?,"
            " ?, ?)",
            (timeutil.fmt(now()), a.id, a.version, str(target), sha,
             json.dumps(reviewed.cves), decision.id, reviewed.sha256, a.reviewed_by, a.text),
        )  # fmt: skip
    diff = "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            text.splitlines(keepends=True),
            f"{a.id} version {listed}" if listed else "/dev/null",
            f"{a.id} version {a.version}",
        )
    )
    return Written(target, sha, branch, diff, fill.render_report(filled), notes)


def sign_command(w_path: Path, pack_id: str, version: int) -> str:
    return f'minisign -S -s {PACK_KEY} -m {w_path} -t "{pack_id} version {version}"'


# after signing


@dataclass
class Checked:
    path: Path
    key: str
    comment: str
    index_output: str


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


def verify(path: Path, keys: list[str], minisign: str = "minisign") -> tuple[str, str]:
    """(the key that signed it, the trusted comment), by minisign itself."""
    if shutil.which(minisign) is None:
        raise AssembleError("minisign isn't installed: it checks the signature")
    if not Path(f"{path}.minisig").is_file():
        raise AssembleError(f"no {path.name}.minisig beside it: sign it first")
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


def check(
    store: Store,
    pack_id: str,
    clone_path: Path,
    *,
    checker: str = "checker",
    minisign: str = "minisign",
) -> Checked:
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
            " assemble it again; never edit a pack after it is written"
        )
    if not Path(f"{path}.minisig").is_file():
        raise AssembleError(f"no {path.name}.minisig beside it: sign it first")
    key, comment = verify(path, _pack_keys(clone), minisign)
    wanted = f"{pack_id} version {row['version']}"
    if comment != wanted:
        raise AssembleError(f"the signature's trusted comment is {comment!r}, not {wanted!r}")
    if shutil.which(checker) is None:
        raise AssembleError(f"the checker ({checker}) isn't installed: it writes the index")
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
        f'draft = "{reviewed_path(draft_path)}"',
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
        "# Which binaries count (drafter fill --binaries): see `drafter fill` for the list.",
        "binaries = []",
        'other_builds = "cant_judge"',
        "# A threat fixed in another package's update is judged from that package's data:",
        f"# packages_from = {json.dumps(reviewed.cves)}",
        '# thirdparty = "proposals.toml"',
        '# stale_code = ["program*"]  # programs to restart after the fix',
        f"# {len(signs)} source(s) about these CVEs in the store.",
    ]
    return "\n".join(lines) + "\n"


def reviewed_path(path: Path | str) -> str:
    return str(Path(os.path.expanduser(str(path))).resolve())
