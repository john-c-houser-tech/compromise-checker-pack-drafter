"""A.4b: which CVEs the signed packs already name, read from a local clone of
compromise-checker-packs, so the page can mark a threat Covered.

Read-only, and the signatures aren't checked: a wrong mark only folds a threat's
form behind "Decide anyway". So anything odd fails towards showing the form:
one pack that can't be read means no threat is marked Covered at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from drafter.feeds import CVE_ID

MAX_FILE = 4 * 1024 * 1024
MAX_PACKS = 500
_ID = re.compile(r"\A[a-z0-9][a-z0-9-]{0,79}\Z")


class PackError(Exception):
    pass


@dataclass(frozen=True)
class Pack:
    id: str
    version: int
    cves: frozenset[str]


def _yaml(path: Path, root: Path) -> object:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise PackError(f"{path.relative_to(root)} isn't there") from None
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise PackError(f"{path.relative_to(root)} isn't a file in the clone")
    if resolved.stat().st_size > MAX_FILE:
        raise PackError(f"{path.relative_to(root)} is too large")
    try:
        return yaml.safe_load(resolved.read_text("utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PackError(f"{path.relative_to(root)} can't be read: {type(exc).__name__}") from None


def load(root: Path) -> list[Pack]:
    """The packs the clone's index lists, with the CVEs each names."""
    root = Path(root)
    index = _yaml(root / "index.yaml", root)
    entries = index.get("packs") if isinstance(index, dict) else None
    if not isinstance(entries, list) or len(entries) > MAX_PACKS:
        raise PackError("index.yaml has no list of packs")
    out = []
    for entry in entries:
        pack_id = entry.get("id") if isinstance(entry, dict) else None
        version = entry.get("version") if isinstance(entry, dict) else None
        if not isinstance(pack_id, str) or not _ID.match(pack_id):
            raise PackError("index.yaml lists a pack with an odd id")
        if isinstance(version, bool) or not isinstance(version, int):
            raise PackError(f"index.yaml: {pack_id} has no version")
        pack = _yaml(root / "packs" / pack_id / "PACK.yaml", root)
        if not isinstance(pack, dict) or pack.get("id") != pack_id:
            raise PackError(f"packs/{pack_id}/PACK.yaml isn't the pack the index names")
        cves = pack.get("cves")
        if (
            not isinstance(cves, list)
            or not cves
            or not all(isinstance(c, str) and CVE_ID.match(c) for c in cves)
        ):
            raise PackError(f"packs/{pack_id}/PACK.yaml has no list of CVEs")
        out.append(Pack(pack_id, version, frozenset(cves)))
    return out


@dataclass(frozen=True)
class Cover:
    pack: Pack
    names: tuple[str, ...]  # the threat's CVEs this pack names
    missing: tuple[str, ...]  # the threat's CVEs it doesn't

    @property
    def full(self) -> bool:
        return not self.missing


def covers(packs: list[Pack], cves: list[str]) -> list[Cover]:
    """Each pack naming any of these CVEs; one naming them all first."""
    wanted = sorted(set(cves))
    out = []
    for pack in packs:
        names = tuple(c for c in wanted if c in pack.cves)
        if names:
            out.append(Cover(pack, names, tuple(c for c in wanted if c not in pack.cves)))
    return sorted(out, key=lambda c: (len(c.missing), c.pack.id))
