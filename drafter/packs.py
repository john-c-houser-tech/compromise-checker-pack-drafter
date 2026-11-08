"""A.4b: which CVEs the signed packs already name, read from a local clone of
compromise-checker-packs, so the page can mark a threat Covered.

Read-only. The index's signature isn't checked (a wrong mark only folds a
threat's form behind "Decide anyway"), but each PACK.yaml must have the hash and
version the index gives it, so a pack edited in the clone since it was signed
doesn't count. Anything odd fails towards showing the form: one pack that can't
be read means no threat is marked Covered at all.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from drafter.feeds import CVE_ID

MAX_FILE = 4 * 1024 * 1024
MAX_PACKS = 500
MAX_DEPTH = 32
# What PyYAML can raise while building a document (as the checker's own reader
# lists them), and deep nesting.
_READ_ERRORS = (
    yaml.YAMLError,
    ValueError,
    TypeError,
    KeyError,
    AttributeError,
    OverflowError,
    RecursionError,
)
_ID = re.compile(r"\A[a-z0-9][a-z0-9-]{0,79}\Z")


class PackError(Exception):
    pass


@dataclass(frozen=True)
class Pack:
    id: str
    version: int
    cves: frozenset[str]


def _shape(text: str) -> None:
    """Refuse anchors, aliases and deep nesting before anything is built: merge keys
    (<<: [*a, *a]) double at each level, so a few hundred bytes could hold the page."""
    depth = 0
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
            raise PackError("anchors and aliases aren't used in packs")
        if isinstance(event, yaml.CollectionStartEvent):
            depth += 1
            if depth > MAX_DEPTH:
                raise PackError("nested too deep")
        elif isinstance(event, yaml.CollectionEndEvent):
            depth -= 1


def _read(path: Path, root: Path) -> bytes:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise PackError(f"{path.relative_to(root)} isn't there") from None
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise PackError(f"{path.relative_to(root)} isn't a file in the clone")
    if resolved.stat().st_size > MAX_FILE:
        raise PackError(f"{path.relative_to(root)} is too large")
    return resolved.read_bytes()


def _yaml(data: bytes, name: str) -> object:
    try:
        text = data.decode("utf-8")
        _shape(text)
        return yaml.safe_load(text)
    except PackError as exc:
        raise PackError(f"{name} can't be read: {exc}") from None
    except (UnicodeDecodeError, *_READ_ERRORS) as exc:
        raise PackError(f"{name} can't be read: {type(exc).__name__}") from None


def load(root: Path) -> list[Pack]:
    """The packs the clone's index lists, with the CVEs each names."""
    root = Path(root)
    index = _yaml(_read(root / "index.yaml", root), "index.yaml")
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
        sha = entry.get("sha256")
        name = f"packs/{pack_id}/PACK.yaml"
        data = _read(root / "packs" / pack_id / "PACK.yaml", root)
        if not isinstance(sha, str) or hashlib.sha256(data).hexdigest() != sha.lower():
            raise PackError(f"{name} isn't the file index.yaml signed (edited since?)")
        pack = _yaml(data, name)
        if not isinstance(pack, dict) or pack.get("id") != pack_id:
            raise PackError(f"{name} isn't the pack the index names")
        if pack.get("version") != version:
            raise PackError(f"{name} isn't the version index.yaml lists")
        cves = pack.get("cves", [])  # a pack may name none (the checker's format allows it)
        if not isinstance(cves, list) or not all(
            isinstance(c, str) and CVE_ID.match(c) for c in cves
        ):
            raise PackError(f"{name} has an odd list of CVEs")
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
