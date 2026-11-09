"""Print what a pack's detections may name, from a Compromise Checker checkout,
to compare with drafter/vocabulary.py when the pinned commit moves.

    git -C ../compromise-checker worktree add --detach /tmp/checker-pin <commit>
    ../compromise-checker/.venv/bin/python scripts/vocabulary.py --checker /tmp/checker-pin

Checks come from checker.checks.load_checks() (the packs' own excepted), sections from
checker.snapshot.SECTIONS less those exposure is judged from. Event types and their
fields are written by hand in drafter/vocabulary.py, from checker/events.py: there is
no list of them to read. Run with the checker's interpreter; the drafter never
imports the checker.
"""

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--checker", required=True, help="a checker checkout at the commit")
    args = parser.parse_args()
    sys.path.insert(0, args.checker)
    from checker.checks import load_checks
    from checker.packs.format import EXPOSURE_SECTIONS
    from checker.snapshot import SECTIONS

    checks = {
        cid: [check.title, list(check.variants)]
        for cid, check in sorted(load_checks().items())
        if not cid.startswith("pack.")
    }
    sections = {name: SECTIONS[name][0] for name in SECTIONS if name not in EXPOSURE_SECTIONS}
    # C.1: each check's bands, from the checker's docs at the commit (read_bands is
    # the drafter's own, so the drift test reads them the same way).
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from drafter.vocabulary import read_bands

    doc = (Path(args.checker) / "docs" / "checks.md").read_text(encoding="utf-8")
    bands = {cid: read_bands(doc).get(cid) for cid in checks}
    print(json.dumps({"checks": checks, "sections": sections, "bands": bands}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
