"""Judge a draft and a signed pack with Compromise Checker's own code, on real
installed versions, and show where they disagree.

    <checker>/.venv/bin/python scripts/judge.py --checker ../compromise-checker \
        draft.yaml ../compromise-checker-packs/packs/php2shell-2026-10/PACK.yaml \
        tests/history/php2shell-cases.tsv

Each case is one host with one package installed, judged by the checker's own
`exposure.judge()`: the draft's packages and other_builds are put into a copy of the
signed pack, so everything else (exposure window, detections) is the same. That
includes the rule that other_builds only applies to a binary some entry on the
release names: a binary named nowhere isn't judged, and the host reads
not_affected. A line marked LESS CAUTIOUS is one where the draft would call a host
fixed or not affected, or leave it unjudged, that the signed pack calls vulnerable.
Run with the checker's interpreter; the drafter itself never imports the checker.
"""

import argparse
import sys
from datetime import UTC, datetime

import yaml

# The checker's own words (checker/packs/exposure.py).
RANK = {
    "vulnerable": 4,
    "can't judge": 3,
    "not covered": 2,
    "unknown release": 2,
    "fixed": 1,
    "not affected": 1,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checker", required=True, help="a Compromise Checker checkout")
    parser.add_argument("draft")
    parser.add_argument("signed")
    parser.add_argument("cases", help="tab-separated: release, binary, version, where from")
    args = parser.parse_args()
    sys.path.insert(0, args.checker)
    from checker.packs import format as pack_format
    from checker.packs.exposure import judge

    signed_data = yaml.safe_load(open(args.signed, encoding="utf-8").read())
    drafted = yaml.safe_load("exposure:\n" + open(args.draft, encoding="utf-8").read())["exposure"]
    draft_data = yaml.safe_load(yaml.safe_dump(signed_data))
    draft_data["exposure"]["packages"] = drafted["packages"]
    draft_data["exposure"]["other_builds"] = drafted.get("other_builds", "not_affected")
    packs = {
        "draft": pack_format.read(yaml.safe_dump(draft_data).encode()),
        "signed": pack_format.read(yaml.safe_dump(signed_data).encode()),
    }
    now = datetime(2026, 11, 7, tzinfo=UTC)

    def verdict(pack, release, binary, version):
        family, number = release.split(":")
        host = {"os": {"id": family, "version_id": number}}
        manager = "dpkg" if family == "ubuntu" else "rpm"
        installed = {
            f"{binary} x86_64": {
                "version": version,
                "manager": manager,
                "installed": "2026-10-01T00:00:00+00:00",
            }
        }
        found = judge(pack, host, installed, [], now)
        states = [p.status for p in found.packages]
        return max(states, key=RANK.get) if states else "not affected"

    worse = 0
    for line in open(args.cases, encoding="utf-8"):
        if not line.strip() or line.startswith("#"):
            continue
        release, binary, version, where = line.rstrip("\n").split("\t")
        d = verdict(packs["draft"], release, binary, version)
        s = verdict(packs["signed"], release, binary, version)
        mark = ""
        if RANK[d] < RANK[s]:
            mark, worse = "  <-- LESS CAUTIOUS", worse + 1
        elif d != s:
            mark = "  (more cautious)" if RANK[d] > RANK[s] else "  (differs)"
        print(f"{release:12} {binary:13} {version:46} {where:32} draft={d:12} signed={s}{mark}")
    print(f"\nless cautious than the signed pack: {worse}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
