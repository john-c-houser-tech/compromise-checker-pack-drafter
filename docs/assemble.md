# Assembling a pack (A.7)

A pack comes from three things:

- **the prose** (title, mitigations, detections, remediation, references): the AI's
  draft from `drafter draft` (A.5), held to the sources (A.6), then **read and
  accepted by a person**, who may edit it;
- **the packages**: vendor data, written by `drafter fill` (A.3) at assembly;
- **what only a person decides**, in an assembly file: the pack's id and version,
  when the threat became usable, how much exposure weighs, which binaries count, and
  whose vendor data the packages come from.

Nothing here holds a key, signs, commits or pushes. Signing is by hand with the pack
key, and the pull request is a person's.

    drafter pack template --draft brotli.draft.yaml --packs ~/Projects/compromise-checker-packs --out brotli.toml
    # edit brotli.toml: reviewed_by, likelihood_ratio, binaries, and anything else
    drafter pack write brotli.toml --packs ~/Projects/compromise-checker-packs
    # read the pack, then sign it by hand:
    minisign -S -s ~/nouriloop-keys/pack.key -m …/packs/brotli-2026-10/PACK.yaml -t "brotli-2026-10 version 1"
    drafter pack check brotli-2026-10 --packs ~/Projects/compromise-checker-packs --checker …/checker
    # then sign the index, commit, push the branch, open a pull request into dev

## The assembly file

TOML. `drafter pack template` writes one with what the store suggests (an id from the
package family and month, the next version from the clone's index, the window from
the vendors' first public word on the threat, CISA's listing date as a note); every
value is still a person's choice.

```toml
id = "brotli-2026-10"
version = 1
draft = "/home/jch/.local/share/pack-drafter/drafts/brotli.draft.yaml"
reviewed_by = "jch"          # who read the draft, edited it as needed, and stands by it

[exposure]
window_start = 2026-10-22T00:00:00Z
# first_seen_in_wild = …     # with a source of its own
# window_end = …
likelihood_ratio = 5         # more than 1, at most 10 (the checker's cap)
binaries = ["brotli", "libbrotli*", "rhel:nodejs"]   # drafter fill --binaries
other_builds = "cant_judge"
# packages_from = {rhel = ["CVE-2026-114406"]}   # a family judged from another CVE's data
# packages_from_reason = "RHEL is fixed by the ca-certificates update"
# thirdparty = "proposals.toml"         # confirmed Sury/Remi builds (drafter propose)
# stale_code = ["node*"]                # programs to restart after the fix
# by_hand = [{release = "rhel:10", binary_names = ["edk2-ovmf"], source = "https://…",
#             note = "Red Hat: Affected, no fix yet"}]   # entries the vendor data can't give
# accept = [{gap = "rhel:9 edk2", reason = "…"}]   # a gap accepted by name, with why
```

**What the vendor data can't settle stops the write**: a release Red Hat calls
affected with no fixed build to take binary names from (edk2), an advisory that can't
be read, a clash between two entries, too many entries, a watched third-party
product with no confirmed proposals file, a CVE with no NVD or CISA row. Settle each
(a `by_hand` entry, the binary filter, `packages_from`, a proposals file), or accept
it **by name** in `accept`, with a reason: each acceptance names the start of one
gap's line, so it never covers a gap that turns up later (a later version reusing the
file), and one that matches no gap any more is refused too. Accepted gaps and their
reasons are shown under NEEDS A PERSON. A vendor that doesn't track a CVE at all
("Ubuntu has no record for …", routine for a RHEL-only CVE) is shown there but
doesn't stop the write. A `by_hand`
entry (release, binary names, source, and optionally versions, a fixed build and a
note) is marked in the pack as written by a person, and held to the same clash rules
as the vendors' entries.

`packages_from` is for a threat whose fix is in another package's update: Red Hat
marks its Java packages "will not fix" for CVE-2026-91403 because RHEL is fixed by the
ca-certificates update (CVE-2026-114406), so a Java pack judged from Java's own data
would show every RHEL host with Java as vulnerable for ever. It is **per family**
(`ubuntu`, `rhel`): only that family's vendor entries come from the other CVE, the
rest stay the pack's own (Ubuntu's own records for the Java CVE still count), and so
do confirmed third-party builds (Sury, Remi). What the vendor data couldn't settle
follows the entries: the replaced family's gaps go, the stand-in's come in. A stand-in
that gives that family no entries with the binary filter is refused (add its
binaries, like `rhel:ca-certificates`). The other CVE must
have that vendor's record in the store (a typo is refused), a reason is required, and
both go into the pack's comments and the output under PACKAGES JUDGED FROM OTHER CVEs,
with the packages that stand in and the ones they replace.

**The binary filter matters for size:** a pack holds at most 100 package entries, and
Ubuntu's records list each affected build of a bundling package separately. Brotli,
unfiltered, gives 239; with its library, tool and Python binding, RHEL's Node.js and
.NET runtimes and Ubuntu's .NET runtimes, 197 (147 of them Ubuntu's .NET); without
Ubuntu's .NET, 50.

## What `write` does

1. Reads the assembly file, and the draft as the person left it: it must be an AI
   draft, not one marked NOT USABLE, holding just the five parts, readable as the
   checker reads a pack (no aliases, no deep nesting).
2. Checks the threat is still approved, and under the same decision the draft was
   made under (decided again since: draft it again); and the version: 1 for a pack
   the clone's index doesn't list, else the listed one plus one; a pack folder the
   index doesn't list, or an id the index lists as withdrawn, is refused. The clone
   must be on `dev` with nothing uncommitted, and not behind GitHub's `dev` (a read-only
   fetch, no token, no prompt; offline, the output says it couldn't check). A write
   that fails part-way puts the clone back on `dev`, without the branch, the file or a
   new pack's folder, and says if any of that couldn't be done.
3. Runs `drafter fill` for the packages (`packages_from`, or the draft's CVEs), with
   the binary filter, `other_builds` and any confirmed third-party builds.
4. Composes the pack, with comments saying where each part came from: the reviewer,
   the draft's SHA-256, whether the prose is the AI's answer **unedited or edited by a
   person** (which parts), compared with the accepted answer on record, and the CVEs
   the packages came from. It reads it **exactly as the checker does** (`drafter/checkerformat`, pinned): one it wouldn't read isn't
   written. Detections are held to the checker's vocabulary, and the prose to A.6's
   dangers, a person's edits too: a pack never needs one. Commands, addresses, paths
   and URLs in the prose, and references, are listed under CHECK BEFORE SIGNING, each
   with the source it came from, or "in no source (a person's own?)"; references on a
   site that isn't a usual advisory publisher are listed too.
5. Creates the branch `pack/ID-vN` in the clone, writes `packs/ID/PACK.yaml`, makes it
   **read-only**, and records its SHA-256 in the store (`pack_assembly`, append-only).
6. Shows what changed since the listed version (or that it's new), then the
   vendor-data report, PACKAGES JUDGED FROM OTHER CVEs, NEEDS A PERSON (what the
   vendor data left out), CHECK BEFORE SIGNING, whether the prose was edited, the
   branch and the commit it started from, commands to review it yourself (`git diff`,
   `sha256sum`), the SHA-256 (of the file as written to disk), and the signing command.

## What `check` does, after signing

1. Refuses a file changed since it was frozen (its SHA-256 against the store's).
2. Refuses a missing signature, or a legacy one (`minisign -l`: the checker refuses
   those), and checks it with `minisign` against each pack key in the clone's
   `keys.yaml`; the trusted comment must be `ID version N`.
3. Writes the index with the checker's own `checker packs index` (which checks every
   pack's signature again, and `keys.yaml`'s against the root key), once: run again
   after signing the index, `check` sees the index already lists this very pack and
   checks the index's signature instead of writing it anew (which would undo the
   signing). It shows the key id (`minisign`'s) that signed each.
4. When the index is signed: commit the pack, the index and both signatures, push the
   branch and open a pull request into dev. Before it is merged, the checker's own
   release steps still apply: check every version and date against the vendors' own
   pages, and prove it on throwaway servers (A.8). Don't touch a file after signing.
