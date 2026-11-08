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
# packages_from = ["CVE-2026-114406"]   # judge the pack from another CVE's packages
# thirdparty = "proposals.toml"         # confirmed Sury/Remi builds (drafter propose)
# stale_code = ["node*"]                # programs to restart after the fix
```

`packages_from` is for a threat whose fix is in another package's update: Red Hat
marks its Java packages "will not fix" for CVE-2026-91403 because RHEL is fixed by the
ca-certificates update (CVE-2026-114406), so a Java pack judged from Java's own data
would show every RHEL host with Java as vulnerable for ever.

**The binary filter matters for size:** a pack holds at most 100 package entries, and
Ubuntu's records list each affected build of a bundling package separately. Brotli,
unfiltered, gives 239; with its library, tool and Python binding, RHEL's Node.js and
.NET runtimes and Ubuntu's .NET runtimes, 197 (147 of them Ubuntu's .NET); without
Ubuntu's .NET, 50.

## What `write` does

1. Reads the assembly file, and the draft as the person left it: it must be an AI
   draft, not one marked NOT USABLE, holding just the five parts, readable as the
   checker reads a pack (no aliases, no deep nesting).
2. Checks the threat is still approved, and the version: 1 for a pack the clone's
   index doesn't list, else the listed one plus one; a pack folder the index doesn't
   list is refused. The clone must have nothing uncommitted.
3. Runs `drafter fill` for the packages (`packages_from`, or the draft's CVEs), with
   the binary filter, `other_builds` and any confirmed third-party builds.
4. Composes the pack, with comments saying where each part came from (the reviewer,
   the draft's SHA-256, the CVEs the packages came from), and reads it **exactly as
   the checker does** (`drafter/checkerformat`, pinned): one it wouldn't read isn't
   written. Detections are held to the checker's vocabulary, and the prose to A.6's
   dangers, a person's edits too: a pack never needs one. Commands, addresses, paths
   and URLs in the prose are listed under CHECK BEFORE SIGNING, each with the source
   it came from, or "in no source (a person's own?)".
5. Creates the branch `pack/ID-vN` in the clone, writes `packs/ID/PACK.yaml`, makes it
   **read-only**, and records its SHA-256 in the store (`pack_assembly`, append-only).
6. Shows what changed since the listed version (or that it's new), the vendor-data
   report, the SHA-256, and the signing command.

## What `check` does, after signing

1. Refuses a file changed since it was frozen (its SHA-256 against the store's).
2. Refuses a missing signature, and checks it with `minisign` against each pack key in
   the clone's `keys.yaml`; the trusted comment must be `ID version N`.
3. Writes the index with the checker's own `checker packs index` (which checks every
   pack's signature again, and `keys.yaml`'s against the root key), and says what's
   left: sign `index.yaml`, commit the pack, the index and both signatures, push the
   branch and open a pull request into dev. Don't touch a file after signing it.
