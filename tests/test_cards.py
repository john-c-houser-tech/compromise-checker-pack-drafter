"""A.4b: what a card says, the signed packs it reads, and schema 5."""

from __future__ import annotations

import gzip
import json
import sqlite3

import pytest

from drafter import candidates as c
from drafter import cards, packs, upgrade
from drafter.feeds import nvd
from drafter.store import SCHEMA_VERSION, Store

A, B = "CVE-2026-5101", "CVE-2026-5102"


def _threat(*cands):
    return c.Threat("judge", ["x"], list(cands))


def _cand(cve, *kinds, note=""):
    return c.Candidate(
        cve, [c.Signal(k, "2026-10-21T00:00:00.000000Z", note) for k in kinds], "judge"
    )


# attacks


def test_exploited_names_cisas_own_words_per_cve():
    known = {
        A: cards.Facts(A, kev_added="2026-10-29", exploitation="active", ssvc_time="2026-10-13T1"),
        B: cards.Facts(B, exploitation="none", ssvc_time="2026-10-21T00"),
    }
    got = cards.attacks(_threat(_cand(A, "kev", "nvd"), _cand(B, "redhat")), known)
    assert got == {
        "word": "exploited",
        "text": f"{A}: on CISA's list since 2026-10-29; CISA says active (2026-10-13)."
        f" {B}: CISA says none (2026-10-21)",
    }


def test_no_sign_of_attacks_says_what_listed_it():
    known = {cve: cards.Facts(cve, exploitation="none", ssvc_time="2026-10-08T0") for cve in (A, B)}
    got = cards.attacks(_threat(_cand(A, "redhat"), _cand(B, "redhat", "ubuntu")), known)
    assert got["word"] == "none"
    assert got["text"] == (
        "CISA says none (2026-10-08), for both. Listed on Red Hat's Critical rating and"
        " Ubuntu's critical priority alone"
    )


def test_poc_and_unassessed_are_not_exploited():
    known = {A: cards.Facts(A, exploitation="poc")}
    got = cards.attacks(_threat(_cand(A, "redhat"), _cand(B, "redhat")), known)
    assert got["word"] == "none"
    assert f"{A}: CISA says proof of concept only" in got["text"]
    assert f"{B}: CISA hasn't assessed it" in got["text"]


def test_added_by_hand_shows_the_note():
    got = cards.attacks(_threat(_cand(A, "manual", note="PHP2Shell reached John first")), {})
    assert got == {
        "word": "hand",
        "text": "CISA hasn't assessed it. Added by hand: PHP2Shell reached John first",
    }


def test_ratings():
    both = _threat(_cand(A, "redhat"), _cand(B, "redhat", "ubuntu"))
    assert cards.ratings(both, False) == f"Red Hat Critical (both); Ubuntu priority critical ({B})"
    assert cards.ratings(_threat(_cand(A, "kev")), True) == "none beyond CISA's"
    assert cards.ratings(_threat(_cand(A, "manual")), False) == "none"


# what


def test_what_prefers_cisas_name_then_red_hats_title():
    known = {
        A: cards.Facts(A, kev_name="PHP Memory Corruption Vulnerability", rh_title="php: OOM"),
        B: cards.Facts(B, rh_title="php: stale state"),
    }
    got = cards.what(_threat(_cand(B), _cand(A), _cand("CVE-2026-5103")), known)
    assert got == [
        (A, "CISA: PHP Memory Corruption Vulnerability"),
        (B, "Red Hat: php: stale state"),
        ("CVE-2026-5103", "no name yet; NVD's description is below, if it has one"),
    ]


def test_words_are_cut_and_the_same_words_shown_once():
    same = "Rated Moderate for the Ruby packages. " * 30
    known = {
        A: cards.Facts(A, rh_statement=same, description="GitLab A"),
        B: cards.Facts(B, rh_statement=same, description="GitLab B"),
    }
    got = cards.words(_threat(_cand(A), _cand(B)), known)
    assert [w["cite"] for w in got] == [
        f"Red Hat's statement, {A} and {B}",
        f"NVD, {A}",
        f"NVD, {B}",
    ]
    assert len(got[0]["text"]) <= cards.WORDS_CUT + 2 and got[0]["text"].endswith(" …")
    assert got[0]["link"] == f"https://access.redhat.com/security/cve/{A}"
    assert got[2]["link"] == f"https://nvd.nist.gov/vuln/detail/{B}"
    one = cards.words(_threat(_cand(A)), {A: cards.Facts(A, description="short")})
    assert one == [
        {"cite": "NVD", "text": "short", "link": f"https://nvd.nist.gov/vuln/detail/{A}"}
    ]


# reach


@pytest.mark.parametrize(
    ("vector", "words"),
    [
        (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "Over the network, no login, no user action",
        ),
        (
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
            "Over the network, no login, needs a user to act, hard to pull off",
        ),
        (
            "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "With local access, a low-privilege login, no user action",
        ),
        (
            "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
            "From the same network, an admin login, no user action",
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            "Over the network, no login, no user action, only under certain conditions",
        ),
        (
            "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "With physical access, no login, needs a user to act",
        ),
        ("CVSS:3.1", None),
    ],
)
def test_reach_words(vector, words):
    assert cards.reach_words(vector) == words


@pytest.mark.parametrize(
    ("source", "who"),
    [
        ("nvd@nist.gov", "NVD's"),
        ("cve@gitlab.com", "GitLab's"),
        ("secalert_us@oracle.com", "Oracle's"),
        ("infosec@edk2.groups.io", "EDK2's"),
        ("psirt@example.org", "example.org's"),
        ("134c704f-9b21-4f2e-91b3-4a467353bcc0", "CISA's"),
        ("416baaa9-dc9f-4396-8d5f-8c081fb06d67", "kernel.org's"),
        ("6b3ad84c-e1a6-4bf7-a703-f496b71e49db", "the reporting organisation's"),
        ("", "the reporting organisation's"),
        ("x@notgitlab.com", "notgitlab.com's"),
    ],
)
def test_whose_score(source, who):
    assert cards.whose(source) == who


def _score(vector, score, source="nvd@nist.gov"):
    return {"version": vector.split("/")[0][5:], "vector": vector, "score": score, "source": source}


NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_reach_is_one_line_when_the_cves_agree_and_per_cve_otherwise():
    same = {A: cards.Facts(A, cvss=_score(NET, 9.8)), B: cards.Facts(B, cvss=_score(NET, 8.1))}
    got = cards.reach(_threat(_cand(A), _cand(B)), same)
    assert got == [
        ("", "Over the network, no login, no user action (CVSS 3.1: 9.8 and 8.1, NVD's scores)")
    ]
    apart = {A: cards.Facts(A, cvss=_score(NET, 9.8, "secure@microsoft.com"))}
    got = cards.reach(_threat(_cand(A), _cand(B)), apart)
    assert got == [
        (A, "Over the network, no login, no user action (CVSS 3.1: 9.8, Microsoft's score)"),
        (B, "no CVSS score yet"),
    ]
    assert cards.reach(_threat(_cand(A)), {A: cards.Facts(A, cvss={"vector": 3})}) == [
        ("", "no CVSS score yet")
    ]


# fix


def _p(release, name, fixed, **extra):
    return {"release": release, "package": name, "fixed": fixed, **extra}


def test_fix_line():
    assert cards.fix([_p("rhel:9", "a", True), _p("rhel:10", "a", True)]) == (
        "Fixed on every listed release"
    )
    assert cards.fix([_p("rhel:9", "a", False)]) == "No fix yet on any listed release"
    got = cards.fix(
        [
            _p("rhel:9", "nodejs", True),
            _p("rhel:9", "nodejs", False),
            _p("ubuntu:22.04", "dotnet6", False),
            _p("ubuntu:22.04", "dotnet7", False),
            _p("ubuntu:22.04", "dotnet8", True),
            _p("ubuntu:22.04", "linux", False, kernel=True),
            _p("ubuntu:22.04", "webkit", False, set_aside="desktop"),
        ]
    )
    assert (
        got == "Fixed for 2 of 5; no fix yet: nodejs (one stream) on rhel:9,"
        " dotnet6 and dotnet7 on ubuntu:22.04"
    )
    assert cards.fix([]) is None


# NVD's score and Red Hat's words, as kept


def _metrics(**kinds):
    out = {}
    for key, items in kinds.items():
        out[key] = [
            {"source": src, "type": kind, "cvssData": {"vectorString": vec, "baseScore": score}}
            for src, kind, vec, score in items
        ]
    return out


V4 = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def test_the_score_shown_is_nvds_31_then_the_reporters_then_older_then_40():
    both = _metrics(
        cvssMetricV40=[("security@php.net", "Secondary", V4, 9.2)],
        cvssMetricV31=[
            ("cve@gitlab.com", "Secondary", NET, 10.0),
            ("nvd@nist.gov", "Primary", NET, 9.8),
        ],
    )
    assert json.loads(nvd.cvss(both)) == {
        "version": "3.1",
        "vector": NET,
        "score": 9.8,
        "source": "nvd@nist.gov",
    }
    only4 = _metrics(cvssMetricV40=[("infosec@edk2.groups.io", "Secondary", V4, 9.5)])
    assert json.loads(nvd.cvss(only4))["version"] == "4.0"
    assert nvd.cvss({}) is None and nvd.cvss("x") is None


@pytest.mark.parametrize(
    "item",
    [
        ("nvd@nist.gov", "Primary", "CVSS:3.1/AV:N<script>", 9.8),
        ("nvd@nist.gov", "Primary", NET, "9.8"),
        ("nvd@nist.gov", "Primary", NET, True),
        ("nvd@nist.gov", "Primary", NET, 11),
        ("nvd@nist.gov", "Primary", "CVSS:2.0/AV:N/AC:L", 7.5),
    ],
)
def test_odd_scores_are_left_out(item):
    assert nvd.cvss(_metrics(cvssMetricV31=[item])) is None


def test_an_odd_source_is_kept_blank():
    got = nvd.cvss(_metrics(cvssMetricV31=[("<b>me</b>", "Primary", NET, 9.8)]))
    assert json.loads(got)["source"] == ""


def test_red_hats_title_and_statement():
    body = json.dumps(
        {"bugzilla": {"description": "ruby:\x1b integer\n overflow"}, "statement": "  Moderate.  "}
    ).encode()
    assert c.redhat_text(body) == ("ruby: integer overflow", "Moderate.")
    assert c.redhat_text(b"[]") == (None, None)
    assert c.redhat_text(b"not json") == (None, None)
    assert c.redhat_text(json.dumps({"bugzilla": "x", "statement": 3}).encode()) == (None, None)
    long = json.dumps({"statement": "x" * 9000}).encode()
    assert len(c.redhat_text(long)[1]) == c.MAX_TEXT


def test_a_refresh_keeps_red_hats_words(ctx, fetcher, store):
    from tests.conftest import ok

    fetcher.add(
        c.REDHAT_URL.format(cve=A),
        ok({"bugzilla": {"description": "php: OOM"}, "statement": "Rated Important."}),
    )
    c._refresh_one(ctx, A, "redhat")
    row = store.db.execute("SELECT title, statement FROM vendor_cve WHERE cve = ?", (A,)).fetchone()
    assert tuple(row) == ("php: OOM", "Rated Important.")


# schema 5


def _schema4(path):
    from drafter.store import _SCHEMA, _STEPS

    db = sqlite3.connect(path)
    db.executescript(_SCHEMA + "".join(_STEPS[n] for n in range(2, 5)) + "PRAGMA user_version = 4;")
    return db


def test_schema_4_moves_up_with_its_decisions_and_their_ids(tmp_path):
    path = tmp_path / "drafter.sqlite3"
    db = _schema4(path)
    for verdict in ("approve", "reject"):
        db.execute(
            "INSERT INTO decision (decided_at, cves, kind, families, verdict, reason,"
            " decided_by) VALUES ('t', '[\"CVE-2026-1\"]', 'judge', '[\"x\"]', ?, 'why', 'jch')",
            (verdict,),
        )
    db.commit()
    db.close()
    s = Store(path)
    assert s.db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION >= 5
    assert s.migrated_from == 4
    rows = s.db.execute("SELECT id, verdict, reason, signs FROM decision ORDER BY id").fetchall()
    assert [tuple(r) for r in rows] == [(1, "approve", "why", None), (2, "reject", "why", None)]
    for sql in ("UPDATE decision SET reason = 'x'", "DELETE FROM decision"):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            s.db.execute(sql)
    insert = (
        "INSERT INTO decision (decided_at, cves, kind, families, verdict, reason, decided_by)"
        " VALUES ('t', '[]', 'judge', '[]', ?, ?, 'jch')"
    )
    with pytest.raises(sqlite3.IntegrityError, match="sign of an attack"):
        s.db.execute(insert, ("approve", ""))  # schema 9: an approve is in scope, or refused
    s.db.execute(
        "INSERT INTO decision (decided_at, cves, kind, families, verdict, reason, decided_by,"
        " signs, leaves) VALUES ('t', '[]', 'judge', '[]', 'approve', '', 'jch',"
        " '[\"kev:CVE-2026-1\"]', 'a webshell')"
    )  # an approve may go without a reason
    with pytest.raises(sqlite3.IntegrityError):
        s.db.execute(insert, ("reject", ""))
    with pytest.raises(sqlite3.IntegrityError):
        s.db.execute(insert, ("approve", "x" * 1001))
    # ids carry on from the highest kept (decisions are never removed, so no id is reused)
    assert max(r[0] for r in s.db.execute("SELECT id FROM decision")) == 3
    cols = {r[1] for r in s.db.execute("PRAGMA table_info(nvd)")}
    assert "cvss" in cols
    cols = {r[1] for r in s.db.execute("PRAGMA table_info(vendor_cve)")}
    assert {"title", "statement"} <= cols
    s.close()


def _nvd_page(cve):
    return json.dumps(
        {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": cve,
                        "lastModified": "2026-10-21T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "A flaw."}],
                        "metrics": _metrics(cvssMetricV31=[("nvd@nist.gov", "Primary", NET, 9.8)]),
                    }
                }
            ],
        }
    ).encode()


def test_moving_up_fills_the_new_columns_from_kept_pages(tmp_path, capsys):
    from drafter import cli

    home = tmp_path / "h"
    home.mkdir()
    db = _schema4(home / "drafter.sqlite3")
    db.execute(
        "INSERT INTO fetches (id, feed, url, fetched_at, status, body) VALUES"
        " (1, 'nvd', 'p', 't', 200, ?), (2, 'vendor-redhat', 'r', 't', 200, ?)",
        (
            gzip.compress(_nvd_page(A)),
            gzip.compress(
                json.dumps({"bugzilla": {"description": "x: y"}, "statement": "S."}).encode()
            ),
        ),
    )
    db.execute("INSERT INTO nvd (cve, last_modified, fetch_id) VALUES (?, 't', 1)", (A,))
    db.execute(
        "INSERT INTO vendor_cve (cve, vendor, attempted_at, checked_at, found, packages, fetch_id)"
        " VALUES (?, 'redhat', 't', 't', 1, '[]', 2)",
        (A,),
    )
    db.commit()
    db.close()
    assert cli.main(["--home", str(home), "candidates", "add", B, "--note", "x"]) == 0
    assert "store filled for schema 5" in capsys.readouterr().out
    s = Store(home / "drafter.sqlite3", read_only=True)
    assert json.loads(s.db.execute("SELECT cvss FROM nvd").fetchone()[0])["score"] == 9.8
    row = s.db.execute("SELECT title, statement FROM vendor_cve").fetchone()
    assert tuple(row) == ("x: y", "S.")
    s.close()
    again = Store(home / "drafter.sqlite3")
    assert upgrade.fill(again) is None  # once only
    again.close()


def test_the_page_fills_them_too_when_it_opens_the_store_first(tmp_path):
    from drafter import web

    db = _schema4(tmp_path / "drafter.sqlite3")
    db.execute(
        "INSERT INTO fetches (id, feed, url, fetched_at, status, body) VALUES"
        " (1, 'nvd', 'p', 't', 200, ?)",
        (gzip.compress(_nvd_page(A)),),
    )
    db.execute("INSERT INTO nvd (cve, last_modified, fetch_id) VALUES (?, 't', 1)", (A,))
    db.commit()
    db.close()
    server = web.make_server(web.Site(home=tmp_path, port=0))
    server.server_close()
    s = Store(tmp_path / "drafter.sqlite3", read_only=True)
    assert s.db.execute("SELECT cvss FROM nvd").fetchone()[0] is not None
    s.close()


def test_a_new_store_fills_nothing(tmp_path):
    s = Store(tmp_path / "new.sqlite3")
    assert s.migrated_from == 0 and upgrade.fill(s) is None
    s.close()


# signed packs


def _clone(tmp_path, packs_yaml="", pack_files=None):
    """A packs clone. Each index line naming a pack file gets that file's real hash,
    as a release writes it."""
    import hashlib
    import re

    root = tmp_path / "packs-clone"
    (root / "packs").mkdir(parents=True)
    for pack_id, text in (pack_files or {}).items():
        (root / "packs" / pack_id).mkdir()
        (root / "packs" / pack_id / "PACK.yaml").write_text(text)

    def hashed(match):
        line, pack_id = match[0], match[1]
        if pack_id not in (pack_files or {}):
            return line
        sha = hashlib.sha256((pack_files[pack_id]).encode()).hexdigest()
        line = re.sub(r', sha256: "[^"]*"', "", line)
        return line.replace("}", f', sha256: "{sha}"}}')

    packs_yaml = re.sub(r'.*id: "([^"]+)".*', hashed, packs_yaml)
    (root / "index.yaml").write_text(f"format: 1\nserial: 1\npacks:\n{packs_yaml}withdrawn: []\n")
    return root


PHP_PACK = "id: php2shell-2026-10\nversion: 1\ncves: [CVE-2026-109618, CVE-2026-109619]\n"


def test_packs_are_read_with_their_cves(tmp_path):
    root = _clone(
        tmp_path,
        '  - {id: "php2shell-2026-10", version: 1, sha256: "x"}\n',
        {"php2shell-2026-10": PHP_PACK},
    )
    [pack] = packs.load(root)
    assert pack == packs.Pack(
        "php2shell-2026-10", 1, frozenset({"CVE-2026-109618", "CVE-2026-109619"})
    )
    [full] = packs.covers([pack], ["CVE-2026-109619", "CVE-2026-109618"])
    assert full.full and full.names == ("CVE-2026-109618", "CVE-2026-109619")
    [part] = packs.covers([pack], ["CVE-2026-109618", "CVE-2026-2"])
    assert not part.full and part.missing == ("CVE-2026-2",)
    assert packs.covers([pack], ["CVE-2026-2"]) == []


@pytest.mark.parametrize(
    ("entry", "files", "message"),
    [
        ('  - {id: "../../etc", version: 1}\n', {}, "odd id"),
        ('  - {id: "a", version: "1"}\n', {}, "no version"),
        ('  - {id: "a", version: 1}\n', {}, "isn't there"),
        ('  - {id: "a", version: 1}\n', {"a": "id: b\ncves: [CVE-2026-1234]\n"}, "isn't the pack"),
        ('  - {id: "a", version: 2}\n', {"a": "id: a\nversion: 1\n"}, "isn't the version"),
        ('  - {id: "a", version: 1, sha256: "00"}\n', {}, "isn't there"),
        (
            '  - {id: "a", version: 1}\n',
            {"a": "id: a\nversion: 1\ncves: [CVE-26-1]\n"},
            "odd list of CVEs",
        ),
        ('  - {id: "a", version: 1}\n', {"a": "id: a\n  cves: : ["}, "can't be read"),
        ("  - just-a-string\n", {}, "odd id"),
    ],
)
def test_an_odd_clone_is_refused_whole(tmp_path, entry, files, message):
    root = _clone(tmp_path, entry, files)
    with pytest.raises(packs.PackError, match=message):
        packs.load(root)


def test_a_pack_outside_the_clone_is_refused(tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "PACK.yaml").write_text("id: a\ncves: [CVE-2026-1234]\n")
    root = _clone(tmp_path, '  - {id: "a", version: 1}\n')
    (root / "packs" / "a").symlink_to(outside)
    with pytest.raises(packs.PackError, match="isn't a file in the clone"):
        packs.load(root)


def test_a_clone_with_no_index_is_refused(tmp_path):
    with pytest.raises(packs.PackError, match="isn't there"):
        packs.load(tmp_path)
    (tmp_path / "index.yaml").write_text("- a list\n")
    with pytest.raises(packs.PackError, match="no list of packs"):
        packs.load(tmp_path)


# from the first review of A.4b


@pytest.mark.parametrize(
    "text",
    [
        "id: a\npublished: 2026-02-30\ncves: [CVE-2026-1234]\n",
        "id: a\ncves: [CVE-2026-1234]\nx: " + "[" * 5000 + "]" * 5000 + "\n",
    ],
)
def test_a_date_that_isnt_one_or_deep_nesting_is_refused_not_raised(tmp_path, text):
    root = _clone(tmp_path, '  - {id: "a", version: 1}\n', {"a": text})
    with pytest.raises(packs.PackError, match="can't be read"):
        packs.load(root)


def test_a_40_vector_with_provider_urgency_is_kept():
    vector = V4 + "/U:Amber"
    got = nvd.cvss(_metrics(cvssMetricV40=[("x@example.org", "Secondary", vector, 9.2)]))
    assert json.loads(got)["vector"] == vector
    assert cards.reach_words(vector) == (
        "Over the network, no login, no user action, only under certain conditions"
    )


def test_a_fill_cut_short_is_done_again_by_the_next_open(tmp_path, monkeypatch):
    path = tmp_path / "drafter.sqlite3"
    db = _schema4(path)
    db.execute(
        "INSERT INTO fetches (id, feed, url, fetched_at, status, body) VALUES"
        " (1, 'nvd', 'p', 't', 200, ?)",
        (gzip.compress(_nvd_page(A)),),
    )
    db.execute("INSERT INTO nvd (cve, last_modified, fetch_id) VALUES (?, 't', 1)", (A,))
    db.commit()
    db.close()

    def busy(store):
        raise sqlite3.OperationalError("database is locked")

    s = Store(path)
    with monkeypatch.context() as m:
        m.setattr(nvd, "reparse_products", busy)
        with pytest.raises(sqlite3.OperationalError):
            upgrade.fill(s)
    s.close()
    s = Store(path)  # already schema 5: the move doesn't happen again, the fill does
    assert s.migrated_from is None
    assert "schema 5" in upgrade.fill(s)
    assert s.db.execute("SELECT cvss FROM nvd").fetchone()[0] is not None
    assert upgrade.fill(s) is None
    s.close()


def test_an_early_vendor_cve_table_keeps_schema_5s_columns(tmp_path):
    path = tmp_path / "early.sqlite3"
    s = Store(path)
    s.db.execute("DELETE FROM refill")
    s.db.execute("DROP TABLE vendor_cve")
    s.db.execute(
        "CREATE TABLE vendor_cve (cve TEXT NOT NULL, vendor TEXT NOT NULL, checked_at TEXT,"
        " found INTEGER, published TEXT, packages TEXT NOT NULL, fetch_id INTEGER,"
        " PRIMARY KEY (cve, vendor))"
    )
    s.close()
    s = Store(path)
    cols = {r[1] for r in s.db.execute("PRAGMA table_info(vendor_cve)")}
    assert {"attempted_at", "title", "statement"} <= cols
    assert upgrade.fill(s) is not None  # owed again, for the rebuilt table
    s.close()


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (
            "id: a\nversion: 1\nl0: &l0 {x: 1}\nl1: &l1 {<<: [*l0, *l0]}\ncves: []\n",
            "anchors and aliases",
        ),
        ("id: a\nversion: 1\nx: " + "[" * 40 + "]" * 40 + "\n", "nested too deep"),
        ("id: a\nversion: 1\nx: !!timestamp nope\n", "can't be read"),
        ("id: a\nversion: 1\nx: !!python/object:os.system {}\n", "can't be read"),
    ],
)
def test_hostile_yaml_is_refused_before_it_is_built(tmp_path, text, message):
    root = _clone(tmp_path, '  - {id: "a", version: 1}\n', {"a": text})
    with pytest.raises(packs.PackError, match=message):
        packs.load(root)


def test_a_pack_edited_since_it_was_signed_doesnt_count(tmp_path):
    root = _clone(
        tmp_path,
        '  - {id: "php2shell-2026-10", version: 1}\n',
        {"php2shell-2026-10": PHP_PACK},
    )
    (root / "packs" / "php2shell-2026-10" / "PACK.yaml").write_text(
        PHP_PACK.replace("]", ", CVE-2026-114406]")
    )
    with pytest.raises(packs.PackError, match="isn't the file index.yaml signed"):
        packs.load(root)


def test_a_pack_naming_no_cves_is_read_and_covers_nothing(tmp_path):
    root = _clone(
        tmp_path,
        '  - {id: "a", version: 1}\n  - {id: "php2shell-2026-10", version: 1}\n',
        {"a": "id: a\nversion: 1\n", "php2shell-2026-10": PHP_PACK},
    )
    got = packs.load(root)
    assert [p.id for p in got] == ["a", "php2shell-2026-10"] and got[0].cves == frozenset()
    assert [c.pack.id for c in packs.covers(got, ["CVE-2026-109618"])] == ["php2shell-2026-10"]


def test_cisas_added_score_comes_after_the_reporters():
    cisa = ("134c704f-9b21-4f2e-91b3-4a467353bcc0", "Secondary", NET, 7.5)
    apache = ("security@apache.org", "Secondary", V4, 9.2)
    got = json.loads(nvd.cvss(_metrics(cvssMetricV31=[cisa], cvssMetricV40=[apache])))
    assert got["source"] == "security@apache.org"
    only = json.loads(nvd.cvss(_metrics(cvssMetricV31=[cisa])))
    assert cards.whose(only["source"]) == "CISA's"


def test_shown_text_loses_control_and_bidi_characters():
    assert cards.clean("ok\u202e reversed\x1b[31m\n x") == "ok reversed [31m x"
    assert cards.clean(None) is None and cards.clean("\u202e") is None


def test_a_cut_doesnt_lose_a_long_run_without_spaces():
    text = "Statement " + "x" * 2000
    got = cards._cut(text)
    assert got.startswith("Statement xxx") and len(got) == cards.WORDS_CUT + 2


# from the third review of A.4b


def test_a_schema_5_store_without_the_refill_table_gets_one_and_owes_a_fill(tmp_path):
    path = tmp_path / "drafter.sqlite3"
    s = Store(path)
    s.db.execute("DROP TABLE refill")
    s.close()
    s = Store(path)
    assert upgrade.fill(s) is not None and upgrade.fill(s) is None
    s.close()


def test_cisas_names_lose_bidi_characters_wherever_they_are_shown(store):
    from tests.test_candidates import _fid, _nvd

    flip = chr(0x202E)
    store.upsert(
        "kev",
        {
            "cve": A,
            "date_added": "2026-10-21",
            "vendor": "SonicWall",
            "product": f"SonicOS{flip}evil",
            "name": None,
            "fetch_id": _fid(store),
        },
        ("cve",),
    )
    _nvd(store, A, "2026-10-21T00:00:00.000000Z", products=())
    [cand] = [x for x in c.classify(store, "2026-10-01T00:00:00.000000Z") if x.cve == A]
    assert cand.kev_name == "SonicWall SonicOS evil"
