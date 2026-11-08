"""A.5: AI drafts of an approved threat, through the real SDK with a fake Messages
API (httpx2.MockTransport): nothing here reaches a network or spends anything."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import anthropic
import httpx2
import pytest

from drafter import candidates as c
from drafter import cli, decisions, draft, vocabulary
from drafter.checkerformat import CHECKER_COMMIT
from drafter.store import Store
from tests.conftest import NOW

KEY = "sk-ant-api03-" + "k" * 40
CVE = "CVE-2026-111497"
OTHER = "CVE-2026-70188"
KEV_URL = "https://www.cisa.gov/kev.json"


def _fetch(store, feed, url, body):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    return store.record_fetch(feed=feed, url=url, fetched_at="t", status=200, body=data)


def _cve(store, cve, *, kev=True, statement="Rated Important.", packages=("brotli",)):
    page = _fetch(store, "nvd", f"https://nvd.example/{cve}", {"page": cve})
    store.upsert(
        "nvd",
        {
            "cve": cve,
            "last_modified": "2026-10-23T00:00:00.000000Z",
            "exploitation": "active" if kev else "none",
            "ssvc_time": "2026-10-23T00:00:00.000000Z",
            "kev_added": None,
            "products": json.dumps(["google:brotli"]),
            "description": "A buffer overflow in the Brotli decoder.",
            "cvss": json.dumps(
                {
                    "version": "3.1",
                    "vector": "CVSS:3.1/AV:N",
                    "score": 9.8,
                    "source": "nvd@nist.gov",
                }
            ),  # fmt: skip
            "fetch_id": page,
        },
        ("cve",),
    )
    if kev:
        feed = _fetch(
            store,
            "kev",
            KEV_URL,
            {"vulnerabilities": [{"cveID": cve, "vulnerabilityName": "Brotli flaw",
                                  "notes": "https://github.com/google/brotli/releases"}]},
        )  # fmt: skip
        store.upsert(
            "kev",
            {"cve": cve, "date_added": "2026-10-27", "vendor": "Google", "product": "Brotli",
             "name": "Brotli flaw", "fetch_id": feed},
            ("cve",),
        )  # fmt: skip
    for vendor, record, pkgs in (
        ("redhat", {"statement": statement, "details": ["An out-of-bounds write."],
                    "references": ["https://access.redhat.com/security/cve/" + cve],
                    "affected_release": [{"package": "never-sent-1.0"}]},
         [{"release": "rhel:9", "package": p, "fixed": True, "product": "enterprise_linux"}
          for p in packages]),
        ("ubuntu", {"id": "UBUNTU-" + cve, "details": "A buffer overflow.",
                    "references": [{"url": "https://ubuntu.com/security/" + cve}]},
         [{"release": "ubuntu:24.04", "package": p, "fixed": True} for p in packages]),
    ):  # fmt: skip
        fid = _fetch(store, f"vendor-{vendor}", f"https://{vendor}.example/{cve}", record)
        store.upsert(
            "vendor_cve",
            {"cve": cve, "vendor": vendor, "attempted_at": "2026-11-07T11:00:00.000000Z",
             "error": None, "checked_at": "2026-11-07T11:00:00.000000Z", "found": 1,
             "published": None, "packages": json.dumps(pkgs), "title": None,
             "statement": None, "fetch_id": fid},
            ("cve", "vendor"),
        )  # fmt: skip


def _threat(store, cve=CVE):
    since = "2026-10-01T00:00:00.000000Z"
    return next(t for t in c.threats(c.classify(store, since, now=NOW))
                if cve in {x.cve for x in t.candidates})  # fmt: skip


@pytest.fixture
def approved_store(store):
    _cve(store, CVE)
    decisions.record(store, _threat(store), "approve", "", "jch", "2026-11-08T18:53:00Z")
    return store


GOOD = {
    "title": "Brotli decoder out-of-bounds write (CVE-2026-111497)",
    "mitigations_yaml": "[]",
    "detections_yaml": "- id: crash\n  check: kernel.segfault\n  counts: while_exposed\n"
    "  likelihood_ratio: 2\n",
    "remediation": ["Update the system Brotli library and restart the services using it."],
    "references": [f"https://access.redhat.com/security/cve/{CVE}"],
    "unknowns": ["No indicators of compromise are given."],
}


def message(body, answer=None, *, stop="end_turn", usage=None, text=None):
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": body["model"],
        "content": [
            {"type": "thinking", "thinking": "", "signature": "sig"},
            {"type": "text", "text": text if text is not None else json.dumps(answer or GOOD)},
        ],
        "stop_reason": stop,
        "stop_sequence": None,
        "usage": usage or {"input_tokens": 8000, "output_tokens": 3000},
    }


class Provider:
    def __init__(self, *replies, status=200, fail=None):
        self.replies = list(replies) or [lambda body: message(body)]
        self.status, self.fail, self.sent = status, fail, []

    def handler(self, request):
        body = json.loads(request.content)
        self.sent.append((dict(request.headers), body))
        if self.fail:
            raise self.fail
        if self.status != 200:
            return httpx2.Response(
                self.status,
                headers={"request-id": "req_err"},
                json={"type": "error", "error": {"type": "x", "message": "no"}},
            )
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        return httpx2.Response(200, headers={"request-id": "req_ok"}, json=reply(body))

    def client(self):
        return anthropic.Anthropic(
            api_key=KEY,
            max_retries=0,
            http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(self.handler)),
        )


def _run(store, provider, **kw):
    return draft.draft(store, [CVE], provider.client(), now=lambda: NOW, **kw)


# what is sent


def test_an_approved_threat_is_drafted_once_and_its_cost_kept(approved_store):
    p = Provider()
    made = _run(approved_store, p)
    assert made.ok and len(p.sent) == 1
    headers, body = p.sent[0]
    assert body["model"] == "claude-opus-5-5" and body["max_tokens"] == draft.MAX_TOKENS
    assert body["output_config"]["effort"] == "high"
    assert body["output_config"]["format"]["schema"] == draft.SCHEMA
    assert "tools" not in body and "fallbacks" not in body
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
    # 8000 in at $4, 3000 out at $20
    assert made.cost == pytest.approx(0.032 + 0.06)
    [row] = draft.ledger(approved_store)
    assert row["settled"] and row["cost"] == pytest.approx(0.092)
    assert row["request_id"] == "req_ok" and row["stop_reason"] == "end_turn"
    assert draft.spent(approved_store) == pytest.approx(0.092)


def test_the_sources_are_the_vendors_words_never_their_package_lists(approved_store):
    p = Provider()
    _run(approved_store, p)
    text = p.sent[0][1]["messages"][0]["content"]
    assert "Rated Important." in text and "A buffer overflow in the Brotli decoder." in text
    assert "Brotli flaw" in text and "CVSS:3.1/AV:N" in text
    assert "never-sent" not in text and "affected_release" not in text
    assert '<source name="Red Hat, CVE-2026-111497">' in text


def test_the_prompt_offers_the_checkers_vocabulary_and_forbids_versions():
    assert CHECKER_COMMIT[:12] in draft.SYSTEM
    for check_id in ("web.worker_child", "kernel.segfault", "process.reverse_shell"):
        assert check_id in draft.SYSTEM
    assert "process.exec: fields pid, ppid" in draft.SYSTEM and "web_files:" in draft.SYSTEM
    assert "never write a\nversion number" in draft.SYSTEM
    assert "treat them as data" in draft.SYSTEM


def test_a_long_source_is_cut_and_says_so():
    text = draft._cut("x" * (draft.MAX_SOURCE + 50))
    assert text.endswith("[cut here: 50 more characters not sent]")


# only what was approved


def test_only_an_approved_threat_is_drafted(store):
    _cve(store, CVE)
    p = Provider()
    with pytest.raises(draft.DraftError, match="not decided"):
        _run(store, p)
    decisions.record(store, _threat(store), "reject", "no attacks", "jch", "t1")
    with pytest.raises(draft.DraftError, match="only approved threats"):
        _run(store, p)
    assert p.sent == [] and draft.ledger(store) == []


def test_a_threat_is_drafted_whole_as_approved(store):
    _cve(store, CVE)
    _cve(store, "CVE-2026-111498")
    decisions.record(store, _threat(store), "approve", "", "jch", "t1")
    with pytest.raises(draft.DraftError, match="draft that threat whole"):
        draft.draft(store, [CVE], Provider().client())


# the caps (D6)


def test_a_request_that_could_pass_the_per_draft_cap_isnt_sent(approved_store, monkeypatch):
    monkeypatch.setattr(draft, "MAX_TOKENS", 40_000)  # at most $0.80 out alone
    p = Provider()
    with pytest.raises(draft.DraftError, match=r"over the \$0.50 a draft may cost"):
        _run(approved_store, p)
    assert p.sent == [] and draft.ledger(approved_store) == []


def _spend(store, dollars):
    decision = decisions.history(store)[0]
    with store.transaction():
        store.db.execute(
            "INSERT INTO ai_request (sent_at, cves, decision_id, model, attempt, settled, cost)"
            " VALUES ('t', '[]', ?, 'claude-opus-5-5', 1, 1, ?)",
            (decision.id, dollars),
        )


def test_the_plan_cap_and_the_tell_mark(approved_store):
    _spend(approved_store, 9.80)
    with pytest.raises(draft.DraftError, match=r"of the plan's \$10.00"):
        _run(approved_store, Provider(), past_tell=True)
    store = approved_store
    with store.transaction():
        store.db.execute("UPDATE ai_request SET cost = 5.00")
    with pytest.raises(draft.DraftError, match=r"told at \$5.00.*--past-tell-mark"):
        _run(store, Provider())
    assert _run(store, Provider(), past_tell=True).ok


def test_the_spending_record_is_kept(approved_store):
    _run(approved_store, Provider())
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError, match="kept"):
        approved_store.db.execute("DELETE FROM ai_request")


def test_a_request_with_no_answer_counts_at_its_worst(approved_store):
    p = Provider(fail=httpx2.ReadTimeout("slow"))
    with pytest.raises(draft.DraftError, match="the most it could have cost"):
        _run(approved_store, p)
    [row] = draft.ledger(approved_store)
    sent = [
        {"role": "user", "content": draft.user_message([CVE], draft.sources(approved_store, [CVE]))}
    ]
    worst = draft.worst_cost(draft.estimate(draft.SYSTEM, sent))
    assert worst > 0.15 and row["cost"] == pytest.approx(worst)
    assert row["settled"] and row["stop_reason"].startswith("no answer")


def test_a_request_the_api_turned_away_costs_nothing(approved_store):
    with pytest.raises(draft.DraftError, match="HTTP 400"):
        _run(approved_store, Provider(status=400))
    [row] = draft.ledger(approved_store)
    assert row["cost"] == 0 and row["stop_reason"] == "HTTP 400"


def test_a_run_killed_mid_request_leaves_its_worst_case(approved_store):
    class Killed(BaseException):
        pass

    p = Provider(fail=None)
    p.handler = lambda request: (_ for _ in ()).throw(Killed())
    with pytest.raises(Killed):
        _run(approved_store, p)
    [row] = draft.ledger(approved_store)
    sent = [
        {"role": "user", "content": draft.user_message([CVE], draft.sources(approved_store, [CVE]))}
    ]
    worst = draft.worst_cost(draft.estimate(draft.SYSTEM, sent))
    assert not row["settled"] and row["cost"] == pytest.approx(worst)


# checking the answer


def _answer(**changes):
    return {**GOOD, **changes}


@pytest.mark.parametrize(
    ("answer", "problem"),
    [
        (
            _answer(detections_yaml="- id: x\n  check: web.no_such\n  likelihood_ratio: 2\n"),
            "the tool has no check web.no_such",
        ),
        (
            _answer(
                detections_yaml="- id: x\n  check: web.worker_child\n  variant: odd\n"
                "  likelihood_ratio: 2\n"
            ),
            "web.worker_child has no variant odd",
        ),
        (
            _answer(
                detections_yaml="- id: x\n  title: t\n  events:\n    any_of:\n"
                "      - type: web.nothing\n  likelihood_ratio: 2\n"
            ),
            "no event type web.nothing",
        ),
        (
            _answer(
                detections_yaml="- id: x\n  title: t\n  events:\n    any_of:\n"
                "      - type: kernel.segfault\n        fields: {exe: {prefix: x}}\n"
                "  likelihood_ratio: 2\n"
            ),
            "kernel.segfault has no field exe",
        ),
        (
            _answer(
                detections_yaml="- id: x\n  title: t\n  snapshot: {section: secrets,"
                " state: added}\n  likelihood_ratio: 2\n"
            ),
            "no snapshot section secrets",
        ),
        (
            _answer(
                detections_yaml="- id: x\n  title: t\n  snapshot: {section: packages,"
                " state: added}\n  likelihood_ratio: 2\n"
            ),
            "what exposure is judged from",
        ),
        (
            _answer(
                detections_yaml="- id: x\n  check: web.worker_child\n  likelihood_ratio: 500\n"
            ),
            "format: detections.0.likelihood_ratio",
        ),
        (_answer(detections_yaml="{x: [unclosed"), "detections_yaml isn't YAML"),
        (_answer(detections_yaml="just: a mapping"), "detections_yaml isn't a YAML list"),
        (
            _answer(references=["https://evil.example/"]),
            "a reference that isn't in the sources: https://evil.example/",
        ),
        (_answer(remediation=["Upgrade to 1.2.1 now."]), "a version in the answer: 1.2.1"),
        (_answer(remediation=["Install 1.0.9-2ubuntu0.1."]), "a version in the answer"),
        (
            _answer(remediation=["Update dotnet8.0 first."]),
            "a package name in the answer: dotnet8.0",
        ),
        (_answer(title="A ‮reversed title"), "format: title"),
        (_answer(remediation=[]), "format: remediation"),
    ],
)
def test_a_bad_answer_is_refused(answer, problem):
    found = [draft.Source("Red Hat", f"https://access.redhat.com/security/cve/{CVE}", 1, None, "u")]
    checked = draft.check(json.dumps(answer), found, {"dotnet8.0"}, [CVE])
    assert any(problem in p for p in checked.problems), checked.problems


def test_a_good_answer_passes_and_urls_dont_count_as_versions():
    said = f"https://example.org/brotli/1.2.1/notes and {GOOD['references'][0]}"
    found = [draft.Source("x", said, 1, None, "u")]
    answer = _answer(references=["https://example.org/brotli/1.2.1/notes"])
    checked = draft.check(json.dumps(answer), found, {"dotnet8.0"}, [CVE])
    assert checked.problems == [] and checked.detections[0]["check"] == "kernel.segfault"
    # NVD's 9.8, CVSS 3.1 and .NET 8.0 are not versions of a package
    prose = _answer(remediation=["NVD scores it 9.8 (CVSS 3.1); .NET 8.0 bundles its own copy."])
    assert draft.check(json.dumps(prose), found, {"dotnet8.0"}, [CVE]).problems == []


def test_an_answer_not_in_the_shape_asked_is_refused():
    assert draft.check("not json", [], set(), [CVE]).problems == ["the answer isn't JSON"]
    odd = draft.check(json.dumps({"title": "x"}), [], set(), [CVE])
    assert odd.problems == ["the answer doesn't have the fields asked for"]


def test_a_refused_answer_goes_back_once_with_its_problems(approved_store):
    bad = _answer(remediation=["Upgrade to 1.2.1."])
    p = Provider(lambda body: message(body, bad), lambda body: message(body))
    made = _run(approved_store, p)
    assert made.ok and len(p.sent) == 2 and [r["attempt"] for r in made.requests] == [1, 2]
    second = p.sent[1][1]["messages"]
    assert second[1]["role"] == "assistant"
    assert second[1]["content"][0] == {"type": "thinking", "thinking": "", "signature": "sig"}
    assert "a version in the answer: 1.2.1" in second[2]["content"]
    assert [r["attempt"] for r in draft.ledger(approved_store)] == [1, 2]


def test_two_refused_answers_end_the_draft_unusable(approved_store):
    bad = _answer(remediation=["Upgrade to 1.2.1."])
    p = Provider(lambda body: message(body, bad))
    made = _run(approved_store, p)
    assert not made.ok and len(p.sent) == draft.MAX_ATTEMPTS
    assert "NOT USABLE" in draft.render(made, "now")


def test_a_refusal_is_recorded_and_nothing_else_is_tried(approved_store):
    p = Provider(lambda body: {**message(body, text=""), "stop_reason": "refusal",
                               "stop_details": {"type": "refusal", "category": "cyber",
                                                "explanation": "x"}})  # fmt: skip
    made = _run(approved_store, p)
    assert not made.ok and len(p.sent) == 1 and made.checked.problems == ["stopped: refusal"]
    assert draft.ledger(approved_store)[0]["stop_reason"] == "refusal"


def test_a_second_try_that_could_pass_the_cap_isnt_sent(approved_store):
    bad = _answer(remediation=["Upgrade to 1.2.1."])
    # A first answer that cost $0.30: a second at its worst would pass $0.50.
    p = Provider(
        lambda body: message(body, bad, usage={"input_tokens": 0, "output_tokens": 15_000})
    )
    made = _run(approved_store, p)
    assert len(p.sent) == 1 and not made.ok
    assert any("not sent again" in x for x in made.checked.problems)


# the draft file and the commands


def test_the_draft_says_where_everything_came_from(approved_store):
    made = _run(approved_store, Provider())
    text = draft.render(made, "2026-11-08 19:00 UTC")
    assert text.startswith("# AI DRAFT (A.5)")
    assert "Request 1: $0.0920, end_turn, req_ok" in text
    assert f"Red Hat, {CVE}: fetch" in text and "sha256" in text
    assert "#   - No indicators of compromise are given." in text
    import yaml

    body = yaml.safe_load(text)
    assert body["title"].startswith("Brotli") and body["detections"][0]["id"] == "crash"
    assert "packages" not in body and "exposure" not in body


def test_hidden_characters_in_the_unknowns_dont_reach_the_file(approved_store):
    odd = _answer(unknowns=["fine\x1b[31m and ‮ flipped"])
    made = _run(approved_store, Provider(lambda body: message(body, odd)))
    text = draft.render(made, "now")
    assert "\x1b" not in text and "‮" not in text


def test_the_cli_dry_run_sends_nothing(tmp_path, capsys, monkeypatch):
    s = Store(tmp_path / "drafter.sqlite3")
    _cve(s, CVE)
    decisions.record(s, _threat(s), "approve", "", "jch", "t1")
    s.close()

    def nowhere(*a, **k):
        raise AssertionError("sent")

    monkeypatch.setattr(httpx2.HTTPTransport, "handle_request", nowhere)
    assert cli.main(["--home", str(tmp_path), "draft", CVE, "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "Nothing sent." in out and "source: Red Hat" in out and "at most $0." in out
    assert cli.main(["--home", str(tmp_path), "spend"]) == 0
    assert "spent $0.00 of $10.00" in capsys.readouterr().out


def test_the_cli_drafts_and_writes_the_file(tmp_path, capsys, monkeypatch):
    s = Store(tmp_path / "drafter.sqlite3")
    _cve(s, CVE, packages=("brotli", "dotnet8.0"))
    decisions.record(s, _threat(s), "approve", "", "jch", "t1")
    s.close()
    p = Provider(lambda body: message(body, _answer(remediation=["Update dotnet8.0."])),
                 lambda body: message(body))  # fmt: skip
    client = p.client()
    monkeypatch.setattr(anthropic, "Anthropic", lambda **kw: client)
    out = tmp_path / "brotli.draft.yaml"
    assert cli.main(["--home", str(tmp_path), "draft", CVE, "--out", str(out)]) == 0
    assert "a package name in the answer: dotnet8.0" in p.sent[1][1]["messages"][2]["content"]
    assert out.read_text().startswith("# AI DRAFT")
    assert cli.main(["--home", str(tmp_path), "spend"]) == 0
    printed = capsys.readouterr().out
    assert "try 2  end_turn" in printed and "of $10.00" in printed


def test_schema_6_keeps_the_spending_record(tmp_path):
    s = Store(tmp_path / "x.sqlite3")
    cols = {r[1] for r in s.db.execute("PRAGMA table_info(ai_request)")}
    assert {"cost", "settled", "request_id", "answer", "problems", "decision_id"} <= cols
    s.close()


# the pinned copies


CHECKER = Path(__file__).resolve().parents[2] / "compromise-checker"


@pytest.mark.skipif(not (CHECKER / ".git").exists(), reason="no checker clone beside this one")
@pytest.mark.parametrize("name", ["format", "versions"])
def test_the_copied_format_is_the_checkers_at_its_commit(name):
    ours = (Path(draft.__file__).parent / "checkerformat" / f"{name}.py").read_text()
    body = "".join(ours.splitlines(keepends=True)[4:]).replace(
        "from drafter.checkerformat.versions import", "from checker.packs.versions import"
    )
    git = ["git", "-C", str(CHECKER), "show", f"{CHECKER_COMMIT}:checker/packs/{name}.py"]
    theirs = subprocess.run(git, capture_output=True, text=True, check=True).stdout  # noqa: S603
    assert body == theirs


def test_the_vocabulary_has_what_a_pack_names():
    signed = Path(__file__).resolve().parents[2] / "compromise-checker-packs" / "packs"
    assert "web.worker_child" in vocabulary.CHECKS and "web.errors" in vocabulary.CHECKS
    assert "comm" in vocabulary.EVENTS["kernel.segfault"]
    assert "message" in vocabulary.EVENTS["web.error"]
    assert "packages" not in vocabulary.SECTIONS and "web_files" in vocabulary.SECTIONS
    if signed.exists():  # every detection in a signed pack passes the drafter's check
        from drafter.checkerformat import format as packformat

        for path in signed.glob("*/PACK.yaml"):
            pack = packformat.read(path.read_bytes())
            raw = [d.model_dump(exclude_none=True) for d in pack.detections]
            assert draft._vocabulary_problems(raw) == []


def test_an_answer_cut_off_at_the_allowance_is_reported_not_tried_again(approved_store):
    p = Provider(lambda body: message(body, stop="max_tokens", text='{"title": "Brot'))
    made = _run(approved_store, p)
    assert not made.ok and len(p.sent) == 1 and made.checked.problems == ["stopped: max_tokens"]
    assert p.sent[0][1]["max_tokens"] == 8_000


def test_a_retry_fits_the_draft_cap_after_a_typical_first_answer(approved_store):
    # A first answer like the measured one (about $0.09) leaves room for a second.
    bad = _answer(remediation=["Upgrade to 1.2.1."])
    p = Provider(lambda body: message(body, bad), lambda body: message(body))
    made = _run(approved_store, p)
    assert len(p.sent) == 2 and made.ok and made.cost <= draft.PER_DRAFT_CAP


def test_cves_decided_apart_are_drafted_apart(store):
    _cve(store, CVE)
    _cve(store, "CVE-2026-111498")
    threat = _threat(store)
    for cand in threat.candidates:
        decisions.record(
            store, c.Threat("judge", threat.families, [cand]), "approve", "", "jch", "t"
        )
    with pytest.raises(draft.DraftError, match="decided apart"):
        draft.draft(store, [CVE, "CVE-2026-111498"], Provider().client())
