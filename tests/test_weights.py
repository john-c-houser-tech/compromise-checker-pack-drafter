"""C.1: detection weights a draft can justify (D11, D12), with a fake Messages API."""

from __future__ import annotations

import json
import subprocess

import pytest

from drafter import draft, vocabulary
from drafter.checkerformat import CHECKER_COMMIT
from tests.test_draft import CHECKER, Provider, _answer, _run, approved_store, message  # noqa: F401


@pytest.mark.skipif(not (CHECKER / ".git").exists(), reason="no checker clone beside this one")
def test_the_bands_are_the_checkers_at_the_pinned_commit():
    git = ["git", "-C", str(CHECKER), "show", f"{CHECKER_COMMIT}:docs/checks.md"]
    doc = subprocess.run(git, capture_output=True, text=True, check=True).stdout  # noqa: S603
    read = vocabulary.read_bands(doc)
    assert {c: read[c] for c in vocabulary.CHECKS} == vocabulary.BANDS
    assert set(vocabulary.BANDS) == set(vocabulary.CHECKS)


def test_how_far_a_pack_may_raise_a_check():
    assert vocabulary.BANDS["web.worker_child"] == ("medium", "high")  # an interpreter: medium
    assert (vocabulary.floor("web.worker_child"), vocabulary.ceiling("web.worker_child")) == (
        4,
        100,
    )
    assert (vocabulary.floor("web.errors"), vocabulary.ceiling("web.errors")) == (1.5, 4)
    assert vocabulary.ceiling("kernel.segfault") == 20  # low to medium: medium's raise
    assert vocabulary.ceiling("process.hidden") == 100  # critical stays critical


def test_the_prompt_gives_each_checks_band_and_the_rule():
    assert "web.worker_child [medium to high]:" in draft.SYSTEM
    assert "web.errors [low]:" in draft.SYSTEM
    assert "never more than one band above its own" in draft.SYSTEM
    # Its example of a raise comes from no signed pack's threat (it would anchor C.2).
    rules = draft.SYSTEM.split("- Weights.", 1)[1].split("- weights:", 1)[0]
    assert "PHP" not in rules and "web worker" not in rules


def _checked(detections, weights=None):
    answer = _answer(
        detections_yaml=detections, **({"weights": weights} if weights is not None else {})
    )
    said = answer["references"][0]
    found = [draft.Source("x", said, 1, None, "u", draft._urls(said))]
    return draft.check(json.dumps(answer), found, set(), ["CVE-2026-111497"])


def test_a_weight_past_the_allowed_raise_is_refused():
    out = _checked(
        "- id: errs\n  check: web.errors\n  counts: while_exposed\n  likelihood_ratio: 20\n"
    )
    assert any("web.errors is in the low band; a pack may raise it to at most 4, not 20" in p
               for p in out.problems)  # fmt: skip


def test_a_weight_that_adds_nothing_is_a_note():
    out = _checked("- id: hit\n  check: web.new_script_hit\n  likelihood_ratio: 20\n")
    assert not out.problems
    assert any("names web.new_script_hit at 20, at or below its lowest band (high, 20)" in n
               for n in out.notes)  # fmt: skip


def test_the_signed_php2shell_weights_pass():
    out = _checked(
        "- id: worker-child\n  check: web.worker_child\n  likelihood_ratio: 100\n"
        "- id: new-script-hit\n  check: web.new_script_hit\n  likelihood_ratio: 50\n"
        "- id: server-errors\n  check: web.errors\n  counts: while_exposed\n  likelihood_ratio: 4\n"
    )
    assert out.problems == [] and not any(
        "adds nothing" in n or "raises none" in n for n in out.notes
    )


def test_every_weight_needs_its_reason():
    out = _checked("- id: hit\n  check: web.new_script_hit\n  likelihood_ratio: 50\n", weights=[])
    assert "detection hit: no reason for its weight in weights" in out.problems


def test_the_header_gives_each_weight_with_its_reason(approved_store):  # noqa: F811
    answer = _answer(
        detections_yaml="- id: worker-child\n  check: web.worker_child\n  likelihood_ratio: 100\n",
        weights=[
            {"id": "worker-child", "why": "A web worker starting a shell is this flaw working."}
        ],
    )
    made = _run(approved_store, Provider(lambda body: message(body, answer)))
    assert made.ok, made.checked.problems
    text = draft.render(made, "2026-11-09 10:00 UTC")
    assert "# Weights, with the AI's reasons" in text
    header = " ".join(line.lstrip("#- ") for line in text.split("# Weights", 1)[1].splitlines())
    assert "worker-child (web.worker_child, band medium/high) at 100: A web worker" in header
    assert "starting a shell is this flaw working." in header
    import yaml

    assert "weights" not in yaml.safe_load(text)  # D12: the header only, not the pack
