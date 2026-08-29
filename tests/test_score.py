"""Scoring: matching rules, N/A logic, and the verified-only trap."""

import json

import pytest
import yaml

from ssbench.generate import generate
from ssbench.models import RunIndex
from ssbench.score import score


@pytest.fixture(scope="module")
def manifest(tmp_path_factory):
    return generate(20260829, tmp_path_factory.mktemp("c") / "bench")


def _write_runs(dir_path, manifest, runs):
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / "index.yaml").write_text(yaml.safe_dump({"runs": runs}))
    return RunIndex.model_validate({"runs": runs})


def test_perfect_tool_scores_full_recall_and_precision(tmp_path, manifest):
    findings = [
        {"RuleID": p.secret_type, "File": p.file, "StartLine": p.line, "Secret": p.value, "Commit": ""}
        for p in manifest.planted
    ]
    (tmp_path / "gl.json").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "gl.json").write_text(json.dumps(findings))
    run_index = _write_runs(tmp_path, manifest, [{
        "tool": "perfect", "version": "1", "parser": "gitleaks", "mode": "default",
        "capabilities": ["working-tree", "history", "verification"], "path": "gl.json",
    }])
    card = score(manifest, run_index, tmp_path)
    run = card.runs[0]
    assert run.overall.tp == manifest.stats.planted_total
    assert run.overall.fp == 0
    assert run.overall.fn == 0
    assert run.overall.recall == 1.0
    assert card.caught_by_no_tool == []


def test_working_tree_only_tool_gets_na_not_fn_for_history(tmp_path, manifest):
    findings = [
        {"RuleID": p.secret_type, "File": p.file, "StartLine": p.line, "Secret": p.value, "Commit": ""}
        for p in manifest.planted if p.present_at_head
    ]
    (tmp_path / "ds.json").write_text(json.dumps(findings))
    run_index = _write_runs(tmp_path, manifest, [{
        "tool": "worktree-only", "version": "1", "parser": "gitleaks", "mode": "default",
        "capabilities": ["working-tree"], "path": "ds.json",
    }])
    card = score(manifest, run_index, tmp_path)
    run = card.runs[0]
    assert run.overall.na == manifest.stats.history_only
    assert run.overall.na > 0


def test_verified_only_run_is_all_misses_but_excluded_from_coverage(tmp_path, manifest):
    (tmp_path / "empty.json").write_text("")
    (tmp_path / "all.json").write_text("\n".join(
        json.dumps({
            "DetectorName": p.secret_type, "Verified": False, "Raw": p.value,
            "SourceMetadata": {"Data": {"Git": {"file": p.file, "line": p.line, "commit": ""}}},
        })
        for p in manifest.planted
    ))
    run_index = _write_runs(tmp_path, manifest, [
        {"tool": "th", "version": "3", "parser": "trufflehog", "mode": "verified-only",
         "capabilities": ["working-tree", "history", "verification"], "path": "empty.json",
         "counts_toward_coverage": False},
        {"tool": "th", "version": "3", "parser": "trufflehog", "mode": "all-results",
         "capabilities": ["working-tree", "history", "verification"], "path": "all.json"},
    ])
    card = score(manifest, run_index, tmp_path)
    verified_only = next(r for r in card.runs if r.mode == "verified-only")
    all_results = next(r for r in card.runs if r.mode == "all-results")
    assert verified_only.overall.tp == 0
    assert verified_only.overall.fn == manifest.stats.planted_total
    assert all_results.overall.tp == manifest.stats.planted_total
    # the empty verified-only run must not make everything look 'caught by none'
    assert card.caught_by_no_tool == []


def test_decoy_hit_is_a_false_positive(tmp_path, manifest):
    decoy = manifest.decoys[0]
    (tmp_path / "gl.json").write_text(json.dumps([
        {"RuleID": "x", "File": decoy.file, "StartLine": decoy.line, "Secret": decoy.value, "Commit": ""}
    ]))
    run_index = _write_runs(tmp_path, manifest, [{
        "tool": "noisy", "version": "1", "parser": "gitleaks", "mode": "default",
        "capabilities": ["working-tree", "history"], "path": "gl.json",
    }])
    card = score(manifest, run_index, tmp_path)
    run = card.runs[0]
    assert run.overall.fp == 1
    assert decoy.id in run.decoys_triggered


def test_tp_fn_na_always_sum_to_planted_total(tmp_path, manifest):
    total = manifest.stats.planted_total
    half = [
        {"RuleID": p.secret_type, "File": p.file, "StartLine": p.line, "Secret": p.value, "Commit": ""}
        for p in manifest.planted[::2]
    ]
    (tmp_path / "gl.json").write_text(json.dumps(half))
    run_index = _write_runs(tmp_path, manifest, [{
        "tool": "wt-only", "version": "1", "parser": "gitleaks", "mode": "default",
        "capabilities": ["working-tree"], "path": "gl.json",
    }])
    card = score(manifest, run_index, tmp_path)
    m = card.runs[0].overall
    assert m.tp + m.fn + m.na == total == m.planted
    assert card.runs[0].planted_total == total


def test_coverage_analysis_union_unique_and_minimal_cover(tmp_path, manifest):
    ids = [p.id for p in manifest.planted]
    by_id = {p.id: p for p in manifest.planted}

    def report(catch_ids):
        return json.dumps([
            {"RuleID": by_id[i].secret_type, "File": by_id[i].file, "StartLine": by_id[i].line,
             "Secret": by_id[i].value, "Commit": ""}
            for i in catch_ids
        ])

    # tool A catches the first 20, tool B the middle 20 (overlap 10), C only id[40]
    (tmp_path / "a.json").write_text(report(ids[:20]))
    (tmp_path / "b.json").write_text(report(ids[10:30]))
    (tmp_path / "c.json").write_text(report([ids[40]]))
    run_index = _write_runs(tmp_path, manifest, [
        {"tool": "A", "version": "1", "parser": "gitleaks", "mode": "default",
         "capabilities": ["working-tree", "history"], "path": "a.json"},
        {"tool": "B", "version": "1", "parser": "gitleaks", "mode": "default",
         "capabilities": ["working-tree", "history"], "path": "b.json"},
        {"tool": "C", "version": "1", "parser": "gitleaks", "mode": "default",
         "capabilities": ["working-tree", "history"], "path": "c.json"},
    ])
    cov = score(manifest, run_index, tmp_path).coverage
    assert cov is not None
    assert cov.union_caught == 31  # 30 from A∪B + id[40] from C
    assert cov.per_tool_unique["C"] == [ids[40]]
    assert set(cov.minimal_cover) >= {"C"}  # C is the only source of id[40]
    assert cov.per_tool_caught == {"A": 20, "B": 20, "C": 1}


def test_indicator_finding_is_neither_a_hit_nor_a_false_positive(tmp_path, manifest):
    """Reporting an AWS access key id scores on neither axis.

    A tool that flags `AKIA…` has surfaced a useful investigative signal and
    nothing confidential. Crediting it as recall would reward finding a value
    that is not a secret; charging it as a false positive would punish a
    legitimate one. It is counted separately and scored nowhere.
    """
    assert manifest.indicators, "corpus must plant at least one indicator"
    findings = [
        {"RuleID": "aws-access-key-id", "File": i.file, "StartLine": i.line,
         "Secret": i.value, "Commit": ""}
        for i in manifest.indicators
    ]
    (tmp_path / "ind.json").write_text(json.dumps(findings))
    run_index = _write_runs(tmp_path, manifest, [{
        "tool": "id-only", "version": "1", "parser": "gitleaks", "mode": "default",
        "capabilities": ["working-tree", "history", "verification"], "path": "ind.json",
    }])
    run = score(manifest, run_index, tmp_path).runs[0]
    assert run.overall.tp == 0
    assert run.overall.fp == 0
    assert run.indicators_reported == sorted(i.id for i in manifest.indicators)
    assert run.overall.planted == manifest.stats.planted_total


def test_access_key_id_hit_is_not_credited_to_the_adjacent_secret_key(tmp_path, manifest):
    """The pair sits on adjacent lines, so proximity matching is the trap.

    Before the ground-truth correction, a finding on the id line could be
    claimed by the secret access key beside it — inflating recall for tools
    that never detected the confidential half at all.
    """
    indicator = manifest.indicators[0]
    partner = next(p for p in manifest.planted if p.id == indicator.id[:-len("-id")])
    assert abs(partner.line - indicator.line) <= 3, "the pair must be adjacent for this to test anything"

    findings = [{"RuleID": "aws-access-key-id", "File": indicator.file,
                 "StartLine": indicator.line, "Secret": indicator.value, "Commit": ""}]
    (tmp_path / "adj.json").write_text(json.dumps(findings))
    run_index = _write_runs(tmp_path, manifest, [{
        "tool": "id-only", "version": "1", "parser": "gitleaks", "mode": "default",
        "capabilities": ["working-tree", "history", "verification"], "path": "adj.json",
    }])
    run = score(manifest, run_index, tmp_path).runs[0]
    assert partner.id in run.missed_planted_ids
    assert run.indicators_reported == [indicator.id]
