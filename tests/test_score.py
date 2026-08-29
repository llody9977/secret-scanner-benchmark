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
