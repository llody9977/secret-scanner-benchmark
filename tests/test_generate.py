"""Corpus generation: determinism, manifest integrity, git visibility."""

import subprocess

import pytest

from ssbench.generate import generate
from ssbench.score import verify_manifest_values


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    out = tmp_path_factory.mktemp("corpus")
    manifest = generate(20260829, out / "bench")
    return out / "bench", manifest


def test_manifest_values_hash_consistently(corpus):
    _, manifest = corpus
    assert verify_manifest_values(manifest) == []


def test_generation_is_byte_deterministic(tmp_path):
    a = generate(999, tmp_path / "a")
    b = generate(999, tmp_path / "b")
    assert a.corpus_head_commit == b.corpus_head_commit
    assert [p.value for p in a.planted] == [p.value for p in b.planted]
    assert [d.value for d in a.decoys] == [d.value for d in b.decoys]


def test_different_seed_changes_the_corpus(tmp_path):
    a = generate(1, tmp_path / "a")
    b = generate(2, tmp_path / "b")
    assert a.corpus_head_commit != b.corpus_head_commit


def test_has_planted_and_decoys(corpus):
    _, manifest = corpus
    assert manifest.stats.planted_total >= 35
    assert manifest.stats.decoy_total >= 15
    assert manifest.stats.history_only >= 5
    assert "feature/payments" in manifest.branches


def test_unscored_values_are_not_planted_secrets(corpus):
    """Ground truth has three populations and they do not overlap.

    An AWS access key id is planted in the corpus and recorded in the manifest,
    but as unscored: it is not confidential on its own, so it cannot count
    toward recall. Regression guard for the run-5 ground-truth correction.
    """
    _, manifest = corpus
    assert manifest.stats.unscored_total == len(manifest.unscored) > 0
    assert {u.reason for u in manifest.unscored} == {"identifier", "malformed"}
    assert all(u.secret_type == "aws-access-key-id" for u in manifest.unscored if u.reason == "identifier")
    assert not any(p.checksum_valid is False for p in manifest.planted)
    assert not any(p.secret_type == "aws-access-key-id" for p in manifest.planted)
    assert manifest.stats.planted_total == len(manifest.planted)

    ids = [p.id for p in manifest.planted] + [d.id for d in manifest.decoys]
    ids += [i.id for i in manifest.unscored]
    assert len(ids) == len(set(ids)), "ground-truth ids must be unique across populations"


def test_every_access_key_id_is_paired_with_a_planted_secret_key(corpus):
    """The pair is still planted whole; only its scoring changed."""
    _, manifest = corpus
    secret_keys = [p for p in manifest.planted if p.secret_type == "aws-secret-access-key"]
    ids = [u for u in manifest.unscored if u.reason == "identifier"]
    assert len(secret_keys) == len(ids)
    for unscored_item in ids:
        assert unscored_item.id.endswith("-id")
        partner = unscored_item.id[:-len("-id")]
        assert any(p.id == partner for p in secret_keys)


def test_broken_checksum_tokens_are_unscored_not_planted(corpus):
    """A token that cannot authenticate is not a planted secret.

    Regression guard: scoring one as planted charges a false negative to any
    scanner that validates the checksum and correctly declines to report it.
    """
    _, manifest = corpus
    malformed = [u for u in manifest.unscored if u.reason == "malformed"]
    assert malformed, "the corpus must still plant broken-checksum tokens"
    assert all(u.secret_type.startswith("github-token-") for u in malformed)
    assert not any(p.checksum_valid is False for p in manifest.planted)


def test_history_only_secrets_are_absent_from_head(corpus):
    repo, manifest = corpus
    head_blob = subprocess.run(
        ["git", "-C", str(repo), "show", "HEAD:src/app/legacy_settings.py"],
        capture_output=True, text=True, check=True,
    ).stdout
    for p in manifest.planted:
        if p.placement == "history-depth":
            assert p.value not in head_blob
            assert p.present_at_head is False


def test_history_only_secrets_are_reachable_in_history(corpus):
    repo, manifest = corpus
    depth_secret = next(p for p in manifest.planted if p.placement == "history-depth")
    log = subprocess.run(
        ["git", "-C", str(repo), "log", "--all", "-p", "-S", depth_secret.value],
        capture_output=True, text=True, check=True,
    ).stdout
    assert depth_secret.value in log


def test_branch_secret_only_on_feature_branch(corpus):
    repo, manifest = corpus
    branch_secret = next(p for p in manifest.planted if p.placement == "non-default-branch")
    on_main = subprocess.run(
        ["git", "-C", str(repo), "grep", "-l", branch_secret.value, "main"],
        capture_output=True, text=True,
    )
    on_branch = subprocess.run(
        ["git", "-C", str(repo), "grep", "-l", branch_secret.value, "feature/payments"],
        capture_output=True, text=True,
    )
    assert on_main.returncode != 0
    assert on_branch.returncode == 0


def test_recorded_line_numbers_point_at_the_secret(corpus):
    repo, manifest = corpus
    for p in manifest.planted:
        if not p.present_at_head or p.branch != "main":
            continue
        if p.placement == "base64-blob":
            continue  # the value is base64-wrapped by design; not literally on the line
        text = (repo / p.file).read_text().splitlines()
        window = "\n".join(text[max(0, p.line - 2): p.line + 2])
        needle = p.value.splitlines()[0][:24]
        assert needle in window, f"{p.id}: {needle!r} not near line {p.line} of {p.file}"
