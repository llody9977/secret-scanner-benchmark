"""Assemble the corpus into a git repository with deterministic history.

Every commit uses a pinned identity and a pinned timestamp derived from
:data:`ssbench.constants.CORPUS_EPOCH`, so two runs of the generator from the
same seed produce byte-identical git object hashes. That property is what lets
the manifest pin ``corpus_head_commit`` and lets a reviewer verify the corpus
was not hand-edited.

History layout (on ``main``):

    c0  skeleton
    c1  add temporary credentials        <- planted, reverted set
    c2  remove temporary credentials     <- revert
    c3  initial service config           <- planted, history-depth set
    c4  application config
    c5  infra + fixtures
    c6  notebook, docker, logs, bundle
    c7  scrub legacy settings            <- history-depth secret replaced; HEAD

    feature/payments branches from c5, adds one commit, stays unmerged.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ssbench.constants import (
    COMMIT_STRIDE_SECONDS,
    CORPUS_EPOCH,
    CORPUS_TZ,
    GIT_AUTHOR_EMAIL,
    GIT_AUTHOR_NAME,
)


@dataclass
class Commit:
    message: str
    writes: Dict[str, str] = field(default_factory=dict)
    deletes: List[str] = field(default_factory=list)
    branch: str = "main"
    from_ref: Optional[str] = None  # branch point for a new branch


@dataclass
class BuildResult:
    head_commit: str
    branch_commits: Dict[str, str]
    # label -> commit sha, for back-filling the manifest
    introduced_at: Dict[str, str]


def _base_env() -> dict:
    """A hermetic environment: the user's global/system git config is ignored."""
    env = dict(os.environ)
    env.update({
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    })
    return env


def _run(args: List[str], cwd: Path, env: Optional[dict] = None) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        env=env or _base_env(),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _commit_env(index: int) -> dict:
    ts = CORPUS_EPOCH + index * COMMIT_STRIDE_SECONDS
    date = f"{ts} {CORPUS_TZ}"
    env = _base_env()
    env.update({
        "GIT_AUTHOR_NAME": GIT_AUTHOR_NAME,
        "GIT_AUTHOR_EMAIL": GIT_AUTHOR_EMAIL,
        "GIT_COMMITTER_NAME": GIT_AUTHOR_NAME,
        "GIT_COMMITTER_EMAIL": GIT_AUTHOR_EMAIL,
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_DATE": date,
    })
    return env


def _apply(commit: Commit, root: Path) -> None:
    for rel, content in commit.writes.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    for rel in commit.deletes:
        path = root / rel
        if path.exists():
            path.unlink()


def build_repo(root: Path, commits: List[Commit], labels_by_commit: Dict[int, List[str]]) -> BuildResult:
    """Create a git repo at ``root`` from an ordered list of commits."""
    root.mkdir(parents=True, exist_ok=True)
    _run(["init", "-q", "-b", "main"], cwd=root)
    _run(["config", "commit.gpgsign", "false"], cwd=root)
    _run(["config", "core.autocrlf", "false"], cwd=root)
    _run(["config", "user.name", GIT_AUTHOR_NAME], cwd=root)
    _run(["config", "user.email", GIT_AUTHOR_EMAIL], cwd=root)

    branch_commits: Dict[str, str] = {}
    introduced_at: Dict[str, str] = {}
    current_branch = "main"

    for index, commit in enumerate(commits):
        if commit.branch != current_branch:
            if commit.from_ref is not None:
                _run(["checkout", "-q", "-b", commit.branch, commit.from_ref], cwd=root)
            else:
                _run(["checkout", "-q", commit.branch], cwd=root)
            current_branch = commit.branch

        _apply(commit, root)
        _run(["add", "-A"], cwd=root)
        _run(["commit", "-q", "--allow-empty", "-m", commit.message], cwd=root, env=_commit_env(index))
        sha = _run(["rev-parse", "HEAD"], cwd=root)

        for label in labels_by_commit.get(index, []):
            introduced_at[label] = sha
        if commit.branch != "main":
            branch_commits[commit.branch] = sha

    _run(["checkout", "-q", "main"], cwd=root)
    head = _run(["rev-parse", "HEAD"], cwd=root)
    return BuildResult(head_commit=head, branch_commits=branch_commits, introduced_at=introduced_at)
