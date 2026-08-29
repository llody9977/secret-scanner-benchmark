"""Shared helpers for scanner-output parsers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def iter_json_lines(path: Path) -> Iterator[dict]:
    """Yield one object per non-empty line (JSON-lines / ND-JSON)."""
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


_ANCHORS = ("src", "tests", "infra", "deploy", "notebooks", "public", "config", "artifacts")


def normalise_path(raw: str) -> str:
    """Strip common prefixes so a finding path lines up with a manifest path.

    Handles ``file://`` URIs, Windows separators, absolute checkout dirs, and a
    ``.../bench/`` corpus-root prefix. Whatever slips through is still caught by
    the suffix match in the scorer's path comparison.
    """
    if not raw:
        return ""
    p = raw.replace("\\", "/").strip()
    for prefix in ("file://", "./"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    parts = [seg for seg in p.split("/") if seg not in ("", ".")]
    # 1. anchor on a known corpus top-level directory
    for anchor in _ANCHORS:
        if anchor in parts:
            return "/".join(parts[parts.index(anchor):])
    # 2. anchor on the generated corpus root, keeping the tail (e.g. Dockerfile)
    for root in ("bench", "corpus"):
        if root in parts and parts.index(root) < len(parts) - 1:
            return "/".join(parts[parts.index(root) + 1:])
    return "/".join(parts)
