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


def normalise_path(raw: str) -> str:
    """Strip common prefixes so a finding path lines up with a manifest path."""
    if not raw:
        return ""
    p = raw.replace("\\", "/").strip()
    for prefix in ("file://", "./"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    # drop a leading absolute checkout dir: keep the repo-relative tail
    parts = p.split("/")
    for anchor in ("src", "tests", "infra", "deploy", "notebooks", "public", "config", "artifacts"):
        if anchor in parts:
            return "/".join(parts[parts.index(anchor):])
    return p.lstrip("/")
