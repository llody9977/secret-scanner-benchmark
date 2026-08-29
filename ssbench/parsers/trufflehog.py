"""Parser for TruffleHog JSON-lines output (``trufflehog ... --json``)."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from ssbench.models import Finding
from ssbench.parsers._util import iter_json_lines, normalise_path


def _git_meta(obj: dict) -> dict:
    data = obj.get("SourceMetadata", {})
    if isinstance(data, dict):
        inner = data.get("Data", {})
        if isinstance(inner, dict):
            git = inner.get("Git") or inner.get("Filesystem") or {}
            if isinstance(git, dict):
                return git
    return {}


def parse(path: Path, tool: str) -> List[Finding]:
    findings: List[Finding] = []
    for obj in iter_json_lines(path):
        if "DetectorName" not in obj and "Raw" not in obj:
            continue
        meta = _git_meta(obj)
        line = meta.get("line")
        verified: Optional[bool] = obj.get("Verified")
        findings.append(Finding(
            tool=tool,
            rule=str(obj.get("DetectorName", "")),
            file=normalise_path(str(meta.get("file", ""))),
            line=int(line) if isinstance(line, int) else None,
            commit=str(meta.get("commit", "")) or None,
            raw_secret=obj.get("Raw") or obj.get("RawV2") or None,
            verified=bool(verified) if verified is not None else None,
        ))
    return findings
