"""Parser for Gitleaks native JSON output (``gitleaks ... -f json``)."""

from __future__ import annotations

from pathlib import Path
from typing import List

from ssbench.models import Finding
from ssbench.parsers._util import load_json, normalise_path


def parse(path: Path, tool: str) -> List[Finding]:
    data = load_json(path)
    if not isinstance(data, list):
        return []
    findings: List[Finding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        line = item.get("StartLine")
        findings.append(Finding(
            tool=tool,
            rule=str(item.get("RuleID", "")),
            file=normalise_path(str(item.get("File", ""))),
            line=int(line) if isinstance(line, int) else None,
            commit=str(item.get("Commit", "")) or None,
            raw_secret=item.get("Secret") or None,
            verified=None,
        ))
    return findings
