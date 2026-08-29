"""Parser for detect-secrets baseline JSON (``detect-secrets scan``).

detect-secrets never emits the raw secret — only ``hashed_secret``, a SHA-1 of
the value. Matching therefore falls back to file + line, and the scorer is told
this tool has no ``verification`` capability and (by default) no ``history``
capability, so history-only placements are scored N/A rather than as misses.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from ssbench.models import Finding
from ssbench.parsers._util import load_json, normalise_path


def parse(path: Path, tool: str) -> List[Finding]:
    data = load_json(path)
    results = data.get("results", {}) if isinstance(data, dict) else {}
    findings: List[Finding] = []
    for file_path, entries in results.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            line = entry.get("line_number")
            findings.append(Finding(
                tool=tool,
                rule=str(entry.get("type", "")),
                file=normalise_path(str(file_path)),
                line=int(line) if isinstance(line, int) else None,
                commit=None,
                raw_secret=None,
                verified=entry.get("is_verified") if isinstance(entry.get("is_verified"), bool) else None,
            ))
    return findings
