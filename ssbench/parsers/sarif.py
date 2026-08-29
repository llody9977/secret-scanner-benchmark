"""Parser for SARIF 2.1.0 output.

Used for GitHub secret scanning exports and for any tool run with a SARIF
formatter (Gitleaks, TruffleHog, Kingfisher, Titus). SARIF carries a location
but rarely the raw secret, so matching leans on file + line. A partial
fingerprint, when present, is preserved as ``raw_secret`` for a best-effort
hash match.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from ssbench.models import Finding
from ssbench.parsers._util import load_json, normalise_path


def _first_location(result: dict) -> tuple:
    locations = result.get("locations") or []
    if not locations:
        return "", None
    phys = locations[0].get("physicalLocation", {})
    uri = phys.get("artifactLocation", {}).get("uri", "")
    region = phys.get("region", {}) or {}
    line = region.get("startLine")
    return normalise_path(str(uri)), int(line) if isinstance(line, int) else None


def _raw_secret(result: dict) -> Optional[str]:
    region = (result.get("locations") or [{}])[0].get("physicalLocation", {}).get("region", {})
    snippet = region.get("snippet", {})
    if isinstance(snippet, dict) and snippet.get("text"):
        return str(snippet["text"])
    return None


def parse(path: Path, tool: str) -> List[Finding]:
    data = load_json(path)
    findings: List[Finding] = []
    for run in data.get("runs", []) if isinstance(data, dict) else []:
        rules = {
            r.get("id"): r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
            if isinstance(r, dict)
        }
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            file_path, line = _first_location(result)
            rule_id = result.get("ruleId") or ""
            partial = result.get("partialFingerprints", {}) or {}
            commit = partial.get("commitSha") or None
            findings.append(Finding(
                tool=tool,
                rule=str(rules.get(rule_id, {}).get("name", rule_id)),
                file=file_path,
                line=line,
                commit=str(commit) if commit else None,
                raw_secret=_raw_secret(result),
                verified=None,
            ))
    return findings
