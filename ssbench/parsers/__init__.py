"""Parsers that normalise scanner output into :class:`ssbench.models.Finding`.

Add a parser by writing ``parse(path, tool) -> list[Finding]`` in a module here
and registering it in :data:`PARSERS`. ``results/index.yaml`` names the parser
per run, so a tool that can emit SARIF and native JSON can be scored both ways.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Dict, List

from ssbench.models import Finding
from ssbench.parsers import detect_secrets, gitleaks, sarif, trufflehog

PARSERS: Dict[str, Callable[[Path, str], List[Finding]]] = {
    "sarif": sarif.parse,
    "gitleaks": gitleaks.parse,
    "trufflehog": trufflehog.parse,
    "detect-secrets": detect_secrets.parse,
}


def parse(parser: str, path: Path, tool: str) -> List[Finding]:
    if parser not in PARSERS:
        raise ValueError(f"unknown parser '{parser}'; known: {sorted(PARSERS)}")
    return PARSERS[parser](Path(path), tool)
