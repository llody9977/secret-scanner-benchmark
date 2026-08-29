"""Typed data model for the corpus manifest and the scoring output."""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, computed_field

SCHEMA_VERSION = "1.0"


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Corpus manifest
# --------------------------------------------------------------------------- #
class PlantedSecret(BaseModel):
    """One credential planted into the corpus, with its ground truth."""

    id: str
    secret_type: str
    category: str = Field(description="structured | generic | private-key")
    value: str = Field(description="the exact sensitive substring planted in the file")
    value_sha256: str
    checksum_valid: Optional[bool] = Field(
        default=None,
        description="for formats with an internal checksum: whether it is correct. "
        "A deliberately broken checksum tests whether a tool validates it.",
    )
    branch: str
    file: str
    line: int
    placement: str
    obfuscation: str
    introduced_commit: Optional[str] = None
    present_at_head: bool = True
    expected_detectable: bool = Field(
        default=True,
        description="False marks a case that is a known structural miss for the "
        "whole category (e.g. a low-entropy password) — informational only.",
    )
    notes: str = ""


class Decoy(BaseModel):
    """A benign string that a well-behaved scanner must NOT report."""

    id: str
    decoy_type: str
    value: str
    value_sha256: str
    branch: str
    file: str
    line: int
    placement: str
    reason: str


class ManifestStats(BaseModel):
    planted_total: int
    decoy_total: int
    by_category: Dict[str, int]
    by_secret_type: Dict[str, int]
    by_placement: Dict[str, int]
    present_at_head: int
    history_only: int


class Manifest(BaseModel):
    schema_version: str = SCHEMA_VERSION
    seed: int
    generator_version: str
    created: str
    corpus_head_commit: Optional[str] = None
    branches: List[str] = Field(default_factory=list)
    placement_requires: Dict[str, str] = Field(default_factory=dict)
    stats: ManifestStats
    planted: List[PlantedSecret]
    decoys: List[Decoy]


# --------------------------------------------------------------------------- #
# Scanner output + scoring
# --------------------------------------------------------------------------- #
class Finding(BaseModel):
    """A single result parsed from a scanner's report, normalised."""

    tool: str
    rule: str = ""
    file: str
    line: Optional[int] = None
    commit: Optional[str] = None
    raw_secret: Optional[str] = None
    verified: Optional[bool] = None

    def secret_hashes(self) -> List[str]:
        """Candidate sha256 values for matching against planted secrets.

        Tools quote, trim or wrap the matched string differently, so a few
        light normalisations are tried.
        """
        if not self.raw_secret:
            return []
        raw = self.raw_secret
        candidates = {raw, raw.strip(), raw.strip("'\"` \t\r\n")}
        return sorted(sha256_hex(c) for c in candidates if c)


class ToolRun(BaseModel):
    """One invocation of one tool, described by ``results/index.yaml``."""

    tool: str
    version: str = "unknown"
    parser: str
    mode: str = "default"
    capabilities: List[str] = Field(default_factory=list)
    path: str
    counts_toward_coverage: bool = Field(
        default=True,
        description="Set False for a secondary mode (e.g. verified-only) so it is "
        "reported but excluded from the cross-tool 'caught by none' tally.",
    )


class RunIndex(BaseModel):
    runs: List[ToolRun]


class Metrics(BaseModel):
    tp: int = 0
    fp: int = 0
    fn: int = 0
    na: int = 0

    @computed_field
    @property
    def precision(self) -> Optional[float]:
        denom = self.tp + self.fp
        return None if denom == 0 else round(self.tp / denom, 4)

    @computed_field
    @property
    def recall(self) -> Optional[float]:
        denom = self.tp + self.fn
        return None if denom == 0 else round(self.tp / denom, 4)

    @computed_field
    @property
    def f1(self) -> Optional[float]:
        p, r = self.precision, self.recall
        if not p or not r:
            return None
        return round(2 * p * r / (p + r), 4)


class RunScore(BaseModel):
    tool: str
    version: str
    mode: str
    overall: Metrics
    by_secret_type: Dict[str, Metrics]
    by_placement: Dict[str, Metrics]
    false_positives: List[Finding]
    missed_planted_ids: List[str]
    decoys_triggered: List[str]


class ScoreCard(BaseModel):
    schema_version: str = SCHEMA_VERSION
    seed: int
    corpus_head_commit: Optional[str]
    generator_version: str
    runs: List[RunScore]
    caught_by_no_tool: List[str]
    caught_by_one_tool: Dict[str, str]
    planted_total: int
    decoy_total: int
