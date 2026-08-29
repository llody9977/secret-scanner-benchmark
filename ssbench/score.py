"""Score scanner output against the corpus manifest.

For each run we compute TP / FP / FN / N/A and precision / recall / F1, broken
out overall, per secret type and per placement. Across the default-mode runs we
also compute the two numbers the analysis actually turns on: how many planted
secrets were caught by exactly one tool, and how many were caught by none.

Matching rules, in priority order:

1. exact value hash (the strong signal — most tools quote the matched string);
2. the planted value is a substring of the finding's string, or vice versa
   (connection strings, JSON blobs);
3. same file and a line within ``LINE_TOLERANCE`` (detect-secrets, SARIF).

A finding that matches nothing planted is a false positive. A finding that
matches a decoy is a false positive and is also named in ``decoys_triggered``.
A planted secret whose placement needs a capability the run lacks is N/A, never
a miss.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ssbench.models import (
    Decoy,
    Finding,
    Manifest,
    Metrics,
    PlantedSecret,
    RunIndex,
    RunScore,
    ScoreCard,
    ToolRun,
    sha256_hex,
)
from ssbench.parsers import parse

LINE_TOLERANCE = 3


def _norm(path: str) -> str:
    p = path.replace("\\", "/").strip()
    while p.startswith(("./", "../")):
        p = p.split("/", 1)[1] if "/" in p else ""
    return p.lstrip("/")


def _paths_align(a: str, b: str) -> bool:
    a, b = _norm(a), _norm(b)
    return bool(a) and bool(b) and (a == b or a.endswith("/" + b) or b.endswith("/" + a))


class _Index:
    """Lookup structures over the manifest for one scoring pass."""

    def __init__(self, manifest: Manifest) -> None:
        self.planted = manifest.planted
        self.decoys = manifest.decoys
        self.by_hash: Dict[str, List[PlantedSecret]] = defaultdict(list)
        self.by_file: Dict[str, List[PlantedSecret]] = defaultdict(list)
        for p in self.planted:
            self.by_hash[p.value_sha256].append(p)
            self.by_file[_norm(p.file)].append(p)
        self.decoy_hashes = {d.value_sha256: d for d in self.decoys}
        self.decoy_by_file: Dict[str, List[Decoy]] = defaultdict(list)
        for d in self.decoys:
            self.decoy_by_file[_norm(d.file)].append(d)

    def _location_aligns(self, finding: Finding, planted: PlantedSecret) -> bool:
        if not _paths_align(finding.file, planted.file):
            return False
        if finding.line is None:
            return True
        return abs(planted.line - finding.line) <= LINE_TOLERANCE

    def candidates(self, finding: Finding):
        """Score every planted secret against a finding.

        Returns ``(planted, score)`` pairs, higher score = stronger match:
        4 hash + location, 3 hash, 2 substring + location, 1 location only.
        Duplicate-valued planted secrets are separated by the location term.
        """
        hashes = set(finding.secret_hashes())
        raw = (finding.raw_secret or "").strip("'\"` \t\r\n")
        out = []
        for p in self.planted:
            aligned = self._location_aligns(finding, p)
            if p.value_sha256 in hashes:
                out.append((p, 4 if aligned else 3))
            elif raw and len(raw) >= 8 and (raw in p.value or p.value in raw):
                out.append((p, 2 if aligned else 1))
            elif aligned and finding.line is not None:
                out.append((p, 1))
        return out

    def match_planted(self, finding: Finding, claimed: Optional[set] = None) -> Optional[PlantedSecret]:
        claimed = claimed or set()
        ranked = sorted(self.candidates(finding), key=lambda pair: -pair[1])
        for planted, _ in ranked:
            if planted.id not in claimed:
                return planted
        return ranked[0][0] if ranked else None

    def match_decoy(self, finding: Finding) -> Optional[Decoy]:
        for h in finding.secret_hashes():
            if h in self.decoy_hashes:
                return self.decoy_hashes[h]
        raw = (finding.raw_secret or "").strip("'\"` \t\r\n")
        if raw and len(raw) >= 8:
            for d in self.decoys:
                if raw in d.value or d.value in raw:
                    return d
        if finding.line is not None:
            for norm_file, dlist in self.decoy_by_file.items():
                if not _paths_align(finding.file, norm_file):
                    continue
                for d in dlist:
                    if abs(d.line - finding.line) <= LINE_TOLERANCE:
                        return d
        return None


def _metrics_bucket() -> Dict[str, Metrics]:
    return defaultdict(Metrics)


def _assign(findings: List[Finding], index: _Index):
    """Greedily assign each finding to at most one planted secret.

    Findings that carry a line number are assigned first, so a precise hit
    claims a duplicate-valued planted secret before a location-less one does.
    """
    hits: Dict[str, PlantedSecret] = {}
    decoys_triggered: List[str] = []
    false_positives: List[Finding] = []
    claimed: set = set()

    ordered = sorted(findings, key=lambda f: (f.line is None, f.file or ""))
    for finding in ordered:
        planted = index.match_planted(finding, claimed)
        if planted is not None and planted.id not in claimed:
            claimed.add(planted.id)
            hits[planted.id] = planted
            continue
        if planted is not None:
            # a duplicate report of an already-claimed secret: ignore, not an FP
            continue
        decoy = index.match_decoy(finding)
        if decoy is not None:
            decoys_triggered.append(decoy.id)
        false_positives.append(finding)
    return hits, decoys_triggered, false_positives


def score_run(manifest: Manifest, run: ToolRun, findings: List[Finding], index: _Index) -> RunScore:
    caps = set(run.capabilities)
    hits, decoys_triggered, false_positives = _assign(findings, index)

    overall = Metrics()
    by_type = _metrics_bucket()
    by_placement = _metrics_bucket()
    missed: List[str] = []

    for p in manifest.planted:
        required = manifest.placement_requires.get(p.placement, "working-tree")
        bucket_t, bucket_p = by_type[p.secret_type], by_placement[p.placement]
        if required not in caps:
            overall.na += 1
            bucket_t.na += 1
            bucket_p.na += 1
            continue
        if p.id in hits:
            overall.tp += 1
            bucket_t.tp += 1
            bucket_p.tp += 1
        else:
            overall.fn += 1
            bucket_t.fn += 1
            bucket_p.fn += 1
            missed.append(p.id)

    fp_count = len(false_positives)
    overall.fp = fp_count
    # Attribute FPs to a placement/type bucket only when they hit a decoy of
    # known origin; spurious FPs land in an "unassigned" bucket.
    for finding in false_positives:
        decoy = index.match_decoy(finding)
        key = f"decoy:{decoy.decoy_type}" if decoy else "spurious"
        by_type[key].fp += 1
        by_placement["decoy-file" if decoy else "spurious"].fp += 1

    return RunScore(
        tool=run.tool,
        version=run.version,
        mode=run.mode,
        overall=overall,
        by_secret_type={k: v for k, v in sorted(by_type.items())},
        by_placement={k: v for k, v in sorted(by_placement.items())},
        false_positives=false_positives,
        missed_planted_ids=missed,
        decoys_triggered=sorted(set(decoys_triggered)),
    )


def _cross_tool(
    manifest: Manifest, scored: List[Tuple[ToolRun, RunScore, List[Finding]]], index: _Index
) -> Tuple[List[str], Dict[str, str]]:
    catchers: Dict[str, List[str]] = defaultdict(list)
    capable: Dict[str, bool] = defaultdict(bool)

    for run, _, findings in scored:
        if not run.counts_toward_coverage:
            continue
        caps = set(run.capabilities)
        run_hits = set(_assign(findings, index)[0])
        for p in manifest.planted:
            required = manifest.placement_requires.get(p.placement, "working-tree")
            if required in caps:
                capable[p.id] = True
                if p.id in run_hits:
                    catchers[p.id].append(run.tool)

    caught_by_none = sorted(
        p.id for p in manifest.planted if capable[p.id] and not catchers[p.id]
    )
    caught_by_one = {
        pid: sorted(set(tools))[0]
        for pid, tools in catchers.items()
        if len(set(tools)) == 1
    }
    return caught_by_none, dict(sorted(caught_by_one.items()))


# A finding pointing at one of these is scanner noise on a benchmark artifact,
# not a result about the repository under test — the manifest holds every
# planted value in plaintext, the seed is the corpus key. This is a fallback:
# the scan target should not contain them in the first place (the CI workflow
# deletes bench/manifest.yaml before scanning). A tool that de-duplicates by
# value can still mis-attribute a real detection to the manifest, so relying on
# this filter under-counts — remove the files, don't lean on the filter.
_ARTIFACT_BASENAMES = {"manifest.yaml", "seed"}


def _drop_artifact_findings(findings: List[Finding]) -> Tuple[List[Finding], int]:
    kept = [f for f in findings if _norm(f.file).rsplit("/", 1)[-1] not in _ARTIFACT_BASENAMES]
    return kept, len(findings) - len(kept)


def score(manifest: Manifest, run_index: RunIndex, results_dir: Path) -> ScoreCard:
    results_dir = Path(results_dir)
    index = _Index(manifest)
    scored: List[Tuple[ToolRun, RunScore, List[Finding]]] = []

    for run in run_index.runs:
        findings = parse(run.parser, results_dir / run.path, run.tool)
        findings, dropped = _drop_artifact_findings(findings)
        if dropped:
            print(f"[score] {run.tool}/{run.mode}: ignored {dropped} finding(s) on "
                  f"manifest.yaml / seed. Exclude these from the scan target — a tool "
                  f"that de-duplicates by value may have attributed real detections to "
                  f"them, so this run's recall is a lower bound.")
        run_score = score_run(manifest, run, findings, index)
        scored.append((run, run_score, findings))

    caught_by_none, caught_by_one = _cross_tool(manifest, scored, index)

    return ScoreCard(
        seed=manifest.seed,
        corpus_head_commit=manifest.corpus_head_commit,
        generator_version=manifest.generator_version,
        runs=[rs for _, rs, _ in scored],
        caught_by_no_tool=caught_by_none,
        caught_by_one_tool=caught_by_one,
        planted_total=manifest.stats.planted_total,
        decoy_total=manifest.stats.decoy_total,
    )


def load_manifest(path: Path) -> Manifest:
    import yaml

    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return Manifest.model_validate(data)


def verify_manifest_values(manifest: Manifest) -> List[str]:
    """Return ids whose recorded sha256 does not match the recorded value.

    Entries in the committed reference manifest have their value redacted; those
    are skipped here (the strong integrity check for that file is
    ``ssbench verify --seed``, which regenerates and compares the HEAD commit).
    """
    bad = []
    for item in (*manifest.planted, *manifest.decoys):
        if item.value.startswith("<redacted"):
            continue
        if sha256_hex(item.value) != item.value_sha256:
            bad.append(item.id)
    return bad
