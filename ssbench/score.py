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

Ground truth has three populations, not two. Alongside planted secrets and
decoys there are **indicators**: credential identifiers that are not themselves
confidential (an AWS access key id is the only case at present). A finding that
resolves to an indicator is scored on neither axis — not a true positive,
because nothing secret was found; not a false positive, because the value is a
legitimate signal. It is tallied in ``indicators_reported`` and nowhere else.
Indicators are matched before planted secrets so that a hit on an access key id
cannot be credited, by line proximity, to the secret access key beside it.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ssbench.models import (
    Decoy,
    Finding,
    Indicator,
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
        self.indicators = manifest.indicators
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

    def _match_strength(self, finding: Finding, item, hashes: set, raw: str) -> int:
        """0 = no match; 4 hash + location, 3 hash, 2 substring + location,
        1 substring or location alone."""
        aligned = self._location_aligns(finding, item)
        if item.value_sha256 in hashes:
            return 4 if aligned else 3
        if raw and len(raw) >= 8 and (raw in item.value or item.value in raw):
            return 2 if aligned else 1
        if aligned and finding.line is not None:
            return 1
        return 0

    def candidates(self, finding: Finding):
        """Rank every ground-truth item against a finding.

        Returns ``(item, kind, strength, line_distance)`` tuples over both
        planted secrets and indicators. Strength dominates; line distance breaks
        ties, which is what keeps a finding on an AWS access key id from being
        credited to the secret access key on the adjacent line.
        """
        hashes = set(finding.secret_hashes())
        raw = (finding.raw_secret or "").strip("'\"` \t\r\n")
        out = []
        for kind, items in (("planted", self.planted), ("indicator", self.indicators)):
            for item in items:
                strength = self._match_strength(finding, item, hashes, raw)
                if strength:
                    distance = abs(item.line - finding.line) if finding.line is not None else 0
                    out.append((item, kind, strength, distance))
        return sorted(out, key=lambda c: (-c[2], c[3]))

    def match_indicator(self, finding: Finding) -> Optional[Indicator]:
        """The finding's best interpretation, if that interpretation is an indicator."""
        ranked = self.candidates(finding)
        if ranked and ranked[0][1] == "indicator":
            return ranked[0][0]
        return None

    def match_planted(self, finding: Finding, claimed: Optional[set] = None) -> Optional[PlantedSecret]:
        claimed = claimed or set()
        ranked = [c for c in self.candidates(finding) if c[1] == "planted"]
        for planted, _, _, _ in ranked:
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
    indicators_reported: List[str] = []
    false_positives: List[Finding] = []
    claimed: set = set()

    ordered = sorted(findings, key=lambda f: (f.line is None, f.file or ""))
    for finding in ordered:
        indicator = index.match_indicator(finding)
        if indicator is not None:
            # A credential identifier, not a credential. Scored on neither axis.
            indicators_reported.append(indicator.id)
            continue
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
    return hits, decoys_triggered, false_positives, sorted(set(indicators_reported))


def score_run(manifest: Manifest, run: ToolRun, findings: List[Finding], index: _Index) -> RunScore:
    caps = set(run.capabilities)
    hits, decoys_triggered, false_positives, indicators_reported = _assign(findings, index)

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

    planted_total = manifest.stats.planted_total
    if overall.planted != planted_total:
        raise AssertionError(
            f"{run.tool}/{run.mode}: TP+FN+N/A = {overall.planted}, expected "
            f"{planted_total} (every planted secret must be exactly one of hit, miss, N/A)"
        )

    return RunScore(
        tool=run.tool,
        version=run.version,
        mode=run.mode,
        overall=overall,
        planted_total=planted_total,
        decoy_total=manifest.stats.decoy_total,
        by_secret_type={k: v for k, v in sorted(by_type.items())},
        by_placement={k: v for k, v in sorted(by_placement.items())},
        false_positives=false_positives,
        missed_planted_ids=missed,
        decoys_triggered=sorted(set(decoys_triggered)),
        indicators_reported=indicators_reported,
    )


def _cross_tool(
    manifest: Manifest, scored: List[Tuple[ToolRun, RunScore, List[Finding]]], index: _Index
) -> Tuple[List[str], Dict[str, str], "CoverageAnalysis"]:
    from ssbench.models import CoverageAnalysis

    catchers: Dict[str, List[str]] = defaultdict(list)
    capable: Dict[str, bool] = defaultdict(bool)
    caught_by: Dict[str, set] = {}  # tool -> set of planted ids it caught

    for run, _, findings in scored:
        if not run.counts_toward_coverage:
            continue
        caps = set(run.capabilities)
        run_hits = set(_assign(findings, index)[0])
        tool_set = caught_by.setdefault(run.tool, set())
        for p in manifest.planted:
            required = manifest.placement_requires.get(p.placement, "working-tree")
            if required in caps:
                capable[p.id] = True
                if p.id in run_hits:
                    catchers[p.id].append(run.tool)
                    tool_set.add(p.id)

    all_ids = [p.id for p in manifest.planted]
    caught_by_none = sorted(i for i in all_ids if capable[i] and not catchers[i])
    caught_by_one = {
        pid: sorted(set(tools))[0]
        for pid, tools in catchers.items()
        if len(set(tools)) == 1
    }

    union = set().union(*caught_by.values()) if caught_by else set()
    tools = sorted(caught_by)
    unique = {
        t: sorted(i for i in caught_by[t] if catchers[i] == [t] or set(catchers[i]) == {t})
        for t in tools
    }
    dominates = {
        a: sorted(b for b in tools if b != a and caught_by[b] and caught_by[b] < caught_by[a])
        for a in tools
    }
    dominates = {a: v for a, v in dominates.items() if v}

    # greedy set cover over `union`
    remaining, cover = set(union), []
    pool = dict(caught_by)
    while remaining:
        best = max(pool, key=lambda t: len(pool[t] & remaining))
        if not (pool[best] & remaining):
            break
        cover.append(best)
        remaining -= pool[best]
        del pool[best]

    best_pair = None
    if len(tools) >= 2:
        pairs = [
            (a, b, len(caught_by[a] | caught_by[b]))
            for i, a in enumerate(tools) for b in tools[i + 1:]
        ]
        a, b, n = max(pairs, key=lambda x: x[2])
        best_pair = [a, b, n]

    coverage = CoverageAnalysis(
        tools=tools,
        planted_total=manifest.stats.planted_total,
        union_caught=len(union),
        union_missed=caught_by_none,
        per_tool_caught={t: len(caught_by[t]) for t in tools},
        per_tool_unique=unique,
        dominates=dominates,
        best_pair=best_pair,
        minimal_cover=cover,
    )
    return caught_by_none, dict(sorted(caught_by_one.items())), coverage


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

    caught_by_none, caught_by_one, coverage = _cross_tool(manifest, scored, index)

    return ScoreCard(
        seed=manifest.seed,
        corpus_head_commit=manifest.corpus_head_commit,
        generator_version=manifest.generator_version,
        runs=[rs for _, rs, _ in scored],
        caught_by_no_tool=caught_by_none,
        caught_by_one_tool=caught_by_one,
        coverage=coverage,
        planted_total=manifest.stats.planted_total,
        decoy_total=manifest.stats.decoy_total,
        indicator_total=manifest.stats.indicator_total,
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
    for item in (*manifest.planted, *manifest.decoys, *manifest.indicators):
        if item.value.startswith("<redacted"):
            continue
        if sha256_hex(item.value) != item.value_sha256:
            bad.append(item.id)
    return bad
