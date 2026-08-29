"""Orchestrate corpus generation: plan -> files -> git history -> manifest."""

from __future__ import annotations

import shutil
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

from ssbench import GENERATOR_VERSION
from ssbench.constants import CORPUS_CREATED, PLACEMENT_REQUIRES
from ssbench.decoys import DecoySpec, build_decoys
from ssbench.formats.base import SecretSpec
from ssbench.gitbuild import Commit, build_repo
from ssbench.models import (
    Decoy,
    Indicator,
    Manifest,
    ManifestStats,
    PlantedSecret,
    sha256_hex,
)
from ssbench.placements import PLACEMENTS, Placement, RenderedFile, render_file
from ssbench.plan import build_plan
from ssbench.rng import SeededRNG
from ssbench.skeleton import SCRUBBED_HOTFIX, SCRUBBED_LEGACY, SKELETON

# Commit indices and their semantic role in the generated history.
C_SKELETON, C_REVERT_ADD, C_REVERT_DEL, C_DEPTH_ADD = 0, 1, 2, 3
C_GROUP_A, C_GROUP_B, C_GROUP_C, C_SCRUB = 4, 5, 6, 7

_HEAD_GROUP = {
    "working-tree": C_GROUP_A,
    "dotenv": C_GROUP_A,
    "terraform-vars": C_GROUP_B,
    "json-fixture": C_GROUP_B,
    "decoy-identifiers": C_GROUP_B,
    "decoy-samples": C_GROUP_B,
    "dockerfile-env": C_GROUP_C,
    "jupyter-output": C_GROUP_C,
    "ci-log-artifact": C_GROUP_C,
    "minified-bundle": C_GROUP_C,
    "base64-blob": C_GROUP_C,
}

_DECOY_PLACEMENTS = (
    Placement("decoy-identifiers", "src/app/identifiers.py", "python"),
    Placement("decoy-samples", "src/app/vendor_samples.py", "python"),
)

_SCRUBBED = {
    "src/app/legacy_settings.py": SCRUBBED_LEGACY,
    "src/app/hotfix.py": SCRUBBED_HOTFIX,
}


class _Stub:
    __slots__ = ("id", "spec", "placement", "obfuscation", "branch")

    def __init__(self, sid: str, spec: SecretSpec, placement: Placement, obf: str) -> None:
        self.id = sid
        self.spec = spec
        self.placement = placement
        self.obfuscation = obf
        self.branch = placement.branch


def _decoy_to_spec(decoy: DecoySpec) -> SecretSpec:
    return SecretSpec(
        secret_type=decoy.decoy_type,
        category="decoy",
        value=decoy.value,
        assignment_key=decoy.assignment_key,
        multiline="\n" in decoy.value,
    )


def _collect(rng: SeededRNG) -> Tuple[List[_Stub], Dict[str, DecoySpec]]:
    stubs: List[_Stub] = []
    for entry in build_plan():
        spec = entry.builder(rng.derive(entry.id), **entry.kwargs)
        placement = PLACEMENTS[entry.placement]
        parts = [spec] + ([spec.companion] if spec.companion is not None else [])
        # The plan entry names a credential; a credential may be written as more
        # than one value (an AWS pair). The confidential half keeps the plan id,
        # the identifier half gets an "-id" suffix, and the file keeps them in
        # the order the builder returned them — identifier first, as it would be
        # written in a real config.
        seen = {True: 0, False: 0}
        for part in parts:
            n = seen[part.is_secret]
            seen[part.is_secret] += 1
            if part.is_secret:
                sid = entry.id if n == 0 else f"{entry.id}-{n + 1}"
            else:
                sid = f"{entry.id}-id" if n == 0 else f"{entry.id}-id{n + 1}"
            stubs.append(_Stub(sid, part, placement, entry.obfuscation))

    decoys = {f"decoy-{i:02d}": d for i, d in enumerate(build_decoys(rng))}
    return stubs, decoys


def _render_targets(
    stubs: List[_Stub], decoys: Dict[str, DecoySpec]
) -> Dict[str, RenderedFile]:
    """Render every file. Returns path -> RenderedFile across all layers."""
    grouped: Dict[Tuple[str, str], List[Tuple[str, SecretSpec, str]]] = defaultdict(list)
    placement_of: Dict[str, Placement] = {}
    for stub in stubs:
        grouped[(stub.branch, stub.placement.key)].append((stub.id, stub.spec, stub.obfuscation))
        placement_of[stub.placement.key] = stub.placement

    rendered: Dict[str, RenderedFile] = {}
    for (_, pkey), insertions in grouped.items():
        rf = render_file(placement_of[pkey], insertions)
        rendered[rf.path] = rf

    decoy_ids = sorted(decoys)
    split = max(1, len(decoy_ids) // 2)
    for idx, placement in enumerate(_DECOY_PLACEMENTS):
        chunk = decoy_ids[:split] if idx == 0 else decoy_ids[split:]
        insertions = [(did, _decoy_to_spec(decoys[did]), "plain") for did in chunk]
        if insertions:
            rf = render_file(placement, insertions)
            rendered[rf.path] = rf
    return rendered


def _classify(stub: _Stub) -> str:
    if stub.branch != "main":
        return "branch"
    if stub.placement.revert:
        return "revert"
    if stub.placement.history:
        return "depth"
    return "head"


def _build_commits(
    stubs: List[_Stub], files: Dict[str, RenderedFile]
) -> Tuple[List[Commit], Dict[int, List[str]]]:
    by_layer: Dict[str, Dict[str, str]] = {"head": {}, "depth": {}, "revert": {}, "branch": {}}
    branch_name = "main"
    for stub in stubs:
        layer = _classify(stub)
        content = files[stub.placement.path].content
        by_layer[layer][stub.placement.path] = content
        if layer == "branch":
            branch_name = stub.branch
    for placement in _DECOY_PLACEMENTS:
        if placement.path in files:
            by_layer["head"][placement.path] = files[placement.path].content

    head_groups: Dict[int, Dict[str, str]] = {C_GROUP_A: {}, C_GROUP_B: {}, C_GROUP_C: {}}
    path_group = {}
    for stub in stubs:
        if _classify(stub) == "head":
            path_group[stub.placement.path] = _HEAD_GROUP.get(stub.placement.key, C_GROUP_B)
    for placement in _DECOY_PLACEMENTS:
        path_group[placement.path] = _HEAD_GROUP[placement.key]
    for path, content in by_layer["head"].items():
        head_groups[path_group.get(path, C_GROUP_B)][path] = content

    revert_files = by_layer["revert"]
    depth_files = by_layer["depth"]

    commits: List[Commit] = [
        Commit(message="chore: project skeleton", writes=dict(SKELETON)),
        Commit(message="feat: add temporary deploy credentials", writes=dict(revert_files)),
        Commit(
            message="revert: remove temporary deploy credentials",
            writes={p: _SCRUBBED[p] for p in revert_files if p in _SCRUBBED},
            deletes=[p for p in revert_files if p not in _SCRUBBED],
        ),
        Commit(message="feat: initial service configuration", writes=dict(depth_files)),
        Commit(message="feat: application configuration", writes=head_groups[C_GROUP_A]),
        Commit(message="feat: infrastructure config and test fixtures", writes=head_groups[C_GROUP_B]),
        Commit(message="feat: container build, notebooks and deploy logs", writes=head_groups[C_GROUP_C]),
        Commit(
            message="refactor: move legacy settings to the secrets manager",
            writes={p: _SCRUBBED[p] for p in depth_files if p in _SCRUBBED},
            deletes=[p for p in depth_files if p not in _SCRUBBED],
        ),
    ]

    labels: Dict[int, List[str]] = defaultdict(list)
    for stub in stubs:
        layer = _classify(stub)
        if layer == "revert":
            labels[C_REVERT_ADD].append(stub.id)
        elif layer == "depth":
            labels[C_DEPTH_ADD].append(stub.id)
        elif layer == "head":
            labels[_HEAD_GROUP.get(stub.placement.key, C_GROUP_B)].append(stub.id)

    if by_layer["branch"]:
        commits.append(Commit(
            message="feat: prototype payments integration",
            writes=dict(by_layer["branch"]),
            branch=branch_name,
            from_ref="main~2",
        ))
        for stub in stubs:
            if _classify(stub) == "branch":
                labels[len(commits) - 1].append(stub.id)

    return commits, labels


def _line_of(stub_id: str, files: Dict[str, RenderedFile]) -> Tuple[str, int]:
    for rendered in files.values():
        if stub_id in rendered.line_map:
            return rendered.path, rendered.line_map[stub_id]
    raise KeyError(f"no line recorded for {stub_id}")


def _manifest_placement(placement: Placement) -> str:
    if placement.revert:
        return "reverted-commit"
    if placement.history and placement.branch != "main":
        return "non-default-branch"
    if placement.history:
        return "history-depth"
    return placement.key


def _stats(
    planted: List[PlantedSecret], decoys: List[Decoy], indicators: List[Indicator]
) -> ManifestStats:
    by_cat: Dict[str, int] = defaultdict(int)
    by_type: Dict[str, int] = defaultdict(int)
    by_place: Dict[str, int] = defaultdict(int)
    head_count = 0
    for p in planted:
        by_cat[p.category] += 1
        by_type[p.secret_type] += 1
        by_place[p.placement] += 1
        head_count += int(p.present_at_head)
    return ManifestStats(
        planted_total=len(planted),
        decoy_total=len(decoys),
        indicator_total=len(indicators),
        by_category=dict(sorted(by_cat.items())),
        by_secret_type=dict(sorted(by_type.items())),
        by_placement=dict(sorted(by_place.items())),
        present_at_head=head_count,
        history_only=len(planted) - head_count,
    )


REDACTED_VALUE = "<redacted: synthetic; regenerate from corpus/seed>"


def _redact(data: dict) -> dict:
    """Strip the literal secret strings from a manifest dict.

    The committed reference manifest keeps every field a reviewer needs — type,
    checksum validity, location, sha256 — but not the value itself, so the file
    is not a pattern-matching landmine for every host it is mirrored to. The
    exact values are a pure function of ``corpus/seed`` and are reproduced by
    ``python generator/generate.py --seed "$(cat corpus/seed)" --output ./bench``.
    """
    for group in ("planted", "decoys", "indicators"):
        for entry in data.get(group, []):
            if entry.get("value"):
                entry["value"] = REDACTED_VALUE
    return data


def _dump_manifest(manifest: Manifest, redact: bool = False) -> str:
    if redact:
        header = (
            "# Ground truth for the secret-scanner benchmark corpus.\n"
            "# Regenerate the full manifest (with values) from the committed seed:\n"
            "#   python generator/generate.py --seed \"$(cat corpus/seed)\" --output ./bench\n"
            "# Values are redacted here on purpose (synthetic, but they match real\n"
            "# secret patterns). value_sha256 is the real hash. See SECURITY.md.\n"
        )
    else:
        header = (
            "# Ground truth for the secret-scanner benchmark corpus.\n"
            "# Generated by ssbench; regenerate with:  ssbench generate --seed <seed>\n"
            "# Every 'value' below is synthetic and non-functional. See SECURITY.md.\n"
        )
    data = manifest.model_dump(mode="json")
    if redact:
        data = _redact(data)
    return header + yaml.safe_dump(data, sort_keys=False, width=100, allow_unicode=True)


def generate(seed: int, output_dir: Path, record_to: Optional[Path] = None) -> Manifest:
    output_dir = Path(output_dir)
    if output_dir.exists():
        shutil.rmtree(output_dir)

    rng = SeededRNG(seed)
    stubs, decoys = _collect(rng)
    files = _render_targets(stubs, decoys)
    commits, labels = _build_commits(stubs, files)
    result = build_repo(output_dir, commits, labels)

    planted: List[PlantedSecret] = []
    indicators: List[Indicator] = []
    for stub in stubs:
        path, line = _line_of(stub.id, files)
        layer = _classify(stub)
        introduced = result.introduced_at.get(stub.id)
        if introduced is None and layer == "branch":
            introduced = result.branch_commits.get(stub.branch)
        if not stub.spec.is_secret:
            indicators.append(Indicator(
                id=stub.id,
                secret_type=stub.spec.secret_type,
                value=stub.spec.value,
                value_sha256=sha256_hex(stub.spec.value),
                branch=stub.branch,
                file=path,
                line=line,
                placement=_manifest_placement(stub.placement),
                obfuscation=stub.obfuscation,
                introduced_commit=introduced,
                present_at_head=(layer == "head"),
                reason=stub.spec.notes,
            ))
            continue
        planted.append(PlantedSecret(
            id=stub.id,
            secret_type=stub.spec.secret_type,
            category=stub.spec.category,
            value=stub.spec.value,
            value_sha256=sha256_hex(stub.spec.value),
            checksum_valid=stub.spec.checksum_valid,
            branch=stub.branch,
            file=path,
            line=line,
            placement=_manifest_placement(stub.placement),
            obfuscation=stub.obfuscation,
            introduced_commit=introduced,
            present_at_head=(layer == "head"),
            expected_detectable=stub.spec.expected_detectable,
            notes=stub.spec.notes,
        ))

    decoy_models: List[Decoy] = []
    for did, spec in sorted(decoys.items()):
        path, line = _line_of(did, files)
        decoy_models.append(Decoy(
            id=did,
            decoy_type=spec.decoy_type,
            value=spec.value,
            value_sha256=sha256_hex(spec.value),
            branch="main",
            file=path,
            line=line,
            placement="decoy-file",
            reason=spec.reason,
        ))

    manifest = Manifest(
        seed=seed,
        generator_version=GENERATOR_VERSION,
        created=CORPUS_CREATED,
        corpus_head_commit=result.head_commit,
        branches=["main", *sorted(result.branch_commits)],
        placement_requires=dict(PLACEMENT_REQUIRES),
        stats=_stats(planted, decoy_models, indicators),
        planted=planted,
        decoys=decoy_models,
        indicators=indicators,
    )

    (output_dir / "manifest.yaml").write_text(_dump_manifest(manifest), encoding="utf-8")
    if record_to is not None:
        record_to = Path(record_to)
        record_to.mkdir(parents=True, exist_ok=True)
        (record_to / "manifest.yaml").write_text(_dump_manifest(manifest, redact=True), encoding="utf-8")
        (record_to / "seed").write_text(f"{seed}\n", encoding="utf-8")

    return manifest
