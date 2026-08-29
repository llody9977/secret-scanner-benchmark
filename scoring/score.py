#!/usr/bin/env python3
"""Scoring entrypoint.

Kept at ``scoring/score.py`` to match the layout published in the article; all
logic lives in :mod:`ssbench`. Equivalent to ``ssbench score``.

    python scoring/score.py --manifest ./bench/manifest.yaml --results ./scan-output --out ./results
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from ssbench.models import RunIndex  # noqa: E402
from ssbench.report import print_console, render_markdown  # noqa: E402
from ssbench.score import load_manifest, score, verify_manifest_values  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Score scanner output against the benchmark manifest.")
    parser.add_argument("--manifest", type=Path, required=True, help="path to manifest.yaml")
    parser.add_argument("--results", type=Path, required=True, help="directory with index.yaml + each tool's report")
    parser.add_argument("--out", type=Path, default=Path("results"), help="directory for results.json / results.md")
    parser.add_argument("--fail-on-missed-by-all", action="store_true",
                        help="exit non-zero if any planted secret was caught by no tool")
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    bad = verify_manifest_values(manifest)
    if bad:
        print(f"ERROR manifest is corrupt — hash mismatch: {bad}", file=sys.stderr)
        return 2

    index_path = args.results / "index.yaml"
    if not index_path.exists():
        print(f"ERROR missing {index_path}", file=sys.stderr)
        return 2
    run_index = RunIndex.model_validate(yaml.safe_load(index_path.read_text(encoding="utf-8")))

    card = score(manifest, run_index, args.results)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(json.dumps(card.model_dump(mode="json"), indent=2), encoding="utf-8")
    (args.out / "results.md").write_text(render_markdown(card), encoding="utf-8")
    print_console(card)

    if args.fail_on_missed_by_all and card.caught_by_no_tool:
        print(f"FAIL {len(card.caught_by_no_tool)} planted secrets caught by no tool", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
