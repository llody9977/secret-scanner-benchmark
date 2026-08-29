#!/usr/bin/env python3
"""Corpus generator entrypoint.

Kept at ``generator/generate.py`` to match the layout published in the article;
all logic lives in :mod:`ssbench`. Equivalent to ``ssbench generate``.

    python generator/generate.py --seed "$(cat corpus/seed)" --output ./bench --record
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ssbench.constants import DEFAULT_SEED  # noqa: E402
from ssbench.generate import generate  # noqa: E402
from ssbench.score import verify_manifest_values  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the synthetic secret-scanner benchmark corpus.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="integer seed (corpus is a pure function of it)")
    parser.add_argument("--output", type=Path, default=Path("bench"), help="output directory for the scannable git repo")
    parser.add_argument("--record", action="store_true", help="also write corpus/manifest.yaml and corpus/seed")
    parser.add_argument("--corpus-dir", type=Path, default=Path("corpus"), help="destination for --record")
    args = parser.parse_args()

    manifest = generate(args.seed, args.output, record_to=args.corpus_dir if args.record else None)
    bad = verify_manifest_values(manifest)
    print(f"planted={manifest.stats.planted_total} decoys={manifest.stats.decoy_total} "
          f"head_visible={manifest.stats.present_at_head} history_only={manifest.stats.history_only}")
    print(f"corpus_head_commit={manifest.corpus_head_commit}")
    print(f"output={args.output}")
    if bad:
        print(f"ERROR manifest hash mismatch: {bad}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
