# corpus/

Committed ground truth for the benchmark.

| File | What it is |
|---|---|
| `seed` | The integer seed. The entire corpus is a pure function of it. |
| `manifest.yaml` | Every planted secret and decoy: type, value, SHA-256, file, line, placement, obfuscation, introducing commit, and whether it is present at HEAD. `corpus_head_commit` pins the deterministic HEAD of the generated repository. |

The scannable git repository itself is **not** committed — it is a build
artifact. Regenerate it:

```bash
python generator/generate.py --seed "$(cat corpus/seed)" --output ./bench
```

After changing `ssbench/plan.py` (or any format module), refresh the manifest
and commit the diff:

```bash
python generator/generate.py --seed "$(cat corpus/seed)" --output ./bench --record
```

CI regenerates on every run and fails if `manifest.yaml` no longer matches, so a
stale corpus cannot go unnoticed.

Every `value` in `manifest.yaml` is synthetic and non-functional. See
[../SECURITY.md](../SECURITY.md).
