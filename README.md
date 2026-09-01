# secret-scanner-benchmark (`ssbench`)

A reproducible benchmark for secret-scanning tools. It plants a synthetic corpus
of credential-shaped strings with a known ground truth, assembles them into a
git repository with deterministic history, runs six selected free/self-hostable
scanners against it in CI, and scores precision and recall — overall, per secret type,
and per placement.

It exists because I found no current independent benchmark of these tools with
comparable reproducibility — one that publishes corpus, seed, ground truth and
scoring so a reader can regenerate it and check the arithmetic. That is what a
search surfaced, not a proof that none exists. The last peer-reviewed comparison
(ESEM 2023) predates Betterleaks, Kingfisher, Titus, and every AI-service
credential format. This is the design
from section four of *Nothing Catches Everything* (chapter 2 of the series), made
runnable.

**On compliance:** no framework requires you to operate a product called a
"secret scanner" — they require outcomes, and scanning is one implementation and
one way to evidence them. Three name hardcoded secrets in normative text, each
scope-limited (PCI DSS 8.6.2, OWASP ASVS 13.3.1, NIST SP 800-218A); ISO 27001,
SOC 2, base NIST SSDF, CIS and DORA reach the control by inference. The
clause-level mapping is in
[chapter 4](https://llody9977.github.io/secret-scanner-benchmark/unnamed-control.html#standards).

**Companion series:** *[Secrets in the Software Supply Chain](https://llody9977.github.io/secret-scanner-benchmark/)*
— [chapter 1](https://llody9977.github.io/secret-scanner-benchmark/sixty-second-credential.html) (threat),
[chapter 2](https://llody9977.github.io/secret-scanner-benchmark/nothing-catches-everything.html) (this benchmark),
[chapter 3](https://llody9977.github.io/secret-scanner-benchmark/governed-pipeline.html) (the implemented
pipeline — `controls/` and `regression/` in this repository),
[chapter 4](https://llody9977.github.io/secret-scanner-benchmark/unnamed-control.html) (governance),
[chapter 5](https://llody9977.github.io/secret-scanner-benchmark/sources.html) (sources and references).

**Every credential here is synthetic and non-functional.** See
[SECURITY.md](SECURITY.md) for how each format is fabricated and why it cannot
be used.

## Two test populations, deliberately separate

This repository holds two corpora that answer different questions. Confusing
them is the easiest mistake to make here, because both are collections of fake
secrets.

| | Comparative benchmark | Configured-control regression suite |
|---|---|---|
| Lives in | `corpus/`, generated to `bench/` | `regression/` |
| Question | Which tool detects what? | Does *our* gate still work? |
| Configuration | Stock, per tool | This repo's `controls/gitleaks.toml` |
| Population | 39 planted secrets, 18 decoys, 6 unscored | 16 must-block, 5 must-pass |
| Output | Precision, recall, F1, coverage | Pass or fail, per control decision |
| A failure means | Interesting; write it up | Something is broken; fix it |

Tuning a tool for the benchmark would measure the tuning. Running the
regression suite against stock configuration would measure the vendor rather
than the control. See [`regression/README.md`](regression/README.md) and
[`controls/README.md`](controls/README.md).

```bash
python regression/run.py        # 21 scenarios; needs gitleaks 8.30.1
```

**Latest results:** [docs/RESULTS.md](docs/RESULTS.md) — best single-tool recall
95% (Betterleaks); no tool has a unique catch; two tools reach 38/39; one
obfuscated secret in history is caught by nothing; every false positive in the
field is a planted decoy.

---

## Quick start

```bash
pip install -e .

# 1. Generate the scannable corpus + ground-truth manifest from the committed seed
python generator/generate.py --seed "$(cat corpus/seed)" --output ./bench

# 2. Keep the manifest for scoring, but move it out of the scan target — it holds
#    every planted value in plaintext, so leaving it in ./bench inflates results
cp bench/manifest.yaml manifest.yaml && rm bench/manifest.yaml

# 3. Run your scanners against ./bench, one report per run into ./scan-output
#    (the CI workflow does this for gitleaks, betterleaks, trufflehog, kingfisher,
#     titus and detect-secrets)

# 4. Score the reports against the manifest
python scoring/score.py --manifest ./manifest.yaml --results ./scan-output --out ./results
```

`ssbench generate`, `ssbench score` and `ssbench verify` are the same commands
via the installed console script.

---

## What the corpus contains

`ssbench/plan.py` fixes the matrix. Values are filled by a seeded Mersenne
Twister (`ssbench/rng.py`); the seed is committed, so the corpus is a pure
function of it.

**Secret types** — structured with a checksum (GitHub tokens, generated in
matched valid/broken pairs), structured without a checksum (AWS, Stripe, Slack,
SendGrid, Google, npm), AI-service keys (OpenAI, Anthropic, HuggingFace,
DeepSeek, Groq, Cohere), private keys (RSA / EC / Ed25519 / OpenSSH, with and
without PEM armour), JWTs, database URIs, GCP service-account JSON, generic
high-entropy strings, and one low-entropy password — the case nothing catches.

**Placements** — working tree, `.env`, JSON fixture, Jupyter output cell,
`Dockerfile ENV`, Terraform vars, a CI log artifact, a minified bundle, a
base64-encoded blob, a commit six deep in history, a commit that was reverted in
the next commit, and a non-default branch that was never merged.

**Obfuscations** — plain, string concatenation across lines, split into an
array and joined, assigned to a meaningless variable name, and value on the line
after the key.

**Decoys** — UUIDs, git SHAs, an npm integrity hash, an OCI image digest, a
base64 PNG, and the literal example keys from provider docs. A scanner must
**not** report these; the false-positive count is meaningless without them.

**Indicators** — AWS access key IDs (`AKIA…`, `ASIA…`). These are planted, but
as a third population that is scored on neither axis. An access key ID is a
credential *identifier*, not an authenticator: AWS sends it in cleartext in
every signed request and it authenticates nothing without the paired secret
access key, so failing to report one is not a miss and reporting one is not a
false positive. The 40-character secret access key beside it is the planted
secret. See [the AWS IAM
documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html).

Current corpus: **39 planted secrets, 18 decoys, 6 unscored** (34 visible at
HEAD, 7 history-only). Regenerate `corpus/manifest.yaml` after changing the
plan:

```bash
python generator/generate.py --seed "$(cat corpus/seed)" --output ./bench --record
```

---

## The manifest

`corpus/manifest.yaml` is the ground truth. Each planted secret records its
type, category, SHA-256, the file and line, the placement, the obfuscation,
whether it is present at HEAD, and the commit that introduced it. For
history-only placements the line number refers to the file *as introduced*, not
at HEAD (where the secret is gone).

The **committed** manifest redacts the literal secret strings — they are
synthetic but they match real secret patterns, and a checked-in file full of
them is a push-protection and secret-scanning landmine for every fork and mirror
(GitHub push protection did flag them; that is noted in the analysis). The
`value` fields are restored in the manifest that `generator/generate.py` writes
next to the corpus, which the scorer uses. Regenerate the full manifest anytime:

```bash
python generator/generate.py --seed "$(cat corpus/seed)" --output ./bench
```

`corpus_head_commit` pins the deterministic HEAD of the generated repository.
CI regenerates and fails if the committed manifest no longer matches — a stale
corpus is always visible.

```bash
ssbench verify --manifest corpus/manifest.yaml --seed 20260829
```

checks the manifest is well-formed and, with `--seed`, regenerates the corpus
and confirms the HEAD commit is identical — the real integrity guarantee when
values are redacted.

---

## Scoring

`scoring/score.py` reads the manifest and a `results/index.yaml` describing each
run (tool, version, parser, mode, capabilities, report path), then matches
findings to planted secrets:

1. exact value hash — the strong signal;
2. the planted value is a substring of the finding's string, or vice versa;
3. same file and a line within tolerance.

Each finding is assigned to at most one planted secret, greedily, location-first,
so a precise hit claims a duplicate-valued secret before a location-less one.

- **True positive** — a planted secret matched by a finding.
- **False positive** — a finding matching nothing planted. If it matches a
  decoy it is also named in `decoys_triggered`.
- **False negative** — a planted secret with no matching finding, *where the
  run has the capability to see that placement*.
- **N/A** — a planted secret whose placement needs a capability the run lacks
  (history for a working-tree-only tool). Never scored as a miss.
- **Indicator** — a finding resolving to a credential identifier rather than a
  credential. Scored on neither axis and tallied in `indicators_reported`.
  Indicators are matched *before* planted secrets, so a hit on an AWS access
  key ID cannot be credited by line proximity to the secret access key beside
  it.

Output: `results/results.json`, `results/results.md`, and a console table.
Across the default-mode runs it also reports the two numbers the analysis turns
on — planted secrets caught by **exactly one** tool, and caught by **none**.

### The verification trap

Every synthetic secret is non-live, so a verification-capable tool
(TruffleHog, Betterleaks, Kingfisher, Titus) classifies all of them as
*unverified*. Run such a tool in verified-only mode against this corpus and
every secret scores as a miss — a result that is not merely imprecise but
exactly backwards. The workflow runs every verification-capable tool **twice**,
`all-results` and `verified-only`, and reports both. The verified-only run is
flagged `counts_toward_coverage: false` so its emptiness does not make every
secret look uncaught.

---

## CI

`.github/workflows/benchmark.yml` runs on push, monthly on a schedule, and on
demand. One job per tool (`fail-fast: false`), `fetch-depth: 0`, every action
and tool pinned to an exact version and recorded in the output, `permissions:
contents: read`, and no repository secret is ever referenced. Results land in
the job summary and a `results` artifact.

Covered: **gitleaks, betterleaks, trufflehog, kingfisher, titus, detect-secrets**
— six selected free/self-hostable scanners, not an exhaustive field. TruffleHog runs
twice (`all-results` and `verified-only`); the other verification-capable tools
(betterleaks, kingfisher, titus) run unfiltered, since every synthetic secret is
non-live. Not covered: `git-secrets` (no structured output to parse) and GitHub
secret scanning (a platform feature, not a CLI — though its push protection
already fires on this corpus; see SECURITY.md).

`.github/workflows/controls.yml` is the other half: the configured control set
rather than the benchmark. Three jobs — the blocking full-history gate, the
configured-control regression suite, and scheduled discovery — each
distinguishing "scanned, clean" from "did not scan", and each verifying report
redaction before publishing a summary. See
[`controls/README.md`](controls/README.md).

Adding a tool: add it to the `scan` matrix with an install + run step that
writes `scan-output/<tool>.<ext>` and `scan-output/<tool>.version`, then add an
`add(...)` line to the run-index builder in the `score` job. Write a parser in
`ssbench/parsers/` if its output format is new; SARIF and the Gitleaks/TruffleHog
JSON shapes are already handled.

---

## Layout

```
ssbench/
  rng.py            seeded Mersenne Twister, forkable per planting
  constants.py      pinned identity/timestamps for deterministic git hashes
  models.py         manifest + scorecard schema (pydantic)
  formats/          one module per provider family; build_*(rng) -> SecretSpec
  decoys.py         benign look-alikes and published sample keys
  obfuscation.py    render a secret into source lines, plain or obfuscated
  placements.py     where each secret goes; special renderers for ipynb/minified
  plan.py           THE BENCHMARK DESIGN: secret x placement x obfuscation matrix
  skeleton.py       innocuous files that make the corpus look like a real repo
  gitbuild.py       assemble deterministic git history
  generate.py       orchestrator: plan -> files -> history -> manifest
  parsers/          scanner output -> normalised Finding list
  score.py          match findings to ground truth, compute metrics
  report.py         render the scorecard (markdown + console)
  cli.py            ssbench generate | score | verify
generator/generate.py   thin entrypoint (article layout)
scoring/score.py        thin entrypoint (article layout)
corpus/                 committed: seed + redacted manifest.yaml

controls/               the configured control set — configuration that ENFORCES
  gitleaks.toml           the blocking ruleset (gate, pre-commit)
  trufflehog.yml          detector set for scheduled discovery
  pre-commit-config.yaml  optional local hooks
regression/             configured-control regression suite — NOT a benchmark
  manifest.yaml           21 scenarios and their specified control decision
  templates/              fixtures with {{PLACEHOLDER}} tokens, never values
  shapes.py               deterministic placeholder values from the seed
  run.py                  materialise, scan, assert every control decision
results/                hosted-push-protection.json — the host-control evidence
docs/                   the published series, RESULTS.md, HOSTED-PUSH-PROTECTION.md,
                        INCIDENT-RESPONSE.md
```

---

## Limitations

- **Synthetic, not harvested.** Real repositories carry obfuscations and edge
  cases no synthetic plan anticipates. This measures the failure modes we can
  name; run it *and* scan one large real repository.
- **Commercial tools are excluded** because they need a paid account, and
  GitHub's own scanner because it is a platform feature rather than a CLI. That
  is a limit of the method, not a verdict: in the ESEM 2023 study the
  highest-precision tool measured was GitHub's scanner (75% precision, 6%
  recall) — the anonymised commercial entrant scored 25%.
- **A result is a snapshot.** Rulesets change monthly. The schedule re-runs it;
  a result older than a few weeks is stale in both directions.
- **This measures detection and nothing else.** Not configuration burden, output
  handling, integration surface, ruleset maintenance, project maturity or
  governance fit. "No detection loss on this corpus at these versions" is not
  operational equivalence, and a recall table is an input to a tool decision
  rather than the decision.
- **Static scanning cannot reach runtime credentials.** Stolen session cookies,
  tokens in process memory, dynamically minted credentials, values from a
  metadata service — none is ever written to a file a scanner walks. Nothing in
  this repository says anything about that surface.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
