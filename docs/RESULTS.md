# Benchmark results

Snapshot of one CI run. The workflow regenerates this every push and on a
monthly schedule; rulesets drift, so a snapshot older than a few weeks is stale.
Reproduce with `python generator/generate.py --seed "$(cat corpus/seed)"` then
the six scanners, or just read the latest `results` artifact from
[Actions](https://github.com/llody9977/secret-scanner-benchmark/actions).

| | |
|---|---|
| Run | [#5](https://github.com/llody9977/secret-scanner-benchmark/actions/runs/33239296691), commit `2c88f4a` |
| Date | 2026-08-29 |
| Corpus | seed `20260829`, HEAD `07e07fadb192ef0610047cc82b404e441d15d44d` |
| Planted | 45 secrets · 18 decoys · 37 present at HEAD · 8 history-only |

## Per-tool totals

| Tool | Version | Mode | TP | FP | FN | N/A | Σ | Precision | Recall | F1 |
|------|---------|------|----|----|----|-----|---|-----------|--------|-----|
| Gitleaks | 8.30.1 | default | 35 | 1 | 10 | 0 | 45 | 97.2% | 77.8% | 86.4% |
| Betterleaks | 1.8.1 | default | 39 | 2 | 6 | 0 | 45 | 95.1% | 86.7% | **90.7%** |
| TruffleHog | 3.97.1 | all-results | 22 | 0 | 23 | 0 | 45 | 100.0% | 48.9% | 65.7% |
| TruffleHog | 3.97.1 | verified-only | 0 | 0 | 45 | 0 | 45 | — | 0.0% | — |
| Kingfisher | 2.0.0 | default | 24 | 1 | 21 | 0 | 45 | 96.0% | 53.3% | 68.6% |
| Titus | 1.2.8 | default | 41 | 4 | 4 | 0 | 45 | 91.1% | 91.1% | **91.1%** |
| detect-secrets | 1.5.0 | default | 26 | 13 | 11 | 8 | 45 | 66.7% | 70.3% | 68.4% |

`Σ` = TP + FN + N/A. Every planted secret is exactly one of caught, missed, or
out-of-reach, so `Σ` equals the planted total (45) on every row — the scorer
fails the run if it does not. `N/A` = the tool cannot reach that placement
(detect-secrets does not walk history). FP is a separate axis: findings matching
nothing planted, bounded by the 18 decoys plus spurious noise. TruffleHog
`verified-only` is excluded from the coverage analysis below.

## Headline

- **Caught by no tool: 1** — `hist-openai`: an OpenAI key, split across a
  string-array and `"".join()`-ed, sitting only in git history (added six
  commits back, scrubbed at HEAD). Catching it needs history traversal *and*
  resistance to the split-string obfuscation. No tool has both.
- **Caught by exactly one tool: 2** — `aws-temp-key` and `hist-aws`, both only
  by Titus. Both are `AKIA`/`ASIA` access-key IDs (see below).
- **Union coverage: 44/45.** Layering gets you almost everything the set can
  find; it does not get you everything.

## Cross-tool coverage

The complementarity question — does the best tool subsume the others, and what
combination covers the corpus?

| Tool | Caught | Unique to it |
|------|-------:|--------------|
| Titus | 41/45 | `aws-temp-key`, `hist-aws` |
| Betterleaks | 39/45 | — |
| Gitleaks | 35/45 | — |
| detect-secrets | 26/45 | — |
| Kingfisher | 24/45 | — |
| TruffleHog (all) | 22/45 | — |

- **Betterleaks strictly dominates Gitleaks, Kingfisher and TruffleHog** — every
  secret any of those three catch, Betterleaks also catches, plus more. A
  Gitleaks user loses nothing by switching. (Titus likewise covers everything
  Kingfisher does.)
- **Only Titus has unique catches** (2). Every other tool's hits are a subset of
  what the rest of the field already covers.
- **Smallest set for 44/45: Titus + Gitleaks** (or Titus + Betterleaks). Two
  tools is the whole story — a third adds nothing but noise.
- **The one gap, `hist-openai`, is not closed by adding tools.** It is an
  obfuscated secret in history; the fix is process (pre-commit hooks, short-lived
  credentials, history rewriting on rotation), not another scanner.

## What the results show

### 1. No single tool is close to complete

Best recall is Titus at 91.1%. The next four sit between 48.9% and 86.7%. The
article's title holds: nothing catches everything, and the gap between "best
tool" and "all tools" is real (44/45 vs 41/45).

### 2. AWS access-key IDs are a systematic blind spot

`AKIA…` / `ASIA…` IDs: **Titus 4/4, everyone else 0/4** (Gitleaks, Betterleaks,
TruffleHog, Kingfisher). The paired 40-char *secret* keys are caught fine by
Gitleaks and Betterleaks (4/4) — it is specifically the ID pattern that four of
six tools skip.

*Caveat (inference, not fact):* the synthetic IDs encode AWS account `0`. Some
detectors validate the account-ID region or require the ID within proximity of
a secret key. Part of this gap may be a corpus artifact rather than a tool
weakness. Re-test with a real-format, revoked ID before citing it as a verdict.

### 3. The verification trap, demonstrated

TruffleHog `verified-only`: **0 / 45**. Every synthetic secret is non-live, so
verified-only mode reports nothing — recall 0%, a result that is not merely
wrong but backwards. Run any verification-capable tool this way against a
synthetic corpus and you will conclude it is useless. Always run `all-results`
for a benchmark; treat verification as a triage input in production, not a
filter.

### 4. Detector-only tools miss the generic and the obfuscated

TruffleHog `all-results` (48.9%) and Kingfisher (53.3%) are pattern-detector
engines with little or no entropy channel. They miss every generic
high-entropy string, JWTs, `mongodb`/`postgres` URIs where the password is the
secret, split-string obfuscation, and the base64-wrapped blob. They are also
the most *precise* (100% / 96%) — a real trade-off, not a defect.

### 5. Test-mode Stripe keys split the field

`sk_test_…` keys: Gitleaks 2/2, Betterleaks 2/2, Titus 2/2 — but **TruffleHog
0/2 and Kingfisher 0/2**. The regex-rule tools match the test-mode prefix; the
detector engines appear to gate on `sk_live_`.

### 6. Nested encoding defeats most tools

The base64-blob placement (a key wrapped in `export …=` then base64-encoded):
caught only by Gitleaks and Betterleaks (1/1), missed by the other four. Only
the Gitleaks lineage decodes and re-scans base64 payloads here.

### 7. detect-secrets: broad recall, heavy noise

70.3% recall on the placements it can reach, but 13 spurious false positives
plus 10 decoys triggered — git SHAs, a base64 PNG, `changeme`, `${VAR}`
placeholders. Precision 66.7%. Entropy plus keywords casts a wide net. Its 8
`N/A` (history + branch) are correctly *not* counted as misses.

### 8. The jwt.io sample token is the universal false positive

`decoy-10` (the demo token pasted into countless READMEs) fires on five of six
tools — everyone except TruffleHog. If you maintain an allowlist, start there.

## Per-placement recall (hits / reachable)

| Placement | Gitleaks | Betterleaks | TruffleHog | Kingfisher | Titus | detect-secrets |
|-----------|:--------:|:-----------:|:----------:|:----------:|:-----:|:--------------:|
| working-tree | 7/11 | 9/11 | 4/11 | 6/11 | 11/11 | 11/11 |
| dotenv | 5/6 | 6/6 | 5/6 | 4/6 | 6/6 | 4/6 |
| json-fixture | 5/5 | 5/5 | 4/5 | 4/5 | 5/5 | 5/5 |
| terraform-vars | 3/4 | 4/4 | 3/4 | 3/4 | 4/4 | 4/4 |
| ci-log-artifact | 3/4 | 3/4 | 1/4 | 1/4 | 3/4 | 1/4 |
| dockerfile-env | 2/2 | 2/2 | 1/2 | 1/2 | 1/2 | 0/2 |
| jupyter-output | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 0/1 |
| minified-bundle | 2/3 | 2/3 | 1/3 | 1/3 | 3/3 | 1/3 |
| base64-blob | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| history-depth | 2/4 | 2/4 | 1/4 | 1/4 | 3/4 | N/A |
| reverted-commit | 2/2 | 2/2 | 0/2 | 0/2 | 2/2 | N/A |
| non-default-branch | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | N/A |

History placements: Gitleaks and Betterleaks walk history but their `2/4` on
history-depth is the obfuscation, not the traversal. TruffleHog and Kingfisher
under-perform on `reverted-commit` (0/2) because they miss those secret *types*
(Stripe test key, generic hex), not because they cannot see the commits.

## Recommendation

- **One tool:** Titus or Betterleaks. Titus for recall (91%) and the only unique
  catches in the field; Betterleaks for the recall/precision balance (87% / 95%)
  and lighter false-positive load. Betterleaks strictly dominates Gitleaks here,
  so a Gitleaks pipeline can switch with nothing to lose.
- **Two tools:** Titus + Betterleaks → 44/45. A third tool adds only noise on
  this corpus.
- **Pre-commit:** detect-secrets or Betterleaks `--pre-commit`; accept that
  history and other surfaces are out of scope there.
- **Do not** rely on verified-only output as a gate, and do not benchmark a
  verifying tool that way.
- **The last secret is a process problem.** `hist-openai` survives every tool
  and every combination — an obfuscated credential in history is the case to
  design your rotation and pre-commit story around, not your scanner choice.
