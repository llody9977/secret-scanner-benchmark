# Benchmark results

Snapshot of one run. The workflow regenerates this every push and on a monthly
schedule; rulesets drift, so a snapshot older than a few weeks is stale.
Reproduce with `python generator/generate.py --seed "$(cat corpus/seed)"` then
the six scanners, or read the latest `results` artifact from
[Actions](https://github.com/llody9977/secret-scanner-benchmark/actions).

| | |
|---|---|
| Run | Scoring generation #7. GitHub Actions workflow [run 9](https://github.com/llody9977/secret-scanner-benchmark/actions/runs/33478315806), `ubuntu-24.04`, commit `9ca7fce` |
| Executed | 2026-09-01 |
| Corpus generated | 2026-08-29 (the seed date, not the run date) |
| Corpus | seed `20260829`, HEAD `07e07fadb192ef0610047cc82b404e441d15d44d` |
| Ground truth | 39 planted secrets · 18 decoys · **6 unscored** · 32 present at HEAD · 7 history-only |
| Tool versions | Gitleaks 8.30.1 · Betterleaks 1.8.1 · TruffleHog 3.97.1 · Kingfisher 2.0.0 · Titus 1.2.8 · detect-secrets 1.5.0 |
| Field | Six *selected* free/self-hostable scanners, not an exhaustive field. "No tool has a unique catch" means no tool **among these six**. |

> **What changed, and why the totals keep moving.** Two ground-truth
> corrections, both the same mistake: counting something as a planted secret
> that cannot authenticate.
>
> Run #5 counted standalone AWS access key IDs (`AKIA…`, `ASIA…`) as secrets. An
> access key ID is an identifier, not an authenticator. AWS transmits it in
> cleartext in the `Authorization` header of every signed request and it opens
> nothing without the paired secret access key
> ([AWS IAM documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)).
> Run #7 also stops counting the two GitHub tokens with a deliberately broken
> CRC32: a token whose checksum is wrong authenticates nowhere, so a scanner
> that validates the checksum and declines to report it would have been charged
> a false negative for being right.
>
> Planted has fallen 45 to 41 to 39 across those corrections. The corpus files
> have never changed; HEAD is still `07e07fa`. Only the ground truth has.
>
> The first correction reversed the headline. Run #5's "Titus leads on recall
> and is the only tool with unique catches" was an artifact of counting IDs:
> **both of Titus's unique catches were access key IDs.** Betterleaks leads now,
> and no tool in the field has a unique catch.

## Ground truth has three populations

| Population | Count | Missing one is | Reporting one is |
|---|---:|---|---|
| Planted secret | 39 | a false negative | a true positive |
| Decoy | 18 | correct behaviour | a false positive |
| Unscored | 6 | correct behaviour | neither; tallied separately |

**Unscored** covers two kinds of value, both credential-shaped and neither able
to authenticate. Four are **identifiers**: AWS access key IDs, half a credential
and sent in the clear by design. Two are **malformed**: GitHub tokens with a
broken CRC32, the right shape and useless everywhere.

Reporting either is defensible behaviour. An access key ID names the account and
the key to disable, which is exactly what incident response needs. A malformed
token is worth surfacing by a regex engine and worth rejecting by a validating
one, and both are correct. Scoring either as recall would credit a tool for
finding something that is not a secret; scoring either as a false positive would
penalise a legitimate signal. So they count on neither axis, and the tally is
reported separately because "which tools surface these" is a real question.

The AWS *secret* access key beside each ID remains a planted secret, and that is
where the real AWS result is.

## Per-tool totals

| Tool | Version | Mode | TP | FP | FN | N/A | Σ | Precision | Recall | F1 | Unscored |
|------|---------|------|----|----|----|-----|---|-----------|--------|-----|---------:|
| Betterleaks | 1.8.1 | default | 37 | 2 | 2 | 0 | 39 | 94.9% | 94.9% | **94.9%** | 2/6 |
| Titus | 1.2.8 | default | 35 | 4 | 4 | 0 | 39 | 89.7% | 89.7% | 89.7% | **5/6** |
| Gitleaks | 8.30.1 | default | 33 | 1 | 6 | 0 | 39 | 97.1% | 84.6% | 90.4% | 2/6 |
| detect-secrets | 1.5.0 | default | 23 | 13 | 9 | 7 | 39 | 63.9% | 71.9% | 67.7% | 2/6 |
| Kingfisher | 2.0.0 | default | 22 | 1 | 17 | 0 | 39 | 95.7% | 56.4% | 71.0% | 2/6 |
| TruffleHog | 3.97.1 | all-results | 20 | 0 | 19 | 0 | 39 | 100.0% | 51.3% | 67.8% | 2/6 |
| TruffleHog | 3.97.1 | verified-only | 0 | 0 | 39 | 0 | 39 | — | 0.0% | — | 0/6 |

`Σ` = TP + FN + N/A. Every planted secret is exactly one of caught, missed, or
out-of-reach, so `Σ` equals the planted total (39) on every row — the scorer
fails the run if it does not. FP is a separate axis. `N/A` = the tool cannot
reach that placement (detect-secrets does not walk history). `Unscored` is the count of
unscored values reported, on neither axis. TruffleHog
`verified-only` is excluded from the coverage analysis below.

## Headline

- **Caught by no tool: 1** — `hist-openai`: an OpenAI key, split across a
  string-array and `"".join()`-ed, sitting only in git history (added six
  commits back, scrubbed at HEAD). Catching it needs history traversal *and*
  resistance to the split-string obfuscation. No tool has both.
- **Caught by exactly one tool: 0.** No tool among these six finds anything the
  other five miss. This is a change from run #5, and it is entirely the AWS
  correction. It is a statement about the six selected tools, not about every
  scanner in existence.
- **Union coverage: 38/39.** Layering gets you almost everything the set can
  find; it does not get you everything.
- **Zero spurious false positives across all six.** Every false positive
  reported by every one of these tools is one of the 18 planted decoys. Nothing invented noise out of
  ordinary source code.

## Cross-tool coverage

| Tool | Caught | Unique to it |
|------|-------:|--------------|
| Betterleaks | 37/39 | — |
| Titus | 35/39 | — |
| Gitleaks | 33/39 | — |
| detect-secrets | 23/39 | — |
| Kingfisher | 22/39 | — |
| TruffleHog (all) | 20/39 | — |

- **Betterleaks catches everything Gitleaks, Kingfisher and TruffleHog catch,
  and more** — a strict superset on this corpus. Titus likewise covers
  everything Kingfisher and detect-secrets cover.
- **No tool has a unique catch.** Every tool's hit-set is contained in the
  union of the others.
- **Smallest set for 38/39: Betterleaks + Titus.** Titus contributes exactly
  one secret Betterleaks misses (`openai-legacy`, the value-on-the-next-line
  obfuscation).
- **The one gap, `hist-openai`, is not closed by adding tools.** It is an
  obfuscated secret in history; the fix is process (pre-commit hooks,
  short-lived credentials, history rewriting on rotation), not another scanner.

## What the results show

### 1. No single tool is complete

Best recall is Betterleaks at 94.9%. The rest of the field runs from 51.3% to
89.7%. The gap between "best tool" and "all tools" is one secret (38/39 vs
37/39) — narrower than run #5 suggested, but the article's title still holds:
nothing catches everything, and what nothing catches is the obfuscated
history case, not a tool-selection problem.

### 2. The AWS gap is in the secret key, not the key ID

Correcting the ground truth did not remove an AWS finding — it relocated it.

| Tool | AWS secret access key | AWS access key ID (unscored) |
|---|:---:|:---:|
| Gitleaks | 4/4 | 0/4 |
| Betterleaks | 4/4 | 0/4 |
| Titus | 4/4 | 3/4 |
| detect-secrets | 2/3 (1 N/A) | 0/4 |
| TruffleHog | **0/4** | 0/4 |
| Kingfisher | **0/4** | 0/4 |

TruffleHog and Kingfisher miss every AWS secret access key in the corpus — the
confidential half, the one that grants access. A 40-character base64 string with
no prefix, no delimiter and no checksum is exactly the shape a pattern-detector
engine has no rule for.

Titus is the only tool that reports access key IDs at all (3 of 4 — it misses
the one split across a string concatenation). That is worth knowing for
incident response, where the ID is what you feed to `aws iam
delete-access-key`. It is not recall.

### 3. The verification trap, demonstrated

TruffleHog `verified-only`: **0 / 39**. Every synthetic secret is non-live, so
verified-only mode reports nothing — recall 0%, a result that is not merely
wrong but backwards. Run any verification-capable tool this way against a
synthetic corpus and you will conclude it is useless. Always run `all-results`
for a benchmark; treat verification as a triage input in production, not a
filter.

### 4. Detector-only tools miss the unstructured

TruffleHog and Kingfisher miss every generic high-entropy string,
every AWS secret access key, the headerless PEM body and the base64-wrapped
blob. They are also the most *precise* in the field, which is the trade-off
rather than a defect.

Two corrections to the obvious reading, both from the per-type table above.
"No entropy channel" is too broad: both tools detect the `postgres` and
`mongodb` URIs where the password is the secret, and Kingfisher detects the
JWT. And the tool that misses those URIs is **Gitleaks** (0 of 3), which is
neither detector-only nor short of an entropy channel.

What these two actually miss is credential material with **no recognisable
shape**. A URI has a scheme and a `user:pass@host` structure to key on; a bare
40-character base64 string has nothing.

### 5. Test-mode Stripe keys split the field

`sk_test_…` keys: Gitleaks 2/2, Betterleaks 2/2, Titus 2/2 — but **TruffleHog
0/2 and Kingfisher 0/2**. The regex-rule tools match the test-mode prefix; the
detector engines appear to gate on `sk_live_`.

### 6. Nested encoding defeats most tools

The base64-blob placement (a key wrapped in `export …=` then base64-encoded):
caught only by Gitleaks and Betterleaks (1/1), missed by the other four. Only
the Gitleaks lineage decodes and re-scans base64 payloads here.

### 7. detect-secrets: broad recall, heavy noise — but all of it on the decoys

71.9% recall on the placements it can reach, at 63.9% precision. It emits **13
false-positive findings, all of them on planted decoy content, resolving to 10
distinct decoys** — git SHAs, a base64 PNG, `changeme`, `${VAR}` placeholders,
the provider documentation samples. Three of the thirteen are a second or third
rule firing on a decoy another rule already matched. Nothing spurious; the net
is simply wide enough to catch everything shaped like a secret, including the
things deliberately planted to look like one. Its 7 `N/A` (history + branch) are
correctly *not* counted as misses.

### 8. The jwt.io sample token is the universal false positive

`decoy-10` (the demo token pasted into countless READMEs) fires on five of six
tools — everyone except TruffleHog. If you maintain an allowlist, start there.

## Per-placement recall (hits / reachable)

| Placement | Titus | Betterleaks | Gitleaks | detect-secrets | Kingfisher | TruffleHog |
|-----------|:-----:|:-----------:|:--------:|:--------------:|:----------:|:----------:|
| working-tree | 9/9 | 8/9 | 6/9 | 9/9 | 5/9 | 3/9 |
| dotenv | 6/6 | 6/6 | 5/6 | 4/6 | 4/6 | 5/6 |
| json-fixture | 4/4 | 4/4 | 4/4 | 4/4 | 3/4 | 3/4 |
| terraform-vars | 4/4 | 4/4 | 3/4 | 4/4 | 3/4 | 3/4 |
| ci-log-artifact | 2/3 | 3/3 | 3/3 | 1/3 | 1/3 | 1/3 |
| dockerfile-env | 1/2 | 2/2 | 2/2 | 0/2 | 1/2 | 1/2 |
| jupyter-output | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 0/1 |
| minified-bundle | 2/2 | 2/2 | 2/2 | 1/2 | 1/2 | 1/2 |
| base64-blob | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| history-depth | 2/3 | 2/3 | 2/3 | N/A | 1/3 | 1/3 |
| reverted-commit | 2/2 | 2/2 | 2/2 | N/A | 0/2 | 0/2 |
| non-default-branch | 2/2 | 2/2 | 2/2 | N/A | 2/2 | 2/2 |

History placements: Gitleaks and Betterleaks walk history but their `2/3` on
history-depth is the obfuscation, not the traversal. TruffleHog and Kingfisher
under-perform on `reverted-commit` (0/2) because they miss those secret *types*
(Stripe test key, generic hex), not because they cannot see the commits.

## Recommendation

Read these as conclusions about **detection coverage on this corpus, at these
versions, in these invocations**. They are not a procurement verdict: this
benchmark measures nothing about configuration burden, output handling,
integration surface, ruleset maintenance, project maturity or governance fit.
Those belong in a pilot, not in a recall table.

- **One tool:** Betterleaks. Highest recall (94.9%), highest F1 (94.9%), two
  false positives, both on planted decoys. Titus is the close alternative and
  the only tool that surfaces access key IDs for response.
- **Two tools:** Betterleaks + Titus → 38/39. The second tool buys exactly one
  additional secret; decide whether that is worth the triage load.
- **Pre-commit:** detect-secrets or Betterleaks `--pre-commit`; accept that
  history and other surfaces are out of scope there.
- **Do not** rely on verified-only output as a gate, and do not benchmark a
  verifying tool that way.
- **The last secret is a process problem.** `hist-openai` survives every tool
  and every combination — an obfuscated credential in history is the case to
  design your rotation and pre-commit story around, not your scanner choice.

## Provenance and limits

- Scoring generation #7 is GitHub Actions workflow run 9 on `ubuntu-24.04`,
  executed 2026-09-01 at commit `9ca7fce`, same six tools at the same
  pinned versions, against a byte-identical corpus (HEAD unchanged), scored with
  the corrected ground truth.
- The correction was developed against a local `darwin/arm64` rescore of the
  run #5 reports. CI reproduced it exactly on six of seven rows. The seventh:
  detect-secrets caught `slack-webhook` (a Slack webhook URL in a `Dockerfile
  ENV`) locally and missed it on CI, which is a one-secret platform difference
  in that tool, not in the scoring. CI is canonical and the figures above are
  CI's; the local run is mentioned only because the discrepancy is real and
  someone reproducing this on macOS will see it.
- Verification callbacks are never enabled in this benchmark. Both
  verification-capable tools are invoked in modes that retain unverified
  findings (`--results=verified,unknown,unverified`, `--validation-filter all`),
  which is why `verified-only` is reported separately rather than treated as a
  result.
- Every credential is synthetic and non-functional. No result here says
  anything about how these tools behave against live credentials.
