# The configured control set

The executable half of [part three, *The Governed
Pipeline*](https://llody9977.github.io/secret-scanner-benchmark/part-3.html).
Everything here is configuration that *enforces* something. Nothing here
measures anything — measurement lives in `corpus/` and `scoring/`, and the two
must not be mixed. A ruleset tuned to make a benchmark look good measures the
tuning; a benchmark run against a tuned ruleset measures nobody's product.

## Control points, and what each one is for

| # | Control point | Type | Owner | On failure | Bypass | Evidence |
|---|---|---|---|---|---|---|
| 1 | Local pre-commit / pre-push | Preventive, advisory | Developer | Blocks the local commit or push | `--no-verify`, unlogged | None |
| 2 | Server-side push protection | **Preventive, enforcing** | Org / repo admin | Rejects the push | Documented reason, logged | Block + bypass record, alert |
| 3 | Pull-request CI gate | Detective, enforcing at merge | Platform team | Fails the required check | Branch-protection override, logged | Check run, job summary |
| 4 | Scheduled full-history scan | Detective | Security engineering | Opens a finding | n/a — nothing is waiting | Workflow run, job summary |
| 5 | Non-repository discovery | Detective | Security engineering | Opens a finding | n/a | Workflow run |

Points 1 and 3 are configured in this directory. Point 2 is a host feature, not
a file — its behaviour on this corpus is recorded in
[`docs/HOSTED-PUSH-PROTECTION.md`](../docs/HOSTED-PUSH-PROTECTION.md). Point 5
has no implementation here and is named so that its absence is visible rather
than assumed.

**Only point 2 is preventive in the sense a control narrative means.** Point 1
is opt-in and removable by the person it constrains. Points 3 to 5 all run
after the secret has reached a server that other people can read, which makes
them detection, however fast they are. Describing a pull-request gate as
"preventing secret exposure" in an audit response is the most common honest-
seeming overclaim in this control family.

## Files

| File | Control point | Notes |
|---|---|---|
| [`gitleaks.toml`](gitleaks.toml) | 1, 3 | The blocking ruleset. Extends the provider defaults; adds one internal format and two generic classes. |
| [`pre-commit-config.yaml`](pre-commit-config.yaml) | 1 | Copy to `.pre-commit-config.yaml`. Optional by design. |
| [`trufflehog.yml`](trufflehog.yml) | 4 | Detector set for scheduled discovery. |
| [`trufflehog-exclude-paths.txt`](trufflehog-exclude-paths.txt) | 4 | Keeps both test corpora out of discovery findings. |

## Why two different tools for two different jobs

Gitleaks gates; TruffleHog discovers. That is not a ranking, it is a
consequence of what each job needs.

A **gate** runs on the critical path of a developer waiting for a check, so it
needs to be fast, deterministic, and precise enough that a failure is believed.
It is allowed to miss things, because it is not the last line.

**Discovery** runs on a schedule with nobody waiting, so it can afford breadth,
a wider detector set, and a lower confidence threshold. Its findings go to a
triage queue, not to a developer's pull request.

Running the wide tool at the gate produces bypass requests. Running the narrow
tool as discovery produces false confidence. The
[benchmark](../docs/RESULTS.md) shows these two tools have genuinely different
shapes — Gitleaks 97.2% precision at 85.4% recall, TruffleHog 100% precision at
53.7% — which is what makes the split defensible rather than arbitrary.

## Verifying the configuration still works

```bash
python regression/run.py
```

See [`regression/README.md`](../regression/README.md). The gate's ruleset is
not self-verifying: a rule that stops matching fails silently and looks exactly
like a clean repository.

## Failure behaviour, and the one thing to get right

Every workflow here distinguishes three outcomes, not two:

| Exit | Meaning | Gate behaviour |
|---|---|---|
| 0 | Scanned, nothing found | Pass |
| 1 | Scanned, findings | **Fail — findings** |
| other | The scanner did not run correctly | **Fail — error** |

Conflating the third case with the first is the single most common way a
pipeline reports green while scanning nothing: a download that 404s, a config
path that moved, a timeout on a large history. The workflows validate that the
report exists and parses before believing a zero, and treat an unparseable
report as an error rather than as an absence of findings.

They also check that the report is redacted before publishing any summary. A
gate that republishes the secret it caught, into job output with wider read
access than the branch it came from, has widened the exposure it was installed
to contain.
