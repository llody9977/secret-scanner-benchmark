# The configured control set

The executable half of [part three, *The Governed
Pipeline*](https://llody9977.github.io/secret-scanner-benchmark/part-3.html).
Everything here is configuration that *enforces* something. Nothing here
measures anything — measurement lives in `corpus/` and `scoring/`, and the two
must not be mixed. A ruleset tuned to make a benchmark look good measures the
tuning; a benchmark run against a tuned ruleset measures nobody's product.

## Control points, and what each one is for

Control points are referred to **by name, not by number**, throughout this
repository and the series. Each article numbers the points in whatever order
suits its own diagram, and those numberings do not agree with each other; the
names do.

| Control point | Type | Owner | On failure | Bypass | Evidence |
|---|---|---|---|---|---|
| Local hooks | Preventive, advisory | Developer | Blocks the local commit or push | `--no-verify`, unlogged | None |
| Server-side push gate | **Preventive, enforcing** | Org / repo admin | Rejects the push | Documented reason, logged | Block + bypass record, alert |
| Pull-request CI gate | Detective, enforcing at merge | Platform team | Fails the required check | Branch-protection override, logged | Check run, job summary |
| Scheduled history scan | Detective | Security engineering | Opens a finding | n/a — nothing is waiting | Workflow run, job summary |
| Non-repository discovery | Detective | Security engineering | Opens a finding | n/a | Workflow run |
| Incident-response trigger | Corrective | Security engineering | Revocation clock starts | None | Incident record, revocation timestamp |

**Local hooks** and the **pull-request CI gate** are configured in this
directory. The **server-side push gate** is a host feature, not a file — its
behaviour is recorded in
[`docs/HOSTED-PUSH-PROTECTION.md`](../docs/HOSTED-PUSH-PROTECTION.md).
**Non-repository discovery** has no implementation here and is named so that
its absence is visible rather than assumed.

**Only the server-side push gate is preventive in the sense a control narrative
means.** Local hooks are opt-in and removable by the person they constrain.
Everything from the CI gate onwards runs after the secret has reached a server
that other people can read, which makes it detection, however fast it is.
Describing a pull-request gate as "preventing secret exposure" in an audit
response is the most common honest-seeming overclaim in this control family.

## Files

| File | Control point | Notes |
|---|---|---|
| [`gitleaks.toml`](gitleaks.toml) | Local hooks, CI gate | The blocking ruleset. Extends the provider defaults; adds one internal format and two generic classes. |
| [`pre-commit-config.yaml`](pre-commit-config.yaml) | Local hooks | Copy to `.pre-commit-config.yaml`. Optional by design. |
| [`trufflehog.yml`](trufflehog.yml) | Scheduled history scan | Detector set for scheduled discovery. |
| [`trufflehog-exclude-paths.txt`](trufflehog-exclude-paths.txt) | Scheduled history scan | Keeps both test corpora out of discovery findings. |

## Why two different tools, and the argument that does not work

Gitleaks gates; TruffleHog discovers. The usual justification is that the gate
wants precision and discovery wants reach, and this repository's own benchmark
does not support it: Gitleaks has the higher recall of the two, 84.6% against
51.3%, at 97.1% precision against 100%. Running TruffleHog as the wide net
would mean running the narrower tool.

The defensible reason is that the two **fail differently**. Gitleaks misses the
`postgres` and `mongodb` URIs where the password is the secret, which TruffleHog
catches. TruffleHog misses every AWS secret access key and every generic
high-entropy string, which Gitleaks catches. A second engine on the scheduled
scan buys independent blind spots rather than additional coverage, and the
scheduled scan is where that is affordable because nobody is waiting on it.

What holds without the benchmark: a **gate** runs on the critical path of a
developer waiting for a check, so it needs to be fast, deterministic and
precise enough that a failure is believed. **Discovery** runs on a schedule, so
it can afford a wider ruleset, a lower threshold and surfaces the gate never
sees, and its findings go to a triage queue rather than a pull request.

Running one product in two modes is a reasonable alternative and this
repository does not argue against it.

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
