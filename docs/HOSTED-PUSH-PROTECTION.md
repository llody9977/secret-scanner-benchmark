# The hosted push-protection test

Control point 2 — server-side push protection — is the only placement in the
control set that is genuinely preventive, and it is the only one that cannot be
tested with a CLI. It is a host feature. The only way to know what it does is to
push at it and record what happens.

This is that test: a deliberate push of a non-issued, credential-shaped fixture
at a repository with GitHub secret scanning and push protection enabled, then a
documented bypass, then the resulting alert. It is the positive case for the
whole series — the one place where scanning demonstrably prevented an exposure
rather than reporting one after the fact.

> **Status.** The recorded result below was produced in
> `llody9977/secret-scan` on 25 August 2026 and is migrated here with its
> original provenance intact. **It has not yet been re-run in this
> repository.** The procedure to reproduce it here is in full below; until
> someone runs it, read the result as evidence about GitHub's behaviour on that
> repository and configuration, not as a property of this one.

Machine-readable record: [`results/hosted-push-protection.json`](../results/hosted-push-protection.json).

## What happened

| Stage | Result |
|---|---|
| Fixture | `mailchimp-api-key`, a Mailchimp-shaped value that Mailchimp never issued |
| Initial push | **Rejected.** Classified as `Mailchimp API Key`; a bypass URL was offered |
| Bypass | `used_in_tests`, GitHub's documented reason |
| Retry | Accepted |
| Alert | [#1](https://github.com/llody9977/secret-scan/security/secret-scanning/1) — `mailchimp_api_key`, state `resolved`, resolution `used_in_tests`, `push_protection_bypassed: true` |
| Same fixture, Gitleaks 8.30.1 | Detected (`mailchimp-api-key`) |
| Same fixture, TruffleHog 3.97.1 | **Not detected** |

Two things are worth reading twice.

**The push was stopped before the object reached a server anyone else could
read.** Not detected, not alerted on — stopped. Nothing downstream of a push
can do that, however fast it runs. This is the difference the series keeps
insisting on, demonstrated rather than asserted.

**The bypass is the control, not the hole in it.** The push succeeded on retry,
because a developer with a legitimate reason could give one. What matters for
governance is that the bypass produced a durable record naming the actor, the
reason and the commit. A preventive control with no escape hatch gets disabled;
a preventive control whose escape hatch is unlogged is theatre. This one is
neither, and the bypass rate is the metric part four asks you to report.

## What this result does not say

- **It is one provider-pattern scenario, not a detection rate.** It says
  nothing about how GitHub handles the other twenty scenarios in the regression
  corpus, several of which are generic or internal shapes.
- **The tested repository was public and personal.** Provider-pattern scanning
  and push protection were on; non-provider generic patterns, validity checks
  and repository custom patterns were unavailable or off. Repository custom
  patterns returned HTTP 404 — *"Feature not available in this repository."*
  An eligible organisation on a GitHub Secret Protection plan gets generic
  detection, AI-assisted detection, validity checks and custom patterns, none
  of which were exercised here. Assess those on your own plan; do not read this
  result as a ceiling or a floor for them.
- **The fixture was never issued and validity checks were disabled.** The
  result records *pattern classification and push behaviour*, not credential
  validity.
- **TruffleHog's miss is not a verdict on TruffleHog.** It is one format, run
  once, with provider checks disabled. The comparative benchmark is where
  detection claims belong.

## Reproducing it in this repository

The fixture already exists as a template: `regression/templates/positive/mailchimp-api-key.env`.
The regression suite materialises it into a temporary directory, which is
exactly why pushing it is a deliberate act rather than an accident.

**Preconditions.**

- Run this only against a repository you own and have explicitly authorised for
  defensive testing.
- Use only a non-issued fixture. Never substitute a real credential, including
  one you believe is revoked.
- Record repository visibility, ownership type, plan, and the scanning,
  push-protection, validity-check and custom-pattern settings. These are part
  of the result, not context around it.
- Keep raw alert API responses private: GitHub's alert API includes a `secret`
  field. Persist only sanitised metadata, as `hosted-push-protection.json`
  does.

**Procedure.**

1. Confirm secret scanning and push protection are enabled on the repository,
   and record the four settings above.
2. Materialise the fixture onto a throwaway branch:
   ```bash
   git switch -c hosted-push-protection-test
   python - <<'PY'
   from pathlib import Path
   from regression import shapes
   import yaml
   seed = yaml.safe_load(Path("regression/manifest.yaml").read_text())["seed"]
   tpl = Path("regression/templates/positive/mailchimp-api-key.env")
   out = Path("hosted-test.env")
   out.write_text(shapes.render(tpl.read_text(), shapes.build(seed)))
   PY
   git add hosted-test.env && git commit -m "test: hosted push-protection fixture"
   ```
3. `git push -u origin hosted-push-protection-test`. Record whether the push was
   rejected, the pattern name and location GitHub reported, and whether a bypass
   URL appeared.
4. If it is blocked, use GitHub's documented **used in tests** bypass reason.
   Do not disable scanning for the actor — that destroys the evidence the test
   exists to produce.
5. Retry the push, then query the alert API and retain only: alert number,
   secret type, display name, state, resolution, bypass metadata, validity,
   HTML URL and sanitised location.
6. Update `results/hosted-push-protection.json` with the new repository block
   and alert, and link the alert.
7. Delete the branch and the fixture commit. The alert stays; that is the point.
8. Re-run `python regression/run.py` on the same fixture so the CLI gate result
   and the host result are recorded against the same value.

## Custom internal formats

The repository-only format is:

```regex
\bDEMO_[A-Z0-9]{32}\b
```

Gitleaks and TruffleHog carry engine-specific versions of it in
[`controls/`](../controls/). GitHub custom patterns were unavailable on the
tested repository, so the internal format was never enforced at the host
boundary — which is the general case worth planning for: **the formats only you
have are the formats the host is least likely to cover**, and they are usually
the ones with no provider revocation behind them either.

On an eligible repository: dry-run the pattern, review its positives and
negatives against the regression corpus, publish it, and enable custom-pattern
push protection only after you have tested host enforcement *and* bypass
governance on that plan.

## Interpreting another run

Do not convert a small corpus into a percentage. Pattern versions, paired-value
logic, encodings, feature settings, plan eligibility, service limits and
optional provider checks all change what a host can report.

For every format the host does not block, choose one explicitly:

- accept the gap and record it as an accepted risk with an owner;
- cover it at control point 3, the CI gate, and accept that the control is now
  detective for that format rather than preventive; or
- remove the need — workload identity, OIDC, or a dynamic credential, so there
  is no static value to leak. Part three's last section is about this option,
  and it is the only one that makes the format stop mattering.
