# Configured-control regression suite

**This is not a benchmark.** It does not compare scanners, it does not measure
recall, and no number in it belongs in a tool-selection argument. If you are
looking for "which scanner detects what", that is the other test population —
see [`corpus/`](../corpus/) and [`docs/RESULTS.md`](../docs/RESULTS.md).

This suite asks a different question, and it is the question a control owner
actually has to answer:

> Does the gate **we configured** still make the control decision we
> specified, for every credential class we said we care about?

A failure here is a broken control, not an interesting result about a product.

## The two test populations

The repository deliberately contains two corpora that must not be confused.

| | Comparative benchmark corpus | Configured-control regression corpus |
|---|---|---|
| Lives in | `corpus/` + generated `bench/` | `regression/templates/` |
| Question | Which tool detects what? | Does our gate still work? |
| Configuration | Stock, per tool | This repository's `controls/gitleaks.toml` |
| Population | 41 planted secrets, 18 decoys, 4 indicators | 16 must-block, 4 must-pass scenarios |
| Output | Precision, recall, F1, coverage | Pass or fail, per control decision |
| Changes when | A tool ships a new ruleset | *We* change our configuration |
| Failure means | Interesting; write it up | Something is broken; fix it today |

Tuning a tool for the benchmark would measure the tuning. Running the
regression suite against stock configuration would measure the vendor rather
than the control. Both are correct in their own population and wrong in the
other.

## Running it

```bash
python regression/run.py
```

Requires `gitleaks` 8.30.1 on `PATH` (or `--gitleaks /path/to/gitleaks`).
Exit codes: `0` every scenario as specified, `1` a control decision was wrong,
`2` the harness could not run. Add `--json out.json` for a machine-readable
record.

## No credential-shaped string is committed

The templates in `templates/` hold `{{PLACEHOLDER}}` tokens, not values. The
values are fabricated from the committed seed by [`shapes.py`](shapes.py) and
materialised into a temporary directory only for the duration of the scan.

This is the same reasoning that redacts `corpus/manifest.yaml`: this repository
is public, forked and mirrored, and a checked-in file full of credential shapes
is a push-protection and secret-scanning landmine for everyone downstream. It
is not obfuscation — every value is worthless — it is not making other people's
scanners your problem.

## What the suite specifies

Sixteen scenarios must block and four must pass. The four that must pass are
the ones that keep the gate usable: a runtime secret reference, a documentation
placeholder, an SSH *public* key, and a bare AWS access key id. A ruleset
change that improves coverage by breaking one of those has not improved
anything — it has moved cost onto every developer who writes a config file, and
bypass requests are how that cost gets paid.

Two scenarios are worth reading the `why:` field for:

- **`aws-split-id` must pass.** A bare `AKIA…` with no secret access key near
  it does not block, and that is specified behaviour rather than a gap. An
  access key id is an identifier that AWS transmits in cleartext in every
  signed request; blocking a push on one costs a bypass request and prevents no
  exposure. This is the same distinction the comparative benchmark scores as an
  *indicator* — asserted here as a control decision instead of measured. The
  cost of the choice is real and named in the manifest: the id is what incident
  response feeds to `aws iam delete-access-key`, so if you want key ids
  surfaced, route them to the scheduled discovery workflow, not the gate.

- **`custom-internal` must block.** The internal token format is the only one
  no vendor ships a detector for, so it is the only one where a silent
  regression is invisible. If someone replaces `useDefault = true` with a
  bespoke ruleset, or an allowlist grows a path that shadows it, this scenario
  is what tells you.

## What is asserted, and what is only recorded

`expected_control_decision` is **asserted**. It is what a control owner signs
off, and a mismatch fails the run.

Detector names and finding counts are **recorded, not asserted**. Detector
names change between releases; pinning them produces failures that teach
nothing and get muted. The JSON record exists so that a reviewer can diff
detector attribution across a version bump and see *how* the gate reached the
same decision — which is often where a coming regression is visible first.

One thing is asserted beyond the decision: any report the gate produces must be
fully redacted. A gate whose own output republishes the secret it caught has
created a second copy of the exposure, in a place with wider read access than
the original.

## It found two gaps the first time it ran

Worth recording, because it is the whole argument for the suite. On its first
run against the stock provider ruleset plus the internal-format rule, two
scenarios failed:

- a PostgreSQL URL with an inline password, and
- an HTTP Basic `Authorization` header.

Neither is exotic and both are on the list of things this repository says it
cares about. Nobody had noticed, because nobody discovers a missing rule by
rereading the rules they already have. Both are now closed by
`connection-string-inline-password` and `http-basic-authorization-header` in
[`controls/gitleaks.toml`](../controls/gitleaks.toml).

The comparative benchmark had already reported the same weakness from the other
direction — Gitleaks misses `postgres-uri` and `mongodb-uri` on the stock
ruleset. That is the intended relationship between the two populations: the
benchmark tells you where the product is weak, and the regression suite is
where you do something about it and keep it done.

## Adding a scenario

1. Add a template under `templates/positive/` or `templates/negative/`, using
   `{{PLACEHOLDER}}` tokens for anything credential-shaped. Add the value to
   [`shapes.py`](shapes.py) if the placeholder is new.
2. Add the scenario to [`manifest.yaml`](manifest.yaml) with its
   `expected_control_decision` and, if the decision is not obvious, a `why:`.
3. Run `python regression/run.py`. If it fails, decide which is wrong — the
   specification or the configuration — and change that one.
4. Never use a real credential, including one you believe is revoked. Prefer a
   provider's documented test value; otherwise fabricate deterministically.
