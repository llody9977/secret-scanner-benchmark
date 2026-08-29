# If a secret reaches git, treat it as an incident

**Deleting the line is not revocation.** A later commit that removes the value
does not remove the earlier git object. The value may still be in local clones,
remote branches, pull-request refs, forks, caches, build output, logs, artifact
storage and backups. History rewriting can reduce future exposure; it cannot
make a value that was copied unknown again.

The benchmark makes the same point structurally: two of its placements are a
secret that was committed and then removed in the next commit, and a secret six
commits deep that is gone at HEAD. Every history-capable scanner in
[the run](RESULTS.md) finds them. So does everyone else's.

This is the response order. It is ordered deliberately: **revocation comes
before repository cleanup**, which is also where GitHub's own history-cleanup
guidance puts it.

## 1. Revoke or rotate first

Invalidate the credential at its issuing system before touching the repository.
Everything else in this list is slower and none of it shortens the window.

Where the provider participates in a host partner programme, this may already
have happened without you: push a live `sk_live_` key to a public GitHub
repository and Stripe is notified and revokes it, typically within minutes.
That covers only public repositories and only participating formats. Assume it
covers nothing internal or bespoke.

Where auto-revocation is too risky, rotate: issue the replacement first, cut
consumers over, then invalidate the old credential. Rotation with a gap is an
outage; rotation without invalidation is not rotation.

## 2. Establish the exposure window

Preserve incident records, then determine:

- the first commit containing the value, and every branch, tag, fork and
  surface it reached;
- who and what could read those surfaces over that period;
- the time revocation actually completed — not the time it was requested.

The window is from first push to completed revocation. That is the interval you
investigate, and it is the number that belongs in the incident record. It is
also the metric part four asks you to report, segmented by exposure class.

## 3. Investigate use

Review provider, identity, cloud, database, CI and application audit logs for
activity inside the window. **Scope the investigation to the permissions the
credential actually had** — not to the permissions you assume it had, which is
usually narrower than reality for a long-lived key nobody has audited.

Two cautions from the case studies in part one:

- Absence of evidence in a log you do not retain is not evidence of absence.
  Establish retention before you conclude "no use".
- The credential's blast radius is what it could reach, not what the service it
  belonged to was for. A publishing token in a CI runner reaches the registry,
  not just the build.

## 4. Replace the storage pattern

Move the value to an approved secret manager or, better, remove the need for a
stored value at all — workload identity, OIDC federation, or a dynamically
minted short-lived credential. Update consumers and confirm the old credential
no longer works.

A rotation that puts the new value back in the same file has bought you one
cycle. This step is the one that changes whether the incident recurs, and it is
the one most often deferred.

## 5. Remove the value from current content, then decide about history

Remove it from HEAD. Then decide — separately and deliberately — whether to
rewrite history. Rewriting:

- changes every commit hash from the rewrite point forward;
- invalidates signatures;
- disrupts every open branch and pull request;
- requires coordination with every clone owner, because a single stale clone
  can push the value back.

Rewriting is sometimes right. It is never urgent in the way revocation is, and
treating it as the emergency is how organisations spend the first hour on the
wrong task.

## 6. Search adjacent surfaces

The same value, and credentials related to it, may be in issues, pull-request
descriptions, wikis, chat, CI logs, build artifacts, container image layers,
package registries, IaC state files, MCP configuration and documentation.
GitGuardian put 28 percent of incidents entirely outside repositories. No git
scanner in [the benchmark](RESULTS.md) looks at any of it.

## 7. Add a regression guard

Add a safe detector test for the credential format and enforce it at the
earliest gate plus a shared gate, so this class cannot recur silently. In this
repository that means a scenario in the
[configured-control regression suite](../regression/README.md): a template with
a `{{PLACEHOLDER}}`, an entry in `regression/manifest.yaml`, and a `why:` that
names the incident.

**Do not commit the real leaked value as a fixture.** Use a provider's
documented test token where one exists; otherwise fabricate one
deterministically, as `regression/shapes.py` does. A fixture built from a real
credential turns a closed incident into a permanent one, and it does it in a
file whose whole purpose is to be widely copied.

## What good looks like as a number

Not "findings closed". **Mean time from detection to confirmed invalidation**,
segmented by exposure class, with a named owner per class. The practitioner
survey behind part one put the industry average at 27 days. The attacker
timings put first use inside sixty seconds.

You cannot win that race, and part one says so plainly. What you can do is
shrink everything after it: 27 days to two days is roughly an order of
magnitude less time for persistence, repeated use, lateral movement and quiet
egress. That is a blast-radius control, not a prevention control, and it is
worth funding as long as nobody claims it prevents the first use.
