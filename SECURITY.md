# Security and safety model

## Every credential in this repository is synthetic

The benchmark works by planting credential-shaped strings in a repository and
measuring which scanners find them. None of those strings is a real credential.

| Family | How it is fabricated | Why it cannot be used |
|---|---|---|
| AWS access key ids | Generated from account id `0` via the documented base32 account-id encoding | Account `0` does not exist; the key authenticates against nothing |
| AWS secret access keys | 40 random base64 characters from the seeded RNG | Not paired with any real key id or account |
| GitHub tokens | `<prefix>_<30 random base62><CRC32>`, half with a deliberately broken checksum | Never issued by GitHub; not registered to any account |
| Stripe / Slack / SendGrid / Google / npm | Seeded-random bodies; test-mode prefixes where the provider offers them (`sk_test_`), zeroed numeric ids where it does not | Not provisioned; test-mode keys at most reach an empty sandbox |
| AI-service keys (OpenAI, Anthropic, HuggingFace, DeepSeek, Groq, Cohere) | Seeded-random bodies with the real prefix shape | Not issued by any provider |
| Private keys (RSA, EC, Ed25519, OpenSSH) | Four keypairs generated once with `openssl` / `ssh-keygen` for this corpus, checked in as constants in `ssbench/formats/keys.py` | Never added to any `authorized_keys`, service, or certificate; they grant access to nothing |
| JWTs | Real header/payload, signature is 32 random bytes | Verifies against no key |
| Database URIs, service-account JSON | Seeded-random passwords; hostnames use `.invalid` / `.example` | Point at no real host |

The generator (`ssbench.rng.SeededRNG`) is a Mersenne Twister seeded from a
committed integer. It is deliberately **not** a CSPRNG: the output is meant to
be predictable and regenerable, which is the opposite of what you want when
minting a credential.

## The decoy group

`ssbench/decoys.py` also plants benign strings a scanner must **not** report —
UUIDs, git SHAs, content hashes, a base64 PNG, and the literal example keys
from provider documentation (`AKIAIOSFODNN7EXAMPLE`, the jwt.io demo token).
These are only ever in the decoy set, never the planted set, so a correct
"ignore" is scored as a correct ignore rather than a miss.

## Redaction in the committed manifest

`corpus/manifest.yaml` in git redacts the literal `value` of every planted
secret and decoy, keeping `value_sha256` and everything else. The values are
synthetic but they match real provider patterns, so a checked-in file full of
them trips push protection and raises secret-scanning alerts on every fork and
mirror. GitHub push protection did flag ~a dozen of them on the first push
attempt — a data point the benchmark analysis keeps. For the same reason the
five PEM keys in `ssbench/formats/keys.py` are stored base64-encoded and decoded
at import.

Nothing is hidden: the full values are a pure function of `corpus/seed` and are
written to `bench/manifest.yaml` by `generator/generate.py`. The scorer uses
that generated manifest, not the committed one.

## What the corpus is not

- **Not a set of live canary tokens.** There is no tripwire credential here. If
  you want one (the article suggests exactly one AWS canary token as a
  tripwire), add it yourself — it is intentionally out of scope so this
  repository has no external dependency and no alerting side effect.
- **Not derived from real repositories.** Unlike SecretBench, nothing here was
  harvested from public code, so there is no question of a harvested credential
  still being valid.

## Running the benchmark

The scanning jobs need **no credentials**. The corpus is the only input. The
CI workflow sets `permissions: contents: read` and never references a secret.
If you add a verification-capable tool, run it in a job with no network egress
to provider APIs, or accept that it will (correctly) report every synthetic
secret as unverified.

## Reporting

If you believe any value in `corpus/manifest.yaml` collides with a real
credential, open an issue and we will rotate the seed. Do not include the
suspected real credential in the report.
