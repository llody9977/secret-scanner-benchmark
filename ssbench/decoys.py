"""Benign strings that a well-behaved scanner must NOT report.

Precision is meaningless without these. A tool that flags every UUID and git
SHA will look excellent on a corpus of only real secrets; the decoy group is
what makes the false-positive count mean something.

Two sub-groups:

* **structural look-alikes** — UUIDs, SHAs, content hashes, base64 blobs. High
  entropy, no secret. These test the entropy channel.
* **published samples** — the literal example keys from provider documentation.
  Scanners ship allowlists for these, so being ignored is the *correct*
  behaviour. They live here, never in the planted set, precisely so a correct
  ignore is not misread as a miss.
"""

from __future__ import annotations

from dataclasses import dataclass

from ssbench.rng import SeededRNG


@dataclass
class DecoySpec:
    decoy_type: str
    value: str
    assignment_key: str
    reason: str


# The literal AWS documentation example. Every serious scanner allowlists it.
AWS_DOC_EXAMPLE_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_DOC_EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# A widely-copied jwt.io sample token.
JWT_IO_SAMPLE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

# 1x1 transparent PNG, base64 — a real data-URI payload, not a secret.
TINY_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
    "+P+/HgAFhAJ/wlseKgAAAABJRU5ErkJggg=="
)


def _uuid4(rng: SeededRNG) -> str:
    h = rng.hexdigits(32)
    # force version 4 and RFC 4122 variant
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-{('89ab'[rng.randint(0, 3)])}{h[17:20]}-{h[20:32]}"


def build_decoys(rng: SeededRNG) -> list:
    """Return the fixed decoy set. Values that need entropy use ``rng``."""
    r = rng.derive("decoys")
    return [
        DecoySpec("uuid4", _uuid4(r.derive("uuid-a")), "request_id",
                  "random UUID; high entropy, carries no secret"),
        DecoySpec("uuid4", _uuid4(r.derive("uuid-b")), "trace_id",
                  "random UUID in a log-like context"),
        DecoySpec("git-sha1", r.derive("sha1").hexdigits(40), "VENDORED_COMMIT",
                  "40 hex chars is a git object id, not a token"),
        DecoySpec("git-sha256", r.derive("sha256").hexdigits(64), "ARTIFACT_DIGEST",
                  "sha256 content digest"),
        DecoySpec("npm-integrity", "sha512-" + r.derive("npm").base64url(88).replace("-", "A"),
                  "integrity", "subresource-integrity hash from a lockfile"),
        DecoySpec("docker-image-digest",
                  "sha256:" + r.derive("oci").hexdigits(64), "BASE_IMAGE",
                  "OCI image digest pinned in a Dockerfile"),
        DecoySpec("base64-png", TINY_PNG_B64, "PIXEL_DATA_URI",
                  "base64 of a 1x1 PNG; a real asset payload"),
        DecoySpec("hex-color-run", r.derive("hex16").hexdigits(16), "PALETTE_HASH",
                  "short hex string that entropy rules over-weight"),
        DecoySpec("aws-doc-example-id", AWS_DOC_EXAMPLE_ID, "AWS_ACCESS_KEY_ID",
                  "the published AWS docs example; correct behaviour is to ignore it"),
        DecoySpec("aws-doc-example-secret", AWS_DOC_EXAMPLE_SECRET, "AWS_SECRET_ACCESS_KEY",
                  "the published AWS docs example secret; allowlisted by design"),
        DecoySpec("jwt-io-sample", JWT_IO_SAMPLE, "SAMPLE_TOKEN",
                  "the jwt.io demo token; appears in countless READMEs"),
        DecoySpec("placeholder-your-key", "YOUR_API_KEY_HERE", "api_key",
                  "literal placeholder text"),
        DecoySpec("placeholder-angle", "<insert-token-here>", "token",
                  "angle-bracket placeholder"),
        DecoySpec("placeholder-env-ref", "${OPENAI_API_KEY}", "OPENAI_API_KEY",
                  "shell variable reference, not a value"),
        DecoySpec("placeholder-changeme", "changeme", "password",
                  "obvious non-secret default"),
        DecoySpec("example-key-literal", "sk_test_" + "0" * 24, "STRIPE_API_KEY",
                  "Stripe publishable-style literal built entirely from zeros"),
        DecoySpec("lorem-high-entropy",
                  "".join(reversed(r.derive("lorem").base62(50))), "CACHE_BUSTER",
                  "random-looking build hash used for cache busting"),
        DecoySpec("certificate-pem",
                  "-----BEGIN CERTIFICATE-----\nMIIBFAKECERTNOTAKEYdGhpcyBpcyBub3QgYSBrZXk=\n"
                  "-----END CERTIFICATE-----", "TLS_CERT",
                  "a certificate is public material; not a private key"),
    ]
