"""Synthetic GitHub tokens, with and without a valid checksum.

GitHub's token format is ``<prefix>_<30 base62 chars><6-char base62 CRC32>``.
The last six characters are a CRC32 of the preceding body, base62-encoded.
GitHub states the prefix alone drops the false-positive rate to ~0.5 percent
and the checksum "virtually eliminates false positives" for offline scanning.

Generating a matched pair — one correct checksum, one deliberately broken —
cleanly separates checksum-aware scanners (reject the broken one) from
regex-only scanners (match both). No other single test does it as precisely.
"""

from __future__ import annotations

from ssbench.formats.base import SecretSpec, crc32_base62, flip_one_char
from ssbench.rng import BASE62, SeededRNG

PREFIXES = {
    "ghp": "personal access token",
    "gho": "OAuth access token",
    "ghu": "user-to-server token",
    "ghs": "server-to-server token",
    "ghr": "refresh token",
}


def _assemble(prefix: str, body: str, checksum: str) -> str:
    return f"{prefix}_{body}{checksum}"


def compute_checksum(body: str) -> str:
    return crc32_base62(body, width=6)


def verify_token(token: str) -> bool:
    """True if ``token`` is well-formed and its trailing CRC32 checks out."""
    if "_" not in token:
        return False
    prefix, _, rest = token.partition("_")
    if prefix not in PREFIXES or len(rest) != 36:
        return False
    body, checksum = rest[:30], rest[30:]
    if any(c not in BASE62 for c in rest):
        return False
    return compute_checksum(body) == checksum


def build_token(rng: SeededRNG, prefix: str = "ghp", valid_checksum: bool = True) -> SecretSpec:
    if prefix not in PREFIXES:
        raise ValueError(f"unknown GitHub token prefix: {prefix}")
    body = rng.derive("body").token(BASE62, 30)
    checksum = compute_checksum(body)

    if valid_checksum:
        token = _assemble(prefix, body, checksum)
        return SecretSpec(
            secret_type=f"github-token-{prefix}",
            category="structured",
            value=token,
            checksum_valid=True,
            assignment_key="GITHUB_TOKEN",
            notes=f"{PREFIXES[prefix]}; CRC32 checksum is correct.",
        )

    broken = flip_one_char(checksum, rng.derive("break"), BASE62)
    token = _assemble(prefix, body, broken)
    return SecretSpec(
        secret_type=f"github-token-{prefix}",
        category="structured",
        value=token,
        checksum_valid=False,
        is_secret=False,
        unscored_reason="malformed",
        assignment_key="GITHUB_TOKEN",
        notes=(
            f"{PREFIXES[prefix]}; checksum deliberately broken, so it authenticates "
            "nowhere. A validating scanner should reject it and a regex-only scanner "
            "will still match: both are correct, which is why this is scored on "
            "neither axis."
        ),
    )


def build_fine_grained_pat(rng: SeededRNG) -> SecretSpec:
    body = rng.derive("body").token(BASE62, 82)
    return SecretSpec(
        secret_type="github-token-github_pat",
        category="structured",
        value=f"github_pat_{body}",
        checksum_valid=None,
        assignment_key="GITHUB_TOKEN",
        notes="fine-grained PAT; longer body, no separately verifiable checksum here.",
    )
