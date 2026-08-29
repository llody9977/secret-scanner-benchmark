"""Synthetic AWS credentials.

AWS access key ids have no checksum, so a scanner cannot validate one offline.
They do embed the account id (for keys issued since ~March 2019): the 16
characters after the prefix are RFC 4648 base32 of a 10-byte payload whose top
40 bits (after masking) are the account number. Every synthetic key here is
generated from account id 0, which is not a real account and decodes back to a
run of ``A`` characters — the clearest possible "this is fake" signal.

The secret access key is a 40-character base64 string with no prefix and no
structure. It is the part that actually grants access, and detecting it depends
entirely on entropy and the surrounding variable name.
"""

from __future__ import annotations

from ssbench.constants import SYNTHETIC_AWS_ACCOUNT_ID
from ssbench.formats.base import SecretSpec, b32_decode_nopad, b32_encode_nopad
from ssbench.rng import SeededRNG

_AWS_SECRET_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def encode_access_key_id(prefix: str, account_id: int, rng: SeededRNG) -> str:
    z = account_id << 7
    payload = z.to_bytes(6, "big") + rng.bytes(4)
    return prefix + b32_encode_nopad(payload)


def decode_account_id(key_id: str) -> int:
    raw = b32_decode_nopad(key_id[4:])
    z = int.from_bytes(raw[:6], "big")
    mask = int.from_bytes(bytes.fromhex("7fffffffff80"), "big")
    return (z & mask) >> 7


def build_access_key_pair(rng: SeededRNG, prefix: str = "AKIA") -> SecretSpec:
    key_id = encode_access_key_id(prefix, SYNTHETIC_AWS_ACCOUNT_ID, rng.derive("id"))
    secret_key = rng.derive("secret").token(_AWS_SECRET_ALPHABET, 40)

    secret_spec = SecretSpec(
        secret_type="aws-secret-access-key",
        category="generic",
        value=secret_key,
        assignment_key="AWS_SECRET_ACCESS_KEY",
        notes="40-char base64, no prefix; detection relies on entropy + context.",
    )
    return SecretSpec(
        secret_type="aws-access-key-id",
        category="structured",
        value=key_id,
        checksum_valid=None,
        assignment_key="AWS_ACCESS_KEY_ID",
        notes=(
            "no checksum exists for this format; account id "
            f"{SYNTHETIC_AWS_ACCOUNT_ID} is embedded and decodes to 0."
        ),
        companion=secret_spec,
    )


def build_temporary_access_key(rng: SeededRNG) -> SecretSpec:
    return build_access_key_pair(rng, prefix="ASIA")
