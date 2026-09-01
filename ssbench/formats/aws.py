"""Synthetic AWS credentials.

An AWS access key is a *pair*: an access key id (``AKIA…`` for a long-lived
IAM user key, ``ASIA…`` for an STS temporary one) and a 40-character secret
access key. Only the second half is confidential. AWS treats the id as an
identifier — it is transmitted in cleartext in every SigV4 ``Authorization``
header and appears in CloudTrail — while the secret access key is the value
that must never be disclosed, and the only one that can be regenerated
independently of the pair.

So this module plants the pair, but marks only the secret access key as a
planted secret. The id rides along as *unscored*: ``is_secret=False``, so
a scanner that never reports it loses no recall, and a scanner that does
report it is not charged a false positive. It is a real signal — it names the
account and the key to disable during response — but on its own it does not
authenticate anything, and scoring it as a secret would reward tools for
finding a value that is not one.

Access key ids have no checksum, so a scanner cannot validate one offline.
They do embed the account id (for keys issued since ~March 2019): the 16
characters after the prefix are RFC 4648 base32 of a 10-byte payload whose top
40 bits (after masking) are the account number. Every synthetic id here is
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
    """The id (unscored) with the secret access key (the planted secret) attached.

    The id is returned as the primary spec so that it is written to the file
    first, as it would be in a real ``.env`` or credentials block; the manifest
    splits them by ``is_secret``, not by position.
    """
    key_id = encode_access_key_id(prefix, SYNTHETIC_AWS_ACCOUNT_ID, rng.derive("id"))
    secret_key = rng.derive("secret").token(_AWS_SECRET_ALPHABET, 40)

    secret_spec = SecretSpec(
        secret_type="aws-secret-access-key",
        category="generic",
        value=secret_key,
        assignment_key="AWS_SECRET_ACCESS_KEY",
        notes="40-char base64, no prefix; detection relies on entropy + context. "
        "This is the confidential half of the pair — the planted secret.",
    )
    return SecretSpec(
        secret_type="aws-access-key-id",
        category="structured",
        value=key_id,
        checksum_valid=None,
        is_secret=False,
        assignment_key="AWS_ACCESS_KEY_ID",
        notes=(
            "identifier, not an authenticator: sent in cleartext in every SigV4 "
            "request, and useless without the paired secret access key. Scored as "
            "unscored, never as a planted secret. No checksum exists for this "
            f"format; account id {SYNTHETIC_AWS_ACCOUNT_ID} is embedded and decodes to 0."
        ),
        companion=secret_spec,
    )


def build_temporary_access_key(rng: SeededRNG) -> SecretSpec:
    return build_access_key_pair(rng, prefix="ASIA")
