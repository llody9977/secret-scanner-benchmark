"""Shared types and encoders for synthetic secret builders.

Each builder takes a :class:`~ssbench.rng.SeededRNG` and returns a
:class:`SecretSpec`. The spec carries the sensitive substring (``value``) plus
enough metadata for the manifest. Placement and obfuscation are applied later.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from typing import Optional

from ssbench.rng import BASE62


@dataclass
class SecretSpec:
    """A single synthetic credential, before it is placed into a file."""

    secret_type: str
    category: str  # "structured" | "generic" | "private-key"
    value: str
    checksum_valid: Optional[bool] = None
    expected_detectable: bool = True
    # False marks a credential *identifier* rather than an authenticator: a
    # value that is part of a credential but is not itself confidential, and so
    # cannot be a planted secret. An AWS access key id is the case that matters
    # here. Missing one is not a miss; reporting one is not a false positive.
    is_secret: bool = True
    # When is_secret is False, why: "identifier" (half a credential, sent in
    # the clear) or "malformed" (right shape, cannot authenticate).
    unscored_reason: str = "identifier"
    multiline: bool = False
    # For multiline secrets (PEM blocks, service-account JSON) the value is
    # written more or less verbatim; ``assignment_key`` names the variable used
    # for single-line secrets when the placement is code.
    assignment_key: str = "api_key"
    notes: str = ""
    # Optional companion secret planted on an adjacent line (e.g. an AWS access
    # key id alongside its secret access key).
    companion: Optional["SecretSpec"] = field(default=None)


def b62_encode_int(value: int, width: int) -> str:
    """Big-endian base62 encoding, left zero-padded to ``width`` characters."""
    if value < 0:
        raise ValueError("value must be non-negative")
    if value == 0:
        digits = "0"
    else:
        out = []
        n = value
        while n:
            n, rem = divmod(n, 62)
            out.append(BASE62[rem])
        digits = "".join(reversed(out))
    return digits.rjust(width, "0")[-width:]


def crc32_base62(payload: str, width: int = 6) -> str:
    """The GitHub token checksum: base62(CRC32(body)), padded to ``width``."""
    crc = binascii.crc32(payload.encode("ascii")) & 0xFFFFFFFF
    return b62_encode_int(crc, width)


def b32_encode_nopad(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii").rstrip("=")


def b32_decode_nopad(text: str) -> bytes:
    pad = "=" * ((8 - len(text) % 8) % 8)
    return base64.b32decode(text + pad)


def flip_one_char(text: str, rng, alphabet: str) -> str:
    """Deterministically replace one character with a different one.

    Used to break an otherwise-valid checksum so a validating scanner rejects
    the token while a naive regex scanner still matches it.
    """
    if not text:
        return text
    idx = rng.randint(0, len(text) - 1)
    current = text[idx]
    replacement = current
    while replacement == current:
        replacement = rng.choice(alphabet)
    return text[:idx] + replacement + text[idx + 1 :]
