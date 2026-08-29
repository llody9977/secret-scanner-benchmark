"""Deterministic pseudo-random generation for the benchmark corpus.

The corpus must be regenerable byte-for-byte from a single committed integer
seed so a reviewer can verify that nothing was hand-planted. ``SeededRNG``
wraps :class:`random.Random` (a Mersenne Twister, stable across CPython
versions and platforms) and adds a :meth:`derive` method that forks an
independent sub-stream keyed by a label. Deriving per planting means adding a
new secret type to the plan does not perturb the values of the existing ones.

This generator is emphatically *not* a CSPRNG and must never be used to mint a
real credential. That is the point: the output is predictable.
"""

from __future__ import annotations

import hashlib
import random
from typing import List, Sequence, TypeVar

T = TypeVar("T")

BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
BASE62_LOWER = "0123456789abcdefghijklmnopqrstuvwxyz"
HEX_LOWER = "0123456789abcdef"
BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
BASE32_RFC4648 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


class SeededRNG:
    """A labelled, forkable deterministic random source."""

    def __init__(self, seed: int) -> None:
        self._seed = int(seed)
        self._random = random.Random(self._seed)

    @property
    def seed(self) -> int:
        return self._seed

    def derive(self, label: str) -> "SeededRNG":
        """Return an independent sub-stream deterministically keyed by ``label``."""
        digest = hashlib.sha256(f"{self._seed}:{label}".encode("utf-8")).digest()
        return SeededRNG(int.from_bytes(digest[:8], "big"))

    def bytes(self, count: int) -> bytes:
        if count <= 0:
            return b""
        return self._random.getrandbits(count * 8).to_bytes(count, "big")

    def token(self, alphabet: str, length: int) -> str:
        if length <= 0:
            return ""
        return "".join(self._random.choice(alphabet) for _ in range(length))

    def base62(self, length: int) -> str:
        return self.token(BASE62, length)

    def base62_lower(self, length: int) -> str:
        return self.token(BASE62_LOWER, length)

    def hexdigits(self, length: int) -> str:
        return self.token(HEX_LOWER, length)

    def base64url(self, length: int) -> str:
        return self.token(BASE64URL, length)

    def digits(self, length: int) -> str:
        return self.token("0123456789", length)

    def randint(self, low: int, high: int) -> int:
        return self._random.randint(low, high)

    def choice(self, seq: Sequence[T]) -> T:
        return self._random.choice(list(seq))

    def sample(self, seq: Sequence[T], k: int) -> List[T]:
        return self._random.sample(list(seq), k)

    def shuffled(self, seq: Sequence[T]) -> List[T]:
        items = list(seq)
        self._random.shuffle(items)
        return items
