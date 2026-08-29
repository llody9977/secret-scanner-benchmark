"""Synthetic secret builders, grouped by provider family.

Every builder has the signature ``build_*(rng: SeededRNG, ...) -> SecretSpec``
and is pure: same seed in, same spec out.
"""
