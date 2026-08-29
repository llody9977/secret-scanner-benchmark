"""Format-level invariants: checksums, encodings, and RNG determinism."""

from ssbench.formats import aws, github
from ssbench.formats.base import b62_encode_int, crc32_base62
from ssbench.rng import SeededRNG


def test_seeded_rng_is_reproducible():
    a = SeededRNG(123)
    b = SeededRNG(123)
    assert a.base62(40) == b.base62(40)
    assert a.derive("x").hexdigits(16) == b.derive("x").hexdigits(16)


def test_seeded_rng_derive_is_independent_of_call_order():
    root_a = SeededRNG(7)
    root_b = SeededRNG(7)
    # Consume an unrelated stream from root_b first.
    root_b.derive("unrelated").base62(50)
    assert root_a.derive("target").base62(20) == root_b.derive("target").base62(20)


def test_aws_access_key_encodes_account_zero():
    key = aws.build_access_key_pair(SeededRNG(1))
    assert key.value.startswith("AKIA")
    assert len(key.value) == 20
    assert aws.decode_account_id(key.value) == 0
    assert key.companion is not None
    assert len(key.companion.value) == 40


def test_aws_access_key_id_is_an_indicator_not_a_secret():
    """The id is half a credential, not a credential.

    It travels in cleartext in every signed request, so it cannot be scored as
    a planted secret; the 40-character secret access key beside it is the
    confidential half and carries the ground truth.
    """
    key = aws.build_access_key_pair(SeededRNG(1))
    assert key.is_secret is False
    assert key.secret_type == "aws-access-key-id"
    assert key.companion.is_secret is True
    assert key.companion.secret_type == "aws-secret-access-key"


def test_aws_temporary_key_id_is_also_an_indicator():
    key = aws.build_temporary_access_key(SeededRNG(3))
    assert key.value.startswith("ASIA")
    assert key.is_secret is False
    assert key.companion.is_secret is True


def test_github_valid_checksum_verifies():
    spec = github.build_token(SeededRNG(2), prefix="ghp", valid_checksum=True)
    assert spec.checksum_valid is True
    assert github.verify_token(spec.value) is True


def test_github_broken_checksum_fails_verification():
    spec = github.build_token(SeededRNG(2), prefix="ghp", valid_checksum=False)
    assert spec.checksum_valid is False
    assert github.verify_token(spec.value) is False
    # ...but the token still matches the shape a regex-only tool keys on.
    assert spec.value.startswith("ghp_")
    assert len(spec.value.split("_", 1)[1]) == 36


def test_b62_encode_int_width():
    assert len(b62_encode_int(0, 6)) == 6
    assert len(b62_encode_int(2**32 - 1, 6)) == 6
    assert crc32_base62("abc") == crc32_base62("abc")
