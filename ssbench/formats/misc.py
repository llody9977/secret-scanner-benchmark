"""JWTs, database connection strings, service-account JSON, and generic secrets.

The generic group is where most real secrets actually live: a high-entropy
string with no vendor identity, or worse, a low-entropy password that no
entropy test will ever flag. The low-entropy case is marked
``expected_detectable=False`` — it is a structural miss for the whole category,
recorded so the scoring can separate "your tool failed" from "nothing can do
this".
"""

from __future__ import annotations

import base64
import json

from ssbench.formats.base import SecretSpec
from ssbench.rng import SeededRNG


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def build_jwt(rng: SeededRNG) -> SecretSpec:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(
        json.dumps(
            {"sub": "0000-benchmark", "name": "synthetic", "iat": 1735689600, "role": "corpus"},
            separators=(",", ":"),
        ).encode()
    )
    signature = _b64url(rng.derive("sig").bytes(32))
    return SecretSpec(
        secret_type="jwt-hs256",
        category="structured",
        value=f"{header}.{payload}.{signature}",
        assignment_key="AUTH_TOKEN",
        notes="HS256 JWT; signature is random bytes and verifies against nothing.",
    )


def build_postgres_uri(rng: SeededRNG, low_entropy: bool = False) -> SecretSpec:
    if low_entropy:
        password = "Autumn2026!"
        detectable = False
        note = "low-entropy password; expected miss for entropy-only detection."
    else:
        password = rng.derive("pw").base62(20)
        detectable = True
        note = "password is the sensitive part of the URI."
    return SecretSpec(
        secret_type="postgres-uri",
        category="generic",
        value=f"postgres://svc_app:{password}@db.internal.invalid:5432/appdb",
        assignment_key="DATABASE_URL",
        expected_detectable=detectable,
        notes=note,
    )


def build_mongodb_uri(rng: SeededRNG) -> SecretSpec:
    password = rng.derive("pw").base62(24)
    return SecretSpec(
        secret_type="mongodb-uri",
        category="generic",
        value=f"mongodb+srv://appuser:{password}@cluster0.aaaaa.mongodb.net/prod?retryWrites=true",
        assignment_key="MONGO_URI",
    )


def build_gcp_service_account(rng: SeededRNG, private_key_pem: str) -> SecretSpec:
    key_id = rng.derive("kid").hexdigits(40)
    client_id = rng.derive("cid").digits(21)
    blob = {
        "type": "service_account",
        "project_id": "benchmark-synthetic",
        "private_key_id": key_id,
        "private_key": private_key_pem + "\n",
        "client_email": "corpus@benchmark-synthetic.iam.gserviceaccount.com",
        "client_id": client_id,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
    return SecretSpec(
        secret_type="gcp-service-account-json",
        category="private-key",
        value=json.dumps(blob, indent=2),
        multiline=True,
        assignment_key="GOOGLE_APPLICATION_CREDENTIALS_JSON",
        notes="full service-account JSON; the private_key field is the secret.",
    )


def build_generic_hex_secret(rng: SeededRNG) -> SecretSpec:
    return SecretSpec(
        secret_type="generic-high-entropy-hex",
        category="generic",
        value=rng.derive("v").hexdigits(64),
        assignment_key="SECRET_KEY",
        notes="64 hex chars, no provider identity; entropy + context only.",
    )


def build_generic_b64_secret(rng: SeededRNG) -> SecretSpec:
    return SecretSpec(
        secret_type="generic-high-entropy-b64",
        category="generic",
        value=_b64url(rng.derive("v").bytes(32)),
        assignment_key="APP_TOKEN",
        notes="43-char base64url, no provider identity.",
    )


def build_internal_api_key(rng: SeededRNG) -> SecretSpec:
    return SecretSpec(
        secret_type="internal-service-key",
        category="generic",
        value=rng.derive("v").base62(32),
        assignment_key="PARTNER_API_KEY",
        notes="internal service credential; no vendor shape at all.",
    )


def build_low_entropy_password(rng: SeededRNG) -> SecretSpec:
    return SecretSpec(
        secret_type="low-entropy-password",
        category="generic",
        value="Summer2026!",
        assignment_key="db_password",
        expected_detectable=False,
        notes="the canonical case nothing catches: a memorable password.",
    )
