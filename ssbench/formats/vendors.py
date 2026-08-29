"""Synthetic tokens for common SaaS providers.

Where a provider offers a test-mode format (Stripe), the test-mode prefix is
used: a collision with a real test key only ever exposes a sandbox. Where it
does not, the token is generated from the deterministic RNG with an obviously
fabricated fixed segment (Slack's numeric team/user ids are all zeros).
"""

from __future__ import annotations

from ssbench.formats.base import SecretSpec
from ssbench.rng import SeededRNG

_STRIPE_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def build_stripe_secret_key(rng: SeededRNG) -> SecretSpec:
    body = rng.derive("body").token(_STRIPE_ALPHABET, 24)
    return SecretSpec(
        secret_type="stripe-secret-key",
        category="structured",
        value=f"sk_test_{body}",
        assignment_key="STRIPE_API_KEY",
        notes="test-mode secret key; live-mode format is identical with sk_live_.",
    )


def build_stripe_webhook_secret(rng: SeededRNG) -> SecretSpec:
    body = rng.derive("body").base64url(32).replace("-", "A").replace("_", "B")
    return SecretSpec(
        secret_type="stripe-webhook-secret",
        category="structured",
        value=f"whsec_{body}",
        assignment_key="STRIPE_WEBHOOK_SECRET",
        notes="webhook signing secret.",
    )


def build_slack_bot_token(rng: SeededRNG) -> SecretSpec:
    body = rng.derive("body").token(_STRIPE_ALPHABET, 24)
    return SecretSpec(
        secret_type="slack-bot-token",
        category="structured",
        value=f"xoxb-0000000000-0000000000000-{body}",
        assignment_key="SLACK_BOT_TOKEN",
        notes="numeric team/bot ids zeroed; only the trailing segment is random.",
    )


def build_slack_webhook_url(rng: SeededRNG) -> SecretSpec:
    tail = rng.derive("tail").token(_STRIPE_ALPHABET, 24)
    return SecretSpec(
        secret_type="slack-webhook-url",
        category="structured",
        value=f"https://hooks.slack.com/services/T00000000/B00000000/{tail}",
        assignment_key="SLACK_WEBHOOK_URL",
        notes="incoming-webhook URL; the path tail is the secret.",
    )


def build_sendgrid_key(rng: SeededRNG) -> SecretSpec:
    part1 = rng.derive("p1").base64url(22)
    part2 = rng.derive("p2").base64url(43)
    return SecretSpec(
        secret_type="sendgrid-api-key",
        category="structured",
        value=f"SG.{part1}.{part2}",
        assignment_key="SENDGRID_API_KEY",
    )


def build_google_api_key(rng: SeededRNG) -> SecretSpec:
    body = rng.derive("body").base64url(35)
    return SecretSpec(
        secret_type="google-api-key",
        category="structured",
        value=f"AIza{body}",
        assignment_key="GOOGLE_API_KEY",
    )


def build_npm_token(rng: SeededRNG) -> SecretSpec:
    body = rng.derive("body").hexdigits(36)
    # npm tokens are UUID-shaped; hyphenate to match the real layout.
    hexed = f"{body[:8]}-{body[8:12]}-{body[12:16]}-{body[16:20]}-{body[20:32]}"
    return SecretSpec(
        secret_type="npm-access-token",
        category="structured",
        value=f"npm_{rng.derive('prefix').base62(36)}",
        assignment_key="NPM_TOKEN",
        notes=f"granular access token format; legacy UUID form would be {hexed}.",
    )
