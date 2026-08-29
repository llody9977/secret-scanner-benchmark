"""The corpus plan: which secret goes where, and how it is written.

This is the design of the benchmark. The RNG fills in values; this file fixes
the matrix of (secret type x placement x obfuscation) so the corpus exercises
every documented failure mode at least once:

* structured-with-checksum, both valid and deliberately broken (GitHub)
* structured-without-checksum (AWS, Stripe, Slack, SendGrid, Google, AI keys)
* private keys, with and without PEM armour
* generic high-entropy, and low-entropy (the known universal miss)
* every placement in :mod:`ssbench.placements`, including history-only ones
* every obfuscation in :mod:`ssbench.obfuscation`
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict

from ssbench.formats import ai, aws, github, keys, misc, vendors
from ssbench.formats.base import SecretSpec
from ssbench.rng import SeededRNG


@dataclass
class PlanEntry:
    id: str
    builder: Callable[..., SecretSpec]
    placement: str
    obfuscation: str = "plain"
    kwargs: Dict[str, object] = field(default_factory=dict)


def build_plan() -> list:
    e = PlanEntry
    return [
        # --- structured, with a checksum: the separator test -----------------
        e("gh-pat-valid", github.build_token, "working-tree", "plain", {"prefix": "ghp", "valid_checksum": True}),
        e("gh-pat-broken", github.build_token, "working-tree", "plain", {"prefix": "ghp", "valid_checksum": False}),
        e("gh-server-valid", github.build_token, "dotenv", "plain", {"prefix": "ghs", "valid_checksum": True}),
        e("gh-oauth-broken", github.build_token, "json-fixture", "plain", {"prefix": "gho", "valid_checksum": False}),
        e("gh-fine-grained", github.build_fine_grained_pat, "terraform-vars", "plain"),

        # --- structured, no checksum ----------------------------------------
        e("aws-key-plain", aws.build_access_key_pair, "working-tree", "plain"),
        e("aws-key-concat", aws.build_access_key_pair, "minified-bundle", "concat"),
        e("aws-temp-key", aws.build_temporary_access_key, "ci-log-artifact", "plain"),
        e("stripe-secret", vendors.build_stripe_secret_key, "dotenv", "plain"),
        e("stripe-webhook", vendors.build_stripe_webhook_secret, "terraform-vars", "plain"),
        e("slack-bot", vendors.build_slack_bot_token, "working-tree", "meaningless-var"),
        e("slack-webhook", vendors.build_slack_webhook_url, "dockerfile-env", "plain"),
        e("sendgrid", vendors.build_sendgrid_key, "json-fixture", "plain"),
        e("google-api", vendors.build_google_api_key, "jupyter-output", "plain"),
        e("npm-token", vendors.build_npm_token, "dotenv", "plain"),

        # --- AI-service keys ----------------------------------------------
        e("openai-legacy", ai.build_openai_key, "working-tree", "value-next-line"),
        e("openai-proj", ai.build_openai_project_key, "dotenv", "plain"),
        e("anthropic", ai.build_anthropic_key, "terraform-vars", "plain"),
        e("huggingface", ai.build_huggingface_token, "ci-log-artifact", "plain"),
        e("deepseek", ai.build_deepseek_key, "json-fixture", "plain"),
        e("groq", ai.build_groq_key, "minified-bundle", "plain"),
        e("cohere-noprefix", ai.build_cohere_key, "working-tree", "plain"),

        # --- private keys -----------------------------------------------
        e("rsa-key", keys.build_private_key, "dotenv", "plain", {"kind": "rsa-2048"}),
        e("ed25519-key-headerless", keys.build_private_key, "base64-blob", "plain",
          {"kind": "ed25519", "headerless": True}),
        e("ec-key", keys.build_private_key, "working-tree", "plain", {"kind": "ec-p256"}),
        e("openssh-key", keys.build_private_key, "json-fixture", "plain", {"kind": "openssh"}),

        # --- JWT, DB, service-account JSON --------------------------------
        e("jwt", misc.build_jwt, "ci-log-artifact", "plain"),
        e("postgres-uri", misc.build_postgres_uri, "dotenv", "plain"),
        e("postgres-uri-lowent", misc.build_postgres_uri, "working-tree", "plain", {"low_entropy": True}),
        e("mongodb-uri", misc.build_mongodb_uri, "terraform-vars", "plain"),

        # --- generic ---------------------------------------------------
        e("generic-hex", misc.build_generic_hex_secret, "working-tree", "plain"),
        e("generic-b64", misc.build_generic_b64_secret, "dockerfile-env", "plain"),
        e("internal-key", misc.build_internal_api_key, "json-fixture", "meaningless-var"),
        e("low-entropy-pw", misc.build_low_entropy_password, "working-tree", "plain"),

        # --- history-only placements ----------------------------------
        e("hist-aws", aws.build_access_key_pair, "history-depth", "plain"),
        e("hist-gh-valid", github.build_token, "history-depth", "plain", {"prefix": "ghp", "valid_checksum": True}),
        e("hist-openai", ai.build_openai_key, "history-depth", "array-join"),
        e("revert-stripe", vendors.build_stripe_secret_key, "reverted-commit", "plain"),
        e("revert-generic", misc.build_generic_hex_secret, "reverted-commit", "plain"),
        e("branch-anthropic", ai.build_anthropic_key, "non-default-branch", "plain"),
        e("branch-ec384", keys.build_private_key, "non-default-branch", "plain", {"kind": "ec-p384"}),
    ]
