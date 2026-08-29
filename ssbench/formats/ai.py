"""Synthetic AI-service credentials.

AI-service key formats are the fastest-growing detector category and the one
most likely to have a coverage gap: a detector only exists after someone writes
it. Several formats here (DeepSeek, Groq) are recent enough that older rulesets
miss them entirely.
"""

from __future__ import annotations

from ssbench.formats.base import SecretSpec
from ssbench.rng import SeededRNG

_ALNUM = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def build_openai_key(rng: SeededRNG) -> SecretSpec:
    body = rng.derive("body").token(_ALNUM, 48)
    return SecretSpec(
        secret_type="openai-api-key",
        category="structured",
        value=f"sk-{body}",
        assignment_key="OPENAI_API_KEY",
        notes="legacy sk- format.",
    )


def build_openai_project_key(rng: SeededRNG) -> SecretSpec:
    proj = rng.derive("proj").token(_ALNUM, 20)
    body = rng.derive("body").token(_ALNUM, 40)
    return SecretSpec(
        secret_type="openai-project-key",
        category="structured",
        value=f"sk-proj-{proj}T3BlbkFJ{body}",
        assignment_key="OPENAI_API_KEY",
        notes="sk-proj- format with the literal infix real keys carry.",
    )


def build_anthropic_key(rng: SeededRNG) -> SecretSpec:
    body = rng.derive("body").token(_ALNUM + "-_", 93)
    return SecretSpec(
        secret_type="anthropic-api-key",
        category="structured",
        value=f"sk-ant-api03-{body}AA",
        assignment_key="ANTHROPIC_API_KEY",
    )


def build_huggingface_token(rng: SeededRNG) -> SecretSpec:
    body = rng.derive("body").token(_ALNUM, 34)
    return SecretSpec(
        secret_type="huggingface-token",
        category="structured",
        value=f"hf_{body}",
        assignment_key="HUGGINGFACE_TOKEN",
    )


def build_deepseek_key(rng: SeededRNG) -> SecretSpec:
    body = rng.derive("body").hexdigits(32)
    return SecretSpec(
        secret_type="deepseek-api-key",
        category="structured",
        value=f"sk-{body}",
        assignment_key="DEEPSEEK_API_KEY",
        notes="sk- + 32 hex; collides in shape with other sk- formats.",
    )


def build_groq_key(rng: SeededRNG) -> SecretSpec:
    body = rng.derive("body").token(_ALNUM, 52)
    return SecretSpec(
        secret_type="groq-api-key",
        category="structured",
        value=f"gsk_{body}",
        assignment_key="GROQ_API_KEY",
    )


def build_cohere_key(rng: SeededRNG) -> SecretSpec:
    body = rng.derive("body").token(_ALNUM, 40)
    return SecretSpec(
        secret_type="cohere-api-key",
        category="generic",
        value=body,
        assignment_key="COHERE_API_KEY",
        notes="no distinctive prefix; detection depends on the variable name.",
    )
