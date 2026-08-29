"""Placeholder values for the configured-control regression templates.

Every value here is fabricated from a committed seed and matches nothing that
was ever issued. They exist so that the regression templates in
``regression/templates/`` can be committed with ``{{PLACEHOLDER}}`` tokens
instead of literal credential-shaped strings: this repository is mirrored and
forked, and a checked-in file full of credential shapes is a push-protection
and secret-scanning landmine for everyone downstream. The same reasoning
redacts ``corpus/manifest.yaml``; see ``SECURITY.md``.

The values are materialised only into a temporary directory by
``regression/run.py``, and only for as long as the scan takes.
"""

from __future__ import annotations

import base64
from typing import Callable, Dict

from ssbench.formats import aws, github, keys
from ssbench.rng import SeededRNG

# The fictional internal format the configured ruleset adds a rule for. Fixed
# rather than random: the rule regex is `DEMO_[A-Z0-9]{32}` and the point of
# the scenario is to prove that this exact rule fires, so a value that drifts
# would make a rule failure and a value failure indistinguishable.
_DEMO_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_HEX = "0123456789abcdef"


def _demo_token(rng: SeededRNG) -> str:
    return "DEMO_" + rng.token(_DEMO_ALPHABET, 32)


def _password(rng: SeededRNG) -> str:
    return "P9-" + rng.hexdigits(29)


def build(seed: int) -> Dict[str, str]:
    """Return every ``{{PLACEHOLDER}}`` value for one seed."""
    root = SeededRNG(seed)

    aws_pair = aws.build_access_key_pair(root.derive("aws"))
    demo = _demo_token(root.derive("demo"))
    password = _password(root.derive("password"))
    rsa = keys.build_private_key(root.derive("rsa"), kind="rsa-2048")
    openssh = keys.build_private_key(root.derive("openssh"), kind="openssh")

    basic = base64.b64encode(f"demo-user:{password}".encode()).decode()

    jwt_rng = root.derive("jwt")
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = (
        base64.urlsafe_b64encode(b'{"sub":"demo-user","exp":4102444800}').decode().rstrip("=")
    )
    signature = jwt_rng.base64url(43)

    return {
        # --- AWS: the pair, and the two halves separately -------------------
        # Note the asymmetry the benchmark's ground-truth correction makes
        # explicit: the id is an identifier, the secret access key is the
        # credential. The split scenarios exist to show what each gate does
        # when it sees only one of them.
        "AWS_KEY_ID": aws_pair.value,
        "AWS_SECRET": aws_pair.companion.value,
        # --- the repository-only internal format ----------------------------
        "DEMO_TOKEN": demo,
        "DEMO_TOKEN_B64": base64.b64encode(demo.encode()).decode(),
        # --- vendor shapes ---------------------------------------------------
        "GITHUB_PAT": github.build_token(root.derive("gh"), prefix="ghp", valid_checksum=True).value,
        "MAILCHIMP_KEY": root.derive("mailchimp").token(_HEX, 32) + "-us99",
        "OAUTH_SECRET": root.derive("oauth").token(_B64_ALPHABET, 40),
        # --- generic shapes --------------------------------------------------
        "PASSWORD": password,
        "BASIC_B64": basic,
        "JWT": f"{header}.{payload}.{signature}",
        "SYMMETRIC_KEY": root.derive("symmetric").hexdigits(64),
        "WEBHOOK_SECRET": root.derive("webhook").token(_B64_ALPHABET, 40),
        # --- private keys ----------------------------------------------------
        "RSA_KEY": rsa.value,
        "OPENSSH_KEY": openssh.value,
        "SA_KEY_ID": root.derive("sa").hexdigits(40),
    }


def render(template: str, values: Dict[str, str]) -> str:
    """Expand ``{{NAME}}`` and ``{{NAME|indentN}}`` tokens in a template."""
    import re

    def _sub(match: "re.Match[str]") -> str:
        name, _, filt = match.group(1).partition("|")
        try:
            value = values[name]
        except KeyError:
            raise KeyError(f"no value for placeholder {{{{{name}}}}}") from None
        if filt.startswith("indent"):
            pad = " " * int(filt[len("indent"):])
            return "\n".join(pad + line for line in value.splitlines())
        if filt:
            raise ValueError(f"unknown placeholder filter: {filt}")
        return value

    return re.sub(r"\{\{([A-Z0-9_]+(?:\|[a-z0-9]+)?)\}\}", _sub, template)


PLACEHOLDERS: Callable[[int], Dict[str, str]] = build
