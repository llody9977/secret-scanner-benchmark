"""Where in the tree each secret goes, and how the containing file is built.

A placement is a single file plus the git visibility it implies. Several
secrets can share a placement; they are stacked in the file and each records
its own line number. Placements flagged ``history`` are only reachable by a
tool that walks git history — a working-tree-only scanner is scored N/A for
them, never as a miss.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from ssbench.formats.base import SecretSpec
from ssbench.obfuscation import render_secret_lines


@dataclass
class Placement:
    key: str
    path: str
    language: str
    history: bool = False
    # history detail
    depth: int = 0            # introduce this many commits before HEAD, then remove
    revert: bool = False      # add in one commit, remove in the next
    branch: str = "main"      # non-default branch name when not "main"
    special: str = ""         # "", "ipynb", "minified", "base64-blob", "json-fixture"


PLACEMENTS: Dict[str, Placement] = {
    "working-tree": Placement("working-tree", "src/app/config.py", "python"),
    "dotenv": Placement("dotenv", "deploy/.env.production", "env"),
    "json-fixture": Placement("json-fixture", "tests/fixtures/session.json", "json", special="json-fixture"),
    "jupyter-output": Placement("jupyter-output", "notebooks/explore.ipynb", "python", special="ipynb"),
    "dockerfile-env": Placement("dockerfile-env", "Dockerfile", "dockerfile"),
    "terraform-vars": Placement("terraform-vars", "infra/prod.tfvars", "hcl"),
    "ci-log-artifact": Placement("ci-log-artifact", "artifacts/deploy.log", "log"),
    "minified-bundle": Placement("minified-bundle", "public/assets/app.min.js", "js", special="minified"),
    "base64-blob": Placement("base64-blob", "config/bootstrap.b64", "python", special="base64-blob"),
    "history-depth": Placement("history-depth", "src/app/legacy_settings.py", "python", history=True, depth=6),
    "reverted-commit": Placement("reverted-commit", "src/app/hotfix.py", "python", history=True, revert=True),
    "non-default-branch": Placement(
        "non-default-branch", "src/app/payments.py", "python", history=True, branch="feature/payments"
    ),
}

_SCAFFOLD = {
    "python": ["\"\"\"Application configuration.\"\"\"", "", "import os", "", "DEBUG = os.getenv(\"DEBUG\") == \"1\"", ""],
    "env": ["# Production environment", "APP_ENV=production", ""],
    "hcl": ["environment = \"production\"", "region      = \"us-east-1\"", ""],
    "dockerfile": ["FROM python:3.12-slim", "WORKDIR /app", "COPY . .", ""],
    "log": ["2025-01-01T00:00:00Z INFO deploy: starting", "2025-01-01T00:00:00Z INFO deploy: image built", ""],
    "js": ["'use strict';", ""],
}


@dataclass
class RenderedFile:
    path: str
    language: str
    content: str
    # planted id -> 1-based line number of its first line
    line_map: Dict[str, int] = field(default_factory=dict)


Insertion = Tuple[str, SecretSpec, str]  # (planted_id, spec, obfuscation)


def _render_json_fixture(placement: Placement, insertions: List[Insertion]) -> RenderedFile:
    lines = ["{", '  "session": {', '    "user": "svc-account",']
    line_map: Dict[str, int] = {}
    for planted_id, spec, _ in insertions:
        line_map[planted_id] = len(lines) + 1
        value = spec.value.replace("\n", "\\n").replace('"', '\\"')
        lines.append(f'    "{spec.assignment_key}": "{value}",')
    lines.append('    "issued_at": "2025-01-01T00:00:00Z"')
    lines.append("  }")
    lines.append("}")
    return RenderedFile(placement.path, "json", "\n".join(lines) + "\n", line_map)


def _render_ipynb(placement: Placement, insertions: List[Insertion]) -> RenderedFile:
    planted_id, spec, _ = insertions[0]
    notebook = {
        "cells": [
            {
                "cell_type": "code",
                "execution_count": 1,
                "metadata": {},
                "outputs": [
                    {
                        "name": "stdout",
                        "output_type": "stream",
                        "text": [f"client configured with {spec.assignment_key}={spec.value}\n"],
                    }
                ],
                "source": ["client = connect()  # noqa\n", "print(client.describe())\n"],
            }
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "name": "python3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    text = json.dumps(notebook, indent=1)
    line_no = 1
    for i, ln in enumerate(text.splitlines(), start=1):
        if spec.value.split("\n")[0] in ln:
            line_no = i
            break
    return RenderedFile(placement.path, "json", text + "\n", {planted_id: line_no})


def _render_minified(placement: Placement, insertions: List[Insertion]) -> RenderedFile:
    segments = ["'use strict';var a=1"]
    for _, spec, _ in insertions:
        segments.append(f'var {spec.assignment_key}="{spec.value}"')
    segments.append("module.exports={a:a}")
    one_line = ";".join(segments) + ";"
    line_map = {planted_id: 1 for planted_id, _, _ in insertions}
    return RenderedFile(placement.path, "js", one_line + "\n", line_map)


def _render_base64_blob(placement: Placement, insertions: List[Insertion]) -> RenderedFile:
    import base64

    planted_id, spec, _ = insertions[0]
    inner = f"export {spec.assignment_key}={spec.value}\n"
    encoded = base64.b64encode(inner.encode("utf-8")).decode("ascii")
    body = "\n".join(encoded[i : i + 76] for i in range(0, len(encoded), 76))
    return RenderedFile(placement.path, "text", body + "\n", {planted_id: 1})


def _render_code(placement: Placement, insertions: List[Insertion]) -> RenderedFile:
    lang = placement.language
    lines = list(_SCAFFOLD.get(lang, ["# module", ""]))
    line_map: Dict[str, int] = {}
    for idx, (planted_id, spec, obf) in enumerate(insertions):
        comment = "#" if lang in ("python", "env", "yaml") else "//"
        if lang == "dockerfile":
            comment = "#"
        lines.append(f"{comment} region {idx}")
        rendered = render_secret_lines(spec, lang, obf, seed=idx)
        line_map[planted_id] = len(lines) + 1
        lines.extend(rendered)
        lines.append("")
    return RenderedFile(placement.path, lang, "\n".join(lines) + "\n", line_map)


def render_file(placement: Placement, insertions: List[Insertion]) -> RenderedFile:
    if not insertions:
        raise ValueError(f"placement {placement.key} has no insertions")
    if placement.special == "json-fixture":
        return _render_json_fixture(placement, insertions)
    if placement.special == "ipynb":
        return _render_ipynb(placement, insertions)
    if placement.special == "minified":
        return _render_minified(placement, insertions)
    if placement.special == "base64-blob":
        return _render_base64_blob(placement, insertions)
    return _render_code(placement, insertions)
