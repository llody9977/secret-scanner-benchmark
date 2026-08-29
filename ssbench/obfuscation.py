"""Render a secret into source lines, optionally obfuscated.

Obfuscation here is almost always accidental in the wild — developers split a
long string for line length, not to evade a scanner — which is exactly why it
is common. Each transform below defeats naive regex matching without any
sophistication.

Only single-line secrets are obfuscated. Multiline secrets (PEM blocks,
service-account JSON) are always written verbatim.
"""

from __future__ import annotations

from typing import Callable, Dict, List

from ssbench.formats.base import SecretSpec

OBFUSCATIONS = (
    "plain",
    "concat",
    "array-join",
    "meaningless-var",
    "value-next-line",
)

_MEANINGLESS = ("cfg7", "_x", "d0", "tmp2", "q")


def _split(value: str, parts: int) -> List[str]:
    if parts <= 1 or len(value) < parts:
        return [value]
    size = len(value) // parts
    chunks = [value[i * size : (i + 1) * size] for i in range(parts - 1)]
    chunks.append(value[(parts - 1) * size :])
    return chunks


def _render_python(spec: SecretSpec, obf: str, seed: int) -> List[str]:
    key = spec.assignment_key
    v = spec.value
    if obf == "plain":
        return [f'{key} = "{v}"']
    if obf == "concat":
        a, b = _split(v, 2)
        return [f'{key} = "{a}" \\', f'    "{b}"']
    if obf == "array-join":
        parts = _split(v, 3)
        joined = ", ".join(f'"{p}"' for p in parts)
        return [f"_parts = [{joined}]", f'{key} = "".join(_parts)']
    if obf == "meaningless-var":
        name = _MEANINGLESS[seed % len(_MEANINGLESS)]
        return [f'{name} = "{v}"']
    if obf == "value-next-line":
        return [f"{key} = (", f'    "{v}"', ")"]
    raise ValueError(obf)


def _render_env(spec: SecretSpec, obf: str, seed: int) -> List[str]:
    # dotenv has no expression syntax; only plain and value-next-line make sense.
    key = spec.assignment_key.upper()
    if obf == "value-next-line":
        return [f"{key}=\\", spec.value]
    return [f"{key}={spec.value}"]


def _render_yaml(spec: SecretSpec, obf: str, seed: int) -> List[str]:
    key = spec.assignment_key
    if obf == "value-next-line":
        return [f"{key}:", f"  {spec.value}"]
    return [f"{key}: {spec.value}"]


def _render_js(spec: SecretSpec, obf: str, seed: int) -> List[str]:
    key = spec.assignment_key
    v = spec.value
    if obf == "concat":
        a, b = _split(v, 2)
        return [f'const {key} = "{a}" +', f'  "{b}";']
    if obf == "array-join":
        parts = _split(v, 3)
        joined = ", ".join(f'"{p}"' for p in parts)
        return [f"const {key} = [{joined}].join('');"]
    if obf == "meaningless-var":
        name = _MEANINGLESS[seed % len(_MEANINGLESS)]
        return [f'const {name} = "{v}";']
    return [f'const {key} = "{v}";']


def _render_hcl(spec: SecretSpec, obf: str, seed: int) -> List[str]:
    return [f'{spec.assignment_key} = "{spec.value}"']


def _render_dockerfile(spec: SecretSpec, obf: str, seed: int) -> List[str]:
    return [f"ENV {spec.assignment_key.upper()}={spec.value}"]


def _render_log(spec: SecretSpec, obf: str, seed: int) -> List[str]:
    return [f"2025-01-01T00:00:00Z INFO deploy: using {spec.assignment_key}={spec.value}"]


_RENDERERS: Dict[str, Callable[[SecretSpec, str, int], List[str]]] = {
    "python": _render_python,
    "env": _render_env,
    "yaml": _render_yaml,
    "js": _render_js,
    "hcl": _render_hcl,
    "dockerfile": _render_dockerfile,
    "log": _render_log,
}


def render_secret_lines(spec: SecretSpec, language: str, obfuscation: str, seed: int) -> List[str]:
    """Return the source line(s) that embed ``spec`` in the given language."""
    if spec.multiline:
        return spec.value.splitlines()
    renderer = _RENDERERS.get(language, _render_python)
    if obfuscation not in OBFUSCATIONS:
        raise ValueError(f"unknown obfuscation: {obfuscation}")
    return renderer(spec, obfuscation, seed)
