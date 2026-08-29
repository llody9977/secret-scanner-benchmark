#!/usr/bin/env python3
"""Run the configured-control regression suite.

Materialises each template from ``regression/manifest.yaml`` into a temporary
directory, runs this repository's *configured* gate against it, and asserts
that the gate makes the control decision the manifest specifies.

This is not the benchmark. The benchmark (``scoring/score.py``) asks which tool
detects what, against stock configurations. This asks whether the gate this
repository has configured still does its job. A failure here is a broken
control, not an interesting result about a product.

Usage::

    python regression/run.py                 # assert; non-zero exit on failure
    python regression/run.py --json out.json # also write a machine-readable record
    python regression/run.py --gitleaks /path/to/gitleaks

Exit codes: 0 all scenarios as specified, 1 one or more control decisions
wrong, 2 the harness could not run (missing scanner, bad template).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from regression import shapes  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "regression" / "templates"
CONFIG = ROOT / "controls" / "gitleaks.toml"

# gitleaks --exit-code 1: 0 = clean, 1 = findings, anything else = the scanner
# itself failed. Conflating the third case with the first is the single most
# common way a pipeline reports green while scanning nothing; see part three.
CLEAN, FINDINGS = 0, 1


def materialise(seed: int, dest: Path) -> None:
    values = shapes.build(seed)
    for src in sorted(TEMPLATES.rglob("*")):
        if not src.is_file():
            continue
        rel = src.relative_to(TEMPLATES)
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        text = src.read_text(encoding="utf-8")
        out.write_text(shapes.render(text, values), encoding="utf-8")


def scan(gitleaks: str, target: Path, report: Path) -> Dict[str, object]:
    """One gate invocation, with the same flags the workflow uses."""
    proc = subprocess.run(
        [
            gitleaks, "dir",
            "--config", str(CONFIG),
            "--exit-code", str(FINDINGS),
            "--max-decode-depth", "1",
            "--no-banner",
            "--redact=100",
            "--report-format", "json",
            "--report-path", str(report),
            str(target),
        ],
        capture_output=True, text=True,
    )
    code = proc.returncode
    if code not in (CLEAN, FINDINGS):
        return {"error": f"gitleaks exited {code}: {proc.stderr.strip()[:400]}"}

    findings: List[dict] = []
    if report.exists() and report.stat().st_size:
        try:
            findings = json.loads(report.read_text(encoding="utf-8")) or []
        except json.JSONDecodeError as exc:
            return {"error": f"report was not valid JSON: {exc}"}

    return {
        "exit_code": code,
        "blocked": code == FINDINGS,
        "finding_count": len(findings),
        "detectors": sorted({f.get("RuleID", "") for f in findings} - {""}),
        "redacted": all(
            f.get("Secret", "") in ("", "REDACTED") or "REDACTED" in f.get("Secret", "")
            for f in findings
        ),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gitleaks", default=shutil.which("gitleaks"))
    ap.add_argument("--json", type=Path, help="write the observed record here")
    ap.add_argument("--manifest", type=Path, default=ROOT / "regression" / "manifest.yaml")
    args = ap.parse_args()

    if not args.gitleaks:
        print("gitleaks not found on PATH; install 8.30.1 or pass --gitleaks", file=sys.stderr)
        return 2
    if not CONFIG.exists():
        print(f"missing configured ruleset: {CONFIG}", file=sys.stderr)
        return 2

    manifest = yaml.safe_load(args.manifest.read_text(encoding="utf-8"))
    version = subprocess.run(
        [args.gitleaks, "version"], capture_output=True, text=True
    ).stdout.strip().splitlines()[-1]

    observed: List[dict] = []
    failures: List[str] = []

    with tempfile.TemporaryDirectory(prefix="ssbench-regression-") as tmp:
        work = Path(tmp)
        materialise(manifest["seed"], work / "corpus")

        for scenario in manifest["scenarios"]:
            target = work / "corpus" / scenario["target"]
            if not target.exists():
                print(f"missing materialised target: {scenario['target']}", file=sys.stderr)
                return 2

            # Scan each scenario in isolation so one fixture's finding cannot
            # be attributed to another's control decision.
            isolated = work / "scan" / scenario["id"]
            isolated.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, isolated / target.name)

            result = scan(args.gitleaks, isolated, work / f"{scenario['id']}.json")
            if "error" in result:
                print(f"{scenario['id']}: {result['error']}", file=sys.stderr)
                return 2

            expected_block = scenario["expected_control_decision"] == "block"
            ok = result["blocked"] == expected_block
            if not ok:
                failures.append(
                    f"{scenario['id']} ({scenario['credential_class']}): specified "
                    f"{scenario['expected_control_decision']}, gate "
                    f"{'blocked' if result['blocked'] else 'passed'}"
                )
            if result["blocked"] and not result["redacted"]:
                failures.append(
                    f"{scenario['id']}: the gate's report contained an unredacted value"
                )

            observed.append({
                "id": scenario["id"],
                "credential_class": scenario["credential_class"],
                "expected_control_decision": scenario["expected_control_decision"],
                "as_specified": ok,
                **{k: v for k, v in result.items() if k != "redacted"},
                "report_redacted": result["redacted"],
            })

    blocked = sum(1 for o in observed if o["blocked"])
    print(f"gitleaks {version} · config controls/gitleaks.toml")
    print(f"{len(observed)} scenarios · {blocked} blocked · "
          f"{len(observed) - blocked} passed · {len(failures)} not as specified")
    for o in observed:
        mark = "ok  " if o["as_specified"] else "FAIL"
        detectors = ", ".join(o["detectors"]) or "—"
        print(f"  {mark} {o['id']:<22} {o['expected_control_decision']:<6} {detectors}")

    if args.json:
        args.json.write_text(json.dumps({
            "schema_version": manifest["schema_version"],
            "seed": manifest["seed"],
            "scanner": "gitleaks",
            "scanner_version": version,
            "config": "controls/gitleaks.toml",
            "provider_checks_enabled": False,
            "secret_material_committed": False,
            "scenarios": observed,
            "failures": failures,
        }, indent=2) + "\n", encoding="utf-8")

    if failures:
        print("\nControl decisions not as specified:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
