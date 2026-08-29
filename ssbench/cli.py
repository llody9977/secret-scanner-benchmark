"""Command-line interface for the secret-scanner benchmark."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console

from ssbench import GENERATOR_VERSION
from ssbench.constants import DEFAULT_SEED
from ssbench.generate import generate as run_generate
from ssbench.models import RunIndex
from ssbench.report import print_console, render_markdown
from ssbench.score import load_manifest, score as run_score, verify_manifest_values

app = typer.Typer(add_completion=False, help="Reproducible secret-scanner benchmark.")
console = Console()


@app.command()
def generate(
    seed: int = typer.Option(DEFAULT_SEED, "--seed", "-s", help="Integer seed; the corpus is a pure function of it."),
    output: Path = typer.Option(Path("bench"), "--output", "-o", help="Directory for the generated scannable git repo."),
    record: bool = typer.Option(False, "--record", help="Also write corpus/manifest.yaml and corpus/seed."),
    corpus_dir: Path = typer.Option(Path("corpus"), "--corpus-dir", help="Where --record writes the committed manifest."),
) -> None:
    """Generate the synthetic corpus and its ground-truth manifest."""
    manifest = run_generate(seed, output, record_to=corpus_dir if record else None)
    console.print(f"[green]Generated[/] {manifest.stats.planted_total} planted secrets, "
                  f"{manifest.stats.decoy_total} decoys")
    console.print(f"  corpus:       {output}")
    console.print(f"  HEAD commit:  {manifest.corpus_head_commit}")
    console.print(f"  present at HEAD: {manifest.stats.present_at_head}   "
                  f"history-only: {manifest.stats.history_only}")
    bad = verify_manifest_values(manifest)
    if bad:
        console.print(f"[red]manifest hash mismatch for: {bad}[/]")
        raise typer.Exit(code=1)


@app.command()
def score(
    manifest: Path = typer.Option(..., "--manifest", "-m", help="Path to manifest.yaml."),
    results: Path = typer.Option(..., "--results", "-r", help="Directory holding index.yaml and each tool's report."),
    out: Path = typer.Option(Path("results"), "--out", "-o", help="Directory for results.json and results.md."),
) -> None:
    """Score scanner output in --results against the manifest."""
    manifest_model = load_manifest(manifest)
    bad = verify_manifest_values(manifest_model)
    if bad:
        console.print(f"[red]manifest is corrupt — hash mismatch for: {bad}[/]")
        raise typer.Exit(code=1)

    index_path = Path(results) / "index.yaml"
    if not index_path.exists():
        console.print(f"[red]missing {index_path}[/]")
        raise typer.Exit(code=1)
    run_index = RunIndex.model_validate(yaml.safe_load(index_path.read_text(encoding="utf-8")))

    card = run_score(manifest_model, run_index, Path(results))
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(card.model_dump(mode="json"), indent=2), encoding="utf-8")
    (out / "results.md").write_text(render_markdown(card), encoding="utf-8")
    print_console(card, console)
    console.print(f"[green]wrote[/] {out / 'results.json'}  {out / 'results.md'}")


@app.command()
def verify(
    manifest: Path = typer.Option(..., "--manifest", "-m", help="Path to manifest.yaml."),
    seed: Optional[int] = typer.Option(None, "--seed", "-s", help="If given, regenerate and compare HEAD commit."),
    workdir: Path = typer.Option(Path("bench-verify"), "--workdir", help="Scratch directory for regeneration."),
) -> None:
    """Check a manifest's internal consistency, optionally by regenerating."""
    manifest_model = load_manifest(manifest)
    bad = verify_manifest_values(manifest_model)
    if bad:
        console.print(f"[red]hash mismatch: {bad}[/]")
        raise typer.Exit(code=1)
    console.print(f"[green]manifest self-consistent[/] — {manifest_model.stats.planted_total} planted values hash OK")

    if seed is not None:
        regenerated = run_generate(seed, workdir)
        same = regenerated.corpus_head_commit == manifest_model.corpus_head_commit
        colour = "green" if same else "red"
        console.print(f"[{colour}]regenerated HEAD {'matches' if same else 'DIFFERS'}[/] "
                      f"({regenerated.corpus_head_commit})")
        if not same:
            raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print the generator version."""
    console.print(GENERATOR_VERSION)


if __name__ == "__main__":
    app()
