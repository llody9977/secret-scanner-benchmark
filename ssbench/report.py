"""Render a :class:`ssbench.models.ScoreCard` to Markdown and to the console."""

from __future__ import annotations

from typing import List, Optional

from rich.console import Console
from rich.table import Table

from ssbench.models import Metrics, ScoreCard


def _pct(value: Optional[float]) -> str:
    return "—" if value is None else f"{value * 100:.1f}%"


def _metric_cells(m: Metrics) -> List[str]:
    return [str(m.tp), str(m.fp), str(m.fn), str(m.na), _pct(m.precision), _pct(m.recall), _pct(m.f1)]


def render_markdown(card: ScoreCard) -> str:
    lines: List[str] = []
    lines.append("# Benchmark results")
    lines.append("")
    lines.append(f"- Corpus seed: `{card.seed}`")
    lines.append(f"- Corpus HEAD: `{card.corpus_head_commit}`")
    lines.append(f"- Generator: `ssbench {card.generator_version}`")
    lines.append(f"- Planted secrets: **{card.planted_total}**  ·  Decoys: **{card.decoy_total}**")
    lines.append("")

    lines.append("## Per-tool totals")
    lines.append("")
    lines.append("| Tool | Version | Mode | TP | FP | FN | N/A | Precision | Recall | F1 |")
    lines.append("|------|---------|------|----|----|----|-----|-----------|--------|----|")
    for run in card.runs:
        cells = _metric_cells(run.overall)
        lines.append(
            f"| {run.tool} | {run.version} | {run.mode} | " + " | ".join(cells) + " |"
        )
    lines.append("")

    lines.append("## Headline")
    lines.append("")
    lines.append(f"- Planted secrets caught by **no tool**: **{len(card.caught_by_no_tool)}**")
    if card.caught_by_no_tool:
        lines.append(f"  - `{'`, `'.join(card.caught_by_no_tool)}`")
    lines.append(f"- Planted secrets caught by **exactly one tool**: **{len(card.caught_by_one_tool)}**")
    for pid, tool in card.caught_by_one_tool.items():
        lines.append(f"  - `{pid}` — only {tool}")
    lines.append("")

    for run in card.runs:
        lines.append(f"## {run.tool} ({run.mode}) — breakdown")
        lines.append("")
        lines.append("### By secret type")
        lines.append("")
        lines.append("| Secret type | TP | FP | FN | N/A | Precision | Recall | F1 |")
        lines.append("|-------------|----|----|----|-----|-----------|--------|----|")
        for name, m in run.by_secret_type.items():
            lines.append(f"| {name} | " + " | ".join(_metric_cells(m)) + " |")
        lines.append("")
        lines.append("### By placement")
        lines.append("")
        lines.append("| Placement | TP | FP | FN | N/A | Precision | Recall | F1 |")
        lines.append("|-----------|----|----|----|-----|-----------|--------|----|")
        for name, m in run.by_placement.items():
            lines.append(f"| {name} | " + " | ".join(_metric_cells(m)) + " |")
        lines.append("")
        if run.missed_planted_ids:
            lines.append(f"**Missed ({len(run.missed_planted_ids)}):** `{'`, `'.join(run.missed_planted_ids)}`")
            lines.append("")
        if run.decoys_triggered:
            lines.append(f"**Decoys triggered ({len(run.decoys_triggered)}):** `{'`, `'.join(run.decoys_triggered)}`")
            lines.append("")

    return "\n".join(lines) + "\n"


def print_console(card: ScoreCard, console: Optional[Console] = None) -> None:
    console = console or Console()
    table = Table(title=f"ssbench — seed {card.seed} — {card.planted_total} planted / {card.decoy_total} decoys")
    for col in ("Tool", "Mode", "TP", "FP", "FN", "N/A", "Precision", "Recall", "F1"):
        table.add_column(col, justify="right" if col not in ("Tool", "Mode") else "left")
    for run in card.runs:
        m = run.overall
        table.add_row(
            run.tool, run.mode, str(m.tp), str(m.fp), str(m.fn), str(m.na),
            _pct(m.precision), _pct(m.recall), _pct(m.f1),
        )
    console.print(table)
    console.print(f"[bold]Caught by no tool:[/] {len(card.caught_by_no_tool)}  "
                  f"[bold]Caught by exactly one:[/] {len(card.caught_by_one_tool)}")
    if card.caught_by_no_tool:
        console.print(f"  [dim]{', '.join(card.caught_by_no_tool)}[/]")
