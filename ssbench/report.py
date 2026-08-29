"""Render a :class:`ssbench.models.ScoreCard` to Markdown and to the console."""

from __future__ import annotations

from typing import List, Optional

from rich.console import Console
from rich.table import Table

from ssbench.models import CoverageAnalysis, Metrics, ScoreCard


def _pct(value: Optional[float]) -> str:
    return "—" if value is None else f"{value * 100:.1f}%"


def _metric_cells(m: Metrics) -> List[str]:
    return [str(m.tp), str(m.fp), str(m.fn), str(m.na), _pct(m.precision), _pct(m.recall), _pct(m.f1)]


def _coverage_markdown(cov: CoverageAnalysis) -> List[str]:
    out: List[str] = []
    out.append("## Cross-tool coverage")
    out.append("")
    out.append(
        f"Across the {len(cov.tools)} default-mode tools, **{cov.union_caught} of "
        f"{cov.planted_total}** planted secrets are caught by at least one tool."
    )
    if cov.union_missed:
        out.append(f"The {len(cov.union_missed)} that nothing catches: "
                   f"`{'`, `'.join(cov.union_missed)}`.")
    out.append("")
    out.append("| Tool | Caught | Unique | Only-this-tool ids |")
    out.append("|------|-------:|-------:|-------------------|")
    for t in sorted(cov.tools, key=lambda x: -cov.per_tool_caught[x]):
        uniq = cov.per_tool_unique.get(t, [])
        ids = "`" + "`, `".join(uniq) + "`" if uniq else "—"
        out.append(f"| {t} | {cov.per_tool_caught[t]}/{cov.planted_total} | {len(uniq)} | {ids} |")
    out.append("")
    if cov.dominates:
        for a, covered in cov.dominates.items():
            out.append(f"- **{a}** catches everything {', '.join(covered)} "
                       f"catch{'es' if len(covered) == 1 else ''}, and more.")
        out.append("")
    if cov.best_pair:
        a, b, n = cov.best_pair
        out.append(f"- Best two-tool combination: **{a} + {b}** → {n}/{cov.planted_total}.")
    if cov.minimal_cover:
        joined = " + ".join(cov.minimal_cover)
        out.append(f"- Smallest set reaching {cov.union_caught}/{cov.planted_total}: "
                   f"**{joined}** ({len(cov.minimal_cover)} tool"
                   f"{'s' if len(cov.minimal_cover) != 1 else ''}).")
    out.append("")
    return out


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
    lines.append("`Σ` = TP + FN + N/A, which must equal the planted total "
                 f"({card.planted_total}) for every row — every planted secret is exactly one "
                 "of caught, missed, or out-of-reach. FP is a separate axis (findings matching "
                 f"nothing planted; bounded by the {card.decoy_total} decoys plus spurious noise).")
    lines.append("")
    lines.append("| Tool | Version | Mode | TP | FP | FN | N/A | Σ | Precision | Recall | F1 |")
    lines.append("|------|---------|------|----|----|----|-----|---|-----------|--------|----|")
    for run in card.runs:
        m = run.overall
        cells = [str(m.tp), str(m.fp), str(m.fn), str(m.na), str(m.planted),
                 _pct(m.precision), _pct(m.recall), _pct(m.f1)]
        lines.append(f"| {run.tool} | {run.version} | {run.mode} | " + " | ".join(cells) + " |")
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

    if card.coverage:
        lines.extend(_coverage_markdown(card.coverage))

    for run in card.runs:
        lines.append(f"## {run.tool} ({run.mode}) — breakdown")
        lines.append("")
        lines.append(f"TP {run.overall.tp} · FP {run.overall.fp} · FN {run.overall.fn} · "
                     f"N/A {run.overall.na} · Σ {run.overall.planted}/{run.planted_total} · "
                     f"decoys triggered {len(run.decoys_triggered)}/{run.decoy_total}")
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
    for col in ("Tool", "Mode", "TP", "FP", "FN", "N/A", "Σ", "Precision", "Recall", "F1"):
        table.add_column(col, justify="right" if col not in ("Tool", "Mode") else "left")
    for run in card.runs:
        m = run.overall
        sigma = f"{m.planted}" if m.planted == run.planted_total else f"[red]{m.planted}![/]"
        table.add_row(
            run.tool, run.mode, str(m.tp), str(m.fp), str(m.fn), str(m.na), sigma,
            _pct(m.precision), _pct(m.recall), _pct(m.f1),
        )
    console.print(table)
    console.print(f"[dim]Σ (TP+FN+N/A) must equal {card.planted_total} on every row.[/]")

    cov = card.coverage
    if cov:
        console.print(f"\n[bold]Union coverage:[/] {cov.union_caught}/{cov.planted_total} "
                      f"caught by ≥1 tool")
        for t in sorted(cov.tools, key=lambda x: -cov.per_tool_caught[x]):
            u = cov.per_tool_unique.get(t, [])
            extra = f"  [yellow]unique: {', '.join(u)}[/]" if u else ""
            console.print(f"  {t:14} {cov.per_tool_caught[t]:>2}/{cov.planted_total}{extra}")
        if cov.minimal_cover:
            console.print(f"  [bold]minimal set:[/] {' + '.join(cov.minimal_cover)} "
                          f"→ {cov.union_caught}/{cov.planted_total}")
    console.print(f"\n[bold]Caught by no tool:[/] {len(card.caught_by_no_tool)}  "
                  f"[bold]Caught by exactly one:[/] {len(card.caught_by_one_tool)}")
    if card.caught_by_no_tool:
        console.print(f"  [dim]{', '.join(card.caught_by_no_tool)}[/]")
