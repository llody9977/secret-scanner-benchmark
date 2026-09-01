"""The published pages are hand-maintained, so nothing stops a figure from going
stale when a rescore lands. Run #7 changed every number in the field and the
propagation was manual, which is how a chapter kept quoting a planted total of
41 after the total became 39.

`docs/figures.json` is the single source. These tests assert that the prose
agrees with it, and that no page quotes a figure a later scoring generation
retired. Update `figures.json` first; the failures then point at every page that
still needs the change.
"""

import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
FIGURES = json.loads((DOCS / "figures.json").read_text())

# `part-*.html` are redirect stubs and carry no figures.
PAGES = sorted(p for p in DOCS.glob("*.html") if not p.name.startswith("part-"))
PROSE = PAGES + [DOCS / "RESULTS.md"]


def _text(path: pathlib.Path) -> str:
    """Page text with the deliberately narrated corrections removed, so the
    sentence that tells the reader the total *used* to be 41 does not read as a
    page that still thinks it is 41."""
    body = path.read_text()
    for allowed in FIGURES["retired"]["allowed_context"]:
        body = body.replace(allowed, "")
    return body


def test_figures_file_is_internally_consistent():
    planted = FIGURES["ground_truth"]["planted"]
    for row in FIGURES["tools"]:
        # The scorer enforces this on the run; assert it on the published table
        # too, because a hand-edited row can break it silently.
        assert row["tp"] + row["fn"] + row["na"] == planted, row["tool"]
        assert row["sigma"] == planted, row["tool"]

    coverage = FIGURES["coverage"]
    best = max(r["tp"] for r in FIGURES["tools"])
    assert coverage["best_single"] == best
    assert coverage["union"] + coverage["caught_by_no_tool"] == planted
    assert coverage["union"] >= best


@pytest.mark.parametrize("path", PROSE, ids=lambda p: p.name)
def test_no_page_quotes_a_retired_figure(path):
    body = _text(path)
    stale = []
    for pattern in FIGURES["retired"]["patterns"]:
        for match in re.finditer(pattern, body):
            start = max(0, match.start() - 70)
            stale.append(f"{pattern!r} in ...{body[start:match.end() + 70]}...")
    assert not stale, f"{path.name} quotes retired figures:\n" + "\n".join(stale)


@pytest.mark.parametrize("path", PROSE, ids=lambda p: p.name)
def test_planted_total_is_never_contradicted(path):
    """Any page that states a planted total must state the current one."""
    planted = FIGURES["ground_truth"]["planted"]
    body = _text(path)
    for match in re.finditer(r"(\d+)[- ](?:planted )?secrets? synthetic|(\d+) planted secrets", body):
        stated = int(match.group(1) or match.group(2))
        assert stated == planted, f"{path.name} states a planted total of {stated}"


def test_results_table_matches_the_figures_file():
    body = (DOCS / "RESULTS.md").read_text()
    for row in FIGURES["tools"]:
        pattern = (
            rf"^\|\s*{re.escape(row['tool'])}\s*\|\s*{re.escape(row['version'])}\s*\|"
            rf"\s*{re.escape(row['mode'])}\s*\|\s*{row['tp']}\s*\|\s*{row['fp']}\s*\|"
            rf"\s*{row['fn']}\s*\|\s*{row['na']}\s*\|"
        )
        assert re.search(pattern, body, re.M), f"RESULTS.md row drifted: {row['tool']} {row['mode']}"


def test_run_provenance_names_the_actual_ci_run():
    """The provenance pointed at a commit that predated the ground-truth
    correction, which made the figures untraceable to the run that produced
    them."""
    run = FIGURES["run"]
    results = (DOCS / "RESULTS.md").read_text()
    sources = (DOCS / "sources.html").read_text()
    for body, name in ((results, "RESULTS.md"), (sources, "sources.html")):
        assert run["commit"] in body, f"{name} does not name commit {run['commit']}"
        assert str(run["workflow_run_id"]) in body, f"{name} does not link workflow run {run['workflow_run']}"


def test_checksum_finding_matches_the_data():
    """All six tools reported both broken-CRC32 tokens, which is derivable from
    the published table: every tool reports at least the two malformed values."""
    malformed = FIGURES["ground_truth"]["unscored_reasons"]["malformed"]
    scored = [r for r in FIGURES["tools"] if r["mode"] != "verified-only"]
    assert len(scored) == FIGURES["findings"]["tools_reporting_both_malformed_tokens"]
    for row in scored:
        reported = int(row["unscored"].split("/")[0])
        assert reported >= malformed, f"{row['tool']} reports {reported} unscored values"
    assert FIGURES["findings"]["tools_validating_github_crc32"] == 0
