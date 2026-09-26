"""Benchmarks for the law side, from the CodSpeed pull request.

`law_checker.check` is not measured: it downloads the acts, and a benchmark
that goes to the network measures somebody else's afternoon. What costs CPU is
`parse_articles`, walking the EUR-Lex markup to pull one article out of a
document — and that runs against the excerpts committed to tests/fixtures, so
it is the same work without the request.

`findings_for` is the other half: turning the facts a scan produced into the
findings that get cited. Both arrived from PR #1, the second one without an
assertion.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from exeradar import law_checker, law_fetcher

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

# Pinned: findings_for takes the moment as an argument, and reading the clock
# would make the measurement depend on when it ran — a certificate expires
# between two runs and the finding count changes underneath the number.
NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)

PART_I = "Allegato I, Parte I"
PART_II = "Allegato I, Parte II"

# Each act and the units the findings actually cite from it.
ACTS = {
    "cra": ("cra_it_excerpt.html", ("6", "13", PART_I, PART_II)),
    "gdpr": ("gdpr_it_excerpt.html", ("32",)),
    "nis2": ("nis2_it_excerpt.html", ("21",)),
}


def test_findings_for(benchmark, scanned):
    """Every finding is drawn from facts the scan already collected, so this is
    the rule engine on its own with no I/O behind it."""
    findings = benchmark(lambda: law_checker.findings_for(scanned, now=NOW))

    assert isinstance(findings, list)
    assert all(getattr(finding, "id", None) for finding in findings), (
        "a finding with no id cannot be cited or suppressed"
    )


@pytest.mark.parametrize("act", sorted(ACTS))
def test_parse_articles(benchmark, act):
    """Walking the real markup of a real act. The excerpts are slices of what
    the Publications Office serves, not a reconstruction, so the shape the
    parser meets here is the shape it meets at runtime."""
    name, units = ACTS[act]
    html = (FIXTURES / name).read_text(encoding="utf-8")

    texts = benchmark(law_fetcher.parse_articles, html, units)

    assert all(unit in texts for unit in units), (
        f"{name}: asked for {units}, got {sorted(texts)}"
    )
    assert all(texts[unit].strip() for unit in units), "an article came back empty"
