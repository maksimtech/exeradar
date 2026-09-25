"""Performance benchmarks, measured by CodSpeed.

Run locally with `pytest tests/benchmarks --codspeed`; without the flag each
benchmark runs once, as an ordinary test. Everything here reads the committed
fixtures and nothing touches the network: `law_checker.check` is left out
because it downloads the acts, and the part of it that costs CPU —
`parse_articles` — is measured on the committed excerpts instead.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from exeradar import law_checker, law_fetcher, report, scanner, signature, strings
from exeradar.formats import pe
from exeradar.models import ExeResult

FIXTURES = Path(__file__).parent.parent / "fixtures"
SAMPLE = FIXTURES / "python.exe"
NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)

PART_I = "Allegato I, Parte I"
PART_II = "Allegato I, Parte II"

# The acts and the units the findings cite from each of them.
ACTS = {
    "cra": ("cra_it_excerpt.html", ("6", "13", PART_I, PART_II)),
    "gdpr": ("gdpr_it_excerpt.html", ("32",)),
    "nis2": ("nis2_it_excerpt.html", ("21",)),
}


@pytest.fixture(scope="module")
def sample_bytes() -> bytes:
    return SAMPLE.read_bytes()


@pytest.fixture(scope="module")
def scanned() -> ExeResult:
    return scanner.scan(SAMPLE)


# --------------------------------------------------------------------------
# end to end
# --------------------------------------------------------------------------


def test_scan_pe(benchmark):
    result = benchmark(scanner.scan, SAMPLE)
    assert result.error is None
    assert result.format == "PE"


def test_format_of(benchmark):
    assert benchmark(scanner.format_of, SAMPLE) == "PE"


# --------------------------------------------------------------------------
# PE parsing
# --------------------------------------------------------------------------


def test_pe_parse(benchmark):
    def parse() -> ExeResult:
        return pe.PEParser(SAMPLE).parse(ExeResult(path=str(SAMPLE), size=0, sha256=""))

    result = benchmark(parse)
    assert result.sections


def test_entropy(benchmark, sample_bytes):
    value = benchmark(pe.entropy, sample_bytes)
    assert 0.0 < value <= 8.0


def test_categorise_imports(benchmark, scanned):
    imports = [(imp.dll, imp.functions) for imp in scanned.imports]
    assert imports

    def categorise_all() -> list[frozenset[str]]:
        return [pe.categorise(dll, functions) for dll, functions in imports]

    benchmark(categorise_all)


# --------------------------------------------------------------------------
# signature
# --------------------------------------------------------------------------


def test_signature_inspect(benchmark):
    benchmark(signature.inspect, SAMPLE)


def test_signed_regions(benchmark):
    benchmark(signature.signed_regions, SAMPLE)


# --------------------------------------------------------------------------
# strings
# --------------------------------------------------------------------------


def test_strings_extract_raw(benchmark, sample_bytes):
    found = benchmark(strings.extract_raw, sample_bytes)
    assert found


def test_strings_classify(benchmark, sample_bytes):
    raw = strings.extract_raw(sample_bytes)
    benchmark(strings.classify, raw)


def test_strings_from_file_excluding_signature(benchmark):
    exclude = signature.signed_regions(SAMPLE)
    benchmark(strings.from_file, SAMPLE, exclude=exclude)


# --------------------------------------------------------------------------
# findings and reports
# --------------------------------------------------------------------------


def test_findings_for(benchmark, scanned):
    benchmark(law_checker.findings_for, scanned, now=NOW)


def test_report_to_json(benchmark, scanned):
    assert benchmark(report.to_json, scanned)


def test_report_to_markdown(benchmark, scanned):
    assert benchmark(report.to_markdown, scanned)


# --------------------------------------------------------------------------
# law texts
# --------------------------------------------------------------------------


@pytest.mark.parametrize("act", sorted(ACTS))
def test_parse_articles(benchmark, act):
    name, units = ACTS[act]
    html = (FIXTURES / name).read_text(encoding="utf-8")
    texts = benchmark(law_fetcher.parse_articles, html, units)
    assert all(unit in texts for unit in units)
