"""Benchmarks for the scan pipeline.

`scan` is what the CLI spends its time in: stat and SHA-256, format detection,
the LIEF parse of headers, sections and imports, the Authenticode chain, the
string extraction, and the law check over the facts that come out. It is by far
the most expensive call in the package, and the only one a user waits for.
"""

from __future__ import annotations

from exeradar import scanner


def test_scan_a_signed_pe(benchmark, pe_path):
    """Everything, end to end, on a 106 KB signed binary."""
    result = benchmark(lambda: scanner.scan(pe_path))

    assert result.error is None
    assert result.format == "PE"
    assert result.imports, "a PE with no imports would mean the parse did nothing"
    assert result.signature.verified


def test_format_of(benchmark, pe_path):
    """What a directory walk pays per file, executable or not: open, read eight
    bytes, compare magics, and for the ambiguous magic look further.

    `detect_format` alone is deliberately not benchmarked. It compares eight
    bytes already in memory, and measured here it came out at 0 ns over six
    million iterations — below the clock. A benchmark that cannot resolve its
    own subject reports noise as a regression, which is worse than not watching
    it at all; `format_of` covers the same comparison and the file open that
    pays for it.
    """
    assert benchmark(lambda: scanner.format_of(pe_path)) == "PE"
