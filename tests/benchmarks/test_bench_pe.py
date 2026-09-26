"""Benchmarks for the PE parser, from the CodSpeed pull request.

Harvested from PR #1, which proposed a benchmark suite the night before this
one was written and covered three things this one did not: the parse itself,
the entropy calculation every section goes through, and the import
categorisation that decides what the console prints.

The assertions are added here. Two of the three arrived as bare
`benchmark(...)` calls, and a benchmark that measures without checking reports
the speed of whatever happened — including an exception being raised, which is
fast and green and says nothing.
"""

from __future__ import annotations

from exeradar.formats import pe
from exeradar.models import ExeResult


def test_parse_a_pe(benchmark, pe_path):
    """Headers, sections and the import table: the part of `scan` that LIEF
    does, before the signature and the strings."""
    def parse() -> ExeResult:
        return pe.PEParser(pe_path).parse(
            ExeResult(path=str(pe_path), size=0, sha256="")
        )

    result = benchmark(parse)

    assert result.error is None
    assert result.sections
    assert result.imports


def test_entropy(benchmark, pe_bytes):
    """Run over every section to tell packed data from code. 106 KB here; a
    section of a real installer is orders of magnitude larger."""
    value = benchmark(pe.entropy, pe_bytes)

    # Eight bits per byte is the ceiling, and a whole PE is never at it.
    assert 0.0 < value < 8.0


def test_categorise_imports(benchmark, scanned):
    """What the report groups a binary's capabilities by — network, crypto,
    process — decided from the imported function names."""
    imports = [(item.dll, item.functions) for item in scanned.imports]
    assert imports, "the fixture imports nothing: there would be nothing to categorise"

    def categorise_all() -> list[frozenset[str]]:
        return [pe.categorise(dll, functions) for dll, functions in imports]

    categories = benchmark(categorise_all)

    assert len(categories) == len(imports)
    # Every one of them comes back empty, and that is the right answer rather
    # than a broken categoriser: this fixture is the Python launcher, eight
    # DLLs of C runtime plus KERNEL32, and the work lives in python314.dll. A
    # capability appearing here would mean a plain launcher had started being
    # reported as doing something, which is the direction that costs a reader
    # their trust.
    assert not any(found for found in categories)
