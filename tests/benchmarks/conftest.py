"""Fixtures for the benchmarks.

They live here rather than in tests/conftest.py on purpose. The price is that
the two conftests do not share, and that is the right price — a benchmark that
silently starts measuring a fixture the test suite changed for its own reasons
is measuring the wrong thing.

This directory is inside `testpaths`, whatever this docstring said until
2026-10-17: the workflows pass `--ignore=tests/benchmarks`, but a plain `pytest`,
the one release.sh runs before committing the bump, collected it and ended in
`fixture 'benchmark' not found`. The runner is installed by codspeed.yml alone,
so without it the benchmarks are skipped and say why, as in cookieradar and
releaseradar.

Everything is session-scoped and read once. A benchmark that re-reads 100 KB
from disk on every round reports the speed of the page cache.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from exeradar import scanner, signature, strings


def pytest_collection_modifyitems(config, items):
    if config.pluginmanager.hasplugin("codspeed"):
        return
    skip = pytest.mark.skip(reason="the CodSpeed runner is not installed: codspeed.yml runs the benchmarks")
    for item in items:
        if "benchmark" in getattr(item, "fixturenames", ()):
            item.add_marker(skip)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "python.exe"


@pytest.fixture(scope="session")
def pe_path() -> Path:
    """A real signed PE: 106 KB, an embedded Authenticode signature, a four
    certificate chain and an RFC3161 countersignature."""
    assert FIXTURE.is_file(), f"the PE fixture is missing: {FIXTURE}"
    return FIXTURE


@pytest.fixture(scope="session")
def pe_bytes(pe_path) -> bytes:
    return pe_path.read_bytes()


@pytest.fixture(scope="session")
def signed_regions(pe_path) -> list[tuple[int, int]]:
    return signature.signed_regions(pe_path)


@pytest.fixture(scope="session")
def candidates(pe_bytes, signed_regions) -> list[str]:
    """The printable runs of the fixture, certificate table excluded — what
    `classify` is actually handed in production."""
    return strings.extract_raw(pe_bytes, exclude=signed_regions)


@pytest.fixture(scope="session")
def scanned(pe_path):
    """One full scan, for the report benchmarks to render."""
    result = scanner.scan(pe_path)
    assert result.error is None, result.error
    return result
