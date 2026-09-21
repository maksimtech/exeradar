"""Where the test binaries come from.

No executable is committed to this repository. notepad++.exe was the obvious
candidate and is 8.1 MB of GPL code, which does not belong in an MIT repository
and would sit in the git history for ever. The other obvious candidates are
Windows system binaries, which are not redistributable either.

So the fixtures resolve a binary in this order:

1. anything dropped in tests/fixtures/ — gitignored, so a developer can put a
   local sample there and the whole suite runs against it;
2. a Windows system binary, when running on Windows;
3. skip, with a reason that says which of the two was missing.

The consequence, stated plainly: on the Linux CI runners the PE tests skip.
What runs everywhere is everything that does not need a binary — the DLL
categoriser, the entropy maths — and that is where the decisions live. The
parsing itself is LIEF's job, and LIEF has its own test suite.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
SYSTEM32 = Path(r"C:\Windows\System32")

# Catalog-signed, not embedded-signed: the case the architecture exists for.
CATALOG_CANDIDATES = ("notepad.exe", "hostname.exe", "where.exe")


def _local_samples() -> list[Path]:
    if not FIXTURES.is_dir():
        return []
    return sorted(p for p in FIXTURES.iterdir() if p.suffix.lower() in {".exe", ".dll"})


def _has_embedded_signature(path: Path) -> bool:
    import lief

    binary = lief.PE.parse(str(path))
    return bool(binary and len(binary.signatures))


@pytest.fixture(scope="session")
def pe_path() -> Path:
    """Any PE at all, for header, section and import parsing."""
    for candidate in _local_samples():
        return candidate
    if sys.platform == "win32":
        for name in ("hostname.exe", "where.exe", "curl.exe"):
            candidate = SYSTEM32 / name
            if candidate.is_file():
                return candidate
    pytest.skip("no PE available: drop one in tests/fixtures/ or run on Windows")


@pytest.fixture(scope="session")
def signed_pe_path() -> Path:
    """A PE carrying an embedded Authenticode signature — path A."""
    for candidate in _local_samples():
        if _has_embedded_signature(candidate):
            return candidate
    if sys.platform == "win32":
        for candidate in sorted(SYSTEM32.glob("*.exe")):
            try:
                if _has_embedded_signature(candidate):
                    return candidate
            except Exception:  # noqa: BLE001 - a broken sample is not a failure
                continue
    pytest.skip("no embedded-signed PE available")


@pytest.fixture(scope="session")
def catalog_pe_path() -> Path:
    """A PE with no embedded signature that Windows still trusts — path B."""
    if sys.platform != "win32":
        pytest.skip("catalog signatures cannot be resolved off Windows")
    for name in CATALOG_CANDIDATES:
        candidate = SYSTEM32 / name
        if candidate.is_file() and not _has_embedded_signature(candidate):
            return candidate
    pytest.skip("no catalog-signed PE found")
