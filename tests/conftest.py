"""Where the test binaries come from.

One executable is committed: `tests/fixtures/python.exe`, 104 KB under the PSF
licence, which names redistribution explicitly — see ATTRIBUTIONS.md for why
that one and not notepad++.exe (8.1 MB, GPL, wrong licence for an MIT
repository) or a Windows system binary (not redistributable at all).

The fixtures still resolve a binary in order, because the committed sample
cannot cover every case:

1. anything in tests/fixtures/, the committed sample included, so a developer
   can drop a local one beside it and the suite runs against that too;
2. a Windows system binary, when running on Windows;
3. skip, with a reason that says which of the two was missing.

Only `catalog_pe_path` reaches step 3 on the CI runners: a catalog signature
is a Windows concept and there is nothing to substitute for it elsewhere.
That is the one thing about this tool that Linux cannot check, which is also
exactly why `SignatureState.UNKNOWN` exists.
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
