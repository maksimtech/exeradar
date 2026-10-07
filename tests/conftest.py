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
from collections.abc import Callable
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


# The data directory that holds the Authenticode blob: index 4 of the optional
# header's directory array, which is the one PE directory whose first field is a
# file offset and not an RVA.
_SECURITY_DIRECTORY = 4
_PE32_PLUS = 0x20B


def _security_directory_offset(data: bytes) -> int:
    """Where the certificate table entry sits in the file."""
    import struct

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
    fixed = 112 if magic == _PE32_PLUS else 96   # PE32+ / PE32 optional header
    return e_lfanew + 24 + fixed + _SECURITY_DIRECTORY * 8


@pytest.fixture
def unsigned_pe_path(signed_pe_path, tmp_path) -> Path:
    """A PE that parses and carries no signature, from one that does.

    Zeroing the certificate table entry is the whole change: every header stays
    consistent, LIEF reads the file, and `signatures` is empty — which is what
    "both paths ran and found nothing" needs in order to mean anything. A file
    of `MZ` and zeros cannot say that: it says nothing could be read.
    """
    import struct

    data = bytearray(signed_pe_path.read_bytes())
    struct.pack_into("<II", data, _security_directory_offset(data), 0, 0)

    target = tmp_path / "unsigned.exe"
    target.write_bytes(bytes(data))
    return target


@pytest.fixture
def forged_certificate_table_pe_path(signed_pe_path, tmp_path) -> Path:
    """A signed PE whose certificate table entry claims 0x400 to the end of the file.

    The entry is a header field, so whoever wrote the file chooses it. Pointed
    over every section, LIEF finds no signature there — and the range used to be
    left out of string extraction all the same.
    """
    import struct

    data = bytearray(signed_pe_path.read_bytes())
    struct.pack_into("<II", data, _security_directory_offset(data), 0x400, len(data) - 0x400)

    target = tmp_path / "hidden.exe"
    target.write_bytes(bytes(data))
    return target


# python.exe's .reloc starts at 0x16600 with 512 raw bytes and 48 virtual ones,
# so from 256 bytes in it is zero padding: inside a section, so not overlay, and
# before the certificate table at 0x16800. LIEF reads nothing there as a
# structure; the strings pass does.
_RELOC_PADDING = 0x16600 + 256


@pytest.fixture
def pe_with_a_string(tmp_path) -> Callable[[bytes], Path]:
    """Make a copy of python.exe carrying `text` in its .reloc padding.

    The way a hostile string reaches the reports: written by whoever built the
    binary, extracted as a fact, and printed.
    """
    sample = FIXTURES / "python.exe"
    if not sample.is_file():
        pytest.skip("tests/fixtures/python.exe is missing")

    def make(text: bytes) -> Path:
        assert len(text) + 2 <= 200, "the padding holds 256 bytes"
        data = bytearray(sample.read_bytes())
        data[_RELOC_PADDING:_RELOC_PADDING + len(text) + 2] = b"\x00" + text + b"\x00"
        target = tmp_path / "crafted.exe"
        target.write_bytes(bytes(data))
        return target

    return make


@pytest.fixture
def truncated_pe_path(signed_pe_path, tmp_path) -> Path:
    """The first 4 KB of a signed binary: an interrupted download.

    Its headers still say where the certificate table is, and the file ends long
    before that. Nothing about the signature can be concluded, which is exactly
    the distinction the tool exists to keep.
    """
    target = tmp_path / "truncated.exe"
    target.write_bytes(signed_pe_path.read_bytes()[:4096])
    return target


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
