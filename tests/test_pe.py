"""What formats/pe.py has to do. Written before it does any of it.

Two halves, deliberately:

The categoriser is pure logic and pure judgement — which DLL and which function
means "this binary talks to the network" — so it is tested exhaustively and
without a binary. It runs on every platform and is where the domain decisions
are pinned.

The parser is a thin layer over LIEF, so the tests check that the layer hands
back the right shapes and does not lose anything, not that LIEF can read a PE.
They need a real binary and skip when there is none; see conftest.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from exeradar.formats import pe
from exeradar.models import ExeResult

# --------------------------------------------------------------------------
# the categoriser — no binary needed, runs everywhere
# --------------------------------------------------------------------------


@pytest.mark.parametrize("dll, expected", [
    ("WS2_32.dll", "network"),
    ("ws2_32.dll", "network"),          # case is not a signal
    ("WININET.dll", "network"),
    ("WINHTTP.dll", "network"),
    ("DNSAPI.dll", "network"),
    ("BCRYPT.dll", "crypto"),
    ("CRYPT32.dll", "crypto"),
    ("ncrypt.dll", "crypto"),
])
def test_dll_alone_is_enough_for_an_unambiguous_library(dll, expected):
    assert expected in pe.categorise(dll)


@pytest.mark.parametrize("dll", ["KERNEL32.dll", "USER32.dll", "GDI32.dll"])
def test_a_general_purpose_dll_claims_nothing_on_its_own(dll):
    """KERNEL32 is in everything. Reporting it as a signal is reporting noise."""
    assert pe.categorise(dll) == frozenset()


@pytest.mark.parametrize("functions, expected", [
    (["CreateProcessW"], "process"),
    (["ShellExecuteExW"], "process"),
    (["WinExec"], "process"),
    (["RegOpenKeyExW"], "registry"),
    (["RegSetValueExW"], "registry"),
    (["CryptAcquireContextW"], "crypto"),
    (["InternetOpenUrlW"], "network"),
    (["socket"], "network"),
])
def test_a_function_can_carry_the_signal_alone(functions, expected):
    """KERNEL32.CreateProcessW says something KERNEL32 by itself does not."""
    assert expected in pe.categorise("KERNEL32.dll", functions)


def test_advapi32_is_split_by_what_is_actually_called():
    """The reason categorise takes functions at all.

    ADVAPI32 covers the registry, process creation and the old crypto API. A
    DLL-only categoriser would tag all three on every binary that touches any
    of them, which is three claims where the evidence supports one.
    """
    assert pe.categorise("ADVAPI32.dll", ["RegOpenKeyExW"]) == frozenset({"registry"})
    assert pe.categorise("ADVAPI32.dll", ["CreateProcessAsUserW"]) == frozenset({"process"})
    assert pe.categorise("ADVAPI32.dll", ["CryptAcquireContextW"]) == frozenset({"crypto"})


@pytest.mark.parametrize("function", [
    "RegisterClassW",
    "RegisterClassExA",
    "RegisterWindowMessageW",
    "RegisterHotKey",
    "RegisterEventSourceW",
    "RegisterServiceCtrlHandlerW",
])
@pytest.mark.parametrize("dll", ["USER32.dll", "ADVAPI32.dll", "KERNEL32.dll"])
def test_registering_something_is_not_touching_the_registry(dll, function):
    """"Register" starts with "Reg", and that is all the two have in common.

    RegisterClassW registers a window class, which every program with a GUI
    does — so every GUI program was reported as touching the registry. Found on
    BIOSdump2license.exe, where USER32 was tagged "registry" although it exports
    no registry function at all. ADVAPI32's RegisterEventSource (event log) and
    RegisterServiceCtrlHandler (services) are the same mistake one DLL over.
    """
    assert "registry" not in pe.categorise(dll, [function])


@pytest.mark.parametrize("function", [
    "RegOpenKeyExW",
    "RegSetValueExW",
    "RegCloseKey",
    "RegCopyTreeW",
    "RegConnectRegistryW",
])
def test_the_registry_api_is_still_recognised_through_kernel32(function):
    """Guards the fix against the other obvious one.

    Leaving KERNEL32 out of the registry category would also have silenced the
    false positive, and traded it for a false negative: kernel32.dll exports 41
    registry functions — counted on this machine — so a binary writing to the
    registry through it would go unreported.
    """
    assert "registry" in pe.categorise("KERNEL32.dll", [function])


def test_categories_accumulate():
    result = pe.categorise("ADVAPI32.dll", ["RegOpenKeyExW", "CreateProcessAsUserW"])
    assert result == frozenset({"registry", "process"})


def test_an_unknown_dll_is_not_guessed_at():
    assert pe.categorise("some-vendor-runtime.dll") == frozenset()


def test_every_category_is_declared():
    """Nothing may return a category that is not in the public list."""
    assert set(pe.CATEGORIES) == {"network", "crypto", "process", "registry"}


# --------------------------------------------------------------------------
# entropy — pure maths, no binary needed
# --------------------------------------------------------------------------


def test_entropy_of_uniform_bytes_is_zero():
    assert pe.entropy(b"\x00" * 4096) == pytest.approx(0.0)


def test_entropy_of_uniform_bytes_is_positive_zero():
    """Not -0.0, which the test above cannot tell apart.

    Shannon's formula negates a sum, and the one term a single repeated byte
    produces is 1 · log2(1) = 0.0 — negated, -0.0. As a number that equals
    0.0, so `pytest.approx(0.0)` passes; formatted, it prints "-0.00". Seen on
    the .tls section of BIOSdump2license.exe.
    """
    value = pe.entropy(b"\x00" * 512)
    assert math.copysign(1.0, value) == 1.0
    assert f"{value:.2f}" == "0.00"


def test_entropy_of_every_byte_once_is_eight():
    assert pe.entropy(bytes(range(256))) == pytest.approx(8.0)


def test_entropy_of_nothing_is_zero_not_an_error():
    """Sections with no raw data exist; .bss is the usual one."""
    assert pe.entropy(b"") == 0.0


# --------------------------------------------------------------------------
# the parser — needs a real PE, skips without one
# --------------------------------------------------------------------------


def test_parse_fills_the_format_fields(pe_path):
    result = pe.PEParser(pe_path).parse(ExeResult(path=str(pe_path), size=0, sha256=""))
    assert result.format == "PE"
    assert result.arch                      # e.g. "AMD64"
    assert result.built                     # the compilation timestamp, as text
    assert result.error is None


def test_sections_are_reported_with_entropy(pe_path):
    result = pe.PEParser(pe_path).parse(ExeResult(path=str(pe_path), size=0, sha256=""))
    assert result.sections
    names = [s.name for s in result.sections]
    assert ".text" in names
    for section in result.sections:
        assert 0.0 <= section.entropy <= 8.0
        assert section.virtual_size >= 0


def test_section_entropy_comes_from_the_tested_function(pe_path, monkeypatch):
    """The report kept printing -0.00 after entropy() had been fixed.

    PEParser was reading LIEF's own `section.entropy`, which is computed the
    textbook way and returns -0.0 just the same, so the function the tests
    cover never reached the report: the fix passed its unit test and changed
    nothing a user sees. Only rerunning the tool on BIOSdump2license.exe showed
    it. This pins the wiring, which together with the sign test above is what
    actually keeps "-0.00" out of the output.
    """
    monkeypatch.setattr(pe, "entropy", lambda data: 1.25)
    result = pe.PEParser(pe_path).parse(ExeResult(path=str(pe_path), size=0, sha256=""))
    assert result.sections
    assert all(section.entropy == 1.25 for section in result.sections)


def test_imports_keep_their_function_names(pe_path):
    result = pe.PEParser(pe_path).parse(ExeResult(path=str(pe_path), size=0, sha256=""))
    assert result.imports
    assert any(imp.functions for imp in result.imports), "no function names survived"
    assert all(imp.dll for imp in result.imports)


def test_a_file_that_is_not_a_pe_is_an_error_not_a_crash(tmp_path):
    not_a_pe = tmp_path / "text.exe"
    not_a_pe.write_text("this is not an executable", encoding="utf-8")
    result = pe.PEParser(not_a_pe).parse(ExeResult(path=str(not_a_pe), size=0, sha256=""))
    assert result.error
    assert result.format is None


@pytest.mark.parametrize("make", [
    lambda tmp_path: tmp_path / "gone.exe",   # nothing at that path
    lambda tmp_path: tmp_path,                 # a directory: there, and not a file
], ids=["missing", "directory"])
def test_a_path_that_cannot_be_opened_parses_to_none(tmp_path, make):
    """Python opens the file and LIEF only parses the bytes, so a path Python
    cannot read has to come back as LIEF answered for one: None, not OSError."""
    assert pe.parse(make(tmp_path)) is None


# --------------------------------------------------------------------------
# imports by ordinal — what the real binaries showed on 2026-10-09
# --------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures"


def _import_lookup_entry(data: bytes, dll: str) -> int:
    """File offset of the first import lookup table entry for `dll`."""
    import lief

    binary = lief.PE.parse(data)
    assert binary is not None
    for imported in binary.imports:
        if imported.name.lower() == dll:
            return binary.rva_to_offset(imported.import_lookup_table_rva or imported.import_address_table_rva)
    raise AssertionError(f"{dll} is not imported")


@pytest.fixture
def pe_importing_by_ordinal(tmp_path) -> Path:
    """python.exe asking python314.dll for ordinal 7 instead of for `Py_Main`.

    The import lookup table is an array of 64-bit entries; the high bit set
    means "by ordinal" and the low 16 bits carry the number. Flipping the one
    entry is the whole change: every other header stays as it was.
    """
    import struct

    sample = FIXTURES / "python.exe"
    if not sample.is_file():
        pytest.skip("tests/fixtures/python.exe is missing")
    data = bytearray(sample.read_bytes())
    struct.pack_into("<Q", data, _import_lookup_entry(bytes(data), "python314.dll"), (1 << 63) | 7)
    target = tmp_path / "ordinal.exe"
    target.write_bytes(bytes(data))
    return target


def test_an_import_by_ordinal_is_counted_and_named_by_its_number(pe_importing_by_ordinal):
    """powershell.exe imports ATL.DLL by ordinal only and was shown importing
    `0` functions from it; Code.exe asks WS2_32.dll for 54 functions, 25 of
    them by ordinal, and was shown 29. A function asked for by number is still
    a function the binary calls, and `#7` is how the linker's own tools name it.
    """
    result = pe.PEParser(pe_importing_by_ordinal).parse(
        ExeResult(path=str(pe_importing_by_ordinal), size=0, sha256="")
    )

    python = next(imp for imp in result.imports if imp.dll.lower() == "python314.dll")
    assert python.functions == ["#7"]


def test_an_ordinal_claims_no_category():
    """`#15` from WS2_32.dll says network through the DLL and nothing through
    the number: there is no name to read a verb from."""
    assert pe.categorise("OLEAUT32.dll", ["#15", "#2"]) == frozenset()
    assert pe.categorise("WS2_32.dll", ["#23"]) == frozenset({"network"})


# --------------------------------------------------------------------------
# section names longer than eight bytes
# --------------------------------------------------------------------------

# python.exe's .reloc has 48 virtual bytes in a 512-byte raw block, so from 256
# bytes in it is zero padding inside a section: a place to put a COFF string
# table that LIEF will read and nothing else will miss. The same padding
# conftest's pe_with_a_string uses.
_RELOC_PADDING = 0x16600 + 256


@pytest.fixture
def pe_with_a_long_section_name(tmp_path) -> Path:
    """python.exe whose last section is called `.debug_gdb_scripts`.

    A COFF section header holds eight bytes for the name. A longer one is kept
    in the string table after the symbol table, and the header carries `/N`,
    the decimal offset of the name in that table — the convention of the PE/COFF
    specification, which Go's linker uses for every `.zdebug_*` section.
    """
    import struct

    sample = FIXTURES / "python.exe"
    if not sample.is_file():
        pytest.skip("tests/fixtures/python.exe is missing")
    data = bytearray(sample.read_bytes())

    name = b".debug_gdb_scripts\x00"
    struct.pack_into("<I", data, _RELOC_PADDING, 4 + len(name))      # the table's size, itself included
    data[_RELOC_PADDING + 4:_RELOC_PADDING + 4 + len(name)] = name

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    struct.pack_into("<I", data, coff + 8, _RELOC_PADDING)             # PointerToSymbolTable, 0 symbols
    count = struct.unpack_from("<H", data, coff + 2)[0]
    optional = struct.unpack_from("<H", data, coff + 16)[0]
    last = coff + 20 + optional + 40 * (count - 1)
    data[last:last + 8] = b"/4".ljust(8, b"\x00")                      # offset 4: just past the size

    target = tmp_path / "long-names.exe"
    target.write_bytes(bytes(data))
    return target


def test_a_long_section_name_is_read_from_the_string_table(pe_with_a_long_section_name):
    """docker.exe (Docker Inc, 44 MB, Go) showed eight sections called `/4`,
    `/19`, `/32`, `/46`, `/65`, `/78`, `/95`, `/112`, five of them at entropy
    8.00 and coloured as packed. They are `.zdebug_abbrev`, `.zdebug_line`,
    `.zdebug_frame`, `.debug_gdb_scripts`, `.zdebug_info` and so on: compressed
    DWARF, which is what entropy 8.00 means once the name is readable."""
    result = pe.PEParser(pe_with_a_long_section_name).parse(
        ExeResult(path=str(pe_with_a_long_section_name), size=0, sha256="")
    )

    assert [s.name for s in result.sections][-1] == ".debug_gdb_scripts"
    assert "/4" not in [s.name for s in result.sections]


def test_a_slash_name_with_no_table_behind_it_is_kept_as_written(pe_path):
    """The convention is only an offset; a header saying `/4` in a file with no
    string table names nothing, and the raw name is the honest answer."""
    import struct

    data = bytearray(pe_path.read_bytes())
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    count = struct.unpack_from("<H", data, coff + 2)[0]
    optional = struct.unpack_from("<H", data, coff + 16)[0]
    last = coff + 20 + optional + 40 * (count - 1)
    data[last:last + 8] = b"/4".ljust(8, b"\x00")
    import lief

    binary = lief.PE.parse(bytes(data))
    names = [pe._section_name(section) for section in binary.sections]

    assert names[-1] == "/4"
