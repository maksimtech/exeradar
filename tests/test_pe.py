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


def test_imports_keep_their_function_names(pe_path):
    result = pe.PEParser(pe_path).parse(ExeResult(path=str(pe_path), size=0, sha256=""))
    assert result.imports
    assert any(imp.functions for imp in result.imports), "no function names survived"
    assert all(imp.dll for imp in result.imports)


def test_a_file_that_is_not_a_pe_is_an_error_not_a_crash(tmp_path):
    not_a_pe = tmp_path / "text.exe"
    not_a_pe.write_text("this is not an executable")
    result = pe.PEParser(not_a_pe).parse(ExeResult(path=str(not_a_pe), size=0, sha256=""))
    assert result.error
    assert result.format is None
