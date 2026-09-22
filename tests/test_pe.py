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
    not_a_pe.write_text("this is not an executable")
    result = pe.PEParser(not_a_pe).parse(ExeResult(path=str(not_a_pe), size=0, sha256=""))
    assert result.error
    assert result.format is None
