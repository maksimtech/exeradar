"""What the scanner has to hand the library pass, and what it must not pay twice.

The library pass needs the *raw* strings, and `result.strings` is the classified
four buckets — a release directory is a path, and `openssl 3.5.8` is in none of
them. So the scanner extracts once and gives both passes the same list. Extracting
twice would work and would also read a 25 MB DLL twice, which is why the call is
counted here rather than left to be noticed later.

The same exclusions have to apply, too. A signed binary's certificate blob is full
of names and numbers that describe whoever signed it, and a version read out of it
would be attributed to the program.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from exeradar import scanner, strings

GIT_BIN = Path(r"C:\Program Files\Git\ucrt64\bin")


def test_the_file_is_read_for_strings_exactly_once(pe_path, monkeypatch):
    """Two passes over one list, not two passes over one file."""
    calls = []
    real = strings.extract_raw

    def counted(data, *args, **kwargs):
        calls.append(len(data))
        return real(data, *args, **kwargs)

    monkeypatch.setattr(strings, "extract_raw", counted)
    scanner.scan(pe_path)

    assert len(calls) == 1


def test_the_result_carries_the_field(pe_path):
    result = scanner.scan(pe_path)

    assert isinstance(result.libraries, list)


def test_the_library_pass_is_given_the_same_exclusions(signed_pe_path, monkeypatch):
    """The certificate blob describes the signer, not the program.

    This asserts the argument and not the outcome, which is the second version of
    the test. The first compared what was reported against the strings that live
    only inside the excluded ranges — and passed with the exclusions removed,
    because no certificate blob available here happens to contain a string shaped
    like a library banner. A check that cannot fail is the defect, so what is
    checked now is the wiring: one extraction, and the ranges reach it.
    """
    from exeradar import signature

    seen: list[list[tuple[int, int]]] = []
    real = strings.extract_raw

    def recording(data, *args, **kwargs):
        seen.append(list(kwargs.get("exclude", args[1] if len(args) > 1 else ())))
        return real(data, *args, **kwargs)

    monkeypatch.setattr(strings, "extract_raw", recording)
    scanner.scan(signed_pe_path)

    assert len(seen) == 1
    assert set(signature.signed_regions(signed_pe_path)) <= set(seen[0])
    assert seen[0], "a signed binary has a blob to exclude"


@pytest.mark.skipif(sys.platform != "win32", reason="the corpus is a Windows install")
def test_end_to_end_on_a_dll_that_is_one_known_library():
    path = GIT_BIN / "libcrypto-3-x64.dll"
    if not path.is_file():
        pytest.skip("libcrypto-3-x64.dll is not installed here")

    result = scanner.scan(path)

    assert [(lib.name, lib.version) for lib in result.libraries] == [("openssl", "3.5.8")]


@pytest.mark.skipif(sys.platform != "win32", reason="the corpus is a Windows install")
def test_a_binary_that_imports_its_crypto_is_told_where_to_look():
    """git.exe links OpenSSL dynamically, so no string in it names a version.

    The row it gets instead is the useful one: the name of the file that does.
    """
    path = Path(r"C:\Program Files\Git\mingw64\bin\git.exe")
    if not path.is_file():
        path = Path(r"C:\Program Files\Git\ucrt64\bin\git.exe")
    if not path.is_file():
        pytest.skip("no git.exe where this looked")

    result = scanner.scan(path)
    imported = [lib for lib in result.libraries if lib.source == "import"]

    assert imported, [(lib.name, lib.version, lib.source) for lib in result.libraries]
    assert all(lib.version is None for lib in imported)
    assert all(lib.evidence.lower().endswith(".dll") for lib in imported)
