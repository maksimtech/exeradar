"""The file's own version number is not an address it contacts.

Measured on 2026-10-09: `C:\\Dev-Cpp\\devcpp.exe` (Dev-C++ 4.9.9.2, Delphi,
UPX-packed, unsigned) was reported with `hardcoded_ip: 4.9.9.2` and cited against
CRA Annex I Part I(2)(j). `4.9.9.2` is the file's own version, stated twice in its
VERSIONINFO resource: as the fixed numbers of VS_FIXEDFILEINFO, which Explorer
shows as "File version", and as the StringFileInfo value under the key
`FileVersion`. The strings pass reads the second as `4.9.9.2` on its own — the
key and the value are separate UTF-16 strings with alignment padding between
them — so `Version=` corroboration never saw the pair, and the file imports
wininet.dll, so the import rule did not stop the finding either.

A dotted quad that equals what VERSIONINFO declares is the version, classified as
such and reported as a fact in its own right ("version 4.9.9.2"). Only what the
resource says: a third party's version carried elsewhere in the file — ICU's
`78.2.0.0` in node.exe — is not covered, because nothing in the file says that
is what it is.

Derived data: the fixture is the repository's python.exe (PSF, see
ATTRIBUTIONS.md) with two alterations, both declared here. Its VS_FIXEDFILEINFO
block — one structure, found by its signature 0xFEEF04BD — has its four version
words set to 4.9.9.2, since python.exe's own 3.14.7150.1013 can never be an
address and so could never have been the bug. And its .reloc padding carries two
strings: `4.9.9.2`, the version just declared, and `203.0.113.42`, an address from
RFC 5737's TEST-NET-3, so that the rule can be seen to remove one and keep the
other. The embedded signature no longer matches the bytes, which is expected and
not what these tests read.
"""

from __future__ import annotations

import json
import struct
from dataclasses import replace
from pathlib import Path

import lief
import pytest
from rich.console import Console

from exeradar import report, scanner, strings
from exeradar.law_checker import findings_of, reaches_the_network
from exeradar.models import Import

# VS_FIXEDFILEINFO: dwSignature, dwStrucVersion, then FileVersionMS, FileVersionLS,
# ProductVersionMS, ProductVersionLS — six little-endian words.
_FIXED_FILE_INFO_SIGNATURE = struct.pack("<I", 0xFEEF04BD)

DECLARED = "4.9.9.2"
TEST_NET_3 = "203.0.113.42"

DEVCPP = Path(r"C:\Dev-Cpp\devcpp.exe")

TALKS_TO_THE_NETWORK = [
    Import(dll="KERNEL32.dll", functions=["CreateFileW"]),
    Import(dll="WS2_32.dll", functions=["socket", "connect", "send"]),
]


def _words(version: str) -> tuple[int, int]:
    a, b, c, d = (int(part) for part in version.split("."))
    return (a << 16) | b, (c << 16) | d


@pytest.fixture
def pe_stating_its_version(pe_with_a_string) -> Path:
    """python.exe declaring 4.9.9.2 in VERSIONINFO, with 4.9.9.2 and 203.0.113.42
    written in its .reloc padding. See the module docstring."""
    target = pe_with_a_string(DECLARED.encode() + b"\x00" + TEST_NET_3.encode())
    data = bytearray(target.read_bytes())
    at = data.find(_FIXED_FILE_INFO_SIGNATURE)
    assert at > 0 and data.count(_FIXED_FILE_INFO_SIGNATURE) == 1, "one fixed block, by its signature"
    ms, ls = _words(DECLARED)
    struct.pack_into("<4I", data, at + 8, ms, ls, ms, ls)
    target.write_bytes(bytes(data))

    binary = lief.PE.parse(bytes(data))
    info = binary.resources_manager.version[0].file_info
    assert (info.file_version_ms, info.file_version_ls) == (ms, ls), "LIEF reads the altered block"
    return target


def test_the_derived_file_carries_both_strings(pe_stating_its_version):
    """What the fixture puts in, before anything is said about what comes out."""
    raw = strings.extract_raw(pe_stating_its_version.read_bytes())

    assert DECLARED in raw
    assert TEST_NET_3 in raw


def test_the_declared_version_is_read_from_the_resource(pe_stating_its_version):
    result = scanner.scan(pe_stating_its_version)

    assert result.version is not None
    assert result.version.file == DECLARED
    assert result.version.product == DECLARED


def test_the_declared_version_is_not_an_address_and_the_test_net_one_still_is(pe_stating_its_version):
    result = scanner.scan(pe_stating_its_version)

    assert result.strings.ips == [TEST_NET_3]


def test_the_finding_names_the_address_and_not_the_version(pe_stating_its_version):
    """python.exe imports no socket function, so the imports are the one thing
    stated here rather than read — as test_hardcoded_ip_context states them —
    to show that the rule removes the version and leaves the finding standing."""
    result = replace(scanner.scan(pe_stating_its_version), imports=TALKS_TO_THE_NETWORK)

    assert findings_of(result)["hardcoded_ip"] == [TEST_NET_3]


def test_the_console_states_the_version(pe_stating_its_version):
    result = scanner.scan(pe_stating_its_version)
    console = Console(record=True, width=200)

    report.to_console(result, console=console)

    assert f"version {DECLARED}" in console.export_text()


def test_the_json_carries_the_version(pe_stating_its_version):
    data = json.loads(report.to_json(scanner.scan(pe_stating_its_version)))

    assert data["version"]["file"] == DECLARED


# ── the file that was measured, when it is on this machine ─────────────────


@pytest.mark.skipif(not DEVCPP.is_file(), reason=f"{DEVCPP} is not installed here")
def test_dev_cpp_is_not_accused_over_its_own_version():
    """Dev-C++ 4.9.9.2: unsigned, UPX-packed, imports wininet.dll. Not copied
    into the repository — read where it is installed, and skipped elsewhere."""
    result = scanner.scan(DEVCPP)

    assert result.error is None
    assert reaches_the_network(result), "the import rule is not what stops the finding"
    assert result.version is not None and result.version.file == "4.9.9.2"
    assert "4.9.9.2" not in result.strings.ips
    assert "hardcoded_ip" not in {finding.id for finding in result.findings}
