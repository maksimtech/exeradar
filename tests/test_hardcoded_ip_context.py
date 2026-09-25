"""A version number is not an endpoint, and exeradar already knows the difference.

Measured on 14 Lenovo driver installers for a ThinkPad X390 Yoga (serial
R90WA98T) on 2026-09-24: five were reported with `hardcoded_ip`, severity low,
and all five were false positives —

    10.1.15.6    2.07.1.23    23.60.0.1    2.25.100.3    23.110.0.5

every one of them the version of the driver inside the installer. Three are
formally valid public addresses, so no amount of octet checking separates them
from the real thing: `23.110.0.5` is a legitimate IPv4 address that happens to be
Intel's WLAN driver version.

What does separate them is context none of these files have. All fourteen import
no network function at all, which exeradar itself detects and prints — its own
`categorise` is what decides whether a binary talks to the network. A literal
address in a binary that cannot open a socket is not an endpoint it contacts.

This is the rule ARCHITECTURE.md section 3 asks for: do not over-interpret. It is
also the same shape as the two rules already in strings.py, which refuse to call
`kernel32.dll` a hostname — written, as the module says, only after running the
tool against a real binary.

The addresses are still reported. They are facts, and section 7 keeps facts and
findings apart: what stops is the finding, the severity and the citation of CRA
Annex I Part I(2)(j) against a file whose dotted quad is a version string. And
because a packed installer can still reach the network through LoadLibrary, the
report says why no finding was raised rather than saying nothing.
"""

from __future__ import annotations

import pytest

from exeradar.law_checker import SEVERITY, findings_of, notes_of
from exeradar.models import ExeResult, Import, Signature, SignatureState, Strings

# The five false positives, verbatim.
DRIVER_VERSIONS = ["10.1.15.6", "2.07.1.23", "23.60.0.1", "2.25.100.3", "23.110.0.5"]

# What those fourteen installers import: compression, UI, the C runtime.
NO_NETWORK = [
    Import(dll="KERNEL32.dll", functions=["CreateFileW", "GetLastError", "LoadLibraryW"]),
    Import(dll="USER32.dll", functions=["MessageBoxW", "RegisterClassW"]),
    Import(dll="ADVAPI32.dll", functions=["RegOpenKeyExW", "RegSetValueExW"]),
]

TALKS_TO_THE_NETWORK = [
    Import(dll="KERNEL32.dll", functions=["CreateFileW"]),
    Import(dll="WS2_32.dll", functions=["socket", "connect", "send"]),
]


def result(*, ips=(), imports=(), error=None) -> ExeResult:
    return ExeResult(
        path="C:/tmp/n2lrg16w.exe",
        size=1000,
        sha256="aa",
        format="PE",
        error=error,
        imports=list(imports),
        strings=Strings(ips=list(ips)),
        signature=Signature(state=SignatureState.EMBEDDED, verified=True, signer="CN=Lenovo"),
    )


# ── the case that was measured ──────────────────────────────────────────────


def test_a_driver_installer_is_not_accused_over_its_version_number():
    """The five addresses, in a file that imports nothing to reach them with."""
    assert findings_of(result(ips=DRIVER_VERSIONS, imports=NO_NETWORK)) == {}


@pytest.mark.parametrize("version", DRIVER_VERSIONS)
def test_each_of_the_five(version):
    assert "hardcoded_ip" not in findings_of(result(ips=[version], imports=NO_NETWORK))


def test_the_same_address_in_a_binary_that_can_use_it_is_a_finding():
    """23.110.0.5 is a driver version here and an endpoint there. The file says
    which by what it imports, not by the digits."""
    found = findings_of(result(ips=["23.110.0.5"], imports=TALKS_TO_THE_NETWORK))

    assert found["hardcoded_ip"] == ["23.110.0.5"]


def test_the_addresses_are_still_reported_as_facts():
    """Section 7: facts are reported without judgement. Suppressing the finding
    must not suppress the evidence — a reader looking for 10.1.15.6 still finds
    it."""
    scanned = result(ips=DRIVER_VERSIONS, imports=NO_NETWORK)

    assert scanned.strings.ips == DRIVER_VERSIONS


def test_the_report_says_why_it_raised_nothing():
    """Silence would be indistinguishable from not having looked.

    And it is only "no imports", not "no networking": a packed installer can
    resolve ws2_32 at run time through LoadLibrary, so the note states what was
    observed rather than concluding.
    """
    notes = notes_of(result(ips=DRIVER_VERSIONS, imports=NO_NETWORK))
    note = next((n for n in notes if "address" in n.lower()), "")

    assert note, notes
    assert "import" in note.lower()


def test_no_note_when_there_was_no_address_to_explain():
    assert not [n for n in notes_of(result(imports=NO_NETWORK)) if "address" in n.lower()]


# ── what counts as being able to reach the network ──────────────────────────


@pytest.mark.parametrize(
    "dll",
    ["WS2_32.dll", "wsock32.dll", "WININET.dll", "WINHTTP.dll", "urlmon.dll",
     "DNSAPI.dll", "IPHLPAPI.DLL", "netapi32.dll"],
)
def test_a_networking_dll_is_enough(dll):
    """The same table pe.categorise already uses; this rule adds no judgement
    of its own."""
    found = findings_of(result(ips=["203.0.113.7"], imports=[Import(dll=dll)]))

    assert "hardcoded_ip" in found


@pytest.mark.parametrize(
    "function",
    ["socket", "connect", "gethostbyname", "getaddrinfo", "InternetOpenUrlW",
     "WinHttpOpen", "URLDownloadToFileW"],
)
def test_a_networking_function_from_any_dll_is_enough(function):
    """A statically linked socket call reaches the import table under whatever
    DLL provides it."""
    found = findings_of(
        result(ips=["203.0.113.7"], imports=[Import(dll="KERNEL32.dll", functions=[function])])
    )

    assert "hardcoded_ip" in found


@pytest.mark.parametrize(
    "imports",
    [
        [Import(dll="CRYPT32.dll", functions=["CryptAcquireContextW"])],
        [Import(dll="ADVAPI32.dll", functions=["RegOpenKeyExW"])],
        [Import(dll="KERNEL32.dll", functions=["CreateProcessW"])],
        [],
    ],
)
def test_crypto_registry_and_process_are_not_network(imports):
    """Four categories exist and only one of them is about reaching outside."""
    assert findings_of(result(ips=["203.0.113.7"], imports=imports)) == {}


# ── what does not change ────────────────────────────────────────────────────


def test_loopback_is_still_not_an_endpoint_even_with_sockets():
    """0.0.0.0 and 127.x are how a program binds. That rule came first and
    stands on its own."""
    found = findings_of(
        result(ips=["127.0.0.1", "0.0.0.0"], imports=TALKS_TO_THE_NETWORK)
    )

    assert found == {}


def test_the_severity_is_unchanged():
    """The finding is not stronger for being rarer — exeradar sees the file and
    not the system, so a literal address is still the weakest evidence it has."""
    assert SEVERITY["hardcoded_ip"] == "low"


def test_a_file_that_failed_to_parse_still_produces_nothing():
    broken = result(ips=["203.0.113.7"], imports=TALKS_TO_THE_NETWORK, error="not a PE file")

    assert findings_of(broken) == {}
