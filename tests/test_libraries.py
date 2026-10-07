"""Which libraries a binary admits to carrying, and which it only points at.

Every string in this file was taken out of a real binary on 2026-10-02, and the
file it came from is named beside it. The corpus was the Git for Windows ucrt64
tree plus C:\\Windows\\System32\\curl.exe: a folder of DLLs that are each one
known library, so an answer can be checked against something true. libpcre2-8-0.dll
either says 10.48 or it does not, and I did not have to guess which library it is.

The three claims this module can make are not the same claim:

* **in this file** — a banner or a compiled-in build path. The code is here.
* **asked of another file** — a .NET assembly reference names a version this file
  wants loaded at run time, which is not a version it contains.
* **used, version unknown here** — an import. The version is in the DLL, and the
  DLL is not this file.

And the fourth answer is silence, which is the one worth most of the tests below.
Four of the fifteen libraries in the corpus carry their version as a bare number
with no name attached — pcre2 as `10.48 2026-08-31`, zstd as `1.5.7`, idn2 as
`2.3.8`, and the committed python.exe as `3.14.7`. A number nothing attributes is
refused, every time: being right about pcre2 by accident is not worth being wrong
about an OID, a protocol version or four bytes of debris.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from exeradar import libraries
from exeradar.models import Import

GIT_BIN = Path(r"C:\Program Files\Git\ucrt64\bin")
SYSTEM_CURL = Path(r"C:\Windows\System32\curl.exe")

# The cases below read DLLs installed on the machine, and those move: Git for
# Windows and Windows Update replace them. They used to assert the versions
# measured on 2026-10-02 — OpenSSL 3.5.8, curl 8.13.0, pcre2 10.48 — and so
# failed on the first machine that had updated, about the machine and not the
# code. The expected version is now read out of the same bytes by a pattern
# written here, the library's own statement of itself; what is asserted is
# unchanged: which library, that version, and nothing else.
_STATED = {
    "zlib": rb"(?:de|in)flate (\d+\.\d+\.\d+) Copyright",
    "expat": rb"expat_(\d+\.\d+\.\d+)",
    "openssl": rb"OpenSSL (\d+\.\d+\.\d+) \d{1,2} [A-Z][a-z]{2} \d{4}",
    "libssh2": rb"libssh2-(\d+\.\d+\.\d+)/",
    "nghttp2": rb"nghttp2-(\d+\.\d+\.\d+)/",
    "curl": rb"curl/(\d+\.\d+\.\d+)",
}


def _stated(data: bytes, library: str) -> str:
    """The version `library` states in `data`, by the pattern above; one, or the test is wrong."""
    found = {match.decode() for match in re.findall(_STATED[library], data)}
    assert len(found) == 1, f"{library}: {sorted(found)}"
    return found.pop()


def versions(*candidates: str) -> set[tuple[str, str | None]]:
    """(name, version) for everything claimed, which is what most tests assert."""
    return {(lib.name, lib.version) for lib in libraries.versions_in(candidates)}


# --------------------------------------------------------------------------
# A build path: the source tree the file was compiled in, left behind by the
# __FILE__ of an assert. This is the only place OpenSSL's version appears in
# some builds, and the only place any version appears in nghttp2's.
# --------------------------------------------------------------------------

def test_a_build_path_names_the_release_it_was_compiled_from():
    # libcrypto-3-x64.dll, which repeats this 611 times with different filenames.
    found = libraries.versions_in(["../openssl-3.5.8/crypto/asn1/a_int.c"])

    assert len(found) == 1
    assert found[0].name == "openssl"
    assert found[0].version == "3.5.8"
    assert found[0].source == "build path"
    assert found[0].evidence == "../openssl-3.5.8/crypto/asn1/a_int.c"


def test_one_release_repeated_is_one_entry():
    """611 strings, one library. A report that lists it 611 times is unreadable."""
    assert versions(
        "../openssl-3.5.8/crypto/aes/aes_ige.c",
        "../openssl-3.5.8/crypto/asn1/a_int.c",
        "../openssl-3.5.8/ssl/ssl_lib.c",
    ) == {("openssl", "3.5.8")}


def test_an_absolute_build_path_counts_too():
    # libnghttp2-14.dll, built on somebody's D: drive.
    assert versions("D:/W/B/src/nghttp2-1.70.0/lib/nghttp2_hd.c") == {("nghttp2", "1.70.0")}


def test_a_backslash_is_a_separator_as_well():
    assert versions(r"C:\M\B\src\libpsl-0.21.5\list\public_suffix_list.dat") == {
        ("libpsl", "0.21.5")
    }


def test_the_release_must_be_a_directory_not_a_name_with_a_number_in_it():
    """libiconv-2.dll is full of charset names shaped exactly like a release.

    `ANSI_X3.4-1986` is a name, not a version, and the thing that tells them
    apart is the separator after it: a release leaves a directory behind.
    """
    assert versions(
        "ANSI_X3.4-1986",
        "ANSI_X3.4-1968",
        "VISCII1.1-1",
        "TIS620.2529-1",
        "JIS_X0212.1990-0",
    ) == set()


def test_a_download_url_is_not_a_component_of_this_file():
    """A link to a release says where it can be got, not that it is in here."""
    assert versions("https://example.org/src/openssl-3.5.8/openssl-3.5.8.tar.gz") == set()


# --------------------------------------------------------------------------
# A banner: the library naming itself. Anchored at the start of the string,
# which is what keeps `SSH-2.0-libssh2_1.11.1` and `(TEST_ENG_OPENSSL_PKEY)`
# out of it.
# --------------------------------------------------------------------------

def test_a_library_that_names_itself():
    # libcrypto-3-x64.dll, and the only string in it with both name and number.
    found = libraries.versions_in(["OpenSSL 3.5.8 25 Aug 2026"])

    assert len(found) == 1
    assert (found[0].name, found[0].version, found[0].source) == (
        "openssl", "3.5.8", "banner",
    )


def test_the_user_agent_shape():
    # libcurl-4.dll says `libcurl/8.22.0`; curl.exe says both this and `curl/8.13.0`.
    assert versions("libcurl/8.22.0") == {("curl", "8.22.0")}


def test_a_printf_template_is_still_a_banner():
    # curl.exe: the format string behind `curl --version`.
    assert versions("curl 8.13.0 (Windows) %s") == {("curl", "8.13.0")}


def test_zlib_names_the_function_and_not_the_library():
    """`inflate 1.3.1 Copyright …` is zlib saying so, and has been since 1995.

    Taken from curl.exe, which links it statically: nothing else in that file
    mentions zlib at all, so without this the bundled copy is invisible.
    """
    assert versions(
        "inflate 1.3.1 Copyright 1995-2024 Mark Adler",
        "deflate 1.3.1 Copyright 1995-2024 Jean-loup Gailly and Mark Adler",
    ) == {("zlib", "1.3.1")}


def test_an_underscore_separates_as_well_as_a_space():
    # libexpat-1.dll, whose entire version string is this.
    assert versions("expat_2.8.5") == {("expat", "2.8.5")}


# --------------------------------------------------------------------------
# The refusals. Each string here is real, and each one is why the rule above
# is narrower than it could be.
# --------------------------------------------------------------------------

def test_a_protocol_version_is_not_a_library_version():
    """curl.exe has sixteen strings shaped `name<sep>number` and fourteen are these.

    A rule that reads `http/1.1` as a library at 1.1 does not produce a wrong
    row — it produces a report nobody reads past.
    """
    assert versions(
        "http/1.1",
        "HTTP/1.0 connection set to keep alive",
        "HTTP/0.9 is not supported in this build",
        "RTSP/1.0",
        "TLS 1.2 (1.1, 1.0) ciphers to use",
        "TLS 1.3 cipher suites to use",
        "TLSv1.3",
        "DTLSv1.2",
        "PRI * HTTP/2.0",
    ) == set()


def test_two_numbers_in_one_string_and_only_one_belongs_to_the_library():
    """libssh2-1.dll's handshake banner is `SSH-2.0-libssh2_1.11.1`.

    2.0 is the protocol and 1.11.1 is the library. Reading left to right gets it
    exactly wrong, so nothing is read out of this string at all — the version is
    taken from the build path in the same file, which says it unambiguously.
    """
    claimed = libraries.versions_in(["SSH-2.0-libssh2_1.11.1"])

    assert all(lib.version != "2.0" for lib in claimed)
    assert all(lib.name != "ssh" for lib in claimed)


def test_libssh2_is_found_by_its_build_path_instead():
    assert versions("../../libssh2-1.11.1/src/channel.c") == {("libssh2", "1.11.1")}


def test_a_name_in_the_middle_of_a_sentence_is_not_a_declaration():
    """Constructed, not measured — and said so because that matters.

    Nothing in the corpus mentions a library's name mid-string next to a version,
    so searching instead of matching would have cost nothing there. The rule is
    kept anyway: a declaration is something a library says about itself, and the
    difference between stating a version and discussing one is not recoverable
    once both are a row in a report.
    """
    assert versions(
        "Loading openssl 1.0.2 compatibility shim",
        "built against zlib 1.2.11 or newer",
    ) == set()


def test_a_bare_number_names_nothing_and_is_refused():
    """The measured cost of this rule, and it is a real cost.

    Each of these is the right version of a real library — pcre2 10.48, zstd
    1.5.7, idn2 2.3.8, and python.exe's own 3.14.7 — and not one of them says so.
    Attributing a number to whichever library the filename suggests would be
    guessing with a citation attached, which is worse than silence.
    """
    assert versions("10.48 2026-08-31", "1.5.7", "2.3.8", "3.14.7", "1.19") == set()


def test_an_object_identifier_is_not_a_version():
    # curl.exe and libcrypto both carry dozens of these next to the real numbers.
    assert versions(
        "1.2.840.113549.1.1.1",
        "2.16.840.1.101.3.4.3.17",
        "1.2.840.10045.4.3.2",
    ) == set()


def test_debris_is_not_a_version():
    # libiconv-2.dll and python.exe, where a printable run crossed into data.
    assert versions("8.9.:.", "9000.0,((((", "h7W7.919-9", r"495@5c5L5.5\5E5V5W5") == set()


def test_two_versions_of_one_library_are_both_reported():
    """A binary that carries two copies has carried two copies.

    Choosing the higher one would read as a measurement and be an invention; the
    older one is the one a CVE will match.
    """
    assert versions(
        "../openssl-3.5.8/crypto/asn1/a_int.c",
        "OpenSSL 1.1.1w 11 Sep 2023",
    ) == {("openssl", "3.5.8"), ("openssl", "1.1.1w")}


# --------------------------------------------------------------------------
# A .NET assembly reference: a version this file asks another file for.
# --------------------------------------------------------------------------

def test_an_assembly_reference_is_a_version_asked_of_somebody_else():
    """The shape four Kyocera installers carry, and the reason strings.py has
    `_versions_declared_in` at all."""
    found = libraries.versions_in(
        ["Katana, Version=1.1.8.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"]
    )

    assert len(found) == 1
    assert (found[0].name, found[0].version) == ("Katana", "1.1.8.0")
    assert found[0].source == "assembly reference"


def test_an_assembly_reference_needs_its_culture_to_be_one():
    """Without `Culture=` this is prose with a number in it."""
    assert versions("Upgraded, Version=2.0 of the protocol") == set()


# --------------------------------------------------------------------------
# Imports: the libraries whose version is somewhere else on the disk. This is
# the difference between "no OpenSSL here" and "the OpenSSL is next door".
# --------------------------------------------------------------------------

def test_an_imported_library_is_reported_with_no_version():
    found = libraries.from_strings_and_imports([], [Import(dll="libcrypto-3-x64.dll")])

    assert len(found) == 1
    assert found[0].name == "openssl"
    assert found[0].version is None
    assert found[0].source == "import"
    assert found[0].evidence == "libcrypto-3-x64.dll"


def test_the_abi_decoration_is_not_part_of_the_name():
    """`-3-x64`, `-8-0`, `-4`, the trailing `1`: soname and build decoration, and
    none of it is the library's version. zlib1.dll is not zlib 1."""
    named = {
        lib.evidence: lib.name
        for lib in libraries.from_strings_and_imports(
            [],
            [Import(dll=name) for name in
             ("zlib1.dll", "libpcre2-8-0.dll", "libssh2-1.dll", "libcurl-4.dll",
              "libnghttp2-14.dll")],
        )
    }

    assert named == {
        "zlib1.dll": "zlib",
        "libpcre2-8-0.dll": "pcre2",
        "libssh2-1.dll": "libssh2",
        "libcurl-4.dll": "curl",
        "libnghttp2-14.dll": "nghttp2",
    }
    assert all(lib.version is None for lib in libraries.from_strings_and_imports(
        [], [Import(dll="zlib1.dll")]))


def test_a_library_both_stated_here_and_imported_gets_a_row_for_each():
    """Two copies are two copies, and the one to patch may be the other file.

    This asserted the opposite first: one library, one row, the versioned one. The
    corpus disagreed on 2026-10-02. Git's curl.exe states `curl 8.22.0` in its own
    banner and imports libcurl-4.dll, which is where the code is and which is the
    file somebody patching curl would have to replace — and the suppressed row was
    the only place that filename appeared.

    libssl-3-x64.dll is the other overlap in the corpus and the redundant one: it
    states openssl 3.5.8 and imports libcrypto at the same version. One extra true
    row there is much the cheaper of the two errors.
    """
    found = libraries.from_strings_and_imports(
        ["libcurl/8.22.0"], [Import(dll="libcurl-4.dll")]
    )

    assert [(lib.name, lib.version, lib.source) for lib in found] == [
        ("curl", "8.22.0", "banner"),
        ("curl", None, "import"),
    ]


def test_two_imported_files_of_one_library_are_two_rows():
    """libcrypto and libssl are one library in two files, and both get replaced."""
    found = libraries.from_strings_and_imports(
        [], [Import(dll="libcrypto-3-x64.dll"), Import(dll="libssl-3-x64.dll")]
    )

    assert [lib.evidence for lib in found] == ["libcrypto-3-x64.dll", "libssl-3-x64.dll"]
    assert {lib.name for lib in found} == {"openssl"}


def test_a_system_dll_is_not_a_library_worth_a_row():
    """Reporting every import would bury the ones that carry a CVE."""
    found = libraries.from_strings_and_imports(
        [], [Import(dll=name) for name in
             ("KERNEL32.dll", "ADVAPI32.dll", "api-ms-win-crt-stdio-l1-1-0.dll",
              "VCRUNTIME140.dll")],
    )

    assert found == []


def test_the_caveat_is_part_of_the_module_and_not_of_one_report():
    """Both renderers say the same thing about what silence means, so the
    sentence lives where they both read it."""
    assert "import" in libraries.CAVEAT
    assert "not" in libraries.CAVEAT


# --------------------------------------------------------------------------
# The sentence each row renders as, kept here so the two renderers agree.
# --------------------------------------------------------------------------

def test_a_bundled_version_is_said_to_be_in_this_file():
    line = libraries.sentence(
        libraries.Library("openssl", "3.5.8", "build path",
                          "../openssl-3.5.8/crypto/asn1/a_int.c")
    )

    assert "3.5.8" in line
    assert "../openssl-3.5.8/crypto/asn1/a_int.c" in line


def test_an_import_says_which_file_to_look_in_next():
    line = libraries.sentence(
        libraries.Library("openssl", None, "import", "libcrypto-3-x64.dll")
    )

    assert "libcrypto-3-x64.dll" in line
    assert "no version" in line.lower()


def test_an_assembly_reference_says_it_is_asked_for_and_not_carried():
    line = libraries.sentence(
        libraries.Library("Katana", "1.1.8.0", "assembly reference",
                          "Katana, Version=1.1.8.0, Culture=neutral")
    )

    assert "1.1.8.0" in line
    assert "run time" in line or "requires" in line


# --------------------------------------------------------------------------
# Against the files themselves, which is the only way to know the rules hold.
# --------------------------------------------------------------------------

def test_the_committed_fixture_claims_nothing(pe_path):
    """python.exe carries `3.14.7` and nothing that attributes it.

    This is the negative the whole module turns on, and it runs on every
    platform: an empty answer here is the honest one, not a broken parser.
    """
    from exeradar import strings

    if pe_path.name != "python.exe":
        pytest.skip("a local sample was dropped in tests/fixtures; this asserts the committed one")

    assert libraries.versions_in(strings.extract_raw(pe_path.read_bytes())) == []


@pytest.mark.skipif(sys.platform != "win32", reason="the corpus is a Windows install")
@pytest.mark.parametrize(
    ("path", "library"),
    [
        (GIT_BIN / "zlib1.dll", "zlib"),
        (GIT_BIN / "libexpat-1.dll", "expat"),
        (GIT_BIN / "libcrypto-3-x64.dll", "openssl"),
        (GIT_BIN / "libssh2-1.dll", "libssh2"),
        (GIT_BIN / "libnghttp2-14.dll", "nghttp2"),
    ],
)
def test_a_dll_that_is_one_known_library_reports_that_library(path, library):
    """Measured on 2026-10-02 against Git for Windows 2.52's ucrt64 tree, and
    read since then against whichever version is installed: see _STATED.

    Exactly equal, not a superset: an extra row here would be a false positive,
    and these files are small enough that there is nothing to hide behind.
    """
    from exeradar import strings

    if not path.is_file():
        pytest.skip(f"{path.name} is not installed here")

    data = path.read_bytes()
    found = {(lib.name, lib.version) for lib in libraries.versions_in(strings.extract_raw(data))}
    assert found == {(library, _stated(data, library))}


@pytest.mark.skipif(sys.platform != "win32", reason="the corpus is a Windows install")
def test_the_librarys_own_word_outranks_the_path_it_was_compiled_in():
    """libcrypto-3-x64.dll says 3.5.8 twice, and the two sayings are not equal.

    `OpenSSL 3.5.8 25 Aug 2026` is the library stating its version;
    `../openssl-3.5.8/crypto/aes/aes_ige.c` is a side effect of how it was built,
    and it is one of 611 strings that differ only in the filename on the end. Both
    give the same number here, but the evidence a report prints is the banner.
    """
    from exeradar import strings

    path = GIT_BIN / "libcrypto-3-x64.dll"
    if not path.is_file():
        pytest.skip("libcrypto-3-x64.dll is not installed here")

    data = path.read_bytes()
    found = libraries.versions_in(strings.extract_raw(data))

    assert len(found) == 1
    assert found[0].source == "banner"
    assert re.fullmatch(_STATED["openssl"].decode(), found[0].evidence), found[0].evidence
    assert found[0].version == _stated(data, "openssl")


@pytest.mark.skipif(sys.platform != "win32", reason="the corpus is a Windows install")
def test_a_dll_that_carries_its_version_unattributed_still_reports_nothing():
    """libpcre2-8-0.dll is pcre2, it does say 10.48, and this says nothing.

    The one test that proves the refusal costs something real.
    """
    from exeradar import strings

    path = GIT_BIN / "libpcre2-8-0.dll"
    if not path.is_file():
        pytest.skip("libpcre2-8-0.dll is not installed here")

    data = path.read_bytes()
    # It is in there: 10.48 when this was written, whichever 10.x is installed now.
    assert re.search(rb"\b10\.\d+ \d{4}-\d{2}-\d{2}\b", data)
    assert libraries.versions_in(strings.extract_raw(data)) == []


@pytest.mark.skipif(sys.platform != "win32", reason="curl.exe ships with Windows")
def test_the_system_curl_reports_its_own_version_and_its_bundled_zlib():
    """Two libraries out of one file, by two different rules: curl names itself
    in a banner, and the zlib it links statically names itself in another."""
    from exeradar import strings

    if not SYSTEM_CURL.is_file():
        pytest.skip("no curl.exe in System32")

    data = SYSTEM_CURL.read_bytes()
    found = {lib.name: lib.version for lib in libraries.versions_in(strings.extract_raw(data))}

    assert found.get("curl") == _stated(data, "curl")
    assert found.get("zlib") == _stated(data, "zlib")
