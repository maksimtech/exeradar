"""What strings.py has to do, and mostly what it has to refuse to claim.

Extraction is trivial. Classification is not: in a Windows binary almost
everything looks like a domain. `kernel32.dll` has a dot and two labels, and so
does every filename ever written. A classifier that calls those domains
produces a report nobody can read, because the noise buries the one host that
actually mattered.

So most of these tests are about what does *not* get reported.
"""

from __future__ import annotations

import pytest

from exeradar import strings

# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------


def test_ascii_runs_are_found():
    data = b"\x00\x01hello world\x00\x02"
    assert "hello world" in strings.extract_raw(data)


def test_runs_shorter_than_the_minimum_are_dropped():
    assert "abc" not in strings.extract_raw(b"\x00abc\x00", min_length=4)
    assert "abcd" in strings.extract_raw(b"\x00abcd\x00", min_length=4)


def test_utf16le_is_found_too():
    """A Windows binary keeps most of its text in UTF-16LE.

    An extractor that only reads ASCII misses the half that matters.
    """
    data = "C:\\Windows\\System32".encode("utf-16-le")
    assert "C:\\Windows\\System32" in strings.extract_raw(data)


def test_utf16le_is_not_also_reported_as_broken_ascii():
    """UTF-16LE text is ASCII bytes with NULs between them.

    Read as ASCII it becomes a stream of one-character runs, which the minimum
    length drops. The test pins that nothing longer leaks through.
    """
    data = "administrator".encode("utf-16-le")
    found = strings.extract_raw(data)
    assert "administrator" in found
    assert not any(s != "administrator" and len(s) >= 4 for s in found)


# --------------------------------------------------------------------------
# URLs and IPs
# --------------------------------------------------------------------------


@pytest.mark.parametrize("text", [
    "http://example.com/path",
    "https://api.example.org:8443/v1",
])
def test_urls_are_recognised(text):
    assert text in strings.classify([text]).urls


def test_a_url_does_not_also_count_as_a_bare_domain():
    """One string, one claim. Reporting example.com twice is noise."""
    found = strings.classify(["https://example.com/x"])
    assert found.urls == ["https://example.com/x"]
    assert found.hosts == []


@pytest.mark.parametrize("text", ["10.0.0.1", "192.168.1.254", "8.8.8.8"])
def test_ipv4_is_recognised(text):
    assert text in strings.classify([text]).ips


@pytest.mark.parametrize("text", [
    "256.1.1.1",        # out of range
    "1.2.3",            # too few octets
    "1.2.3.4.5",        # too many
    "10.0.19045",       # a Windows build number, not an address
])
def test_things_shaped_like_an_ip_but_not_one(text):
    assert text not in strings.classify([text]).ips


def test_a_version_number_is_not_an_address():
    """1.2.3.4 is a valid address and a common version string.

    It is reported, because refusing every dotted quad would lose real
    addresses, but this test exists so the ambiguity is a decision on record
    rather than an accident.
    """
    assert "1.2.3.4" in strings.classify(["1.2.3.4"]).ips


# --------------------------------------------------------------------------
# domains — where the false positives live
# --------------------------------------------------------------------------


@pytest.mark.parametrize("text", [
    "example.com",
    "api.github.com",
    "sub.domain.co.uk",
])
def test_real_domains_are_recognised(text):
    assert text in strings.classify([text]).hosts


@pytest.mark.parametrize("text", [
    "kernel32.dll",
    "MSVCRT.dll",
    "advapi32.DLL",
    "setup.exe",
    "config.ini",
    "output.log",
    "data.tmp",
    "notes.txt",
    "module.sys",
])
def test_a_filename_is_not_a_domain(text):
    """The single most common false positive in a PE.

    Every imported DLL name has this shape, so a classifier that gets this
    wrong reports thirty domains for a binary that contacts none.
    """
    assert text not in strings.classify([text]).hosts


def test_a_dll_name_is_not_smuggled_in_as_a_path_either():
    assert "kernel32.dll" not in strings.classify(["kernel32.dll"]).paths


@pytest.mark.parametrize("text", ["localhost", "no-dot-here", "..", "a.b"])
def test_things_that_are_not_domains(text):
    assert text not in strings.classify([text]).hosts


# --------------------------------------------------------------------------
# paths
# --------------------------------------------------------------------------


@pytest.mark.parametrize("text", [
    "C:\\Windows\\System32\\drivers",
    "D:\\Program Files\\App\\bin",
])
def test_windows_paths(text):
    assert text in strings.classify([text]).paths


@pytest.mark.parametrize("text", ["/usr/local/bin", "/etc/passwd"])
def test_unix_paths(text):
    assert text in strings.classify([text]).paths


def test_a_url_path_is_not_a_unix_path():
    found = strings.classify(["https://example.com/usr/local/bin"])
    assert found.paths == []


# --------------------------------------------------------------------------
# the whole pass
# --------------------------------------------------------------------------


def test_results_are_deduplicated_and_ordered():
    found = strings.classify(["example.com", "example.com", "aaa.example.com"])
    assert found.hosts == ["aaa.example.com", "example.com"]


def test_extract_reads_a_real_binary(pe_path):
    found = strings.extract(pe_path.read_bytes())
    assert isinstance(found.urls, list)
    # python.exe is not expected to carry any of these; the point is that a
    # real 100 KB binary does not blow the classifier up or flood it.
    assert len(found.hosts) < 50, found.hosts[:10]


# --------------------------------------------------------------------------
# regressions found by running against a real binary, not by imagining inputs
# --------------------------------------------------------------------------


@pytest.mark.parametrize("text, expected", [
    ("Vhttp://example.com/a.crl0t", "http://example.com/a.crl"),
    ("Xhttps://example.com/b.crt0T", "https://example.com/b.crt"),
])
def test_a_url_embedded_in_binary_noise_is_trimmed(text, expected):
    """Certificates store URLs with DER length bytes either side.

    The first pass reported `Vhttp://...crl0t` as a URL, scheme and all,
    because the pattern only required "something, then ://". Six of the seven
    URLs found in the fixture looked like that.
    """
    assert strings.classify([text]).urls == [expected]


def test_urls_run_together_are_split_at_each_scheme():
    """A font's name table stores its strings back to back, no separator.

    The NK57 Monospace font embedded in BIOSdump2license.exe gave three URLs
    as one: `http://typodermicfonts.com/pages/licensehttp://www.typo...`. A
    scheme can only start a URL, so wherever one appears, the previous URL
    ended.
    """
    text = (
        "http://typodermicfonts.com/pages/license"
        "http://www.typodermicfonts.com"
        "http://typodermicfonts.com/license"
    )
    assert strings.classify([text]).urls == sorted([
        "http://typodermicfonts.com/pages/license",
        "http://www.typodermicfonts.com",
        "http://typodermicfonts.com/license",
    ])


def test_the_split_works_across_schemes():
    text = "ftp://a.example.com/xhttps://b.example.com/y"
    assert strings.classify([text]).urls == ["ftp://a.example.com/x", "https://b.example.com/y"]


def test_each_url_of_a_run_is_still_trimmed_of_der_debris():
    """The certificate trimming must survive being applied per URL."""
    text = "Vhttp://example.com/a.crl0thttp://example.com/b.crt0T"
    assert strings.classify([text]).urls == ["http://example.com/a.crl", "http://example.com/b.crt"]


def test_only_real_schemes_count():
    assert strings.classify(["Vhttp://example.com/x"]).urls == ["http://example.com/x"]
    assert strings.classify(["zzz://example.com/x"]).urls == []


@pytest.mark.parametrize("text", ["g.iG", "a.bc", "x.yZ"])
def test_two_tiny_labels_are_noise_not_a_domain(text):
    """`g.iG` came out of the certificate bytes of the fixture.

    A single-character label with a two-character suffix is far more often
    random bytes than a hostname. This costs the rare real `x.co`, which is a
    trade worth making when the alternative is a report full of debris.
    """
    assert text not in strings.classify([text]).hosts


# --------------------------------------------------------------------------
# excluding regions — the signature blob is not the program's text
# --------------------------------------------------------------------------


def test_an_excluded_region_contributes_nothing():
    data = b"\x00keepthisone\x00" + b"\x00dropthisone\x00"
    start = data.index(b"dropthisone")
    found = strings.extract_raw(data, exclude=[(start, start + len(b"dropthisone"))])
    assert "keepthisone" in found
    assert "dropthisone" not in found


def test_a_string_straddling_the_boundary_is_not_reported_whole():
    """Half a string is not the string. Cutting at the boundary is the point."""
    data = b"\x00" + b"aaaaBBBB" + b"\x00"
    start = data.index(b"BBBB")
    found = strings.extract_raw(data, exclude=[(start, start + 4)])
    assert "aaaaBBBB" not in found
    assert "aaaa" in found


def test_several_regions_can_be_excluded():
    data = b"\x00first\x00second\x00third\x00"
    regions = [(data.index(b"first"), data.index(b"first") + 5),
               (data.index(b"third"), data.index(b"third") + 5)]
    found = strings.extract_raw(data, exclude=regions)
    assert found == ["second"]


def test_no_regions_behaves_as_before():
    data = b"\x00hello there\x00"
    assert strings.extract_raw(data) == strings.extract_raw(data, exclude=[])


# --------------------------------------------------------------------------
# what a last label has to be
# --------------------------------------------------------------------------


def test_a_suffix_nobody_delegated_is_not_a_domain():
    """Measured on a 436 MiB HP installer, 2026-09-26: 2,449 "hosts" came out
    of its compressed payload — `00c.Bvv`, `01.CX`, `03V.yP` — and not one of
    them was real. What they have in common is a last label that does not
    exist: IANA delegates 1,438 and `bvv` is not among them."""
    found = strings.classify(["00c.bvv", "03v.yp", "zzq.qqz"])

    assert found.hosts == []


def test_a_dotnet_namespace_is_not_a_domain():
    """The largest class by count in the Kyocera installers. `Mono.Cecil` and
    `IniParser.Model` match every structural rule a hostname has; the last
    label is what tells them apart, because no one delegated `.cecil`."""
    found = strings.classify([
        "mono.cecil", "iniparser.model", "mono.security.cryptography",
        "katana.models", "mono.cecil.metadata", "communitytoolkit.mvvm",
    ])

    assert found.hosts == []


@pytest.mark.parametrize(
    "namespace", ["katana.services", "microsoft.net", "mono.cecil.pe", "system.management"]
)
def test_a_namespace_ending_in_a_delegated_word_is_the_residue(namespace):
    """Named rather than hidden: this is what the rule cannot do.

    The new-gTLD programme turned ordinary English words into suffixes, so
    `.services`, `.tools`, `.management` and `.pe` are real delegations and a
    namespace ending in one is a hostname as far as any rule here can tell.
    `Microsoft.NET` is the honest worst case. Measured on the Kyocera
    installers, five namespace suffixes of thirteen collided this way.
    """
    assert strings.classify([namespace]).hosts == [namespace]


def test_real_domains_still_come_through():
    found = strings.classify([
        "www.example.com", "kyoceradocumentsolutions.it", "crl.microsoft.com",
        "sub.domain.co.uk",
    ])

    assert found.hosts == [
        "crl.microsoft.com", "kyoceradocumentsolutions.it", "sub.domain.co.uk",
        "www.example.com",
    ]


def test_a_delegated_suffix_is_enough_whatever_its_case():
    """Hostnames are case-insensitive and a binary may well write HP.COM."""
    assert strings.classify(["WWW.EXAMPLE.COM"]).hosts == ["WWW.EXAMPLE.COM"]


# --------------------------------------------------------------------------
# filenames wearing an archive's signature
# --------------------------------------------------------------------------


def test_a_filename_followed_by_a_zip_signature_is_still_a_filename():
    """`PK` is the first two bytes of a ZIP local file header and `UT` is the
    extended-timestamp extra field: inside an archive both land immediately
    after the member's name, so the printable run is `Newtonsoft.Json.dllPK`.
    The extension list never saw it, because `dllpk` is not `dll`."""
    found = strings.classify([
        "Newtonsoft.Json.dllPK", "KmInstall.exeUT", "lang.datUT",
        "0001.txtux", "Install.pnfUT", "KmInstall4.iniUT",
    ])

    assert found.hosts == []


def test_a_real_domain_is_not_mistaken_for_an_archive_artefact():
    """Stripping a trailing marker must only apply when what is left is a
    filename. `example.computer` ends in `ux`-nothing and is a real TLD."""
    assert strings.classify(["shop.computer"]).hosts == ["shop.computer"]


# --------------------------------------------------------------------------
# a dotted quad the file itself calls a version
# --------------------------------------------------------------------------


def test_a_quad_the_file_calls_a_version_is_not_an_address():
    """Four Kyocera installers reported `1.1.8.0`, `1.1.3.0`, `1.1.2.0` as IP
    addresses. Each appears twice in its binary: once alone, in the .NET
    metadata where strings are length-prefixed, and once inside
    `Katana, Version=1.1.8.0, Culture=neutral`. The second occurrence is the
    file saying what the first one is."""
    found = strings.classify([
        "1.1.8.0",
        "Katana, Version=1.1.8.0, Culture=neutral, PublicKeyToken=79af7b307b65cf3c",
    ])

    assert found.ips == []


def test_fileversion_and_productversion_count_too():
    found = strings.classify(["1.1.2.0", "FileVersion=1.1.2.0"])

    assert found.ips == []


def test_a_quad_with_nothing_to_explain_it_is_still_reported():
    """The rule is corroboration, not shape. `1.1.8.0` on its own is a valid
    address and a likely version, and this tool does not get to guess: the
    comment in _is_ipv4 has been right about that since it was written."""
    assert strings.classify(["1.1.8.0"]).ips == ["1.1.8.0"]


def test_an_address_the_file_never_calls_a_version_survives():
    found = strings.classify([
        "8.8.8.8", "Katana, Version=1.1.8.0, Culture=neutral", "1.1.8.0",
    ])

    assert found.ips == ["8.8.8.8"]


def test_the_cost_of_the_rule_is_written_down():
    """A binary that hardcodes 8.8.8.8 *and* carries version 8.8.8.8 loses the
    address. It is the one way this rule is wrong, it needs both facts in one
    file, and it is cheaper than reporting every build number as an endpoint.
    """
    found = strings.classify(["8.8.8.8", "ProductVersion=8.8.8.8"])

    assert found.ips == []
