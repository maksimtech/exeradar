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
