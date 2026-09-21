"""What scanner.py has to do: pick a parser, run the passes, lose nothing.

The scanner owns the two things that are true of any executable — its hash and
its size — and delegates everything else. The tests check the delegation and
the failure modes, because those are what a caller depends on.
"""

from __future__ import annotations

import hashlib

import pytest

from exeradar import scanner
from exeradar.models import ExeResult, SignatureState

# --------------------------------------------------------------------------
# format detection
# --------------------------------------------------------------------------


@pytest.mark.parametrize("magic, expected", [
    (b"MZ\x90\x00", "PE"),
    (b"\x7fELF\x02\x01\x01\x00", "ELF"),
    (b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01", "MachO"),   # 64-bit, little endian
    (b"\xfe\xed\xfa\xcf\x00\x00\x00\x0c", "MachO"),   # big endian
])
def test_formats_are_told_apart_by_their_magic(magic, expected):
    assert scanner.detect_format(magic) == expected


@pytest.mark.parametrize("data", [b"", b"not an exe", b"%PDF-1.7", b"\x00\x00\x00\x00"])
def test_anything_else_has_no_format(data):
    assert scanner.detect_format(data) is None


# --------------------------------------------------------------------------
# what the scanner always fills in
# --------------------------------------------------------------------------


def test_hash_and_size_come_from_the_scanner(pe_path):
    result = scanner.scan(pe_path)
    expected = hashlib.sha256(pe_path.read_bytes()).hexdigest()

    assert result.sha256 == expected
    assert result.size == pe_path.stat().st_size
    assert result.path == str(pe_path)


def test_a_missing_file_is_an_error_not_an_exception(tmp_path):
    result = scanner.scan(tmp_path / "does-not-exist.exe")
    assert result.error
    assert result.format is None


def test_a_file_that_is_not_an_executable_says_so(tmp_path):
    plain = tmp_path / "notes.txt"
    plain.write_text("just text")

    result = scanner.scan(plain)

    assert result.error
    assert "format" in result.error.lower() or "recognis" in result.error.lower()
    assert result.sha256, "the hash is still a fact about the file"


# --------------------------------------------------------------------------
# the PE pass, end to end
# --------------------------------------------------------------------------


def test_a_pe_is_parsed_and_every_pass_runs(pe_path):
    result = scanner.scan(pe_path)

    assert result.error is None
    assert result.format == "PE"
    assert result.sections, "the PE parser did not run"
    assert result.imports, "the import table was lost"
    assert result.signature.state is not None, "signature.inspect did not run"
    assert isinstance(result.strings.hosts, list), "the string pass did not run"


def test_the_signature_pass_reaches_the_result(signed_pe_path):
    result = scanner.scan(signed_pe_path)
    assert result.signature.state is SignatureState.EMBEDDED
    assert result.signature.chain


def test_scan_returns_a_result_object_not_a_dict(pe_path):
    assert isinstance(scanner.scan(pe_path), ExeResult)


# --------------------------------------------------------------------------
# the formats that are not here yet
# --------------------------------------------------------------------------


@pytest.mark.parametrize("magic, name", [
    (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56, "ELF"),
    (b"\xcf\xfa\xed\xfe" + b"\x00" * 60, "MachO"),
])
def test_a_recognised_but_unimplemented_format_says_which(tmp_path, magic, name):
    """Detected, named, and declined — not silently treated as unknown.

    "ELF is not supported yet" and "I have no idea what this is" are different
    answers, and a caller can act on the first one.
    """
    sample = tmp_path / "binary"
    sample.write_bytes(magic)

    result = scanner.scan(sample)

    assert result.format == name
    assert result.error and "not supported" in result.error.lower()
    assert result.sha256


# --------------------------------------------------------------------------
# the signature blob is not the program's text
# --------------------------------------------------------------------------


def test_the_signature_region_is_found(signed_pe_path):
    from exeradar import signature

    regions = signature.signed_regions(signed_pe_path)

    assert regions, "a signed binary has a certificate table"
    start, end = regions[0]
    assert 0 < start < end <= signed_pe_path.stat().st_size


def test_an_unsigned_file_has_no_regions(tmp_path):
    from exeradar import signature

    plain = tmp_path / "nothing.exe"
    plain.write_bytes(b"MZ" + b"\x00" * 128)
    assert signature.signed_regions(plain) == []


def test_no_reported_string_comes_only_from_the_signature(signed_pe_path):
    """Every URL in the report must exist outside the certificate table.

    Before this, eleven URLs were reported for python.exe and almost all of
    them were CRL and OCSP endpoints belonging to the Microsoft certificate
    chain — facts about who signed the file, not about what it does.
    """
    from exeradar import signature

    result = scanner.scan(signed_pe_path)
    data = signed_pe_path.read_bytes()
    regions = signature.signed_regions(signed_pe_path)
    outside = bytearray(data)
    for start, end in regions:
        outside[start:end] = b"\x00" * (end - start)
    outside = bytes(outside)

    for url in result.strings.urls:
        assert url.encode("ascii", "ignore") in outside or \
               url.encode("utf-16-le") in outside, f"{url} exists only inside the signature"


def test_excluding_the_signature_drops_the_certificate_urls(signed_pe_path):
    """The whole point, measured: fewer URLs, and no CRL endpoints left."""
    from exeradar import signature, strings as strings_module

    everything = strings_module.from_file(signed_pe_path)
    filtered = strings_module.from_file(
        signed_pe_path, exclude=signature.signed_regions(signed_pe_path)
    )

    assert len(filtered.urls) < len(everything.urls)
    assert not [u for u in filtered.urls if "/crl/" in u.lower()]
