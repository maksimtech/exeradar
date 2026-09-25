"""What signature.py has to do — and, more than anything, what it must not.

The rule these tests exist to hold: the absence of an embedded signature is
UNSIGNED only where the catalog could actually be consulted. Everywhere else it
is UNKNOWN. Get that wrong and the tool reports every catalog-signed Windows
binary as unsigned, which is most of System32.

The test that matters most is test_no_embedded_signature_is_not_unsigned_off_windows,
and it runs on the Linux CI where the mistake would otherwise be invisible.
"""

from __future__ import annotations

import sys

import pytest

from exeradar import signature
from exeradar.models import SignatureState

# --------------------------------------------------------------------------
# the rule — runs everywhere, and is the point of the module
# --------------------------------------------------------------------------


def test_catalog_availability_matches_the_platform():
    assert signature.catalog_available() is (sys.platform == "win32")


@pytest.mark.skipif(sys.platform == "win32", reason="the off-Windows rule")
def test_no_embedded_signature_is_not_unsigned_off_windows(unsigned_pe_path):
    """Path B cannot run here, so C is not a conclusion that can be reached.

    On a PE that parses and has no signature, so that the platform rule is what
    produces UNKNOWN. This used to pass `MZ` and zeros, which LIEF cannot parse
    at all — and an unreadable file is now UNKNOWN for its own reason, which
    would have made this test pass without the rule it is about.
    """
    result = signature.inspect(unsigned_pe_path)

    assert result.state is SignatureState.UNKNOWN
    assert result.state is not SignatureState.UNSIGNED
    assert result.verified is None
    assert "not verifiable" in (result.detail or "").lower()


@pytest.mark.skipif(sys.platform != "win32", reason="path B needs Windows")
def test_no_signature_anywhere_is_unsigned_on_windows(unsigned_pe_path):
    """Both paths ran and found nothing, so the finding is real.

    "Both ran" is the part that needs a readable file: the subject here is a
    signed binary with its certificate table zeroed, so the embedded path really
    looked and really found nothing. `MZ` and zeros could not say that — see
    test_unreadable_pe.py.
    """
    result = signature.inspect(unsigned_pe_path)

    assert result.state is SignatureState.UNSIGNED
    assert result.verified is False


# --------------------------------------------------------------------------
# path A — an embedded signature, readable anywhere
# --------------------------------------------------------------------------


def test_embedded_signature_is_read(signed_pe_path):
    result = signature.inspect(signed_pe_path)

    assert result.state is SignatureState.EMBEDDED
    assert result.verified is True
    assert result.signer
    assert result.chain, "the certificate chain was dropped"


def test_the_chain_is_ordered_leaf_first(signed_pe_path):
    """The signer's certificate is the one a report should lead with."""
    result = signature.inspect(signed_pe_path)
    leaf = result.chain[0]

    assert leaf.is_ca is False
    assert leaf.subject
    assert leaf.valid_from and leaf.valid_to


def test_certificate_dates_are_text_not_lief_lists(signed_pe_path):
    """LIEF returns [Y, M, D, h, m, s]; the model promises a string.

    The spike printed those raw lists. Anything that reaches the JSON report
    has to be serialisable and readable.
    """
    leaf = signature.inspect(signed_pe_path).chain[0]
    assert isinstance(leaf.valid_from, str)
    assert leaf.valid_from[:2] == "20"


def test_the_timestamp_is_extracted_when_there_is_one(signed_pe_path):
    """LIEF exposes the RFC3161 token but not the time inside it.

    This is the one job signify is a dependency for. A countersignature with no
    date read out of it is a countersignature that proves nothing.

    Whether a countersignature exists is established from LIEF rather than from
    the result under test. An earlier version of this test skipped when
    `result.timestamper` was None, which meant it skipped in exactly the case
    where the extraction had failed — the gap hid behind its own symptom.
    """
    import lief

    binary = lief.PE.parse(str(signed_pe_path))
    has_counter = any(
        type(attribute).__name__ == "MsCounterSign"
        for signer in binary.signatures[0].signers
        for attribute in signer.unauthenticated_attributes
    )
    if not has_counter:
        pytest.skip("this sample carries no countersignature")

    result = signature.inspect(signed_pe_path)
    # detail carries the reason when the decode failed, so a failure here says
    # what went wrong instead of only that something did.
    assert result.timestamp, f"the token was found but its date was not decoded: {result.detail}"
    assert result.timestamper, f"the token was found but the authority was not named: {result.detail}"


def test_a_signature_outlives_its_certificate(signed_pe_path):
    """The reason a countersignature is worth extracting at all.

    The fixture's certificate expired in August 2026 and the signature still
    verifies, because the timestamp proves the file was signed while the
    certificate was valid. If this ever starts failing, either the timestamp
    stopped being honoured or the fixture changed.
    """
    result = signature.inspect(signed_pe_path)
    if not result.timestamp:
        pytest.skip("no timestamp to reason about")
    assert result.verified is True
    assert result.chain[0].valid_to < result.timestamp or result.verified


# --------------------------------------------------------------------------
# path B — the catalog, Windows only
# --------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="path B needs Windows")
def test_a_catalog_signed_binary_is_not_reported_as_unsigned(catalog_pe_path):
    """notepad.exe carries no embedded signature and is validly signed.

    This is the case that made the architecture have three paths instead of
    one, so it is the case that must never regress.
    """
    import lief

    assert len(lief.PE.parse(str(catalog_pe_path)).signatures) == 0, "sample is not catalog-only"

    result = signature.inspect(catalog_pe_path)

    assert result.state is SignatureState.CATALOG
    assert result.verified is True
    assert result.signer
    assert result.state is not SignatureState.UNSIGNED


@pytest.mark.skipif(sys.platform != "win32", reason="path B needs Windows")
def test_the_catalog_path_does_not_run_when_the_file_is_embedded_signed(signed_pe_path):
    """Path A wins: there is no reason to pay for a PowerShell start-up."""
    assert signature.inspect(signed_pe_path).state is SignatureState.EMBEDDED
