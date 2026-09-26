"""The other way a signature carries its time.

Reported from real use on 2026-09-26: two Canon printer drivers came back with
no timestamp at all, while Windows read one from the same files —
`Get-AuthenticodeSignature` named `CN=DigiCert Timestamp 2021` as the
timestamper of MF440SeriesMFDriverV6604WP.exe.

The cause is that Authenticode has two countersignature forms and this package
looked for one. The RFC3161 token lives in an unsigned attribute called
`microsoft_time_stamp_token`; the older PKCS#9 form is a whole `SignerInfo` in
an attribute called `counter_signature`, with the time in its own
`signing_time` and the authority named by issuer and serial rather than carried
alongside. Canon signs with the second. Asked for the first and finding
nothing, `_timestamp` returned "no timestamp" — and returned it as a fact about
the file rather than as a form it had not looked for, which is the distinction
this package exists to keep.

The fixture is the PKCS#7 blob of that driver, 7,560 bytes lifted out of a
308 MB installer that is not in this repository. It carries public
certificates and a signature over bytes nobody here has; it is here because a
structure described in a comment is a structure nobody checked.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from asn1crypto import cms

from exeradar import signature

FIXTURE = Path(__file__).parent / "fixtures" / "canon_countersignature.der"

# Recorded when the blob was lifted, 2026-09-26. A fixture that changes without
# anyone saying so is a test measuring something else.
FIXTURE_SHA256 = "4efcc9abae41b5a4885897d654526038db6649a9115777e1002249b84089917e"


@pytest.fixture(scope="module")
def content():
    return cms.ContentInfo.load(FIXTURE.read_bytes())


def test_the_fixture_is_the_blob_that_was_recorded():
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == FIXTURE_SHA256


def test_the_fixture_really_carries_the_old_form(content):
    """Otherwise this whole file tests the path it was written to avoid."""
    signer = content["content"]["signer_infos"][0]
    present = {attribute["type"].native for attribute in signer["unsigned_attrs"]}

    assert "counter_signature" in present
    assert "microsoft_time_stamp_token" not in present


def test_the_time_is_read_from_a_pkcs9_countersignature(content):
    when, _, problem = signature.timestamp_of(content)

    assert problem is None
    assert when == "2022-03-09 04:29:54 UTC"


def test_the_authority_is_the_certificate_the_countersignature_names(content):
    """Named by issuer and serial, not bundled: the certificate has to be found
    among the ones the outer signature carries. Windows reads the same file and
    reports `CN=DigiCert Timestamp 2021`."""
    _, authority, _ = signature.timestamp_of(content)

    assert authority is not None
    assert "DigiCert Timestamp 2021" in authority


def test_a_signature_with_neither_form_reports_no_timestamp(content):
    """Still the honest answer when it is the true one: nothing found, and no
    reason, because there was nothing to fail at."""
    stripped = cms.ContentInfo.load(FIXTURE.read_bytes())
    stripped["content"]["signer_infos"][0]["unsigned_attrs"] = cms.CMSAttributes([])

    assert signature.timestamp_of(stripped) == (None, None, None)


def test_the_rfc3161_form_still_works():
    """The fixture that was already here signs with the other form, so both
    paths are exercised by real bytes."""
    pe = Path(__file__).parent / "fixtures" / "python.exe"
    when, authority, problem = signature._timestamp(pe)

    assert problem is None
    assert when and when.endswith("UTC")
    assert authority and "Time Stamping" in authority
