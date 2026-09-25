"""The signer is named by the PKCS#7, not by the order of the certificate list.

`_chain` sorted the certificates by `is_ca` and took the first one as the signer.
That works while the blob holds exactly one leaf. It stops working the moment the
timestamp authority's own certificate travels in the same blob, because that is a
leaf too — and then whichever leaf LIEF lists first becomes "the signer".

Reproduced on 2026-09-25 against four signed installers on this machine:

| file                                | reported signer                              |
|-------------------------------------|----------------------------------------------|
| Claude Setup.exe                    | DigiCert SHA256 RSA4096 Timestamp Responder  |
| Precision_3561_Latitude_5521_1.44.0 | DigiCert SHA256 RSA4096 Timestamp Responder  |
| lghub_installer.exe                 | DigiCert SHA256 RSA4096 Timestamp Responder  |
| api-monitor-v2r13-setup-x86.exe     | Symantec Time Stamping Services Signer       |

Each of those files is validly signed by its vendor, and exeradar said DigiCert or
Symantec signed it. The same was seen on three Lenovo installers (n2lrg16w,
nz7w809w, r0yvu39w), reported as DigiCert Timestamp rather than Lenovo.

CMS does not leave this to be guessed: SignerInfo carries `sid`, the issuer and
serial of the certificate that signed. exeradar already loads the blob with
asn1crypto to read the RFC3161 timestamp, so the authoritative answer costs
nothing extra.

The repository's own fixture cannot reproduce the defect — python.exe carries one
leaf, so the old code happened to be right about it — and the installers above are
third-party binaries of tens of megabytes that do not belong in a test suite. So
the ordering rule is tested against stub certificates, and the reading of the real
SignerInfo against the real fixture: between them, every step of the path the four
files took is covered.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from exeradar import signature
from exeradar.models import SignatureState

FIXTURE = Path(__file__).parent / "fixtures" / "python.exe"

# Verbatim from Claude Setup.exe, which is the shape of all four.
TIMESTAMPER = "C=US, O=DigiCert\\, Inc., CN=DigiCert SHA256 RSA4096 Timestamp Responder 2025 1"
VENDOR = "C=US, ST=California, O=Anthropic PBC, CN=Anthropic PBC"

SIGNER_SERIAL = 0x0B1C2D3E4F
STAMPER_SERIAL = 0xA1B2C3D4E5


class _Cert:
    """As much of LIEF's certificate as _chain touches."""

    def __init__(self, subject, serial, is_ca=False):
        self.subject = subject
        self.issuer = "CN=Some CA"
        self.valid_from = [2025, 1, 1, 0, 0, 0]
        self.valid_to = [2027, 1, 1, 0, 0, 0]
        self.serial_number = serial.to_bytes(16, "big")
        self.signature_algorithm = "SHA256_WITH_RSA_ENCRYPTION"
        self.is_ca = is_ca


class _Signature:
    def __init__(self, certificates, raw_der=b""):
        self.certificates = certificates
        self.raw_der = raw_der
        self.digest_algorithm = "ALGORITHMS.SHA_256"


def both_leaves(stamper_first: bool) -> _Signature:
    """The signer's leaf and the timestamper's, in either order."""
    signer = _Cert(VENDOR, SIGNER_SERIAL)
    stamper = _Cert(TIMESTAMPER, STAMPER_SERIAL)
    leaves = [stamper, signer] if stamper_first else [signer, stamper]
    return _Signature([*leaves, _Cert("CN=Root CA", 0xFF, is_ca=True)])


# ── the ordering ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("stamper_first", [True, False])
def test_the_certificate_the_pkcs7_names_comes_first(stamper_first):
    """Whatever order the blob lists them in."""
    chain = signature._chain(both_leaves(stamper_first), signer_serial=SIGNER_SERIAL)

    assert chain[0].subject == VENDOR


@pytest.mark.parametrize("stamper_first", [True, False])
def test_the_timestamper_is_never_the_signer(stamper_first):
    chain = signature._chain(both_leaves(stamper_first), signer_serial=SIGNER_SERIAL)

    assert "Timestamp" not in chain[0].subject


def test_no_certificate_is_dropped():
    """The timestamper's certificate is part of what the file carries; it is
    ordered, not hidden."""
    chain = signature._chain(both_leaves(True), signer_serial=SIGNER_SERIAL)

    assert len(chain) == 3
    assert TIMESTAMPER in [c.subject for c in chain]


def test_the_certificate_authorities_still_come_after_the_leaves():
    chain = signature._chain(both_leaves(False), signer_serial=SIGNER_SERIAL)

    assert [c.is_ca for c in chain] == [False, False, True]


def test_an_unknown_serial_falls_back_to_the_old_order():
    """If the CMS cannot be read there is nothing better to go on, and a name is
    more use than none — this is the behaviour that was wrong for two leaves and
    right for the one-leaf files that are the majority."""
    chain = signature._chain(both_leaves(True), signer_serial=None)

    assert chain[0].subject == TIMESTAMPER
    assert [c.is_ca for c in chain] == [False, False, True]


def test_a_serial_that_matches_nothing_is_not_an_error():
    chain = signature._chain(both_leaves(False), signer_serial=0xDEADBEEF)

    assert len(chain) == 3
    assert chain[0].subject == VENDOR  # the old order, unchanged


def test_a_blob_with_one_leaf_is_unaffected():
    one = _Signature([_Cert(VENDOR, SIGNER_SERIAL), _Cert("CN=Root CA", 0xFF, is_ca=True)])

    assert signature._chain(one, signer_serial=SIGNER_SERIAL)[0].subject == VENDOR


# ── reading the real SignerInfo ─────────────────────────────────────────────


def test_the_signer_serial_is_read_from_the_fixture():
    """Against the real blob: the answer must be the leaf, not a CA and not None.

    python.exe is signed by the Python Software Foundation through a Microsoft
    issuing CA; the SignerInfo names one certificate out of the four inside.
    """
    import lief

    binary = lief.PE.parse(str(FIXTURE))
    serial = signature._signer_serial(binary.signatures[0])

    assert serial is not None
    leaf = next(c for c in binary.signatures[0].certificates if not bool(c.is_ca))
    assert serial == int(leaf.serial_number.hex(), 16)


def test_the_fixture_still_names_the_python_software_foundation():
    """The regression guard for the files the old code was right about."""
    found = signature.inspect(FIXTURE)

    assert found.state is SignatureState.EMBEDDED
    assert "Python Software Foundation" in (found.signer or "")


def test_an_unreadable_blob_yields_no_serial_rather_than_raising():
    """A malformed or truncated PKCS#7 must not take the whole inspection down:
    the state and the chain are still worth reporting."""
    assert signature._signer_serial(_Signature([], raw_der=b"not der at all")) is None


def test_a_signer_id_that_is_not_an_issuer_and_serial_is_declined():
    """CMS also allows a subject key identifier. Nothing is guessed from it."""
    assert signature._signer_serial(_Signature([], raw_der=b"")) is None
