"""What LIEF's verification answer is worth, which is not one thing.

`verify_signature()` returns a bitmask of thirteen flags and this package read it
as `== OK`. Everything else became `verified=False`, which law_checker turns into
`signature_invalid` — "Embedded signature not valid", severity high, cited against
CRA Annex I Part I(2)(f) and art. 13(1), NIS2 21(2)(d) and GDPR 32(1).

Five of those flags say no such thing:

    UNSUPPORTED_ALGORITHM         LIEF does not implement the algorithm
    CERT_NOT_FOUND                the blob does not carry the signer's own
                                  certificate, so there is nothing to compare
    MISSING_PKCS9_MESSAGE_DIGEST  the authenticated attributes are not laid out
                                  the way LIEF looks for. Older Authenticode
                                  blobs are not, and Windows accepts them
    CERT_EXPIRED / CERT_FUTURE    the certificate's dates do not cover the
                                  moment of the check, which says nothing about
                                  the digest — and `certificate_expired` is a
                                  separate finding, with its own provisions and
                                  its own severity

So the verdict is three-valued, `verified is None` means the check did not reach
a conclusion, and the flags travel with it so that a report can say which.

The other half of this file is the state, not the verdict: a certificate table
that is inside the file and still unreadable used to end up as UNSIGNED — "no
embedded signature and no catalog entry" — for a file that carries one.
"""

from __future__ import annotations

import lief
import pytest

from exeradar import report, signature
from exeradar.models import Signature, SignatureState

FLAGS = lief.PE.Signature.VERIFICATION_FLAGS


def flag(*names: str):
    """The bitmask LIEF would return for these flags together."""
    mask = 0
    for name in names:
        mask |= int(getattr(FLAGS, name))
    return FLAGS(mask)


# --------------------------------------------------------------------------
# the verdict
# --------------------------------------------------------------------------


def test_ok_is_a_pass_and_says_so_by_name():
    assert signature._verdict(FLAGS.OK) == (True, ("ok",))


@pytest.mark.parametrize(
    "name",
    ["BAD_DIGEST", "BAD_SIGNATURE", "CORRUPTED_AUTH_DATA", "CORRUPTED_CONTENT_INFO",
     "INCONSISTENT_DIGEST_ALGORITHM", "INVALID_SIGNER", "NO_SIGNATURE"],
)
def test_the_flags_that_mean_the_file_does_not_match_are_a_failure(name):
    verified, names = signature._verdict(flag(name))

    assert verified is False
    assert names == (name.lower(),)


@pytest.mark.parametrize(
    "name",
    ["UNSUPPORTED_ALGORITHM", "CERT_NOT_FOUND", "MISSING_PKCS9_MESSAGE_DIGEST",
     "CERT_EXPIRED", "CERT_FUTURE"],
)
def test_the_flags_that_mean_we_could_not_check_are_not_a_failure(name):
    """The defect, one flag at a time. Each of these produced a high-severity
    finding against the publisher for a limitation of the check."""
    verified, names = signature._verdict(flag(name))

    assert verified is None
    assert names == (name.lower(),)


def test_one_real_failure_outweighs_any_number_of_unknowns():
    """LIEF's own answer for the repository fixture under LIFETIME_SIGNING is
    BAD_SIGNATURE|CERT_EXPIRED, so this combination is not hypothetical."""
    verified, names = signature._verdict(flag("BAD_SIGNATURE", "CERT_EXPIRED"))

    assert verified is False
    assert set(names) == {"bad_signature", "cert_expired"}


def test_every_flag_lief_has_is_classified():
    """The check on the check: a flag nobody sorted would fall to "could not
    tell" and quietly stop being reported. If LIEF adds one, this fails here
    rather than in a report.
    """
    known = {name.lower() for name in signature._INVALID_FLAGS}
    known |= {name.lower() for name in signature._UNDETERMINED_FLAGS}
    theirs = {
        name.lower() for name in dir(FLAGS)
        if not name.startswith("_") and name != "OK" and isinstance(getattr(FLAGS, name), FLAGS)
    }

    assert theirs - known == set(), f"unclassified LIEF flags: {sorted(theirs - known)}"


def test_a_mask_with_nothing_recognisable_still_says_something():
    """A number this code cannot name is reported as that number, not dropped."""
    verified, names = signature._verdict(1 << 20)

    assert verified is None
    assert names == ("unrecognised:1048576",)


# --------------------------------------------------------------------------
# the fixture, which is the whole path at once
# --------------------------------------------------------------------------


def test_the_committed_sample_matches_its_signature(signed_pe_path):
    found = signature.inspect(signed_pe_path)

    assert found.state is SignatureState.EMBEDDED
    assert found.verified is True
    assert found.verification == ("ok",)


def _with_signer_serial_changed(signed_pe_path, tmp_path):
    """The sample with one byte of the signer's serial changed where SignerInfo
    names it, and nowhere else. Derived data: the certificate itself and every
    signed byte are as recorded, so the blob no longer points at the certificate
    it carries — the case of Steam's WriteMiniDump.exe, whose one certificate LIEF
    1.0.0 could not parse."""
    data = signed_pe_path.read_bytes()
    serial = bytes(lief.PE.parse(str(signed_pe_path)).signatures[0].signers[0].serial_number)
    assert data.count(serial) == 2, "the serial is in the certificate and in SignerInfo"
    changed = bytearray(data)
    changed[data.rfind(serial) + len(serial) - 1] ^= 0x01
    target = tmp_path / "signer_not_found.exe"
    target.write_bytes(bytes(changed))
    return target


def test_a_signer_certificate_that_cannot_be_found_is_not_a_bad_signature(signed_pe_path, tmp_path):
    """LIEF's `verify_signature()` adds BAD_SIGNATURE whenever the signature check
    did not pass, for whatever reason. With the signer's certificate missing it
    answered CERT_NOT_FOUND|BAD_SIGNATURE, which `_verdict` read as "not valid"
    and law_checker turned into `signature_invalid`, severity high — for
    WriteMiniDump.exe, which Windows and signtool validate, and whose digest is
    the one signed. Nothing was found wrong; the check could not be made."""
    found = signature.inspect(_with_signer_serial_changed(signed_pe_path, tmp_path))

    assert found.verified is None, found.verification
    assert "cert_not_found" in found.verification
    assert "bad_signature" not in found.verification


def test_a_changed_byte_is_still_a_file_that_does_not_match(signed_pe_path, tmp_path):
    """The other side of the case above: when the bytes are not the bytes that
    were signed, that is still said, by the flag that means it."""
    data = bytearray(signed_pe_path.read_bytes())
    data[0x500] ^= 0xFF
    tampered = tmp_path / "tampered.exe"
    tampered.write_bytes(bytes(data))

    found = signature.inspect(tampered)

    assert found.verified is False
    assert found.verification == ("bad_digest",)


# Files on this machine that Windows validates and LIEF 1.0.0 called not valid,
# found by comparing 1,500 PE files with Get-AuthenticodeSignature on 2026-10-17.
# Not redistributable, so they are asked where they exist and skipped elsewhere.
WINDOWS_VALIDATES = [
    r"C:\Program Files (x86)\Steam\WriteMiniDump.exe",       # CERT_NOT_FOUND|BAD_SIGNATURE
    r"C:\Windows\System32\drivers\Usb4HR64.sys",             # BAD_SIGNATURE|CERT_EXPIRED, not timestamped
]


@pytest.mark.parametrize("path", WINDOWS_VALIDATES)
def test_a_file_windows_validates_is_not_called_invalid(path):
    import os

    if not os.path.isfile(path):
        pytest.skip(f"{path} is not on this machine")

    found = signature.inspect(path)

    assert found.verified is not False, found.verification


def test_a_signature_that_is_there_and_unreadable_is_not_an_absent_one(signed_pe_path, tmp_path):
    """The bytes of the blob replaced, the certificate table left in place.

    LIEF parses the file, finds no signature it can read, and before this the
    answer was UNSIGNED: "no embedded signature and no catalog entry", about a
    file that carries 14 KB of one. On Windows the catalog was asked first and
    said no, which made the wrong answer look corroborated.
    """
    regions = signature.signed_regions(signed_pe_path)
    assert regions, "the fixture is supposed to be signed"
    start, end = regions[0]

    data = signed_pe_path.read_bytes()
    garbled = tmp_path / "garbled.exe"
    garbled.write_bytes(data[:start] + b"\x00" * (end - start) + data[end:])

    found = signature.inspect(garbled)

    assert found.state is SignatureState.UNKNOWN
    assert found.state is not SignatureState.UNSIGNED
    assert found.verified is None
    assert "present, unreadable" in (found.detail or "")
    assert str(end - start) in (found.detail or "")


def test_a_truncated_file_does_not_assert_why_it_is_truncated(signed_pe_path, tmp_path):
    """"truncated, so the signature cannot be read" named a cause.

    A certificate table pointing past the end of the file is a measurement; that
    a download was cut off is an explanation, and a malformed or forged header
    produces the same measurement. The report now gives the first and offers the
    second as the ordinary case.
    """
    cut = tmp_path / "cut.exe"
    cut.write_bytes(signed_pe_path.read_bytes()[:512])

    found = signature.inspect(cut)

    assert found.state is SignatureState.UNKNOWN
    detail = found.detail or ""
    assert "past the end of a 512-byte file" in detail
    assert "has not been established" in detail


# --------------------------------------------------------------------------
# what a reader is told
# --------------------------------------------------------------------------


def _embedded(verified, verification):
    return Signature(
        state=SignatureState.EMBEDDED, verified=verified, verification=verification
    )


def test_the_sentence_for_a_match_claims_no_trust():
    """"valid" was doing the work of "from a publisher you can trust", and no
    certificate store is consulted anywhere in this tool."""
    sentence = report.signature_sentence(_embedded(True, ("ok",)))

    assert "matches what was signed" in sentence
    assert "valid" not in sentence


def test_the_sentence_for_a_mismatch_says_which_flag():
    sentence = report.signature_sentence(_embedded(False, ("bad_digest",)))

    assert "does not match what was signed" in sentence
    assert "bad_digest" in sentence


def test_a_failure_that_is_not_the_digest_does_not_say_the_bytes_changed():
    """BAD_SIGNATURE is the signature over the signed attributes not verifying;
    the file may well be exactly what was signed. Only BAD_DIGEST says it is not."""
    sentence = report.signature_sentence(_embedded(False, ("bad_signature",)))

    assert "does not match what was signed" not in sentence
    assert "does not verify" in sentence
    assert "bad_signature" in sentence


def test_the_sentence_for_an_undetermined_check_accuses_nobody():
    sentence = report.signature_sentence(_embedded(None, ("unsupported_algorithm",)))

    assert "not checked to a conclusion" in sentence
    assert "unsupported_algorithm" in sentence
    assert "not valid" not in sentence


# --------------------------------------------------------------------------
# the exit code, which is what a script reads
# --------------------------------------------------------------------------


def test_verify_exits_two_when_the_check_did_not_conclude(signed_pe_path, monkeypatch):
    """0 matches, 1 does not, 2 could not be established.

    An embedded signature whose check did not conclude exited 1 — the code for
    "this signature is bad" — so a script gating an installation on it treated an
    algorithm LIEF cannot read as a tampered file.
    """
    from typer.testing import CliRunner

    from exeradar.cli import app

    monkeypatch.setattr(
        signature, "inspect",
        lambda path: _embedded(None, ("unsupported_algorithm",)),
    )
    outcome = CliRunner().invoke(app, ["verify", str(signed_pe_path)])

    assert outcome.exit_code == 2
    assert "not checked to a conclusion" in outcome.stdout
