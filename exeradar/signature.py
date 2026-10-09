"""Code signing, by the three paths of ARCHITECTURE.md section 3.

A — an embedded Authenticode blob, read by LIEF. Works on every platform.
B — a catalog signature: the file itself carries nothing and the signature
    lives in a .cat file under CatRoot. Windows only.
C — neither, which is a finding.

The distinction this module exists to keep is between C and "we could not
look". Path B cannot run off Windows, so there the absence of an embedded
signature is UNKNOWN. Reporting it as UNSIGNED would fire on most of System32,
which is precisely where a reader would trust the tool least to be wrong.

The same distinction applies to the verdict on a signature that *is* there, and
that is newer than the three paths: `verified` is True, False or None, and None
covers everything LIEF declined to check rather than found wrong. See
`_verdict`.

What none of this establishes is trust. No operating system certificate store is
consulted, on any platform, so a self-signed certificate verifies exactly as
well as one from a commercial authority. The question answered here is whether
the file still matches what somebody signed, not whether anybody should have.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import lief

from exeradar.formats import pe
from exeradar.models import Certificate, Signature, SignatureState

_POWERSHELL_TIMEOUT = 60

# Where path B hands PowerShell the file to look at. See `_catalog`.
_TARGET_VARIABLE = "EXERADAR_TARGET"

# UNKNOWN has more than one cause, and a reader is told which. This one is about
# the platform and not about the file; law_checker matches on it to decide which
# note to print, so it is a constant rather than a literal in two places.
NOT_VERIFIABLE_HERE = "catalog signature: not verifiable on this platform"


def catalog_available() -> bool:
    """Whether path B can run at all here."""
    return sys.platform == "win32"


def signed_regions(path: str | Path) -> list[tuple[int, int]]:
    """The byte ranges the signature occupies, as (start, end) file offsets.

    Everything in there belongs to whoever signed the file, not to the program:
    certificate subjects, CRL distribution points, OCSP responders. Reporting
    those as the binary's URLs answers a question nobody asked — on the test
    fixture it was almost every URL found.

    The certificate table is the one PE data directory whose first field is a
    file offset rather than an RVA, which is what makes this cheap to do.
    """
    path = Path(path)
    try:
        binary = pe.parse(path)
    except Exception:  # noqa: BLE001 - nothing to exclude in a file we cannot read
        return []
    if binary is None:
        return []

    size = path.stat().st_size
    regions: list[tuple[int, int]] = []
    for directory in binary.data_directories:
        if "CERTIFICATE" not in str(directory.type).upper():
            continue
        if not directory.size:
            continue
        start = min(directory.rva, size)
        end = min(directory.rva + directory.size, size)
        if start < end:
            regions.append((start, end))
    return regions


def inspect(path: str | Path) -> Signature:
    path = Path(path)

    # Before anything is concluded: a file that cannot be read cannot be
    # reported as unsigned. UNSIGNED means both paths ran and found nothing.
    unreadable = _unreadable(path)
    if unreadable is not None:
        return Signature(state=SignatureState.UNKNOWN, verified=None, detail=unreadable)

    embedded = _embedded(path)
    if embedded is not None:
        return embedded

    # A certificate table the parser could not turn into a signature is not the
    # absence of a signature. Nothing above catches this: _unreadable only
    # objects to a table that runs past the end of the file, so a blob that is
    # entirely inside the file and still unreadable — a damaged copy, a format
    # LIEF declines, a deliberately malformed one — fell through to UNSIGNED and
    # was reported as "no embedded signature and no catalog entry".
    declared = signed_regions(path)
    if declared:
        start, end = declared[0]
        return Signature(
            state=SignatureState.UNKNOWN,
            verified=None,
            detail=(
                f"the file declares a certificate table of {end - start} bytes at offset "
                f"{start}, and it could not be read as a signature: present, unreadable, "
                "which is not the same as absent"
            ),
        )

    if not catalog_available():
        return Signature(
            state=SignatureState.UNKNOWN,
            verified=None,
            detail=NOT_VERIFIABLE_HERE,
        )

    catalog = _catalog(path)
    if catalog is not None:
        return catalog

    return Signature(
        state=SignatureState.UNSIGNED,
        verified=False,
        detail="no embedded signature and no catalog entry",
    )


# ---------------------------------------------------------------------------
# before the three paths: can the file be examined at all
# ---------------------------------------------------------------------------


def _unreadable(path: Path) -> str | None:
    """Why no conclusion can be drawn about this file, or None if one can.

    Two reasons, both about the file and neither about the platform:

    LIEF returns nothing, so there was no chance to look for an embedded
    signature. Reporting UNSIGNED then means "we could not read it, so we say it
    has none", and on Windows the catalog agrees for the same reason — it cannot
    identify the file either.

    Or the file is shorter than its own headers describe. LIEF is lenient enough
    to parse 512 bytes of a 104 KB binary and report no signature, because the
    Authenticode blob sits at the end and the end is missing. A cut-off download
    is the ordinary way this happens, and calling it unsigned accuses whoever
    built it of something the network did.
    """
    try:
        binary = pe.parse(path)
    except Exception as exc:  # noqa: BLE001 - reported, not hidden
        return f"not a readable PE: {type(exc).__name__}"
    if binary is None:
        return "not a readable PE: the headers could not be parsed"

    try:
        size = path.stat().st_size
    except OSError:
        return None

    for directory in binary.data_directories:
        if "CERTIFICATE" not in str(directory.type).upper() or not directory.size:
            continue
        # The one directory whose first field is a file offset, which is what
        # makes this comparison meaningful.
        if directory.rva + directory.size > size:
            return (
                "the certificate table starts at "
                f"{directory.rva} and runs {directory.size} bytes, past the end of a "
                f"{size}-byte file, so the signature cannot be read. A cut-off "
                "download is the ordinary cause and a malformed header looks the "
                "same from here; which of the two it is has not been established"
            )
    return None


# ---------------------------------------------------------------------------
# path A — embedded
# ---------------------------------------------------------------------------


# LIEF answers with a bitmask, and `!= OK` was read as "the signature is not
# valid". Thirteen flags share that answer and they do not mean one thing.
#
# These say the file does not match what was signed, or that the structure is
# broken. Nothing else can be concluded from them and nothing less: this is the
# case where somebody changed the file after it was signed.
_INVALID_FLAGS = (
    "INVALID_SIGNER",
    "INCONSISTENT_DIGEST_ALGORITHM",
    "CORRUPTED_CONTENT_INFO",
    "CORRUPTED_AUTH_DATA",
    "BAD_DIGEST",
    "BAD_SIGNATURE",
    "NO_SIGNATURE",
)

# These say the check could not be completed. Reported as "not valid" they
# accuse the publisher of the tool's own limits:
#
#   UNSUPPORTED_ALGORITHM         LIEF does not implement the digest or the key
#   CERT_NOT_FOUND                the blob does not carry the signer's own
#                                 certificate, so there is nothing to check
#                                 against — normal for a file meant to be
#                                 verified against a certificate store
#   MISSING_PKCS9_MESSAGE_DIGEST  the authenticated attributes do not carry the
#                                 PKCS#9 messageDigest LIEF looks for. Older
#                                 Authenticode blobs are assembled differently,
#                                 and Windows accepts them; what LIEF is saying
#                                 is that it cannot do the comparison
#   CERT_EXPIRED / CERT_FUTURE    the certificate's validity window does not
#                                 cover the moment of the check. The digest is
#                                 a separate question and this says nothing
#                                 about it — and a countersignature usually
#                                 answers it, which is why law_checker raises
#                                 `certificate_expired` only without one
_UNDETERMINED_FLAGS = (
    "UNSUPPORTED_ALGORITHM",
    "CERT_NOT_FOUND",
    "MISSING_PKCS9_MESSAGE_DIGEST",
    "CERT_EXPIRED",
    "CERT_FUTURE",
)


def _flag_names(flags) -> tuple[str, ...]:
    """The flags LIEF set, by name, lowest bit first.

    OK is zero, so an empty mask is the good answer and has to be named rather
    than left as an empty tuple that reads like "nothing was checked".
    """
    kinds = lief.PE.Signature.VERIFICATION_FLAGS
    try:
        mask = int(flags)
    except (TypeError, ValueError):  # a LIEF that stops exposing the int
        return (str(flags).rsplit(".", 1)[-1].lower(),)
    if mask == 0:
        return ("ok",)
    names = []
    for name in (*_INVALID_FLAGS, *_UNDETERMINED_FLAGS):
        bit = int(getattr(kinds, name))
        if bit and mask & bit:
            names.append(name.lower())
    if not names:                    # a flag this code has not heard of
        names.append(f"unrecognised:{mask}")
    return tuple(names)


def _verdict(flags) -> tuple[bool | None, tuple[str, ...]]:
    """What LIEF's answer is worth: valid, not valid, or not established.

    The third is the one that was missing. `verify_signature() != OK` treated an
    expired certificate and an algorithm LIEF cannot read as a file whose
    signature does not check out — a `signature_invalid` finding, severity high,
    cited against the CRA — when neither says anything about the bytes.
    """
    names = _flag_names(flags)
    if names == ("ok",):
        return True, names
    if any(name in [f.lower() for f in _INVALID_FLAGS] for name in names):
        return False, names
    return None, names


def _embedded(path: Path) -> Signature | None:
    try:
        binary = pe.parse(path)
    except Exception:  # noqa: BLE001 - a file we cannot parse is not signed
        return None
    if binary is None or not binary.signatures:
        return None

    signature = binary.signatures[0]
    chain = _chain(signature, _signer_serial(signature))
    stamp, stamper, problem = _timestamp(path)
    verified, flags = _verdict(binary.verify_signature())

    detail = f"embedded {signature.digest_algorithm}".replace("ALGORITHMS.", "")
    if verified is None:
        detail = f"{detail}; not established: {', '.join(flags)}"
    elif verified is False:
        detail = f"{detail}; does not check out: {', '.join(flags)}"
    if problem:
        detail = f"{detail}; timestamp not read: {problem}"

    return Signature(
        state=SignatureState.EMBEDDED,
        verified=verified,
        verification=flags,
        signer=chain[0].subject if chain else None,
        chain=chain,
        timestamp=stamp,
        timestamper=stamper,
        detail=detail,
    )


def _signer_serial(signature) -> int | None:
    """The serial of the certificate that signed, from the CMS SignerInfo.

    A PKCS#7 blob can carry more than one leaf — the timestamp authority's
    certificate is one — and then the order of the list says nothing about which
    of them signed. SignerInfo does say: `sid` is the issuer and serial of the
    signing certificate.

    Returns None when the blob cannot be read or identifies its signer by
    subject key identifier instead, which CMS also allows. Nothing is guessed
    from that; the caller falls back to the order.
    """
    try:
        from asn1crypto import cms

        content = cms.ContentInfo.load(bytes(signature.raw_der))
        sid = content["content"]["signer_infos"][0]["sid"]
        if sid.name != "issuer_and_serial_number":
            return None
        return int(sid.chosen["serial_number"].native)
    except Exception:  # noqa: BLE001 - a blob we cannot read names nobody
        return None


def _chain(signature, signer_serial: int | None = None) -> list[Certificate]:
    """Leaf first: the signer is what a report leads with, not the root.

    `signer_serial` is the one the PKCS#7 names. With it, that certificate leads
    however the blob ordered its contents — otherwise a file whose timestamper
    travels in the same blob is reported as signed by the timestamper. Without
    it the order is by is_ca alone, which is what this did before and is still
    right for a blob with a single leaf.

    No certificate is dropped: the timestamper's is part of what the file
    carries, and the report shows the chain as well as the signer.
    """
    certificates = [
        Certificate(
            subject=str(cert.subject),
            issuer=str(cert.issuer),
            valid_from=_cert_date(cert.valid_from),
            valid_to=_cert_date(cert.valid_to),
            serial=cert.serial_number.hex(),
            algorithm=str(cert.signature_algorithm),
            is_ca=bool(cert.is_ca),
        )
        for cert in signature.certificates
    ]
    # Sorted, not filtered, and stable: leaves keep their relative order and
    # the named signer is lifted to the front of them.
    certificates.sort(key=lambda c: c.is_ca)
    if signer_serial is not None:
        certificates.sort(key=lambda c: int(c.serial or "0", 16) != signer_serial)
    return certificates


def _cert_date(value) -> str | None:
    """LIEF hands back [Y, M, D, h, m, s]; the model promises text.

    The spike printed those lists raw, which is fine on a terminal and useless
    in JSON.
    """
    try:
        year, month, day, hour, minute, second = value
    except (TypeError, ValueError):
        return None
    return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"


def _timestamp(path: Path) -> tuple[str | None, str | None, str | None]:
    """Decode the RFC3161 token that LIEF hands over but does not open.

    LIEF exposes the countersignature as a structure and stops there: the time
    the file was signed lives in the TSTInfo inside it. Without that time a
    countersignature proves nothing, which matters most for a certificate that
    has since expired — the fixture in this repository is exactly that case.

    signify was the obvious way to do this and was dropped: it depends on
    oscrypto, unmaintained since March 2022, whose libcrypto version detection
    fails against OpenSSL 3.x. That surfaced as LibraryNotFoundError on the
    Linux CI while Windows was fine. asn1crypto is pure Python and already
    understands the structure.

    Returns the reason as a third value rather than swallowing it: a timestamp
    missing because the token was absent and one missing because the decoder
    raised look identical from the outside, and only one is a fact about the
    file.
    """
    try:
        from asn1crypto import cms

        binary = pe.parse(path)
        if binary is None or not binary.signatures:
            return None, None, None

        return timestamp_of(cms.ContentInfo.load(bytes(binary.signatures[0].raw_der)))
    except Exception as exc:  # noqa: BLE001 - reported, not hidden
        return None, None, f"{type(exc).__name__}: {exc}"


def timestamp_of(content) -> tuple[str | None, str | None, str | None]:
    """The signing time and its authority, whichever form the file used.

    Authenticode countersigns in two ways and this package looked for one of
    them. Two Canon printer drivers came back with no timestamp on 2026-09-26
    while Windows read `CN=DigiCert Timestamp 2021` out of the same bytes: they
    use the older PKCS#9 form, a whole SignerInfo in an unsigned attribute
    called `counter_signature`, and the RFC3161 token this looked for was
    simply not there. "No timestamp" was returned as a fact about the file when
    it was a form nobody had looked for — and a signature whose time cannot be
    read stops being verifiable the day its certificate expires, so the two
    answers are not close to each other.
    """
    from asn1crypto import tsp

    signer = content["content"]["signer_infos"][0]
    unsigned = {attribute["type"].native: attribute for attribute in signer["unsigned_attrs"]}

    token = unsigned.get("microsoft_time_stamp_token")
    if token is not None:
        signed = token["values"][0]["content"]
        info = tsp.TSTInfo.load(signed["encap_content_info"]["content"].contents)
        when = info["gen_time"].native
        return (
            _in_utc(when),
            _authority(signed),
            None if when else "the token carried no gen_time",
        )

    counter = unsigned.get("counter_signature")
    if counter is not None:
        return _countersigned(counter["values"][0], content)

    return None, None, None


def _in_utc(when: datetime | None) -> str | None:
    """A signing time as text, converted to UTC rather than labelled as it.

    DER requires `Z`, and BER or a malformed blob does not: `+0200` was printed
    as local time with " UTC" after it, two hours off on the date that decides
    whether an expired certificate is covered. A time with no zone at all says
    so instead of being given one.
    """
    if not when:
        return None
    if when.tzinfo is None:
        return f"{when:%Y-%m-%d %H:%M:%S} (no time zone stated)"
    return f"{when.astimezone(UTC):%Y-%m-%d %H:%M:%S} UTC"


def _countersigned(counter, content) -> tuple[str | None, str | None, str | None]:
    """The PKCS#9 form: a SignerInfo over the outer signature.

    Its time is an ordinary `signing_time` signed attribute. Its certificate is
    not bundled with it — it is named by issuer and serial and has to be found
    among the ones the outer signature already carries, which is why the
    timestamper used to end up in the chain looking like any other certificate.
    """
    times = [
        attribute for attribute in counter["signed_attrs"]
        if attribute["type"].native == "signing_time"
    ]
    when = times[0]["values"][0].native if times else None
    return (
        _in_utc(when),
        _named_certificate(counter["sid"], content),
        None if when else "the countersignature carried no signing_time",
    )


def _named_certificate(sid, content) -> str | None:
    """The certificate a signer identifier points at, out of the ones present."""
    if sid.name != "issuer_and_serial_number":
        return None
    issuer = sid.chosen["issuer"]
    serial = sid.chosen["serial_number"].native
    for wrapped in content["content"]["certificates"]:
        certificate = wrapped.chosen
        if getattr(certificate, "serial_number", None) != serial:
            continue
        if certificate.issuer == issuer:
            return _distinguished_name(certificate.subject)
    return None


# asn1crypto names an attribute type in words; LIEF, and every certificate viewer,
# by its X.520 short name. The report shows the signer through LIEF and the
# timestamper through asn1crypto, and on 2026-10-09 showed `C=US, O=…, CN=…`
# three lines above `Common Name: …; Organization: …; Country: US` on gpg.exe,
# docker.exe and Code.exe. One spelling, the signer's.
_SHORT_NAMES = {
    "common_name": "CN",
    "organization_name": "O",
    "organizational_unit_name": "OU",
    "country_name": "C",
    "state_or_province_name": "ST",
    "locality_name": "L",
    "email_address": "emailAddress",
    "serial_number": "serialNumber",
    "street_address": "STREET",
    "domain_component": "DC",
    "business_category": "businessCategory",
    "jurisdiction_country_name": "jurisdictionC",
    "jurisdiction_state_or_province_name": "jurisdictionST",
    "jurisdiction_locality_name": "jurisdictionL",
}


def _distinguished_name(name) -> str:
    """An asn1crypto Name as `C=US, O=DigiCert, Inc., CN=DigiCert Timestamp 2021`.

    In the order the certificate stores it, which is the order LIEF prints the
    signer in. A type this table has no short name for keeps asn1crypto's word
    or its dotted identifier, which is still one spelling: `kind=value`.
    """
    parts = []
    for rdn in name.chosen:
        for attribute in rdn:
            kind = attribute["type"].native
            parts.append(f"{_SHORT_NAMES.get(kind, kind)}={attribute['value'].native}")
    return ", ".join(parts)


def _authority(signed) -> str | None:
    """The timestamping authority: the one certificate in the token that is not a CA.

    A token bundles the authority together with the CA that vouches for it, so
    the leaf is the one that actually issued the time.
    """
    for wrapped in signed["certificates"]:
        certificate = wrapped.chosen
        constraints = certificate.basic_constraints_value
        if not (constraints and constraints["ca"].native):
            return _distinguished_name(certificate.subject)
    return None


# ---------------------------------------------------------------------------
# path B — catalog, Windows only
# ---------------------------------------------------------------------------


def _catalog(path: Path) -> Signature | None:
    """Ask Windows, which consults the catalog store as well as the file.

    A subprocess rather than WinVerifyTrust through ctypes: it is the version
    that works today, and the API is the version that stops paying for a
    PowerShell start-up once batch mode makes that cost visible.
    """
    try:
        completed = _ask_powershell(path)
        return _catalog_answer(completed.returncode, completed.stdout)
    # ValueError is an answer that is not JSON, which `_catalog_fields` explains
    # cannot happen; should it happen anyway, it is PowerShell not answering, as
    # much as a PowerShell that would not start, and the honest reply to both is
    # "I could not tell" rather than a traceback out of `analyze` or `verify`.
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def _ask_powershell(path: Path) -> subprocess.CompletedProcess[str]:
    """Run the one script path B has, about `path`, and return what it said."""
    # The path travels in an environment variable and is never part of the
    # script. It used to be interpolated as a single-quoted literal with the
    # ASCII quote doubled, and PowerShell closes that literal on U+2018, U+2019,
    # U+201A and U+201B as well: a file named `a’; <command>; ’b.exe`, legal on
    # NTFS, ran <command>. $args is not populated under -Command, which is why it
    # was interpolated at all; $env: is, and what it holds is data whatever it
    # contains, so there is no escaping left to get wrong.
    script = (
        # A certificate Subject carries whichever alphabet the CA uses, and
        # PowerShell writes stdout in the console encoding — cp850 or cp1252
        # depending on the machine. Both ends are pinned to UTF-8 so that the
        # same file gives the same answer on every Windows install.
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
        "$ErrorActionPreference='Stop';"
        f"$s = Get-AuthenticodeSignature -LiteralPath $env:{_TARGET_VARIABLE};"
        # JSON, not fields joined by `|`: a Subject may contain the separator
        # (O=Contoso|Fabrikam), and then part of the signer's name was read as
        # the timestamper. The values are made strings here because Windows
        # PowerShell serialises an enum as its number.
        '[ordered]@{Status="$($s.Status)";Type="$($s.SignatureType)";'
        'Signer="$($s.SignerCertificate.Subject)";'
        'Stamper="$($s.TimeStamperCertificate.Subject)"} | ConvertTo-Json -Compress'
    )
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=_POWERSHELL_TIMEOUT, env={**os.environ, _TARGET_VARIABLE: str(path)},
    )


def _catalog_answer(returncode: int, stdout: str | None) -> Signature | None:
    """What PowerShell's reply says about the file: a catalog signature, or None."""
    if returncode != 0:
        return None
    # capture_output collects the pipes on reader threads, so a decoding failure
    # there does not reach this frame as an exception: it leaves stdout as None.
    # Dereferencing that raised AttributeError, which the except in `_catalog`
    # does not cover — a crash instead of the honest "I could not tell".
    if not stdout:
        return None

    fields = _catalog_fields(stdout)
    if fields["Status"] != "Valid" or fields["Type"] != "Catalog":
        return None

    return Signature(
        state=SignatureState.CATALOG,
        verified=True,
        signer=fields["Signer"] or None,
        timestamper=fields["Stamper"] or None,
        detail="signed by catalog, not by an embedded blob",
    )


def _catalog_fields(stdout: str) -> dict[str, str]:
    """The four values of an answer the script gave with exit code 0, as text."""
    # Exit 0 is always one JSON object, so it is parsed without a fallback. The
    # script prints one hashtable through ConvertTo-Json and nothing else, and
    # under $ErrorActionPreference='Stop' every failure — no such file, a
    # directory, access denied, a file in use — ends it with exit code 1 before
    # that line, which `_catalog_answer` has already turned away. Measured with
    # the real PowerShell on 2026-10-07 and held by test_catalog_encoding.py; the
    # not-JSON and not-an-object branches that were here could not be reached.
    answer = json.loads(stdout)
    return {key: str(answer.get(key) or "").strip() for key in ("Status", "Type", "Signer", "Stamper")}
