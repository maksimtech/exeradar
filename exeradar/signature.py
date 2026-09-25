"""Code signing, by the three paths of ARCHITECTURE.md section 3.

A — an embedded Authenticode blob, read by LIEF. Works on every platform.
B — a catalog signature: the file itself carries nothing and the signature
    lives in a .cat file under CatRoot. Windows only.
C — neither, which is a finding.

The distinction this module exists to keep is between C and "we could not
look". Path B cannot run off Windows, so there the absence of an embedded
signature is UNKNOWN. Reporting it as UNSIGNED would fire on most of System32,
which is precisely where a reader would trust the tool least to be wrong.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import lief

from exeradar.models import Certificate, Signature, SignatureState

_POWERSHELL_TIMEOUT = 60


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
        binary = lief.PE.parse(str(path))
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

    if not catalog_available():
        return Signature(
            state=SignatureState.UNKNOWN,
            verified=None,
            detail="catalog signature: not verifiable on this platform",
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
        binary = lief.PE.parse(str(path))
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
                f"{size}-byte file: truncated, so the signature cannot be read"
            )
    return None


# ---------------------------------------------------------------------------
# path A — embedded
# ---------------------------------------------------------------------------


def _embedded(path: Path) -> Signature | None:
    try:
        binary = lief.PE.parse(str(path))
    except Exception:  # noqa: BLE001 - a file we cannot parse is not signed
        return None
    if binary is None or not binary.signatures:
        return None

    signature = binary.signatures[0]
    chain = _chain(signature, _signer_serial(signature))
    stamp, stamper, problem = _timestamp(path)

    detail = f"embedded {signature.digest_algorithm}".replace("ALGORITHMS.", "")
    if problem:
        detail = f"{detail}; timestamp not read: {problem}"

    return Signature(
        state=SignatureState.EMBEDDED,
        verified=binary.verify_signature() == lief.PE.Signature.VERIFICATION_FLAGS.OK,
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
        from asn1crypto import cms, tsp

        binary = lief.PE.parse(str(path))
        if binary is None or not binary.signatures:
            return None, None, None

        content = cms.ContentInfo.load(bytes(binary.signatures[0].raw_der))
        signer = content["content"]["signer_infos"][0]
        tokens = [
            attribute for attribute in signer["unsigned_attrs"]
            if attribute["type"].native == "microsoft_time_stamp_token"
        ]
        if not tokens:
            return None, None, None

        signed = tokens[0]["values"][0]["content"]
        info = tsp.TSTInfo.load(signed["encap_content_info"]["content"].contents)
        when = info["gen_time"].native
        return (
            f"{when:%Y-%m-%d %H:%M:%S} UTC" if when else None,
            _authority(signed),
            None if when else "the token carried no gen_time",
        )
    except Exception as exc:  # noqa: BLE001 - reported, not hidden
        return None, None, f"{type(exc).__name__}: {exc}"


def _authority(signed) -> str | None:
    """The timestamping authority: the one certificate in the token that is not a CA.

    A token bundles the authority together with the CA that vouches for it, so
    the leaf is the one that actually issued the time.
    """
    for wrapped in signed["certificates"]:
        certificate = wrapped.chosen
        constraints = certificate.basic_constraints_value
        if not (constraints and constraints["ca"].native):
            return certificate.subject.human_friendly
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
    # The path is interpolated rather than passed as an argument: $args is not
    # populated under -Command, only under -File, and PowerShell answers with a
    # parse error. Single quotes are the literal form there, escaped by
    # doubling, which also makes the value inert.
    quoted = str(path).replace("'", "''")
    script = (
        # A certificate Subject carries whichever alphabet the CA uses, and
        # PowerShell writes stdout in the console encoding — cp850 or cp1252
        # depending on the machine. Both ends are pinned to UTF-8 so that the
        # same file gives the same answer on every Windows install.
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
        "$ErrorActionPreference='Stop';"
        f"$s = Get-AuthenticodeSignature -LiteralPath '{quoted}';"
        '"$($s.Status)|$($s.SignatureType)|$($s.SignerCertificate.Subject)|'
        '$($s.TimeStamperCertificate.Subject)"'
    )
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=_POWERSHELL_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    # capture_output collects the pipes on reader threads, so a decoding failure
    # there does not reach this frame as an exception: it leaves stdout as None.
    # Dereferencing that raised AttributeError, which the except above does not
    # cover — a crash instead of the honest "I could not tell".
    if not completed.stdout:
        return None

    parts = (completed.stdout.strip().split("|") + [""] * 4)[:4]
    status, kind, signer, stamper = (part.strip() for part in parts)
    if status != "Valid" or kind != "Catalog":
        return None

    return Signature(
        state=SignatureState.CATALOG,
        verified=True,
        signer=signer or None,
        timestamper=stamper or None,
        detail="signed by catalog, not by an embedded blob",
    )
