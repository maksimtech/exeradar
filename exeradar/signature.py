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
    chain = _chain(signature)
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


def _chain(signature) -> list[Certificate]:
    """Leaf first: the signer is what a report leads with, not the root."""
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
    certificates.sort(key=lambda c: c.is_ca)
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
        "$ErrorActionPreference='Stop';"
        f"$s = Get-AuthenticodeSignature -LiteralPath '{quoted}';"
        '"$($s.Status)|$($s.SignatureType)|$($s.SignerCertificate.Subject)|'
        '$($s.TimeStamperCertificate.Subject)"'
    )
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=_POWERSHELL_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
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
