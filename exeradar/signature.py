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
    stamp, stamper = _timestamp(path)

    return Signature(
        state=SignatureState.EMBEDDED,
        verified=binary.verify_signature() == lief.PE.Signature.VERIFICATION_FLAGS.OK,
        signer=chain[0].subject if chain else None,
        chain=chain,
        timestamp=stamp,
        timestamper=stamper,
        detail=f"embedded {signature.digest_algorithm}".replace("ALGORITHMS.", ""),
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


def _timestamp(path: Path) -> tuple[str | None, str | None]:
    """The one job signify is a dependency for.

    LIEF exposes the RFC3161 countersignature as a structure but does not
    decode the TSTInfo inside it, so the time the file was signed is not
    reachable through LIEF alone. Without it a countersignature proves nothing,
    which matters most for a certificate that has since expired.
    """
    try:
        from signify.authenticode import AuthenticodeFile

        with path.open("rb") as handle:
            signed = AuthenticodeFile.from_stream(handle)
            for signature in signed.signatures:
                counter = getattr(signature.signer_info, "countersigner", None)
                if counter is None:
                    continue
                when = getattr(counter, "signing_time", None)
                return (
                    f"{when:%Y-%m-%d %H:%M:%S} UTC" if when else None,
                    _timestamper(counter),
                )
    except Exception:  # noqa: BLE001 - a missing timestamp is not a failure
        return None, None
    return None, None


def _timestamper(counter) -> str | None:
    """Who issued the timestamp, which the RFC3161 signer_info only points at.

    signify gives the countersigner an issuer and a serial but no certificate,
    so the authority has to be found among the certificates the token carries.
    Matching on the serial is exact; the non-CA certificate is the fallback,
    since a token bundles the authority and the CA that vouches for it.
    """
    certificates = list(getattr(counter, "certificates", []) or [])
    if not certificates:
        return None

    wanted = getattr(getattr(counter, "signer_info", None), "serial_number", None)
    if wanted is not None:
        for certificate in certificates:
            if getattr(certificate, "serial_number", None) == wanted:
                return str(certificate.subject)

    for certificate in certificates:
        if "Timestamping CA" not in str(certificate.subject):
            return str(certificate.subject)
    return str(certificates[0].subject)


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
