"""The shapes every other module fills in or reads.

Defined first on purpose: ARCHITECTURE.md section 5 derives the console, JSON
and Markdown outputs from one model, so the model is what the parsers target.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class SignatureState(StrEnum):
    """The three paths of ARCHITECTURE.md section 3, plus their honest gap.

    StrEnum rather than (str, Enum): with the mixin, f"{state}" renders
    "SignatureState.EMBEDDED" while state.value renders "embedded", and every
    caller here has to remember .value. test_report.py already guards that a
    consumer sees "embedded"; StrEnum makes the two forms agree instead.

    UNKNOWN exists because it is not the same as UNSIGNED: on Linux and macOS
    the catalog cannot be consulted, so the absence of an embedded signature
    proves nothing. Reporting UNSIGNED there would fire on every catalog-signed
    Windows system binary.
    """

    EMBEDDED = "embedded"          # A — signature inside the file, LIEF read it
    CATALOG = "catalog"            # B — signature in a .cat, Windows confirmed it
    UNSIGNED = "unsigned"          # C — both paths ran and found nothing
    UNKNOWN = "unknown"            # B could not run on this platform


@dataclass
class Certificate:
    subject: str
    issuer: str
    valid_from: str | None = None
    valid_to: str | None = None
    serial: str | None = None
    algorithm: str | None = None
    is_ca: bool = False


@dataclass
class Signature:
    state: SignatureState = SignatureState.UNKNOWN
    # True: the file matches what was signed and the blob is self-consistent.
    # False: it does not — the digest, the signature or the structure is wrong.
    # None: it could not be established, which is not the same as wrong. An
    # algorithm LIEF does not implement, a signer certificate the blob does not
    # carry and a certificate outside its validity window all land here.
    #
    # Note what True does not say: no operating system trust store is consulted,
    # so a self-signed certificate verifies exactly as well as a commercial one.
    verified: bool | None = None
    # LIEF's verification flags, lowercased — ("ok",), ("cert_expired",),
    # ("bad_digest",). The reason behind `verified`, kept so that a report can
    # name it instead of printing a verdict with nothing behind it.
    verification: tuple[str, ...] = ()
    signer: str | None = None
    chain: list[Certificate] = field(default_factory=list)
    # From the RFC3161 token; None when there is no countersignature, which
    # means nothing proves when the file was signed.
    timestamp: str | None = None
    timestamper: str | None = None
    detail: str | None = None


@dataclass
class Section:
    name: str
    virtual_size: int
    raw_size: int
    entropy: float


@dataclass
class Import:
    dll: str
    functions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Library:
    """A library the file names, and what naming it consisted of.

    Frozen, unlike the rest of this module: `libraries` deduplicates by putting
    these in a dict, and 611 copies of one OpenSSL build path have to collapse to
    one row.

    `version` is None when the file uses a library without saying which version —
    an import, where the version is in the other file. That is a different answer
    from the library being absent, and `source` is what tells them apart.
    """

    name: str
    version: str | None
    source: str        # see exeradar.libraries: banner, build path, assembly, import
    evidence: str      # the string that said it, or the DLL that was imported


@dataclass
class Strings:
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """Only findings carry a severity and reach law_checker.

    Facts — headers, imports, strings, hashes — are reported without judgement.
    See ARCHITECTURE.md section 7.
    """

    id: str
    severity: str
    evidence: str


@dataclass
class ExeResult:
    path: str
    size: int
    sha256: str
    format: str | None = None
    arch: str | None = None
    built: str | None = None
    sections: list[Section] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    strings: Strings = field(default_factory=Strings)
    # Drawn from the strings and the imports together, because the two answer
    # different halves of the question: a string can say which version is in here,
    # and an import can only say which file to ask next. An empty list is not
    # "no libraries" — see exeradar.libraries.CAVEAT, which the reports carry.
    libraries: list[Library] = field(default_factory=list)
    signature: Signature = field(default_factory=Signature)
    findings: list[Finding] = field(default_factory=list)
    # Bytes past the last section, which the strings pass did not read. Kept on
    # the result so the report can say what was skipped instead of skipping it
    # quietly.
    overlay: int = 0
    error: str | None = None
