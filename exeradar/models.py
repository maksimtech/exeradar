"""The shapes every other module fills in or reads.

Defined first on purpose: ARCHITECTURE.md section 5 derives the console, JSON
and Markdown outputs from one model, so the model is what the parsers target.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SignatureState(str, Enum):
    """The three paths of ARCHITECTURE.md section 3, plus their honest gap.

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
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    serial: Optional[str] = None
    algorithm: Optional[str] = None
    is_ca: bool = False


@dataclass
class Signature:
    state: SignatureState = SignatureState.UNKNOWN
    verified: Optional[bool] = None
    signer: Optional[str] = None
    chain: list[Certificate] = field(default_factory=list)
    # From the RFC3161 token; None when there is no countersignature, which
    # means nothing proves when the file was signed.
    timestamp: Optional[str] = None
    timestamper: Optional[str] = None
    detail: Optional[str] = None


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
    format: Optional[str] = None
    arch: Optional[str] = None
    built: Optional[str] = None
    sections: list[Section] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    strings: Strings = field(default_factory=Strings)
    signature: Signature = field(default_factory=Signature)
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None
