"""
ExeRadar — EU law provisions for the findings of a static analysis.

Maps what the analysis found to the provisions it concerns, and cites each one
with the SHA-256 of the exact text applied and the date of that wording. The
text is downloaded on every run and compared with the local cache; without
network the cached copy is cited.

Shared by the Radar tools: only the mapping section is specific to ExeRadar,
and it is the part that needed thinking about. The other four Radars examine
the processing of personal data and cite the GDPR for it. ExeRadar examines an
artefact, where an unsigned binary is not by itself unlawful processing, so the
act that fits is the Cyber Resilience Act — regulation (EU) 2024/2847, which
governs products with digital elements.

Three things about citing it are easy to get wrong, and all three are handled
below rather than left to the reader:

- the requirements are in **Annex I**, not in an article. Article 6 says a
  product may be placed on the market only if it meets "the essential
  cybersecurity requirements set out in Part I of Annex I" and article 13(1)
  puts that duty on the manufacturer. Neither contains a rule about signing
  anything. Citing them alone would be citing a pointer.
- the CRA **applies from 11 December 2027** (article 71(2)). It is in force and
  not yet applicable, which is stated in a note on every report that cites it.
- it binds **manufacturers placing a product on the market** (article 2(1)).
  ExeRadar reads one file; whether that file is part of such a product is not
  something a PE header can answer, so that too is a note and not an assumption.

Two languages meet in this module, along a seam worth keeping straight. The
evidence of a finding describes the binary and is English, like the rest of the
tool and like the JSON it ends up in. The titles, the notes and the citations
are the legal report and are Italian, like the other four Radars.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from exeradar import law_fetcher
from exeradar.law_cache import Key, LawCache
from exeradar.law_fetcher import CRA, GDPR, NIS2, Act, LawFetchError, Provision
from exeradar.models import ExeResult, Finding, SignatureState

# ─── Mapping: ExeRadar findings → provisions ──────────────────────────────────

_PART_I = "Allegato I, Parte I"
_PART_II = "Allegato I, Parte II"

# Finding → cited provisions, in report order.
#
# Annex I, Part I(2)(f) carries the three signature findings on its own words:
# products shall "proteggono l'integrità ... dei comandi, dei programmi e della
# configurazione da qualsiasi manipolazione o modifica non autorizzata". A code
# signature is the mechanism by which that integrity can be checked at all, so
# its absence, its failure and the expiry of the key that made it are the same
# requirement seen three times. Article 13(1) is cited next to it because it is
# what turns the annex into an obligation.
#
# (2)(j) — "limitare le superfici di attacco, comprese le interfacce esterne" —
# is the only provision the text offers for a hardcoded address, and it is a
# general requirement rather than a rule about addresses. That is why the
# finding carries a note saying so, and why nothing else is cited for it.
FINDING_ARTICLES: dict[str, tuple[tuple[Act, str], ...]] = {
    "unsigned": ((CRA, f"{_PART_I}(2)(f)"), (CRA, "13(1)"),
                 (NIS2, "21(2)(d)"), (GDPR, "32(1)")),
    "signature_invalid": ((CRA, f"{_PART_I}(2)(f)"), (CRA, "13(1)"),
                          (NIS2, "21(2)(d)"), (GDPR, "32(1)")),
    "certificate_expired": ((CRA, f"{_PART_I}(2)(f)"), (GDPR, "32(1)")),
    "hardcoded_ip": ((CRA, f"{_PART_I}(2)(j)"),),
    "known_vulnerabilities": ((CRA, f"{_PART_I}(2)(a)"), (CRA, f"{_PART_II}(1)"),
                              (CRA, f"{_PART_II}(2)"), (NIS2, "21(2)(e)")),
}

FINDING_TITLES = {
    "unsigned": "Unsigned binary",
    "signature_invalid": "Embedded signature not valid",
    "certificate_expired": "Signing certificate expired",
    "hardcoded_ip": "IP address in the binary",
    "known_vulnerabilities": "Dependencies with known vulnerabilities",
}

# Declared, mapped, and produced by nothing yet: ExeRadar does not read
# dependencies. Kept in the map because the provisions were verified along with
# the others and the finding is the next one planned, not a guess.
FUTURE_FINDINGS = frozenset({"known_vulnerabilities"})

# Articles downloaded and cached even when not cited, by act
ALSO_FETCH: dict = {}

CRA_APPLICATION_NOTE = (
    "CRA art. 71(2): regulation (EU) 2024/2847 applies from 11 December 2027 "
    "(art. 14 from 11 September 2026, chapter IV from 11 June 2026); the citations "
    "therefore concern a rule in force but not yet applicable"
)
CRA_SCOPE_NOTE = (
    "CRA art. 2(1): the regulation concerns products with digital elements made "
    "available on the market and binds the manufacturer; ExeRadar examines a single "
    "file and cannot establish which product it is part of"
)
NIS2_SCOPE_NOTE = (
    "NIS2 art. 21 binds essential and important entities (art. 3 of the directive): "
    "check that the organisation falls within scope"
)
GDPR_SCOPE_NOTE = (
    "GDPR art. 32 applies to the processing of personal data: ExeRadar cannot "
    "establish from the binary whether the program processes any"
)
UNKNOWN_SIGNATURE_NOTE = (
    "signature not verifiable on this platform: the Windows catalog cannot be "
    "consulted, so the absence of an embedded signature proves nothing and no "
    "provision is cited"
)
HARDCODED_IP_NOTE = (
    "a literal IPv4 address and a version number have the same shape: check each "
    "address before treating it as an endpoint"
)

# How a program binds, not somewhere it calls.
_UNSPECIFIED = "0.0.0.0"
_LOOPBACK = "127."

# Certificates and countersignatures are stored as text by the model; these are
# the two shapes signature.py writes.
_CERT_TIME = "%Y-%m-%d %H:%M:%S"

_ANNEX_CITATION = re.compile(r"^(?:Allegato|Annex)\b", re.I)


def _expiry(value: str | None) -> datetime | None:
    """The expiry date as a moment, or None when it cannot be read.

    Unreadable is not expired. A date the parser could not make sense of is a
    gap in what is known about the file, and a finding says the opposite.
    """
    if not value:
        return None
    try:
        return datetime.strptime(value, _CERT_TIME).replace(tzinfo=UTC)
    except ValueError:
        return None


def _is_local(address: str) -> bool:
    return address == _UNSPECIFIED or address.startswith(_LOOPBACK)


def findings_of(result: ExeResult, *, now: datetime | None = None) -> dict[str, list[str]]:
    """
    Findings in an ExeResult, with the evidence for each.

    Everything here turns on the signature state, which is where ExeRadar is
    careful: UNKNOWN produces nothing. On Linux and macOS the Windows catalog
    cannot be consulted, so a file with no embedded signature may be perfectly
    signed and the analysis cannot tell. Citing a provision against it would be
    an accusation drawn from the absence of a capability.
    """
    if result.error:
        return {}
    now = now or datetime.now(UTC)

    found: dict[str, list[str]] = {}
    signature = result.signature

    if signature.state is SignatureState.UNSIGNED:
        found["unsigned"] = [
            signature.detail or "no embedded signature and no catalog entry"
        ]
    elif signature.state is SignatureState.EMBEDDED:
        if signature.verified is False:
            found["signature_invalid"] = [
                "embedded signature present but not valid; declared signer: "
                f"{signature.signer or 'none stated'}"
            ]
        else:
            leaf = signature.chain[0] if signature.chain else None
            expiry = _expiry(leaf.valid_to) if leaf else None
            # A countersignature answers the question the expiry raises: it
            # says the file was signed while the certificate was still valid,
            # which is why LIEF still verifies this repository's own fixture.
            if leaf and expiry is not None and expiry < now and not signature.timestamp:
                found["certificate_expired"] = [
                    f"{leaf.subject} expired on {leaf.valid_to}, with no RFC3161 countersignature"
                ]

    addresses = [ip for ip in result.strings.ips if not _is_local(ip)]
    if addresses:
        found["hardcoded_ip"] = addresses

    return found


# How much the evidence proves, which is not how much it costs. ExeRadar sees
# a file and never the system it runs on, so it cannot rank risk. An embedded
# signature that does not verify is the strongest statement available — the
# bytes are not the bytes that were signed — while a dotted quad that may well
# be a version number is the weakest.
SEVERITY = {
    "signature_invalid": "high",
    "unsigned": "medium",
    "certificate_expired": "medium",
    "hardcoded_ip": "low",
    "known_vulnerabilities": "high",
}


def findings_for(result: ExeResult, *, now: datetime | None = None) -> list[Finding]:
    """The same findings as `findings_of`, as the objects the model carries."""
    return [
        Finding(id=name, severity=SEVERITY[name], evidence="; ".join(evidence))
        for name, evidence in findings_of(result, now=now).items()
    ]


def notes_of(result: ExeResult, *, now: datetime | None = None) -> list[str]:
    """Remarks that belong in the report without being citations.

    An act is only qualified when something actually cites it: a note about
    whom NIS2 binds, printed under a report that never mentions NIS2, is noise
    that teaches the reader to skip the notes.
    """
    if result.error:
        return []

    notes = []
    if result.signature.state is SignatureState.UNKNOWN:
        notes.append(UNKNOWN_SIGNATURE_NOTE)

    found = findings_of(result, now=now)
    acts = {act for finding in found for act, _ in FINDING_ARTICLES[finding]}
    if CRA in acts:
        notes += [CRA_APPLICATION_NOTE, CRA_SCOPE_NOTE]
    if NIS2 in acts:
        notes.append(NIS2_SCOPE_NOTE)
    if GDPR in acts:
        notes.append(GDPR_SCOPE_NOTE)
    if "hardcoded_ip" in found:
        notes.append(HARDCODED_IP_NOTE)
    return notes


# ─── Citations ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Citation:
    finding: str
    law: str                      # act as cited: "GDPR"
    article: str                  # "32(1)" or "Allegato I, Parte I(2)(f)"
    sha256: str | None         # None when the text could not be obtained
    version_date: str | None   # YYYY-MM-DD the wording was downloaded


@dataclass(frozen=True)
class ActStatus:
    act: Act
    # "verified": downloaded now from the act's source; "cache": source
    # unreachable, cached copy; "unavailable": no text at all
    source: str
    error: str | None = None


@dataclass
class LawCheckResult:
    citations: list[Citation]
    acts: list[ActStatus] = field(default_factory=list)
    # What triggered each finding, e.g. {"unsigned": ["no embedded signature"]}
    evidence: dict[str, list[str]] = field(default_factory=dict)
    # "GDPR art. 32" → SHA-256 of its previous text, for cited provisions
    # whose text changed since the last run
    changed: dict[str, str] = field(default_factory=dict)
    # Remarks without a citation, e.g. why no verdict was possible
    notes: list[str] = field(default_factory=list)


def check(
    subject: ExeResult,
    *,
    cache: LawCache | None = None,
    now: datetime | None = None,
    **context,
) -> LawCheckResult:
    """Cite the provisions that apply to the findings about `subject`."""
    now = now or datetime.now(UTC)
    evidence = findings_of(subject, now=now, **context)
    notes = notes_of(subject, now=now, **context)
    cited = [
        (finding, act, ref)
        for finding in evidence
        for act, ref in FINDING_ARTICLES[finding]
    ]
    if not cited:
        return LawCheckResult(citations=[], notes=notes)

    cache = cache or LawCache()

    acts = list(dict.fromkeys(act for _, act, _ in cited))
    # Keyed by (celex, article) — the cache's key, not the fetcher's.
    fresh: dict[Key, Provision] = {}
    errors: dict[Act, str] = {}
    for act in acts:
        # The units cited — "13" is the article behind "13(1)", "Allegato I,
        # Parte I" the annex part behind its points — plus ALSO_FETCH
        articles = tuple(dict.fromkeys(
            [ref.split("(")[0] for _, a, ref in cited if a == act] + list(ALSO_FETCH.get(act, ()))
        ))
        try:
            by_article = law_fetcher.fetch_provisions(act, articles, now=now)
        except LawFetchError as e:
            errors[act] = str(e)
        else:
            fresh.update({p.key: p for p in by_article.values()})

    changed: dict[Key, str] = {}
    try:
        if fresh:
            provisions, changed = cache.update(fresh, checked_at=law_fetcher.utc_stamp(now))
        else:
            provisions = cache.load()
    except OSError:
        provisions = {**cache.load(), **fresh}   # the text just downloaded can still be cited

    statuses = []
    for act in acts:
        if act not in errors:
            statuses.append(ActStatus(act, "verified"))
        else:
            cached = any((act.celex, ref) in provisions for _, a, ref in cited if a == act)
            statuses.append(ActStatus(act, "cache" if cached else "unavailable", errors[act]))

    citations = []
    for finding, act, ref in cited:
        provision = provisions.get((act.celex, ref))
        citations.append(Citation(
            finding=finding,
            law=act.name,
            article=ref,
            sha256=provision.sha256 if provision else None,
            version_date=provision.fetched_at[:10] if provision else None,
        ))

    names = {act.celex: act.name for act in acts}
    cited_keys = {(act.celex, ref) for _, act, ref in cited}
    return LawCheckResult(
        citations=citations,
        acts=statuses,
        evidence=evidence,
        changed={
            f"{names[celex]} {article}": sha
            for (celex, article), sha in changed.items()
            if (celex, article) in cited_keys
        },
        notes=notes,
    )


def format_citation(citation: Citation) -> str:
    """One citation as three lines.

    An annex is not an article, and the difference shows: "art. Allegato I,
    Parte I(2)(f)" would be wrong in the one line of the report whose whole job
    is to be exact about where the rule comes from. The reference itself keeps
    the spelling the act uses, because that is what a reader has to look up.
    """
    where = citation.article
    if not _ANNEX_CITATION.match(where):
        where = f"art. {where}"
    return (
        f"Provision applied: {citation.law} {where}\n"
        f"SHA256: {citation.sha256 or 'not available'}\n"
        f"Version of: {citation.version_date or 'not available'}"
    )
