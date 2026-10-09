"""Findings to provisions, and the promise that nothing here was invented.

Two kinds of test. The ordinary kind checks that a result produces the
findings it should and no others. The other kind — `test_every_citation_is_in_
the_act` — reads the acts themselves and refuses a reference they do not
contain; it is the thing that makes the mapping a citation rather than an
assertion.

What is deliberately absent matters as much. There is no finding for a URL
served over http: the only URL in this repository's own fixture is
`http://schemas.microsoft.com/SMI/2016/WindowsSettings`, an XML namespace out
of the PE manifest and not an endpoint the program contacts. A finding that
fires on every Windows binary with a manifest is not a finding.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from exeradar import law_checker, law_fetcher
from exeradar.law_cache import LawCache
from exeradar.law_checker import (
    CRA_APPLICATION_NOTE,
    FINDING_ARTICLES,
    FINDING_TITLES,
    FUTURE_FINDINGS,
    check,
    findings_of,
    format_citation,
    notes_of,
)
from exeradar.law_fetcher import CRA, GDPR, NIS2, LawFetchError, Provision
from exeradar.models import (
    Certificate,
    ExeResult,
    Import,
    Signature,
    SignatureState,
    Strings,
)

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
PART_I = "Allegato I, Parte I"

ACT_FIXTURES = {
    CRA: "cra_it_excerpt.html",
    GDPR: "gdpr_it_excerpt.html",
    NIS2: "nis2_it_excerpt.html",
}


# A binary that can contact an address. `hardcoded_ip` is only raised for one,
# since a driver installer carries its version number in the same shape — see
# test_hardcoded_ip_context.py. The tests below are not about that rule; they
# pass this so that the finding they rely on exists.
SOCKETS = [Import(dll="WS2_32.dll", functions=["connect"])]


def result(
    *,
    state=SignatureState.EMBEDDED,
    verified=True,
    chain=(),
    timestamp=None,
    ips=(),
    imports=(),
    error=None,
    detail="detail",
    verification=(),
) -> ExeResult:
    return ExeResult(
        path="C:/tmp/sample.exe",
        size=1000,
        sha256="aa",
        format="PE",
        error=error,
        imports=list(imports),
        strings=Strings(ips=list(ips)),
        signature=Signature(
            state=state,
            verified=verified,
            signer="CN=Example",
            chain=list(chain),
            timestamp=timestamp,
            detail=detail,
            verification=tuple(verification),
        ),
    )


def cert(valid_to, valid_from="2020-01-01 00:00:00") -> Certificate:
    return Certificate(subject="CN=Example", issuer="CN=CA",
                       valid_from=valid_from, valid_to=valid_to)


# --------------------------------------------------------------------------
# the mapping itself
# --------------------------------------------------------------------------


def test_mapping():
    assert FINDING_ARTICLES == {
        "unsigned": ((CRA, PART_I + "(2)(f)"), (CRA, "13(1)"),
                     (NIS2, "21(2)(d)"), (GDPR, "32(1)")),
        "signature_invalid": ((CRA, PART_I + "(2)(f)"), (CRA, "13(1)"),
                              (NIS2, "21(2)(d)"), (GDPR, "32(1)")),
        "certificate_expired": ((CRA, PART_I + "(2)(f)"), (GDPR, "32(1)")),
        "hardcoded_ip": ((CRA, PART_I + "(2)(j)"),),
        "known_vulnerabilities": ((CRA, PART_I + "(2)(a)"),
                                  (CRA, "Allegato I, Parte II(1)"),
                                  (CRA, "Allegato I, Parte II(2)"),
                                  (NIS2, "21(2)(e)")),
    }
    assert set(FINDING_TITLES) == set(FINDING_ARTICLES)


def test_the_only_finding_nothing_produces_yet_is_declared_as_such():
    """`known_vulnerabilities` waits for a dependency scanner; the rest fire."""
    assert {"known_vulnerabilities"} == FUTURE_FINDINGS
    assert set(FINDING_ARTICLES) - FUTURE_FINDINGS == {
        "unsigned", "signature_invalid", "certificate_expired", "hardcoded_ip",
    }


@pytest.mark.parametrize("finding", sorted(FINDING_ARTICLES))
def test_every_citation_is_in_the_act(finding):
    """Read the acts and refuse a reference they do not contain.

    The CRA keeps its requirements in Annex I and its articles only point at
    it, so this also guards against citing article 6 as though it said
    something: the rule has to be quoted from the annex point that carries it.
    """
    for act, ref in FINDING_ARTICLES[finding]:
        html = (FIXTURES / ACT_FIXTURES[act]).read_text(encoding="utf-8")
        unit = ref.split("(")[0]
        texts = law_fetcher.parse_articles(html, (unit,))
        assert ref in texts, f"{act.name} {ref} is not in the act"
        assert len(texts[ref]) > 40


def test_the_integrity_requirement_says_what_the_signature_findings_claim():
    """The signature findings stand on one sentence; read it.

    Annex I, Part I(2)(f) is about the integrity of programs against
    unauthorised modification, which is what a code signature is for. If the
    wording ever changes, the citation has to be looked at again.
    """
    html = (FIXTURES / ACT_FIXTURES[CRA]).read_text(encoding="utf-8")
    point = law_fetcher.parse_articles(html, (PART_I,))[PART_I + "(2)(f)"]

    assert "integrità" in point
    assert "programmi" in point
    assert "modifica non autorizzata" in point


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------


def test_a_valid_signature_accuses_nobody():
    assert findings_of(result(), now=NOW) == {}
    assert notes_of(result(), now=NOW) == []


def test_a_catalog_signature_accuses_nobody():
    assert findings_of(result(state=SignatureState.CATALOG), now=NOW) == {}


def test_an_unsigned_binary_is_a_finding():
    found = findings_of(result(state=SignatureState.UNSIGNED, verified=False), now=NOW)
    assert set(found) == {"unsigned"}
    assert found["unsigned"]


def test_an_unknown_signature_is_never_reported_as_unsigned():
    """The reason the signature module has three paths, carried into the law.

    Off Windows the catalog cannot be consulted, so the absence of an embedded
    signature proves nothing — and a citation is an accusation.
    """
    from exeradar.signature import NOT_VERIFIABLE_HERE

    unknown = result(state=SignatureState.UNKNOWN, verified=None, detail=NOT_VERIFIABLE_HERE)
    assert findings_of(unknown, now=NOW) == {}
    assert any("not verifiable" in note for note in notes_of(unknown, now=NOW))


def test_an_unknown_signature_says_which_of_its_reasons_applies():
    """UNKNOWN has four causes and the note stated one of them regardless.

    A truncated file, a PE that will not parse and a certificate table that
    cannot be read all arrive here, and none of them are "the Windows catalog
    cannot be consulted on this platform" — which is what a reader was told,
    including on Windows, where the catalog had in fact been consulted.
    """
    truncated = result(
        state=SignatureState.UNKNOWN,
        verified=None,
        detail="the certificate table starts at 100 and runs 4000 bytes, past the end of a 512-byte file",
    )
    notes = notes_of(truncated, now=NOW)

    assert findings_of(truncated, now=NOW) == {}
    assert any("past the end of a 512-byte file" in note for note in notes)
    assert not any("on this platform" in note for note in notes)


def test_a_check_that_did_not_conclude_is_a_note_and_not_a_finding():
    """`verified is None` used to be indistinguishable from False.

    An expired certificate, an algorithm LIEF does not implement, a signer
    certificate the blob does not carry: all three came back as
    "signature_invalid", severity high, cited against the CRA — for a file whose
    bytes nobody had found fault with.
    """
    undetermined = result(verified=None, verification=("unsupported_algorithm",))
    found = findings_of(undetermined, now=NOW)
    notes = notes_of(undetermined, now=NOW)

    assert "signature_invalid" not in found
    assert any("did not conclude" in note and "unsupported_algorithm" in note for note in notes)
    assert any("not a finding about the file" in note for note in notes)


def test_an_invalid_signature_names_what_came_back():
    """A verdict with nothing behind it is the thing this repository keeps
    finding: the flags that produced it are in the evidence."""
    found = findings_of(result(verified=False, verification=("bad_digest",)), now=NOW)

    assert set(found) == {"signature_invalid"}
    assert "bad_digest" in found["signature_invalid"][0]


def test_an_embedded_signature_that_does_not_verify_is_a_finding():
    found = findings_of(result(verified=False), now=NOW)
    assert set(found) == {"signature_invalid"}
    assert "CN=Example" in found["signature_invalid"][0]


def test_an_expired_certificate_is_a_finding():
    found = findings_of(result(chain=[cert("2026-08-07 11:08:35")]), now=NOW)
    assert set(found) == {"certificate_expired"}
    assert "2026-08-07" in found["certificate_expired"][0]


def test_an_expired_certificate_with_a_countersignature_is_not():
    """What a timestamp is for, and the case this repository's fixture is.

    python.exe was signed with a certificate valid for three days in August
    2026. It is long expired and LIEF still verifies the signature, because
    the RFC3161 countersignature says the signing happened while the
    certificate was good. Reporting that as a finding would be wrong.
    """
    signed_in_time = result(
        chain=[cert("2026-08-07 11:08:35")],
        timestamp="2026-08-05 11:45:32 UTC",
    )
    assert findings_of(signed_in_time, now=NOW) == {}


def test_a_certificate_that_has_not_expired_is_not_a_finding():
    assert findings_of(result(chain=[cert("2030-01-01 00:00:00")]), now=NOW) == {}


def test_only_the_leaf_certificate_is_judged():
    """A root that outlives the leaf says nothing about this file."""
    found = findings_of(
        result(chain=[cert("2026-08-07 11:08:35"), cert("2045-01-01 00:00:00")]),
        now=NOW,
    )
    assert set(found) == {"certificate_expired"}


def test_an_unreadable_expiry_date_is_not_turned_into_a_finding():
    assert findings_of(result(chain=[cert(None)]), now=NOW) == {}


def test_a_hardcoded_address_is_a_finding():
    found = findings_of(result(ips=["203.0.113.7"], imports=SOCKETS), now=NOW)
    assert set(found) == {"hardcoded_ip"}
    assert found["hardcoded_ip"] == ["203.0.113.7"]


def test_loopback_and_the_unspecified_address_are_not_endpoints():
    """0.0.0.0 and 127.x are how a program binds, not somewhere it calls.

    With sockets imported, so that the rule under test is the one doing the
    work: a file with no network imports raises nothing anyway, and this would
    have passed with the loopback rule deleted.
    """
    assert findings_of(result(ips=["127.0.0.1", "0.0.0.0"], imports=SOCKETS), now=NOW) == {}


def test_a_result_that_failed_to_parse_produces_no_findings():
    """No facts, no accusations."""
    broken = result(error="unrecognised format", state=SignatureState.UNKNOWN)
    assert findings_of(broken, now=NOW) == {}


def test_findings_can_coexist():
    found = findings_of(
        result(state=SignatureState.UNSIGNED, verified=False,
               ips=["203.0.113.7"], imports=SOCKETS),
        now=NOW,
    )
    assert set(found) == {"unsigned", "hardcoded_ip"}


# --------------------------------------------------------------------------
# notes
# --------------------------------------------------------------------------


def test_the_cra_is_cited_before_it_applies_and_the_note_says_so():
    """Article 71(2): the regulation applies from 11 December 2027.

    Citing it today is citing a rule that is in force and not yet applicable.
    A report that hides that is misleading, so the note is not optional.
    """
    notes = notes_of(result(state=SignatureState.UNSIGNED, verified=False), now=NOW)
    assert CRA_APPLICATION_NOTE in notes
    assert "2027" in CRA_APPLICATION_NOTE


def test_the_nis2_and_gdpr_notes_state_whom_those_acts_bind():
    notes = " ".join(notes_of(result(state=SignatureState.UNSIGNED, verified=False), now=NOW))
    assert "essential and important entities" in notes
    assert "personal data" in notes


def test_a_note_is_only_added_for_an_act_that_is_actually_cited():
    """A hardcoded address cites the CRA alone; NIS2 has nothing to do with it."""
    notes = " ".join(notes_of(result(ips=["203.0.113.7"], imports=SOCKETS), now=NOW))
    assert "essential and important entities" not in notes
    assert "2027" in notes


def test_the_hardcoded_address_note_admits_what_cannot_be_told_apart():
    """1.2.3.4 is both a valid address and a common version string.

    With sockets in the import table the finding is raised, and this is the note
    that goes with it. Without them the finding is not raised at all and a
    different note explains why, which is a different test.
    """
    notes = " ".join(notes_of(result(ips=["1.2.3.4"], imports=SOCKETS), now=NOW))
    assert "version number" in notes


# --------------------------------------------------------------------------
# check()
# --------------------------------------------------------------------------


def _fake_fetch(suffix=""):
    calls = []

    def fake(act, articles, now=None, **kwargs):
        calls.append((act, articles))
        stamp = law_fetcher.utc_stamp(now)
        refs = {ref for pairs in FINDING_ARTICLES.values() for a, ref in pairs if a == act}
        return {
            ref: Provision.from_text(ref, f"{act.name} {ref}{suffix}", stamp, act.celex)
            for ref in refs if ref.split("(")[0] in articles
        }

    fake.calls = calls
    return fake


@pytest.fixture
def cache(tmp_path):
    return LawCache(tmp_path / "law_cache.json")


@pytest.fixture
def online(monkeypatch):
    fake = _fake_fetch()
    monkeypatch.setattr(law_fetcher, "fetch_provisions", fake)
    return fake.calls


def test_a_clean_file_cites_nothing(cache, online):
    outcome = check(result(), cache=cache, now=NOW)
    assert outcome.citations == []
    assert online == []


def test_every_cited_provision_carries_its_hash_and_date(cache, online):
    outcome = check(result(state=SignatureState.UNSIGNED, verified=False), cache=cache, now=NOW)

    assert [c.article for c in outcome.citations] == [
        PART_I + "(2)(f)", "13(1)", "21(2)(d)", "32(1)",
    ]
    for citation in outcome.citations:
        assert citation.finding == "unsigned"
        assert len(citation.sha256) == 64
        assert citation.version_date == "2026-09-21"


def test_the_annex_and_the_article_are_fetched_in_one_request(cache, online):
    """Both live in the same act, so the act is downloaded once."""
    check(result(state=SignatureState.UNSIGNED, verified=False), cache=cache, now=NOW)

    by_act = dict(online)
    assert set(by_act[CRA]) == {PART_I, "13"}
    assert len(online) == 3


def test_the_evidence_travels_with_the_citations(cache, online):
    outcome = check(result(ips=["203.0.113.7"], imports=SOCKETS), cache=cache, now=NOW)
    assert outcome.evidence == {"hardcoded_ip": ["203.0.113.7"]}


def test_an_act_that_cannot_be_reached_is_cited_from_the_cache(cache, monkeypatch):
    monkeypatch.setattr(law_fetcher, "fetch_provisions", _fake_fetch())
    first = check(result(ips=["203.0.113.7"], imports=SOCKETS), cache=cache, now=NOW)

    def unreachable(act, articles, now=None, **kwargs):
        raise LawFetchError("Cellar answered HTTP 202; and EUR-Lex answered HTTP 202")

    monkeypatch.setattr(law_fetcher, "fetch_provisions", unreachable)
    second = check(result(ips=["203.0.113.7"], imports=SOCKETS), cache=cache, now=NOW)

    assert [c.sha256 for c in second.citations] == [c.sha256 for c in first.citations]
    assert [status.source for status in second.acts] == ["cache"]
    assert "202" in second.acts[0].error


def test_an_act_reachable_by_neither_route_is_cited_without_a_hash(cache, monkeypatch):
    """Better an empty hash than a hash of nothing."""
    def unreachable(act, articles, now=None, **kwargs):
        raise LawFetchError("unreachable")

    monkeypatch.setattr(law_fetcher, "fetch_provisions", unreachable)
    outcome = check(result(ips=["203.0.113.7"], imports=SOCKETS), cache=cache, now=NOW)

    assert outcome.citations[0].sha256 is None
    assert outcome.acts[0].source == "unavailable"


def test_a_changed_provision_is_reported_with_its_previous_hash(cache, monkeypatch):
    monkeypatch.setattr(law_fetcher, "fetch_provisions", _fake_fetch())
    check(result(ips=["203.0.113.7"], imports=SOCKETS), cache=cache, now=NOW)

    monkeypatch.setattr(law_fetcher, "fetch_provisions", _fake_fetch(" amended"))
    outcome = check(result(ips=["203.0.113.7"], imports=SOCKETS), cache=cache, now=NOW)

    assert list(outcome.changed) == [f"{CRA.name} {PART_I}(2)(j)"]


def test_offline_cites_from_the_cache_the_hashes_an_online_run_stored(cache, network):
    """The module cites the cached copy when there is no network, and offline by
    choice is the same: nothing downloaded, the hashes and dates read from the cache.

    Derived data: the cache is filled from the saved pages in ACT_FIXTURES by the
    parser and the cache an online run uses after a download, so it holds what
    such a run stores; only the download date, NOW, is set here.
    """
    unsigned = result(state=SignatureState.UNSIGNED, verified=False)
    stamp = law_fetcher.utc_stamp(NOW)
    stored: dict = {}
    for act, fixture in ACT_FIXTURES.items():
        units = tuple(dict.fromkeys(ref.split("(")[0] for a, ref in FINDING_ARTICLES["unsigned"] if a == act))
        html = (FIXTURES / fixture).read_text(encoding="utf-8")
        for ref, text in law_fetcher.parse_articles(html, units).items():
            provision = Provision.from_text(ref, text, stamp, act.celex)
            stored[provision.key] = provision
    cache.update(stored, checked_at=stamp)

    offline_run = check(unsigned, cache=cache, now=NOW, offline=True)

    assert network == []
    expected = [stored[(act.celex, ref)].sha256 for act, ref in FINDING_ARTICLES["unsigned"]]
    assert all(expected)
    assert [c.sha256 for c in offline_run.citations] == expected
    assert {c.version_date for c in offline_run.citations} == {"2026-09-21"}
    assert {status.source for status in offline_run.acts} == {"cache"}


# --------------------------------------------------------------------------
# rendering a citation
# --------------------------------------------------------------------------


def test_an_annex_citation_does_not_call_itself_an_article(cache, online):
    """"art. Allegato I" would be wrong in the one place it has to be right."""
    outcome = check(result(ips=["203.0.113.7"], imports=SOCKETS), cache=cache, now=NOW)
    rendered = format_citation(outcome.citations[0])

    assert "art. Allegato" not in rendered
    assert PART_I + "(2)(j)" in rendered
    assert "SHA256" in rendered


def test_an_article_citation_still_says_article(cache, online):
    outcome = check(result(state=SignatureState.UNSIGNED, verified=False), cache=cache, now=NOW)
    article = next(c for c in outcome.citations if c.article == "13(1)")

    assert "art. 13(1)" in format_citation(article)


# --------------------------------------------------------------------------
# findings as the objects the model carries
# --------------------------------------------------------------------------


def test_every_finding_has_a_severity():
    assert set(law_checker.SEVERITY) == set(FINDING_ARTICLES)


def test_findings_for_builds_the_model_objects():
    found = law_checker.findings_for(
        result(state=SignatureState.UNSIGNED, verified=False,
               ips=["203.0.113.7"], imports=SOCKETS),
        now=NOW,
    )

    assert [f.id for f in found] == ["unsigned", "hardcoded_ip"]
    assert [f.severity for f in found] == ["medium", "low"]
    assert all(f.evidence for f in found)


def test_a_clean_file_carries_no_finding_objects():
    assert law_checker.findings_for(result(), now=NOW) == []


# --------------------------------------------------------------------------
# what Code.exe showed on 2026-10-09
# --------------------------------------------------------------------------

# Dotted quads read out of Code.exe (VS Code 1.105, Microsoft, 238 MB). The six
# that begin with 0 sit in a resource table beside `0.0.10.4425`; none of them
# can be a destination, because 0.0.0.0/8 is "this network" (RFC 1122 3.2.1.3,
# RFC 6890) and no packet is routed to it. The others are Chromium's
# DNS-over-HTTPS resolvers, and are endpoints.
THIS_NETWORK = ["0.0.10.0", "0.0.100.0", "0.0.13.0", "0.0.14.0", "0.0.15.0", "0.1.0.0"]
RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "149.112.112.112"]


def test_this_network_is_not_an_endpoint():
    """`0.0.0.0` was already excluded; `0.0.10.0` was raised as a hardcoded
    address and cited against the CRA, from a Microsoft binary."""
    assert findings_of(result(ips=THIS_NETWORK, imports=SOCKETS), now=NOW) == {}


def test_the_resolvers_beside_them_are_still_a_finding():
    found = findings_of(result(ips=[*THIS_NETWORK, *RESOLVERS], imports=SOCKETS), now=NOW)

    assert found == {"hardcoded_ip": RESOLVERS}


def test_this_network_is_treated_as_the_loopback_is():
    """Not an endpoint, so neither the finding nor the note that explains a
    withheld one: the same silence `0.0.0.0` and `127.0.0.1` already get."""
    notes = notes_of(result(ips=THIS_NETWORK, imports=SOCKETS), now=NOW)

    assert law_checker.ADDRESSES_WITHOUT_NETWORK_NOTE not in notes
    assert law_checker.HARDCODED_IP_NOTE not in notes
