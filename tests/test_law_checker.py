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

from datetime import datetime, timezone
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
    Signature,
    SignatureState,
    Strings,
)

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
PART_I = "Allegato I, Parte I"

ACT_FIXTURES = {
    CRA: "cra_it_excerpt.html",
    GDPR: "gdpr_it_excerpt.html",
    NIS2: "nis2_it_excerpt.html",
}


def result(
    *,
    state=SignatureState.EMBEDDED,
    verified=True,
    chain=(),
    timestamp=None,
    ips=(),
    error=None,
) -> ExeResult:
    return ExeResult(
        path="C:/tmp/sample.exe",
        size=1000,
        sha256="aa",
        format="PE",
        error=error,
        strings=Strings(ips=list(ips)),
        signature=Signature(
            state=state,
            verified=verified,
            signer="CN=Example",
            chain=list(chain),
            timestamp=timestamp,
            detail="detail",
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
    assert FUTURE_FINDINGS == {"known_vulnerabilities"}
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
    unknown = result(state=SignatureState.UNKNOWN, verified=None)
    assert findings_of(unknown, now=NOW) == {}
    assert any("non verificabile" in note for note in notes_of(unknown, now=NOW))


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
    found = findings_of(result(ips=["203.0.113.7"]), now=NOW)
    assert set(found) == {"hardcoded_ip"}
    assert found["hardcoded_ip"] == ["203.0.113.7"]


def test_loopback_and_the_unspecified_address_are_not_endpoints():
    """0.0.0.0 and 127.x are how a program binds, not somewhere it calls."""
    assert findings_of(result(ips=["127.0.0.1", "0.0.0.0"]), now=NOW) == {}


def test_a_result_that_failed_to_parse_produces_no_findings():
    """No facts, no accusations."""
    broken = result(error="unrecognised format", state=SignatureState.UNKNOWN)
    assert findings_of(broken, now=NOW) == {}


def test_findings_can_coexist():
    found = findings_of(
        result(state=SignatureState.UNSIGNED, verified=False, ips=["203.0.113.7"]),
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
    assert "soggetti essenziali e importanti" in notes
    assert "dati personali" in notes


def test_a_note_is_only_added_for_an_act_that_is_actually_cited():
    """A hardcoded address cites the CRA alone; NIS2 has nothing to do with it."""
    notes = " ".join(notes_of(result(ips=["203.0.113.7"]), now=NOW))
    assert "soggetti essenziali e importanti" not in notes
    assert "2027" in notes


def test_the_hardcoded_address_note_admits_what_cannot_be_told_apart():
    notes = " ".join(notes_of(result(ips=["1.2.3.4"]), now=NOW))
    assert "versione" in notes


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

    by_act = {act: articles for act, articles in online}
    assert set(by_act[CRA]) == {PART_I, "13"}
    assert len(online) == 3


def test_the_evidence_travels_with_the_citations(cache, online):
    outcome = check(result(ips=["203.0.113.7"]), cache=cache, now=NOW)
    assert outcome.evidence == {"hardcoded_ip": ["203.0.113.7"]}


def test_an_act_that_cannot_be_reached_is_cited_from_the_cache(cache, monkeypatch):
    monkeypatch.setattr(law_fetcher, "fetch_provisions", _fake_fetch())
    first = check(result(ips=["203.0.113.7"]), cache=cache, now=NOW)

    def unreachable(act, articles, now=None, **kwargs):
        raise LawFetchError("Cellar answered HTTP 202; and EUR-Lex answered HTTP 202")

    monkeypatch.setattr(law_fetcher, "fetch_provisions", unreachable)
    second = check(result(ips=["203.0.113.7"]), cache=cache, now=NOW)

    assert [c.sha256 for c in second.citations] == [c.sha256 for c in first.citations]
    assert [status.source for status in second.acts] == ["cache"]
    assert "202" in second.acts[0].error


def test_an_act_reachable_by_neither_route_is_cited_without_a_hash(cache, monkeypatch):
    """Better an empty hash than a hash of nothing."""
    def unreachable(act, articles, now=None, **kwargs):
        raise LawFetchError("unreachable")

    monkeypatch.setattr(law_fetcher, "fetch_provisions", unreachable)
    outcome = check(result(ips=["203.0.113.7"]), cache=cache, now=NOW)

    assert outcome.citations[0].sha256 is None
    assert outcome.acts[0].source == "unavailable"


def test_a_changed_provision_is_reported_with_its_previous_hash(cache, monkeypatch):
    monkeypatch.setattr(law_fetcher, "fetch_provisions", _fake_fetch())
    check(result(ips=["203.0.113.7"]), cache=cache, now=NOW)

    monkeypatch.setattr(law_fetcher, "fetch_provisions", _fake_fetch(" amended"))
    outcome = check(result(ips=["203.0.113.7"]), cache=cache, now=NOW)

    assert list(outcome.changed) == [f"{CRA.name} {PART_I}(2)(j)"]


# --------------------------------------------------------------------------
# rendering a citation
# --------------------------------------------------------------------------


def test_an_annex_citation_does_not_call_itself_an_article(cache, online):
    """"art. Allegato I" would be wrong in the one place it has to be right."""
    outcome = check(result(ips=["203.0.113.7"]), cache=cache, now=NOW)
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
        result(state=SignatureState.UNSIGNED, verified=False, ips=["203.0.113.7"]),
        now=NOW,
    )

    assert [f.id for f in found] == ["unsigned", "hardcoded_ip"]
    assert [f.severity for f in found] == ["medium", "low"]
    assert all(f.evidence for f in found)


def test_a_clean_file_carries_no_finding_objects():
    assert law_checker.findings_for(result(), now=NOW) == []
