"""The law check end to end, on the services' own answers.

httpx.MockTransport answers at the HTTP boundary, as test_law_fetch_https.py
does, from what the services sent: Cellar's 303 recorded in
fixtures/cellar_redirect_32016R0679.json, the CRA and GDPR pages the other law
tests use, and Normattiva's art. 24 recorded page. Where a test needs a service
to misbehave, the answer is derived from those, and the test says what was
changed. Any URL not listed is answered 404, and every request is seen.

What these tests hold the check to: a citation is "verified" only when the
reference it cites was in the text downloaded now, from the host it was asked
of; anything else falls back to the cache, labelled as such, and the status
says which source was tried and why it was not used. The cases are mailradar's
(its PR #103), ported.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from exeradar import law_checker, law_fetcher, report
from exeradar.law_cache import LawCache
from exeradar.law_checker import check
from exeradar.law_fetcher import CRA, DLGS_138_2024, GDPR, LawFetchError
from exeradar.models import ExeResult, Signature, SignatureState, Strings
from tests.names import mentions

FIXTURES = Path(__file__).parent / "fixtures"
REDIRECT = json.loads((FIXTURES / "cellar_redirect_32016R0679.json").read_text(encoding="utf-8"))
CRA_PAGE = (FIXTURES / "cra_it_excerpt.html").read_text(encoding="utf-8")
GDPR_PAGE = (FIXTURES / "gdpr_it_excerpt.html").read_text(encoding="utf-8")
NORMATTIVA_PAGE = (FIXTURES / "normattiva_dlgs138_2024_art24_recorded.html").read_text(encoding="utf-8")

CELLAR_CRA = law_fetcher.CELLAR_URL.format(celex=CRA.celex)
CELLAR_GDPR = REDIRECT["request"]
EURLEX_GDPR = law_fetcher.SOURCE_URL.format(lang="IT", celex=GDPR.celex)
ART_24 = law_fetcher.NORMATTIVA_URL.format(urn=DLGS_138_2024.celex, article="24")

DAY1 = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
DAY2 = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)

# The recorded 303, with its Location replaced by a host IDNA refuses: httpx
# raises idna.core.IDNAError for it, a ValueError and no httpx.HTTPError
BAD_HOST = "http://xn--/DOC_1"


def unsigned() -> ExeResult:
    """Cites the CRA (annex and art. 13(1)), D.Lgs. 138/2024 art. 24(2)(d) and GDPR art. 32(1)."""
    return ExeResult(
        path="C:/tmp/sample.exe", size=1000, sha256="aa", format="PE",
        strings=Strings(ips=[]),
        signature=Signature(state=SignatureState.UNSIGNED, verified=False, detail="no signature"),
    )


def page(text: str) -> tuple[int, dict[str, str], str]:
    return 200, {"Content-Type": "text/html; charset=UTF-8"}, text


def redirect(location: str) -> tuple[int, dict[str, str], str]:
    """Cellar's recorded 303, pointed elsewhere."""
    return REDIRECT["status"], {**REDIRECT["headers"], "Location": location}, ""


WAF_202 = (202, {"x-amzn-waf-action": "challenge"}, "")   # what EUR-Lex answers every automated request


def services(answers: dict[str, tuple[int, dict[str, str], str]], seen: list[str] | None = None) -> httpx.Client:
    """The services as recorded: `answers` by URL, 404 for anything else."""
    seen = [] if seen is None else seen

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if str(request.url) not in answers:
            return httpx.Response(404)
        status, headers, text = answers[str(request.url)]
        return httpx.Response(status, headers=headers, text=text)

    return httpx.Client(transport=httpx.MockTransport(answer))


def recorded(**override: tuple[int, dict[str, str], str]) -> dict[str, tuple[int, dict[str, str], str]]:
    """Every act served as recorded, with the answers in `override` (by URL) instead."""
    answers = {CELLAR_CRA: page(CRA_PAGE), CELLAR_GDPR: page(GDPR_PAGE), ART_24: page(NORMATTIVA_PAGE)}
    return {**answers, **override}


def status_of(outcome, act):
    return next(status for status in outcome.acts if status.act == act)


@pytest.fixture
def cache(tmp_path):
    return LawCache(tmp_path / "law_cache.json")


# --------------------------------------------------------------------------
# any failure to fetch is a LawFetchError, so the fallbacks apply
# --------------------------------------------------------------------------


@pytest.mark.parametrize("location", [BAD_HOST, BAD_HOST.replace("http://", "https://")])
def test_a_redirect_httpx_cannot_follow_is_a_fetch_error(location):
    """It went past the EUR-Lex fallback and the cache, and out of check()."""
    with pytest.raises(LawFetchError, match="Cellar"):
        law_fetcher.fetch_html(CELLAR_GDPR, client=services({CELLAR_GDPR: redirect(location)}))


def test_a_host_httpx_cannot_encode_is_a_fetch_error():
    with pytest.raises(LawFetchError, match="unreachable"):
        law_fetcher.fetch_html("https://xn--/DOC_1", client=services({}))


def test_then_eur_lex_is_tried(cache):
    answers = recorded(**{CELLAR_GDPR: redirect(BAD_HOST), EURLEX_GDPR: page(GDPR_PAGE)})
    outcome = check(unsigned(), cache=cache, now=DAY1, client=services(answers))

    assert (status_of(outcome, GDPR).source, status_of(outcome, GDPR).origin) == ("verified", "EUR-Lex")


def test_then_the_cache(cache):
    first = check(unsigned(), cache=cache, now=DAY1, client=services(recorded()))
    assert status_of(first, GDPR).source == "verified"

    answers = recorded(**{CELLAR_GDPR: redirect(BAD_HOST), EURLEX_GDPR: WAF_202})
    outcome = check(unsigned(), cache=cache, now=DAY2, client=services(answers))

    assert status_of(outcome, GDPR).source == "cache"
    gdpr = [c for c in outcome.citations if c.law == GDPR.name]
    assert [c.sha256 for c in gdpr] == [c.sha256 for c in first.citations if c.law == GDPR.name]


# --------------------------------------------------------------------------
# redirects stay on the source's host
# --------------------------------------------------------------------------

# Cellar's recorded 303, pointed at another host and at another port
OFF_HOST = ["https://example.org/resource/DOC_1", "http://example.org/resource/DOC_1",
            "https://publications.europa.eu:8443/resource/DOC_1"]


@pytest.mark.parametrize("location", OFF_HOST)
def test_a_redirect_to_another_host_is_not_followed(location):
    """The text another host serves is not Cellar's, whatever Cellar's 303 says."""
    seen: list[str] = []
    forged = page(GDPR_PAGE.replace("Tenendo conto", "Testo falso"))
    client = services({CELLAR_GDPR: redirect(location), location.replace("http://", "https://", 1): forged}, seen)

    with pytest.raises(LawFetchError, match="redirected"):
        law_fetcher.fetch_html(CELLAR_GDPR, client=client)
    assert seen == [CELLAR_GDPR]


@pytest.mark.parametrize("location", OFF_HOST)
def test_a_text_from_another_host_is_not_verified_against_cellar(cache, location):
    """It was fetched, hashed, cached and cited as "verified", origin Cellar."""
    seen: list[str] = []
    forged = page(GDPR_PAGE.replace("Tenendo conto", "Testo falso"))
    answers = recorded(**{
        CELLAR_GDPR: redirect(location),
        location.replace("http://", "https://", 1): forged,
        EURLEX_GDPR: WAF_202,
    })
    outcome = check(unsigned(), cache=cache, now=DAY1, client=services(answers, seen))

    assert (status_of(outcome, GDPR).source, status_of(outcome, GDPR).origin) == ("unavailable", None)
    assert [url for url in seen if url not in (CELLAR_GDPR, EURLEX_GDPR, CELLAR_CRA, ART_24)] == []
    assert {c.sha256 for c in outcome.citations if c.law == GDPR.name} == {None}


# --------------------------------------------------------------------------
# errors and statuses name the source that was tried
# --------------------------------------------------------------------------


def test_an_article_missing_from_normattiva_names_normattiva():
    """It said "Article 99 not found in the EUR-Lex page" of a Normattiva page.
    Derived: Normattiva's recorded art. 24 page, served for art. 99."""
    art_99 = law_fetcher.NORMATTIVA_URL.format(urn=DLGS_138_2024.celex, article="99")
    with pytest.raises(LawFetchError) as caught:
        law_fetcher.fetch_provisions_from(DLGS_138_2024, ("99",), client=services({art_99: page(NORMATTIVA_PAGE)}))

    assert "Normattiva" in str(caught.value)
    assert "EUR-Lex" not in str(caught.value)
    assert (caught.value.source, caught.value.reached) == ("Normattiva", True)


def test_an_article_missing_from_cellar_names_cellar():
    with pytest.raises(LawFetchError) as caught:
        law_fetcher.fetch_provisions_from(GDPR, ("99",), client=services(recorded()))

    assert "Cellar" in str(caught.value)
    assert "EUR-Lex" not in str(caught.value)
    assert (caught.value.source, caught.value.reached) == ("Cellar", True)


def test_an_annex_missing_from_cellar_names_cellar():
    """The annex message named no source at all: "Allegato IV not found in the page"."""
    with pytest.raises(LawFetchError, match="Allegato IV") as caught:
        law_fetcher.fetch_provisions_from(CRA, ("Allegato IV",), client=services(recorded()))

    assert "Cellar" in str(caught.value)
    assert (caught.value.source, caught.value.reached) == ("Cellar", True)


@pytest.mark.parametrize("location", OFF_HOST)
def test_a_refused_redirect_names_the_source_and_the_host(location):
    with pytest.raises(LawFetchError) as caught:
        law_fetcher.fetch_html(CELLAR_GDPR, client=services({CELLAR_GDPR: redirect(location)}))

    assert (caught.value.source, caught.value.reached) == ("Cellar", False)
    host = httpx.URL(location).host
    assert mentions(str(caught.value), host)


def test_a_status_says_the_source_answered_without_the_text(cache):
    """Cellar was reached and its page lacked the article: not "unreachable".
    Derived: the recorded GDPR page with article 32 renumbered 99."""
    answers = recorded(**{CELLAR_GDPR: page(GDPR_PAGE.replace('id="art_32"', 'id="art_99"'))})
    gdpr = status_of(check(unsigned(), cache=cache, now=DAY1, client=services(answers)), GDPR)

    assert (gdpr.source, gdpr.tried, gdpr.failure) == ("unavailable", "Cellar", "not_in_text")
    assert gdpr.reason == "Cellar answered without the text cited"
    assert "EUR-Lex" not in (gdpr.error or "")


def test_a_status_names_both_sources_when_neither_answered(cache):
    answers = recorded(**{CELLAR_GDPR: redirect("https://example.org/DOC_1"), EURLEX_GDPR: WAF_202})
    gdpr = status_of(check(unsigned(), cache=cache, now=DAY1, client=services(answers)), GDPR)

    assert (gdpr.source, gdpr.tried, gdpr.failure) == ("unavailable", "Cellar and EUR-Lex", "unreachable")
    assert gdpr.reason == "Cellar and EUR-Lex unreachable"


def test_a_status_names_normattiva_when_normattiva_did_not_answer(cache):
    answers = recorded(**{ART_24: (503, {}, "")})
    decree = status_of(check(unsigned(), cache=cache, now=DAY1, client=services(answers)), DLGS_138_2024)

    assert (decree.tried, decree.failure, decree.reason) == ("Normattiva", "unreachable", "Normattiva unreachable")


def test_a_verified_status_has_no_reason(cache):
    gdpr = status_of(check(unsigned(), cache=cache, now=DAY1, client=services(recorded())), GDPR)

    assert (gdpr.source, gdpr.tried, gdpr.failure, gdpr.reason) == ("verified", None, None, None)


def test_offline_is_its_own_reason_and_names_no_source(cache):
    """Nothing was tried: "EUR-Lex unreachable", or any other source, would be
    an outage that never happened."""
    outcome = check(unsigned(), cache=cache, now=DAY1, offline=True)

    for status in outcome.acts:
        assert (status.source, status.tried, status.failure) == ("unavailable", None, "offline")
        assert status.reason == law_checker.OFFLINE
        assert "unreachable" not in status.reason


def test_the_report_says_why_an_act_was_not_verified(cache):
    """report.py printed the error alone, or nothing a reader could act on."""
    answers = recorded(**{CELLAR_GDPR: page(GDPR_PAGE.replace('id="art_32"', 'id="art_99"'))})
    outcome = check(unsigned(), cache=cache, now=DAY1, client=services(answers))

    text = report.to_markdown(unsigned(), law=outcome)

    assert (f"{GDPR.name}: no text available, cited without a hash "
            "(Cellar answered without the text cited: ") in text


# --------------------------------------------------------------------------
# a cited reference must be in the text downloaded now
# --------------------------------------------------------------------------

POINT_F = "Allegato I, Parte I(2)(f)"
# Derived: the recorded CRA page with the label of point (2)(f) of Annex I,
# Part I blanked, so the part and its other points parse and that point does not
CRA_WITHOUT_POINT_F = CRA_PAGE.replace('<p class="oj-normal">f)</p>', '<p class="oj-normal">-</p>')
# Derived: the recorded GDPR page with paragraph 1 of art. 32 no longer marked
# as a paragraph, so article 32 parses and 32(1) does not
GDPR_WITHOUT_32_1 = GDPR_PAGE.replace('id="032.001"', 'id="x"')


def test_the_derived_pages_lack_only_the_reference_cited():
    """What the tests below rely on."""
    annex = law_fetcher.parse_articles(CRA_WITHOUT_POINT_F, ("Allegato I, Parte I",))
    assert "Allegato I, Parte I(2)(e)" in annex and POINT_F not in annex
    gdpr = law_fetcher.parse_articles(GDPR_WITHOUT_32_1, ("32",))
    assert "32" in gdpr and "32(1)" not in gdpr


def test_a_point_missing_from_the_fresh_text_is_not_verified(cache):
    """The annex part parsed and the point cited was not in it: the act was
    "verified against Cellar" beside "SHA256: not available"."""
    answers = recorded(**{CELLAR_CRA: page(CRA_WITHOUT_POINT_F)})
    outcome = check(unsigned(), cache=cache, now=DAY1, client=services(answers))

    cra = status_of(outcome, CRA)
    assert (cra.source, cra.tried, cra.failure) == ("unavailable", "Cellar", "not_in_text")
    assert POINT_F in (cra.error or "")
    assert next(c for c in outcome.citations if c.article == POINT_F).sha256 is None


def test_a_cached_reference_is_not_served_as_verified(cache):
    """The same, with 32(1) cached by an earlier run: its old SHA-256 and date
    came back under the "verified" label, as if checked against today's text."""
    first = check(unsigned(), cache=cache, now=DAY1, client=services(recorded()))
    assert status_of(first, GDPR).source == "verified"
    cached = next(c for c in first.citations if c.law == GDPR.name)
    assert cached.sha256 is not None

    answers = recorded(**{CELLAR_GDPR: page(GDPR_WITHOUT_32_1)})
    outcome = check(unsigned(), cache=cache, now=DAY2, client=services(answers))

    gdpr = status_of(outcome, GDPR)
    assert (gdpr.source, gdpr.failure) == ("cache", "not_in_text")
    assert gdpr.reason == "Cellar answered without the text cited"
    citation = next(c for c in outcome.citations if c.law == GDPR.name)
    assert (citation.sha256, citation.version_date) == (cached.sha256, "2026-09-21")


def test_the_report_says_where_each_verified_text_came_from(cache):
    """It added no remark for a verified act, so a reader could not tell a
    citation checked today against Cellar from one out of the cache."""
    answers = recorded(**{CELLAR_GDPR: redirect(BAD_HOST), EURLEX_GDPR: page(GDPR_PAGE)})
    text = report.to_markdown(unsigned(), law=check(unsigned(), cache=cache, now=DAY1, client=services(answers)))

    assert f"{CRA.name}: verified against Cellar (CELEX {CRA.celex})" in text
    assert f"{GDPR.name}: verified against EUR-Lex (CELEX {GDPR.celex})" in text
    assert f"{DLGS_138_2024.name}: verified against Normattiva (URN {DLGS_138_2024.celex})" in text
