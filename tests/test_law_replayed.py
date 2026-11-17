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

from exeradar import law_fetcher
from exeradar.law_cache import LawCache
from exeradar.law_checker import check
from exeradar.law_fetcher import CRA, DLGS_138_2024, GDPR, LawFetchError
from exeradar.models import ExeResult, Signature, SignatureState, Strings

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
