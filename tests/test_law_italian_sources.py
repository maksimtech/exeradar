"""The provisions are cited where they bind, and the source named is the one that answered.

- The NIS2 directive binds the Member States; in Italy the duty of essential and important entities to take
  security measures is art. 24 of d.lgs. 138/2024 (rubrica "Obblighi in materia di misure di gestione dei rischi
  per la sicurezza informatica"), not art. 21 of the directive.
- EU texts are downloaded from Cellar (publications.europa.eu), with EUR-Lex only as the fallback: "verified
  against EUR-Lex" named a site the text did not come from.

Recorded at the HTTP boundary, as CLAUDE.md allows: fixtures/normattiva_dlgs138_2024_art24_recorded.html is
Normattiva's answer to the URL below, saved byte for byte on 2026-10-23 at 15:53 UTC (sha256 3a2ace83…ee76, the
same at 15:52); gdpr_it_excerpt.html is the GDPR page the other law tests already use. httpx.MockTransport answers
only those URLs, so nothing reaches the network and every request is seen.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from exeradar import law_checker, law_fetcher
from exeradar.law_cache import LawCache
from exeradar.models import ExeResult, Signature, SignatureState, Strings

FIXTURES = Path(__file__).parent / "fixtures"
NORMATTIVA_PAGE = (FIXTURES / "normattiva_dlgs138_2024_art24_recorded.html").read_text(encoding="utf-8")
GDPR_PAGE = (FIXTURES / "gdpr_it_excerpt.html").read_text(encoding="utf-8")
DLGS_138_URN = "urn:nir:stato:decreto.legislativo:2024-09-04;138"
ART_24_URL = f"https://www.normattiva.it/uri-res/N2Ls?{DLGS_138_URN}~art24!vig="
GDPR_CELLAR_URL = "https://publications.europa.eu/resource/celex/32016R0679"
GDPR_EURLEX_URL = "https://eur-lex.europa.eu/legal-content/IT/TXT/HTML/?uri=CELEX:32016R0679"
NOW = datetime(2026, 10, 23, 16, 0, tzinfo=UTC)

# An unsigned binary: the CRA, the GDPR (from Cellar) and the decree's art. 24(2)(d)
UNSIGNED = ExeResult(path="C:/tmp/sample.exe", size=1000, sha256="aa", format="PE", error=None, imports=[],
                     strings=Strings(ips=[]),
                     signature=Signature(state=SignatureState.UNSIGNED, verified=False, signer="", chain=[],
                                         timestamp=None, detail="detail", verification=()))


@pytest.fixture
def real_fetch(monkeypatch):
    """conftest disables fetch_html so that no test reaches the network; these tests pass a client that answers
    only from the recordings, so the real function goes back."""
    monkeypatch.setattr(law_fetcher, "fetch_html", REAL_FETCH_HTML)


REAL_FETCH_HTML = law_fetcher.fetch_html


def recorded(pages: dict[str, str], seen: list[str]) -> httpx.Client:
    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if str(request.url) in pages:
            return httpx.Response(200, text=pages[str(request.url)])
        return httpx.Response(503)

    return httpx.Client(transport=httpx.MockTransport(answer))


def test_the_recording_is_article_24_of_the_decree():
    """What the tests below rely on, so that they cannot pass on a page that no longer shows it."""
    assert "Obblighi in materia di misure di gestione dei rischi per la sicurezza informatica" in NORMATTIVA_PAGE


def test_article_24_of_dlgs_138_2024_is_read_from_normattiva(real_fetch):
    seen: list[str] = []
    provisions = law_fetcher.fetch_provisions(law_fetcher.DLGS_138_2024, ("24",), now=NOW,
                                              client=recorded({ART_24_URL: NORMATTIVA_PAGE}, seen))
    assert seen == [ART_24_URL]
    assert provisions["24"].text.startswith(
        "1. I soggetti essenziali e i soggetti importanti adottano misure tecniche, operative e organizzative")
    assert law_fetcher.DLGS_138_2024.celex == DLGS_138_URN
    assert law_fetcher.DLGS_138_2024.source == "Normattiva"


def test_the_findings_cite_the_letters_of_the_italian_decree():
    """The directive's art. 21 is addressed to the Member States; the entities are bound by art. 24 of the decree,
    whose paragraph 2 has the same letters: (d) supply chain security, (e) security in acquisition, development and
    maintenance, vulnerability handling included."""
    expected = {"unsigned": "24(2)(d)", "signature_invalid": "24(2)(d)", "known_vulnerabilities": "24(2)(e)"}
    for finding, ref in expected.items():
        cited = law_checker.FINDING_ARTICLES[finding]
        assert (law_fetcher.DLGS_138_2024, ref) in cited, finding
        assert all(act != law_fetcher.NIS2 for act, _ in cited), finding


def test_the_letters_cited_are_the_ones_the_decree_has(real_fetch):
    seen: list[str] = []
    provisions = law_fetcher.fetch_provisions(law_fetcher.DLGS_138_2024, ("24",), now=NOW,
                                              client=recorded({ART_24_URL: NORMATTIVA_PAGE}, seen))
    assert provisions["24(2)(d)"].text.startswith("d) sicurezza della catena di approvvigionamento")
    assert provisions["24(2)(e)"].text.startswith(
        "e) sicurezza dell'acquisizione, dello sviluppo e della manutenzione dei sistemi informativi e di rete")


def test_the_scope_note_comes_with_the_decree():
    notes = law_checker.notes_of(UNSIGNED, now=NOW)
    assert law_checker.NIS2_SCOPE_NOTE in notes


def test_the_scope_note_names_the_decree():
    note = law_checker.NIS2_SCOPE_NOTE
    assert "D.Lgs. 138/2024 art. 24" in note and "art. 3" in note
    assert "essential and important entities" in note
    assert "directive" not in note


def statuses(pages: dict[str, str], tmp_path: Path, seen: list[str]) -> dict[str, str | None]:
    result = law_checker.check(UNSIGNED, cache=LawCache(tmp_path / "law_cache.json"), now=NOW,
                               client=recorded(pages, seen))
    return {status.act.name: (status.source, status.origin) for status in result.acts}


def test_the_status_names_cellar_when_cellar_answered(real_fetch, tmp_path):
    seen: list[str] = []
    got = statuses({GDPR_CELLAR_URL: GDPR_PAGE, ART_24_URL: NORMATTIVA_PAGE}, tmp_path, seen)
    assert got[law_fetcher.GDPR.name] == ("verified", "Cellar")
    assert got[law_fetcher.DLGS_138_2024.name] == ("verified", "Normattiva")
    assert GDPR_EURLEX_URL not in seen


def test_the_status_names_eur_lex_when_only_the_fallback_answered(real_fetch, tmp_path):
    seen: list[str] = []
    got = statuses({GDPR_EURLEX_URL: GDPR_PAGE, ART_24_URL: NORMATTIVA_PAGE}, tmp_path, seen)
    assert got[law_fetcher.GDPR.name] == ("verified", "EUR-Lex")
    assert seen.index(GDPR_CELLAR_URL) < seen.index(GDPR_EURLEX_URL)   # Cellar first, then the fallback


def test_a_text_from_the_cache_names_no_source(real_fetch, tmp_path):
    """Nothing answered now: the copy is the cache's, and no site is claimed."""
    seen: list[str] = []
    statuses({GDPR_CELLAR_URL: GDPR_PAGE, ART_24_URL: NORMATTIVA_PAGE}, tmp_path, seen)
    got = statuses({}, tmp_path, seen)
    assert got[law_fetcher.GDPR.name] == ("cache", None)
