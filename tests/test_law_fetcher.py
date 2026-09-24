"""What ExeRadar adds to the shared fetcher, tested on the real act.

The machinery below `parse_articles` is the family's and is already covered in
the four other Radar repositories; what is new here is two things, and both
were forced by the CRA rather than chosen:

- the requirements ExeRadar cites are in *Annex I*, not in an article. Article
  6 says a product may be placed on the market only if it "meets the essential
  cybersecurity requirements set out in Part I of Annex I" and stops there, so
  an annex that cannot be fetched means citing a pointer instead of a rule.
- eur-lex.europa.eu now answers automated requests with HTTP 202 and an AWS
  WAF challenge — every request, for every act, so the family's source is
  simply unreachable. The Publications Office's Cellar service serves the same
  documents to machines, which is what it exists for.

The fixtures are cut from the documents the fetcher really downloads, keeping
their own markup: see ATTRIBUTIONS.md.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from exeradar import law_fetcher
from exeradar.law_fetcher import (
    CRA,
    Act,
    LawFetchError,
    parse_articles,
)

FIXTURES = Path(__file__).parent / "fixtures"

PART_I = "Allegato I, Parte I"
PART_II = "Allegato I, Parte II"


@pytest.fixture(scope="module")
def cra() -> str:
    return (FIXTURES / "cra_it_excerpt.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def annex(cra) -> dict[str, str]:
    return parse_articles(cra, (PART_I, PART_II))


# --------------------------------------------------------------------------
# the act
# --------------------------------------------------------------------------


def test_the_cra_is_an_eur_lex_act_with_its_celex_number():
    assert CRA.celex == "32024R2847"
    assert CRA.source == "EUR-Lex"
    assert "2024/2847" in CRA.name


# --------------------------------------------------------------------------
# annexes
# --------------------------------------------------------------------------


def test_an_annex_part_is_a_fetchable_unit(annex):
    """"Allegato I, Parte I" is addressed the way "13" is."""
    assert annex[PART_I]
    assert annex[PART_II]


def test_the_two_parts_do_not_run_into_each_other(annex):
    """Part I states properties of the product, Part II duties of the maker.

    Both are numbered from (1), which is why the part is part of the reference
    and not an afterthought.
    """
    assert annex[f"{PART_I}(1)"] != annex[f"{PART_II}(1)"]
    assert annex[f"{PART_II}(1)"] not in annex[PART_I]
    assert annex[f"{PART_I}(2)"] not in annex[PART_II]


def test_the_integrity_requirement_is_where_exeradar_says_it_is(annex):
    """Part I(2)(f) is the provision the signature findings are cited under.

    Pinned to the wording, not to the reference: if the point ever moves, the
    citation is wrong and this test is the thing that says so.
    """
    point = annex[f"{PART_I}(2)(f)"]
    assert point.startswith("f)")
    assert "integrità" in point
    assert "programmi" in point


def test_the_confidentiality_requirement_is_a_different_point(annex):
    point = annex[f"{PART_I}(2)(e)"]
    assert point.startswith("e)")
    assert "riservatezza" in point
    assert "criptando" in point


def test_a_numbered_point_contains_its_lettered_points(annex):
    """Same rule the article parser follows: the paragraph holds its points."""
    assert annex[f"{PART_I}(2)(f)"] in annex[f"{PART_I}(2)"]
    assert annex[f"{PART_I}(2)"] in annex[PART_I]


def test_the_annex_heading_is_not_part_of_the_text(annex):
    assert not annex[PART_I].startswith("ALLEGATO")
    assert "REQUISITI ESSENZIALI DI CIBERSICUREZZA" not in annex[PART_I]


def test_part_two_carries_the_vulnerability_duties(annex):
    """Cited by the finding that does not exist yet; fetched all the same."""
    assert "distinta base del software" in annex[f"{PART_II}(1)"]


def test_an_annex_that_is_not_there_is_an_error_not_an_empty_string(cra):
    with pytest.raises(LawFetchError, match="Allegato IV"):
        parse_articles(cra, ("Allegato IV",))


def test_articles_still_parse_next_to_annexes(cra):
    """The dispatch must not cost the existing path anything."""
    texts = parse_articles(cra, ("6", "13", PART_I))
    assert texts["13(1)"].startswith("1. ")
    assert "allegato I, parte I" in texts["6"]
    assert texts[PART_I]


# --------------------------------------------------------------------------
# where the text comes from
# --------------------------------------------------------------------------


def test_cellar_is_tried_first(monkeypatch):
    seen = []

    def fake(url, **kwargs):
        seen.append(url)
        return "<html></html>"

    monkeypatch.setattr(law_fetcher, "fetch_html", fake)
    law_fetcher.fetch_act_html(CRA, "IT")

    assert len(seen) == 1
    assert "publications.europa.eu" in seen[0]
    assert CRA.celex in seen[0]


def test_the_web_interface_is_the_fallback(monkeypatch):
    seen = []

    def fake(url, **kwargs):
        seen.append(url)
        if "publications.europa.eu" in url:
            raise LawFetchError("Cellar answered HTTP 500")
        return "<html>fallback</html>"

    monkeypatch.setattr(law_fetcher, "fetch_html", fake)
    assert law_fetcher.fetch_act_html(CRA, "IT") == "<html>fallback</html>"

    assert len(seen) == 2
    assert "eur-lex.europa.eu" in seen[1]


def test_both_sources_failing_names_both(monkeypatch):
    """The reason CI could not cite the law has to survive into the message.

    Learned the hard way in this repository: an exception that says only
    "unreachable" costs a debugging session to turn back into a cause.
    """
    def fake(url, **kwargs):
        raise LawFetchError("HTTP 202" if "publications" in url else "HTTP 403")

    monkeypatch.setattr(law_fetcher, "fetch_html", fake)
    with pytest.raises(LawFetchError) as caught:
        law_fetcher.fetch_act_html(CRA, "IT")

    assert "202" in str(caught.value)
    assert "403" in str(caught.value)


def test_the_language_reaches_cellar_as_a_three_letter_code(monkeypatch):
    """Cellar negotiates on Accept-Language and wants "ita", not "IT"."""
    seen = {}

    def fake(url, **kwargs):
        seen.update(kwargs.get("headers") or {})
        return "<html></html>"

    monkeypatch.setattr(law_fetcher, "fetch_html", fake)
    law_fetcher.fetch_act_html(CRA, "IT")

    assert seen["Accept-Language"] == "ita"
    assert "xhtml" in seen["Accept"]


def test_normattiva_acts_do_not_go_through_cellar():
    """Cellar publishes EU law; Italian acts are not in it."""
    italian = Act("x", "urn:nir:stato:legge:2000-01-01;1", source="Normattiva")
    with pytest.raises(ValueError):
        law_fetcher.fetch_act_html(italian, "IT")
