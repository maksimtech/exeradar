"""The local cache of law texts: what it reads back, and what a merge reports.

The cache is copied, not shared, across the Radar family (CLAUDE.md); these
cases are mailradar's, ported with the fixes of its PR #103.
"""

from __future__ import annotations

from datetime import UTC, datetime

from exeradar.law_cache import LawCache
from exeradar.law_checker import check
from exeradar.law_fetcher import GDPR, Provision
from exeradar.models import ExeResult, Signature, SignatureState, Strings

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
NESTED = "[" * 200_000 + "]" * 200_000


def _unsigned() -> ExeResult:
    return ExeResult(
        path="C:/tmp/sample.exe", size=1000, sha256="aa", format="PE",
        strings=Strings(ips=[]),
        signature=Signature(state=SignatureState.UNSIGNED, verified=False, detail="no signature"),
    )


def test_a_corrupt_file_is_an_empty_cache(tmp_path):
    path = tmp_path / "law_cache.json"
    path.write_text("{not json", encoding="utf-8")
    assert LawCache(path).load() == {}


def test_a_deeply_nested_file_is_an_empty_cache(tmp_path):
    """json.loads raises RecursionError here, which is neither OSError nor
    ValueError: the corrupt cache took the whole law check down."""
    path = tmp_path / "law_cache.json"
    path.write_text(NESTED, encoding="utf-8")
    assert LawCache(path).load() == {}


def test_a_deeply_nested_cache_does_not_end_the_check(tmp_path):
    """`analyze` printed "provisions not cited: maximum recursion depth
    exceeded" and no provision at all, instead of citing without a hash."""
    path = tmp_path / "law_cache.json"
    path.write_text('{"entries": ' + NESTED + "}", encoding="utf-8")

    outcome = check(_unsigned(), cache=LawCache(path), now=NOW, offline=True)

    assert outcome.citations
    assert {c.sha256 for c in outcome.citations} == {None}
    assert {s.source for s in outcome.acts} == {"unavailable"}


def test_an_entry_whose_hash_does_not_match_its_text_is_dropped(tmp_path):
    cache = LawCache(tmp_path / "law_cache.json")
    good = Provision.from_text("32(1)", "testo", "2026-01-01T00:00:00Z", GDPR.celex)
    cache.update({good.key: good}, checked_at="2026-01-01T00:00:00Z")
    text = cache.path.read_text(encoding="utf-8").replace('"testo"', '"altro testo"')
    cache.path.write_text(text, encoding="utf-8")

    assert cache.load() == {}
