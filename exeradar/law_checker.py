"""Findings -> the provisions that apply to them.

Same machinery as the rest of the Radar family; only the mapping is new. What
to cite is still open: the Cyber Resilience Act, regulation (EU) 2024/2847, is
the closest fit and has to be checked against EUR-Lex through law_fetcher
before anything is claimed. See ARCHITECTURE.md section 4.
"""

from __future__ import annotations

from exeradar.models import ExeResult

FINDING_ARTICLES: dict[str, list[tuple[str, str]]] = {}


def check(result: ExeResult):
    raise NotImplementedError
