"""PE: headers, sections with entropy, import table.

Entropy is kept even though it was not on the v1 list: a few lines, and the
most informative signal per unit of effort for spotting packed binaries.
"""

from __future__ import annotations

from pathlib import Path

from exeradar.models import ExeResult


def parse(path: Path, result: ExeResult) -> ExeResult:
    raise NotImplementedError
