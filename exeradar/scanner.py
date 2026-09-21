"""Orchestration: a path in, an ExeResult out.

Picks a parser by magic number so that ELF and Mach-O are an addition rather
than a rewrite.
"""

from __future__ import annotations

from pathlib import Path

from exeradar.models import ExeResult


def scan(path: str | Path) -> ExeResult:
    raise NotImplementedError
