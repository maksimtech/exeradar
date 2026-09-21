"""Code signing, by the three paths of ARCHITECTURE.md section 3.

A — embedded signature, read by LIEF, works everywhere.
B — catalog signature, Windows only, because the signature is in a .cat file
    under CatRoot and no PE parser can see it.
C — neither, which is a finding only when B was actually able to run.

The rule this module exists to enforce: on Linux and macOS the absence of an
embedded signature is UNKNOWN, never UNSIGNED.
"""

from __future__ import annotations

from pathlib import Path

from exeradar.models import Signature


def inspect(path: Path) -> Signature:
    raise NotImplementedError


def catalog_available() -> bool:
    """Whether path B can run here at all."""
    raise NotImplementedError
