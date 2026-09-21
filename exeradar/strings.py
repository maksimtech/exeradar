"""Readable strings, then classification into URL, IP, host and path.

ASCII and UTF-16LE: a Windows binary keeps most of its text in the latter.
"""

from __future__ import annotations

from exeradar.models import Strings


def extract(data: bytes, min_length: int = 6) -> Strings:
    raise NotImplementedError
