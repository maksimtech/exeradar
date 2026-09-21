"""Rendering: console, JSON, Markdown.

Implemented as a module rather than left inside the CLI, and --output infers
the format from the extension instead of being declared and ignored.
"""

from __future__ import annotations

from exeradar.models import ExeResult


def to_console(result: ExeResult) -> None:
    raise NotImplementedError


def to_json(result: ExeResult) -> str:
    raise NotImplementedError


def to_markdown(result: ExeResult) -> str:
    raise NotImplementedError
