"""How CHANGELOG.md is laid out, which the release notes inherit.

The release workflow publishes a version's section as it stands, so a section
that repeats a heading publishes it twice. On 2026-11-16 `## [2026.41]` was
found carrying `### Added` three times: entries added in three sittings, each
under a heading of its own, and the reader of the release had to find all three.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"


def sections() -> dict[str, list[str]]:
    """Each `## ` section with the `### ` headings under it, in order."""
    found: dict[str, list[str]] = {}
    current = None
    for line in CHANGELOG.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            found[current] = []
        elif line.startswith("### ") and current is not None:
            found[current].append(line[4:].strip())
    return found


def test_no_version_appears_twice():
    versions = [re.match(r"\[([^\]]+)\]", name).group(1) for name in sections() if name.startswith("[")]
    repeated = [version for version, count in Counter(versions).items() if count > 1]
    assert not repeated, f"versions with more than one section: {repeated}"


def test_no_section_repeats_a_heading():
    repeated = {
        name: sorted(heading for heading, count in Counter(headings).items() if count > 1)
        for name, headings in sections().items()
    }
    repeated = {name: headings for name, headings in repeated.items() if headings}
    assert not repeated, f"headings that appear more than once in a section: {repeated}"
