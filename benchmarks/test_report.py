"""Benchmarks for rendering.

Cheap per file and not cheap over a directory: `exeradar scan` on a folder
renders one table per binary, and the console renderer is the only one of the
three that has to lay text out rather than serialise it.

The console is constructed explicitly — width, no colour, `legacy_windows` off.
Left to itself, rich reads the terminal it happens to be attached to, and this
project has already been bitten by that: `Console().legacy_windows` is True on
this machine, which substitutes the box characters. A benchmark that renders a
different table on the developer's machine than in CI is comparing two things.
"""

from __future__ import annotations

import io

from rich.console import Console

from exeradar import report

# A directory of binaries, the case where rendering stops being free.
BATCH = 50


def fixed_console() -> Console:
    return Console(file=io.StringIO(), width=100, legacy_windows=False, no_color=True)


def test_to_json(benchmark, scanned):
    rendered = benchmark(lambda: report.to_json(scanned))

    assert rendered.startswith("{")
    assert "sha256" in rendered


def test_to_markdown(benchmark, scanned):
    rendered = benchmark(lambda: report.to_markdown(scanned))

    assert rendered.strip(), "an empty report would measure nothing"
    assert "#" in rendered


def test_to_console(benchmark, scanned):
    console = fixed_console()

    benchmark(lambda: report.to_console(scanned, console))

    assert console.file.getvalue().strip(), "nothing reached the console"


def test_to_console_many(benchmark, scanned):
    """The directory case: one table per binary, fifty of them."""
    results = [scanned] * BATCH
    console = fixed_console()

    benchmark(lambda: report.to_console_many(results, console))

    assert console.file.getvalue().count(scanned.sha256[:8]) >= 1


def test_to_json_many(benchmark, scanned):
    results = [scanned] * BATCH

    rendered = benchmark(lambda: report.to_json_many(results))

    assert rendered.count('"sha256"') == BATCH
