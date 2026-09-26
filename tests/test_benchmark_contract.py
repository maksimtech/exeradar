"""Where the benchmarks live, and what a benchmark has to do to count.

Three things go wrong with a benchmark suite and all three have happened here.

The first is that it drags a dependency into the test suite. mailradar's
benchmarks sat in `tests/benchmarks` with pytest-codspeed declared nowhere, so
`pytest tests/` collected them and the run died on a missing plugin. The fix
the other Radar settled on is not to move the directory but to skip it:
`--ignore=tests/benchmarks` in the workflow that runs the suite, and the runner
installed by codspeed.yml alone. A suite that checks four Python versions for
correctness has no business depending on a benchmark tool.

This repository briefly kept them at the top level instead, which avoided the
same trap by a different route and left it the odd one of five. It came back
on 2026-09-26, when a CodSpeed pull request proposing `tests/benchmarks` turned
out to be the house convention and this the deviation.

The second is that the benchmarks stop being read. Under tests/ they are
covered by `ruff check exeradar tests` like everything else, which is the other
reason the convention is worth following.

The third is subtler and is the one this project keeps meeting: a benchmark
that measures without checking. `benchmark(scan, path)` on a path that stopped
existing still produces a number, a green run and a chart — of an exception
being raised. Six of the fourteen benchmarks in that pull request were bare
calls of exactly that shape. Every benchmark here asserts on its result, and
the last test refuses one that does not.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS = ROOT / "tests" / "benchmarks"
WORKFLOWS = ROOT / ".github" / "workflows"
CODSPEED = WORKFLOWS / "codspeed.yml"
TESTS_WORKFLOW = WORKFLOWS / "tests.yml"
PYPROJECT = ROOT / "pyproject.toml"


def benchmark_files() -> list[Path]:
    return sorted(BENCHMARKS.glob("test_*.py"))


def test_there_are_benchmarks_to_run():
    """codspeed.yml is only worth having if it measures something. An empty
    directory would give it a green run with nothing behind it."""
    assert BENCHMARKS.is_dir()
    assert benchmark_files(), "tests/benchmarks holds no test_*.py"


def test_they_are_where_the_other_radar_keep_theirs():
    """apkradar, mailradar and cookieradar all use tests/benchmarks with an
    __init__.py. Being the fourth is worth more than being right alone."""
    assert (BENCHMARKS / "__init__.py").is_file()
    assert not (ROOT / "benchmarks").exists(), (
        "two benchmark directories: one of them is not being run"
    )


def test_the_suite_skips_them_rather_than_needing_their_runner():
    """The failure this arrangement exists to prevent, in the words of the
    workflow that prevents it."""
    workflow = TESTS_WORKFLOW.read_text(encoding="utf-8")

    assert "--ignore=tests/benchmarks" in workflow


def test_the_runner_is_not_a_project_dependency():
    """pytest-codspeed is installed by codspeed.yml and nowhere else, as in the
    other three. Declaring it would put a benchmark tool in the way of finding
    out whether the code works on Python 3.11."""
    config = PYPROJECT.read_text(encoding="utf-8")

    assert "pytest-codspeed" not in config
    assert "pytest-codspeed" in CODSPEED.read_text(encoding="utf-8")


def test_the_workflow_runs_the_directory_that_exists():
    assert "pytest tests/benchmarks --codspeed" in CODSPEED.read_text(encoding="utf-8")


def test_nothing_here_shadows_a_test_module():
    """`tests/test_strings.py` and a benchmark called the same thing are two
    modules with one name unless the package keeps them apart. The prefix is
    cheaper than relying on that."""
    for path in benchmark_files():
        assert path.name.startswith("test_bench_"), (
            f"{path.name} does not carry the bench prefix the other Radar use"
        )


@pytest.mark.parametrize("path", benchmark_files(), ids=lambda p: p.name)
def test_every_benchmark_checks_its_result(path):
    """A `benchmark(...)` call with no assertion after it reports the speed of
    whatever happened, including nothing useful."""
    tree = ast.parse(path.read_text(encoding="utf-8"))

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
            continue
        calls_benchmark = any(
            isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Name)
            and inner.func.id == "benchmark"
            for inner in ast.walk(node)
        )
        if not calls_benchmark:
            continue
        assert any(isinstance(stmt, ast.Assert) for stmt in ast.walk(node)), (
            f"{path.name}::{node.name} measures something it never checks"
        )


def test_no_benchmark_reads_the_clock():
    """A measurement that depends on today drifts without anyone touching it:
    a certificate expires between two runs and the finding count moves
    underneath the number."""
    for path in benchmark_files():
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"datetime\.now\(|time\.time\(", text), (
            f"{path.name} reads the clock; pin the moment instead"
        )
