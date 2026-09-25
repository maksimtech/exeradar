"""Where the benchmarks live, and what a benchmark has to do to count.

Two things go wrong with a benchmark suite, and both have happened in these
repositories.

The first is that it drags a dependency into the test suite. mailradar's
benchmarks sat in `tests/benchmarks`, so `pytest tests/` collected them and the
run died on a missing pytest-codspeed that nothing declared. Here they live in a
top-level `benchmarks/`, outside `testpaths`, so the ordinary suite cannot reach
them by accident.

The second is subtler and is the one this project keeps running into: a
benchmark that measures without checking. `benchmark(lambda: scan(path))` on a
path that stopped existing still produces a number, a green run and a chart —
of an exception being raised. So every benchmark here asserts on its result, and
this test refuses a file that does not.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS = ROOT / "benchmarks"
WORKFLOW = ROOT / ".github" / "workflows" / "codspeed.yml"
PYPROJECT = ROOT / "pyproject.toml"


def benchmark_files() -> list[Path]:
    return sorted(p for p in BENCHMARKS.glob("test_*.py"))


def test_there_are_benchmarks_to_run():
    """codspeed.yml is only worth having if it measures something. An empty
    directory would give it a green run with nothing behind it."""
    assert BENCHMARKS.is_dir()
    assert benchmark_files(), "benchmarks/ holds no test_*.py"


def test_the_ordinary_suite_cannot_collect_them():
    """pytest-codspeed is not in the dev group and must not need to be: the
    suite runs on four Python versions and a benchmark runner is not part of
    checking that the code is correct."""
    config = PYPROJECT.read_text(encoding="utf-8")

    assert 'testpaths = ["tests"]' in config
    assert not (ROOT / "tests" / "benchmarks").exists(), (
        "benchmarks under tests/ are collected by `pytest tests/` — mailradar's CI "
        "died of exactly this"
    )


def test_the_benchmarks_are_linted():
    """Keeping them out of `testpaths` costs them the test suite's attention.
    Lint is what is left, so quality.yml has to be pointed at them — otherwise
    the one directory pytest never opens is also the one ruff never reads."""
    quality = (ROOT / ".github" / "workflows" / "quality.yml").read_text(encoding="utf-8")

    assert "ruff check exeradar tests benchmarks" in quality


def test_the_workflow_runs_the_directory_that_exists():
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "pytest benchmarks/ --codspeed" in workflow
    assert "pytest-codspeed" in workflow, "the runner has to be installed somewhere"


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
