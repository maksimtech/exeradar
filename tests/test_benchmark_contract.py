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

from exeradar import law_checker, scanner
from tests.benchmarks import test_bench_law

ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS = ROOT / "tests" / "benchmarks"
WORKFLOWS = ROOT / ".github" / "workflows"
CODSPEED = WORKFLOWS / "codspeed.yml"
TESTS_WORKFLOW = WORKFLOWS / "tests.yml"
PYPROJECT = ROOT / "pyproject.toml"
FIXTURE = ROOT / "tests" / "fixtures" / "python.exe"


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


def test_the_mutation_run_skips_them_as_well():
    """`mutation.yml` is the other workflow that runs the suite, and it was the
    one nobody had written down: on 2026-10-03 the Saturday run died in the stats
    phase on the missing fixture, before a single mutant was tried.

    mutmut takes no pytest arguments on its command line, so the exclusion lives
    in its configuration rather than in the workflow file — which is why asserting
    on the workflow, as the test above does, could not have caught this.
    """
    config = PYPROJECT.read_text(encoding="utf-8")

    assert "--ignore=tests/benchmarks" in config.split("[tool.mutmut]", 1)[1]


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


def test_the_law_benchmark_exercises_every_rule():
    """`test_findings_for` has to put every rule of `findings_of` to work.

    The fixture alone does not: python.exe is signed, verified, countersigned
    and carries no address, so `findings_for` on it returns an empty list in
    about 6 µs — thirty Python calls, almost all of it `_expiry`. On CodSpeed
    the measured window is then mostly the harness, and on 2026-10-08 the same
    code, the same pytest-codspeed 5.0.3, the same runner image and the same
    CPython 3.12.15 measured 219.6 µs on main and 339 µs on PR #5, which touched
    only `.github/workflows/release.yml` — a −35% regression on nothing.

    The benchmark now walks one derived ExeResult per rule, and this test is
    what keeps that true: a rule added to `findings_of` without a case here
    fails this before it fails to be measured. `known_vulnerabilities` is in
    SEVERITY and in the map but is produced by nothing yet — FUTURE_FINDINGS is
    where that is declared, and `test_law_checker.py` checks that it is the
    only one — so it is not asked of the benchmark.
    """
    scanned = scanner.scan(FIXTURE)
    assert scanned.error is None, scanned.error

    emitted = {
        finding.id
        for case in test_bench_law.cases(scanned).values()
        for finding in law_checker.findings_for(case, now=test_bench_law.NOW)
    }
    produced = set(law_checker.SEVERITY) - law_checker.FUTURE_FINDINGS

    assert emitted == produced, (
        f"the benchmark exercises {sorted(emitted) or 'no rule'}; "
        f"findings_of can produce {sorted(produced)}"
    )
