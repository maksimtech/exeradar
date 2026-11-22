"""The coverage upload, and its three silent failures.

Added on 2026-09-25, when only apkradar was sending coverage anywhere. The three
ways this arrangement breaks without reddening anything:

* no XML is produced, and the upload step sends a file that is not there;
* an XML is produced at one path and another is uploaded;
* the step is guarded to a Python version the matrix does not contain, so it
  never runs.

`fail_ci_if_error: false` is deliberate — a failed upload loses a metric and does
not invalidate a suite that just passed — and it is exactly what makes all three
invisible. Hence these.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEST_WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"


@pytest.fixture(scope="module")
def workflow() -> str:
    return TEST_WORKFLOW.read_text(encoding="utf-8")


def test_the_suite_writes_a_coverage_report(workflow):
    assert "--cov-report=xml" in workflow, "no XML is produced, so nothing can be uploaded"


def test_the_file_uploaded_is_the_file_written(workflow):
    """A path typo here reads as zero coverage, not as a broken upload."""
    written = re.search(r"--cov-report=xml(?::(\S+))?", workflow)
    assert written, "no XML report is written"
    produced = written.group(1) or "coverage.xml"

    uploaded = re.search(r"^\s*files?:\s*(\S+)", workflow, re.MULTILINE)
    assert uploaded, "the upload step names no file"
    assert uploaded.group(1) == produced


def test_the_upload_runs_once_on_a_version_the_matrix_has(workflow):
    import yaml

    parsed = yaml.safe_load(workflow)
    versions = {
        str(version)
        for job in parsed["jobs"].values()
        for version in (job.get("strategy", {}).get("matrix", {}).get("python-version") or [])
    }

    guard = re.search(r"matrix\.python-version\s*==\s*'([^']+)'", workflow)
    assert guard, "the upload is not guarded to a single matrix entry"
    assert guard.group(1) in versions, (
        f"the upload is pinned to Python {guard.group(1)}, absent from {sorted(versions)}"
    )


def test_the_upload_proves_which_repository_it_comes_from(workflow):
    """Codecov wants the upload authenticated even for a public repository; without
    it the upload is rejected, and quietly.

    It was a `CODECOV_TOKEN` secret until 2026-11-22, and Codecov files an upload
    under the project the token belongs to, not under the repository that sends it.
    This repository's token was right, but it had been copied into three other
    Radars, whose reports landed in this project for at least a month. With OIDC,
    GitHub itself tells Codecov which repository the job runs in, so no report can
    land in the wrong project; there is no secret to get wrong. The job needs
    `id-token: write` for that, and a token in the step would only be ignored next
    to `use_oidc` and mislead whoever reads it."""
    import yaml

    jobs = yaml.safe_load(workflow)["jobs"]
    uploads = [(name, job, step) for name, job in jobs.items() for step in job.get("steps", [])
               if str(step.get("uses", "")).startswith("codecov/codecov-action@")]
    assert uploads, "nothing uploads coverage"
    for name, job, step in uploads:
        options = step.get("with") or {}
        assert options.get("use_oidc") is True, f"{name}: the upload does not use OIDC"
        assert "token" not in options, f"{name}: a token next to use_oidc is ignored"
        assert (job.get("permissions") or {}).get("id-token") == "write", (
            f"{name}: without id-token: write the job cannot ask GitHub for the OIDC token")
    assert "secrets.CODECOV_TOKEN" not in workflow, "the secret is still read somewhere"


def test_the_coverage_is_measured_on_this_package(workflow):
    assert "--cov=exeradar" in workflow


# The matrix the guard above points into. Added on 2026-10-08, the day before
# Python 3.15.0 final (PEP 790): the stable rows are the versions the package
# claims to support, and the next one runs ahead of them as a row that may
# fail without reddening the suite. Both halves drift silently otherwise — a
# classifier nobody tests, or a `-dev` row that stays after the final ships.

PYPROJECT = ROOT / "pyproject.toml"


def _test_job(workflow: str) -> dict:
    import yaml

    parsed = yaml.safe_load(workflow)
    jobs = [job for job in parsed["jobs"].values() if "matrix" in job.get("strategy", {})]
    assert len(jobs) == 1, "expected exactly one job with a Python matrix"
    return jobs[0]


def _classified_versions() -> list[str]:
    import tomllib

    classifiers = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["classifiers"]
    found = [m.group(1) for c in classifiers if (m := re.fullmatch(r"Programming Language :: Python :: (3\.\d+)", c))]
    assert found, "pyproject.toml declares no `Programming Language :: Python :: 3.x`"
    return found


def test_the_stable_matrix_is_the_list_of_classifiers(workflow):
    """One list, written twice. The comment in tests.yml says "keep in sync";
    this is what does."""
    stable = [str(v) for v in _test_job(workflow)["strategy"]["matrix"]["python-version"]]
    assert stable == _classified_versions()


def test_the_next_python_runs_as_an_experimental_row(workflow):
    """The version after the last classifier, as `-dev`, and nothing else in
    `include`: the row exists to find out early, not to be a second matrix."""
    matrix = _test_job(workflow)["strategy"]["matrix"]
    major, minor = _classified_versions()[-1].split(".")
    expected = f"{major}.{int(minor) + 1}-dev"

    assert matrix.get("experimental") == [False], "the stable rows are not marked stable"
    include = matrix.get("include") or []
    assert include == [{"python-version": expected, "experimental": True}], (
        f"expected one experimental row for {expected}, found {include}"
    )


def test_an_experimental_row_cannot_redden_the_suite(workflow):
    """`continue-on-error` keyed on the matrix, not a bare `true`: the stable
    rows must still fail the summary job the branch ruleset requires."""
    job = _test_job(workflow)
    assert job.get("continue-on-error") == "${{ matrix.experimental }}"
