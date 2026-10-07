"""What publishing to PyPI is allowed to do, and in what order.

publish.yml uploads the package, and a version cannot be taken back off PyPI:
whatever reaches it under a number is that number for good. Two things stood
between a careless push and a bad release, and neither was there — the workflow
waited for no test, and a dispatch from a branch skipped the check that the tag
and the version agree.

Static checks on the workflow text, plus the one step that can be run as it is:
the tag check is plain bash, so it is run here with the environment GitHub would
give it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLISH = ROOT / ".github" / "workflows" / "publish.yml"


def workflow() -> dict:
    import yaml

    return yaml.safe_load(PUBLISH.read_text(encoding="utf-8"))


def test_nothing_is_published_before_the_suite_has_passed():
    """A tag pushed by hand never went through release.sh, and publish.yml
    depended on no test job: it published whatever the tag pointed at. The test
    job must not hold the publishing token either."""
    jobs = workflow()["jobs"]
    needed = jobs["build-and-publish"].get("needs") or []
    needed = [needed] if isinstance(needed, str) else needed

    assert needed, "build-and-publish waits for no job"
    commands = " ".join(
        str(step.get("run", "")) for name in needed for step in jobs[name].get("steps", [])
    )
    assert "pytest" in commands
    assert all("id-token" not in (jobs[name].get("permissions") or {}) for name in needed)


def test_a_ref_that_is_not_a_tag_does_not_publish():
    """The tag and version were compared only when GITHUB_REF_TYPE was `tag`, so
    a workflow_dispatch from a branch skipped the comparison and published that
    branch. The step is run here with bash, without GitHub."""
    steps = workflow()["jobs"]["build-and-publish"]["steps"]
    check = next(step["run"] for step in steps if "GITHUB_REF_TYPE" in str(step.get("run", "")))
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("needs bash")
    env = {**os.environ, "GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "main"}

    outcome = subprocess.run([bash, "-c", check], cwd=ROOT, env=env, capture_output=True, text=True,
                             encoding="utf-8", errors="replace")

    assert outcome.returncode != 0, outcome.stdout + outcome.stderr
