"""Which workflows this Radar has, and why the rest are not here.

The five Radar had drifted apart without anyone deciding it — on 2026-09-26
exeradar carried eight workflows of fifteen and cookieradar all of them, and the
absences turned out to be nobody's choice rather than anybody's judgement. The
missing ones were ported; this is what keeps them from drifting again.

The core set is required everywhere. Everything else follows from what the
repository actually contains: a Dockerfile, a Docker smoke test, benchmarks —
because a workflow that measures nothing still reports success, which is the
failure mode this project spends most of its tests on.

`KNOWN_GAPS` holds what is still missing and the reason. A gap that is not listed
fails the test; a listed one stays visible until somebody closes it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
RELEASE = WORKFLOWS / "release.yml"

# Required of every Radar, whatever it does.
CORE = {
    "quality",      # ruff and mypy
    "sonarcloud",   # quality gate and coverage
    "snyk",         # dependencies
    "codeql",       # code scanning
    "bandit",       # Python security lint
    "trivy",        # filesystem CVEs
    "licenses",     # no GPL/AGPL/LGPL creeping in
    "mutation",     # do the tests actually test
    "publish",      # PyPI
    "release",      # GitHub release from a tag
    # The gate that refuses. Every other security workflow reports: snyk
    # carries continue-on-error, CodeQL and Docker Scout upload SARIF, and
    # SonarCloud decides its gate after the job has already succeeded. This
    # one reads what they published and fails when a blocking finding has
    # nobody's name against it. It belongs here and not in CAPABILITY: the
    # policy is not optional.
    "security-posture",
}

# Required only of a Radar that has what they need.
CAPABILITY = {
    "docker-build-check": lambda: (ROOT / "Dockerfile").is_file()
    and (ROOT / "tests" / "docker" / "smoke.py").is_file(),
    "docker": lambda: (ROOT / "Dockerfile").is_file(),
    "docker-scout": lambda: (ROOT / "Dockerfile").is_file(),
    "codspeed": lambda: (ROOT / "tests" / "benchmarks").is_dir()
    or (ROOT / "benchmarks").is_dir(),
}

# Empty, and it took until 2026.40 to get there. The last entry was
# docker-scout, which was held back because maksimtech/exeradar answered 404 on
# Docker Hub: a CVE scan pointed at an image that does not exist passes every
# run by finding nothing, which is the one failure this package is written to
# tell apart from the others. The image exists now, so the workflow does too.
KNOWN_GAPS: set[str] = set()


def present(name: str) -> bool:
    return (WORKFLOWS / f"{name}.yml").is_file()


@pytest.mark.parametrize("name", sorted(CORE))
def test_the_core_workflow_is_here(name):
    assert present(name), f"{name}.yml is missing from a Radar that must have it"


def test_the_test_suite_has_a_workflow():
    """tests.yml in three of them and test.yml in two: the name is not the point,
    running the suite is."""
    assert present("tests") or present("test")


@pytest.mark.parametrize("name", sorted(CAPABILITY))
def test_a_workflow_this_repository_can_support_is_here(name):
    if not CAPABILITY[name]():
        pytest.skip(f"{name} needs something this repository does not have")
    if name in KNOWN_GAPS:
        pytest.xfail(f"{name} is a known gap — see KNOWN_GAPS")
    assert present(name)


def test_every_known_gap_is_still_a_gap():
    """A note that outlives the thing it describes is worse than no note: it
    teaches the reader that the list is stale."""
    for name in KNOWN_GAPS:
        assert not present(name), (
            f"{name}.yml exists now — remove it from KNOWN_GAPS"
        )


def test_no_workflow_is_here_without_being_accounted_for():
    """Anything not in CORE, CAPABILITY or this list is a workflow nobody
    described. Naming them is how the set stays a decision."""
    extra = {
        "docker-publish", "dependabot", "stale", "labeler",
    }
    known = CORE | set(CAPABILITY) | extra | {"tests", "test"}

    found = {path.stem for path in WORKFLOWS.glob("*.yml")}
    assert found <= known, f"undescribed workflows: {sorted(found - known)}"


# --- What release.yml publishes --------------------------------------------
#
# The CHANGELOG is written by hand and is the release notes: it says why a
# thing changed, which the list of merged pull requests GitHub generates
# never does. mailradar's release.yml has read it from the start; this one
# shipped `generate_release_notes: true` and the bare tag as a name until
# 2026.42, whose notes had to be rewritten by hand with `gh release edit`.


def release() -> dict:
    import yaml

    return yaml.safe_load(RELEASE.read_text(encoding="utf-8"))


def release_step() -> dict:
    steps = release()["jobs"]["release"]["steps"]
    return next(step for step in steps if "action-gh-release" in step.get("uses", ""))


def test_the_release_notes_are_the_changelog_section_not_the_pull_requests():
    with_ = release_step()["with"]
    scripts = " ".join(str(step.get("run", "")) for step in release()["jobs"]["release"]["steps"])

    assert "generate_release_notes" not in with_, "GitHub's list of PRs says what changed and never why"
    assert "steps.changelog.outputs" in str(with_.get("body", "")), "the body does not come from a changelog step"
    assert "CHANGELOG.md" in scripts, "no step reads CHANGELOG.md"


def test_the_release_is_named_after_the_product_not_the_bare_tag():
    name = str(release_step()["with"].get("name", ""))

    assert name.startswith("ExeRadar "), f"release name is {name!r}, not 'ExeRadar <version>'"
    assert "steps.version.outputs.VERSION" in name


def test_the_changelog_step_finds_this_version_in_the_changelog(tmp_path):
    """The step is plain bash and awk, so it is run here as GitHub would run it,
    on the CHANGELOG as it is and the version as it is. An empty section would
    silently ship the fallback `Release <version>`; that is what this catches."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("needs bash")
    version = next(
        line.split('"')[1] for line in (ROOT / "exeradar" / "__init__.py").read_text(encoding="utf-8").splitlines()
        if line.startswith("__version__")
    )
    steps = release()["jobs"]["release"]["steps"]
    step = next(step for step in steps if "CHANGELOG.md" in str(step.get("run", "")))
    # The version reaches the script through env, never pasted in as ${{ }}.
    assert "${{" not in step["run"]
    assert step["env"]["VERSION"] == "${{ steps.version.outputs.VERSION }}"
    output = tmp_path / "github_output"
    output.touch()
    env = {**os.environ, "GITHUB_OUTPUT": str(output), "VERSION": version}

    outcome = subprocess.run([bash, "-c", step["run"]], cwd=ROOT, env=env, capture_output=True, text=True,
                             encoding="utf-8", errors="replace")

    assert outcome.returncode == 0, outcome.stdout + outcome.stderr
    notes = output.read_text(encoding="utf-8").split("NOTES<<EOF\n", 1)[1].rsplit("\nEOF", 1)[0].strip()
    assert notes, f"CHANGELOG.md has an empty section for {version}"
    assert notes != f"Release {version}", f"the fallback was used: no section for {version} in CHANGELOG.md"
    assert notes.startswith("###"), notes[:80]
