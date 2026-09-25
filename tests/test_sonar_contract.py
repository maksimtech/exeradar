"""`sonar-project.properties` has two ways of being wrong in silence.

The project had no such file at all, so SonarCloud analysed everything it found.
Checked on 2026-09-25, that produced 71 findings on a project whose own code is
clean, and the two that broke the quality gate came from
`tests/fixtures/cra_it_excerpt.html` — a saved excerpt of the Cyber Resilience Act,
told off for having no `<!DOCTYPE>`, no `lang` attribute and no `<th>` in its
tables. It is the text of a regulation, kept so the citations can be verified
offline; it is not a web page this project ships.

Hence this file. And hence these tests, because two of its keys fail quietly:

* a wrong `sonar.projectKey` analyses somebody else's project and reports it as
  yours. Nothing errors — the numbers are simply about another repository.
* a `sonar.python.coverage.reportPaths` that does not match what the workflow
  writes makes coverage read as zero, which looks like untested code rather than
  like a path typo.

Both are the same failure mode this repository exists to avoid: an answer that
looks measured and is not.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PROPERTIES = ROOT / "sonar-project.properties"
WORKFLOW = ROOT / ".github" / "workflows" / "sonarcloud.yml"


@pytest.fixture(scope="module")
def properties() -> dict[str, str]:
    if not PROPERTIES.is_file():
        pytest.fail(f"{PROPERTIES.name} is missing: SonarCloud would analyse everything")
    settings = {}
    for line in PROPERTIES.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        settings[key.strip()] = value.strip()
    return settings


# ── the key that silently points elsewhere ──────────────────────────────────


def test_the_project_key_is_this_repository(properties):
    """Read from SonarCloud on 2026-09-25: the project is maksimtech_exeradar."""
    assert properties["sonar.projectKey"] == "maksimtech_exeradar"
    assert properties["sonar.organization"] == "maksimtech"


def test_no_version_is_declared(properties):
    """A version written here drifts from the package's own and nothing notices:
    apkradar's says 2026.09.1 while the package is at 2026.09.32. Left out, as
    patchradar does — the scanner does not need it."""
    assert "sonar.projectVersion" not in properties


# ── the path that silently reads as zero coverage ───────────────────────────


def test_the_coverage_path_is_the_one_the_workflow_writes(properties):
    """`pytest --cov --cov-report=xml:coverage.xml` in sonarcloud.yml."""
    written = re.search(r"--cov-report=xml:(\S+)", WORKFLOW.read_text(encoding="utf-8"))

    assert written, "the workflow no longer writes an XML coverage report"
    assert properties["sonar.python.coverage.reportPaths"] == written.group(1)


# ── what is source, what is test, what is neither ───────────────────────────


def test_the_sources_directory_exists(properties):
    assert (ROOT / properties["sonar.sources"]).is_dir()
    assert (ROOT / properties["sonar.tests"]).is_dir()


@pytest.mark.parametrize(
    "fixture",
    ["tests/fixtures/cra_it_excerpt.html", "tests/fixtures/python.exe"],
)
def test_the_fixtures_are_left_out_of_the_analysis(properties, fixture):
    """Legal texts from EUR-Lex and a redistributed python.exe. Neither is code
    this project wrote, and the HTML ones are what failed the quality gate."""
    patterns = (
        properties.get("sonar.exclusions", "").split(",")
        + properties.get("sonar.test.exclusions", "").split(",")
    )

    assert any(
        pattern.strip() and _matches(pattern.strip(), fixture) for pattern in patterns
    ), f"{fixture} is still analysed; patterns are {patterns}"


def _matches(pattern: str, path: str) -> bool:
    """Sonar's `**` and `*`, enough of them for these patterns."""
    regex = re.escape(pattern).replace(r"\*\*/", "(.*/)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return re.fullmatch(regex, path) is not None


def test_the_fixtures_really_are_there_to_be_excluded():
    """A guard on the test above: if the fixtures move, the patterns are stale
    and the exclusion silently protects nothing."""
    assert (ROOT / "tests" / "fixtures" / "cra_it_excerpt.html").is_file()
    assert (ROOT / "tests" / "fixtures" / "python.exe").is_file()


def test_the_projects_own_code_is_not_excluded(properties):
    """The point of the file is to remove noise, not coverage of the tool."""
    patterns = properties.get("sonar.exclusions", "").split(",")

    for module in ("exeradar/scanner.py", "exeradar/signature.py", "exeradar/law_checker.py"):
        assert not any(
            pattern.strip() and _matches(pattern.strip(), module) for pattern in patterns
        ), f"{module} would not be analysed"


def test_the_workflows_are_still_analysed(properties):
    """Deliberately kept: the GitHub Actions findings — a missing
    `--only-binary :all:`, actions not pinned by SHA — are about this repository's
    own supply chain. They are worth a decision in SonarCloud, not an exclusion
    here that makes them disappear."""
    patterns = properties.get("sonar.exclusions", "").split(",")

    assert not any(
        pattern.strip() and _matches(pattern.strip(), ".github/workflows/quality.yml")
        for pattern in patterns
    )
