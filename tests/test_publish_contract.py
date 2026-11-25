"""What publishing to PyPI is allowed to do, and in what order.

publish.yml uploads the package, and a version cannot be taken back off PyPI:
whatever reaches it under a number is that number for good. Two things stood
between a careless push and a bad release, and neither was there — the workflow
waited for no test, and a dispatch from a branch skipped the check that the tag
and the version agree.

And the job PyPI trusts installs and runs nothing. A job holding
`id-token: write` can mint the OIDC token PyPI accepts from this repository.
Until 2026-11-25 that job also installed the newest build tools of that minute,
built in an isolation that fetched an unpinned hatchling again, and after the
upload installed the release with all its runtime dependencies. On 2026-11-18
two releases of `agent-framework`, published from that project's own account,
carried a `.pth` file that runs at every Python start-up and mints OIDC tokens;
a package like that, anywhere in what the job installed, could have published
a release of exeradar under its name (maksimtech/apkradar#135, #65 here). So,
as PyPA documents for trusted publishing and as releaseradar has done since
maksimtech/releaseradar#72:

- `test` runs the suite, without the token;
- `build` checks the tag against the version, installs the build tools from a
  hash-pinned file and builds without isolation; no token;
- `publish` downloads what `build` made and uploads it: no checkout, no Python,
  no `run:` step, and the only job with `id-token: write`;
- `verify` installs the release from PyPI, as before, without the token.

`publish` and `verify` run on a `v*` tag only. Dispatched from a branch, the
workflow tests and builds and stops: that is the dry run.

Static checks on the workflow text, plus the one step that can be run as it is:
the tag check is plain bash, so it is run here with the environment GitHub would
give it.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
PUBLISH = ROOT / ".github" / "workflows" / "publish.yml"
BUILD_REQUIREMENTS = ROOT / ".github" / "requirements-build.txt"
BUILD_INPUT = ROOT / ".github" / "requirements-build.in"

# What a job holding the token may use, and nothing else.
TOKEN_ACTIONS = ("actions/download-artifact@", "pypa/gh-action-pypi-publish@")
ON_A_TAG = "startsWith(github.ref, 'refs/tags/v')"


def workflow() -> dict:
    return yaml.safe_load(PUBLISH.read_text(encoding="utf-8"))


def jobs() -> dict:
    return workflow()["jobs"]


def holds_the_token(job: dict) -> bool:
    return (job.get("permissions") or {}).get("id-token") == "write"


def runs(job: dict) -> list[str]:
    return [s["run"] for s in job.get("steps", []) if "run" in s]


def needs(job: dict) -> list[str]:
    value = job.get("needs") or []
    return [value] if isinstance(value, str) else list(value)


# ─── order ──────────────────────────────────────────────────────────────────

def test_test_then_build_then_publish_then_verify():
    found = jobs()
    assert set(found) == {"test", "build", "publish", "verify"}
    assert needs(found["build"]) == ["test"]
    assert needs(found["publish"]) == ["build"]
    assert "publish" in needs(found["verify"])


def test_nothing_is_published_before_the_suite_has_passed():
    """A tag pushed by hand never went through release.sh, and publish.yml
    depended on no test job: it published whatever the tag pointed at. The test
    job must not hold the publishing token either."""
    found = jobs()
    commands = " ".join(runs(found["test"]))
    assert "pytest" in commands
    assert not holds_the_token(found["test"])


# ─── the token ──────────────────────────────────────────────────────────────

def test_the_workflow_grants_nothing_and_every_job_asks_for_what_it_needs():
    """A job without its own `permissions` inherits the workflow's, and without
    those the repository's default token, which can be broad."""
    assert workflow().get("permissions") == {}
    for name, job in jobs().items():
        assert "permissions" in job, f"{name} inherits its permissions"


def test_only_publish_holds_the_token():
    assert [name for name, job in jobs().items() if holds_the_token(job)] == ["publish"]
    assert jobs()["publish"]["permissions"] == {"id-token": "write"}


def test_the_job_holding_the_token_runs_nothing_and_uses_only_the_two_actions():
    for name, job in jobs().items():
        if not holds_the_token(job):
            continue
        assert not runs(job), f"{name} runs a command next to the token"
        uses = [s.get("uses", "") for s in job["steps"]]
        assert uses and all(u.startswith(TOKEN_ACTIONS) for u in uses), f"{name}: {uses}"


def test_no_job_that_runs_pip_or_python_holds_the_token():
    for name, job in jobs().items():
        if any(re.search(r"\b(?:pip3?|python3?|pytest)\b", run) for run in runs(job)):
            assert not holds_the_token(job), name


def test_publishing_is_on_the_pypi_environment():
    """PyPI's trusted publisher names the environment too, so a token minted by a
    job outside it is refused."""
    environment = jobs()["publish"]["environment"]
    assert environment == "pypi" or environment["name"] == "pypi"


def test_no_secret_reaches_the_workflow():
    assert "secrets." not in PUBLISH.read_text(encoding="utf-8")


# ─── a tag publishes, a branch is a dry run ─────────────────────────────────

@pytest.mark.parametrize("name", ["publish", "verify"])
def test_only_a_tag_publishes(name):
    assert ON_A_TAG in str(jobs()[name].get("if", "")), f"{name} would run on a branch"


@pytest.mark.parametrize("name", ["test", "build"])
def test_a_dispatch_from_a_branch_tests_and_builds(name):
    assert "if" not in jobs()[name], "the test and the build are what the dry run proves"


def _tag_check() -> str:
    return next(s["run"] for s in jobs()["build"]["steps"] if "GITHUB_REF_TYPE" in s.get("run", ""))


def _run_tag_check(ref_type: str, ref_name: str, tmp_path: Path) -> subprocess.CompletedProcess:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("needs bash")
    output = tmp_path / "github_output"
    env = {**os.environ, "GITHUB_REF_TYPE": ref_type, "GITHUB_REF_NAME": ref_name, "GITHUB_OUTPUT": str(output)}
    return subprocess.run([bash, "-c", _tag_check()], cwd=ROOT, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def _version() -> str:
    text = (ROOT / "exeradar" / "__init__.py").read_text(encoding="utf-8")
    return re.search(r"__version__\s*=\s*[\"']([^\"']+)", text).group(1)


def test_a_tag_that_disagrees_with_the_version_stops_the_build(tmp_path):
    """hatchling reads the version from exeradar/__init__.py, so a tag that
    disagrees with it would publish under the wrong number. The step is run here
    with bash, without GitHub."""
    outcome = _run_tag_check("tag", "v0.0.1", tmp_path)
    assert outcome.returncode != 0, outcome.stdout + outcome.stderr


def test_the_tag_of_the_version_builds(tmp_path):
    outcome = _run_tag_check("tag", f"v{_version()}", tmp_path)
    assert outcome.returncode == 0, outcome.stdout + outcome.stderr


def test_a_branch_builds_and_says_it_is_a_dry_run(tmp_path):
    """Before the split a dispatch from a branch failed here, and that was what
    kept a branch off PyPI. The `if` on publish keeps it off now; the build runs
    so the dispatch proves something."""
    outcome = _run_tag_check("branch", "main", tmp_path)
    assert outcome.returncode == 0, outcome.stdout + outcome.stderr
    assert "dry run" in outcome.stdout


# ─── the build ──────────────────────────────────────────────────────────────

def test_the_build_installs_from_hashes_and_builds_without_isolation():
    build = "\n".join(runs(jobs()["build"]))
    assert re.search(r"pip install --require-hashes -r \.github/requirements-build\.txt", build), build
    assert re.search(r"\bpython -m build --no-isolation\b", build), build
    assert "--upgrade" not in build, "the newest of the minute is what the hashes replace"


def test_publish_uploads_exactly_what_build_made():
    upload = [s for s in jobs()["build"]["steps"] if s.get("uses", "").startswith("actions/upload-artifact@")]
    download = [s for s in jobs()["publish"]["steps"] if s.get("uses", "").startswith("actions/download-artifact@")]
    assert len(upload) == len(download) == 1
    assert upload[0]["with"]["name"] == download[0]["with"]["name"]
    assert upload[0]["with"]["path"].rstrip("/") == download[0]["with"]["path"].rstrip("/") == "dist"


def pinned() -> dict[str, str]:
    text = BUILD_REQUIREMENTS.read_text(encoding="utf-8")
    return dict(re.findall(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)", text, re.MULTILINE))


def test_every_build_tool_is_pinned_with_its_hashes():
    text = BUILD_REQUIREMENTS.read_text(encoding="utf-8")
    blocks = re.split(r"\n(?=[A-Za-z0-9])", text.split("\n", 2)[2])
    requirements = [b for b in blocks if re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*==", b)]
    assert len(requirements) == len(pinned()) >= 2
    for block in requirements:
        assert "--hash=sha256:" in block, block.splitlines()[0]


def test_the_backend_pyproject_names_is_one_of_them():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    backend = re.search(r'requires\s*=\s*\["([A-Za-z0-9_.-]+)', pyproject).group(1)
    assert backend in pinned()
    assert "build" in pinned()
    assert set(BUILD_INPUT.read_text(encoding="utf-8").split()) == {"build", backend}


def header_arguments() -> list[str]:
    header = BUILD_REQUIREMENTS.read_text(encoding="utf-8").splitlines()[1]
    command = header.removeprefix("#").split()
    assert command[:3] == ["uv", "pip", "compile"], header
    return command[3:]


def test_the_file_is_compiled_for_the_python_the_build_runs_and_for_any_system():
    """`--universal` keeps the file the same wherever it is compiled: colorama,
    which build wants on Windows only, is in it under `os_name == 'nt'`, and pip
    on the Linux runner skips it."""
    arguments = header_arguments()
    setup = next(s for s in jobs()["build"]["steps"] if s.get("uses", "").startswith("actions/setup-python@"))
    assert "--generate-hashes" in arguments
    assert "--universal" in arguments
    assert f"--python-version={setup['with']['python-version']}" in arguments
    assert "--output-file=.github/requirements-build.txt" in arguments
    assert ".github/requirements-build.in" in arguments


# What Renovate's pip-compile manager accepts in a `uv pip compile` header
# (renovatebot/renovate, lib/modules/manager/pip-compile/common.ts). Anything
# else, or an option whose argument follows a space instead of `=`, and it
# skips the file with "pip-compile error": releaseradar's first header had
# `--python-platform linux` and `--python-version 3.12`, and on 2026-11-25 its
# Dependency Dashboard (maksimtech/releaseradar#71) reported exactly that.
RENOVATE_UV_FLAGS = {"--no-strip-extras", "--universal", "-v", "--generate-hashes", "--emit-index-url", "--all-extras"}
RENOVATE_UV_WITH_ARGUMENT = {
    "--constraints", "--constraint", "--python-version", "--no-emit-package", "--prerelease", "--format",
    "--resolution", "--fork-strategy", "--exclude-newer", "--exclude-newer-package", "--group", "--override",
    "--overrides", "--output-file", "--extra", "--extra-index-url", "--index-url",
}


def test_renovate_can_read_the_header():
    for argument in header_arguments():
        if not argument.startswith("-"):
            continue
        option, equals, _ = argument.partition("=")
        if option in RENOVATE_UV_WITH_ARGUMENT:
            assert equals, f"{option} needs '=' before its argument for Renovate"
        else:
            assert option in RENOVATE_UV_FLAGS and not equals, f"Renovate does not accept {argument}"
