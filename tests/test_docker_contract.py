"""What publishing the image is allowed to do, and in what order.

docker.yml pushes maksimtech/exeradar:latest to Docker Hub. Everything about
that is one-way — a bad :latest is what everyone pulling the image gets — so the
parts that are easy to get quietly wrong are pinned here rather than discovered
by whoever pulls it.

These are static checks on the workflow text: they need no Docker daemon, which
is the point, because the machine this was written on does not have one.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PUBLISH = WORKFLOWS / "docker.yml"
BUILD_CHECK = WORKFLOWS / "docker-build-check.yml"
DOCKERFILE = ROOT / "Dockerfile"
SMOKE = ROOT / "tests" / "docker" / "smoke.py"

IMAGE = "maksimtech/exeradar"


def published() -> str:
    return PUBLISH.read_text(encoding="utf-8")


def test_the_image_is_published_under_both_tags():
    """`:latest` alone leaves no way to pull a known version; a version alone
    leaves `docker pull maksimtech/exeradar` broken."""
    workflow = published()

    assert f"{IMAGE}:latest" in workflow
    assert f"{IMAGE}:${{{{ steps.version.outputs.VERSION }}}}" in workflow


def test_the_smoke_test_runs_before_anything_is_pushed():
    """Otherwise the verification is an epitaph. The image is built twice on
    purpose — once loaded locally to be run, once pushed — and the run has to
    come first."""
    workflow = published()

    smoke_at = workflow.index("tests/docker/smoke.py")
    push_at = workflow.index("push: true")

    assert smoke_at < push_at, "the image is pushed before the smoke test runs"


def test_the_published_image_is_built_from_the_tag_not_from_pypi():
    """The other four Radar install themselves from PyPI inside the image, so
    their docker.yml has to poll until the release propagates — patchradar's
    2026.9.4 failed on a fixed `sleep 60` that raced with its own publish.

    This Dockerfile installs the checkout, so there is no propagation to wait
    for and no version to agree on with PyPI. If that ever changes, this test
    fails and the wait has to come back with it.
    """
    assert "pip install --no-cache-dir --root-user-action=ignore /app/src" in (
        DOCKERFILE.read_text(encoding="utf-8")
    )
    assert "wait_for_pypi" not in published()
    # Nothing to parameterise: the other four pass a source and a version in,
    # and a build-arg here would mean the image had learned to install itself
    # from somewhere the tag does not control.
    assert "build-args" not in published()


def test_the_tag_and_the_code_have_to_agree():
    """Built from the checkout, the image's version comes from
    exeradar/__init__.py while its Docker tag comes from the git tag. Nothing
    makes those two match, so v2026.9.9 could ship 2026.9.8's code under it and
    only a pull would tell. The smoke test is given the tag and compares."""
    workflow = published()

    assert "EXPECTED_VERSION" in workflow
    assert "EXPECTED_VERSION" in SMOKE.read_text(encoding="utf-8")


def test_the_build_check_still_pushes_nothing():
    """It is the only way to try a Dockerfile change without publishing one,
    and it stops being that the moment it grows a push."""
    workflow = BUILD_CHECK.read_text(encoding="utf-8")

    assert "push: false" in workflow
    assert "docker/login-action" not in workflow, (
        "a build check has no business holding Docker Hub credentials"
    )
