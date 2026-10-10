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


def test_the_base_image_is_pulled_with_credentials():
    """Every build pulls python:*-slim from Docker Hub, and an anonymous pull
    from a GitHub runner shares one rate limit with every other anonymous pull
    from that address: on 2026-10-09 a day of builds across the five Radar ended
    in `429 Too Many Requests` on the base image. The login has to come before
    the first build, not only before the push, or the smoke-test build is the
    one that fails and the release stops there."""
    workflow = published()

    login_at = workflow.index("docker/login-action")
    first_build_at = workflow.index("docker/build-push-action")

    assert login_at < first_build_at, "the first build pulls the base image anonymously"


def test_the_published_image_is_built_from_the_tag_not_from_pypi():
    """apkradar, cookieradar and mailradar install themselves from PyPI inside the
    image, so their docker.yml has to poll until the release propagates —
    patchradar's 2026.9.4 failed on a fixed `sleep 60` that raced with its own
    publish, and polling only narrowed it. patchradar stopped asking the index on
    2026-10-04 and now builds from the tag, as this one always has; the other three
    have not moved yet.

    This Dockerfile installs the checkout, so there is no propagation to wait for and
    no version to agree on with PyPI. If that ever changes, this test fails and the
    wait has to come back with it.

    Where the checkout stands is a separate question, and the answer used to be "the
    default branch" — see the rebuild case further down.
    """
    assert "pip install --no-cache-dir --root-user-action=ignore /app/src" in (
        DOCKERFILE.read_text(encoding="utf-8")
    )
    assert "wait_for_pypi" not in published()
    # Nothing to parameterise: the three that still install from the index pass a
    # source and a version in, and a build-arg here would mean the image had learned
    # to install itself from somewhere the tag does not control. patchradar keeps one
    # — it has both branches and names the local one — which is a different shape, not
    # a reason to grow one here.
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


def test_a_rebuild_stands_on_the_tag_it_was_asked_for():
    """Dispatched with an old tag, this workflow has to check that tag out.

    It did not, and the consequence was milder than it looks, which is why it
    survived: the image is built from the checkout, so a rebuild of v2026.40 run
    from the default branch builds whatever main holds — and then the smoke test
    compares the installed version against the tag and refuses, before the login
    and before any push. So nothing was ever mis-published.

    What it means is that rebuilding an older release could not work at all. The
    input exists, the workflow accepts it, and the job fails on a version mismatch
    that reads like a packaging problem rather than like a checkout standing in the
    wrong place. patchradar had the same shape with no comparison behind it, where
    the same omission would have tagged main's code with an old release's number.
    """
    workflow = published()
    checkout = workflow.index("actions/checkout")
    # To the end of this step, not a fixed window: the step after it extracts the
    # version and names `inputs.version` for its own reasons, so a window wide enough
    # to reach it reports a checkout that looks at the input when it does not. Which
    # is what a 400-character window did here, and what mutating the ref to
    # `${{ github.ref }}` showed.
    end = workflow.find("\n      - name:", checkout)
    step = workflow[checkout:end if end != -1 else len(workflow)]

    assert "ref:" in step, "the checkout does not say which ref to stand on"
    assert "inputs.version" in step, (
        "a dispatched rebuild has to stand on the version it was given"
    )


def test_the_build_check_runs_on_its_own():
    """Otherwise the only thing that builds this image is the workflow that
    publishes it, and the first attempt at a build is the one that releases.

    This image is built from the checkout with no arguments to resolve, so there is
    nothing stopping it from being built on every change — unlike apkradar and
    mailradar, whose build check needs a published version handed to it because
    their Dockerfiles install from the index.
    """
    workflow = BUILD_CHECK.read_text(encoding="utf-8")
    triggers = workflow[workflow.index("\non:"):workflow.index("permissions:")]

    assert "pull_request" in triggers, "a change that breaks the image should say so in its PR"
    assert "push" in triggers, "and on main, because that is what the next release builds"
