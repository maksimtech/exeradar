FROM python:3.14-slim-trixie

LABEL maintainer="maksimtech <github@maksimtech.com>"
LABEL org.opencontainers.image.title="ExeRadar"
LABEL org.opencontainers.image.description="Static analysis of Windows, macOS and Linux executables"
LABEL org.opencontainers.image.source="https://github.com/maksimtech/exeradar"
LABEL org.opencontainers.image.licenses="MIT"

RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1

WORKDIR /app

# Built from the checkout, not from PyPI: nothing is published yet, and a
# build-only check has to work before the first release.
#
# Install exeradar, then take the build tooling back out. A runtime image needs
# neither pip, setuptools nor wheel: the entrypoint is `exeradar`, and none of
# lief, asn1crypto, typer, rich or httpx imports pkg_resources. While the tooling
# is installed, the copies it *vendors* are what a scanner reports, and a pin
# cannot reach those — on 2026-09-29 Docker Scout reported CVE-2025-47273
# (setuptools), CVE-2026-57585 and GHSA-6v7p-g79w-8964 (msgpack) against
# `pip/_vendor/bom.cdx.json`, a path no dependency of this project can influence.
# Installing a patched msgpack alongside would add a second copy and leave the
# vulnerable one exactly where the scanner reads it; removing the tooling removes
# it. Learned in patchradar, where the same three findings closed this way.
#
# `pip uninstall` is the last pip call in this file, because it removes pip. A
# package that is not installed is a warning and not an error, so the build does
# not depend on which of the three the base image happens to ship.
COPY pyproject.toml README.md LICENSE /app/src/
COPY exeradar/ /app/src/exeradar/
RUN pip install --no-cache-dir --root-user-action=ignore /app/src && \
    rm -rf /app/src && \
    pip uninstall --yes --root-user-action=ignore pip setuptools wheel

RUN useradd -m -u 1000 exeradar
USER exeradar
WORKDIR /home/exeradar

ENTRYPOINT ["exeradar"]
CMD ["--help"]
