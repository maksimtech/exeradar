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
COPY pyproject.toml README.md LICENSE /app/src/
COPY exeradar/ /app/src/exeradar/
RUN pip install --no-cache-dir --root-user-action=ignore /app/src && rm -rf /app/src

RUN useradd -m -u 1000 exeradar
USER exeradar
WORKDIR /home/exeradar

ENTRYPOINT ["exeradar"]
CMD ["--help"]
