#!/bin/sh
# What the image actually contains, printed rather than remembered.
#
# Two questions the SECURITY-EXCEPTIONS.toml entries answer on trust, and which
# only the built image can settle.
#
# 1. Is the build tooling gone? The Dockerfile removes pip, setuptools and wheel
#    after installing exeradar, because CVE-2025-47273, CVE-2026-57585 and
#    GHSA-6v7p-g79w-8964 are reported against copies vendored *inside* them, at
#    `pip/_vendor/`, where no pin can reach. If they are still here the fix did
#    not work, and the record says it did.
#
# 2. Which perl is installed? Docker Scout names the *source* package for
#    CVE-2026-82560, and Debian's `perl` source produces `perl-base` — Essential,
#    which dpkg itself depends on and which cannot be removed — as well as
#    `perl`, which can. Which of them is here decides whether that finding is
#    ours to close or only ours to record.
#
# Run by .github/workflows/docker-build-check.yml, which builds and publishes
# nothing:
#     docker run --rm -i --entrypoint sh exeradar:build-check - < inspect.sh
#
# This script reports; it does not judge. A failure here would be a failure of
# the diagnostic, and the numbers are what the exceptions record has to match.
set -eu

echo "── build tooling, which the Dockerfile removes ──"
still_here=""
for pkg in pip setuptools wheel; do
    if python -c "import importlib.metadata as m, sys; sys.stdout.write(m.version('$pkg'))" \
        2>/dev/null; then
        echo "  <- $pkg is STILL PRESENT"
        still_here="$still_here $pkg"
    else
        echo "  $pkg absent, as intended"
    fi
done
if [ -n "$still_here" ]; then
    echo "  NOTE: the three vendored CVEs cannot close while$still_here remain."
fi

echo
echo "── anything left under pip/_vendor ──"
find / -path '*/pip/_vendor*' -name 'bom.cdx.json' 2>/dev/null | sed 's/^/  /' \
    || true
echo "  (no output above means the path Scout reported is gone)"

echo
echo "── perl packages installed ──"
dpkg-query -W -f '${Package} ${Version} essential=${Essential} priority=${Priority}\n' \
    'perl*' 'libperl*' 2>/dev/null || echo "  none"

echo
echo "── size of the installed set ──"
printf '  %s packages\n' "$(dpkg-query -f '.\n' -W | wc -l)"
