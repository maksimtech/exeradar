"""Docker smoke test: the package imports, the CLI starts, and the version in
the image is the one being tagged.

EXPECTED_VERSION is set by docker.yml, which takes it from the git tag. Nothing
else makes the two agree: the image installs the checkout, so its version comes
from exeradar/__init__.py while its Docker tag comes from the tag that triggered
the build. v2026.09.9 could carry 2026.09.8's code and only a pull would say so.

The comparison is made between normalised forms, not literally. The tag carries
a leading `v` that the metadata never has, and the two disagree about the padded
month depending on where you look: measured on 2026-09-26, hatchling writes
`Version: 2026.09.3` into METADATA while naming the wheel exeradar-2026.9.3. The
version this reads today is the padded one, and a literal comparison would be
one packaging change away from failing on every tag this project has.

Without EXPECTED_VERSION — docker-build-check, where there is no tag to compare
against — the version is reported and not judged.
"""

import os
import subprocess
import sys
from importlib.metadata import version


def _normalize(v: str) -> str:
    return ".".join(str(int(p)) if p.isdigit() else p for p in v.lstrip("v").split("."))


installed = version("exeradar")
expected = os.environ.get("EXPECTED_VERSION")
if expected:
    assert _normalize(installed) == _normalize(expected), (
        f"the image holds exeradar {installed}, the tag says {expected}"
    )
print(f"smoke: exeradar {installed} OK")

import exeradar  # noqa: E402

assert exeradar.__version__ == installed, (exeradar.__version__, installed)

result = subprocess.run([sys.executable, "-m", "exeradar", "--help"],
                        capture_output=True, text=True, encoding="utf-8", errors="replace")
assert result.returncode == 0, result.stderr
assert "analyze" in result.stdout, result.stdout
print("smoke: cli OK")
