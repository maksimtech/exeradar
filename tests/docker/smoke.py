"""Docker smoke test: the package imports and the CLI starts.

Deliberately thin while the modules are stubs — it proves the image is built
and runnable, which is all there is to prove before there is behaviour.
"""

import subprocess
import sys
from importlib.metadata import version

installed = version("exeradar")
print(f"smoke: exeradar {installed} OK")

import exeradar  # noqa: E402

assert exeradar.__version__ == installed, (exeradar.__version__, installed)

result = subprocess.run([sys.executable, "-m", "exeradar", "--help"],
                        capture_output=True, text=True, encoding="utf-8", errors="replace")
assert result.returncode == 0, result.stderr
assert "analyze" in result.stdout, result.stdout
print("smoke: cli OK")
