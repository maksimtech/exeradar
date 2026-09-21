"""What holds while the modules are still stubs.

Thin on purpose, but not vacuous: pytest exits 5 when it collects nothing, so a
skeleton with no tests is a red pipeline from the first commit. These check the
few things that are already true and would be worth catching if they broke.
"""

from __future__ import annotations

import re

import pytest
from typer.testing import CliRunner

import exeradar
from exeradar.cli import app
from exeradar.models import ExeResult, Signature, SignatureState

runner = CliRunner()


def test_version_is_calver():
    """YYYY.0M.PATCH, and hatchling reads it from here to build the package."""
    assert re.fullmatch(r"\d{4}\.\d{2}\.\d+", exeradar.__version__)


def test_unsigned_and_unknown_are_distinct():
    """The rule the whole signature module exists to enforce.

    On Linux and macOS the catalog cannot be consulted, so "no embedded
    signature" is UNKNOWN, not UNSIGNED. Collapsing the two would make the tool
    report every catalog-signed Windows binary as unsigned.
    """
    assert SignatureState.UNSIGNED is not SignatureState.UNKNOWN
    assert SignatureState.UNSIGNED.value == "unsigned"
    assert SignatureState.UNKNOWN.value == "unknown"


def test_a_fresh_signature_claims_nothing():
    """The default has to be UNKNOWN: absence of evidence is not a finding."""
    assert Signature().state is SignatureState.UNKNOWN
    assert Signature().verified is None


def test_result_defaults_are_not_shared():
    """Mutable defaults on a dataclass are a classic way to leak state."""
    first = ExeResult(path="a", size=1, sha256="x")
    second = ExeResult(path="b", size=2, sha256="y")
    first.findings.append(object())
    assert second.findings == []


@pytest.mark.parametrize("command", ["analyze", "batch", "verify"])
def test_cli_exposes_the_documented_commands(command):
    """ARCHITECTURE.md section 1 promises these three."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert command in result.stdout


@pytest.mark.parametrize("module", [
    "exeradar.scanner",
    "exeradar.signature",
    "exeradar.strings",
    "exeradar.report",
    "exeradar.law_checker",
    "exeradar.formats.pe",
])
def test_every_stub_imports(module):
    """A stub that cannot be imported is worse than no stub."""
    __import__(module)
