"""How the catalog path decodes what PowerShell sends back.

This is path B of ARCHITECTURE.md section 3, and it is the one Linux CI cannot
reach: `catalog_available()` is false there, so every one of these cases is
green by absence. They matter anyway, because a certificate Subject is the least
ASCII string in the whole tool — it carries the name of whichever CA signed the
file, in whatever alphabet that CA uses.

`subprocess.run(..., text=True)` with no `encoding=` decodes with the locale,
which on an Italian Windows is cp1252. Three things follow:

- a Subject with a character outside cp1252 cannot be decoded, and because
  capture_output collects the pipes on reader threads, the failure does not
  surface as an exception from `run` — it leaves `completed.stdout` as None;
- `completed.stdout.strip()` then raises AttributeError, which the surrounding
  `except (OSError, subprocess.SubprocessError)` does not catch;
- so a catalog-signed file with a non-cp1252 signer crashed the scan, on the
  only platform where that code runs at all.

Found on 2026-09-24, the same family as the cp1252 console crash already in the
backlog, on the input side.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from exeradar import signature

# A real one: the Subject of a CA that does not fit in cp1252.
CHINESE_CA = "CN=沃通根证书, O=WoSign CA Limited, C=CN"
GERMAN_CA = "CN=Müller Sicherheit GmbH, O=Bundesdruckerei, C=DE"


class _Completed:
    def __init__(self, stdout, returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


@pytest.fixture
def powershell(monkeypatch):
    """Stand in for PowerShell, and record how it was called."""
    calls = []

    def fake_run(argv, **kwargs):
        calls.append({"argv": argv, "kwargs": kwargs})
        return fake_run.result

    fake_run.result = _Completed("Valid|Catalog|CN=Test, O=Test|")
    monkeypatch.setattr(subprocess, "run", fake_run)
    return fake_run, calls


# ── the crash ───────────────────────────────────────────────────────────────


def test_a_subject_that_failed_to_decode_is_not_dereferenced(powershell):
    """stdout is None when the reader thread could not decode the bytes.

    The tool must answer "I do not know" — which is what None means here, and
    what SignatureState.UNKNOWN exists for — rather than raise AttributeError
    from inside a scan the user asked for.
    """
    fake_run, _ = powershell
    fake_run.result = _Completed(None)

    assert signature._catalog(Path("whatever.exe")) is None


def test_an_empty_answer_is_not_a_valid_signature(powershell):
    fake_run, _ = powershell
    fake_run.result = _Completed("")

    assert signature._catalog(Path("whatever.exe")) is None


# ── the encoding ────────────────────────────────────────────────────────────


def test_the_decoding_is_named_and_not_left_to_the_locale(powershell):
    """The same file must give the same answer on every Windows install.

    Without an explicit encoding the answer depends on the console code page,
    which differs by machine and by locale — and reads as a difference in the
    file being examined.
    """
    _, calls = powershell
    signature._catalog(Path("whatever.exe"))

    kwargs = calls[0]["kwargs"]
    assert kwargs.get("encoding") == "utf-8", kwargs
    assert kwargs.get("errors"), "a replacement policy, so one odd byte is not fatal"


def test_powershell_is_told_to_write_utf8(powershell):
    """Naming the encoding on this side is only half of it.

    PowerShell writes its output in the console encoding, so it has to be asked
    for UTF-8 too; otherwise we would be decoding cp850 as UTF-8, which is a
    different wrong answer from the one this replaces.
    """
    _, calls = powershell
    signature._catalog(Path("whatever.exe"))

    script = calls[0]["argv"][-1]
    assert "OutputEncoding" in script, script
    assert "UTF8" in script, script


@pytest.mark.parametrize("subject", [CHINESE_CA, GERMAN_CA])
def test_a_non_cp1252_signer_survives_the_round_trip(powershell, subject):
    """The name the CA chose is the name the report must print."""
    fake_run, _ = powershell
    fake_run.result = _Completed(f"Valid|Catalog|{subject}|")

    result = signature._catalog(Path("whatever.exe"))

    assert result is not None
    assert result.signer == subject


# ── what was already true, and must stay true ───────────────────────────────


def test_a_status_other_than_valid_is_not_a_signature(powershell):
    fake_run, _ = powershell
    fake_run.result = _Completed("NotSigned|None||")

    assert signature._catalog(Path("whatever.exe")) is None


def test_an_embedded_signature_is_not_claimed_as_a_catalog_one(powershell):
    """Only SignatureType Catalog belongs to path B."""
    fake_run, _ = powershell
    fake_run.result = _Completed("Valid|Embedded|CN=Test|")

    assert signature._catalog(Path("whatever.exe")) is None


def test_a_non_zero_exit_is_not_a_signature(powershell):
    fake_run, _ = powershell
    fake_run.result = _Completed("Valid|Catalog|CN=Test|", returncode=1)

    assert signature._catalog(Path("whatever.exe")) is None


def test_the_path_is_quoted_so_it_cannot_close_the_literal(powershell):
    """A single quote in a filename doubled, which is PowerShell's escape."""
    _, calls = powershell
    signature._catalog(Path("it's here.exe"))

    script = calls[0]["argv"][-1]
    assert "it''s here.exe" in script, script
