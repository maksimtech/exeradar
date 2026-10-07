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

import json
import subprocess
import sys
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


def _answer(status, kind, signer="", stamper=""):
    """What the script prints: one JSON object, the way ConvertTo-Json writes it."""
    return json.dumps({"Status": status, "Type": kind, "Signer": signer, "Stamper": stamper},
                      ensure_ascii=False)


@pytest.fixture
def powershell(monkeypatch):
    """Stand in for PowerShell, and record how it was called."""
    calls = []

    def fake_run(argv, **kwargs):
        calls.append({"argv": argv, "kwargs": kwargs})
        return fake_run.result

    fake_run.result = _Completed(_answer("Valid", "Catalog", "CN=Test, O=Test"))
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
    fake_run.result = _Completed(_answer("Valid", "Catalog", subject))

    result = signature._catalog(Path("whatever.exe"))

    assert result is not None
    assert result.signer == subject


def test_a_pipe_in_the_subject_does_not_shift_the_fields(powershell):
    """A Subject can contain `|`, as in O=Contoso|Fabrikam. The answer used to be
    four fields joined by `|`, so half the signer's name became the timestamper.

    No separator in plain text is safe from a Subject, which can hold a line
    break as well; the script answers in JSON, and this is that answer.
    """
    fake_run, _ = powershell
    fake_run.result = _Completed(
        _answer("Valid", "Catalog", "CN=Contoso, O=Contoso|Fabrikam", "CN=Contoso TSA") + "\n"
    )

    result = signature._catalog(Path("whatever.exe"))

    assert result is not None
    assert result.signer == "CN=Contoso, O=Contoso|Fabrikam"
    assert result.timestamper == "CN=Contoso TSA"


# ── what was already true, and must stay true ───────────────────────────────


def test_a_status_other_than_valid_is_not_a_signature(powershell):
    fake_run, _ = powershell
    fake_run.result = _Completed(_answer("NotSigned", "None"))

    assert signature._catalog(Path("whatever.exe")) is None


def test_an_embedded_signature_is_not_claimed_as_a_catalog_one(powershell):
    """Only SignatureType Catalog belongs to path B."""
    fake_run, _ = powershell
    fake_run.result = _Completed(_answer("Valid", "Embedded", "CN=Test"))

    assert signature._catalog(Path("whatever.exe")) is None


def test_a_non_zero_exit_is_not_a_signature(powershell):
    fake_run, _ = powershell
    fake_run.result = _Completed(_answer("Valid", "Catalog", "CN=Test"), returncode=1)

    assert signature._catalog(Path("whatever.exe")) is None


def test_the_path_is_quoted_so_it_cannot_close_the_literal(powershell):
    """The filename is not in the script at all, so no quote in it can close anything.

    Doubling the ASCII quote was the escape until 2026-10-07, and PowerShell closes
    a single-quoted literal on four other characters too (U+2018 to U+201B). The
    path now reaches PowerShell as data, through the environment, and intact.
    """
    _, calls = powershell
    path = Path("it's here’.exe")
    signature._catalog(path)

    script = calls[0]["argv"][-1]
    assert "here" not in script, script
    assert calls[0]["kwargs"]["env"][signature._TARGET_VARIABLE] == str(path)


# ── the filename is data, never code ────────────────────────────────────────

# PowerShell takes U+2018, U+2019, U+201A and U+201B for a single quote as well.
_SINGLE_QUOTES = "'\u2018\u2019\u201a\u201b"

# Legal on NTFS. With only the ASCII quote doubled, U+2019 closed the literal
# and the rest of the name ran as PowerShell, with the user's rights.
INJECTION = "C:\\tmp\\a\u2019; Write-Output PWNED; \u2019b.exe"

# Captured before any test replaces it, for the one test that parses for real.
_REAL_RUN = subprocess.run


def _single_quoted_literal(script: str, after: str) -> str:
    """The value of the single-quoted literal after `after`, read the way
    PowerShell's tokenizer reads it: a doubled quote is a literal quote."""
    i = script.index(after) + len(after)
    assert script[i] in _SINGLE_QUOTES
    i += 1
    out = []
    while i < len(script):
        ch = script[i]
        if ch in _SINGLE_QUOTES:
            if i + 1 < len(script) and script[i + 1] in _SINGLE_QUOTES:
                out.append(ch)
                i += 2
                continue
            return "".join(out)
        out.append(ch)
        i += 1
    raise AssertionError("unterminated literal")


def test_a_typographic_quote_in_the_name_cannot_close_the_literal(powershell):
    """Two fixes are sound, and this admits both: the path stays out of the
    script and reaches PowerShell as data (environment or argument), or it stays
    in as one literal whose value is exactly the path. A literal that closes
    early is the one thing refused."""
    _, calls = powershell
    signature._catalog(Path(INJECTION))

    argv, kwargs = calls[0]["argv"], calls[0]["kwargs"]
    script = argv[-1]
    if "PWNED" in script:
        assert _single_quoted_literal(script, "-LiteralPath ") == INJECTION
    else:
        assert INJECTION in [*argv, *(kwargs.get("env") or {}).values()]


def _command_names(script: str, tmp_path: Path, name: str) -> list[str]:
    """The commands in `script`, by PowerShell's own parser: parsed, never run."""
    script_file = tmp_path / f"{name}.ps1"
    script_file.write_text(script, encoding="utf-8-sig")
    lister = tmp_path / "list.ps1"
    lister.write_text(
        "param($p)\n"
        "$t=$null;$e=$null\n"
        "$ast=[System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$t,[ref]$e)\n"
        "$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]},$true)"
        " | ForEach-Object { $_.GetCommandName() }\n",
        encoding="utf-8-sig",
    )
    try:
        parsed = _REAL_RUN(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(lister), str(script_file)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
        )
    except OSError:
        pytest.skip("PowerShell is not available")
    return [line.strip() for line in parsed.stdout.splitlines() if line.strip()]


@pytest.mark.skipif(sys.platform != "win32", reason="needs PowerShell's parser")
def test_the_name_adds_no_command_by_powershell_s_own_parser(powershell, tmp_path):
    """Checked against the real parser, without running anything. The commands
    are compared with those of the script built for a harmless name rather than
    with a list written here, so the test does not depend on how the script
    formats its answer."""
    _, calls = powershell
    signature._catalog(Path(INJECTION))
    signature._catalog(Path("C:\\tmp\\plain.exe"))

    commands = _command_names(calls[0]["argv"][-1], tmp_path, "injected")
    expected = _command_names(calls[1]["argv"][-1], tmp_path, "plain")

    assert "Get-AuthenticodeSignature" in expected, expected
    assert "Write-Output" not in commands, commands
    assert commands == expected, commands


# ── the real PowerShell: what `_catalog_answer` relies on ───────────────────

# The not-JSON and not-an-object branches were taken out of `_catalog_answer`
# because the script cannot reach them: exit 0 comes with one JSON object, and
# every failure is a non-zero exit with nothing on stdout. That is a claim about
# PowerShell, so it is asked of PowerShell, and only Windows has the one that
# answers it.
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="path B is Windows PowerShell")

_FIELDS = ["Status", "Type", "Signer", "Stamper"]


@pytest.fixture
def denied(tmp_path):
    """A file this user may not read: an ACL deny entry, removed afterwards."""
    import os
    import shutil

    target = tmp_path / "denied.exe"
    shutil.copy(Path(sys.executable), target)
    who = os.environ.get("USERNAME", "")
    made = _REAL_RUN(["icacls", str(target), "/deny", f"{who}:(R)"],
                     capture_output=True, text=True, encoding="utf-8", errors="replace")
    if made.returncode != 0:
        pytest.skip(f"icacls could not deny read: {made.stdout}{made.stderr}")
    try:
        yield target
    finally:
        _REAL_RUN(["icacls", str(target), "/remove:d", who], capture_output=True)


@windows_only
@pytest.mark.parametrize("kind", ["catalog", "embedded", "unsigned", "empty", "text"])
def test_exit_0_is_always_one_json_object(kind, request, tmp_path):
    """Whatever the file, an answer is the four values in one object, and the
    catalog is claimed for the catalog-signed file alone."""
    if kind == "catalog":
        target = request.getfixturevalue("catalog_pe_path")
    elif kind == "embedded":
        target = request.getfixturevalue("signed_pe_path")
    elif kind == "unsigned":
        target = request.getfixturevalue("unsigned_pe_path")
    else:
        target = tmp_path / f"{kind}.exe"
        target.write_bytes(b"" if kind == "empty" else b"not an executable\r\n")

    completed = signature._ask_powershell(target)

    assert completed.returncode == 0, completed.stderr
    answer = json.loads(completed.stdout)
    assert isinstance(answer, dict) and list(answer) == _FIELDS, completed.stdout
    found = signature._catalog(target)
    assert (found is not None) is (kind == "catalog"), found
    if found is not None:
        assert found.signer and found.signer.startswith("CN=Microsoft Windows"), found.signer


@windows_only
@pytest.mark.parametrize("kind", ["missing", "directory", "denied"])
def test_every_failure_is_a_non_zero_exit_with_nothing_on_stdout(kind, request, tmp_path):
    """No such file, a directory, a file this user may not read: each ends the
    script at Get-AuthenticodeSignature, and none of them is a signature."""
    target = {
        "missing": lambda: tmp_path / "missing.exe",
        "directory": lambda: tmp_path,
        "denied": lambda: request.getfixturevalue("denied"),
    }[kind]()

    completed = signature._ask_powershell(target)

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr
    assert signature._catalog(target) is None


def test_no_powershell_is_no_answer(unsigned_pe_path):
    """A machine without PowerShell cannot be asked: "I could not tell", the
    reply to every failure of path B, and not a traceback."""
    import shutil

    if shutil.which("powershell"):
        pytest.skip("PowerShell is installed here")

    assert signature._catalog(unsigned_pe_path) is None
