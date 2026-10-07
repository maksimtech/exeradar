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

Where these cases need an answer from PowerShell they ask the real one, about
real files, and are skipped where there is none. What decides on an answer is
also fed, on every platform, the answers PowerShell gave to the same call,
recorded in tests/fixtures/powershell_catalog_replies.json; on Windows one case
asks again, so a recording that stops being true fails rather than lingers.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from exeradar import signature
from exeradar.models import SignatureState

FIXTURES = Path(__file__).parent / "fixtures"
REPLIES = json.loads((FIXTURES / "powershell_catalog_replies.json").read_text(encoding="utf-8"))

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="path B is Windows PowerShell")

# Names a certificate can carry, each exactly the 26 bytes `_with_signer` has
# room for. 沃通根证书 is WoSign's root CA, a real Subject that does not fit in
# cp1252; the German one fits cp1252 and not ASCII.
CHINESE_CN = "沃通根证书 WoSign Ltd"
GERMAN_CN = "Müller Sicherheit GmbH KG"
PIPE_CN = "Contoso|Fabrikam Code Sign"
# The rest of the signer's Subject in tests/fixtures/python.exe.
REST_OF_SUBJECT = "O=Python Software Foundation, L=Beaverton, S=Oregon, C=US"

# The CN of python.exe's signing certificate: OID 2.5.4.3, a PrintableString of 26 bytes.
_SIGNER_CN = b"\x06\x03U\x04\x03\x13\x1aPython Software Foundation"


def _with_signer(tmp_path: Path, cn: str) -> Path:
    """tests/fixtures/python.exe, signed by a certificate whose CN is `cn`.

    Derived data: the recorded file with that one PrintableString rewritten as a
    UTF8String of the same length, so that no length around it changes; every
    other byte is as recorded. The certificate's own signature no longer
    matches and Windows answers UnknownError, but it reads and prints the
    Subject, which is all these cases need.
    """
    raw = cn.encode("utf-8")
    assert len(raw) == 26, f"{cn!r} is {len(raw)} bytes; the field holds 26"
    data = (FIXTURES / "python.exe").read_bytes()
    assert data.count(_SIGNER_CN) == 1
    target = tmp_path / "resigned.exe"
    target.write_bytes(data.replace(_SIGNER_CN, b"\x06\x03U\x04\x03\x0c\x1a" + raw))
    return target


def _replied(name: str) -> tuple[int, str]:
    """A recorded answer, as `_catalog_answer` takes it."""
    return REPLIES[name]["returncode"], REPLIES[name]["stdout"]


class _Completed:
    def __init__(self, stdout, returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


@pytest.fixture
def powershell(monkeypatch):
    """Stand in for PowerShell, and record how it was called.

    Used only by the cases that predate the answer in JSON. What it answers is
    what the real PowerShell said about a catalog-signed file.
    """
    calls = []

    def fake_run(argv, **kwargs):
        calls.append({"argv": argv, "kwargs": kwargs})
        return fake_run.result

    fake_run.result = _Completed(REPLIES["catalog"]["stdout"])
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


@windows_only
@pytest.mark.parametrize("cn", [CHINESE_CN, GERMAN_CN])
def test_a_non_cp1252_signer_survives_the_round_trip(cn, tmp_path):
    """The name the CA chose is the name the report must print.

    Asked of the real PowerShell about a certificate that carries the name, so
    that both halves of the encoding — PowerShell writing, Python reading — are
    the ones in use.
    """
    completed = signature._ask_powershell(_with_signer(tmp_path, cn))

    assert completed.returncode == 0, completed.stderr
    assert signature._catalog_fields(completed.stdout)["Signer"] == f"CN={cn}, {REST_OF_SUBJECT}"


def test_a_pipe_in_the_subject_does_not_shift_the_fields():
    """A Subject can contain `|`, as in O=Contoso|Fabrikam. The answer used to be
    four fields joined by `|`, so half the signer's name became the timestamper.

    No separator in plain text is safe from a Subject, which can hold a line
    break as well; the script answers in JSON, and this is the answer the real
    PowerShell gave about a certificate whose CN holds the separator.
    """
    fields = signature._catalog_fields(REPLIES["pipe"]["stdout"])

    assert fields["Signer"] == f"CN={PIPE_CN}, {REST_OF_SUBJECT}"
    assert fields["Stamper"].startswith("CN=Microsoft Public RSA Time Stamping Authority, ")


# ── what was already true, and must stay true ───────────────────────────────


def test_a_catalog_answer_is_a_catalog_signature():
    """The one answer path B exists for, so that the refusals below refuse
    something that would otherwise be accepted."""
    found = signature._catalog_answer(*_replied("catalog"))

    assert found is not None
    assert found.state is SignatureState.CATALOG and found.verified is True
    assert found.signer == "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"


def test_a_status_other_than_valid_is_not_a_signature():
    assert signature._catalog_fields(REPLIES["unsigned"]["stdout"])["Status"] == "NotSigned"
    assert signature._catalog_answer(*_replied("unsigned")) is None


def test_an_embedded_signature_is_not_claimed_as_a_catalog_one():
    """Only SignatureType Catalog belongs to path B: a valid embedded signature
    is path A's to report."""
    fields = signature._catalog_fields(REPLIES["embedded"]["stdout"])

    assert (fields["Status"], fields["Type"]) == ("Valid", "Authenticode")
    assert signature._catalog_answer(*_replied("embedded")) is None


def test_a_non_zero_exit_is_not_a_signature():
    assert REPLIES["missing"]["returncode"] != 0
    assert signature._catalog_answer(*_replied("missing")) is None


@windows_only
def test_the_recorded_replies_are_what_powershell_answers_today(request, tmp_path):
    """The replies above were recorded once; this asks again about the same files.

    Exactly, except for the catalog-signed file, which belongs to Windows: an
    update re-stamps its catalog, so its timestamper is not compared.
    """
    asked = {
        "catalog": request.getfixturevalue("catalog_pe_path"),
        "embedded": FIXTURES / "python.exe",
        "unsigned": request.getfixturevalue("unsigned_pe_path"),
        "missing": tmp_path / "missing.exe",
        "pipe": _with_signer(tmp_path, PIPE_CN),
    }
    assert set(asked) == set(REPLIES) - {"_recorded"}

    for name, path in asked.items():
        completed = signature._ask_powershell(path)
        recorded = REPLIES[name]
        assert completed.returncode == recorded["returncode"], name
        if name == "catalog":
            today = signature._catalog_fields(completed.stdout)
            then = signature._catalog_fields(recorded["stdout"])
            del today["Stamper"], then["Stamper"]
            assert today == then, name
        else:
            assert completed.stdout == recorded["stdout"], name


# ── the filename is data, never code ────────────────────────────────────────

# Legal on NTFS. With only the ASCII quote doubled, U+2019 closed the literal
# and the rest of the name ran as PowerShell, with the user's rights.
INJECTION = "a’; Write-Output PWNED; ’b.exe"


def _catalog_signed_copy(catalog_pe_path: Path, target: Path) -> Path:
    """A catalog signature is looked up by the file's hash, so a copy keeps it,
    whatever it is called and wherever it is."""
    shutil.copy(catalog_pe_path, target)
    return target


@windows_only
def test_a_name_with_quotes_reaches_powershell_intact(catalog_pe_path, tmp_path):
    """The filename is not in the script at all, so no quote in it can close anything.

    Doubling the ASCII quote was the escape until 2026-10-07, and PowerShell closes
    a single-quoted literal on four other characters too (U+2018 to U+201B). The
    path now reaches PowerShell as data, through the environment, and intact:
    the file it names is the one Windows finds in its catalog.
    """
    target = _catalog_signed_copy(catalog_pe_path, tmp_path / "it's here’.exe")

    found = signature._catalog(target)

    assert found is not None and found.state is SignatureState.CATALOG


@windows_only
def test_a_typographic_quote_in_the_name_cannot_close_the_literal(catalog_pe_path, tmp_path):
    """A name built to close the literal early and run a command is one value,
    and the file it names is found."""
    target = _catalog_signed_copy(catalog_pe_path, tmp_path / INJECTION)

    found = signature._catalog(target)

    assert found is not None and found.state is SignatureState.CATALOG


@windows_only
def test_the_name_runs_no_command(catalog_pe_path, tmp_path, monkeypatch):
    """Checked by running it. `a` exists, so a literal closed at the quote would
    name a real file and PowerShell would go on to `ni pwned`, which creates
    `pwned` in the working directory: that is what happened while the path was
    part of the script."""
    _catalog_signed_copy(catalog_pe_path, tmp_path / "a")
    target = _catalog_signed_copy(catalog_pe_path, tmp_path / "a’; ni pwned; ’b.exe")
    monkeypatch.chdir(tmp_path)

    found = signature._catalog(target)

    assert not (tmp_path / "pwned").exists()
    assert found is not None and found.state is SignatureState.CATALOG


# ── the real PowerShell: what `_catalog_fields` relies on ───────────────────

# The not-JSON and not-an-object branches were taken out of `_catalog_fields`
# because the script cannot reach them: exit 0 comes with one JSON object, and
# every failure is a non-zero exit with nothing on stdout. That is a claim about
# PowerShell, so it is asked of PowerShell, and only Windows has the one that
# answers it.

_FIELDS = ["Status", "Type", "Signer", "Stamper"]


@pytest.fixture
def denied(tmp_path):
    """A file this user may not read: an ACL deny entry, removed afterwards."""
    import os

    target = tmp_path / "denied.exe"
    shutil.copy(Path(sys.executable), target)
    who = os.environ.get("USERNAME", "")
    made = subprocess.run(["icacls", str(target), "/deny", f"{who}:(R)"],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    if made.returncode != 0:
        pytest.skip(f"icacls could not deny read: {made.stdout}{made.stderr}")
    try:
        yield target
    finally:
        subprocess.run(["icacls", str(target), "/remove:d", who], capture_output=True)


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
    if shutil.which("powershell"):
        pytest.skip("PowerShell is installed here")

    assert signature._catalog(unsigned_pe_path) is None
