"""The two commands that were stubs: `batch` and `verify`.

`verify` is the one with a contract beyond its output, because it is meant to
be a gate in a script. Its exit codes are three and not two:

    0  signed, and the signature verifies
    1  not signed, or signed and the signature does not verify
    2  could not be determined here

The third exists for the same reason `SignatureState.UNKNOWN` does. Off
Windows the catalog cannot be consulted, so a file with no embedded signature
may be perfectly signed and this tool cannot tell. Returning 1 there would fail
a pipeline over a missing capability, and returning 0 would pass a file nobody
checked; 2 is the honest answer, and `|| exit` still catches it.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from exeradar import signature
from exeradar.cli import app
from exeradar.models import Signature, SignatureState

runner = CliRunner()

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE = FIXTURES / "python.exe"


@pytest.fixture(scope="module")
def sample() -> Path:
    if not SAMPLE.is_file():
        pytest.skip("tests/fixtures/python.exe is missing")
    return SAMPLE


@pytest.fixture(scope="module")
def tree(sample, tmp_path_factory) -> Path:
    """A directory holding two PEs, one nested, and two files that are not.

    The non-PE files are the point: a batch that reports them has no way to
    say anything true about them.
    """
    root = tmp_path_factory.mktemp("tree")
    shutil.copy(sample, root / "a.exe")
    (root / "sub").mkdir()
    shutil.copy(sample, root / "sub" / "b.exe")
    (root / "notes.txt").write_text("not an executable", encoding="utf-8")
    (root / "sub" / "data.bin").write_bytes(b"\x01\x02\x03\x04" * 64)
    return root


# --------------------------------------------------------------------------
# batch
# --------------------------------------------------------------------------


def test_batch_finds_the_pe_files_recursively(tree):
    outcome = runner.invoke(app, ["batch", str(tree)])

    assert outcome.exit_code == 0
    assert "a.exe" in outcome.stdout
    assert "b.exe" in outcome.stdout


def test_batch_leaves_alone_what_is_not_a_pe(tree):
    outcome = runner.invoke(app, ["batch", str(tree)])

    assert "notes.txt" not in outcome.stdout
    assert "data.bin" not in outcome.stdout


def test_batch_says_how_many_it_looked_at(tree):
    outcome = runner.invoke(app, ["batch", str(tree)])
    assert "2" in outcome.stdout


def test_batch_writes_an_array_of_results(tree, tmp_path):
    target = tmp_path / "report.json"
    outcome = runner.invoke(app, ["batch", str(tree), "--output", str(target)])

    assert outcome.exit_code == 0
    data = json.loads(target.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) == 2
    assert {Path(entry["path"]).name for entry in data} == {"a.exe", "b.exe"}
    assert all(entry["format"] == "PE" for entry in data)


def test_batch_reports_in_a_stable_order(tree, tmp_path):
    """Two runs that disagree on order make a diff of two reports useless."""
    first, second = tmp_path / "one.json", tmp_path / "two.json"
    runner.invoke(app, ["batch", str(tree), "--output", str(first)])
    runner.invoke(app, ["batch", str(tree), "--output", str(second)])

    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")


def test_batch_refuses_a_directory_that_is_not_there(tmp_path):
    outcome = runner.invoke(app, ["batch", str(tmp_path / "nowhere")])
    assert outcome.exit_code == 2


def test_batch_refuses_a_file_where_a_directory_was_asked_for(sample):
    outcome = runner.invoke(app, ["batch", str(sample)])
    assert outcome.exit_code == 2


def test_batch_checks_the_output_name_before_doing_the_work(tree, tmp_path):
    """Refusing a filename after scanning a directory is a poor trade."""
    target = tmp_path / "report.doc"
    outcome = runner.invoke(app, ["batch", str(tree), "--output", str(target)])

    assert outcome.exit_code == 2
    assert not target.exists()


def test_batch_on_a_directory_with_nothing_in_it_is_not_a_failure(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    outcome = runner.invoke(app, ["batch", str(empty)])

    assert outcome.exit_code == 0
    assert "no" in outcome.stdout.lower()


def test_batch_writes_nothing_when_it_found_nothing(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    target = tmp_path / "report.json"
    outcome = runner.invoke(app, ["batch", str(empty), "--output", str(target)])

    assert outcome.exit_code == 0
    assert not target.exists()


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------


def test_verify_passes_a_signed_binary(sample):
    outcome = runner.invoke(app, ["verify", str(sample)])

    assert outcome.exit_code == 0
    assert "embedded" in outcome.stdout


def test_verify_fails_a_binary_that_was_changed_after_signing(sample, tmp_path):
    """The case the exit code exists for: the bytes no longer match the signature.

    Patched inside the code section, far from the certificate table, so the
    signature is still there and still parses — and no longer describes the
    file, which is what an invalid signature means.
    """
    tampered = tmp_path / "tampered.exe"
    data = bytearray(sample.read_bytes())
    data[0x2000:0x2010] = b"\x90" * 16
    tampered.write_bytes(bytes(data))

    outcome = runner.invoke(app, ["verify", str(tampered)])

    assert outcome.exit_code == 1
    assert "embedded" in outcome.stdout


def test_verify_refuses_something_that_is_not_an_executable(tmp_path):
    """Silence about a text file would read as "unsigned", which it is not."""
    text = tmp_path / "notes.txt"
    text.write_text("not an executable", encoding="utf-8")

    outcome = runner.invoke(app, ["verify", str(text)])

    assert outcome.exit_code == 2
    # A refusal is an error, so it goes to stderr; `output` holds both streams.
    assert "PE" in outcome.output


def test_verify_refuses_a_file_that_is_not_there(tmp_path):
    outcome = runner.invoke(app, ["verify", str(tmp_path / "nowhere.exe")])
    assert outcome.exit_code == 2


def test_verify_does_not_fail_a_build_over_a_missing_capability(sample, monkeypatch):
    """UNKNOWN is not UNSIGNED, and a CI gate must not pretend otherwise.

    This is the Linux case for a catalog-signed Windows binary: nothing is
    wrong with the file, the platform simply cannot answer.
    """
    monkeypatch.setattr(
        signature, "inspect",
        lambda path: Signature(state=SignatureState.UNKNOWN, verified=None,
                               detail="catalog signature: not verifiable on this platform"),
    )
    outcome = runner.invoke(app, ["verify", str(sample)])

    assert outcome.exit_code == 2
    assert "unknown" in outcome.stdout


def test_verify_fails_an_unsigned_binary(sample, monkeypatch):
    monkeypatch.setattr(
        signature, "inspect",
        lambda path: Signature(state=SignatureState.UNSIGNED, verified=False,
                               detail="no embedded signature and no catalog entry"),
    )
    outcome = runner.invoke(app, ["verify", str(sample)])

    assert outcome.exit_code == 1
    assert "unsigned" in outcome.stdout


def test_verify_passes_a_catalog_signature(sample, monkeypatch):
    """Path B is a pass: Windows confirmed the file, the blob is just elsewhere."""
    monkeypatch.setattr(
        signature, "inspect",
        lambda path: Signature(state=SignatureState.CATALOG, verified=True,
                               detail="signed by catalog, not by an embedded blob"),
    )
    outcome = runner.invoke(app, ["verify", str(sample)])

    assert outcome.exit_code == 0
    assert "catalog" in outcome.stdout


def test_verify_reads_the_signature_and_nothing_else(sample, monkeypatch):
    """"Controlla SOLO la firma": no hashing, no imports, no strings.

    Worth pinning. The obvious implementation calls scan() and throws most of
    it away, which on a large binary is seconds of work for an answer that
    needed milliseconds.
    """
    from exeradar import scanner

    def refuse(path):
        raise AssertionError("verify must not run a full scan")

    monkeypatch.setattr(scanner, "scan", refuse)
    outcome = runner.invoke(app, ["verify", str(sample)])

    assert outcome.exit_code == 0


@pytest.mark.skipif(sys.platform != "win32", reason="the catalog needs Windows")
def test_verify_agrees_with_windows_about_a_system_binary(catalog_pe_path):
    """End to end on the file that started the whole design."""
    outcome = runner.invoke(app, ["verify", str(catalog_pe_path)])

    assert outcome.exit_code == 0
    assert "catalog" in outcome.stdout
