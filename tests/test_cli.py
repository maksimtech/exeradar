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

`analyze` is here for what only the command line decides: where the report
goes, what happens when it cannot be written, and whether the network is
reached at all.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
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


def test_batch_says_the_report_it_was_asked_for_was_not_written(tmp_path):
    """No file is still right when there is nothing to report, but whoever
    named one has to be told it is not there."""
    empty = tmp_path / "empty"
    empty.mkdir()
    target = tmp_path / "report.json"

    outcome = runner.invoke(app, ["batch", str(empty), "--output", str(target)])

    assert outcome.exit_code == 0
    assert not target.exists()
    assert "report.json" in outcome.output
    assert "not written" in outcome.output


def test_batch_refuses_an_output_in_a_directory_that_is_not_there(sample, tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    shutil.copy(sample, tree / "one.exe")
    output = tmp_path / "missing-dir" / "run.json"

    outcome = runner.invoke(app, ["batch", str(tree), "--output", str(output)])

    assert outcome.exception is None or isinstance(outcome.exception, SystemExit), repr(outcome.exception)
    assert outcome.exit_code == 2


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are NTFS")
def test_batch_does_not_list_a_file_twice_through_a_junction(sample, tmp_path):
    """Path.rglob skips symlinks and follows junctions: one pointing back at its
    parent listed the same PE once per level, until the path grew too long."""
    root = tmp_path / "tree"
    root.mkdir()
    shutil.copy(sample, root / "one.exe")
    junction = root / "loop"
    made = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(root)],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    if made.returncode != 0:
        pytest.skip(f"mklink /J is not available: {made.stdout}{made.stderr}")
    out = tmp_path / "run.json"
    try:
        outcome = runner.invoke(app, ["batch", str(root), "--output", str(out)])
        rows = json.loads(out.read_text(encoding="utf-8"))
    finally:
        os.rmdir(junction)   # removes the link only, not what it points at

    assert outcome.exit_code == 0
    assert len(rows) == 1, f"{len(rows)} rows for one file"


def test_batch_does_not_enter_a_directory_twice_through_a_symlink(sample, tmp_path):
    """The same guarantee for a directory symlink, which Linux can check too.

    rglob already skipped symlinks; this guards the walk rewritten for junctions.
    """
    root = tmp_path / "tree"
    root.mkdir()
    shutil.copy(sample, root / "one.exe")
    try:
        os.symlink(root, root / "loop", target_is_directory=True)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks are not available: {error}")
    out = tmp_path / "run.json"

    outcome = runner.invoke(app, ["batch", str(root), "--output", str(out)])

    assert outcome.exit_code == 0, outcome.output
    assert len(json.loads(out.read_text(encoding="utf-8"))) == 1


def test_an_entry_that_is_gone_by_the_time_it_is_checked_is_not_a_link(tmp_path):
    """os.walk lists a directory and the link check comes after: whatever was
    removed in between cannot be lstat-ed, and is not a link to stay out of."""
    from exeradar.cli import _is_link

    assert _is_link(str(tmp_path / "removed-meanwhile")) is False


@pytest.mark.skipif(sys.platform != "linux", reason="PATH_MAX is the Linux limit")
def test_batch_walks_past_a_directory_whose_path_is_too_long_to_stat(sample, tmp_path):
    """A directory can be listed while the path of an entry in it is longer than
    PATH_MAX: lstat fails with ENAMETOOLONG, and that is not a reason to fail
    the whole run over the PE files it can read."""
    import errno

    root = tmp_path / "tree"
    root.mkdir()
    shutil.copy(sample, root / "one.exe")
    limit = os.pathconf(root, "PC_PATH_MAX")
    name = "d" * 250
    deepest = root
    while len(os.fsencode(deepest / name)) < limit:
        deepest = deepest / name
        deepest.mkdir()
    # Created relative to its parent, the only way to make it: its full path
    # does not fit in a system call.
    parent = os.open(deepest, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.mkdir(name, dir_fd=parent)
    finally:
        os.close(parent)
    with pytest.raises(OSError) as too_long:
        os.lstat(os.path.join(deepest, name))
    assert too_long.value.errno == errno.ENAMETOOLONG
    out = tmp_path / "run.json"

    outcome = runner.invoke(app, ["batch", str(root), "--output", str(out)])

    assert outcome.exception is None or isinstance(outcome.exception, SystemExit), repr(outcome.exception)
    assert outcome.exit_code == 0, outcome.output
    assert len(json.loads(out.read_text(encoding="utf-8"))) == 1


def test_batch_a_write_that_fails_after_the_walk_is_not_a_traceback(sample, tmp_path):
    """The report's directory is there, so the run starts; the name itself is a
    directory, so the write fails after every file has been scanned. Said, with
    exit code 2, as analyze does."""
    tree = tmp_path / "tree"
    tree.mkdir()
    shutil.copy(sample, tree / "one.exe")
    output = tmp_path / "run.json"
    output.mkdir()

    outcome = runner.invoke(app, ["batch", str(tree), "--output", str(output)])

    assert outcome.exception is None or isinstance(outcome.exception, SystemExit), repr(outcome.exception)
    assert outcome.exit_code == 2
    assert f"cannot write {output}" in outcome.output
    assert output.is_dir()


# --------------------------------------------------------------------------
# analyze
# --------------------------------------------------------------------------


def test_analyze_does_not_crash_on_a_url_with_square_brackets(pe_with_a_string):
    """`http://evil.example/[/x]` in a binary is a fact to print, not Rich
    markup: it raised MarkupError and ended `analyze` with a traceback."""
    target = pe_with_a_string(b"http://evil.example/[/x]")

    outcome = runner.invoke(app, ["analyze", str(target)])

    assert outcome.exception is None or isinstance(outcome.exception, SystemExit), repr(outcome.exception)
    assert outcome.exit_code == 0
    assert "http://evil.example/[/x]" in outcome.output


def test_analyze_refuses_an_output_in_a_directory_that_is_not_there(sample, tmp_path):
    """The extension was checked before the scan and the directory was not: a
    missing one surfaced as a FileNotFoundError traceback after all the work."""
    output = tmp_path / "missing-dir" / "report.json"

    outcome = runner.invoke(app, ["analyze", str(sample), "--output", str(output)])

    assert outcome.exception is None or isinstance(outcome.exception, SystemExit), repr(outcome.exception)
    assert outcome.exit_code != 0


def test_analyze_a_write_that_fails_after_the_scan_is_not_a_traceback(sample, tmp_path):
    """The directory is there and the write still fails — here because a
    directory already has the report's name, as permissions or a full disk
    would make it fail: checking up front is not enough, the write has to be
    handled too."""
    output = tmp_path / "r.json"
    output.mkdir()

    outcome = runner.invoke(app, ["analyze", str(sample), "--output", str(output)])

    assert outcome.exception is None or isinstance(outcome.exception, SystemExit), repr(outcome.exception)
    assert outcome.exit_code == 2
    assert f"cannot write {output}" in outcome.output
    assert output.is_dir()


def test_analyze_a_citation_that_fails_costs_only_the_citation(tampered):
    """EXERADAR_HOME naming the home of a user this machine does not have —
    copied from another machine's setup — leaves no directory for the cache, and
    law_checker raises. The analysis is already done: it is printed, the
    failure is one warning line, and the exit code is the analysis's.

    USERPROFILE and HOMEPATH are removed because Windows expands `~name` from
    them whether or not that user exists; without them it cannot either.
    """
    outcome = runner.invoke(app, ["analyze", str(tampered)], env={
        "EXERADAR_HOME": "~exeradar-no-such-user/cache",
        "USERPROFILE": None, "HOMEPATH": None, "HOMEDRIVE": None,
    })

    assert outcome.exception is None or isinstance(outcome.exception, SystemExit), repr(outcome.exception)
    assert outcome.exit_code == 0, outcome.output
    assert "provisions not cited: Could not determine home directory" in outcome.output
    assert "signature_invalid" in outcome.output
    assert "Provisions applied" not in outcome.output


# --------------------------------------------------------------------------
# analyze: the provisions are cited offline unless --online is asked for
# --------------------------------------------------------------------------


@pytest.fixture
def tampered(sample, tmp_path) -> Path:
    """The sample with one byte of .text changed: the signature no longer matches
    on any platform, so `signature_invalid` is raised and the CRA is cited."""
    data = bytearray(sample.read_bytes())
    data[0x500] ^= 0xFF
    target = tmp_path / "tampered.exe"
    target.write_bytes(bytes(data))
    return target


@pytest.fixture
def law_home(monkeypatch, tmp_path) -> Path:
    """An empty cache of legal texts: the first run of every installation."""
    home = tmp_path / "home"
    monkeypatch.setenv("EXERADAR_HOME", str(home))
    return home


# Whether a request leaves the machine is asked of the network itself: the
# `network` fixture is a real listener named as the proxy, and it records every
# connection made through it. Nothing in the tool is replaced to find out.


def test_analyze_downloads_nothing_by_default(tampered, network, law_home):
    """The provisions are cited all the same, from the cache."""
    outcome = runner.invoke(app, ["analyze", str(tampered)])

    assert outcome.exit_code == 0, outcome.output
    assert network == []
    assert "signature_invalid" in outcome.output
    assert "Provisions applied" in outcome.output


def test_analyze_downloads_the_texts_only_with_online(tampered, network, law_home):
    """--online asks the publishers for the acts. The network it meets here is
    not there, and the run still ends with the analysis it has done."""
    outcome = runner.invoke(app, ["analyze", str(tampered), "--online"])

    assert outcome.exit_code == 0, outcome.output
    assert any("europa.eu" in line for line in network), f"--online asked nobody: {network}"


def test_analyze_says_how_to_get_a_text_the_cache_does_not_have(tampered, network, law_home):
    """Offline over an empty cache the provisions are cited without a hash; the
    run has to say that, and how to fill the cache, rather than fail."""
    outcome = runner.invoke(app, ["analyze", str(tampered)])

    assert outcome.exit_code == 0, outcome.output
    assert outcome.exception is None or isinstance(outcome.exception, SystemExit), repr(outcome.exception)
    assert "Traceback" not in outcome.output
    assert "--online" in outcome.output
    assert "Provisions applied" in outcome.output
    assert network == []


def test_analyze_cites_the_provisions_in_the_report_without_downloading_anything(
    tampered, network, law_home, tmp_path,
):
    """End to end, on every platform: `signature_invalid` (high) cites the CRA,
    and the Markdown report carries the citations and the note that qualifies
    them, all from the local cache."""
    from exeradar import law_checker

    output = tmp_path / "report.md"

    outcome = runner.invoke(app, ["analyze", str(tampered), "--output", str(output)])

    assert outcome.exit_code == 0, outcome.output
    assert network == []
    text = output.read_text(encoding="utf-8")
    assert "signature_invalid" in text
    assert "## Provisions applied" in text
    assert f"Provision applied: {law_checker.CRA.name} Allegato I, Parte I(2)(f)" in text
    assert law_checker.CRA_APPLICATION_NOTE in text


def test_analyze_has_no_offline_option_any_more(tampered, network, law_home):
    """Offline is the default, so the old flag would be a no-op: refused, not
    ignored, and refused before anything is analysed or cited."""
    outcome = runner.invoke(app, ["analyze", str(tampered), "--offline"])

    assert outcome.exit_code == 2
    assert "Provisions applied" not in outcome.output
    assert network == []


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------


def test_verify_passes_a_signed_binary(sample):
    outcome = runner.invoke(app, ["verify", str(sample)])

    assert outcome.exit_code == 0
    assert "embedded" in outcome.stdout


def test_verify_answers_the_same_whatever_the_file_is_called(sample, tmp_path):
    """LIEF opened the path through the narrow API on Windows: the same validly
    signed file answered 0 as `plain.exe` and 2 as `Привет.exe`."""
    plain = tmp_path / "plain.exe"
    shutil.copy(sample, plain)
    accented = tmp_path / "Привет.exe"
    shutil.copy(sample, accented)

    expected = runner.invoke(app, ["verify", str(plain)]).exit_code
    outcome = runner.invoke(app, ["verify", str(accented)])

    assert expected == 0
    assert outcome.exit_code == expected, outcome.output


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


def test_version_option_prints_the_package_version():
    """Reported missing from real use on 2026-09-26: the other four Radar all
    answer `--version` and this one did not, so the version had to be read out
    of `pip list`. It comes from `exeradar.__version__` rather than a literal,
    which is the thing worth pinning — a hardcoded copy drifts the first time
    someone releases without touching the CLI.
    """
    from typer.testing import CliRunner

    import exeradar
    from exeradar.cli import app

    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0, result.output
    assert exeradar.__version__ in result.output
    assert "ExeRadar" in result.output
