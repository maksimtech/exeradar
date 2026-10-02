"""`--tlp` on the commands that write a file somebody else will read.

`analyze --output` and `batch --output` produce the document that goes to a PSIRT.
The option marks it; omitted, the document is unmarked, which is not TLP:CLEAR.

A label the standard does not define stops the command **before the scan**: the
option is wrong on its own terms, and reading a binary first would mean failing
after the work over a typo. `TLP:WHITE` is the case worth testing, because it was a
real label until TLP 2.0 renamed it in 2022 and somebody will type it.

The console output is deliberately not marked. A terminal is not a document that
gets forwarded, and a label printed where it cannot travel teaches a reader to
ignore it where it can.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from exeradar.cli import app

runner = CliRunner()


def test_a_marked_markdown_report_is_written(signed_pe_path, tmp_path):
    target = tmp_path / "finding.md"

    outcome = runner.invoke(app, ["analyze", str(signed_pe_path), "-o", str(target),
                                  "--tlp", "amber+strict"])

    assert outcome.exit_code == 0, outcome.output
    text = target.read_text(encoding="utf-8")
    assert "TLP:AMBER+STRICT" in text
    assert text.index("TLP:AMBER+STRICT") < text.index("#")


def test_a_marked_json_report_carries_the_field(signed_pe_path, tmp_path):
    target = tmp_path / "finding.json"

    outcome = runner.invoke(app, ["analyze", str(signed_pe_path), "-o", str(target),
                                  "--tlp", "red"])

    assert outcome.exit_code == 0, outcome.output
    assert json.loads(target.read_text(encoding="utf-8"))["tlp"] == "TLP:RED"


def test_without_the_option_the_report_is_unmarked(signed_pe_path, tmp_path):
    target = tmp_path / "finding.json"

    runner.invoke(app, ["analyze", str(signed_pe_path), "-o", str(target)])

    assert "tlp" not in json.loads(target.read_text(encoding="utf-8"))


def test_a_label_from_the_old_standard_stops_the_command(signed_pe_path, tmp_path):
    target = tmp_path / "finding.md"

    outcome = runner.invoke(app, ["analyze", str(signed_pe_path), "-o", str(target),
                                  "--tlp", "white"])

    assert outcome.exit_code == 2, outcome.output
    assert "CLEAR" in outcome.output
    assert "2.0" in outcome.output
    assert not target.exists()          # nothing written


def test_a_label_nobody_defines_stops_it_before_the_file_is_read(tmp_path):
    """No binary is opened: the option is answerable on its own, and the path
    given here does not even exist."""
    outcome = runner.invoke(app, ["analyze", str(tmp_path / "nowhere.exe"),
                                  "-o", str(tmp_path / "out.md"), "--tlp", "orange"])

    assert outcome.exit_code == 2, outcome.output
    assert "orange" in outcome.output
    assert "TLP:AMBER+STRICT" in outcome.output      # the labels that do exist
    assert "cannot read" not in outcome.output       # it never got as far as the file


def test_the_console_report_is_not_marked(signed_pe_path):
    """A terminal is not a document that travels. Marking it would teach a reader
    to skip the label in the place where it matters."""
    outcome = runner.invoke(app, ["analyze", str(signed_pe_path), "--tlp", "red"])

    assert outcome.exit_code == 0, outcome.output
    assert "TLP:RED" not in outcome.output


def test_a_batch_report_is_marked_once(signed_pe_path, tmp_path):
    # `batch` walks a directory, so the binaries are put in one.
    folder = tmp_path / "files"
    folder.mkdir()
    for name in ("one.exe", "two.exe"):
        (folder / name).write_bytes(signed_pe_path.read_bytes())
    target = tmp_path / "batch.md"

    outcome = runner.invoke(app, ["batch", str(folder), "-o", str(target),
                                  "--tlp", "green"])

    assert outcome.exit_code == 0, outcome.output
    text = target.read_text(encoding="utf-8")
    assert text.count("TLP:GREEN") == 1
    assert text.index("TLP:GREEN") < 20


def test_a_batch_json_report_marks_every_object(signed_pe_path, tmp_path):
    """A consumer can read one row out of the array and must still see the terms."""
    # `batch` walks a directory, so the binaries are put in one.
    folder = tmp_path / "files"
    folder.mkdir()
    for name in ("one.exe", "two.exe"):
        (folder / name).write_bytes(signed_pe_path.read_bytes())
    target = tmp_path / "batch.json"

    runner.invoke(app, ["batch", str(folder), "-o", str(target), "--tlp", "amber"])

    rows = json.loads(target.read_text(encoding="utf-8"))
    assert len(rows) == 2
    assert all(row["tlp"] == "TLP:AMBER" for row in rows)
