"""The libraries on a report, and the sentence an empty list has to carry.

Three rows that mean three different things have to still mean three different
things once rendered, so each renderer is checked on all three: a version carried
in the file, a version the file asks another file for, and a library used with no
version stated here.

The last one is why this file exists. A reader who sees four libraries and no
OpenSSL will conclude there is no OpenSSL, and for a dynamically linked binary that
is wrong — the version is in the DLL next door. So the row says which DLL, and the
caveat says what the list does not mean. Both are asserted here rather than left to
whoever edits the renderer next.

The JSON keeps `"version": null` rather than dropping the key, which is the
opposite of what `tlp` does, and deliberately. An absent `tlp` means nobody chose a
label; a null version means the file was asked and did not say. One is silence
about the question, the other is an answer to it.
"""

from __future__ import annotations

import json

import pytest
from rich.console import Console

from exeradar import libraries, report
from exeradar.models import ExeResult, Library, Signature, SignatureState


@pytest.fixture
def result() -> ExeResult:
    return ExeResult(
        path="C:/tmp/sample.exe",
        size=711736,
        sha256="4942b86a",
        format="PE",
        arch="AMD64",
        signature=Signature(state=SignatureState.UNSIGNED),
        libraries=[
            Library("curl", "8.13.0", libraries.BANNER, "curl 8.13.0 (Windows) %s"),
            Library("Katana", "1.1.8.0", libraries.ASSEMBLY,
                    "Katana, Version=1.1.8.0, Culture=neutral"),
            Library("openssl", None, libraries.IMPORT, "libcrypto-3-x64.dll"),
            Library("zlib", "1.3.1", libraries.BUILD_PATH,
                    "../zlib-1.3.1/inflate.c"),
        ],
    )


def test_the_json_carries_every_row_with_its_evidence(result):
    rows = json.loads(report.to_json(result))["libraries"]

    assert [row["name"] for row in rows] == ["curl", "Katana", "openssl", "zlib"]
    assert rows[0] == {
        "name": "curl",
        "version": "8.13.0",
        "source": "banner",
        "evidence": "curl 8.13.0 (Windows) %s",
    }


def test_the_json_says_null_rather_than_dropping_the_version(result):
    """A tool filtering for "libraries whose version I do not know" needs the key.

    Not the same choice as `tlp`, which is absent when unset: there, nobody asked
    the question; here, the file was asked and had no answer.
    """
    rows = json.loads(report.to_json(result))["libraries"]
    imported = next(row for row in rows if row["name"] == "openssl")

    assert imported["version"] is None
    assert imported["source"] == "import"
    assert imported["evidence"] == "libcrypto-3-x64.dll"


def test_the_markdown_names_the_version_and_what_said_it(result):
    text = report.to_markdown(result)

    assert "## Libraries" in text
    assert "curl 8.13.0" in text
    assert "curl 8.13.0 (Windows) %s" in text


def test_the_markdown_says_which_file_to_open_for_a_missing_version(result):
    text = report.to_markdown(result)

    section = text.split("## Libraries", 1)[1]
    assert "libcrypto-3-x64.dll" in section
    assert "no version" in section.lower()


def test_the_markdown_carries_the_caveat_next_to_the_list(result):
    """So that four rows are not read as "these four and no others"."""
    section = report.to_markdown(result).split("## Libraries", 1)[1]

    assert libraries.CAVEAT in section


def test_an_empty_list_still_carries_the_caveat():
    """The case the caveat exists for: silence read as absence.

    python.exe reaches this, and it does carry a Python version — as a bare
    `3.14.7` that nothing attributes. "None stated" is the true sentence; "no
    libraries" would not be.
    """
    bare = ExeResult(path="C:/tmp/bare.exe", size=1, sha256="aa",
                     format="PE", signature=Signature(state=SignatureState.UNSIGNED))

    section = report.to_markdown(bare).split("## Libraries", 1)[1]

    assert libraries.CAVEAT in section
    assert "none" in section.lower()


def test_an_assembly_reference_is_not_said_to_be_in_the_file(result):
    section = report.to_markdown(result).split("## Libraries", 1)[1]
    line = next(ln for ln in section.splitlines() if "Katana" in ln)

    assert "1.1.8.0" in line
    assert "run time" in line or "requires" in line
    assert "in this file" not in line


def test_the_console_prints_the_rows_and_the_caveat(result):
    console = Console(width=100, force_terminal=False, no_color=True, record=True)

    report.to_console(result, console)
    text = console.export_text()

    assert "curl 8.13.0" in text
    assert "libcrypto-3-x64.dll" in text
    # Whitespace-normalised, because the console wraps the caveat and a test that
    # asserts a fragment instead would pass on half a sentence.
    assert libraries.CAVEAT in " ".join(text.split())


def test_the_console_and_the_markdown_use_one_sentence_per_row(result):
    """Not the same layout — the same words. Two renderers drifting apart on what
    a row means is how "no version here" becomes "no version"."""
    console = Console(width=200, force_terminal=False, no_color=True, record=True)
    report.to_console(result, console)
    printed = console.export_text()
    markdown = report.to_markdown(result)

    for library in result.libraries:
        # `sentence` is the single source; the renderers only decorate it. Whole,
        # not a prefix: comparing up to the dash would reduce an import row to its
        # library name and assert nothing about the half that carries the meaning.
        line = libraries.sentence(library)
        assert line in printed, line
        assert line in markdown, line
