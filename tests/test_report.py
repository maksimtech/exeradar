"""What report.py has to do with a result once something else has produced it.

Three renderings of one object, and the rule that holds across all of them: a
renderer reports, it does not decide. Anything it computes — the import
categories are the only such thing — is derived from what is already in the
result, never from the file.

The JSON output is the one with a contract. A person reading the console can
cope with a changed label; a pipeline parsing the JSON cannot, so the shape is
pinned here rather than left to whatever asdict() happens to produce.
"""

from __future__ import annotations

import copy
import json

import pytest
from rich.console import Console

from exeradar import report
from exeradar.models import (
    Certificate,
    ExeResult,
    Finding,
    Import,
    Library,
    Section,
    Signature,
    SignatureState,
    Strings,
)


@pytest.fixture
def result() -> ExeResult:
    """A filled-in result, so the renderers are tested on something complete."""
    return ExeResult(
        path="C:/tmp/sample.exe",
        size=106208,
        sha256="4942b86a",
        format="PE",
        arch="AMD64",
        built="2026-08-05 10:58:33 UTC",
        sections=[Section(name=".text", virtual_size=1000, raw_size=1024, entropy=6.28)],
        imports=[
            Import(dll="WS2_32.dll", functions=["socket", "connect"]),
            Import(dll="KERNEL32.dll", functions=["CreateProcessW"]),
        ],
        strings=Strings(urls=["https://example.com/a"], ips=["10.0.0.1"],
                        hosts=["example.org"], paths=["C:\\Windows\\Temp"]),
        signature=Signature(
            state=SignatureState.EMBEDDED,
            verified=True,
            signer="CN=Example",
            chain=[Certificate(subject="CN=Example", issuer="CN=Example CA",
                               valid_from="2026-01-01 00:00:00",
                               valid_to="2027-01-01 00:00:00",
                               serial="ab", algorithm="sha256", is_ca=False)],
            timestamp="2026-08-05 11:45:32 UTC",
            timestamper="CN=Example TSA",
            detail="embedded SHA_256",
        ),
    )


# --------------------------------------------------------------------------
# picking a format from the filename
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name, expected", [
    ("report.json", "json"),
    ("REPORT.JSON", "json"),
    ("notes.md", "markdown"),
    ("notes.markdown", "markdown"),
    ("out/deep/path/report.json", "json"),
])
def test_the_extension_picks_the_format(name, expected):
    assert report.format_for(name) == expected


@pytest.mark.parametrize("name", ["report.txt", "report", "report.xlsx", "report.json.bak"])
def test_an_unknown_extension_is_refused_not_guessed(name):
    """Writing Markdown into a file called .xlsx would be worse than refusing.

    The caller asked for something specific; silently producing something else
    is the kind of helpfulness that costs an hour to debug.
    """
    with pytest.raises(ValueError, match="(?i)extension|format"):
        report.format_for(name)


# --------------------------------------------------------------------------
# JSON — the output with a contract
# --------------------------------------------------------------------------


def test_json_is_valid_json(result):
    json.loads(report.to_json(result))


def test_json_carries_every_fact_from_the_result(result):
    data = json.loads(report.to_json(result))

    assert data["path"] == result.path
    assert data["size"] == result.size
    assert data["sha256"] == result.sha256
    assert data["format"] == "PE"
    assert data["arch"] == "AMD64"
    assert data["built"] == result.built
    assert data["sections"][0]["name"] == ".text"
    assert data["sections"][0]["entropy"] == pytest.approx(6.28)
    assert data["imports"][0]["dll"] == "WS2_32.dll"
    assert "socket" in data["imports"][0]["functions"]
    assert data["strings"]["urls"] == ["https://example.com/a"]


def test_the_signature_state_is_a_string_not_an_enum_repr(result):
    """A consumer matches on "embedded", not on "SignatureState.EMBEDDED"."""
    data = json.loads(report.to_json(result))
    assert data["signature"]["state"] == "embedded"
    assert data["signature"]["verified"] is True
    assert data["signature"]["chain"][0]["subject"] == "CN=Example"


def test_categories_are_derived_and_marked_as_such(result):
    """The only thing the renderer computes, and it computes it from imports."""
    data = json.loads(report.to_json(result))
    assert set(data["categories"]) == {"network", "process"}


def test_an_errored_result_still_produces_json(result):
    broken = ExeResult(path="x", size=0, sha256="", error="unrecognised format")
    data = json.loads(report.to_json(broken))
    assert data["error"] == "unrecognised format"
    assert data["format"] is None


def test_json_is_stable_across_calls(result):
    """Serialising twice gives the same bytes.

    What it guards is a clock or an address reaching the output: both would make
    the second call differ from the first. It used to be written as
    `to_json(result) == to_json(result)`, which does test that and reads like a
    tautology — the first call is kept in a name so the assertion says what it
    compares.
    """
    first = report.to_json(result)

    assert report.to_json(result) == first


def test_equal_results_serialise_identically(result):
    """The property the test above cannot reach: same data, same JSON.

    Two distinct objects holding the same facts. This is what catches an identity
    leaking into the output — an id(), a repr with an address, a path object's
    memory-dependent hash — because there two calls on one object agree with each
    other and disagree with an equal object.
    """
    twin = copy.deepcopy(result)

    assert twin is not result
    assert report.to_json(twin) == report.to_json(result)


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------


def test_markdown_leads_with_the_file(result):
    text = report.to_markdown(result)
    assert text.startswith("# ")
    assert "sample.exe" in text


def test_markdown_states_the_signature_in_words(result):
    text = report.to_markdown(result)
    assert "embedded" in text.lower()
    assert "CN=Example" in text
    assert result.signature.timestamp in text


def test_markdown_does_not_dump_every_imported_function(result):
    """A ticket wants the shape of the imports, not four hundred names."""
    text = report.to_markdown(result)
    assert "WS2_32.dll" in text
    assert text.count("\n") < 80


def test_markdown_says_so_when_there_is_nothing_to_say():
    empty = ExeResult(path="x.exe", size=1, sha256="aa", format="PE")
    text = report.to_markdown(empty)
    assert "none" in text.lower() or "no " in text.lower()


def _parsed(text: str) -> list:
    """The Markdown as markdown-it reads it (CommonMark, through Rich), inline
    tokens included."""
    from rich.markdown import Markdown

    return [child for token in Markdown(text).parsed for child in [token, *(token.children or [])]]


def _raw_html(text: str) -> list[str]:
    return [token.content for token in _parsed(text) if token.type in ("html_inline", "html_block")]


def test_markdown_carries_no_html_from_the_strings_of_the_binary(pe_with_a_string):
    """A path out of the binary with a backtick in it closed its code span, and
    the rest reached the ticket it was pasted into as raw HTML."""
    from exeradar.scanner import scan

    payload = rb"C:\y\`<img src=x onerror=alert(1)>`"
    result = scan(pe_with_a_string(payload))

    assert payload.decode() in result.strings.paths   # the premise: it was extracted
    assert _raw_html(report.to_markdown(result)) == []


def test_markdown_neutralises_markup_in_every_field_that_comes_from_the_binary():
    """Not only the strings: the signer, the DLL names, a library's evidence,
    the file name and the section names come out of the file too. None of them
    may produce HTML or a link, and a section named `a|b` must not add a column."""
    result = ExeResult(
        path="[x](http___evil.example).exe", size=1, sha256="ab", format="PE", arch="AMD64",
        signature=Signature(state=SignatureState.EMBEDDED, verified=True, signer="s",
                            chain=[Certificate(subject="CN=`<b>x</b>`", issuer="CN=i")]),
        imports=[Import(dll="k`<i>32</i>`.dll", functions=["f"])],
        libraries=[Library("zlib", "1.3.1", "build path", "C:\\b\\<img src=x>\\zlib-1.3.1")],
        sections=[Section("a|b", 1, 1, 1.0)],
    )

    text = report.to_markdown(result)

    assert _raw_html(text) == []
    assert [t for t in _parsed(text) if t.type in ("link_open", "image")] == []
    header = next(line for line in text.splitlines() if line.startswith("| Name"))
    row = next(line for line in text.splitlines() if "a" in line and line.startswith("| ") and "1.00" in line)
    assert row.replace("\\|", "").count("|") == header.count("|"), row


def _with_an_address_finding() -> ExeResult:
    from exeradar import signature

    return ExeResult(
        path="x.exe", size=1, sha256="ab", format="PE", arch="AMD64",
        signature=Signature(state=SignatureState.UNKNOWN, detail=signature.NOT_VERIFIABLE_HERE),
        strings=Strings(ips=["8.8.8.8"]),
        findings=[Finding(id="hardcoded_ip", severity="low", evidence="8.8.8.8")],
    )


def _shows_the_finding(text: str) -> bool:
    from exeradar.law_checker import FINDING_TITLES

    return "hardcoded_ip" in text or FINDING_TITLES["hardcoded_ip"] in text


def test_markdown_shows_the_findings():
    """ARCHITECTURE.md section 7 separates facts from findings, and the report
    carried only the facts: a finding the scan raised reached the JSON and
    nobody reading the Markdown."""
    assert _shows_the_finding(report.to_markdown(_with_an_address_finding()))


def _unsigned() -> ExeResult:
    return ExeResult(
        path="x.exe", size=1, sha256="ab", format="PE", arch="AMD64",
        signature=Signature(state=SignatureState.UNSIGNED, verified=False,
                            detail="no embedded signature and no catalog entry"),
        findings=[Finding(id="unsigned", severity="medium", evidence="no signature")],
    )


def _cited_offline(result: ExeResult, tmp_path):
    """What analyze hands the renderer, computed from an empty cache: no
    network, and citations without a hash rather than with an invented one."""
    from exeradar import law_checker
    from exeradar.law_cache import LawCache

    return law_checker.check(result, offline=True, cache=LawCache(tmp_path / "law_cache.json"))


def test_markdown_carries_the_provisions_and_the_notes_that_qualify_them(tmp_path):
    """The "Provisions applied" section README and ARCHITECTURE.md section 5
    describe, with the CRA note law_checker promises on "every report that cites
    it". Nothing called law_checker, so no report had either. The renderer is
    handed the result of the check, as `law` in section 5, and decides nothing."""
    from exeradar import law_checker

    result = _unsigned()

    text = report.to_markdown(result, law=_cited_offline(result, tmp_path))

    assert "## Provisions applied" in text
    assert law_checker.CRA_APPLICATION_NOTE in text
    assert f"Provision applied: {law_checker.CRA.name} Allegato I, Parte I(2)(f)" in text
    assert "SHA256: not available" in text


# --------------------------------------------------------------------------
# console
# --------------------------------------------------------------------------


def test_console_prints_the_essentials(result):
    console = Console(record=True, width=120)
    report.to_console(result, console=console)
    text = console.export_text()

    assert "sample.exe" in text
    assert "AMD64" in text
    assert "embedded" in text
    assert "WS2_32.dll" in text


def test_console_reports_an_error_without_pretending_to_have_results():
    broken = ExeResult(path="x.exe", size=0, sha256="", error="unrecognised format")
    console = Console(record=True, width=120)
    report.to_console(broken, console=console)
    text = console.export_text()

    assert "unrecognised format" in text
    assert "sections" not in text.lower()


def test_console_prints_a_section_name_that_looks_like_markup_as_it_is():
    """Eight bytes chosen by whoever built the PE. `[/x]` was handed to Rich as
    markup, and a closing tag with nothing open is a MarkupError: a hostile
    binary ended `analyze` with a traceback."""
    result = ExeResult(path="x.exe", size=1, sha256="ab", format="PE", arch="AMD64",
                       sections=[Section("[/x]", 1, 1, 1.0)])
    console = Console(record=True, width=200)

    report.to_console(result, console=console)

    assert "[/x]" in console.export_text()


def test_console_does_not_obey_valid_tags_in_the_data_of_the_binary():
    """A well-formed tag does not crash, it is obeyed: whoever writes the binary
    chooses the styles and the links. It is printed literally, in `analyze` and
    in the `batch` table — file name and error included."""
    result = ExeResult(
        path="[bold]x.exe", size=1, sha256="ab", format="PE", arch="AMD64",
        signature=Signature(state=SignatureState.EMBEDDED, verified=True,
                            signer="[bold red]Microsoft Corporation[/bold red]"),
        imports=[Import(dll="[link=http://evil.example]k32.dll", functions=["f"])],
        strings=Strings(paths=["C:\\[i]x[/i]"]),
    )
    broken = ExeResult(path="[u]y.exe", size=1, sha256="cd", error="not a PE file: [u]y.exe")
    console = Console(record=True, width=200)

    report.to_console(result, console=console)
    report.to_console(broken, console=console)
    report.to_console_many([result, broken], console)
    text = console.export_text()

    assert "[bold red]Microsoft Corporation[/bold red]" in text
    assert "[link=http://evil.example]k32.dll" in text
    assert "C:\\[i]x[/i]" in text
    assert "[bold]x.exe" in text
    assert "not a PE file: [u]y.exe" in text


def test_console_shows_the_findings():
    console = Console(record=True, width=200)

    report.to_console(_with_an_address_finding(), console=console)

    assert _shows_the_finding(console.export_text())


def test_console_ends_with_the_provisions_applied(tmp_path):
    """ARCHITECTURE.md section 5: 'console through Rich with a "Provisions
    applied" section at the end'."""
    from exeradar import law_checker

    result = _unsigned()
    console = Console(record=True, width=200)

    report.to_console(result, console=console, law=_cited_offline(result, tmp_path))
    text = " ".join(console.export_text().split())

    assert "Provisions applied" in text
    assert f"Provision applied: {law_checker.CRA.name} art. 13(1)" in text
    assert law_checker.CRA_APPLICATION_NOTE in text


# --------------------------------------------------------------------------
# writing to a file
# --------------------------------------------------------------------------


def test_write_produces_the_format_the_name_asks_for(result, tmp_path):
    target = tmp_path / "out.json"
    report.write(result, target)
    assert json.loads(target.read_text(encoding="utf-8"))["format"] == "PE"


def test_write_markdown(result, tmp_path):
    target = tmp_path / "out.md"
    report.write(result, target)
    assert target.read_text(encoding="utf-8").startswith("# ")


def test_write_refuses_an_unknown_extension(result, tmp_path):
    with pytest.raises(ValueError):
        report.write(result, tmp_path / "out.doc")


# --------------------------------------------------------------------------
# many results at once — what `batch` renders
# --------------------------------------------------------------------------


@pytest.fixture
def results(result) -> list[ExeResult]:
    """Three files: one clean, one with findings, one that could not be read."""
    unsigned = ExeResult(
        path="C:/tmp/other.exe", size=2048, sha256="ff0011223344556677",
        format="PE", arch="i386",
        signature=Signature(state=SignatureState.UNSIGNED, verified=False,
                            detail="no embedded signature and no catalog entry"),
        findings=[Finding(id="unsigned", severity="medium", evidence="no signature")],
    )
    broken = ExeResult(path="C:/tmp/notes.txt", size=10, sha256="aabb",
                       error="unrecognised format")
    return [result, unsigned, broken]


def test_json_for_many_is_an_array_of_the_same_objects(results):
    data = json.loads(report.to_json_many(results))

    assert isinstance(data, list)
    assert len(data) == 3
    assert data[0] == json.loads(report.to_json(results[0]))
    assert data[2]["error"] == "unrecognised format"


def test_markdown_for_many_keeps_one_section_per_file(results):
    text = report.to_markdown_many(results)

    assert text.count("\n# ") + text.startswith("# ") == 3
    assert "sample.exe" in text
    assert "other.exe" in text
    assert "unrecognised format" in text


def test_the_table_has_a_row_per_file(results):
    console = Console(record=True, width=120)
    report.to_console_many(results, console=console)
    text = console.export_text()

    assert "sample.exe" in text
    assert "other.exe" in text
    assert "notes.txt" in text


def test_the_table_shortens_the_hash_without_inventing_one(results):
    console = Console(record=True, width=120)
    report.to_console_many(results, console=console)
    text = console.export_text()

    assert results[1].sha256[:12] in text
    assert results[1].sha256 not in text


def test_the_table_states_the_signature_and_counts_the_findings(results):
    console = Console(record=True, width=120)
    report.to_console_many(results, console=console)
    text = console.export_text()

    assert "embedded" in text
    assert "unsigned" in text


def test_a_file_that_could_not_be_read_is_shown_and_not_dropped(results):
    """A batch that silently skips what it could not open is a batch that lies."""
    console = Console(record=True, width=120)
    report.to_console_many(results, console=console)
    text = console.export_text()

    assert "notes.txt" in text
    assert "unrecognised" in text or "error" in text.lower()


def test_the_table_survives_an_empty_run():
    console = Console(record=True, width=120)
    report.to_console_many([], console=console)
    assert console.export_text().strip()


def test_write_many_produces_an_array(results, tmp_path):
    target = tmp_path / "out.json"
    assert report.write_many(results, target) == "json"
    assert len(json.loads(target.read_text(encoding="utf-8"))) == 3


def test_write_many_markdown(results, tmp_path):
    target = tmp_path / "out.md"
    assert report.write_many(results, target) == "markdown"
    assert target.read_text(encoding="utf-8").startswith("# ")


def test_write_many_refuses_an_unknown_extension(results, tmp_path):
    with pytest.raises(ValueError):
        report.write_many(results, tmp_path / "out.doc")

