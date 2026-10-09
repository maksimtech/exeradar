"""Rendering: console, JSON, Markdown, from one result object.

A renderer reports, it does not decide. The only thing computed here is the
set of import categories, and that is derived from the imports already in the
result — nothing in this module reads the file.

Of the three, JSON is the one with a contract. A person reading the console
copes with a changed label; a pipeline parsing the JSON does not, so the shape
is written out explicitly rather than left to whatever `asdict` produces from
the current field names.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from exeradar import libraries
from exeradar.formats import pe
from exeradar.models import ExeResult, Signature
from exeradar.tlp import Label, banner

if TYPE_CHECKING:
    from exeradar.law_checker import LawCheckResult

_EXTENSIONS = {
    ".json": "json",
    ".md": "markdown",
    ".markdown": "markdown",
}

# Imports worth naming in a summary: the ones a category was claimed for, plus
# enough of the rest to show the shape.
_IMPORTS_SHOWN = 8

# Enough of a digest to tell two files apart at a glance and to paste into a
# search; the whole thing is in the JSON, where something will read it.
_HASH_SHOWN = 12

# The import column is at least this wide, and as wide as the longest name shown.
# It was exactly this wide: `api-ms-win-core-libraryloader-l1-2-0.dll` is 40
# characters, and on notepad.exe, cmd.exe and git.exe its count sat six places to
# the right of every other row's.
_IMPORT_COLUMN = 34


def format_for(path: str | Path) -> str:
    """The output format the filename asks for.

    Refuses rather than guesses. Writing Markdown into a file called .xlsx
    would be worse than saying no: the caller asked for something specific.
    """
    suffix = Path(path).suffix.lower()
    if suffix in _EXTENSIONS:
        return _EXTENSIONS[suffix]
    known = ", ".join(sorted(_EXTENSIONS))
    raise ValueError(f"cannot tell the format from '{Path(path).name}'; known extensions: {known}")


def categories_of(result: ExeResult) -> list[str]:
    """Which of the four categories the import table supports a claim for."""
    found: set[str] = set()
    for imported in result.imports:
        found |= pe.categorise(imported.dll, imported.functions)
    return sorted(found)


def _as_data(result: ExeResult) -> dict:
    data = asdict(result)
    data["signature"]["state"] = result.signature.state.value
    # Derived, not measured: everything else here came out of the file.
    data["categories"] = categories_of(result)
    return data


def _marked(data: dict, label: Label | None) -> dict:
    """The record with its distribution label, or exactly the record.

    A field and not a banner: JSON is read by a tool, and a marking inside a
    string would have to be parsed back out — a consumer that cannot see it cannot
    respect it. Absent rather than null when nothing was asked for, because
    `"tlp": null` and `"tlp": "TLP:CLEAR"` both say something, and nobody said it.
    """
    if label is None:
        return data
    return {"tlp": label.value, **data}


def to_json(result: ExeResult, tlp_label: Label | None = None) -> str:
    return json.dumps(_marked(_as_data(result), tlp_label), indent=2,
                      ensure_ascii=False, sort_keys=False)


def to_json_many(results: Iterable[ExeResult], tlp_label: Label | None = None) -> str:
    """One array, same objects. A consumer parses one shape, not two.

    The label goes on every object rather than on a wrapper: a batch report is one
    document, and a consumer reading a single row out of the array must still see
    the terms it came under.
    """
    return json.dumps([_marked(_as_data(r), tlp_label) for r in results], indent=2,
                      ensure_ascii=False, sort_keys=False)


def _markdown_banner(label: Label | None) -> list[str]:
    """The distribution block, above the heading, where a reader meets it."""
    if label is None:
        return []
    return [f"> {line}" for line in banner(label).splitlines()] + [""]


_SEVERITY_COLOURS = {"high": "red", "medium": "yellow", "low": "cyan"}


def _finding_title(finding_id: str) -> str:
    """The title law_checker gives a finding, or its id when it gives none.

    Imported here rather than at the top, as the scanner does: rendering a
    report should not pull in the law machinery and its HTTP client.
    """
    from exeradar.law_checker import FINDING_TITLES

    return FINDING_TITLES.get(finding_id, finding_id)


# Markdown is meant to be pasted into a ticket, where it is rendered, and most of
# what it reports was written by whoever built the binary. A string such as
# C:\y\`<img src=x onerror=alert(1)>` closed its code span and arrived as raw
# HTML. Two helpers, for the two places a value can stand.
_BACKTICKS = re.compile(r"`+")
_INERT = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;", "[": "&#91;", "]": "&#93;",
                        "\r": " ", "\n": " "})


def _code(value: str, *, cell: bool = False) -> str:
    """`value` as one code span, whatever it contains.

    The fence is one backtick longer than the longest run inside, which is the
    CommonMark rule, and padded when the value would otherwise touch it. In a
    table a pipe still ends the cell inside a code span, so there it is escaped.
    """
    value = value.replace("\r", " ").replace("\n", " ")
    if cell:
        value = value.replace("|", "\\|")
    fence = "`" * (max((len(run) for run in _BACKTICKS.findall(value)), default=0) + 1)
    if value[:1] in ("`", " ") or value[-1:] in ("`", " "):
        value = f" {value} "
    return f"{fence}{value}{fence}"


def _inert(text: str) -> str:
    """Text that renders as itself: no HTML, no link, no image, one line.

    Entities rather than backslashes, because a backslash already in the value
    would escape the escape; an entity cannot turn back into markup.
    """
    return text.translate(_INERT)


def to_markdown(result: ExeResult, tlp_label: Label | None = None,
                law: LawCheckResult | None = None) -> str:
    name = Path(result.path).name
    lines = [*_markdown_banner(tlp_label), f"# {_inert(name)}", ""]

    if result.error:
        lines += [f"**Could not analyse:** {_inert(result.error)}", "",
                  f"- SHA-256: `{result.sha256 or 'unknown'}`", ""]
        return "\n".join(lines)

    lines += [
        f"- **Format:** {result.format} {result.arch or ''}".rstrip(),
        f"- **Size:** {result.size:,} bytes",
        *(
            [f"- **Overlay:** {result.overlay:,} bytes past the last section, not read"]
            if result.overlay else []
        ),
        f"- **SHA-256:** `{result.sha256}`",
        f"- **Built:** {result.built or 'not stated'}",
        "",
        "## Signature",
        "",
        _inert(signature_sentence(result.signature)),
        "",
    ]

    if result.signature.chain:
        leaf = result.signature.chain[0]
        lines += [
            f"- Signer: {_code(leaf.subject)}",
            f"- Issuer: {_code(leaf.issuer)}",
            f"- Valid: {leaf.valid_from} to {leaf.valid_to}",
        ]
    if result.signature.timestamp:
        lines.append(f"- Timestamped: {_inert(result.signature.timestamp)}")
        if result.signature.timestamper:
            lines.append(f"- Authority: {_code(result.signature.timestamper)}")
    lines.append("")

    categories = categories_of(result)
    lines += [
        "## Imports",
        "",
        f"{len(result.imports)} libraries, "
        f"{sum(len(i.functions) for i in result.imports)} functions.",
        "",
        f"Categories: {', '.join(categories) if categories else 'none claimed'}",
        "",
    ]
    for imported in sorted(result.imports, key=lambda i: -len(i.functions))[:_IMPORTS_SHOWN]:
        marks = pe.categorise(imported.dll, imported.functions)
        suffix = f" — {', '.join(sorted(marks))}" if marks else ""
        lines.append(f"- {_code(imported.dll)} ({len(imported.functions)}){suffix}")
    if len(result.imports) > _IMPORTS_SHOWN:
        lines.append(f"- …and {len(result.imports) - _IMPORTS_SHOWN} more")
    lines.append("")

    lines += ["## Libraries", "", f"_{libraries.CAVEAT}_", ""]
    if result.libraries:
        lines += [f"- {_inert(libraries.sentence(library))}" for library in result.libraries]
    else:
        lines.append("None stated.")
    lines.append("")

    lines += ["## Strings", ""]
    buckets = (("URLs", result.strings.urls), ("IPs", result.strings.ips),
               ("Hosts", result.strings.hosts), ("Paths", result.strings.paths))
    if not any(values for _, values in buckets):
        lines += ["None found.", ""]
    else:
        for label, values in buckets:
            if values:
                lines.append(f"- **{label}:** " + ", ".join(_code(v) for v in values[:10]))
                if len(values) > 10:
                    lines.append(f"  - …and {len(values) - 10} more")
        lines.append("")

    if result.sections:
        lines += ["## Sections", "", "| Name | Virtual | Raw | Entropy |", "| --- | ---: | ---: | ---: |"]
        for section in result.sections:
            lines.append(
                f"| {_code(section.name, cell=True)} | {section.virtual_size:,} | "
                f"{section.raw_size:,} | {section.entropy:.2f} |"
            )
        lines.append("")

    # The second register of ARCHITECTURE.md section 7. Computed by the scanner
    # and, until this section existed, visible only in the JSON and as a count
    # in `batch`: a `signature_invalid` of severity high never reached a reader
    # of `analyze` or of the Markdown pasted into a ticket.
    lines += ["## Findings", ""]
    if result.findings:
        lines += [
            f"- **{finding.severity}** {_finding_title(finding.id)} (`{finding.id}`): {_inert(finding.evidence)}"
            for finding in result.findings
        ]
    else:
        lines.append("None raised.")
    lines.append("")

    if law is not None:
        lines += _markdown_provisions(law)

    return "\n".join(lines)


def _law_remarks(law: LawCheckResult) -> list[str]:
    """What a reader needs beside the citations: where each text came from,
    which wording changed since the last run, and law_checker's notes.

    A citation from the cache, or without a hash, has to say so: "SHA256: not
    available" alone reads like a defect of the act rather than of the network.
    """
    remarks = []
    for status in law.acts:
        if status.source == "cache":
            remarks.append(f"{status.act.name}: cited from the local cache ({status.error})")
        elif status.source == "unavailable":
            remarks.append(f"{status.act.name}: no text available, cited without a hash ({status.error})")
    remarks += [
        f"{provision}: the text changed since the last run (previous SHA-256 {previous})"
        for provision, previous in law.changed.items()
    ]
    return remarks + law.notes


def _markdown_provisions(law: LawCheckResult) -> list[str]:
    """The section ARCHITECTURE.md section 5 promised and nothing printed."""
    from exeradar.law_checker import format_citation

    if not law.citations and not law.notes:
        return []
    lines = ["## Provisions applied", ""]
    for citation in law.citations:
        first, *rest = format_citation(citation).splitlines()
        lines.append(f"- {first} (`{citation.finding}`)")
        lines += [f"  - {line}" for line in rest]
    remarks = _law_remarks(law)
    if remarks:
        lines += ["", "Notes:", ""] + [f"- {_inert(remark)}" for remark in remarks]
    lines.append("")
    return lines


def to_console(result: ExeResult, console: Console | None = None,
               law: LawCheckResult | None = None) -> None:
    """The human report.

    Everything that came out of the file — its name, strings, section and DLL
    names, the signer — goes through `escape`. Rich reads `[...]` as markup, so
    a string such as `http://evil.example/[/x]` ended `analyze` with a
    MarkupError, and a well-formed tag was obeyed: whoever built the binary chose
    the styles and links of the report about it.
    """
    console = console or Console()

    if result.error:
        console.print(f"[red]{escape(f'{Path(result.path).name}: {result.error}')}[/red]")
        if result.sha256:
            console.print(f"  sha256 {result.sha256}")
        return

    console.print(f"[bold]{escape(result.path)}[/bold]")
    console.print(
        f"  {result.format} {result.arch}, {result.size:,} bytes, "
        f"built {result.built or 'not stated'}"
    )
    console.print(f"  sha256 [dim]{result.sha256}[/dim]")
    if result.overlay:
        # Said rather than skipped quietly. On a self-extracting installer this
        # is most of the file, and a reader who does not know it was left out
        # will read "no hosts" as a fact about the program.
        console.print(
            f"  [dim]overlay {result.overlay:,} bytes past the last section, "
            f"not read for strings[/dim]"
        )
    console.print()

    signature = result.signature
    colour = {"embedded": "green", "catalog": "green",
              "unsigned": "red", "unknown": "yellow"}[signature.state.value]
    console.print(f"[bold]Signature[/bold] [{colour}]{signature.state.value}[/{colour}]")
    console.print(f"  {escape(signature_sentence(result.signature))}")
    if signature.signer:
        console.print(f"  signer     {escape(signature.signer)}")
    if signature.timestamp:
        console.print(f"  signed     {escape(signature.timestamp)}")
    console.print()

    categories = categories_of(result)
    console.print(
        f"[bold]Imports[/bold] {len(result.imports)} libraries, "
        f"{sum(len(i.functions) for i in result.imports)} functions — "
        f"{', '.join(categories) if categories else 'no category claimed'}"
    )
    shown = sorted(result.imports, key=lambda i: -len(i.functions))[:_IMPORTS_SHOWN]
    width = max([_IMPORT_COLUMN, *(len(imported.dll) for imported in shown)])
    for imported in shown:
        marks = pe.categorise(imported.dll, imported.functions)
        suffix = f"  [cyan]{', '.join(sorted(marks))}[/cyan]" if marks else ""
        console.print(f"  {escape(f'{imported.dll:<{width}}')} {len(imported.functions):>4}{suffix}")
    if len(result.imports) > _IMPORTS_SHOWN:
        console.print(f"  [dim]…and {len(result.imports) - _IMPORTS_SHOWN} more[/dim]")
    console.print()

    console.print(f"[bold]Libraries[/bold] {len(result.libraries) or 'none stated'}")
    for library in result.libraries:
        console.print(f"  {escape(libraries.sentence(library))}")
    # Printed whether or not there are rows: an empty list is the case most often
    # misread, and a short list is misread the same way.
    console.print(f"  [dim]{libraries.CAVEAT}[/dim]")
    console.print()

    found = result.strings
    console.print(
        f"[bold]Strings[/bold] {len(found.urls)} urls, {len(found.ips)} ips, "
        f"{len(found.hosts)} hosts, {len(found.paths)} paths"
    )
    for label, values in (("url", found.urls), ("ip", found.ips),
                          ("host", found.hosts), ("path", found.paths)):
        for value in values[:5]:
            console.print(f"  {label:<5} {escape(value)}")
    console.print()

    if result.sections:
        table = Table("section", "virtual", "raw", "entropy", title=None, box=None)
        for section in result.sections:
            entropy = f"{section.entropy:.2f}"
            # Above roughly 7.0 a section is packed, compressed or encrypted.
            table.add_row(
                escape(section.name),
                f"{section.virtual_size:,}",
                f"{section.raw_size:,}",
                f"[yellow]{entropy}[/yellow]" if section.entropy > 7.0 else entropy,
            )
        console.print(table)
        console.print()

    console.print(f"[bold]Findings[/bold] {len(result.findings) or 'none raised'}")
    for finding in result.findings:
        colour = _SEVERITY_COLOURS.get(finding.severity, "white")
        console.print(
            f"  [{colour}]{finding.severity:<6}[/{colour}] {_finding_title(finding.id)} "
            f"({finding.id}): {escape(finding.evidence)}"
        )

    if law is not None and (law.citations or law.notes):
        from exeradar.law_checker import format_citation

        console.print()
        console.print("[bold]Provisions applied[/bold]")
        for citation in law.citations:
            first, *rest = format_citation(citation).splitlines()
            console.print(f"  {escape(first)}  [dim]({citation.finding})[/dim]")
            for line in rest:
                console.print(f"    {escape(line)}")
        for remark in _law_remarks(law):
            console.print(f"  [dim]note[/dim]  {escape(remark)}")


def to_markdown_many(results: Iterable[ExeResult],
                     tlp_label: Label | None = None) -> str:
    """One document, so the marking appears once at the top of it.

    Not once per file: a batch report is a single thing a person reads and
    forwards, and repeating the block between every heading would train the eye to
    skip it. The JSON form is the opposite — a consumer can read one object out of
    the array, so there the label is on each.
    """
    body = "\n".join(to_markdown(result) for result in results)
    return "\n".join([*_markdown_banner(tlp_label), body])


def to_console_many(results: Sequence[ExeResult], console: Console | None = None) -> None:
    """One row per file: the summary `batch` exists to produce.

    A file that could not be parsed keeps its row and shows why. Dropping it
    would make the count agree with nothing, and the question a batch answers
    is "what is in this directory", not "what went well".
    """
    console = console or Console()

    if not results:
        console.print("[dim]no PE files found[/dim]")
        return

    table = Table("file", "sha256", "signature", "findings", box=None)
    for result in results:
        if result.error:
            state = f"[red]{escape(result.error)}[/red]"
        else:
            colour = {"embedded": "green", "catalog": "green",
                      "unsigned": "red", "unknown": "yellow"}[result.signature.state.value]
            state = f"[{colour}]{result.signature.state.value}[/{colour}]"
        count = len(result.findings)
        table.add_row(
            escape(Path(result.path).name),
            result.sha256[:_HASH_SHOWN] if result.sha256 else "-",
            state,
            f"[yellow]{count}[/yellow]" if count else "0",
        )
    console.print(table)

    signed = sum(
        1 for r in results
        if not r.error and r.signature.state.value in ("embedded", "catalog")
        and r.signature.verified
    )
    # "signed and verified" read as "from a publisher this machine trusts", which
    # is not what was measured: the file matches what was signed, by whoever
    # signed it. No certificate store is consulted.
    flagged = sum(1 for r in results if r.findings)
    console.print(
        f"\n{len(results)} files, {signed} matching their signature, {flagged} with findings"
    )


def write(result: ExeResult, path: str | Path, tlp_label: Label | None = None,
          law: LawCheckResult | None = None) -> str:
    """Render to the file the name asks for. Returns the format used.

    `law` reaches the Markdown only. The JSON shape is a contract and the
    citations are not part of it yet; the findings they derive from are.
    """
    chosen = format_for(path)
    text = (to_json(result, tlp_label) if chosen == "json"
            else to_markdown(result, tlp_label, law))
    Path(path).write_text(text + "\n", encoding="utf-8")
    return chosen


def write_many(results: Sequence[ExeResult], path: str | Path,
               tlp_label: Label | None = None) -> str:
    """Render a whole run to the file the name asks for. Returns the format."""
    chosen = format_for(path)
    text = (to_json_many(results, tlp_label) if chosen == "json"
            else to_markdown_many(results, tlp_label))
    Path(path).write_text(text + "\n", encoding="utf-8")
    return chosen


def signature_sentence(signature: Signature) -> str:
    """One line that does not overstate what was checked.

    The difference between "unsigned" and "unknown" is the whole reason the
    signature module has three paths, so it has to survive into the report.

    Takes the signature rather than the whole result, because `verify` has
    nothing else: it reads the signature and stops.
    """
    state = signature.state.value

    if state == "embedded":
        # Three answers, not two. `not signature.verified` made "the check did
        # not conclude" read as "present but not valid", which is an accusation
        # where there was a limitation — and the limitation is usually ours: an
        # algorithm LIEF does not implement, a certificate the blob does not
        # carry, a validity window that does not cover today.
        #
        # "the file matches what was signed" and not "valid": no trust store is
        # consulted anywhere in this tool, so a self-signed certificate gets the
        # same sentence as a commercial one.
        if signature.verified is True:
            return "Embedded Authenticode signature; the file matches what was signed."
        if signature.verified is False:
            return (
                "Embedded Authenticode signature, and the file does not match what was "
                f"signed ({', '.join(signature.verification) or 'no reason reported'})."
            )
        return (
            "Embedded Authenticode signature, not checked to a conclusion "
            f"({', '.join(signature.verification) or 'no reason reported'})."
        )
    if state == "catalog":
        return "Signed by catalog; the file carries no embedded signature."
    if state == "unsigned":
        return "No signature: neither embedded nor in a catalog."
    return signature.detail or "Signature could not be determined on this platform."
