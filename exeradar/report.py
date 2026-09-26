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
from collections.abc import Iterable, Sequence
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.table import Table

from exeradar.formats import pe
from exeradar.models import ExeResult, Signature

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


def to_json(result: ExeResult) -> str:
    return json.dumps(_as_data(result), indent=2, ensure_ascii=False, sort_keys=False)


def to_json_many(results: Iterable[ExeResult]) -> str:
    """One array, same objects. A consumer parses one shape, not two."""
    return json.dumps([_as_data(r) for r in results], indent=2,
                      ensure_ascii=False, sort_keys=False)


def to_markdown(result: ExeResult) -> str:
    name = Path(result.path).name
    lines = [f"# {name}", ""]

    if result.error:
        lines += [f"**Could not analyse:** {result.error}", "", f"- SHA-256: `{result.sha256 or 'unknown'}`", ""]
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
        signature_sentence(result.signature),
        "",
    ]

    if result.signature.chain:
        leaf = result.signature.chain[0]
        lines += [
            f"- Signer: `{leaf.subject}`",
            f"- Issuer: `{leaf.issuer}`",
            f"- Valid: {leaf.valid_from} to {leaf.valid_to}",
        ]
    if result.signature.timestamp:
        lines.append(f"- Timestamped: {result.signature.timestamp}")
        if result.signature.timestamper:
            lines.append(f"- Authority: `{result.signature.timestamper}`")
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
        lines.append(f"- `{imported.dll}` ({len(imported.functions)}){suffix}")
    if len(result.imports) > _IMPORTS_SHOWN:
        lines.append(f"- …and {len(result.imports) - _IMPORTS_SHOWN} more")
    lines.append("")

    lines += ["## Strings", ""]
    buckets = (("URLs", result.strings.urls), ("IPs", result.strings.ips),
               ("Hosts", result.strings.hosts), ("Paths", result.strings.paths))
    if not any(values for _, values in buckets):
        lines += ["None found.", ""]
    else:
        for label, values in buckets:
            if values:
                lines.append(f"- **{label}:** " + ", ".join(f"`{v}`" for v in values[:10]))
                if len(values) > 10:
                    lines.append(f"  - …and {len(values) - 10} more")
        lines.append("")

    if result.sections:
        lines += ["## Sections", "", "| Name | Virtual | Raw | Entropy |", "| --- | ---: | ---: | ---: |"]
        for section in result.sections:
            lines.append(
                f"| `{section.name}` | {section.virtual_size:,} | "
                f"{section.raw_size:,} | {section.entropy:.2f} |"
            )
        lines.append("")

    return "\n".join(lines)


def to_console(result: ExeResult, console: Console | None = None) -> None:
    console = console or Console()

    if result.error:
        console.print(f"[red]{Path(result.path).name}: {result.error}[/red]")
        if result.sha256:
            console.print(f"  sha256 {result.sha256}")
        return

    console.print(f"[bold]{result.path}[/bold]")
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
    console.print(f"  {signature_sentence(result.signature)}")
    if signature.signer:
        console.print(f"  signer     {signature.signer}")
    if signature.timestamp:
        console.print(f"  signed     {signature.timestamp}")
    console.print()

    categories = categories_of(result)
    console.print(
        f"[bold]Imports[/bold] {len(result.imports)} libraries, "
        f"{sum(len(i.functions) for i in result.imports)} functions — "
        f"{', '.join(categories) if categories else 'no category claimed'}"
    )
    for imported in sorted(result.imports, key=lambda i: -len(i.functions))[:_IMPORTS_SHOWN]:
        marks = pe.categorise(imported.dll, imported.functions)
        suffix = f"  [cyan]{', '.join(sorted(marks))}[/cyan]" if marks else ""
        console.print(f"  {imported.dll:<34} {len(imported.functions):>4}{suffix}")
    if len(result.imports) > _IMPORTS_SHOWN:
        console.print(f"  [dim]…and {len(result.imports) - _IMPORTS_SHOWN} more[/dim]")
    console.print()

    found = result.strings
    console.print(
        f"[bold]Strings[/bold] {len(found.urls)} urls, {len(found.ips)} ips, "
        f"{len(found.hosts)} hosts, {len(found.paths)} paths"
    )
    for label, values in (("url", found.urls), ("ip", found.ips),
                          ("host", found.hosts), ("path", found.paths)):
        for value in values[:5]:
            console.print(f"  {label:<5} {value}")
    console.print()

    if result.sections:
        table = Table("section", "virtual", "raw", "entropy", title=None, box=None)
        for section in result.sections:
            entropy = f"{section.entropy:.2f}"
            # Above roughly 7.0 a section is packed, compressed or encrypted.
            table.add_row(
                section.name,
                f"{section.virtual_size:,}",
                f"{section.raw_size:,}",
                f"[yellow]{entropy}[/yellow]" if section.entropy > 7.0 else entropy,
            )
        console.print(table)


def to_markdown_many(results: Iterable[ExeResult]) -> str:
    return "\n".join(to_markdown(result) for result in results)


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
            state = f"[red]{result.error}[/red]"
        else:
            colour = {"embedded": "green", "catalog": "green",
                      "unsigned": "red", "unknown": "yellow"}[result.signature.state.value]
            state = f"[{colour}]{result.signature.state.value}[/{colour}]"
        count = len(result.findings)
        table.add_row(
            Path(result.path).name,
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
    flagged = sum(1 for r in results if r.findings)
    console.print(
        f"\n{len(results)} files, {signed} signed and verified, {flagged} with findings"
    )


def write(result: ExeResult, path: str | Path) -> str:
    """Render to the file the name asks for. Returns the format used."""
    chosen = format_for(path)
    text = to_json(result) if chosen == "json" else to_markdown(result)
    Path(path).write_text(text + "\n", encoding="utf-8")
    return chosen


def write_many(results: Sequence[ExeResult], path: str | Path) -> str:
    """Render a whole run to the file the name asks for. Returns the format."""
    chosen = format_for(path)
    text = to_json_many(results) if chosen == "json" else to_markdown_many(results)
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
        verdict = "valid" if signature.verified else "present but not valid"
        return f"Embedded Authenticode signature, {verdict}."
    if state == "catalog":
        return "Signed by catalog; the file carries no embedded signature."
    if state == "unsigned":
        return "No signature: neither embedded nor in a catalog."
    return signature.detail or "Signature could not be determined on this platform."
