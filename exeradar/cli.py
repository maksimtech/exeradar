"""Command line.

The three commands of ARCHITECTURE.md section 1 are declared here as stubs.
Declared rather than deferred for two reasons: typer collapses a single command
into the root, so the help would not show a command name at all, and the shape
of the interface is a design decision that belongs with the design.

Nothing is rendered here. The interim print that lived in `analyze` while
report.py was a stub is gone; the command now scans and hands the result to a
renderer.
"""

from __future__ import annotations

import typer
import sys


def enable_utf8_output() -> None:
    """Make stdout and stderr accept characters the console cannot encode.

    On Windows the console code page is cp1252, and Python encodes output with
    it: the first emoji — the one in this CLI's own help text — ended the
    program with UnicodeEncodeError before any command had run. It was never
    the command failing, only the printing of its output.

    errors="replace" rather than "strict": a glyph the terminal cannot show
    should come out as a question mark, never as a traceback.

    Streams that cannot be reconfigured are left alone. pytest's capture and
    anything wrapping a pipe are not TextIOWrapper, and replacing them would
    break whatever is reading them; a cosmetic setting is not worth raising
    over, so this gives up quietly.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if encoding == "utf8":
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass

enable_utf8_output()


app = typer.Typer(help="Static analysis of Windows, macOS and Linux executables.")


@app.command()
def analyze(
    path: str = typer.Argument(..., help="Executable to analyse"),
    output: str = typer.Option(None, "--output", "-o",
                               help="Write the report to a file; the extension picks the format"),
) -> None:
    """Analyse one executable."""
    from exeradar import report
    from exeradar.scanner import scan

    # Checked before the scan: refusing a filename after a minute of work
    # would be a poor trade, and the extension is knowable up front.
    if output:
        try:
            report.format_for(output)
        except ValueError as exc:
            typer.secho(str(exc), fg=typer.colors.RED, err=True)
            raise typer.Exit(2) from exc

    result = scan(path)

    if output and not result.error:
        chosen = report.write(result, output)
        typer.secho(f"{chosen} report written to {output}", fg=typer.colors.GREEN)
    else:
        report.to_console(result)

    if result.error:
        raise typer.Exit(1)


@app.command()
def batch(
    directory: str = typer.Argument(..., help="Directory to walk"),
    output: str = typer.Option(None, "--output", "-o",
                               help="Write one report for the run; the extension picks the format"),
) -> None:
    """Analyse every PE in a directory, recursively."""
    from pathlib import Path

    from exeradar import report
    from exeradar.scanner import format_of, scan

    root = Path(directory)
    if not root.is_dir():
        typer.secho(f"not a directory: {directory}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)

    # Both checks before the walk: a directory of binaries takes real time, and
    # refusing the filename afterwards would throw all of it away.
    if output:
        try:
            report.format_for(output)
        except ValueError as exc:
            typer.secho(str(exc), fg=typer.colors.RED, err=True)
            raise typer.Exit(2) from exc

    # Sorted, so two runs over the same directory produce the same report and a
    # diff of the two means something.
    targets = sorted(p for p in root.rglob("*") if p.is_file() and format_of(p) == "PE")
    results = [scan(target) for target in targets]

    report.to_console_many(results)

    if output and results:
        chosen = report.write_many(results, output)
        typer.secho(f"{chosen} report written to {output}", fg=typer.colors.GREEN)


@app.command()
def verify(
    path: str = typer.Argument(..., help="Executable to check"),
) -> None:
    """Report only the code signature, by the three paths of the architecture.

    Made to be a gate in a script, so the exit code carries the answer:

        0  signed, and the signature verifies
        1  not signed, or signed and the signature does not verify
        2  could not be determined: unreadable, not a PE, or no way to check here

    The third is the one that matters. Off Windows the catalog cannot be
    consulted, so a file with no embedded signature may be perfectly signed and
    this tool cannot tell; failing a build over that would be failing it over a
    missing capability rather than over the file.
    """
    from pathlib import Path

    from exeradar import report, signature
    from exeradar.models import SignatureState
    from exeradar.scanner import format_of

    target = Path(path)
    if not target.is_file():
        typer.secho(f"cannot read: {path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    if format_of(target) != "PE":
        typer.secho(f"not a PE binary: {path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)

    # Only the signature is read: no hashing, no imports, no strings.
    found = signature.inspect(target)
    state = found.state

    colour = {"embedded": "green", "catalog": "green",
              "unsigned": "red", "unknown": "yellow"}[state.value]
    typer.secho(state.value, fg=getattr(typer.colors, colour.upper()))
    typer.echo(report.signature_sentence(found))
    if found.signer:
        typer.echo(f"signer    {found.signer}")
    if found.timestamp:
        typer.echo(f"signed    {found.timestamp}")

    if state is SignatureState.CATALOG or (state is SignatureState.EMBEDDED and found.verified):
        raise typer.Exit(0)
    if state is SignatureState.UNKNOWN:
        raise typer.Exit(2)
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
