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
    directory: str = typer.Argument(..., help="Directory of executables"),
    output: str = typer.Option(None, "--output", "-o", help="Directory for the reports"),
) -> None:
    """Analyse every executable in a directory."""
    raise NotImplementedError


@app.command()
def verify(
    path: str = typer.Argument(..., help="Executable to check"),
) -> None:
    """Report only the code signature, by the three paths of the architecture."""
    raise NotImplementedError


if __name__ == "__main__":
    app()
