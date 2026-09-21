"""Command line.

The three commands of ARCHITECTURE.md section 1 are declared here as stubs.
Declared rather than deferred for two reasons: typer collapses a single command
into the root, so the help would not show a command name at all, and the shape
of the interface is a design decision that belongs with the design.
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
    raise NotImplementedError


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
