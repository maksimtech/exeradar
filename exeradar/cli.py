"""Command line.

The three commands of ARCHITECTURE.md section 1 are declared here as stubs.
Declared rather than deferred for two reasons: typer collapses a single command
into the root, so the help would not show a command name at all, and the shape
of the interface is a design decision that belongs with the design.
"""

from __future__ import annotations

import typer

from exeradar.formats import pe

app = typer.Typer(help="Static analysis of Windows, macOS and Linux executables.")


@app.command()
def analyze(
    path: str = typer.Argument(..., help="Executable to analyse"),
    output: str = typer.Option(None, "--output", "-o",
                               help="Write the report to a file; the extension picks the format"),
) -> None:
    """Analyse one executable."""
    from exeradar.scanner import scan

    result = scan(path)
    if result.error:
        typer.secho(f"{result.path}: {result.error}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    # Interim output. Rendering belongs in report.py, which will take this
    # result and produce console, JSON and Markdown from it; printing here
    # keeps the command runnable in the meantime and is meant to be deleted.
    categories: set[str] = set()
    for imported in result.imports:
        categories |= pe.categorise(imported.dll, imported.functions)

    print(f"{result.path}")
    print(f"  {result.format} {result.arch}, {result.size:,} bytes, built {result.built}")
    print(f"  sha256      {result.sha256}")
    print(f"  sections    {len(result.sections)}")
    print(f"  imports     {len(result.imports)} DLLs, "
          f"{sum(len(i.functions) for i in result.imports)} functions")
    print(f"  categories  {', '.join(sorted(categories)) or 'none claimed'}")
    print(f"  signature   {result.signature.state.value}"
          f" (verified={result.signature.verified})")
    if result.signature.signer:
        print(f"              {result.signature.signer}")
    if result.signature.timestamp:
        print(f"              signed {result.signature.timestamp}")
    print(f"  strings     {len(result.strings.urls)} urls, {len(result.strings.ips)} ips, "
          f"{len(result.strings.hosts)} hosts, {len(result.strings.paths)} paths")

    if output:
        typer.secho("--output needs report.py; not written", fg=typer.colors.YELLOW, err=True)


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
