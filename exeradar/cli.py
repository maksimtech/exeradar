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

import contextlib
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import typer

if TYPE_CHECKING:
    from exeradar.law_checker import LawCheckResult


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
        with contextlib.suppress(ValueError, OSError):
            reconfigure(encoding="utf-8", errors="replace")

enable_utf8_output()


app = typer.Typer(help="Static analysis of Windows, macOS and Linux executables.")


def _version_callback(value: bool) -> None:
    if value:
        import exeradar  # read at call time, never a hardcoded copy

        typer.echo(f"ExeRadar {exeradar.__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Show the version and exit",
    ),
) -> None:
    pass


# IO_REPARSE_TAG_MOUNT_POINT. Written out because the stat module defines it on
# Windows only: referenced from there, batch raised AttributeError on Linux at the
# first subdirectory.
_JUNCTION_TAG = 0xA0000003


def _is_link(path: str) -> bool:
    """A symlink, or an NTFS junction, which is not one as far as islink knows.

    Read from the reparse tag rather than os.path.isjunction, which is 3.12 and
    later; the tag is what that function reads, and only Windows has one.
    """
    if os.path.islink(path):
        return True
    try:
        tag = getattr(os.lstat(path), "st_reparse_tag", 0)
    except OSError:
        return False
    return tag == _JUNCTION_TAG


def _files_under(root: Path) -> Iterator[Path]:
    """Every file below `root`, never entering a directory through a link.

    Path.rglob does not follow symlinks and does follow junctions: one pointing
    back at its own parent, which `mklink /J` makes without any privilege, put
    the same PE in the report 64 times, once per level until the path length
    ran out. A directory reached through a link is walked where it really is,
    if it is under `root` at all, or not at all.
    """
    for top, directories, files in os.walk(root):
        directories[:] = [name for name in directories if not _is_link(os.path.join(top, name))]
        for name in files:
            path = Path(top) / name
            if path.is_file():
                yield path


def _check_output(output: str) -> None:
    """Refuse an --output that cannot be honoured, before any work is done.

    The extension has to name a format, and the directory has to exist: a
    missing one used to surface as a FileNotFoundError traceback after the
    whole scan, which is the trade the extension check was there to avoid.
    """
    from exeradar import report

    try:
        report.format_for(output)
    except ValueError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    if not Path(output).parent.is_dir():
        typer.secho(f"no such directory for the report: {Path(output).parent}",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(2)


def _write_failed(output: str, error: OSError) -> typer.Exit:
    """A report that could not be written: said, with exit code 2, not a traceback.

    The directory was there when the run started; permissions, a full disk or a
    directory removed meanwhile only show at the write.
    """
    typer.secho(f"cannot write {output}: {error.strerror or error}", fg=typer.colors.RED, err=True)
    return typer.Exit(2)


def _say_what_the_cache_lacks(law: LawCheckResult, online: bool) -> None:
    """A provision cited without a hash, and how to get one.

    Offline over an empty cache is the first run of every installation: the
    report says "no text available" act by act, and this says, once, that
    --online is what fills the cache.
    """
    missing = [status.act.name for status in law.acts if status.source == "unavailable"]
    if missing and not online:
        typer.secho(
            f"no cached text for {', '.join(missing)}: cited without a hash; "
            "run again with --online to download the texts",
            fg=typer.colors.YELLOW, err=True,
        )


@app.command()
def analyze(
    path: str = typer.Argument(..., help="Executable to analyse"),
    output: str = typer.Option(None, "--output", "-o",
                               help="Write the report to a file; the extension picks the format"),
    tlp: str = typer.Option(
        None, "--tlp",
        help="Mark the written report with a FIRST TLP 2.0 label: clear, green, "
             "amber, amber+strict, red. Omitted, the report is unmarked.",
    ),
    online: bool = typer.Option(
        False, "--online",
        help="Download the texts of the provisions cited and refresh the local cache. "
             "Without it nothing is downloaded and the cache is cited.",
    ),
) -> None:
    """Analyse one executable."""
    from exeradar import report

    # Before the file is opened: a label the standard does not define is
    # answerable on its own, and reading a binary first would mean failing after
    # the work over a typo. The same reason `--output` is validated up here.
    from exeradar import tlp as tlp_mod
    from exeradar.scanner import scan

    try:
        label = tlp_mod.parse_optional(tlp)
    except tlp_mod.TlpError as error:
        typer.secho(str(error), fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None

    # Checked before the scan: refusing a filename after a minute of work
    # would be a poor trade, and the extension is knowable up front.
    if output:
        _check_output(output)

    result = scan(path)

    # The provisions the findings concern, for the "Provisions applied" section
    # README and ARCHITECTURE.md section 5 describe and nothing used to print.
    # Offline unless --online: analysing a file is not a reason to reach the
    # network, so the texts are cited from the local cache and downloaded only
    # when asked. A clean file cites nothing either way. Failing to cite is
    # said, and never costs the analysis that has already been done.
    law = None
    if not result.error:
        from exeradar import law_checker

        try:
            law = law_checker.check(result, offline=not online)
        except Exception as error:  # noqa: BLE001 - reported, never a traceback
            typer.secho(f"provisions not cited: {error}", fg=typer.colors.YELLOW, err=True)
        else:
            _say_what_the_cache_lacks(law, online)

    if output and not result.error:
        try:
            chosen = report.write(result, output, tlp_label=label, law=law)
        except OSError as error:
            raise _write_failed(output, error) from error
        typer.secho(f"{chosen} report written to {output}", fg=typer.colors.GREEN)
    else:
        report.to_console(result, law=law)

    if result.error:
        raise typer.Exit(1)


@app.command()
def batch(
    directory: str = typer.Argument(..., help="Directory to walk"),
    output: str = typer.Option(None, "--output", "-o",
                               help="Write one report for the run; the extension picks the format"),
    tlp: str = typer.Option(
        None, "--tlp",
        help="Mark the written report with a FIRST TLP 2.0 label: clear, green, "
             "amber, amber+strict, red. Omitted, the report is unmarked.",
    ),
) -> None:
    """Analyse every PE in a directory, recursively."""
    from exeradar import report

    # Before the file is opened: a label the standard does not define is
    # answerable on its own, and reading a binary first would mean failing after
    # the work over a typo. The same reason `--output` is validated up here.
    from exeradar import tlp as tlp_mod
    from exeradar.scanner import format_of, scan

    try:
        label = tlp_mod.parse_optional(tlp)
    except tlp_mod.TlpError as error:
        typer.secho(str(error), fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None

    root = Path(directory)
    if not root.is_dir():
        typer.secho(f"not a directory: {directory}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)

    # Both checks before the walk: a directory of binaries takes real time, and
    # refusing the filename afterwards would throw all of it away.
    if output:
        _check_output(output)

    # Sorted, so two runs over the same directory produce the same report and a
    # diff of the two means something.
    targets = sorted(p for p in _files_under(root) if format_of(p) == "PE")
    results = [scan(target) for target in targets]

    report.to_console_many(results)

    if output and results:
        try:
            chosen = report.write_many(results, output, tlp_label=label)
        except OSError as error:
            raise _write_failed(output, error) from error
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

    # 0 the file matches what was signed, 1 it does not, 2 it could not be
    # established. The third used to collapse into the second for an embedded
    # signature whose check did not conclude: a script reading the exit code was
    # told the signature was bad when the answer was that nobody knows.
    if state is SignatureState.CATALOG or (state is SignatureState.EMBEDDED and found.verified):
        raise typer.Exit(0)
    if state is SignatureState.UNKNOWN or found.verified is None:
        raise typer.Exit(2)
    raise typer.Exit(1)


@app.command()
def psirt(
    organisation: str = typer.Argument(..., help='Organisation name, e.g. "HP Inc."'),
    key: bool = typer.Option(
        False, "--key", help="Print only the PGP public key block, for piping into gpg --import."
    ),
) -> None:
    """Who answers for a vulnerability, from FIRST's member directory.

    Made to be used from a script, so the exit code carries the answer:

        0  one team, matched exactly on its name
        1  FIRST lists no member team by that name
        2  it could not be settled — the directory was unreachable, or nothing
           it returned matches the name exactly

    The third is the one that earns its keep. "Hewlett Packard" returns Hewlett
    Packard Enterprise, split off in 2015, and not HP Inc., whose name is on a
    250 G6; printing what came back would hand a script the address of the wrong
    company for an embargoed finding. Whatever the directory returned is printed
    and nothing is chosen — one inexact candidate is no more an answer than two.

    1 and 2 are not the same answer either: FIRST is a membership body and does
    not list every PSIRT, so "no member team" is a fact about the directory and
    sends a reader to the vendor's security.txt, while 2 says nobody got an
    answer at all.
    """
    from exeradar import first_teams

    try:
        resolution = first_teams.resolve(organisation)
    except Exception as error:  # noqa: BLE001 - reported, never a traceback
        typer.secho(f"could not ask FIRST: {error}", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(2) from error

    team = resolution.team
    if team is None:
        typer.secho(resolution.reason, fg=typer.colors.YELLOW, err=True)
        for candidate in resolution.candidates:
            typer.echo(f"  {candidate.host or candidate.name}  {candidate.email}")
        # Candidates mean the question has more than one answer; none means the
        # directory answered that it has no such member.
        raise typer.Exit(2 if resolution.candidates else 1)

    if key:
        # Nothing else on stdout: this is meant to be piped into gpg --import.
        if not team.pgp_key:
            typer.secho(
                f"{team.host or team.name} has no PGP key in the directory; "
                f"fingerprint on record: {team.pgp_fingerprint or 'none'}",
                fg=typer.colors.YELLOW,
                err=True,
            )
            raise typer.Exit(1)
        typer.echo(team.pgp_key)
        raise typer.Exit(0)

    typer.secho(team.full_name, bold=True)
    typer.echo(f"  organisation  {team.host}")
    typer.echo(f"  membership    {team.membership}" + (f", since {team.member_since}" if team.member_since else ""))
    typer.echo(f"  country       {team.country}")
    typer.echo(f"  report to     {team.email}")
    if team.website:
        typer.echo(f"  policy        {team.website}")
    if team.pgp_fingerprint:
        typer.echo(f"  pgp           {team.pgp_fingerprint}" + (f"  ({team.pgp_id})" if team.pgp_id else ""))
        typer.echo("                --key prints the block, for gpg --import")
    else:
        typer.echo("  pgp           none in the directory")
    if team.last_modified:
        # An entry from 2019 is still the authoritative one; its age is not a
        # reason to doubt it, and is a reason to read it as a record rather than
        # as something checked this morning.
        typer.echo(f"  entry dated   {team.last_modified}")
    raise typer.Exit(0)


if __name__ == "__main__":
    app()
