""""Unsigned" is a claim. A file that could not be read does not support it.

Section 3 of ARCHITECTURE.md is built around one distinction: UNSIGNED means both
paths ran and found nothing, UNKNOWN means a path could not run. It is applied
carefully to the platform — off Windows the catalog cannot be consulted, so
nothing is concluded — and not at all to the file. Two cases slip through:

- `MZ` followed by rubbish. LIEF returns None, so the embedded path never ran,
  and on Windows the catalog says "not signed" about a file it cannot identify
  either. The answer was UNSIGNED, with a CRA citation behind it.
- a cut-off download. LIEF is lenient enough to parse 512 bytes of a 104 KB
  binary, reports no signatures — the blob is past the end of the file — and the
  certificate table in the headers still says where it should have been. The
  answer was UNSIGNED, about a file that was signed.

The second is the one that happens by itself, to anyone whose download dropped.
Both are the same mistake exeradar names elsewhere: "bad" and "could not tell"
are different answers, which is why SignatureState has four members and not three.

So a PE that cannot be parsed, or whose own headers place the certificate table
beyond the end of the file, is UNKNOWN. Nothing is cited against it.
"""

from __future__ import annotations

from exeradar import law_checker, signature
from exeradar.models import ExeResult, SignatureState


def unreadable(tmp_path):
    """`MZ` and nothing that follows it means anything."""
    target = tmp_path / "rubbish.exe"
    target.write_bytes(b"MZ" + b"\x00" * 128)
    return target


# ── a file that cannot be parsed ────────────────────────────────────────────


def test_a_file_that_cannot_be_parsed_is_not_called_unsigned(tmp_path):
    found = signature.inspect(unreadable(tmp_path))

    assert found.state is SignatureState.UNKNOWN
    assert found.state is not SignatureState.UNSIGNED


def test_and_it_does_not_claim_the_signature_is_invalid_either(tmp_path):
    """verified=False says a signature was checked and failed."""
    assert signature.inspect(unreadable(tmp_path)).verified is None


def test_it_says_why_it_could_not_tell(tmp_path):
    detail = (signature.inspect(unreadable(tmp_path)).detail or "").lower()

    assert "read" in detail or "parse" in detail, detail


def test_nothing_is_cited_against_it(tmp_path):
    """An unsigned finding carries CRA Annex I Part I(2)(f) and three more
    provisions. Against a file nobody could open, that is an accusation drawn
    from a failure to look."""
    result = ExeResult(
        path=str(unreadable(tmp_path)), size=130, sha256="aa", format="PE",
        signature=signature.inspect(unreadable(tmp_path)),
    )

    assert "unsigned" not in law_checker.findings_of(result)


# ── an interrupted download ─────────────────────────────────────────────────


def test_a_truncated_binary_is_not_called_unsigned(truncated_pe_path):
    """It was signed. The bytes that prove it are simply not there."""
    found = signature.inspect(truncated_pe_path)

    assert found.state is SignatureState.UNKNOWN
    assert found.state is not SignatureState.UNSIGNED


def test_the_truncation_is_named(truncated_pe_path):
    detail = (signature.inspect(truncated_pe_path).detail or "").lower()

    assert "certificate table" in detail or "truncat" in detail, detail


def test_nothing_is_cited_against_a_truncated_binary(truncated_pe_path):
    result = ExeResult(
        path=str(truncated_pe_path), size=4096, sha256="aa", format="PE",
        signature=signature.inspect(truncated_pe_path),
    )

    assert law_checker.findings_of(result) == {}


# ── what must keep working ──────────────────────────────────────────────────


def test_the_intact_binary_is_still_read(signed_pe_path):
    found = signature.inspect(signed_pe_path)

    assert found.state is SignatureState.EMBEDDED
    assert found.signer


# A readable PE with no signature is still UNSIGNED on Windows, and UNKNOWN off
# it: that is the platform rule, and test_signature.py asserts it against the
# same `unsigned_pe_path` fixture. Not repeated here — one requirement, one test.


# ── the command ─────────────────────────────────────────────────────────────


def test_verify_exits_with_the_could_not_tell_code(tmp_path):
    """2, not 1: the caller has to be able to tell a failed check from a file
    that failed to be a file. A CI job that treats 1 as "reject" would have
    rejected this one for being unsigned."""
    from typer.testing import CliRunner

    from exeradar.cli import app

    outcome = CliRunner().invoke(app, ["verify", str(unreadable(tmp_path))])

    assert outcome.exit_code == 2, outcome.output
    assert "unknown" in outcome.output


def test_verify_does_not_print_unsigned_for_it(tmp_path):
    from typer.testing import CliRunner

    from exeradar.cli import app

    outcome = CliRunner().invoke(app, ["verify", str(unreadable(tmp_path))])

    assert "unsigned" not in outcome.output
