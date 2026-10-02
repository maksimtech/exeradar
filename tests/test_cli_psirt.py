"""`exeradar psirt` — the door onto FIRST's directory.

`first_teams.py` arrived as a library with no caller. This is the caller, and like
`verify` it is meant to be usable from a script, so the exit code carries the
answer:

    0  one team, matched exactly
    1  FIRST has no member team by that name — a fact about the directory
    2  it could not be settled: the directory was unreachable, or the name
       matches more than one organisation and this tool will not choose

The third code is the one that earns its keep. "hewlett" matches Hewlett Packard
Enterprise and HP Inc., and a command that printed the first would hand a script
the address of the company that was split off in 2015. Exiting 2 with both
candidates printed is the only honest answer, and `|| exit` still catches it.

`--key` exists for the next step after the lookup:

    exeradar psirt "HP Inc." --key | gpg --import
"""

from __future__ import annotations

import httpx
import pytest
from typer.testing import CliRunner

from exeradar import first_teams
from exeradar.cli import app

runner = CliRunner()

HP_INC = first_teams.Team(
    id="hp_inc-psrt",
    name="HP Inc. PSRT",
    full_name="HP Inc. Product Security Response Team",
    host="HP Inc.",
    membership="Full Member",
    country="US",
    email="hp-security-alert@hp.com",
    website="https://ssl.www8.hp.com/h41268/live/index.aspx?qid=25434",
    pgp_id="0xF46ECE7D08F8DDD9",
    pgp_fingerprint="E28D172B46A939287A7E9B2CF46ECE7D08F8DDD9",
    pgp_key="-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQ...\n-----END PGP PUBLIC KEY BLOCK-----",
    member_since="August 23, 2019",
    last_modified="Thu, 29 Aug 2019 21:31:54 GMT",
)

HPE = first_teams.Team(
    id="hewlett_packard_enterprise-hpe-psrt",
    name="HPE PSRT",
    full_name="Hewlett Packard Enterprise (HPE) PSRT",
    host="Hewlett Packard Enterprise",
    membership="Full Member",
    country="US",
    email="security-alert@hpe.com",
    pgp_fingerprint="413D5CAB4E965971FE3442ABBBBC7C69DCA3EC0E",
)


@pytest.fixture
def answering(monkeypatch):
    """Replace the lookup, so no test here reaches the network."""
    def install(resolution=None, *, error=None):
        def resolve(organisation, **kwargs):
            if error is not None:
                raise error
            return resolution
        monkeypatch.setattr(first_teams, "resolve", resolve)
    return install


def found(team):
    return first_teams.Resolution(team=team, candidates=[], reason=f"exact match on {team.host}")


# ── the answer ──────────────────────────────────────────────────────────────


def test_an_exact_match_prints_the_contact_and_exits_zero(answering):
    answering(found(HP_INC))

    outcome = runner.invoke(app, ["psirt", "HP Inc."])

    assert outcome.exit_code == 0, outcome.output
    assert "hp-security-alert@hp.com" in outcome.output
    assert "E28D172B46A939287A7E9B2CF46ECE7D08F8DDD9" in outcome.output
    assert "Full Member" in outcome.output
    assert "HP Inc. Product Security Response Team" in outcome.output


def test_the_output_says_when_the_entry_was_last_touched(answering):
    """A directory entry from 2019 is still the authoritative one, and a reader
    should see its age rather than assume it was checked this morning."""
    answering(found(HP_INC))

    outcome = runner.invoke(app, ["psirt", "HP Inc."])

    assert "August 23, 2019" in outcome.output or "29 Aug 2019" in outcome.output


# ── the refusal to choose ───────────────────────────────────────────────────


def test_two_candidates_exit_two_and_both_are_printed(answering):
    answering(first_teams.Resolution(
        team=None,
        candidates=[HPE, HP_INC],
        reason="no exact match for 'Hewlett Packard'; the directory returned "
               "Hewlett Packard Enterprise, HP Inc. Choose by name rather than "
               "letting the order choose.",
    ))

    outcome = runner.invoke(app, ["psirt", "Hewlett Packard"])

    assert outcome.exit_code == 2, outcome.output
    assert "Hewlett Packard Enterprise" in outcome.output
    assert "HP Inc." in outcome.output
    assert "security-alert@hpe.com" in outcome.output
    assert "hp-security-alert@hp.com" in outcome.output


def test_an_ambiguous_answer_never_reads_as_a_single_address(answering):
    """The failure this command exists to prevent: a script taking the last line
    of the output and sending an embargoed report there."""
    answering(first_teams.Resolution(
        team=None, candidates=[HPE, HP_INC], reason="no exact match"
    ))

    outcome = runner.invoke(app, ["psirt", "Hewlett Packard"])

    lines = [line for line in outcome.output.splitlines() if line.strip()]
    assert outcome.exit_code != 0
    assert "@" in lines[-1] or "exact" in lines[-1].lower()  # whatever it is, not one chosen address
    assert sum(1 for line in lines if "@" in line) == 2, outcome.output


# ── no member, and no answer ────────────────────────────────────────────────


def test_no_member_team_exits_one_and_points_somewhere_else(answering):
    answering(first_teams.Resolution(
        team=None,
        candidates=[],
        reason=("FIRST lists no member team matching 'Some Vendor Ltd'. FIRST is a "
                "membership body and does not list every PSIRT, so this is not a "
                "finding about the vendor: check its security.txt."),
    ))

    outcome = runner.invoke(app, ["psirt", "Some Vendor Ltd"])

    assert outcome.exit_code == 1, outcome.output
    assert "security.txt" in outcome.output
    assert "membership body" in outcome.output


def test_an_unreachable_directory_exits_two_and_not_one(answering):
    """1 would say the vendor has no team. 2 says nobody asked successfully."""
    answering(error=first_teams.FirstLookupError("FIRST team directory unreachable: boom"))

    outcome = runner.invoke(app, ["psirt", "HP Inc."])

    assert outcome.exit_code == 2, outcome.output
    assert "unreachable" in outcome.output.lower()
    assert outcome.exception is None or isinstance(outcome.exception, SystemExit)


def test_an_httpx_error_does_not_escape_as_a_traceback(answering):
    answering(error=httpx.ConnectError("no route"))

    outcome = runner.invoke(app, ["psirt", "HP Inc."])

    assert outcome.exit_code == 2
    assert "Traceback" not in outcome.output
    # Typer exits 2 on an unknown command too, so the code alone proves nothing:
    # this is the message only the command can have printed.
    assert "no route" in outcome.output
    assert "No such command" not in outcome.output


# ── --key, for the step after the lookup ────────────────────────────────────


def test_key_prints_the_block_and_nothing_else(answering):
    answering(found(HP_INC))

    outcome = runner.invoke(app, ["psirt", "HP Inc.", "--key"])

    assert outcome.exit_code == 0, outcome.output
    assert outcome.output.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    assert outcome.output.rstrip().endswith("-----END PGP PUBLIC KEY BLOCK-----")
    assert "hp-security-alert@hp.com" not in outcome.output      # pipeable into gpg


def test_key_without_a_key_exits_one_rather_than_printing_nothing(answering):
    answering(found(HPE))      # a team with a fingerprint and no key block

    outcome = runner.invoke(app, ["psirt", "Hewlett Packard Enterprise", "--key"])

    assert outcome.exit_code == 1
    assert "no pgp key" in outcome.output.lower()
    assert "413D5CAB4E965971FE3442ABBBBC7C69DCA3EC0E" in outcome.output  # verify it elsewhere


def test_key_refuses_on_an_ambiguous_name_instead_of_printing_one(answering):
    answering(first_teams.Resolution(team=None, candidates=[HPE, HP_INC], reason="no exact match"))

    outcome = runner.invoke(app, ["psirt", "Hewlett Packard", "--key"])

    assert outcome.exit_code == 2
    assert "BEGIN PGP" not in outcome.output
    # As above: without this the test passes against a command that does not exist.
    assert "No such command" not in outcome.output
    assert "exact" in outcome.output.lower()
