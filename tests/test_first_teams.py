"""FIRST's member directory: who a vulnerability is reported to.

CVE names a flaw; FIRST is the body that says who answers for it. Its directory
at api.first.org/data/v1/teams is public and carries, per team, the verified
contact and the PGP key to encrypt to — which is exactly what a disclosure needs
and what is currently found by hand.

The rule this module exists to hold is the one the Radar keep relearning: two
things that look like one are not one. Searching the directory for "hewlett"
returns **Hewlett Packard Enterprise**, the company that was split off in 2015,
and not HP Inc., whose name is on a 250 G6. Both are FIRST full members, with
different addresses:

    HP Inc. PSRT   hp-security-alert@hp.com     0xF46ECE7D08F8DDD9
    HPE PSRT       security-alert@hpe.com       (a different key)

A module that picked the first row for you would send an embargoed BIOS finding
to the wrong company. So `search` returns every candidate and `resolve` refuses
to choose unless the match is exact.

The second rule is the collectors' rule: an empty answer must never mean "I could
not ask". No match is a fact about *the directory* — FIRST lists its members, not
every PSIRT in existence — and a timeout is not a fact about anybody.

The payloads below are trimmed copies of what the live API returned on
2026-10-02.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest

from exeradar import first_teams
from exeradar.first_teams import FirstLookupError, Team

FIXTURES = Path(__file__).parent / "fixtures"

HP_INC = {
    "id": "hp_inc-psrt",
    "team": "HP Inc. PSRT",
    "team-full": "HP Inc. Product Security Response Team",
    "membership": "Full Member",
    "host": "HP Inc.",
    "country": "US",
    "email": "hp-security-alert@hp.com",
    "website": "https://ssl.www8.hp.com/h41268/live/index.aspx?qid=25434",
    "pgp-id": "0xF46ECE7D08F8DDD9",
    "pgp-fingerprint": "E28D172B46A939287A7E9B2CF46ECE7D08F8DDD9",
    "pgp-key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQ...\n-----END PGP PUBLIC KEY BLOCK-----",
    "member-since": "August 23, 2019",
    "last-modified": "Thu, 29 Aug 2019 21:31:54 GMT",
}

HPE = {
    "id": "hewlett_packard_enterprise-hpe-psrt",
    "team": "HPE PSRT",
    "team-full": "Hewlett Packard Enterprise (HPE) PSRT",
    "membership": "Full Member",
    "host": "Hewlett Packard Enterprise",
    "country": "US",
    "email": "security-alert@hpe.com",
    "pgp-fingerprint": "413D5CAB4E965971FE3442ABBBBC7C69DCA3EC0E",
}


class _Response:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class _FakeClient:
    """Stands in for httpx.Client, recording what was asked."""

    def __init__(self, response):
        self._response = response
        self.calls: list[tuple[str, dict]] = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def answering(*teams, status="OK", status_code=200, http=200):
    payload = {
        "status": status,
        "status-code": status_code,
        "version": "1.0",
        "access": "public",
        "total": len(teams),
        "data": list(teams),
    }
    return _FakeClient(_Response(payload, status_code=http))


# ── what a team is ──────────────────────────────────────────────────────────


def test_a_team_carries_the_contact_and_the_key_to_encrypt_to():
    client = answering(HP_INC)

    found = first_teams.search("hp inc", client=client)

    assert len(found) == 1
    team = found[0]
    assert isinstance(team, Team)
    assert team.id == "hp_inc-psrt"
    assert team.host == "HP Inc."
    assert team.email == "hp-security-alert@hp.com"
    assert team.membership == "Full Member"
    assert team.country == "US"
    assert team.pgp_fingerprint == "E28D172B46A939287A7E9B2CF46ECE7D08F8DDD9"
    assert team.pgp_key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    assert team.last_modified == "Thu, 29 Aug 2019 21:31:54 GMT"


def test_the_query_reaches_the_api_as_a_query_and_not_in_the_path():
    client = answering(HP_INC)

    first_teams.search("hp inc", client=client)

    url, kwargs = client.calls[0]
    assert url == first_teams.TEAMS_URL
    assert kwargs["params"]["q"] == "hp inc"
    assert "User-Agent" in kwargs["headers"]


def test_a_team_without_a_key_says_so_with_none_and_not_with_an_empty_string():
    """An empty string reads as "the directory has a key and it is blank"."""
    client = answering({k: v for k, v in HP_INC.items() if not k.startswith("pgp")})

    team = first_teams.search("hp inc", client=client)[0]

    assert team.pgp_fingerprint is None
    assert team.pgp_key is None
    assert team.email == "hp-security-alert@hp.com"      # the rest survives


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("E28D 172B 46A9 3928 7A7E  9B2C F46E CE7D 08F8 DDD9", "E28D172B46A939287A7E9B2CF46ECE7D08F8DDD9"),
        ("e28d172b46a939287a7e9b2cf46ece7d08f8ddd9", "E28D172B46A939287A7E9B2CF46ECE7D08F8DDD9"),
    ],
)
def test_a_fingerprint_is_normalised_because_it_is_what_a_key_is_checked_against(raw, expected):
    client = answering({**HP_INC, "pgp-fingerprint": raw})

    assert first_teams.search("x", client=client)[0].pgp_fingerprint == expected


@pytest.mark.parametrize("raw", ["DEADBEEF", "not a fingerprint", "ZZZZ172B46A939287A7E9B2CF46ECE7D08F8DDD9"])
def test_a_fingerprint_that_is_not_one_is_dropped_rather_than_passed_on(raw):
    """Forty hex characters or nothing. A malformed fingerprint offered as a
    fingerprint is worse than none: it is what somebody verifies a key against."""
    client = answering({**HP_INC, "pgp-fingerprint": raw})

    team = first_teams.search("x", client=client)[0]

    assert team.pgp_fingerprint is None
    assert team.email == "hp-security-alert@hp.com"


# ── the rule: two organisations are not one ─────────────────────────────────


def test_a_search_returns_every_candidate_and_chooses_none():
    client = answering(HPE, HP_INC)

    found = first_teams.search("hewlett", client=client)

    assert [team.host for team in found] == ["Hewlett Packard Enterprise", "HP Inc."]


def test_resolve_picks_the_exact_organisation_and_ignores_the_near_one():
    client = answering(HPE, HP_INC)

    resolution = first_teams.resolve("HP Inc.", client=client)

    assert resolution.team is not None
    assert resolution.team.email == "hp-security-alert@hp.com"
    assert resolution.candidates == []


def test_resolve_refuses_to_guess_when_nothing_matches_exactly():
    """"hewlett" matches HPE and HP Inc. and neither is what was asked for.

    Returning the first row would have sent the 250 G6 finding to the company
    that was split off in 2015. The candidates come back so a person can choose.
    """
    client = answering(HPE, HP_INC)

    resolution = first_teams.resolve("Hewlett Packard", client=client)

    assert resolution.team is None
    assert [team.host for team in resolution.candidates] == [
        "Hewlett Packard Enterprise", "HP Inc."
    ]
    assert "exact" in resolution.reason.lower()


def _replaying(recording: Path, *, query: str) -> httpx.Client:
    """A real httpx client whose transport answers with a recorded response.

    The module builds the request and httpx sends it; only the socket is
    replaced, by the bytes the live API returned, and only for the request that
    was recorded — any other is a failure of the test, not an answer.
    """
    body = recording.read_bytes()

    def answer(request: httpx.Request) -> httpx.Response:
        asked = (str(request.url.copy_with(query=None)), request.url.params.get("q"))
        assert asked == (first_teams.TEAMS_URL, query), request.url
        return httpx.Response(200, content=body, headers={"content-type": "application/json; charset=utf-8"})

    return httpx.Client(transport=httpx.MockTransport(answer))


def test_resolve_does_not_choose_between_two_exact_matches():
    """The module never chooses between two organisations, nor between two teams
    of one: an organisation can have more than one member team, with different
    addresses and keys, and the first in the response was returned.

    "EY" is such a name in the directory: the team called EY, hosted by Ernst &
    Young LLP, and EY CSIRT, hosted by EY. tests/fixtures/first_teams_ey.json is
    the body api.first.org answered on 2026-10-07 to the request `search` makes
    for it, `?q=EY&limit=20`, saved as it came.
    """
    with _replaying(FIXTURES / "first_teams_ey.json", query="EY") as client:
        resolution = first_teams.resolve("EY", client=client)

    assert resolution.team is None
    assert {team.id for team in resolution.candidates} == {"ey", "ey_csirt"}
    assert len({team.email for team in resolution.candidates}) == 2


def test_resolve_matches_the_full_team_name_too_and_is_case_insensitive():
    client = answering(HP_INC)

    assert first_teams.resolve("hp inc. product security response team", client=client).team
    assert first_teams.resolve("hp inc.", client=client).team


# ── the rule: an empty answer is not an answer about the vendor ─────────────


def test_no_member_team_is_a_fact_about_the_directory_and_not_about_the_vendor():
    client = answering()

    resolution = first_teams.resolve("Some Vendor Ltd", client=client)

    assert resolution.team is None
    assert resolution.candidates == []
    assert "member" in resolution.reason.lower()
    assert "not" in resolution.reason.lower()      # FIRST lists members, not every PSIRT


def test_a_network_failure_raises_instead_of_reading_as_no_team():
    import httpx

    client = _FakeClient(httpx.ConnectError("boom"))

    with pytest.raises(FirstLookupError) as error:
        first_teams.search("hp inc", client=client)

    assert "unreachable" in str(error.value).lower()


def test_an_http_error_raises_instead_of_reading_as_no_team():
    client = answering(HP_INC, http=503)

    with pytest.raises(FirstLookupError) as error:
        first_teams.search("hp inc", client=client)

    assert "503" in str(error.value)


def test_a_payload_that_does_not_say_ok_is_refused_rather_than_read():
    """status 200 with status "error" in the body: the data key may still be
    there, and reading it would turn a refusal into an answer."""
    client = answering(HP_INC, status="error", status_code=400)

    with pytest.raises(FirstLookupError):
        first_teams.search("hp inc", client=client)


def test_a_row_without_an_email_is_dropped_because_it_answers_nothing():
    """The point of a lookup is somewhere to send a report."""
    client = answering({k: v for k, v in HP_INC.items() if k != "email"}, HPE)

    found = first_teams.search("hewlett", client=client)

    assert [team.host for team in found] == ["Hewlett Packard Enterprise"]


# ── against the live directory, when asked ──────────────────────────────────


@pytest.mark.skipif(
    os.environ.get("EXERADAR_LIVE") != "1",
    reason="live FIRST lookup; set EXERADAR_LIVE=1 to run it",
)
def test_the_live_directory_still_answers_the_way_this_parser_reads_it():
    """The fixtures above are copies, and a copy cannot notice a renamed field.

    FIRST could rename `pgp-fingerprint` tomorrow and every test here would stay
    green while the letters went out without a key. This is the one test that
    would see it, and it is the HP case because that is the one in hand.
    """
    resolution = first_teams.resolve("HP Inc.")

    assert resolution.team is not None, resolution.reason
    assert resolution.team.email == "hp-security-alert@hp.com"
    assert resolution.team.pgp_fingerprint == "E28D172B46A939287A7E9B2CF46ECE7D08F8DDD9"
    assert resolution.team.membership == "Full Member"

    # And the near miss is still a near miss.
    ambiguous = first_teams.resolve("Hewlett Packard")
    assert ambiguous.team is None
    assert any("Enterprise" in (team.host or "") for team in ambiguous.candidates)
