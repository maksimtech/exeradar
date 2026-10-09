"""FIRST's member directory: who a vulnerability is reported to.

CVE names a flaw and NVD scores it; FIRST is the body that says who answers for
it. Its directory at api.first.org/data/v1/teams is public — the responses carry
`"access": "public"` and need no credentials — and each team brings the verified
address and the PGP key to encrypt to. Until now that was looked up by hand, once
per disclosure, in a browser.

Two rules shape the whole module, and neither is about HTTP.

**It never chooses between two organisations.** Searching for "hewlett" returns
Hewlett Packard Enterprise, the company split off in 2015, before it returns HP
Inc., whose name is on a 250 G6. Both are full members with different addresses
and different keys. Taking the first row would send an embargoed finding to the
wrong company, so `search` returns every candidate and `resolve` answers only on
an exact name, handing back the candidates when there is no exact match.

**An empty answer is never an answer about the vendor.** FIRST lists its members;
most PSIRTs in the world are not in it. "No member team" is a fact about the
directory, and a timeout is a fact about the afternoon. Neither says a vendor has
nowhere to receive a report, so the first is a reason and the second is an
exception — the same split `collectors/` keeps between "nothing found" and "could
not ask".

Shared by copy across the Radar, the way `law_fetcher` and `law_cache` are: the
directory is the same directory whichever tool is writing the letter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

from exeradar import __version__

TEAMS_URL = "https://api.first.org/data/v1/teams"
SOURCE = "FIRST team directory"
USER_AGENT = f"ExeRadar/{__version__} (+https://github.com/maksimtech/exeradar)"

# A v4 OpenPGP fingerprint is 40 hex characters. The directory prints some of
# them in spaced groups of four, which is how a human reads one aloud.
_FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")


class FirstLookupError(Exception):
    """The directory could not be asked, or answered something unusable."""


@dataclass(frozen=True)
class Team:
    """One team as the directory describes it.

    `pgp_fingerprint` and `pgp_key` are None when the entry carries none, never
    an empty string: a blank where a key belongs reads as "the directory holds
    one and it is empty", which is a different and wrong claim.
    """

    id: str
    name: str
    full_name: str
    host: str
    membership: str
    country: str
    email: str
    website: str | None = None
    pgp_id: str | None = None
    pgp_fingerprint: str | None = None
    pgp_key: str | None = None
    member_since: str | None = None
    last_modified: str | None = None


@dataclass(frozen=True)
class Resolution:
    """The answer to "who do I send this to", including when there is none.

    `team` is set only on an exact name match. Otherwise `candidates` carries
    what the directory did return and `reason` says why none of it was chosen —
    for a person to read, not for code to match on.
    """

    team: Team | None
    candidates: list[Team]
    reason: str


def _text(row: dict, key: str) -> str | None:
    value = row.get(key)
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _fingerprint(row: dict) -> str | None:
    """Uppercase, unspaced, forty hex characters — or nothing at all.

    Anything else is dropped rather than passed on: a fingerprint is what
    somebody checks a key against, and a malformed one offered as a fingerprint
    is worse than an absent one.
    """
    raw = _text(row, "pgp-fingerprint")
    if raw is None:
        return None
    candidate = raw.replace(" ", "").upper()
    return candidate if _FINGERPRINT.match(candidate) else None


def _team(row: dict) -> Team | None:
    """A row as a Team, or None when it answers nothing.

    No address means no answer to the question this module exists for, so the
    row is dropped instead of being returned as a team with nowhere to write.
    """
    email = _text(row, "email")
    identifier = _text(row, "id")
    if email is None or identifier is None:
        return None
    name = _text(row, "team") or identifier
    return Team(
        id=identifier,
        name=name,
        full_name=_text(row, "team-full") or name,
        host=_text(row, "host") or "",
        membership=_text(row, "membership") or "",
        country=_text(row, "country") or "",
        email=email,
        website=_text(row, "website"),
        pgp_id=_text(row, "pgp-id"),
        pgp_fingerprint=_fingerprint(row),
        pgp_key=_text(row, "pgp-key"),
        member_since=_text(row, "member-since"),
        last_modified=_text(row, "last-modified"),
    )


def search(
    query: str,
    *,
    limit: int = 20,
    client: httpx.Client | None = None,
    timeout: float = 30.0,
) -> list[Team]:
    """Every team the directory returns for `query`, in its order.

    Raises rather than returning [] when the directory cannot be reached or
    answers something other than a list of teams: an empty list has to mean
    "the directory has no such member", and nothing else.
    """
    # Annotated, not inferred: a dict holding a str and an int infers as
    # `dict[str, object]` and httpx's `params` rejects it. The third time this
    # exact collapse has cost a mypy error this week — see patchradar's
    # debian_status and apkradar's search_cmd.
    params: dict[str, str | int] = {"q": query, "limit": limit}
    headers = {"User-Agent": USER_AGENT}
    try:
        if client is None:
            with httpx.Client(timeout=timeout, follow_redirects=True) as own:
                response = own.get(TEAMS_URL, params=params, headers=headers)
        else:
            response = client.get(TEAMS_URL, params=params, headers=headers)
    except httpx.HTTPError as error:
        raise FirstLookupError(f"{SOURCE} unreachable: {error}") from error

    if response.status_code != 200:
        raise FirstLookupError(f"{SOURCE} answered HTTP {response.status_code}")

    try:
        payload = response.json()
    except ValueError as error:
        raise FirstLookupError(f"{SOURCE} answered something that is not JSON") from error
    if not isinstance(payload, dict):
        raise FirstLookupError(f"{SOURCE} answered something that is not an object")

    status = payload.get("status")
    if status != "OK":
        raise FirstLookupError(
            f"{SOURCE} answered status {status!r} ({payload.get('status-code')})"
        )

    rows = payload.get("data")
    if not isinstance(rows, list):
        raise FirstLookupError(f"{SOURCE} answered no list of teams")

    return [team for row in rows if isinstance(row, dict) and (team := _team(row)) is not None]


def resolve(
    organisation: str,
    *,
    client: httpx.Client | None = None,
    timeout: float = 30.0,
) -> Resolution:
    """The team for `organisation`, named exactly, or the reason there is none.

    Exact means exact, case and surrounding space aside, against the host
    organisation or the team's full name. "Hewlett Packard" is not HP Inc. and
    is not Hewlett Packard Enterprise either; it is a question with two answers,
    and a tool that picks one has decided something a person has to.
    """
    candidates = search(organisation, client=client, timeout=timeout)
    wanted = organisation.strip().casefold()
    exact = [
        team for team in candidates
        if wanted in {team.host.casefold(), team.full_name.casefold(), team.name.casefold()}
    ]
    if len(exact) == 1:
        team = exact[0]
        return Resolution(team=team, candidates=[], reason=f"exact match on {team.host or team.name}")
    # Two exact matches are still two answers. One organisation can have more
    # than one member team — a product PSIRT and a corporate CERT, with different
    # addresses and keys — and the first in the response was the one returned.
    if exact:
        names = ", ".join(f"{team.full_name or team.name} <{team.email}>" for team in exact)
        return Resolution(
            team=None,
            candidates=exact,
            reason=(
                f"{len(exact)} member teams match {organisation!r} exactly: {names}. "
                "Choose by name rather than letting the order choose."
            ),
        )

    if not candidates:
        return Resolution(
            team=None,
            candidates=[],
            reason=(
                f"FIRST lists no member team matching {organisation!r}. FIRST is a "
                "membership body and does not list every PSIRT, so this is not a "
                "finding about the vendor: check its security.txt and its own "
                "advisory page. The directory is searched by team name, so an "
                "organisation's name finds nothing when its team is called otherwise."
            ),
        )

    # Named by the team, with the organisation beside it. The directory searches
    # team names and not hosts: `?q=Microsoft` returns Microsoft Security PSIRT,
    # hosted by Microsoft Corporation, and `?q=Microsoft Corporation` returns
    # nothing — measured 2026-10-09. Printing the host alone told a reader to ask
    # again with a name that could not be found.
    names = ", ".join(described(team) for team in candidates)
    return Resolution(
        team=None,
        candidates=candidates,
        reason=(
            f"no exact match for {organisation!r}; the directory returned {names}. "
            "Ask again with the team's name, which is what the directory searches, "
            "rather than letting the order choose: these are different organisations "
            "with different addresses and keys."
        ),
    )


def described(team: Team) -> str:
    """The team by the name the directory can be asked for, and whose it is."""
    if team.host and team.host.casefold() != team.name.casefold():
        return f"{team.name} ({team.host})"
    return team.name
