"""Benchmarks for the law side, from the CodSpeed pull request.

`law_checker.check` is not measured: it downloads the acts, and a benchmark
that goes to the network measures somebody else's afternoon. What costs CPU is
`parse_articles`, walking the EUR-Lex markup to pull one article out of a
document — and that runs against the excerpts committed to tests/fixtures, so
it is the same work without the request.

`findings_for` is the other half: turning the facts a scan produced into the
findings that get cited. Both arrived from PR #1, the second one without an
assertion.

Until 2026-10-08 `findings_for` was measured on the fixture alone, and the
fixture produces nothing: python.exe is signed, verified, countersigned and
carries no address, so the call returns an empty list in about 6 µs. What
CodSpeed counted was mostly its own harness, and on the same code, the same
pytest-codspeed 5.0.3, the same runner image and the same CPython 3.12.15 it
read 219.6 µs on main and 339 µs on PR #5, which touched only a workflow — a
red −35% on nothing. It was not the garbage collector: pytest-codspeed runs
`gc.collect()` and `gc.disable()` around the measured call, which is also why
no fixture here does the same. A window that small is just noise.

The benchmark now walks one ExeResult per rule `findings_of` can fire, each
derived from the real scan by `dataclasses.replace` — see `cases` — and
`tests/test_benchmark_contract.py` refuses a rule the cases do not reach.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from exeradar import law_checker, law_fetcher
from exeradar.law_checker import FUTURE_FINDINGS, SEVERITY
from exeradar.models import ExeResult, Import, Signature, SignatureState

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

# Pinned: findings_for takes the moment as an argument, and reading the clock
# would make the measurement depend on when it ran — a certificate expires
# between two runs and the finding count changes underneath the number.
NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)

PART_I = "Allegato I, Parte I"
PART_II = "Allegato I, Parte II"

# Each act and the units the findings actually cite from it.
ACTS = {
    "cra": ("cra_it_excerpt.html", ("6", "13", PART_I, PART_II)),
    "gdpr": ("gdpr_it_excerpt.html", ("32",)),
    "nis2": ("nis2_it_excerpt.html", ("21",)),
}


# The rules `findings_of` fires today. `known_vulnerabilities` is in SEVERITY
# and in the map, and is produced by nothing yet — law_checker declares it in
# FUTURE_FINDINGS — so it is not a case here and the guard does not ask for it.
RULES = frozenset(SEVERITY) - FUTURE_FINDINGS

# RFC 5737 documentation ranges: addresses no host answers on, which is what
# an address in a test should be. The fixture carries none, so these are added
# rather than derived. The two local ones are there for `_is_local` to drop,
# which is part of the work the rule does on a real binary.
PUBLIC_ADDRESSES = ["192.0.2.10", "198.51.100.7", "203.0.113.42"]
LOCAL_ADDRESSES = ["0.0.0.0", "127.0.0.1"]

# Winsock, the DLL `pe.categorise` files under "network". Placed after the
# fixture's own eight DLLs so that `reaches_the_network` walks all of them
# before it finds the one that answers, as it would on a real binary.
WINSOCK = Import(dll="WS2_32.dll", functions=["connect", "send", "recv"])


def cases(scanned: ExeResult) -> dict[str, ExeResult]:
    """One ExeResult per rule, derived from the scan of the fixture.

    Derived data: every case is `dataclasses.replace` on the ExeResult that
    `scanner.scan` produced for tests/fixtures/python.exe, with the fields named
    below changed and nothing else — the sections, imports, strings, libraries
    and certificate chain are the fixture's own. The scan is the one the other
    benchmarks share, read once per session.

    - `none`: the fixture as it is. Signed by the PSF on 2026-08-04 with a leaf
      valid three days, countersigned by Microsoft's TSA, no address: nothing
      fires, and that is the path the benchmark used to measure alone.
    - `unsigned`: the Signature `signature.inspect` returns when neither the
      embedded path nor the catalog finds anything, in place of the real one.
    - `signature_invalid`: the real signature with `verified` False and the
      flag LIEF raises when the bytes are not the bytes that were signed.
    - `certificate_expired`: the real chain — its leaf expired on 2026-08-07,
      before NOW — with the countersignature removed, which is the one fact
      that keeps the rule quiet on the fixture. LIEF then reports CERT_EXPIRED
      and `_verdict` turns that into `verified` None, so both are set that way.
    - `hardcoded_ip`: public addresses added to the strings and Winsock added
      to the imports, because the rule only fires when both are there.
    """
    signature = scanned.signature
    return {
        "none": scanned,
        "unsigned": replace(scanned, signature=Signature(
            state=SignatureState.UNSIGNED,
            verified=False,
            detail="no embedded signature and no catalog entry",
        )),
        "signature_invalid": replace(scanned, signature=replace(
            signature,
            verified=False,
            verification=("bad_digest",),
            detail=f"{signature.detail}; does not check out: bad_digest",
        )),
        "certificate_expired": replace(scanned, signature=replace(
            signature,
            verified=None,
            verification=("cert_expired",),
            timestamp=None,
            timestamper=None,
            detail=f"{signature.detail}; not established: cert_expired",
        )),
        "hardcoded_ip": replace(
            scanned,
            strings=replace(scanned.strings, ips=[*LOCAL_ADDRESSES, *PUBLIC_ADDRESSES]),
            imports=[*scanned.imports, WINSOCK],
        ),
    }


def test_findings_for(benchmark, scanned):
    """Every finding is drawn from facts the scan already collected, so this is
    the rule engine on its own with no I/O behind it — every rule of it, on the
    cases above, and the empty path with them."""
    results = cases(scanned)

    findings = benchmark(
        lambda: {name: law_checker.findings_for(result, now=NOW) for name, result in results.items()}
    )

    assert not findings["none"], "the fixture is signed, verified and countersigned"
    assert {finding.id for found in findings.values() for finding in found} == RULES, (
        "a rule findings_of can fire was not measured"
    )
    assert all(getattr(finding, "id", None) for found in findings.values() for finding in found), (
        "a finding with no id cannot be cited or suppressed"
    )


@pytest.mark.parametrize("act", sorted(ACTS))
def test_parse_articles(benchmark, act):
    """Walking the real markup of a real act. The excerpts are slices of what
    the Publications Office serves, not a reconstruction, so the shape the
    parser meets here is the shape it meets at runtime."""
    name, units = ACTS[act]
    html = (FIXTURES / name).read_text(encoding="utf-8")

    texts = benchmark(law_fetcher.parse_articles, html, units)

    assert all(unit in texts for unit in units), (
        f"{name}: asked for {units}, got {sorted(texts)}"
    )
    assert all(texts[unit].strip() for unit in units), "an article came back empty"
