"""Benchmarks for Authenticode inspection.

Pure parsing work: LIEF hands over the PKCS#7 blob, this package walks the
certificate chain, picks the signer out of it and decodes the RFC3161 TSTInfo
that carries the countersignature date. No network, no filesystem beyond the
one read — which is what makes it worth measuring: any change in the number is
a change in the code.
"""

from __future__ import annotations

from exeradar import signature


def test_inspect_an_embedded_signature(benchmark, pe_path):
    """The whole of path A: blob, chain, signer, timestamp."""
    result = benchmark(lambda: signature.inspect(pe_path))

    assert result.verified
    assert len(result.chain) == 4, "the fixture's chain is signer plus three CAs"
    assert result.timestamp, "the RFC3161 countersignature date has to come out"


def test_signed_regions(benchmark, pe_path):
    """Called on every scan, signed or not: it is how the string extractor
    learns which bytes belong to the certificate table and must be left out."""
    regions = benchmark(lambda: signature.signed_regions(pe_path))

    assert len(regions) == 1
    start, end = regions[0]
    assert end > start
