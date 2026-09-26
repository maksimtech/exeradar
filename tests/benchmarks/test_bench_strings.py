"""Benchmarks for string extraction and classification.

This is the module with a measured history. `_WINDOWS_PATH` and `_UNIX_PATH`
were written as `X* sep X*$`, which backtracks quadratically on a string that
looks like a path right up to the end and then fails to reach `$` — a drive
letter followed by a long run with no second separator, which is what a binary
is full of. A linear guard test pins the worst case; these pin the ordinary one,
where a quadratic rewrite would show up as a number rather than a hang.
"""

from __future__ import annotations

from exeradar import strings

# 200 of each shape: about 1600 candidates and ~9 ms, the same order as the real
# binary's 590. Large enough that the regex engine, not the loop around it, is
# what is being measured.
CORPUS_SIZE = 200

# Longer than any real path in the fixture, so the assertion below can tell the
# near-misses from the genuine paths without listing them.
NEAR_MISS_LENGTH = 120


def path_heavy_corpus(n: int = CORPUS_SIZE) -> list[str]:
    """Genuine paths, near-misses, and the rest of what a binary holds.

    The near-misses are the point: `C:\\` plus a long run and no second
    separator matches every part of the pattern except the end of it, which is
    the input the old regex spent its time on.
    """
    out: list[str] = []
    for i in range(n):
        out.append(rf"C:\Program Files\App{i}\bin\tool{i}.dll")
        out.append(f"/usr/lib/app{i}/lib{i}.so")
        out.append("C:\\" + "a" * NEAR_MISS_LENGTH)
        out.append("/" + "b" * NEAR_MISS_LENGTH)
        out.append(f"cdn{i}.example.com")
        out.append(f"https://example.com/a/{i}?q=1")
        out.append(f"10.0.{i // 256}.{i % 256}")
        out.append("the quick brown fox " * 4)
    return out


def test_extract_raw(benchmark, pe_bytes, signed_regions):
    """Both passes over 106 KB: ASCII and UTF-16LE, with the certificate table
    cut out."""
    found = benchmark(lambda: strings.extract_raw(pe_bytes, exclude=signed_regions))

    assert len(found) > 100, "the fixture has hundreds of printable runs"


def test_classify_a_real_binary(benchmark, candidates):
    """The production input: every printable run of a signed PE."""
    result = benchmark(lambda: strings.classify(candidates))

    assert result.urls, "python.exe carries at least the CRL and OCSP URLs"


def test_classify_a_path_heavy_corpus(benchmark):
    """The shape that backtracked, at a size where backtracking is visible."""
    corpus = path_heavy_corpus()

    result = benchmark(lambda: strings.classify(corpus))

    # Two genuine paths per iteration and not one of the near-misses: if a
    # rewrite ever makes them match, the benchmark stops measuring the failing
    # branch and its number stops meaning anything.
    assert len(result.paths) == 2 * CORPUS_SIZE
    assert all(len(p) < NEAR_MISS_LENGTH for p in result.paths)
    assert len(result.urls) == CORPUS_SIZE
    assert len(result.ips) == CORPUS_SIZE
    assert len(result.hosts) == CORPUS_SIZE
