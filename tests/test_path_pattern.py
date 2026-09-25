"""The Windows-path pattern backtracks, and on a long string it stops being fast.

    ^[a-z]:[\\/][^\r\n]*[\\/][^\r\n]*$

Both `[^\r\n]*` can eat a separator, so the engine has to try every separator as
the one the middle `[\\/]` matches. When the tail cannot reach `$` it tries them
all, and each attempt rescans the rest. Measured on this machine, Python 3.14.7,
against `"C:\\" + "a\\" * n + "\r"` — many separators and a carriage return, which
`$` will not skip the way it skips a newline:

    n =  2,000      110 ms
    n =  8,000    2,118 ms
    n = 32,000   30,428 ms

Quadrupling the input multiplies the time by twenty, then by fourteen. The
rewrite below stays linear on the same inputs — 0.4 ms, 2.2 ms, 13.3 ms — because
a segment cannot contain a separator, so every character has exactly one place it
can go and there is nothing to reconsider.

How much this is exposed through the tool itself: not at all today.
`extract_raw` only ever yields runs of `[\x20-\x7e]`, which excludes `\r` and
`\n`, so a candidate coming from a scanned binary cannot carry the tail that
triggers it. `classify` and `from_file` are public, though, and a caller passing
its own strings is not a strange thing to do.
"""

from __future__ import annotations

import time

import pytest

from exeradar.strings import classify

# The carriage return sits in the middle, not at the end, because `classify`
# strips its input: a trailing one is removed before the pattern ever sees it,
# and the string then matches immediately. That is how the first version of this
# test passed against the very code it was written to fail — worth remembering,
# since a test that cannot fail is the other defect fixed alongside this one.
#
# Measured through classify() on this machine: 26 ms at n=1,000 and 502 ms at
# n=4,000 — quadrupling the length multiplies the time by nineteen. At n=8,000
# it is about two seconds.
PATHOLOGICAL = "C:\\" + "a\\" * 8_000 + "\rb"

# Two seconds before the fix, a few milliseconds after. One second sits between
# them with room for a runner several times slower than this machine.
BUDGET_SECONDS = 1.0


def test_a_long_string_of_separators_does_not_take_seconds():
    start = time.perf_counter()
    classify([PATHOLOGICAL])
    elapsed = time.perf_counter() - start

    assert elapsed < BUDGET_SECONDS, (
        f"classify took {elapsed:.2f}s on {len(PATHOLOGICAL)} characters: "
        "the path pattern is backtracking again"
    )


def test_the_pathological_string_is_not_a_path_anyway():
    """It carries a carriage return. The point is what it costs to say no."""
    assert PATHOLOGICAL not in classify([PATHOLOGICAL]).paths


# ── and it still recognises the same things ─────────────────────────────────


@pytest.mark.parametrize(
    "text",
    [
        r"C:\Windows\System32\cmd.exe",
        r"C:\a\b",
        "c:/Program Files/app/x.dll",
        "C:/a/b/",
        r"C:\a\\",
        r"C:\dir\sub\deep\deeper\file.ext",
        r"D:\x\y.txt",
    ],
)
def test_a_windows_path_is_still_a_path(text):
    assert text in classify([text]).paths


@pytest.mark.parametrize(
    "text",
    [
        r"C:\a",          # one separator: a drive and a name, not a path
        "C:",
        r"\\server\share\file",   # UNC: no drive letter, and never matched before
        "notes.txt",
        "kernel32.dll",
        "C:/",
    ],
)
def test_what_was_not_a_path_still_is_not(text):
    assert text not in classify([text]).paths


def test_a_unix_path_is_unaffected():
    assert "/usr/local/bin" in classify(["/usr/local/bin"]).paths
