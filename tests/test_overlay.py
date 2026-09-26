"""Strings are read from the image, not from what is glued behind it.

An overlay is whatever follows the last section: bytes the loader never maps,
which in a self-extracting installer is the compressed payload and in every
signed binary includes the Authenticode blob.

Reported from real use on 2026-09-26. A 457 MB HP webpack produced 2,449
hostnames and 350 paths, and not one of them was real — `00c.Bvv`, `/-/9`,
`/./G`. The structural cause was in the section table exeradar already prints:
the sections sum to 684 KB, so 99.85% of the file is overlay, and pulling
printable runs out of compressed data will always manufacture `xx.yy` pairs
that happen to end in a delegated ccTLD.

Measured before this was written, on four real binaries:

    HP webpack     747 hosts, 350 paths  ->  0 hosts, 1 path
    two Kyocera installers                ->  unchanged
    python.exe                            ->  unchanged

The three that did not move have overlays of ten to fourteen kilobytes, which
is the signature and nothing else. Nothing true was lost anywhere, and the URL
and IP counts did not move at all — an installer that genuinely referenced 747
hosts would carry URLs too, and that one carried none.

Entropy was considered as the discriminator and dropped: it reads 7.5 to 8.0 in
all four, because a signature blob is as random as a compressed archive. There
is nothing to tell apart. The overlay is simply not the program.
"""

from __future__ import annotations

import pytest

from exeradar import scanner, strings
from exeradar.formats import pe

HOST_IN_OVERLAY = b"overlay-marker.example.com"
PATH_IN_OVERLAY = rb"C:\overlay\marker\file.txt"


@pytest.fixture
def pe_with_text_after_the_sections(pe_path, tmp_path):
    """The real fixture with a hostname and a path appended past the image."""
    target = tmp_path / "with-overlay.exe"
    target.write_bytes(
        pe_path.read_bytes()
        + b"\x00" * 16 + HOST_IN_OVERLAY
        + b"\x00" * 16 + PATH_IN_OVERLAY
        + b"\x00" * 16
    )
    return target


def test_the_overlay_begins_where_the_last_section_ends(pe_path):
    start = pe.overlay_start(pe_path)

    assert start is not None
    assert 0 < start < pe_path.stat().st_size
    # python.exe carries its signature there and nothing else.
    assert pe_path.stat().st_size - start == 14048


def test_a_file_with_nothing_appended_has_the_overlay_it_always_had(pe_path):
    """Guarding the arithmetic rather than the feature: an off-by-one here
    would silently cut the last section's strings instead of the overlay."""
    data = pe_path.read_bytes()
    start = pe.overlay_start(pe_path)

    inside = strings.extract(data[:start])
    assert inside.urls, "the manifest URL lives in .rsrc and has to survive"


def test_what_is_appended_after_the_sections_is_not_reported(
    pe_with_text_after_the_sections,
):
    result = scanner.scan(pe_with_text_after_the_sections)

    assert HOST_IN_OVERLAY.decode() not in result.strings.hosts
    assert PATH_IN_OVERLAY.decode() not in result.strings.paths


def test_what_lives_in_a_section_is_still_reported(
    pe_with_text_after_the_sections,
):
    """The other half. A change that drops the overlay and the image with it
    would pass the test above and be useless."""
    result = scanner.scan(pe_with_text_after_the_sections)

    assert any("schemas.microsoft.com" in url for url in result.strings.urls)
    assert any(url.endswith(".pdb") or "python.pdb" in url for url in result.strings.paths)


def test_the_result_says_how_much_was_left_unread(pe_with_text_after_the_sections):
    """Skipping bytes quietly is the failure this package is named after. The
    count is on the result so the report can say it."""
    result = scanner.scan(pe_with_text_after_the_sections)

    assert result.overlay > 14048
    assert result.overlay == (
        pe_with_text_after_the_sections.stat().st_size
        - pe.overlay_start(pe_with_text_after_the_sections)
    )


def test_a_binary_whose_sections_cannot_be_read_keeps_all_of_it(truncated_pe_path):
    """No sections means no boundary, and a boundary of zero would exclude the
    whole file — reporting nothing at all as though it had looked."""
    assert pe.overlay_start(truncated_pe_path) is None

    result = scanner.scan(truncated_pe_path)
    assert result.overlay == 0
