"""Properties, checked against generated input rather than chosen examples.

Three of the bugs this repository has already paid for were shapes nobody
thought to write a fixture for: a section of one repeated byte printing
"-0.00", a font name table running three URLs together, a certificate URL
losing its last character. Example tests pin the case that was found.
These pin the rule the case broke.

The `normalize_text` block is the most valuable one here, and the reason is not
the parser: its output is hashed, and that hash is what tells an operator "the
law changed". A normalisation that is not idempotent would report a change in a
text that nobody edited.
"""

from __future__ import annotations

import ipaddress
import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from exeradar.formats.pe import entropy
from exeradar.law_fetcher import normalize_text
from exeradar.strings import _is_ipv4, _urls_in

# ── Shannon entropy ─────────────────────────────────────────────────────────


@given(st.binary(max_size=4096))
def test_entropy_stays_inside_its_own_scale(data):
    """The docstring promises 0.0 to 8.0 — a byte cannot carry more than 8 bits."""
    assert 0.0 <= entropy(data) <= 8.0


@given(st.integers(min_value=0, max_value=255), st.integers(min_value=1, max_value=4096))
def test_one_repeated_byte_is_exactly_positive_zero(byte, count):
    """The -0.00 in the report came from here, and must not come back.

    A section of one repeated byte carries no information, and 0.0 == -0.0 in
    Python, so an equality assertion cannot tell the two apart. copysign can.
    """
    result = entropy(bytes([byte]) * count)
    assert result == 0.0
    assert math.copysign(1.0, result) == 1.0, "negative zero prints as -0.00"


@given(st.binary(min_size=1, max_size=2048))
def test_entropy_does_not_depend_on_the_order_of_the_bytes(data):
    """Shannon entropy is a function of the byte counts, nothing else."""
    assert entropy(data) == entropy(bytes(sorted(data)))


@given(st.binary(min_size=1, max_size=1024), st.integers(min_value=2, max_value=5))
def test_repeating_a_section_does_not_change_its_entropy(data, times):
    """The proportions are unchanged, so the bits per byte are too."""
    assert entropy(data * times) == entropy(data)


@given(st.sets(st.integers(min_value=0, max_value=255), min_size=1, max_size=64))
def test_a_uniform_section_reaches_log2_of_its_alphabet(alphabet):
    """The maximum for n equally likely values, which is where "packed" lives.

    Compared with a tolerance: the sum runs over the alphabet in a different
    order than log2 does, so the two agree to within floating-point noise
    rather than bit for bit.
    """
    data = bytes(sorted(alphabet))
    assert entropy(data) == pytest.approx(math.log2(len(alphabet)))


# ── URLs pulled out of raw bytes ────────────────────────────────────────────

_SAFE = st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), max_size=200)


@given(_SAFE)
def test_every_url_found_was_really_in_the_text(text):
    """A URL that is not a substring of the input was invented by the trimmer.

    _trim removes a DER tail, so the result may be shorter than what matched —
    but it is still a slice of the text, never a rewrite of it.
    """
    for url in _urls_in(text):
        assert url in text


@given(_SAFE)
def test_no_url_carries_whitespace_or_a_quote(text):
    """These are the framing bytes the first version kept; see _URL."""
    for url in _urls_in(text):
        assert not any(c.isspace() for c in url)
        assert '"' not in url and "'" not in url


@given(_SAFE)
def test_every_url_begins_at_a_scheme(text):
    for url in _urls_in(text):
        assert url.lower().startswith(("http://", "https://", "ftp://", "ftps://"))


# ── Dotted quads ────────────────────────────────────────────────────────────


@given(st.integers(0, 255), st.integers(0, 255), st.integers(0, 255), st.integers(0, 255))
def test_every_real_address_is_recognised(a, b, c, d):
    assert _is_ipv4(f"{a}.{b}.{c}.{d}")


# Octets past 255 on purpose: "999.1.1.1" is the shape the range check exists
# for. Leading zeros are excluded because the stdlib rejects them as ambiguous
# octal while this pattern does not, and that disagreement is its own question.
_OCTET = st.integers(0, 999).filter(lambda n: str(n) == str(n).lstrip("0") or n == 0)


@given(_OCTET, _OCTET, _OCTET, _OCTET)
def test_a_quad_is_an_address_exactly_when_every_octet_is_in_range(a, b, c, d):
    text = f"{a}.{b}.{c}.{d}"
    assert _is_ipv4(text) == all(n <= 255 for n in (a, b, c, d))


@given(_OCTET, _OCTET, _OCTET, _OCTET)
def test_the_pattern_and_the_standard_library_reach_the_same_verdict(a, b, c, d):
    """The agreed authority is the stdlib, not this pattern.

    Stated as an equality rather than "assume it parses, then parse it": a
    valid quad is well under 1% of this space, so assume() would throw away
    almost every case and Hypothesis would rightly complain about it.
    """
    text = f"{a}.{b}.{c}.{d}"
    try:
        ipaddress.IPv4Address(text)
        stdlib_accepts = True
    except ValueError:
        stdlib_accepts = False
    assert _is_ipv4(text) == stdlib_accepts


# ── The hash that decides "the law changed" ─────────────────────────────────

_LEGAL_TEXT = st.text(
    alphabet=st.characters(
        min_codepoint=32, max_codepoint=0x2FFF,
        blacklist_categories=("Cs",),
    ),
    max_size=400,
)


@given(_LEGAL_TEXT)
@settings(max_examples=300)
def test_normalising_twice_says_the_same_as_normalising_once(text):
    """If this ever failed, the cache would report a change nobody made."""
    once = normalize_text(text)
    assert normalize_text(once) == once


@given(_LEGAL_TEXT)
def test_the_normal_form_holds_no_run_of_spaces_and_no_edges(text):
    result = normalize_text(text)
    assert "  " not in result
    assert result == result.strip()


@given(_LEGAL_TEXT)
def test_the_normal_form_never_leaves_a_space_before_punctuation(text):
    """"Consiglio ;" is what a removed footnote reference leaves behind."""
    result = normalize_text(text)
    for mark in ";,.:":
        assert f" {mark}" not in result
