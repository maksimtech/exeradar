"""TLP 2.0, FIRST's Traffic Light Protocol, on documents that leave this machine.

A report sent to a vendor's PSIRT describes a flaw in its product before the flaw
is public. Whether the recipient may forward it is the sender's
decision, and until now the document carried no way of expressing one. TLP is the
standard for exactly that, published by FIRST — the same body behind EPSS and the
team directory — so it is part of making FIRST a source these tools cite rather
than consume.

Four rules the tests hold, and only the first is about spelling.

**The labels are tokens, not words.** `TLP:AMBER+STRICT`, uppercase, no space
after the colon. They are not translated: the letter is in Italian and the label
stays as the standard writes it, because a recipient's tooling matches on the
token.

**`TLP:WHITE` is refused and not quietly mapped.** TLP 2.0 renamed WHITE to CLEAR
in 2022. Accepting WHITE would put a label on a document that the current standard
does not define; the refusal names the replacement instead.

**AMBER and AMBER+STRICT are different answers.** AMBER lets the recipient share
with its clients; AMBER+STRICT stops at the organisation. They are the pair most
often conflated, and the difference is the whole reason +STRICT was added.

**An unmarked document is unmarked, not CLEAR.** No label means the sender said
nothing about redistribution — defaulting to CLEAR would turn silence into
unlimited permission, which is the same class of mistake as reading an empty
result list as "nothing is there".
"""

from __future__ import annotations

import pytest

from exeradar import tlp
from exeradar.tlp import Label, TlpError

# ── the tokens ──────────────────────────────────────────────────────────────


def test_the_five_labels_are_spelled_the_way_the_standard_writes_them():
    assert [label.value for label in Label] == [
        "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED",
    ]


def test_the_standard_is_named_with_its_version_so_a_report_can_cite_it():
    assert tlp.VERSION == "2.0"
    assert tlp.STANDARD_URL.startswith("https://www.first.org/tlp")


@pytest.mark.parametrize(
    "written, expected",
    [
        ("amber", Label.AMBER),
        ("AMBER", Label.AMBER),
        ("TLP:AMBER", Label.AMBER),
        ("tlp:amber", Label.AMBER),
        ("  amber  ", Label.AMBER),
        ("amber+strict", Label.AMBER_STRICT),
        ("AMBER+STRICT", Label.AMBER_STRICT),
        ("TLP:AMBER+STRICT", Label.AMBER_STRICT),
        ("clear", Label.CLEAR),
        ("green", Label.GREEN),
        ("red", Label.RED),
    ],
)
def test_a_label_is_read_however_it_was_typed_and_comes_back_canonical(written, expected):
    assert tlp.parse(written) is expected
    assert tlp.parse(written).value.isupper()


def test_white_is_refused_and_the_refusal_names_what_replaced_it():
    """TLP 2.0 renamed WHITE to CLEAR. Mapping it silently would emit a label the
    current standard does not define, in a document meant to be unambiguous."""
    with pytest.raises(TlpError) as error:
        tlp.parse("TLP:WHITE")

    message = str(error.value)
    assert "WHITE" in message
    assert "CLEAR" in message
    assert "2.0" in message


@pytest.mark.parametrize("written", ["", "   ", "orange", "TLP:ORANGE", "amber strict", "amber-strict", "tlp"])
def test_anything_else_is_refused_and_never_defaults_to_clear(written):
    with pytest.raises(TlpError):
        tlp.parse(written)


def test_none_is_not_a_label_and_not_an_error_either():
    """`--tlp` not given at all: the document goes out unmarked, deliberately."""
    assert tlp.parse_optional(None) is None
    assert tlp.parse_optional("") is None


# ── what each label permits ─────────────────────────────────────────────────


def test_amber_and_amber_strict_do_not_say_the_same_thing():
    amber = tlp.permission(Label.AMBER)
    strict = tlp.permission(Label.AMBER_STRICT)

    assert amber != strict
    assert "client" in amber.lower()          # AMBER reaches clients
    assert "client" not in strict.lower()     # +STRICT stops at the organisation


@pytest.mark.parametrize("label", list(Label))
def test_every_label_says_what_the_recipient_may_do(label):
    text = tlp.permission(label)

    assert len(text) > 20
    assert label.value not in text            # the permission explains, it does not repeat


def test_the_permissions_are_all_different():
    assert len({tlp.permission(label) for label in Label}) == len(Label)


# ── where the marking goes ──────────────────────────────────────────────────


def test_the_subject_carries_the_label_first():
    """FIRST's guidance for email: the label in the subject line as well as the
    body, so it is visible before the message is opened."""
    marked = tlp.subject("Finding in vendor.exe", Label.AMBER)

    assert marked.startswith("TLP:AMBER ")
    assert "Finding in vendor.exe" in marked


def test_an_already_marked_subject_is_not_marked_twice():
    once = tlp.subject("Report", Label.RED)

    assert tlp.subject(once, Label.RED) == once


def test_a_subject_is_compared_on_its_first_word_and_not_on_a_prefix():
    """A subject opening with TLP:REDACTED is not marked TLP:RED, and one opening
    with TLP:AMBER+STRICT is not TLP:AMBER: both used to be taken as already marked."""
    assert tlp.subject("TLP:REDACTED minutes", Label.RED).startswith("TLP:RED ")
    assert tlp.subject("TLP:AMBER+STRICT minutes", Label.AMBER).startswith("TLP:AMBER TLP:AMBER+STRICT")
    assert tlp.subject("TLP:RED", Label.RED) == "TLP:RED"
    assert tlp.subject("", Label.RED) == "TLP:RED "


def test_the_banner_names_the_standard_the_label_and_the_permission():
    banner = tlp.banner(Label.AMBER_STRICT)

    assert "TLP:AMBER+STRICT" in banner
    assert tlp.permission(Label.AMBER_STRICT) in banner
    assert tlp.STANDARD_URL in banner
    assert "2.0" in banner


def test_the_banner_is_written_in_the_language_of_the_document_but_the_label_is_not():
    italian = tlp.banner(Label.AMBER, lang="it")
    english = tlp.banner(Label.AMBER, lang="en")

    assert italian != english
    assert "TLP:AMBER" in italian and "TLP:AMBER" in english
    assert "destinatario" in italian.lower()
    assert "recipient" in english.lower()


def test_an_unknown_language_falls_back_to_english_rather_than_losing_the_marking():
    banner = tlp.banner(Label.RED, lang="fi")

    assert "TLP:RED" in banner
    assert tlp.permission(Label.RED) in banner
