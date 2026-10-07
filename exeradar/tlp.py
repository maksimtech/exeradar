"""TLP 2.0 — FIRST's Traffic Light Protocol, for documents that leave here.

A report that goes to a vendor's PSIRT under embargo is the case this standard
exists for: it describes a flaw in somebody's product before the flaw is public.
Whether the recipient may forward it is the sender's decision, and the document had
no way of carrying one. TLP is the standard for saying so, published by FIRST — the
same body behind EPSS and the team directory —
which is what makes FIRST a source these tools cite rather than merely consume.

Four rules, and only the first is about spelling.

**The labels are tokens, not words.** `TLP:AMBER+STRICT`, uppercase, no space
after the colon, never translated: the letter is in Italian and the label stays as
the standard writes it, because a recipient's mail rules match on the token.

**`TLP:WHITE` is refused rather than quietly mapped.** TLP 2.0 renamed WHITE to
CLEAR in 2022. Accepting WHITE would put a label on a document that the current
standard does not define; the refusal names the replacement instead.

**AMBER and AMBER+STRICT are different answers.** AMBER permits sharing with
clients, AMBER+STRICT stops at the organisation. They are the pair people conflate,
and that difference is why +STRICT was added.

**An unmarked document is unmarked, not CLEAR.** Silence from the sender is not
unlimited permission, so there is no default label: `parse_optional(None)` is None
and the report then carries no marking at all.

Shared by copy, like `law_fetcher`: the standard is the same standard whichever
tool is writing the document.
"""

from __future__ import annotations

from enum import StrEnum

VERSION = "2.0"
STANDARD_URL = "https://www.first.org/tlp/"


class TlpError(ValueError):
    """What was given is not a label of TLP 2.0."""


class Label(StrEnum):
    """The five labels of TLP 2.0, in order of how far they travel."""

    CLEAR = "TLP:CLEAR"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    AMBER_STRICT = "TLP:AMBER+STRICT"
    RED = "TLP:RED"


# What the recipient may do, which is the whole content of a label. Written out
# per label rather than generated: AMBER and AMBER+STRICT differ by one clause,
# and a template would invite writing that clause once.
_PERMISSION_EN = {
    Label.CLEAR: "May be shared without restriction, subject to copyright.",
    Label.GREEN: (
        "May be shared with peers and partner organisations in the community, "
        "but not through publicly accessible channels."
    ),
    Label.AMBER: (
        "May be shared with members of the recipient's organisation and with its "
        "clients who need to know in order to act, and no further."
    ),
    Label.AMBER_STRICT: (
        "May be shared with members of the recipient's organisation only, and no "
        "further."
    ),
    Label.RED: (
        "For the named recipients only. May not be shared with anybody else, "
        "inside the organisation or outside it."
    ),
}

_PERMISSION_IT = {
    Label.CLEAR: "Divulgabile senza restrizioni, nel rispetto del diritto d'autore.",
    Label.GREEN: (
        "Condivisibile con pari e organizzazioni partner della comunità, ma non "
        "attraverso canali pubblicamente accessibili."
    ),
    Label.AMBER: (
        "Condivisibile all'interno dell'organizzazione del destinatario e con i "
        "suoi clienti che devono conoscerla per agire, e non oltre."
    ),
    Label.AMBER_STRICT: (
        "Condivisibile unicamente all'interno dell'organizzazione del "
        "destinatario, e non oltre."
    ),
    Label.RED: (
        "Riservata ai soli destinatari indicati. Non condivisibile con nessun "
        "altro, né dentro né fuori l'organizzazione."
    ),
}

_HEADING = {
    "en": "Distribution: {label} (TLP {version} — {url})",
    "it": "Distribuzione: {label} (TLP {version} — {url})",
}

# The pre-2.0 name, kept only so that the refusal can be specific. TLP 2.0
# renamed it in 2022 and there is no WHITE to emit any more.
_RENAMED = {"WHITE": Label.CLEAR}

_BY_NAME = {label.value.removeprefix("TLP:"): label for label in Label}


def parse(text: str) -> Label:
    """A label from whatever a person typed, or TlpError.

    Case and surrounding space are forgiven; the result is always canonical.
    Nothing defaults: an unrecognised value is refused rather than treated as the
    most permissive label, which is the direction a mistake must never take.
    """
    if not isinstance(text, str):
        raise TlpError(f"not a TLP label: {text!r}")
    name = text.strip().upper().removeprefix("TLP:").strip()
    if not name:
        raise TlpError("no TLP label given")
    if name in _RENAMED:
        replacement = _RENAMED[name]
        raise TlpError(
            f"TLP:{name} belongs to TLP 1.0 and was renamed in TLP {VERSION}: "
            f"use {replacement.value} instead"
        )
    if name not in _BY_NAME:
        allowed = ", ".join(label.value for label in Label)
        raise TlpError(f"not a TLP {VERSION} label: {text!r} — the labels are {allowed}")
    return _BY_NAME[name]


def parse_optional(text: str | None) -> Label | None:
    """None when nothing was asked for, which is a document with no marking.

    Not CLEAR. A sender who said nothing has not granted unlimited distribution,
    and a tool that read silence that way would be making the decision for them.
    """
    if text is None or not text.strip():
        return None
    return parse(text)


def permission(label: Label, *, lang: str = "en") -> str:
    """What the recipient of a document with this label may do with it."""
    table = _PERMISSION_IT if lang == "it" else _PERMISSION_EN
    return table[label]


def subject(line: str, label: Label) -> str:
    """The subject line with the label in front of it.

    FIRST's guidance for email is the label in the subject as well as in the
    body, so that it is visible before the message is opened. Marking an already
    marked subject again would produce "TLP:RED TLP:RED …".
    """
    tag = label.value
    # The first word, not a prefix: "TLP:REDACTED minutes" starts with TLP:RED
    # and carries no label, and "TLP:AMBER+STRICT" is not TLP:AMBER.
    if line.split(maxsplit=1)[:1] == [tag]:
        return line
    return f"{tag} {line}"


def banner(label: Label, *, lang: str = "en") -> str:
    """The block that goes at the top of the document body.

    Names the standard and its version, because a label without them is a word:
    WHITE meant something in TLP 1.0 and AMBER+STRICT did not exist. A report
    that cites the version can be read correctly in five years.

    An unknown language falls back to English rather than dropping the marking:
    a missing translation must not cost the document its distribution terms.
    """
    heading = _HEADING.get(lang, _HEADING["en"])
    return "\n".join([
        heading.format(label=label.value, version=VERSION, url=STANDARD_URL),
        permission(label, lang=lang if lang in {"it", "en"} else "en"),
    ])
