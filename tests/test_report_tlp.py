"""TLP 2.0 on a report that leaves this machine.

This is the canonical use of FIRST's Traffic Light Protocol and the reason it was
written: a vulnerability finding sent to a vendor's PSIRT, under embargo, where
whether the recipient may forward it is the whole question. exeradar is the Radar
whose reports go to a PSIRT — `exeradar psirt` now finds the address and the key —
so the report has to be able to say its own distribution terms.

The module arrives by copy from apkradar, the way `law_fetcher` and
`first_teams` do, and its own tests travel with it. What is new here is where the
marking goes, and that differs by format:

- **Markdown** is read by a person: the block goes at the top, before the heading,
  which is where a reader meets it.
- **JSON** is read by a tool: a comment is not available and a banner in a string
  would have to be parsed back out, so the label is a **field**. A consumer that
  forwards the data can read `tlp` and decide; one that cannot see the marking
  cannot respect it.

The two must agree, which is what `test_both_formats_carry_the_same_label` holds.

And an unmarked report stays unmarked in both: no `tlp` key in the JSON, no block in
the Markdown. Silence from whoever ran the scan is not permission to redistribute,
and a default of `TLP:CLEAR` would turn it into one.
"""

from __future__ import annotations

import json

import pytest

from exeradar import report
from exeradar.models import ExeResult, Signature, SignatureState
from exeradar.tlp import Label


def _result(error: str | None = None) -> ExeResult:
    return ExeResult(
        path="C:/tmp/sample.exe",
        size=1024,
        sha256="ab" * 32,
        format="PE",
        arch="x86-64",
        error=error,
        signature=Signature(state=SignatureState.UNSIGNED, verified=False,
                            detail="no embedded signature and no catalog entry"),
    )


# ── markdown: the block a person meets first ────────────────────────────────


def test_the_markdown_carries_the_label_above_the_heading():
    text = report.to_markdown(_result(), tlp_label=Label.AMBER_STRICT)

    assert "TLP:AMBER+STRICT" in text
    assert text.index("TLP:AMBER+STRICT") < text.index("# sample.exe")
    assert "first.org/tlp" in text
    assert "2.0" in text


def test_the_markdown_says_what_the_recipient_may_do():
    from exeradar import tlp

    text = report.to_markdown(_result(), tlp_label=Label.AMBER)

    assert tlp.permission(Label.AMBER) in text


def test_an_unmarked_markdown_report_says_nothing_about_distribution():
    text = report.to_markdown(_result())

    assert "TLP" not in text
    assert "first.org/tlp" not in text


def test_a_failed_analysis_is_marked_too():
    """The one a PSIRT is least likely to want forwarded is the one that says what
    could not be read about their file."""
    text = report.to_markdown(_result(error="not a PE"), tlp_label=Label.RED)

    assert "TLP:RED" in text
    assert "Could not analyse" in text


# ── json: a field, because a tool cannot read a banner ──────────────────────


def test_the_json_carries_the_label_as_a_field():
    data = json.loads(report.to_json(_result(), tlp_label=Label.AMBER))

    assert data["tlp"] == "TLP:AMBER"
    assert data["sha256"] == "ab" * 32        # and the rest of the record is untouched


def test_the_json_field_is_the_token_and_not_a_sentence():
    """A consumer matches on it: `TLP:AMBER+STRICT`, not "amber, strictly"."""
    data = json.loads(report.to_json(_result(), tlp_label=Label.AMBER_STRICT))

    assert data["tlp"] == "TLP:AMBER+STRICT"


def test_an_unmarked_json_report_has_no_tlp_key_at_all():
    """Not `"tlp": null`, and not `"tlp": "TLP:CLEAR"`. The key is absent, because
    the absence is the fact: nobody said anything about redistribution."""
    data = json.loads(report.to_json(_result()))

    assert "tlp" not in data


def test_many_results_are_marked_once_for_the_document_and_once_each():
    """A batch report is one document. The label belongs to the document, and a
    consumer reading a single row out of the array must still see it — so it is on
    every object rather than on a wrapper the row loses."""
    payload = json.loads(report.to_json_many([_result(), _result()], tlp_label=Label.GREEN))

    assert len(payload) == 2
    assert all(row["tlp"] == "TLP:GREEN" for row in payload)


def test_the_markdown_batch_carries_it_once_at_the_top():
    text = report.to_markdown_many([_result(), _result()], tlp_label=Label.GREEN)

    assert text.count("TLP:GREEN") == 1
    assert text.index("TLP:GREEN") < 20


# ── the two formats must not disagree ───────────────────────────────────────


@pytest.mark.parametrize("label", list(Label))
def test_both_formats_carry_the_same_label(label):
    text = report.to_markdown(_result(), tlp_label=label)
    data = json.loads(report.to_json(_result(), tlp_label=label))

    assert data["tlp"] == label.value
    assert label.value in text


# ── through the file, which is what is actually sent ────────────────────────


def test_write_marks_the_file_it_writes(tmp_path):
    target = tmp_path / "finding.md"

    report.write(_result(), target, tlp_label=Label.AMBER_STRICT)

    assert "TLP:AMBER+STRICT" in target.read_text(encoding="utf-8")


def test_write_marks_json_as_a_field(tmp_path):
    target = tmp_path / "finding.json"

    report.write(_result(), target, tlp_label=Label.RED)

    assert json.loads(target.read_text(encoding="utf-8"))["tlp"] == "TLP:RED"


def test_write_without_a_label_writes_what_it_always_wrote(tmp_path):
    md, js = tmp_path / "a.md", tmp_path / "a.json"

    report.write(_result(), md)
    report.write(_result(), js)

    assert "TLP" not in md.read_text(encoding="utf-8")
    assert "tlp" not in json.loads(js.read_text(encoding="utf-8"))
