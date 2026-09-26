"""Genera exeradar/tlds.py dalla lista ufficiale IANA.

Un modulo Python e non un file dati: cosi' non c'e' niente da configurare
nell'impacchettamento, e la provenienza sta scritta accanto ai dati invece che
in un README che nessuno apre.
"""
import pathlib
import textwrap
import urllib.request
from datetime import UTC, datetime

OUT = pathlib.Path(r"C:\Users\Massimo\Documents\Dev\exeradar\exeradar\tlds.py")
SOURCE = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

HEADER = '''"""The top-level domains IANA delegates, and nothing else.

A dotted string is not a hostname because it has dots. `Mono.Cecil` is a .NET
namespace, `Newtonsoft.Json.dll` is a filename, and a compressed payload
produces thousands of two-label strings that look exactly like domains — 2,449
of them from one 436 MiB installer, measured on 2026-09-26, with not a single
real host among them. What separates a hostname from all of those is the last
label, and the list of last labels that exist is public and finite.

Generated from {source}
Version line as published: {version}
Downloaded {downloaded}

Refreshing it is re-running tools/gen_tlds.py. The list grows by a few entries a
year and shrinks when a delegation is withdrawn; a stale copy costs a false
negative on a new TLD, which is the cheaper error here — the alternative is
trusting every suffix, which is what produced the 2,449.
"""

from __future__ import annotations

# Lowercase, as compared: hostnames are case-insensitive.
TLDS: frozenset[str] = frozenset({{
{entries}
}})

SOURCE = "{source}"
VERSION = "{version}"
DOWNLOADED = "{downloaded}"
'''


def main() -> None:
    with urllib.request.urlopen(SOURCE, timeout=60) as response:
        body = response.read().decode("utf-8")

    lines = body.splitlines()
    version = lines[0].lstrip("# ").strip() if lines and lines[0].startswith("#") else "unknown"
    names = sorted(
        line.strip().lower()
        for line in lines
        if line.strip() and not line.startswith("#")
    )

    quoted = ", ".join(f'"{name}"' for name in names)
    entries = "\n".join(
        "    " + chunk
        for chunk in textwrap.wrap(
            quoted, width=92, break_long_words=False, break_on_hyphens=False
        )
    )

    OUT.write_text(
        HEADER.format(
            source=SOURCE,
            version=version,
            downloaded=datetime.now(UTC).strftime("%Y-%m-%d"),
            entries=entries,
        ),
        encoding="utf-8",
    )
    print(f"  exeradar/tlds.py: {len(names)} TLD, versione IANA «{version}»")


if __name__ == "__main__":
    main()
