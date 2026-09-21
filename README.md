# ExeRadar

Static analysis of executables: PE first, ELF and Mach-O after. Headers,
imports, readable strings, code signing.

**Status: PE works.** Headers, sections with entropy, the import table and its
categories, classified strings, the three signature paths, and reports as
console, JSON or Markdown. ELF and Mach-O are recognised by their magic number
and declined by name — not mistaken for an unknown format.

The design is written down first, in [ARCHITECTURE.md](ARCHITECTURE.md), and
the part worth reading is section 3.

## Why section 3

A spike against Windows' own `notepad.exe` found that LIEF reports zero
embedded signatures for a file that Windows reports as validly signed: the
signature lives in a catalog under `CatRoot`, which is how most Windows system
binaries are signed and which no PE parser can see.

So signature checking has three paths, not one, and on Linux and macOS — where
the catalog cannot be consulted — the absence of an embedded signature is
reported as `unknown` and never as `unsigned`. Calling a catalog-signed
Microsoft binary unsigned would be the worst false positive this tool could
ship.

## Use

```
exeradar analyze FILE [--output report.json|report.md]
exeradar batch DIR   [--output report.json|report.md]
exeradar verify FILE
```

`analyze` prints one file in full; `--output` picks its format from the
extension and refuses one it does not know rather than guessing.

`batch` walks a directory recursively, analyses every PE it finds and prints a
row per file. With `--output` it writes the whole run: a JSON array, or one
Markdown section per file.

`verify` reads the signature and nothing else — no hashing, no imports, no
strings — and is meant to be a gate in a script:

| Exit | Meaning |
| --- | --- |
| `0` | signed, and the signature verifies |
| `1` | not signed, or signed and the signature does not verify |
| `2` | could not be determined: unreadable, not a PE, or no way to check here |

The third code is the point. Off Windows the catalog cannot be consulted, so a
file with no embedded signature may be perfectly signed and the tool cannot
tell. Returning `1` there would fail a build over a missing capability rather
than over the file; `|| exit` still catches it.

## Legal citations

`law_checker` maps findings to the provisions they concern — Cyber Resilience
Act, NIS2, GDPR — and cites each with the SHA-256 of the exact wording applied.
Nothing is cited that the acts do not contain: a test reads them and fails on
any reference they lack. See ARCHITECTURE.md section 4 for what is deliberately
*not* cited, and why.

## Part of the Radar family

Alongside [apkradar](https://github.com/maksimtech/apkradar),
[mailradar](https://github.com/maksimtech/mailradar),
[cookieradar](https://github.com/maksimtech/cookieradar) and
[patchradar](https://github.com/maksimtech/patchradar).

## Licence

MIT.
