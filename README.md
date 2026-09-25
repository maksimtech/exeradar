# ExeRadar

Static analysis of executables: PE first, ELF and Mach-O after. Headers,
imports, readable strings, code signing.

**Status: PE works.** Headers, sections with entropy, the import table and its
categories, classified strings, the three signature paths, and reports as
console, JSON or Markdown. ELF and Mach-O are recognised by their magic number
and declined by name — not mistaken for an unknown format. That includes a
universal ("fat") Mach-O, the ordinary shape of a shipped macOS binary, whose
magic it shares with Java class files: the fat header is validated rather than
guessed at, so a class file is still declined.

The design is written down first, in [ARCHITECTURE.md](ARCHITECTURE.md), and
the part worth reading is section 3.

## Install

```
pip install exeradar
```

Python 3.11 or later.

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

The same rule applies to the file and not only to the platform. A file that
cannot be parsed, and one whose own headers place the certificate table past the
end of it — an interrupted download — are `unknown` too: the signature could not
be looked for, which is not the same as finding none. Nothing is cited against
either.

## Use

```
exeradar analyze FILE [--output report.json|report.md]
exeradar batch DIR   [--output report.json|report.md]
exeradar verify FILE
```

### `analyze` — one binary in full

```
$ exeradar analyze python.exe

python.exe
  PE AMD64, 106,208 bytes, built 2026-08-05 10:58:33 UTC
  sha256 4942b86a6597e5aee0128daa00050ed79bc21f6e709a78eb19cbfeb0c2f39ac9

Signature embedded
  Embedded Authenticode signature, valid.
  signer     C=US, ST=Oregon, L=Beaverton, O=Python Software Foundation, CN=Python Software Foundation
  signed     2026-08-05 11:45:32 UTC

Imports 8 libraries, 44 functions — no category claimed
  api-ms-win-crt-runtime-l1-1-0.dll    18
  KERNEL32.dll                         15
  VCRUNTIME140.dll                      5
  api-ms-win-crt-stdio-l1-1-0.dll       2
  python314.dll                         1
  api-ms-win-crt-math-l1-1-0.dll        1
  api-ms-win-crt-locale-l1-1-0.dll      1
  api-ms-win-crt-heap-l1-1-0.dll        1

Strings 1 urls, 0 ips, 0 hosts, 1 paths
  url   http://schemas.microsoft.com/SMI/2016/WindowsSettings
  path  D:\a\1\b\bin\amd64\python.pdb

 section  virtual  raw     entropy
 .text    3,628    4,096   6.00
 .rdata   3,942    4,096   4.27
 .data    1,664    512     0.53
 .pdata   348      512     3.77
 .rsrc    80,928   81,408  6.17
 .reloc   48       512     3.90
```

Three things in that output are the tool refusing to overclaim.

**"no category claimed"** — `KERNEL32.dll` imports 15 functions and the
categoriser says nothing about them, because a library that every binary loads
tells you nothing about what this one does. Categories are decided from the
imported functions, not from the library name.

**One URL, not eleven** — the certificate table is excluded from string
extraction. Everything in there belongs to whoever signed the file: on this
binary it was ten Microsoft CRL and OCSP endpoints, which describe the signer
and not the program.

**And that one URL is not a finding.** `http://schemas.microsoft.com/...` is an
XML namespace out of the PE manifest, not an endpoint the program contacts. A
"plaintext endpoint" finding would fire on every Windows binary with a
manifest, so there isn't one.

`--output` picks its format from the extension, `.json` or `.md`, and refuses an
extension it does not know rather than guessing. The name is checked before the
scan starts, so a rejected filename never costs the work.

### `batch` — a directory

Walks recursively and analyses every PE, chosen by magic bytes and not by
extension, sorted by path so two runs stay comparable.

```
$ exeradar batch ./downloads

 file          sha256        signature  findings
 clean.exe     4942b86a6597  embedded   0
 nested.exe    4942b86a6597  embedded   0
 tampered.exe  ec7e1e10899c  embedded   1

3 files, 2 signed and verified, 1 with findings
```

With `--output` it writes the whole run: a JSON array, or one Markdown section
per file.

### `verify` — a gate for a script

Reads the signature and nothing else: no hashing, no imports, no strings, so it
stays fast on a large binary.

```
$ exeradar verify python.exe
embedded
Embedded Authenticode signature, valid.
signer    C=US, ST=Oregon, L=Beaverton, O=Python Software Foundation, CN=Python Software Foundation
signed    2026-08-05 11:45:32 UTC
$ echo $?
0
```

Change one byte in the code section and the signature still parses, still names
its signer, and no longer describes the file:

```
$ exeradar verify tampered.exe
embedded
Embedded Authenticode signature, present but not valid.
signer    C=US, ST=Oregon, L=Beaverton, O=Python Software Foundation, CN=Python Software Foundation
signed    2026-08-05 11:45:32 UTC
$ echo $?
1
```

The exit code carries the answer:

| Exit | Meaning |
| --- | --- |
| `0` | signed, and the signature verifies |
| `1` | not signed, or signed and the signature does not verify |
| `2` | could not be determined: unreadable, truncated, not a PE, or no way to check here |

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
