# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses calendar versioning (YYYY.MM.N).

## [Unreleased]

## [2026.40] - 2026-09-26
### Changed

- **Baseline: the five Radar restart from a common number.** They had drifted to
  .32, .12, .11, .6 and .3 of the same generation, which left the shared part of
  the version meaning nothing at all. The highest count in the suite was taken,
  rounded up for headroom, and every Radar starts again from 2026.40 — a jump
  for most of them, and a number that means the same thing in all five.

  From here the count belongs to each Radar again, and something urgent gets a
  third segment on top: 2026.40.1 before 2026.41, the way a suite has always
  done it. 2026 is a settling year; from 2027 the count moves when the code
  moves.


### Fixed

- **Four findings that named the wrong thing.** A version number is not an
  endpoint: five of fourteen Lenovo driver installers were reported with
  `hardcoded_ip`, and all five addresses were the version of the driver inside —
  `10.1.15.6`, `2.07.1.23`, `23.60.0.1`, `2.25.100.3`, `23.110.0.5`. Three are
  formally valid public addresses, so no octet rule separates them from the real
  thing; what does is that none of those files imports a single network function.
  The finding now requires that capability. The addresses stay in the report as
  facts, with a note saying why nothing was raised — "imports no network
  function" is an observation and not a conclusion, since a packed binary can
  resolve `ws2_32` at run time.

- **The signer is named by the PKCS#7, not by the position of a certificate in
  the list.**

- **A path pattern that stops backtracking.** `_WINDOWS_PATH` was written so that
  two segments could each swallow a separator, which makes every separator in the
  string a candidate for the middle one and rescans the tail for each: measured
  through `classify()`, 26 ms at n=1,000 and 2.9 s at n=8,000 — quadruple the
  input, multiply the time by nineteen. A segment can no longer contain a
  separator, so every character has exactly one place it can go. The same twelve
  paths and non-paths are recognised.

- **Five type errors that only appear with the dependencies installed.** Among
  them, lief types a section or import name as `str | bytes` and returns `bytes`
  for a name whose bytes are not valid UTF-8 — which would have reached both the
  console report and the JSON output as `b'.text'`, quoted prefix and all.

- **A dotted quad the file itself calls a version is no longer reported as an
  IP address.** Four Kyocera installers listed `1.1.2.0`, `1.1.8.0`, `1.1.3.0`
  and `2.1.7.0` among their addresses. Each appears twice in its binary: once
  alone in the .NET metadata, where strings are length-prefixed, and once
  inside `Katana, Version=1.1.8.0, Culture=neutral`. The second occurrence is
  the file saying what the first one is, and `classify` sees both.

  Corroboration inside one file, not a rule about shape: a quad nothing
  explains is still reported, because nothing established what it is. Three of
  the seven survive for that reason and are named in the tests.

- **A hostname's last label has to be a top-level domain that IANA actually
  delegates.** Without that rule every dotted identifier in a binary was a
  host: `Mono.Cecil` and `IniParser.Model` are .NET namespaces,
  `Newtonsoft.Json.dllPK` is a ZIP member name with the archive's own signature
  stuck to it, and the compressed payload of one 436 MiB installer produced
  2,449 two-label strings of which not one was real. That installer now reports
  747 — 1,702 fewer — and every namespace and archive case is gone.

  The residue is named rather than hidden: `.services`, `.tools`, `.management`
  and `.net` are real delegations, so a namespace ending in one still reads as
  a host, and `Microsoft.NET` is the honest worst case.

- **The signing time is read from both countersignature forms.** Two Canon
  printer drivers reported no timestamp while Windows read
  `CN=DigiCert Timestamp 2021` from the same bytes. Authenticode countersigns
  either with an RFC3161 token or with the older PKCS#9 `counter_signature`,
  a whole SignerInfo whose time is its own `signing_time` and whose certificate
  is named by issuer and serial rather than bundled. Only the first was read,
  and the second came back as "no timestamp" — stated as a fact about the file
  rather than as a form nobody had looked for. A signature whose time cannot be
  read stops being verifiable the day its certificate expires.

### Added

- **The Docker image is published.** Built from the tag rather than from PyPI, so
  there is no propagation to wait for, and the smoke test is given the tag as
  `EXPECTED_VERSION`: built from the checkout, the image's version comes from
  `exeradar/__init__.py` while its Docker tag comes from git, and nothing else
  makes those two agree.

- Benchmarks for the calls a scan spends its time in, watched by CodSpeed.

## [2026.09.3] - 2026-09-24

### Fixed
- **Catalog-signed files with a non-cp1252 signer no longer crash the scan.**
  The catalog path — path B of ARCHITECTURE.md section 3, and the only code here
  that runs on Windows and nowhere else — asked PowerShell for a certificate
  Subject and decoded the answer with the locale encoding. A Subject carries
  whichever alphabet the signing CA uses, and one outside cp1252 could not be
  decoded. Because `capture_output` collects the pipes on reader threads, that
  failure never arrived as an exception: it left `stdout` as `None`, and reading
  it raised `AttributeError`, which the surrounding `except (OSError,
  SubprocessError)` does not catch. Both ends are now pinned to UTF-8, and an
  undecodable answer reports `UNKNOWN` — "I could not tell" — rather than
  raising. Ten tests cover it; Linux CI can reach none of them, because
  `catalog_available()` is false there.
- **`EXERADAR_HOME` is no longer taken literally.** `~/cache` made a directory
  actually named `~`, which is what anyone writing that in a Dockerfile `ENV`
  got. A relative value resolved against the working directory, so the cache
  landed somewhere different depending on where the command ran from and quietly
  stopped being one cache. And `"   "` is truthy, so whitespace became a
  directory name. A tilde is expanded, a blank value means unset, and a relative
  value is read against `$HOME` — the variable is called `*_HOME`, and it has to
  mean the same thing wherever the command is run.
- **`f"{signature.state}"` renders `embedded`, not `SignatureState.EMBEDDED`.**
  `SignatureState` is a `StrEnum` rather than a `(str, Enum)` mixin. Every
  caller already wrote `.value`, so no output changes; the two spellings now
  agree instead of relying on everyone remembering which to use.

### Changed
- ruff, mypy, hypothesis and mutmut are development dependencies, with a
  `Quality` workflow running ruff and mypy on every push and pull request, and a
  weekly, non-blocking mutation run. mypy is permissive rather than strict: the
  permissive pass found 42 real defects across the family, all fixed.
- The suite gains fourteen properties checked against generated input, including
  one that pins `entropy()` returning positive zero — `0.0 == -0.0`, so an
  equality assertion cannot tell the two apart and the `-0.00` in the report
  could have come back. Another pins that `normalize_text` is idempotent: its
  output is hashed, and that hash is what says "the law changed", so a
  normalisation that drifted would report a change nobody made.
- A contract test refuses any code in this repository that lets the locale
  choose a text encoding.
- **Every string the tool writes itself is now in English**, which the
  CHANGELOGs already were. The report's section is `Provisions applied` rather
  than `Norme applicate`, and finding titles, scope notes, evidence lines and
  the release script's messages follow. What the tool *quotes* is unchanged: a
  provision's text is fetched from the official Italian version of each act and
  hashed, so translating it would change every SHA-256 in every cache and report
  "the law changed" for every citation on the next run, for nothing.

## [2026.09.2] - 2026-09-22

Three bugs, all found by pointing ExeRadar at a real third-party binary —
BIOSdump2license.exe, a BIOS-dump tool — rather than at the test fixture.

### Fixed
- **`Register*` functions no longer claim the registry category.**
  `RegisterClassW` registers a window class, which every program with a GUI
  does, so every GUI program was reported as touching the registry — through
  USER32, which exports no registry function at all. The rule is now "starts
  with `Reg` but not with `Register`": kernel32 exports 41 real registry
  functions and advapi32 82, and none of them begins with `Register`. Leaving
  the system DLLs out of the category would have hidden those 41, so a test
  guards that `RegOpenKeyExW` and friends are still recognised through
  KERNEL32.
- **Section entropy no longer prints as `-0.00`.** The textbook
  −Σ p·log₂(p) negates its sum, and for a section of one repeated byte that
  sum is 0.0, so it returned −0.0. It is now written Σ p·log₂(1/p), which
  cannot produce a negative zero.
- **…and the report now actually uses that function.** Sections were measured
  with LIEF's own `section.entropy`, which has the same flaw, so fixing
  ExeRadar's function changed nothing a user saw; only rerunning the tool on
  the binary showed it. The values agree with LIEF's to within 1.2 × 10⁻¹⁴.
- **URLs stored back to back are reported separately.** A font's name table
  keeps its strings with no separator, and three URLs came out as one. A URL
  now ends where another scheme begins; each part is still trimmed of the
  DER debris certificates leave around theirs.

### Notes
- Two existing tests could not have caught the entropy bug: both compared
  values (`== approx(0.0)`, `0.0 <= entropy`), and −0.0 equals 0.0. The new
  test checks the sign.
- A URL followed directly by ordinary text keeps that text
  (`…/licenseNK57`): with no separator in the data there is nothing honest to
  cut on.
- 255 tests pass, 28 more than 2026.09.1.

## [2026.09.1] - 2026-09-21

First release. Static analysis of PE binaries: headers, imports, strings, code
signing, and the legal provisions the findings concern.

### Added
- `analyze FILE`: one binary in full — PE headers, sections with entropy, the
  import table and its categories, classified strings, and the signature.
  `--output` picks its format from the extension, `.json` or `.md`, and refuses
  an extension it does not know rather than guessing. The name is checked
  before the scan starts, so a rejected filename never costs the work.
- `batch DIR`: walks a directory recursively and analyses every PE in it,
  chosen by magic bytes rather than by extension, sorted by path so two runs
  produce comparable reports. Prints a row per file — name, short hash,
  signature state, number of findings — and `--output` writes the whole run as
  a JSON array or one Markdown section per file.
- `verify FILE`: reads the signature and nothing else, with no hashing, no
  imports and no strings, so it stays fast on a large binary. Meant as a gate
  in a script, and its exit code carries the answer: `0` signed and verified,
  `1` unsigned or signed with a signature that does not verify, `2` could not
  be determined — unreadable, not a PE, or no way to check on this platform.
- Signature checking by three paths, which is the design this tool exists
  around. A spike against Windows' own `notepad.exe` found LIEF reporting zero
  embedded signatures for a file Windows reports as validly signed: the
  signature is in a catalog under `CatRoot`, which no PE parser can see. So an
  embedded Authenticode blob is read and verified (path A), a catalog entry is
  confirmed through Windows (path B), and only when both have run and found
  nothing is a file called `unsigned` (path C).
- `SignatureState.UNKNOWN`, distinct from `UNSIGNED`. On Linux and macOS the
  catalog cannot be consulted, so the absence of an embedded signature proves
  nothing and is never reported as unsigned. Calling a catalog-signed Microsoft
  binary unsigned would be the worst false positive this tool could ship.
- RFC3161 countersignature decoding, so an expired signing certificate is not
  mistaken for a bad signature when the file was signed while the certificate
  was valid.
- String extraction in ASCII and UTF-16LE, classified into URLs, IP addresses,
  hostnames and paths, with the certificate table excluded: everything in there
  belongs to whoever signed the file, not to the program. On the repository's
  own fixture that took the URLs found from 11 to 1, removing ten Microsoft CRL
  and OCSP endpoints.
- Import categorisation into network, filesystem, registry, process and crypto,
  decided from the imported functions and not from the library alone —
  `ADVAPI32.dll` covers three of the five, and `KERNEL32.dll` claims none by
  itself.
- Section entropy, which marks a packed or encrypted section above roughly 7.0.
- `law_checker`: findings mapped to the provisions they concern, each cited
  with the SHA-256 of the exact wording applied and the date of that wording.
  The acts are downloaded on every run and cached in `~/.exeradar/law_cache.json`
  (`EXERADAR_HOME` moves the folder).
  - Unsigned, invalid signature, expired certificate → **Cyber Resilience Act**,
    regulation (EU) 2024/2847, Annex I, Part I(2)(f), which requires products
    to protect the integrity of programs against unauthorised modification, and
    art. 13(1), which puts that duty on the manufacturer. Also NIS2 art.
    21(2)(d) and GDPR art. 32(1).
  - A hardcoded IPv4 address → CRA Annex I, Part I(2)(j), attack surfaces and
    external interfaces, cited alone and with a note that it is a general
    requirement rather than a rule about addresses.
  - Every CRA citation carries two notes: the regulation applies from
    11 December 2027 (art. 71(2)), so it is in force and not yet applicable;
    and it binds a manufacturer placing a product on the market (art. 2(1)),
    which a PE header cannot establish about a single file.
  - Nothing is cited that the acts do not contain: a test reads them and fails
    on any reference they lack.
- `publish.yml`: tagged releases are built with hatchling and published to PyPI
  through trusted publishing, with no API token in the repository.

### Not implemented
- ELF and Mach-O are recognised by their magic number and declined by name, so
  a Linux binary is answered with "ELF is not supported yet" and not mistaken
  for an unknown format.
- `known_vulnerabilities` is mapped to its provisions — CRA Annex I, Part
  I(2)(a) and Part II(1) and (2), NIS2 art. 21(2)(e) — and produced by nothing:
  ExeRadar does not read dependencies yet.
- No Docker image. `docker-build-check.yml` builds one from the repository to
  keep the Dockerfile honest, and nothing is published.

### Deliberately not reported
- No finding for a URL served over `http://`. The obvious candidate was CRA
  Annex I, Part I(2)(e), confidentiality in transit. The only URL in this
  repository's own fixture is `http://schemas.microsoft.com/SMI/2016/WindowsSettings`,
  an XML namespace out of the PE manifest and not an endpoint the program
  contacts: a finding that fires on every Windows binary with a manifest is not
  a finding.
- Loopback and `0.0.0.0` are not reported as hardcoded addresses: they are how
  a program binds, not somewhere it calls.

### Notes
- EU acts are fetched from the Publications Office's Cellar service,
  `publications.europa.eu/resource/celex/`, with the eur-lex.europa.eu page as
  a fallback. That page now answers automated requests with HTTP 202 and an AWS
  WAF challenge. The two renderings hash identically on the provisions cited.
- `asn1crypto` decodes the RFC3161 token, in place of `signify`. signify was
  the obvious choice and depends on `oscrypto`, unmaintained since March 2022
  and broken against OpenSSL 3.x, which failed on the Linux runners with
  `LibraryNotFoundError`.
- Requires Python 3.11 or later; tested on 3.11, 3.12, 3.13 and 3.14.

[Unreleased]: https://github.com/maksimtech/exeradar/compare/v2026.09.2...HEAD
[2026.09.2]: https://github.com/maksimtech/exeradar/releases/tag/v2026.09.2
[2026.09.1]: https://github.com/maksimtech/exeradar/releases/tag/v2026.09.1
