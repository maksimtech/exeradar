# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses calendar versioning (YYYY.MM.N).

## [Unreleased]

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

[Unreleased]: https://github.com/maksimtech/exeradar/compare/v2026.09.1...HEAD
[2026.09.1]: https://github.com/maksimtech/exeradar/releases/tag/v2026.09.1
