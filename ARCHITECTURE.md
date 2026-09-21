# ExeRadar — architecture

Static analysis of executables: PE first, ELF and Mach-O after.

This is the design, written before the code. Where it makes a claim about a
library it is because the claim was measured, not remembered; the spike that
produced the measurements is in `Documents/Dev/exeradar-spike/spike_lief.py`.

---

## 1. Layout

Same shape as the other Radar projects, minus the files that are dead there.

```
exeradar/
  __init__.py          __version__ — hatchling reads the version from here
  __main__.py
  cli.py               typer: analyze, batch, verify
  scanner.py           orchestrates: a path in, an ExeResult out
  formats/
    __init__.py        dispatch on the magic number
    pe.py              headers, sections, import table
    elf.py             v2
    macho.py           v2
  signature.py         the three paths of section 3
  strings.py           extraction, then classification into URL / IP / host
  models.py            the result dataclasses
  report.py            console, JSON, Markdown
  law_checker.py       findings -> legal citations
  law_cache.py         from the family, unchanged
  law_fetcher.py       from the family, plus annexes and the Cellar source
  utils.py
tests/
  fixtures/            sample binaries, legal HTML
  docker/smoke.py
```

Two deliberate differences from apkradar:

**`formats/` is a subpackage from day one.** The name promises three platforms
while v1 delivers one. Splitting the parsers now makes ELF and Mach-O an
addition rather than a rewrite: `scanner.py` picks a parser by magic number and
works against a shared model.

**`report.py` is implemented.** In apkradar, `reporter.py`, `analyzer.py` and
`legal.py` are empty files and the `--output` option of `audit` is declared but
never read — only `batch-excel` writes anything. ExeRadar renders through one
module with three outputs, and `--output` infers the format from the extension.

---

## 2. Dependencies

| Package | Why | Measured |
| --- | --- | --- |
| `lief` | PE, ELF and Mach-O in one library | 1.0.0, July 2026, 76 wheels; installs on Python 3.14 through a `cp312-abi3` wheel |
| `asn1crypto` | RFC3161 timestamp decoding, and nothing else | 1.5.1, pure Python |
| `typer`, `rich` | CLI and console rendering, as the family | |
| `httpx` | `law_fetcher` | |

`pefile` was the obvious candidate and was rejected: its last release is
2024-08-26, it covers PE only, and pairing it with `pyelftools` and `macholib`
for v2 would mean three parsers with three models.

`asn1crypto` earns its place for one job. LIEF exposes the countersignature
structure but not the time inside it: the date lives in the TSTInfo and LIEF
does not decode the ASN.1. Everything else — headers, sections, imports,
certificate chain, `verify_signature()` — is LIEF.

`signify` was the first choice and was dropped after it failed on the Linux
runners with `LibraryNotFoundError: Error detecting the version of libcrypto`.
It depends on `oscrypto`, whose last release is 2022-03-18 and whose libcrypto
version detection does not cope with OpenSSL 3.x. asn1crypto parses the same
structure in pure Python, with no native library to find.

---

## 3. `signature.py` — three paths, not one

This is the part the spike changed. An embedded signature and a signed file are
not the same thing.

### A. Embedded signature — LIEF — every platform

The Authenticode blob is inside the PE. LIEF parses it fully: digest algorithm,
the certificate chain with subjects, issuers, validity, serials and key usage,
the signer, the countersignature structure, and `verify_signature()`.

Measured on `notepad++.exe`: SHA-256 digest, a two-certificate chain from
GlobalSign to `CN=NOTEPAD++`, valid 2025-10-09 to 2028-10-09, an `MsCounterSign`
RFC3161 token carrying four certificates, and `VERIFICATION_FLAGS.OK`.

Two gaps to work around, both in the countersignature: the timestamp date is not
exposed, which is what `asn1crypto` is for, and `signers[0].cert` comes back
`None` even though the certificates are present in the structure.

### B. Catalog signature — Windows only

The file carries no signature at all; the signature lives in a `.cat` file under
`CatRoot` and covers the file by hash. Most Windows system binaries are signed
this way.

Measured on `C:\Windows\System32\notepad.exe`: LIEF reports **zero** embedded
signatures, while `Get-AuthenticodeSignature` reports

```
status        Valid
type          Catalog
OS binary     True
signer        CN=Microsoft Windows, O=Microsoft Corporation
timestamper   CN=Microsoft Time-Stamp Service
```

The file is validly signed and no PE parser can see it. Implementation is
`WinVerifyTrust` through `ctypes`, or a `Get-AuthenticodeSignature` subprocess;
the subprocess is the pragmatic first cut and the API is the version that does
not pay for a PowerShell start-up per file.

### C. No signature — a finding

Neither A nor B produced anything, on a platform where both could run. This is
the only case that is reported as a finding with a severity.

### The rule that follows

**On Linux and macOS, path B cannot run.** A and C still work, so an embedded
signature is still parsed and verified, but the absence of one is no longer
evidence of anything.

There the result is reported as:

```
catalog signature: not verifiable on this platform
```

and **never** as `unsigned`. Calling a catalog-signed Microsoft binary unsigned
would be the worst false positive this tool could ship — it would fire on
exactly the files that are most obviously legitimate.

The same restraint applies inside a Linux container analysing Windows binaries,
which is the normal case in CI.

| | Embedded (A) | Catalog (B) | Verdict when both are empty |
| --- | --- | --- | --- |
| Windows | parsed and verified | verified | `unsigned` — a finding |
| Linux, macOS | parsed and verified | not verifiable | `unknown` — not a finding |

---

## 4. `law_checker` integration

The question this section opened with — what to cite for an artefact, when the
rest of the family cites the GDPR for the processing of personal data — has
been answered against the texts. The answer is the **Cyber Resilience Act**,
regulation (EU) 2024/2847, and it cost two changes to machinery that was
supposed to be reused unchanged.

### What the CRA actually says

Its articles do not contain the requirements. Article 6 allows a product on the
market only if it "meets the essential cybersecurity requirements set out in
Part I of Annex I", and article 13(1) puts that duty on the manufacturer;
both point at **Annex I** and stop. Citing them on their own would be citing a
pointer, so `law_fetcher` learned to address annexes: `"Allegato I, Parte I"`
is a fetchable unit, and its points resolve as `"Allegato I, Parte I(2)(f)"`.
The part belongs in the reference because Part I and Part II are both numbered
from (1).

The provision that carries the signature findings is Annex I, Part I(2)(f):
products shall *"proteggono l'integrità ... dei comandi, dei programmi e della
configurazione da qualsiasi manipolazione o modifica non autorizzata"*. A code
signature is how that integrity can be checked at all, so its absence, its
failure and the expiry of the key behind it are one requirement seen three
times.

### Where the text comes from

Not from `eur-lex.europa.eu` any more. That host now answers every automated
request with HTTP 202 and an AWS WAF challenge (`x-amzn-waf-action: challenge`)
— measured on the CRA and on the GDPR, in both languages, so it is the client
being refused and not the document being missing. The Publications Office
serves the same acts, in the same ELI markup, at
`publications.europa.eu/resource/celex/<CELEX>`, which is the interface that
exists for machines. `fetch_act_html` tries it first and falls back to the old
page, in case the rule is relaxed again.

**This affects the whole family**: APKRadar, MailRadar, PatchRadar and
CookieRadar all fetch through the blocked host and will cite from cache until
they take the same route.

### The mapping

| Finding | Cited |
| --- | --- |
| `unsigned` | CRA Annex I, Part I(2)(f); CRA art. 13(1); NIS2 art. 21(2)(d); GDPR art. 32(1) |
| `signature_invalid` | the same four |
| `certificate_expired` | CRA Annex I, Part I(2)(f); GDPR art. 32(1) |
| `hardcoded_ip` | CRA Annex I, Part I(2)(j) |
| `known_vulnerabilities` *(not produced yet)* | CRA Annex I, Part I(2)(a), Part II(1) and (2); NIS2 art. 21(2)(e) |

Three refusals are as much a part of the design as the citations.

- **No finding for `http://` URLs.** The obvious candidate was Annex I, Part
  I(2)(e), confidentiality in transit. The only URL in this repository's own
  fixture is `http://schemas.microsoft.com/SMI/2016/WindowsSettings`, an XML
  namespace from the PE manifest — a finding that fires on every Windows
  binary with a manifest is not a finding.
- **`hardcoded_ip` cites one provision and admits its weakness.** Part I(2)(j)
  asks products to "limit attack surfaces, including external interfaces"; it
  is a general requirement, not a rule about addresses, and the report says so
  in a note rather than borrowing weight from a stronger article.
- **`unknown` signatures cite nothing.** Off Windows the catalog cannot be
  consulted, so the absence of an embedded signature proves nothing. The whole
  of section 3 exists to avoid that false positive, and a citation is an
  accusation.

Two scope notes accompany every CRA citation, because both would otherwise
mislead: the regulation **applies from 11 December 2027** (art. 71(2)), so it is
in force and not yet applicable; and it binds a manufacturer placing a *product*
on the market (art. 2(1)), which is not something a PE header can establish
about a single file.

### What guards it

`test_every_citation_is_in_the_act` parses the acts and fails on a reference
they do not contain, so the map cannot drift into invention. It reads excerpts
of the real documents, cut from what the fetcher itself downloads; see
ATTRIBUTIONS.md.

---

## 5. Report

The model everything else derives from:

```
ExeResult
  file       path, size, sha256, format, arch, build timestamp
  pe         machine, subsystem, sections [name, size, entropy, characteristics]
  imports    [{dll, functions[]}] plus derived categories
             (network, crypto, process, registry)
  strings    {url[], ip[], host[], path[]}
  signature  state (A / B / C / unknown), chain[], signer, validity,
             timestamp, verification result
  law        LawCheckResult
  findings   [{id, severity, evidence}]
```

Three outputs: **console** through Rich with a "Norme applicate" section at the
end, as mailradar and cookieradar do; **JSON**, which serialises the whole
`ExeResult` and is what makes the tool usable from a pipeline; **Markdown** for
pasting into a ticket.

---

## 6. v1 scope

| Feature | Module | Note |
| --- | --- | --- |
| PE header | `formats/pe.py` | machine, subsystem, sections, entropy |
| Import table | `formats/pe.py` | plus DLL categorisation, which is the value added |
| Readable strings | `strings.py` | ASCII and UTF-16LE, then classification |
| Certificates | `signature.py` | chain, issuer, subject, validity |
| Signature verification | `signature.py` | the three paths of section 3 |
| SHA-256 | `scanner.py` | of the file as given |

Section entropy is not on the original list and is kept anyway: it costs a few
lines and it is the single most informative signal per unit of effort, flagging
packed or encrypted binaries.

---

## 7. Facts and findings

The other Radars reach a verdict because a provision is either respected or it
is not. An executable does not work that way: "imports `WinHttpConnect`" is not
a defect, it is a fact. A report that lists neutral observations without a
thesis is not worth reading.

So the report separates two registers:

- **Facts** — headers, imports, strings, hashes — always reported, never judged.
- **Findings** — unsigned, expired certificate, invalid signature, hardcoded IP
  — carry a severity and may cite a provision.

Only findings reach `law_checker`.

---

## 8. Later, not now

- NVD lookup for known vulnerabilities in identified components.
- Domain allowlist and blocklist comparison for extracted hosts.
- SBOM integration.
- ELF and Mach-O, through `formats/`.

Each of these is a reason the structure above is what it is; none of them is v1.
