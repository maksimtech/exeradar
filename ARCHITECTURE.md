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
  law_fetcher.py       from the family, unchanged
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
| `signify` | RFC3161 timestamp decoding, and nothing else | 0.9.2, December 2025 |
| `typer`, `rich` | CLI and console rendering, as the family | |
| `httpx` | `law_fetcher` | |

`pefile` was the obvious candidate and was rejected: its last release is
2024-08-26, it covers PE only, and pairing it with `pyelftools` and `macholib`
for v2 would mean three parsers with three models.

`signify` earns its place for one job. LIEF exposes the countersignature
structure but not the time inside it: the date lives in the TSTInfo of
`content_info.value` and LIEF does not decode the ASN.1. Everything else —
headers, sections, imports, certificate chain, `verify_signature()` — is LIEF.

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
exposed, which is what `signify` is for, and `signers[0].cert` comes back `None`
even though the certificates are present in the structure.

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

The machinery is reused as it stands: `Citation`, `ActStatus`, `LawCheckResult`,
`LawCache` and `law_fetcher` are self-contained and depend only on the standard
library. Only the `FINDING_ARTICLES` map has to be written.

What to cite is an open question, and it is not the one the other Radars answer.
They cite the GDPR because they examine the processing of personal data;
ExeRadar examines an artefact, where an unsigned binary is not by itself
unlawful processing. Candidates, in order of how well they fit:

- **Cyber Resilience Act**, regulation (EU) 2024/2847, which governs products
  with digital elements and their secure development, SBOM and vulnerability
  handling. The closest fit, and unused by the rest of the family. **To be
  verified**: that the text is reachable from EUR-Lex through the existing
  `law_fetcher`, and which articles actually apply.
- **NIS2**, directive (EU) 2022/2555 art. 21, supply chain security — the right
  reference for "is this signed by who it claims".
- **GDPR** art. 32 for findings that touch the security of processing: an
  expired certificate, a plaintext endpoint.

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
