# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses **CalVer, Apple style**: `YYYY.count[.fix]`, not SemVer.
`YYYY` is the generation, shared by the five Radar; the count belongs to each of
them and moves when its code moves; the third segment is for something urgent on
what has already shipped. The line above said `YYYY.MM.N` until 2026-09-29, which
no version in this file has ever matched — 40 is not a month, and
`tests/test_version_contract.py` has been enforcing the real form all along.

## [Unreleased]

### Fixed

- **An object identifier is not an IP address.** Run on 2026-10-09 against the
  binaries on a Windows 11 workstation, `gpg.exe` 2.5.24 was reported with four
  hardcoded addresses — `1.3.101.110` to `1.3.101.113`, RFC 8410's X25519, X448,
  Ed25519 and Ed448 — and `node.exe` with 189, the whole of OpenSSL's X.520 and X.509
  object table (`2.5.4.3` is commonName). Both raised `hardcoded_ip` and cited the CRA.
  A dotted quad under one of the arcs the registries assign at four components
  (`1.3.6.1`, `1.3.14.3`, `1.3.36`, `1.3.101`, `1.3.132.0`, `2.5`, `2.23`) is now
  read as an identifier when the same file carries an identifier no address can be —
  five arcs, or an arc past 255. Corroboration inside the file, as for versions: the
  arcs are also allocated address blocks, so the arc alone decides nothing, and
  Cloudflare's `1.1.1.1` beside Chromium's OpenSSL table is still reported.

- **An address in 0.0.0.0/8 is not an endpoint.** `0.0.0.0` was already how a
  program binds rather than somewhere it calls; the rest of the block was not, and
  Code.exe (VS Code 1.105, Microsoft) was reported with `0.0.10.0`, `0.0.100.0`,
  `0.1.0.0` as hardcoded addresses out of a resource table. RFC 1122 reserves the
  whole block for "this network" and nothing is routed to it, so it is treated as
  the loopback is: reported as a string, raised as nothing.

- **The evidence of a finding is a line, not a wall.** `hardcoded_ip` on `node.exe`
  listed 191 addresses in one evidence string — nine lines of console, nine of
  ticket. The first ten are named and the rest are counted (`…and 181 more`); the
  whole list stays in the JSON under `strings.ips`, where a tool reads it.

- **A function imported by ordinal is counted.** It has no name, and was dropped:
  `powershell.exe` was shown importing `0` functions from `ATL.DLL`, and `Code.exe`
  29 from `WS2_32.dll` when it asks for 54, 25 of them by number. An ordinal is now a
  function named `#7`, the way dumpbin writes one; the category rules read nothing
  from it, since a number carries no verb.

### Changed

- **The suite also runs on Python 3.15-dev**, as an experimental matrix row that may
  fail without failing the check. 3.15.0 final ships on 2026-10-09 (PEP 790); the row
  is there to learn before the classifier moves, and it becomes a stable row when it
  does. The stable rows must now equal the `Programming Language :: Python :: 3.x`
  classifiers in `pyproject.toml`, and `tests/test_codecov_contract.py` enforces both.

## [2026.42] - 2026-10-08

### Security

- **A filename can no longer run PowerShell.** The catalog check (path B, Windows only)
  put the path into the script as a single-quoted literal and doubled the ASCII quote,
  and PowerShell closes that literal on U+2018, U+2019, U+201A and U+201B as well: a
  file named `a’; <command>; ’b.exe`, legal on NTFS, ran `<command>` with the user's
  rights when `analyze`, `batch` or `verify` reached it — one name in a downloaded folder
  was enough for `batch`. The path now travels in the `EXERADAR_TARGET` environment
  variable and is never part of the script, so there is no escaping left to get wrong.
  Checked against PowerShell's own parser, and on Windows by running it: a name that
  carries `ni pwned` is analysed as the catalog-signed file it is, and no `pwned` appears.

- **Strings out of the binary are printed, not obeyed.** The console report passed
  them to Rich as markup: `http://evil.example/[/x]` in a PE ended `analyze` with a
  `MarkupError`, and a well-formed tag such as `[link=…]` was followed. Every value that
  comes out of the file — its name, strings, section and DLL names, the signer, errors —
  is escaped, in `analyze` and in the `batch` table.

- **The Markdown report cannot carry HTML from the binary.** A path such as
  ``C:\y\`<img src=x onerror=alert(1)>` `` closed its code span and reached the ticket it
  was pasted into as raw HTML; a section named `a|b` added a column to the table. Code
  spans now use a fence longer than any run of backticks inside them, pipes are escaped
  in table cells, and free text — the file name, the signature sentence, library
  evidence, notes — has `& < > [ ]` written as entities, which cannot turn back into
  markup whatever precedes them.

- **A forged certificate table no longer hides the file's strings.** The range the
  header declares for the certificate table was left out of string extraction even when
  LIEF found no signature in it and even when it covered the sections: pointed at
  0x400..EOF, it removed every URL, address and path from the report, and the
  `hardcoded_ip` finding with them. It is skipped now only when a signature was read
  there, and only past the last section.

### Fixed

- **A file whose path is not ASCII is analysed on Windows.** LIEF opens a path through
  the narrow API there, so `caffè.exe`, or anything under `C:\Users\José`, came back as
  "not a PE file", `verify` answered 2 for a validly signed file, and `batch` dropped it.
  Python reads the bytes and LIEF parses them (`pe.parse`), on every platform.

- **A countersignature time with an offset is converted to UTC.** `+0200` was printed as
  local time with " UTC" after it, two hours off on the date that decides whether an
  expired certificate is covered. A time with no zone at all says so instead of being
  given one.

- **A catalog signer whose Subject contains `|` keeps its name.** PowerShell's answer was
  four fields joined by `|`, so `O=Contoso|Fabrikam` lost half of itself to the
  timestamper. The script now answers in JSON.

- **`--output` into a directory that is not there is refused before the scan**, with exit
  code 2, instead of a `FileNotFoundError` traceback after it; a write that fails anyway
  (permissions, a full disk) is reported the same way.

- **`batch` does not follow NTFS junctions.** `Path.rglob` skips symlinks and follows
  junctions, and one pointing back at its parent — `mklink /J`, no privilege needed —
  listed the same PE 64 times. `batch -o` with nothing to report now says that no file
  was written, instead of saying nothing.

- **`tlp.subject` compares the first word, not a prefix:** "TLP:REDACTED minutes" was
  taken as already marked TLP:RED, and "TLP:AMBER+STRICT" as TLP:AMBER.

- **`first_teams.resolve` does not choose between two exact matches.** An organisation
  can have more than one member team — a product PSIRT and a corporate CERT, with
  different addresses and keys — and the first in the response was returned. Both are
  now candidates, and `psirt` exits 2.

- **PyPI is published from a tag only, and after the suite.** `publish.yml` compared tag
  and version for tags alone, so a dispatch from a branch published that branch; and it
  waited for no test. A `test` job, without the publishing token, now comes first.

- **The README examples say what the tool prints**: "2 matching their signature" and
  the signature sentences of `verify`, which had changed since they were written.

- **`.gitattributes` keeps shell scripts LF.** With `core.autocrlf=true` a Windows
  checkout turned `release.sh` into CRLF and bash stopped at `set -euo pipefail`.

- **Five tests no longer assert the author's installed DLL versions** (OpenSSL 3.5.8,
  curl 8.13.0, pcre2 10.48): they failed on any machine that had updated Git for
  Windows or Windows. The expected version is read from the library's own statement in
  the same bytes; which library, and nothing else, is still asserted exactly.

- **A dispatched rebuild now stands on the tag it was given.** `docker.yml` can be run by
  hand with the tag of an already published release to rebuild it, and it checked out the
  default branch — while the image is built from that checkout.

  The consequence was milder than it sounds, which is why it survived: the smoke test
  compares the version inside the image against the tag and runs on a `push: false`
  build, before the login and before anything is pushed, so a rebuild of `v2026.40` from
  a `main` holding 2026.41 failed rather than publishing the wrong code. What it meant is
  that rebuilding an older release could not work at all, and failed with a version
  mismatch that reads like a packaging problem rather than like a checkout standing in
  the wrong place. patchradar had the same omission on 2026-10-04 with no comparison
  behind it, where it would have tagged `main`'s code with an old release's number.

- **The image is built on every push and pull request, not only when asked.**
  `docker-build-check.yml` was reachable by hand alone, so the only thing that built this
  image automatically was `docker.yml` — on a tag, pushing as it went. The first attempt
  at a build was the one that published it. Nothing stopped it from running on every
  change: this image is built from the checkout with no version to resolve, unlike
  apkradar's and mailradar's, whose build check has to be handed a published version
  because their Dockerfiles install from the index.

- **Three comments that said "the other four Radar install from PyPI".** patchradar
  stopped on 2026-10-04 and builds from the tag's source, as this one always has. Three
  of four now, and the difference matters, because those comments are what somebody will
  read when deciding what to do about the remaining ones.

  Four mutations hold the two new cases. One of them did not fail at first: the case read
  a fixed 400-character window after `actions/checkout`, which reaches into the step that
  extracts the version and names `inputs.version` for its own reasons — so a checkout
  that ignored the input looked like one that used it. The window now ends where the step
  ends.

### Added

- **Findings in the `analyze` report.** ARCHITECTURE.md section 7 separates facts from
  findings, and the console and Markdown reports showed only the facts: a
  `signature_invalid` of severity high reached the JSON and the count in `batch` and
  nobody reading `analyze`. Both now end with the findings, title and severity first.

- **"Provisions applied", as README and ARCHITECTURE.md section 5 describe.**
  `law_checker.check` was called by nothing, so no report carried a citation or the notes
  that qualify them (the CRA applies from 11 December 2027; it binds a manufacturer).
  `analyze` now cites, in the console and in Markdown. The JSON is unchanged: it
  carries the findings, not the citations.

- **`analyze --online`, and offline by default.** `analyze` cites from the local cache
  in `~/.exeradar` and downloads nothing; `--online` downloads the texts the findings
  need and refreshes the cache. A provision the cache does not hold is cited without a
  hash, and the run says so and suggests `--online`, instead of failing. A clean file
  touches no network either way.

- **The files the build is told to include are checked to be there.** apkradar lost its
  `LICENSE` out of the working tree on 2026-10-04 and the loss reached `main`: pyproject
  names the file, so `python -m build` failed with `License file does not exist: LICENSE`,
  and the PyPI publish and the image went down with it. cookieradar lost its own a few
  hours later, during a run of the suite. Neither suite noticed, because neither looked.

  What removes them is still not known, and these cases do not explain it. They stop it
  reaching a commit, which is the part that can be fixed without knowing.

  The expectation is read out of the declarations rather than written down as `LICENSE`,
  because the five Radar do not declare it the same way: patchradar states its licence as
  text and only its Dockerfile names the file, the other four name it in pyproject, and of
  those apkradar and mailradar do not copy it into the image. So two cases — every file
  pyproject names, and every path the Dockerfile copies — and between them each repository
  is covered, three of them twice.

  Checked by moving the file aside in all five: it fails where it should and passes where
  the declaration genuinely does not name it, and pointing pyproject at a file that is not
  there fails too.

- **A release script, which this repository never had.** The other four Radar release
  through `release.sh` or `scripts/bump_version.py`; here `__version__` was edited by
  hand, committed, tagged and pushed. That is why the suite gate the other four were
  given had nowhere to live: there was nothing to put it in. Ported from cookieradar,
  where the script and its cases were written, with the version file and the product
  name changed and nothing else.

  What it refuses: a version that is not `YYYY.count[.fix]`, a middle segment that
  reads as a month, the version already in `__init__.py`, a branch other than `main`,
  a dirty tree, a local `main` out of step with the remote, and a tag that exists
  either side. Then it bumps, **runs the suite with the new version in place**, and
  commits only if it passes — `publish.yml` already checks that the tag matches
  `v$VERSION`, so the two halves agree.

  23 cases hold it, and five mutations were checked against them: the gate removed,
  the version check disabled, a dirty tree allowed, an existing tag no longer
  stopping anything, and the push no longer atomic. All five fail.

### Changed

- **`law_checker.check` takes `offline` instead of `**context`.** The extra keywords were
  passed to `findings_of` and `notes_of`, which accept none, so any of them ended in a
  `TypeError` from inside the check.

- **The catalog check has no branch left for an answer that is not JSON.** Exit 0 from
  the script is always one JSON object — `[ordered]@{…} | ConvertTo-Json -Compress` under
  `$ErrorActionPreference='Stop'` — and every failure (no such file, a directory, access
  denied, a file in use) is a non-zero exit with nothing on stdout, which was already
  turned away. Measured with the real PowerShell on 2026-10-07, on catalog-signed,
  embedded-signed, unsigned, empty and text files, and held by `test_catalog_encoding.py`.
  Should it happen anyway, a `ValueError` from `json.loads` joins the `OSError` and
  `SubprocessError` path: "I could not tell", never a traceback out of `analyze` or
  `verify`.

- **The tests behind the fixes above ask real inputs, not mocks.** PowerShell is the real
  one on Windows; elsewhere it is its real replies, recorded in
  `tests/fixtures/powershell_catalog_replies.json`, which a Windows case asks again and
  compares, so a recording that stops being true fails rather than lingers. "No network
  without `--online`" is a listener on 127.0.0.1 named as the proxy for every scheme, and
  it hears `--online` reach europa.eu — which is what makes an empty list evidence. The
  two exact matches in FIRST's directory are its real answer to `?q=EY`, "EY" and
  "EY CSIRT", in `tests/fixtures/first_teams_ey.json`. Against `main` before the fixes,
  each converted test fails on the defect it protects.

## [2026.41] - 2026-10-03

### Added

- **Library versions, read out of the strings: a new `libraries.py` and a
  `libraries` field on every report.** A statically linked zlib is invisible to
  every dependency scanner that reads a manifest, because there is no manifest —
  the code is inside the executable and the only place it says so is a string.
  System32's `curl.exe` is the case in one line: it reports `curl 8.13.0` and
  `zlib 1.3.1`, and nothing else in that file mentions zlib at all.

  Four claims, and they are deliberately not the same claim:

  | source | what it means |
  |---|---|
  | `banner` | the library states its own version and the code is here — `OpenSSL 3.5.8 25 Aug 2026`, `libcurl/8.22.0`, `expat_2.8.5` |
  | `build path` | the source directory it was compiled in, left behind by an assert's `__FILE__` — `../openssl-3.5.8/crypto/asn1/a_int.c` |
  | `assembly reference` | a version this file asks another file for at run time, not one it carries |
  | `import` | used, and the version is in that DLL and not in this file — so the row names the DLL |

  Every rule came out of running a loose version against a corpus of DLLs that are
  each one known library — the Git for Windows ucrt64 tree plus
  `C:\Windows\System32\curl.exe`, fifteen libraries, measured 2026-10-02 — so that
  each answer could be checked against something true rather than against a
  plausible shape.

  **What it refuses matters more than what it finds.** Four of those fifteen carry
  their version as a bare number with no name beside it: pcre2 as
  `10.48 2026-08-31`, zstd as `1.5.7`, idn2 as `2.3.8`, and the committed
  `python.exe` as `3.14.7`. None is reported. That shape is also an OID
  (`1.2.840.113549.1.1.1`) and four bytes of debris (`8.9.:.`), both out of the
  same corpus, and being right about pcre2 by accident is not worth being wrong
  about those. Nor is a protocol version a library version: `http/1.1`,
  `RTSP/1.0`, `TLS 1.2 (1.1, 1.0) ciphers to use` and `TLSv1.3` are fourteen of
  the sixteen name-then-number strings in `curl.exe`, and libssh2's handshake
  banner `SSH-2.0-libssh2_1.11.1` holds both numbers at once with only the second
  belonging to the library.

  Because silence is the common answer, `libraries.CAVEAT` is printed next to the
  list whether or not there are rows: *a library missing from this list is not
  absent*. An empty list is the answer most often misread.

  Two decisions were wrong first and are recorded in the code as such. One row per
  library hid the file that matters — Git's `curl.exe` states `curl 8.22.0` in its
  own banner and imports `libcurl-4.dll`, which is where the code is and what
  somebody patching curl would have to replace — so a library stated here *and*
  imported now gets a row for each. And a comment claimed the banner's anchoring
  was the rule doing the work; a mutation showed it changes no answer anywhere in
  the corpus, so the comment now says what is true and the rule is kept for the
  reason it actually has.

  JSON keeps `"version": null` rather than dropping the key, which is the opposite
  of what `tlp` does and deliberately: an absent `tlp` means nobody chose a label,
  while a null version means the file was asked and did not say.

  The scanner now extracts the strings once and gives both passes the same list —
  the library pass needs the raw runs, since a release directory is a path and
  `OpenSSL 3.5.8 25 Aug 2026` is in none of the four buckets. A second call would
  have read a 25 MB DLL twice, which `test_the_file_is_read_for_strings_exactly_once`
  now prevents.

  54 tests, of which eight run against the corpus itself. `ARCHITECTURE.md` gains
  section 8 for the module, and its layout list is brought back in line — four
  modules added in earlier commits were missing from it and one that does not exist
  was in it.

### Removed

- **Four settled entries out of `SECURITY-EXCEPTIONS.toml`, and the fifth kept on
  purpose.** The gate has been reporting five exceptions whose finding nobody
  reports any more, and the difference between them is the whole decision.

  `CVE-2025-47273`, `CVE-2026-57585`, `GHSA-6v7p-g79w-8964` and `CVE-2026-84782`
  were all closed by GitHub at **2026-09-30T19:26:53Z** — one timestamp, which is
  the republish — and Docker Scout has run six times since without mentioning any
  of them. The absence is explained in both cases: the first three were copies
  vendored under `pip/_vendor/`, which the Dockerfile removes along with the rest
  of the build tooling, and the fourth was openssl, which
  `patchradar debian CVE-2026-84782` reports resolved in trixie at
  `3.5.7-1~deb13u3` and which `apt-get upgrade` picked up at the rebuild. Each was
  written as "closes when the next image is published"; it was published, so they
  are gone. Their return would mean a fix regressed, which is worth a build
  failing over.

  `CVE-2026-82560` stays, and **not** because its silence is shorter — it is
  longer. That alert closed at 2026-09-29T15:08:22Z, a different and earlier
  moment, with nothing done to the image in between, and the absence has held
  across eleven Scout runs over three days against the other four's six. The
  deciding fact is elsewhere: `patchradar debian CVE-2026-82560` on 2026-10-02
  still reports `perl` no-dsa in trixie at `5.40.1-6+deb13u1`, no fix in any
  suite, Debian bug 1148455. perl-base is still installed and still unfixed; only
  the reporting changed, and Scout has already changed its mind about this exact
  id once — which is why the gate reads closed alerts at all. Deleting a flaw that
  is demonstrably present because a scanner fell silent is the one direction this
  file must not drift in, so the entry now says so in writing.

  `tests/docker/inspect.sh` keeps its pip/setuptools probe and gains the reason:
  with those three entries gone, that probe is the only thing that would notice
  the removal regressing.

  Fourteen entries down to ten. The gate still passes, which was checked by
  running it locally against this repository's live alerts and not by inference.

### Changed

- **The CI runners are pinned to `ubuntu-26.04`, and the benchmarks job is pinned
  to `ubuntu-24.04` because CodSpeed cannot run on 26.04.** `ubuntu-latest` was
  Ubuntu 24.04 — read off a live run on 2026-10-02, image `ubuntu24/20260927.320` —
  and GitHub moves that label on its own schedule, so the choice was between finding
  out what breaks on a branch or finding out later on `main` at a moment nobody
  picked.

  Something did break, which is the whole value of having asked: `CodSpeedHQ/action`
  v5 fails on 26.04 with `##[error]Unsupported system`. `mode: simulation` was
  already set and the action was pinned, so it is the image and nothing else. Every
  one of the five Radar runs CodSpeed, so every one of them would have broken the
  same way the day the label moved by itself.

  That job is pinned to **24.04 rather than left on `ubuntu-latest`**: left there it
  keeps working right up to the day the label moves and then fails on `main`. 24.04
  is supported until April 2029, and a comment beside it says to try 26.04 again now
  and then, because nothing here will notice when CodSpeed adds support.

  The risk surface was measured before anything changed — no `apt-get` and no `sudo`
  in any workflow, Python from `actions/setup-python` at explicit versions, no
  `container:` or `services:` jobs — and the Docker path was checked on its own by
  dispatching `docker-build-check.yml` against the branch, which succeeded on image
  `ubuntu26/20260927.149`.

  What pinning costs: nothing bumps it for you. Dependabot updates action versions,
  not `runs-on`.

- **ruff now lints `tools/` as well, because it never did.** Every one of the five
  Radar lints its package and its tests and stops there, which left
  `tools/security_exceptions.py` outside the check — the script that refuses a build
  over an unexplained alert had never been seen by the linter that gates the build.
  Found on 2026-10-02 by running ruff over the whole tree by hand while working on
  something else, which is not a way of finding things that scales.

- **`README.md`'s `analyze` transcript is regenerated from the tool.** It was a
  claim about what gets printed, and three things had drifted out of it: the
  overlay line, the signature sentence — which stopped saying "valid" when it
  stopped being able to mean it — and now the Libraries block. `python.exe` turns
  out to be the best example of the new refusal, so the three things in that output
  that are the tool declining to overclaim are now four.

- **A report can carry its own distribution terms: `--tlp` on `analyze` and
  `batch`.** This is the case FIRST's Traffic Light Protocol exists for — a finding
  sent to a vendor's PSIRT before it is public, where whether the recipient may
  forward it is the whole question. exeradar is the Radar whose reports go to a
  PSIRT, and since `exeradar psirt` now finds the address and the key, the document
  needed a way to say its own terms.

  Where the label goes differs by format, and that is the one new decision here:

  | format | where | why |
  |---|---|---|
  | Markdown | a quoted block above the heading | it is read by a person, and that is where they meet it |
  | JSON | a `tlp` field, first | it is read by a tool; a banner in a string would have to be parsed back out, and a consumer that cannot see a marking cannot respect it |

  A batch report is marked **once** in Markdown — one document, and repeating the
  block between headings teaches the eye to skip it — and on **every object** in
  JSON, because a consumer can read a single row out of the array and must still see
  the terms it came under. `test_both_formats_carry_the_same_label` holds the two
  forms to the same answer for all five labels.

  Written for real while this was added:

  ```
  > Distribution: TLP:AMBER+STRICT (TLP 2.0 — https://www.first.org/tlp/)
  > May be shared with members of the recipient's organisation only, and no further.

  # python.exe
  ```

  An unmarked report stays unmarked: no block, and **no `tlp` key at all** — not
  `null`, and not `TLP:CLEAR`. Silence from whoever ran the scan is not permission
  to redistribute. A label the standard does not define stops the command before
  the file is opened, and `TLP:WHITE` is refused by name with its replacement:
  *TLP:WHITE belongs to TLP 1.0 and was renamed in TLP 2.0: use TLP:CLEAR instead*.

  The console output is deliberately not marked. A terminal is not a document that
  travels, and a label printed where it cannot be respected teaches a reader to
  ignore it where it can.

  `exeradar/tlp.py` arrives by copy from apkradar, the way `law_fetcher` and
  `first_teams` do, with its own thirty-four tests; seventeen more cover the report
  and the commands.

- **The gate reads FIRST's forecast on the CVEs it already holds.** EPSS is indexed
  by CVE, and `SECURITY-EXCEPTIONS.toml` is the one surface in this repository that
  holds CVE ids: Docker Scout names its alerts by CVE, so every accepted finding
  already has an id, a written reason and a review date. The forecast is what those
  records lacked — "no fix in any suite" accepted until December is comfortable at
  an EPSS of 0.1% and is something else at 40%.

  The forecast changes no verdict. The gate fails on a blocking alert with no entry
  and on an entry past its date, and on nothing else: `exit_code` takes the
  forecasts and ignores them, so the signature says they were available and did not
  decide anything. Only ids that *are* CVE ids are looked up —
  `SNYK-DEBIAN13-GCC14-20386241` is CVE-2026-95619 and says so in its description,
  and reading prose is guessing. A CVE FIRST does not score prints "not scored by
  FIRST" rather than 0.0%, which is a real reading at the floor of the scale; FIRST
  unreachable prints nothing and the report is the one this script produced before.

  The accepted findings are listed on a **passing** run, worst first, because that
  is where somebody decides whether to renew a review date and nothing else prompts
  it.

  Ported from patchradar with its nineteen tests; `tools/security_exceptions.py` is
  shared by copy across the five, and all four copies were byte-identical before
  this.

The signature entries below *do* change the package, so the next release carries
a version. The Docker entry further down does not and never did: that image is
republished by dispatching `docker.yml` with the current version, and a tag for
it would have claimed a package change that had not happened.

### Added

- **FIRST's member directory, as a source.** CVE names a flaw and NVD scores it;
  FIRST is the body that says who answers for it. `exeradar/first_teams.py` reads
  `api.first.org/data/v1/teams` — public, no credentials, `"access": "public"` in
  every response — and returns each team with its verified address and the PGP key
  to encrypt to. Until now that lookup happened by hand, in a browser, once per
  disclosure.

  Two rules shape it, and neither is about HTTP.

  **It never chooses between two organisations.** A search for "hewlett" returns
  Hewlett Packard Enterprise — split off in 2015 — *before* HP Inc., whose name is
  on a 250 G6. Both are full members, with different addresses and different keys:

  | | | |
  |---|---|---|
  | HP Inc. PSRT | `hp-security-alert@hp.com` | `0xF46ECE7D08F8DDD9` |
  | HPE PSRT | `security-alert@hpe.com` | a different key |

  Taking the first row would send an embargoed finding to the wrong company, so
  `search` returns every candidate and `resolve` answers only on an exact name,
  handing the candidates back otherwise. Measured by mutation: a resolver that
  takes `candidates[0]` fails two of the tests.

  **An empty answer is never an answer about the vendor.** FIRST lists its members;
  most PSIRTs are not in it. "No member team" comes back as a reason that says so
  and points at security.txt instead; a timeout raises. The same split
  `collectors/` keeps between "nothing found" and "could not ask".

  A fingerprint is normalised to forty uppercase hex characters or dropped — the
  directory prints some of them in spaced groups, and a malformed fingerprint
  offered as one is worse than none, because it is what a key gets checked
  against. A row with no address is dropped: it answers nothing.

  Eighteen tests. Seventeen run on trimmed copies of the live payloads; the
  eighteenth asks the real directory, and only when `EXERADAR_LIVE=1` — a copy
  cannot notice a renamed field, and `pgp-fingerprint` disappearing would leave
  every other test green while the letters went out without a key.

  **`exeradar psirt <organisation>`** is the caller. Like `verify` it is meant to
  be used from a script, so the exit code carries the answer: **0** one team
  matched exactly, **1** FIRST lists no member team by that name, **2** the
  directory was unreachable or nothing it returned matches exactly. 1 and 2 are
  different answers — the first sends a reader to the vendor's security.txt, the
  second says nobody got an answer — and 2 also covers the case this command
  exists for, where printing what came back would hand a script the wrong
  company's address.

  `--key` prints the public key block and nothing else, for
  `exeradar psirt "HP Inc." --key | gpg --import`. With a fingerprint on record
  and no key block it exits 1 and prints the fingerprint, so the key can be
  fetched elsewhere and checked against it.

  Ten more tests. Two of them passed before the command existed — Typer exits 2
  on an unknown command, so an exit code alone proves nothing — and were tightened
  until they could only pass against the real thing.

### Fixed

- **Mutation testing runs again: `also_copy` in `[tool.mutmut]`.** The Saturday
  run died in all five Radar on 2026-10-03, before a single mutant was tried, and
  the cause was the same one each time with a different victim — here, `tests/test_exceptions_epss.py` could not import `security_exceptions` from `tools/`.

  mutmut copies `source_paths` into `mutants/` and runs the suite from there,
  adding only `tests/`, `test/`, `setup.cfg`, `pyproject.toml` and `uv.lock` of its
  own accord. So every test that imports from `tools/` or `scripts/`, or reads a
  file at the repository root, found nothing — and since the stats phase runs the
  suite rather than merely collecting it, one such test killed the whole run.

  The list was verified rather than guessed. mutmut 3.8 refuses to run on Windows,
  so the `mutants/` tree was rebuilt by hand from mutmut's own copy rules —
  `configuration.py:184` and `utils/file_utils.py:66` — and the suite run inside it
  until it passed: **725 passed, 4 skipped**.

  This is *not* the previous day's move to `ubuntu-26.04`: the failures are
  Python-level, inside a copied tree, and patchradar's instance dates from
  2026-09-26. The weekly cron is only what surfaced them all at once — the first
  firing since the tests that trip it were written.

- **The image Snyk scans has a fixed tag, so code scanning keeps one
  configuration for it.** It was built as `snyk-scan:${GITHUB_SHA}`, and Snyk
  Container writes its own automation id into the SARIF from the image reference it
  scanned — overriding the `category:` given to `upload-sarif`. So every commit
  minted a new code-scanning configuration that nothing could ever find again, and a
  pull request was told *"configurations present on refs/heads/main were not
  found"* and could no longer be shown which alerts it had introduced.

  Measured on 2026-10-02 in apkradar, which had reached **32** of them and whose
  pull request #16 could not be diffed. This repository shows one, because its image
  does not carry the extra target Snyk names the image in. The tag is the same in
  all five, so the fix is too: the defect is there whether or not it has surfaced.

- **Two advisories of 2026-09-30 are recorded.** `CVE-2026-84782` (OpenSSL, DTLS
  retransmission, already fixed in Debian at 3.5.7-1~deb13u3 and waiting only on a
  rebuild) and `SNYK-DEBIAN13-GCC14-20335537` / CVE-2026-102010 (open in trixie
  with no fix in any suite, and `libstdc++6` is what LIEF is built on). The other
  four Radar had these entries before their tags went out; exeradar was not
  released that day, so its gate refused the next push to main instead — which is
  the gate doing its job rather than a new defect.

- **"Not valid" no longer means "we could not check".** `verify_signature()`
  returns a bitmask of thirteen flags and this package read it as `== OK`;
  everything else became `verified=False`, which `law_checker` turns into
  `signature_invalid` — "Embedded signature not valid", severity high, cited
  against CRA Annex I Part I(2)(f) and art. 13(1), NIS2 art. 21(2)(d) and GDPR
  art. 32(1). Five of the flags say nothing of the kind:

  | flag | what it actually says |
  |---|---|
  | `UNSUPPORTED_ALGORITHM` | LIEF does not implement the algorithm |
  | `CERT_NOT_FOUND` | the blob does not carry the signer's certificate, so there is nothing to compare against |
  | `MISSING_PKCS9_MESSAGE_DIGEST` | the authenticated attributes are not laid out the way LIEF looks for. Older Authenticode blobs are not, and Windows accepts them |
  | `CERT_EXPIRED`, `CERT_FUTURE` | the certificate's dates do not cover the moment of the check, which says nothing about the digest — and an expired certificate already has its own finding, with its own provisions |

  `verified` is now three-valued and `None` means the check did not reach a
  conclusion; the flags travel with it, so a report names the reason instead of
  printing a verdict with nothing behind it. A file in that state produces a note
  saying it is a limit of the check rather than a finding about the file, and
  `exeradar verify` exits 2 — "could not be established" — where it used to exit
  1, the code a script reads as "this signature is bad".

- **A signature that is present and unreadable is no longer reported as absent.**
  A certificate table that lies inside the file and cannot be parsed — a damaged
  copy, a format LIEF declines, a deliberately malformed blob — fell through to
  `UNSIGNED`: "no embedded signature and no catalog entry", about a file carrying
  14 KB of one. On Windows the catalog was consulted first and also said no, which
  made the wrong answer look corroborated. It is `UNKNOWN` now, with the size and
  the offset of what is there.

- **The notes no longer state a cause for `UNKNOWN` that may not be the one.**
  Every unknown signature printed "the Windows catalog cannot be consulted on this
  platform", including on Windows, where it had been consulted, and for a file
  that simply would not parse. `UNKNOWN` has four causes and the note now carries
  the one that applied.

- **"Truncated" is no longer asserted as the cause.** A certificate table pointing
  past the end of the file is a measurement; a cut-off download is an explanation,
  and a malformed or forged header produces the same measurement. The detail gives
  the numbers, offers the ordinary cause, and says which of the two it is has not
  been established.

- **The report claims no trust.** "signed and verified" and "valid" were doing the
  work of "from a publisher this machine trusts", and no certificate store is
  consulted anywhere in this tool: a self-signed certificate verified exactly as
  well as a commercial one. What is measured is that the file still matches what
  somebody signed, and that is what the sentence now says.

  Twenty-three tests, including one that walks every flag LIEF exposes and fails
  if a future version adds one nobody has classified — an unsorted flag would land
  in "could not tell" and quietly stop being reported.

- **The runtime image no longer carries the build tooling.** Docker Scout reported
  CVE-2025-47273, CVE-2026-57585 and GHSA-6v7p-g79w-8964 against
  `pip/_vendor/bom.cdx.json` — copies vendored *inside* pip and setuptools, at a
  path no dependency of this project can influence. Pinning cannot reach them: an
  explicit install of a patched msgpack adds a second copy beside the first and
  leaves the one the scanner reads exactly where it was. patchradar spent a month
  with pins in place and the same three findings open before that became clear.

  A runtime image needs none of the three: the entrypoint is `exeradar`, and
  neither lief, asn1crypto, typer, rich nor httpx imports `pkg_resources` —
  checked rather than assumed. Verified by building the image in
  `docker-build-check.yml`, which publishes nothing: pip, setuptools and wheel all
  absent, no `pip/_vendor/bom.cdx.json` anywhere, 87 packages, and the smoke test
  and CLI still passing — which is the part a removal like this could have broken.

  The three alerts close when the next image reaches Docker Hub, because that is
  what Scout reads, not the image CI builds.

- **The SonarCloud workflow ran the benchmarks and died on them.** It had been
  failing since at least 2026-09-26, and not on the quality gate: `pytest tests/`
  includes `tests/benchmarks`, whose nineteen tests need the `benchmark` fixture
  that only `codspeed.yml` installs. All nineteen errored and the workflow ended
  before the scan, with 571 tests passing in the same run. Benchmarks are excluded
  here now, as in three of the other four Radar — a timing measured under coverage
  instrumentation means nothing anyway.

### Added

- **A CI gate that refuses.** Every other security workflow reports: `snyk.yml`
  carries `continue-on-error`, CodeQL and Docker Scout upload SARIF, and
  SonarCloud decides its quality gate after the job has already succeeded. On
  2026-09-29 all of them were green while nine high-severity alerts were open.
  `security-posture.yml` reads what they published and fails when a blocking
  finding has nobody's name against it; `SECURITY-EXCEPTIONS.toml` records the
  accepted ones with a reason and a review date. `sonarcloud.yml` now waits for
  its own quality gate, without which a red gate is a green job.

- **`tests/docker/inspect.sh` prints what the image contains** instead of leaving
  it to be remembered. It settles the two claims the exceptions record rests on:
  that the build tooling is gone, and that only `perl-base` is installed —
  Essential, which dpkg itself depends on, so CVE-2026-82560 is ours to record and
  not ours to close. `perl`, `perl-modules` and the two `perlapi` entries come
  back from dpkg-query with no version at all: virtual packages perl-base
  provides, not installs. That measurement had been borrowed from patchradar's
  image and is now taken in this one.

## [2026.40.1] - 2026-09-26

### Fixed

- **Strings are read from the image, not from what is glued behind it.** A
  457 MB HP webpack reported 747 hostnames and 350 paths and not one was real:
  `00c.Bvv`, `/-/9`, `/./G`. The cause was in the section table exeradar
  already prints — the sections sum to 684 KB, so 99.85% of the file is
  overlay, the bytes past the last section that the loader never maps and that
  in a self-extracting installer are the compressed payload. Printable runs
  pulled out of compressed data will always manufacture `xx.yy` pairs that
  happen to end in a delegated suffix.

  The overlay now joins the certificate table as a range the strings pass does
  not read. Measured on four binaries: the webpack drops to 0 hosts and 1 path,
  and two Kyocera installers and the test fixture do not move at all — their
  overlays are the signature and nothing else. The one path left on the webpack
  is the build path of its 7-Zip SFX stub, which was always there under the
  noise. The scan also went from 135 seconds to 9.

  How much was skipped is on the result and in the report. Leaving most of a
  file unread is defensible; doing it without saying so is not.

### Added

- **`exeradar --version`**, which the other four Radar had and this one did
  not, so the version had to be read out of `pip list`. It comes from
  `exeradar.__version__` rather than a literal.

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

[Unreleased]: https://github.com/maksimtech/exeradar/compare/v2026.42...HEAD
[2026.42]: https://github.com/maksimtech/exeradar/releases/tag/v2026.42
[2026.41]: https://github.com/maksimtech/exeradar/releases/tag/v2026.41
[2026.40.1]: https://github.com/maksimtech/exeradar/releases/tag/v2026.40.1
[2026.40]: https://github.com/maksimtech/exeradar/releases/tag/v2026.40
[2026.09.3]: https://github.com/maksimtech/exeradar/releases/tag/v2026.09.3
[2026.09.2]: https://github.com/maksimtech/exeradar/releases/tag/v2026.09.2
[2026.09.1]: https://github.com/maksimtech/exeradar/releases/tag/v2026.09.1
