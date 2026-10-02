"""Which libraries a file admits to carrying, and which it only points at.

A version read out of a binary is worth having for one reason: it is what a CVE
matches against. Which is also why getting it wrong is expensive — a row saying
`http 1.1` next to a row saying `openssl 3.5.8` costs the second one its
credibility, and a report nobody reads past measures nothing at all.

So the rules here, like the ones in `strings`, are mostly about refusing. They
were written after running a loose version of each against a corpus of DLLs that
are each one known library — the Git for Windows ucrt64 tree plus
C:\\Windows\\System32\\curl.exe, measured 2026-10-02 — so that every answer could
be checked against something true rather than against a plausible shape. What the
corpus proved is noted where it proved it.

Three claims, and they are not the same claim:

* **in this file** — a banner the library prints about itself, or the source
  directory it was compiled in, left behind by the ``__FILE__`` of an assert.
* **asked of another file** — a .NET assembly reference names a version this file
  wants loaded at run time, which is not a version it carries.
* **used, version unknown here** — an import. The version is in that DLL, and
  that DLL is not this file; the useful thing to say is which file to open next.

The fourth answer is silence, and it is the common one. Four of the fifteen
libraries in the corpus carry their version as a bare number with no name beside
it — pcre2 as ``10.48 2026-08-31``, zstd as ``1.5.7``, idn2 as ``2.3.8``, and the
committed python.exe as ``3.14.7``. None of them is reported. Attributing a number
to whichever library a filename suggests would be guessing with a citation
attached, and the same shape is also what an OID and four bytes of debris look
like: ``1.2.840.113549.1.1.1`` and ``8.9.:.`` both came out of this corpus.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from exeradar.models import Import, Library

# Said wherever the list is shown, because an empty list is the answer most
# often misread. "No libraries" is not what this measures.
CAVEAT = (
    "A version here is one the file states about itself. A library missing from this "
    "list is not absent: a dynamically linked one leaves an import, not a string, and "
    "some state no version at all."
)

BANNER = "banner"
BUILD_PATH = "build path"
ASSEMBLY = "assembly reference"
IMPORT = "import"

# When one library said it twice, the row to keep. Its own banner outranks a
# build path: the first is a statement, the second is a side effect of how it was
# compiled, and libcrypto-3-x64.dll carries both.
_PRECEDENCE = {BANNER: 0, ASSEMBLY: 1, BUILD_PATH: 2}

# A release directory: `../openssl-3.5.8/crypto/asn1/a_int.c`. Generic, with no
# list of names behind it, because the separator after the version is enough of a
# guard — a release leaves a *directory* behind. That is what tells it apart from
# libiconv-2.dll's charset names, which have the same shape and no separator:
# `ANSI_X3.4-1986`, `VISCII1.1-1`, `TIS620.2529-1`.
_BUILD_PATH = re.compile(
    r"(?:^|[/\\])"
    r"(?P<name>[a-z][a-z0-9_+]{2,30})"
    r"-(?P<version>\d+\.\d+(?:\.\d+){0,2}[a-z]?)"
    r"[/\\]",
    re.I,
)

# A library naming itself: `OpenSSL 3.5.8 25 Aug 2026`, `libcurl/8.22.0`,
# `expat_2.8.5`, `curl 8.13.0 (Windows) %s`.
#
# Matched with `match` and not `search`, so a declaration has to be the whole
# start of the string: `openssl 1.0.2` inside a sentence is somebody writing about
# a version, not a library stating one. That is a precaution and not a measured
# rule — searching instead of matching changes no answer anywhere in the corpus,
# which was checked rather than assumed.
#
# What actually refuses libssh2's handshake banner `SSH-2.0-libssh2_1.11.1` is the
# separator: `-` is not one of them, so `SSH-2.0` cannot be read as a name and a
# version. Reading that string left to right gets it exactly backwards — 2.0 is
# the protocol and 1.11.1 is the library — and the build path in the same DLL
# gives 1.11.1 with nothing to misread. `v` is not a separator either, which is
# what refuses `TLSv1.3` and `DTLSv1.2` before any name is looked at.
_BANNER = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9_+]{2,30})"
    r"[ /_]v?"
    r"(?P<version>\d+\.\d+(?:\.\d+){0,2}[a-z]?)"
    r"(?![\w.])"
)

# A .NET assembly reference, which names a version this file asks for rather than
# one it carries. `Culture=` is required: without it the shape is prose with a
# number in it. `strings._versions_declared_in` reads the same text for a
# different purpose — it suppresses a dotted quad that would otherwise be
# reported as an IP address.
_ASSEMBLY = re.compile(
    r"^(?P<name>[A-Za-z][\w.\-]{1,60}), "
    r"Version=(?P<version>\d+\.\d+\.\d+\.\d+), "
    r"Culture="
)

# Windows build decoration on a DLL filename: a soname, a code-unit width, an
# architecture. None of it is a version — `libpcre2-8-0.dll` is not pcre2 8.0,
# the 8 is the code-unit width, and `libnghttp2-14.dll` is nghttp2 at ABI 14.
_DECORATION = re.compile(r"(?:-\d+)*(?:-x(?:86|64))?(?:-\d+)*$", re.I)

# Every name this tool can put to a library, in any of the three places a name
# turns up: a banner, a release directory, a DLL filename. A name that is not
# here is not reported from a banner or an import — which is the right failure,
# because the alternative is a row per system DLL and the five that carry a CVE
# buried under them.
#
# The first block is the corpus, with what proved each one. The second is
# libraries that were not in it: they use the same shapes, and a name missing
# from this table is a silent miss rather than a wrong row.
_COMPONENTS = {
    "openssl": "openssl",            # libcrypto-3-x64.dll: banner and build path
    "libcrypto": "openssl",          # what an importer of it writes
    "libssl": "openssl",
    "curl": "curl",                  # curl.exe: `curl 8.13.0 (Windows) %s`
    "libcurl": "curl",               # libcurl-4.dll: `libcurl/8.22.0`
    "zlib": "zlib",
    "zlib1": "zlib",                 # zlib1.dll, the Windows filename
    "inflate": "zlib",               # zlib's banner names the function
    "deflate": "zlib",
    "expat": "expat",                # libexpat-1.dll: `expat_2.8.5`
    "libexpat": "expat",
    "nghttp2": "nghttp2",            # libnghttp2-14.dll, build path only
    "libnghttp2": "nghttp2",
    "libssh2": "libssh2",            # libssh2-1.dll, build path only
    "libpsl": "libpsl",              # libpsl-5.dll, build path only
    "pcre2": "pcre2",                # libpcre2-8-0.dll: version present, unattributed
    "libpcre2": "pcre2",
    "zstd": "zstd",                  # libzstd.dll: the same
    "libzstd": "zstd",
    "idn2": "idn2",                  # libidn2-0.dll: the same
    "libidn2": "idn2",
    "iconv": "iconv",                # libiconv-2.dll: the same
    "libiconv": "iconv",
    "brotli": "brotli",              # libbrotlidec.dll: no version anywhere in it
    "libbrotlidec": "brotli",
    "libbrotlienc": "brotli",
    "libbrotlicommon": "brotli",

    # Not measured here; the same shapes, and unambiguous names.
    "sqlite": "sqlite", "sqlite3": "sqlite",
    "libpng": "libpng", "libpng16": "libpng",
    "libjpeg": "libjpeg", "libjpeg-turbo": "libjpeg",
    "libtiff": "libtiff",
    "libxml2": "libxml2", "libxslt": "libxslt",
    "freetype": "freetype", "libfreetype": "freetype",
    "harfbuzz": "harfbuzz", "libharfbuzz": "harfbuzz",
    "libarchive": "libarchive",
    "bzip2": "bzip2", "libbz2": "bzip2",
    "lz4": "lz4", "liblz4": "lz4",
    "libgcrypt": "libgcrypt", "libgpg-error": "libgpg-error",
    "gnutls": "gnutls", "libgnutls": "gnutls",
    "mbedtls": "mbedtls", "wolfssl": "wolfssl",
    "libsodium": "libsodium",
    "libevent": "libevent", "libuv": "libuv",
    "c-ares": "c-ares", "libcares": "c-ares",
    "libwebp": "libwebp",
    "openjpeg": "openjpeg", "libopenjp2": "openjpeg",
    "lua": "lua", "ncurses": "ncurses", "readline": "readline",
    "protobuf": "protobuf", "libprotobuf": "protobuf",
    "jansson": "jansson", "libjansson": "jansson",
    "libffi": "libffi",
}


def versions_in(candidates: Iterable[str]) -> list[Library]:
    """Every version the strings of one file state, each with what stated it.

    One row per library and version. A library that said the same thing twice is
    one row — libcrypto-3-x64.dll repeats its build path 611 times with a
    different filename on the end — and one that says two different versions gets
    both, because a binary carrying two copies has carried two copies and picking
    the higher would read as a measurement.
    """
    best: dict[tuple[str, str], Library] = {}

    for raw in candidates:
        text = raw.strip()
        if not text or "://" in text:
            # A link to a release says where the source can be got, not that it
            # is in this file. `strings.classify` has already reported it as a URL.
            continue
        for found in _claims_in(text):
            key = (found.name, found.version or "")
            kept = best.get(key)
            if kept is None or _PRECEDENCE[found.source] < _PRECEDENCE[kept.source]:
                best[key] = found

    return _sorted(best.values())


def from_strings_and_imports(
    candidates: Iterable[str],
    imports: Iterable[Import] = (),
) -> list[Library]:
    """The versions, plus the libraries whose version is in another file.

    The second half is what turns silence into a next step. A binary that imports
    `libcrypto-3-x64.dll` and says nothing about OpenSSL has not told us its
    OpenSSL version — but it has told us where to find it, and "no OpenSSL here"
    would be a different and false answer.

    A library that is both stated here and imported gets a row for each, which is
    the second version of this function. The first suppressed the import when a
    version had been found, on the grounds that one library deserves one row.
    Measured against the corpus on 2026-10-02 that rule hid the file that matters:
    Git's curl.exe states `curl 8.22.0` in its own banner and imports libcurl-4.dll,
    where the code actually is and which is what somebody patching it would have to
    replace. One extra true row is much the cheaper error.

    One row per imported file, too, and not per library: a program importing both
    libcrypto and libssl has two files to replace, and naming the library once
    names neither.
    """
    found = versions_in(candidates)

    elsewhere: dict[str, Library] = {}
    for imported in imports:
        component = component_of(imported.dll)
        if component is None or imported.dll in elsewhere:
            continue
        elsewhere[imported.dll] = Library(
            name=component, version=None, source=IMPORT, evidence=imported.dll
        )

    return _sorted([*found, *elsewhere.values()])


def component_of(dll: str) -> str | None:
    """The library an imported DLL belongs to, or None when it is not one we name.

    None covers two different things on purpose, because neither is reportable:
    a Windows system DLL, and a third-party one this table has never heard of.
    """
    stem = dll.rsplit(".", 1)[0] if "." in dll else dll
    return _COMPONENTS.get(_DECORATION.sub("", stem).lower())


def sentence(library: Library) -> str:
    """One line, so the console and the Markdown cannot drift apart.

    Each source gets its own verb, because the three are different claims and a
    reader acting on them does three different things.
    """
    if library.source == IMPORT:
        # Short on purpose: libcurl-4.dll produces six of these, and a sentence
        # that explains itself six times is a wall a reader skips. What the row
        # means is in CAVEAT, which is printed once.
        return f"{library.name} — no version here: it is in `{library.evidence}`"
    if library.source == ASSEMBLY:
        # Without the evidence, which for this shape only restates the name and the
        # version. It is still in the JSON, where nothing is being read aloud.
        return f"{library.name} {library.version} — required at run time, not carried here"
    return f"{library.name} {library.version} — in this file ({library.source}: {library.evidence})"


def _claims_in(text: str) -> list[Library]:
    """Everything one string supports, by the three rules, in order of strength."""
    claims: list[Library] = []

    assembly = _ASSEMBLY.match(text)
    if assembly:
        # Not lowercased: this one is matched case-sensitively, so the spelling is
        # the manifest's own and carries information the others' does not.
        claims.append(Library(
            name=assembly.group("name"),
            version=assembly.group("version"),
            source=ASSEMBLY,
            evidence=text,
        ))

    seen = _BANNER.match(text)
    if seen:
        component = _COMPONENTS.get(seen.group("name").lower())
        if component is not None:
            claims.append(Library(
                name=component,
                version=seen.group("version"),
                source=BANNER,
                evidence=text,
            ))

    for path in _BUILD_PATH.finditer(text):
        name = path.group("name").lower()
        claims.append(Library(
            name=_COMPONENTS.get(name, name),
            version=path.group("version"),
            source=BUILD_PATH,
            evidence=text,
        ))

    return claims


def _sorted(found: Iterable[Library]) -> list[Library]:
    # Within one library the answered row comes before the unanswered one: when a
    # file both states a version and imports another copy, a reader wants the
    # version first and the pointer to the other file after it.
    return sorted(
        found,
        key=lambda lib: (lib.name.lower(), lib.version is None, lib.version or ""),
    )
