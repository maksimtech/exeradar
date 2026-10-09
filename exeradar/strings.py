"""Readable strings, and what little can honestly be said about them.

Extraction is the easy half. The hard half is that in a Windows binary almost
everything has the shape of a domain: `kernel32.dll` is two labels and a dot,
and so is every filename. A classifier that reports those produces thirty
hosts for a program that contacts none, and the one address that mattered is
lost in the list.

So the rules below are mostly about refusing to claim things. Two of them were
written only after running the first version against a real binary, which is
noted where they appear.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from exeradar.models import Strings
from exeradar.tlds import TLDS

MIN_LENGTH = 4

_PRINTABLE = rb"[\x20-\x7e]"

# Anchored on real schemes and searched for inside the string rather than
# matched against the whole of it: a certificate stores its CRL and issuer
# URLs with DER length bytes on both sides, so the URL is almost never the
# entire run.
# The excluded characters are the ones RFC 3986 does not allow unescaped, which
# is what ends the URL when it is embedded in the XML of a PE manifest:
# .../WindowsSettings">true</longPathAware> was being reported whole.
#
# A URL also ends where another scheme begins. A font's name table stores its
# strings back to back with no separator, and the one embedded in
# BIOSdump2license.exe gave three URLs as a single string. The cost is a URL
# carrying an unescaped one in its query — ?to=http://b — which comes out as
# two; both hosts are then reported, which for this tool is the useful half.
_SCHEME = r"(?:https?|ftps?)://"
_URL = re.compile(rf"""{_SCHEME}(?:(?!{_SCHEME})[^\s\x00"'<>`\\])+""", re.I)

# The tail DER leaves behind: a SEQUENCE tag, which prints as '0', and usually
# one length byte after it. Matched as a shape rather than as a set of unwanted
# characters — the first attempt used a character set and ate the final 't' of
# `.crt`, because 't' is both DER debris and an ordinary letter.
_DER_TAIL = re.compile(r"0[\x20-\x7e]?$")

_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
# A segment cannot contain a separator, and the separator lives only in the
# repeated group: every character has exactly one place it can go, so there is
# nothing for the engine to reconsider. Written the obvious way —
# `[^\r\n]*[\\/][^\r\n]*` — both halves can swallow separators, so each one in
# the string is a candidate for the middle and every attempt rescans the tail.
# Measured through classify() on 2026-09-25, with a carriage return partway
# through "C:\\" + "a\\" * n: 26 ms at n=1,000, 502 ms at n=4,000, 2.9 s at
# n=8,000. This form does the last of those in a few milliseconds.
#
# extract_raw cannot produce such a string — it yields runs of [\x20-\x7e], so
# no CR or LF — but classify() and from_file() are public, and a caller with its
# own strings is not a strange thing.
_WINDOWS_PATH = re.compile(r"^[a-z]:[\\/][^\\/\r\n]*(?:[\\/][^\\/\r\n]*)+$", re.I)
_UNIX_PATH = re.compile(r"^/[\w.\-]+(/[\w.\-]+)+/?$")
_HOST = re.compile(
    r"^(?=.{4,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"([a-z]{2,24})$",
    re.I,
)

# A filename is a domain as far as a regex is concerned. The last label is the
# only thing that tells them apart, so the extensions a PE is full of are
# listed here. `com` is deliberately absent: it was an executable extension on
# DOS and has been a top-level domain everywhere since, and the domain reading
# is the one worth having.
_FILE_EXTENSIONS = frozenset({
    "dll", "exe", "sys", "drv", "ocx", "cpl", "scr", "msi", "cab",
    "dat", "tmp", "log", "txt", "ini", "cfg", "conf", "xml", "json", "yaml",
    "bat", "cmd", "ps1", "vbs", "js", "py", "pyc", "pyd", "h", "c", "cpp",
    "lib", "obj", "pdb", "res", "rc", "manifest", "bin", "db", "bak",
    "png", "jpg", "gif", "ico", "bmp", "wav", "avi", "mp3", "zip", "gz",
    # Catalonia's TLD, and the extension of the catalog files path B of the
    # signature check reads: wireguard.exe names its drivers' `WIREGUARD.CAT`.
    "cat",
})


def extract_raw(
    data: bytes,
    min_length: int = MIN_LENGTH,
    exclude: Iterable[tuple[int, int]] = (),
) -> list[str]:
    """Every printable run, ASCII and UTF-16LE, in order of first appearance.

    UTF-16LE text is ASCII bytes with NULs between them, so an ASCII-only pass
    turns it into single characters that the minimum length throws away. Both
    passes are needed, and a Windows binary keeps most of its text in the
    second one.

    `exclude` is a list of (start, end) byte ranges to leave out — the
    signature blob, in practice. The ranges are cut rather than blanked, so a
    string that straddles a boundary is reported as the part that lies outside
    and not as the whole: half a string is not the string.
    """
    if min_length < 1:
        raise ValueError("min_length must be at least 1")

    found: dict[str, None] = {}
    ascii_run = rb"%s{%d,}" % (_PRINTABLE, min_length)
    utf16_run = rb"(?:%s\x00){%d,}" % (_PRINTABLE, min_length)

    for chunk in _outside(data, exclude):
        for match in re.finditer(ascii_run, chunk):
            found[match.group().decode("ascii")] = None
        for match in re.finditer(utf16_run, chunk):
            found[match.group().decode("utf-16-le")] = None

    return list(found)


def _outside(data: bytes, exclude: Iterable[tuple[int, int]]) -> list[bytes]:
    """The parts of `data` that no excluded range covers, in order."""
    ranges = sorted(
        (max(0, start), min(len(data), end))
        for start, end in exclude
        if start < end
    )
    if not ranges:
        return [data]

    chunks: list[bytes] = []
    cursor = 0
    for start, end in ranges:
        if start > cursor:
            chunks.append(data[cursor:start])
        cursor = max(cursor, end)
    if cursor < len(data):
        chunks.append(data[cursor:])
    return chunks


def classify(candidates: Iterable[str]) -> Strings:
    """Sort strings into the four buckets, claiming nothing that is doubtful.

    Each string lands in at most one bucket: a URL is not also reported as the
    host inside it, because one string making two claims reads as two findings.
    """
    # Materialised: the version pass reads every candidate before the
    # classification pass does, and a generator cannot be read twice.
    candidates = list(candidates)
    declared_versions = _versions_declared_in(candidates)
    # One check for the whole file, not one per quad: whether it carries an
    # object identifier table at all is what makes the arc rule applicable. Made
    # only when a quad under an arc turns up: on a file with none — most of them
    # — it is a pass over every string that decides nothing, and CodSpeed
    # measured it at 11% of classify() on the path-heavy corpus.
    has_oids: bool | None = None

    urls: set[str] = set()
    ips: set[str] = set()
    hosts: set[str] = set()
    paths: set[str] = set()

    for raw in candidates:
        text = raw.strip()
        if not text:
            continue

        found_urls = _urls_in(text)
        if found_urls:
            urls.update(found_urls)
            continue
        if _is_ipv4(text):
            if text in declared_versions:
                continue
            if _under_an_oid_arc(text):
                if has_oids is None:
                    has_oids = _carries_oids(candidates)
                if has_oids:
                    continue
            ips.add(text)
            continue
        if _WINDOWS_PATH.match(text) or _is_unix_path(text):
            paths.add(text)
            continue
        if _is_host(text):
            hosts.add(text)

    return Strings(
        urls=sorted(urls),
        ips=sorted(ips),
        hosts=sorted(hosts),
        paths=sorted(paths),
    )


def extract(
    data: bytes,
    min_length: int = MIN_LENGTH,
    exclude: Iterable[tuple[int, int]] = (),
) -> Strings:
    return classify(extract_raw(data, min_length, exclude))


def from_file(
    path: str | Path,
    min_length: int = MIN_LENGTH,
    exclude: Iterable[tuple[int, int]] = (),
) -> Strings:
    return extract(Path(path).read_bytes(), min_length, exclude)


def _urls_in(text: str) -> list[str]:
    """Every URL inside a string, each trimmed of the bytes that framed it.

    Found by running the first version against the test fixture: six of its
    seven URLs came back as `Vhttp://...crl0t`, scheme and all, because the
    pattern only asked for "something, then ://". Plural since a font's name
    table ran three of them together; see _URL.

    Then two more refusals, both from running it against Go and Node binaries
    on 2026-10-09. Go writes its string literals back to back, so `https://`
    is followed by whatever came next in the table — `https://,`, `https://H`,
    `http://);` — and Node's test code carries `http://${input}` and
    `http://%s:80`; a scheme is only a URL when a host follows it, which is
    `_has_a_host`. And a URL quoted in a sentence ends with that sentence's
    punctuation — `https://www.python.org/psf/license/)` out of python314.dll
    — which is `_unpunctuated`.
    """
    found = []
    for match in _URL.finditer(text):
        url = _unpunctuated(_trim(match.group()))
        if url and _has_a_host(url):
            found.append(url)
    return found


# The authority after the scheme: an optional user part, then a bracketed IPv6
# address or dotted labels with an optional root dot, then an optional port, then
# whatever the path, query or fragment is. Nothing else may follow the host.
_AUTHORITY = re.compile(
    rf"^{_SCHEME}(?:[^@/\s]+@)?"
    r"(?:\[[0-9a-f:.]+\]|(?P<host>[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?P<root>\.?)))"
    r"(?P<port>:\d{1,5})?(?P<rest>[/?#].*)?$",
    re.I,
)

# What may close a sentence a URL was quoted in, and never a URL.
_SENTENCE_PUNCTUATION = ".,;:!?'\""
_CLOSERS = {")": "(", "]": "["}


def _has_a_host(url: str) -> bool:
    """Whether what follows the scheme is a host, by the only tests available.

    Two labels or an address make a host on their own. One label is a host
    when a path or a port follows it — `http://wpad/wpad.dat` is Chromium's
    proxy discovery, `http://localhost:8000` is anybody's — and a sentence when
    nothing does: `http://An`, `https://insecure`. A root dot is allowed only at
    the very end, where Go's own source writes `https://proxy.golang.org.`;
    `http://www./div` is two strings of a table read as one.
    """
    match = _AUTHORITY.match(url)
    if match is None:
        return False
    host = match.group("host")
    if host is None:                       # a bracketed IPv6 address
        return True
    labels = host.rstrip(".").split(".")
    follows = bool(match.group("port") or match.group("rest"))
    if match.group("root") and follows:
        return False
    if len(labels) >= 2:
        return True
    return host.lower() == "localhost" or (follows and not match.group("root"))


def _unpunctuated(url: str) -> str:
    """The URL without the punctuation of the sentence it was quoted in.

    A closing bracket is kept when the URL opened it — Wikipedia's
    `Go_(programming_language)` — and a final dot is kept when nothing but the
    host precedes it, where it is a fully qualified name's root and not a full
    stop; after a path it is the full stop.
    """
    while url:
        last = url[-1]
        if last in _CLOSERS:
            if url.count(_CLOSERS[last]) >= url.count(last):
                break
        elif last == ".":
            if "/" not in url.split("://", 1)[-1]:
                break
        elif last not in _SENTENCE_PUNCTUATION:
            break
        url = url[:-1]
    return url


def _trim(found: str) -> str:
    # Trim the DER tail only when what is left still ends in something that
    # looks deliberate — a last path segment with a dot in it, which is what a
    # CRL or certificate URL ends with. Without that guard this would turn
    # http://example.com/v0 into http://example.com/v.
    trimmed = _DER_TAIL.sub("", found)
    if trimmed != found:
        tail = trimmed.rsplit("/", 1)[-1]
        if tail and "." in tail:
            return trimmed
    return found


# `FileVersion=1.1.2.0`, `Katana, Version=1.1.8.0, Culture=neutral`. No \b
# before the word: in `FileVersion` there is no boundary between `e` and `V`,
# and that spelling is the common one in a PE.
_DECLARED_VERSION = re.compile(r"version\s*[=:]?\s*(\d{1,3}(?:\.\d{1,3}){3})", re.I)


def _versions_declared_in(candidates: list[str]) -> set[str]:
    """Dotted quads this file names as versions somewhere in its own bytes.

    A quad alone cannot be told from an address — `_is_ipv4` has said so since
    it was written, and it is right. But a file that carries `1.1.8.0` on its
    own in the .NET metadata *and* `Katana, Version=1.1.8.0, Culture=neutral`
    a few kilobytes away has answered the question itself. Four Kyocera
    installers reported exactly that as an IP address on 2026-09-26.

    Corroboration inside one file, not a rule about shape: a quad nothing
    explains is still reported, because nothing established what it is.
    """
    return {
        match.group(1)
        for text in candidates
        for match in _DECLARED_VERSION.finditer(text)
    }


# Object identifiers that are four arcs long and whose arcs all fit in an octet,
# which is exactly the shape of an address. Not a rule about shape: these are the
# arcs the ITU-T and ISO registries assign at that depth and that every TLS and
# PGP library writes into its object table as text —
#
#   1.3.6.1      internet (RFC 1155), the root of every private-enterprise arc
#   1.3.14.3     OIW secsig algorithms (sha1 is 1.3.14.3.2.26)
#   1.3.36.*     TeleTrusT (1.3.36.3 is its algorithm arc)
#   1.3.101.*    RFC 8410: 110 X25519, 111 X448, 112 Ed25519, 113 Ed448
#   1.3.132.0    SECG named curves
#   2.5.*        X.500 directory: 2.5.4 attribute types, 2.5.6 object classes,
#                2.5.29 certificate extensions
#   2.23.*       joint international organisations: 2.23.42 SET, 2.23.133 TCG,
#                2.23.140 CA/Browser Forum
#
# Measured 2026-10-09: gpg.exe 2.5.24 reported RFC 8410's four identifiers as four
# addresses, and node.exe reported 189 — the whole of OpenSSL's X.520 and X.509
# tables — and raised `hardcoded_ip` over them, cited against the CRA. 2.5.0.0/16
# and 1.3.0.0/16 are allocated address blocks all the same, so the arc alone
# decides nothing: the file has to carry an object identifier table too. That is
# the same corroboration `_versions_declared_in` asks for, and it is what keeps
# Cloudflare's 1.1.1.1 and 1.0.0.1 in Code.exe — arcs nobody assigns — reported.
_OID_FAMILIES = ("1.3.36.", "1.3.101.", "2.5.", "2.23.")
_OID_EXACT = frozenset({"1.3.6.1", "1.3.14.3", "1.3.132.0"})

# An object identifier no address can be: five arcs or more, or an arc past 255.
# The first arc is 0, 1 or 2 by the standard, which is what refuses `3.4.5.6.7`.
_UNMISTAKABLE_OID = re.compile(r"^[0-2](?:\.\d+){2,}$")


def _carries_oids(candidates: list[str]) -> bool:
    """Whether the file writes object identifiers as text at all."""
    for text in candidates:
        text = text.strip()
        # The first character before the pattern: an OID starts with 0, 1 or 2,
        # and almost nothing else in a binary does, so the regex runs on few.
        if text[:1] not in "012" or not _UNMISTAKABLE_OID.match(text):
            continue
        arcs = text.split(".")
        if len(arcs) >= 5 or any(int(arc) > 255 for arc in arcs):
            return True
    return False


def _under_an_oid_arc(quad: str) -> bool:
    """Whether a dotted quad sits under one of the registered arcs above.

    The three exact ones are four arcs themselves: `1.3.6.10` is not under
    `1.3.6.1`, and a prefix test would have said it was.
    """
    return quad in _OID_EXACT or quad.startswith(_OID_FAMILIES)


def _is_ipv4(text: str) -> bool:
    """Four octets in range.

    1.2.3.4 is both a valid address and a common version string, and there is
    no way to tell them apart from the bytes alone. It is reported: refusing
    every dotted quad would lose real addresses, which is the worse error.
    """
    match = _IPV4.match(text)
    if not match:
        return False
    return all(0 <= int(octet) <= 255 for octet in match.groups())


def _is_unix_path(text: str) -> bool:
    """An absolute path, and not four bytes with slashes in them.

    The minimum string length is four, and `/o/O` is four printable bytes.
    Measured on 2026-10-09: eleven of docker.exe's 2,218 paths were `/1/4`,
    `/./u`, `/o/O`; sixteen of node.exe's 250 were `/-/S/k/`, `/s/s/s/s/s/s`;
    thirty-two of Code.exe's 87 were `/R/R`, `/u/M`. A path names a directory
    somewhere along it, so one segment of three characters is asked for —
    anywhere, not first: `/go/src/github.com/docker/...` is the GOPATH of the
    machine that built Docker, and the other 2,207 paths of docker.exe are
    source files under it and under /usr/local/go, every one of them real.
    """
    return bool(_UNIX_PATH.match(text) and _UNIX_DIRECTORY.search(text))


# A segment of three characters, found by the engine rather than by splitting
# the string and measuring every piece in Python.
_UNIX_DIRECTORY = re.compile(r"/[^/]{3}")


def _is_host(text: str) -> bool:
    """A hostname, and not one of the many things shaped like one.

    Three rules beyond the pattern.

    The suffix must be a top-level domain IANA actually delegates. Without it,
    every dotted identifier in a binary is a host: `Mono.Cecil` and
    `Katana.Services` are .NET namespaces, `Newtonsoft.Json.dllPK` is a ZIP
    member name with the archive's own signature stuck to it, and the
    compressed payload of one 436 MiB installer produced 2,449 two-label
    strings of which not one was real. Measured on 2026-09-26: the delegated
    suffixes remove 1,702 of those 2,449 and every one of the namespace and
    archive cases, and cost nothing that was ever a host.

    The suffix must also not be a file extension — `com` is a TLD and was never
    listed, but `dll` is what separates example.com from kernel32.dll.

    And some label before the suffix must be at least three characters: `g.iG`
    came out of the certificate bytes of the test fixture, and the Go binaries
    measured on 2026-10-09 — docker.exe, go.exe, wireguard.exe — produced the
    two-character form by the dozen: `0y.nf`, `6J.vA`, `LG.HK`, four random
    printable bytes and a dot, each with a country code on the end. That costs
    the rare real `t.co`, which is the cheaper of the two errors; `aka.ms` has
    its three.

    Two more, from the same day. A label written in both cases is an
    identifier: DNS is case-insensitive and a program has no reason to write
    `System.Net.Ping`, `bytes.Compare` or `StreamReader.read` as a hostname,
    while a .NET namespace, a Go symbol and a Python attribute are written in
    nothing else — and `.net`, `.compare` and `.read` are all delegated. `DNS.SB`
    and `WWW.EXAMPLE.COM` are one case throughout and come through.
    """
    match = _HOST.match(text)
    if not match:
        return False
    suffix = match.group(1).lower()
    if suffix in _FILE_EXTENSIONS:
        return False
    if suffix not in TLDS:
        return False
    labels = text.split(".")
    if any(_mixed_case(label) for label in labels):
        return False
    return any(len(label) >= 3 for label in labels[:-1])


def _mixed_case(label: str) -> bool:
    """Whether one label carries both an upper- and a lower-case letter."""
    return any(ch.isupper() for ch in label) and any(ch.islower() for ch in label)
