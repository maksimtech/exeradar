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
from pathlib import Path
from typing import Iterable

from exeradar.models import Strings

MIN_LENGTH = 4

_PRINTABLE = rb"[\x20-\x7e]"

# Anchored on real schemes and searched for inside the string rather than
# matched against the whole of it: a certificate stores its CRL and issuer
# URLs with DER length bytes on both sides, so the URL is almost never the
# entire run.
# The excluded characters are the ones RFC 3986 does not allow unescaped, which
# is what ends the URL when it is embedded in the XML of a PE manifest:
# .../WindowsSettings">true</longPathAware> was being reported whole.
_URL = re.compile(r"""(?:https?|ftps?)://[^\s\x00"'<>`\\]+""", re.I)

# The tail DER leaves behind: a SEQUENCE tag, which prints as '0', and usually
# one length byte after it. Matched as a shape rather than as a set of unwanted
# characters — the first attempt used a character set and ate the final 't' of
# `.crt`, because 't' is both DER debris and an ordinary letter.
_DER_TAIL = re.compile(r"0[\x20-\x7e]?$")

_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_WINDOWS_PATH = re.compile(r"^[a-z]:[\\/][^\r\n]*[\\/][^\r\n]*$", re.I)
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
})


def extract_raw(data: bytes, min_length: int = MIN_LENGTH) -> list[str]:
    """Every printable run, ASCII and UTF-16LE, in order of first appearance.

    UTF-16LE text is ASCII bytes with NULs between them, so an ASCII-only pass
    turns it into single characters that the minimum length throws away. Both
    passes are needed, and a Windows binary keeps most of its text in the
    second one.
    """
    if min_length < 1:
        raise ValueError("min_length must be at least 1")

    found: dict[str, None] = {}

    ascii_run = rb"%s{%d,}" % (_PRINTABLE, min_length)
    for match in re.finditer(ascii_run, data):
        found[match.group().decode("ascii")] = None

    utf16_run = rb"(?:%s\x00){%d,}" % (_PRINTABLE, min_length)
    for match in re.finditer(utf16_run, data):
        found[match.group().decode("utf-16-le")] = None

    return list(found)


def classify(candidates: Iterable[str]) -> Strings:
    """Sort strings into the four buckets, claiming nothing that is doubtful.

    Each string lands in at most one bucket: a URL is not also reported as the
    host inside it, because one string making two claims reads as two findings.
    """
    urls: set[str] = set()
    ips: set[str] = set()
    hosts: set[str] = set()
    paths: set[str] = set()

    for raw in candidates:
        text = raw.strip()
        if not text:
            continue

        url = _url_in(text)
        if url:
            urls.add(url)
            continue
        if _is_ipv4(text):
            ips.add(text)
            continue
        if _WINDOWS_PATH.match(text) or _UNIX_PATH.match(text):
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


def extract(data: bytes, min_length: int = MIN_LENGTH) -> Strings:
    return classify(extract_raw(data, min_length))


def from_file(path: str | Path, min_length: int = MIN_LENGTH) -> Strings:
    return extract(Path(path).read_bytes(), min_length)


def _url_in(text: str) -> str | None:
    """The URL inside a string, trimmed of the bytes that framed it.

    Found by running the first version against the test fixture: six of its
    seven URLs came back as `Vhttp://...crl0t`, scheme and all, because the
    pattern only asked for "something, then ://".
    """
    match = _URL.search(text)
    if not match:
        return None
    found = match.group()

    # Trim the DER tail only when what is left still ends in something that
    # looks deliberate — a last path segment with a dot in it, which is what a
    # CRL or certificate URL ends with. Without that guard this would turn
    # http://example.com/v0 into http://example.com/v.
    trimmed = _DER_TAIL.sub("", found)
    if trimmed != found:
        tail = trimmed.rsplit("/", 1)[-1]
        if tail and "." in tail:
            found = trimmed

    return found or None


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


def _is_host(text: str) -> bool:
    """A hostname, and not one of the many things shaped like one.

    Two rules beyond the pattern. The suffix must not be a file extension,
    which is what separates example.com from kernel32.dll. And some label
    before the suffix must be at least two characters: `g.iG` came out of the
    certificate bytes of the test fixture, and a one-character label with a
    two-character suffix is noise far more often than it is a host. That costs
    the rare real `x.co`, which is the cheaper of the two errors.
    """
    match = _HOST.match(text)
    if not match:
        return False
    if match.group(1).lower() in _FILE_EXTENSIONS:
        return False
    labels = text.split(".")[:-1]
    return any(len(label) >= 2 for label in labels)
