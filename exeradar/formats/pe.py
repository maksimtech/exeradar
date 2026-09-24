"""PE: headers, sections with entropy, import table, and what the imports mean.

The parsing is LIEF's work and this module is a thin layer over it. The part
that is not thin is `categorise`: deciding that a binary talks to the network
is a claim, and the rules behind it are the only place in this file where
judgement is exercised.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import lief

from exeradar.models import ExeResult, Import, Section

CATEGORIES = ("network", "crypto", "process", "registry")

# A DLL whose whole purpose is one category. Lower case; matched on the stem,
# so "WS2_32.dll" and "ws2_32" are the same thing.
_DLL_CATEGORIES: dict[str, str] = {
    "ws2_32": "network",
    "wsock32": "network",
    "wininet": "network",
    "winhttp": "network",
    "urlmon": "network",
    "dnsapi": "network",
    "iphlpapi": "network",
    "netapi32": "network",
    "bcrypt": "crypto",
    "ncrypt": "crypto",
    "crypt32": "crypto",
    "cryptsp": "crypto",
    "cryptbase": "crypto",
    "secur32": "crypto",
    "bcryptprimitives": "crypto",
}

# General-purpose libraries are deliberately absent from the table above.
# KERNEL32 is in every binary ever linked; reporting it as a signal reports
# noise. ADVAPI32 is worse than useless there — it covers the registry, process
# creation and the legacy crypto API at once, so a DLL-level rule would make
# three claims where the evidence supports one. For those, the function name
# decides.
_FUNCTION_PREFIXES: tuple[tuple[str, str], ...] = (
    ("reg", "registry"),            # RegOpenKeyExW, RegSetValueExW
    ("crypt", "crypto"),            # CryptAcquireContextW
    ("bcrypt", "crypto"),
    ("ncrypt", "crypto"),
    ("createprocess", "process"),   # CreateProcessW, CreateProcessAsUserW
    ("shellexecute", "process"),
    ("winexec", "process"),
    ("createremotethread", "process"),
    ("openprocess", "process"),
    ("internet", "network"),        # InternetOpenUrlW
    ("winhttp", "network"),
    ("httpopen", "network"),
    ("urldownload", "network"),
)

# "Register" starts with "Reg" and has nothing else in common with the
# registry. RegisterClassW registers a window class and every GUI program calls
# it, so without this every GUI program was reported as touching the registry —
# BIOSdump2license.exe was, through a USER32 that exports no registry function
# at all. Counted on Windows 10: kernel32 exports 41 registry functions,
# advapi32 82, user32 none — and not one of them begins with "Register".
#
# Leaving USER32 and KERNEL32 out of the category would have been the other
# fix, and a worse one: kernel32.dll exports 41 of those functions, so it would
# have traded a false positive for a false negative.
_NOT_REGISTRY = "register"

# Exact matches, for the Berkeley sockets names that carry no prefix.
_FUNCTION_NAMES: dict[str, str] = {
    "socket": "network",
    "connect": "network",
    "send": "network",
    "recv": "network",
    "bind": "network",
    "listen": "network",
    "accept": "network",
    "gethostbyname": "network",
    "getaddrinfo": "network",
    "closesocket": "network",
}



def _as_text(name: str | bytes) -> str:
    """A section or import name as text.

    lief types these as `str | bytes` and returns `str` for a well-formed PE —
    but a name whose bytes are not valid UTF-8 comes back as `bytes`, and a
    `bytes` value reaching the report would print as `b'.text'`, quoted prefix
    and all, in both the console output and the JSON.
    """
    if isinstance(name, bytes):
        return name.decode("utf-8", errors="replace")
    return name

def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte, 0.0 to 8.0.

    Above roughly 7.0 a section is compressed, encrypted or packed. Empty
    sections are real — .bss has no raw data — so they return 0.0 rather than
    raising.

    Written as p · log2(1/p) rather than the textbook -Σ p · log2(p). The two
    are equal, but the textbook form negates its sum, and for a section of one
    repeated byte that sum is 1 · log2(1) = 0.0 — so it returned -0.0, which
    the report printed as "-0.00". This form has no negation, every term is
    ≥ 0, and a negative zero cannot arise.
    """
    if not data:
        return 0.0
    total = len(data)
    return sum(
        (count / total) * math.log2(total / count)
        for count in Counter(data).values()
    )


def categorise(dll: str, functions: Iterable[str] = ()) -> frozenset[str]:
    """What a DLL and the functions called from it say about the binary.

    Returns an empty set when nothing can be claimed, which is the common case
    and the right answer for KERNEL32 on its own.
    """
    found: set[str] = set()

    stem = dll.lower().rsplit(".", 1)[0] if dll else ""
    if stem in _DLL_CATEGORIES:
        found.add(_DLL_CATEGORIES[stem])

    for name in functions:
        if not name:
            continue
        lowered = name.lower().rstrip("aw")  # CreateProcessW -> createprocess
        exact = name.lower()
        if exact in _FUNCTION_NAMES:
            found.add(_FUNCTION_NAMES[exact])
            continue
        for prefix, category in _FUNCTION_PREFIXES:
            if category == "registry" and exact.startswith(_NOT_REGISTRY):
                continue
            if lowered.startswith(prefix) or exact.startswith(prefix):
                found.add(category)
                break

    return frozenset(found)


class PEParser:
    """Fills an ExeResult from a PE file.

    Takes the result rather than building one so that the hash and size, which
    are format-independent, stay with the scanner.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def parse(self, result: ExeResult) -> ExeResult:
        binary = lief.PE.parse(str(self.path))
        if binary is None:
            result.error = f"not a PE file: {self.path.name}"
            return result

        header = binary.header
        result.format = "PE"
        result.arch = str(header.machine).rsplit(".", 1)[-1]
        result.built = self._built(header.time_date_stamps)
        # Our entropy(), not LIEF's section.entropy: LIEF computes it the
        # textbook way and returns -0.0 for a section of one repeated byte, and
        # reading its value meant the tested function never reached the report.
        result.sections = [
            Section(
                name=_as_text(section.name),
                virtual_size=section.virtual_size,
                raw_size=section.sizeof_raw_data,
                entropy=entropy(bytes(section.content)),
            )
            for section in binary.sections
        ]
        result.imports = [
            Import(
                dll=_as_text(imported.name),
                functions=[_as_text(entry.name) for entry in imported.entries if entry.name],
            )
            for imported in binary.imports
        ]
        return result

    @staticmethod
    def _built(timestamp: int) -> str | None:
        """The COFF timestamp, which is not always a timestamp.

        Reproducible builds put a hash of the inputs in this field, so the
        value can be absurd. Returning None beats reporting 1974 or 2089 as if
        it were a build date.
        """
        try:
            moment = datetime.fromtimestamp(timestamp, UTC)
        except (OSError, OverflowError, ValueError):
            return None
        if not 1990 < moment.year < datetime.now(UTC).year + 2:
            return None
        return f"{moment:%Y-%m-%d %H:%M:%S} UTC"
