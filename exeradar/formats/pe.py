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

from exeradar.models import ExeResult, Import, Section, Version

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


def _section_name(section) -> str:
    """The section's name, long names included.

    The header holds eight bytes. A longer name lives in the COFF string table
    and the header says `/N`, the decimal offset of the name in it — the PE/COFF
    specification's convention, and the one Go's linker uses for every
    `.zdebug_*` section. docker.exe (Docker Inc, Go, measured 2026-10-09) showed
    eight sections called `/4`, `/19`, `/32`, `/46`, `/65`, `/78`, `/95`, `/112`,
    five of them at entropy 8.00 and coloured as packed; readable, they are
    `.zdebug_info` and its siblings, compressed DWARF, and 8.00 is what that is.

    LIEF resolves the reference when the table is there. When it is not — a
    header that says `/4` in a file with no string table — the raw name is kept:
    the convention is only an offset, and an offset into nothing names nothing.
    """
    name = _as_text(section.name)
    if name.startswith("/") and name[1:].isdigit():
        resolved = getattr(section, "coff_string", None)
        long_name = getattr(resolved, "string", None) if resolved is not None else None
        if long_name:
            return _as_text(long_name)
    return name


def _function_name(entry) -> str:
    """What the import table asks the DLL for: a name, or a number.

    A function imported by ordinal has no name, and was dropped: powershell.exe
    showed `ATL.DLL 0`, and Code.exe showed 29 functions from WS2_32.dll when it
    asks for 54, 25 of them by number. `#7` is how dumpbin and the linker's map
    files write an ordinal, so it is readable next to the names; `categorise`
    reads nothing from it, since there is no verb in a number.
    """
    if entry.name:
        return _as_text(entry.name)
    return f"#{entry.ordinal}"


def _dotted(ms: int, ls: int) -> str | None:
    """Two dwords of VS_FIXEDFILEINFO as the four numbers Explorer shows.

    Each dword holds two 16-bit words, major.minor and build.revision. A block
    of zeros declares nothing, and None says so rather than `0.0.0.0`.
    """
    if not ms and not ls:
        return None
    return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


def _string_entry(table, key: str) -> str | None:
    """One StringFileInfo value, or None when absent or blank: devcpp.exe
    writes `LegalTrademarks` as an empty string, and an empty version is none."""
    if table is None:
        return None
    value = table.get(key)
    return value.strip() or None if value else None


def version_of(binary: lief.PE.Binary) -> Version | None:
    """What the VERSIONINFO resource declares, or None when it declares nothing.

    Both halves of the resource are read, because they answer differently.
    The fixed block is what Explorer shows as "File version" and what an
    installer compares. The StringFileInfo values are the text the manufacturer
    typed — and that text is the very UTF-16 string the strings pass extracts
    from `.rsrc`: devcpp.exe's `4.9.9.2` on its own is its FileVersion value,
    standing a few padding bytes away from the key that names it. The first
    string table is the one read; a file with several language blocks states
    the same version in each.

    The resource tree is the part of a PE a packer rewrites, and LIEF raises on
    one it cannot walk. Any failure is the same answer as no resource at all.
    """
    try:
        if not binary.has_resources:
            return None
        # Typed as a manager or a LIEF error code, and the error is a value here
        # rather than an exception.
        manager = binary.resources_manager
        if not isinstance(manager, lief.PE.ResourcesManager) or not manager.has_version:
            return None
        entries = list(manager.version)
    except Exception:  # noqa: BLE001 - an unreadable resource declares nothing
        return None
    for entry in entries:
        info = entry.file_info
        strings = entry.string_file_info
        table = next(iter(strings.children), None) if strings is not None else None
        version = Version(
            file=_dotted(info.file_version_ms, info.file_version_ls) if info is not None else None,
            product=_dotted(info.product_version_ms, info.product_version_ls) if info is not None else None,
            file_string=_string_entry(table, "FileVersion"),
            product_string=_string_entry(table, "ProductVersion"),
        )
        if version.stated():
            return version
    return None


def parse(path: str | Path) -> lief.PE.Binary | None:
    """LIEF's parser, handed the bytes rather than the name.

    On Windows LIEF opens a path through the narrow API, so a file called
    caffè.exe — or any file under C:\\Users\\José — "failed to open" and came
    back as None: a valid PE reported as not a PE, and a signed one as
    unreadable. Python opens the file and LIEF only parses it, which is the same
    on every platform. None when the file cannot be read, as LIEF answered.
    """
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    return lief.PE.parse(data)


def overlay_start(path: str | Path) -> int | None:
    """Where the mapped image ends and appended data begins.

    Everything past the last section is overlay: the loader never maps it, and
    in a self-extracting installer it is the compressed payload. A 457 MB HP
    webpack measured on 2026-09-26 was 99.85% overlay — 684 KB of sections and
    456 MB of archive — and every one of the 747 hostnames and 350 paths pulled
    out of it was manufactured by reading printable runs out of compressed
    bytes.

    None when the boundary cannot be established, which is the answer that
    matters: a truncated or malformed PE has no last section, and returning
    zero there would exclude the entire file and report the silence as a
    finding.
    """
    try:
        binary = parse(path)
    except Exception:  # noqa: BLE001 - any parse failure is the same answer
        return None
    if binary is None or not binary.sections:
        return None
    end = max(section.offset + section.size for section in binary.sections)

    # A truncated file keeps its original headers, so LIEF reports sections
    # ending where they were meant to: 92,160 for the first 4 KB of the test
    # fixture. A boundary past the end of the file is not a boundary, and
    # answering with one would be worse than answering with nothing.
    size = Path(path).stat().st_size
    if not end or end > size:
        return None
    return end


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


def _positive(value: float) -> float:
    """LIEF's entropy as the report may print it: never -0.0.

    The textbook form negates a sum, and for one repeated byte that sum is
    1 · log2(1) = 0.0 — negated, -0.0, which formats as "-0.00". IEEE 754 has
    -0.0 + 0.0 == +0.0, and every other value is unchanged.
    """
    return float(value) + 0.0


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
        binary = parse(self.path)
        if binary is None:
            result.error = f"not a PE file: {self.path.name}"
            return result

        header = binary.header
        result.format = "PE"
        result.arch = str(header.machine).rsplit(".", 1)[-1]
        result.built = self._built(header.time_date_stamps)
        result.version = version_of(binary)
        # LIEF's section.entropy, with its sign put right. It was `entropy()`
        # over `bytes(section.content)`, so that the tested function reached the
        # report — and on Code.exe (VS Code, 238 MB) that was six seconds of
        # Counter() walking the 186 MB of .text one byte at a time, for a number
        # LIEF had computed in 70 ms. The two agree to the last digit, which
        # test_pe holds them to; what LIEF gets wrong is the sign of nothing,
        # and `_positive` is what puts it right.
        result.sections = [
            Section(
                name=_section_name(section),
                virtual_size=section.virtual_size,
                raw_size=section.sizeof_raw_data,
                entropy=_positive(section.entropy),
            )
            for section in binary.sections
        ]
        result.imports = [
            Import(
                dll=_as_text(imported.name),
                functions=[_function_name(entry) for entry in imported.entries if entry.name or entry.is_ordinal],
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
