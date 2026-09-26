"""Orchestration: a path in, an ExeResult out.

The scanner owns the two facts that hold for any file — its size and its hash
— and delegates the rest. The format is chosen from the magic bytes rather
than the extension, because the extension is a claim by whoever named the file
and the magic is a property of its contents.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from exeradar import signature, strings
from exeradar.models import ExeResult

_READ_CHUNK = 1 << 20

# Enough bytes to tell the formats apart; read once, used by every check.
_MAGIC_LENGTH = 8

_MACHO_MAGICS = (
    b"\xfe\xed\xfa\xce",   # 32-bit, big endian
    b"\xfe\xed\xfa\xcf",   # 64-bit, big endian
    b"\xce\xfa\xed\xfe",   # 32-bit, little endian
    b"\xcf\xfa\xed\xfe",   # 64-bit, little endian
)

# Parsers that exist. A format that is recognised but absent from here is
# declined by name, which is a different answer from "unknown" and one a
# caller can act on.
_IMPLEMENTED = {"PE"}

# A universal ("fat") archive: several Mach-O slices in one file, which is the
# ordinary shape of a shipped macOS binary. Both magics are big endian.
_FAT_MAGICS = {0xCAFEBABE: 20, 0xCAFEBABF: 32}   # magic -> size of one fat_arch

# nfat_arch beyond this is not a build. A Java class file — same magic — has its
# minor and major version where the count would be, which reads as 45 to 69 for
# Java 1.1 through Java 25, so the bound also happens to reject those outright.
_MAX_SLICES = 32

_FAT_HEADER = 8


def detect_format(head: bytes) -> str | None:
    """The format, from the first bytes, or None when nothing matches.

    A fat Mach-O archive starts with 0xcafebabe, which is also the magic of a
    Java class file, and eight bytes cannot tell them apart — so this declines
    it. `is_fat_macho` reads enough of the file to settle it, and `format_of`
    asks that question when this one has no answer.
    """
    if head.startswith(b"MZ"):
        return "PE"
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if any(head.startswith(magic) for magic in _MACHO_MAGICS):
        return "MachO"
    return None


def is_fat_macho(path: str | Path) -> bool:
    """Whether the file really is a universal Mach-O archive.

    The magic alone is shared with Java class files, so three things are checked
    instead of assumed: the slice count is plausible, the first slice lies inside
    the file, and the bytes at its offset are one of the thin Mach-O magics. A
    class file fails on all three — its version fields read as a count of 45 or
    more — and so does a download that stopped before the slices arrived.

    Only the first slice is validated. A second wrong one would make the file
    broken rather than make it something else, and this function answers "what is
    this", not "is it intact".
    """
    try:
        with Path(path).open("rb") as handle:
            header = handle.read(_FAT_HEADER)
            if len(header) < _FAT_HEADER:
                return False
            magic = int.from_bytes(header[:4], "big")
            entry_size = _FAT_MAGICS.get(magic)
            if entry_size is None:
                return False

            slices = int.from_bytes(header[4:8], "big")
            if not 1 <= slices <= _MAX_SLICES:
                return False

            entry = handle.read(entry_size)
            if len(entry) < entry_size:
                return False
            # cputype, cpusubtype, then offset and size — 4 bytes each in a
            # fat_arch, 8 in a fat_arch_64.
            width = 8 if entry_size == 32 else 4
            offset = int.from_bytes(entry[8:8 + width], "big")
            size = int.from_bytes(entry[8 + width:8 + 2 * width], "big")

            end = Path(path).stat().st_size
            least = _FAT_HEADER + entry_size * slices
            if not size or offset < least or offset + size > end:
                return False

            handle.seek(offset)
            return handle.read(4) in _MACHO_MAGICS
    except OSError:
        return False


def format_of(path: str | Path) -> str | None:
    """The format of a file on disk, without reading the rest of it.

    What `batch` walks a directory with: a folder holds far more files than
    executables, and opening eight bytes is the cheapest way to tell which is
    which. A file that cannot be opened is not a format this tool declines —
    it is nothing at all, so None covers both.

    The one format that costs more than eight bytes is a universal Mach-O, and
    only for a file that starts with the ambiguous magic: see `is_fat_macho`.
    """
    try:
        with Path(path).open("rb") as handle:
            head = handle.read(_MAGIC_LENGTH)
    except OSError:
        return None

    fmt = detect_format(head)
    if fmt is not None:
        return fmt
    if int.from_bytes(head[:4], "big") in _FAT_MAGICS and is_fat_macho(path):
        return "MachO"
    return None


def scan(path: str | Path) -> ExeResult:
    path = Path(path)

    try:
        size = path.stat().st_size
        digest = _sha256(path)
    except OSError as exc:
        return ExeResult(path=str(path), size=0, sha256="", error=f"cannot read: {exc.strerror or exc}")

    result = ExeResult(path=str(path), size=size, sha256=digest)

    # Through format_of, so that `scan` and the directory walk agree on what a
    # file is: they used to detect it separately and only one of them learned
    # about universal archives.
    fmt = format_of(path)
    if fmt is None:
        result.error = "unrecognised format: not a PE, ELF or Mach-O binary"
        return result

    result.format = fmt
    if fmt not in _IMPLEMENTED:
        result.error = f"{fmt} is not supported yet"
        return result

    from exeradar.formats import pe

    result = pe.PEParser(path).parse(result)
    if result.error:
        return result

    # The signature and the strings are independent of the format parser and
    # of each other, so neither failing should cost the other its output.
    result.signature = signature.inspect(path)
    # Two ranges are skipped, for the same reason in two sizes.
    #
    # The certificate table: its URLs and names describe whoever signed the
    # file, not what the file does, and on a signed binary they outnumber the
    # program's own by an order of magnitude.
    #
    # The overlay: everything past the last section, which the loader never
    # maps. In a self-extracting installer that is the compressed payload, and
    # printable runs pulled from compressed bytes are not strings — they are
    # pairs of characters that happen to look like hostnames. One 457 MB
    # webpack produced 747 of them and not one was real.
    excluded = list(signature.signed_regions(path))
    start = pe.overlay_start(path)
    if start is not None:
        result.overlay = max(size - start, 0)
        if result.overlay:
            excluded.append((start, size))
    result.strings = strings.from_file(path, exclude=excluded)

    # Last, because every finding is drawn from the facts above. Imported here
    # rather than at the top so that reading a file does not pull in the law
    # machinery and its HTTP client; nothing in this call touches the network.
    from exeradar import law_checker

    result.findings = law_checker.findings_for(result)
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_READ_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()
