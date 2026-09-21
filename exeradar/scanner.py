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


def detect_format(head: bytes) -> str | None:
    """The format, from the first bytes, or None when nothing matches.

    A fat Mach-O archive starts with 0xcafebabe, which is also the magic of a
    Java class file. It is left out rather than guessed at.
    """
    if head.startswith(b"MZ"):
        return "PE"
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if any(head.startswith(magic) for magic in _MACHO_MAGICS):
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

    with path.open("rb") as handle:
        head = handle.read(_MAGIC_LENGTH)

    fmt = detect_format(head)
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
    result.strings = strings.from_file(path)
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_READ_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()
