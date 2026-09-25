"""A universal Mach-O is the normal shape on macOS, and it came out "unrecognised".

The README promises: "ELF and Mach-O are recognised by their magic number and
declined by name — not mistaken for an unknown format." A universal binary — one
file holding an arm64 slice and an x86_64 slice, which is what every shipped macOS
binary has been since 2020 — starts with 0xCAFEBABE, and that was left out on
purpose: it is also the magic of a Java class file, and guessing between them from
four bytes is guessing.

Four bytes, yes. Eight say more, and the file says everything:

    struct fat_header  { uint32 magic; uint32 nfat_arch; }        big endian
    struct fat_arch    { cputype; cpusubtype; offset; size; align }

A Java class file's bytes 4–8 are its minor and major version, which read as a
big-endian count of 45 to 69 — Java 1.1 through Java 25. A universal binary holds
two to about six slices. And the first slice's offset and size point inside the
file, at a thin Mach-O magic. A class file's do not.

So this is not a guess between two readings: it is checking whether the fat
structure is there. When it is, the format is named and declined as the README
says. When it is not — a Java class, a truncated download, anything else wearing
that magic — nothing is claimed, exactly as before.
"""

from __future__ import annotations

import struct

from exeradar import scanner

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

# One of the thin magics a slice has to start with.
ARM64 = b"\xcf\xfa\xed\xfe"

CPU_ARM64 = 0x0100000C
CPU_X86_64 = 0x01000007


def fat(slices, *, magic=FAT_MAGIC, count=None, body=True) -> bytes:
    """A universal binary holding `slices` — each (cputype, contents).

    `count` overrides nfat_arch, and `body=False` leaves the slices out, which is
    how a cut-off download looks.
    """
    wide = magic == FAT_MAGIC_64
    entry = 32 if wide else 20
    header = 8 + entry * len(slices)

    offset = header
    entries = b""
    payload = b""
    for cputype, contents in slices:
        if wide:
            entries += struct.pack(">IIQQII", cputype, 0, offset, len(contents), 12, 0)
        else:
            entries += struct.pack(">IIIII", cputype, 0, offset, len(contents), 12)
        payload += contents
        offset += len(contents)

    out = struct.pack(">II", magic, len(slices) if count is None else count) + entries
    return out + (payload if body else b"")


def universal() -> bytes:
    """arm64 and x86_64, the ordinary macOS build."""
    return fat([
        (CPU_ARM64, ARM64 + b"\x00" * 60),
        (CPU_X86_64, b"\xcf\xfa\xed\xfe" + b"\x11" * 60),
    ])


def java_class() -> bytes:
    """0xCAFEBABE, minor 0, major 52 — a Java 8 class, then a constant pool."""
    return struct.pack(">IHH", FAT_MAGIC, 0, 52) + b"\x00\x1f" + b"\x07\x00\x02" * 20


def written(tmp_path, name, data):
    target = tmp_path / name
    target.write_bytes(data)
    return target


# ── recognised ──────────────────────────────────────────────────────────────


def test_a_universal_binary_is_recognised(tmp_path):
    assert scanner.format_of(written(tmp_path, "tool", universal())) == "MachO"


def test_and_declined_by_name_as_the_readme_says(tmp_path):
    """"not supported yet" is a different answer from "unrecognised format": one
    says the tool knows what this is, the other says it does not."""
    result = scanner.scan(written(tmp_path, "tool", universal()))

    assert result.format == "MachO"
    assert "not supported" in (result.error or "")
    assert "unrecognised" not in (result.error or "")


def test_a_single_slice_archive_counts(tmp_path):
    """A fat wrapper around one architecture is still a fat wrapper."""
    one = fat([(CPU_ARM64, ARM64 + b"\x00" * 60)])

    assert scanner.format_of(written(tmp_path, "one", one)) == "MachO"


def test_the_64_bit_fat_header_counts_too(tmp_path):
    """0xCAFEBABF, with 64-bit offsets — what a slice past 4 GB needs."""
    wide = fat([(CPU_ARM64, ARM64 + b"\x00" * 60)], magic=FAT_MAGIC_64)

    assert scanner.format_of(written(tmp_path, "wide", wide)) == "MachO"


# ── not recognised, and not guessed at ──────────────────────────────────────


def test_a_java_class_is_not_a_mach_o(tmp_path):
    """The collision the old comment was right about. Nothing is claimed for it:
    exeradar does not read Java."""
    assert scanner.format_of(written(tmp_path, "Main.class", java_class())) is None


def test_a_java_class_is_still_reported_as_unrecognised(tmp_path):
    result = scanner.scan(written(tmp_path, "Main.class", java_class()))

    assert result.format is None
    assert "unrecognised" in (result.error or "")


def test_an_archive_claiming_no_slices_is_declined(tmp_path):
    empty = fat([(CPU_ARM64, ARM64 + b"\x00" * 60)], count=0)

    assert scanner.format_of(written(tmp_path, "zero", empty)) is None


def test_an_absurd_slice_count_is_declined(tmp_path):
    """4096 architectures is not a build, it is a coincidence of bytes."""
    many = fat([(CPU_ARM64, ARM64 + b"\x00" * 60)], count=4096)

    assert scanner.format_of(written(tmp_path, "many", many)) is None


def test_a_truncated_download_is_declined(tmp_path):
    """The header promises slices the file does not contain."""
    cut = fat([(CPU_ARM64, ARM64 + b"\x00" * 60)], body=False)

    assert scanner.format_of(written(tmp_path, "cut", cut)) is None


def test_a_slice_that_is_not_a_mach_o_is_declined(tmp_path):
    """The structure can be right by accident; the slice's own magic cannot."""
    wrong = fat([(CPU_ARM64, b"NOPE" + b"\x00" * 60)])

    assert scanner.format_of(written(tmp_path, "wrong", wrong)) is None


def test_eight_bytes_alone_still_decline_it(tmp_path):
    """detect_format() sees the head and nothing else, and a head cannot tell:
    that is why the check is a second function and not a wider magic table."""
    assert scanner.detect_format(universal()[:8]) is None


# ── nothing else moves ──────────────────────────────────────────────────────


def test_a_thin_mach_o_is_unaffected(tmp_path):
    thin = ARM64 + b"\x00" * 60

    assert scanner.format_of(written(tmp_path, "thin", thin)) == "MachO"


def test_a_pe_is_unaffected(signed_pe_path):
    assert scanner.format_of(signed_pe_path) == "PE"


def test_an_elf_is_unaffected(tmp_path):
    elf = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 57

    assert scanner.format_of(written(tmp_path, "elf", elf)) == "ELF"


def test_a_text_file_is_unaffected(tmp_path):
    assert scanner.format_of(written(tmp_path, "notes.txt", b"hello there\n" * 4)) is None


def test_an_empty_file_is_not_a_fat_archive(tmp_path):
    assert scanner.format_of(written(tmp_path, "empty", b"")) is None


def test_a_missing_file_is_still_none():
    assert scanner.format_of("no/such/file.bin") is None
