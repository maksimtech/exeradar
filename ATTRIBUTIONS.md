# Attributions

Third-party material redistributed in this repository.

## `tests/fixtures/python.exe`

The CPython interpreter launcher for Windows, version 3.14, 106,208 bytes,
SHA-256 `4942b86a6597e5aee0128daa00050ed79bc21f6e709a78eb19cbfeb0c2f39ac9`.

Copyright (c) 2001-2026 Python Software Foundation. All Rights Reserved.

Redistributed under the PSF License Agreement, reproduced in full in
[`tests/fixtures/python-LICENSE.txt`](tests/fixtures/python-LICENSE.txt), which
permits redistribution in binary form provided the copyright notice is
retained. Python is a trademark of the Python Software Foundation; its presence
here implies no endorsement of this project by the PSF.

### Why this file and not another

The tests need a real PE: headers with real section characteristics, a real
import table, and a real Authenticode signature. Three candidates were
rejected before this one.

- **notepad++.exe**, the first suggestion, is 8.1 MB and GPL. Redistributing it
  from an MIT repository is a licence conflict, and it would sit in the git
  history permanently.
- **Windows system binaries** are not redistributable at all.
- **The LIEF sample corpus** lives in `lief-project/samples`, which declares no
  licence. No licence means no permission.

pefile's corpus is MIT but ships as one encrypted 64 MB archive, and LIEF's own
`tests/pe` directory holds no binaries — it pulls them from the unlicensed
samples repository.

Building a fixture instead of borrowing one was tried and abandoned: LIEF 1.0
cannot construct a `PE.Binary` from Python, and a hand-written minimal PE turns
into a PE writer, at which point the tests would be checking the writer rather
than the parser.

`python.exe` fits where the others did not: 104 KB, a permissive licence that
names redistribution explicitly, and a genuine embedded signature from the
Python Software Foundation with an RFC3161 countersignature.

### One property worth keeping

The signing certificate on this binary was valid from 2026-08-04 to 2026-08-07
— three days — and `verify_signature()` still returns OK today, well after it
expired. The countersignature proves the file was signed while the certificate
was valid, which is exactly what a countersignature is for.

That makes the fixture better than a freshly signed one: the test that asserts
a valid signature is already past the expiry date, so it cannot start failing
later for a reason that has nothing to do with this code.
