# ExeRadar

Static analysis of executables: PE first, ELF and Mach-O after. Headers,
imports, readable strings, code signing.

**Status: skeleton.** The modules are stubs and nothing analyses anything yet.
The design is written down first, in [ARCHITECTURE.md](ARCHITECTURE.md), and
the part worth reading is section 3.

## Why section 3

A spike against Windows' own `notepad.exe` found that LIEF reports zero
embedded signatures for a file that Windows reports as validly signed: the
signature lives in a catalog under `CatRoot`, which is how most Windows system
binaries are signed and which no PE parser can see.

So signature checking has three paths, not one, and on Linux and macOS — where
the catalog cannot be consulted — the absence of an embedded signature is
reported as `unknown` and never as `unsigned`. Calling a catalog-signed
Microsoft binary unsigned would be the worst false positive this tool could
ship.

## Part of the Radar family

Alongside [apkradar](https://github.com/maksimtech/apkradar),
[mailradar](https://github.com/maksimtech/mailradar),
[cookieradar](https://github.com/maksimtech/cookieradar) and
[patchradar](https://github.com/maksimtech/patchradar).

## Licence

MIT.
