# ExeRadar — CLAUDE.md

Contesto rapido per riprendere il lavoro senza ricostruire la storia.

## Cos'è

Analisi statica di eseguibili Windows (PE), macOS (Mach-O/FAT) e Linux (ELF):
headers, import, stringhe, code signing, controfirme, TLP classification,
PSIRT lookup, librerie embedded. CLI Typer, output report testuale/HTML.

Repo: <https://github.com/maksimtech/exeradar> (sotto org `maksimtech`)

## Struttura

```
exeradar/
  cli.py          # entry point `exeradar`
  scanner.py      # orchestrazione analisi
  models.py       # dataclass risultati
  report.py       # generazione output
  signature.py    # code signing (Authenticode, notarization, GPG)
  strings.py      # estrazione stringhe significative
  libraries.py    # rilevamento librerie embedded
  first_teams.py  # lookup FIRST PSIRT
  tlds.py         # Public Suffix List per domain extraction
  tlp.py          # TLP classification
  formats/
    __init__.py
    pe.py         # PE (Windows) parser
  law_fetcher.py  # scarica GDPR/NIS2 da Cellar/EUR-Lex (copia da patchradar)
  law_checker.py  # confronta testo con cache SHA-256
  law_cache.py    # ~/.exeradar/law_cache.json
tests/
  fixtures/       # binari di test (PE, Mach-O, ELF reali o sintetici)
```

## Comandi essenziali

```bash
pip install -e . --break-system-packages

python -m pytest tests/ -q
python -m pytest tests/test_law_fetcher.py -q   # se esiste

ruff check exeradar/ tests/
mypy exeradar/
```

## law_fetcher.py — stato

- Fix HTTPS redirect Cellar (`ed56bdb`) su main
- Changelog aggiornato (`669d6e0`)
- Stessa logica di mailradar/patchradar: Cellar prima, EUR-Lex fallback
- Cache in `~/.exeradar/law_cache.json`

## Differenze rispetto agli altri radar

| Aspetto | exeradar | mailradar | patchradar |
|---------|----------|-----------|------------|
| Focus | File binari | Email domains | CVE/software |
| asyncio | Da verificare | No | Sì |
| DB | No | No | aiosqlite |
| API | No | No | FastAPI |
| Input | Eseguibili | Lista domini | Inventory YAML |

## Git

Branch principale: `main`. Push diretto per fix/test.  
Repo sotto `maksimtech/exeradar` (clonato in `/home/claude/maksimtech/exeradar/`).

Attribuzione da aggiungere in fondo a ogni commit:
```
Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_0154qVT8TUGnkx4DFoZCbD76
```

## PR recenti

- `#8` — fix 13 binari reali prima di una demo
- `ed56bdb` — fix HTTPS redirect Cellar (push diretto su main, stessa fix degli altri)

## Note veloci

- `fixtures/` contiene binari reali — non committare eseguibili non verificati
- ARCHITECTURE.md e ATTRIBUTIONS.md presenti nel repo (insoliti, probabilmente
  documentano dipendenze con licenze particolari)
- `SECURITY-EXCEPTIONS.toml` — eccezioni deliberate ai check di sicurezza
- `__main__.py` presente → `python -m exeradar` funziona
