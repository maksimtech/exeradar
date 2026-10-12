# ExeRadar — istruzioni per Claude Code

Claude Code legge questo file da solo. Contiene regole di lavoro e fatti che il
repository conferma; la storia sta nel CHANGELOG e nelle pull request, non qui.

## Cos'è

Analisi statica di eseguibili, a riga di comando: PE prima, ELF e Mach-O dopo.
Intestazioni, import, stringhe leggibili, firma del codice. Comandi: `analyze`,
`batch`, `verify`, `psirt`. L'architettura è descritta in `ARCHITECTURE.md`; cosa
contatta in rete e cosa scrive su disco è in `docs/nis2-compliance.md`,
sezione 3.

## Regole di lavoro

- **Ogni modifica passa da una pull request** su `main`, unita quando i controlli
  obbligatori sono verdi, anche se il ruleset di questo repository non la impone.
  Niente push diretti su `main` e niente `gh pr merge --admin`. Unica eccezione,
  il commit di versione che crea `release.sh`.
- **Commit firmati** con l'identità e la chiave configurate nel repository:
  `git log -1 --format=%G?` deve dare `G`. Messaggi `tipo(ambito): …`, con il
  perché nel corpo. La riga `Co-Authored-By` la indica l'ambiente di Claude Code;
  non scrivere nomi di modello né link a sessioni in questo file.
- **TDD**: il test che riproduce il difetto fallisce prima della correzione, e si
  vede fallire.
- **Niente mock.** Input reali, oggetti reali, server locali veri, binari veri in
  `tests/fixtures/`. Al confine di rete si possono riprodurre solo risposte
  registrate dal servizio vero, in fixture che lo dichiarano (`_recorded`); una
  fixture costruita o ricavata si dichiara `_derived`. Risposte inventate e patch
  di funzioni interne per simulare un comportamento non si usano. "Non misurato"
  non è zero.
- **`docs/nis2-compliance.md` è documentazione per i clienti** ed è tenuta al
  codice da `tests/test_nis2_evidence.py`: se cambiano gli host contattati, i file
  scritti, l'immagine o i workflow, il documento si aggiorna nella stessa PR.
  Nessuna affermazione che il repository non possa dimostrare.
- **Avvisi di sicurezza accettati** solo in `SECURITY-EXCEPTIONS.toml`, con motivo
  e `review_by`; mai `# nosec` o `# noqa` per zittire uno scanner.
- **Repository di terzi**: nessuna issue, PR o commento senza conferma esplicita
  del proprietario.

## Comandi

Come li esegue la CI (Quality e Tests). Su Windows il Python del venv è
`.venv/Scripts/python`, su Linux `.venv/bin/python`. Le dipendenze di sviluppo
sono un gruppo PEP 735 e servono pip 25.1 o successivo.

```bash
python -m venv .venv
.venv/Scripts/python -m pip install --upgrade pip
.venv/Scripts/python -m pip install --group dev -e .
.venv/Scripts/python -m pytest -q
.venv/Scripts/ruff check exeradar tests tools
.venv/Scripts/mypy exeradar
uv lock --check            # con uv 0.12.18, la versione fissata in quality.yml
```

Su Windows i test di `tests/test_release_script.py` falliscono anche su un `main`
pulito, perché lanciano bash, e quelli in `tests/benchmarks` chiedono il plugin
di CodSpeed: non sono regressioni. Per confrontare, usare un
`git worktree add --detach <cartella> origin/main`.

## Release

`release.sh` porta la versione (CalVer `YYYY.count[.fix]`), crea il tag `vX` e
pubblica. Il tag fa partire PyPI, la release GitHub con le note dal CHANGELOG e
l'immagine `maksimtech/exeradar:vX`; poi Release Evidence (`sbom.yml`) allega
SBOM e scansioni datate. Per una release già uscita:
`gh workflow run sbom.yml -f tag=vX`.

## Note

- `law_fetcher.py` e `law_cache.py` sono copiati, non condivisi, in mailradar,
  exeradar, cookieradar, apkradar e patchradar, come `first_teams.py` dice di sé:
  una correzione va portata in tutte le copie. I redirect si seguono a mano e mai
  in chiaro (`_get_over_https`): Cellar risponde con un 303 verso `http://`.
- L'analisi è offline salvo `--online` (testi di legge) e `psirt` (FIRST); su
  Windows la verifica della firma passa anche da `Get-AuthenticodeSignature`.
