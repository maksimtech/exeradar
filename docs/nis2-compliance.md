# ExeRadar: risposte alle sette domande NIS2 sul software

Revisione 1 · 2026-10-11 · vale per il ramo `main` e per le release successive alla 2026.43

Questo documento risponde alle domande che un cliente soggetto alla direttiva NIS2
(UE 2022/2555, recepita in Italia con il d.lgs. 138/2024) può porre a un fornitore di
software. Ogni affermazione verificabile nel repository è controllata dai test in
`tests/test_nis2_evidence.py`: se il codice cambia e il documento no, la CI fallisce.
Quello che il repository non può dimostrare è indicato con la data in cui è stato
verificato, oppure dichiarato assente.

La NIS2 non prevede una certificazione di prodotto: gli obblighi della direttiva
ricadono sui soggetti, non sugli strumenti che usano. Quello che segue sono le prove
che il fornitore è in grado di dare, non un attestato di conformità.

## 1. Di cosa è fatto il software

- Dipendenze dichiarate in `pyproject.toml`; risoluzione completa in `uv.lock`. La CI
  (workflow Quality) fallisce se `uv.lock` non corrisponde più a `pyproject.toml`.
- Ogni release su GitHub porta in allegato due SBOM in formato CycloneDX 1.5:
  quella dell'immagine Docker, pacchetti di sistema inclusi, e quella dell'ambiente
  Python del pacchetto installato da sorgente (vedi la tabella al punto 6).
- Provenienza firmata: le wheel su PyPI hanno un'attestazione PEP 740 firmata con
  Sigstore dal workflow di pubblicazione; le immagini su Docker Hub
  (`maksimtech/exeradar`) hanno un'attestazione di provenienza SLSA generata da
  BuildKit al momento del push.
- Licenze: il workflow Licenses fallisce se una dipendenza è sotto GPL, AGPL o LGPL.

## 2. Chi può vedere cosa, dentro l'applicazione

ExeRadar è uno strumento a riga di comando che analizza file eseguibili sul sistema di
chi lo esegue. Non ha account, sessioni, ruoli né un'interfaccia multiutente, quindi non
implementa controlli di accesso: l'accesso al sistema su cui gira è responsabilità
dell'operatore. Una matrice ruoli-permessi non esiste perché non ci sono ruoli.

L'immagine Docker gira come utente non privilegiato `exeradar`, UID 1000.

## 3. Se succede qualcosa, si può ricostruire chi ha fatto cosa

ExeRadar non tiene un registro proprio: scrive i risultati su stdout o nel file
indicato con `--output`, e gli errori su stderr; la conservazione dei log è a carico di
chi lo esegue. Non contiene telemetria e non invia nulla al fornitore.

L'analisi di un file avviene sul disco locale e ExeRadar non contatta nessun servizio,
salvo che l'utente aggiunga `--online`. Il file analizzato, e qualunque informazione su
di esso, non viene mai inviato.

Su Windows, `analyze` e `verify` chiedono anche al sistema operativo di verificare la
firma Authenticode del file, con `Get-AuthenticodeSignature`. Per farlo Windows può
contattare i server della CA indicati nel certificato, per controllare catena e
revoche: quei contatti li decide la configurazione di Windows, non ExeRadar.

I servizi esterni che ExeRadar stesso può contattare sono questi:

<!-- hosts:start -->
| Host | Quando | Cosa riceve |
| --- | --- | --- |
| `api.first.org` | `exeradar psirt` | il nome dell'organizzazione cercata |
| `eur-lex.europa.eu` | `exeradar analyze --online` | il riferimento dell'atto e degli articoli citati |
| `publications.europa.eu` | come sopra | come sopra |
| `www.normattiva.it` | come sopra | come sopra |
<!-- hosts:end -->

Ogni richiesta HTTP si presenta con uno User-Agent che indica questo repository.

Su disco ExeRadar scrive solo la cache dei testi di legge citati, in
`~/.exeradar/law_cache.json` (oppure nella cartella indicata da `EXERADAR_HOME`), e il
report se l'utente lo chiede con `--output`. La cache non contiene dati sui file
analizzati.

## 4. Come arrivano gli aggiornamenti, e in quanto tempo

La politica completa è in `SECURITY.md`: fonti di monitoraggio, tempi di risposta,
notifica ai clienti, procedura di rollback. In sintesi:

- le correzioni escono con la release successiva, che può arrivare fino a un mese dopo
  la precedente; per una vulnerabilità con CVSS pari o superiore a 9.0 il cliente che
  ha indicato un contatto di sicurezza viene avvisato entro 48 ore dalla presa in
  carico, anche se la correzione non è ancora pronta;
- le vulnerabilità accettate, con motivazione e data di revisione, sono in
  `SECURITY-EXCEPTIONS.toml`;
- ogni versione ha un tag Docker dedicato (es. `maksimtech/exeradar:v2026.43`) e un
  digest SHA256 immutabile; il rollback consiste nel tornare a quel tag o a quel
  digest.

Contatto per le segnalazioni: <security@maksimtech.com>.

## 5. Il codice viene controllato prima di andare in produzione

Analisi automatiche, ciascuna con il proprio workflow in `.github/workflows`:

<!-- scanners:start -->
| Strumento | Cosa controlla | Quando |
| --- | --- | --- |
| `CodeQL` | analisi statica del codice | ogni pull request, ogni push su `main`, ogni settimana |
| `Bandit` | analisi statica di sicurezza Python | ogni pull request, ogni push su `main`, ogni settimana |
| `Trivy` | vulnerabilità note nei file del repository | ogni pull request, ogni push su `main`, ogni settimana |
| `Snyk` | vulnerabilità note nelle dipendenze | ogni pull request, ogni push su `main` |
| `SonarCloud` | qualità, duplicazioni e copertura | ogni pull request, ogni push su `main` |
| `Docker Scout` | vulnerabilità note nell'immagine | ogni push su `main`, ogni settimana |
| `Security Posture` | raccoglie gli avvisi pubblicati dagli altri e fallisce se un avviso alto o critico non ha un'eccezione motivata | ogni pull request, ogni push su `main`, ogni settimana |
| `CodSpeed` | prestazioni: esegue i benchmark del repository e pubblica sulla pull request il confronto con `main`; non blocca il merge | ogni pull request che tocca codice, test o `pyproject.toml`, ogni push su `main` |
| `mutmut` | mutation testing: verifica che i test si accorgano delle modifiche al codice | ogni settimana |
<!-- scanners:end -->

A questi si aggiungono i test automatici (pytest, con copertura inviata a Codecov),
ruff e mypy nel workflow Quality.

Le regole del ramo `main`, lette dalle impostazioni del repository il 2026-10-12,
impongono che ogni modifica passi da una pull request, senza approvazioni richieste, e
che superi due controlli: Tests e Quality; richiedono una storia lineare e vietano la
cancellazione del ramo e la riscrittura della storia. Non prevedono eccezioni, nemmeno
per l'account del manutentore: anche il commit che aggiorna il numero di versione
arriva su `main` attraverso una pull request. Fino a quel giorno non c'era una regola
che imponesse la pull request, e l'account del manutentore poteva scavalcare le altre.
Security Posture e CodeQL girano su ogni pull request ma non sono tra i controlli
obbligatori.

ExeRadar ha un manutentore unico. Non c'è nessuna revisione obbligatoria da parte di
una seconda persona: le modifiche vengono unite dal manutentore dopo che la CI è verde.
È un limite noto di un progetto con una sola persona.

## 6. Qualcuno dall'esterno ha provato a entrare

Non è stato eseguito un penetration test. Esiste una scansione automatica continua
delle vulnerabilità note, descritta al punto 5, ma non è un penetration test: non ha un
ambito concordato, non è condotta da un tester indipendente e non produce un rapporto
con vulnerabilità trovate e correzioni datate.

Ogni release porta in allegato i risultati datati di quella scansione, insieme alle
SBOM:

<!-- assets:start -->
| File allegato alla release | Contenuto |
| --- | --- |
| `sbom-image-<versione>.cdx.json` | SBOM CycloneDX 1.5 dell'immagine Docker della versione |
| `sbom-source-<versione>.cdx.json` | SBOM CycloneDX 1.5 dell'ambiente Python del pacchetto |
| `trivy-image-<versione>-<data>.json` | vulnerabilità note nell'immagine, scansione Trivy |
| `trivy-fs-<versione>-<data>.json` | vulnerabilità note nei file del repository al tag, scansione Trivy |
| `EVIDENCE-<versione>.md` | cosa sono questi file, quando e da quale commit sono stati prodotti |
<!-- assets:end -->

Se a un tag il repository non contiene un file che Trivy sappia analizzare, come un
lockfile, il rapporto `trivy-fs` di quella release è vuoto. Un rapporto vuoto non
indica l'assenza di vulnerabilità, e in quel caso la nota `EVIDENCE` lo dice.

## 7. E se il fornitore sparisce

Il codice sorgente è pubblico su <https://github.com/maksimtech/exeradar> con licenza
MIT, e resta accessibile indipendentemente dalle sorti commerciali del fornitore. Le
versioni pubblicate restano su PyPI e su Docker Hub.

ExeRadar non conserva dati del cliente: tutto l'output è prodotto sull'infrastruttura
di chi lo esegue, quindi non c'è nulla da esportare.

Una clausola contrattuale su questo punto va concordata caso per caso e fatta rivedere
da un legale.
