# Security Policy — Assistente-Aggiornamento

## 1. Modello di Minaccia e Obiettivo di Sicurezza

Questo repository mantiene un catalogo (`links.json` e `catalog.manifest.json`) di riferimenti a immagini ISO di Windows 11. Il repository **non ospita, non compila e non distribuisce direttamente** binari eseguibili o immagini disco di sistema operativo.

I rischi primari affrontati dalla presente policy includono:
- **Manomissione del catalogo (Supply Chain Attack):** sostituzione malevola di URL o introduzione di link verso immagini compromesse.
- **Attacchi Man-in-the-Middle o Mirror Compromessi:** alterazione del contenuto durante il download da mirror di terze parti (es. Archive.org).
- **Esecuzione di media non autenticati:** installazione accidentale di immagini prive di validazione crittografica.

---

## 2. Linee Guida Obbligatorie per gli Utenti

1. **Priorità alle Fonti Ufficiali:** quando disponibile per la versione target, scaricare sempre le immagini tramite il canale ufficiale Microsoft: [Download di Windows 11 (Microsoft)](https://www.microsoft.com/software-download/windows11).
2. **Verifica Crittografica Pre-Installazione:** **MAI** montare, masterizzare o avviare un file ISO senza averne preventivamente verificato l'integrità crittografica.
   È fornito lo script ufficiale di verifica:
   ```powershell
   .\scripts\Verify-IsoIntegrity.ps1 -IsoPath "C:\Percorso\immagine.iso"
   ```
   Lo script controlla in streaming sia l'hash crittografico (SHA-1 / MD5) sia l'esatta dimensione in byte rispetto al manifest firmato `catalog.manifest.json`.
3. **Controllo con Checksum Standard:**
   ```powershell
   Get-FileHash -Path "C:\Percorso\immagine.iso" -Algorithm SHA1
   ```
   Confrontare l'output con `checksums.sha1`.

---

## 3. Provenienza Crittografica dei Commit (GPG Signing)

Tutti i commit e i tag ufficiali di questo repository sono firmati digitalmente tramite OpenPGP/GPG.

- **Autore:** Light Yagami (`maule2703@gmail.com`)
- **Key ID:** `CC21AE8B31EBE91F`
- **Fingerprint:** `99F1B31CFF6CC21485D87687CC21AE8B31EBE91F`

Per verificare l'integrità del clone locale:
```powershell
git log --show-signature -n 5
git verify-commit HEAD
```
Commit non firmati o con firme non corrispondenti devono essere considerati non affidabili.

---

## 4. Controlli CI/CD e Hardening

- **Zero-Trust Token Permissions:** i workflow di GitHub Actions operano con `permissions: {}` a livello globale e `contents: read` strettamente limitato ai singoli job.
- **Pinned Commit SHAs:** tutte le azioni esterne (es. `actions/checkout`) sono vincolate a commit SHA immutabili.
- **Validazione Difensiva:** la suite di test esegue controlli positivi e negativi rigorosi su host allowlist (`archive.org`), protocollo HTTPS obbligatorio, assenza di parametri query/frammenti/credenziali e protezione da path traversal.
- **Dependabot:** scansione automatica giornaliera delle dipendenze dei workflow con etichettatura di sicurezza.

---

## 5. Segnalazione di Vulnerabilità

Per segnalare una vulnerabilità di sicurezza (es. discrepanza crittografica, potenziale vettore di iniezione o URL non conforme):
- Utilizzare la funzione privata **Report a vulnerability** nella scheda Security del repository GitHub.
- Non aprire issue pubbliche né pull request contenenti exploit o URL non verificati.
- Includere dettagli tecnici riproducibili, l'identificatore del commit interessato e l'output della verifica.
