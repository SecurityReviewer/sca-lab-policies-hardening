# sca-lab-policies-hardening

Materiale che non sta nel repository del prodotto: viveva nel laboratorio (`lab-business-apps/lab-ot`) e nelle cartelle di lavoro.

## `ot-topology/`: policy SCA della rete industriale
Policy `ot_topology` (id 62301-62317) e il suo generatore.
- `ot_catalog.json`: catalogo degli apparati del laboratorio (firewall IT/OT, switch, server SCADA, historian, workstation di ingegneria,
  PLC e gateway Modbus) con livello Purdue, IP, modello, collegamenti e testi dei controlli.
- `gen_sca.py`: genera `ot_topology.yml` dal catalogo, un controllo per apparato e tipo di verifica. Il campo `description` porta i
  metadati nel formato `ot|tipo=..|level=..|ip=..|model=..|links=..`: Decision Reviewer li legge dall'indice per disegnare il
  diagramma della rete OT. Uso: `python gen_sca.py ot_catalog.json ot_topology.yml`.
- `ot_scan.py`: sonde attive reali del sensore OT sulla rete simulata (Modbus TCP FC43/FC03/FC06, porte di gestione, console del
  firewall, HMI SCADA); scrive `/var/ossec/var/ot-topology/inventory.json`. `ot_check.py <apparato> <controllo>` legge quel file e
  stampa PASS/FAIL/ERROR (la regola SCA è `r:^PASS`).
- `ot_topology.yml`: la policy generata. Si carica **solo sul sensore**: gli altri apparati con agente ricevono solo le policy CIS.

Verifiche: scritture Modbus non autenticate, firmware, gestione in chiaro, credenziali di fabbrica, Modbus raggiungibile dalla rete IT,
HMI senza TLS, workstation di ingegneria sul bus di campo. Il laboratorio è simulato (container); gli IP 10.72.x.x sono di esempio.

## `cis-hardening-windows/`: hardening CIS di un portatile Windows 11
Script PowerShell (da amministratore) con backup e undo, applicati e verificati nel 2026 (SCA da 122 a 169 controlli superati):
- `cis-hardening-win11-v3.ps1`: password (lunghezza 14, storico 24, durata 60 giorni) e blocco account (5/15/15), firme SMB,
  restrizioni anonime, NoLMHash, LmCompatibilityLevel 5, Guest disattivato, timeout di inattività, servizi inutili disabilitati, 21
  sottocategorie di audit. **Prima salva** ogni valore toccato in `cis-v3-backup\` (mai sovrascritto).
- `cis-hardening-win11-v3-undo.ps1`: ripristina dal backup; funziona anche da modalità provvisoria.
- `cis-hardening-win11-v3-audit-addon.ps1` e `...-audit-addon-undo.ps1`: cinque sottocategorie di audit in più (Application
  Group Management, Detailed File Share, File Share, Other Object Access Events, Other Policy Change Events) con snapshot `auditpol`.

**Avvertenze**
- Le versioni v1 e v2 mandarono in crash-loop il portatile (BSOD `ks.sys`, 0x3B) per un difetto di Windows attivato dal driver di un
  programma audio, non da un'impostazione: causa rimossa, v3 stabile. Provare sempre prima su una macchina non critica e con punto di
  ripristino.
- Il backup viene scritto in `cis-v3-backup\` accanto agli script (`$PSScriptRoot`): lanciarli da una cartella scrivibile e conservarla per l'undo.
- Il controllo SCA `SCENoApplyLegacyAuditPolicy` richiede `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy = 1`,
  che questi script non impostano.

## Licenza
GNU GPL versione 2 (vedi `LICENSE`). I controlli CIS richiamati nelle policy fanno riferimento a benchmark che appartengono a CIS e non
sono coperti dalla GPL.
