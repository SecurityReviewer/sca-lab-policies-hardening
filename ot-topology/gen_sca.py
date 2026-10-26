#!/usr/bin/env python3
"""Genera ot_topology.yml (policy SCA) dal catalogo ot_catalog.json: un controllo per apparato e tipo di verifica.
Il campo 'description' di ogni controllo porta i metadati dell'apparato (tipo, livello Purdue, IP, modello, collegamenti)
nel formato 'ot|chiave=valore|...': Decision Reviewer li legge dall'indice per disegnare il diagramma della rete OT.
Uso: gen_sca.py [catalogo.json] [uscita.yml]
"""
import json
import sys

cat = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "ot_catalog.json", encoding="utf-8"))
out = sys.argv[2] if len(sys.argv) > 2 else "ot_topology.yml"

COMPLIANCE = {
    "modbus_write_auth": ('"21.2.i"', '"A.8.20"'),
    "fw_current": ('"21.2.e"', '"A.8.8"'),
    "switch_mgmt_encrypted": ('"21.2.h"', '"A.8.20"'),
    "fw_default_creds": ('"21.2.i"', '"A.8.5"'),
    "fw_it_to_modbus": ('"21.2.e"', '"A.8.22"'),
    "hmi_default_creds": ('"21.2.i"', '"A.8.5"'),
    "hmi_tls": ('"21.2.h"', '"A.8.24"'),
    "eng_segmentation": ('"21.2.e"', '"A.8.22"'),
    "no_legacy_mgmt": ('"21.2.h"', '"A.8.20"'),
}

texts = {k: {f: v.replace('"', "'") for f, v in t.items()} for k, t in cat["check_texts"].items()}
body = ""
cid = 62301
for d in cat["devices"]:
    meta = "ot|" + "|".join(f"{k}={v}" for k, v in [("type", d["type"]), ("level", d["level"]), ("ip", d["ip"]), ("model", d["model"]),
                                                    ("role", d["role"]), ("links", ",".join(d["links"]))])
    for ck in d["checks"]:
        nis2, iso = COMPLIANCE[ck]
        body += f"""  - id: {cid}
    name: "{cat['check_titles'][ck]} — {d['name']}"
    description: "{texts[ck]['description']}\n{meta}"
    rationale: "{texts[ck]['rationale']}"
    remediation: "{texts[ck]['remediation']}"
    condition: all
    rules:
      - 'c:python3 /var/ossec/wodles/ot-topology/ot_check.py {d['name']} {ck} -> r:^PASS'
    compliance:
      nis2: [{nis2}]
      gdpr: [""]
      iso_27001: [{iso}]
"""
        cid += 1

yml = f"""policy:
  id: "ot_topology"
  file: "ot_topology.yml"
  name: "Rete industriale OT, SCADA e Modbus (Cyber Reviewer, laboratorio)"
  description: "Censimento attivo dell'impianto di magazzino logistico di esempio (firewall IT/OT, switch industriale, server SCADA, historian, workstation di ingegneria, PLC e gateway Modbus) con verifiche di hardening: scritture Modbus non autenticate, firmware, gestione in chiaro, credenziali di fabbrica, segmentazione."
  references:
    - https://www.cisa.gov/topics/industrial-control-systems
    - https://csrc.nist.gov/pubs/sp/800/82/r3/final

requirements:
  name: "Censimento OT presente"
  condition: all
  rules:
    - 'f:/var/ossec/var/ot-topology/inventory.json'

checks:
{body}"""
open(out, "w", encoding="utf-8").write(yml)
print(f"{cid - 62301} controlli -> {out}")
