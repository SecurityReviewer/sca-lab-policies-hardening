#!/usr/bin/env python3
"""Controlli SCA sul censimento OT (ot_scan.py). Uso: ot_check.py <apparato> <controllo>
Stampa PASS/FAIL/ERROR: la regola SCA e' 'r:^PASS'.
"""
import json
import sys

INV = "/var/ossec/var/ot-topology/inventory.json"


def main():
    if len(sys.argv) != 3:
        print("ERROR: uso ot_check.py <apparato> <controllo>")
        return
    name, check = sys.argv[1], sys.argv[2]
    try:
        data = json.load(open(INV, encoding="utf-8"))
    except (OSError, ValueError):
        print(f"ERROR: censimento OT non disponibile ({INV})")
        return
    d = next((x for x in data.get("devices", []) if x["name"] == name), None)
    if d is None or not d.get("reachable"):
        # un apparato che non risponde e' un problema di monitoraggio, non un esito positivo
        print(f"FAIL: {name} non raggiungibile dal sensore OT")
        return

    def res(ok, good, bad):
        print(("PASS: " + good) if ok else ("FAIL: " + bad))

    if check == "modbus_write_auth":
        res(not d.get("unauth_write"), f"{name} rifiuta le scritture Modbus da host non autorizzati", f"{name} accetta scritture Modbus da qualsiasi host (nessuna autenticazione)")
    elif check == "fw_current":
        res(d.get("fw_current"), f"firmware {d.get('firmware')} aggiornato", f"firmware {d.get('firmware')} obsoleto su {name}")
    elif check == "switch_mgmt_encrypted":
        res(not d.get("telnet_open"), f"{name} non offre telnet", f"gestione in chiaro (telnet/23) attiva su {name}")
    elif check == "fw_default_creds":
        res(not d.get("default_creds"), f"credenziali di fabbrica non valide su {name}", f"credenziali di fabbrica (admin/admin) valide sulla console di {name}")
    elif check == "fw_it_to_modbus":
        rules = d.get("it_to_modbus") or []
        res(not rules, f"nessuna regola Modbus dalla rete IT su {name}", f"{len(rules)} regola/e accettano tcp/502 dalla rete IT su {name}: {'; '.join(rules)[:160]}")
    elif check == "hmi_default_creds":
        res(not d.get("default_creds"), f"credenziali di fabbrica non valide sull'HMI di {name}", f"credenziali di fabbrica (admin/admin) valide sull'HMI di {name}")
    elif check == "hmi_tls":
        res(d.get("tls"), f"HMI di {name} con TLS", f"HMI di {name} servita senza TLS (HTTP in chiaro)")
    elif check == "eng_segmentation":
        res(not d.get("on_field_bus"), f"{name} non e' sul bus di campo", f"{name} ha un indirizzo nella subnet del bus di campo (rete piatta verso i PLC)")
    elif check == "no_legacy_mgmt":
        ports = d.get("legacy_ports") or []
        res(not ports, f"nessun servizio in chiaro su {name}", f"servizio/i in chiaro in ascolto su {name}: porte {ports}")
    else:
        print("ERROR: controllo sconosciuto")


if __name__ == "__main__":
    main()
