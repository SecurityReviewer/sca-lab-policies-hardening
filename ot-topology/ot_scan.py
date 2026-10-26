#!/usr/bin/env python3
"""Censimento OT attivo (sensore dsp-ot-sensor): per ogni apparato del catalogo esegue sonde REALI sulla rete simulata
(Modbus TCP FC43/FC03/FC06, porte di gestione, console del firewall, HMI SCADA) e scrive i risultati in
/var/ossec/var/ot-topology/inventory.json. I controlli SCA (ot_check.py) leggono quel file.
Uso: ot_scan.py [--loop SECONDI]
"""
import base64
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.request

CATALOG = os.environ.get("OT_CATALOG", "/var/ossec/wodles/ot-topology/ot_catalog.json")
OUT = "/var/ossec/var/ot-topology/inventory.json"
SCRATCH = 200  # registro di prova (non usato dai processi)


def tcp_open(host, port, t=1.5):
    try:
        with socket.create_connection((host, port), timeout=t):
            return True
    except OSError:
        return False


def mb(host, pdu, unit=1, t=2.0):
    with socket.create_connection((host, 502), timeout=t) as s:
        s.settimeout(t)
        s.sendall(struct.pack(">HHHB", 7, 0, len(pdu) + 1, unit) + pdu)
        head = s.recv(7)
        n = struct.unpack(">H", head[4:6])[0] - 1
        data = b""
        while len(data) < n:
            data += s.recv(n - len(data))
        return data


def ver(v):
    return tuple(int(x) for x in v.lstrip("v").split(".") if x.isdigit())


def probe_modbus(d):
    r = {"reachable": False}
    host = d["ip"]
    if not tcp_open(host, 502):
        return r
    r["reachable"] = True
    # FC43/14: identificazione (vendor, prodotto, revisione)
    resp = mb(host, bytes([43, 0x0E, 0x01, 0x00]))
    r["id_exposed"] = resp[0] == 43
    if r["id_exposed"]:
        n, p = resp[6], 7
        objs = {}
        for _ in range(n):
            oid, ln = resp[p], resp[p + 1]
            objs[oid] = resp[p + 2:p + 2 + ln].decode(errors="replace")
            p += 2 + ln
        r["vendor"], r["product"], r["firmware"] = objs.get(0, ""), objs.get(1, ""), objs.get(2, "")
    # FC03: lettura registri (informativa)
    r["read_ok"] = mb(host, struct.pack(">BHH", 3, 0, 1))[0] == 3
    # FC06: scrittura di prova su un registro scratch, poi ripristino
    before = mb(host, struct.pack(">BHH", 3, SCRATCH, 1))
    old = struct.unpack(">H", before[2:4])[0] if before[0] == 3 else 0
    w = mb(host, struct.pack(">BHH", 6, SCRATCH, 0x5A5A))
    r["unauth_write"] = w[0] == 6
    if r["unauth_write"]:
        mb(host, struct.pack(">BHH", 6, SCRATCH, old))
    min_fw = d.get("min_fw")
    r["fw_current"] = bool(min_fw and r.get("firmware") and ver(r["firmware"]) >= ver(min_fw))
    return r


def http_get(url, auth=None):
    req = urllib.request.Request(url)
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=3) as res:
            return res.status, res.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except OSError:
        return 0, ""


def tls_ok(host, port):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=2) as s:
            with ctx.wrap_socket(s):
                return True
    except (OSError, ssl.SSLError):
        return False


def scan_one(d, devs):
    host, t = d["ip"], d["type"]
    r = {"name": d["name"], "type": t, "ip": host}
    if t in ("plc", "rtu_gateway"):
        r.update(probe_modbus(d))
    else:
        r["reachable"] = any(tcp_open(host, p) for p in (23, 21, 22, 8080, 9000, 80))
    if t == "sensor":
        r["reachable"] = True  # e' il punto da cui parte il censimento
    if t == "switch":
        r["telnet_open"] = tcp_open(host, 23)
        r["ssh_open"] = tcp_open(host, 22)
    if t == "firewall":
        code, _ = http_get(f"http://{host}:8080/rules", "admin:admin")
        r["default_creds"] = code == 200
        _, rules = http_get(f"http://{host}:8080/rules", "admin:admin")
        # regola che accetta tcp/502 con sorgente fuori dalla rete OT 10.72.0.0/16 (cioe' dalla rete IT)
        exposed = []
        for line in rules.splitlines():
            if "--dport 502" in line and "-j ACCEPT" in line:
                src = line.split("-s ")[1].split()[0] if "-s " in line else "0.0.0.0/0"
                if not src.startswith("10.72."):
                    exposed.append(line.strip())
        r["it_to_modbus"] = exposed
    if t == "scada":
        r["default_creds"] = http_get(f"http://{host}:8080/", "admin:admin")[0] == 200
        r["tls"] = tls_ok(host, 8080)
    if t == "workstation":
        # la workstation dichiara i propri indirizzi sulla 9000: ha un IP nella subnet del bus di campo?
        try:
            with socket.create_connection((host, 9000), timeout=2) as s:
                s.settimeout(2)
                addrs = s.recv(2048).decode(errors="replace")
        except OSError:
            addrs = ""
        r["on_field_bus"] = "10.72.30." in addrs
    if t in ("workstation", "historian", "sensor"):
        r["legacy_ports"] = [p for p in (21, 23) if tcp_open(host, p)]
    return r


EVENTS = "/var/ossec/var/ot-agentless/events.jsonl"
STATE = "/var/ossec/var/ot-agentless/state.json"
CHECK_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ot_check.py")
ACTIONS = {
    "modbus_write_auth": "ot-write-unauthenticated", "fw_current": "ot-firmware-outdated", "switch_mgmt_encrypted": "ot-cleartext-management",
    "fw_default_creds": "ot-default-credentials", "fw_it_to_modbus": "ot-modbus-exposed-to-it", "hmi_default_creds": "ot-default-credentials",
    "hmi_tls": "ot-no-tls", "eng_segmentation": "ot-flat-network", "no_legacy_mgmt": "ot-cleartext-management",
}


def emit_failures(cat):
    """Raccolta agentless: ogni controllo non superato diventa un evento JSON (letto dall'agente con un <localfile> json), al piu' ogni 6 ore."""
    try:
        state = json.load(open(STATE, encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    now = time.time()
    os.makedirs(os.path.dirname(EVENTS), exist_ok=True)
    with open(EVENTS, "a", encoding="utf-8") as out:
        for d in cat["devices"]:
            for ck in d.get("checks", []):
                key = f"{d['name']}:{ck}"
                res = subprocess.run(["python3", CHECK_PY, d["name"], ck], capture_output=True, text=True).stdout.strip()
                if not res.startswith("FAIL") or now - state.get(key, 0) < 6 * 3600:
                    continue
                state[key] = now
                out.write(json.dumps({"module": "ot-agentless", "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "source": "scan",
                                      "device": d["name"], "device_type": d["type"], "device_ip": d["ip"], "action": ACTIONS.get(ck, "ot-control-failed"),
                                      "outcome": "failure", "check": ck, "detail": res[6:].strip()}, ensure_ascii=False) + "\n")
    json.dump(state, open(STATE, "w", encoding="utf-8"))


def run():
    cat = json.load(open(CATALOG, encoding="utf-8"))
    out = []
    for d in cat["devices"]:
        try:
            out.append(scan_one(d, cat["devices"]))
        except Exception as e:
            out.append({"name": d["name"], "type": d["type"], "ip": d["ip"], "reachable": False, "error": str(e)[:80]})
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = OUT + ".tmp"
    json.dump({"network": cat["network"], "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "devices": out}, open(tmp, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    os.replace(tmp, OUT)
    print(f"{len(out)} apparati OT censiti -> {OUT}")
    emit_failures(cat)


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--loop":
        while True:
            run()
            time.sleep(int(sys.argv[2]))
    else:
        run()
