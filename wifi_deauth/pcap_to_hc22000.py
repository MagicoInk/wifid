#!/usr/bin/env python3
"""
Convert a captured WPA handshake .pcap into hashcat 22000 (.hc22000) format, for
GPU cracking (much faster than aircrack-ng on CPU).

Uses hcxpcapngtool when it is installed; otherwise extracts the handshake in pure
Python (EAPOL M1 for the ANonce + M2 for the MIC) and writes the WPA*02 line.

    python3 -m wifi_deauth.pcap_to_hc22000 handshake.pcap -o out.hc22000
    hashcat -m 22000 out.hc22000 /path/to/rockyou.txt

Only use on captures from networks you own or are authorized to test.
"""

import os
import sys
import shutil
import argparse
import subprocess

from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt
from scapy.layers.eap import EAPOL

KI_MIC = 0x0100
KI_ACK = 0x0080


def _mac_hex(mac):
    return mac.lower().replace(":", "")


def _parse_key(pkt):
    """Return parsed EAPOL-Key fields, or None."""
    if not pkt.haslayer(EAPOL):
        return None
    raw = bytes(pkt[EAPOL])
    if len(raw) < 95 + 4:
        return None
    kb = raw[4:]  # key body, after the 4-byte 802.1X header
    try:
        key_info = int.from_bytes(kb[1:3], "big")
        nonce = kb[13:45]
        mic = kb[77:93]
        kdlen = int.from_bytes(kb[93:95], "big")
    except Exception:
        return None
    return {"raw": raw, "key_info": key_info, "nonce": nonce, "mic": mic,
            "kdlen": kdlen, "src": str(pkt.addr2) if pkt.addr2 else "",
            "dst": str(pkt.addr1) if pkt.addr1 else ""}


def convert_python(pcap_path):
    """Pure-Python extraction. Returns the hc22000 line, or raises ValueError."""
    pkts = rdpcap(pcap_path)
    essid_by_bssid = {}
    for p in pkts:
        if p.haslayer(Dot11Beacon):
            try:
                name = p[Dot11Elt].info.decode("utf-8", "ignore")
                if name:
                    essid_by_bssid[str(p.addr3).lower()] = name
            except Exception:
                pass

    m1 = {}   # bssid -> parsed (ANonce)
    m2 = {}   # client -> parsed (MIC + eapol)
    for p in pkts:
        k = _parse_key(p)
        if not k:
            continue
        ki = k["key_info"]
        if (ki & KI_ACK) and not (ki & KI_MIC):
            m1.setdefault(k["src"].lower(), k)            # from AP
        elif (ki & KI_MIC) and not (ki & KI_ACK) and k["kdlen"] > 0:
            m2.setdefault(k["src"].lower(), k)            # from client (M2, has key data)

    # pair an AP M1 with a client M2 that talks to it
    for client, c in m2.items():
        ap = c["dst"].lower()
        if ap in m1:
            a = m1[ap]
            essid = essid_by_bssid.get(ap)
            if not essid:
                raise ValueError("No encontré el ESSID (beacon) en el pcap.")
            eapol = bytearray(c["raw"])
            eapol[81:97] = b"\x00" * 16          # zero the MIC field for hashcat
            line = "*".join([
                "WPA", "02",
                c["mic"].hex(),
                _mac_hex(ap),
                _mac_hex(client),
                essid.encode().hex(),
                a["nonce"].hex(),
                eapol.hex(),
                "00",                            # messagepair: M1+M2, EAPOL from M2
            ])
            return line
    raise ValueError("No hay un par M1+M2 válido en el pcap (handshake incompleto).")


def main():
    ap = argparse.ArgumentParser(description="pcap -> hashcat 22000")
    ap.add_argument("pcap")
    ap.add_argument("-o", "--out", default=None, help="archivo .hc22000 de salida")
    args = ap.parse_args()

    if not os.path.exists(args.pcap):
        sys.exit(f"No existe: {args.pcap}")
    out = args.out or (os.path.splitext(args.pcap)[0] + ".hc22000")

    tool = shutil.which("hcxpcapngtool")
    if tool:
        print(f"[*] Usando {tool}")
        rc = subprocess.call([tool, "-o", out, args.pcap])
        if rc == 0 and os.path.exists(out) and os.path.getsize(out) > 0:
            print(f"[+] Escrito: {out}")
        else:
            print("[!] hcxpcapngtool no produjo salida; probando extracción en Python...")
            tool = None
    if not tool:
        try:
            line = convert_python(args.pcap)
        except ValueError as exc:
            sys.exit(f"[!] {exc}")
        with open(out, "w") as fh:
            fh.write(line + "\n")
        print(f"[+] Escrito (Python): {out}")

    print("\n[+] Crackea por GPU con:")
    print(f"    hashcat -m 22000 {out} ~/rockyou.txt")
    print("    (ver resultado:  hashcat -m 22000 {}  --show)".format(out))


if __name__ == "__main__":
    main()
