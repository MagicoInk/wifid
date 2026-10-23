#!/usr/bin/env python3
"""
Headless hunt for Wi-Fi camera / DVR clients.

Scans channels passively, attributes each associated station to its AP, classifies
it by OUI (reusing the GUI's classifier) and prints the networks that have a client
that looks like a camera / DVR.

    sudo python3 -m wifi_deauth.scan_cameras            # iface wlan1, 2 passes
    sudo python3 wifi_deauth/scan_cameras.py wlan1 --passes 3 --secs 1.5

Honest limits: a camera only shows up if it transmits during the scan and its MAC
is a recognizable vendor OUI (randomized MACs can't be classified). Classification
by OUI is a strong hint, not a guarantee.
"""

import os
import sys
import time
import argparse
from collections import defaultdict

try:
    from .gui import (vendor_for, classify_device, mac_is_group, band_for_channel,
                      get_supported_channels, set_channel, interface_mode, enable_monitor_mode)
except ImportError:
    from gui import (vendor_for, classify_device, mac_is_group, band_for_channel,
                     get_supported_channels, set_channel, interface_mode, enable_monitor_mode)

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt

APS = {}                         # bssid -> ssid
HIDDEN = set()                   # bssids whose beacon had an empty SSID (hidden network)
CLIENTS = defaultdict(dict)      # bssid -> {client_mac: {count, bytes, rssi, ch}}
_CUR_CH = [0]

# OUI vendor keywords that commonly appear in Tuya / Smart Life camera WiFi modules
IOT_MODULE_HINTS = ("espressif", "tuya", "realtek", "beken", "hi-flying",
                    "winner micro", "mxchip", "ralink", "ai-thinker",
                    # SoCs/modules frecuentes en cámaras IP baratas / Tuya
                    "altobeam", "bilian", "smartchip", "gaoshengda", "hualai",
                    "ingenic", "anyka", "grain media", "sigmastar", "xiongmai")


def _cb(pkt):
    try:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            mac = str(pkt.addr3)
            try:
                raw = pkt[Dot11Elt].info.strip(b"\x00").decode("utf-8", "ignore").strip()
            except Exception:
                raw = ""
            if mac and mac != "ff:ff:ff:ff:ff:ff":
                if raw:
                    APS[mac] = raw          # real name (also reveals a hidden net via probe resp)
                    HIDDEN.discard(mac)
                else:
                    APS.setdefault(mac, mac)
                    if pkt.haslayer(Dot11Beacon):
                        HIDDEN.add(mac)     # beacon with empty SSID = hidden network
        if pkt.haslayer(Dot11) and not pkt.haslayer(Dot11Beacon):
            a1 = str(pkt.addr1) if pkt.addr1 else None
            a2 = str(pkt.addr2) if pkt.addr2 else None
            a3 = str(pkt.addr3) if pkt.addr3 else None
            ap = next((a for a in (a1, a2, a3) if a in APS), None)
            if ap:
                for cand in (a1, a2):
                    if cand and cand != ap and cand not in APS and not mac_is_group(cand):
                        info = CLIENTS[ap].setdefault(cand, {"count": 0, "bytes": 0,
                                                              "rssi": None, "ch": _CUR_CH[0]})
                        info["count"] += 1
                        info["bytes"] += len(pkt)
                        info["ch"] = _CUR_CH[0]
                        try:
                            info["rssi"] = int(pkt.dBm_AntSignal)
                        except Exception:
                            pass
                        break
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description="Find Wi-Fi networks that have a camera/DVR client")
    ap.add_argument("iface", nargs="?", default="wlan1", help="monitor-mode interface (default wlan1)")
    ap.add_argument("--secs", type=float, default=1.2, help="seconds sniffed per channel")
    ap.add_argument("--passes", type=int, default=2, help="how many times to sweep all channels")
    ap.add_argument("--all-clients", action="store_true", help="also list non-camera clients")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Debe ejecutarse como root (usa sudo).")

    iface = args.iface
    if interface_mode(iface) != "monitor":
        print(f"[*] {iface} no está en monitor; intentando activarlo...")
        if not enable_monitor_mode(iface):
            sys.exit(f"No pude poner {iface} en modo monitor. Actívalo y reintenta.")
    print(f"[*] Escaneando en {iface} — {args.passes} pasada(s), {args.secs}s por canal. Ctrl-C para cortar.")

    channels = get_supported_channels(iface)
    try:
        for p in range(args.passes):
            for ch in channels:
                set_channel(iface, ch)
                _CUR_CH[0] = ch
                print(f"\r[*] pasada {p + 1}/{args.passes}  canal {ch}   APs={len(APS)} "
                      f"clientes={sum(len(c) for c in CLIENTS.values())}   ", end="")
                sys.stdout.flush()
                sniff(iface=iface, prn=_cb, timeout=args.secs, store=False)
    except KeyboardInterrupt:
        print("\n[*] Cortado por el usuario.")
    print()

    # build one row per client with candidate reasons
    rows = []
    for bssid, clients in CLIENTS.items():
        hidden = bssid in HIDDEN
        net = APS.get(bssid, bssid)
        for cmac, info in clients.items():
            vendor = vendor_for(cmac)
            label = classify_device(vendor, cmac)
            v = (vendor or "").lower()
            reasons = []
            if "Cámara" in label:
                reasons.append("OUI de marca de cámara")
            if any(k in v for k in IOT_MODULE_HINTS):
                reasons.append(f"módulo IoT/cámara típico ({vendor})")
            rows.append({"net": net, "bssid": bssid, "hidden": hidden, "mac": cmac,
                         "vendor": vendor, "label": label, "reasons": reasons,
                         "bytes": info.get("bytes", 0), "count": info.get("count", 0),
                         "rssi": info.get("rssi"), "ch": info.get("ch")})

    # the camera streams video -> it is usually a top talker
    rows.sort(key=lambda r: r["bytes"], reverse=True)
    for i, r in enumerate(rows[:5]):
        if r["bytes"] > 0:
            r["reasons"].append(f"alto tráfico (top #{i + 1})")

    def fmt(r):
        rssi = f"{r['rssi']} dBm" if r["rssi"] is not None else "?"
        why = (" · " + "; ".join(r["reasons"])) if r["reasons"] else ""
        return (f"{r['mac']}  {r['vendor']}  [{r['label']}]  "
                f"(ch {r['ch']} {band_for_channel(r['ch'])}, {rssi}, "
                f"{r['count']} frames, {r['bytes']} B){why}")

    print("=" * 78)
    nhidden = len(HIDDEN)
    print(f"RESULTADO: {len(APS)} redes ({nhidden} ocultas), "
          f"{sum(len(c) for c in CLIENTS.values())} clientes\n")

    if HIDDEN:
        print("REDES OCULTAS detectadas:")
        for b in HIDDEN:
            print(f"  🔒 [{b}]  ch {_ap_channel(b)}  ·  {len(CLIENTS.get(b, {}))} cliente(s)")
        print("\n>>> CLIENTES EN REDES OCULTAS (sospechosos principales de tu cámara):")
        hid_rows = [r for r in rows if r["hidden"]]
        if hid_rows:
            for r in sorted(hid_rows, key=lambda r: r["bytes"], reverse=True):
                print(f"   📷? {fmt(r)}")
        else:
            print("   (ninguna red oculta tenía clientes transmitiendo en esta ventana)")
        print()

    print("CANDIDATOS A CÁMARA en todas las redes (ordenados por tráfico):")
    cands = [r for r in rows if r["reasons"] or r["hidden"]]
    if cands:
        for r in cands:
            tag = "🔒oculta" if r["hidden"] else r["net"]
            print(f"  📷? [{tag}]  {fmt(r)}")
    else:
        print("  Ningún candidato claro en esta ventana (prueba --passes 4 --secs 2, o acerca la antena).")

    if args.all_clients:
        print("\nTodos los clientes vistos:")
        for r in rows:
            tag = "🔒oculta" if r["hidden"] else r["net"]
            print(f"  [{tag}]  {fmt(r)}")
    print("=" * 78)


def _ap_channel(bssid):
    cl = CLIENTS.get(bssid, {})
    if cl:
        return next(iter(cl.values())).get("ch", "?")
    return "?"


if __name__ == "__main__":
    main()
