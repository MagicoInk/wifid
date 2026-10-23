#!/usr/bin/env python3
"""
Minimal read-only client for the Kismet REST API (stdlib only, HTTP Basic auth).

Kismet does the heavy 802.11 capture; this client just pulls its device list so the
GUI can show the rich data (type, manufacturer, associated clients, signal, bytes,
first/last seen) and feed targets into the de-auth engine.

Field names follow the documented Kismet REST schema and are read defensively, so a
missing field never crashes the UI.
"""

import os
import json
import base64
import urllib.request
import urllib.parse
import urllib.error

DEFAULT_URL = "http://localhost:2501"

# candidate locations for the httpd credentials (root first: `sudo kismet` uses /root)
_CONF_PATHS = [
    os.path.expanduser("~/.kismet/kismet_httpd.conf"),
    "/root/.kismet/kismet_httpd.conf",
    "/home/kali/.kismet/kismet_httpd.conf",
]

# summary fields requested per device; [path, alias] flattens a nested value under `alias`
_FIELDS = [
    "kismet.device.base.key",
    "kismet.device.base.macaddr",
    "kismet.device.base.type",
    "kismet.device.base.manuf",
    "kismet.device.base.channel",
    "kismet.device.base.frequency",
    "kismet.device.base.first_time",
    "kismet.device.base.last_time",
    "kismet.device.base.packets.total",
    "kismet.device.base.datasize",
    ["kismet.device.base.commonname", "name"],
    ["kismet.device.base.signal/kismet.common.signal.last_signal", "signal_dbm"],
    ["dot11.device/dot11.device.last_bssid", "last_bssid"],
    ["dot11.device/dot11.device.associated_client_map", "assoc_clients"],
]


class KismetError(Exception):
    pass


class KismetClient:
    def __init__(self, url=DEFAULT_URL, username=None, password=None, timeout=8):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout

    # -- credentials ------------------------------------------------------
    @classmethod
    def from_config(cls, url=DEFAULT_URL, timeout=8):
        user, pwd = None, None
        for path in _CONF_PATHS:
            try:
                with open(path) as fh:
                    for line in fh:
                        line = line.strip()
                        if line.startswith("httpd_username="):
                            user = line.split("=", 1)[1].strip()
                        elif line.startswith("httpd_password="):
                            pwd = line.split("=", 1)[1].strip()
                if user and pwd:
                    break
            except Exception:
                continue
        return cls(url=url, username=user, password=pwd, timeout=timeout)

    def _auth_header(self):
        if not self.username:
            return None
        raw = f"{self.username}:{self.password or ''}".encode()
        return "Basic " + base64.b64encode(raw).decode()

    # -- raw request ------------------------------------------------------
    def _request(self, path, post_data=None):
        url = self.url + path
        headers = {}
        auth = self._auth_header()
        if auth:
            headers["Authorization"] = auth
        data = None
        if post_data is not None:
            body = "json=" + urllib.parse.quote(json.dumps(post_data))
            data = body.encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "ignore"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise KismetError("Autenticación rechazada (revisa usuario/contraseña de Kismet)")
            raise KismetError(f"HTTP {exc.code} en {path}")
        except urllib.error.URLError as exc:
            raise KismetError(f"No se pudo conectar a Kismet en {self.url} ({exc.reason})")
        except Exception as exc:
            raise KismetError(str(exc))

    # -- endpoints --------------------------------------------------------
    def status(self):
        return self._request("/system/status.json")

    def datasources(self):
        return self._request("/datasource/all_sources.json")

    def devices(self, since_ts=0):
        """Devices active since `since_ts` (epoch). 0 = all. Returns normalized dicts."""
        path = f"/devices/views/all/last-time/{int(since_ts)}/devices.json"
        raw = self._request(path, post_data={"fields": _FIELDS})
        if not isinstance(raw, list):
            return []
        return [normalize(d) for d in raw]


def band_from_freq(freq_khz):
    try:
        f = int(freq_khz)
    except (TypeError, ValueError):
        return "—"
    if f >= 4900000:
        return "5 GHz"
    if f >= 2400000:
        return "2.4 GHz"
    if f > 0:
        return f"{f // 1000} MHz"
    return "—"


def normalize(dev):
    g = dev.get
    return {
        "key": g("kismet.device.base.key"),
        "mac": g("kismet.device.base.macaddr") or "",
        "name": dev.get("name") or "",
        "type": g("kismet.device.base.type") or "",
        "manuf": g("kismet.device.base.manuf") or "",
        "channel": str(g("kismet.device.base.channel") or ""),
        "band": band_from_freq(g("kismet.device.base.frequency")),
        "signal": dev.get("signal_dbm"),
        "first": g("kismet.device.base.first_time"),
        "last": g("kismet.device.base.last_time"),
        "packets": g("kismet.device.base.packets.total") or 0,
        "datasize": g("kismet.device.base.datasize") or 0,
        "bssid": dev.get("last_bssid") or "",
        "clients": dev.get("assoc_clients") or {},
    }
