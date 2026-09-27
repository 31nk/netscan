"""The remembered device list, scan history, risky ports, device-type guesses and spoofing checks."""

import contextlib
import datetime
import json
import os
import re

from PySide6.QtCore import (
    QStandardPaths,
)

from .discovery import SERVICE_TYPE_HINTS
from .scanning import ip_sort_key, merge_ports, port_label
from .system import neighbour_macs, now_iso


def data_dir():
    base = (QStandardPaths.writableLocation(QStandardPaths.AppDataLocation)
            or os.path.expanduser("~/.local/share/netscan"))
    os.makedirs(base, exist_ok=True)
    return base


def devices_file():
    return os.path.join(data_dir(), "devices.json")


def history_dir():
    path = os.path.join(data_dir(), "history")
    os.makedirs(path, exist_ok=True)
    return path


HISTORY_KEEP = 30


def save_history(record, path=None):
    """Write a scan record to the history folder (or overwrite path); keep the newest HISTORY_KEEP."""
    folder = history_dir()
    if path is None:
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(folder, f"scan_{stamp}.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=1)
        for old in sorted(n for n in os.listdir(folder) if n.startswith("scan_"))[:-HISTORY_KEEP]:
            os.remove(os.path.join(folder, old))
    except OSError:
        return None
    return path


def list_history():
    """[(path, record summary dict)] newest first."""
    folder = history_dir()
    out = []
    for name in sorted((n for n in os.listdir(folder) if n.startswith("scan_") and n.endswith(".json")),
                       reverse=True):
        path = os.path.join(folder, name)
        try:
            with open(path, encoding="utf-8") as f:
                rec = json.load(f)
            out.append((path, {"saved": rec.get("saved", ""), "target": rec.get("target", ""),
                               "hosts": len(rec.get("hosts", []))}))
        except (OSError, ValueError, AttributeError):
            continue
    return out


def hour_bucket(when=None):
    return (when or datetime.datetime.now()).strftime("%Y-%m-%dT%H")


HOURS_KEEP_DAYS = 30

# ---- risky ports -------------------------------------------------------------

# (port, proto) -> why it's worth a look. Open doesn't mean compromised; these are
# services that are often unencrypted, frequently attacked, or unsafe without a password.
RISKY_PORTS = {
    (21, "tcp"): "FTP: passwords and files travel unencrypted",
    (23, "tcp"): "Telnet: unencrypted remote login, a favourite of IoT malware",
    (69, "udp"): "TFTP: file transfer with no authentication",
    (135, "tcp"): "Windows RPC: often targeted, rarely needs to be reachable",
    (139, "tcp"): "NetBIOS file sharing: old and frequently attacked",
    (445, "tcp"): "SMB file sharing: a common ransomware and worm target",
    (161, "udp"): "SNMP: often uses default 'public' community strings",
    (512, "tcp"): "rexec: legacy remote execution without encryption",
    (513, "tcp"): "rlogin: legacy unencrypted remote login",
    (514, "tcp"): "rsh: legacy unencrypted remote shell",
    (1433, "tcp"): "Microsoft SQL Server: databases shouldn't be widely reachable",
    (1900, "udp"): "UPnP: lets devices open router ports on their own",
    (2375, "tcp"): "Docker API without TLS: gives full control of the host",
    (3306, "tcp"): "MySQL: databases shouldn't be widely reachable",
    (3389, "tcp"): "Remote Desktop: heavily brute-forced; keep it off untrusted networks",
    (5432, "tcp"): "PostgreSQL: databases shouldn't be widely reachable",
    (5900, "tcp"): "VNC remote desktop: often weak or no password",
    (5901, "tcp"): "VNC remote desktop: often weak or no password",
    (6379, "tcp"): "Redis: often runs with no password",
    (9200, "tcp"): "Elasticsearch: often runs with no password",
    (11211, "tcp"): "Memcached: no authentication by default",
    (27017, "tcp"): "MongoDB: often runs with no password",
}


def port_risk(p):
    if p.get("local_only") or p.get("temporary"):
        return ""  # nothing on the network can reach it
    return RISKY_PORTS.get((p["port"], p["proto"]), "")


def risky(ports):
    return [p for p in ports or [] if port_risk(p)]


def label_risky(label):
    """Same check for a stored port label like '23/telnet' or '161/snmp (udp)'."""
    m = re.match(r"(\d+)", label)
    return bool(m) and (int(m.group(1)), "udp" if "(udp)" in label else "tcp") in RISKY_PORTS


# ---- device types ------------------------------------------------------------

DEVICE_TYPES = {
    "router": "Router", "computer": "Computer", "phone": "Phone / tablet", "printer": "Printer",
    "media": "TV / media", "nas": "NAS / server", "pi": "Raspberry Pi", "iot": "Smart home / IoT",
    "unknown": "Unknown",
}
_TYPE_VENDORS = [
    ("pi", ("raspberry pi",)),
    ("printer", ("brother", "canon", "epson", "lexmark", "kyocera", "xerox", "ricoh")),
    ("nas", ("synology", "qnap", "western digital", "buffalo", "asustor", "drobo")),
    ("media", ("roku", "sonos", "nvidia", "vizio", "tcl", "hisense", "bose")),
    ("iot", ("espressif", "tuya", "shelly", "philips lighting", "signify", "ecobee", "nest labs",
             "general electric", "wemo", "belkin", "ring ", "wyze", "tp-link smart", "lifx", "amazon")),
    ("router", ("zyxel", "netgear", "ubiquiti", "mikrotik", "arris", "technicolor", "sagemcom",
                "linksys", "eero", "juniper", "cisco", "tp-link", "d-link", "draytek", "fritz", "avm")),
    ("computer", ("intel", "dell", "lenovo", "hewlett", "micro-star", "gigabyte", "asrock",
                  "realtek", "microsoft", "framework", "asustek", "apple")),
]
_TYPE_HOSTNAMES = [
    ("phone", ("iphone", "ipad", "android", "pixel", "galaxy", "oneplus", "phone")),
    ("media", ("tv", "chromecast", "roku", "appletv", "apple-tv", "firetv", "shield", "sonos")),
    ("printer", ("printer", "brn", "epson", "canon")),
    ("nas", ("nas", "diskstation", "synology", "qnap", "server")),
    ("pi", ("raspberrypi", "pihole", "pi-hole")),
    ("computer", ("desktop", "laptop", "macbook", "imac", "-pc", "pc-", "workstation")),
]


def guess_type(host, ports=None, gateway=None):
    """Best guess at what kind of device this is, from what a scan can see."""
    vendor = (host.get("vendor") or "").lower()
    name = (host.get("hostname") or "").lower()
    os_name = (host.get("os") or "").lower()
    open_tcp = {p["port"] for p in ports or [] if p["proto"] == "tcp"}
    if gateway and host.get("ip") == gateway or name in ("_gateway", "router", "gateway"):
        return "router"
    if vendor == "(this computer)":
        return "computer"
    if open_tcp & {631, 9100, 515}:
        return "printer"
    if open_tcp & {62078} or any(w in os_name for w in ("ios", "android")):
        return "phone"
    if open_tcp & {8008, 8009, 8060, 1400, 7000}:
        return "media"
    for kind, words in _TYPE_HOSTNAMES:
        if any(w in name for w in words):
            return kind
    # What the device announces about itself beats guessing from its network card's maker.
    hints = [SERVICE_TYPE_HINTS.get(t) for t in host.get("svc_types") or []]
    for kind in ("printer", "media", "iot", "nas", "phone"):
        if kind in hints:
            return kind
    upnp_type = (host.get("upnp_type") or "").lower()
    for word, kind in (("internetgatewaydevice", "router"), ("mediarenderer", "media"), ("printer", "printer")):
        if word in upnp_type:
            return kind
    model = f'{host.get("model") or ""} {host.get("friendly") or ""}'.lower()
    for words, kind in ((("iphone", "ipad", "pixel", "galaxy"), "phone"),
                        (("macbook", "imac", "mac mini", "thinkpad"), "computer"),
                        (("tv", "chromecast", "shield", "roku", "sonos"), "media"),
                        (("printer", "laserjet", "officejet", "deskjet"), "printer")):
        if any(w in model for w in words):
            return kind
    if open_tcp & {5000, 5001} and open_tcp & {139, 445}:
        return "nas"
    for kind, words in _TYPE_VENDORS:
        if any(w in vendor for w in words):
            return kind
    if "computer" in hints:
        return "computer"
    if vendor.startswith("(private"):
        return "phone"  # phones and tablets are what randomise their MAC per network
    if any(w in os_name for w in ("windows", "mac os", "macos", "linux")) or open_tcp & {22, 3389, 5900}:
        return "computer"
    return "unknown"


class DeviceStore:
    """Every device NetScan has seen, keyed by MAC ("ip:<addr>" for nicknames of MAC-less hosts).

    Per device: nickname, notes, trusted flag, type override, IPs used, hours seen online,
    last known open ports and a log of port changes. Also the hours when NetScan checked the
    network at all, so the online history can tell "offline" from "not checked".
    """

    def __init__(self, path):
        self.path = path
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            self.devices = data.get("devices", {})
            self.checked_hours = data.get("checked_hours", [])
            self.gateways = data.get("gateways", {})
        except (OSError, ValueError, AttributeError):
            self.devices = {}
            self.checked_hours = []
            self.gateways = {}
        self._any_trusted = None
        self._deferred = 0
        self._dirty = False

    @contextlib.contextmanager
    def batch(self):
        """Group many updates into a single write (per-host saves are O(n^2) on big networks)."""
        self._deferred += 1
        try:
            yield
        finally:
            self._deferred -= 1
            if not self._deferred and self._dirty:
                self.save()

    @staticmethod
    def key(host):
        return host.get("mac") or f"ip:{host['ip']}"

    def get(self, host):
        return self.devices.get(self.key(host), {})

    def nickname(self, host):
        return self.get(host).get("nickname", "")

    def set_field(self, host, field, value):
        """Set (or clear, when value is falsy) a user field such as nickname, notes, trusted, type."""
        rec = self.devices.setdefault(self.key(host), {"first_seen": now_iso()})
        rec.update({k: host[k] for k in ("ip", "mac") if host.get(k)})
        if value:
            rec[field] = value
        else:
            rec.pop(field, None)
        self.save()

    def set_nickname(self, host, name):
        self.set_field(host, "nickname", name)

    def forget(self, key):
        if self.devices.pop(key, None) is not None:
            self.save()

    def known_macs(self):
        return {k for k, d in self.devices.items() if d.get("mac")}

    def any_trusted(self):
        # Asked once per table row, so cache it; save() runs after every change and refreshes it.
        if self._any_trusted is None:
            self._any_trusted = any(d.get("trusted") for d in self.devices.values())
        return self._any_trusted

    def record(self, hosts, checked=True):
        """Remember hosts that have a MAC; return the MACs never seen before.

        checked: this was a sweep of the local network, so count the hour as checked.
        """
        now = datetime.datetime.now()
        stamp, hour = now.isoformat(timespec="seconds"), hour_bucket(now)
        cutoff = hour_bucket(now - datetime.timedelta(days=HOURS_KEEP_DAYS))
        new = []
        for h in hosts:
            if not h.get("mac"):
                continue
            if h["mac"] not in self.devices:
                new.append(h["mac"])
            rec = self.devices.setdefault(h["mac"], {"first_seen": stamp})
            rec.update({k: h[k] for k in ("ip", "mac", "hostname", "vendor", "os") if h.get(k)})
            rec["last_seen"] = stamp
            ips = [ip for ip in rec.get("ips", []) if ip != h["ip"]] + [h["ip"]]
            rec["ips"] = ips[-10:]
            hours = rec.setdefault("hours", [])
            if not hours or hours[-1] != hour:
                hours.append(hour)
            rec["hours"] = [x for x in hours if x >= cutoff]
        if checked:
            if not self.checked_hours or self.checked_hours[-1] != hour:
                self.checked_hours.append(hour)
            self.checked_hours = [x for x in self.checked_hours if x >= cutoff]
        self.save()
        return new

    def update_ports(self, mac, ports, scanned):
        """Merge a port scan into a device's known open ports and log what changed.

        scanned is {"tcp": set, "udp": set}; only those ports are compared. The first scan of a
        device just sets a baseline. Returns (opened, closed) as lists of port dicts.
        """
        rec = self.devices.get(mac)
        if rec is None:
            return [], []
        ports = [p for p in ports if p["port"] in scanned.get(p["proto"], set())]
        old = rec.get("ports")
        merged = merge_ports(old, ports, scanned)
        opened = closed = []
        if old is not None:
            key = lambda p: (p["port"], p["proto"])
            before, after = {key(p) for p in old}, {key(p) for p in merged}
            opened = [p for p in merged if key(p) not in before]
            closed = [p for p in old if key(p) not in after]
            if opened or closed:
                log = rec.setdefault("port_changes", [])
                log.append({"time": now_iso(), "opened": [port_label(p) for p in opened],
                            "closed": [port_label(p) for p in closed]})
                rec["port_changes"] = log[-20:]
        rec["ports"] = merged
        self.save()
        return opened, closed

    def update(self, host, **fields):
        rec = self.devices.get(self.key(host))
        if rec is not None and any(rec.get(k) != v for k, v in fields.items()):
            rec.update(fields)
            self.save()

    def device_type(self, host, ports=None, gateway=None):
        """(type, guessed?) — the user's override if set, else a guess."""
        rec = self.get(host)
        if rec.get("type") in DEVICE_TYPES:
            return rec["type"], False
        merged = {**rec, **{k: v for k, v in host.items() if v}}
        return guess_type(merged, ports if ports is not None else rec.get("ports"), gateway), True

    USER_FIELDS = ("nickname", "notes", "trusted", "type", "ssh_user")

    def merge_from(self, devices):
        """Merge another NetScan's device list. New devices are added whole; for known ones, only
        your own fields (nickname, notes, trusted, type, SSH user) that are empty here are filled.
        Returns (added, updated)."""
        added = updated = 0
        with self.batch():
            for key, rec in devices.items():
                if not isinstance(rec, dict):
                    continue
                mine = self.devices.get(key)
                if mine is None:
                    self.devices[key] = dict(rec)
                    added += 1
                    continue
                changed = False
                for field in self.USER_FIELDS:
                    if rec.get(field) and not mine.get(field):
                        mine[field] = rec[field]
                        changed = True
                for field in ("first_seen",):  # keep the earliest sighting
                    if rec.get(field) and (not mine.get(field) or rec[field] < mine[field]):
                        mine[field] = rec[field]
                updated += changed
            self.save()
        return added, updated

    def wakeable(self):
        """Devices with a MAC, nicknamed ones first, then by name."""
        label = lambda d: (d.get("nickname") or d.get("hostname") or d.get("ip", "")).lower()
        return sorted((d for d in self.devices.values() if d.get("mac")),
                      key=lambda d: (not d.get("nickname"), label(d)))

    def save(self):
        self._any_trusted = None
        if self._deferred:
            self._dirty = True
            return
        self._dirty = False
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"netscan_devices": 1, "devices": self.devices,
                           "checked_hours": self.checked_hours, "gateways": self.gateways}, f, indent=1)
            os.replace(tmp, self.path)
        except OSError:
            pass


def spoof_check(store, net, hosts):
    """Signs of ARP spoofing on this network. hosts: {ip: mac}. Returns [(severity, text)].

    Remembers the router's MAC per network the first time; later a different MAC for the router,
    or the router's MAC showing up on another address, is what an attacker in the middle looks like.
    """
    gw = net.get("gateway")
    if not gw:
        return []
    warnings = []
    key = f"{net['network']}|{gw}"
    mac = hosts.get(gw) or neighbour_macs(net["iface"]).get(gw, "")
    known = store.gateways.get(key)
    if mac:
        if known is None:
            store.gateways[key] = {"mac": mac, "since": now_iso()}
            store.save()
        elif known["mac"] != mac:
            warnings.append(("high", f"The router ({gw}) now answers from hardware address {mac}, not "
                                     f"{known['mac']} as before. That's what ARP spoofing looks like (a device "
                                     "posing as the router to intercept traffic), unless the router was replaced. "
                                     "If it was, right-click the router → Accept this router."))
    by_mac = {}
    for ip, m in hosts.items():
        if m and ":" not in ip:
            by_mac.setdefault(m, []).append(ip)
    router_mac = (known or {}).get("mac") or mac
    for m, ips in by_mac.items():
        if len(ips) < 2:
            continue
        ips = sorted(ips, key=ip_sort_key)
        if m == router_mac:
            others = [ip for ip in ips if ip != gw]
            warnings.append(("high", f"{', '.join(others)} answers with the router's hardware address ({m}). A device "
                                     "claiming the router's identity is a strong sign of ARP spoofing."))
        else:
            warnings.append(("low", f"One device ({m}) answers for {', '.join(ips)}. Fine if it's a device with "
                                    "several addresses (servers, VMs, Docker); worth a look otherwise."))
    return warnings
