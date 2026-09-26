#!/usr/bin/env python3
"""NetScan: a small Qt front end for nmap host discovery and port scanning.

Auto-detects the LAN subnet from the default route, runs nmap, and lists every
live host with its IP, hostname, MAC address, NIC vendor and open ports.
Results stream in while nmap runs. Scans can be saved as JSON and compared
against a later scan to spot new hosts, missing hosts and port changes.

Root (via pkexec on Linux, sudo with a password dialog on macOS, Npcap on
Windows) gives better discovery, SYN scans and UDP; unprivileged scans fall
back to the kernel neighbour/ARP table for MACs.

Runs on Linux, macOS (nmap from Homebrew) and Windows (nmap + Npcap).
Run with --self-test to check the setup without opening the window.
"""

import base64
import contextlib
import codecs
import csv
import datetime
import getpass
import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET

from PySide6.QtCore import (
    QObject, QProcess, QProcessEnvironment, QSettings, QStandardPaths, Qt, QTimer, QUrl,
    Signal,
)
from PySide6.QtGui import (
    QAction, QActionGroup, QColor, QDesktopServices, QFont, QFontDatabase, QGuiApplication,
    QIcon, QKeySequence, QPainter, QPalette,
)
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog, QFrame,
    QGridLayout, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow, QMenu,
    QMessageBox, QPlainTextEdit, QScrollArea, QStackedWidget, QSystemTrayIcon, QTabBar,
    QProgressBar, QPushButton, QSplitter, QStyleFactory, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

COLUMNS = ["IP Address", "Name", "Hostname", "MAC Address", "Vendor", "OS", "Open Ports", "Change"]
COL_IP, COL_NAME, COL_HOST, COL_MAC, COL_VENDOR, COL_OS, COL_PORTS, COL_CHANGE = range(8)
PORT_COLUMNS = ["Port", "Proto", "Service", "Version", "Note"]
# Devices tab: everything NetScan remembers. The first column is the online dot.
DEV_COLUMNS = ["", "Name", "Type", "Last seen", "Trusted", "Last IP", "Hostname", "MAC Address", "Vendor"]
DEV_STATUS, DEV_NAME, DEV_TYPE, DEV_SEEN, DEV_TRUST, DEV_IP, DEV_HOST, DEV_MAC, DEV_VENDOR = range(9)
# Background watch: (label, minutes between checks; 0 = off).
WATCH_INTERVALS = [("Off", 0), ("Every minute", 1), ("Every 5 minutes", 5),
                   ("Every 15 minutes", 15), ("Every 30 minutes", 30), ("Every hour", 60)]

# Port profiles for the Scan Ports button: (label, TCP top-N count, or None).
PORT_PROFILES = [
    ("Top 100 TCP ports", 100),
    ("Top 1000 TCP ports", 1000),
    ("All 65535 TCP ports (slow)", 65535),
    ("Custom ports…", None),
]
CUSTOM_PROFILE = len(PORT_PROFILES) - 1
# Common UDP services worth checking at work: DNS, DHCP, TFTP, NTP, NetBIOS,
# SNMP, IKE, syslog, SSDP/UPnP, mDNS.
UDP_PORTS = "53,67,69,123,137,161,500,514,1900,5353"
# Tighter timing for targets on a directly attached LAN, where replies take
# milliseconds. Cuts "Find Hosts" with top-100 ports from ~5s to ~2s on a /24
# with identical results; not used for typed/remote targets, where it could miss hosts.
# Not used for Scan Ports either: on big port ranges it gave up on slow replies and
# missed real open ports (full scan of a router: 2 of 3 found), for only ~15% speed.
LAN_FAST = ["--max-rtt-timeout", "200ms", "--max-retries", "1", "--min-rate", "1000"]

WEB_PORTS = [(443, "https"), (8443, "https"), (80, "http"), (8080, "http"),
             (8000, "http"), (3000, "http")]


IS_MAC = sys.platform == "darwin"
IS_WIN = sys.platform == "win32"
# GUI apps on macOS don't get Homebrew's bin directory on PATH, and on Windows
# PATH may not include nmap until the next login after installing it.
if IS_MAC:
    EXTRA_BIN_DIRS = ["/opt/homebrew/bin", "/usr/local/bin"]
elif IS_WIN:
    EXTRA_BIN_DIRS = [r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap"]
else:
    EXTRA_BIN_DIRS = []
EXE = ".exe" if IS_WIN else ""
# Keep helper processes (PowerShell) from flashing a console window on Windows.
NO_WINDOW = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WIN else {}


def find_program(name):
    return shutil.which(name) or next(
        (p for d in EXTRA_BIN_DIRS if os.access(p := os.path.join(d, name + EXE), os.X_OK)), None)


def npcap_installed():
    """Npcap is what lets nmap on Windows send raw packets (SYN/UDP scans, ARP discovery)."""
    system = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    return IS_WIN and os.path.exists(os.path.join(system, "Npcap", "wpcap.dll"))


def nmap_data_file(name):
    """Path to one of nmap's data files (Linux package or Homebrew install)."""
    candidates = []
    nmap = find_program("nmap")
    if nmap:
        bindir = os.path.dirname(os.path.realpath(nmap))
        candidates.append(os.path.join(bindir, name))  # Windows keeps them next to nmap.exe
        candidates.append(os.path.join(os.path.dirname(bindir), "share", "nmap", name))
    candidates += [os.path.join(d, name) for d in
                   ("/usr/share/nmap", "/opt/homebrew/share/nmap", "/usr/local/share/nmap")]
    return next((c for c in candidates if os.path.exists(c)), candidates[-1])


def run_text(*argv):
    try:
        return subprocess.run(argv, capture_output=True, text=True, **NO_WINDOW).stdout
    except OSError:
        return ""


def powershell_json(script):
    """Run a PowerShell snippet that ends in ConvertTo-Json and return the parsed result."""
    # -EncodedCommand (UTF-16LE base64) sidesteps Windows command-line quoting entirely.
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    out = run_text("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
    try:
        return json.loads(out) if out.strip() else None
    except json.JSONDecodeError:
        return None


def as_list(value):
    """PowerShell's ConvertTo-Json turns one-item lists into a bare object."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def ip_json(*args):
    out = subprocess.run(["ip", "-j", *args], capture_output=True, text=True)
    try:
        return json.loads(out.stdout or "[]")
    except json.JSONDecodeError:
        return []


def detect_networks():
    """Return scannable IPv4 networks, best (lowest-metric default route) first.

    Each entry: dict(iface, network, local_ip, gateway, mac).
    Point-to-point/VPN addresses (/32) are skipped since there is nothing to scan.
    """
    if IS_MAC:
        return detect_networks_mac()
    if IS_WIN:
        return detect_networks_win()
    routes = sorted(ip_json("-4", "route", "show", "default"),
                    key=lambda r: r.get("metric", 0))
    gateways = {}
    order = []
    for r in routes:
        dev = r.get("dev")
        if dev and dev not in gateways:
            gateways[dev] = r.get("gateway")
            order.append(dev)

    links = {l["ifname"]: l.get("address") for l in ip_json("link", "show")}
    nets = []
    for entry in ip_json("-4", "addr", "show", "scope", "global"):
        dev = entry["ifname"]
        for a in entry.get("addr_info", []):
            if a.get("family") != "inet" or a.get("prefixlen", 32) >= 31:
                continue
            iface = ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}")
            nets.append({
                "iface": dev,
                "network": iface.network,
                "local_ip": a["local"],
                "gateway": gateways.get(dev),
                "mac": (links.get(dev) or "").upper(),
            })
    rank = {dev: i for i, dev in enumerate(order)}
    nets.sort(key=lambda n: rank.get(n["iface"], len(rank)))
    return nets


def detect_networks_mac(netstat_out=None, ifconfig_out=None):
    """macOS version of detect_networks, from `netstat -rn` and `ifconfig`."""
    if netstat_out is None:
        netstat_out = run_text("/usr/sbin/netstat", "-rn", "-f", "inet")
    if ifconfig_out is None:
        ifconfig_out = run_text("/sbin/ifconfig")
    # Default routes are listed in priority order: default <gateway> <flags> <iface>
    gateways = {}
    order = []
    for line in netstat_out.splitlines():
        f = line.split()
        if len(f) >= 4 and f[0] == "default" and f[3] not in gateways:
            gw = f[1] if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", f[1]) else None
            gateways[f[3]] = gw
            order.append(f[3])

    nets = []
    dev = mac = None
    addrs = []

    def flush():
        for ip, prefix in addrs:
            iface = ipaddress.ip_interface(f"{ip}/{prefix}")
            if prefix >= 31 or iface.ip.is_loopback or iface.ip.is_link_local:
                continue
            nets.append({"iface": dev, "network": iface.network, "local_ip": ip,
                         "gateway": gateways.get(dev), "mac": (mac or "").upper()})

    for line in ifconfig_out.splitlines():
        if line and not line[0].isspace():
            flush()
            dev, mac, addrs = line.split(":", 1)[0], None, []
        elif (m := re.match(r"\s+ether ([0-9a-f:]+)", line)):
            mac = normalize_mac(m.group(1))
        elif (m := re.match(r"\s+inet (\S+) .*netmask 0x([0-9a-f]{8})", line)):
            addrs.append((m.group(1), bin(int(m.group(2), 16)).count("1")))
    flush()
    rank = {d: i for i, d in enumerate(order)}
    nets.sort(key=lambda n: rank.get(n["iface"], len(rank)))
    return nets


WIN_NETWORK_PS = """
$ErrorActionPreference = 'SilentlyContinue'
@{
  routes   = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
               Select-Object ifIndex, NextHop, RouteMetric)
  metrics  = @(Get-NetIPInterface -AddressFamily IPv4 | Select-Object ifIndex, InterfaceMetric)
  addrs    = @(Get-NetIPAddress -AddressFamily IPv4 |
               Select-Object InterfaceIndex, InterfaceAlias, IPAddress, PrefixLength)
  adapters = @(Get-NetAdapter | Select-Object ifIndex, MacAddress)
} | ConvertTo-Json -Depth 3 -Compress
"""


def detect_networks_win(info=None):
    """Windows version of detect_networks, from the NetTCPIP PowerShell cmdlets."""
    if info is None:
        info = powershell_json(WIN_NETWORK_PS) or {}
    metric = {m["ifIndex"]: m.get("InterfaceMetric") or 0 for m in as_list(info.get("metrics"))}
    gateways = {}
    cost = {}
    for r in as_list(info.get("routes")):
        idx = r["ifIndex"]
        c = (r.get("RouteMetric") or 0) + metric.get(idx, 0)
        if idx not in cost or c < cost[idx]:
            cost[idx] = c
            hop = r.get("NextHop")
            gateways[idx] = hop if hop and hop != "0.0.0.0" else None
    macs = {a["ifIndex"]: (a.get("MacAddress") or "").replace("-", ":").upper()
            for a in as_list(info.get("adapters"))}
    nets = []
    for a in as_list(info.get("addrs")):
        idx, prefix = a["InterfaceIndex"], a.get("PrefixLength", 32)
        try:
            iface = ipaddress.ip_interface(f"{a['IPAddress']}/{prefix}")
        except ValueError:
            continue
        if prefix >= 31 or iface.ip.is_loopback or iface.ip.is_link_local:
            continue
        nets.append({"iface": a["InterfaceAlias"], "ifindex": idx, "network": iface.network,
                     "local_ip": a["IPAddress"], "gateway": gateways.get(idx),
                     "mac": macs.get(idx, "")})
    nets.sort(key=lambda n: cost.get(n["ifindex"], float("inf")))
    return nets


def normalize_mac(mac):
    """macOS drops leading zeros (0:1b:2:...); pad every octet to two digits."""
    return ":".join(part.zfill(2) for part in mac.split(":")).upper()


def win_neighbour_macs(entries):
    """Parse Get-NetNeighbor rows, skipping unresolved and broadcast/multicast entries."""
    macs = {}
    for n in as_list(entries):
        mac = (n.get("LinkLayerAddress") or "").replace("-", ":").upper()
        if (mac and mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF")
                and n.get("State") not in ("Unreachable", "Incomplete")):
            macs[n["IPAddress"]] = mac
    return macs


def neighbour_macs(iface):
    if IS_MAC:
        return arp_macs(run_text("/usr/sbin/arp", "-an", "-i", iface))
    if IS_WIN:
        alias = iface.replace("'", "''")
        return win_neighbour_macs(powershell_json(
            f"Get-NetNeighbor -AddressFamily IPv4 -InterfaceAlias '{alias}' | "
            "Select-Object IPAddress, LinkLayerAddress, @{n='State';e={\"$($_.State)\"}} | "
            "ConvertTo-Json -Compress"))
    macs = {}
    for n in ip_json("-4", "neigh", "show", "dev", iface):
        if n.get("lladdr") and "FAILED" not in n.get("state", []):
            macs[n["dst"]] = n["lladdr"].upper()
    return macs


def arp_macs(arp_out):
    """Parse macOS `arp -an`: ? (192.168.1.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]"""
    macs = {}
    for m in re.finditer(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5}) ",
                         arp_out):
        macs[m.group(1)] = normalize_mac(m.group(2))
    return macs


# ---- this computer's own open ports ---------------------------------------
# A network scan only probes a list of common ports and can't see ports bound to
# localhost, so for the machine NetScan runs on we ask the OS for its listening
# sockets instead: complete, instant, no root, and it names the program.

def _listener(proto, address, port, process="", pid=None):
    return {"proto": proto, "address": address.strip("[]").split("%")[0], "port": int(port),
            "process": process, "pid": pid}


def parse_ss(out):
    """Linux `ss -tulnpH`: 'tcp LISTEN 0 128 0.0.0.0:27036 0.0.0.0:* users:(("steam",pid=1,fd=2))'"""
    found = []
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5 or f[0] not in ("tcp", "udp") or (f[0] == "tcp" and f[1] != "LISTEN"):
            continue
        address, _, port = f[4].rpartition(":")
        if port.isdigit():
            m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            found.append(_listener(f[0], address, port, m.group(1) if m else "",
                                   int(m.group(2)) if m else None))
    return found


def parse_lsof(out):
    """macOS `lsof -nP -iTCP -sTCP:LISTEN -iUDP -F cPn` (field output: c=command, P=proto, n=name)."""
    found, command, proto, pid = [], "", "", None
    for line in out.splitlines():
        tag, value = line[:1], line[1:]
        if tag == "p" and value.isdigit():
            pid = int(value)
        elif tag == "c":
            command = value
        elif tag == "P":
            proto = value.lower()
        elif tag == "n" and proto in ("tcp", "udp") and "->" not in value:
            address, _, port = value.rpartition(":")
            if port.isdigit():
                found.append(_listener(proto, address, port, command, pid))
    return found


def parse_netstat_mac(out):
    """macOS `netstat -an`: 'tcp4 0 0 *.27036 *.* LISTEN' / 'udp4 0 0 *.5353 *.*' (no program names)."""
    found = []
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5 or not f[0].startswith(("tcp", "udp")):
            continue
        if f[0].startswith("tcp") and "LISTEN" not in f:
            continue
        if f[0].startswith("udp") and f[4] != "*.*":
            continue  # connected UDP socket, not a listener
        address, _, port = f[3].rpartition(".")
        if port.isdigit():
            found.append(_listener(f[0][:3], address, port))
    return found


WIN_LISTENERS_PS = """
$ErrorActionPreference = 'SilentlyContinue'
$names = @{}; Get-Process | ForEach-Object { $names[$_.Id] = $_.ProcessName }
@(Get-NetTCPConnection -State Listen | ForEach-Object {
    @{ proto = 'tcp'; address = "$($_.LocalAddress)"; port = $_.LocalPort; pid = [int]$_.OwningProcess
       process = $names[[int]$_.OwningProcess] } }) +
@(Get-NetUDPEndpoint | ForEach-Object {
    @{ proto = 'udp'; address = "$($_.LocalAddress)"; port = $_.LocalPort; pid = [int]$_.OwningProcess
       process = $names[[int]$_.OwningProcess] } }) |
    ConvertTo-Json -Compress
"""


def local_listeners():
    """Every listening TCP socket and bound UDP socket on this machine."""
    if IS_WIN:
        return [_listener(l.get("proto", "tcp"), l.get("address") or "", l.get("port", 0), l.get("process") or "",
                          l.get("pid")) for l in as_list(powershell_json(WIN_LISTENERS_PS)) if l.get("port")]
    if IS_MAC:
        # lsof names the program but only sees our own processes; netstat sees system services too.
        return (parse_lsof(run_text("/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP", "-F", "cPn"))
                + parse_netstat_mac(run_text("/usr/sbin/netstat", "-an", "-p", "tcp"))
                + parse_netstat_mac(run_text("/usr/sbin/netstat", "-an", "-p", "udp")))
    return parse_ss(run_text("ss", "-tulnpH"))


def is_loopback(address):
    return address.startswith("127.") or address in ("::1", "localhost")


def local_open_ports(listeners):
    """Merge raw listeners into port dicts like parse_ports(), plus 'local_only' and 'program'.

    A port is local-only when every socket on it is bound to loopback, so nothing on the
    network can reach it. A 'temporary' UDP socket is a high, unregistered port: almost always
    an app's socket for its own outgoing traffic (DNS lookups, calls), not a service.
    NetScan's own sockets (name lookups) are left out.
    """
    merged = {}
    for l in listeners:
        if l.get("pid") == os.getpid():
            continue
        m = merged.setdefault((l["proto"], l["port"]), {"programs": [], "exposed": False})
        m["exposed"] = m["exposed"] or not is_loopback(l["address"])
        if l["process"] and l["process"] not in m["programs"]:
            m["programs"].append(l["process"])
    ports = []
    for (proto, port), m in sorted(merged.items()):
        try:
            known = socket.getservbyport(port, proto)
        except (OSError, OverflowError):
            known = ""
        program = ", ".join(m["programs"])
        ports.append({"port": port, "proto": proto, "service": m["programs"][0] if m["programs"] else known,
                      "version": f"programs: {program}" if len(m["programs"]) > 1 else "", "program": program,
                      "local_only": not m["exposed"],
                      "temporary": proto == "udp" and port >= EPHEMERAL_START and not known})
    # listening ports first, temporary sockets at the end
    return sorted(ports, key=lambda p: (p["temporary"], p["proto"], p["port"]))


EPHEMERAL_START = 32768  # start of the OS's range for temporary ports (Linux; Windows/macOS use 49152)


def this_os_name():
    try:
        if IS_MAC:
            return f"macOS {platform.mac_ver()[0]}"
        if IS_WIN:
            return f"Windows {platform.release()}"
        return platform.freedesktop_os_release().get("PRETTY_NAME", "Linux")
    except (OSError, AttributeError):
        return platform.system()


_VENDORS = None


def mac_vendor(mac):
    """Look up a MAC's vendor in nmap's own OUI database (works without root)."""
    global _VENDORS
    if not mac:
        return ""
    if int(mac[:2], 16) & 0x02:
        return "(private/randomised MAC)"
    if _VENDORS is None:
        _VENDORS = {}
        try:
            with open(nmap_data_file("nmap-mac-prefixes"), errors="replace") as f:
                for line in f:
                    if line and line[0] != "#":
                        prefix, _, name = line.rstrip("\n").partition(" ")
                        _VENDORS[prefix.upper()] = name
        except OSError:
            pass
    hexmac = mac.replace(":", "").upper()
    # The file mixes 24-, 28- and 36-bit prefixes; prefer the longest match.
    for n in (9, 7, 6):
        if hexmac[:n] in _VENDORS:
            return _VENDORS[hexmac[:n]]
    return ""


_TOP_TCP = None


def top_tcp_ports(n):
    """The n most common TCP ports, ranked by nmap-services frequency (as --top-ports does)."""
    global _TOP_TCP
    if n >= 65535:
        return "1-65535"
    if _TOP_TCP is None:
        ranked = []
        try:
            with open(nmap_data_file("nmap-services"), errors="replace") as f:
                for line in f:
                    fields = line.split()
                    if len(fields) < 3 or line[0] == "#" or not fields[1].endswith("/tcp"):
                        continue
                    ranked.append((float(fields[2]), int(fields[1].split("/")[0])))
        except (OSError, ValueError):
            pass
        ranked.sort(reverse=True)
        _TOP_TCP = [port for _, port in ranked]
    return ",".join(str(p) for p in sorted(_TOP_TCP[:n]))


def valid_port_list(text):
    """Validate a custom port list like '22,80,443,8000-8100'."""
    if not re.fullmatch(r"\d+(-\d+)?(,\d+(-\d+)?)*", text):
        return False
    return all(1 <= int(n) <= 65535 for n in re.findall(r"\d+", text))


def port_set(spec):
    """Expand '22,80,8000-8100' into a set of ints."""
    ports = set()
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        ports.update(range(int(lo), int(hi or lo) + 1))
    return ports


def merge_ports(old, new, scanned):
    """Replace results for scanned ports, keep earlier findings for the rest.

    scanned is {"tcp": set, "udp": set} of the ports this scan actually probed.
    """
    kept = [p for p in (old or []) if p["port"] not in scanned.get(p["proto"], set())]
    return sorted(kept + new, key=lambda x: (x["proto"], x["port"]))


def parse_host(elem):
    """Turn an nmap <host> element into a host dict, or None if it isn't up."""
    status = elem.find("status")
    if status is None or status.get("state") != "up":
        return None
    host = {"ip": "", "hostname": "", "mac": "", "vendor": ""}
    for addr in elem.findall("address"):
        if addr.get("addrtype") == "ipv4":
            host["ip"] = addr.get("addr", "")
        elif addr.get("addrtype") == "mac":
            host["mac"] = addr.get("addr", "").upper()
            host["vendor"] = addr.get("vendor", "")
    names = [hn.get("name") for hn in elem.findall("hostnames/hostname") if hn.get("name")]
    host["hostname"] = names[0] if names else ""
    return host if host["ip"] else None


def parse_ports(elem):
    """Open ports of an nmap <host> element, sorted by protocol then port."""
    ports = []
    for p in elem.findall("ports/port"):
        state = p.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = p.find("service")
        svc = svc.attrib if svc is not None else {}
        version = " ".join(v for v in (svc.get("product"), svc.get("version"),
                                       svc.get("extrainfo")) if v)
        ports.append({
            "port": int(p.get("portid")),
            "proto": p.get("protocol", "tcp"),
            "service": svc.get("name", ""),
            "version": version,
        })
    return sorted(ports, key=lambda x: (x["proto"], x["port"]))


def port_label(p):
    label = f"{p['port']}/{p['service']}" if p["service"] else str(p["port"])
    return label + (" (udp)" if p["proto"] == "udp" else "")


def summarize_ports(ports):
    if ports is None:
        return ""
    if not ports:
        return "none open"
    return ", ".join(port_label(p) for p in ports)


def _read_dns_name(buf, off):
    """Decode a (possibly compressed) DNS name starting at off."""
    labels, jumps = [], 0
    while off < len(buf) and jumps < 20:
        n = buf[off]
        if n == 0:
            break
        if n & 0xC0 == 0xC0:
            off = ((n & 0x3F) << 8) | buf[off + 1]
            jumps += 1
            continue
        labels.append(buf[off + 1:off + 1 + n].decode(errors="replace"))
        off += 1 + n
    return ".".join(labels)


def mdns_name(ip, timeout=1.0):
    """Ask the host itself for its name over unicast mDNS (PTR on in-addr.arpa)."""
    qname = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    q = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\0"
    packet = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + q + b"\x00\x0c\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(packet, (ip, 5353))
            buf, _ = s.recvfrom(4096)
        except OSError:
            return ""
    try:
        ancount = int.from_bytes(buf[6:8], "big")
        if not ancount:
            return ""
        off = 12
        for _ in range(int.from_bytes(buf[4:6], "big")):  # skip questions
            while buf[off] != 0 and buf[off] & 0xC0 != 0xC0:
                off += buf[off] + 1
            off += 2 if buf[off] & 0xC0 == 0xC0 else 1
            off += 4
        while buf[off] != 0 and buf[off] & 0xC0 != 0xC0:  # answer name
            off += buf[off] + 1
        off += 2 if buf[off] & 0xC0 == 0xC0 else 1
        if int.from_bytes(buf[off:off + 2], "big") != 12:  # not a PTR
            return ""
        return _read_dns_name(buf, off + 10).removesuffix(".local")
    except IndexError:
        return ""


def netbios_name(ip, timeout=1.0):
    """NetBIOS node-status query (Windows machines, Samba, many NAS boxes)."""
    name = b"\x20" + b"CK" + b"A" * 30 + b"\x00"  # encoded "*"
    packet = b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x21\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(packet, (ip, 137))
            buf, _ = s.recvfrom(4096)
        except OSError:
            return ""
    try:
        count, off = buf[56], 57
        for i in range(count):
            entry = buf[off + i * 18:off + i * 18 + 18]
            flags = int.from_bytes(entry[16:18], "big")
            if entry[15] == 0x00 and not flags & 0x8000:  # workstation, unique
                return entry[:15].decode(errors="replace").strip()
    except IndexError:
        pass
    return ""


def dns_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def lookup_name(ip):
    """Query mDNS, NetBIOS and DNS at once; return the first hit in that order, or ''.

    Each silent source costs a 1s timeout, so asking in parallel instead of
    one after another halves the wait for devices that don't answer.
    """
    results = {}
    threads = [threading.Thread(target=lambda fn=fn: results.__setitem__(fn, fn(ip)), daemon=True)
               for fn in (netbios_name, dns_name)]
    for t in threads:
        t.start()
    name = mdns_name(ip)
    for fn, t in zip((netbios_name, dns_name), threads):
        if name:
            break
        t.join()
        name = results.get(fn, "")
    return name


def compare_scans(baseline, hosts, ports):
    """Diff the current scan against a saved one.

    Hosts are matched by MAC when both sides have one (DHCP may move IPs),
    otherwise by IP. Returns ({ip: change text}, [baseline hosts not seen now]).
    """
    by_mac = {h["mac"]: h for h in baseline if h.get("mac")}
    by_ip = {h["ip"]: h for h in baseline}
    matched = set()
    changes = {}
    for ip, h in hosts.items():
        old = by_mac.get(h["mac"]) if h["mac"] else None
        old = old or by_ip.get(ip)
        if old is None:
            changes[ip] = "NEW"
            continue
        matched.add(id(old))
        notes = []
        if old["ip"] != ip:
            notes.append(f"was {old['ip']}")
        cur_ports, old_ports = ports.get(ip), old.get("ports")
        if cur_ports is not None and old_ports is not None:
            key = lambda p: (p["port"], p["proto"])
            cur = {key(p): p for p in cur_ports}
            prev = {key(p): p for p in old_ports}
            notes += [f"+{port_label(cur[k])}" for k in sorted(cur.keys() - prev.keys())]
            notes += [f"−{port_label(prev[k])}" for k in sorted(prev.keys() - cur.keys())]
        changes[ip] = ", ".join(notes)
    gone = [h for h in baseline if id(h) not in matched]
    return changes, gone


# ---- device names from the router ---------------------------------------------
# Routers running dnsmasq (OpenWrt, OpenSync and many others) keep every DHCP client's
# name in a lease file. NetScan reads it over SSH with one read-only command.
ROUTER_LEASE_CMD = ("cat /tmp/dhcp.leases 2>/dev/null || cat /var/lib/misc/dnsmasq.leases 2>/dev/null"
                    " || cat /tmp/dnsmasq.leases 2>/dev/null")


def parse_dnsmasq_leases(text):
    """dnsmasq leases, '<expiry> <mac> <ip> <hostname|*> <client-id|*>' per line -> {MAC: (ip, name)}."""
    leases = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 4 and re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", f[1]):
            leases[f[1].upper()] = (f[2], "" if f[3] == "*" else f[3][:63])
    return leases


def askpass_helper():
    """Small launcher that ssh runs (SSH_ASKPASS) to ask for a password with NetScan's own dialog.

    The password goes straight from that separate process to ssh; the NetScan window never sees it.
    """
    script, exe = os.path.abspath(__file__), sys.executable
    if IS_WIN:
        path, body = os.path.join(data_dir(), "askpass.cmd"), f'@"{exe}" "{script}" --askpass %*\r\n'
    else:
        path = os.path.join(data_dir(), "askpass")
        body = f'#!/bin/sh\nexec {shlex.quote(exe)} {shlex.quote(script)} --askpass "$@"\n'
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, 0o700)
    return path


def askpass_main(prompt):
    """--askpass mode: show a password box, print the answer for ssh, exit."""
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("NetScan")
    apply_theme(app, QSettings("netscan", "netscan").value("theme", "system", type=str))
    text, ok = QInputDialog.getText(None, "NetScan: router login", prompt.strip() or "Password:",
                                    QLineEdit.Password)
    if not ok:
        return 1
    sys.stdout.write(text + "\n")
    return 0


def valid_ssh_user(name):
    """Usernames only: no spaces, '@' or shell characters, and can't start with '-' (an ssh option)."""
    return bool(re.fullmatch(r"[A-Za-z0-9._][A-Za-z0-9._-]{0,63}", name))


def parse_os(elem):
    """nmap's best OS guess for a <host> element, e.g. 'Linux 5.0 - 5.14 (96%)', or ''."""
    match = elem.find("os/osmatch")
    if match is None or not match.get("name"):
        return ""
    return f"{match.get('name')} ({match.get('accuracy', '?')}%)"


def parse_mac(text):
    """Find a MAC address in free text (AA:BB:.., aa-bb-.., or 12 bare hex digits)."""
    m = re.search(r"[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}", text)
    digits = re.sub(r"[:-]", "", m.group(0)) if m else re.sub(r"[\s:.-]", "", text)
    if not re.fullmatch(r"[0-9A-Fa-f]{12}", digits):
        return None
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).upper()


def wake_on_lan(mac, broadcasts):
    """Send a Wake-on-LAN magic packet (6 x FF, then the MAC 16 times) to each broadcast address.

    Returns how many packets went out.
    """
    payload = b"\xff" * 6 + bytes.fromhex(mac.replace(":", "")) * 16
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for addr in dict.fromkeys(broadcasts):
            for port in (9, 7):  # the usual WoL ports; devices listen on either
                try:
                    s.sendto(payload, (addr, port))
                    sent += 1
                except OSError:
                    pass
    return sent


def now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


def relative_time(iso, now=None):
    """'just now', '5 min ago', '3 h ago', 'yesterday', '12 days ago' for an ISO timestamp."""
    try:
        then = datetime.datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return ""
    secs = ((now or datetime.datetime.now()) - then).total_seconds()
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)} min ago"
    if secs < 86400:
        return f"{int(secs // 3600)} h ago"
    days = int(secs // 86400)
    return "yesterday" if days == 1 else f"{days} days ago" if days < 60 else then.date().isoformat()


def notify(title, body):
    """Desktop notification: notify-send on Linux, Notification Center on macOS, tray balloon on Windows."""
    if IS_MAC:
        esc = lambda t: t.replace("\\", "\\\\").replace('"', '\\"')
        QProcess.startDetached("/usr/bin/osascript",
                               ["-e", f'display notification "{esc(body)}" with title "{esc(title)}"'])
    elif not IS_WIN and shutil.which("notify-send"):
        QProcess.startDetached("notify-send", ["-a", "NetScan", "-i", "network-wired", title, body])
    elif QSystemTrayIcon.isSystemTrayAvailable():
        global _TRAY
        if _TRAY is None:
            _TRAY = QSystemTrayIcon(QApplication.windowIcon())
            _TRAY.show()
        _TRAY.showMessage(title, body)


_TRAY = None


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
    if open_tcp & {5000, 5001} and open_tcp & {139, 445}:
        return "nas"
    for kind, words in _TYPE_VENDORS:
        if any(w in vendor for w in words):
            return kind
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
        except (OSError, ValueError, AttributeError):
            self.devices = {}
            self.checked_hours = []
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
                           "checked_hours": self.checked_hours}, f, indent=1)
            os.replace(tmp, self.path)
        except OSError:
            pass


class HistoryGrid(QWidget):
    """Last 7 days x 24 hours: seen online / checked but not seen / not checked."""

    CELL, GAP, LEFT, BOTTOM = 10, 2, 34, 16

    def __init__(self):
        super().__init__()
        self.seen, self.checked = set(), set()
        w = self.LEFT + 24 * (self.CELL + self.GAP)
        h = 7 * (self.CELL + self.GAP) + self.BOTTOM
        self.setFixedSize(w, h)

    def set_data(self, seen, checked):
        self.seen, self.checked = set(seen), set(checked)
        self.update()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        small = QFont(self.font())
        small.setPointSizeF(max(7.0, small.pointSizeF() * 0.8))
        p.setFont(small)
        today = datetime.date.today()
        step = self.CELL + self.GAP
        for row in range(7):
            day = today - datetime.timedelta(days=6 - row)
            y = row * step
            p.setPen(QColor(MUTED))
            p.drawText(0, y, self.LEFT - 6, self.CELL + 1, Qt.AlignRight | Qt.AlignVCenter,
                       "Today" if row == 6 else day.strftime("%a"))
            for hour in range(24):
                bucket = f"{day.isoformat()}T{hour:02d}"
                x = self.LEFT + hour * step
                if bucket in self.seen:
                    p.setPen(Qt.NoPen)
                    p.setBrush(QColor(GREEN))
                elif bucket in self.checked:
                    p.setPen(Qt.NoPen)
                    p.setBrush(QColor(DIM))
                else:
                    p.setPen(QColor(BORDER))
                    p.setBrush(Qt.NoBrush)
                p.drawRoundedRect(x + 0.5, y + 0.5, self.CELL - 1, self.CELL - 1, 2.5, 2.5)
        p.setPen(QColor(MUTED))
        for hour in (0, 6, 12, 18):
            p.drawText(self.LEFT + hour * step - 2, 7 * step, 30, self.BOTTOM,
                       Qt.AlignLeft | Qt.AlignVCenter, f"{hour:02d}")
        p.end()


def find_terminal():
    """Return argv prefix that runs a command in a terminal window, or None."""
    for term, prefix in (("konsole", ["-e"]), ("kitty", []), ("alacritty", ["-e"]),
                         ("gnome-terminal", ["--"]), ("xterm", ["-e"])):
        path = shutil.which(term)
        if path:
            return [path, *prefix]
    return None


def terminal_argv(cmd):
    """argv that runs cmd (a list) in a new terminal window, or None if there's no terminal."""
    if IS_MAC:
        line = " ".join(shlex.quote(c) for c in cmd).replace("\\", "\\\\").replace('"', '\\"')
        return ["/usr/bin/osascript", "-e", 'tell application "Terminal"', "-e", "activate",
                "-e", f'do script "{line}"', "-e", "end tell"]
    if IS_WIN:
        return ["cmd.exe", "/c", "start", "cmd.exe", "/k", *cmd]
    term = find_terminal()
    return [*term, *cmd] if term else None


def iface_args(net):
    """nmap -e for the chosen network. Windows nmap uses its own names (eth0...), so skip it there."""
    return ["-e", net["iface"]] if net and not IS_WIN else []


# SUDO_ASKPASS helper for macOS: sudo -A runs it to get the password from a dialog.
ASKPASS_SCRIPT = """#!/bin/sh
exec /usr/bin/osascript -e 'text returned of (display dialog "NetScan needs your password to run nmap as root." default answer "" with hidden answer with title "NetScan" with icon caution)'
"""


NMAP_CAPS = ("cap_net_raw", "cap_net_admin")


def nmap_has_caps(nmap):
    """True if nmap has raw-packet capabilities (see setup-no-password.sh).

    Then `nmap --privileged` can do everything root can for scanning (ARP discovery,
    SYN, UDP, OS detection) without pkexec, so there's no password prompt.
    """
    if IS_MAC or IS_WIN or not nmap:
        return False
    out = run_text("getcap", os.path.realpath(nmap))
    return all(c in out for c in NMAP_CAPS)


def root_prefix():
    """argv prefix that runs a command as root after a graphical password prompt, or None."""
    if IS_MAC:
        return ["/usr/bin/sudo", "-A"] if os.path.exists("/usr/bin/sudo") else None
    pkexec = shutil.which("pkexec")
    return [pkexec] if pkexec else None


def write_askpass():
    folder = os.path.expanduser("~/Library/Application Support/NetScan")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, "askpass.sh")
    with open(path, "w") as f:
        f.write(ASKPASS_SCRIPT)
    os.chmod(path, 0o700)
    return path


# ---- theme -----------------------------------------------------------------

THEMES = {
    "dark": dict(
        BG="#0e1016", SURFACE="#151823", RAISED="#1c2030", BORDER="#262b3b", BORDER_HI="#363d54",
        TEXT="#e5e7ee", MUTED="#8a90a6", DIM="#565c70", ACCENT="#5b8cff", ACCENT_HI="#7aa2ff",
        GREEN="#34d399", AMBER="#fbbf24", RED="#f87171",
        HOVER="#232839", PRESSED="#171a26", PRIMARY_PRESSED="#4a78e6", PRIMARY_OFF_BG="#26304d",
        PRIMARY_OFF_FG="#6f7899", ALT_ROW="#181b27", ROW_LINE="#1d2130", SCROLL="#2d3345",
        SCROLL_HI="#3b4259", SELECT="#26355c", SELECT_TEXT="#ffffff"),
    "light": dict(
        BG="#f3f4f8", SURFACE="#ffffff", RAISED="#eef0f5", BORDER="#e1e4ec", BORDER_HI="#c9cfdb",
        TEXT="#1a1d26", MUTED="#667086", DIM="#a3a9ba", ACCENT="#3b6ef0", ACCENT_HI="#2c5ed8",
        GREEN="#0c9467", AMBER="#b45309", RED="#dc2626",
        HOVER="#e6e9f1", PRESSED="#dce0ea", PRIMARY_PRESSED="#2c5ed8", PRIMARY_OFF_BG="#c7d4f7",
        PRIMARY_OFF_FG="#ffffff", ALT_ROW="#fafbfd", ROW_LINE="#eef0f5", SCROLL="#ccd2de",
        SCROLL_HI="#b1b9c9", SELECT="#dbe5fd", SELECT_TEXT="#1a1d26"),
}
THEME_MODES = ["system", "light", "dark"]
THEME = "dark"
globals().update(THEMES[THEME])  # BG, TEXT, ACCENT... are read at use time, so switching works live

_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">{}</svg>'
_LINE = 'fill="none" stroke="{c}" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"'


def icon_svgs():
    """SVG sources for stylesheet images and device-type icons, in the current theme's colours."""
    line = _LINE.format(c=MUTED)
    dot = f'fill="{MUTED}"'
    return {
        "check": _SVG.format('<path d="M3.5 8.5l3 3 6-7" fill="none" stroke="#ffffff" stroke-width="2.2" '
                             'stroke-linecap="round" stroke-linejoin="round"/>'),
        "chevron": _SVG.format(f'<path d="M4 6l4 4 4-4" {_LINE.format(c=MUTED).replace("1.4", "1.8")}/>'),
        "search": _SVG.format(f'<circle cx="7" cy="7" r="4.5" {line}/><path d="M10.5 10.5L14 14" {line}/>'),
        # device types
        "type-router": _SVG.format(f'<rect x="1.5" y="8.5" width="13" height="5" rx="1.5" {line}/>'
                                   f'<path d="M4.5 8.5L3.5 3M11.5 8.5l1-5.5" {line}/>'
                                   f'<circle cx="4.5" cy="11" r=".9" {dot}/><circle cx="7" cy="11" r=".9" {dot}/>'),
        "type-phone": _SVG.format(f'<rect x="4.5" y="1.5" width="7" height="13" rx="1.6" {line}/>'
                                  f'<path d="M7 12.3h2" {line}/>'),
        "type-computer": _SVG.format(f'<rect x="1.5" y="2.5" width="13" height="8.5" rx="1.2" {line}/>'
                                     f'<path d="M8 11v3M5 14h6" {line}/>'),
        "type-printer": _SVG.format(f'<path d="M4.5 5.5v-4h7v4" {line}/>'
                                    f'<rect x="1.5" y="5.5" width="13" height="6" rx="1.2" {line}/>'
                                    f'<path d="M4.5 9.5h7v5h-7z" {line}/>'),
        "type-media": _SVG.format(f'<rect x="1.5" y="3.5" width="13" height="8.5" rx="1.2" {line}/>'
                                  f'<path d="M5.5 14.5h5M6 1.5l2 2 2-2" {line}/>'),
        "type-pi": _SVG.format(f'<rect x="1.5" y="3.5" width="13" height="9" rx="1.2" {line}/>'
                               f'<rect x="6" y="7" width="4" height="3.5" rx=".5" {line}/>'
                               + "".join(f'<circle cx="{x}" cy="5.3" r=".6" {dot}/>' for x in (4, 6, 8, 10, 12))),
        "type-nas": _SVG.format(f'<rect x="3" y="1.5" width="10" height="13" rx="1.2" {line}/>'
                                f'<path d="M5.5 4.5h5M5.5 7h5" {line}/><circle cx="8" cy="11" r="1.1" {line}/>'),
        "type-iot": _SVG.format(f'<path d="M8 1.8a4.4 4.4 0 0 0-2.6 8V11.5h5.2V9.8A4.4 4.4 0 0 0 8 1.8z" {line}/>'
                                f'<path d="M6.2 14h3.6" {line}/>'),
        "type-unknown": _SVG.format(f'<circle cx="8" cy="8" r="6.5" {line}/>'
                                    f'<path d="M6.2 6.3a1.9 1.9 0 1 1 2.6 1.8c-.5.2-.8.6-.8 1.1v.4" {line}/>'
                                    f'<circle cx="8" cy="11.6" r=".7" {dot}/>'),
    }


STYLESHEET = """
QMainWindow, QWidget#central {{ background: {BG}; }}
QToolTip {{ background: {RAISED}; color: {TEXT}; border: 1px solid {BORDER}; padding: 6px; }}

QLabel#title {{ font-size: 17pt; font-weight: 700; }}
QLabel#subtitle, QLabel#muted {{ color: {MUTED}; }}
QLabel#cardTitle, QLabel#fieldLabel {{ color: {MUTED}; font-size: 8pt; font-weight: 700; }}
QLabel#bigName {{ font-size: 13pt; font-weight: 700; }}
QLabel#pill {{ background: {RAISED}; border: 1px solid {BORDER}; border-radius: 11px;
               padding: 3px 11px; color: {MUTED}; }}

QFrame#card {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 12px; }}
QFrame#statusbar {{ background: {SURFACE}; border-top: 1px solid {BORDER}; }}
QScrollArea#plain, QScrollArea#plain > QWidget > QWidget {{ background: transparent; border: none; }}

QPushButton {{ background: {RAISED}; border: 1px solid {BORDER}; border-radius: 8px;
               padding: 7px 14px; color: {TEXT}; }}
QPushButton:hover {{ background: {HOVER}; border-color: {BORDER_HI}; }}
QPushButton:pressed {{ background: {PRESSED}; }}
QPushButton:disabled {{ color: {DIM}; background: {SURFACE}; border-color: {BORDER}; }}
QPushButton#primary {{ background: {ACCENT}; border: 1px solid {ACCENT}; color: #ffffff;
                       font-weight: 600; padding: 7px 20px; }}
QPushButton#primary:hover {{ background: {ACCENT_HI}; border-color: {ACCENT_HI}; }}
QPushButton#primary:pressed {{ background: {PRIMARY_PRESSED}; }}
QPushButton#primary:disabled {{ background: {PRIMARY_OFF_BG}; border-color: {PRIMARY_OFF_BG};
                                color: {PRIMARY_OFF_FG}; }}
QPushButton::menu-indicator {{ image: url({chevron}); width: 12px; height: 12px;
                               subcontrol-origin: padding; subcontrol-position: right center;
                               right: 8px; }}
QPushButton#menuButton {{ padding-right: 28px; }}

QLineEdit, QComboBox, QPlainTextEdit {{ background: {BG}; border: 1px solid {BORDER}; border-radius: 8px;
                        padding: 6px 10px; color: {TEXT}; selection-background-color: {ACCENT};
                        selection-color: #ffffff; }}
QLineEdit:hover, QComboBox:hover, QPlainTextEdit:hover {{ border-color: {BORDER_HI}; }}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus {{ border-color: {ACCENT}; }}
QLineEdit:disabled, QComboBox:disabled {{ color: {DIM}; }}
QComboBox::drop-down {{ border: none; width: 28px; }}
QComboBox::down-arrow {{ image: url({chevron}); width: 12px; height: 12px; }}
QComboBox QAbstractItemView {{ background: {RAISED}; border: 1px solid {BORDER}; padding: 4px;
                               outline: 0; color: {TEXT}; selection-background-color: {ACCENT};
                               selection-color: #ffffff; }}

QCheckBox {{ spacing: 8px; color: {TEXT}; }}
QCheckBox:disabled {{ color: {DIM}; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 5px;
                        border: 1px solid {BORDER_HI}; background: {BG}; }}
QCheckBox::indicator:hover {{ border-color: {ACCENT}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; image: url({check}); }}
QCheckBox::indicator:disabled {{ background: {SURFACE}; border-color: {BORDER}; }}
QCheckBox::indicator:checked:disabled {{ background: {PRIMARY_OFF_BG}; border-color: {PRIMARY_OFF_BG}; }}

QTableWidget {{ background: {SURFACE}; alternate-background-color: {ALT_ROW}; border: none;
                color: {TEXT}; gridline-color: transparent; outline: 0;
                selection-background-color: {SELECT}; selection-color: {SELECT_TEXT}; }}
QTableWidget::item {{ padding: 0 10px; border-bottom: 1px solid {ROW_LINE}; }}
QTableWidget::item:selected {{ background: {SELECT}; color: {SELECT_TEXT}; }}
QHeaderView {{ background: {SURFACE}; border: none; }}
QHeaderView::section {{ background: {SURFACE}; color: {MUTED}; border: none;
                        border-bottom: 1px solid {BORDER}; padding: 8px 10px;
                        font-size: 8pt; font-weight: 700; }}
QHeaderView::section:hover {{ color: {TEXT}; }}
QTableCornerButton::section {{ background: {SURFACE}; border: none; }}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle {{ background: {SCROLL}; border-radius: 3px; }}
QScrollBar::handle:vertical {{ min-height: 30px; }}
QScrollBar::handle:horizontal {{ min-width: 30px; }}
QScrollBar::handle:hover {{ background: {SCROLL_HI}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}

QProgressBar {{ background: {RAISED}; border: none; border-radius: 7px; color: {TEXT};
                text-align: center; font-size: 8pt; max-height: 14px; min-height: 14px; }}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 7px; }}

QSplitter::handle {{ background: transparent; }}

QFrame#segment {{ background: {RAISED}; border: 1px solid {BORDER}; border-radius: 11px; }}
QTabBar#pages {{ background: transparent; }}
QTabBar#pages::tab {{ background: transparent; color: {MUTED}; border: none; border-radius: 8px;
                      padding: 7px 18px; margin: 3px; font-weight: 600; }}
QTabBar#pages::tab:hover:!selected {{ color: {TEXT}; background: {HOVER}; }}
QTabBar#pages::tab:selected {{ background: {ACCENT}; color: #ffffff; }}

QMenu {{ background: {RAISED}; border: 1px solid {BORDER}; padding: 6px; color: {TEXT}; }}
QMenu::item {{ padding: 6px 22px 6px 14px; border-radius: 6px; }}
QMenu::item:selected {{ background: {ACCENT}; color: #ffffff; }}
QMenu::item:disabled {{ color: {DIM}; }}
QMenu::separator {{ height: 1px; background: {BORDER}; margin: 5px 8px; }}
QMenu::indicator {{ width: 14px; height: 14px; }}
"""


def theme_icon_dir():
    """Write the current theme's SVGs and return their folder (one folder per theme)."""
    base = QStandardPaths.writableLocation(QStandardPaths.CacheLocation) or os.path.expanduser("~/.cache/netscan")
    folder = os.path.join(base, "theme-" + THEME)
    os.makedirs(folder, exist_ok=True)
    for name, svg in icon_svgs().items():
        path = os.path.join(folder, name + ".svg")
        try:
            with open(path) as f:
                if f.read() == svg:
                    continue
        except OSError:
            pass
        with open(path, "w") as f:
            f.write(svg)
    return folder


_ICON_DIR = {}


def icon_path(name):
    # Qt stylesheet url()s want forward slashes, even on Windows.
    if THEME not in _ICON_DIR:
        _ICON_DIR[THEME] = theme_icon_dir()
    return os.path.join(_ICON_DIR[THEME], name + ".svg").replace("\\", "/")


def system_prefers_dark():
    hints = QGuiApplication.styleHints()
    if hasattr(hints, "colorScheme"):
        scheme = hints.colorScheme()
        if scheme != Qt.ColorScheme.Unknown:
            return scheme == Qt.ColorScheme.Dark
    # Older Qt or no preference reported: guess from the platform's window colour.
    return QGuiApplication.palette().color(QPalette.Window).lightness() < 128


def apply_theme(app, mode="system"):
    """Fusion palette plus stylesheet in the chosen theme, so dialogs and menus match too.

    mode: 'system' (follow the desktop's light/dark setting), 'light' or 'dark'.
    """
    global THEME
    THEME = mode if mode in THEMES else "dark" if system_prefers_dark() else "light"
    globals().update(THEMES[THEME])
    app.setStyle(QStyleFactory.create("Fusion"))
    pal = QPalette()
    for role, color in ((QPalette.Window, BG), (QPalette.WindowText, TEXT), (QPalette.Base, SURFACE),
                        (QPalette.AlternateBase, RAISED), (QPalette.Text, TEXT),
                        (QPalette.Button, RAISED), (QPalette.ButtonText, TEXT),
                        (QPalette.ToolTipBase, RAISED), (QPalette.ToolTipText, TEXT),
                        (QPalette.Highlight, ACCENT), (QPalette.HighlightedText, "#ffffff"),
                        (QPalette.PlaceholderText, DIM), (QPalette.Link, ACCENT_HI),
                        (QPalette.Mid, BORDER), (QPalette.Dark, BG), (QPalette.Light, BORDER_HI)):
        pal.setColor(role, QColor(color))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        pal.setColor(QPalette.Disabled, role, QColor(DIM))
    app.setPalette(pal)
    app.setStyleSheet(STYLESHEET.format(
        **THEMES[THEME], check=icon_path("check"), chevron=icon_path("chevron")))


def mono_font():
    f = QFontDatabase.systemFont(QFontDatabase.FixedFont)
    f.setPointSizeF(QApplication.font().pointSizeF() * 0.95)
    return f


def make_card(title=None):
    """A rounded panel; returns (frame, vertical layout, header row or None)."""
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(14, 12, 14, 12)
    layout.setSpacing(10)
    header = None
    if title:
        header = QHBoxLayout()
        header.setSpacing(10)
        label = QLabel(title.upper())
        label.setObjectName("cardTitle")
        header.addWidget(label)
        layout.addLayout(header)
    return frame, layout, header


class SortItem(QTableWidgetItem):
    """Sorts by a hidden key (Qt.UserRole) instead of its display text."""

    def __lt__(self, other):
        return (self.data(Qt.UserRole) or "") < (other.data(Qt.UserRole) or "")


class IPItem(QTableWidgetItem):
    """Sorts IP addresses numerically instead of as strings."""

    def __lt__(self, other):
        try:
            return ipaddress.ip_address(self.text()) < ipaddress.ip_address(other.text())
        except ValueError:
            return super().__lt__(other)


class Resolver(QObject):
    """Background name lookups: mDNS, NetBIOS, then system DNS."""

    resolved = Signal(str, str)  # ip, name ("" if nothing found)

    def lookup(self, ips):
        def run(ip):
            self.resolved.emit(ip, lookup_name(ip))

        for ip in ips:
            self.pool.submit(run, ip)

    # Bounded, so a /16 doesn't start thousands of threads at once.
    pool = ThreadPoolExecutor(max_workers=32)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetScan")
        self.resize(1060, 660)

        self.nmap = find_program("nmap")
        self.root = root_prefix() if not IS_WIN else None
        self.nmap_caps = nmap_has_caps(self.nmap)
        self.prompted = False
        # On Windows nmap needs no password prompt: Npcap gives it raw packet access.
        self.has_root = bool(self.root) or npcap_installed() or self.nmap_caps
        self.askpass = write_askpass() if IS_MAC and self.root else None
        self.settings = QSettings("netscan", "netscan")
        self.proc = None
        self.output = ""
        self.last_xml = ""
        self.parser = None
        self.on_host = None
        self.on_done = None
        self.used_root = False
        self.current = None
        self.last_target = ""
        self.elapsed = 0
        self.pending = set()
        self.summary = ""
        self.hosts = {}   # ip -> host dict
        self.ports = {}   # ip -> list of open-port dicts (absent = not scanned)
        self.scan_ips = []
        self.reported = set()

        self.mono = mono_font()
        self.devices = DeviceStore(devices_file())
        self.new_devices = set()
        self.online_macs = set()  # seen in the latest scan or watch check
        self.history_path = None  # this scan's file in the history folder
        self.router_proc = None
        self._icons = {}
        self.watch_proc = None
        self.networks = []
        self.ip_items = {}
        self.count_timer = QTimer(self)
        self.count_timer.setSingleShot(True)
        self.count_timer.setInterval(0)
        self.count_timer.timeout.connect(self.update_count)
        self.resolver = Resolver()
        self.resolver.resolved.connect(self.on_resolved)

        # Discover card: target and host discovery
        self.target = QComboBox()
        self.target.setEditable(True)
        self.target.setMinimumWidth(320)
        self.target.lineEdit().setPlaceholderText("Network, e.g. 192.168.1.0/24")
        self.target.setToolTip("Detected networks. You can also type a CIDR, range "
                               "or list, e.g. 10.0.0.0/16 or 10.1.1.1-50,10.1.2.0/24")
        self.refresh_btn = QPushButton("Re-detect")
        self.refresh_btn.setToolTip("Detect local networks again")
        self.refresh_btn.clicked.connect(self.populate_networks)
        self.root_box = QCheckBox("Raw scans (Npcap)" if IS_WIN else "Run as root")
        if IS_WIN:
            self.root_box.setToolTip(
                "Uses Npcap for raw packets: better host discovery, faster SYN port scans, "
                "and needed for UDP." + ("" if self.has_root else " Npcap is not installed."))
        else:
            if self.nmap_caps:
                self.root_box.setText("Privileged scans (no password)")
            self.root_box.setToolTip(("Asks for your Mac password (sudo)." if IS_MAC else
                                      "nmap has raw-packet permission, so no password is needed." if self.nmap_caps
                                      else "Uses pkexec (asks for your password). Run setup-no-password.sh "
                                           "once to stop the prompts.")
                                     + " Better host discovery, faster SYN port scans, and needed for UDP.")
        self.root_box.toggled.connect(self.update_controls)
        self.scan_btn = QPushButton("Find Hosts")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.setDefault(True)
        self.scan_btn.clicked.connect(self.start_scan)
        self.auto_ports_box = QCheckBox("Also scan top 100 ports")
        self.version_box = QCheckBox("Detect versions (slower)")
        self.os_box = QCheckBox("Detect OS")
        self.os_box.setToolTip("Guess each host's operating system while scanning ports "
                               "(needs root). Includes the top 100 port scan, which OS detection needs.")
        self.os_box.toggled.connect(self.os_toggled)
        self.auto_before_os = None

        discover, dl, _ = make_card("Discover")
        row = QHBoxLayout()
        row.addWidget(self.target, 1)
        row.addWidget(self.refresh_btn)
        row.addWidget(self.scan_btn)
        dl.addLayout(row)
        row = QHBoxLayout()
        row.setSpacing(18)
        row.addWidget(self.root_box)
        row.addWidget(self.auto_ports_box)
        row.addWidget(self.version_box)
        row.addWidget(self.os_box)
        row.addStretch(1)
        dl.addLayout(row)

        # Ports card: port scan of selected hosts
        self.profile = QComboBox()
        for label, _ in PORT_PROFILES:
            self.profile.addItem(label)
        self.profile.currentIndexChanged.connect(self.update_controls)
        self.custom_ports = QLineEdit()
        self.custom_ports.setPlaceholderText("22,80,443,8000-8100")
        self.custom_ports.setMinimumWidth(190)
        self.udp_box = QCheckBox("+ common UDP")
        self.udp_box.setToolTip(f"Also scan UDP {UDP_PORTS} (needs root)")
        self.ports_btn = QPushButton("Scan Ports")
        self.ports_btn.setObjectName("primary")
        self.ports_btn.setToolTip("Scans the selected hosts, or every visible host if none are selected.")
        self.ports_btn.clicked.connect(self.start_port_scan)

        ports_card, pl, _ = make_card("Ports")
        row = QHBoxLayout()
        row.addWidget(self.profile, 1)
        row.addWidget(self.ports_btn)
        pl.addLayout(row)
        row = QHBoxLayout()
        row.setSpacing(18)
        row.addWidget(self.custom_ports, 1)
        row.addWidget(self.udp_box)
        row.addStretch(1)
        pl.addLayout(row)

        # Hosts card: filter bar and results table
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by IP, name, MAC, vendor, OS, port…")
        self.filter_edit.setClearButtonEnabled(True)
        self.search_act = self.filter_edit.addAction(QIcon(icon_path("search")), QLineEdit.LeadingPosition)
        self.filter_edit.setMaximumWidth(420)
        self.filter_edit.textChanged.connect(self.apply_filter)
        self.open_only_box = QCheckBox("Only open ports")
        self.open_only_box.setToolTip("Only show hosts with open ports")
        self.open_only_box.toggled.connect(self.apply_filter)
        self.count_label = QLabel("")
        self.count_label.setObjectName("pill")

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels([c.upper() for c in COLUMNS])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setFocusPolicy(Qt.StrongFocus)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(34)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setHighlightSections(False)
        header.setStretchLastSection(True)
        # Show Change (NEW DEVICE, compare results) right after Name, where it's noticed.
        header.moveSection(header.visualIndex(COL_CHANGE), COL_HOST)
        self.table.setColumnHidden(COL_CHANGE, True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.copy_act = QAction("Copy rows", self.table)
        self.copy_act.setShortcut(QKeySequence.Copy)
        self.copy_act.setShortcutContext(Qt.WidgetShortcut)
        self.copy_act.triggered.connect(self.copy_selection)
        self.table.addAction(self.copy_act)
        self.table.itemSelectionChanged.connect(self.show_port_details)
        self.table.itemDoubleClicked.connect(lambda item: self.edit_nickname(
            self.table.item(item.row(), COL_IP).text()))
        rename = QAction("Set nickname…", self.table)
        rename.setShortcut(QKeySequence(Qt.Key_F2))
        rename.setShortcutContext(Qt.WidgetShortcut)
        rename.triggered.connect(self.rename_selected)
        self.table.addAction(rename)
        self.table.setColumnHidden(COL_OS, True)

        hosts_card, hl, hh = make_card("Hosts")
        hh.addWidget(self.count_label)
        hh.addStretch(1)
        hh.addWidget(self.open_only_box)
        hh.addSpacing(8)
        hh.addWidget(self.filter_edit, 1)
        hl.addWidget(self.table)

        # Details card: open ports of the selected host
        self.details_label = QLabel("Select a host to see its open ports.")
        self.details_label.setObjectName("muted")
        self.details = QTableWidget(0, len(PORT_COLUMNS))
        self.details.setHorizontalHeaderLabels([c.upper() for c in PORT_COLUMNS])
        self.details.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.details.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.details.setAlternatingRowColors(True)
        self.details.setShowGrid(False)
        self.details.verticalHeader().setVisible(False)
        self.details.verticalHeader().setDefaultSectionSize(32)
        self.details.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.details.horizontalHeader().setHighlightSections(False)
        self.details.horizontalHeader().setStretchLastSection(True)
        details_box, del_, dh = make_card("Open ports")
        dh.addWidget(self.details_label)
        dh.addStretch(1)
        del_.addWidget(self.details)

        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.setHandleWidth(12)
        self.splitter.addWidget(hosts_card)
        self.splitter.addWidget(details_box)
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 2)

        # Status bar
        self.progress = QProgressBar()
        self.progress.setFixedWidth(220)
        self.progress.setTextVisible(True)
        self.progress.hide()
        self.status_dot = QLabel("●")
        self.status = QLabel("Ready.")
        self.status.setWordWrap(True)

        self.compare_btn = QPushButton("Compare…")
        self.compare_btn.setToolTip("Compare these results with a saved scan (.json)")
        self.compare_btn.setObjectName("menuButton")
        self.compare_menu = QMenu(self.compare_btn)
        self.compare_menu.aboutToShow.connect(self.build_compare_menu)
        self.compare_btn.setMenu(self.compare_menu)
        self.export_btn = QPushButton("Save / Export")
        self.export_btn.setObjectName("menuButton")
        export_menu = QMenu(self.export_btn)
        export_menu.addAction("Save scan (JSON, for Compare)…", self.save_json)
        export_menu.addAction("Export CSV…", self.export_csv)
        export_menu.addAction("Export last nmap output (XML)…", self.export_xml)
        self.export_btn.setMenu(export_menu)

        statusbar = QFrame()
        statusbar.setObjectName("statusbar")
        bottom = QHBoxLayout(statusbar)
        bottom.setContentsMargins(18, 10, 18, 10)
        bottom.addWidget(self.status_dot)
        bottom.addWidget(self.status, 1)
        bottom.addWidget(self.progress)
        bottom.addSpacing(6)
        bottom.addWidget(self.compare_btn)
        bottom.addWidget(self.export_btn)

        # Title row
        title = QLabel("NetScan")
        title.setObjectName("title")
        subtitle = QLabel("Network discovery and port scanning with nmap")
        subtitle.setObjectName("subtitle")
        titles = QVBoxLayout()
        titles.setSpacing(0)
        titles.addWidget(title)
        titles.addWidget(subtitle)
        self.tabbar = QTabBar()
        self.tabbar.setObjectName("pages")
        self.tabbar.setDrawBase(False)
        self.tabbar.setExpanding(False)
        self.tabbar.addTab("Scan")
        self.tabbar.addTab("Devices && Wake-on-LAN")
        self.tabbar.setTabToolTip(0, "Find hosts and scan ports (Ctrl+1)")
        self.tabbar.setTabToolTip(1, "Every device NetScan has seen: nicknames, wake, watch (Ctrl+2)")
        segment = QFrame()
        segment.setObjectName("segment")
        sl = QHBoxLayout(segment)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.addWidget(self.tabbar)
        self.nmap_pill = QLabel()
        self.nmap_pill.setObjectName("pill")
        self.theme_btn = QPushButton("Theme")
        self.theme_btn.setObjectName("menuButton")
        self.theme_btn.setToolTip("Light, dark, or follow your system setting")
        theme_menu = QMenu(self.theme_btn)
        self.theme_group = QActionGroup(self)
        for mode in THEME_MODES:
            act = theme_menu.addAction(mode.capitalize() if mode != "system" else "System (auto)")
            act.setCheckable(True)
            act.setData(mode)
            self.theme_group.addAction(act)
        self.theme_group.triggered.connect(lambda act: self.retheme(act.data()))
        self.theme_btn.setMenu(theme_menu)
        head = QHBoxLayout()
        head.addLayout(titles)
        head.addStretch(1)
        head.addWidget(segment, 0, Qt.AlignVCenter)
        head.addStretch(1)
        head.addWidget(self.theme_btn, 0, Qt.AlignVCenter)
        head.addSpacing(6)
        head.addWidget(self.nmap_pill, 0, Qt.AlignVCenter)

        cards = QHBoxLayout()
        cards.setSpacing(12)
        cards.addWidget(discover, 3)
        cards.addWidget(ports_card, 2)

        body = QVBoxLayout()
        body.setContentsMargins(18, 16, 18, 6)
        body.setSpacing(12)
        scan_page = QWidget()
        sp = QVBoxLayout(scan_page)
        sp.setContentsMargins(0, 0, 0, 0)
        sp.setSpacing(12)
        sp.addLayout(cards)
        sp.addWidget(self.splitter, 1)
        self.pages = QStackedWidget()
        self.pages.addWidget(scan_page)
        self.pages.addWidget(self.build_devices_page())
        self.tabbar.currentChanged.connect(self.switch_page)

        body.addLayout(head)
        body.addWidget(self.pages, 1)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addLayout(body, 1)
        layout.addWidget(statusbar)
        central = QWidget()
        central.setObjectName("central")
        central.setLayout(layout)
        self.setCentralWidget(central)

        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.tick)
        self.watch_timer = QTimer(self)
        self.watch_timer.timeout.connect(self.watch_scan)

        for keys, slot in (("F5", self.shortcut_scan), (QKeySequence.Find, self.focus_filter),
                           ("Ctrl+1", lambda: self.tabbar.setCurrentIndex(0)),
                           ("Ctrl+2", lambda: self.tabbar.setCurrentIndex(1))):
            act = QAction(self)
            act.setShortcut(QKeySequence(keys))
            act.triggered.connect(slot)
            self.addAction(act)

        self.load_settings()
        self.populate_networks()
        self.set_busy(False)
        version = re.search(r"version (\S+)", run_text(self.nmap, "--version")) if self.nmap else None
        self.nmap_version = version.group(1) if version else ""
        self.update_nmap_pill()
        self.theme_mode = self.settings.value("theme", "system", type=str)
        if self.theme_mode not in THEME_MODES:
            self.theme_mode = "system"
        for act in self.theme_group.actions():
            act.setChecked(act.data() == self.theme_mode)
        hints = QGuiApplication.styleHints()
        if hasattr(hints, "colorSchemeChanged"):
            hints.colorSchemeChanged.connect(lambda _s: self.theme_mode == "system" and self.retheme("system"))
        if not self.nmap:
            self.set_dot(RED)
            self.status.setText("nmap not found. Install it with: "
                                + ("brew install nmap" if IS_MAC else
                                   "install-windows.ps1 (or choco install nmap)" if IS_WIN else
                                   "sudo pacman -S nmap"))
        self.refresh_devices()
        self.watch_combo.currentIndexChanged.connect(self.set_watch)
        self.set_watch(first_delay=5000)

    # ---- settings ----------------------------------------------------------

    def load_settings(self):
        s = self.settings
        b = lambda key, default: s.value(key, default, type=bool)
        self.root_box.setChecked(b("root", True) and self.has_root)
        self.auto_ports_box.setChecked(b("auto_ports", True))
        self.version_box.setChecked(b("versions", False))
        self.os_box.setChecked(b("os", False))
        self.watch_combo.setCurrentIndex(min(s.value("watch", 0, type=int), len(WATCH_INTERVALS) - 1))
        self.watch_ports_box.setChecked(b("watch_ports", False))
        if s.contains("dev_split"):
            self.dev_split.restoreState(s.value("dev_split"))
        self.udp_box.setChecked(b("udp", False))
        self.profile.setCurrentIndex(min(s.value("profile", 0, type=int), len(PORT_PROFILES) - 1))
        self.custom_ports.setText(s.value("custom_ports", "", type=str))
        self.open_only_box.setChecked(b("open_only", False))
        if s.contains("geometry"):
            self.restoreGeometry(s.value("geometry"))
        if s.contains("splitter"):
            self.splitter.restoreState(s.value("splitter"))

    def save_settings(self):
        s = self.settings
        s.setValue("root", self.root_box.isChecked())
        # While Detect OS forces the port scan on, save the user's own choice instead.
        s.setValue("auto_ports", self.auto_ports_box.isChecked() if self.auto_before_os is None
                   else self.auto_before_os)
        s.setValue("versions", self.version_box.isChecked())
        s.setValue("os", self.os_box.isChecked())
        s.setValue("watch", self.watch_combo.currentIndex())
        s.setValue("watch_ports", self.watch_ports_box.isChecked())
        s.setValue("theme", self.theme_mode)
        s.setValue("dev_split", self.dev_split.saveState())
        s.setValue("udp", self.udp_box.isChecked())
        s.setValue("profile", self.profile.currentIndex())
        s.setValue("custom_ports", self.custom_ports.text())
        s.setValue("open_only", self.open_only_box.isChecked())
        s.setValue("geometry", self.saveGeometry())
        s.setValue("splitter", self.splitter.saveState())

    # ---- network detection -------------------------------------------------

    def populate_networks(self):
        self.target.clear()
        self.networks = detect_networks()
        for n in self.networks:
            self.target.addItem(
                f"{n['network']}  ({n['iface']}, you are {n['local_ip']})", n)
        if not self.networks:
            self.status.setText("No LAN subnet detected. Type a target, e.g. 192.168.1.0/24")

    def selected_target(self):
        """Return (nmap target list, network dict or None)."""
        idx = self.target.currentIndex()
        text = self.target.currentText().strip()
        if idx >= 0 and text == self.target.itemText(idx):
            n = self.target.itemData(idx)
            return [str(n["network"])], n
        # Free-typed: allow comma/space separated targets.
        targets = [t for t in re.split(r"[,\s]+", text) if t]
        match = None
        if len(targets) == 1:
            try:
                net = ipaddress.ip_network(targets[0], strict=False)
                match = next((n for n in self.networks if net.subnet_of(n["network"])), None)
            except ValueError:
                pass
        return targets, match

    # ---- running nmap ------------------------------------------------------

    def run_nmap(self, args, message, on_host, on_done):
        """Run nmap (as root via pkexec/sudo if requested), streaming results.

        on_host(elem) is called for each <host> element as nmap finishes it;
        on_done(stderr, code) once nmap exits.
        """
        use_root = self.root_box.isChecked() and self.has_root
        # -n: nmap's reverse DNS can hang for minutes behind a VPN that blocks
        # LAN DNS; names are looked up separately by Resolver instead.
        args = ["-n", "-T4", "--stats-every", "1s", "-oX", "-", *args]
        if IS_WIN and not use_root:
            args.insert(0, "--unprivileged")
        # With capabilities, nmap itself can send raw packets: no pkexec, no prompt.
        prompt = bool(use_root and self.root and not self.nmap_caps)
        if use_root and self.nmap_caps:
            args.insert(0, "--privileged")
        program, argv = ((self.root[0], [*self.root[1:], self.nmap, *args]) if prompt
                         else (self.nmap, args))
        self.prompted = prompt

        self.output = ""
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.parser = ET.XMLPullParser(events=("end",))
        self.elapsed = 0
        self.on_host = on_host
        self.on_done = on_done
        self.used_root = use_root
        self.scan_message = message
        self.set_busy(True)
        self.status.setText(message + (" (authorise in the prompt)" if prompt else ""))

        self.proc = QProcess(self)
        self.proc.setProcessChannelMode(QProcess.SeparateChannels)
        self.proc.readyReadStandardOutput.connect(self.read_output)
        self.proc.finished.connect(self.nmap_finished)
        self.proc.errorOccurred.connect(self.nmap_error)
        if use_root and self.askpass:
            env = QProcessEnvironment.systemEnvironment()
            env.insert("SUDO_ASKPASS", self.askpass)
            self.proc.setProcessEnvironment(env)
        self.proc.start(program, argv)
        self.timer.start()

    def is_running(self):
        return self.proc is not None and self.proc.state() != QProcess.NotRunning

    def update_controls(self):
        """Enable/disable controls based on busy state and current choices."""
        busy = self.is_running()
        has_hosts = self.table.rowCount() > 0
        root = self.root_box.isChecked() and self.has_root
        self.scan_btn.setEnabled(not busy and bool(self.nmap))
        self.ports_btn.setEnabled(not busy and has_hosts)
        for w in (self.target, self.refresh_btn, self.profile, self.version_box, self.compare_btn):
            w.setEnabled(not busy)
        self.root_box.setEnabled(not busy and self.has_root)
        self.udp_box.setEnabled(not busy and root)
        self.os_box.setEnabled(not busy and root)
        # OS detection fingerprints open/closed ports, so it forces the port scan on.
        os_on = self.os_box.isChecked() and root
        self.auto_ports_box.setEnabled(not busy and not os_on)
        self.auto_ports_box.setToolTip("Included automatically: OS detection needs a port scan." if os_on
                                       else "Scan each host's top 100 TCP ports while finding hosts.")
        self.udp_box.setToolTip(f"Also scan UDP {UDP_PORTS}" + ("" if root else " (needs root)"))
        self.custom_ports.setVisible(self.profile.currentIndex() == CUSTOM_PROFILE)
        self.custom_ports.setEnabled(not busy)
        self.export_btn.setEnabled(not busy and has_hosts)
        self.compare_btn.setEnabled(not busy and has_hosts)

    def os_toggled(self, on):
        """Tick (and lock) the port scan while Detect OS is on; restore the user's choice after."""
        if on:
            self.auto_before_os = self.auto_ports_box.isChecked()
            self.auto_ports_box.setChecked(True)
        elif self.auto_before_os is not None:
            self.auto_ports_box.setChecked(self.auto_before_os)
            self.auto_before_os = None
        self.update_controls()

    def update_nmap_pill(self):
        self.nmap_pill.setText(
            f'<span style="color:{GREEN if self.nmap else RED}">●</span>&nbsp; '
            + (f"nmap {self.nmap_version}" if self.nmap_version else
               "nmap ready" if self.nmap else "nmap not found"))

    def retheme(self, mode):
        """Switch theme live: restyle, then repaint everything that was coloured by hand."""
        self.theme_mode = mode
        apply_theme(QApplication.instance(), mode)
        for act in self.theme_group.actions():
            act.setChecked(act.data() == mode)
        self.search_act.setIcon(QIcon(icon_path("search")))
        self.dev_search_act.setIcon(QIcon(icon_path("search")))
        for i in range(1, self.detail_type.count()):
            self.detail_type.setItemIcon(i, QIcon(icon_path("type-" + self.detail_type.itemData(i))))
        for ip in self.hosts:
            self.refresh_row(ip)
        for row in range(self.table.rowCount()):
            text = self.table.item(row, COL_CHANGE).text()
            if text:
                self.set_change(row, text)
        self.update_nmap_pill()
        self.set_dot(ACCENT if self.is_running() else GREEN)
        self.show_port_details()
        self.refresh_devices()

    def set_dot(self, color):
        self.status_dot.setStyleSheet(f"color: {color};")

    def set_busy(self, busy):
        self.set_dot(ACCENT if busy else GREEN)
        self.progress.setVisible(busy)
        self.progress.setRange(0, 0)  # indeterminate until nmap reports %
        self.progress.setFormat("%p%")
        self.update_controls()

    def tick(self):
        self.elapsed += 1

    def read_output(self):
        chunk = self.decoder.decode(bytes(self.proc.readAllStandardOutput()))
        self.output += chunk
        if self.parser is None:
            return
        try:
            self.parser.feed(chunk)
            for _event, elem in self.parser.read_events():
                if elem.tag == "host":
                    self.on_host(elem)
                elif elem.tag == "taskprogress":
                    pct = float(elem.get("percent", 0))
                    left = int(elem.get("remaining", 0) or 0)
                    self.progress.setRange(0, 100)
                    self.progress.setValue(int(pct))
                    self.progress.setFormat(f"%p%  ~{left}s left" if left else "%p%")
        except ET.ParseError:
            self.parser = None  # keep what we have; report on finish

    def nmap_error(self, err):
        if err == QProcess.FailedToStart:
            self.timer.stop()
            self.set_busy(False)
            self.set_dot(RED)
            self.status.setText("Could not start nmap.")

    def nmap_finished(self, code, _status):
        self.timer.stop()
        self.read_output()
        stderr = bytes(self.proc.readAllStandardError()).decode(errors="replace").strip()
        self.set_busy(False)
        # pkexec: 126 = auth dialog dismissed, 127 = not authorised.
        # sudo -A: password dialog cancelled or wrong, reported as "sudo: ..." with no nmap output.
        declined = ("sudo:" in stderr and "<nmaprun" not in self.output) if IS_MAC \
            else code in (126, 127)
        if declined and self.prompted:
            self.set_dot(AMBER)
            self.status.setText("Root access was declined. Untick “Run as root” to scan without it.")
            self.on_done(stderr, code, failed=True)
            return
        if "<nmaprun" not in self.output:
            self.set_dot(RED)
            self.status.setText("Scan failed. " + (stderr.splitlines()[-1] if stderr else f"nmap exit {code}"))
            self.on_done(stderr, code, failed=True)
            return
        self.last_xml = self.output
        self.on_done(stderr, code, failed=False)

    # ---- host discovery ----------------------------------------------------

    def start_scan(self):
        targets, net = self.selected_target()
        if not targets or not all(re.fullmatch(r"[0-9A-Za-z.\-/:]+", t) for t in targets):
            QMessageBox.warning(self, "NetScan", "Enter a valid target, e.g. 192.168.1.0/24")
            return
        self.current = net
        self.last_target = " ".join(targets)
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.ip_items = {}
        self.table.setColumnHidden(COL_CHANGE, True)
        self.table.setColumnHidden(COL_OS, True)
        self.new_devices = set()
        self.hosts = {}
        self.ports = {}
        self.pending = set()
        self.show_port_details()

        # With auto port scan, one nmap run does discovery and then scans each
        # live host (one password prompt instead of two).
        self.auto_ports = self.auto_ports_box.isChecked() or bool(self.os_args())
        if self.auto_ports:
            args = ["--top-ports", "100"] + (["-sV"] if self.version_box.isChecked() else [])
            args += self.os_args()
            message = (f"Finding hosts, scanning top 100 ports{' and detecting OS' if self.os_args() else ''}"
                       f" on {self.last_target}…")
        else:
            args = ["-sn"]
            message = f"Finding hosts on {self.last_target}…"
        if self.auto_ports and net:
            args += LAN_FAST
        if net:
            # Scanning ourselves in the same run throws off nmap's timing for every other host
            # (a full port scan found 1 of the router's 3 open ports); our ports come from the OS.
            args += ["--exclude", net["local_ip"]]
        args += iface_args(net) + targets
        self.run_nmap(args, message, self.host_found, self.hosts_done)

    def host_found(self, elem):
        h = parse_host(elem)
        if h is None:
            return
        net = self.current
        if net and h["ip"] == net["local_ip"]:
            h["mac"] = h["mac"] or net["mac"]
            h["hostname"] = h["hostname"] or socket.gethostname()
            h["vendor"] = h["vendor"] or "(this computer)"
        h["vendor"] = h["vendor"] or mac_vendor(h["mac"])
        self.hosts[h["ip"]] = h
        h["os"] = parse_os(elem)
        if self.auto_ports:
            self.ports[h["ip"]] = parse_ports(elem)
        self.add_row(h)
        if not h["hostname"]:
            self.pending.add(h["ip"])
            self.resolver.lookup([h["ip"]])
        self.status.setText(f"{self.scan_message} {len(self.hosts)} host(s) so far.")

    def hosts_done(self, _stderr, _code, failed):
        # Fill MACs nmap couldn't see (unprivileged scans) from the kernel's ARP cache.
        if self.current:
            macs = neighbour_macs(self.current["iface"])
            for ip, h in self.hosts.items():
                if not h["mac"] and ip in macs:
                    h["mac"] = macs[ip]
                    h["vendor"] = h["vendor"] or mac_vendor(h["mac"])
                    self.refresh_row(ip)
        if not failed:
            self.add_this_computer()
            self.apply_local_ports()
            # Flag devices never seen before, unless this is the first scan ever
            # (then everything would be "new").
            first_run = not self.devices.known_macs()
            with self.devices.batch():
                new = self.devices.record(self.hosts.values(), checked=bool(self.current))
                if self.auto_ports:
                    top = {"tcp": port_set(top_tcp_ports(100)), "udp": set()}
                    for ip, h in self.hosts.items():
                        if h["mac"]:
                            self.devices.update_ports(h["mac"], self.network_ports(ip), top)
            if self.current:
                self.online_macs = {h["mac"] for h in self.hosts.values() if h["mac"]}
            for ip, h in self.hosts.items():
                if not h["hostname"] and self.devices.get(h).get("hostname"):
                    h["hostname"] = self.devices.get(h)["hostname"]  # e.g. learned from the router
                self.refresh_row(ip)  # MACs, trust and device types are settled now
            self.history_path = save_history(self.scan_record()) if self.hosts else None
            self.refresh_devices()
            if not first_run and self.current:
                self.new_devices = set(new)
                for ip, h in self.hosts.items():
                    if h["mac"] in self.new_devices:
                        self.set_change(self.row_for_ip(ip), "NEW DEVICE")
        self.table.setSortingEnabled(True)
        self.table.sortItems(COL_IP)
        self.table.resizeColumnsToContents()
        self.update_controls()
        if failed:
            return

        n = len(self.hosts)
        self.summary = f"Found {n} host(s) in {max(self.elapsed, 1)}s."
        if n <= 1:
            self.summary += " Few results? If you use a VPN (e.g. Mullvad), enable Local Network Sharing."
            if IS_MAC:
                self.summary += (" Also allow NetScan under System Settings › Privacy & Security"
                                 " › Local Network.")
        if not self.used_root:
            self.summary += " Unprivileged scan: some devices may be missed."
        if self.auto_ports:
            total = sum(len(p) for ip, p in self.ports.items() if ip != self.local_ip())
            self.summary += f" {total} open port(s) in the top 100."
        elif n:
            self.summary += " Select hosts and press Scan Ports to check for services."
        self.summary += self.os_summary(self.hosts)
        self.summary += self.this_computer_summary(self.hosts)
        self.summary += self.risk_summary(self.hosts)
        if self.new_devices:
            self.summary += f" {len(self.new_devices)} device(s) never seen before."
        self.update_status()

    def update_status(self):
        extra = f" Looking up {len(self.pending)} name(s)…" if self.pending else ""
        self.status.setText(self.summary + extra)

    # ---- table helpers -----------------------------------------------------

    def add_row(self, h):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.ip_items[h["ip"]] = IPItem(h["ip"])
        self.table.setItem(row, COL_IP, self.ip_items[h["ip"]])
        for col in range(1, len(COLUMNS)):
            self.table.setItem(row, col, QTableWidgetItem(""))
        for col in (COL_IP, COL_MAC):
            self.table.item(row, col).setFont(self.mono)
        bold = QFont()
        bold.setBold(True)
        self.table.item(row, COL_NAME).setFont(bold)
        self.refresh_row(h["ip"], row)

    def refresh_row(self, ip, row=None):
        row = self.row_for_ip(ip) if row is None else row
        if row is None:
            return
        h = self.hosts[ip]
        rec = self.devices.get(h)
        ip_item = self.table.item(row, COL_IP)
        kind, guessed = self.devices.device_type(h, self.ports.get(ip), self.gateway())
        ip_item.setIcon(self.type_icon(kind))
        tips = [DEVICE_TYPES[kind] + (" (guessed)" if guessed else "")]
        untrusted = (bool(h["mac"]) and h["vendor"] != "(this computer)" and not rec.get("trusted")
                     and self.devices.any_trusted())
        if untrusted:
            tips.append("Not marked as trusted")
        ip_item.setForeground(QColor(AMBER if untrusted else TEXT))
        ip_item.setToolTip("\n".join(tips))
        self.table.item(row, COL_NAME).setText(rec.get("nickname", ""))
        self.table.item(row, COL_HOST).setText(h["hostname"])
        self.table.item(row, COL_OS).setText(h.get("os", ""))
        if h.get("os"):
            self.table.setColumnHidden(COL_OS, False)
        self.table.item(row, COL_MAC).setText(h["mac"])
        vendor = self.table.item(row, COL_VENDOR)
        vendor.setText(h["vendor"])
        # "(this computer)", "(private/randomised MAC)": notes rather than real vendors
        vendor.setForeground(QColor(ACCENT_HI if h["vendor"] == "(this computer)" else
                                    MUTED if h["vendor"].startswith("(") else TEXT))
        ports = self.table.item(row, COL_PORTS)
        bad = risky(self.ports.get(ip))
        text = summarize_ports(self.ports.get(ip))
        reachable = self.network_ports(ip)
        if ip == self.local_ip() and ip in self.ports:  # reachable vs localhost-only
            local_only = sum(1 for p in self.ports[ip] if p.get("local_only") and not p.get("temporary"))
            text = (summarize_ports(reachable) if reachable else "none reachable from the network") \
                + (f"  · +{local_only} local-only" if local_only else "")
        ports.setText(("⚠ " if bad else "") + text)
        ports.setForeground(QColor(AMBER if bad else GREEN if reachable else MUTED))
        ports.setToolTip("\n".join(f"{port_label(p)}: {port_risk(p)}" for p in bad))
        self.apply_filter_row(row)

    def gateway(self):
        return self.current.get("gateway") if self.current else None

    def type_icon(self, kind):
        key = (THEME, kind)
        if key not in self._icons:
            self._icons[key] = QIcon(icon_path("type-" + kind))
        return self._icons[key]

    def set_change(self, row, text):
        """Fill the Change column (compare results, new devices) and make sure it's showing."""
        if row is None:
            return
        item = self.table.item(row, COL_CHANGE)
        item.setText(text)
        font = QFont()
        font.setBold(bool(text))
        item.setFont(font)
        item.setForeground(QColor(GREEN if text.startswith("NEW") else
                                  RED if text.startswith("−") else AMBER))
        if text:
            self.table.setColumnHidden(COL_CHANGE, False)
            self.table.resizeColumnToContents(COL_CHANGE)

    def row_for_ip(self, ip):
        item = self.ip_items.get(ip)
        return item.row() if item is not None else None

    def on_resolved(self, ip, name):
        if ip not in self.pending:
            return  # stale result from a previous scan
        self.pending.discard(ip)
        if name and ip in self.hosts:
            self.hosts[ip]["hostname"] = name
            self.devices.update(self.hosts[ip], hostname=name)
            self.refresh_row(ip)
            self.table.resizeColumnToContents(COL_HOST)
        if not self.is_running():
            self.update_status()

    def apply_filter(self):
        for row in range(self.table.rowCount()):
            self.apply_filter_row(row)
        self.update_count()

    def apply_filter_row(self, row):
        text = self.filter_edit.text().strip().lower()
        ip = self.table.item(row, COL_IP).text()
        visible = True
        if text:
            visible = any(text in (self.table.item(row, c).text().lower())
                          for c in range(len(COLUMNS)))
        if visible and self.open_only_box.isChecked():
            visible = bool(self.ports.get(ip))
        self.table.setRowHidden(row, not visible)
        self.count_timer.start()

    def update_count(self):
        total = self.table.rowCount()
        shown = sum(not self.table.isRowHidden(r) for r in range(total))
        self.count_label.setText(f"{shown} of {total} shown" if shown != total else f"{total} host(s)")

    def visible_ips(self):
        return [self.table.item(r, COL_IP).text() for r in range(self.table.rowCount())
                if not self.table.isRowHidden(r)]

    def selected_ips(self):
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        return [self.table.item(r, COL_IP).text() for r in rows if not self.table.isRowHidden(r)]

    # ---- port scanning -----------------------------------------------------

    def port_args(self):
        """nmap args for the chosen port profile, or None if the input is invalid."""
        idx = self.profile.currentIndex()
        if idx == CUSTOM_PROFILE:
            tcp = self.custom_ports.text().replace(" ", "")
            if not valid_port_list(tcp):
                QMessageBox.warning(self, "NetScan",
                                    "Enter ports like 22,80,443 or ranges like 8000-8100.")
                return None
        else:
            tcp = top_tcp_ports(PORT_PROFILES[idx][1])
        self.scanned = {"tcp": port_set(tcp), "udp": set()}
        if self.udp_box.isChecked() and self.udp_box.isEnabled():
            self.scanned["udp"] = port_set(UDP_PORTS)
            return ["-sS", "-sU", "-p", f"T:{tcp},U:{UDP_PORTS}"]
        return ["-p", tcp]

    def start_port_scan(self, ips=None):
        ips = ips or self.selected_ips() or self.visible_ips()
        if not ips:
            return
        args = self.port_args()
        if args is None:
            return
        me = self.local_ip()
        others = [ip for ip in ips if ip != me]
        if not others:  # only this computer: read its ports from the OS, no nmap needed
            self.apply_local_ports()
            self.show_port_details()
            self.summary = ("This computer's ports come from its own list of listening sockets."
                            + self.this_computer_summary([me]))
            self.update_status()
            return
        if self.profile.currentIndex() == 2 and len(others) > 3:
            answer = QMessageBox.question(
                self, "NetScan",
                f"Scanning all 65535 ports on {len(others)} hosts can take a long time. Continue?")
            if answer != QMessageBox.Yes:
                return

        self.scan_ips = ips
        self.reported = set()
        for ip in ips:
            row = self.row_for_ip(ip)
            if row is not None:
                self.table.item(row, COL_PORTS).setText("scanning…")
                self.table.item(row, COL_PORTS).setForeground(QColor(ACCENT_HI))

        # -Pn: hosts are already known to be up, skip re-pinging them.
        args = ["-Pn", "--open", *args]
        if self.version_box.isChecked():
            args.append("-sV")
        args += self.os_args()
        args += iface_args(self.current) + others
        what = f"{len(others)} host(s)" if len(others) > 1 else others[0]
        label = self.profile.currentText().removesuffix("…").split(" (")[0].lower()
        self.run_nmap(args, f"Scanning {label} on {what}…", self.ports_found, self.ports_done)

    def ports_found(self, elem):
        ip = next((a.get("addr") for a in elem.findall("address")
                   if a.get("addrtype") == "ipv4"), None)
        if ip not in self.hosts:
            return
        self.reported.add(ip)
        self.ports[ip] = merge_ports(self.ports.get(ip), parse_ports(elem), self.scanned)
        os_guess = parse_os(elem)
        if os_guess:
            self.hosts[ip]["os"] = os_guess
            self.devices.update(self.hosts[ip], os=os_guess)
        self.refresh_row(ip)
        if self.selected_ips() == [ip]:
            self.show_port_details()

    def ports_done(self, _stderr, _code, failed):
        for ip in self.scan_ips:
            if ip not in self.reported:
                if failed:
                    self.refresh_row(ip)  # restore previous value
                    continue
                # --open omits hosts without open ports
                self.ports[ip] = merge_ports(self.ports.get(ip), [], self.scanned)
                self.refresh_row(ip)
        self.table.resizeColumnToContents(COL_PORTS)
        self.show_port_details()
        if failed:
            return
        if self.local_ip() in self.scan_ips:
            self.apply_local_ports()
        total = sum(len(self.ports.get(ip, [])) for ip in self.scan_ips if ip != self.local_ip())
        mode = "SYN" if self.used_root else "TCP connect"
        self.summary = (f"Port scan done in {max(self.elapsed, 1)}s ({mode}): "
                        f"{total} open port(s) on {len(self.scan_ips)} host(s).")
        self.summary += self.os_summary({ip: self.hosts[ip] for ip in self.scan_ips if ip in self.hosts})
        self.summary += self.this_computer_summary(self.scan_ips)
        self.summary += self.risk_summary(self.scan_ips)
        with self.devices.batch():
            for ip in self.scan_ips:
                h = self.hosts.get(ip)
                if h and h["mac"]:
                    self.devices.update_ports(h["mac"], self.network_ports(ip), self.scanned)
        for ip in self.scan_ips:
            if ip in self.hosts:
                self.refresh_row(ip)
        if self.history_path:
            save_history(self.scan_record(), self.history_path)
        self.refresh_devices()
        self.update_status()

    # ---- this computer ------------------------------------------------------

    def local_ip(self):
        return self.current["local_ip"] if self.current else None

    def network_ports(self, ip):
        """Open ports other machines can reach (drops this computer's localhost-only ones and
        temporary sockets, which change every run)."""
        return [p for p in self.ports.get(ip) or [] if not (p.get("local_only") or p.get("temporary"))]

    def this_computer_summary(self, ips):
        me = self.local_ip()
        if me not in ips or me not in self.ports:
            return ""
        return f" This computer: {len(self.network_ports(me))} port(s) reachable from the network."

    def add_this_computer(self):
        """List this computer even if nmap didn't report it, when its IP is inside the scanned range."""
        ip, net = self.local_ip(), self.current
        if not ip or ip in self.hosts:
            return
        addr = ipaddress.ip_address(ip)
        inside = False
        for t in self.last_target.split():
            try:
                inside = inside or addr in ipaddress.ip_network(t, strict=False)
            except ValueError:
                pass  # ranges like 10.0.0.1-50: leave it to nmap
        if not inside:
            return
        h = {"ip": ip, "hostname": socket.gethostname(), "mac": net["mac"], "vendor": "(this computer)",
             "os": ""}
        self.hosts[ip] = h
        self.add_row(h)

    def apply_local_ports(self):
        """This computer's ports straight from the OS: complete, and including localhost-only ones."""
        ip = self.local_ip()
        if ip not in self.hosts:
            return
        self.ports[ip] = local_open_ports(local_listeners())
        self.hosts[ip]["os"] = self.hosts[ip].get("os") or this_os_name()
        self.refresh_row(ip)

    def risk_summary(self, ips):
        bad = {ip: risky(self.ports.get(ip)) for ip in ips}
        bad = {ip: r for ip, r in bad.items() if r}
        if not bad:
            return ""
        return f" ⚠ {sum(len(r) for r in bad.values())} risky port(s) on {len(bad)} host(s)."

    def os_args(self):
        if not (self.os_box.isChecked() and self.os_box.isEnabled()):
            return []
        # --osscan-limit: skip hosts without an open and a closed port, where guesses are poor.
        return ["-O", "--osscan-limit"]

    def os_summary(self, hosts):
        if not self.os_args():
            return ""
        guessed = sum(1 for h in hosts.values() if h.get("os"))
        return f" OS identified for {guessed} of {len(hosts)}."

    def show_port_details(self):
        ips = self.selected_ips()
        self.details.setRowCount(0)
        if len(ips) != 1:
            self.details_label.setText("Select a host to see its open ports.")
            return
        ip = ips[0]
        h = self.hosts.get(ip, {})
        kind = self.devices.device_type(h, self.ports.get(ip), self.gateway())[0] if h else "unknown"
        who = " · ".join(x for x in (self.devices.nickname(h) if h else "", ip, DEVICE_TYPES[kind],
                                     h.get("os", "")) if x)
        if ip not in self.ports:
            self.details_label.setText(f"{who}: not port-scanned yet.")
            return
        ports = self.ports[ip]
        local = ip == self.local_ip()
        if local:
            reachable = len(self.network_ports(ip))
            temporary = sum(1 for p in ports if p.get("temporary"))
            self.details_label.setText(f"{who}: {reachable} reachable from the network, "
                                       f"{len(ports) - reachable - temporary} local-only, {temporary} temporary "
                                       "(from this computer's own list)")
        else:
            self.details_label.setText(f"{who}: {len(ports)} open port(s)")
        for p in ports:
            row = self.details.rowCount()
            self.details.insertRow(row)
            port_item = QTableWidgetItem()
            port_item.setData(Qt.DisplayRole, p["port"])
            self.details.setItem(row, 0, port_item)
            self.details.setItem(row, 1, QTableWidgetItem(p["proto"]))
            self.details.setItem(row, 2, QTableWidgetItem(p["service"]))
            self.details.setItem(row, 3, QTableWidgetItem(p["version"]))
            if port_risk(p):
                note = QTableWidgetItem("⚠ " + port_risk(p))
                note.setForeground(QColor(AMBER))
            elif local:
                note = QTableWidgetItem("Temporary socket for the program's own traffic" if p.get("temporary")
                                        else "Only this computer (localhost)" if p.get("local_only")
                                        else "Reachable from your network")
                note.setForeground(QColor(TEXT if not (p.get("local_only") or p.get("temporary")) else MUTED))
            else:
                note = QTableWidgetItem("")
            self.details.setItem(row, 4, note)
            if port_risk(p):
                port_item.setForeground(QColor(AMBER))
        self.details.resizeColumnsToContents()

    # ---- context menu ------------------------------------------------------

    def show_context_menu(self, pos):
        ips = self.selected_ips()
        if not ips:
            return
        menu = QMenu(self)
        menu.addAction(self.copy_act)
        menu.addAction("Copy IP address" + ("es" if len(ips) > 1 else ""),
                       lambda: QGuiApplication.clipboard().setText("\n".join(ips)))
        menu.addSeparator()
        scan = menu.addAction(f"Scan ports on {'this host' if len(ips) == 1 else f'{len(ips)} hosts'}",
                              lambda: self.start_port_scan(ips))
        scan.setEnabled(not self.is_running())
        if len(ips) == 1:
            ip = ips[0]
            h = self.hosts[ip]
            menu.addAction("Rename…" if self.devices.nickname(h) else "Set nickname…",
                           lambda: self.edit_nickname(ip))
            if h["mac"]:
                trusted = self.devices.get(h).get("trusted")
                menu.addAction("Unmark as trusted" if trusted else "Mark as trusted",
                               lambda: self.set_trusted([h["mac"]], not trusted))
            if h["mac"] and not (self.current and ip == self.current["local_ip"]):
                menu.addAction("Wake-on-LAN", lambda: self.wake(h["mac"], self.devices.nickname(h)
                                                                  or h["hostname"] or ip))
            menu.addSeparator()
            open_ports = {p["port"] for p in self.ports.get(ip, []) if p["proto"] == "tcp"}
            if open_ports & {139, 445}:
                menu.addAction("Open file share (SMB)", lambda: self.open_service("smb", ip))
            if 3389 in open_ports:
                menu.addAction("Remote Desktop (RDP)", lambda: self.open_service("rdp", ip))
            vnc = next((port for port in (5900, 5901, 5902) if port in open_ports), None)
            if vnc:
                menu.addAction("VNC remote desktop", lambda: self.open_service("vnc", ip, vnc))
            if 22 in open_ports:
                menu.addAction("Copy ssh command", lambda: self.copy_ssh(h))
            if ip == self.gateway():
                act = menu.addAction("Get device names from router (SSH)", lambda: self.fetch_router_names(h))
                act.setEnabled(not (self.router_proc and self.router_proc.state() != QProcess.NotRunning))
            web = next(((port, scheme) for port, scheme in WEB_PORTS if port in open_ports), None)
            if web:
                port, scheme = web
                default = 443 if scheme == "https" else 80
                url = f"{scheme}://{ip}" + ("" if port == default else f":{port}")
                menu.addAction(f"Open {url}", lambda: QDesktopServices.openUrl(QUrl(url)))
            else:
                menu.addAction(f"Open http://{ip}",
                               lambda: QDesktopServices.openUrl(QUrl(f"http://{ip}")))
            ping = terminal_argv(["ping", ip])
            if ping:
                if 22 in open_ports or ip not in self.ports:
                    user = self.devices.get(h).get("ssh_user")
                    menu.addAction(f"SSH to {user}@{ip}" if user else f"SSH to {ip}…", lambda: self.ssh_to(h))
                    if user:
                        menu.addAction("Change SSH user…", lambda: self.ssh_target(h, change=True))
                menu.addAction(f"Ping {ip} in terminal",
                               lambda: QProcess.startDetached(ping[0], ping[1:]))
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def ssh_target(self, host, change=False):
        """'user@ip' for this device, asking for (and remembering) the username the first time.

        Without a username ssh uses this computer's login name, which rarely matches the
        account on other machines. Returns None if cancelled.
        """
        user = self.devices.get(host).get("ssh_user", "")
        if not user or change:
            who = self.devices.nickname(host) or host.get("hostname") or host["ip"]
            while True:
                name, ok = QInputDialog.getText(
                    self, "SSH username", f"Username to log in to {who} with:",
                    text=user or getpass.getuser())
                if not ok:
                    return None
                name = name.strip()
                if valid_ssh_user(name):
                    break
                QMessageBox.warning(self, "NetScan", "Usernames can only contain letters, digits, "
                                    "'.', '_' and '-', and can't start with '-'.")
            user = name
            self.devices.set_field(host, "ssh_user", user)
            self.show_device_details()
        return f"{user}@{host['ip']}"

    def fetch_router_names(self, router):
        """Read the router's DHCP lease list over SSH (read-only) and name devices that have no name."""
        ssh = find_program("ssh")
        if not ssh:
            self.status.setText("ssh not found; install OpenSSH to read names from the router.")
            return
        target = self.ssh_target(router)  # asks for the router's username the first time
        if not target:
            return
        env = QProcessEnvironment.systemEnvironment()
        env.insert("SSH_ASKPASS", askpass_helper())
        env.insert("SSH_ASKPASS_REQUIRE", "force")  # always use the dialog, even from a terminal
        self.router_proc = proc = QProcess(self)
        proc.setProcessEnvironment(env)
        proc.setStandardInputFile(QProcess.nullDevice())
        proc.finished.connect(lambda code, _s: self.router_names_done(proc, code))
        self.set_dot(ACCENT)
        self.status.setText(f"Reading the device list from the router ({target})… "
                            "Enter the router's password if asked.")
        # StrictHostKeyChecking=yes: only a router whose key you've already accepted in a terminal.
        proc.start(ssh, ["-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
                         "-o", "NumberOfPasswordPrompts=2", target, ROUTER_LEASE_CMD])
        QTimer.singleShot(120_000, lambda: proc.state() != QProcess.NotRunning and proc.kill())

    def router_names_done(self, proc, code):
        out = bytes(proc.readAllStandardOutput()).decode(errors="replace")
        err = bytes(proc.readAllStandardError()).decode(errors="replace")
        leases = parse_dnsmasq_leases(out)
        if code != 0 or not leases:
            self.set_dot(AMBER)
            if "Host key verification failed" in err or "No ED25519 host key" in err or "host key" in err.lower():
                msg = ("The router's SSH key isn't known on this computer (or it changed). "
                       f"Connect once from a terminal (ssh {self.ssh_target_text()}) to check and accept it, "
                       "then try again.")
            elif "Permission denied" in err:
                msg = "Router login failed: wrong username or password."
            elif code == 0:
                msg = "Logged in to the router, but it has no dnsmasq lease list (/tmp/dhcp.leases)."
            else:
                last = [l for l in err.splitlines() if l.strip() and not l.startswith("**")]
                msg = "Couldn't read the router's device list: " + (last[-1] if last else f"ssh exit code {code}")
            self.status.setText(msg)
            return
        named = 0
        by_ip = {lease_ip: name for lease_ip, name in leases.values()}
        with self.devices.batch():
            for ip, h in self.hosts.items():
                # Match by MAC; fall back to IP only for hosts whose MAC we don't know.
                name = leases[h["mac"]][1] if h["mac"] in leases else ("" if h["mac"] else by_ip.get(ip, ""))
                if name and not h["hostname"]:
                    h["hostname"] = name
                    self.pending.discard(ip)
                    self.devices.update(h, hostname=name)
                    self.refresh_row(ip)
                    named += 1
            for mac, (_ip, name) in leases.items():  # devices remembered but not in this scan
                rec = self.devices.devices.get(mac)
                if name and rec is not None and not rec.get("hostname"):
                    rec["hostname"] = name
                    self.devices.save()
        self.table.resizeColumnToContents(COL_HOST)
        self.refresh_devices()
        self.set_dot(GREEN)
        self.status.setText(f"Router: {len(leases)} device(s) in its DHCP list, "
                            f"{sum(1 for _, n in leases.values() if n)} with names; "
                            f"named {named} device(s) that had no name.")

    def ssh_target_text(self):
        gw = self.gateway()
        h = self.hosts.get(gw, {"ip": gw or "router"})
        user = self.devices.get(h).get("ssh_user") if gw in self.hosts else ""
        return f"{user}@{h['ip']}" if user else h["ip"]

    def ssh_to(self, host):
        target = self.ssh_target(host)
        argv = terminal_argv(["ssh", target]) if target else None
        if argv:
            QProcess.startDetached(argv[0], argv[1:])
            self.status.setText(f"Opened ssh {target} in a terminal.")

    def copy_ssh(self, host):
        target = self.ssh_target(host)
        if target:
            QGuiApplication.clipboard().setText(f"ssh {target}")
            self.status.setText(f"Copied: ssh {target}")

    def open_service(self, kind, ip, port=None):
        """Open a file share, RDP or VNC session with whatever app this system has for it."""
        argv, url = None, None
        if kind == "smb":
            url = f"smb://{ip}/"
            if IS_WIN:
                argv = ["explorer.exe", f"\\\\{ip}"]
            elif not IS_MAC:
                # Many desktops set no default smb:// handler, so ask a file manager directly.
                fm = next((f for f in ("dolphin", "nautilus", "nemo", "thunar", "caja", "pcmanfm")
                           if shutil.which(f)), None)
                argv = [fm, url] if fm else None
        elif kind == "rdp":
            if IS_WIN:
                argv = ["mstsc.exe", f"/v:{ip}"]
            elif not IS_MAC:
                for prog, args in (("xfreerdp3", [f"/v:{ip}", "/dynamic-resolution"]),
                                   ("xfreerdp", [f"/v:{ip}", "/dynamic-resolution"]),
                                   ("remmina", ["-c", f"rdp://{ip}"]), ("krdc", [f"rdp://{ip}"])):
                    if shutil.which(prog):
                        argv = [prog, *args]
                        break
            url = f"rdp://full%20address=s:{ip}" if IS_MAC else f"rdp://{ip}"
        elif kind == "vnc":
            if not IS_MAC and not IS_WIN:
                for prog, args in (("remmina", ["-c", f"vnc://{ip}:{port}"]), ("krdc", [f"vnc://{ip}:{port}"]),
                                   ("vncviewer", [f"{ip}::{port}"])):
                    if shutil.which(prog):
                        argv = [prog, *args]
                        break
            url = f"vnc://{ip}:{port}"
        ok = QProcess.startDetached(argv[0], argv[1:]) if argv else QDesktopServices.openUrl(QUrl(url))
        if isinstance(ok, tuple):
            ok = ok[0]
        if not ok:
            app = {"smb": "a file manager that supports smb://", "rdp": "Remmina or FreeRDP",
                   "vnc": "Remmina, KRDC or a VNC viewer"}[kind]
            self.set_dot(AMBER)
            self.status.setText(f"No app found to open {kind.upper()} on {ip}. Install {app}.")

    def set_trusted(self, macs, trusted):
        with self.devices.batch():
            for mac in macs:
                rec = self.devices.devices.get(mac)
                if rec is not None:
                    self.devices.set_field(rec, "trusted", trusted)
        # Trusting the first device changes how every untrusted row looks.
        for ip in self.hosts:
            self.refresh_row(ip)
        self.refresh_devices()

    # ---- nicknames / wake-on-lan -------------------------------------------

    def shortcut_scan(self):
        if self.tabbar.currentIndex() == 0 and self.scan_btn.isEnabled():
            self.start_scan()

    def rename_selected(self):
        ips = self.selected_ips()
        if len(ips) == 1:
            self.edit_nickname(ips[0])

    def edit_nickname(self, ip):
        h = self.hosts.get(ip)
        if h is None:
            return
        name = self.ask_nickname(h["hostname"] or ip, h["mac"], self.devices.nickname(h))
        if name is None:
            return
        self.devices.set_nickname(h, name)
        self.refresh_row(ip)  # hosts without a MAC are keyed by IP, so refresh this row directly
        self.after_device_change(h["mac"])

    def broadcasts(self):
        return [str(n["network"].broadcast_address) for n in self.networks] + ["255.255.255.255"]

    def wake(self, mac, label=""):
        sent = wake_on_lan(mac, self.broadcasts())
        who = f"{label} ({mac})" if label else mac
        if sent:
            self.set_dot(GREEN)
            self.status.setText(f"Sent Wake-on-LAN packet to {who}. It may take a minute to come up.")
        else:
            self.set_dot(RED)
            self.status.setText(f"Could not send Wake-on-LAN packet to {who}.")

    def ask_nickname(self, who, mac, current):
        """Nickname prompt; returns the new name ('' removes it) or None if cancelled."""
        name, ok = QInputDialog.getText(
            self, "Nickname", f"Nickname for {who}" + (f"  ({mac})" if mac else "")
            + "\nLeave empty to remove it.", text=current)
        return name.strip() if ok else None

    def switch_page(self, index):
        self.pages.setCurrentIndex(index)
        for w in (self.compare_btn, self.export_btn):
            w.setVisible(index == 0)
        if index == 1:
            self.refresh_devices()

    def focus_filter(self):
        edit = self.filter_edit if self.tabbar.currentIndex() == 0 else self.dev_filter
        edit.setFocus()
        edit.selectAll()

    # ---- devices tab -------------------------------------------------------

    def build_devices_page(self):
        # Watch card: background re-scans that notify about new devices and port changes
        self.watch_combo = QComboBox()
        for label, _ in WATCH_INTERVALS:
            self.watch_combo.addItem(label)
        self.watch_label = QLabel("Off")
        self.watch_label.setObjectName("muted")
        self.watch_now_btn = QPushButton("Check now")
        self.watch_now_btn.clicked.connect(self.watch_scan)
        self.watch_ports_box = QCheckBox("Also alert on port changes")
        self.watch_ports_box.setToolTip("Each check also scans the top 100 ports and notifies you when a "
                                        "known device opens or closes one. Takes a few seconds longer.")
        hint = QLabel("Quietly re-checks your network and sends a desktop notification when a "
                      "device NetScan has never seen joins. No password needed; runs while NetScan is open.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        watch, wl, _ = make_card("Watch for new devices")
        row = QHBoxLayout()
        row.addWidget(self.watch_combo)
        row.addWidget(self.watch_now_btn)
        row.addSpacing(8)
        row.addWidget(self.watch_ports_box)
        row.addStretch(1)
        wl.addLayout(row)
        wl.addWidget(self.watch_label)
        wl.addWidget(hint)

        # Wake-any-MAC card, for devices NetScan has never seen
        self.mac_edit = QLineEdit()
        self.mac_edit.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        self.mac_edit.returnPressed.connect(self.wake_typed_mac)
        mac_btn = QPushButton("Wake")
        mac_btn.setObjectName("primary")
        mac_btn.clicked.connect(self.wake_typed_mac)
        hint = QLabel("For a device not in the list. It needs Wake-on-LAN enabled in its "
                      "BIOS or network settings.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        wake_any, al, _ = make_card("Wake by MAC address")
        row = QHBoxLayout()
        row.addWidget(self.mac_edit, 1)
        row.addWidget(mac_btn)
        al.addLayout(row)
        al.addWidget(hint)
        al.addStretch(1)

        # Known devices card
        self.dev_count = QLabel("")
        self.dev_count.setObjectName("pill")
        self.dev_filter = QLineEdit()
        self.dev_filter.setPlaceholderText("Filter by name, type, MAC, vendor, IP…")
        self.dev_filter.setClearButtonEnabled(True)
        self.dev_search_act = self.dev_filter.addAction(QIcon(icon_path("search")), QLineEdit.LeadingPosition)
        self.dev_filter.setMaximumWidth(380)
        self.dev_filter.textChanged.connect(self.filter_devices)
        self.dev_show = QComboBox()
        for label in ("All devices", "Online now", "Untrusted", "With risky ports"):
            self.dev_show.addItem(label)
        self.dev_show.currentIndexChanged.connect(self.filter_devices)

        self.dev_table = QTableWidget(0, len(DEV_COLUMNS))
        self.dev_table.setHorizontalHeaderLabels([c.upper() for c in DEV_COLUMNS])
        self.dev_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.dev_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.dev_table.setAlternatingRowColors(True)
        self.dev_table.setShowGrid(False)
        self.dev_table.verticalHeader().setVisible(False)
        self.dev_table.verticalHeader().setDefaultSectionSize(34)
        header = self.dev_table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setHighlightSections(False)
        header.setStretchLastSection(True)
        header.setSortIndicator(DEV_STATUS, Qt.AscendingOrder)  # online devices first
        self.dev_table.setSortingEnabled(True)
        self.dev_table.itemSelectionChanged.connect(self.device_selection_changed)
        self.dev_table.itemDoubleClicked.connect(lambda _item: self.rename_device())
        self.dev_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.dev_table.customContextMenuRequested.connect(self.device_menu)

        self.dev_wake_btn = QPushButton("Wake")
        self.dev_wake_btn.setObjectName("primary")
        self.dev_wake_btn.setToolTip("Send a Wake-on-LAN packet to the selected device(s)")
        self.dev_wake_btn.clicked.connect(self.wake_selected_devices)
        self.dev_rename_btn = QPushButton("Rename…")
        self.dev_rename_btn.clicked.connect(self.rename_device)
        self.dev_forget_btn = QPushButton("Forget")
        self.dev_forget_btn.setToolTip("Remove from the list; it will count as new if seen again")
        self.dev_forget_btn.clicked.connect(self.forget_devices)

        known, kl, kh = make_card("Known devices")
        kh.addWidget(self.dev_count)
        kh.addStretch(1)
        kh.addWidget(self.dev_show)
        kh.addWidget(self.dev_filter, 1)
        kl.addWidget(self.dev_table, 1)
        row = QHBoxLayout()
        row.addWidget(self.dev_wake_btn)
        row.addWidget(self.dev_rename_btn)
        row.addWidget(self.dev_forget_btn)
        row.addStretch(1)
        tip = QLabel("Double-click to rename")
        tip.setObjectName("muted")
        row.addWidget(tip)
        kl.addLayout(row)

        self.dev_split = QSplitter(Qt.Horizontal)
        self.dev_split.setHandleWidth(12)
        self.dev_split.addWidget(known)
        self.dev_split.addWidget(self.build_device_details())
        self.dev_split.setStretchFactor(0, 3)
        self.dev_split.setStretchFactor(1, 2)
        self.dev_split.setSizes([700, 380])

        top = QHBoxLayout()
        top.setSpacing(12)
        top.addWidget(watch, 3)
        top.addWidget(wake_any, 2)
        page = QWidget()
        pl = QVBoxLayout(page)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.setSpacing(12)
        pl.addLayout(top)
        pl.addWidget(self.dev_split, 1)
        self.update_device_buttons()
        return page

    def build_device_details(self):
        """Right-hand panel: everything known about the selected device, plus notes."""
        card, cl, _ = make_card("Device details")
        self.detail_stack = QStackedWidget()
        empty = QLabel("Select a device to see its details, online history and notes.")
        empty.setObjectName("muted")
        empty.setWordWrap(True)
        empty.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.detail_stack.addWidget(empty)

        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(0, 0, 6, 0)
        bl.setSpacing(10)
        self.detail_icon = QLabel()
        self.detail_name = QLabel()
        self.detail_name.setObjectName("bigName")
        self.detail_name.setWordWrap(True)
        self.detail_sub = QLabel()
        self.detail_sub.setObjectName("muted")
        self.detail_sub.setWordWrap(True)
        names = QVBoxLayout()
        names.setSpacing(0)
        names.addWidget(self.detail_name)
        names.addWidget(self.detail_sub)
        head = QHBoxLayout()
        head.addWidget(self.detail_icon, 0, Qt.AlignTop)
        head.addLayout(names, 1)
        bl.addLayout(head)

        self.detail_type = QComboBox()
        self.detail_type.addItem("Auto", "")
        for key, label in DEVICE_TYPES.items():
            if key != "unknown":
                self.detail_type.addItem(QIcon(icon_path("type-" + key)), label, key)
        self.detail_type.currentIndexChanged.connect(self.detail_type_changed)
        self.detail_trusted = QCheckBox("Trusted")
        self.detail_trusted.setToolTip("Once any device is trusted, untrusted ones are highlighted "
                                       "on the Scan tab and can be filtered here.")
        self.detail_trusted.toggled.connect(self.detail_trusted_changed)
        row = QHBoxLayout()
        row.addWidget(self.field_label("Type"))
        row.addWidget(self.detail_type, 1)
        row.addSpacing(8)
        row.addWidget(self.detail_trusted)
        bl.addLayout(row)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(6)
        self.detail_fields = {}
        for i, name in enumerate(("First seen", "Last seen", "IP addresses", "OS", "Open ports")):
            value = QLabel()
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid.addWidget(self.field_label(name), i, 0, Qt.AlignTop)
            grid.addWidget(value, i, 1)
            self.detail_fields[name] = value
        grid.setColumnStretch(1, 1)
        bl.addLayout(grid)

        bl.addWidget(self.field_label("Online, last 7 days"))
        self.detail_grid = HistoryGrid()
        bl.addWidget(self.detail_grid)
        self.detail_legend = QLabel()
        self.detail_legend.setObjectName("muted")
        bl.addWidget(self.detail_legend)

        bl.addWidget(self.field_label("Port changes"))
        self.detail_changes = QLabel()
        self.detail_changes.setWordWrap(True)
        self.detail_changes.setTextInteractionFlags(Qt.TextSelectableByMouse)
        bl.addWidget(self.detail_changes)

        self.detail_ssh = QLineEdit()
        self.detail_ssh.setPlaceholderText(f"{getpass.getuser()} (this computer's username)")
        self.detail_ssh.setToolTip("Username for NetScan's SSH actions on this device")
        self.detail_ssh.editingFinished.connect(self.save_ssh_user)
        row = QHBoxLayout()
        row.addWidget(self.field_label("SSH user"))
        row.addWidget(self.detail_ssh, 1)
        bl.addLayout(row)

        bl.addWidget(self.field_label("Notes"))
        self.detail_notes = QPlainTextEdit()
        self.detail_notes.setPlaceholderText("Anything worth remembering: owner, location, login…")
        self.detail_notes.setFixedHeight(90)
        self.detail_notes.textChanged.connect(lambda: self.notes_timer.start())
        self.notes_timer = QTimer(self)
        self.notes_timer.setSingleShot(True)
        self.notes_timer.setInterval(600)
        self.notes_timer.timeout.connect(self.save_notes)
        bl.addWidget(self.detail_notes)
        bl.addStretch(1)

        scroll = QScrollArea()
        scroll.setObjectName("plain")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(body)
        self.detail_stack.addWidget(scroll)
        cl.addWidget(self.detail_stack, 1)
        self.detail_mac = None
        return card

    @staticmethod
    def field_label(text):
        label = QLabel(text.upper())
        label.setObjectName("fieldLabel")
        return label

    def device_selection_changed(self):
        self.update_device_buttons()
        self.show_device_details()

    def show_device_details(self):
        macs = self.selected_device_macs()
        if len(macs) != 1 or macs[0] not in self.devices.devices:
            self.save_notes()
            self.save_ssh_user()
            self.detail_mac = None
            self.detail_stack.setCurrentIndex(0)
            return
        mac = macs[0]
        if mac != self.detail_mac:
            self.save_notes()  # flush edits to the previous device
            self.save_ssh_user()
        same = mac == self.detail_mac
        self.detail_mac = mac
        d = self.devices.devices[mac]
        kind, guessed = self.devices.device_type(d, gateway=self.gateway())
        online = mac in self.online_macs
        self.detail_icon.setPixmap(self.type_icon(kind).pixmap(28, 28))
        self.detail_name.setText(d.get("nickname") or d.get("hostname") or d.get("vendor") or mac)
        self.detail_sub.setText(" · ".join(x for x in (
            d.get("hostname") if d.get("nickname") else "", d.get("vendor", ""), mac) if x))

        self.detail_type.blockSignals(True)
        self.detail_type.setItemText(0, f"Auto ({DEVICE_TYPES[guess_type(d, d.get('ports'), self.gateway())]})")
        self.detail_type.setCurrentIndex(max(0, self.detail_type.findData(d.get("type", ""))))
        self.detail_type.blockSignals(False)
        self.detail_trusted.blockSignals(True)
        self.detail_trusted.setChecked(bool(d.get("trusted")))
        self.detail_trusted.blockSignals(False)

        f = self.detail_fields
        f["First seen"].setText(self.when_text(d.get("first_seen")))
        f["Last seen"].setText(f'<span style="color:{GREEN}">Online now</span>' if online
                               else self.when_text(d.get("last_seen")))
        ips = list(reversed(d.get("ips") or [d.get("ip", "")]))
        f["IP addresses"].setText(ips[0] + (f'<br><span style="color:{MUTED}">before: '
                                            + ", ".join(ips[1:]) + "</span>" if len(ips) > 1 else ""))
        f["OS"].setText(d.get("os") or f'<span style="color:{MUTED}">not detected yet</span>')
        if not (same and self.detail_ssh.hasFocus()):
            self.detail_ssh.setText(d.get("ssh_user", ""))
        ports = d.get("ports")
        if ports is None:
            f["Open ports"].setText(f'<span style="color:{MUTED}">not port-scanned yet</span>')
        elif not ports:
            f["Open ports"].setText(f'<span style="color:{MUTED}">none open</span>')
        else:
            f["Open ports"].setText("<br>".join(
                f'<span style="color:{AMBER}">⚠ {port_label(p)}</span> '
                f'<span style="color:{MUTED}">{port_risk(p)}</span>' if port_risk(p) else port_label(p)
                for p in ports))

        self.detail_grid.set_data(d.get("hours", []), self.devices.checked_hours)
        self.detail_legend.setText(
            f'<span style="color:{GREEN}">■</span> seen &nbsp; <span style="color:{DIM}">■</span> '
            f'checked, not seen &nbsp; <span style="color:{BORDER_HI}">□</span> not checked')
        log = d.get("port_changes", [])[-6:]
        if not log:
            self.detail_changes.setText(f'<span style="color:{MUTED}">None recorded yet. Changes show up '
                                        "after this device has been port-scanned twice.</span>")
        else:
            lines = []
            for entry in reversed(log):
                parts = [f'<span style="color:{AMBER if label_risky(o) else GREEN}">'
                         f"+{o}</span>" for o in entry.get("opened", [])]
                parts += [f'<span style="color:{MUTED}">−{c}</span>' for c in entry.get("closed", [])]
                lines.append(f'<span style="color:{MUTED}">{self.when_text(entry.get("time"))}</span> '
                             + ", ".join(parts))
            self.detail_changes.setText("<br>".join(lines))
        if not (same and self.detail_notes.hasFocus()):
            self.detail_notes.blockSignals(True)
            self.detail_notes.setPlainText(d.get("notes", ""))
            self.detail_notes.blockSignals(False)
        self.detail_stack.setCurrentIndex(1)

    @staticmethod
    def when_text(iso):
        try:
            when = datetime.datetime.fromisoformat(iso)
        except (TypeError, ValueError):
            return "—"
        return f"{when:%d %b %Y, %H:%M}  ({relative_time(iso)})"

    def save_notes(self):
        self.notes_timer.stop()
        mac = self.detail_mac
        if mac and mac in self.devices.devices:
            text = self.detail_notes.toPlainText().strip()
            if text != self.devices.devices[mac].get("notes", ""):
                self.devices.set_field(self.devices.devices[mac], "notes", text)

    def save_ssh_user(self):
        if self.detail_mac not in self.devices.devices:
            return
        d = self.devices.devices[self.detail_mac]
        name = self.detail_ssh.text().strip()
        if name == d.get("ssh_user", ""):
            return
        if name and not valid_ssh_user(name):
            self.detail_ssh.setText(d.get("ssh_user", ""))
            self.set_dot(AMBER)
            self.status.setText("SSH usernames can only contain letters, digits, '.', '_' and '-'.")
            return
        self.devices.set_field(d, "ssh_user", name)
        self.status.setText(f"SSH user for {self.device_label(self.detail_mac) or self.detail_mac}: "
                            + (name or f"{getpass.getuser()} (default)"))

    def detail_type_changed(self):
        if self.detail_mac in self.devices.devices:
            self.devices.set_field(self.devices.devices[self.detail_mac], "type",
                                   self.detail_type.currentData())
            self.after_device_change(self.detail_mac)

    def detail_trusted_changed(self, on):
        if self.detail_mac:
            self.set_trusted([self.detail_mac], on)

    def refresh_devices(self):
        """Rebuild the devices table from the store, keeping the selection."""
        keep = set(self.selected_device_macs())
        t = self.dev_table
        t.blockSignals(True)
        t.setSortingEnabled(False)
        t.setRowCount(0)
        bold = QFont()
        bold.setBold(True)
        gateway = self.gateway()
        for d in (d for d in self.devices.devices.values() if d.get("mac")):
            row = t.rowCount()
            t.insertRow(row)
            online = d["mac"] in self.online_macs
            dot = SortItem("●")
            dot.setData(Qt.UserRole, "0" if online else "1")
            dot.setForeground(QColor(GREEN if online else DIM))
            dot.setTextAlignment(Qt.AlignCenter)
            dot.setToolTip("Online (seen in the latest scan)" if online else "Not seen in the latest scan")
            t.setItem(row, DEV_STATUS, dot)
            kind, guessed = self.devices.device_type(d, gateway=gateway)
            values = {DEV_NAME: d.get("nickname", ""), DEV_TYPE: DEVICE_TYPES[kind],
                      DEV_HOST: d.get("hostname", ""), DEV_MAC: d["mac"], DEV_VENDOR: d.get("vendor", "")}
            for col, text in values.items():
                t.setItem(row, col, QTableWidgetItem(text))
            t.item(row, DEV_TYPE).setIcon(self.type_icon(kind))
            t.item(row, DEV_TYPE).setToolTip("Guessed; change it in Device details" if guessed else "Set by you")
            if guessed:
                t.item(row, DEV_TYPE).setForeground(QColor(MUTED))
            t.setItem(row, DEV_IP, IPItem(d.get("ip", "")))
            trust = SortItem("✓" if d.get("trusted") else "")
            trust.setData(Qt.UserRole, "0" if d.get("trusted") else "1")
            trust.setForeground(QColor(GREEN))
            t.setItem(row, DEV_TRUST, trust)
            seen = SortItem("online now" if online else relative_time(d.get("last_seen")))
            seen.setData(Qt.UserRole, d.get("last_seen", ""))
            seen.setForeground(QColor(GREEN if online else MUTED))
            t.setItem(row, DEV_SEEN, seen)
            bad = risky(d.get("ports"))
            if bad:
                t.item(row, DEV_NAME).setToolTip("Risky ports: " + ", ".join(port_label(p) for p in bad))
                t.item(row, DEV_VENDOR).setData(Qt.UserRole + 1, True)
            t.item(row, DEV_NAME).setFont(bold)
            for col in (DEV_MAC, DEV_IP):
                t.item(row, col).setFont(self.mono)
            if d["mac"] in keep:
                t.selectRow(row)
        t.setSortingEnabled(True)  # re-sorts by the user's column (the online dot by default)
        t.resizeColumnsToContents()
        t.setColumnWidth(DEV_STATUS, 36)
        t.blockSignals(False)
        self.filter_devices()
        self.show_device_details()

    def filter_devices(self):
        text = self.dev_filter.text().strip().lower()
        show = self.dev_show.currentIndex()  # 0 all, 1 online, 2 untrusted, 3 risky
        t = self.dev_table
        shown = online = 0
        for row in range(t.rowCount()):
            is_online = t.item(row, DEV_STATUS).data(Qt.UserRole) == "0"
            online += is_online
            visible = not text or any(text in t.item(row, c).text().lower()
                                      for c in range(1, len(DEV_COLUMNS)))
            if show == 1:
                visible = visible and is_online
            elif show == 2:
                visible = visible and not t.item(row, DEV_TRUST).text()
            elif show == 3:
                visible = visible and bool(t.item(row, DEV_VENDOR).data(Qt.UserRole + 1))
            t.setRowHidden(row, not visible)
            shown += visible
        total = t.rowCount()
        self.dev_count.setText(f"{shown} of {total} shown" if shown != total
                               else f"{total} device(s) · {online} online")
        self.update_device_buttons()

    def selected_device_macs(self):
        t = self.dev_table
        rows = sorted({i.row() for i in t.selectedIndexes()})
        return [t.item(r, DEV_MAC).text() for r in rows if not t.isRowHidden(r)]

    def update_device_buttons(self):
        macs = self.selected_device_macs()
        self.dev_wake_btn.setEnabled(bool(macs))
        self.dev_rename_btn.setEnabled(len(macs) == 1)
        self.dev_forget_btn.setEnabled(bool(macs))

    def device_label(self, mac):
        d = self.devices.devices.get(mac, {})
        return d.get("nickname") or d.get("hostname") or d.get("vendor") or ""

    def wake_selected_devices(self):
        macs = self.selected_device_macs()
        if len(macs) == 1:
            self.wake(macs[0], self.device_label(macs[0]))
        elif macs:
            sent = sum(1 for mac in macs if wake_on_lan(mac, self.broadcasts()))
            self.status.setText(f"Sent Wake-on-LAN packets to {sent} of {len(macs)} devices.")

    def wake_typed_mac(self):
        text = self.mac_edit.text()
        mac = parse_mac(text)
        if not mac:
            QMessageBox.warning(self, "NetScan", "Enter a MAC address like AA:BB:CC:DD:EE:FF.")
            return
        self.wake(mac, self.device_label(mac))

    def rename_device(self):
        macs = self.selected_device_macs()
        if len(macs) != 1:
            return
        mac = macs[0]
        d = self.devices.devices[mac]
        name = self.ask_nickname(d.get("hostname") or d.get("ip") or mac, mac, d.get("nickname", ""))
        if name is None:
            return
        self.devices.set_nickname({"mac": mac, "ip": d.get("ip", "")}, name)
        self.after_device_change(mac)

    def forget_devices(self):
        macs = self.selected_device_macs()
        if not macs:
            return
        what = self.device_label(macs[0]) or macs[0] if len(macs) == 1 else f"{len(macs)} devices"
        if QMessageBox.question(self, "NetScan", f"Forget {what}? Its nickname, notes and history are "
                                "removed, and it will show as a new device if it's seen again.") != QMessageBox.Yes:
            return
        for mac in macs:
            self.devices.forget(mac)
        self.after_device_change(*macs)

    def after_device_change(self, *macs):
        """A change from the Devices tab: update matching rows on the Scan tab too."""
        for ip, h in self.hosts.items():
            if h["mac"] in macs:
                self.refresh_row(ip)
        self.table.resizeColumnToContents(COL_NAME)
        self.show_port_details()
        self.refresh_devices()

    def device_menu(self, pos):
        macs = self.selected_device_macs()
        if not macs:
            return
        menu = QMenu(self)
        menu.addAction("Wake-on-LAN", self.wake_selected_devices)
        if len(macs) == 1:
            menu.addAction("Rename…", self.rename_device)
        all_trusted = all(self.devices.devices.get(m, {}).get("trusted") for m in macs)
        menu.addAction("Unmark as trusted" if all_trusted else "Mark as trusted",
                       lambda: self.set_trusted(macs, not all_trusted))
        if len(macs) == 1 and self.devices.devices.get(macs[0], {}).get("ip"):
            d = self.devices.devices[macs[0]]
            host = {"ip": d["ip"], "mac": macs[0], "hostname": d.get("hostname", "")}
            user = d.get("ssh_user")
            if terminal_argv(["true"]):
                menu.addAction(f"SSH to {user}@{d['ip']}" if user else f"SSH to {d['ip']}…",
                               lambda: self.ssh_to(host))
            menu.addAction("Copy ssh command", lambda: self.copy_ssh(host))
        menu.addAction("Copy MAC address" + ("es" if len(macs) > 1 else ""),
                       lambda: QGuiApplication.clipboard().setText("\n".join(macs)))
        menu.addSeparator()
        menu.addAction("Forget", self.forget_devices)
        menu.exec(self.dev_table.viewport().mapToGlobal(pos))

    # ---- watch mode --------------------------------------------------------

    def set_watch(self, _index=None, first_delay=0):
        minutes = WATCH_INTERVALS[self.watch_combo.currentIndex()][1]
        if not minutes:
            self.watch_timer.stop()
            self.watch_label.setText("Off. Pick an interval to start watching.")
            return
        self.watch_timer.start(minutes * 60_000)
        if first_delay:
            QTimer.singleShot(first_delay, self.watch_scan)  # at startup, let the window settle
        else:
            self.watch_scan()

    def watch_target(self):
        idx = self.target.currentIndex()
        net = self.target.itemData(idx) if idx >= 0 else None
        return net or (self.networks[0] if self.networks else None)

    def watch_scan(self):
        """One quiet, unprivileged check; runs alongside (not instead of) the Scan tab."""
        if not self.nmap or (self.watch_proc is not None
                             and self.watch_proc.state() != QProcess.NotRunning):
            return
        net = self.watch_target()
        if net is None:
            self.watch_label.setText("No local network detected.")
            return
        self.watch_ports = self.watch_ports_box.isChecked()
        scan = ["--top-ports", "100", *LAN_FAST] if self.watch_ports else ["-sn"]
        args = ["-n", "-T4", *scan, "-oX", "-", *iface_args(net), "--exclude", net["local_ip"],
                str(net["network"])]
        if IS_WIN:
            args.insert(0, "--unprivileged")
        elif self.nmap_caps:
            args.insert(0, "--privileged")  # ARP discovery: finds devices that ignore pings
        self.watch_net = net
        self.watch_proc = QProcess(self)
        self.watch_proc.finished.connect(self.watch_done)
        self.watch_label.setText(f"Checking {net['network']}" + (" and its ports" if self.watch_ports else "")
                                 + "…")
        self.watch_proc.start(self.nmap, args)

    def watch_done(self, *_):
        out = bytes(self.watch_proc.readAllStandardOutput()).decode(errors="replace")
        stamp = datetime.datetime.now().strftime("%H:%M")
        try:
            root = ET.fromstring(out[out.index("<nmaprun"):])
        except (ValueError, ET.ParseError):
            self.watch_label.setText(f"Check at {stamp} failed.")
            return
        net = self.watch_net
        macs = neighbour_macs(net["iface"])
        found = []  # (host, ports or None)
        for elem in root.findall("host"):
            h = parse_host(elem)
            if h is None:
                continue
            if h["ip"] == net["local_ip"]:
                h["mac"] = h["mac"] or net["mac"]
                h["vendor"] = h["vendor"] or "(this computer)"
            h["mac"] = h["mac"] or macs.get(h["ip"], "")
            h["vendor"] = h["vendor"] or mac_vendor(h["mac"])
            found.append((h, parse_ports(elem) if self.watch_ports else None))
        if net["mac"] and not any(h["ip"] == net["local_ip"] for h, _ in found):
            found.append(({"ip": net["local_ip"], "hostname": socket.gethostname(), "mac": net["mac"],
                           "vendor": "(this computer)", "os": ""}, None))  # excluded from nmap, but online
        hosts = [h for h, _ in found]
        first_run = not self.devices.known_macs()
        new = self.devices.record(hosts)
        if first_run:
            new = []  # the very first check just learns what's normal
        self.online_macs = {h["mac"] for h in hosts if h["mac"]}

        changes = []  # (host, opened, closed)
        top = {"tcp": port_set(top_tcp_ports(100)), "udp": set()}
        with self.devices.batch():
            for h, ports in found:
                if not (self.watch_ports and h["mac"]) or ports is None:  # None: this computer
                    continue
                opened, closed = self.devices.update_ports(h["mac"], ports, top)
                if (opened or closed) and h["mac"] not in new:  # new devices just get a baseline
                    changes.append((h, opened, closed))

        self.watch_label.setText(f"Last check {stamp}: {len(hosts)} online"
                                 + (f", {len(new)} new" if new else "")
                                 + (f", port changes on {len(changes)}" if changes else "") + ".")
        what = lambda h: ("Device with a private MAC" if h["vendor"].startswith("(")
                          else h["vendor"] or "Unknown device")
        name = lambda h: self.devices.nickname(h) or h["hostname"] or self.devices.get(h).get("hostname") \
            or f"{what(h)} ({h['ip']})"
        if new:
            joined = [h for h in hosts if h["mac"] in new]
            notify(f"{len(new)} new device(s) on your network",
                   "\n".join(f"{what(h)}  {h['ip']}  {h['mac']}" for h in joined))
            self.set_dot(AMBER)
            self.status.setText(f"Watch: {len(new)} new device(s) joined: "
                                + ", ".join(f"{h['ip']} ({what(h)})" for h in joined))
        if changes:
            lines = []
            for h, opened, closed in changes:
                bits = [("⚠ " if port_risk(p) else "") + f"opened {port_label(p)}" for p in opened]
                bits += [f"closed {port_label(p)}" for p in closed]
                lines.append(f"{name(h)}: " + ", ".join(bits))
            notify("Port changes on your network", "\n".join(lines))
            self.set_dot(AMBER)
            self.status.setText("Watch: " + "; ".join(lines))
        for ip in self.hosts:
            self.refresh_row(ip)
        self.refresh_devices()

    # ---- save / compare / export ------------------------------------------

    def scan_record(self):
        return {
            "netscan": 1,
            "saved": datetime.datetime.now().isoformat(timespec="seconds"),
            "target": self.last_target,
            "hosts": [{**h, "ports": self.network_ports(ip) if ip in self.ports else None} for ip, h in
                      sorted(self.hosts.items(), key=lambda kv: ipaddress.ip_address(kv[0]))],
        }

    def default_name(self, ext):
        stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
        target = re.sub(r"[^0-9A-Za-z.-]+", "_", self.last_target).strip("_") or "scan"
        return f"netscan_{target}_{stamp}.{ext}"

    def save_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save scan", self.default_name("json"),
                                              "NetScan scan (*.json)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.scan_record(), f, indent=2)
        self.status.setText(f"Saved {len(self.hosts)} host(s) to {path}")

    def build_compare_menu(self):
        """Recent scans (kept automatically) plus 'From file…'."""
        menu = self.compare_menu
        menu.clear()
        today = datetime.date.today()
        entries = [(path, info) for path, info in list_history() if path != self.history_path][:12]
        if entries:
            title = menu.addAction("Recent scans")
            title.setEnabled(False)
        for path, info in entries:
            try:
                when = datetime.datetime.fromisoformat(info["saved"])
                day = ("Today" if when.date() == today else
                       "Yesterday" if when.date() == today - datetime.timedelta(days=1) else
                       when.strftime("%a %d %b"))
                label = f"{day} {when:%H:%M}   {info['target']} · {info['hosts']} host(s)"
            except (TypeError, ValueError):
                label = os.path.basename(path)
            menu.addAction(label, lambda p=path: self.compare_with_file(p))
        if entries:
            menu.addSeparator()
        menu.addAction("From file…", self.compare_with_file)

    def compare_with_file(self, path=None):
        if not path:
            path, _ = QFileDialog.getOpenFileName(self, "Compare with saved scan", "",
                                                  "NetScan scan (*.json)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                record = json.load(f)
            baseline = record["hosts"]
        except (OSError, ValueError, KeyError, TypeError) as e:
            QMessageBox.warning(self, "NetScan", f"Could not read scan file:\n{e}")
            return
        changes, gone = compare_scans(baseline, self.hosts,
                                      {ip: self.network_ports(ip) for ip in self.ports})
        self.table.setColumnHidden(COL_CHANGE, False)
        for row in range(self.table.rowCount()):
            self.set_change(row, changes.get(self.table.item(row, COL_IP).text(), ""))
        self.apply_filter()

        new = sum(1 for c in changes.values() if c == "NEW")
        changed = sum(1 for c in changes.values() if c and c != "NEW")
        self.summary = (f"Compared with scan from {record.get('saved', '?')}: "
                        f"{new} new, {changed} changed, {len(gone)} missing.")
        self.update_status()
        if gone:
            lines = [f"{h['ip']:15}  {h.get('hostname') or '-':20}  {h.get('mac') or ''}"
                     for h in gone]
            box = QMessageBox(self)
            box.setWindowTitle("NetScan: hosts no longer seen")
            box.setText(f"{len(gone)} host(s) from the saved scan were not found this time:")
            box.setDetailedText("\n".join(lines))
            box.exec()

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", self.default_name("csv"), "CSV (*.csv)")
        if not path:
            return
        cols = [c for c in range(len(COLUMNS)) if not self.table.isColumnHidden(c)]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([COLUMNS[c] for c in cols])
            for r in range(self.table.rowCount()):
                w.writerow([self.table.item(r, c).text() for c in cols])
        self.status.setText(f"Saved {self.table.rowCount()} host(s) to {path}")

    def export_xml(self):
        if not self.last_xml:
            QMessageBox.information(self, "NetScan", "No nmap output yet.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export nmap XML", self.default_name("xml"),
                                              "nmap XML (*.xml)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.last_xml[self.last_xml.find("<?xml"):] if "<?xml" in self.last_xml
                    else self.last_xml)
        self.status.setText(f"Saved raw nmap output to {path}")

    def copy_selection(self):
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        cols = [c for c in range(len(COLUMNS)) if not self.table.isColumnHidden(c)]
        lines = ["\t".join(self.table.item(r, c).text() for c in cols) for r in rows]
        QGuiApplication.clipboard().setText("\n".join(lines))

    def closeEvent(self, event):
        self.save_notes()
        self.save_settings()
        if self.watch_proc is not None and self.watch_proc.state() != QProcess.NotRunning:
            self.watch_proc.kill()
        if self.is_running():
            self.proc.kill()
        super().closeEvent(event)


def self_test():
    """Check the setup without a window: nmap, its data files, network detection, a test scan."""
    ok = True

    def check(label, good, detail=""):
        nonlocal ok
        ok = ok and good
        print(f"[{'OK' if good else 'FAIL'}] {label}" + (f": {detail}" if detail else ""))

    nmap = find_program("nmap")
    check("nmap found", bool(nmap), nmap or "not on PATH or in the usual install folders")
    if nmap:
        version = run_text(nmap, "--version").strip().splitlines()
        check("nmap runs", bool(version), version[0] if version else "no output")
    for name in ("nmap-services", "nmap-mac-prefixes"):
        path = nmap_data_file(name)
        check(f"{name} found", os.path.exists(path), path)
    if IS_WIN:
        check("Npcap installed", npcap_installed(),
              "" if npcap_installed() else "raw scans unavailable; install from https://npcap.com")
    else:
        print(f"[INFO] root helper: {' '.join(root_prefix() or ['none'])}")
        print("[INFO] nmap capabilities: " + ("set, privileged scans need no password" if nmap_has_caps(nmap)
                                             else "not set (run setup-no-password.sh to skip password prompts)"))
    nets = detect_networks()
    check("network detected", bool(nets),
          ", ".join(f"{n['network']} on {n['iface']} (you are {n['local_ip']})" for n in nets)
          or "none; you can still type a target in the app")
    if nmap:
        args = [nmap, "-n", "-sn", "-oX", "-", "127.0.0.1"]
        if IS_WIN and not npcap_installed():
            args.insert(1, "--unprivileged")
        out = run_text(*args)
        up = 'state="up"' in out
        check("test scan of 127.0.0.1", up, "host is up" if up else (out.strip()[-200:] or "no output"))
    print("All checks passed." if ok else "Some checks failed.")
    return 0 if ok else 1


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--askpass":
        sys.exit(askpass_main(" ".join(sys.argv[2:])))
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    app = QApplication(sys.argv)
    app.setApplicationName("NetScan")
    app.setDesktopFileName("netscan")
    apply_theme(app, QSettings("netscan", "netscan").value("theme", "system", type=str))
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
