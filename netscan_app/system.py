"""Platform helpers: finding programs, network detection, neighbour/ARP tables, this computer's listening sockets, terminals, root helpers and ping."""

import base64
import datetime
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


# Tighter timing for targets on a directly attached LAN, where replies take
# milliseconds. Cuts "Find Hosts" with top-100 ports from ~5s to ~2s on a /24
# with identical results; not used for typed/remote targets, where it could miss hosts.
# Not used for Scan Ports either: on big port ranges it gave up on slow replies and
# missed real open ports (full scan of a router: 2 of 3 found), for only ~15% speed.
LAN_FAST = ["--max-rtt-timeout", "200ms", "--max-retries", "1", "--min-rate", "1000"]


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


def ping_once(ip, timeout_s=1):
    """Round-trip time in ms for one ping, or None if no reply. Uses the system ping (no root)."""
    if IS_WIN:
        argv = ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip]
    elif IS_MAC:
        argv = ["/sbin/ping", "-n", "-c", "1", "-W", str(timeout_s * 1000), ip]
    else:
        argv = ["ping", "-n", "-c", "1", "-W", str(timeout_s), ip]
    out = run_text(*argv)
    m = re.search(r"time[=<]\s*([\d.]+)\s*ms", out)
    return float(m.group(1)) if m else None
