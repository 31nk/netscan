"""nmap data and results: port profiles, MAC vendors, top ports, parsing nmap XML, comparing scans."""

import ipaddress
import re

from .system import nmap_data_file


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

WEB_PORTS = [(443, "https"), (8443, "https"), (80, "http"), (8080, "http"),
             (8000, "http"), (3000, "http")]


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
        svc_elem = p.find("service")
        svc = svc_elem.attrib if svc_elem is not None else {}
        cpes = [c.text for c in svc_elem.findall("cpe") if c.text] if svc_elem is not None else []
        version = " ".join(v for v in (svc.get("product"), svc.get("version"),
                                       svc.get("extrainfo")) if v)
        ports.append({
            "port": int(p.get("portid")),
            "proto": p.get("protocol", "tcp"),
            "service": svc.get("name", ""),
            "version": version,
            "cpe": cpes,  # e.g. cpe:/a:openbsd:openssh:10.0p2 (with version detection)
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


def ip_sort_key(ip):
    addr = ipaddress.ip_address(ip)
    return addr.version, addr
