"""The Tools tab's engines: DNS lookup, port check, IP info, HTTP inspector, subnet calculator, MAC lookup, Wi-Fi scan and trace route."""

import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .discovery import parse_dns_records, tls_certificate
from .internet import dns_servers
from .scanning import mac_vendor, parse_mac, port_set
from .system import IS_MAC, IS_WIN, run_text


# ---- tools tab: DNS, port check, IP info, HTTP inspector, subnet, MAC, Wi-Fi ------

DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
DNS_RCODES = {0: "OK", 1: "format error", 2: "server failure", 3: "no such name (NXDOMAIN)",
              4: "not implemented", 5: "refused"}


def dns_query(server, name, qtype="A", timeout=3.0):
    """Ask one DNS server directly (UDP). Returns (rcode, [(type name, value)], ms)."""
    ident = int.from_bytes(os.urandom(2), "big")
    question = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.rstrip(".").split(".")) + b"\0"
    packet = struct.pack(">6H", ident, 0x0100, 1, 0, 0, 0) + question + struct.pack(">HH", DNS_TYPES[qtype], 1)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        t = time.perf_counter()
        s.sendto(packet, (server, 53))
        while True:
            data, _ = s.recvfrom(65535)
            if data[:2] == packet[:2]:  # ignore stray replies
                break
        ms = (time.perf_counter() - t) * 1000
    rcode = data[3] & 0x0F
    names = {v: k for k, v in DNS_TYPES.items()}
    answers = []
    an = struct.unpack(">H", data[6:8])[0]
    for rtype, _name, value in parse_dns_records(data)[:an]:
        if rtype in names and value is not None:
            answers.append((names[rtype], value))
    return rcode, answers, ms


BLOCKED_ANSWERS = {"0.0.0.0", "::", "127.0.0.1", "::1"}


def doh_query(name, qtype="A"):
    """Cloudflare over DNS-over-HTTPS: works through VPNs that block other DNS servers, can't be altered in transit.
    Same return shape as dns_query."""
    names = {v: k for k, v in DNS_TYPES.items()}
    url = "https://1.1.1.1/dns-query?" + urllib.parse.urlencode({"name": name, "type": qtype})
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "NetScan"})
    t = time.perf_counter()
    with urllib.request.urlopen(req, timeout=6) as r:
        d = json.loads(r.read(1_000_000))
    ms = (time.perf_counter() - t) * 1000
    answers = []
    for a in d.get("Answer", []):
        kind, data = names.get(a.get("type")), a.get("data", "")
        if kind == "MX":
            pref, _, host = data.partition(" ")
            answers.append((kind, (int(pref), host.rstrip("."))))
        elif kind == "TXT":
            answers.append((kind, re.findall(r'"((?:[^"\\]|\\.)*)"', data) or [data]))
        elif kind:
            answers.append((kind, data.rstrip(".")))
    return d.get("Status", 2), answers, ms


def dns_tool(name, qtype):
    """Look a name up on your DNS and on Cloudflare; spot blocking and hijacking."""
    mine = (dns_servers() or ["1.1.1.1"])[0]
    out = {"name": name, "type": qtype, "servers": {}}
    for label, server, ask in (("yours", mine, lambda: dns_query(mine, name, qtype)),
                               ("cloudflare", "1.1.1.1 (DNS-over-HTTPS)", lambda: doh_query(name, qtype))):
        try:
            out["servers"][label] = (server,) + ask()
        except (OSError, ValueError, UnicodeError, http.client.HTTPException) as e:
            out["servers"][label] = (server, None, [], None, str(e))
    # NXDOMAIN hijacking: a made-up name should not exist; some ISPs answer with their ad server.
    try:
        rcode, answers, _ = dns_query(mine, f"netscan-{os.urandom(5).hex()}.com", "A")
        out["hijack"] = rcode == 0 and bool(answers)
    except (OSError, ValueError):
        out["hijack"] = None
    return out


def port_check(host, spec, timeout=2.0):
    """TCP connect to each port: {"ip", "results": [(port, "open"|"closed"|"no answer", service)]}."""
    ip = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0][4][0]
    ports = sorted(port_set(spec))[:1024]

    def one(port):
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                state = "open" if s.connect_ex((ip, port)) == 0 else "closed"
            except socket.timeout:
                state = "no answer"
            except OSError:
                state = "closed"
        try:
            service = socket.getservbyport(port, "tcp")
        except OSError:
            service = ""
        return port, state, service

    with ThreadPoolExecutor(max_workers=64) as ex:
        return {"host": host, "ip": ip, "results": list(ex.map(one, ports))}


def ip_info(query):
    """Owner of an IP from the public RDAP registries, plus its reverse DNS name."""
    ip = socket.getaddrinfo(query, None)[0][4][0]
    addr = ipaddress.ip_address(ip)
    info = {"ip": ip, "rdns": ""}
    try:
        info["rdns"] = socket.gethostbyaddr(ip)[0]
    except OSError:
        pass
    if not addr.is_global:
        info["private"] = ("a private/local address (your LAN or a VPN)" if addr.is_private else
                           "a special-purpose address")
        return info
    req = urllib.request.Request(f"https://rdap.org/ip/{ip}", headers={"User-Agent": "NetScan",
                                                                        "Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        d = json.loads(r.read(1_000_000))
    orgs = []
    for ent in d.get("entities", []):
        vcard = ent.get("vcardArray", [None, []])[1]
        fn = next((v[3] for v in vcard if v and v[0] == "fn"), "")
        if fn and fn not in orgs:
            orgs.append(fn)
    info.update({"name": d.get("name", ""), "handle": d.get("handle", ""), "country": d.get("country", ""),
                 "range": f"{d.get('startAddress', '')} – {d.get('endAddress', '')}", "orgs": orgs[:4],
                 "registry": (d.get("port43") or "").replace("whois.", "").upper()})
    return info


SECURITY_HEADERS = {
    "strict-transport-security": "forces HTTPS on later visits",
    "content-security-policy": "limits what scripts and content can load",
    "x-frame-options": "stops the site being framed (clickjacking)",
    "x-content-type-options": "stops browsers guessing file types",
    "referrer-policy": "controls what the site leaks in links",
    "permissions-policy": "restricts camera, microphone, location…",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http_inspect(url):
    """Redirect chain, final headers, missing security headers, and the certificate's validity."""
    if "://" not in url:
        url = "https://" + url
    lenient = ssl.create_default_context()
    lenient.check_hostname = False
    lenient.verify_mode = ssl.CERT_NONE  # still inspect LAN devices with self-signed certs
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=lenient))
    chain = []
    for _ in range(8):
        req = urllib.request.Request(url, headers={"User-Agent": "NetScan"}, method="GET")
        t = time.perf_counter()
        try:
            r = opener.open(req, timeout=10)
            status, headers = r.status, r.headers
            r.close()
        except urllib.error.HTTPError as e:
            status, headers = e.code, e.headers
        chain.append({"url": url, "status": status, "ms": (time.perf_counter() - t) * 1000})
        location = headers.get("Location")
        if status in (301, 302, 303, 307, 308) and location:
            url = urllib.parse.urljoin(url, location)
            continue
        break
    final = urllib.parse.urlparse(chain[-1]["url"])
    out = {"chain": chain, "headers": dict(headers.items()),
           "missing": [h for h in SECURITY_HEADERS if h not in {k.lower() for k in headers.keys()}]}
    if final.scheme == "https":
        host, port = final.hostname, final.port or 443
        out["cert"] = tls_certificate(host, port)
        try:  # does it pass the normal browser check?
            with socket.create_connection((host, port), timeout=5) as raw, \
                    ssl.create_default_context().wrap_socket(raw, server_hostname=host):
                out["cert_valid"] = True
        except ssl.SSLCertVerificationError as e:
            out["cert_valid"] = e.verify_message or str(e)
        except OSError as e:
            out["cert_valid"] = str(e)
    return out


def subnet_info(text):
    """Everything about a network (CIDR) or an address with a prefix."""
    iface = ipaddress.ip_interface(text.strip())
    net = iface.network
    hosts = net.num_addresses - (2 if net.version == 4 and net.prefixlen < 31 else 0)
    rows = [("Network", f"{net.network_address}/{net.prefixlen}"),
            ("Netmask", str(net.netmask)), ("Wildcard (Cisco ACL)", str(net.hostmask)),
            ("Usable addresses", f"{hosts:,}")]
    if net.version == 4:
        first = net.network_address + (1 if net.prefixlen < 31 else 0)
        last = net.broadcast_address - (1 if net.prefixlen < 31 else 0)
        rows += [("First usable", str(first)), ("Last usable", str(last)), ("Broadcast", str(net.broadcast_address))]
    else:
        rows += [("First", str(net.network_address)), ("Last", str(net.broadcast_address))]
    rows += [("Type", "private" if net.is_private else "public" if net.is_global else "special-purpose")]
    if iface.ip != net.network_address:
        rows.insert(0, ("Address", str(iface.ip)))
    return rows


def mac_info(text):
    mac = parse_mac(text)
    if not mac:
        raise ValueError("That isn't a MAC address (e.g. AA:BB:CC:DD:EE:FF).")
    first = int(mac[:2], 16)
    rows = [("MAC", mac), ("Manufacturer prefix (OUI)", mac[:8])]
    if first & 0x02:
        rows.append(("Manufacturer", "none: this is a private/randomised address (phones and laptops use "
                                     "these per network for privacy)"))
    else:
        rows.append(("Manufacturer", mac_vendor(mac) or "unknown (not in nmap's list)"))
    rows.append(("Kind", "multicast/group address" if first & 0x01 else "single device"))
    return rows


def _split_nmcli(line):
    """Split nmcli terse output on ':' that isn't escaped as '\\:'."""
    parts, cur, esc = [], "", False
    for ch in line:
        if esc:
            cur, esc = cur + ch, False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    return parts + [cur]


def wifi_band(freq_mhz):
    return "6 GHz" if freq_mhz >= 5925 else "5 GHz" if freq_mhz >= 4900 else "2.4 GHz"


def wifi_scan(rescan=False):
    """This computer's Wi-Fi link and the networks around it:
    [{ssid, bssid, channel, freq, band, signal, security, cipher, active}]. rescan: fresh readings (Linux; slower)."""
    nets = []
    if IS_WIN:
        cur = run_text("netsh", "wlan", "show", "interfaces")
        cur_bssid = (re.search(r"BSSID\s*:\s*(\S+)", cur) or [None, ""])[1].lower()
        ssid = None
        for block in re.split(r"\r?\n(?=SSID \d+)", run_text("netsh", "wlan", "show", "networks", "mode=bssid")):
            m = re.match(r"SSID \d+\s*:\s*(.*)", block)
            if not m:
                continue
            ssid = m.group(1).strip()
            sec = (re.search(r"Authentication\s*:\s*(.*)", block) or [None, ""])[1].strip()
            cipher = (re.search(r"Encryption\s*:\s*(.*)", block) or [None, ""])[1].strip()
            for b in re.finditer(r"BSSID \d+\s*:\s*(\S+).*?Signal\s*:\s*(\d+)%.*?Channel\s*:\s*(\d+)", block, re.S):
                ch = int(b.group(3))
                freq = 2407 + 5 * ch if ch <= 14 else 5000 + 5 * ch
                nets.append({"ssid": ssid, "bssid": b.group(1).lower(), "channel": ch, "freq": freq,
                             "band": wifi_band(freq), "signal": int(b.group(2)), "security": sec,
                             "cipher": cipher, "active": b.group(1).lower() == cur_bssid})
    elif IS_MAC:
        out = run_text("/usr/sbin/system_profiler", "SPAirPortDataType")
        section = "current"
        for m in re.finditer(r"^\s{12}(\S.*?):\n(.*?)(?=^\s{12}\S|\Z)|^\s{10}(Other Local Wi-Fi Networks|Current Network Information):",
                             out, re.M | re.S):
            if m.group(3):
                section = "other" if m.group(3).startswith("Other") else "current"
                continue
            body = m.group(2)
            ch = re.search(r"Channel:\s*(\d+)", body)
            if not ch:
                continue
            sig = re.search(r"Signal / Noise:\s*(-?\d+) dBm", body)
            ch = int(ch.group(1))
            freq = 2407 + 5 * ch if ch <= 14 else 5000 + 5 * ch
            nets.append({"ssid": m.group(1), "bssid": "", "channel": ch, "freq": freq, "band": wifi_band(freq),
                         "signal": min(100, max(0, 2 * (int(sig.group(1)) + 100))) if sig else None,
                         "security": (re.search(r"Security:\s*(.*)", body) or [None, ""])[1].strip(),
                         "active": section == "current"})
    elif shutil.which("nmcli"):
        out = run_text("nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY,WPA-FLAGS,RSN-FLAGS",
                       "dev", "wifi", "list", *(["--rescan", "yes"] if rescan else []))
        for line in out.splitlines():
            f = _split_nmcli(line)
            if len(f) < 8:
                continue
            freq = int(re.sub(r"\D", "", f[4]) or 0)
            nets.append({"ssid": f[1] or "(hidden)", "bssid": f[2].lower(), "channel": int(f[3] or 0), "freq": freq,
                         "band": wifi_band(freq), "rate": f[5], "signal": int(f[6] or 0), "security": f[7] or "open",
                         "cipher": " ".join(f[8:10]) if len(f) >= 10 else "", "active": f[0] == "yes"})
    return sorted(nets, key=lambda n: (not n["active"], -(n["signal"] or 0)))


def radio_family(bssid):
    """Routers broadcast several networks (guest, mesh, hidden) from addresses that differ only in the
    first and last byte; the middle four identify the router."""
    parts = bssid.lower().split(":")
    return ":".join(parts[1:5]) if len(parts) == 6 else bssid


def channel_advice(nets):
    """Per band: how many *other* routers sit on each channel, and the least crowded choice.

    Your own router's extra networks don't count against you, and a router with several networks
    on one channel counts once.
    """
    out = {}
    active = next((n for n in nets if n["active"]), None)
    own = radio_family(active["bssid"]) if active and active["bssid"] else None
    for band, choices in (("2.4 GHz", (1, 6, 11)), ("5 GHz", None)):
        here = [n for n in nets if n["band"] == band]
        if not here:
            continue
        routers = {}
        for n in here:
            if active and (n["ssid"] == active["ssid"] or (own and radio_family(n["bssid"]) == own)):
                continue
            routers.setdefault(n["channel"], set()).add(radio_family(n["bssid"]) if n["bssid"] else n["ssid"])
        counts = {ch: len(r) for ch, r in routers.items()}
        mine = next((n["channel"] for n in here if n["active"]), None)
        pool = choices or sorted(counts)
        best = min(pool, key=lambda c: (counts.get(c, 0), c)) if pool else None
        out[band] = {"counts": dict(sorted(counts.items())), "yours": mine, "best": best}
    return out


def traceroute_argv(target):
    """Trace-route command that needs no root on each OS, or None if none is installed."""
    if IS_WIN:
        return ["tracert", "-d", "-w", "1000", target]
    if IS_MAC:
        return ["/usr/sbin/traceroute", "-n", "-w", "1", "-q", "1", target]
    # stdbuf: these buffer their output when it isn't a terminal, so hops would only show at the end.
    line = ["stdbuf", "-oL"] if shutil.which("stdbuf") else []
    if shutil.which("tracepath"):
        return [*line, "tracepath", "-n", "-m", "30", target]
    if shutil.which("traceroute"):
        return [*line, "traceroute", "-n", "-w", "1", "-q", "1", "-m", "30", target]
    return None
