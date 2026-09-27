"""Background discovery after a scan: mDNS/SSDP announcements, router UPnP port forwards, IPv6 neighbours, web page titles and TLS certificates. All read-only."""

import datetime
import html
import http.client
import os
import re
import socket
import ssl
import struct
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from .system import (
    IS_MAC, IS_WIN, as_list, iface_args, ip_json, normalize_mac, powershell_json, run_text,
)


# ---- extra discovery: mDNS, SSDP/UPnP, router port forwards, IPv6, web titles -----
# All of it is read-only and needs no password. Runs in the background after Find Hosts.

MDNS_ADDR, SSDP_ADDR = ("224.0.0.251", 5353), ("239.255.255.250", 1900)

# mDNS/DNS-SD service types that say what kind of device something is.
SERVICE_TYPE_HINTS = {
    "_googlecast._tcp": "media", "_airplay._tcp": "media", "_raop._tcp": "media",
    "_spotify-connect._tcp": "media", "_sonos._tcp": "media", "_roku-rcp._tcp": "media",
    "_ipp._tcp": "printer", "_ipps._tcp": "printer", "_printer._tcp": "printer",
    "_pdl-datastream._tcp": "printer", "_scanner._tcp": "printer", "_uscan._tcp": "printer",
    "_hap._tcp": "iot", "_hue._tcp": "iot", "_matter._tcp": "iot", "_esphomelib._tcp": "iot",
    "_shelly._tcp": "iot", "_adisk._tcp": "nas", "_apple-mobdev2._tcp": "phone",
    "_workstation._tcp": "computer",
}
# TXT keys that carry a model name (Chromecast md, printers ty/usb_MDL, Apple model/am/rpMd).
MODEL_TXT_KEYS = ("md", "ty", "usb_MDL", "product", "model", "am", "rpMd")


def _dns_name(buf, off):
    """(name, offset just past it) for a possibly-compressed DNS name."""
    labels, end, jumps = [], None, 0
    while off < len(buf) and jumps < 30:
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | buf[off + 1]
            jumps += 1
            continue
        labels.append(buf[off + 1:off + 1 + n].decode(errors="replace"))
        off += 1 + n
    return ".".join(labels), (end if end is not None else off)


def parse_dns_records(buf):
    """Every resource record in a DNS message: (type, name, value).

    PTR/NS/CNAME -> name, MX -> (preference, host), SRV -> (port, target), TXT -> [strings],
    A/AAAA -> address, others -> None.
    """
    qd, an, ns, ar = struct.unpack(">4H", buf[4:12])
    off, records = 12, []
    for _ in range(qd):
        off = _dns_name(buf, off)[1] + 4
    for _ in range(an + ns + ar):
        name, off = _dns_name(buf, off)
        rtype, _cls, _ttl, length = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        data = buf[off:off + length]
        if rtype in (2, 5, 12):  # NS, CNAME, PTR
            value = _dns_name(buf, off)[0]
        elif rtype == 15 and length >= 3:  # MX: preference, mail server
            value = (struct.unpack(">H", data[:2])[0], _dns_name(buf, off + 2)[0])
        elif rtype == 33 and length >= 7:
            value = (struct.unpack(">H", data[4:6])[0], _dns_name(buf, off + 6)[0])
        elif rtype == 16:
            value, i = [], 0
            while i < len(data):
                value.append(data[i + 1:i + 1 + data[i]].decode(errors="replace"))
                i += 1 + data[i]
        elif rtype == 1 and length == 4:
            value = socket.inet_ntoa(data)
        elif rtype == 28 and length == 16:
            value = socket.inet_ntop(socket.AF_INET6, data)
        else:
            value = None
        records.append((rtype, name, value))
        off += length
    return records


def _dns_query(names, qtype=12):
    q = b"".join(b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\0"
                 + struct.pack(">HH", qtype, 1) for n in names)
    return struct.pack(">6H", 0, 0, len(names), 0, 0, 0) + q


def _mdns_socket(local_ip):
    """Socket on port 5353 in the mDNS group, so answers sent to the group reach us.

    Multicast answers get through host firewalls like ufw, whose default rules allow mDNS;
    direct (unicast) answers to a random port usually don't.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    try:
        s.bind(("", 5353))
    except OSError:
        s.bind(("", 0))  # 5353 taken exclusively (e.g. Windows): answers may be unicast then
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                 socket.inet_aton(MDNS_ADDR[0]) + socket.inet_aton(local_ip))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
    s.settimeout(0.25)
    return s


def _collect(sock, seconds, keep):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            data, (ip, _port) = sock.recvfrom(9000)
        except socket.timeout:
            continue
        except OSError:
            break
        keep(ip, data)


def mdns_browse(local_ip, seconds=3.0):
    """What every mDNS responder offers: {ip: {"name", "services", "types", "model", "friendly"}}."""
    found = {}

    def keep(ip, data):
        if len(data) < 12 or not data[2] & 0x80:  # responses only
            return
        try:
            records = parse_dns_records(data)
        except (struct.error, IndexError):
            return
        d = found.setdefault(ip, {"name": "", "services": [], "types": [], "txt": {}})
        for rtype, name, value in records:
            if rtype == 12 and name == "_services._dns-sd._udp.local":
                types.add(value)
            elif rtype == 12 and value and value.endswith(name) and name.startswith("_"):
                label, kind = value[:-len(name) - 1], name.removesuffix(".local")
                if label and label not in d["services"]:
                    d["services"].append(label)
                if kind not in d["types"]:
                    d["types"].append(kind)
            elif rtype == 1 and value == ip and name.endswith(".local"):
                d["name"] = name.removesuffix(".local")
            elif rtype == 16 and value:
                for kv in value:
                    key, _, val = kv.partition("=")
                    if val:
                        d["txt"].setdefault(key, val)

    types = set()
    try:
        sock = _mdns_socket(local_ip)
    except OSError:
        return found
    with sock:
        # Each question goes out twice: mDNS answers are best-effort and sleepy devices miss one.
        for share in (0.2, 0.25):
            sock.sendto(_dns_query(["_services._dns-sd._udp.local"]), MDNS_ADDR)
            _collect(sock, seconds * share, keep)
        for share in (0.25, 0.3):
            if types:
                sock.sendto(_dns_query(sorted(types)), MDNS_ADDR)
            _collect(sock, seconds * share, keep)
    for d in found.values():
        txt = d.pop("txt")
        d["model"] = next((txt[k] for k in MODEL_TXT_KEYS if txt.get(k)), "")
        d["friendly"] = txt.get("fn", "")
        # Instance names often include the host's MAC ("pi5 [88:a2:...]"); keep them readable.
        d["services"] = [re.sub(r"\s*\[[0-9a-f:]{17}\]$", "", s) for s in d["services"]]
    return found


def ssdp_search(local_ip, seconds=3.0):
    """UPnP devices answering an SSDP search: {ip: sorted description URLs}."""
    found = {}

    def keep(ip, data):
        m = re.search(rb"(?im)^location:\s*(\S+)", data)
        if m:
            found.setdefault(ip, set()).add(m.group(1).decode(errors="replace"))

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except OSError:
        return {}
    with s:
        try:
            s.bind((local_ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.settimeout(0.25)
            for st in ("ssdp:all", "upnp:rootdevice"):
                s.sendto((f'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
                          f"MX: 2\r\nST: {st}\r\n\r\n").encode(), SSDP_ADDR)
        except OSError:
            return {}
        _collect(s, seconds, keep)
    return {ip: sorted(urls) for ip, urls in found.items()}


def _http_get(url, timeout=3.0, limit=262144):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # LAN devices use self-signed certificates
    req = urllib.request.Request(url, headers={"User-Agent": "NetScan"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.read(limit)


def _xml_text(elem, tag):
    """Text of the first descendant with this local tag name (UPnP XML uses namespaces)."""
    for e in elem.iter():
        if e.tag.rsplit("}", 1)[-1] == tag and e.text:
            return e.text.strip()
    return ""


def upnp_description(url):
    """A UPnP device description: names, model, device type, and its WAN connection service if it's a router."""
    try:
        root = ET.fromstring(_http_get(url))
    except (OSError, ValueError, ET.ParseError, http.client.HTTPException):
        return None
    info = {"url": url, "friendly": _xml_text(root, "friendlyName"),
            "manufacturer": _xml_text(root, "manufacturer"), "model": _xml_text(root, "modelName"),
            "model_number": _xml_text(root, "modelNumber"), "device_type": _xml_text(root, "deviceType"),
            "wan": None}
    for svc in root.iter():
        if svc.tag.rsplit("}", 1)[-1] != "service":
            continue
        stype = _xml_text(svc, "serviceType")
        if re.search(r":service:WAN(IP|PPP)Connection:\d", stype):
            info["wan"] = (stype, urllib.parse.urljoin(url, _xml_text(svc, "controlURL")))
            break
    return info


def _soap(control_url, service_type, action, args=""):
    body = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{service_type}">{args}</u:{action}></s:Body></s:Envelope>')
    req = urllib.request.Request(control_url, body.encode(), {
        "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{service_type}#{action}"'})
    with urllib.request.urlopen(req, timeout=3) as r:
        return ET.fromstring(r.read(65536))


def upnp_port_mappings(wan):
    """Ask the router which ports devices have opened to the internet via UPnP (read-only).

    Returns (public_ip, [{"protocol", "external_port", "client", "internal_port", "description",
    "enabled", "lease"}]).
    """
    stype, control = wan
    try:
        public_ip = _xml_text(_soap(control, stype, "GetExternalIPAddress"), "NewExternalIPAddress")
    except (OSError, ET.ParseError, http.client.HTTPException):
        public_ip = ""
    mappings = []
    for index in range(256):
        try:
            r = _soap(control, stype, "GetGenericPortMappingEntry",
                      f"<NewPortMappingIndex>{index}</NewPortMappingIndex>")
        except (OSError, ET.ParseError, http.client.HTTPException):
            break  # the router answers "SpecifiedArrayIndexInvalid" (an HTTP 500) past the last entry
        t = lambda tag: _xml_text(r, tag)
        port = t("NewExternalPort")
        mappings.append({"protocol": t("NewProtocol").lower(), "external_port": int(port) if port.isdigit() else 0,
                         "client": t("NewInternalClient"), "internal_port": t("NewInternalPort"),
                         "description": t("NewPortMappingDescription"), "enabled": t("NewEnabled") != "0",
                         "lease": t("NewLeaseDuration")})
    return public_ip, mappings


IGD_PATHS = ("/rootDesc.xml", "/igd.xml", "/gatedesc.xml", "/description.xml", "/DeviceDescription.xml",
             "/upnp/IGD.xml", "/igdupnp/igddesc.xml")
IGD_PORTS = (5000, 49152, 2048, 1780, 49000, 52869, 5431, 60000, 80)


def find_router_upnp(gateway, candidates=(), ports=()):
    """The router's UPnP description, trying: remembered/SSDP URLs, then its open ports, then common ones."""
    urls = list(candidates)
    for port in list(ports) + [p for p in IGD_PORTS if p not in ports]:
        urls += [f"http://{gateway}:{port}{path}" for path in IGD_PATHS]
    for url in dict.fromkeys(urls):
        info = upnp_description(url)
        if info and info["wan"]:
            return info
    return None


def ipv6_neighbours(net):
    """{MAC: [IPv6 addresses]} of devices answering an all-nodes ping on the network's interface."""
    iface = net["iface"]
    if IS_WIN:
        idx = net.get("ifindex")
        run_text("ping", "-n", "2", f"ff02::1%{idx}" if idx else "ff02::1")
        rows = powershell_json("Get-NetNeighbor -AddressFamily IPv6 | Where-Object { $_.State -ne 'Unreachable' } | "
                               "Select-Object IPAddress, LinkLayerAddress | ConvertTo-Json -Compress")
        pairs = [(r.get("IPAddress", ""), (r.get("LinkLayerAddress") or "").replace("-", ":")) for r in as_list(rows)]
    elif IS_MAC:
        run_text("/sbin/ping6", "-c", "2", f"ff02::1%{iface}")
        pairs = []
        for line in run_text("/usr/sbin/ndp", "-an").splitlines()[1:]:
            f = line.split()
            if len(f) >= 2 and ":" in f[1]:
                pairs.append((f[0], normalize_mac(f[1])))
    else:
        # Let the multicast ping run its full time (-c would stop at the first couple of replies,
        # before the kernel has learned everyone's MAC), then resolve any MAC still missing.
        replies = run_text("ping", "-6", "-w", "2", "-i", "1", f"ff02::1%{iface}")  # users: >= 1s for multicast
        addrs = set(re.findall(r"from ([0-9a-f:]+)%", replies))

        def table():
            return {n.get("dst", ""): n.get("lladdr", "") for n in ip_json("-6", "neigh", "show", "dev", iface)
                    if n.get("lladdr") and "FAILED" not in n.get("state", [])}

        known = table()
        missing = [a for a in addrs if a not in known]
        if missing:
            with ThreadPoolExecutor(max_workers=16) as ex:
                list(ex.map(lambda a: run_text("ping", "-6", "-c", "1", "-w", "1", f"{a}%{iface}"), missing))
            known = table()
        pairs = list(known.items())
    out = {}
    for addr, mac in pairs:
        mac = mac.upper()
        addr = addr.split("%")[0]
        if mac and addr and mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF") and not addr.startswith("ff"):
            out.setdefault(mac, [])
            if addr not in out[mac]:
                out[mac].append(addr)
    return out


WEB_HINT_PORTS = {80, 81, 443, 591, 3000, 5000, 5001, 7080, 8000, 8008, 8080, 8081, 8088, 8123, 8443,
                  8888, 9000, 9090, 9443, 10000}


def is_web_port(p):
    return p["proto"] == "tcp" and (p["port"] in WEB_HINT_PORTS
                                    or any(w in (p.get("service") or "") for w in ("http", "ssl", "https")))


TLS_HINT_PORTS = {443, 465, 636, 853, 993, 995, 5001, 7681, 8443, 9443}


def is_tls_port(p):
    return p["proto"] == "tcp" and (p["port"] in TLS_HINT_PORTS
                                    or any(w in (p.get("service") or "") for w in ("ssl", "https", "tls")))


def parse_certificate(der):
    """{subject, issuer, expires (ISO date), days_left, self_signed, names} from a DER certificate."""
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        c = x509.load_der_x509_certificate(der)
        cn = lambda name: next((a.value for a in name.get_attributes_for_oid(NameOID.COMMON_NAME)), "") \
            or name.rfc4514_string()
        try:
            names = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
                x509.DNSName)
        except x509.ExtensionNotFound:
            names = []
        expires = c.not_valid_after_utc
        subject, issuer, self_signed = cn(c.subject), cn(c.issuer), c.subject == c.issuer
    except ImportError:
        # No 'cryptography' (e.g. the macOS/Windows installs): CPython's own decoder, via a temp file.
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(ssl.DER_cert_to_PEM_cert(der))
            d = ssl._ssl._test_decode_cert(path)
        finally:
            os.remove(path)
        flat = lambda rdns: dict(x for rdn in rdns for x in rdn)
        subject, issuer = flat(d.get("subject", ())), flat(d.get("issuer", ()))
        self_signed = subject == issuer
        subject, issuer = subject.get("commonName", ""), issuer.get("commonName", "") or issuer.get("organizationName", "")
        names = [v for k, v in d.get("subjectAltName", ()) if k == "DNS"]
        expires = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(d["notAfter"]), datetime.timezone.utc)
    return {"subject": subject, "issuer": issuer, "expires": expires.date().isoformat(),
            "days_left": (expires - now).days, "self_signed": self_signed, "names": names[:6]}


def tls_certificate(ip, port, timeout=3):
    """Certificate a TLS service presents (not verified; LAN devices are usually self-signed), or None."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw, \
                ctx.wrap_socket(raw, server_hostname=None) as tls:
            der = tls.getpeercert(binary_form=True)
        return parse_certificate(der) if der else None
    except (OSError, ValueError):
        return None


def cert_note(cert):
    """(text for the details table, warning or '')."""
    who = "self-signed" if cert["self_signed"] else f"issued by {cert['issuer']}"
    text = f"cert {cert['subject'] or '(no name)'}, {who}, expires {cert['expires']}"
    days = cert["days_left"]
    warn = (f"Certificate expired {-days} day(s) ago" if days < 0 else
            f"Certificate expires in {days} day(s)" if days < 14 else "")
    return text, warn


def web_title(ip, port):
    """<title> of the page at ip:port (HTTPS first for TLS-ish ports), or 'HTTP 401 Unauthorized' etc."""
    schemes = ("https", "http") if port in (443, 8443, 9443, 5001) else ("http", "https")
    host = f"[{ip}]" if ":" in ip else ip
    for scheme in schemes:
        url = f"{scheme}://{host}:{port}/"
        try:
            body = _http_get(url, timeout=3, limit=65536)
            status = ""
        except urllib.error.HTTPError as e:
            body, status = e.read(65536), f"HTTP {e.code} {e.reason}"
        except (OSError, ValueError, http.client.HTTPException):
            continue
        m = re.search(rb"(?is)<title[^>]*>(.*?)</title>", body)
        if m:
            title = re.sub(r"\s+", " ", html.unescape(m.group(1).decode(errors="replace"))).strip()
            if title:
                return title[:80]
        if status:
            return status
        return ""
    return ""


def run_discovery(job):
    """Background part of discovery; every step is read-only and optional. Returns a result dict."""
    net, gw, out = job["net"], job["gateway"], {"token": job["token"]}
    with ThreadPoolExecutor(max_workers=24) as ex:
        tasks = {}
        if "names" in job["what"]:
            tasks["mdns"] = ex.submit(mdns_browse, net["local_ip"])
            tasks["ssdp"] = ex.submit(ssdp_search, net["local_ip"])
            tasks["ipv6"] = ex.submit(ipv6_neighbours, net)
        titles = {key: ex.submit(web_title, *key) for key in job["web"]}
        certs = {key: ex.submit(tls_certificate, *key) for key in job.get("tls", [])}
        for key, fut in tasks.items():
            try:
                out[key] = fut.result()
            except Exception as e:  # noqa: BLE001 - one failing source mustn't sink the rest
                out[key] = {}
                out.setdefault("errors", []).append(f"{key}: {e}")
        out["certs"] = {key: fut.result() for key, fut in certs.items() if fut.result()}
        out["titles"] = {}
        for key, fut in titles.items():
            try:
                if fut.result():
                    out["titles"][key] = fut.result()
            except Exception:  # noqa: BLE001
                pass
        if "names" in job["what"]:
            descs = {}
            for ip, urls in job.get("announced", {}).items():  # heard by the SsdpListener
                out.setdefault("ssdp", {}).setdefault(ip, [])
                out["ssdp"][ip] = sorted(set(out["ssdp"][ip]) | set(urls))
            wanted = {ip: urls[:3] for ip, urls in out.get("ssdp", {}).items()}
            futs = {(ip, u): ex.submit(upnp_description, u) for ip, urls in wanted.items() for u in urls}
            for (ip, _u), fut in futs.items():
                info = fut.result()
                if info and ip not in descs:
                    descs[ip] = info
                elif info and info["wan"] and not descs[ip]["wan"]:
                    descs[ip] = info
            out["upnp_devices"] = descs
    if "names" in job["what"] and gw:
        known = [d["url"] for ip, d in out.get("upnp_devices", {}).items() if ip == gw and d["wan"]]
        router = find_router_upnp(gw, known + list(job["upnp_urls"]), job["upnp_ports"])
        if not router and job.get("nmap"):
            # UPnP often sits on a random high port that quick scans skip and firewalls hide from
            # SSDP. Sweep the router once; the URL found is remembered, so this is rare.
            out_g = run_text(job["nmap"], "-n", "-Pn", "-T4", "--open", "-p", "1024-65535",
                             *iface_args(net), gw, "-oG", "-")
            ports = [int(x) for x in re.findall(r"(\d+)/open/tcp", out_g)]
            router = find_router_upnp(gw, (), [p for p in ports if p not in job["upnp_ports"]]) if ports else None
        if router:
            public_ip, mappings = upnp_port_mappings(router["wan"])
            out["upnp"] = {"url": router["url"], "public_ip": public_ip, "mappings": mappings,
                           "friendly": router["friendly"]}
        else:
            out["upnp"] = None
    return out


def ufw_active():
    return not (IS_WIN or IS_MAC) and run_text("systemctl", "is-active", "ufw").strip() == "active"
