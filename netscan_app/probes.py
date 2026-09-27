"""Engines for the newer Tools panels: this computer's connections and traffic, hop discovery for the
continuous trace, the domain toolkit and website checks. No GUI code; all read-only."""

import datetime
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .devices import data_dir
from .discovery import tls_certificate
from .system import IS_MAC, IS_WIN, as_list, powershell_json, run_text
from .tools import doh_query

AGENT = {"User-Agent": "NetScan"}

# ---- connections -------------------------------------------------------------------


def _split_hostport(text):
    """'1.2.3.4:443', '[::1]:53', '192.168.1.5%wlan0:68' -> (host, port)."""
    host, _, port = text.rpartition(":")
    return host.strip("[]").split("%")[0], int(port) if port.isdigit() else 0


def list_connections():
    """This computer's established connections: [{proto, local_port, ip, port, program}], loopback left out."""
    rows = []
    if IS_WIN:
        data = powershell_json("""
$ErrorActionPreference = 'SilentlyContinue'
$names = @{}; Get-Process | ForEach-Object { $names[$_.Id] = $_.ProcessName }
Get-NetTCPConnection -State Established | ForEach-Object {
  @{ lport = $_.LocalPort; ip = "$($_.RemoteAddress)"; port = $_.RemotePort; program = $names[[int]$_.OwningProcess] } } |
  ConvertTo-Json -Compress""")
        for r in as_list(data):
            rows.append({"proto": "tcp", "local_port": r.get("lport", 0), "ip": r.get("ip", ""),
                         "port": r.get("port", 0), "program": r.get("program") or ""})
    elif IS_MAC:
        command = ""
        for line in run_text("/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "cn").splitlines():
            if line.startswith("c"):
                command = line[1:]
            elif line.startswith("n") and "->" in line:
                local, remote = line[1:].split("->", 1)
                ip, port = _split_hostport(remote)
                rows.append({"proto": "tcp", "local_port": _split_hostport(local)[1], "ip": ip, "port": port,
                             "program": command})
    else:
        for line in run_text("ss", "-tunpH", "state", "established").splitlines():
            f = line.split()
            if len(f) < 5:
                continue
            ip, port = _split_hostport(f[4])
            m = re.search(r'users:\(\("([^"]+)"', line)
            rows.append({"proto": f[0], "local_port": _split_hostport(f[3])[1], "ip": ip, "port": port,
                         "program": m.group(1) if m else ""})
    out = []
    for r in rows:
        try:
            addr = ipaddress.ip_address(r["ip"])
        except ValueError:
            continue
        if addr.is_loopback or addr.is_unspecified:
            continue
        out.append(r)
    return out


REGISTRY_REGION = {"ARIN": "North America", "RIPE": "Europe/Middle East", "APNIC": "Asia-Pacific",
                   "LACNIC": "Latin America", "AFRINIC": "Africa"}
_OWNERS = {"cache": None, "lock": threading.Lock()}
OWNER_CACHE_DAYS = 14


def _owner_cache():
    if _OWNERS["cache"] is None:
        try:
            with open(os.path.join(data_dir(), "ip_owners.json"), encoding="utf-8") as f:
                _OWNERS["cache"] = json.load(f)
        except (OSError, ValueError):
            _OWNERS["cache"] = {}
    return _OWNERS["cache"]


def ip_owner(ip):
    """(owner, where) for an IP: 'your network' for private ones, else from RDAP; cached on disk for two weeks."""
    addr = ipaddress.ip_address(ip)
    if not addr.is_global:
        return ("your network" if addr.is_private else "special address"), ""
    cache = _owner_cache()
    hit = cache.get(ip)
    if hit and time.time() - hit[2] < OWNER_CACHE_DAYS * 86400:
        return hit[0], hit[1]
    req = urllib.request.Request(f"https://rdap.org/ip/{ip}", headers={**AGENT, "Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        d = json.loads(r.read(1_000_000))
    owner = ""
    for ent in d.get("entities", []):
        vcard = ent.get("vcardArray", [None, []])[1]
        owner = next((v[3] for v in vcard if v and v[0] == "fn"), "")
        if owner:
            break
    registry = (d.get("port43") or "").replace("whois.", "").split(".")[0].upper()
    where = d.get("country") or REGISTRY_REGION.get(registry, "")
    owner = owner or d.get("name", "") or "unknown"
    with _OWNERS["lock"]:
        cache[ip] = [owner, where, time.time()]
        try:
            with open(os.path.join(data_dir(), "ip_owners.json"), "w", encoding="utf-8") as f:
                json.dump(cache, f)
        except OSError:
            pass
    return owner, where


def reverse_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def describe_connections(limit=40):
    """Connections grouped by program + remote address, with owner/where/name for up to `limit` remote IPs."""
    groups = {}
    for c in list_connections():
        key = (c["program"], c["ip"], c["port"], c["proto"])
        groups.setdefault(key, 0)
        groups[key] += 1
    cache = _owner_cache()
    ips = list(dict.fromkeys(ip for _p, ip, _port, _proto in groups))
    fresh = [ip for ip in ips if ip not in cache and ipaddress.ip_address(ip).is_global][:limit]
    ips = [ip for ip in ips if ip in cache or not ipaddress.ip_address(ip).is_global] + fresh

    def look(ip):
        try:
            owner = ip_owner(ip)
        except (OSError, ValueError, http.client.HTTPException):
            owner = ("", "")
        return ip, owner, reverse_name(ip)

    with ThreadPoolExecutor(max_workers=8) as ex:  # RDAP servers dislike bursts
        info = {ip: (owner, name) for ip, owner, name in ex.map(look, ips)}
    rows = []
    for (program, ip, port, proto), count in groups.items():
        (owner, where), name = info.get(ip, (("", ""), ""))
        try:
            service = socket.getservbyport(port, "tcp" if proto.startswith("tcp") else "udp")
        except OSError:
            service = ""
        rows.append({"program": program or "(system)", "ip": ip, "port": port, "service": service, "proto": proto,
                     "count": count, "owner": owner, "where": where, "name": name})
    return sorted(rows, key=lambda r: (r["program"].lower(), r["owner"], r["ip"]))


# ---- traffic -------------------------------------------------------------------------


def interface_counters():
    """{interface: (bytes received, bytes sent)} since boot."""
    out = {}
    if IS_WIN:
        for r in as_list(powershell_json("Get-NetAdapterStatistics | Select-Object Name, ReceivedBytes, SentBytes | "
                                         "ConvertTo-Json -Compress")):
            out[r.get("Name", "?")] = (int(r.get("ReceivedBytes") or 0), int(r.get("SentBytes") or 0))
    elif IS_MAC:
        for line in run_text("/usr/sbin/netstat", "-ibn").splitlines()[1:]:
            f = line.split()
            if len(f) >= 10 and f[2].startswith("<Link#") and f[0] not in out:
                try:  # columns: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes
                    out[f[0]] = (int(f[6]), int(f[9]))
                except ValueError:
                    pass
    else:
        try:
            with open("/proc/net/dev") as f:
                for line in f.readlines()[2:]:
                    name, _, rest = line.partition(":")
                    v = rest.split()
                    out[name.strip()] = (int(v[0]), int(v[8]))
        except OSError:
            pass
    return {k: v for k, v in out.items() if k not in ("lo", "lo0") and not k.startswith("Loopback")}


# ---- continuous trace ---------------------------------------------------------------


def ttl_probe(target, ttl, timeout=2):
    """Who answers a ping allowed only `ttl` hops: (ip or None, reached the target?)."""
    if IS_WIN:
        out = run_text("ping", "-n", "1", "-w", str(timeout * 1000), "-i", str(ttl), target)
        m = re.search(r"Reply from ([0-9a-fA-F.:]+)", out)
        return (m.group(1), "TTL expired" not in out) if m else (None, False)
    ttl_flag = "-m" if IS_MAC else "-t"
    out = run_text("ping" if not IS_MAC else "/sbin/ping", "-n", "-c", "1", ttl_flag, str(ttl),
                   "-W", str(timeout * 1000 if IS_MAC else timeout), target)
    reached = re.search(r"bytes from ([0-9a-fA-F.:]+)", out)
    if reached:
        return reached.group(1).rstrip(":"), True  # "64 bytes from 1.1.1.1: icmp_seq=1"
    m = re.search(r"[Ff]rom ([0-9a-fA-F.:]+)", out)
    return (m.group(1).rstrip(":"), False) if m else (None, False)


def find_hops(target, max_hops=24):
    """The path to target, found with TTL-limited pings all at once: [ip or None per hop]."""
    target_ip = socket.getaddrinfo(target, None, socket.AF_INET)[0][4][0]
    with ThreadPoolExecutor(max_workers=max_hops) as ex:
        results = list(ex.map(lambda ttl: ttl_probe(target_ip, ttl), range(1, max_hops + 1)))
    hops = []
    for ip, reached in results:
        hops.append(ip)
        if reached:
            break
    if not any(reached for _ip, reached in results):
        while hops and hops[-1] is None:  # trailing silence past the last hop that answered
            hops.pop()
        hops.append(target_ip)
    return target_ip, hops


# ---- domain toolkit --------------------------------------------------------------------

DKIM_SELECTORS = ("google", "default", "selector1", "selector2", "k1", "k2", "dkim", "mail", "s1", "s2",
                  "smtp", "mx", "email", "20230601", "fm1", "protonmail")


def domain_report(domain):
    """Registration (RDAP), name servers, mail servers and email security records for a domain."""
    domain = domain.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    out = {"domain": domain, "rdap": None}
    try:
        req = urllib.request.Request(f"https://rdap.org/domain/{domain}", headers={**AGENT,
                                                                                  "Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read(1_000_000))
        events = {e.get("eventAction"): e.get("eventDate", "")[:10] for e in d.get("events", [])}
        registrar = ""
        for ent in d.get("entities", []):
            if "registrar" in ent.get("roles", []):
                vcard = ent.get("vcardArray", [None, []])[1]
                registrar = next((v[3] for v in vcard if v and v[0] == "fn"), "")
        out["rdap"] = {"registrar": registrar, "created": events.get("registration", ""),
                       "expires": events.get("expiration", ""), "changed": events.get("last changed", ""),
                       "status": d.get("status", []),
                       "nameservers": [n.get("ldhName", "").lower() for n in d.get("nameservers", [])]}
    except (OSError, ValueError, http.client.HTTPException) as e:
        out["rdap_error"] = str(getattr(e, "reason", e))

    def txt(name):
        try:
            return [" ".join(v) if isinstance(v, list) else v for t, v in doh_query(name, "TXT")[1] if t == "TXT"]
        except (OSError, ValueError, http.client.HTTPException):
            return []

    try:
        out["ns"] = [v for t, v in doh_query(domain, "NS")[1] if t == "NS"]
        mx = sorted(v for t, v in doh_query(domain, "MX")[1] if t == "MX")
        out["null_mx"] = bool(mx) and all(not host for _pref, host in mx)  # RFC 7505 "0 ." = accepts no mail
        out["mx"] = [m for m in mx if m[1]]
    except (OSError, ValueError, http.client.HTTPException) as e:
        out["dns_error"] = str(e)
        out["ns"], out["mx"] = [], []
    out["spf"] = [t for t in txt(domain) if t.lower().startswith("v=spf1")]
    out["dmarc"] = [t for t in txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    with ThreadPoolExecutor(max_workers=8) as ex:
        found = list(ex.map(lambda sel: (sel, txt(f"{sel}._domainkey.{domain}")), DKIM_SELECTORS))
    # A real key has a long base64 p= value; an empty p= means "no/revoked key". Many selectors all
    # returning the same record means a catch-all (wildcard) record, not real keys.
    keyed = [(sel, r) for sel, recs in found for r in recs if re.search(r"\bp=[A-Za-z0-9+/=]{40,}", r)]
    records = {r for _sel, r in keyed}
    out["dkim_wildcard"] = len(keyed) > 4 and len(records) == 1
    out["dkim"] = [] if out["dkim_wildcard"] else list(dict.fromkeys(sel for sel, _r in keyed))
    out["dkim_null"] = any(re.search(r"\bp=\s*(;|$)", r) for _sel, recs in found for r in recs)
    return out


def email_verdicts(rep):
    """[(level, text)] in plain English: level is 'good', 'warn' or 'info'."""
    v = []
    if rep.get("null_mx"):
        v.append(("info", "Null MX record: this domain explicitly accepts no email."))
    elif not rep["mx"]:
        v.append(("info", "No mail servers (MX): this domain doesn't receive email."))
    spf = rep["spf"][0].lower() if rep["spf"] else ""
    redirect = re.search(r"\bredirect=(\S+)", spf)
    if not spf:
        v.append(("warn", "No SPF record: anyone can send email pretending to be from this domain."))
    elif redirect:
        v.append(("good", f"SPF hands off to {redirect.group(1)}, which sets the policy (common for big providers)."))
    elif spf.rstrip().endswith("-all"):
        v.append(("good", "SPF is strict (-all): mail from unlisted servers should be rejected."))
    elif spf.rstrip().endswith("~all"):
        v.append(("good", "SPF is in soft-fail mode (~all): common and fine alongside DMARC."))
    else:
        v.append(("warn", "SPF doesn't end in -all or ~all, so it doesn't really block spoofing."))
    policy = re.search(r"\bp=(\w+)", rep["dmarc"][0].lower()).group(1) if rep["dmarc"] and \
        re.search(r"\bp=(\w+)", rep["dmarc"][0].lower()) else ""
    if not rep["dmarc"]:
        v.append(("warn", "No DMARC record: receivers aren't told what to do with forged mail."))
    elif policy == "none":
        v.append(("warn", "DMARC is monitor-only (p=none): forged mail is reported but still delivered."))
    else:
        v.append(("good", f"DMARC enforces p={policy}: forged mail gets {'quarantined' if policy == 'quarantine' else 'rejected'}."))
    if rep.get("dkim_null") and not rep["dkim"] and not rep["mx"]:
        v.append(("info", "DKIM record with an empty key: the domain signs no mail (it sends no email)."))
    elif rep.get("dkim_null") and not rep["dkim"]:
        v.append(("info", "Only retired (empty) DKIM keys under common names; the active key uses a custom name "
                          "(visible in a received email's headers)."))
    elif rep.get("dkim_wildcard"):
        v.append(("info", "A catch-all DKIM record answers for every name, so real keys can't be told apart."))
    elif rep["dkim"]:
        v.append(("good", "DKIM signing keys found (selectors: " + ", ".join(rep["dkim"]) + ")."))
    elif rep["mx"]:
        v.append(("info", "No DKIM key under common selector names. It may still exist under a custom name "
                          "(only visible in a received email's headers)."))
    exp = (rep.get("rdap") or {}).get("expires")
    if exp:
        days = (datetime.date.fromisoformat(exp) - datetime.date.today()).days
        if days < 0:
            v.append(("warn", f"The domain registration EXPIRED {-days} day(s) ago."))
        elif days < 30:
            v.append(("warn", f"The domain registration expires in {days} day(s)."))
    return v


# ---- website watch ---------------------------------------------------------------------


def check_site(url, timeout=10):
    """{ok, status, ms, cert_days, error} for one URL (follows redirects, verifies HTTPS like a browser)."""
    if "://" not in url:
        url = "https://" + url
    out = {"url": url, "ok": False, "status": None, "ms": None, "cert_days": None, "error": "",
           "checked": datetime.datetime.now().isoformat(timespec="seconds")}
    req = urllib.request.Request(url, headers=AGENT)
    t = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            r.read(65536)
            out["status"] = r.status
    except urllib.error.HTTPError as e:
        out["status"] = e.code
    except (OSError, http.client.HTTPException) as e:
        out["error"] = str(getattr(e, "reason", e))
    out["ms"] = (time.perf_counter() - t) * 1000
    out["ok"] = out["status"] is not None and out["status"] < 400
    u = urllib.parse.urlparse(url)
    if u.scheme == "https":
        cert = tls_certificate(u.hostname, u.port or 443)
        if cert:
            out["cert_days"] = cert["days_left"]
    return out


def watch_file():
    return os.path.join(data_dir(), "website_watch.json")


def load_watch():
    try:
        with open(watch_file(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def save_watch(sites):
    try:
        with open(watch_file(), "w", encoding="utf-8") as f:
            json.dump(sites, f, indent=1)
    except OSError:
        pass
