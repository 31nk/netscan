"""Checks that look at your connection from the outside: what the internet sees on your public address
(Shodan's free InternetDB and spam blocklists), VPN and DNS leaks, and latency to game/call regions.
Every function here contacts outside services, and only when you press the button that runs it."""

import json
import socket
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .internet import cloudflare_trace, dns_servers
from .system import ping_once

AGENT = {"User-Agent": "NetScan"}


def _get_json(url, timeout=8):
    req = urllib.request.Request(url, headers={**AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(2_000_000))


# ---- what the internet sees -----------------------------------------------------------------

# DNS blocklists: (zone, name, what a listing means). Queried as <reversed ip>.<zone>; an answer means listed.
BLOCKLISTS = [
    ("zen.spamhaus.org", "Spamhaus", "mail from this address is widely rejected"),
    ("b.barracudacentral.org", "Barracuda", "mail from this address is rejected by Barracuda filters"),
    ("bl.spamcop.net", "SpamCop", "this address recently sent spam (listings expire within a day)"),
    ("psbl.surriel.com", "PSBL", "this address sent mail to spam traps"),
]


def spamhaus_meaning(codes):
    """(status, meaning) for Spamhaus ZEN answers (127.0.0.x), worst first."""
    last = {int(c.rsplit(".", 1)[1]) for c in codes}
    if last & {2, 3, 9}:
        return "listed", "a known spam operation used this address"
    if last & {4, 5, 6, 7}:
        return "listed", "a device using this address recently showed signs of malware or abuse"
    if last & {10, 11}:
        return "policy", "a home, mobile or VPN range that shouldn't send mail directly (normal)"
    return "listed", "listed"


def blocklist_status(ip):
    """[(list name, "listed"|"policy"|"clean"|"unknown", meaning)] for a public IPv4 address."""
    rev = ".".join(reversed(ip.split(".")))

    def one(entry):
        zone, name, meaning = entry
        try:
            codes = socket.gethostbyname_ex(f"{rev}.{zone}")[2]
        except socket.gaierror:
            return name, "clean", meaning
        except OSError:
            return name, "unknown", meaning
        # 127.255.255.x: the list refuses to answer (e.g. queries from big public DNS servers), not a listing.
        if not codes or any(c.startswith("127.255.255.") or not c.startswith("127.") for c in codes):
            return name, "unknown", meaning
        return (name, *spamhaus_meaning(codes)) if name == "Spamhaus" else (name, "listed", meaning)

    with ThreadPoolExecutor(max_workers=len(BLOCKLISTS)) as ex:
        return list(ex.map(one, BLOCKLISTS))


def exposure_check(gateway=None):
    """Your public IPv4 address, what Shodan's scanners last saw on it, blocklist listings, and whether a VPN
    is in the path (then the address is the VPN server's, not your home's)."""
    from .probes import ttl_probe  # late: probes imports tools
    trace = cloudflare_trace()
    ip = trace.get("ip", "")
    hop = ttl_probe("1.1.1.1", 1)[0]
    out = {"ip": ip, "country": trace.get("loc", ""), "shodan": None, "shodan_error": "", "blocklists": [],
           "vpn": bool(hop and gateway and hop != gateway)}
    if not ip or ":" in ip:
        out["shodan_error"] = "no public IPv4 address found"
        return out
    try:
        out["shodan"] = _get_json(f"https://internetdb.shodan.io/{ip}")
    except urllib.error.HTTPError as e:
        if e.code == 404:  # "No information available": Shodan has never seen anything open here
            out["shodan"] = {"ports": [], "vulns": [], "hostnames": [], "cpes": [], "tags": []}
        else:
            out["shodan_error"] = f"HTTP {e.code}"
    except (OSError, ValueError) as e:
        out["shodan_error"] = str(e)
    out["blocklists"] = blocklist_status(ip)
    return out


# Ports seen from the internet: what they usually are and how worried to be.
EXPOSED_PORTS = {
    21: ("FTP", "high"), 22: ("SSH remote login", "medium"), 23: ("Telnet", "high"), 25: ("mail server", "info"),
    53: ("DNS server (can be abused for attacks if open to all)", "high"), 80: ("web page", "medium"),
    443: ("web page (HTTPS)", "medium"), 445: ("Windows file sharing", "high"), 1723: ("PPTP VPN (outdated)", "high"),
    1900: ("UPnP (should never face the internet)", "high"), 3389: ("Remote Desktop", "high"),
    5900: ("VNC screen sharing", "high"), 7547: ("TR-069 provider management", "medium"),
    8080: ("web page", "medium"), 8443: ("web page (HTTPS)", "medium"), 32400: ("Plex", "low"),
    51820: ("WireGuard VPN", "low"), 1194: ("OpenVPN", "low"),
}


def exposure_findings(res, vpn=False, forwards=()):
    """[(level, title, detail)] for exposure_check(). forwards: the router's UPnP port forwards, to name them."""
    f = []
    who = "your VPN's server" if vpn else "your home connection"
    s = res.get("shodan")
    if s is None:
        f.append(("info", "Couldn't ask Shodan", res.get("shodan_error") or "no answer"))
    else:
        ports = sorted(s.get("ports") or [])
        if not ports:
            f.append(("good", "Nothing open to the internet",
                      f"Shodan's scanners haven't found any open ports on {res['ip']} ({who})."))
        for port in ports:
            name, level = EXPOSED_PORTS.get(port, ("unknown service", "medium"))
            fwd = next((m for m in forwards if m.get("external_port") == port), None)
            detail = (f"Forwarded by your router to {fwd['client']}" + (f" ({fwd['description']})"
                                                                        if fwd.get("description") else "") + ". "
                      if fwd else "")
            detail += ("Anyone on the internet can try to connect. Close it in the router unless you run it on "
                       "purpose; if you do, keep it updated and use strong passwords." if level in ("high", "medium")
                       else "Normal if you use this app.")
            f.append(({"high": "bad", "medium": "warn"}.get(level, "info"), f"Port {port} is open: {name}", detail))
        vulns = s.get("vulns") or []
        if vulns:
            f.append(("bad", f"{len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'} matched",
                      "Shodan matched the software it saw to published advisories: " + ", ".join(sorted(vulns)[:12])
                      + (" …" if len(vulns) > 12 else "") + ". Update whatever answers on those ports."))
        if s.get("hostnames"):
            f.append(("info", "Names pointing here", ", ".join(s["hostnames"][:6])))
        if ports:
            f.append(("info", "About this data", "Shodan scans the whole internet every few days, so this can be up "
                                                  "to a week old. Check again after closing a port."))
    listed = [(n, m) for n, st, m in res.get("blocklists") or [] if st == "listed"]
    unknown = [n for n, st, _m in res.get("blocklists") or [] if st == "unknown"]
    for name, meaning in listed:
        f.append(("info" if vpn else "warn", f"Listed on {name}",
                  f"{res['ip']} is on the {name} blocklist: {meaning}. "
                  + ("Normal for a VPN address shared by many people; some sites may show you extra captchas."
                     if vpn else "On a home connection this usually means another customer had this address before, "
                     "or a device on your network is infected. The list's website has a removal form.")))
    for name, st, meaning in res.get("blocklists") or []:
        if st == "policy":
            f.append(("info", f"In {name}'s policy list", f"{meaning.capitalize()}. Only matters if you run a mail "
                                                            "server at home."))
    clean = [n for n, st, _m in res.get("blocklists") or [] if st in ("clean", "policy")]
    if clean:
        f.append(("good", f"Not on {'the spam blocklists checked' if not listed else 'the other blocklists'}",
                  ", ".join(clean) + (f" (couldn't check {', '.join(unknown)}: it refuses lookups from big public DNS "
                                      "servers)" if unknown else "")))
    return f


# ---- VPN and DNS leaks --------------------------------------------------------------------------

V6_TRACE = "https://[2606:4700:4700::1111]/cdn-cgi/trace"


def ipv6_exit():
    """This connection's public IPv6 address, or None if it has no IPv6 route to the internet."""
    try:
        req = urllib.request.Request(V6_TRACE, headers=AGENT)
        body = urllib.request.urlopen(req, timeout=5).read(4096).decode()
    except (OSError, ValueError):
        return None
    return dict(line.split("=", 1) for line in body.splitlines() if "=" in line).get("ip")


def dns_leak_test():
    """Which DNS servers really carry your lookups (bash.ws): [{"ip", "org", "country"}] plus its conclusion."""
    ident = urllib.request.urlopen(urllib.request.Request("https://bash.ws/id", headers=AGENT),
                                   timeout=8).read(64).decode().strip()
    if not ident.isalnum():
        raise OSError("unexpected answer from bash.ws")
    for n in range(1, 7):  # each lookup of a fresh name reaches bash.ws's servers through your real resolvers
        try:
            socket.getaddrinfo(f"{n}.{ident}.bash.ws", None)
        except OSError:
            pass
    time.sleep(0.5)
    rows = _get_json(f"https://bash.ws/dnsleak/test/{ident}?json")
    servers = [{"ip": r["ip"], "org": r.get("org") or r.get("asn") or "?", "country": r.get("country_name", "")}
               for r in rows if r.get("type") == "dns"]
    conclusion = next((r["ip"] for r in rows if r.get("type") == "conclusion"), "")
    return servers, conclusion


def privacy_check(gateway):
    """Public IPv4/IPv6 exits and their owners, whether a VPN is in the path, and the DNS leak test."""
    from .probes import ip_owner, ttl_probe  # late: probes imports tools
    out = {"errors": []}
    with ThreadPoolExecutor(max_workers=5) as ex:
        f4, f6 = ex.submit(cloudflare_trace), ex.submit(ipv6_exit)
        fhop, fdns = ex.submit(lambda: ttl_probe("1.1.1.1", 1)[0]), ex.submit(dns_leak_test)
        flocal = ex.submit(dns_servers)
        try:
            trace = f4.result()
            out["v4"], out["country"] = trace.get("ip"), trace.get("loc", "")
        except OSError as e:
            out["v4"], out["country"] = None, ""
            out["errors"].append(f"IPv4: {e}")
        out["v6"] = f6.result()
        out["first_hop"] = fhop.result() if not fhop.exception() else None
        try:
            out["dns"], out["dns_conclusion"] = fdns.result()
        except (OSError, ValueError, KeyError) as e:
            out["dns"], out["dns_conclusion"] = None, ""
            out["errors"].append(f"DNS leak test: {e}")
        out["local_dns"] = flocal.result() if not flocal.exception() else []
    out["gateway"] = gateway
    for key in ("v4", "v6"):
        try:
            out[f"{key}_owner"] = ip_owner(out[key])[0] if out.get(key) else None
        except (OSError, ValueError):
            out[f"{key}_owner"] = None
    return out


def _org_key(name):
    """Compare company names loosely: 'Tzulo, Inc.' ~ 'Tzulo Inc.'"""
    words = [w for w in "".join(c if c.isalnum() else " " for c in (name or "").lower()).split()
             if w not in ("inc", "llc", "ltd", "ab", "gmbh", "bv", "limited", "corp", "co", "services")]
    return " ".join(words[:2])


def privacy_findings(m):
    f = []
    vpn = bool(m.get("first_hop") and m.get("gateway") and m["first_hop"] != m["gateway"])
    v4, v6 = m.get("v4"), m.get("v6")
    o4, o6 = m.get("v4_owner"), m.get("v6_owner")
    if vpn:
        f.append(("good", "A VPN is on",
                  f"Traffic leaves through {m['first_hop']}, not straight through your router ({m['gateway']}). Sites "
                  f"see {v4 or '?'}" + (f", owned by {o4.rstrip('.')}" if o4 else "") + "."))
    else:
        f.append(("info", "No VPN in use",
                  f"Sites see your home address {v4 or '?'}" + (f" ({o4})" if o4 else "") + ". That's normal; a VPN "
                  "only matters on untrusted Wi-Fi or if you want to hide your address."))
    if v6:
        same = o4 and o6 and _org_key(o4) == _org_key(o6)
        if vpn and not same:
            f.append(("bad", "IPv6 bypasses your VPN",
                      f"IPv6 traffic leaves from {v6}" + (f" ({o6})" if o6 else "") + ", not through the VPN. Sites "
                      "that support IPv6 see your real connection. Turn on the VPN's IPv6 leak protection, or turn "
                      "IPv6 off on this computer."))
        elif vpn:
            f.append(("good", "IPv6 goes through the VPN too", f"IPv6 exit {v6}, same provider as IPv4."))
        else:
            f.append(("info", "IPv6 works", f"Public IPv6 address {v6}. Devices on IPv6 are reachable only if the "
                                            "router's IPv6 firewall allows it (most block incoming by default)."))
    else:
        f.append(("info", "No IPv6", "This connection doesn't reach the internet over IPv6, so nothing can leak "
                                     "that way. Some games and sites are slightly faster over IPv6."))
    servers = m.get("dns")
    if servers:
        orgs = sorted({s["org"] for s in servers})
        listing = "; ".join(f"{s['ip']} ({s['org']}, {s['country']})" for s in servers[:6])
        exit_key = _org_key(o4)
        outside = [o for o in orgs if _org_key(o) != exit_key]
        if vpn and outside:
            f.append(("warn", "DNS lookups don't all go through the VPN",
                      f"Your lookups reach the internet via {', '.join(outside)}, not only the VPN ({o4 or 'its exit'}). "
                      "Whoever runs those servers, and anyone between, can see which sites you visit. Use the VPN's "
                      f"own DNS setting to fix it. Servers: {listing}."))
        elif vpn:
            f.append(("good", "DNS goes through the VPN", f"Servers: {listing}."))
        else:
            f.append(("info", f"Your lookups are answered by {', '.join(orgs)}",
                      f"They can see which sites you visit. Servers: {listing}."))
    return f, vpn


# ---- gaming and calls -------------------------------------------------------------------------

# Cloud regions games and call services commonly run in. Timed as a TCP handshake to port 443 (works
# without admin rights and through firewalls that drop pings).
REGIONS = [
    ("US East (Virginia)", "dynamodb.us-east-1.amazonaws.com"),
    ("US Central (Ohio)", "dynamodb.us-east-2.amazonaws.com"),
    ("US West (Oregon)", "dynamodb.us-west-2.amazonaws.com"),
    ("Europe (Frankfurt)", "dynamodb.eu-central-1.amazonaws.com"),
    ("Europe (London)", "dynamodb.eu-west-2.amazonaws.com"),
    ("South America (São Paulo)", "dynamodb.sa-east-1.amazonaws.com"),
    ("Asia (Tokyo)", "dynamodb.ap-northeast-1.amazonaws.com"),
    ("Asia (Singapore)", "dynamodb.ap-southeast-1.amazonaws.com"),
    ("Australia (Sydney)", "dynamodb.ap-southeast-2.amazonaws.com"),
]


def tcp_rtt(ip, port=443, timeout=2.0):
    t = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return (time.perf_counter() - t) * 1000
    except OSError:
        return None


def region_latency(host, samples=8, gap=0.4):
    try:
        ip = socket.getaddrinfo(host, 443, socket.AF_INET)[0][4][0]
    except OSError:
        return None
    values = []
    for _ in range(samples):
        values.append(tcp_rtt(ip))
        time.sleep(gap)
    ok = [v for v in values if v is not None]
    return {"median": statistics.median(ok) if ok else None, "min": min(ok) if ok else None,
            "jitter": statistics.mean(abs(a - b) for a, b in zip(ok, ok[1:])) if len(ok) > 1 else None,
            "failed": len(values) - len(ok)}


def stability(target="1.1.1.1", count=40, gap=0.25):
    """Jitter and loss over ~15 s of pings: what calls and games feel."""
    values = []
    for _ in range(count):
        values.append(ping_once(target))
        time.sleep(gap)
    ok = [v for v in values if v is not None]
    return {"median": statistics.median(ok) if ok else None,
            "jitter": statistics.mean(abs(a - b) for a, b in zip(ok, ok[1:])) if len(ok) > 1 else None,
            "loss": 100 * (count - len(ok)) / count,
            "spikes": sum(1 for v in ok if ok and v > 3 * statistics.median(ok) + 20)}


def gaming_check():
    with ThreadPoolExecutor(max_workers=len(REGIONS) + 1) as ex:
        stab = ex.submit(stability)
        regions = {name: ex.submit(region_latency, host) for name, host in REGIONS}
        return {"stability": stab.result(), "regions": [(name, fut.result()) for name, fut in regions.items()]}


def gaming_verdicts(res, speed=None, nat_kind=None):
    """Per activity: [(activity, level, verdict, why)] plus the nearest region."""
    st = res["stability"]
    reachable = [(name, r) for name, r in res["regions"] if r and r["median"] is not None]
    nearest = min(reachable, key=lambda x: x[1]["median"]) if reachable else None
    near_ms = nearest[1]["median"] if nearest else None
    jitter, loss = st["jitter"] or 0, st["loss"]
    bloat = (speed or {}).get("grade")
    down, up = (speed or {}).get("down"), (speed or {}).get("up")
    out = []

    def grade(activity, checks, fine="latency, jitter and loss are all low"):
        """checks: [(ok?, soft-fail?, reason)] -> good if all ok, warn if only soft fails, else bad."""
        hard = [r for ok, soft, r in checks if not ok and not soft]
        soft = [r for ok, s, r in checks if not ok and s]
        level = "bad" if hard else "warn" if soft else "good"
        verdict = {"good": "Great", "warn": "OK, with hiccups", "bad": "Poor"}[level]
        out.append((activity, level, verdict, "; ".join(hard + soft) or fine))

    grade("Video calls (Zoom, Teams, FaceTime)", [
        (loss < 1, loss < 3, f"{loss:.0f}% packet loss (calls break up)"),
        (jitter < 30, jitter < 50, f"jitter {jitter:.0f} ms (choppy audio)"),
        (near_ms is None or near_ms < 150, True, f"{near_ms or 0:.0f} ms to the nearest region"),
        (up is None or up >= 3, up is not None and up >= 1.5, f"upload {up or 0:.1f} Mbit/s (your video)"),
        (bloat not in ("D", "F"), bloat != "F", f"bufferbloat grade {bloat} (lag when others use the line)"),
    ])
    grade("Online games", [
        (near_ms is None or near_ms < 60, near_ms is not None and near_ms < 120,
         f"{near_ms or 0:.0f} ms to the nearest region ({nearest[0] if nearest else '?'})"),
        (jitter < 10, jitter < 25, f"jitter {jitter:.0f} ms (rubber-banding)"),
        (loss == 0, loss < 2, f"{loss:.0f}% packet loss"),
        (bloat in (None, "A+", "A", "B"), bloat not in ("D", "F"), f"bufferbloat grade {bloat}"),
        (nat_kind not in ("double", "cgnat"), True, "strict NAT likely (double NAT / shared address): trouble "
                                                    "joining or hosting lobbies"),
    ])
    grade("Cloud gaming (GeForce Now, Xbox Cloud)", [
        (near_ms is None or near_ms < 40, near_ms is not None and near_ms < 80, f"{near_ms or 0:.0f} ms to the nearest region"),
        (jitter < 5, jitter < 15, f"jitter {jitter:.0f} ms"),
        (loss == 0, loss < 1, f"{loss:.0f}% packet loss"),
        (down is None or down >= 45, down is not None and down >= 20, f"download {down or 0:.0f} Mbit/s (1080p+ needs 45)"),
    ])
    if down is None:
        out.append(("4K streaming", "info", "Unknown", "needs a speed test: tick “Include a speed test” or run one "
                                                       "on the Internet tab"))
    else:
        grade("4K streaming", [(down >= 25, down >= 15, f"download {down:.0f} Mbit/s (4K needs about 25)")],
              fine=f"download {down:.0f} Mbit/s, plenty for 4K")
    return out, nearest

