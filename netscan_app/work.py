"""Tools for IT work on client networks: outbound firewall test, VoIP readiness, bulk domain checks, mail server
checks, blocklists for any address, DNS propagation, and the documentation CSV. None of it logs in anywhere:
everything uses public services and standard protocols."""

import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .online import AGENT, spamhaus_meaning

# ---- outbound firewall test ---------------------------------------------------------------------

PORTQUIZ = "portquiz.net"   # answers on every TCP port, so a failed connection means something in between blocks it

# (category, port, what uses it). TCP only: UDP is tested separately with STUN and DNS below.
OUTBOUND_PORTS = [
    ("Web", 80, "HTTP"), ("Web", 443, "HTTPS (almost everything)"), ("Web", 8080, "HTTP alternate"),
    ("Mail", 25, "SMTP (sending server to server)"), ("Mail", 465, "SMTPS (mail apps)"),
    ("Mail", 587, "Submission (mail apps)"), ("Mail", 993, "IMAPS"), ("Mail", 995, "POP3S"), ("Mail", 143, "IMAP"),
    ("Remote access", 22, "SSH / SFTP"), ("Remote access", 3389, "Remote Desktop"),
    ("Remote access", 5938, "TeamViewer"), ("Remote access", 7070, "AnyDesk"),
    ("Remote access", 8041, "ScreenConnect relay"), ("Remote access", 5900, "VNC"),
    ("VPN", 1194, "OpenVPN (TCP)"), ("VPN", 1723, "PPTP"), ("VPN", 4433, "SSL VPN (e.g. SonicWall, Fortinet)"),
    ("VPN", 10443, "SSL VPN (Fortinet)"),
    ("Voice & video", 5060, "SIP"), ("Voice & video", 5061, "SIP over TLS"), ("Voice & video", 3478, "STUN/TURN (TCP)"),
    ("Files", 21, "FTP"), ("Files", 445, "SMB file sharing (should be blocked outbound)"),
    ("Other", 53, "DNS over TCP"), ("Other", 853, "DNS over TLS"), ("Other", 123, "NTP (TCP; real NTP is UDP)"),
]


def tcp_out(port, host=PORTQUIZ, timeout=4.0):
    """"open", "blocked" (no connection), or "intercepted" (connected, but something else answered)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: NetScan\r\n\r\n".encode())
            data = b""
            while len(data) < 4096:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    except OSError:
        return "blocked"
    return "open" if b"Port test successful" in data or b"portquiz" in data.lower() else "intercepted"


def stun_mapping(host, port=3478, timeout=3.0, sock=None):
    """Ask a STUN server what address and port it sees us at: (ip, port) or None if UDP is blocked."""
    tid = os.urandom(12)
    msg = struct.pack("!HHI", 1, 0, 0x2112A442) + tid
    own = sock is None
    s = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
        for _ in range(2):  # UDP: one retry
            s.sendto(msg, addr)
            try:
                data, _ = s.recvfrom(2048)
            except socket.timeout:
                continue
            if data[8:20] == tid:
                return parse_stun(data)
        return None
    except OSError:
        return None
    finally:
        if own:
            s.close()


def parse_stun(data):
    """(ip, port) from a STUN binding response's XOR-MAPPED-ADDRESS (or MAPPED-ADDRESS)."""
    pos, found = 20, None
    while pos + 4 <= len(data):
        atype, alen = struct.unpack("!HH", data[pos:pos + 4])
        value = data[pos + 4:pos + 4 + alen]
        if atype in (0x0020, 0x0001) and len(value) >= 8 and value[1] == 1:
            port = struct.unpack("!H", value[2:4])[0]
            raw = value[4:8]
            if atype == 0x0020:
                port ^= 0x2112
                raw = bytes(b ^ m for b, m in zip(raw, struct.pack("!I", 0x2112A442)))
            found = (socket.inet_ntoa(raw), port)
            if atype == 0x0020:
                return found
        pos += 4 + alen + (-alen % 4)
    return found


def nat_behaviour():
    """Same local UDP socket to two STUN servers: the same public port both times means calls can connect
    directly ('friendly' NAT); different ports ('symmetric' NAT) forces calls through relays."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", 0))
        a = stun_mapping("stun.cloudflare.com", 3478, sock=s)
        b = stun_mapping("stun.l.google.com", 19302, sock=s)
    if not a and not b:
        return {"udp": False, "kind": "blocked", "mapped": None}
    if a and b:
        return {"udp": True, "kind": "symmetric" if a[1] != b[1] else "friendly", "mapped": a}
    return {"udp": True, "kind": "unknown", "mapped": a or b}


def udp_dns_ok(server="1.1.1.1"):
    from .tools import dns_query  # late: tools pulls in discovery
    try:
        return dns_query(server, "cloudflare.com", "A", timeout=3)[0] == 0
    except OSError:
        return False


def firewall_test():
    """Every outbound port in OUTBOUND_PORTS plus UDP (DNS, STUN) and the NAT behaviour: about 5-10 seconds."""
    with ThreadPoolExecutor(max_workers=5) as ex:
        dns = ex.submit(udp_dns_ok)
        nat = ex.submit(nat_behaviour)
        # portquiz.net drops connections when one address opens many at once: three at a time, then any
        # failure is tried again on its own before it counts as blocked.
        with ThreadPoolExecutor(max_workers=3) as tcp_ex:
            first = dict(zip([p for _c, p, _w in OUTBOUND_PORTS], tcp_ex.map(tcp_out, [p for _c, p, _w in OUTBOUND_PORTS])))
        final = {p: st if st == "open" else tcp_out(p, timeout=3) for p, st in first.items()}
        rows = [(cat, port, what, final[port]) for cat, port, what in OUTBOUND_PORTS]
        return {"tcp": rows, "udp_dns": dns.result(), "nat": nat.result()}


def firewall_findings(res):
    f = []
    blocked = [r for r in res["tcp"] if r[3] == "blocked"]
    intercepted = [r for r in res["tcp"] if r[3] == "intercepted"]
    if not blocked and not intercepted:
        f.append(("good", "Every outbound port tested is open", "Nothing on this network restricts outgoing TCP."))
    for port_list, level, title, detail in (
            ([r for r in blocked if r[1] == 25], "info", "Port 25 is blocked",
             "Normal: most internet providers block it so infected computers can't send spam. Mail apps use 587 or "
             "465 instead, which is what matters."),
            ([r for r in blocked if r[1] == 445], "good", "SMB (445) is blocked outbound", "As it should be."),
            ([r for r in blocked if r[0] == "Voice & video"], "warn", "Voice ports are blocked",
             "SIP phones and softphones may fail to register. Allow the provider's SIP ports outbound."),
            ([r for r in blocked if r[0] == "VPN"], "warn", "Some VPN ports are blocked",
             "Remote users' VPN clients won't connect from here on those ports."),
            ([r for r in blocked if r[0] == "Remote access"], "warn", "Some remote-access ports are blocked",
             "Remote support tools usually fall back to 443, but direct connections on these ports will fail."),
            ([r for r in blocked if r[0] in ("Web", "Mail") and r[1] != 25], "bad", "Basic web or mail ports are blocked",
             "Mail apps or browsing will fail. Check the firewall's outbound rules or web filter.")):
        if port_list:
            f.append((level, title, detail + " Ports: " + ", ".join(f"{p} ({w})" for _c, p, w, _s in port_list) + "."))
    if intercepted:
        f.append(("warn", "Something answers in place of the real server",
                  "A proxy, web filter or captive portal intercepts these ports: " +
                  ", ".join(str(p) for _c, p, _w, _s in intercepted) + ". Apps that expect a direct connection may "
                  "fail; SSL inspection breaks some of them."))
    nat = res["nat"]
    if not res["udp_dns"]:
        f.append(("warn", "Outgoing DNS to public servers is blocked",
                  "Devices must use the network's own DNS server. Fine when intended (DNS filtering)."))
    if nat["kind"] == "blocked":
        f.append(("bad", "Outgoing UDP (STUN) is blocked",
                  "Teams, Zoom, WebRTC and most VoIP send audio and video over UDP; they'll fall back to slower TCP "
                  "relays or fail. Allow UDP 3478-3481 and high ports outbound."))
    elif nat["kind"] == "symmetric":
        f.append(("warn", "Symmetric NAT: calls can't connect directly",
                  "The firewall gives each connection a different public port, so calls go through relay servers "
                  "(more delay). On most firewalls this is a 'port randomisation' or 'strict NAT' setting."))
    elif nat["kind"] == "friendly":
        f.append(("good", "UDP works and calls can connect directly", f"Public address {nat['mapped'][0]}."))
    return f


# ---- VoIP readiness ------------------------------------------------------------------------------

def mos_score(latency_ms, jitter_ms, loss_pct):
    """Estimated call quality (MOS, 1-5) from latency, jitter and loss: the simplified ITU-T G.107 E-model
    commonly used by network monitoring tools."""
    effective = latency_ms + 2 * jitter_ms + 10
    r = 93.2 - (effective / 40 if effective < 160 else (effective - 120) / 10)
    r -= 2.5 * loss_pct
    r = max(0.0, min(100.0, r))
    return round(1 + 0.035 * r + 0.000007 * r * (r - 60) * (100 - r), 2)


def mos_label(mos):
    return ("good", "excellent") if mos >= 4.3 else ("good", "good") if mos >= 4.0 else \
        ("warn", "fair: some people will notice") if mos >= 3.6 else ("bad", "poor: calls will be hard to follow")


def voip_check():
    """Call quality inputs: 15 s of pings, SIP/STUN reachability and NAT behaviour."""
    from .online import stability  # late: pulls in the internet module
    with ThreadPoolExecutor(max_workers=6) as ex:
        st = ex.submit(stability)
        sip = {port: ex.submit(tcp_out, port) for port in (5060, 5061)}
        nat = ex.submit(nat_behaviour)
        return {"stability": st.result(), "sip": {p: f.result() for p, f in sip.items()}, "nat": nat.result()}


def voip_findings(res, speed=None):
    st = res["stability"]
    f = []
    mos = None
    if st["median"] is not None:
        mos = mos_score(st["median"], st["jitter"] or 0, st["loss"])
        level, text = mos_label(mos)
        f.append((level, f"Estimated call quality {mos:.1f} / 5 ({text})",
                  f"From {st['median']:.0f} ms latency, {st['jitter'] or 0:.1f} ms jitter and {st['loss']:.0f}% loss. "
                  "Over 4.0 is what business calls need."))
    else:
        f.append(("bad", "No replies from the internet", "Calls can't work until the connection does."))
    if st.get("spikes"):
        f.append(("warn", f"{st['spikes']} latency spike(s) during the test",
                  "Short spikes cause robotic audio. Often bufferbloat or Wi-Fi interference."))
    grade = (speed or {}).get("grade")
    if grade in ("C", "D", "F"):
        f.append(("warn", f"Bufferbloat grade {grade}",
                  "Calls will break up whenever someone downloads or uploads. Enable SQM/QoS on the firewall and "
                  "prioritise voice traffic."))
    up = (speed or {}).get("up")
    if up is not None and up < 1:
        f.append(("warn", f"Upload is only {up:.1f} Mbit/s", "Each call needs about 0.1 Mbit/s each way, video 1-3."))
    blocked = [p for p, s in res["sip"].items() if s != "open"]
    if blocked:
        f.append(("warn", "SIP ports " + ", ".join(map(str, blocked)) + " aren't reachable outbound",
                  "Desk phones and softphones that register on these ports will fail; hosted systems that use 443 "
                  "or their own ports may be fine."))
    else:
        f.append(("good", "SIP (5060, 5061) reaches the internet", ""))
    nat = res["nat"]
    if nat["kind"] == "blocked":
        f.append(("bad", "Outgoing UDP is blocked", "Voice audio travels over UDP (RTP); calls will have no audio."))
    elif nat["kind"] == "symmetric":
        f.append(("warn", "Symmetric NAT", "One-way or no audio is likely unless the phone system uses a relay."))
    f.append(("info", "SIP ALG can't be tested from here",
              "Many routers rewrite SIP traffic ('SIP ALG') and break calls: one-way audio, drops after 30 seconds, "
              "phones unregistering. If you see that, turn SIP ALG off on the router or firewall."))
    return f, mos


# ---- domains and mail ---------------------------------------------------------------------------

MAIL_PROVIDERS = [
    ("mail.protection.outlook.com", "Microsoft 365"), ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"), ("pphosted.com", "Proofpoint"), ("mimecast", "Mimecast"),
    ("barracudanetworks.com", "Barracuda"), ("messagelabs.com", "Symantec"), ("zoho", "Zoho Mail"),
    ("secureserver.net", "GoDaddy"), ("emailsrvr.com", "Rackspace"), ("mailgun", "Mailgun"),
    ("icloud.com", "iCloud"), ("protonmail", "Proton Mail"), ("yahoodns", "Yahoo"), ("ppe-hosted", "Proofpoint"),
    ("arsmtp.com", "Mimecast"), ("sophos", "Sophos"), ("trendmicro", "Trend Micro"), ("fastmail", "Fastmail"),
]


def mail_provider(mx_hosts):
    names = [p for host in mx_hosts for pattern, p in MAIL_PROVIDERS if pattern in host.lower()]
    return names[0] if names else ("self-hosted / other" if mx_hosts else "no mail")


def m365_tenant(domain):
    """Microsoft 365 status of a domain from Microsoft's public sign-in lookup: (managed/federated, brand) or None."""
    url = f"https://login.microsoftonline.com/getuserrealm.srf?login=netscan@{domain}&json=1"
    try:
        d = json.loads(urllib.request.urlopen(urllib.request.Request(url, headers=AGENT), timeout=8).read(65536))
    except (OSError, ValueError):
        return None
    if d.get("NameSpaceType") in ("Managed", "Federated") and d.get("DomainName", "").lower() == domain.lower():
        return d["NameSpaceType"].lower(), d.get("FederationBrandName", "")
    return None


def domain_row(domain):
    """One line of the bulk domain check."""
    from .probes import check_site, domain_report  # late: probes imports tools
    domain = domain.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    with ThreadPoolExecutor(max_workers=3) as ex:
        rep_f, site_f, tenant_f = ex.submit(domain_report, domain), ex.submit(check_site, domain), ex.submit(m365_tenant, domain)
        rep, site, tenant = rep_f.result(), site_f.result(), tenant_f.result()
    mx = [host for _p, host in rep.get("mx", [])]
    rdap = rep.get("rdap") or {}
    expires = rdap.get("expires") or ""
    days = None
    if expires:
        try:
            days = (time.mktime(time.strptime(expires, "%Y-%m-%d")) - time.time()) // 86400
        except ValueError:
            pass
    dmarc = rep["dmarc"][0] if rep.get("dmarc") else ""
    policy = (re.search(r"\bp=(\w+)", dmarc) or [None, ""])[1].lower() if dmarc else ""
    spf = rep["spf"][0] if rep.get("spf") else ""
    return {"domain": domain, "provider": mail_provider(mx) if not rep.get("null_mx") else "accepts no mail",
            "m365": tenant, "mx": mx, "spf": spf, "spf_all": (re.search(r"([~\-?+])all\b", spf) or [None, ""])[1],
            "dmarc": policy, "dkim": rep.get("dkim") or [], "expires": expires, "expires_days": days,
            "registrar": rdap.get("registrar", ""), "web_ok": site["ok"], "web_status": site["status"],
            "web_error": site["error"], "cert_days": site["cert_days"], "error": rep.get("dns_error", "")}


def domain_issues(r):
    """[(level, text)] worth flagging for one bulk row."""
    out = []
    if r["error"]:
        return [("bad", f"DNS lookup failed: {r['error']}")]
    if r["provider"] not in ("no mail", "accepts no mail"):
        if not r["spf"]:
            out.append(("bad", "no SPF"))
        elif r["spf_all"] in ("+", "?", ""):
            out.append(("warn", "SPF allows anyone" if r["spf_all"] == "+" else "SPF doesn't end in -all/~all"))
        if not r["dmarc"]:
            out.append(("bad", "no DMARC"))
        elif r["dmarc"] == "none":
            out.append(("warn", "DMARC p=none (monitor only)"))
        if not r["dkim"] and r["provider"] != "self-hosted / other":
            out.append(("info", "DKIM not found under common selectors"))
    if r["expires_days"] is not None and r["expires_days"] < 30:
        out.append(("bad" if r["expires_days"] < 7 else "warn", f"domain expires in {int(r['expires_days'])} days"))
    if r["cert_days"] is not None and r["cert_days"] < 14:
        out.append(("bad" if r["cert_days"] < 3 else "warn", f"website certificate expires in {r['cert_days']} days"))
    if not r["web_ok"] and r["web_error"]:
        out.append(("info", f"website: {r['web_error'][:60]}"))
    return out


def bulk_domains(domains, workers=4):
    domains = list(dict.fromkeys(d.strip().lower() for d in domains if d.strip()))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {d: ex.submit(domain_row, d) for d in domains}
        rows = []
        for d, fut in futs.items():
            try:
                rows.append(fut.result())
            except Exception as e:  # noqa: BLE001 - one bad domain mustn't sink the rest
                rows.append({"domain": d, "error": str(e), "provider": "", "m365": None, "mx": [], "spf": "",
                             "spf_all": "", "dmarc": "", "dkim": [], "expires": "", "expires_days": None,
                             "registrar": "", "web_ok": False, "web_status": None, "web_error": "", "cert_days": None})
        return rows


# More blocklists for mail servers (IP-based). Some refuse queries from big public DNS resolvers ("unknown").
MAIL_BLOCKLISTS = [
    ("zen.spamhaus.org", "Spamhaus ZEN"), ("b.barracudacentral.org", "Barracuda"), ("bl.spamcop.net", "SpamCop"),
    ("psbl.surriel.com", "PSBL"), ("dnsbl-1.uceprotect.net", "UCEPROTECT 1"), ("bl.mailspike.net", "Mailspike"),
    ("dnsbl.dronebl.org", "DroneBL"), ("ix.dnsbl.manitu.net", "NiX Spam"), ("truncate.gbudb.net", "GBUdb"),
    ("all.s5h.net", "s5h"), ("bl.0spam.org", "0spam"), ("spam.dnsbl.anonmails.de", "anonmails"),
    ("dnsbl.spfbl.net", "SPFBL"), ("rbl.interserver.net", "InterServer"),
]
DOMAIN_BLOCKLISTS = [("dbl.spamhaus.org", "Spamhaus DBL"), ("multi.surbl.org", "SURBL")]


def _listed(query):
    try:
        codes = socket.gethostbyname_ex(query)[2]
    except socket.gaierror:
        return "clean", []
    except OSError:
        return "unknown", []
    if not codes or any(c.startswith("127.255.255.") or not c.startswith("127.") for c in codes):
        return "unknown", codes
    return "listed", codes


def blocklist_all(target):
    """[(list, status, detail)] for an IPv4 address (IP lists) or a domain (domain lists)."""
    try:
        ip = ipaddress.IPv4Address(target)
        base, lists = ".".join(reversed(str(ip).split("."))), MAIL_BLOCKLISTS
    except ValueError:
        base, lists = target.lower().strip("."), DOMAIN_BLOCKLISTS
    with ThreadPoolExecutor(max_workers=len(lists)) as ex:
        found = list(ex.map(lambda z: (z[1], *_listed(f"{base}.{z[0]}")), lists))
    out = []
    for name, status, codes in found:
        detail = ""
        if name == "Spamhaus ZEN" and status == "listed":
            status, detail = spamhaus_meaning(codes)
        elif name == "Spamhaus DBL" and status == "listed" and any(c.startswith("127.0.1.1") and c != "127.0.1.1"
                                                                    for c in codes):
            detail = "abused legitimate domain"
        out.append((name, status, detail))
    return out


def smtp_probe(host, timeout=8):
    """Connect to a mail server on port 25: banner, EHLO extensions, STARTTLS and its certificate."""
    out = {"host": host, "ips": [], "reachable": False, "banner": "", "starttls": False, "tls": None,
           "cert": None, "error": ""}
    try:
        out["ips"] = sorted({a[4][0] for a in socket.getaddrinfo(host, 25, socket.AF_INET, socket.SOCK_STREAM)})
    except OSError as e:
        out["error"] = f"doesn't resolve: {e}"
        return out
    try:
        with socket.create_connection((host, 25), timeout=timeout) as s:
            f = s.makefile("rb")

            def reply():
                lines = []
                while True:
                    line = f.readline(1024).decode(errors="replace").rstrip()
                    lines.append(line)
                    if len(line) < 4 or line[3] != "-":
                        return lines

            out["reachable"] = True
            out["banner"] = reply()[0][4:]
            s.sendall(b"EHLO netscan.invalid\r\n")
            ext = [line[4:].upper() for line in reply()]
            out["starttls"] = any(x.startswith("STARTTLS") for x in ext)
            if out["starttls"]:
                s.sendall(b"STARTTLS\r\n")
                if reply()[0].startswith("220"):
                    ctx = ssl.create_default_context()
                    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # report problems, don't refuse
                    with ctx.wrap_socket(s, server_hostname=host) as tls:
                        out["tls"] = tls.version()
                        der = tls.getpeercert(binary_form=True)
                        from .discovery import parse_certificate  # late: heavy module
                        out["cert"] = parse_certificate(der) if der else None
                    return out
            s.sendall(b"QUIT\r\n")
    except OSError as e:
        out["error"] = str(e) or type(e).__name__
    return out


def reverse_dns(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except OSError:
        return "", False
    try:
        confirmed = ip in {a[4][0] for a in socket.getaddrinfo(name, None, socket.AF_INET)}
    except OSError:
        confirmed = False
    return name, confirmed


def port25_open():
    return tcp_out(25) == "open"


def mail_check(target):
    """A domain's mail servers (or one IP / host): SMTP, STARTTLS, certificate, reverse DNS and blocklists."""
    from .tools import doh_query  # late: tools pulls in discovery
    target = target.strip().lower()
    try:
        ipaddress.IPv4Address(target)
        hosts, domain = [target], None
    except ValueError:
        domain = target
        try:
            mx = sorted(v for t, v in doh_query(domain, "MX")[1] if t == "MX")
            hosts = [h for _p, h in mx if h] or [domain]
        except OSError:
            hosts = [domain]
    can_25 = port25_open()
    with ThreadPoolExecutor(max_workers=8) as ex:
        probes = {h: ex.submit(smtp_probe, h) for h in hosts[:4]} if can_25 else {}
        results = []
        for h in hosts[:4]:
            p = probes[h].result() if can_25 else {"host": h, "ips": [], "reachable": None, "error": "",
                                                   "banner": "", "starttls": None, "tls": None, "cert": None}
            if not p["ips"]:
                try:
                    p["ips"] = sorted({a[4][0] for a in socket.getaddrinfo(h, 25, socket.AF_INET)})
                except OSError:
                    pass
            p["ptr"] = {ip: reverse_dns(ip) for ip in p["ips"][:2]}
            p["blocklists"] = {ip: blocklist_all(ip) for ip in p["ips"][:2]}
            results.append(p)
        domain_lists = blocklist_all(domain) if domain else []
    return {"target": target, "domain": domain, "servers": results, "port25": can_25, "domain_lists": domain_lists}


def mail_findings(res):
    f = []
    if not res["port25"]:
        f.append(("info", "This network blocks outgoing port 25",
                  "So the servers' SMTP answers can't be tested from here (common on home and VPN connections). "
                  "Reverse DNS and blocklists are still checked."))
    for s in res["servers"]:
        h = s["host"]
        if s["reachable"] is False:
            f.append(("bad", f"{h} doesn't answer on port 25", s["error"] or "no connection"))
        elif s["reachable"]:
            if s["starttls"]:
                cert = s["cert"] or {}
                days = cert.get("days_left")
                f.append(("good" if days is None or days > 14 else "warn",
                          f"{h}: STARTTLS ({s['tls'] or 'TLS'})" + (f", certificate {days} days left" if days is not None
                                                                   else ""), s["banner"][:120]))
            else:
                f.append(("warn", f"{h} doesn't offer STARTTLS", "Mail to and from it travels unencrypted."))
        for ip, (name, ok) in s["ptr"].items():
            if not name:
                f.append(("warn", f"{ip} has no reverse DNS", "Many receivers reject mail from servers without one."))
            elif not ok:
                f.append(("info", f"{ip} reverse DNS {name} doesn't point back", "Forward-confirmed reverse DNS helps delivery."))
        for ip, lists in s["blocklists"].items():
            listed = [(n, d) for n, st, d in lists if st == "listed"]
            clean = sum(1 for _n, st, _d in lists if st in ("clean", "policy"))
            unknown = [n for n, st, _d in lists if st == "unknown"]
            for name, detail in listed:
                f.append(("bad", f"{ip} is listed on {name}", detail or "Mail from this server may be rejected."))
            if not listed:
                f.append(("good", f"{ip} is on none of {clean} blocklists",
                          f"Couldn't check: {', '.join(unknown)} (they refuse lookups from big public DNS servers)."
                          if unknown else ""))
    for name, st, detail in res["domain_lists"]:
        if st == "listed":
            f.append(("bad", f"{res['domain']} is listed on {name}", detail or "Links to it may be blocked in mail."))
    return f


# ---- DNS propagation --------------------------------------------------------------------------

# (name, IP for plain DNS or None, DNS-over-HTTPS URL or None, where). Plain DNS first; HTTPS when the network
# blocks outgoing DNS (VPNs and filtered offices often do) or for resolvers that only answer over HTTPS here.
PUBLIC_RESOLVERS = [
    ("Cloudflare", "1.1.1.1", "https://1.1.1.1/dns-query", "Global"),
    ("Google", "8.8.8.8", "https://dns.google/dns-query", "Global"),
    ("Quad9", "9.9.9.9", None, "Switzerland"),
    ("OpenDNS", "208.67.222.222", "https://doh.opendns.com/dns-query", "US (Cisco)"),
    ("Level3 / Lumen", "4.2.2.1", None, "US"), ("Comodo", "8.26.56.26", None, "US"),
    ("CleanBrowsing", "185.228.168.9", "https://doh.cleanbrowsing.org/doh/security-filter/", "Global"),
    ("AdGuard", "94.140.14.14", "https://dns.adguard-dns.com/dns-query", "Cyprus"),
    ("DNS.WATCH", "84.200.69.80", None, "Germany"), ("Hurricane Electric", "74.82.42.42", None, "US"),
    ("Control D", "76.76.2.0", "https://freedns.controld.com/p0", "Canada"),
    ("Yandex", "77.88.8.8", None, "Russia"), ("Quad101", "101.101.101.101", None, "Taiwan"),
    ("114DNS", "114.114.114.114", None, "China"), ("UltraDNS", "64.6.64.6", None, "US (Vercara)"),
    ("NextDNS", None, "https://dns.nextdns.io/dns-query", "Global"),
    ("DNS.SB", None, "https://doh.dns.sb/dns-query", "Germany"),
    ("LibreDNS", None, "https://doh.libredns.gr/dns-query", "Greece"),
    ("AliDNS", None, "https://dns.alidns.com/dns-query", "China"),
    ("DNSPod", None, "https://doh.pub/dns-query", "China"),
]


def _wire(name, qtype, ident=0):
    from .tools import DNS_TYPES  # late: tools pulls in discovery
    question = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.split(".")) + b"\0"
    return struct.pack(">6H", ident, 0x0100, 1, 0, 0, 0) + question + struct.pack(">HH", DNS_TYPES[qtype], 1)


def doh_wire_query(url, name, qtype="A", timeout=6):
    """Any record type over DNS-over-HTTPS (RFC 8484 wire format): (rcode, [(type name, value)], ms)."""
    from .discovery import parse_dns_records
    from .tools import DNS_TYPES
    enc = base64.urlsafe_b64encode(_wire(name, qtype)).rstrip(b"=").decode()
    req = urllib.request.Request(f"{url}{'&' if '?' in url else '?'}dns={enc}",
                                 headers={"Accept": "application/dns-message", **AGENT})
    t = time.perf_counter()
    data = urllib.request.urlopen(req, timeout=timeout).read(65535)
    ms = (time.perf_counter() - t) * 1000
    names = {v: k for k, v in DNS_TYPES.items()}
    count = struct.unpack(">H", data[6:8])[0]
    return data[3] & 0x0F, [(names[t], v) for t, _n, v in parse_dns_records(data)[:count] if t in names and v is not None], ms


def _norm(answers, qtype):
    vals = []
    for t, v in answers:
        if t != qtype:
            continue
        if isinstance(v, tuple):
            v = f"{v[0]} {v[1]}"
        elif isinstance(v, list):
            v = " ".join(v)
        vals.append(str(v).rstrip("."))
    return tuple(sorted(vals))


def propagation(name, qtype="A"):
    """The answer every public resolver gives, plus the authoritative one (asked at the domain's own name
    servers). Returns {"authoritative": {...} or None, "rows": [(resolver, where, answer, ms, how, error)]}."""
    from .tools import dns_query, doh_query  # late: tools pulls in discovery
    name = name.strip().rstrip(".").lower()
    auth = None
    parts = name.split(".")
    for i in range(len(parts) - 1):  # the closest zone with NS records; ask one of its servers
        zone = ".".join(parts[i:])
        try:
            ns = [v for t, v in doh_query(zone, "NS")[1] if t == "NS"]
        except OSError:
            ns = []
        if ns:
            for server in ns[:2]:
                try:
                    ip = socket.getaddrinfo(server, 53, socket.AF_INET)[0][4][0]
                    rcode, answers, _ms = dns_query(ip, name, qtype, timeout=4)
                    auth = {"server": server, "answer": _norm(answers, qtype), "rcode": rcode}
                    break
                except (OSError, ValueError):
                    continue
            break

    def ask(entry):
        label, ip, doh, where = entry
        error = ""
        if ip:
            try:
                rcode, answers, ms = dns_query(ip, name, qtype, timeout=3)
                return label, where, _norm(answers, qtype), ms, "DNS", "" if rcode in (0, 3) else f"error {rcode}"
            except (OSError, ValueError, struct.error) as e:
                error = "no answer" if isinstance(e, (socket.timeout, TimeoutError)) else "blocked here"
        if doh:
            try:
                rcode, answers, ms = doh_wire_query(doh, name, qtype)
                return label, where, _norm(answers, qtype), ms, "HTTPS", "" if rcode in (0, 3) else f"error {rcode}"
            except (OSError, ValueError, struct.error) as e:
                error = str(getattr(e, "reason", e))[:60]
        return label, where, None, None, "", error or "no answer"

    with ThreadPoolExecutor(max_workers=len(PUBLIC_RESOLVERS)) as ex:
        rows = list(ex.map(ask, PUBLIC_RESOLVERS))
    return {"name": name, "type": qtype, "authoritative": auth, "rows": rows}


def propagation_summary(res):
    auth = (res["authoritative"] or {}).get("answer")
    answered = [r for r in res["rows"] if r[2] is not None]
    if auth is None:
        groups = {}
        for r in answered:
            groups.setdefault(r[2], []).append(r[0])
        auth = max(groups.items(), key=lambda kv: len(kv[1]))[0] if groups else None
    return auth, sum(1 for r in answered if r[2] == auth), len(answered)


# ---- documentation export ---------------------------------------------------------------------

INVENTORY_COLUMNS = ["Name", "Type", "IP address", "MAC address", "Manufacturer", "Model", "Hostname", "OS",
                     "Open ports", "Trusted", "First seen", "Last seen", "Notes"]


def inventory_rows(devices, device_type, port_text):
    """Rows for a CSV that IT Glue, Hudu and similar documentation tools can import (Configurations).
    devices: {key: record}; device_type(key, record) -> type; port_text(record) -> "22/ssh, 80/http"."""
    rows = []
    for key, d in devices.items():
        rows.append([d.get("nickname") or d.get("hostname") or d.get("ip") or key, device_type(key, d),
                     d.get("ip", ""), d.get("mac", "") if not key.startswith("ip:") else "",
                     d.get("maker") or d.get("vendor", ""), d.get("model", ""), d.get("hostname", ""),
                     d.get("os", ""), port_text(d), "yes" if d.get("trusted") else "",
                     (d.get("first_seen") or "")[:10], (d.get("last_seen") or "")[:10],
                     (d.get("notes") or "").replace("\n", " ")])
    return sorted(rows, key=lambda r: [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", r[2] or "~")])

