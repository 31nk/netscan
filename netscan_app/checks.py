"""Plain-English checkups built on the other engines: "why is my internet slow?", the security checkup,
double NAT / shared-address detection, DHCP servers, Wi-Fi survey readings and who's-home rows.

Each check has a gathering function (network, run in the background) and a pure verdict function
(no network, unit-tested) that turns the measurements into findings."""

import datetime
import ipaddress
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from .devices import port_risk
from .internet import cloudflare_trace, dns_lookup_ms, latency_stats
from .system import IS_MAC, IS_WIN, ping_once, run_text
from .tools import channel_advice, wifi_scan

# Order findings are shown in, worst first.
LEVELS = ("bad", "warn", "info", "good")


def _sorted(findings):
    return sorted(findings, key=lambda f: LEVELS.index(f[0]))


# ---- this computer's link ---------------------------------------------------------------


def is_wireless(iface):
    """Is this network interface Wi-Fi?"""
    if not iface:
        return False
    if IS_WIN:
        names = re.findall(r"^\s*Name\s*:\s*(.+?)\s*$", run_text("netsh", "wlan", "show", "interfaces"), re.M)
        return iface in names
    if IS_MAC:
        ports = run_text("/usr/sbin/networksetup", "-listallhardwareports")
        return bool(re.search(rf"Hardware Port: (?:Wi-Fi|AirPort)\s*\nDevice: {re.escape(iface)}\b", ports))
    return os.path.isdir(f"/sys/class/net/{iface}/wireless") or os.path.exists(f"/sys/class/net/{iface}/phy80211")


def linux_signal_dbm(iface):
    """Live signal level of a Linux Wi-Fi link from /proc/net/wireless, or None."""
    try:
        with open("/proc/net/wireless") as f:
            for line in f:
                if line.strip().startswith(iface + ":"):
                    level = float(line.split()[3].rstrip("."))
                    return level if level < 0 else None
    except (OSError, ValueError, IndexError):
        pass
    return None


def active_wifi(rescan=False):
    """The Wi-Fi network this computer is on, with how crowded its channel is; None if not on Wi-Fi."""
    nets = wifi_scan(rescan=rescan)
    active = next((n for n in nets if n["active"]), None)
    if not active:
        return None
    advice = channel_advice(nets).get(active["band"], {})
    return {**active, "crowd": advice.get("counts", {}).get(active["channel"], 0), "best": advice.get("best"),
            "nearby": len({n["bssid"] or n["ssid"] for n in nets})}


# ---- "why is my internet slow?" ---------------------------------------------------------


def ping_series(ip, count=10, gap=0.2):
    samples = []
    for _ in range(count):
        samples.append((time.time(), ping_once(ip)))
        time.sleep(gap)
    return latency_stats(samples)


def names_resolve():
    try:
        socket.getaddrinfo("cloudflare.com", 443)
        return True
    except OSError:
        return False


def measure_connection(net):
    """Everything the diagnosis needs except the speed test: about 5 seconds."""
    from .probes import ttl_probe  # late: probes imports tools, as this module does
    iface, gateway = (net or {}).get("iface"), (net or {}).get("gateway")
    wireless = is_wireless(iface)
    m = {"iface": iface, "gateway": gateway, "wireless": wireless, "errors": []}
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {"cf": ex.submit(ping_series, "1.1.1.1"), "google": ex.submit(ping_series, "8.8.8.8"),
                "dns_ok": ex.submit(names_resolve), "dns_ms": ex.submit(dns_lookup_ms, 3)}
        if gateway:
            futs["router"] = ex.submit(ping_series, gateway)
        if wireless:
            futs["wifi"] = ex.submit(active_wifi)
        futs["first_hop"] = ex.submit(lambda: ttl_probe("1.1.1.1", 1)[0])
        for key, fut in futs.items():
            try:
                m[key] = fut.result()
            except Exception as e:  # noqa: BLE001 - one failed measurement mustn't sink the rest
                m[key] = None
                m["errors"].append(f"{key}: {e}")
    return m


def _best(*stats):
    """The healthier of several ping results (the internet is fine if either big server answers well)."""
    ok = [s for s in stats if s and s.get("count")]
    return min(ok, key=lambda s: (s["loss"], s["avg"] if s["avg"] is not None else 1e9)) if ok else None


def diagnosis(m, speed=None, plan=None):
    """Turn measure_connection() (+ an optional speed test and the plan's Mbit/s) into a verdict.

    Returns {"level", "headline", "where", "findings": [(level, title, detail)]}. 'where' says which part of the
    path is at fault: "this computer", "wifi", "router", "provider", "dns", "load", "plan" or "".
    """
    f = []  # (level, where, title, detail)
    router, internet = m.get("router"), _best(m.get("cf"), m.get("google"))
    wifi, wireless = m.get("wifi"), m.get("wireless")
    link = "Wi-Fi" if wireless else "cable"

    if wireless and wifi:
        sig = wifi.get("signal")
        if sig is not None and sig < 35:
            f.append(("bad", "wifi", f"Very weak Wi-Fi signal ({sig}%)",
                      f"This computer barely hears “{wifi['ssid']}”. Move closer to the router, remove obstacles, "
                      "or add a mesh point or access point in this room."))
        elif sig is not None and sig < 55:
            f.append(("warn", "wifi", f"Weak Wi-Fi signal ({sig}%)",
                      "Speeds drop and delays grow at this distance. Closer to the router or a mesh point helps."))
        if wifi.get("band") == "2.4 GHz" and wifi.get("crowd", 0) >= 3:
            best = wifi.get("best")
            f.append(("warn", "wifi", f"Crowded Wi-Fi channel ({wifi['crowd']} other networks on channel "
                                      f"{wifi['channel']})",
                      "Neighbouring networks share the airtime. "
                      + (f"Channel {best} is the least crowded; change it in the router's settings. " if best and
                         best != wifi["channel"] else "")
                      + "5 GHz, if your devices support it, is usually far less crowded."))
        elif wifi.get("band") == "2.4 GHz" and sig is not None and sig >= 55:
            f.append(("info", "wifi", "On 2.4 GHz Wi-Fi",
                      "2.4 GHz reaches further but is slower and more crowded than 5 GHz. If this spot has a good "
                      "5 GHz signal, use it for faster speeds."))

    if m.get("gateway") and (router is None or router["loss"] == 100):
        f.append(("bad", "router", "Your router isn't answering",
                  f"Nothing came back from the router ({m['gateway']}). Check the {link}, then restart the router. "
                  "(A few routers ignore pings on purpose; if everything else works, that's all it is.)"))
    elif router:
        slow = 30 if wireless else 5
        if router["loss"] > 0:
            f.append(("bad", "wifi" if wireless else "this computer",
                      f"Packets lost between this computer and the router ({router['loss']:.0f}%)",
                      "Lost packets make everything stall and retry. " +
                      ("On Wi-Fi this is usually signal or interference: move closer or change channel."
                       if wireless else "On a cable this points at the cable, the port or the network adapter.")))
        elif router["avg"] is not None and (router["avg"] > slow or (router["jitter"] or 0) > slow):
            f.append(("warn", "wifi" if wireless else "this computer",
                      f"Slow link to the router ({router['avg']:.0f} ms, varying by {router['jitter'] or 0:.0f} ms)",
                      f"The router is right next to you in network terms; it should answer in under {slow} ms. "
                      + ("Wi-Fi congestion or a weak signal is the usual cause." if wireless else
                         "Something on this computer or network is flooding the link.")))

    router_ok = bool(router) and router["loss"] == 0
    hop, gw = m.get("first_hop"), m.get("gateway")
    vpn = bool(hop and gw and hop != gw)
    if vpn:
        f.append(("info", "", "Measured through a VPN",
                  f"Traffic leaves via {hop}, not straight through your router, so internet results include the "
                  "VPN. If something past the router looks bad, try again with the VPN off to tell them apart."))
    if internet is None or internet["loss"] == 100:
        if router_ok or not m.get("gateway"):
            f.append(("bad", "provider", "The internet isn't answering, but your router is" + (" (via the VPN)" if vpn else ""),
                      "Your home network works; the problem is past the router: the modem or your internet "
                      "provider. Restart the modem/router; if that doesn't help, check your provider's status page."))
    else:
        if internet["loss"] > 0 and router_ok:
            f.append(("bad", "provider", f"Packets lost past your router ({internet['loss']:.0f}%"
                                         + (", through the VPN)" if vpn else ")"),
                      "Your home network is clean, so the loss is on your provider's side (or the modem). If it "
                      "keeps happening, Tools → Continuous trace shows where it starts: useful evidence for them."))
        base = router["avg"] if router_ok and router["avg"] is not None else 0
        if internet["avg"] is not None and internet["avg"] - base > 80:
            f.append(("warn", "provider", f"High delay to the internet ({internet['avg']:.0f} ms)",
                      "Big sites usually answer in 5–40 ms on cable or fibre. Satellite, mobile and far-away "
                      "connections are slower; otherwise your provider's network is congested."))

    if m.get("dns_ok") is False and internet and internet["loss"] < 100:
        f.append(("bad", "dns", "Website names don't resolve (DNS is failing)",
                  "The internet works but names can't be looked up, so every site “is down”. Restart the "
                  "router, or set this computer's DNS to 1.1.1.1 or 9.9.9.9."))
    elif m.get("dns_ms") and m["dns_ms"] > 300:
        f.append(("warn", "dns", f"Slow DNS ({m['dns_ms']:.0f} ms for a new name)",
                  "Every new site waits for this before it starts loading. Tools → DNS speed compares your "
                  "DNS server with faster public ones."))
    elif m.get("dns_ms") and m["dns_ms"] > 150:
        f.append(("info", "dns", f"New names take {m['dns_ms']:.0f} ms to look up",
                  "A little slow for the first visit to a site; repeat visits are cached. Normal for a DNS server "
                  "that looks names up itself (Unbound, a Pi-hole with Unbound); Tools → DNS speed compares."))

    if speed:
        if speed.get("grade") in ("C", "D", "F"):
            f.append(("warn", "load", f"Lag when the connection is busy (bufferbloat grade {speed['grade']})",
                      f"Delay grows by {speed['added_ms']:.0f} ms while downloading or uploading, so calls and "
                      "games stutter whenever someone streams or uploads. Turn on SQM / “smart queue” / QoS in "
                      "the router's settings."))
        if plan and plan.get("down") and speed.get("down") is not None:
            pct = 100 * speed["down"] / plan["down"]
            if pct < 50:
                f.append(("warn", "plan", f"Download is {pct:.0f}% of your plan ({speed['down']:.0f} of "
                                          f"{plan['down']:.0f} Mbit/s)",
                          ("Wi-Fi may be the limit here; test again on a cable to be sure. " if wireless else "")
                          + "If it stays low on a cable, tell your provider: History has the record."))
            elif pct < 80:
                f.append(("info", "plan", f"Download is {pct:.0f}% of your plan",
                          "A bit under what you pay for; normal at busy times, worth watching in History."))

    findings = [(lvl, title, detail) for lvl, _where, title, detail in _sorted(f)]
    if not findings or all(lvl in ("info", "good") for lvl, _t, _d in findings):
        parts = []
        if router and router["avg"] is not None:
            parts.append(f"router {router['avg']:.0f} ms")
        if internet and internet["avg"] is not None:
            parts.append(f"internet {internet['avg']:.0f} ms, no loss")
        if speed and speed.get("down") is not None:
            parts.append(f"{speed['down']:.0f}/{speed['up']:.0f} Mbit/s")
        findings.insert(0, ("good", "Everything looks healthy",
                            ("Measured " + ", ".join(parts) + ". " if parts else "")
                            + "If it still feels slow, it may be the site or app itself, or a busy moment: try again "
                              "when it happens, with the speed test ticked."))
        return {"level": "good", "headline": "No problems found", "where": "", "findings": findings}
    top = _sorted(f)[0]
    headline = {"wifi": "The problem is your Wi-Fi", "this computer": "The problem is between this computer and "
                "the router", "router": "The problem is your router", "provider": "The problem is past your router: "
                + ("the VPN or your internet provider" if vpn else "your internet provider"), "dns": "The problem is DNS (looking up site names)",
                "load": "The connection lags when busy", "plan": "You're getting less speed than you pay for"}[top[1]]
    return {"level": top[0], "headline": headline, "where": top[1], "findings": findings}


# ---- double NAT / shared address ----------------------------------------------------------

CGNAT = ipaddress.ip_network("100.64.0.0/10")
# Home/office networks (RFC 1918). ipaddress's is_private is broader (documentation and reserved ranges too).
LAN_RANGES = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _lan(addr):
    return addr is not None and any(addr in n for n in LAN_RANGES)


def _addr(ip):
    try:
        return ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return None


def nat_measure(net, router_wan=None):
    """Public IP (Cloudflare) and the first hops towards the internet."""
    from .probes import find_hops  # late: probes imports tools, as this module does
    out = {"gateway": (net or {}).get("gateway"), "router_wan": router_wan, "errors": []}
    try:
        out["public_ip"] = cloudflare_trace().get("ip")
    except OSError as e:
        out["public_ip"] = None
        out["errors"].append(f"public IP: {e}")
    try:
        out["hops"] = find_hops("1.1.1.1", max_hops=8)[1]
    except OSError as e:
        out["hops"] = []
        out["errors"].append(f"route: {e}")
    return out


def nat_verdict(m):
    """{"kind": direct|double|cgnat|vpn|unknown, "level", "headline", "findings"}; kind decides whether port
    forwarding and hosting can work."""
    public, wan, hops, gw = _addr(m.get("public_ip")), _addr(m.get("router_wan")), m.get("hops") or [], m.get("gateway")
    hop_addrs = [_addr(h) for h in hops]
    f = []
    forwarding = ("Port forwarding, hosting a game or server, and some consoles' “open NAT” need the router to "
                  "hold the public address itself.")
    via_vpn = bool(hops and gw and hops[0] and hops[0] != gw)
    if wan is not None:
        if wan in CGNAT:
            kind = "cgnat"
            f.append(("warn", "Your provider shares one public address among many customers (CGNAT)",
                      f"The router's internet-side address is {wan}, from the range providers use for sharing "
                      f"(100.64.0.0/10). {forwarding} Ask your provider for a public IPv4 address (often free or "
                      "a small fee), or use IPv6 or a tunnel like Tailscale."))
        elif _lan(wan):
            kind = "double"
            f.append(("warn", "Two routers in a row (double NAT)",
                      f"Your router's internet-side address is {wan}, a private one: there's another router (often "
                      f"the provider's modem) in front of it. {forwarding} Put the modem in “bridge mode”, or "
                      "forward ports on both."))
        elif public is not None and wan != public:
            kind = "vpn"
            f.append(("info", "The internet sees a different address than your router has",
                      f"Router: {wan}; the internet sees: {public}. Usually a VPN on this computer; otherwise your "
                      "provider routes you through another address."))
        else:
            kind = "direct"
            f.append(("good", "Direct connection: your router holds the public address",
                      f"The router's address {wan} is what the internet sees. Port forwarding works."))
    elif via_vpn:
        kind = "unknown"
        f.append(("info", "This computer is using a VPN, so its route says nothing about your home connection",
                  f"The first hop is {hops[0]}, not your router ({gw}). The router's own UPnP answer would settle "
                  "it: find hosts on the Scan tab, then check again (or check with the VPN off)."))
    else:
        after = [a for a in hop_addrs[1:] if a is not None][:3]
        if any(a in CGNAT for a in hop_addrs if a):
            kind = "cgnat"
            f.append(("warn", "Your provider probably shares public addresses (CGNAT)",
                      f"A hop just past your router uses the shared-address range (100.64.0.0/10). {forwarding} "
                      "The router's own UPnP answer would confirm it: find hosts on the Scan tab first."))
        elif after and _lan(after[0]):
            kind = "double"
            f.append(("warn", "Probably two routers in a row (double NAT)",
                      f"The hop after your router ({after[0]}) is a private address, so another router (often the "
                      f"provider's modem) sits in front. {forwarding} Some providers use private addresses inside "
                      "their own network too; the router's UPnP answer would settle it (find hosts on the Scan "
                      "tab, then check again)."))
        elif after:
            kind = "direct"
            f.append(("good", "Looks direct: the next hop past your router is your provider",
                      "No second router or shared-address range on the way out. Confirm with the router's UPnP "
                      "answer (find hosts on the Scan tab, then check again)."))
        else:
            kind = "unknown"
            f.append(("info", "Couldn't tell", "No hops past the router answered and the router's UPnP isn't "
                                              "available. Find hosts on the Scan tab, then check again."))
    headline = {"direct": "Direct connection", "double": "Double NAT", "cgnat": "Shared address (CGNAT)",
                "vpn": "Different public address", "unknown": "Unknown"}[kind]
    return {"kind": kind, "level": _sorted(f)[0][0], "headline": headline, "findings": _sorted(f)}


# ---- DHCP servers -------------------------------------------------------------------------------


def dhcp_args(iface):
    """nmap arguments that ask every DHCP server on the network for an offer (needs raw packets)."""
    return ["--script", "broadcast-dhcp-discover", "--script-args", "broadcast-dhcp-discover.timeout=6",
            *(["-e", iface] if iface and not IS_WIN else [])]


def parse_dhcp_discover(text):
    """nmap's broadcast-dhcp-discover output -> [{"server", "offered", "router", "dns", "lease", "mask"}]."""
    found = []
    for block in re.split(r"\|\s+Response \d+ of \d+:", text)[1:]:
        field = lambda name: (re.search(rf"{name}:\s*(.+)", block) or [None, ""])[1].strip()
        entry = {"server": field("Server Identifier"), "offered": field("IP Offered"), "router": field("Router"),
                 "dns": field("Domain Name Server"), "lease": field("IP Address Lease Time"),
                 "mask": field("Subnet Mask")}
        if entry["server"] and entry["server"] not in [e["server"] for e in found]:
            found.append(entry)
    return found


def dhcp_verdict(servers, gateway):
    if not servers:
        return [("info", "No DHCP server answered",
                 "Fine if your devices use fixed addresses; otherwise the router's DHCP may be off or this "
                 "computer's firewall dropped the answer.")]
    if len(servers) > 1:
        names = ", ".join(s["server"] for s in servers)
        return [("bad", f"{len(servers)} DHCP servers are handing out addresses ({names})",
                 "There should be one. Devices get whichever answers first, so some end up with the wrong router or "
                 "DNS and “randomly” lose the internet. Usually a second router or extender not in access-point "
                 "mode; at worst a device intercepting traffic. Switch DHCP off on all but one.")]
    s = servers[0]
    if gateway and s["server"] != gateway:
        return [("info", f"Addresses come from {s['server']}, not the router",
                 "Only one DHCP server, which is what matters. Normal if you run it on a Pi-hole or server on "
                 "purpose; if not, find out what that device is.")]
    return [("good", "One DHCP server: your router", "Exactly as it should be.")]


# ---- security checkup ---------------------------------------------------------------------------

# Points taken off 100 per finding.
WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0, "good": 0}
RISKY_FORWARDS = {21, 22, 23, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 27017}


def wifi_security_issue(net):
    """(severity, title, detail) for a Wi-Fi network's protection, or None if it's fine."""
    sec = (net.get("security") or "").upper()
    cipher = (net.get("cipher") or "").upper()
    if sec in ("", "OPEN", "--", "NONE") or ("OPEN" in sec and "WPA" not in sec):
        return ("critical", "Your Wi-Fi has no password",
                "Anyone nearby can join and see your devices. Turn on WPA2 or WPA3 in the router's settings.")
    if "WEP" in sec:
        return ("critical", "Your Wi-Fi uses WEP",
                "WEP can be cracked in minutes. Switch the router to WPA2 or WPA3.")
    if ("WPA1" in sec or sec in ("WPA", "WPA-PERSONAL", "WPA PERSONAL")) and "WPA2" not in sec and "WPA3" not in sec:
        return ("high", "Your Wi-Fi uses old WPA",
                "The first WPA is broken. Switch the router to WPA2 (AES) or WPA3.")
    if "TKIP" in cipher and "CCMP" not in cipher and "AES" not in cipher:
        return ("high", "Your Wi-Fi uses TKIP encryption",
                "TKIP is outdated and slow. Set the router to AES (CCMP) only.")
    if "TKIP" in cipher:
        return ("low", "Your Wi-Fi still allows TKIP",
                "Old devices may connect with weak encryption. Set the router to AES (CCMP) only.")
    return None


def security_checkup(ctx):
    """Score a network 0-100 from what NetScan already knows. ctx keys (all optional):
    hosts: [{ip, name, ports (list or None if not scanned), upnp, trusted, router, this}],
    upnp: the router's UPnP answer or None, any_trusted, wifi (active network), dns_hijack (bool or None),
    spoof: [(severity, text)], local_ports (this computer's open ports).
    Returns {"score", "grade", "complete" (ports of at least one device were scanned),
    "findings": [(severity, title, detail)]}."""
    f = []
    hosts = ctx.get("hosts") or []
    for sev, text in ctx.get("spoof") or []:
        f.append(("critical" if sev == "high" else "low", "Possible ARP spoofing", text))
    wifi = ctx.get("wifi")
    if wifi:
        issue = wifi_security_issue(wifi)
        f.append(issue or ("good", f"Wi-Fi “{wifi['ssid']}” is protected ({wifi.get('security') or 'WPA2+'})", ""))
    if ctx.get("dns_hijack"):
        f.append(("medium", "Your DNS answers for names that don't exist",
                  "Typing a wrong address lands on an advertising or search page instead of an error: your provider "
                  "(or something on the network) is rewriting DNS answers. Use 1.1.1.1 or 9.9.9.9 instead."))
    upnp = ctx.get("upnp")
    if upnp:
        maps = [mp for mp in upnp.get("mappings", []) if mp.get("enabled", True)]
        for mp in maps:
            dangerous = mp["external_port"] in RISKY_FORWARDS
            f.append(("high" if dangerous else "low",
                      f"Port {mp['external_port']}/{mp['protocol']} is open to the internet → {mp['client']}",
                      (mp.get("description") or "opened automatically via UPnP")
                      + (". This service is a common attack target; close it unless you run it on purpose."
                         if dangerous else ". Fine if you know the app; otherwise check the device.")))
        if not maps:
            f.append(("info", "UPnP is on but nothing is forwarded",
                      "Devices can open router ports on their own. Switch UPnP off in the router if you don't game "
                      "or host anything."))
    scanned = [h for h in hosts if h.get("ports") is not None]
    device_points = 0
    for h in scanned:
        bad = [p for p in h["ports"] if port_risk(p)]
        if not bad:
            continue
        where = "your router" if h.get("router") else "this computer" if h.get("this") else h.get("name") or h["ip"]
        sev = "high" if h.get("router") or any(p["port"] in (23, 2375) for p in bad) else "medium"
        if device_points >= 40 and sev == "medium":
            sev = "low"  # many devices with the same issue shouldn't sink the score on its own
        device_points += WEIGHTS[sev]
        f.append((sev, f"Risky service{'s' if len(bad) > 1 else ''} on {where} ({h['ip']})",
                  "; ".join(f"{p['port']}/{p['proto']}: {port_risk(p)}" for p in bad[:4])
                  + ". Turn off what you don't use, or keep it to trusted devices."))
    for p in ctx.get("local_ports") or []:
        if port_risk(p) and not any(h.get("this") for h in scanned):
            f.append(("medium", f"This computer shares {p['port']}/{p['proto']} with the network",
                      f"{port_risk(p)} ({p.get('program') or 'unknown program'})."))
    if ctx.get("any_trusted"):
        strangers = [h for h in hosts if not h.get("trusted")]
        if strangers:
            f.append(("low" if len(strangers) < 3 else "medium",
                      f"{len(strangers)} device(s) you haven't marked as trusted",
                      ", ".join((h.get("name") or h["ip"]) for h in strangers[:8])
                      + (" …" if len(strangers) > 8 else "") + ". If you don't recognise one, check the Devices tab."))
    elif hosts:
        f.append(("info", "Mark the devices you know as trusted",
                  "Right-click them on the Scan tab. The checkup then points out anything new or unknown."))
    if hosts and not scanned:
        f.append(("info", "Ports weren't scanned",
                  "Find hosts with “Also scan top 100 ports” ticked for a much fuller checkup."))
    elif not hosts:
        f.append(("info", "No devices scanned yet",
                  "Find hosts on the Scan tab (with “Also scan top 100 ports”) and run the checkup again."))
    score = max(0, 100 - sum(WEIGHTS[s] for s, _t, _d in f))
    grade = next(g for limit, g in ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")) if score >= limit)
    order = list(WEIGHTS)
    return {"score": score, "grade": grade, "complete": bool(scanned),
            "findings": sorted(f, key=lambda x: order.index(x[0]))}


def security_measure():
    """The parts of the checkup that need the network or the OS: Wi-Fi, DNS rewriting, this computer's ports."""
    from .system import local_listeners, local_open_ports
    from .tools import dns_query
    from .internet import dns_servers
    out = {"errors": []}
    try:
        out["wifi"] = active_wifi()
    except Exception as e:  # noqa: BLE001
        out["wifi"] = None
        out["errors"].append(f"Wi-Fi: {e}")
    try:
        server = (dns_servers() or ["1.1.1.1"])[0]
        rcode, answers, _ms = dns_query(server, f"netscan-{os.urandom(5).hex()}.com", "A")
        out["dns_hijack"] = rcode == 0 and bool(answers)
    except (OSError, ValueError) as e:
        out["dns_hijack"] = None
        out["errors"].append(f"DNS: {e}")
    try:
        out["local_ports"] = [p for p in local_open_ports(local_listeners()) if not p["local_only"]]
    except Exception as e:  # noqa: BLE001
        out["local_ports"] = []
        out["errors"].append(f"this computer: {e}")
    return out


# ---- Wi-Fi survey -------------------------------------------------------------------------------


def survey_reading(iface=None, samples=3):
    """Average signal of the current Wi-Fi link over a few readings, plus which access point and band."""
    readings, dbms, last = [], [], None
    for i in range(samples):
        last = active_wifi(rescan=(i == 0)) or last
        if last and last.get("signal") is not None:
            readings.append(last["signal"])
        if iface and not (IS_WIN or IS_MAC):
            dbm = linux_signal_dbm(iface)
            if dbm is not None:
                dbms.append(dbm)
        if i < samples - 1:
            time.sleep(1)
    if not last:
        raise OSError("Not connected to Wi-Fi")
    return {"signal": round(sum(readings) / len(readings)) if readings else None,
            "dbm": round(sum(dbms) / len(dbms)) if dbms else None, "ssid": last["ssid"], "bssid": last["bssid"],
            "band": last["band"], "channel": last["channel"], "when": datetime.datetime.now().isoformat(timespec="seconds")}


def survey_verdict(signal):
    """(level, text) for a signal percentage."""
    if signal is None:
        return "info", "no reading"
    if signal >= 70:
        return "good", "great"
    if signal >= 50:
        return "good", "good"
    if signal >= 35:
        return "warn", "weak: slower, video calls may stutter"
    return "bad", "dead spot: add a mesh point or access point"


# ---- who's home -------------------------------------------------------------------------------


def presence_rows(devices, checked_hours, hours=24, now=None, only=None):
    """Rows for the who's-home chart: [{"key", "name", "cells": ["seen"|"away"|"" per hour], "home_now",
    "last_seen"}], oldest hour first. only(mac, record) picks the devices to show."""
    now = now or datetime.datetime.now()
    buckets = [(now - datetime.timedelta(hours=hours - 1 - i)).strftime("%Y-%m-%dT%H") for i in range(hours)]
    checked = set(checked_hours)
    rows = []
    for mac, d in devices.items():
        if mac.startswith("ip:") or (only and not only(mac, d)):
            continue  # no hardware address (e.g. seen over IPv6 only): not a device we can follow over time
        seen = set(d.get("hours", []))
        if not seen.intersection(buckets):
            continue
        cells = ["seen" if b in seen else "away" if b in checked else "" for b in buckets]
        ip = d.get("ip") or ""
        name = (d.get("nickname") or d.get("hostname") or (ip if ip and not ip.startswith("fe80") else "")
                or f"Unnamed device ({d.get('vendor') or mac})")
        rows.append({"key": mac, "name": name,
                     "cells": cells, "home_now": cells[-1] == "seen" or (cells[-1] == "" and len(cells) > 1
                                                                         and cells[-2] == "seen"),
                     "last_seen": d.get("last_seen", "")})
    return sorted(rows, key=lambda r: (not r["home_now"], r["name"].lower()))


# ---- services and web pages ---------------------------------------------------------------------

# mDNS service types people recognise.
SERVICE_NAMES = {
    "_googlecast._tcp": "Chromecast / Google Cast", "_airplay._tcp": "AirPlay", "_raop._tcp": "AirPlay speaker",
    "_spotify-connect._tcp": "Spotify Connect", "_sonos._tcp": "Sonos", "_ipp._tcp": "Printer (IPP)",
    "_ipps._tcp": "Printer (IPP, secure)", "_printer._tcp": "Printer", "_pdl-datastream._tcp": "Printer (raw)",
    "_scanner._tcp": "Scanner", "_uscan._tcp": "Scanner", "_ssh._tcp": "SSH", "_sftp-ssh._tcp": "SFTP",
    "_smb._tcp": "Windows file sharing", "_afpovertcp._tcp": "Mac file sharing", "_adisk._tcp": "Time Machine disk",
    "_hap._tcp": "HomeKit accessory", "_homekit._tcp": "HomeKit", "_matter._tcp": "Matter device",
    "_hue._tcp": "Philips Hue", "_esphomelib._tcp": "ESPHome", "_home-assistant._tcp": "Home Assistant",
    "_rfb._tcp": "Screen sharing (VNC)", "_companion-link._tcp": "Apple device", "_http._tcp": "Web page",
    "_https._tcp": "Web page (HTTPS)", "_workstation._tcp": "Computer", "_daap._tcp": "Music library",
    "_mqtt._tcp": "MQTT broker", "_octoprint._tcp": "OctoPrint", "_plexmediasvr._tcp": "Plex",
    "_amzn-wplay._tcp": "Fire TV", "_androidtvremote2._tcp": "Android TV", "_nvstream._tcp": "NVIDIA GameStream",
    "_shelly._tcp": "Shelly", "_elg._tcp": "Elgato light", "_touch-able._tcp": "Apple TV remote",
    "_kdeconnect._udp": "KDE Connect", "_mpd._tcp": "MPD music player", "_mopidy-http._tcp": "Mopidy music",
    "_ftp._tcp": "FTP", "_nfs._tcp": "NFS file sharing", "_webdav._tcp": "WebDAV", "_sftp._tcp": "SFTP",
}
# Announced but meaningless to people (Apple internals, metadata, web pages found by probing instead).
HIDDEN_SERVICES = {"_http._tcp", "_https._tcp", "_device-info._tcp", "_rdlink._tcp", "_sleep-proxy._udp",
                   "_apple-mobdev2._tcp", "_remotepairing._tcp", "_asquic._udp", "_meshcop._udp", "_trel._udp",
                   "_srpl-tls._tcp", "_dhnap._tcp"}

# Ports web interfaces commonly use, with the app that usually sits there.
WEB_APPS = {80: "", 443: "", 81: "", 8080: "", 8443: "", 8000: "", 8008: "", 8081: "", 8888: "", 5000: "",
            5001: "Synology DSM", 3000: "", 8123: "Home Assistant", 32400: "Plex", 8096: "Jellyfin",
            9000: "", 9443: "Portainer", 9090: "Cockpit", 19999: "Netdata", 8006: "Proxmox", 631: "Printer (CUPS)",
            2283: "Immich", 7681: "", 8384: "Syncthing", 5055: "Overseerr", 8989: "Sonarr", 7878: "Radarr"}


def _open(ip, port, timeout=0.6):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def find_services(local_ip, ips, known_web=(), network=None):
    """Every web page and advertised service on the network: [{"ip", "kind", "name", "url", "detail"}].
    ips: devices to probe for web pages; known_web: (ip, port) pairs a scan already found; network: only
    list mDNS answers from this network (a VPN or second interface can relay others)."""
    from .discovery import mdns_browse, web_title  # late: discovery is heavy and GUI-only here
    rows = []
    with ThreadPoolExecutor(max_workers=64) as ex:
        mdns = ex.submit(mdns_browse, local_ip) if local_ip else None
        probes = {(ip, port): ex.submit(_open, ip, port) for ip in ips for port in WEB_APPS}
        found = sorted(set(known_web) | {key for key, fut in probes.items() if fut.result()})
        titles = {key: ex.submit(web_title, *key) for key in found}
        for (ip, port), fut in titles.items():
            try:
                title = fut.result()
            except Exception:  # noqa: BLE001 - a page that errors is still worth listing
                title = ""
            scheme = "https" if port in (443, 8443, 9443, 5001, 8006) else "http"
            error = bool(re.match(r"(HTTP )?\d{3} ", title or ""))  # "401 Unauthorized": a login or error page
            app = WEB_APPS.get(port)
            rows.append({"ip": ip, "kind": "Web page", "name": app or ("" if error else title),
                         "url": f"{scheme}://{ip}{'' if port in (80, 443) else f':{port}'}/",
                         "detail": ("needs a login" if "401" in title[:8] else title) if (error or app) and title else ""})
        for ip, d in (mdns.result() if mdns else {}).items():
            if network is not None and _addr(ip) not in network:
                continue
            instance = d["services"][0] if d["services"] else ""
            if re.fullmatch(r"[0-9a-f]{16,}", instance):
                instance = ""  # an app's random ID, not a name
            for kind in d["types"]:
                if kind in HIDDEN_SERVICES:
                    continue
                rows.append({"ip": ip, "kind": SERVICE_NAMES.get(kind, kind.strip("_").split(".")[0]),
                             "name": d.get("friendly") or instance or d.get("name", ""),
                             "url": "", "detail": d.get("model", "")})
    return sorted(rows, key=lambda r: (_ip_key(r["ip"]), r["kind"] != "Web page", r["kind"]))


def _ip_key(ip):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, 0)
