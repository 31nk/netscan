"""The Traffic tab's engine: reads the capture helper's pcap stream and turns packets into things people can use:
which switch port this computer is plugged into (LLDP / CDP), spanning tree, DHCP servers, DNS lookups, ARP
conflicts, broadcast storms, protocols and top talkers."""

import collections
import os
import socket
import struct
import subprocess
import sys
import threading
import time

from .discovery import _dns_name, parse_dns_records
from .system import IS_MAC, IS_WIN, NO_WINDOW

HELPER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "capture_helper.py")

# Well-known ports, for naming what traffic is: (proto, port) -> name.
APPS = {
    ("tcp", 443): "HTTPS", ("udp", 443): "QUIC (HTTP/3)", ("tcp", 80): "HTTP", ("tcp", 8080): "HTTP",
    ("udp", 53): "DNS", ("tcp", 53): "DNS", ("tcp", 853): "DNS over TLS", ("tcp", 22): "SSH",
    ("tcp", 3389): "Remote Desktop", ("udp", 3389): "Remote Desktop", ("tcp", 445): "SMB file sharing",
    ("udp", 137): "NetBIOS", ("udp", 138): "NetBIOS", ("tcp", 139): "NetBIOS", ("udp", 5353): "mDNS",
    ("udp", 5355): "LLMNR", ("udp", 1900): "SSDP / UPnP", ("udp", 67): "DHCP", ("udp", 68): "DHCP",
    ("udp", 123): "NTP", ("tcp", 25): "Mail (SMTP)", ("tcp", 587): "Mail (SMTP)", ("tcp", 465): "Mail (SMTP)",
    ("tcp", 993): "Mail (IMAP)", ("tcp", 143): "Mail (IMAP)", ("tcp", 995): "Mail (POP3)",
    ("udp", 51820): "WireGuard VPN", ("udp", 1194): "OpenVPN", ("tcp", 1194): "OpenVPN", ("udp", 500): "IPsec VPN",
    ("udp", 4500): "IPsec VPN", ("udp", 3478): "STUN (calls)", ("udp", 3479): "Teams / calls",
    ("udp", 3480): "Teams / calls", ("udp", 3481): "Teams / calls", ("udp", 19302): "STUN (calls)",
    ("udp", 5060): "SIP (VoIP)", ("tcp", 5060): "SIP (VoIP)", ("tcp", 5061): "SIP (VoIP)",
    ("tcp", 1883): "MQTT", ("tcp", 8883): "MQTT", ("tcp", 5222): "XMPP", ("tcp", 32400): "Plex",
    ("tcp", 8009): "Chromecast", ("tcp", 7000): "AirPlay", ("udp", 1716): "KDE Connect", ("tcp", 1716): "KDE Connect",
    ("udp", 27036): "Steam", ("tcp", 27036): "Steam", ("udp", 41641): "Tailscale", ("tcp", 5938): "TeamViewer",
    ("udp", 161): "SNMP", ("udp", 514): "Syslog", ("tcp", 9100): "Printing", ("tcp", 631): "Printing (IPP)",
    ("udp", 3702): "WS-Discovery", ("udp", 10001): "Ubiquiti discovery",
}
DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}
LLDP_CAPS = [(1, "other"), (2, "repeater"), (4, "switch"), (8, "Wi-Fi access point"), (16, "router"),
             (32, "phone"), (64, "DOCSIS"), (128, "station")]
# IEEE 802.3 operational MAU types (RFC 4836) that are common enough to name.
MAU_TYPES = {10: "10 Mbit/s half duplex", 11: "10 Mbit/s full duplex", 15: "100 Mbit/s half duplex",
             16: "100 Mbit/s full duplex", 29: "1 Gbit/s half duplex", 30: "1 Gbit/s full duplex",
             54: "10 Gbit/s", 110: "2.5 Gbit/s", 111: "5 Gbit/s", 119: "2.5 Gbit/s", 120: "5 Gbit/s"}
STORM_PPS = 300           # broadcast frames per second, sustained, that count as a storm
DNS_TYPES = {1: "A", 28: "AAAA", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 33: "SRV", 65: "HTTPS", 64: "SVCB",
             2: "NS", 6: "SOA", 255: "ANY"}


def mac_text(b):
    return ":".join(f"{x:02X}" for x in b)


def _printable(b):
    """Text from a protocol field (line breaks folded into spaces), or "" for binary data."""
    text = " ".join(b.decode("utf-8", errors="replace").strip("\x00 ").split())
    return text if text and all(c.isprintable() for c in text) else ""


# ---- pcap stream ------------------------------------------------------------------------------------


class PcapReader:
    """Incremental pcap parser: feed() bytes as they arrive, get back (ts, frame, wire length) tuples."""

    def __init__(self):
        self.buf = b""
        self.endian = None
        self.linktype = None

    def feed(self, data):
        self.buf += data
        out = []
        if self.endian is None:
            if len(self.buf) < 24:
                return out
            magic = self.buf[:4]
            if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                self.endian = "<"
            elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                self.endian = ">"
            else:
                raise ValueError("not a pcap stream")
            self.nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
            self.linktype = struct.unpack(self.endian + "I", self.buf[20:24])[0]
            self.buf = self.buf[24:]
        pos = 0
        while len(self.buf) - pos >= 16:
            sec, frac, cap, wire = struct.unpack(self.endian + "IIII", self.buf[pos:pos + 16])
            if len(self.buf) - pos - 16 < cap:
                break
            out.append((sec + frac / (1e9 if self.nano else 1e6), self.buf[pos + 16:pos + 16 + cap], wire))
            pos += 16 + cap
        self.buf = self.buf[pos:]
        return out


def pcap_bytes(records):
    """A pcap file (Ethernet) from [(ts, frame, wire length)]."""
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for ts, frame, wire in records:
        out.append(struct.pack("<IIII", int(ts), int(ts % 1 * 1e6), len(frame), wire) + frame)
    return b"".join(out)


# ---- decoders for the interesting frames -------------------------------------------------------------


def parse_lldp(payload):
    """LLDP TLVs -> {"protocol", "switch", "port", "port_desc", "description", "caps", "mgmt", "vlan",
    "voice_vlan", "speed", "chassis", "vlans"}."""
    info = {"protocol": "LLDP", "vlans": []}
    off = 0
    while off + 2 <= len(payload):
        head = struct.unpack("!H", payload[off:off + 2])[0]
        ttype, length = head >> 9, head & 0x1FF
        value = payload[off + 2:off + 2 + length]
        off += 2 + length
        if ttype == 0:
            break
        if ttype in (1, 2) and value:
            sub, raw = value[0], value[1:]
            if (ttype == 1 and sub == 4) or (ttype == 2 and sub == 3):
                text = mac_text(raw) if len(raw) == 6 else raw.hex()
            elif sub == 5 and len(raw) >= 5 and raw[0] == 1:
                text = socket.inet_ntoa(raw[1:5])
            else:
                text = _printable(raw) or raw.hex()
            info["chassis" if ttype == 1 else "port"] = text
        elif ttype == 4:
            info["port_desc"] = _printable(value)
        elif ttype == 5:
            info["switch"] = _printable(value)
        elif ttype == 6:
            info["description"] = _printable(value)
        elif ttype == 7 and len(value) >= 4:
            enabled = struct.unpack("!H", value[2:4])[0]
            info["caps"] = [name for bit, name in LLDP_CAPS if enabled & bit]
        elif ttype == 8 and len(value) >= 6 and value[1] == 1:
            info["mgmt"] = socket.inet_ntoa(value[2:6])
        elif ttype == 127 and len(value) >= 4:
            oui, sub, data = value[:3], value[3], value[4:]
            if oui == b"\x00\x80\xc2" and sub == 1 and len(data) >= 2:
                info["vlan"] = struct.unpack("!H", data[:2])[0]
            elif oui == b"\x00\x80\xc2" and sub == 3 and len(data) >= 3:
                info["vlans"].append((struct.unpack("!H", data[:2])[0], _printable(data[3:3 + data[2]])))
            elif oui == b"\x00\x12\x0f" and sub == 1 and len(data) >= 5:
                info["speed"] = MAU_TYPES.get(struct.unpack("!H", data[3:5])[0], "")
            elif oui == b"\x00\x12\xbb" and sub == 2 and len(data) >= 4 and data[0] == 1:
                info["voice_vlan"] = (struct.unpack("!I", data[:4])[0] >> 9) & 0xFFF
    return info


def parse_cdp(payload):
    """CDP (Cisco) TLVs after the 4-byte header -> the same keys as parse_lldp."""
    info = {"protocol": "CDP", "vlans": []}
    off = 4
    while off + 4 <= len(payload):
        ttype, length = struct.unpack("!HH", payload[off:off + 4])
        if length < 4:
            break
        value = payload[off + 4:off + length]
        off += length
        if ttype == 0x0001:
            info["switch"] = _printable(value)
        elif ttype == 0x0003:
            info["port"] = _printable(value)
        elif ttype == 0x0005:  # software version: several lines; the first names it
            lines = value.decode("utf-8", errors="replace").strip("\x00 ").splitlines()
            info["description"] = _printable(lines[0].encode()) if lines else ""
        elif ttype == 0x0006:
            info["platform"] = _printable(value)
        elif ttype == 0x000A and len(value) >= 2:
            info["vlan"] = struct.unpack("!H", value[:2])[0]
        elif ttype == 0x000B and value:
            info["speed"] = "full duplex" if value[0] else "half duplex"
        elif ttype == 0x000E and len(value) >= 3:
            info["voice_vlan"] = struct.unpack("!H", value[1:3])[0]
        elif ttype in (0x0002, 0x0016) and len(value) >= 4 and "mgmt" not in info:
            i = 4
            if i + 2 <= len(value):
                plen = value[i + 1]
                proto = value[i + 2:i + 2 + plen]
                i += 2 + plen
                alen = struct.unpack("!H", value[i:i + 2])[0] if i + 2 <= len(value) else 0
                if proto == b"\xcc" and alen == 4:
                    info["mgmt"] = socket.inet_ntoa(value[i + 2:i + 6])
    return info


def parse_stp(payload):
    """A spanning tree BPDU (after the LLC header): root bridge and whether the topology just changed."""
    if len(payload) < 35 or payload[:2] != b"\x00\x00" or payload[3] not in (0x00, 0x02):
        return None
    flags = payload[4]
    root_pri = struct.unpack("!H", payload[5:7])[0]
    return {"root_priority": root_pri & 0xF000, "root_mac": mac_text(payload[7:13]),
            "cost": struct.unpack("!I", payload[13:17])[0], "change": bool(flags & 0x01),
            "version": {0: "STP", 2: "RSTP/MSTP"}.get(payload[2], "STP")}


def parse_dhcp(udp_payload):
    """A DHCP message -> {"type", "client", "hostname", "server", "offered", "requested", "router", "dns",
    "vendor"} or None."""
    p = udp_payload
    if len(p) < 240 or p[236:240] != b"\x63\x82\x53\x63":
        return None
    out = {"client": mac_text(p[28:34]), "offered": socket.inet_ntoa(p[16:20]), "type": "", "hostname": "",
           "server": "", "requested": "", "router": "", "dns": "", "vendor": ""}
    off = 240
    while off < len(p):
        code = p[off]
        if code == 255:
            break
        if code == 0:
            off += 1
            continue
        if off + 1 >= len(p):
            break
        length = p[off + 1]
        value = p[off + 2:off + 2 + length]
        off += 2 + length
        if code == 53 and value:
            out["type"] = DHCP_TYPES.get(value[0], str(value[0]))
        elif code == 12:
            out["hostname"] = _printable(value)
        elif code == 54 and len(value) == 4:
            out["server"] = socket.inet_ntoa(value)
        elif code == 50 and len(value) == 4:
            out["requested"] = socket.inet_ntoa(value)
        elif code == 3 and len(value) >= 4:
            out["router"] = socket.inet_ntoa(value[:4])
        elif code == 6 and len(value) >= 4:
            out["dns"] = ", ".join(socket.inet_ntoa(value[i:i + 4]) for i in range(0, len(value) - 3, 4))
        elif code == 60:
            out["vendor"] = _printable(value)
    if out["offered"] == "0.0.0.0":
        out["offered"] = ""
    return out


def dns_question(msg):
    """(name, type) of a DNS message's first question, or None."""
    if len(msg) < 17:
        return None
    try:
        name, off = _dns_name(msg, 12)
        qtype = struct.unpack("!H", msg[off:off + 2])[0]
    except (IndexError, struct.error):
        return None
    return name, DNS_TYPES.get(qtype, str(qtype))


# ---- the analyser --------------------------------------------------------------------------------------


class Analyzer:
    """Keeps running totals from decoded frames. Thread-safe: add() from the reader, snapshot() from the GUI."""

    def __init__(self, local_macs=(), local_ips=(), gateway=None):
        self.lock = threading.Lock()
        self.local_macs = {m.upper() for m in local_macs if m}
        self.local_ips = set(local_ips)
        self.gateway = gateway
        self.started = time.time()
        self.packets = self.bytes = 0
        self.protocols = collections.defaultdict(lambda: [0, 0])      # name -> [packets, bytes]
        self.talkers = {}                                              # ip -> {"in", "out", "packets", "apps"}
        self.names = {}                                                # ip -> DNS name seen in answers
        self.dns = collections.deque(maxlen=400)                        # (ts, client, name, type)
        self.switch = None
        self.switch_seen = 0.0
        self.stp = None
        self.dhcp_servers = {}                                         # server ip -> last offer/ack
        self.arp = {}                                                  # ip -> {mac: last seen}
        self.vlans = collections.Counter()
        self.events = collections.deque(maxlen=300)                    # (ts, level, text)
        self._event_keys = {}
        self.second = int(time.time())
        self.second_counts = collections.Counter()                     # this second: bcast, mcast, packets, bytes
        self.rates = collections.deque(maxlen=120)                     # (ts, pps, bytes/s, bcast/s)
        self.storm_run = 0

    def event(self, level, text, key=None, every=300):
        """Log an event, but the same key at most once per `every` seconds."""
        key = key or text
        now = time.time()
        if now - self._event_keys.get(key, 0) < every:
            return
        self._event_keys[key] = now
        self.events.append((now, level, text))

    def _tick(self, ts):
        sec = int(ts)
        if sec == self.second:
            return
        c = self.second_counts
        self.rates.append((self.second, c["packets"], c["bytes"], c["bcast"]))
        if c["bcast"] >= STORM_PPS:
            self.storm_run += 1
            if self.storm_run == 3:
                self.event("bad", f"Broadcast storm: {c['bcast']} broadcast frames a second. Usually a network "
                                  "loop (a cable plugged into two switch ports) or a failing device.", key="storm")
        else:
            self.storm_run = 0
        self.second, self.second_counts = sec, collections.Counter()

    def add(self, ts, frame, wire):
        if len(frame) < 14:
            return
        with self.lock:
            self._tick(ts)
            self.packets += 1
            self.bytes += wire
            c = self.second_counts
            c["packets"] += 1
            c["bytes"] += wire
            dst, src = frame[:6], frame[6:12]
            if dst == b"\xff" * 6:
                c["bcast"] += 1
            elif dst[0] & 1:
                c["mcast"] += 1
            etype = struct.unpack("!H", frame[12:14])[0]
            off = 14
            if etype == 0x8100 and len(frame) >= 18:
                self.vlans[struct.unpack("!H", frame[14:16])[0] & 0xFFF] += 1
                etype = struct.unpack("!H", frame[16:18])[0]
                off = 18
            outgoing = mac_text(src) in self.local_macs
            name = self._decode(ts, frame, off, etype, dst, src, wire, outgoing)
            p = self.protocols[name]
            p[0] += 1
            p[1] += wire

    def _decode(self, ts, frame, off, etype, dst, src, wire, outgoing):
        if etype == 0x88CC:
            self._switch(parse_lldp(frame[off:]), ts)
            return "LLDP (switch info)"
        if etype <= 1500:  # 802.3 length field: LLC frames (CDP, STP)
            llc = frame[off:off + 8]
            if dst == b"\x01\x00\x0c\xcc\xcc\xcc" and llc[:3] == b"\xaa\xaa\x03" and llc[6:8] == b"\x20\x00":
                self._switch(parse_cdp(frame[off + 8:]), ts)
                return "CDP (switch info)"
            if llc[:2] == b"\x42\x42":
                bpdu = parse_stp(frame[off + 3:])
                if bpdu:
                    if bpdu["change"]:
                        self.event("warn", "Spanning tree topology change: a switch port went up or down, or a "
                                           "loop was blocked. Frequent changes cause brief outages.", key="stpchange",
                                   every=60)
                    self.stp = bpdu
                return "Spanning tree"
            return "Other (802.3)"
        if etype == 0x0806:
            self._arp(frame[off:], ts)
            return "ARP"
        if etype == 0x0800 and len(frame) >= off + 20:
            ihl = (frame[off] & 0x0F) * 4
            proto = frame[off + 9]
            s_ip, d_ip = socket.inet_ntoa(frame[off + 12:off + 16]), socket.inet_ntoa(frame[off + 16:off + 20])
            return self._ip(ts, frame, off + ihl, proto, s_ip, d_ip, wire, outgoing, dst)
        if etype == 0x86DD and len(frame) >= off + 40:
            proto = frame[off + 6]
            s_ip = socket.inet_ntop(socket.AF_INET6, frame[off + 8:off + 24])
            d_ip = socket.inet_ntop(socket.AF_INET6, frame[off + 24:off + 40])
            if proto == 58:
                return "IPv6 neighbour discovery" if len(frame) > off + 40 and 133 <= frame[off + 40] <= 137 else "ICMPv6"
            return self._ip(ts, frame, off + 40, proto, s_ip, d_ip, wire, outgoing, dst)
        return {0x888E: "802.1X (network login)", 0x8863: "PPPoE", 0x8864: "PPPoE", 0x88A8: "VLAN (Q-in-Q)",
                0x8899: "Realtek", 0x893A: "IEEE 1905 (mesh)", 0x88E1: "HomePlug"}.get(etype, f"Other (0x{etype:04x})")

    def _ip(self, ts, frame, l4, proto, s_ip, d_ip, wire, outgoing, dst):
        app = {1: "ICMP (ping)", 2: "IGMP (multicast)"}.get(proto, "")
        sport = dport = None
        if proto in (6, 17) and len(frame) >= l4 + 4:
            sport, dport = struct.unpack("!HH", frame[l4:l4 + 4])
            kind = "tcp" if proto == 6 else "udp"
            app = APPS.get((kind, min(sport, dport))) or APPS.get((kind, sport)) or APPS.get((kind, dport)) or ""
            if not app:
                app = f"Other {kind.upper()}"
            if proto == 17:
                payload = frame[l4 + 8:]
                if 53 in (sport, dport):
                    self._dns(ts, payload, s_ip if dport == 53 else d_ip, response=sport == 53)
                elif {sport, dport} & {67, 68}:
                    self._dhcp(ts, payload, s_ip)
        elif not app:
            app = f"Other IP ({proto})"
        # Who's on the other end: for this computer's own traffic, the far side; otherwise the sender.
        if s_ip in self.local_ips or outgoing:
            remote, direction = d_ip, "out"
        elif d_ip in self.local_ips:
            remote, direction = s_ip, "in"
        else:
            remote, direction = s_ip, "in"
        if not (dst[0] & 1) or remote == s_ip:
            t = self.talkers.setdefault(remote, {"in": 0, "out": 0, "packets": 0, "apps": collections.Counter()})
            t[direction] += wire
            t["packets"] += 1
            t["apps"][app] += wire
        return app

    def _dns(self, ts, msg, client, response):
        q = dns_question(msg)
        if not q:
            return
        if not response:
            self.dns.append((ts, client, q[0], q[1]))
            return
        try:
            for rtype, _name, value in parse_dns_records(msg):
                if rtype in (1, 28) and value:
                    self.names[value] = q[0]
        except (struct.error, IndexError, ValueError, OSError):
            pass

    def _dhcp(self, ts, payload, sender):
        d = parse_dhcp(payload)
        if not d:
            return
        who = d["hostname"] or d["client"]
        if d["type"] in ("OFFER", "ACK", "NAK"):
            server = d["server"] or sender
            first = server not in self.dhcp_servers
            self.dhcp_servers[server] = {**d, "ts": ts}
            if first and len(self.dhcp_servers) > 1:
                self.event("bad", f"A second DHCP server is answering: {server} (also "
                                  f"{', '.join(s for s in self.dhcp_servers if s != server)}). Devices may get the wrong "
                                  "router or DNS; find it and turn its DHCP off.", key=f"dhcp2-{server}")
            text = f"DHCP {d['type']} from {server}" + (f": {d['offered']}" if d["offered"] else "") + f" for {who}"
        else:
            text = f"DHCP {d['type'] or '?'} from {who}" + (f" (asking for {d['requested']})" if d["requested"] else "")
        self.event("info", text, key=f"dhcp-{d['type']}-{d['client']}", every=20)

    def _arp(self, payload, ts):
        if len(payload) < 28:
            return
        s_mac, s_ip = mac_text(payload[8:14]), socket.inet_ntoa(payload[14:18])
        if s_ip == "0.0.0.0":
            return  # address probes
        seen = self.arp.setdefault(s_ip, {})
        seen[s_mac] = ts
        recent = [m for m, t in seen.items() if ts - t < 600]
        if len(recent) > 1:
            level = "bad" if s_ip == self.gateway else "warn"
            what = "the router's address" if s_ip == self.gateway else s_ip
            self.event(level, f"Two devices claim {what}: {', '.join(recent)}. That's an IP address conflict, or "
                              "someone intercepting traffic (ARP spoofing) if it's the router.", key=f"arp-{s_ip}")

    def _switch(self, info, ts):
        before = self.switch
        self.switch, self.switch_seen = info, ts
        if not before or (before.get("switch"), before.get("port")) != (info.get("switch"), info.get("port")):
            self.event("good", f"Switch announcement ({info['protocol']}): {info.get('switch') or '?'} port "
                               f"{info.get('port_desc') or info.get('port') or '?'}"
                       + (f", VLAN {info['vlan']}" if info.get("vlan") else ""), key=f"sw-{info.get('port')}")

    def snapshot(self, top=40):
        """A copy of everything for the GUI."""
        with self.lock:
            talkers = sorted(self.talkers.items(), key=lambda kv: -(kv[1]["in"] + kv[1]["out"]))[:top]
            return {
                "packets": self.packets, "bytes": self.bytes, "seconds": max(1.0, time.time() - self.started),
                "protocols": sorted(((k, v[0], v[1]) for k, v in self.protocols.items()), key=lambda x: -x[2]),
                "talkers": [(ip, t["in"], t["out"], t["packets"], t["apps"].most_common(1)[0][0] if t["apps"] else "",
                             self.names.get(ip, "")) for ip, t in talkers],
                "dns": list(self.dns)[-200:][::-1], "switch": dict(self.switch) if self.switch else None,
                "switch_seen": self.switch_seen, "stp": dict(self.stp) if self.stp else None,
                "dhcp_servers": dict(self.dhcp_servers), "vlans": dict(self.vlans),
                "events": list(self.events)[::-1], "rates": list(self.rates)[-60:],
            }


# ---- running a capture ---------------------------------------------------------------------------------


def capture_argv(net, root_prefix=None, python=None):
    """The command that captures on this network's interface, as (argv, needs a password prompt)."""
    python = python or sys.executable
    if IS_WIN:
        return [python, HELPER, net["local_ip"]], False
    if IS_MAC:
        return [*(root_prefix or []), "/usr/sbin/tcpdump", "-i", net["iface"], "-U", "-s", "1600", "-w", "-"], bool(root_prefix)
    if os.geteuid() == 0:
        return [python, HELPER, net["iface"]], False
    return [*(root_prefix or []), python, HELPER, net["iface"]], bool(root_prefix)


class Capture:
    """Runs the capture command, feeds an Analyzer from a background thread, and keeps the most recent
    packets (up to KEEP_BYTES) so they can be saved for Wireshark."""

    KEEP_BYTES = 64_000_000

    def __init__(self, argv, analyzer, env=None):
        self.analyzer = analyzer
        self.kept = collections.deque()
        self.kept_bytes = 0
        self.error = ""
        self.running = True
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=env, **NO_WINDOW)
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        reader = PcapReader()
        out = self.proc.stdout
        try:
            while True:
                data = out.read1(65536) if hasattr(out, "read1") else out.read(4096)
                if not data:
                    break
                for ts, frame, wire in reader.feed(data):
                    self.analyzer.add(ts, frame, wire)
                    self.kept.append((ts, frame, wire))
                    self.kept_bytes += len(frame) + 16
                    while self.kept_bytes > self.KEEP_BYTES:
                        _t, f, _w = self.kept.popleft()
                        self.kept_bytes -= len(f) + 16
        except (OSError, ValueError) as e:
            self.error = str(e)
        self.running = False
        try:
            err = self.proc.stderr.read().decode(errors="replace").strip()
        except (OSError, ValueError):
            err = ""
        code = self.proc.wait()
        if code not in (0, None) and not self.error:
            self.error = ("the password prompt was cancelled" if code in (126, 127) else
                          err.splitlines()[-1] if err else f"capture stopped (code {code})")

    def stop(self):
        """Close our end of the pipes: the helper sees that and exits (it may be root, so it can't be killed)."""
        for pipe in (self.proc.stdin, self.proc.stdout):
            try:
                pipe.close()
            except OSError:
                pass
        try:
            self.proc.terminate()
        except (PermissionError, ProcessLookupError, OSError):
            pass
        self.running = False

    def save(self, path):
        with open(path, "wb") as f:
            f.write(pcap_bytes(list(self.kept)))
        return len(self.kept)
