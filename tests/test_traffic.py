"""The Traffic tab's engine with hand-built packets: pcap reading, LLDP, CDP, spanning tree, DHCP (and a second
DHCP server), ARP conflicts, DNS, VLAN tags, broadcast storms, talkers and the capture helper. The end-to-end
capture runs inside a user namespace (no root needed) where the system allows it."""

import os
import shutil
import socket
import struct
import subprocess
import sys
import unittest

import _support

from netscan_app import capture_helper
from netscan_app.traffic import (
    HELPER, Analyzer, PcapReader, capture_argv, parse_cdp, parse_dhcp, parse_lldp, pcap_bytes,
)

ME, ROUTER, OTHER = bytes.fromhex("74563cb92e89"), bytes.fromhex("143375fe1598"), bytes.fromhex("aabbccddeeff")
BCAST = b"\xff" * 6


def eth(dst, src, etype, payload):
    return dst + src + struct.pack("!H", etype) + payload


def tlv(ttype, value):
    return struct.pack("!H", (ttype << 9) | len(value)) + value


def lldp_frame():
    body = (tlv(1, b"\x04" + ROUTER) + tlv(2, b"\x05Gi1/0/12") + tlv(3, b"\x00\x78") + tlv(4, b"Office desk 12")
            + tlv(5, b"core-sw1") + tlv(6, b"Cisco IOS Software, C2960X\nTechnical Support") + tlv(7, struct.pack("!HH", 0x14, 0x04))
            + tlv(8, b"\x05\x01" + socket.inet_aton("10.0.0.2") + b"\x02\x00\x00\x00\x01\x00")
            + tlv(127, b"\x00\x80\xc2\x01" + struct.pack("!H", 20))
            + tlv(127, b"\x00\x12\x0f\x01" + b"\x03\x6c\x00" + struct.pack("!H", 30))
            + tlv(127, b"\x00\x12\xbb\x02" + struct.pack("!I", (1 << 24) | (30 << 9)))
            + tlv(0, b""))
    return eth(bytes.fromhex("0180c200000e"), ROUTER, 0x88CC, body)


def cdp_frame():
    def t(ttype, value):
        return struct.pack("!HH", ttype, len(value) + 4) + value
    addr = struct.pack("!I", 1) + b"\x01\x01\xcc" + struct.pack("!H", 4) + socket.inet_aton("10.0.0.3")
    body = (b"\x02\xb4\x00\x00" + t(1, b"sw-floor2") + t(2, addr) + t(3, b"FastEthernet0/7")
            + t(5, b"Cisco IOS 15.2\nmore") + t(6, b"cisco WS-C3560") + t(0x0A, struct.pack("!H", 10))
            + t(0x0B, b"\x01") + t(0x0E, b"\x01" + struct.pack("!H", 110)))
    llc = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
    return bytes.fromhex("01000ccccccc") + ROUTER + struct.pack("!H", len(llc + body)) + llc + body


def stp_frame(change=False):
    bpdu = (b"\x00\x00\x02\x02" + bytes([0x01 if change else 0x00]) + struct.pack("!H", 0x8000) + ROUTER
            + struct.pack("!I", 4) + struct.pack("!H", 0x8000) + OTHER + b"\x80\x01" + b"\x00" * 8)
    llc = b"\x42\x42\x03"
    return bytes.fromhex("0180c2000000") + OTHER + struct.pack("!H", len(llc + bpdu)) + llc + bpdu


def ipv4(src, dst, proto, payload):
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0, socket.inet_aton(src),
                       socket.inet_aton(dst))
    return head + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dhcp(msg_type, client, yiaddr="0.0.0.0", server=None, hostname=None):
    p = bytearray(240)
    p[0] = 2 if msg_type in (2, 5) else 1
    p[16:20] = socket.inet_aton(yiaddr)
    p[28:34] = client
    p[236:240] = b"\x63\x82\x53\x63"
    opts = bytes([53, 1, msg_type])
    if server:
        opts += bytes([54, 4]) + socket.inet_aton(server)
    if hostname:
        opts += bytes([12, len(hostname)]) + hostname.encode()
    return bytes(p) + opts + b"\xff"


def dns_query(name, ident=7):
    q = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0" + b"\x00\x01\x00\x01"
    return struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0) + q


def dns_answer(name, ip, ident=7):
    q = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0" + b"\x00\x01\x00\x01"
    a = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return struct.pack("!6H", ident, 0x8180, 1, 1, 0, 0) + q + a


def arp(sender_mac, sender_ip):
    return eth(BCAST, sender_mac, 0x0806, struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + sender_mac
               + socket.inet_aton(sender_ip) + b"\x00" * 6 + socket.inet_aton("10.0.0.50"))


class Decoders(unittest.TestCase):
    def test_lldp(self):
        info = parse_lldp(lldp_frame()[14:])
        self.assertEqual((info["switch"], info["port"], info["port_desc"]), ("core-sw1", "Gi1/0/12", "Office desk 12"))
        self.assertEqual((info["vlan"], info["voice_vlan"], info["mgmt"]), (20, 30, "10.0.0.2"))
        self.assertEqual(info["speed"], "1 Gbit/s full duplex")
        self.assertEqual(info["caps"], ["switch"])
        self.assertEqual(info["chassis"], "14:33:75:FE:15:98")
        self.assertEqual(info["description"], "Cisco IOS Software, C2960X Technical Support")

    def test_cdp(self):
        frame = cdp_frame()
        info = parse_cdp(frame[14 + 8:])
        self.assertEqual((info["switch"], info["port"], info["platform"]), ("sw-floor2", "FastEthernet0/7", "cisco WS-C3560"))
        self.assertEqual((info["vlan"], info["voice_vlan"], info["mgmt"]), (10, 110, "10.0.0.3"))
        self.assertEqual(info["description"], "Cisco IOS 15.2")

    def test_dhcp(self):
        d = parse_dhcp(dhcp(2, OTHER, "10.0.0.60", server="10.0.0.1", hostname="laptop"))
        self.assertEqual((d["type"], d["offered"], d["server"], d["hostname"]), ("OFFER", "10.0.0.60", "10.0.0.1", "laptop"))
        self.assertEqual(d["client"], "AA:BB:CC:DD:EE:FF")
        self.assertIsNone(parse_dhcp(b"\x00" * 100))


class Analysis(unittest.TestCase):
    def setUp(self):
        self.a = Analyzer(local_macs=["74:56:3C:B9:2E:89"], local_ips=["10.0.0.9"], gateway="10.0.0.1")
        self.t = 1_000_000.0

    def add(self, frame, wire=None, dt=0.001):
        self.t += dt
        self.a.add(self.t, frame, wire or len(frame))

    def test_switch_stp_and_vlans(self):
        self.add(lldp_frame())
        self.add(stp_frame(change=True))
        self.add(eth(ME, ROUTER, 0x8100, struct.pack("!HH", 30, 0x0800) + ipv4("10.0.0.1", "10.0.0.9", 1, b"\x00" * 8)))
        s = self.a.snapshot()
        self.assertEqual(s["switch"]["port"], "Gi1/0/12")
        self.assertEqual(s["stp"]["root_mac"], "14:33:75:FE:15:98")
        self.assertEqual(s["vlans"], {30: 1})
        texts = [text for _t, _l, text in s["events"]]
        self.assertTrue(any(t.startswith("Switch announcement (LLDP): core-sw1 port Office desk 12") for t in texts))
        self.assertTrue(any("topology change" in t for t in texts))
        names = {name for name, _p, _b in s["protocols"]}
        self.assertTrue({"LLDP (switch info)", "Spanning tree", "ICMP (ping)"} <= names)
        self.add(cdp_frame())
        self.assertEqual(self.a.snapshot()["switch"]["protocol"], "CDP")

    def test_second_dhcp_server(self):
        for server, mac in (("10.0.0.1", ROUTER), ("10.0.0.254", OTHER)):
            self.add(eth(BCAST, mac, 0x0800, ipv4(server, "255.255.255.255", 17,
                                                  udp(67, 68, dhcp(2, ME, "10.0.0.77", server=server)))))
        s = self.a.snapshot()
        self.assertEqual(set(s["dhcp_servers"]), {"10.0.0.1", "10.0.0.254"})
        self.assertTrue(any(lvl == "bad" and "second DHCP server" in text for _t, lvl, text in s["events"]))

    def test_arp_conflict_on_the_router(self):
        self.add(arp(ROUTER, "10.0.0.1"))
        self.add(arp(OTHER, "10.0.0.1"))
        s = self.a.snapshot()
        self.assertTrue(any(lvl == "bad" and "router's address" in text for _t, lvl, text in s["events"]))

    def test_dns_and_talkers(self):
        self.add(eth(ROUTER, ME, 0x0800, ipv4("10.0.0.9", "10.0.0.1", 17, udp(50000, 53, dns_query("example.com")))))
        self.add(eth(ME, ROUTER, 0x0800, ipv4("10.0.0.1", "10.0.0.9", 17,
                                              udp(53, 50000, dns_answer("example.com", "93.184.215.14")))))
        tcp = struct.pack("!HHIIBBHHH", 443, 51000, 0, 0, 0x50, 0x10, 0, 0, 0)
        self.add(eth(ME, ROUTER, 0x0800, ipv4("93.184.215.14", "10.0.0.9", 6, tcp)), wire=1500)
        self.add(eth(ROUTER, ME, 0x0800, ipv4("10.0.0.9", "93.184.215.14", 6, tcp)), wire=100)
        s = self.a.snapshot()
        self.assertEqual(s["dns"][0][1:], ("10.0.0.9", "example.com", "A"))
        top = s["talkers"][0]
        self.assertEqual(top[:3], ("93.184.215.14", 1500, 100))
        self.assertEqual((top[4], top[5]), ("HTTPS", "example.com"))

    def test_broadcast_storm(self):
        frame = eth(BCAST, OTHER, 0x0806, b"\x00" * 28)
        for second in range(5):
            for _ in range(350):
                self.a.add(2_000_000.0 + second + 0.001, frame, 60)
        self.a.add(2_000_010.0, frame, 60)
        s = self.a.snapshot()
        self.assertTrue(any("Broadcast storm" in text for _t, _l, text in s["events"]))
        self.assertEqual(max(r[3] for r in s["rates"]), 350)


class Pcap(unittest.TestCase):
    def test_round_trip_in_pieces(self):
        records = [(1000.5, lldp_frame(), len(lldp_frame())), (1001.25, cdp_frame(), 1400)]
        data = pcap_bytes(records)
        reader, got = PcapReader(), []
        for i in range(0, len(data), 7):
            got += reader.feed(data[i:i + 7])
        self.assertEqual([(round(t, 2), f, w) for t, f, w in got], [(1000.5, records[0][1], records[0][2]),
                                                                    (1001.25, records[1][1], 1400)])

    def test_big_endian(self):
        frame = lldp_frame()
        data = (struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                + struct.pack(">IIII", 5, 0, len(frame), len(frame)) + frame)
        self.assertEqual(PcapReader().feed(data)[0][1], frame)

    def test_not_pcap(self):
        with self.assertRaises(ValueError):
            PcapReader().feed(b"<html>not a capture</html>")

    def test_helper_trims_but_keeps_what_we_decode(self):
        big = eth(ROUTER, ME, 0x0800, ipv4("10.0.0.9", "1.1.1.1", 6, b"\x00" * 1400))
        self.assertEqual(capture_helper.keep_length(big), capture_helper.TRIM)
        dns = eth(ROUTER, ME, 0x0800, ipv4("10.0.0.9", "10.0.0.1", 17, udp(5000, 53, b"x" * 400)))
        self.assertEqual(capture_helper.keep_length(dns), len(dns))
        self.assertEqual(capture_helper.keep_length(lldp_frame() + b"\x00" * 300), len(lldp_frame()) + 300)
        rec = capture_helper.pcap_record(big, 12.5)
        self.assertEqual(struct.unpack("<IIII", rec[:16]), (12, 500000, capture_helper.TRIM, len(big)))

    def test_capture_command(self):
        net = {"iface": "eth0", "local_ip": "10.0.0.9"}
        argv, prompt = capture_argv(net, ["/usr/bin/pkexec"], python="/usr/bin/python3")
        if sys.platform.startswith("linux") and os.geteuid() != 0:
            self.assertEqual(argv, ["/usr/bin/pkexec", "/usr/bin/python3", HELPER, "eth0"])
            self.assertTrue(prompt)


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("unshare"), "Linux user namespaces only")
class RealCapture(unittest.TestCase):
    def test_capture_in_a_user_namespace(self):
        """The real helper, reading real packets, with the real Capture reader, on the namespace's loopback."""
        script = f"""
import socket, sys, time
sys.path.insert(0, {_support.ROOT!r})
from netscan_app.traffic import Analyzer, Capture, capture_argv
import subprocess
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
argv, prompt = capture_argv({{"iface": "lo", "local_ip": "127.0.0.1"}})
assert not prompt, argv
cap = Capture(argv, Analyzer(local_ips=["127.0.0.1"]))
time.sleep(0.8)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
q = b"\\x00\\x07\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01"
for _ in range(3):
    s.sendto(q, ("127.0.0.1", 53))
time.sleep(1.5)
snap = cap.analyzer.snapshot()
cap.stop()
cap.thread.join(3)
print("DNS", len(snap["dns"]), "PKTS", snap["packets"], "KEPT", len(cap.kept), "ALIVE", cap.proc.poll() is None)
"""
        try:
            out = subprocess.run(["unshare", "-rn", sys.executable, "-c", script], capture_output=True, text=True,
                                 timeout=30)
        except subprocess.TimeoutExpired:
            self.fail("capture didn't stop when its pipe was closed")
        if out.returncode != 0 and "Operation not permitted" in out.stderr and "unshare" in out.stderr:
            self.skipTest("user namespaces are disabled here")
        self.assertEqual(out.returncode, 0, out.stderr)
        words = out.stdout.split()
        self.assertGreaterEqual(int(words[words.index("DNS") + 1]), 3)
        self.assertGreaterEqual(int(words[words.index("PKTS") + 1]), 3)
        self.assertEqual(words[words.index("ALIVE") + 1], "False")


if __name__ == "__main__":
    unittest.main()
