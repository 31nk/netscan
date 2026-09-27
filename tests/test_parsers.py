"""Parsing what the OS and nmap print."""

import unittest
import xml.etree.ElementTree as ET

import _support  # noqa: F401

from netscan_app.scanning import (compare_scans, merge_ports, parse_host, parse_mac, parse_ports, port_set,
                                  summarize_ports, valid_port_list, valid_ssh_user)
from netscan_app.system import arp_macs, local_open_ports, parse_lsof, parse_netstat_mac, parse_ss

NMAP_HOST = """<host><status state="up"/>
<address addr="192.168.1.20" addrtype="ipv4"/>
<address addr="dc:a6:32:01:02:03" addrtype="mac" vendor="Raspberry Pi Trading"/>
<hostnames><hostname name="pi.lan" type="PTR"/></hostnames>
<ports>
 <port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="10.0p2" extrainfo="Debian 7">
   <cpe>cpe:/a:openbsd:openssh:10.0p2</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
 <port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
 <port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>
</ports></host>"""


class NmapXml(unittest.TestCase):
    def test_host(self):
        h = parse_host(ET.fromstring(NMAP_HOST))
        self.assertEqual(h, {"ip": "192.168.1.20", "hostname": "pi.lan", "mac": "DC:A6:32:01:02:03",
                             "vendor": "Raspberry Pi Trading"})

    def test_down_host_is_skipped(self):
        self.assertIsNone(parse_host(ET.fromstring('<host><status state="down"/></host>')))

    def test_ports_only_open_with_version_and_cpe(self):
        ports = parse_ports(ET.fromstring(NMAP_HOST))
        self.assertEqual([(p["proto"], p["port"]) for p in ports], [("tcp", 22), ("udp", 53)])
        self.assertEqual(ports[0]["version"], "OpenSSH 10.0p2 Debian 7")
        self.assertEqual(ports[0]["cpe"], ["cpe:/a:openbsd:openssh:10.0p2", "cpe:/o:linux:linux_kernel"])
        self.assertEqual(ports[1]["cpe"], [])
        self.assertEqual(summarize_ports(ports), "22/ssh, 53/domain (udp)")
        self.assertEqual(summarize_ports([]), "none open")
        self.assertEqual(summarize_ports(None), "")


class PortLists(unittest.TestCase):
    def test_valid_port_list(self):
        self.assertTrue(valid_port_list("22,80,8000-8100"))
        for bad in ("", "22,", "0", "70000", "22;rm", "a-b"):
            self.assertFalse(valid_port_list(bad), bad)

    def test_port_set(self):
        self.assertEqual(port_set("22,80,100-102"), {22, 80, 100, 101, 102})

    def test_merge_keeps_unscanned(self):
        old = [{"port": 22, "proto": "tcp"}, {"port": 8080, "proto": "tcp"}, {"port": 53, "proto": "udp"}]
        new = [{"port": 443, "proto": "tcp"}]
        merged = merge_ports(old, new, {"tcp": {22, 443}, "udp": set()})
        self.assertEqual([(p["proto"], p["port"]) for p in merged], [("tcp", 443), ("tcp", 8080), ("udp", 53)])


class CompareScans(unittest.TestCase):
    def test_moved_new_gone_and_port_changes(self):
        p = lambda n, s: {"port": n, "proto": "tcp", "service": s}
        baseline = [{"ip": "10.0.0.5", "mac": "AA:00:00:00:00:01", "ports": [p(22, "ssh")]},
                    {"ip": "10.0.0.9", "mac": "", "ports": None},
                    {"ip": "10.0.0.7", "mac": "AA:00:00:00:00:07"}]
        hosts = {"10.0.0.6": {"ip": "10.0.0.6", "mac": "AA:00:00:00:00:01"},
                 "10.0.0.9": {"ip": "10.0.0.9", "mac": ""},
                 "10.0.0.8": {"ip": "10.0.0.8", "mac": "AA:00:00:00:00:08"}}
        changes, gone = compare_scans(baseline, hosts, {"10.0.0.6": [p(80, "http")]})
        self.assertEqual(changes["10.0.0.6"], "was 10.0.0.5, +80/http, −22/ssh")
        self.assertEqual(changes["10.0.0.9"], "")
        self.assertEqual(changes["10.0.0.8"], "NEW")
        self.assertEqual([h["ip"] for h in gone], ["10.0.0.7"])


class TextInput(unittest.TestCase):
    def test_parse_mac(self):
        for text in ("aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "MAC is aa:bb:cc:dd:ee:ff here"):
            self.assertEqual(parse_mac(text), "AA:BB:CC:DD:EE:FF", text)
        self.assertIsNone(parse_mac("not a mac"))

    def test_ssh_user(self):
        self.assertTrue(valid_ssh_user("pi"))
        for bad in ("-oProxyCommand=x", "a b", "root@host", "x;y", ""):
            self.assertFalse(valid_ssh_user(bad), bad)


class Listeners(unittest.TestCase):
    def test_ss(self):
        out = ('tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=411,fd=3))\n'
               'tcp ESTAB 0 0 10.0.0.2:5000 10.0.0.3:443\n'
               'udp UNCONN 0 0 [fe80::1%wlan0]:5353 [::]:*\n'
               'tcp LISTEN 0 4096 [::1]:631 [::]:*\n')
        got = parse_ss(out)
        self.assertEqual([(l["proto"], l["address"], l["port"], l["process"], l["pid"]) for l in got],
                         [("tcp", "0.0.0.0", 22, "sshd", 411), ("udp", "fe80::1", 5353, "", None),
                          ("tcp", "::1", 631, "", None)])

    def test_lsof(self):
        out = "p120\ncrapportd\nPTCP\nn*:7000\nPTCP\nn10.0.0.2:5000->1.2.3.4:443\np130\ncmDNSResponder\nPUDP\nn*:5353\n"
        got = parse_lsof(out)
        self.assertEqual([(l["proto"], l["port"], l["process"], l["pid"]) for l in got],
                         [("tcp", 7000, "rapportd", 120), ("udp", 5353, "mDNSResponder", 130)])

    def test_netstat_mac(self):
        out = ("tcp4 0 0 *.22 *.* LISTEN\ntcp4 0 0 10.0.0.2.5000 1.2.3.4.443 ESTABLISHED\n"
               "udp4 0 0 *.5353 *.*\nudp4 0 0 10.0.0.2.6000 1.1.1.1.53\n")
        self.assertEqual([(l["proto"], l["port"]) for l in parse_netstat_mac(out)], [("tcp", 22), ("udp", 5353)])

    def test_arp(self):
        out = "? (192.168.1.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]\n? (192.168.1.9) at (incomplete) on en0\n"
        self.assertEqual(arp_macs(out), {"192.168.1.1": "A4:2B:B0:01:02:03"})

    def test_local_open_ports(self):
        listeners = [{"proto": "tcp", "address": "127.0.0.1", "port": 631, "process": "cupsd", "pid": 1},
                     {"proto": "tcp", "address": "0.0.0.0", "port": 22, "process": "sshd", "pid": 2},
                     {"proto": "tcp", "address": "::", "port": 22, "process": "sshd", "pid": 2},
                     {"proto": "udp", "address": "0.0.0.0", "port": 51234, "process": "app", "pid": 3}]
        ports = {(p["proto"], p["port"]): p for p in local_open_ports(listeners)}
        self.assertTrue(ports[("tcp", 631)]["local_only"])
        self.assertFalse(ports[("tcp", 22)]["local_only"])
        self.assertEqual(ports[("tcp", 22)]["program"], "sshd")
        self.assertTrue(ports[("udp", 51234)]["temporary"])
        self.assertEqual(list(ports)[-1], ("udp", 51234))  # temporary sockets sort last


if __name__ == "__main__":
    unittest.main()
