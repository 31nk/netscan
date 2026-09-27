"""The checkup verdicts: slow internet, security grade, double NAT / CGNAT, DHCP servers, Wi-Fi survey,
who's home, and portable mode's folders. No network: measurements are made up."""

import datetime
import os
import unittest
from unittest import mock

import _support

from netscan_app import devices
from netscan_app.checks import (
    diagnosis, dhcp_verdict, nat_verdict, parse_dhcp_discover, presence_rows, security_checkup, survey_verdict,
    wifi_security_issue,
)


def pings(avg, loss=0.0, jitter=0.5):
    return {"avg": avg, "loss": loss, "jitter": jitter, "count": 10, "last": avg, "min": avg, "max": avg}


def healthy(**over):
    m = {"iface": "eth0", "gateway": "192.168.1.1", "wireless": False, "router": pings(1.0), "cf": pings(12.0),
         "google": pings(14.0), "dns_ok": True, "dns_ms": 30.0, "first_hop": "192.168.1.1", "errors": []}
    m.update(over)
    return m


class Diagnosis(unittest.TestCase):
    def test_healthy(self):
        d = diagnosis(healthy())
        self.assertEqual(d["level"], "good")
        self.assertEqual(d["findings"][0][1], "Everything looks healthy")

    def test_weak_wifi_is_the_problem(self):
        wifi = {"ssid": "Home", "signal": 25, "band": "5 GHz", "channel": 44, "crowd": 0, "best": 36}
        d = diagnosis(healthy(wireless=True, wifi=wifi, router=pings(45.0, loss=10.0, jitter=30)))
        self.assertEqual(d["where"], "wifi")
        self.assertIn("Wi-Fi", d["headline"])

    def test_crowded_24ghz_channel(self):
        wifi = {"ssid": "Home", "signal": 80, "band": "2.4 GHz", "channel": 6, "crowd": 5, "best": 1}
        d = diagnosis(healthy(wireless=True, wifi=wifi))
        self.assertTrue(any("Channel 1" in detail for _l, _t, detail in d["findings"]))

    def test_router_silent(self):
        d = diagnosis(healthy(router=pings(None, loss=100.0)))
        self.assertEqual(d["where"], "router")

    def test_provider_outage(self):
        d = diagnosis(healthy(cf=pings(None, loss=100.0), google=pings(None, loss=100.0)))
        self.assertEqual(d["where"], "provider")
        self.assertIn("internet provider", d["headline"])

    def test_loss_past_the_router(self):
        d = diagnosis(healthy(cf=pings(20.0, loss=20.0), google=pings(22.0, loss=30.0)))
        self.assertEqual((d["level"], d["where"]), ("bad", "provider"))

    def test_one_good_public_server_is_enough(self):
        self.assertEqual(diagnosis(healthy(cf=pings(None, loss=100.0)))["level"], "good")

    def test_dns_broken(self):
        d = diagnosis(healthy(dns_ok=False))
        self.assertEqual(d["where"], "dns")

    def test_recursive_dns_is_only_info(self):
        d = diagnosis(healthy(dns_ms=210.0))
        self.assertEqual(d["level"], "good")
        self.assertEqual(diagnosis(healthy(dns_ms=450.0))["where"], "dns")

    def test_bufferbloat_and_plan(self):
        speed = {"down": 180.0, "up": 20.0, "grade": "D", "added_ms": 250.0}
        d = diagnosis(healthy(), speed, {"down": 500, "up": 50})
        titles = " ".join(t for _l, t, _d in d["findings"])
        self.assertIn("bufferbloat grade D", titles)
        self.assertIn("36% of your plan", titles)

    def test_vpn_named_in_verdict(self):
        d = diagnosis(healthy(first_hop="10.128.0.1", cf=pings(None, loss=100.0), google=pings(None, loss=100.0)))
        self.assertIn("VPN", d["headline"])
        self.assertTrue(any(t == "Measured through a VPN" for _l, t, _d in d["findings"]))


class Nat(unittest.TestCase):
    def verdict(self, **m):
        return nat_verdict({"gateway": "192.168.1.1", "public_ip": "203.0.113.5", "router_wan": None, "hops": [], **m})

    def test_from_router_wan(self):
        self.assertEqual(self.verdict(router_wan="203.0.113.5")["kind"], "direct")
        self.assertEqual(self.verdict(router_wan="100.72.1.9")["kind"], "cgnat")
        self.assertEqual(self.verdict(router_wan="192.168.0.20")["kind"], "double")
        self.assertEqual(self.verdict(router_wan="198.51.100.7")["kind"], "vpn")

    def test_from_route(self):
        self.assertEqual(self.verdict(hops=["192.168.1.1", "192.168.0.1", "198.51.100.1"])["kind"], "double")
        self.assertEqual(self.verdict(hops=["192.168.1.1", "100.64.0.1", "198.51.100.1"])["kind"], "cgnat")
        self.assertEqual(self.verdict(hops=["192.168.1.1", "198.51.100.1", "1.1.1.1"])["kind"], "direct")
        self.assertEqual(self.verdict(hops=["192.168.1.1", None, None])["kind"], "unknown")

    def test_vpn_route_says_nothing(self):
        v = self.verdict(hops=["10.128.0.1", "68.235.46.1", "1.1.1.1"])
        self.assertEqual(v["kind"], "unknown")
        self.assertIn("VPN", v["findings"][0][1])


DHCP_OUT = """Starting Nmap 7.95
Pre-scan script results:
| broadcast-dhcp-discover:
|   Response 1 of 2:
|     Interface: eth0
|     IP Offered: 192.168.1.114
|     DHCP Message Type: DHCPOFFER
|     Server Identifier: 192.168.1.1
|     IP Address Lease Time: 1d00h00m00s
|     Subnet Mask: 255.255.255.0
|     Router: 192.168.1.1
|     Domain Name Server: 192.168.1.1
|   Response 2 of 2:
|     Interface: eth0
|     IP Offered: 192.168.0.50
|     Server Identifier: 192.168.0.1
|     Router: 192.168.0.1
|_    Domain Name Server: 8.8.8.8
Nmap done: 0 IP addresses (0 hosts up) scanned in 6.10 seconds
"""


class Dhcp(unittest.TestCase):
    def test_parse(self):
        servers = parse_dhcp_discover(DHCP_OUT)
        self.assertEqual([s["server"] for s in servers], ["192.168.1.1", "192.168.0.1"])
        self.assertEqual(servers[0]["offered"], "192.168.1.114")
        self.assertEqual(servers[1]["dns"], "8.8.8.8")
        self.assertEqual(parse_dhcp_discover("Nmap done"), [])

    def test_verdicts(self):
        servers = parse_dhcp_discover(DHCP_OUT)
        self.assertEqual(dhcp_verdict(servers, "192.168.1.1")[0][0], "bad")
        self.assertEqual(dhcp_verdict(servers[:1], "192.168.1.1")[0][0], "good")
        self.assertEqual(dhcp_verdict(servers[:1], "192.168.1.254")[0][0], "info")
        self.assertEqual(dhcp_verdict([], "192.168.1.1")[0][0], "info")


class Security(unittest.TestCase):
    def test_wifi_protection(self):
        issue = lambda sec, cipher="": (wifi_security_issue({"security": sec, "cipher": cipher}) or ("ok",))[0]
        self.assertEqual(issue("open"), "critical")
        self.assertEqual(issue("Open"), "critical")
        self.assertEqual(issue("WEP"), "critical")
        self.assertEqual(issue("WPA1"), "high")
        self.assertEqual(issue("WPA2", "pair_tkip group_tkip psk"), "high")
        self.assertEqual(issue("WPA1 WPA2", "pair_tkip pair_ccmp group_tkip psk"), "low")
        self.assertEqual(issue("WPA2", "(none) pair_ccmp group_ccmp psk"), "ok")
        self.assertEqual(issue("WPA2-Personal", "CCMP"), "ok")
        self.assertEqual(issue("WPA3 Personal"), "ok")

    def test_clean_network_scores_high(self):
        hosts = [{"ip": "192.168.1.1", "ports": [{"port": 443, "proto": "tcp"}], "trusted": True, "router": True},
                 {"ip": "192.168.1.5", "name": "laptop", "ports": [], "trusted": True}]
        res = security_checkup({"hosts": hosts, "any_trusted": True, "dns_hijack": False,
                                "wifi": {"ssid": "Home", "security": "WPA2", "cipher": "pair_ccmp"},
                                "upnp": {"mappings": []}})
        self.assertEqual((res["score"], res["grade"]), (100, "A"))

    def test_problems_cost_points(self):
        hosts = [{"ip": "192.168.1.1", "ports": [{"port": 23, "proto": "tcp"}], "trusted": True, "router": True},
                 {"ip": "192.168.1.9", "name": "cam", "ports": [{"port": 554, "proto": "tcp"}], "trusted": False}]
        upnp = {"mappings": [{"external_port": 3389, "protocol": "tcp", "client": "192.168.1.20", "enabled": True},
                             {"external_port": 41641, "protocol": "udp", "client": "192.168.1.5", "enabled": True,
                              "description": "Tailscale"}]}
        res = security_checkup({"hosts": hosts, "any_trusted": True, "upnp": upnp, "dns_hijack": True,
                                "wifi": {"ssid": "Home", "security": "WPA1"},
                                "spoof": [("high", "router MAC changed")]})
        severities = [s for s, _t, _d in res["findings"]]
        self.assertEqual(severities[0], "critical")  # worst first
        self.assertIn("high", severities)
        self.assertEqual(res["score"], max(0, 100 - 25 - 15 - 8 - 15 - 3 - 15 - 3))
        self.assertEqual(res["grade"], "F")

    def test_hints_when_nothing_scanned(self):
        res = security_checkup({})
        self.assertEqual(res["score"], 100)
        self.assertTrue(any("No devices scanned" in t for _s, t, _d in res["findings"]))
        res = security_checkup({"hosts": [{"ip": "10.0.0.2", "ports": None}]})
        self.assertTrue(any("Ports weren't scanned" in t for _s, t, _d in res["findings"]))


class SurveyAndPresence(unittest.TestCase):
    def test_survey_verdicts(self):
        self.assertEqual(survey_verdict(85), ("good", "great"))
        self.assertEqual(survey_verdict(55)[0], "good")
        self.assertEqual(survey_verdict(40)[0], "warn")
        self.assertEqual(survey_verdict(20)[0], "bad")
        self.assertEqual(survey_verdict(None)[0], "info")

    def test_presence_rows(self):
        now = datetime.datetime(2026, 9, 27, 18, 30)
        hour = lambda h: f"2026-09-27T{h:02d}"
        devs = {"AA": {"nickname": "Sam's phone", "hours": [hour(9), hour(17), hour(18)], "last_seen": "x"},
                "BB": {"hostname": "tv", "hours": [hour(10)], "last_seen": "2026-09-27T10:05:00"},
                "CC": {"hostname": "old", "hours": ["2026-09-20T10"]}}
        checked = [hour(h) for h in range(8, 19)]
        rows = presence_rows(devs, checked, hours=24, now=now)
        self.assertEqual([r["name"] for r in rows], ["Sam's phone", "tv"])  # CC wasn't seen in the window
        self.assertTrue(rows[0]["home_now"])
        self.assertFalse(rows[1]["home_now"])
        cells = rows[1]["cells"]
        self.assertEqual(len(cells), 24)
        self.assertEqual(cells[-1 - 8], "seen")   # 10:00 is 8 hours before 18:00
        self.assertEqual(cells[-1], "away")       # checked at 18:00, not seen
        self.assertEqual(cells[0], "")            # 19:00 yesterday: not checked
        only = presence_rows(devs, checked, hours=24, now=now, only=lambda _mac, d: "nickname" in d)
        self.assertEqual(len(only), 1)


class Portable(unittest.TestCase):
    def test_env_folder_wins(self):
        self.assertEqual(devices.portable_dir(), os.environ["NETSCAN_DATA"])
        self.assertEqual(devices.data_dir(), os.environ["NETSCAN_DATA"])

    def test_computer_folder_is_netscans_own(self):
        from PySide6.QtCore import QCoreApplication, QStandardPaths
        QCoreApplication.setApplicationName("")
        with mock.patch.object(devices, "QStandardPaths", QStandardPaths):
            self.assertEqual(os.path.basename(devices.computer_data_dir()), "NetScan")

    def test_never_copies_a_folder_that_isnt_netscans(self):
        other = os.path.join(_support.TMP, "share")
        os.makedirs(os.path.join(other, "someone-elses-app"))
        target = os.path.join(_support.TMP, "stick2", "NetScan-data")
        with mock.patch.object(devices, "PORTABLE_DIR", target), \
                mock.patch.object(devices, "computer_data_dir", lambda: other), \
                mock.patch.object(devices, "QSettings", _PortableSettings):
            devices.make_portable()
        self.assertEqual(os.listdir(target), ["settings.ini"])

    def test_make_portable_copies_data_and_settings(self):
        home = os.path.join(_support.TMP, "NetScan")
        os.makedirs(os.path.join(home, "venv"))
        with open(os.path.join(home, "devices.json"), "w") as f:
            f.write("{}")
        target = os.path.join(_support.TMP, "stick", "NetScan-data")
        native = _support.settings()
        native.setValue("theme", "dark")
        native.sync()
        with mock.patch.object(devices, "PORTABLE_DIR", target), \
                mock.patch.object(devices, "computer_data_dir", lambda: home), \
                mock.patch.object(devices, "QSettings", _PortableSettings):
            folder, created = devices.make_portable()
            self.assertTrue(created)
            self.assertEqual(folder, target)
            self.assertTrue(os.path.exists(os.path.join(target, "devices.json")))
            self.assertFalse(os.path.exists(os.path.join(target, "venv")))  # the Linux installer's Python stays
            self.assertEqual(_PortableSettings(os.path.join(target, "settings.ini"), 1).value("theme"), "dark")
            self.assertEqual(devices.make_portable(), (target, False))
            with mock.patch.dict(os.environ, {"NETSCAN_DATA": ""}):
                self.assertEqual(devices.portable_dir(), target)


class _PortableSettings:
    """QSettings stand-in: ("netscan", "netscan") is the test's settings file, a path is its own INI file."""

    IniFormat = 1

    def __new__(cls, *args):
        from PySide6.QtCore import QSettings
        if args == ("netscan", "netscan"):
            return _support.settings()
        return QSettings(args[0], QSettings.IniFormat)


if __name__ == "__main__":
    unittest.main()
