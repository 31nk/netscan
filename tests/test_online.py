"""Outside-in checks with made-up answers: blocklists, Shodan exposure, VPN/DNS leaks, gaming verdicts,
service discovery, the outage log and the ISP report. No network."""

import ipaddress
import os
import socket
import time
import unittest
from unittest import mock

import _support

from netscan_app import checks, history_db, online
from netscan_app.online import (
    _org_key, blocklist_status, exposure_findings, gaming_verdicts, privacy_findings, spamhaus_meaning,
)
from netscan_app.outages import OutageLog, build_isp_report, report_data, summarize

T0 = time.time() - 7200  # recent: the log forgets outages older than 90 days


class Blocklists(unittest.TestCase):
    def test_spamhaus_codes(self):
        self.assertEqual(spamhaus_meaning(["127.0.0.11"])[0], "policy")
        self.assertEqual(spamhaus_meaning(["127.0.0.11", "127.0.0.4"])[0], "listed")
        self.assertIn("spam operation", spamhaus_meaning(["127.0.0.2"])[1])

    def test_lookup_results(self):
        answers = {"zen.spamhaus.org": ["127.0.0.10"], "b.barracudacentral.org": ["127.0.0.2"],
                   "bl.spamcop.net": None, "psbl.surriel.com": ["127.255.255.254"]}

        def fake(name):
            zone = next(z for z in answers if name.endswith(z))
            if answers[zone] is None:
                raise socket.gaierror("NXDOMAIN")
            return name, [], answers[zone]

        with mock.patch.object(online.socket, "gethostbyname_ex", fake):
            got = {name: status for name, status, _m in blocklist_status("203.0.113.9")}
        self.assertEqual(got, {"Spamhaus": "policy", "Barracuda": "listed", "SpamCop": "clean", "PSBL": "unknown"})


class Exposure(unittest.TestCase):
    def test_nothing_open(self):
        f = exposure_findings({"ip": "203.0.113.9", "shodan": {"ports": [], "vulns": []}, "blocklists": []})
        self.assertEqual(f[0][0], "good")

    def test_open_port_names_the_forward(self):
        res = {"ip": "203.0.113.9", "shodan": {"ports": [3389, 51820], "vulns": ["CVE-2019-0708"]},
               "blocklists": [("Spamhaus", "listed", "malware"), ("SpamCop", "clean", "")]}
        forwards = [{"external_port": 3389, "client": "192.168.1.20", "description": "RDP"}]
        f = exposure_findings(res, vpn=False, forwards=forwards)
        rdp = next(x for x in f if "3389" in x[1])
        self.assertEqual(rdp[0], "bad")
        self.assertIn("192.168.1.20", rdp[2])
        self.assertEqual(next(x for x in f if "51820" in x[1])[0], "info")
        self.assertTrue(any("vulnerabilit" in x[1] and x[0] == "bad" for x in f))
        self.assertEqual(next(x for x in f if "Spamhaus" in x[1])[0], "warn")
        self.assertEqual(next(x for x in exposure_findings(res, vpn=True) if "Spamhaus" in x[1])[0], "info")

    def test_shodan_unreachable(self):
        f = exposure_findings({"ip": "203.0.113.9", "shodan": None, "shodan_error": "timeout", "blocklists": []})
        self.assertEqual(f[0][:2], ("info", "Couldn't ask Shodan"))


class Privacy(unittest.TestCase):
    def m(self, **over):
        base = {"first_hop": "10.64.0.1", "gateway": "192.168.1.1", "v4": "198.51.100.4", "v4_owner": "VPN Co, Inc.",
                "v6": None, "v6_owner": None, "dns": [{"ip": "10.64.0.1", "org": "VPN Co AB", "country": "SE"}]}
        base.update(over)
        return base

    def test_org_names_compare_loosely(self):
        self.assertEqual(_org_key("Tzulo, Inc."), _org_key("tzulo inc"))
        self.assertEqual(_org_key("VPN Co, Inc."), _org_key("VPN Co AB"))

    def test_clean_vpn(self):
        f, vpn = privacy_findings(self.m())
        self.assertTrue(vpn)
        self.assertFalse([x for x in f if x[0] in ("bad", "warn")])

    def test_ipv6_leak(self):
        f, _vpn = privacy_findings(self.m(v6="2001:db8::5", v6_owner="Home ISP"))
        self.assertTrue(any(x[0] == "bad" and x[1] == "IPv6 bypasses your VPN" for x in f))

    def test_dns_leak(self):
        f, _vpn = privacy_findings(self.m(dns=[{"ip": "9.9.9.9", "org": "Quad9", "country": "CH"}]))
        self.assertTrue(any(x[0] == "warn" and "DNS" in x[1] for x in f))

    def test_no_vpn(self):
        f, vpn = privacy_findings(self.m(first_hop="192.168.1.1"))
        self.assertFalse(vpn)
        self.assertEqual(f[0][1], "No VPN in use")


def stab(jitter=1.0, loss=0.0):
    return {"median": 12.0, "jitter": jitter, "loss": loss, "spikes": 0}


class Gaming(unittest.TestCase):
    regions = [("Near", {"median": 20.0, "min": 19.0, "jitter": 1.0, "failed": 0}), ("Far", None)]

    def verdicts(self, **kw):
        return {a: (lvl, why) for a, lvl, _v, why in gaming_verdicts({"stability": kw.pop("st", stab()),
                                                                      "regions": self.regions}, **kw)[0]}

    def test_all_good_with_speed(self):
        v = self.verdicts(speed={"down": 300, "up": 30, "grade": "A"})
        self.assertTrue(all(lvl == "good" for lvl, _w in v.values()))

    def test_no_speed_test_means_unknown_streaming(self):
        self.assertEqual(self.verdicts()["4K streaming"][0], "info")

    def test_jitter_and_loss_hurt(self):
        v = self.verdicts(st=stab(jitter=60, loss=5))
        self.assertEqual(v["Video calls (Zoom, Teams, FaceTime)"][0], "bad")
        self.assertEqual(v["Online games"][0], "bad")

    def test_strict_nat_is_a_soft_fail_for_games(self):
        self.assertEqual(self.verdicts(nat_kind="cgnat")["Online games"][0], "warn")

    def test_nearest_region(self):
        _v, nearest = gaming_verdicts({"stability": stab(), "regions": self.regions})
        self.assertEqual(nearest[0], "Near")


class Services(unittest.TestCase):
    def test_find_services(self):
        mdns = {"192.168.1.9": {"types": ["_ipp._tcp", "_http._tcp", "_rdlink._tcp"], "services": ["Office printer"],
                                "friendly": "", "name": "printer", "model": "HP 4100"},
                "10.8.0.2": {"types": ["_ssh._tcp"], "services": ["vpn-peer"], "friendly": "", "name": "", "model": ""},
                "192.168.1.20": {"types": ["_kdeconnect._udp"], "services": ["dec6c18b95164e78a165c4f4e8f5a8b0"],
                                 "friendly": "", "name": "laptop", "model": ""}}
        open_ports = {("192.168.1.9", 80), ("192.168.1.5", 8123)}
        titles = {("192.168.1.9", 80): "HP LaserJet", ("192.168.1.5", 8123): "Home Assistant",
                  ("192.168.1.1", 443): "401 Unauthorized"}
        with mock.patch("netscan_app.discovery.mdns_browse", lambda _ip: mdns), \
                mock.patch("netscan_app.discovery.web_title", lambda ip, port: titles[(ip, port)]), \
                mock.patch.object(checks, "_open", lambda ip, port: (ip, port) in open_ports):
            rows = checks.find_services("192.168.1.2", ["192.168.1.9", "192.168.1.5"], [("192.168.1.1", 443)],
                                        ipaddress.ip_network("192.168.1.0/24"))
        by = {(r["ip"], r["kind"]): r for r in rows}
        self.assertEqual(by[("192.168.1.1", "Web page")]["detail"], "needs a login")
        self.assertEqual(by[("192.168.1.1", "Web page")]["url"], "https://192.168.1.1/")
        self.assertEqual(by[("192.168.1.5", "Web page")]["name"], "Home Assistant")
        self.assertEqual(by[("192.168.1.5", "Web page")]["url"], "http://192.168.1.5:8123/")
        self.assertEqual(by[("192.168.1.9", "Printer (IPP)")]["name"], "Office printer")
        self.assertEqual(by[("192.168.1.20", "KDE Connect")]["name"], "laptop")  # not the random ID
        self.assertNotIn(("10.8.0.2", "SSH"), by)                                # not this network
        self.assertFalse([r for r in rows if r["kind"] in ("rdlink", "Web page (HTTPS)")])
        self.assertEqual([r["ip"] for r in rows][0], "192.168.1.1")             # sorted by address


class Outages(unittest.TestCase):
    def log(self):
        path = os.path.join(_support.TMP, "outages-test.json")
        if os.path.exists(path):
            os.remove(path)
        return OutageLog(path)

    def test_needs_two_misses_and_times_from_the_first(self):
        log = self.log()
        self.assertIsNone(log.sample(True, True, now=T0 + 1000))
        self.assertIsNone(log.sample(True, False, now=T0 + 1030))       # one miss: could be a blip
        started = log.sample(True, False, now=T0 + 1060)
        self.assertEqual(started, ("started", {"start": T0 + 1030, "kind": "internet"}))
        self.assertIsNone(log.sample(True, False, now=T0 + 1090))
        kind, o = log.sample(True, True, now=T0 + 1120)
        self.assertEqual((kind, o["start"], o["end"]), ("ended", T0 + 1030, T0 + 1120))
        self.assertEqual(OutageLog(log.path).outages, [o])          # saved

    def test_single_blip_is_not_an_outage(self):
        log = self.log()
        log.sample(True, False, now=T0 + 10)
        log.sample(True, True, now=T0 + 40)
        self.assertEqual((log.outages, log.ongoing), ([], None))

    def test_router_down_is_the_home_network(self):
        log = self.log()
        log.sample(False, False, now=T0 + 10)
        self.assertEqual(log.sample(False, False, now=T0 + 40)[1]["kind"], "home")

    def test_left_open_by_a_closed_app(self):
        log = self.log()
        log.sample(True, False, now=T0 + 10)
        log.sample(True, False, now=T0 + 40)
        again = OutageLog(log.path)
        again.resume_check()
        self.assertTrue(again.outages[0]["unknown_end"])
        self.assertIsNone(again.ongoing)

    def test_summary_counts_only_internet_outages(self):
        outs = [{"start": 100, "end": 400, "kind": "internet"}, {"start": 500, "end": 900, "kind": "home"}]
        s = summarize(outs, watched_minutes=100, since=0, until=6000)
        self.assertEqual((s["count"], s["home_count"], s["down_seconds"], s["longest"]), (1, 1, 300, 300))
        self.assertAlmostEqual(s["uptime"], 95.0)
        self.assertEqual(summarize(outs, watched_minutes=2, since=0, until=6000)["uptime"], 0.0)  # never negative

    def test_report(self):
        log = self.log()
        log.outages = [{"start": 2_000_000_000, "end": 2_000_000_300, "kind": "internet"}]
        history_db.record_many([(2_000_000_000 + 60 * i, "loss", "Internet (connection watch)", 0.0) for i in range(60)]
                               + [(2_000_000_000 + 60 * i, "latency", "Internet (connection watch)", 20.0 + i % 3)
                                  for i in range(60)]
                               + [(2_000_001_000, "down", "Test", 90.0), (2_000_001_000, "up", "Test", 10.0)])
        d = report_data(log, 1_999_999_000, 2_000_010_000, plan={"down": 300, "up": 20})
        self.assertEqual(d["summary"]["count"], 1)
        self.assertAlmostEqual(d["summary"]["uptime"], 100 * (1 - 300 / 3600))
        page = build_isp_report(d, where="<b>laptop</b>")
        self.assertIn("5 min", page)
        self.assertIn("30% of plan", page)
        self.assertIn("1 of 1 speed tests were under half", page)
        self.assertIn("&lt;b&gt;laptop", page)


if __name__ == "__main__":
    unittest.main()
