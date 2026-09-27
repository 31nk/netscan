"""Tools and the pure logic behind the Internet tab, Domain toolkit, DNS speed and vulnerability check."""

import datetime
import http.server
import threading
import unittest
from unittest import mock

import _support  # noqa: F401

from netscan_app import vulns
from netscan_app.cli import cli_table
from netscan_app.internet import _speed_phase, bloat_grade, latency_stats
from netscan_app.probes import dns_verdict, email_verdicts
from netscan_app.tools import channel_advice, mac_info, subnet_info


class Subnets(unittest.TestCase):
    def test_ipv4(self):
        rows = dict(subnet_info("192.168.1.77/24"))
        self.assertEqual(rows["Address"], "192.168.1.77")
        self.assertEqual(rows["Network"], "192.168.1.0/24")
        self.assertEqual((rows["First usable"], rows["Last usable"]), ("192.168.1.1", "192.168.1.254"))
        self.assertEqual(rows["Usable addresses"], "254")
        self.assertEqual(rows["Type"], "private")

    def test_point_to_point_and_ipv6(self):
        self.assertEqual(dict(subnet_info("10.0.0.0/31"))["Usable addresses"], "2")
        rows = dict(subnet_info("2001:db8::/64"))
        self.assertEqual(rows["First"], "2001:db8::")
        self.assertNotIn("Address", rows)

    def test_bad_input(self):
        with self.assertRaises(ValueError):
            subnet_info("300.1.1.1/24")


class Macs(unittest.TestCase):
    def test_private_and_multicast(self):
        rows = dict(mac_info("DA:A1:19:00:00:01"))
        self.assertIn("private", rows["Manufacturer"])
        self.assertEqual(dict(mac_info("01:00:5e:00:00:fb"))["Kind"], "multicast/group address")
        with self.assertRaises(ValueError):
            mac_info("hello")


class WiFi(unittest.TestCase):
    def test_own_router_networks_dont_count(self):
        net = lambda ssid, bssid, ch, active=False, band="2.4 GHz": {"ssid": ssid, "bssid": bssid, "channel": ch,
                                                                    "active": active, "band": band}
        nets = [net("Home", "a0:11:22:33:44:01", 6, active=True),
                net("Home-guest", "a2:11:22:33:44:02", 6),       # same router, other network
                net("Neighbour", "b0:01:02:03:04:01", 1),
                net("Neighbour-5G", "b0:01:02:03:04:02", 36, band="5 GHz"),
                net("Other", "c0:05:06:07:08:01", 1)]
        advice = channel_advice(nets)
        self.assertEqual(advice["2.4 GHz"]["counts"], {1: 2})
        self.assertEqual((advice["2.4 GHz"]["yours"], advice["2.4 GHz"]["best"]), (6, 6))
        self.assertEqual(advice["5 GHz"]["best"], 36)


class Email(unittest.TestCase):
    BASE = {"mx": [(10, "mx.example.com")], "spf": ["v=spf1 include:_spf.example.com -all"],
            "dmarc": ["v=DMARC1; p=reject"], "dkim": ["google"]}

    def levels(self, **changes):
        return [level for level, _text in email_verdicts({**self.BASE, **changes})]

    def test_good_setup(self):
        self.assertEqual(self.levels(), ["good", "good", "good"])

    def test_missing_records(self):
        self.assertEqual(self.levels(spf=[], dmarc=[], dkim=[]), ["warn", "warn", "info"])

    def test_monitor_only_dmarc(self):
        self.assertIn("warn", self.levels(dmarc=["v=DMARC1; p=none"]))

    def test_no_mail_domain(self):
        v = email_verdicts({"mx": [], "null_mx": True, "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"],
                            "dkim": [], "dkim_null": True})
        self.assertIn("Null MX", v[0][1])
        self.assertIn("sends no email", v[-1][1])

    def test_spf_redirect_and_expiry(self):
        soon = (datetime.date.today() + datetime.timedelta(days=10)).isoformat()
        v = email_verdicts({**self.BASE, "spf": ["v=spf1 redirect=_spf.google.com"], "rdap": {"expires": soon}})
        self.assertIn("hands off", v[0][1])
        self.assertIn("expires in 10 day(s)", v[-1][1])


class DnsSpeed(unittest.TestCase):
    def row(self, name, cached, uncached):
        return {"name": name, "cached": cached, "uncached": uncached}

    def test_slow_recursive_resolver(self):
        text = dns_verdict([self.row("Your DNS (10.0.0.1)", 0.4, 120), self.row("Quad9 9.9.9.9", 20, 28)])
        self.assertIn("under 1 ms", text)
        self.assertIn("Unbound", text)

    def test_fine(self):
        text = dns_verdict([self.row("Your DNS (10.0.0.1)", 5, 30), self.row("Quad9 9.9.9.9", 20, 28)])
        self.assertIn("No need to change", text)

    def test_not_enough(self):
        self.assertEqual(dns_verdict([self.row("Quad9", 1, 2)]), "Not enough answers to compare.")


class Vulnerabilities(unittest.TestCase):
    def test_cpe23(self):
        self.assertEqual(vulns.cpe23("cpe:/a:openbsd:openssh:10.0p2"), "cpe:2.3:a:openbsd:openssh:10.0:*:*:*:*:*:*:*")
        self.assertEqual(vulns.cpe23("cpe:/a:matt_johnston:dropbear_ssh_server:2022.83"),
                         "cpe:2.3:a:matt_johnston:dropbear_ssh_server:2022.83:*:*:*:*:*:*:*")
        for no_version in ("cpe:/o:linux:linux_kernel", "cpe:/a:apache:http_server", "cpe:/a:x:y:beta"):
            self.assertIsNone(vulns.cpe23(no_version))

    def test_lookup_parses_sorts_and_caches(self):
        answer = {"vulnerabilities": [
            {"cve": {"id": "CVE-1", "published": "2024-01-02T00:00", "descriptions": [{"lang": "en", "value": "low"}],
                     "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.1, "baseSeverity": "LOW"}}]}}},
            {"cve": {"id": "CVE-2", "descriptions": [{"lang": "en", "value": "bad"}],
                     "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 9.8}, "baseSeverity": "HIGH"}]}}}]}
        name = "cpe:2.3:a:test:thing:1.0:*:*:*:*:*:*:*"
        with mock.patch.object(vulns, "_nvd_get", return_value=answer) as get:
            found = vulns.nvd_lookup(name)
            self.assertEqual([(v["id"], v["severity"]) for v in found], [("CVE-2", "HIGH"), ("CVE-1", "LOW")])
            self.assertEqual(vulns.nvd_lookup(name), found)  # second time from the cache
            self.assertEqual(get.call_count, 1)

    def test_unknown_product_is_none_not_all_clear(self):
        with mock.patch.object(vulns, "_nvd_get", return_value={"vulnerabilities": [], "totalResults": 0}):
            self.assertIsNone(vulns.nvd_lookup("cpe:2.3:a:nobody:nothing:1.0:*:*:*:*:*:*:*"))

    def test_host_vulnerabilities(self):
        ports = [{"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 10.0p2",
                  "cpe": ["cpe:/a:openbsd:openssh:10.0p2", "cpe:/o:linux:linux_kernel"]},
                 {"port": 80, "proto": "tcp", "service": "http", "version": "", "cpe": []}]
        self.assertEqual(vulns.versioned_cpes(ports), ["cpe:/a:openbsd:openssh:10.0p2"])
        with mock.patch.object(vulns, "nvd_lookup", return_value=[]) as lookup:
            found = vulns.host_vulnerabilities(ports)
        lookup.assert_called_once_with("cpe:2.3:a:openbsd:openssh:10.0:*:*:*:*:*:*:*")
        self.assertEqual(list(found), ["22/ssh"])


class Measurements(unittest.TestCase):
    def test_latency_stats(self):
        s = latency_stats([(0, 10.0), (1, None), (2, 20.0), (3, 12.0)])
        self.assertEqual((s["min"], s["max"], s["loss"], s["count"], s["last"]), (10.0, 20.0, 25.0, 4, 12.0))
        self.assertAlmostEqual(s["avg"], 14.0)
        self.assertAlmostEqual(s["jitter"], 9.0)
        self.assertIsNone(latency_stats([])["avg"])

    def test_bloat_grade(self):
        self.assertEqual([bloat_grade(ms) for ms in (2, 20, 50, 150, 300, 900)], ["A+", "A", "B", "C", "D", "F"])

    def test_cli_table(self):
        self.assertEqual(cli_table([["10.0.0.1", "router"]], ["IP", "NAME"]).splitlines(),
                         ["IP        NAME", "--------  ------", "10.0.0.1  router"])


class _Blob(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(1 << 20))
        self.end_headers()
        try:
            self.wfile.write(b"\0" * (1 << 20))
        except (BrokenPipeError, ConnectionResetError):
            pass  # the measurement stops reading once its time is up

    def log_message(self, *args):
        pass


class SpeedPhase(unittest.TestCase):
    """The multi-connection measurement, against a local web server instead of the internet."""

    def test_measures_a_local_server(self):
        import urllib.request
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Blob)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_address[1]}/"

        def download(add):
            with urllib.request.urlopen(url, timeout=5) as r:
                while chunk := r.read(65536):
                    if not add(len(chunk)):
                        return False
            return True

        try:
            mbps, total = _speed_phase(download, streams=2, seconds=1.0, cap=40 << 20, warmup=0.2)
        finally:
            server.shutdown()
            server.server_close()
        self.assertGreater(total, 1 << 20)
        self.assertGreater(mbps, 1)

    def test_nothing_through_is_an_error(self):
        def refused(_add):
            raise ConnectionRefusedError
        with self.assertRaises(OSError):
            _speed_phase(refused, streams=1, seconds=0.3)


if __name__ == "__main__":
    unittest.main()
