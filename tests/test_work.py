"""Client-work tools with made-up answers: firewall test, STUN, MOS, domains, mail, blocklists, DNS propagation,
inventory CSV rows and client sites. The only network use is a local test server on 127.0.0.1."""

import json
import os
import socket
import struct
import threading
import unittest
from unittest import mock

import _support

from netscan_app import work
from netscan_app.sites import HOME, Sites, visit_changes
from netscan_app.work import (
    domain_issues, firewall_findings, inventory_rows, mail_findings, mail_provider, mos_label, mos_score, parse_stun,
    propagation_summary, voip_findings,
)


class Stun(unittest.TestCase):
    def test_xor_mapped_address(self):
        ip, port = "203.0.113.7", 50000
        xport = port ^ 0x2112
        xip = bytes(b ^ m for b, m in zip(socket.inet_aton(ip), struct.pack("!I", 0x2112A442)))
        attr = struct.pack("!HH", 0x0020, 8) + b"\0\1" + struct.pack("!H", xport) + xip
        msg = struct.pack("!HHI", 0x0101, len(attr), 0x2112A442) + b"x" * 12 + attr
        self.assertEqual(parse_stun(msg), (ip, port))

    def test_plain_mapped_address(self):
        attr = struct.pack("!HH", 0x0001, 8) + b"\0\1" + struct.pack("!H", 1234) + socket.inet_aton("198.51.100.1")
        msg = struct.pack("!HHI", 0x0101, len(attr), 0x2112A442) + b"x" * 12 + attr
        self.assertEqual(parse_stun(msg), ("198.51.100.1", 1234))


def _server(reply):
    """A one-thread TCP server on 127.0.0.1 that answers every connection with `reply`."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                conn.recv(1024)
                conn.sendall(reply)

    threading.Thread(target=loop, daemon=True).start()
    return srv


class Outbound(unittest.TestCase):
    def test_open_intercepted_blocked(self):
        good = _server(b"HTTP/1.0 200 OK\r\n\r\nPort test successful!")
        proxy = _server(b"HTTP/1.0 403 Forbidden\r\n\r\nBlocked by web filter")
        try:
            self.assertEqual(work.tcp_out(good.getsockname()[1], "127.0.0.1"), "open")
            self.assertEqual(work.tcp_out(proxy.getsockname()[1], "127.0.0.1"), "intercepted")
        finally:
            good.close()
            proxy.close()
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        self.assertEqual(work.tcp_out(port, "127.0.0.1", timeout=1), "blocked")

    def res(self, blocked=(), intercepted=(), nat="friendly", dns=True):
        rows = [(c, p, w, "blocked" if p in blocked else "intercepted" if p in intercepted else "open")
                for c, p, w in work.OUTBOUND_PORTS]
        return {"tcp": rows, "udp_dns": dns, "nat": {"udp": nat != "blocked", "kind": nat,
                                                     "mapped": ("203.0.113.1", 5000)}}

    def test_findings(self):
        levels = lambda res: {t: lvl for lvl, t, _d in firewall_findings(res)}
        self.assertIn("Every outbound port tested is open", levels(self.res()))
        self.assertEqual(levels(self.res(blocked=(25,)))["Port 25 is blocked"], "info")
        self.assertEqual(levels(self.res(blocked=(443,)))["Basic web or mail ports are blocked"], "bad")
        self.assertEqual(levels(self.res(blocked=(5060,)))["Voice ports are blocked"], "warn")
        self.assertIn("Something answers in place of the real server", levels(self.res(intercepted=(8080,))))
        self.assertEqual(levels(self.res(nat="blocked"))["Outgoing UDP (STUN) is blocked"], "bad")
        self.assertIn("Symmetric NAT: calls can't connect directly", levels(self.res(nat="symmetric")))


class Voip(unittest.TestCase):
    def test_mos(self):
        self.assertGreaterEqual(mos_score(15, 0.5, 0), 4.3)
        self.assertLess(mos_score(300, 60, 5), 3.6)
        self.assertEqual(mos_label(4.4)[0], "good")
        self.assertEqual(mos_label(3.0)[0], "bad")
        self.assertGreaterEqual(mos_score(0, 0, 0), 1)
        self.assertLessEqual(mos_score(0, 0, 0), 5)

    def test_findings(self):
        res = {"stability": {"median": 20.0, "jitter": 2.0, "loss": 0.0, "spikes": 0},
               "sip": {5060: "open", 5061: "blocked"}, "nat": {"kind": "friendly"}}
        f, mos = voip_findings(res, {"grade": "D", "up": 0.5})
        titles = " | ".join(t for _l, t, _d in f)
        self.assertGreater(mos, 4)
        self.assertIn("Bufferbloat grade D", titles)
        self.assertIn("Upload is only 0.5", titles)
        self.assertIn("SIP ports 5061", titles)
        self.assertIn("SIP ALG", titles)
        dead = voip_findings({"stability": {"median": None, "jitter": None, "loss": 100.0, "spikes": 0},
                              "sip": {5060: "blocked", 5061: "blocked"}, "nat": {"kind": "blocked"}})
        self.assertIsNone(dead[1])
        self.assertEqual(dead[0][0][0], "bad")


def row(**over):
    r = {"domain": "client.com", "provider": "Microsoft 365", "m365": ("managed", "Client"), "mx": [], "spf": "v=spf1 -all",
         "spf_all": "-", "dmarc": "reject", "dkim": ["selector1"], "expires": "2030-01-01", "expires_days": 1000,
         "registrar": "", "web_ok": True, "web_status": 200, "web_error": "", "cert_days": 60, "error": ""}
    r.update(over)
    return r


class Domains(unittest.TestCase):
    def test_provider(self):
        self.assertEqual(mail_provider(["client-com.mail.protection.outlook.com"]), "Microsoft 365")
        self.assertEqual(mail_provider(["aspmx.l.google.com"]), "Google Workspace")
        self.assertEqual(mail_provider(["mx1.client.com"]), "self-hosted / other")
        self.assertEqual(mail_provider([]), "no mail")

    def test_issues(self):
        self.assertEqual(domain_issues(row()), [])
        texts = lambda **o: [t for _l, t in domain_issues(row(**o))]
        self.assertIn("no SPF", texts(spf="", spf_all=""))
        self.assertIn("SPF allows anyone", texts(spf_all="+"))
        self.assertIn("no DMARC", texts(dmarc=""))
        self.assertIn("DMARC p=none (monitor only)", texts(dmarc="none"))
        self.assertIn("domain expires in 5 days", texts(expires_days=5))
        self.assertIn("website certificate expires in 2 days", texts(cert_days=2))
        self.assertEqual(texts(provider="no mail", spf="", dmarc=""), [])  # no mail, no mail records needed

    def test_bulk_survives_a_failing_domain(self):
        def fake(domain):
            if domain == "bad.example":
                raise OSError("boom")
            return row(domain=domain)
        with mock.patch.object(work, "domain_row", fake):
            rows = work.bulk_domains(["good.example", "bad.example", "good.example"])
        self.assertEqual([r["domain"] for r in rows], ["good.example", "bad.example"])
        self.assertEqual(rows[1]["error"], "boom")


class Blocklists(unittest.TestCase):
    def test_ip_and_domain_lists(self):
        def fake(name):
            if name.endswith("zen.spamhaus.org"):
                return name, [], ["127.0.0.2"]
            if name.endswith("bl.spamcop.net"):
                return name, [], ["127.255.255.254"]
            raise socket.gaierror("NXDOMAIN")
        with mock.patch.object(work.socket, "gethostbyname_ex", fake):
            ip = {n: st for n, st, _d in work.blocklist_all("203.0.113.5")}
            dom = {n: st for n, st, _d in work.blocklist_all("client.com")}
        self.assertEqual(ip["Spamhaus ZEN"], "listed")
        self.assertEqual(ip["SpamCop"], "unknown")
        self.assertEqual(ip["Barracuda"], "clean")
        self.assertEqual(len(ip), len(work.MAIL_BLOCKLISTS))
        self.assertEqual(set(dom), {"Spamhaus DBL", "SURBL"})

    def test_mail_findings(self):
        lists = [("Spamhaus ZEN", "clean", ""), ("SpamCop", "listed", ""), ("UCEPROTECT 1", "unknown", "")]
        res = {"target": "client.com", "domain": "client.com", "port25": True, "domain_lists": [("SURBL", "listed", "")],
               "servers": [{"host": "mx.client.com", "ips": ["203.0.113.5"], "reachable": True, "starttls": False,
                            "tls": None, "cert": None, "banner": "220 mx ESMTP", "error": "",
                            "ptr": {"203.0.113.5": ("", False)}, "blocklists": {"203.0.113.5": lists}}]}
        titles = [t for _l, t, _d in mail_findings(res)]
        self.assertIn("mx.client.com doesn't offer STARTTLS", titles)
        self.assertIn("203.0.113.5 has no reverse DNS", titles)
        self.assertIn("203.0.113.5 is listed on SpamCop", titles)
        self.assertIn("client.com is listed on SURBL", titles)
        res["port25"] = False
        self.assertEqual(mail_findings(res)[0][1], "This network blocks outgoing port 25")


class Propagation(unittest.TestCase):
    def test_norm(self):
        self.assertEqual(work._norm([("A", "2.2.2.2"), ("A", "1.1.1.1"), ("CNAME", "x.")], "A"), ("1.1.1.1", "2.2.2.2"))
        self.assertEqual(work._norm([("MX", (10, "mx.a.com."))], "MX"), ("10 mx.a.com",))

    def test_summary(self):
        rows = [("A", "", ("1.1.1.1",), 5, "DNS", ""), ("B", "", ("1.1.1.1",), 5, "DNS", ""),
                ("C", "", ("9.9.9.9",), 5, "HTTPS", ""), ("D", "", None, None, "", "blocked here")]
        self.assertEqual(propagation_summary({"authoritative": None, "rows": rows}), (("1.1.1.1",), 2, 3))
        auth = {"authoritative": {"answer": ("9.9.9.9",)}, "rows": rows}
        self.assertEqual(propagation_summary(auth), (("9.9.9.9",), 1, 3))


class Inventory(unittest.TestCase):
    def test_rows(self):
        devs = {"AA:BB:CC:00:00:02": {"ip": "10.0.0.20", "hostname": "nas", "vendor": "Synology", "trusted": True,
                                      "first_seen": "2026-01-02T10:00:00", "notes": "rack\\nshelf 2"},
                "AA:BB:CC:00:00:01": {"ip": "10.0.0.3", "nickname": "Front desk PC"},
                "ip:10.0.0.100": {"ip": "10.0.0.100"}}
        rows = inventory_rows(devs, lambda _k, _d: "Computer", lambda d: "445/microsoft-ds" if d.get("hostname") else "")
        self.assertEqual([r[2] for r in rows], ["10.0.0.3", "10.0.0.20", "10.0.0.100"])  # numeric order
        self.assertEqual(rows[0][0], "Front desk PC")
        self.assertEqual(rows[1][8:11], ["445/microsoft-ds", "yes", "2026-01-02"])
        self.assertEqual(rows[2][3], "")  # no MAC for address-only devices
        self.assertEqual(len(rows[0]), len(work.INVENTORY_COLUMNS))


class ClientSites(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(_support.TMP, "sites-test.json")
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_lifecycle(self):
        s = Sites(self.path)
        self.assertEqual((s.current, s.name()), (HOME, "Home"))
        sid = s.add("Acme Dental", "aa:bb:cc:dd:ee:01", "10.1.0.0/24")
        self.assertEqual(s.find_by_router("AA:BB:CC:DD:EE:01"), sid)
        self.assertTrue(s.folder(sid).endswith(os.path.join("sites", sid)))
        self.assertIsNone(s.folder(HOME))
        self.assertEqual(s.switch(sid), "")
        self.assertNotEqual(Sites(self.path).switch(sid), "")  # remembered: the previous visit time
        s.assign_router(HOME, "AA:BB:CC:DD:EE:01")  # a router belongs to one site only
        self.assertEqual(s.find_by_router("aa:bb:cc:dd:ee:01"), HOME)
        self.assertIsNone(s.record_scan(sid, "10.1.0.0/24", ["M1", "M2"]))
        before = s.record_scan(sid, "10.1.0.0/24", ["M2", "M3"])
        self.assertEqual(visit_changes(before, ["M2", "M3"]), (["M3"], ["M1"]))
        os.makedirs(s.folder(sid), exist_ok=True)
        s.remove(sid)
        self.assertNotIn(sid, Sites(self.path).sites)
        self.assertFalse(os.path.exists(s.folder(sid)))
        s.remove(HOME)
        self.assertIn(HOME, s.sites)  # Home can't be deleted

    def test_existing_install_knows_its_router(self):
        with open(os.path.join(os.environ["NETSCAN_DATA"], "devices.json"), "w") as f:
            json.dump({"devices": {}, "gateways": {"192.168.1.0/24|192.168.1.1": {"mac": "AA:00:00:00:00:01"}}}, f)
        try:
            self.assertEqual(Sites(self.path).find_by_router("aa:00:00:00:00:01"), HOME)
        finally:
            os.remove(os.path.join(os.environ["NETSCAN_DATA"], "devices.json"))




if __name__ == "__main__":
    unittest.main()
