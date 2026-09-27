"""Open the whole window without a display: every tab, every tool, both themes, help, and the HTML report."""

import os
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

import _support

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QDialog

from netscan_app import window
from netscan_app.columns import TAB_DASHBOARD, TAB_SCAN, TAB_TOOLS, TAB_TRAFFIC
from netscan_app.help import TOOLS as HELP_TOOLS
from netscan_app.tools_tab import TOOL_GROUPS
from netscan_app.report import build_report

HOST = """<host><status state="up"/><address addr="10.9.9.{n}" addrtype="ipv4"/>
<address addr="AA:00:00:00:00:{n:02d}" addrtype="mac" vendor="Test"/>
<hostnames><hostname name="{name}"/></hostnames>
<ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports></host>"""


class Window(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = _support.app()
        cls.patches = [mock.patch.object(window, "app_settings", _support.settings),
                       mock.patch("netscan_app.widgets.notify"), mock.patch("netscan_app.watch.notify"),
                       mock.patch("netscan_app.uptime.notify"), mock.patch("netscan_app.toolkit_tab.notify"),
                       mock.patch("netscan_app.online_tab.notify")]
        for p in cls.patches:
            p.start()
        cls.win = window.MainWindow()
        cls.win.sites.auto = False  # the test machine's own router mustn't switch sites mid-test
        cls.win.show()
        QApplication.processEvents()

    @classmethod
    def tearDownClass(cls):
        cls.win.close()
        QApplication.processEvents()
        for p in cls.patches:
            p.stop()

    def test_every_tab_tool_and_theme(self):
        win = self.win
        for mode in ("light", "dark"):
            win.retheme(mode)
            for tab in range(win.tabbar.count()):
                win.tabbar.setCurrentIndex(tab)
                QApplication.processEvents()
            win.tabbar.setCurrentIndex(TAB_TOOLS)
            for row, name in win.tool_rows():
                win.tool_nav.setCurrentRow(row)
                QApplication.processEvents()
                self.assertEqual(win.tool_stack.currentIndex(), win.tool_nav.item(row).data(Qt.UserRole))
            self.assertEqual(win.tool_stack.count(), len(win.tool_rows()))
        win.traffic_timer.stop()

    def test_tool_groups(self):
        win = self.win
        grouped = [name for _group, names in TOOL_GROUPS for name in names]
        self.assertEqual(sorted(grouped), sorted(name for _row, name in win.tool_rows()))
        self.assertEqual(len(grouped), len(set(grouped)))
        self.assertEqual(set(grouped), set(HELP_TOOLS))
        headings = [win.tool_nav.item(r) for r in range(win.tool_nav.count()) if win.tool_nav.item(r).data(Qt.UserRole) is None]
        self.assertEqual([h.text() for h in headings], [g.upper() for g, _names in TOOL_GROUPS])
        self.assertTrue(all(h.flags() == Qt.NoItemFlags for h in headings))
        win.tool_nav.setCurrentRow(0)  # a heading: nothing changes
        self.assertIsNotNone(win.tool_nav.item(win.tool_rows()[0][0]).data(Qt.UserRole))

    def test_help_opens(self):
        self.win.show_help()
        QApplication.processEvents()
        dialogs = [w for w in QApplication.topLevelWidgets() if isinstance(w, QDialog) and w.isVisible()
                   and w.windowTitle() == "NetScan help"]
        self.assertEqual(len(dialogs), 1)
        dialogs[0].close()

    def test_palette_lists_every_tool(self):
        labels = {entry[1] for entry in self.win.palette_entries()}
        for _row, name in self.win.tool_rows():
            self.assertIn(name, labels)
        self.assertIn("Help", labels)

    def test_report_escapes_names(self):
        win = self.win
        win.current, win.auto_ports, win.scan_message = None, True, "Test scan."
        win.host_found(ET.fromstring(HOST.format(n=5, name="&lt;script&gt;alert(1)&lt;/script&gt;")))
        win.host_found(ET.fromstring(HOST.format(n=6, name="nas.lan")))
        page = build_report(win.report_data())
        self.assertNotIn("<script>alert(1)", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("nas.lan", page)
        self.assertIn("telnet", page)  # the risky port is called out

    def test_checkup_panels(self):
        win = self.win
        ok = {"avg": 2.0, "loss": 0.0, "jitter": 0.3, "count": 10, "last": 2.0, "min": 1.0, "max": 3.0}
        m = {"iface": "eth0", "gateway": "10.9.9.1", "wireless": False, "router": ok, "cf": ok, "google": ok,
             "dns_ok": True, "dns_ms": 20.0, "first_hop": "10.9.9.1", "errors": []}
        win.plan_spins["down"].setValue(500)
        win.plan_spins["up"].setValue(50)
        self.assertEqual(win.speed_plan(), {"down": 500, "up": 50})
        speed = {"server": "Test", "down": 100.0, "up": 45.0, "used_mb": 80.0, "idle_ms": 10.0, "when": "12:00",
                 "loaded_ms": {"down": 300.0, "up": 20.0}, "added_ms": 290.0, "grade": "D"}
        win.insights_done("diagnose", (m, speed))
        self.assertEqual(win.diag_head.text(), "The connection lags when busy")
        self.assertIn("20% of your plan", win.diag_out.toPlainText())
        self.assertIn("20% of your plan", win.speed_tiles["down"][1].text())
        win.insights_done("diagnose", (m, None))
        self.assertEqual(win.diag_head.text(), "No problems found")

        win.insights_done("security", {"wifi": {"ssid": "Home", "security": "open"}, "dns_hijack": False,
                                       "local_ports": [], "errors": []})
        self.assertEqual(win.sec_score.text(), "Incomplete")  # no scanned devices: no grade
        self.assertIn("no password", win.sec_out.toPlainText())
        win.current, win.auto_ports, win.scan_message = None, True, "Test scan."
        win.host_found(ET.fromstring(HOST.format(n=7, name="cam.lan")))
        win.ports["10.9.9.7"] = [{"port": 23, "proto": "tcp", "service": "telnet"}]
        win.insights_done("security", {"wifi": None, "dns_hijack": False, "local_ports": [], "errors": []})
        self.assertIn("/100", win.sec_score.text())
        self.assertIn("Telnet", win.sec_out.toPlainText())

        win.insights_done("nat", {"gateway": "10.9.9.1", "public_ip": "8.8.4.4", "router_wan": "100.70.0.2",
                                  "hops": [], "errors": []})
        self.assertIn("CGNAT", win.router_head.text())

        reading = {"signal": 30, "dbm": -80, "ssid": "Home", "bssid": "aa:bb", "band": "5 GHz", "channel": 36,
                   "when": "2026-09-27T12:00:00"}
        win.insights_done("survey", ("Garage", reading))
        win.insights_done("survey", ("Office", {**reading, "signal": 90}))
        self.assertEqual(win.survey_table.rowCount(), 2)
        self.assertEqual(win.survey_table.item(0, 0).text(), "Office")  # strongest first
        self.assertIn("Garage", win.survey_note.text())

        hour = __import__("datetime").datetime.now().strftime("%Y-%m-%dT%H")
        win.devices.devices["AA:00:00:00:00:77"] = {"mac": "AA:00:00:00:00:77", "nickname": "Test phone",
                                                    "hours": [hour], "last_seen": "2026-09-27T12:00:00"}
        win.presence_filter.setCurrentIndex(2)  # devices with a nickname
        win.show_presence()
        self.assertEqual([r["name"] for r in win.presence_chart.rows], ["Test phone"])
        QApplication.processEvents()

    def test_online_panels(self):
        win = self.win
        regions = [("Near", {"median": 20.0, "min": 19.0, "jitter": 1.0, "failed": 0}), ("Far", None)]
        win.online_done("gaming", {"stability": {"median": 12.0, "jitter": 1.0, "loss": 0.0, "spikes": 0},
                                   "regions": regions})
        self.assertEqual(win.game_table.rowCount(), 4)
        self.assertEqual(win.region_table.item(0, 0).text(), "Near")
        self.assertEqual(win.region_table.item(1, 1).text(), "no answer")

        win.online_done("privacy", {"first_hop": "10.64.0.1", "gateway": "10.9.9.1", "v4": "198.51.100.4",
                                    "v4_owner": "VPN Co", "v6": "2001:db8::1", "v6_owner": "Home ISP",
                                    "dns": [], "dns_conclusion": "", "local_dns": ["10.9.9.1"], "errors": []})
        self.assertEqual(win.priv_head.text(), "Your VPN is leaking")

        win.online_done("exposure", {"ip": "203.0.113.9", "country": "US", "vpn": False, "blocklists": [],
                                     "shodan": {"ports": [23], "vulns": ["CVE-2020-0001"]}, "shodan_error": ""})
        self.assertEqual(win.exp_head.text(), "1 port(s) open to the internet")
        self.assertIn("CVE-2020-0001", win.exp_out.toHtml())

        rows = [{"ip": "10.9.9.5", "kind": "Web page", "name": "Home Assistant", "url": "http://10.9.9.5:8123/",
                 "detail": ""}, {"ip": "10.9.9.6", "kind": "AirPlay", "name": "TV", "url": "", "detail": ""}]
        win.online_done("services", rows)
        self.assertEqual(win.svc_table.rowCount(), 2)
        with mock.patch("netscan_app.online_tab.QDesktopServices.openUrl") as opened:
            win.open_service_row(0, 0)
            win.open_service_row(1, 0)
        self.assertEqual(opened.call_count, 1)
        win.svc_filter.setText("airplay")
        self.assertTrue(win.svc_table.isRowHidden(0))
        win.svc_filter.clear()

        win.outage_log.path = os.path.join(_support.TMP, "gui-outages.json")
        win.outage_log.outages, win.outage_log.ongoing = [], None
        for router, internet in ((1.0, 10.0), (1.0, None), (1.0, None), (1.0, None), (1.0, 11.0)):
            win.net_watch_result(("10.9.9.1", router, internet))
        self.assertEqual(len(win.outage_log.outages), 1)
        win.outage_range.setCurrentIndex(0)
        win.show_outages()
        self.assertEqual(win.outage_tiles["count"][0].text(), "1")
        self.assertEqual(win.outage_table.rowCount(), 1)
        target = os.path.join(_support.TMP, "report.html")
        with mock.patch("netscan_app.online_tab.QFileDialog.getSaveFileName", return_value=(target, "")), \
                mock.patch("netscan_app.online_tab.QDesktopServices.openUrl"):
            win.save_isp_report()
        with open(target, encoding="utf-8") as f:
            self.assertIn("Internet connection report", f.read())

    def test_sites_keep_devices_apart(self):
        win = self.win
        home_count = len(win.devices.devices)
        win.devices.devices["AA:00:00:00:00:99"] = {"mac": "AA:00:00:00:00:99", "nickname": "Home thing"}
        sid = win.sites.add("Acme Dental", "AA:BB:00:00:00:01", "10.50.0.0/24")
        win.switch_site(sid)
        self.assertEqual(win.site_btn.text(), "Site: Acme Dental")
        self.assertEqual(win.devices.devices, {})
        self.assertEqual(win.table.rowCount(), 0)
        win.devices.devices["BB:00:00:00:00:01"] = {"mac": "BB:00:00:00:00:01", "nickname": "Reception PC"}
        win.devices.save()
        win.switch_site("home")
        self.assertIn("AA:00:00:00:00:99", win.devices.devices)
        self.assertNotIn("BB:00:00:00:00:01", win.devices.devices)
        self.assertEqual(len(win.devices.devices), home_count + 1)
        win.sites.auto = True
        win.site_detected({"network": "10.50.0.0/24"}, "AA:BB:00:00:00:01")  # arriving at Acme: switch by router
        self.assertEqual(win.sites.current, sid)
        self.assertIn("Reception PC", [d.get("nickname") for d in win.devices.devices.values()])
        win.site_detected({"network": "10.77.0.0/24"}, "CC:00:00:00:00:01")  # an unknown network: its own site
        self.assertTrue(win.sites.name().startswith("New site 10.77.0.0/24"))
        win.sites.auto = False
        win.switch_site("home")

    def test_copy_for_ticket(self):
        win = self.win
        win.open_tool("Firewall test")
        rows = [(c, p, w, "blocked" if p == 25 else "open") for c, p, w in __import__("netscan_app.work",
                                                                                        fromlist=["x"]).OUTBOUND_PORTS]
        win.work_done("firewall", {"tcp": rows, "udp_dns": True, "nat": {"udp": True, "kind": "friendly",
                                                                          "mapped": ("203.0.113.1", 1)}})
        win.copy_for_ticket()
        text = QApplication.clipboard().text()
        self.assertTrue(text.startswith("NetScan · Firewall test · site "))
        self.assertIn("Port 25 is blocked", text)
        self.assertIn("Remote access", text)   # the table came along
        self.assertIn("OUTBOUND", text)

    def test_work_panels(self):
        win = self.win
        win.work_done("voip", {"stability": {"median": 20.0, "jitter": 1.0, "loss": 0.0, "spikes": 0},
                               "sip": {5060: "open", 5061: "open"}, "nat": {"kind": "friendly"}})
        self.assertTrue(win.voip_head.text().startswith("Call quality 4."))
        bulk = {"domain": "client.com", "provider": "Google Workspace", "m365": None, "mx": ["aspmx.l.google.com"],
                "spf": "", "spf_all": "", "dmarc": "none", "dkim": [], "expires": "2030-01-01", "expires_days": 900,
                "registrar": "X", "web_ok": True, "web_status": 200, "web_error": "", "cert_days": 40, "error": ""}
        win.work_done("bulk", [bulk])
        self.assertEqual(win.bulk_table.item(0, 3).text(), "missing")
        self.assertIn("no SPF", win.bulk_table.item(0, 8).text())
        win.work_done("mail", {"target": "203.0.113.5", "domain": None, "port25": False, "domain_lists": [],
                               "servers": [{"host": "203.0.113.5", "ips": ["203.0.113.5"], "reachable": None,
                                            "starttls": None, "tls": None, "cert": None, "banner": "", "error": "",
                                            "ptr": {"203.0.113.5": ("mail.client.com", True)},
                                            "blocklists": {"203.0.113.5": [("SpamCop", "clean", "")]}}]})
        self.assertIn("on none of 1 blocklists", win.mail_out.toPlainText())
        win.prop_expected.setText("1.1.1.1")
        win.work_done("prop", {"name": "a.com", "type": "A", "authoritative": None,
                               "rows": [("A", "US", ("1.1.1.1",), 5.0, "DNS", ""), ("B", "EU", ("2.2.2.2",), 6.0,
                                                                                    "HTTPS", ""),
                                        ("C", "CN", None, None, "", "blocked here")]})
        self.assertEqual(win.prop_head.text(), "1 of 2 resolvers have 1.1.1.1")
        self.assertEqual(win.prop_table.item(1, 5).text(), "differs")

    def test_site_audit_and_inventory(self):
        win = self.win
        win.current, win.auto_ports, win.scan_message = None, True, "Test scan."
        win.host_found(ET.fromstring(HOST.format(n=8, name="printer.lan")))
        win.audit_company.setText("Contoso IT <b>")
        gathered = {"security": {"wifi": None, "dns_hijack": False, "local_ports": [], "errors": []},
                    "dns": ["10.9.9.1"], "services": [{"ip": "10.9.9.8", "kind": "Web page", "name": "Printer",
                                                       "url": "http://10.9.9.8/", "detail": ""}],
                    "wifi": [], "public": "203.0.113.9 (ISP, US)", "firewall": None}
        target = os.path.join(_support.TMP, "audit.html")
        with mock.patch("netscan_app.work_tab.QFileDialog.getSaveFileName", return_value=(target, "")), \
                mock.patch("netscan_app.work_tab.QDesktopServices.openUrl"):
            win.work_done("audit", gathered)
        with open(target, encoding="utf-8") as f:
            page = f.read()
        self.assertIn("Network audit: Home", page)
        self.assertIn("Contoso IT &lt;b&gt;", page)
        self.assertIn("printer.lan", page)
        self.assertIn("http://10.9.9.8/", page)
        csv_path = os.path.join(_support.TMP, "inventory.csv")
        with mock.patch("netscan_app.work_tab.QFileDialog.getSaveFileName", return_value=(csv_path, "")):
            win.export_inventory()
        with open(csv_path, encoding="utf-8") as f:
            self.assertTrue(f.readline().startswith("Name,Type,IP address"))

    def test_traffic_tab(self):
        import test_traffic as tt
        from netscan_app.traffic import Analyzer
        win = self.win
        analyzer = Analyzer(local_macs=["74:56:3C:B9:2E:89"], local_ips=["10.0.0.9"], gateway="10.0.0.1")
        t = 1_000_000.0
        for frame in (tt.lldp_frame(), tt.stp_frame(), tt.arp(tt.ROUTER, "10.0.0.1"), tt.arp(tt.OTHER, "10.0.0.1")):
            t += 0.5
            analyzer.add(t, frame, len(frame))

        class FakeCapture:
            running, error, kept = True, "", [(t, tt.lldp_frame(), 100)]

            def __init__(self):
                self.analyzer = analyzer

            def stop(self):
                self.running = False

            def save(self, path):
                return 1

        win.capture = FakeCapture()
        win.tabbar.setCurrentIndex(TAB_TRAFFIC)
        win.refresh_traffic()
        self.assertEqual(win.cap_tiles["switch"][0].text(), "core-sw1 · port Office desk 12")
        self.assertIn("VLAN 20", win.cap_tiles["switch"][1].text())
        self.assertIn("router's address", win.cap_events.toPlainText())
        self.assertIn("Root switch", win.cap_events.toPlainText())
        self.assertGreater(win.cap_proto.rowCount(), 2)
        win.tabbar.setCurrentIndex(TAB_DASHBOARD)  # the Dashboard lists the capture's warnings too
        self.assertIn("Traffic: Two devices claim the router's address", win.dash_attention.toPlainText())
        win.capture.stop()
        win.capture = None
        win.refresh_traffic()
        self.assertEqual(win.cap_tiles["switch"][0].text(), "—")

    def test_dashboard(self):
        win = self.win
        win.last_security = {"score": 62, "grade": "C", "complete": True, "findings": [], "when": 0}
        win.web_state = {"https://client.example": {"ok": False, "error": "timed out", "status": None,
                                                    "cert_days": None}}
        win.tabbar.setCurrentIndex(TAB_DASHBOARD)
        text = win.dash_attention.toPlainText()
        self.assertIn("https://client.example is down", text)
        self.assertIn("Security grade C (62/100)", text)
        self.assertEqual(win.dash_tiles["security"][0].text(), "C  62")
        self.assertTrue(win.dash_timer.isActive())
        win.tabbar.setCurrentIndex(TAB_SCAN)
        self.assertFalse(win.dash_timer.isActive())
        win.web_state = {}

    def test_health_score(self):
        from netscan_app.dashboard_tab import health_score, health_words
        self.assertIsNone(health_score([], 0, False, measured=False))
        self.assertEqual(health_score([("info", "", ""), ("good", "", "")], 0, False, True), 100)
        items = [("bad", "", "")] * 5 + [("warn", "", "")] * 7
        self.assertEqual(health_score(items, 9, False, True), 100 - 40 - 15 - 20)
        self.assertEqual(health_score([], 0, True, True), 25)
        self.assertEqual([health_words(s) for s in (None, 90, 70, 20)],
                         ["Not enough data yet", "Healthy", "Needs a look", "Trouble"])
        self.win.tabbar.setCurrentIndex(TAB_DASHBOARD)
        self.assertIn(self.win.dash_headline.text(), ("Healthy", "Needs a look", "Trouble", "Not enough data yet"))

    def test_tab_order(self):
        win = self.win
        self.assertEqual([win.tabbar.tabText(i) for i in range(win.tabbar.count())],
                         ["Dashboard", "Scan", "Devices", "Monitor", "Internet", "Map", "Tools", "Traffic"])
        self.assertEqual(win.pages.count(), win.tabbar.count())
        for i in range(win.tabbar.count()):  # each tab shows its own page
            win.tabbar.setCurrentIndex(i)
            self.assertIs(win.pages.currentWidget(), win.pages.widget(i))
        self.assertIs(win.pages.widget(TAB_DASHBOARD).findChild(type(win.dash_attention)), win.dash_attention)
        self.assertIs(win.pages.widget(TAB_TRAFFIC).findChild(type(win.cap_iface)), win.cap_iface)

    def test_open_tool(self):
        self.win.open_tool("Security checkup")
        self.assertEqual(self.win.tool_nav.currentItem().text(), "Security checkup")
        self.assertEqual(self.win.tabbar.currentIndex(), TAB_TOOLS)


if __name__ == "__main__":
    unittest.main()
