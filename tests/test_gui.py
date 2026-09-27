"""Open the whole window without a display: every tab, every tool, both themes, help, and the HTML report."""

import os
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

import _support

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QDialog

from netscan_app import window
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
            win.tabbar.setCurrentIndex(5)
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

    def test_open_tool(self):
        self.win.open_tool("Security checkup")
        self.assertEqual(self.win.tool_nav.currentItem().text(), "Security checkup")
        self.assertEqual(self.win.tabbar.currentIndex(), 5)


if __name__ == "__main__":
    unittest.main()
