"""Open the whole window without a display: every tab, every tool, both themes, help, and the HTML report."""

import unittest
import xml.etree.ElementTree as ET
from unittest import mock

import _support

from PySide6.QtWidgets import QApplication, QDialog

from netscan_app import window
from netscan_app.report import build_report

HOST = """<host><status state="up"/><address addr="10.9.9.{n}" addrtype="ipv4"/>
<address addr="AA:00:00:00:00:{n:02d}" addrtype="mac" vendor="Test"/>
<hostnames><hostname name="{name}"/></hostnames>
<ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports></host>"""


class Window(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = _support.app()
        cls.patches = [mock.patch.object(window, "QSettings", _support.settings),
                       mock.patch("netscan_app.widgets.notify"), mock.patch("netscan_app.watch.notify"),
                       mock.patch("netscan_app.uptime.notify"), mock.patch("netscan_app.toolkit_tab.notify")]
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
            for row in range(win.tool_nav.count()):
                win.tool_nav.setCurrentRow(row)
                QApplication.processEvents()
            self.assertEqual(win.tool_stack.count(), win.tool_nav.count())
        win.traffic_timer.stop()

    def test_help_opens(self):
        self.win.show_help()
        QApplication.processEvents()
        dialogs = [w for w in QApplication.topLevelWidgets() if isinstance(w, QDialog) and w.isVisible()
                   and w.windowTitle() == "NetScan help"]
        self.assertEqual(len(dialogs), 1)
        dialogs[0].close()

    def test_palette_lists_every_tool(self):
        labels = {entry[1] for entry in self.win.palette_entries()}
        for row in range(self.win.tool_nav.count()):
            self.assertIn(self.win.tool_nav.item(row).text(), labels)
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


if __name__ == "__main__":
    unittest.main()
