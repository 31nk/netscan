"""The Traffic tab: a live look at what this computer's network card sees. The switch port it's plugged into,
spanning tree, DHCP, DNS lookups, ARP conflicts, broadcast storms, protocols and top talkers. Engine: traffic.py."""

import html
import os
import time

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QGridLayout, QLabel, QMessageBox, QPushButton, QSplitter, QTextBrowser,
    QVBoxLayout, QWidget,
)

from . import theme as T
from .columns import TAB_TRAFFIC
from .insights_tab import level_color
from .scanning import mac_vendor
from .system import IS_MAC, IS_WIN, npcap_installed, relative_time
from .theme import make_card
from .toolkit_tab import _set_row, _table
from .traffic import Analyzer, Capture, capture_argv

MARK = {"bad": "✗", "warn": "⚠", "info": "·", "good": "✓"}


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1000 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} GB"


class TrafficMixin:
    """The Traffic tab. Mixed into MainWindow."""

    def build_traffic_page(self):
        self.capture = None
        page = QWidget()
        pl = QVBoxLayout(page)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.setSpacing(12)

        card, cl, head = make_card("Traffic")
        self.cap_iface = QComboBox()
        self.cap_iface.setMinimumWidth(260)
        self.cap_note = QLabel("Shows what this computer's network card sees: its own traffic plus everything sent "
                               "to the whole network. Needs your password to start (it only listens, never sends).")
        self.cap_note.setObjectName("muted")
        self.cap_note.setWordWrap(True)
        self.cap_btn = QPushButton("Start capture")
        self.cap_btn.setObjectName("primary")
        self.cap_btn.clicked.connect(self.toggle_capture)
        self.cap_save = QPushButton("Save for Wireshark…")
        self.cap_save.setEnabled(False)
        self.cap_save.clicked.connect(self.save_capture)
        head.addWidget(self.cap_note, 1)
        head.addWidget(self.cap_iface)
        head.addWidget(self.cap_save)
        head.addWidget(self.cap_btn)
        grid = QGridLayout()
        grid.setSpacing(10)
        self.cap_tiles = {}
        for i, (key, label) in enumerate((("switch", "Switch port"), ("rate", "Right now"), ("total", "Captured"),
                                          ("bcast", "Broadcasts"))):
            frame, value, detail = self.make_tile(label)
            grid.addWidget(frame, 0, i if i == 0 else i + 1, 1, 2 if i == 0 else 1)
            self.cap_tiles[key] = (value, detail)
        grid.setColumnStretch(0, 2)
        grid.setColumnStretch(1, 2)
        for col in (2, 3, 4):
            grid.setColumnStretch(col, 1)
        cl.addLayout(grid)
        pl.addWidget(card)

        self.cap_proto = _table(["What", "Packets", "Data", "Share"], stretch_col=0)
        self.cap_talkers = _table(["Address", "Name", "Mostly", "Down", "Up"], stretch_col=1)
        self.cap_dns = _table(["Time", "Device", "Looked up", "Type"], stretch_col=2)
        self.cap_events = QTextBrowser()
        top, bottom = QSplitter(Qt.Horizontal), QSplitter(Qt.Horizontal)
        for splitter, items in ((top, (("Protocols", self.cap_proto), ("Top talkers", self.cap_talkers))),
                                (bottom, (("DNS lookups seen", self.cap_dns),
                                          ("Events: switches, DHCP, conflicts, storms", self.cap_events)))):
            for title, widget in items:
                c, lay, _h = make_card(title)
                lay.addWidget(widget, 1)
                splitter.addWidget(c)
            splitter.setSizes([500, 700])
        v = QSplitter(Qt.Vertical)
        v.addWidget(top)
        v.addWidget(bottom)
        v.setChildrenCollapsible(False)
        pl.addWidget(v, 1)
        self.cap_timer = QTimer(self)
        self.cap_timer.timeout.connect(self.refresh_traffic)
        self.fill_capture_ifaces()
        self.refresh_traffic()
        return page

    def fill_capture_ifaces(self):
        current = self.cap_iface.currentData()
        self.cap_iface.clear()
        for n in self.networks:
            self.cap_iface.addItem(f"{n['iface']}  ({n['local_ip']})", n)
        if current:
            idx = next((i for i in range(self.cap_iface.count()) if self.cap_iface.itemData(i)["iface"] ==
                        current["iface"]), 0)
            self.cap_iface.setCurrentIndex(idx)

    def toggle_capture(self):
        if self.capture and self.capture.running:
            self.stop_capture()
            return
        net = self.cap_iface.currentData()
        if not net:
            self.fill_capture_ifaces()
            net = self.cap_iface.currentData()
            if not net:
                return
        if IS_WIN and not npcap_installed():
            QMessageBox.information(self, "NetScan", "Capturing needs Npcap, which comes with nmap. Run "
                                                     "install-windows.ps1 (or install nmap from nmap.org).")
            return
        argv, prompt = capture_argv(net, self.root)
        env = None
        if IS_MAC and self.askpass:
            env = {**os.environ, "SUDO_ASKPASS": self.askpass}
        macs = [n["mac"] for n in self.networks if n["iface"] == net["iface"]]
        analyzer = Analyzer(local_macs=macs, local_ips=[n["local_ip"] for n in self.networks],
                            gateway=net.get("gateway"))
        try:
            self.capture = Capture(argv, analyzer, env=env)
        except OSError as e:
            self.cap_note.setText(f"⚠ Couldn't start the capture: {e}")
            return
        self.cap_net = net
        self.cap_btn.setText("Stop")
        self.cap_iface.setEnabled(False)
        self.cap_save.setEnabled(True)
        self.cap_note.setText(f"Capturing on {net['iface']}" + (" (authorise in the password prompt)" if prompt else "")
                              + ". Switches announce themselves every 30 to 60 seconds.")
        self.cap_timer.start(1000)

    def stop_capture(self):
        if self.capture:
            self.capture.stop()
        self.cap_timer.stop()
        self.cap_btn.setText("Start capture")
        self.cap_iface.setEnabled(True)
        self.refresh_traffic()
        if self.capture:
            self.cap_note.setText(f"Stopped. {self.capture.analyzer.packets} packets captured"
                                  + (f"; {self.capture.error}." if self.capture.error else "."))

    def save_capture(self):
        if not self.capture or not self.capture.kept:
            return
        default = os.path.join(os.path.expanduser("~"), f"capture-{time.strftime('%Y-%m-%d-%H%M')}.pcap")
        path, _ = QFileDialog.getSaveFileName(self, "Save capture", default, "Packet capture (*.pcap)")
        if path:
            n = self.capture.save(path)
            self.status.setText(f"Saved {n} packets to {path}. Most are trimmed to their headers; switch, DHCP, "
                                "DNS and ARP packets are complete.")

    def refresh_traffic(self):
        cap = self.capture
        if cap and not cap.running and self.cap_timer.isActive():
            self.stop_capture()  # the helper ended (cancelled prompt, error, or the network went away)
            return
        if cap is None:
            for key, text in (("switch", "Start a capture to see which switch port you're on"), ("rate", ""),
                              ("total", ""), ("bcast", "")):
                self.cap_tiles[key][0].setText("—")
                self.cap_tiles[key][0].setStyleSheet("")
                self.cap_tiles[key][1].setText(text)
            self.cap_events.setHtml(f'<p style="color:{T.MUTED}">Switch announcements (LLDP from most brands, CDP '
                                    "from Cisco), spanning tree changes, DHCP servers, IP conflicts and broadcast "
                                    "storms will appear here.</p>")
            return
        s = cap.analyzer.snapshot()
        self.show_switch(s)
        rate = s["rates"][-1] if s["rates"] else (0, 0, 0, 0)
        self.cap_tiles["rate"][0].setText(f"{rate[2] * 8 / 1e6:.1f} Mbit/s")
        self.cap_tiles["rate"][1].setText(f"{rate[1]} packets a second")
        self.cap_tiles["total"][0].setText(human_bytes(s["bytes"]))
        self.cap_tiles["total"][1].setText(f"{s['packets']} packets in {int(s['seconds'] // 60)} min "
                                           f"{int(s['seconds'] % 60)} s")
        bcast = rate[3]
        self.cap_tiles["bcast"][0].setText(f"{bcast} / s")
        self.cap_tiles["bcast"][0].setStyleSheet(f"color: {T.RED};" if bcast >= 300 else "")
        self.cap_tiles["bcast"][1].setText("storm!" if bcast >= 300 else "normal" if bcast < 50 else "busy")
        if self.tabbar.currentIndex() != TAB_TRAFFIC:
            return  # tables only while they're on screen
        total = max(1, s["bytes"])
        t = self.cap_proto
        t.setRowCount(len(s["protocols"]))
        for i, (name, pkts, size) in enumerate(s["protocols"]):
            _set_row(t, i, [name, pkts, human_bytes(size), f"{100 * size / total:.0f}%"])
        t = self.cap_talkers
        t.setRowCount(len(s["talkers"]))
        for i, (ip, down, up, _pkts, app, dns_name) in enumerate(s["talkers"]):
            name = dns_name or (self.device_name_for(ip) if hasattr(self, "device_name_for") else "")
            _set_row(t, i, [ip, name, app, human_bytes(down), human_bytes(up)],
                     {1: T.TEXT if name else T.MUTED})
        t = self.cap_dns
        t.setRowCount(len(s["dns"]))
        for i, (ts, client, name, qtype) in enumerate(s["dns"]):
            who = self.device_name_for(client) or client
            _set_row(t, i, [time.strftime("%H:%M:%S", time.localtime(ts)), who, name, qtype])
        for table in (self.cap_proto, self.cap_talkers, self.cap_dns):
            table.resizeColumnsToContents()
        e = html.escape
        extra = []
        if s["stp"]:
            st = s["stp"]
            vendor = mac_vendor(st["root_mac"])
            extra.append((time.time(), "info", f"Spanning tree ({st['version']}) is running. Root switch: "
                                               f"{st['root_mac']}" + (f" ({vendor})" if vendor else "")
                          + f", priority {st['root_priority']}, path cost {st['cost']}."))
        if s["vlans"]:
            extra.append((time.time(), "info", "Tagged VLAN traffic seen: " + ", ".join(
                f"VLAN {v} ({n} packets)" for v, n in sorted(s["vlans"].items())) + ". This port is probably a trunk."))
        rows = [(ts, lvl, text) for ts, lvl, text in extra + s["events"]]
        self.cap_events.setHtml("".join(
            f'<p style="margin:4px 0"><span style="color:{T.MUTED}">{time.strftime("%H:%M:%S", time.localtime(ts))}'
            f'</span>&nbsp; <span style="color:{level_color(lvl)}">{MARK[lvl]}</span> {e(text)}</p>'
            for ts, lvl, text in rows[:150]) or f'<p style="color:{T.MUTED}">Nothing yet.</p>')

    def show_switch(self, s):
        value, detail = self.cap_tiles["switch"]
        sw = s["switch"]
        if not sw:
            waited = s["seconds"]
            value.setText("Listening…" if waited < 65 else "No announcement")
            detail.setText("Switches announce every 30 s (LLDP) or 60 s (CDP)." if waited < 65 else
                           "Unmanaged switches, most home routers and Wi-Fi don't announce themselves. A managed "
                           "switch with LLDP/CDP turned off won't either.")
            value.setStyleSheet("")
            return
        port = sw.get("port_desc") or sw.get("port") or "?"
        value.setText(f"{sw.get('switch') or sw.get('chassis') or 'Switch'} · port {port}")
        value.setStyleSheet(f"color: {T.GREEN};")
        bits = []
        if sw.get("port_desc") and sw.get("port") and sw["port"] != sw["port_desc"]:
            bits.append(f"port ID {sw['port']}")
        if sw.get("vlan"):
            bits.append(f"VLAN {sw['vlan']}")
        if sw.get("voice_vlan"):
            bits.append(f"voice VLAN {sw['voice_vlan']}")
        if sw.get("speed"):
            bits.append(sw["speed"])
        if sw.get("mgmt"):
            bits.append(f"switch at {sw['mgmt']}")
        model = sw.get("platform") or (sw.get("description") or "").split(",")[0][:60]
        if model:
            bits.append(model)
        bits.append(f"{sw['protocol']}, seen {relative_time(time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(s['switch_seen'])))}")
        detail.setText(" · ".join(bits))
