"""Command palette (Ctrl+K): type to jump to any tab, tool, action or device."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QVBoxLayout

from . import theme as T
from .columns import DEV_MAC
from .scanning import ip_sort_key
from .tools_tab import TOOL_GROUPS


# Extra words people search for (the palette matches these as well as the names).
TOOL_KEYWORDS = {
    "DNS lookup": "dig nslookup resolve pihole hijack", "Check ports": "port scan telnet nc open",
    "IP info": "whois rdap owner asn", "HTTP inspector": "headers curl redirect https ssl",
    "Subnet calculator": "cidr netmask ipcalc", "MAC lookup": "oui vendor manufacturer",
    "Wi-Fi": "wifi wlan channel signal ssid", "Connections": "netstat sockets ss lsof tcpview",
    "Live traffic": "bandwidth throughput usage graph", "Continuous trace": "mtr traceroute ping path hops loss",
    "LAN speed test": "iperf throughput local", "Domain toolkit": "whois spf dmarc dkim mx email registrar",
    "Website watch": "uptime monitor ssl certificate expiry down",
    "DNS speed": "dns benchmark resolver faster namebench unbound pihole",
    "History": "history log timeline outages charts past week",
}


class PaletteDialog(QDialog):
    def __init__(self, parent, entries):
        super().__init__(parent, Qt.Popup | Qt.FramelessWindowHint)
        self.entries = entries  # [(kind, text, callable)]
        self.setMinimumWidth(560)
        self.setStyleSheet(f"QDialog {{ background: {T.RAISED}; border: 1px solid {T.BORDER_HI}; border-radius: 12px; }}")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        self.edit = QLineEdit()
        self.edit.setPlaceholderText("Type a tab, tool, action or device… (Enter to go, Esc to close)")
        self.list = QListWidget()
        self.list.setObjectName("toolNav")
        self.list.setMinimumHeight(320)
        hint = QLabel("↑↓ to choose · Enter to run")
        hint.setObjectName("muted")
        lay.addWidget(self.edit)
        lay.addWidget(self.list)
        lay.addWidget(hint)
        self.edit.textChanged.connect(self.refill)
        self.edit.returnPressed.connect(self.run_current)
        self.list.itemActivated.connect(lambda _i: self.run_current())
        self.edit.installEventFilter(self)
        self.refill("")

    def eventFilter(self, obj, event):
        if obj is self.edit and event.type() == event.Type.KeyPress and event.key() in (Qt.Key_Down, Qt.Key_Up):
            row = self.list.currentRow() + (1 if event.key() == Qt.Key_Down else -1)
            self.list.setCurrentRow(max(0, min(row, self.list.count() - 1)))
            return True
        return super().eventFilter(obj, event)

    @staticmethod
    def score(query, label, keywords=""):
        """Lower is better; None = no match. Label word-starts beat keywords beat substrings beat letters
        spread out in order (where letters starting words and close together count as better)."""
        q, t = query.lower(), label.lower()
        if not q:
            return 0
        if t.startswith(q) or f" {q}" in t:
            return 1
        if any(k.startswith(q) for k in keywords.lower().split()):
            return 1.5
        if q in t:
            return 2
        pos, cost = 0, 0.0
        for ch in q:  # e.g. "spt" -> "Speed test": s, p close together, t starts a word
            found = t.find(ch, pos)
            if found < 0:
                return None
            starts_word = found == 0 or t[found - 1] in " -·/"
            cost += 0 if starts_word else (found - pos) * 0.1 + 0.2
            pos = found + 1
        return 3 + cost

    def refill(self, text):
        self.list.clear()
        ranked = sorted(((s, n, kind, label, fn) for n, (kind, label, fn, *kw) in enumerate(self.entries)
                         if (s := self.score(text.strip(), label, " ".join(kw) + " " + kind)) is not None),
                        key=lambda x: (x[0], x[1]))
        for _s, _n, kind, label, fn in ranked[:60]:
            item = QListWidgetItem(f"{label}    ·  {kind}")
            item.setData(Qt.UserRole, fn)
            self.list.addItem(item)
        self.list.setCurrentRow(0)

    def run_current(self):
        item = self.list.currentItem()
        if item:
            fn = item.data(Qt.UserRole)
            self.accept()
            fn()


class PaletteMixin:
    """Ctrl+K command palette. Mixed into MainWindow."""

    def palette_entries(self):
        tab = lambda i: (lambda: self.tabbar.setCurrentIndex(i))
        entries = [("Tab", self.tabbar.tabText(i), tab(i)) for i in range(self.tabbar.count())]
        group_of = {name: group for group, names in TOOL_GROUPS for name in names}
        for row, name in self.tool_rows():
            entries.append(("Tool", name, (lambda r=row: (self.tabbar.setCurrentIndex(5), self.tool_nav.setCurrentRow(r))),
                            TOOL_KEYWORDS.get(name, "") + " " + group_of.get(name, "")))
        entries += [
            ("Action", "Find hosts", lambda: (self.tabbar.setCurrentIndex(0), self.scan_btn.isEnabled() and self.start_scan())),
            ("Action", "Scan ports", lambda: (self.tabbar.setCurrentIndex(0), self.ports_btn.isEnabled() and self.start_port_scan())),
            ("Action", "Internet check", lambda: (self.tabbar.setCurrentIndex(3), self.run_internet_check())),
            ("Action", "Speed test", lambda: (self.tabbar.setCurrentIndex(3), self.speed_btn.isEnabled() and self.run_speed_test()),
             "bandwidth internet bufferbloat librespeed"),
            ("Action", "Network report (HTML)", self.export_report),
            ("Action", "Save scan", self.save_json),
            ("Action", "Trace route to the internet", lambda: self.trace_route("1.1.1.1", "the internet (1.1.1.1)")),
            ("Action", "Wake-on-LAN by MAC", lambda: (self.tabbar.setCurrentIndex(1), self.mac_edit.setFocus())),
            ("Action", "Help", self.show_help),
            ("Action", "Theme: light", lambda: self.retheme("light")),
            ("Action", "Theme: dark", lambda: self.retheme("dark")),
            ("Action", "Theme: system", lambda: self.retheme("system")),
        ]
        for ip in sorted(self.hosts, key=ip_sort_key):
            h = self.hosts[ip]
            label = " · ".join(x for x in (self.devices.nickname(h), h["hostname"], ip, h["vendor"]) if x)
            entries.append(("Device", label, lambda ip=ip: self.show_host(ip)))
        for mac, d in self.devices.devices.items():
            if d.get("mac") and not any(h["mac"] == mac for h in self.hosts.values()):
                label = " · ".join(x for x in (d.get("nickname"), d.get("hostname"), d.get("ip"), mac) if x)
                entries.append(("Known device", label, lambda mac=mac: self.show_known_device(mac)))
        return entries

    def show_known_device(self, mac):
        self.tabbar.setCurrentIndex(1)
        self.dev_filter.clear()
        self.dev_show.setCurrentIndex(0)
        for r in range(self.dev_table.rowCount()):
            if self.dev_table.item(r, DEV_MAC) and self.dev_table.item(r, DEV_MAC).text() == mac:
                self.dev_table.selectRow(r)
                self.dev_table.scrollToItem(self.dev_table.item(r, 0))

    def open_palette(self):
        dlg = PaletteDialog(self, self.palette_entries())
        geo = self.geometry()
        dlg.move(geo.x() + (geo.width() - dlg.minimumWidth()) // 2, geo.y() + 80)
        dlg.edit.setFocus()
        dlg.exec()
