"""Tools for IT work on client networks: client sites (switched by router), the site audit and inventory CSV,
outbound firewall test, VoIP readiness, bulk domain check, mail server check, DNS propagation, and
"Copy for ticket". Engines: work.py, sites.py, audit.py."""

import csv
import datetime
import html
import os
import re
import time

from PySide6.QtCore import QUrl, Qt
from PySide6.QtGui import QDesktopServices, QGuiApplication, QTextDocumentFragment
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFrame, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMenu, QMessageBox,
    QPlainTextEdit, QPushButton, QTableWidget, QTextBrowser, QWidget,
)

from . import theme as T
from .audit import build_audit, logo_data_uri
from .checks import find_services, security_checkup, security_measure
from .devices import DEVICE_TYPES, DeviceStore, devices_file, set_site_dir
from .insights_tab import findings_html, level_color
from .internet import cloudflare_trace, dns_servers
from .scanning import mac_vendor, port_label
from .sites import HOME, visit_changes
from .system import neighbour_macs, ping_once, relative_time
from .toolkit_tab import _panel, _set_row, _table
from .tools import DNS_TYPES, wifi_scan
from .work import (
    INVENTORY_COLUMNS, bulk_domains, domain_issues, firewall_findings, firewall_test, inventory_rows, mail_check,
    mail_findings, propagation, propagation_summary, voip_check, voip_findings,
)


def router_mac(net):
    """The MAC address of a network's router, from the neighbour table (pinging it first if needed)."""
    gw = (net or {}).get("gateway")
    if not gw:
        return None
    mac = neighbour_macs(net["iface"]).get(gw)
    if not mac:
        ping_once(gw)
        mac = neighbour_macs(net["iface"]).get(gw)
    return (mac or "").upper() or None


def widget_text(root):
    """A plain-text rendering of a panel: labels, stat tiles, tables and result text, in on-screen order."""
    lines = []

    def plain(text):
        return QTextDocumentFragment.fromHtml(text).toPlainText() if re.search(r"<[a-zA-Z/][^>]*>", text) else text

    def walk(w):
        if isinstance(w, QWidget) and not w.isVisibleTo(root) and w is not root:
            return
        if isinstance(w, QFrame) and w.objectName() == "tile":
            parts = [plain(lab.text()).strip() for lab in w.findChildren(QLabel) if lab.text().strip()]
            if parts:
                lines.append(f"{parts[0].title()}: {parts[1] if len(parts) > 1 else ''}"
                             + (f" ({'; '.join(parts[2:])})" if len(parts) > 2 else ""))
            return
        if isinstance(w, QTableWidget):
            cols = [c for c in range(w.columnCount()) if not w.isColumnHidden(c)]
            head = [w.horizontalHeaderItem(c).text() if w.horizontalHeaderItem(c) else "" for c in cols]
            rows = [[w.item(r, c).text() if w.item(r, c) else "" for c in cols]
                    for r in range(w.rowCount()) if not w.isRowHidden(r)][:300]
            if rows:
                widths = [max(len(x) for x in [h] + [r[i] for r in rows]) for i, h in enumerate(head)]
                fmt = lambda cells: "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells)).rstrip()
                lines.extend([fmt(head), fmt(["-" * n for n in widths])] + [fmt(r) for r in rows])
            return
        if isinstance(w, QTextBrowser):
            text = w.toPlainText().strip()
            if text:
                lines.append(text)
            return
        if isinstance(w, QLabel) and w.property("noTicket"):
            return
        if isinstance(w, QLabel) and w.text().strip() and not w.pixmap():
            lines.append(plain(w.text()).strip())
            return
        if isinstance(w, QLineEdit) and w.text().strip() and not w.isReadOnly():
            lines.append(f"> {w.text().strip()}")
            return
        for child in w.children():
            walk(child)

    walk(root)
    return "\n".join(line for line in lines if line)


class WorkMixin:
    """Client sites and the tools for client work. Mixed into MainWindow."""

    def build_work_panels(self):
        """[(title, widget)] for the Tools list (tools_tab.TOOL_GROUPS decides where each goes)."""
        return [("Client sites", self.build_sites_panel()), ("Site audit", self.build_audit_panel()),
                ("Firewall test", self.build_firewall_panel()), ("VoIP readiness", self.build_voip_panel()),
                ("Domain check (bulk)", self.build_bulk_panel()), ("Mail server check", self.build_mail_panel()),
                ("DNS propagation", self.build_prop_panel())]

    # ---- the site switcher in the header ---------------------------------------------------

    def build_site_button(self):
        self.site_btn = QPushButton()
        self.site_btn.setObjectName("menuButton")
        self.site_btn.setToolTip("Client site: each has its own device list and saved scans. NetScan switches "
                                 "automatically by the network's router.")
        self.site_menu = QMenu(self.site_btn)
        self.site_menu.aboutToShow.connect(self.fill_site_menu)
        self.site_btn.setMenu(self.site_menu)
        self.update_site_button()
        return self.site_btn

    def update_site_button(self):
        self.site_btn.setText(f"Site: {self.sites.name()}")
        if hasattr(self, "sites_table"):
            self.show_sites()

    def fill_site_menu(self):
        m = self.site_menu
        m.clear()
        for sid, s in sorted(self.sites.sites.items(), key=lambda kv: (kv[0] != HOME, kv[1]["name"].lower())):
            act = m.addAction(s["name"])
            act.setCheckable(True)
            act.setChecked(sid == self.sites.current)
            act.triggered.connect(lambda _c=False, sid=sid: self.switch_site(sid))
        m.addSeparator()
        m.addAction("New site for this network…", self.new_site_here)
        m.addAction("Manage sites…", lambda: self.open_tool("Client sites"))
        auto = m.addAction("Switch automatically by network")
        auto.setCheckable(True)
        auto.setChecked(self.sites.auto)
        auto.toggled.connect(self.set_site_auto)

    def set_site_auto(self, on):
        self.sites.auto = on
        self.sites.save()
        if hasattr(self, "site_auto_box"):
            self.site_auto_box.blockSignals(True)
            self.site_auto_box.setChecked(on)
            self.site_auto_box.blockSignals(False)
        if on:
            self.detect_site()

    def detect_site(self):
        net = self.networks[0] if self.networks else None
        if net and net.get("gateway"):
            self.worker.run("wk:site", lambda: (net, router_mac(net)))

    def site_detected(self, net, mac):
        self.current_router = mac
        if not mac or not self.sites.auto:
            return
        sid = self.sites.find_by_router(mac)
        if sid is None:
            home = self.sites.sites[HOME]
            if self.sites.current == HOME and not home.get("routers"):
                self.sites.assign_router(HOME, mac)  # first network ever seen: this is home
                return
            vendor = mac_vendor(mac)
            sid = self.sites.add(f"New site {net['network']}" + (f" ({vendor.split()[0]})" if vendor else ""), mac,
                                 str(net["network"]))
            self.switch_site(sid)
            self.status.setText(f"New network: saved as site “{self.sites.name(sid)}”. Rename it in Tools → Client "
                                "sites; its devices and scans are kept separate.")
            return
        if sid != self.sites.current:
            self.switch_site(sid)

    def switch_site(self, sid):
        if sid == self.sites.current and hasattr(self, "_site_switched"):
            return
        if self.is_running():
            QMessageBox.information(self, "NetScan", "Wait for the scan to finish before switching sites.")
            return
        self._site_switched = True
        self.devices.save()
        previous = self.sites.switch(sid)
        set_site_dir(self.sites.folder(sid))
        self.devices = DeviceStore(devices_file())
        # The results on screen belong to the old site.
        self.table.setRowCount(0)
        self.ip_items, self.hosts, self.ports = {}, {}, {}
        self.upnp, self.spoof_warnings, self.new_devices, self.online_macs = None, [], set(), set()
        self.history_path = None
        self.uptime_state = {}
        self.uptime_restart()
        self.show_port_details()
        self.refresh_devices()
        self.update_site_button()
        self.update_controls()
        when = f" Last visit {relative_time(previous)}." if previous else ""
        self.status.setText(f"Site: {self.sites.name(sid)}.{when}")

    def new_site_here(self):
        name, ok = QInputDialog.getText(self, "New site", "Client or site name:")
        if not ok or not name.strip():
            return
        net = self.networks[0] if self.networks else None
        sid = self.sites.add(name.strip(), getattr(self, "current_router", None), str(net["network"]) if net else "")
        self.switch_site(sid)

    def site_visit_summary(self):
        """After a scan: what changed since the previous scan at this site (appended to the scan summary)."""
        if not self.current:
            return ""
        macs = [h["mac"] for h in self.hosts.values() if h["mac"]]
        before = self.sites.record_scan(self.sites.current, str(self.current["network"]), macs)
        self.show_sites()
        if not before:
            return ""
        age = (datetime.datetime.now() - datetime.datetime.fromisoformat(before["when"])).total_seconds()
        if self.sites.current == HOME and age < 86400:
            return ""  # at home, scans are frequent; only mention a proper gap
        new, gone = visit_changes(before, macs)
        names = lambda keys: ", ".join((self.devices.devices.get(k, {}).get("nickname")
                                        or self.devices.devices.get(k, {}).get("hostname") or k) for k in keys[:5])
        text = f" Since the last visit ({relative_time(before['when'])}): "
        text += ", ".join(x for x in (f"{len(new)} new ({names(new)})" if new else "",
                                      f"{len(gone)} not seen ({names(gone)})" if gone else "") if x) or "no changes"
        return text + "."

    # ---- client sites panel ------------------------------------------------------------------

    def build_sites_panel(self):
        w, lay = _panel("Client sites", "Each client network gets its own device list and saved scans. NetScan "
                                        "recognises a site by its router and switches automatically when you "
                                        "arrive; history, settings and caches are shared.")
        row = QHBoxLayout()
        self.site_auto_box = QCheckBox("Switch automatically by network")
        self.site_auto_box.setChecked(self.sites.auto)
        self.site_auto_box.toggled.connect(self.set_site_auto)
        row.addWidget(self.site_auto_box)
        row.addStretch(1)
        for label, slot in (("Switch to", self.switch_selected_site), ("New…", self.new_site_here),
                            ("Rename…", self.rename_selected_site), ("This network belongs here", self.claim_network),
                            ("Delete…", self.delete_selected_site)):
            b = QPushButton(label)
            b.clicked.connect(slot)
            row.addWidget(b)
        lay.addLayout(row)
        self.sites_table = _table(["Site", "Networks", "Devices", "Last visit", "Routers"], stretch_col=1)
        self.sites_table.cellDoubleClicked.connect(lambda r, _c: self.switch_selected_site())
        self.sites_table.itemSelectionChanged.connect(self.show_site_notes)
        lay.addWidget(self.sites_table, 2)
        notes_head = QLabel("NOTES FOR THIS SITE (contacts, ISP, circuit ID, where the rack is…)")
        notes_head.setObjectName("tileLabel")
        lay.addWidget(notes_head)
        self.site_notes = QPlainTextEdit()
        self.site_notes.setPlaceholderText("Saved as you type. Included in the site audit.")
        self.site_notes.textChanged.connect(self.save_site_notes)
        lay.addWidget(self.site_notes, 1)
        self.show_sites()
        return w

    def selected_site(self):
        items = self.sites_table.selectedItems()
        return items[0].data(Qt.UserRole) if items else None

    def show_sites(self):
        t = self.sites_table
        t.setRowCount(len(self.sites.sites))
        for i, (sid, s) in enumerate(sorted(self.sites.sites.items(),
                                            key=lambda kv: (kv[0] != HOME, kv[1]["name"].lower()))):
            count = len(self.devices.devices) if sid == self.sites.current else self._site_device_count(sid)
            _set_row(t, i, [s["name"] + ("  (current)" if sid == self.sites.current else ""),
                            ", ".join(s.get("networks", [])), count,
                            "here now" if sid == self.sites.current else
                            relative_time(s.get("last_visit", "")) if s.get("last_visit") else "",
                            ", ".join(s.get("routers", []))], {0: T.ACCENT_HI if sid == self.sites.current else T.TEXT})
            t.item(i, 0).setData(Qt.UserRole, sid)
        t.resizeColumnsToContents()

    def _site_device_count(self, sid):
        folder = self.sites.folder(sid)
        path = os.path.join(folder, "devices.json") if folder else None
        return len(DeviceStore(path).devices) if path and os.path.exists(path) else 0

    def show_site_notes(self):
        sid = self.selected_site() or self.sites.current
        self.site_notes.blockSignals(True)
        self.site_notes.setPlainText(self.sites.sites.get(sid, {}).get("notes", ""))
        self.site_notes.blockSignals(False)

    def save_site_notes(self):
        sid = self.selected_site() or self.sites.current
        if sid in self.sites.sites:
            self.sites.update(sid, notes=self.site_notes.toPlainText())

    def switch_selected_site(self):
        sid = self.selected_site()
        if sid:
            self.switch_site(sid)

    def rename_selected_site(self):
        sid = self.selected_site() or self.sites.current
        name, ok = QInputDialog.getText(self, "Rename site", "Name:", text=self.sites.name(sid))
        if ok and name.strip():
            self.sites.rename(sid, name.strip())
            self.update_site_button()

    def claim_network(self):
        """Tie this network's router to the selected site (e.g. after NetScan made a new site for it)."""
        sid = self.selected_site()
        mac = getattr(self, "current_router", None)
        if not sid or not mac:
            QMessageBox.information(self, "NetScan", "Select a site, and be connected to the network (its router "
                                                     "must answer).")
            return
        self.sites.assign_router(sid, mac)
        self.switch_site(sid)

    def delete_selected_site(self):
        sid = self.selected_site()
        if not sid or sid == HOME:
            QMessageBox.information(self, "NetScan", "Select a client site to delete (Home can't be deleted).")
            return
        if QMessageBox.question(self, "Delete site", f"Delete “{self.sites.name(sid)}” and its device list and "
                                                      "saved scans? This can't be undone.") != QMessageBox.Yes:
            return
        if sid == self.sites.current:
            self.switch_site(HOME)
        self.sites.remove(sid)
        self.update_site_button()

    # ---- site audit ------------------------------------------------------------------------------

    def build_audit_panel(self):
        w, lay = _panel("Site audit", "A report of this client network to hand over or file: network details, "
                                      "security findings, every device with its open ports, services, Wi-Fi and "
                                      "(optionally) the outbound firewall test, under your company's name. Uses "
                                      "your latest scan: find hosts with “Also scan top 100 ports” first.")
        form = QHBoxLayout()
        self.audit_company = QLineEdit(self.settings.value("audit_company", "", type=str))
        self.audit_company.setPlaceholderText("Your company")
        self.audit_tech = QLineEdit(self.settings.value("audit_tech", "", type=str))
        self.audit_tech.setPlaceholderText("Technician")
        self.audit_logo = QLineEdit(self.settings.value("audit_logo", "", type=str))
        self.audit_logo.setPlaceholderText("Logo image (optional)")
        browse = QPushButton("Logo…")
        browse.clicked.connect(self.pick_audit_logo)
        for edit, key in ((self.audit_company, "audit_company"), (self.audit_tech, "audit_tech"),
                          (self.audit_logo, "audit_logo")):
            edit.textChanged.connect(lambda v, k=key: self.settings.setValue(k, v))
            form.addWidget(edit, 1)
        form.addWidget(browse)
        lay.addLayout(form)
        row = QHBoxLayout()
        self.audit_fw = QCheckBox("Include the outbound firewall test (about 15 s)")
        self.audit_fw.setChecked(True)
        self.audit_btn = QPushButton("Create audit…")
        self.audit_btn.setObjectName("primary")
        self.audit_btn.clicked.connect(self.run_audit)
        csv_btn = QPushButton("Export inventory CSV…")
        csv_btn.setToolTip("Every device this site has seen, in columns documentation tools (IT Glue, Hudu…) import")
        csv_btn.clicked.connect(self.export_inventory)
        row.addWidget(self.audit_fw)
        row.addStretch(1)
        row.addWidget(csv_btn)
        row.addWidget(self.audit_btn)
        lay.addLayout(row)
        self.audit_note = QLabel("")
        self.audit_note.setObjectName("muted")
        self.audit_note.setWordWrap(True)
        lay.addWidget(self.audit_note)
        lay.addStretch(1)
        return w

    def pick_audit_logo(self):
        path, _ = QFileDialog.getOpenFileName(self, "Company logo", os.path.expanduser("~"),
                                              "Images (*.png *.jpg *.jpeg *.svg *.gif *.webp)")
        if path:
            self.audit_logo.setText(path)

    def run_audit(self):
        if not self.hosts:
            QMessageBox.information(self, "NetScan", "Find hosts on the Scan tab first (tick “Also scan top 100 "
                                                     "ports” for a complete audit).")
            return
        net = self.current or self.watch_target()
        ips = sorted(ip for ip in self.hosts if ":" not in ip and ip != (net or {}).get("local_ip"))
        known = [(ip, p["port"]) for ip in ips for p in self.ports.get(ip) or [] if p.get("title")]
        include_fw = self.audit_fw.isChecked()
        self.audit_btn.setEnabled(False)
        self.audit_note.setText("Gathering: security checks, services, Wi-Fi, public address"
                                + (", outbound firewall" if include_fw else "") + "…")

        def gather():
            out = {"security": security_measure(), "dns": dns_servers()}
            try:
                out["services"] = find_services(net["local_ip"], ips, known, net["network"]) if net else []
            except OSError:
                out["services"] = []
            try:
                out["wifi"] = wifi_scan()
            except OSError:
                out["wifi"] = []
            try:
                trace = cloudflare_trace()
                from .probes import ip_owner
                out["public"] = f"{trace.get('ip', '')} ({ip_owner(trace['ip'])[0]}, {trace.get('loc', '')})"
            except (OSError, ValueError, KeyError):
                out["public"] = ""
            out["firewall"] = firewall_test() if include_fw else None
            return out

        self.worker.run("wk:audit", gather)

    def audit_gathered(self, g):
        sec = security_checkup(self.security_context(g["security"]))
        speed = self.latest_speed(days=1)
        gw = self.gateway()
        router = self.hosts.get(gw) if gw else None
        dhcp = [s for s in getattr(self, "last_dhcp", [])]
        data = {"client": self.sites.name(), "company": self.audit_company.text().strip(),
                "technician": self.audit_tech.text().strip(), "logo": logo_data_uri(self.audit_logo.text().strip()),
                "when": datetime.datetime.now().strftime("%d %b %Y, %H:%M"), "network": self.report_data(),
                "security": sec, "networks": self.networks, "dns": g["dns"], "dhcp": dhcp,
                "router": " · ".join(x for x in (self.monitor_label(gw) if router else "", router["vendor"] if router else "",
                                                 router["mac"] if router else "") if x),
                "public": g["public"], "wifi": g["wifi"], "speed": speed, "services": g["services"],
                "firewall": g["firewall"], "firewall_findings": firewall_findings(g["firewall"]) if g["firewall"] else [],
                "notes": self.sites.sites[self.sites.current].get("notes", "")}
        page = build_audit(data)
        name = "".join(c if c.isalnum() else "-" for c in self.sites.name()).strip("-").lower() or "site"
        default = os.path.join(os.path.expanduser("~"), f"network-audit-{name}-{time.strftime('%Y-%m-%d')}.html")
        path, _ = QFileDialog.getSaveFileName(self, "Save site audit", default, "Web page (*.html)")
        if not path:
            self.audit_note.setText("Not saved.")
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(page)
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        self.audit_note.setText(f"Saved {path}. To make a PDF, print it from the browser.")

    def export_inventory(self):
        name = "".join(c if c.isalnum() else "-" for c in self.sites.name()).strip("-").lower() or "site"
        default = os.path.join(os.path.expanduser("~"), f"inventory-{name}-{time.strftime('%Y-%m-%d')}.csv")
        path, _ = QFileDialog.getSaveFileName(self, "Export inventory", default, "CSV (*.csv)")
        if not path:
            return
        gw = self.gateway()

        def kind(key, d):
            return DEVICE_TYPES[self.devices.device_type({"mac": key if not key.startswith("ip:") else "",
                                                          "ip": d.get("ip", "")}, None, gw)[0]]

        def ports(d):
            return ", ".join(port_label(p) for p in d.get("ports") or [] if isinstance(p, dict))

        rows = inventory_rows(self.devices.devices, kind, ports)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(INVENTORY_COLUMNS)
            w.writerows(rows)
        self.audit_note.setText(f"Saved {len(rows)} device(s) to {path}.")

    # ---- firewall test -----------------------------------------------------------------------------

    def build_firewall_panel(self):
        w, lay = _panel("Firewall test", "Which outgoing ports this network lets through: web, mail, remote access, "
                                         "VPN, VoIP and more, tested against portquiz.net (a public server that "
                                         "answers on every port), plus UDP and NAT behaviour for calls.")
        self.fw_btn, self.fw_note = self._run_row(lay, "Test (about 15 seconds)", self.run_firewall)
        self.fw_out = QTextBrowser()
        self.fw_out.setMaximumHeight(220)
        lay.addWidget(self.fw_out)
        self.fw_table = _table(["Category", "Port", "Used by", "Outbound"], stretch_col=2)
        lay.addWidget(self.fw_table, 1)
        return w

    def run_firewall(self):
        self.fw_btn.setEnabled(False)
        self.fw_note.setText("Testing…")
        self.worker.run("wk:firewall", firewall_test)

    def show_firewall(self, res):
        self.fw_out.setHtml(findings_html(firewall_findings(res)))
        t = self.fw_table
        t.setRowCount(len(res["tcp"]))
        for i, (cat, port, what, st) in enumerate(res["tcp"]):
            _set_row(t, i, [cat, port, what, st], {3: T.GREEN if st == "open" else T.AMBER})
        t.resizeColumnsToContents()
        blocked = sum(1 for r in res["tcp"] if r[3] != "open")
        self.fw_note.setText(f"{len(res['tcp']) - blocked} of {len(res['tcp'])} ports open outbound · UDP "
                             f"{'works' if res['nat']['udp'] else 'blocked'} · tested {time.strftime('%H:%M')}")

    # ---- VoIP readiness ------------------------------------------------------------------------------

    def build_voip_panel(self):
        w, lay = _panel("VoIP readiness", "Whether this network is ready for business phone calls: an estimated "
                                          "call-quality score (MOS, the 1 to 5 scale phone systems use), SIP ports, "
                                          "UDP and NAT behaviour, bufferbloat and upload from your latest speed "
                                          "test. Takes 15 seconds.")
        self.voip_btn, self.voip_note = self._run_row(lay, "Test", self.run_voip)
        self.voip_head = QLabel("")
        self.voip_head.setObjectName("bigName")
        lay.addWidget(self.voip_head)
        self.voip_out = QTextBrowser()
        lay.addWidget(self.voip_out, 1)
        return w

    def run_voip(self):
        self.voip_btn.setEnabled(False)
        self.voip_head.setText("")
        self.voip_note.setText("Measuring for 15 seconds…")
        self.worker.run("wk:voip", voip_check)

    def show_voip(self, res):
        speed = self.latest_speed()
        findings, mos = voip_findings(res, speed)
        worst = next((lvl for lvl in ("bad", "warn") if any(f[0] == lvl for f in findings)), "good")
        self.voip_head.setText(f"Call quality {mos:.1f} / 5" if mos is not None else "Calls won't work")
        self.voip_head.setStyleSheet(f"color: {level_color(worst)};")
        self.voip_note.setText("Speed and bufferbloat from your latest speed test." if speed else
                               "Run a speed test (Internet tab) to include upload and bufferbloat.")
        self.voip_out.setHtml(findings_html(findings))

    # ---- bulk domain check ------------------------------------------------------------------------

    def build_bulk_panel(self):
        w, lay = _panel("Domain check (bulk)", "Many client domains at once: who hosts their email (and whether "
                                               "Microsoft 365 knows the domain), SPF, DMARC, DKIM, when the domain "
                                               "and website certificate expire. One domain per line.")
        row = QHBoxLayout()
        self.bulk_edit = QPlainTextEdit(self.settings.value("bulk_domains", "", type=str))
        self.bulk_edit.setPlaceholderText("client1.com\nclient2.co.uk\n…")
        self.bulk_edit.setMaximumHeight(110)
        self.bulk_edit.textChanged.connect(lambda: self.settings.setValue("bulk_domains", self.bulk_edit.toPlainText()))
        side = QHBoxLayout()
        self.bulk_btn = QPushButton("Check all")
        self.bulk_btn.setObjectName("primary")
        self.bulk_btn.clicked.connect(self.run_bulk)
        export = QPushButton("Export CSV…")
        export.clicked.connect(self.export_bulk)
        side.addWidget(export)
        side.addWidget(self.bulk_btn)
        row.addWidget(self.bulk_edit, 1)
        row.addLayout(side)
        lay.addLayout(row)
        self.bulk_note = QLabel("")
        self.bulk_note.setObjectName("muted")
        lay.addWidget(self.bulk_note)
        self.bulk_table = _table(["Domain", "Email", "Microsoft 365", "SPF", "DMARC", "DKIM", "Domain expires",
                                  "Web cert", "Issues"], stretch_col=8)
        lay.addWidget(self.bulk_table, 1)
        self.bulk_rows = []
        return w

    def run_bulk(self):
        domains = [d for d in self.bulk_edit.toPlainText().replace(",", "\n").split() if "." in d]
        if not domains:
            return
        self.bulk_btn.setEnabled(False)
        self.bulk_note.setText(f"Checking {len(domains)} domain(s), about 3 seconds each (4 at a time)…")
        self.worker.run("wk:bulk", bulk_domains, domains)

    def show_bulk(self, rows):
        self.bulk_rows = rows
        t = self.bulk_table
        t.setRowCount(len(rows))
        worst_total = 0
        for i, r in enumerate(rows):
            issues = domain_issues(r)
            worst = next((lvl for lvl in ("bad", "warn") if any(x[0] == lvl for x in issues)), "good")
            worst_total += worst != "good"
            tenant = r["m365"]
            spf = {"-": "-all (strict)", "~": "~all (soft)", "?": "?all", "+": "+all (open!)"}.get(r["spf_all"], "")
            _set_row(t, i, [r["domain"], r["provider"], f"yes ({tenant[1] or tenant[0]})" if tenant else "",
                            spf if r["spf"] else "missing", r["dmarc"] or "missing",
                            ", ".join(r["dkim"][:3]) or "—", r["expires"] or "?",
                            "—" if r["cert_days"] is None else f"{r['cert_days']} days",
                            "; ".join(x[1] for x in issues) or "OK"],
                     {8: level_color(worst), 3: T.RED if not r["spf"] else T.TEXT,
                      4: T.RED if not r["dmarc"] else T.AMBER if r["dmarc"] == "none" else T.TEXT})
        t.resizeColumnsToContents()
        self.bulk_note.setText(f"{len(rows)} domain(s) checked, {worst_total} with something to fix.")

    def export_bulk(self):
        if not self.bulk_rows:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export domain check",
                                              os.path.join(os.path.expanduser("~"), "domain-check.csv"), "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Domain", "Email provider", "Microsoft 365", "MX", "SPF", "DMARC policy", "DKIM selectors",
                        "Registrar", "Domain expires", "Web certificate days", "Issues"])
            for r in self.bulk_rows:
                w.writerow([r["domain"], r["provider"], (r["m365"] or ("", ""))[1] or (r["m365"] or ("",))[0],
                            " ".join(r["mx"]), r["spf"], r["dmarc"], " ".join(r["dkim"]), r["registrar"],
                            r["expires"], "" if r["cert_days"] is None else r["cert_days"],
                            "; ".join(x[1] for x in domain_issues(r))])
        self.bulk_note.setText(f"Saved {path}")

    # ---- mail server check ----------------------------------------------------------------------------

    def build_mail_panel(self):
        w, lay = _panel("Mail server check", "A domain's mail servers (or any server's IP address): do they answer, "
                                             "offer encryption (STARTTLS), have valid reverse DNS, and are they on any "
                                             "of 14 spam blocklists? The domain itself is checked against domain "
                                             "blocklists too.")
        row = QHBoxLayout()
        self.mail_edit = QLineEdit()
        self.mail_edit.setPlaceholderText("client.com or 203.0.113.25")
        self.mail_edit.returnPressed.connect(self.run_mail)
        self.mail_btn = QPushButton("Check")
        self.mail_btn.setObjectName("primary")
        self.mail_btn.clicked.connect(self.run_mail)
        row.addWidget(self.mail_edit, 1)
        row.addWidget(self.mail_btn)
        lay.addLayout(row)
        self.mail_out = QTextBrowser()
        lay.addWidget(self.mail_out, 1)
        return w

    def run_mail(self):
        target = self.mail_edit.text().strip()
        if not target or not all(c.isalnum() or c in ".-" for c in target):
            return
        self.mail_btn.setEnabled(False)
        self.mail_out.setHtml(f'<p style="color:{T.MUTED}">Checking mail servers and blocklists (up to 30 seconds)…</p>')
        self.worker.run("wk:mail", mail_check, target)

    def show_mail(self, res):
        servers = ", ".join(f"{s['host']} ({', '.join(s['ips'][:2])})" for s in res["servers"])
        self.mail_out.setHtml(f"<p><b>{html.escape(res['target'])}</b>: {html.escape(servers)}</p>"
                              + findings_html(mail_findings(res)))

    # ---- DNS propagation ------------------------------------------------------------------------------

    def build_prop_panel(self):
        w, lay = _panel("DNS propagation", "Has a DNS change reached the world? Asks 20 public DNS servers around "
                                           "the world, and the domain's own name servers for the true answer. Put "
                                           "the new value in “Expected” to see exactly who has it.")
        row = QHBoxLayout()
        self.prop_name = QLineEdit()
        self.prop_name.setPlaceholderText("www.client.com")
        self.prop_name.returnPressed.connect(self.run_prop)
        self.prop_type = QComboBox()
        self.prop_type.addItems(list(DNS_TYPES))
        self.prop_expected = QLineEdit()
        self.prop_expected.setPlaceholderText("Expected (optional), e.g. 203.0.113.10")
        self.prop_btn = QPushButton("Check")
        self.prop_btn.setObjectName("primary")
        self.prop_btn.clicked.connect(self.run_prop)
        row.addWidget(self.prop_name, 2)
        row.addWidget(self.prop_type)
        row.addWidget(self.prop_expected, 2)
        row.addWidget(self.prop_btn)
        lay.addLayout(row)
        self.prop_head = QLabel("")
        self.prop_head.setObjectName("bigName")
        self.prop_head.setWordWrap(True)
        lay.addWidget(self.prop_head)
        self.prop_note = QLabel("")
        self.prop_note.setObjectName("muted")
        self.prop_note.setWordWrap(True)
        lay.addWidget(self.prop_note)
        self.prop_table = _table(["Resolver", "Where", "Answer", "Time", "Via", ""], stretch_col=2)
        lay.addWidget(self.prop_table, 1)
        return w

    def run_prop(self):
        name = self.prop_name.text().strip()
        if not name or not all(c.isalnum() or c in ".-_" for c in name):
            return
        self.prop_btn.setEnabled(False)
        self.prop_head.setText("")
        self.prop_note.setText("Asking 20 resolvers…")
        self.worker.run("wk:prop", propagation, name, self.prop_type.currentText())

    def show_prop(self, res):
        expected = self.prop_expected.text().strip().rstrip(".").lower()
        truth, agree, answered = propagation_summary(res)
        auth = res["authoritative"]
        t = self.prop_table
        t.setRowCount(len(res["rows"]))
        matches = 0
        for i, (label, where, answer, ms, via, error) in enumerate(res["rows"]):
            if answer is None:
                _set_row(t, i, [label, where, error, "", "", ""], {2: T.MUTED})
                continue
            text = ", ".join(answer) or "(no record)"
            if expected:
                ok = any(expected == a.lower() or expected in a.lower().split() for a in answer)
            else:
                ok = truth is not None and answer == truth
            matches += ok
            _set_row(t, i, [label, where, text, f"{ms:.0f} ms", via, "✓" if ok else "differs"],
                     {5: T.GREEN if ok else T.AMBER})
        t.resizeColumnsToContents()
        if expected:
            self.prop_head.setText(f"{matches} of {answered} resolvers have {expected}")
            self.prop_head.setStyleSheet(f"color: {level_color('good' if matches == answered else 'warn')};")
        else:
            self.prop_head.setText(f"{agree} of {answered} resolvers give "
                                   + ("the authoritative answer" if auth else "the most common answer"))
            self.prop_head.setStyleSheet(f"color: {level_color('good' if agree == answered else 'warn')};")
        notes = []
        if auth:
            notes.append(f"Authoritative ({auth['server']}): {', '.join(auth['answer']) or '(no record)'}.")
        else:
            notes.append("The domain's own name servers couldn't be asked from this network (outgoing DNS is "
                         "blocked here), so the most common answer is shown as the reference.")
        if not expected and agree < answered:
            notes.append("Answers that differ are normal for big sites that load-balance (each resolver is given a "
                         "different server). For a record you just changed, put the new value in Expected. Old "
                         "answers clear once their cache time (TTL) runs out.")
        if any(r[4] == "HTTPS" for r in res["rows"]):
            notes.append("Some resolvers were asked over HTTPS because this network blocks outgoing DNS.")
        self.prop_note.setText(" ".join(notes))

    # ---- copy for ticket -------------------------------------------------------------------------------

    def copy_for_ticket(self):
        """Copy what's on screen (the current tool, or the current tab) as plain text for a ticket."""
        tab = self.tabbar.currentIndex()
        if tab == 5 and self.tool_nav.currentItem():
            title, widget = self.tool_nav.currentItem().text(), self.tool_stack.currentWidget()
        else:
            title, widget = self.tabbar.tabText(tab), self.pages.currentWidget()
        body = widget_text(widget)
        if tab == 0 and self.summary:
            body = self.summary.strip() + "\n\n" + body
        head = (f"NetScan · {title} · site {self.sites.name()} · "
                f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
        QGuiApplication.clipboard().setText(f"{head}\n{'=' * len(head)}\n{body}\n")
        self.status.setText(f"Copied “{title}” for a ticket ({len(body.splitlines())} lines).")

    # ---- results from the background worker -----------------------------------------------------------

    def work_done(self, tag, res):
        failed = isinstance(res, Exception)
        why = html.escape(str(res)) if failed else ""
        if tag == "site":
            if not failed:
                self.site_detected(*res)
        elif tag == "audit":
            self.audit_btn.setEnabled(True)
            if failed:
                self.audit_note.setText(f"⚠ {res}")
            else:
                self.audit_gathered(res)
        elif tag == "firewall":
            self.fw_btn.setEnabled(True)
            if failed:
                self.fw_note.setText(f"⚠ {res}")
            else:
                self.show_firewall(res)
        elif tag == "voip":
            self.voip_btn.setEnabled(True)
            if failed:
                self.voip_out.setHtml(f'<p style="color:{T.AMBER}">⚠ {why}</p>')
            else:
                self.show_voip(res)
        elif tag == "bulk":
            self.bulk_btn.setEnabled(True)
            if failed:
                self.bulk_note.setText(f"⚠ {res}")
            else:
                self.show_bulk(res)
        elif tag == "mail":
            self.mail_btn.setEnabled(True)
            if failed:
                self.mail_out.setHtml(f'<p style="color:{T.AMBER}">⚠ {why}</p>')
            else:
                self.show_mail(res)
        elif tag == "prop":
            self.prop_btn.setEnabled(True)
            if failed:
                self.prop_note.setText(f"⚠ {res}")
            else:
                self.show_prop(res)
