"""Saving, comparing and exporting scans; closing."""

import csv
import datetime
import json
import os
import re
import socket

from PySide6.QtCore import (
    QProcess, QUrl,
)
from PySide6.QtGui import (
    QDesktopServices, QGuiApplication,
)
from PySide6.QtWidgets import (
    QFileDialog, QMessageBox,
)

from .columns import COLUMNS, COL_CHANGE, COL_IP
from .devices import DEVICE_TYPES, list_history, risky
from .report import build_report
from .scanning import compare_scans, ip_sort_key


class ExportMixin:
    """Saving, comparing and exporting scans; closing. Mixed into MainWindow."""

    # ---- save / compare / export ------------------------------------------

    def scan_record(self):
        return {
            "netscan": 1,
            "saved": datetime.datetime.now().isoformat(timespec="seconds"),
            "target": self.last_target,
            "hosts": [{**h, "ports": self.network_ports(ip) if ip in self.ports else None} for ip, h in
                      sorted(self.hosts.items(), key=lambda kv: ip_sort_key(kv[0]))],
        }

    def default_name(self, ext):
        stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
        target = re.sub(r"[^0-9A-Za-z.-]+", "_", self.last_target).strip("_") or "scan"
        return f"netscan_{target}_{stamp}.{ext}"

    def save_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save scan", self.default_name("json"),
                                              "NetScan scan (*.json)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.scan_record(), f, indent=2)
        self.status.setText(f"Saved {len(self.hosts)} host(s) to {path}")

    def build_compare_menu(self):
        """Recent scans (kept automatically) plus 'From file…'."""
        menu = self.compare_menu
        menu.clear()
        today = datetime.date.today()
        entries = [(path, info) for path, info in list_history() if path != self.history_path][:12]
        if entries:
            title = menu.addAction("Recent scans")
            title.setEnabled(False)
        for path, info in entries:
            try:
                when = datetime.datetime.fromisoformat(info["saved"])
                day = ("Today" if when.date() == today else
                       "Yesterday" if when.date() == today - datetime.timedelta(days=1) else
                       when.strftime("%a %d %b"))
                label = f"{day} {when:%H:%M}   {info['target']} · {info['hosts']} host(s)"
            except (TypeError, ValueError):
                label = os.path.basename(path)
            menu.addAction(label, lambda p=path: self.compare_with_file(p))
        if entries:
            menu.addSeparator()
        menu.addAction("From file…", self.compare_with_file)

    def compare_with_file(self, path=None):
        if not path:
            path, _ = QFileDialog.getOpenFileName(self, "Compare with saved scan", "",
                                                  "NetScan scan (*.json)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                record = json.load(f)
            baseline = record["hosts"]
        except (OSError, ValueError, KeyError, TypeError) as e:
            QMessageBox.warning(self, "NetScan", f"Could not read scan file:\n{e}")
            return
        changes, gone = compare_scans(baseline, self.hosts,
                                      {ip: self.network_ports(ip) for ip in self.ports})
        self.table.setColumnHidden(COL_CHANGE, False)
        for row in range(self.table.rowCount()):
            self.set_change(row, changes.get(self.table.item(row, COL_IP).text(), ""))
        self.apply_filter()

        new = sum(1 for c in changes.values() if c == "NEW")
        changed = sum(1 for c in changes.values() if c and c != "NEW")
        self.summary = (f"Compared with scan from {record.get('saved', '?')}: "
                        f"{new} new, {changed} changed, {len(gone)} missing.")
        self.update_status()
        if gone:
            lines = [f"{h['ip']:15}  {h.get('hostname') or '-':20}  {h.get('mac') or ''}"
                     for h in gone]
            box = QMessageBox(self)
            box.setWindowTitle("NetScan: hosts no longer seen")
            box.setText(f"{len(gone)} host(s) from the saved scan were not found this time:")
            box.setDetailedText("\n".join(lines))
            box.exec()

    def report_data(self):
        """Everything the HTML report shows, as plain data."""
        me, any_trusted = self.local_ip(), self.devices.any_trusted()
        hosts = []
        for ip, h in sorted(self.hosts.items(), key=lambda kv: ip_sort_key(kv[0])):
            rec = self.devices.get(h)
            ports = self.ports.get(ip)
            shown = self.network_ports(ip) if ip in self.ports else None
            kind = self.devices.device_type(h, ports, self.gateway())[0]
            hosts.append({
                "ip": ip, "nickname": rec.get("nickname", ""), "hostname": h["hostname"], "mac": h["mac"],
                "vendor": h["vendor"], "os": h.get("os", ""), "type": DEVICE_TYPES[kind],
                "identified": self.identified(h, ports)[0], "ports": shown, "all_ports": ports or [],
                "risky": risky(shown), "upnp": h.get("upnp") or [], "this": ip == me,
                "new": h["mac"] in self.new_devices, "notes": rec.get("notes", ""),
                "untrusted": any_trusted and bool(h["mac"]) and ip != me and not rec.get("trusted"),
                "label": rec.get("nickname") or h["hostname"] or ip,
            })
        return {"network": self.last_target, "when": datetime.datetime.now().strftime("%d %b %Y, %H:%M"),
                "scanner": f"{socket.gethostname()} ({me})" if me else socket.gethostname(),
                "upnp": self.upnp, "hosts": hosts, "spoof": self.spoof_warnings}

    def export_report(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save network report", self.default_name("html"),
                                              "Web page (*.html)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(build_report(self.report_data()))
        self.status.setText(f"Saved the network report to {path}")
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", self.default_name("csv"), "CSV (*.csv)")
        if not path:
            return
        cols = [c for c in range(len(COLUMNS)) if not self.table.isColumnHidden(c)]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([COLUMNS[c] for c in cols])
            for r in range(self.table.rowCount()):
                w.writerow([self.table.item(r, c).text() for c in cols])
        self.status.setText(f"Saved {self.table.rowCount()} host(s) to {path}")

    def export_xml(self):
        if not self.last_xml:
            QMessageBox.information(self, "NetScan", "No nmap output yet.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export nmap XML", self.default_name("xml"),
                                              "nmap XML (*.xml)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.last_xml[self.last_xml.find("<?xml"):] if "<?xml" in self.last_xml
                    else self.last_xml)
        self.status.setText(f"Saved raw nmap output to {path}")

    def copy_selection(self):
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        cols = [c for c in range(len(COLUMNS)) if not self.table.isColumnHidden(c)]
        lines = ["\t".join(self.table.item(r, c).text() for c in cols) for r in rows]
        QGuiApplication.clipboard().setText("\n".join(lines))

    def closeEvent(self, event):
        self.mon_timer.stop()
        self.uptime_timer.stop()
        self.save_notes()
        self.save_settings()
        if self.watch_proc is not None and self.watch_proc.state() != QProcess.NotRunning:
            self.watch_proc.kill()
        if self.is_running():
            self.proc.kill()
        super().closeEvent(event)
