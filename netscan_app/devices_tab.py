"""Devices tab: remembered devices, details, Wake-on-LAN, export/import."""

import datetime
import getpass
import html
import json

from PySide6.QtCore import (
    QTimer, Qt,
)
from PySide6.QtGui import (
    QColor, QFont, QGuiApplication, QIcon,
)
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLabel,
    QLineEdit, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy,
    QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from . import theme as T
from .columns import (
    COL_NAME, DEV_COLUMNS, DEV_HOST, DEV_IP, DEV_MAC, DEV_NAME, DEV_SEEN, DEV_STATUS, DEV_TRUST,
    DEV_TYPE, DEV_VENDOR, WATCH_INTERVALS,
)
from .devices import DEVICE_TYPES, guess_type, label_risky, port_risk, risky
from .scanning import parse_mac, port_label, valid_ssh_user
from .system import now_iso, relative_time, terminal_argv, wake_on_lan
from .theme import icon_path, make_card
from .widgets import HistoryGrid, IPItem, RowHover, SortItem


class DevicesMixin:
    """Devices tab: remembered devices, details, Wake-on-LAN, export/import. Mixed into MainWindow."""

    # ---- devices tab -------------------------------------------------------

    def build_devices_page(self):
        # Watch card: background re-scans that notify about new devices and port changes
        self.watch_combo = QComboBox()
        for label, _ in WATCH_INTERVALS:
            self.watch_combo.addItem(label)
        self.watch_label = QLabel("Off")
        self.watch_label.setObjectName("muted")
        self.watch_now_btn = QPushButton("Check now")
        self.watch_now_btn.clicked.connect(self.watch_scan)
        self.watch_ports_box = QCheckBox("Also alert on port changes")
        self.watch_ports_box.setToolTip("Each check also scans the top 100 ports and notifies you when a "
                                        "known device opens or closes one. Takes a few seconds longer.")
        hint = QLabel("Quietly re-checks your network and sends a desktop notification when a "
                      "device NetScan has never seen joins. No password needed; runs while NetScan is open.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        watch, wl, _ = make_card("Watch for new devices")
        row = QHBoxLayout()
        row.addWidget(self.watch_combo)
        row.addWidget(self.watch_now_btn)
        row.addSpacing(8)
        row.addWidget(self.watch_ports_box)
        row.addStretch(1)
        wl.addLayout(row)
        wl.addWidget(self.watch_label)
        wl.addWidget(hint)

        # Wake-any-MAC card, for devices NetScan has never seen
        self.mac_edit = QLineEdit()
        self.mac_edit.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        self.mac_edit.returnPressed.connect(self.wake_typed_mac)
        mac_btn = QPushButton("Wake")
        mac_btn.setObjectName("primary")
        mac_btn.clicked.connect(self.wake_typed_mac)
        hint = QLabel("For a device not in the list. It needs Wake-on-LAN enabled in its "
                      "BIOS or network settings.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        wake_any, al, _ = make_card("Wake by MAC address")
        row = QHBoxLayout()
        row.addWidget(self.mac_edit, 1)
        row.addWidget(mac_btn)
        al.addLayout(row)
        al.addWidget(hint)
        al.addStretch(1)

        # Known devices card
        self.dev_count = QLabel("")
        self.dev_count.setObjectName("pill")
        self.dev_count.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Preferred)
        self.dev_filter = QLineEdit()
        self.dev_filter.setPlaceholderText("Filter by name, type, MAC, vendor, IP…")
        self.dev_filter.setClearButtonEnabled(True)
        self.dev_search_act = self.dev_filter.addAction(QIcon(icon_path("search")), QLineEdit.LeadingPosition)
        self.dev_filter.setMaximumWidth(380)
        self.dev_filter.textChanged.connect(self.filter_devices)
        self.dev_show = QComboBox()
        for label in ("All devices", "Online now", "Untrusted", "With risky ports"):
            self.dev_show.addItem(label)
        self.dev_show.currentIndexChanged.connect(self.filter_devices)

        self.dev_table = QTableWidget(0, len(DEV_COLUMNS))
        RowHover(self.dev_table)
        self.dev_table.setHorizontalHeaderLabels([c.upper() for c in DEV_COLUMNS])
        self.dev_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.dev_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.dev_table.setAlternatingRowColors(True)
        self.dev_table.setShowGrid(False)
        self.dev_table.verticalHeader().setVisible(False)
        self.dev_table.verticalHeader().setDefaultSectionSize(34)
        header = self.dev_table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setHighlightSections(False)
        header.setStretchLastSection(True)
        header.setSortIndicator(DEV_STATUS, Qt.AscendingOrder)  # online devices first
        self.dev_table.setSortingEnabled(True)
        self.dev_table.itemSelectionChanged.connect(self.device_selection_changed)
        self.dev_table.itemDoubleClicked.connect(lambda _item: self.rename_device())
        self.dev_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.dev_table.customContextMenuRequested.connect(self.device_menu)

        self.dev_wake_btn = QPushButton("Wake")
        self.dev_wake_btn.setObjectName("primary")
        self.dev_wake_btn.setToolTip("Send a Wake-on-LAN packet to the selected device(s)")
        self.dev_wake_btn.clicked.connect(self.wake_selected_devices)
        self.dev_rename_btn = QPushButton("Rename…")
        self.dev_rename_btn.clicked.connect(self.rename_device)
        self.dev_forget_btn = QPushButton("Forget")
        self.dev_forget_btn.setToolTip("Remove from the list; it will count as new if seen again")
        self.dev_forget_btn.clicked.connect(self.forget_devices)

        export_btn = QPushButton("Export…")
        export_btn.setToolTip("Save the device list (names, notes, trusted, history) to a file")
        export_btn.clicked.connect(self.export_devices)
        import_btn = QPushButton("Import…")
        import_btn.setToolTip("Merge a device list exported from NetScan on another computer")
        import_btn.clicked.connect(self.import_devices)
        known, kl, kh = make_card("Known devices")
        kh.addWidget(self.dev_count)
        kh.addStretch(1)
        kh.addWidget(self.dev_show)
        kh.addWidget(self.dev_filter, 1)
        kl.addWidget(self.dev_table, 1)
        row = QHBoxLayout()
        row.addWidget(self.dev_wake_btn)
        row.addWidget(self.dev_rename_btn)
        row.addWidget(self.dev_forget_btn)
        row.addSpacing(12)
        row.addWidget(export_btn)
        row.addWidget(import_btn)
        row.addStretch(1)
        tip = QLabel("Double-click to rename")
        tip.setObjectName("muted")
        row.addWidget(tip)
        kl.addLayout(row)

        self.dev_split = QSplitter(Qt.Horizontal)
        self.dev_split.setHandleWidth(12)
        self.dev_split.addWidget(known)
        self.dev_split.addWidget(self.build_device_details())
        self.dev_split.setStretchFactor(0, 3)
        self.dev_split.setStretchFactor(1, 2)
        self.dev_split.setSizes([700, 380])

        top = QHBoxLayout()
        top.setSpacing(12)
        top.addWidget(watch, 3)
        top.addWidget(wake_any, 2)
        page = QWidget()
        pl = QVBoxLayout(page)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.setSpacing(12)
        pl.addLayout(top)
        pl.addWidget(self.dev_split, 1)
        self.update_device_buttons()
        return page

    def build_device_details(self):
        """Right-hand panel: everything known about the selected device, plus notes."""
        card, cl, _ = make_card("Device details")
        self.detail_stack = QStackedWidget()
        empty = QLabel("Select a device to see its details, online history and notes.")
        empty.setObjectName("muted")
        empty.setWordWrap(True)
        empty.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.detail_stack.addWidget(empty)

        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(0, 0, 6, 0)
        bl.setSpacing(10)
        self.detail_icon = QLabel()
        self.detail_name = QLabel()
        self.detail_name.setObjectName("bigName")
        self.detail_name.setWordWrap(True)
        self.detail_sub = QLabel()
        self.detail_sub.setObjectName("muted")
        self.detail_sub.setWordWrap(True)
        names = QVBoxLayout()
        names.setSpacing(0)
        names.addWidget(self.detail_name)
        names.addWidget(self.detail_sub)
        head = QHBoxLayout()
        head.addWidget(self.detail_icon, 0, Qt.AlignTop)
        head.addLayout(names, 1)
        bl.addLayout(head)

        self.detail_type = QComboBox()
        self.detail_type.addItem("Auto", "")
        for key, label in DEVICE_TYPES.items():
            if key != "unknown":
                self.detail_type.addItem(QIcon(icon_path("type-" + key)), label, key)
        self.detail_type.currentIndexChanged.connect(self.detail_type_changed)
        self.detail_trusted = QCheckBox("Trusted")
        self.detail_trusted.setToolTip("Once any device is trusted, untrusted ones are highlighted "
                                       "on the Scan tab and can be filtered here.")
        self.detail_trusted.toggled.connect(self.detail_trusted_changed)
        self.detail_important = QCheckBox("Alert when offline")
        self.detail_important.setToolTip("NetScan pings it every 30 s while open and notifies you when it goes "
                                         "down or comes back. Best for servers, NAS, Pis and printers; phones "
                                         "sleep and ignore pings, so they'd look offline.")
        self.detail_important.toggled.connect(self.detail_important_changed)
        row = QHBoxLayout()
        row.addWidget(self.field_label("Type"))
        row.addWidget(self.detail_type, 1)
        row.addSpacing(8)
        row.addWidget(self.detail_trusted)
        row.addWidget(self.detail_important)
        bl.addLayout(row)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(6)
        self.detail_fields = {}
        for i, name in enumerate(("First seen", "Last seen", "IP addresses", "IPv6", "Identified as", "OS",
                                  "Open ports")):
            value = QLabel()
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid.addWidget(self.field_label(name), i, 0, Qt.AlignTop)
            grid.addWidget(value, i, 1)
            self.detail_fields[name] = value
        grid.setColumnStretch(1, 1)
        bl.addLayout(grid)

        bl.addWidget(self.field_label("Online, last 7 days"))
        self.detail_grid = HistoryGrid()
        bl.addWidget(self.detail_grid)
        self.detail_legend = QLabel()
        self.detail_legend.setObjectName("muted")
        bl.addWidget(self.detail_legend)

        bl.addWidget(self.field_label("Uptime alerts"))
        self.detail_uptime = QLabel()
        self.detail_uptime.setWordWrap(True)
        bl.addWidget(self.detail_uptime)

        bl.addWidget(self.field_label("Port changes"))
        self.detail_changes = QLabel()
        self.detail_changes.setWordWrap(True)
        self.detail_changes.setTextInteractionFlags(Qt.TextSelectableByMouse)
        bl.addWidget(self.detail_changes)

        self.detail_ssh = QLineEdit()
        self.detail_ssh.setPlaceholderText(f"{getpass.getuser()} (this computer's username)")
        self.detail_ssh.setToolTip("Username for NetScan's SSH actions on this device")
        self.detail_ssh.editingFinished.connect(self.save_ssh_user)
        row = QHBoxLayout()
        row.addWidget(self.field_label("SSH user"))
        row.addWidget(self.detail_ssh, 1)
        bl.addLayout(row)

        bl.addWidget(self.field_label("Notes"))
        self.detail_notes = QPlainTextEdit()
        self.detail_notes.setPlaceholderText("Anything worth remembering: owner, location, login…")
        self.detail_notes.setFixedHeight(90)
        self.detail_notes.textChanged.connect(lambda: self.notes_timer.start())
        self.notes_timer = QTimer(self)
        self.notes_timer.setSingleShot(True)
        self.notes_timer.setInterval(600)
        self.notes_timer.timeout.connect(self.save_notes)
        bl.addWidget(self.detail_notes)
        bl.addStretch(1)

        scroll = QScrollArea()
        scroll.setObjectName("plain")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(body)
        self.detail_stack.addWidget(scroll)
        cl.addWidget(self.detail_stack, 1)
        self.detail_mac = None
        return card

    @staticmethod
    def field_label(text):
        label = QLabel(text.upper())
        label.setObjectName("fieldLabel")
        return label

    def device_selection_changed(self):
        self.update_device_buttons()
        self.show_device_details()

    def show_device_details(self):
        macs = self.selected_device_macs()
        if len(macs) != 1 or macs[0] not in self.devices.devices:
            self.save_notes()
            self.save_ssh_user()
            self.detail_mac = None
            self.detail_stack.setCurrentIndex(0)
            return
        mac = macs[0]
        if mac != self.detail_mac:
            self.save_notes()  # flush edits to the previous device
            self.save_ssh_user()
        same = mac == self.detail_mac
        self.detail_mac = mac
        d = self.devices.devices[mac]
        kind, guessed = self.devices.device_type(d, gateway=self.gateway())
        online = mac in self.online_macs
        self.detail_icon.setPixmap(self.type_icon(kind).pixmap(28, 28))
        self.detail_name.setText(d.get("nickname") or d.get("hostname") or d.get("vendor") or mac)
        self.detail_sub.setText(" · ".join(x for x in (
            d.get("hostname") if d.get("nickname") else "", d.get("vendor", ""), mac) if x))

        self.detail_type.blockSignals(True)
        self.detail_type.setItemText(0, f"Auto ({DEVICE_TYPES[guess_type(d, d.get('ports'), self.gateway())]})")
        self.detail_type.setCurrentIndex(max(0, self.detail_type.findData(d.get("type", ""))))
        self.detail_type.blockSignals(False)
        self.detail_trusted.blockSignals(True)
        self.detail_trusted.setChecked(bool(d.get("trusted")))
        self.detail_trusted.blockSignals(False)
        self.detail_important.blockSignals(True)
        self.detail_important.setChecked(bool(d.get("important")))
        self.detail_important.blockSignals(False)
        events = d.get("uptime_log", [])[-6:]
        if not d.get("important"):
            self.detail_uptime.setText(f'<span style="color:{T.MUTED}">Off. Tick “Alert when offline” to watch it.</span>')
        elif not events:
            self.detail_uptime.setText(f'<span style="color:{T.MUTED}">Watching; no outages recorded yet.</span>')
        else:
            self.detail_uptime.setText("<br>".join(
                f'<span style="color:{T.MUTED}">{self.when_text(ev["time"])}</span> '
                + (f'<span style="color:{T.AMBER}">went offline</span>' if ev["state"] == "down" else
                   f'<span style="color:{T.GREEN}">back online</span>'
                   + (f" after {ev['downtime']}" if ev.get("downtime") else ""))
                for ev in reversed(events)))

        f = self.detail_fields
        f["First seen"].setText(self.when_text(d.get("first_seen")))
        f["Last seen"].setText(f'<span style="color:{T.GREEN}">Online now</span>' if online
                               else self.when_text(d.get("last_seen")))
        ips = list(reversed(d.get("ips") or [d.get("ip", "")]))
        f["IP addresses"].setText(ips[0] + (f'<br><span style="color:{T.MUTED}">before: '
                                            + ", ".join(ips[1:]) + "</span>" if len(ips) > 1 else ""))
        f["OS"].setText(d.get("os") or f'<span style="color:{T.MUTED}">not detected yet</span>')
        f["IPv6"].setText(", ".join(d.get("ipv6") or []) or f'<span style="color:{T.MUTED}">none seen</span>')
        ident, tip = self.identified(d, d.get("ports"))
        f["Identified as"].setText(html.escape(ident) or f'<span style="color:{T.MUTED}">nothing announced</span>')
        f["Identified as"].setToolTip(tip)
        if not (same and self.detail_ssh.hasFocus()):
            self.detail_ssh.setText(d.get("ssh_user", ""))
        ports = d.get("ports")
        if ports is None:
            f["Open ports"].setText(f'<span style="color:{T.MUTED}">not port-scanned yet</span>')
        elif not ports:
            f["Open ports"].setText(f'<span style="color:{T.MUTED}">none open</span>')
        else:
            f["Open ports"].setText("<br>".join(
                f'<span style="color:{T.AMBER}">⚠ {port_label(p)}</span> '
                f'<span style="color:{T.MUTED}">{port_risk(p)}</span>' if port_risk(p) else port_label(p)
                for p in ports))

        self.detail_grid.set_data(d.get("hours", []), self.devices.checked_hours)
        self.detail_legend.setText(
            f'<span style="color:{T.GREEN}">■</span> seen &nbsp; <span style="color:{T.DIM}">■</span> '
            f'checked, not seen &nbsp; <span style="color:{T.BORDER_HI}">□</span> not checked')
        log = d.get("port_changes", [])[-6:]
        if not log:
            self.detail_changes.setText(f'<span style="color:{T.MUTED}">None recorded yet. Changes show up '
                                        "after this device has been port-scanned twice.</span>")
        else:
            lines = []
            for entry in reversed(log):
                parts = [f'<span style="color:{T.AMBER if label_risky(o) else T.GREEN}">'
                         f"+{o}</span>" for o in entry.get("opened", [])]
                parts += [f'<span style="color:{T.MUTED}">−{c}</span>' for c in entry.get("closed", [])]
                lines.append(f'<span style="color:{T.MUTED}">{self.when_text(entry.get("time"))}</span> '
                             + ", ".join(parts))
            self.detail_changes.setText("<br>".join(lines))
        if not (same and self.detail_notes.hasFocus()):
            self.detail_notes.blockSignals(True)
            self.detail_notes.setPlainText(d.get("notes", ""))
            self.detail_notes.blockSignals(False)
        self.detail_stack.setCurrentIndex(1)

    @staticmethod
    def when_text(iso):
        try:
            when = datetime.datetime.fromisoformat(iso)
        except (TypeError, ValueError):
            return "—"
        return f"{when:%d %b %Y, %H:%M}  ({relative_time(iso)})"

    def save_notes(self):
        self.notes_timer.stop()
        mac = self.detail_mac
        if mac and mac in self.devices.devices:
            text = self.detail_notes.toPlainText().strip()
            if text != self.devices.devices[mac].get("notes", ""):
                self.devices.set_field(self.devices.devices[mac], "notes", text)

    def save_ssh_user(self):
        if self.detail_mac not in self.devices.devices:
            return
        d = self.devices.devices[self.detail_mac]
        name = self.detail_ssh.text().strip()
        if name == d.get("ssh_user", ""):
            return
        if name and not valid_ssh_user(name):
            self.detail_ssh.setText(d.get("ssh_user", ""))
            self.set_dot(T.AMBER)
            self.status.setText("SSH usernames can only contain letters, digits, '.', '_' and '-'.")
            return
        self.devices.set_field(d, "ssh_user", name)
        self.status.setText(f"SSH user for {self.device_label(self.detail_mac) or self.detail_mac}: "
                            + (name or f"{getpass.getuser()} (default)"))

    def detail_type_changed(self):
        if self.detail_mac in self.devices.devices:
            self.devices.set_field(self.devices.devices[self.detail_mac], "type",
                                   self.detail_type.currentData())
            self.after_device_change(self.detail_mac)

    def detail_important_changed(self, on):
        if self.detail_mac in self.devices.devices:
            self.set_important([self.detail_mac], on)

    def detail_trusted_changed(self, on):
        if self.detail_mac:
            self.set_trusted([self.detail_mac], on)

    def refresh_devices(self):
        """Rebuild the devices table from the store, keeping the selection."""
        keep = set(self.selected_device_macs())
        t = self.dev_table
        t.blockSignals(True)
        t.setSortingEnabled(False)
        t.setRowCount(0)
        bold = QFont()
        bold.setBold(True)
        gateway = self.gateway()
        for d in (d for d in self.devices.devices.values() if d.get("mac")):
            row = t.rowCount()
            t.insertRow(row)
            online = d["mac"] in self.online_macs
            dot = SortItem("●")
            dot.setData(Qt.UserRole, "0" if online else "1")
            dot.setForeground(QColor(T.GREEN if online else T.DIM))
            dot.setTextAlignment(Qt.AlignCenter)
            dot.setToolTip("Online (seen in the latest scan)" if online else "Not seen in the latest scan")
            t.setItem(row, DEV_STATUS, dot)
            kind, guessed = self.devices.device_type(d, gateway=gateway)
            fallback = d.get("hostname") or d.get("friendly") or d.get("model") or ""
            values = {DEV_NAME: d.get("nickname") or fallback, DEV_TYPE: DEVICE_TYPES[kind],
                      DEV_HOST: d.get("hostname", ""), DEV_MAC: d["mac"], DEV_VENDOR: d.get("vendor", "")}
            for col, text in values.items():
                t.setItem(row, col, QTableWidgetItem(text))
            t.item(row, DEV_TYPE).setIcon(self.type_icon(kind))
            t.item(row, DEV_TYPE).setToolTip("Guessed; change it in Device details" if guessed else "Set by you")
            if guessed:
                t.item(row, DEV_TYPE).setForeground(QColor(T.MUTED))
            t.setItem(row, DEV_IP, IPItem(d.get("ip", "")))
            trust = SortItem("✓" if d.get("trusted") else "")
            trust.setData(Qt.UserRole, "0" if d.get("trusted") else "1")
            trust.setForeground(QColor(T.GREEN))
            t.setItem(row, DEV_TRUST, trust)
            seen = SortItem("online now" if online else relative_time(d.get("last_seen")))
            seen.setData(Qt.UserRole, d.get("last_seen", ""))
            seen.setForeground(QColor(T.GREEN if online else T.MUTED))
            t.setItem(row, DEV_SEEN, seen)
            bad = risky(d.get("ports"))
            if bad:
                t.item(row, DEV_NAME).setToolTip("Risky ports: " + ", ".join(port_label(p) for p in bad))
                t.item(row, DEV_VENDOR).setData(Qt.UserRole + 1, True)
            if d.get("nickname"):
                t.item(row, DEV_NAME).setFont(bold)
            else:
                t.item(row, DEV_NAME).setForeground(QColor(T.MUTED))
                t.item(row, DEV_NAME).setToolTip(t.item(row, DEV_NAME).toolTip() or "No nickname yet: double-click to name it")
            for col in (DEV_MAC, DEV_IP):
                t.item(row, col).setFont(self.mono)
            if d["mac"] in keep:
                t.selectRow(row)
        t.setSortingEnabled(True)  # re-sorts by the user's column (the online dot by default)
        t.resizeColumnsToContents()
        t.setColumnWidth(DEV_STATUS, 36)
        t.blockSignals(False)
        self.filter_devices()
        self.show_device_details()

    def filter_devices(self):
        text = self.dev_filter.text().strip().lower()
        show = self.dev_show.currentIndex()  # 0 all, 1 online, 2 untrusted, 3 risky
        t = self.dev_table
        shown = online = 0
        for row in range(t.rowCount()):
            is_online = t.item(row, DEV_STATUS).data(Qt.UserRole) == "0"
            online += is_online
            visible = not text or any(text in t.item(row, c).text().lower()
                                      for c in range(1, len(DEV_COLUMNS)))
            if show == 1:
                visible = visible and is_online
            elif show == 2:
                visible = visible and not t.item(row, DEV_TRUST).text()
            elif show == 3:
                visible = visible and bool(t.item(row, DEV_VENDOR).data(Qt.UserRole + 1))
            t.setRowHidden(row, not visible)
            shown += visible
        total = t.rowCount()
        self.dev_count.setText(f"{shown} of {total} shown" if shown != total
                               else f"{total} device(s) · {online} online")
        self.update_device_buttons()

    def selected_device_macs(self):
        t = self.dev_table
        rows = sorted({i.row() for i in t.selectedIndexes()})
        return [t.item(r, DEV_MAC).text() for r in rows if not t.isRowHidden(r)]

    def update_device_buttons(self):
        macs = self.selected_device_macs()
        self.dev_wake_btn.setEnabled(bool(macs))
        self.dev_rename_btn.setEnabled(len(macs) == 1)
        self.dev_forget_btn.setEnabled(bool(macs))

    def device_label(self, mac):
        d = self.devices.devices.get(mac, {})
        return d.get("nickname") or d.get("hostname") or d.get("vendor") or ""

    def wake_selected_devices(self):
        macs = self.selected_device_macs()
        if len(macs) == 1:
            self.wake(macs[0], self.device_label(macs[0]))
        elif macs:
            sent = sum(1 for mac in macs if wake_on_lan(mac, self.broadcasts()))
            self.status.setText(f"Sent Wake-on-LAN packets to {sent} of {len(macs)} devices.")

    def wake_typed_mac(self):
        text = self.mac_edit.text()
        mac = parse_mac(text)
        if not mac:
            QMessageBox.warning(self, "NetScan", "Enter a MAC address like AA:BB:CC:DD:EE:FF.")
            return
        self.wake(mac, self.device_label(mac))

    def export_devices(self):
        stamp = datetime.datetime.now().strftime("%Y-%m-%d")
        path, _ = QFileDialog.getSaveFileName(self, "Export device list", f"netscan-devices_{stamp}.json",
                                              "NetScan device list (*.json)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"netscan_devices": 1, "exported": now_iso(), "devices": self.devices.devices}, f, indent=1)
        self.status.setText(f"Exported {len(self.devices.devices)} device(s) to {path}")

    def import_devices(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import device list", "", "NetScan device list (*.json)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            devices = data["devices"]
            if not isinstance(devices, dict):
                raise TypeError("'devices' isn't a list of devices")
        except (OSError, ValueError, KeyError, TypeError) as e:
            QMessageBox.warning(self, "NetScan", f"That isn't a NetScan device list:\n{e}")
            return
        added, updated = self.devices.merge_from(devices)
        for ip in self.hosts:
            self.refresh_row(ip)
        self.refresh_devices()
        self.status.setText(f"Imported {path}: {added} new device(s), filled in details for {updated}. "
                            "Existing names and notes were kept.")

    def rename_device(self):
        macs = self.selected_device_macs()
        if len(macs) != 1:
            return
        mac = macs[0]
        d = self.devices.devices[mac]
        name = self.ask_nickname(d.get("hostname") or d.get("ip") or mac, mac, d.get("nickname", ""))
        if name is None:
            return
        self.devices.set_nickname({"mac": mac, "ip": d.get("ip", "")}, name)
        self.after_device_change(mac)

    def forget_devices(self):
        macs = self.selected_device_macs()
        if not macs:
            return
        what = self.device_label(macs[0]) or macs[0] if len(macs) == 1 else f"{len(macs)} devices"
        if QMessageBox.question(self, "NetScan", f"Forget {what}? Its nickname, notes and history are "
                                "removed, and it will show as a new device if it's seen again.") != QMessageBox.Yes:
            return
        for mac in macs:
            self.devices.forget(mac)
        self.after_device_change(*macs)

    def after_device_change(self, *macs):
        """A change from the Devices tab: update matching rows on the Scan tab too."""
        for ip, h in self.hosts.items():
            if h["mac"] in macs:
                self.refresh_row(ip)
        self.table.resizeColumnToContents(COL_NAME)
        self.show_port_details()
        self.refresh_devices()

    def device_menu(self, pos):
        macs = self.selected_device_macs()
        if not macs:
            return
        menu = QMenu(self)
        menu.addAction("Wake-on-LAN", self.wake_selected_devices)
        if len(macs) == 1:
            menu.addAction("Rename…", self.rename_device)
        all_trusted = all(self.devices.devices.get(m, {}).get("trusted") for m in macs)
        menu.addAction("Unmark as trusted" if all_trusted else "Mark as trusted",
                       lambda: self.set_trusted(macs, not all_trusted))
        if len(macs) == 1 and self.devices.devices.get(macs[0], {}).get("ip"):
            d = self.devices.devices[macs[0]]
            host = {"ip": d["ip"], "mac": macs[0], "hostname": d.get("hostname", "")}
            user = d.get("ssh_user")
            if terminal_argv(["true"]):
                menu.addAction(f"SSH to {user}@{d['ip']}" if user else f"SSH to {d['ip']}…",
                               lambda: self.ssh_to(host))
            menu.addAction("Copy ssh command", lambda: self.copy_ssh(host))
        all_important = all(self.devices.devices.get(m, {}).get("important") for m in macs)
        menu.addAction("Stop offline alerts" if all_important else "Alert when offline",
                       lambda: self.set_important(macs, not all_important))
        menu.addAction("Copy MAC address" + ("es" if len(macs) > 1 else ""),
                       lambda: QGuiApplication.clipboard().setText("\n".join(macs)))
        menu.addSeparator()
        menu.addAction("Forget", self.forget_devices)
        menu.exec(self.dev_table.viewport().mapToGlobal(pos))
