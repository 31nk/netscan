"""Monitor tab: latency, jitter and loss over time."""

import re
import time
from collections import deque

from PySide6.QtCore import (
    QItemSelectionModel, QTimer, Qt,
)
from PySide6.QtGui import (
    QAction, QColor, QKeySequence,
)
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QLabel, QLineEdit, QMenu, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from . import history_db
from . import theme as T
from .columns import TAB_MONITOR
from .internet import latency_stats
from .theme import make_card
from .widgets import LatencyChart, MONITOR_MAX, Pinger, SERIES_COLORS


class MonitorMixin:
    """Monitor tab: latency, jitter and loss over time. Mixed into MainWindow."""

    # ---- connection monitor --------------------------------------------------

    def build_monitor_page(self):
        self.monitored = {}  # ip -> {"slot", "label", "samples": deque[(time, ms or None)]}
        self.history_avg = history_db.MinuteAverager()
        self.pinger = Pinger()
        self.pinger.result.connect(self.monitor_result)
        self.mon_timer = QTimer(self)
        self.mon_timer.timeout.connect(self.monitor_tick)

        self.mon_add = QLineEdit()
        self.mon_add.setPlaceholderText("Add an IP address or hostname, e.g. 192.168.1.1 or 1.1.1.1")
        self.mon_add.returnPressed.connect(self.monitor_typed)
        add_btn = QPushButton("Add")
        add_btn.setObjectName("primary")
        add_btn.clicked.connect(self.monitor_typed)
        self.mon_interval = QComboBox()
        for label, _secs in (("Every second", 1), ("Every 2 seconds", 2), ("Every 5 seconds", 5)):
            self.mon_interval.addItem(label, _secs)
        self.mon_interval.currentIndexChanged.connect(self.monitor_restart)
        self.mon_span = QComboBox()
        for label, mins in (("Last 5 minutes", 5), ("Last 15 minutes", 15)):
            self.mon_span.addItem(label, mins)
        self.mon_span.currentIndexChanged.connect(self.refresh_monitor)
        self.mon_pause = QPushButton("Pause")
        self.mon_pause.setCheckable(True)
        self.mon_pause.toggled.connect(lambda on: (self.mon_pause.setText("Resume" if on else "Pause"),
                                                   self.monitor_restart()))
        controls, cl, _ = make_card("Monitor connection quality")
        row = QHBoxLayout()
        row.addWidget(self.mon_add, 1)
        row.addWidget(add_btn)
        row.addSpacing(12)
        row.addWidget(self.mon_interval)
        row.addWidget(self.mon_span)
        row.addWidget(self.mon_pause)
        cl.addLayout(row)
        hint = QLabel("Pings each device and charts how long replies take. Spikes mean lag; × marks are "
                      "pings that got no reply (dropped packets). Up to 8 devices.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        cl.addWidget(hint)

        chart_card, chl, _ = make_card("Latency")
        self.mon_chart = LatencyChart(self)
        chl.addWidget(self.mon_chart, 1)

        self.mon_table = QTableWidget(0, 8)
        self.mon_table.setHorizontalHeaderLabels(["", "DEVICE", "LAST", "AVERAGE", "MIN", "MAX", "JITTER", "LOSS"])
        self.mon_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.mon_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.mon_table.setShowGrid(False)
        self.mon_table.verticalHeader().setVisible(False)
        self.mon_table.verticalHeader().setDefaultSectionSize(30)
        self.mon_table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.mon_table.horizontalHeader().setHighlightSections(False)
        self.mon_table.horizontalHeader().setStretchLastSection(True)
        self.mon_table.setMaximumHeight(34 + 30 * 4)
        self.mon_table.itemSelectionChanged.connect(self.monitor_buttons)
        self.mon_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.mon_table.customContextMenuRequested.connect(self.monitor_menu)
        delete = QAction("Remove", self.mon_table)
        delete.setShortcut(QKeySequence.Delete)
        delete.setShortcutContext(Qt.WidgetShortcut)
        delete.triggered.connect(self.monitor_remove_selected)
        self.mon_table.addAction(delete)
        self.mon_remove_btn = remove_btn = QPushButton("Remove")
        remove_btn.setToolTip("Remove the selected device(s) from the monitor (or press Delete)")
        remove_btn.clicked.connect(self.monitor_remove_selected)
        clear_btn = QPushButton("Clear all")
        clear_btn.clicked.connect(lambda: self.monitor_remove(list(self.monitored)))
        table_card, tl, th = make_card("Devices")
        th.addStretch(1)
        th.addWidget(remove_btn)
        th.addWidget(clear_btn)
        tl.addWidget(self.mon_table)

        page = QWidget()
        pl = QVBoxLayout(page)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.setSpacing(12)
        pl.addWidget(controls)
        pl.addWidget(chart_card, 1)
        pl.addWidget(table_card)
        return page

    def monitor_interval(self):
        return self.mon_interval.currentData() or 1

    def monitor_span(self):
        return (self.mon_span.currentData() or 5) * 60

    def monitor_label(self, ip):
        h = self.hosts.get(ip)
        if not h:
            return ip
        return self.devices.nickname(h) or h.get("hostname") or h.get("friendly") or ip

    def monitor_hosts(self, ips):
        added = [ip for ip in ips if self.monitor_add(ip, self.monitor_label(ip))]
        if added:
            self.tabbar.setCurrentIndex(TAB_MONITOR)

    def monitor_typed(self):
        target = self.mon_add.text().strip()
        if not re.fullmatch(r"[0-9A-Za-z.:-]{1,253}", target) or target.startswith("-"):
            self.status.setText("Enter an IP address or hostname to monitor.")
            return
        if self.monitor_add(target, self.monitor_label(target)):
            self.mon_add.clear()

    def monitor_add(self, ip, label):
        if ip in self.monitored:
            return True
        if len(self.monitored) >= MONITOR_MAX:
            self.status.setText(f"The monitor shows up to {MONITOR_MAX} devices (one colour each). "
                                "Remove one to add another.")
            return False
        used = {m["slot"] for m in self.monitored.values()}
        slot = next(i for i in range(MONITOR_MAX) if i not in used)  # a colour stays with its device
        self.monitored[ip] = {"slot": slot, "label": label, "samples": deque(maxlen=3600)}
        self.monitor_restart()
        self.refresh_monitor()
        return True

    def monitor_selected(self):
        t = self.mon_table
        return [t.item(r, 1).data(Qt.UserRole) for r in sorted({i.row() for i in t.selectedIndexes()})
                if t.item(r, 1)]

    def monitor_buttons(self):
        # With a single device there's nothing to choose, so Remove works without selecting it.
        self.mon_remove_btn.setEnabled(bool(self.monitor_selected()) or len(self.monitored) == 1)

    def monitor_menu(self, pos):
        ips = self.monitor_selected()
        if not ips:
            return
        menu = QMenu(self)
        menu.addAction("Remove" + (f" {len(ips)} devices" if len(ips) > 1 else ""), self.monitor_remove_selected)
        menu.exec(self.mon_table.viewport().mapToGlobal(pos))

    def monitor_remove_selected(self):
        ips = self.monitor_selected() or (list(self.monitored) if len(self.monitored) == 1 else [])
        self.monitor_remove(ips)

    def monitor_remove(self, ips):
        for ip in ips:
            self.monitored.pop(ip, None)
        self.monitor_restart()
        self.refresh_monitor()

    def monitor_restart(self):
        if self.monitored and not self.mon_pause.isChecked():
            self.mon_timer.start(self.monitor_interval() * 1000)
            self.monitor_tick()
        else:
            self.mon_timer.stop()

    def monitor_tick(self):
        self.pinger.ping(list(self.monitored))

    def monitor_result(self, ip, when, ms):
        if ip in self.monitored and not self.mon_pause.isChecked():
            self.monitored[ip]["samples"].append((when, ms))
            self.history_avg.add(self.monitored[ip]["label"], ms, when)
            if self.tabbar.currentIndex() == TAB_MONITOR:
                self.refresh_monitor()

    def visible_series(self, t0):
        colors = SERIES_COLORS[T.THEME]
        return [(ip, colors[m["slot"]], m["label"], [s for s in m["samples"] if s[0] >= t0])
                for ip, m in sorted(self.monitored.items(), key=lambda kv: kv[1]["slot"])]

    def refresh_monitor(self):
        self.mon_chart.update()
        t = self.mon_table
        t0 = time.time() - self.monitor_span()
        series = self.visible_series(t0)
        rows_now = [t.item(r, 1).data(Qt.UserRole) if t.item(r, 1) else None for r in range(t.rowCount())]
        if rows_now != [ip for ip, *_ in series]:
            # The device list changed: rebuild the rows, keeping the selection by IP.
            keep = set(self.monitor_selected())
            t.blockSignals(True)
            t.clearSelection()
            t.setRowCount(0)
            t.setRowCount(len(series))
            for row, (ip, _color, _label, _samples) in enumerate(series):
                for col in range(t.columnCount()):
                    t.setItem(row, col, QTableWidgetItem(""))
                t.item(row, 1).setData(Qt.UserRole, ip)
                t.item(row, 0).setTextAlignment(Qt.AlignCenter)
                if ip in keep:
                    t.selectionModel().select(t.model().index(row, 0),
                                              QItemSelectionModel.Select | QItemSelectionModel.Rows)
            t.blockSignals(False)
        fmt = lambda v: "—" if v is None else f"{v:.1f} ms"
        for row, (ip, color, label, samples) in enumerate(series):
            # Update the existing items' text in place, so selection and clicks are never disturbed.
            st = latency_stats(samples)
            last = "no reply" if samples and st["last"] is None else fmt(st["last"])
            loss = "—" if st["loss"] is None else f"{st['loss']:.0f}%  ({sum(1 for s in samples if s[1] is None)}/{st['count']})"
            texts = ["●", label if label == ip else f"{label}  ({ip})", last, fmt(st["avg"]), fmt(st["min"]),
                     fmt(st["max"]), fmt(st["jitter"]), loss]
            for col, text in enumerate(texts):
                if t.item(row, col).text() != text:
                    t.item(row, col).setText(text)
            t.item(row, 0).setForeground(QColor(color))
            t.item(row, 7).setForeground(QColor(T.AMBER if st["loss"] else T.TEXT))
        t.resizeColumnsToContents()
        t.setColumnWidth(0, 30)
        self.monitor_buttons()
