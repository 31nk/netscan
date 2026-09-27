"""Custom Qt widgets and background workers: charts, the network map, dialogs, notifications."""

import datetime
import html
import math
import re
import shutil
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import (
    QObject, QPointF, QProcess, QRectF, Qt, Signal,
)
from PySide6.QtGui import (
    QColor, QFont, QFontDatabase, QPainter, QPainterPath, QPen, QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication, QDialog, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QSystemTrayIcon,
    QTableWidgetItem, QToolTip, QVBoxLayout, QWidget,
)

from . import theme as T
from .devices import risky
from .discovery import SSDP_ADDR, run_discovery
from .names import lookup_name
from .scanning import ip_sort_key
from .system import IS_MAC, IS_WIN, ping_once
from .tools import traceroute_argv


def notify(title, body):
    """Desktop notification: notify-send on Linux, Notification Center on macOS, tray balloon on Windows."""
    if IS_MAC:
        esc = lambda t: t.replace("\\", "\\\\").replace('"', '\\"')
        QProcess.startDetached("/usr/bin/osascript",
                               ["-e", f'display notification "{esc(body)}" with title "{esc(title)}"'])
    elif not IS_WIN and shutil.which("notify-send"):
        QProcess.startDetached("notify-send", ["-a", "NetScan", "-i", "network-wired", title, body])
    elif QSystemTrayIcon.isSystemTrayAvailable():
        global _TRAY
        if _TRAY is None:
            _TRAY = QSystemTrayIcon(QApplication.windowIcon())
            _TRAY.show()
        _TRAY.showMessage(title, body)


_TRAY = None


class HistoryGrid(QWidget):
    """Last 7 days x 24 hours: seen online / checked but not seen / not checked."""

    CELL, GAP, LEFT, BOTTOM = 10, 2, 34, 16

    def __init__(self):
        super().__init__()
        self.seen, self.checked = set(), set()
        w = self.LEFT + 24 * (self.CELL + self.GAP)
        h = 7 * (self.CELL + self.GAP) + self.BOTTOM
        self.setFixedSize(w, h)

    def set_data(self, seen, checked):
        self.seen, self.checked = set(seen), set(checked)
        self.update()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        small = QFont(self.font())
        small.setPointSizeF(max(7.0, small.pointSizeF() * 0.8))
        p.setFont(small)
        today = datetime.date.today()
        step = self.CELL + self.GAP
        for row in range(7):
            day = today - datetime.timedelta(days=6 - row)
            y = row * step
            p.setPen(QColor(T.MUTED))
            p.drawText(0, y, self.LEFT - 6, self.CELL + 1, Qt.AlignRight | Qt.AlignVCenter,
                       "Today" if row == 6 else day.strftime("%a"))
            for hour in range(24):
                bucket = f"{day.isoformat()}T{hour:02d}"
                x = self.LEFT + hour * step
                if bucket in self.seen:
                    p.setPen(Qt.NoPen)
                    p.setBrush(QColor(T.GREEN))
                elif bucket in self.checked:
                    p.setPen(Qt.NoPen)
                    p.setBrush(QColor(T.DIM))
                else:
                    p.setPen(QColor(T.BORDER))
                    p.setBrush(Qt.NoBrush)
                p.drawRoundedRect(x + 0.5, y + 0.5, self.CELL - 1, self.CELL - 1, 2.5, 2.5)
        p.setPen(QColor(T.MUTED))
        for hour in (0, 6, 12, 18):
            p.drawText(self.LEFT + hour * step - 2, 7 * step, 30, self.BOTTOM,
                       Qt.AlignLeft | Qt.AlignVCenter, f"{hour:02d}")
        p.end()


class SortItem(QTableWidgetItem):
    """Sorts by a hidden key (Qt.UserRole) instead of its display text."""

    def __lt__(self, other):
        return (self.data(Qt.UserRole) or "") < (other.data(Qt.UserRole) or "")


class IPItem(QTableWidgetItem):
    """Sorts IP addresses numerically instead of as strings."""

    def __lt__(self, other):
        try:
            return ip_sort_key(self.text()) < ip_sort_key(other.text())
        except ValueError:
            return super().__lt__(other)


# ---- connection monitor ------------------------------------------------------

# Categorical series colours, fixed order, stepped per theme. Validated with the dataviz
# palette checker on NetScan's chart surfaces (#ffffff light, #151823 dark): CVD and
# normal-vision separation pass; three light slots are under 3:1, so every series is also
# named in the stats table and (up to 4) directly labelled on the chart.
SERIES_COLORS = {
    "light": ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"],
    "dark": ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"],
}
MONITOR_MAX = len(SERIES_COLORS["dark"])  # never cycle colours: a 9th device isn't allowed


def nice_ceiling(value):
    """Round an axis maximum up to 1/2/5 x 10^n so tick labels are readable."""
    if value <= 0:
        return 1.0
    exp = 10 ** math.floor(math.log10(value))
    return next(m * exp for m in (1, 2, 5, 10) if m * exp >= value)


class Pinger(QObject):
    """Pings each monitored address on a timer, in the background; one ping in flight per address."""

    result = Signal(str, float, object)  # ip, time.time(), ms or None

    def __init__(self):
        super().__init__()
        self.pool = ThreadPoolExecutor(max_workers=MONITOR_MAX)
        self.busy = set()

    def ping(self, ips):
        for ip in ips:
            if ip in self.busy:
                continue  # previous ping still waiting for its timeout
            self.busy.add(ip)
            self.pool.submit(self._run, ip)

    def _run(self, ip):
        try:
            ms = ping_once(ip)
        except Exception:  # noqa: BLE001 - a failed ping is just a lost sample
            ms = None
        self.busy.discard(ip)
        self.result.emit(ip, time.time(), ms)


class LatencyChart(QWidget):
    """Latency over time: one line per device, gaps and x marks for lost pings, crosshair on hover."""

    LEFT, RIGHT, TOP, BOTTOM = 56, 120, 14, 44  # bottom holds the "no reply" lane and time labels
    LANE = 16

    def __init__(self, window):
        super().__init__()
        self.window = window  # MainWindow: series data, colours and the time span live there
        self.hover_x = None
        self.setMouseTracking(True)
        self.setMinimumHeight(240)

    def leaveEvent(self, _event):
        self.hover_x = None
        self.update()

    def mouseMoveEvent(self, event):
        self.hover_x = event.position().x()
        self.update()

    def plot_rect(self):
        return QRectF(self.LEFT, self.TOP, max(10, self.width() - self.LEFT - self.RIGHT),
                      max(10, self.height() - self.TOP - self.BOTTOM))

    @staticmethod
    def ticks(top):
        """Round tick values (1/2/5 steps) from 0 up to at least top."""
        step = nice_ceiling(top / 5)
        n = math.ceil(top / step - 1e-9)
        return [i * step for i in range(n + 1)], n * step

    def paintEvent(self, _event):
        w = self.window
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        small = QFont(self.font())
        small.setPointSizeF(max(7.5, small.pointSizeF() * 0.85))
        p.setFont(small)
        r = self.plot_rect()
        now = time.time()
        span = w.monitor_span()
        t0 = now - span
        series = w.visible_series(t0)
        if not w.monitored:
            p.setPen(QColor(T.MUTED))
            p.drawText(self.rect(), Qt.AlignCenter,
                       "Right-click a device on the Scan tab → Monitor connection,\nor add an IP address above.")
            return
        values = [ms for _ip, _c, _l, samples in series for _t, ms in samples if ms is not None]
        tick_values, top = self.ticks(max(max(values) * 1.15 if values else 10.0, 2.0))
        x_of = lambda t: r.left() + (t - t0) / span * r.width()
        y_of = lambda ms: r.bottom() - ms / top * r.height()

        # recessive grid + axis labels (one y-axis, ms)
        p.setPen(QPen(QColor(T.BORDER), 1))
        for ms in tick_values:
            y = y_of(ms)
            p.drawLine(QPointF(r.left(), y), QPointF(r.right(), y))
            p.setPen(QColor(T.MUTED))
            label = f"{ms:g} ms"
            p.drawText(QRectF(0, y - 8, self.LEFT - 6, 16), Qt.AlignRight | Qt.AlignVCenter, label)
            p.setPen(QPen(QColor(T.BORDER), 1))
        lane_y = r.bottom() + 4 + self.LANE / 2  # lost pings get their own lane, clear of the data
        p.setPen(QColor(T.MUTED))
        p.drawText(QRectF(0, lane_y - 8, self.LEFT - 6, 16), Qt.AlignRight | Qt.AlignVCenter, "no reply")
        minutes = span / 60
        for i in range(int(minutes) + 1):
            if minutes > 5 and i % 5:
                continue
            x = x_of(now - i * 60)
            p.setPen(QColor(T.MUTED))
            p.drawText(QRectF(x - 30, r.bottom() + 6 + self.LANE, 60, 18), Qt.AlignHCenter | Qt.AlignTop,
                       "now" if i == 0 else f"-{i} min")

        # lines (2px, round joins), gaps where pings were lost, x marks at the baseline for them
        labels = []
        for _ip, color, label, samples in series:
            pen = QPen(QColor(color), 2)
            pen.setCapStyle(Qt.RoundCap)
            pen.setJoinStyle(Qt.RoundJoin)
            path, drawing = QPainterPath(), False
            for t, ms in samples:
                if ms is None:
                    drawing = False
                    continue
                pt = QPointF(x_of(t), y_of(ms))
                path.lineTo(pt) if drawing else path.moveTo(pt)
                drawing = True
            p.setPen(pen)
            p.setBrush(Qt.NoBrush)
            p.drawPath(path)
            p.setPen(QPen(QColor(color), 2))
            for t, ms in samples:
                if ms is None:
                    x, y = x_of(t), lane_y
                    p.drawLine(QPointF(x - 4, y - 4), QPointF(x + 4, y + 4))
                    p.drawLine(QPointF(x - 4, y + 4), QPointF(x + 4, y - 4))
            last = next((s for s in reversed(samples) if s[1] is not None), None)
            if last:
                labels.append([y_of(last[1]), color, label])
        # direct labels at the line ends for up to 4 series (the table is the legend beyond that)
        if len(series) <= 4:
            labels.sort()
            for i in range(1, len(labels)):  # nudge apart so labels don't collide
                labels[i][0] = max(labels[i][0], labels[i - 1][0] + 15)
            for y, color, label in labels:
                p.setBrush(QColor(color))
                p.setPen(Qt.NoPen)
                p.drawEllipse(QPointF(r.right() + 10, y), 4, 4)
                p.setPen(QColor(T.TEXT))
                p.drawText(QRectF(r.right() + 18, y - 8, self.RIGHT - 20, 16), Qt.AlignLeft | Qt.AlignVCenter,
                           p.fontMetrics().elidedText(label, Qt.ElideRight, int(self.RIGHT - 20)))

        # hover: crosshair + tooltip with every series' value at that moment
        if self.hover_x is not None and r.left() <= self.hover_x <= r.right():
            t = t0 + (self.hover_x - r.left()) / r.width() * span
            rows = []
            for _ip, color, label, samples in series:
                near = min(samples, key=lambda s: abs(s[0] - t), default=None)
                if near and abs(near[0] - t) <= max(w.monitor_interval() * 1.5, span / r.width() * 2):
                    rows.append((color, label, "no reply" if near[1] is None else f"{near[1]:.1f} ms"))
            p.setPen(QPen(QColor(T.MUTED), 1, Qt.DashLine))
            p.drawLine(QPointF(self.hover_x, r.top()), QPointF(self.hover_x, r.bottom()))
            if rows:
                fm = p.fontMetrics()
                head = datetime.datetime.fromtimestamp(t).strftime("%H:%M:%S")
                width = max([fm.horizontalAdvance(head)] +
                            [fm.horizontalAdvance(f"{l}  {v}") + 18 for _c, l, v in rows]) + 20
                height = 22 + 18 * len(rows)
                bx = self.hover_x + 12 if self.hover_x + 12 + width < self.width() else self.hover_x - 12 - width
                box = QRectF(bx, r.top() + 6, width, height)
                p.setPen(QPen(QColor(T.BORDER), 1))
                p.setBrush(QColor(T.RAISED))
                p.drawRoundedRect(box, 6, 6)
                p.setPen(QColor(T.MUTED))
                p.drawText(QRectF(box.left() + 10, box.top() + 4, width, 16), Qt.AlignLeft, head)
                for i, (color, label, value) in enumerate(rows):
                    y = box.top() + 22 + 18 * i
                    p.setPen(Qt.NoPen)
                    p.setBrush(QColor(color))
                    p.drawEllipse(QPointF(box.left() + 14, y + 8), 4, 4)
                    p.setPen(QColor(T.TEXT))
                    p.drawText(QRectF(box.left() + 24, y, width - 30, 16), Qt.AlignLeft | Qt.AlignVCenter,
                               f"{label}  {value}")
        p.end()


class Worker(QObject):
    """Runs one function in a background thread and emits (tag, result or Exception)."""

    done = Signal(str, object)

    def run(self, tag, fn, *args):
        def go():
            try:
                result = fn(*args)
            except Exception as e:  # noqa: BLE001 - handed to the GUI to report
                result = e
            try:
                self.done.emit(tag, result)
            except RuntimeError:
                pass  # window already closed
        threading.Thread(target=go, daemon=True).start()


class TraceDialog(QDialog):
    """Runs a trace route and shows each hop as it arrives."""

    def __init__(self, parent, target, label):
        super().__init__(parent)
        self.setWindowTitle(f"Trace route to {label}")
        self.resize(760, 460)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        head = QLabel(f"Every router (hop) between this computer and <b>{html.escape(label)}</b>, with the "
                      "time each took. A jump in time shows where delay starts; “no reply” hops are "
                      "common and usually harmless.")
        head.setWordWrap(True)
        head.setObjectName("muted")
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.stop_btn = QPushButton("Stop")
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(self.stop_btn)
        row.addWidget(close_btn)
        layout.addWidget(head)
        layout.addWidget(self.out, 1)
        layout.addLayout(row)
        argv = traceroute_argv(target)
        self.proc = QProcess(self)
        self.proc.setProcessChannelMode(QProcess.MergedChannels)
        self.proc.readyReadStandardOutput.connect(self.read)
        self.proc.finished.connect(lambda *_: (self.stop_btn.setEnabled(False),
                                               self.out.appendPlainText("\n— finished —")))
        self.stop_btn.clicked.connect(self.proc.kill)
        if argv is None:
            self.out.setPlainText("No trace-route tool found. Install one, e.g. the 'iputils' (tracepath) or "
                                  "'traceroute' package.")
            self.stop_btn.setEnabled(False)
        else:
            self.out.setPlainText("$ " + " ".join(argv) + "\n")
            self.proc.start(argv[0], argv[1:])

    def read(self):
        text = bytes(self.proc.readAllStandardOutput()).decode(errors="replace")
        self.out.moveCursor(QTextCursor.End)
        self.out.insertPlainText(text.replace("\r\n", "\n"))
        self.out.moveCursor(QTextCursor.End)

    def closeEvent(self, event):
        if self.proc.state() != QProcess.NotRunning:
            self.proc.kill()
            self.proc.waitForFinished(1000)
        super().closeEvent(event)


MAP_GROUP_ORDER = ["computer", "pi", "nas", "phone", "media", "iot", "printer", "unknown"]


class StatusLabel(QLabel):
    """Status line: wraps to at most two lines, ending in … when longer; the full text is the tooltip."""

    def __init__(self, text=""):
        super().__init__()
        self.setWordWrap(True)
        self.full = ""
        self.setText(text)

    def setText(self, text):
        self.full = text
        self.setToolTip(text if len(text) > 120 else "")
        self._fit()

    def text(self):
        return self.full

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._fit()

    def _fit(self):
        fm = self.fontMetrics()
        budget = max(200, int(self.width() * 1.85))  # roughly two lines of the current width
        shown = fm.elidedText(self.full, Qt.ElideRight, budget) if fm.horizontalAdvance(self.full) > budget else self.full
        QLabel.setText(self, shown)
        self.setFixedHeight(fm.lineSpacing() * (2 if fm.horizontalAdvance(shown) > self.width() else 1) + 4)


class NetworkMap(QWidget):
    """Router in the middle, every device around it grouped by type; warnings ringed, hover for details."""

    NODE = 22  # node radius

    def __init__(self, window):
        super().__init__()
        self.window = window
        self.nodes = []   # [(ip, QPointF)] from the last paint, for hover/click
        self.hover = None
        self.setMouseTracking(True)
        self.setMinimumHeight(420)

    def node_at(self, pos):
        return next((ip for ip, pt in self.nodes
                     if (pt.x() - pos.x()) ** 2 + (pt.y() - pos.y()) ** 2 <= (self.NODE + 4) ** 2), None)

    def mouseMoveEvent(self, event):
        ip = self.node_at(event.position())
        if ip != self.hover:
            self.hover = ip
            self.setCursor(Qt.PointingHandCursor if ip else Qt.ArrowCursor)
            self.update()
        if ip:
            QToolTip.showText(event.globalPosition().toPoint(), self.window.map_tooltip(ip), self)
        else:
            QToolTip.hideText()

    def mousePressEvent(self, event):
        ip = self.node_at(event.position())
        if ip:
            self.window.show_host(ip)

    def paintEvent(self, _event):
        w = self.window
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        small = QFont(self.font())
        small.setPointSizeF(max(7.5, small.pointSizeF() * 0.85))
        self.nodes = []
        if not w.hosts:
            p.setPen(QColor(T.MUTED))
            p.drawText(self.rect(), Qt.AlignCenter, "Press Find Hosts on the Scan tab to draw the network map.")
            return
        gw = w.gateway()
        others = [ip for ip in w.hosts if ip != gw]
        kind = {ip: w.devices.device_type(w.hosts[ip], w.ports.get(ip), gw)[0] for ip in others}
        others.sort(key=lambda ip: (MAP_GROUP_ORDER.index(kind[ip]) if kind[ip] in MAP_GROUP_ORDER else 99,
                                    ip_sort_key(ip)))
        legend_h = 26
        center = QPointF(self.width() / 2, (self.height() - legend_h) / 2)
        max_r = min(self.width() / 2 - 90, (self.height() - legend_h) / 2 - 40)
        rings = 1 if len(others) <= 16 else 2
        placed = {}
        for i, ip in enumerate(others):
            angle = -math.pi / 2 + 2 * math.pi * i / max(len(others), 1)
            radius = max_r * (1.0 if rings == 1 or i % 2 == 0 else 0.62)
            placed[ip] = QPointF(center.x() + radius * math.cos(angle), center.y() + radius * math.sin(angle))
        placed[gw or "_net"] = center

        p.setPen(QPen(QColor(T.BORDER), 1.5))
        for ip in others:  # links to the router
            p.drawLine(center, placed[ip])
        for ip, pt in placed.items():
            h = w.hosts.get(ip, {"ip": ip, "mac": "", "vendor": "", "hostname": ""})
            k = "router" if ip == (gw or "_net") else kind.get(ip, "unknown")
            warn = bool(risky(w.network_ports(ip)) or h.get("upnp"))
            me = ip == w.local_ip()
            new = h.get("mac") in w.new_devices
            ring = T.AMBER if warn else T.ACCENT if me else T.BORDER_HI
            r = self.NODE + (4 if ip == self.hover else 0) + (6 if k == "router" else 0)
            p.setPen(QPen(QColor(ring), 3 if warn or me else 1.5))
            p.setBrush(QColor(T.HOVER if ip == self.hover else T.RAISED))
            p.drawEllipse(pt, r, r)
            icon = w.type_icon(k).pixmap(24 if k == "router" else 20, 24 if k == "router" else 20)
            p.drawPixmap(QPointF(pt.x() - icon.width() / 2, pt.y() - icon.height() / 2), icon)
            if new:  # small green dot: first time seen
                p.setPen(QPen(QColor(T.SURFACE), 2))
                p.setBrush(QColor(T.GREEN))
                p.drawEllipse(QPointF(pt.x() + r * 0.72, pt.y() - r * 0.72), 5, 5)
            if ip == "_net":
                continue
            label = w.monitor_label(ip)
            p.setFont(small)
            fm = p.fontMetrics()
            p.setPen(QColor(T.TEXT))
            name = fm.elidedText(label, Qt.ElideRight, 130)
            p.drawText(QRectF(pt.x() - 70, pt.y() + r + 3, 140, 16), Qt.AlignHCenter | Qt.AlignTop, name)
            if label != ip:
                p.setPen(QColor(T.MUTED))
                p.drawText(QRectF(pt.x() - 70, pt.y() + r + 17, 140, 16), Qt.AlignHCenter | Qt.AlignTop,
                           fm.elidedText(ip, Qt.ElideMiddle, 130))
            self.nodes.append((ip, pt))

        # legend: what the rings and dot mean (never colour alone: the tooltip spells it out too)
        p.setFont(small)
        x, y = 12.0, self.height() - legend_h / 2
        for color, text, dot in ((T.AMBER, "risky port or opened to the internet", False),
                                 (T.ACCENT, "this computer", False), (T.GREEN, "new device", True)):
            p.setPen(QPen(QColor(color), 3) if not dot else Qt.NoPen)
            p.setBrush(QColor(color) if dot else Qt.NoBrush)
            p.drawEllipse(QPointF(x + 6, y), 5 if dot else 6, 5 if dot else 6)
            p.setPen(QColor(T.MUTED))
            p.drawText(QPointF(x + 18, y + 4), text)
            x += 30 + p.fontMetrics().horizontalAdvance(text)
        p.end()


class SsdpListener(QObject):
    """Listens for UPnP devices' own multicast announcements (NOTIFY) while NetScan is open.

    Firewalls like ufw drop the direct replies to an SSDP search but let these multicast
    announcements through, and routers repeat them every minute or so.
    """

    found = Signal(str, str)  # ip, description URL

    def __init__(self):
        super().__init__()
        self.seen = {}  # ip -> set of URLs (read from the GUI thread; only ever grows)
        self.local_ip = None

    def start(self, local_ip):
        if self.local_ip == local_ip:
            return
        self.local_ip = local_ip
        threading.Thread(target=self._run, args=(local_ip,), daemon=True).start()

    def _run(self, local_ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.bind(("", SSDP_ADDR[1]))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                         socket.inet_aton(SSDP_ADDR[0]) + socket.inet_aton(local_ip))
        except OSError:
            return  # port 1900 not shareable here (e.g. Windows' own SSDP service); searches still work
        s.settimeout(2)
        while self.local_ip == local_ip:
            try:
                data, (ip, _port) = s.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            m = re.search(rb"(?im)^location:\s*(\S+)", data)
            if m and data.startswith((b"NOTIFY", b"HTTP/")):
                url = m.group(1).decode(errors="replace")
                if url not in self.seen.setdefault(ip, set()):
                    self.seen[ip].add(url)
                    self.found.emit(ip, url)
        s.close()


class Discovery(QObject):
    done = Signal(object)

    def start(self, job):
        threading.Thread(target=self._run, args=(job,), daemon=True).start()

    def _run(self, job):
        try:
            result = run_discovery(job)
        except RuntimeError:
            return  # NetScan is closing: Python won't start new worker threads during exit
        self.done.emit(result)


class Resolver(QObject):
    """Background name lookups: mDNS, NetBIOS, then system DNS."""

    resolved = Signal(str, str)  # ip, name ("" if nothing found)

    def lookup(self, ips):
        def run(ip):
            self.resolved.emit(ip, lookup_name(ip))

        for ip in ips:
            self.pool.submit(run, ip)

    # Bounded, so a /16 doesn't start thousands of threads at once.
    pool = ThreadPoolExecutor(max_workers=32)
