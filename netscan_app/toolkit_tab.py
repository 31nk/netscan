"""The newer Tools panels: connections, live traffic, continuous trace, LAN speed test, domain toolkit
and website watch. Engines live in probes.py and lanspeed.py."""

import html
import time
from collections import deque

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox,
    QPushButton,
    QTableWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget,
)

from . import history_db
from . import theme as T
from .discovery import ufw_active
from .lanspeed import LAN_PORT, LanSpeedServer, lan_speed_test
from .probes import (
    check_site, describe_connections, dns_benchmark, domain_report, email_verdicts, find_hops, interface_counters,
    load_watch, reverse_name, save_watch,
)
from .scanning import ip_sort_key
from .vulns import host_vulnerabilities, versioned_cpes
from .widgets import Pinger, TimeSeriesChart, TrafficChart, notify

WEB_WATCH_MINUTES = 5


def _table(headers, stretch_col=None):
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels([h.upper() for h in headers])
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setAlternatingRowColors(True)
    t.setShowGrid(False)
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(30)
    t.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    t.horizontalHeader().setHighlightSections(False)
    t.horizontalHeader().setStretchLastSection(stretch_col is None)
    if stretch_col is not None:
        t.horizontalHeader().setSectionResizeMode(stretch_col, QHeaderView.Stretch)
    return t


def _panel(title, desc):
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(10)
    head = QLabel(title)
    head.setObjectName("bigName")
    info = QLabel(desc)
    info.setObjectName("muted")
    info.setWordWrap(True)
    info.setProperty("noTicket", True)  # Copy for ticket leaves the tool's description out
    lay.addWidget(head)
    lay.addWidget(info)
    return w, lay


def _set_row(t, row, values, colors=None):
    for col, v in enumerate(values):
        item = t.item(row, col)
        if item is None:
            item = QTableWidgetItem()
            t.setItem(row, col, item)
        if item.text() != str(v):
            item.setText(str(v))
        if colors and colors.get(col):
            item.setForeground(QColor(colors[col]))


class ToolkitMixin:
    """The newer Tools panels. Mixed into MainWindow."""

    def build_toolkit_panels(self):
        """[(title, widget)] for the Tools list (tools_tab.TOOL_GROUPS decides where each goes)."""
        return [("Connections", self.build_connections_panel()), ("Live traffic", self.build_traffic_panel()),
                ("Continuous trace", self.build_mtr_panel()), ("LAN speed test", self.build_lan_panel()),
                ("Domain toolkit", self.build_domain_panel()), ("Website watch", self.build_webwatch_panel()),
                ("DNS speed", self.build_dnsbench_panel()), ("History", self.build_history_panel())]

    def toolkit_tool_changed(self, title):
        """Only run the live panels while they're on screen."""
        if title == "History":
            self.show_history()
        if title == "Who's home":
            self.show_presence()
        if title == "Outages":
            self.show_outages()
        if title == "Client sites":
            self.show_sites()
        if title == "LAN speed test":
            self.lan_hosts_changed()
        if title == "Live traffic":
            self.traffic_timer.start(2000 if self.traffic_slow else 1000)
            self.traffic_tick()
        else:
            self.traffic_timer.stop()

    # ---- connections -----------------------------------------------------------------

    def build_connections_panel(self):
        w, lay = _panel("Connections", "What this computer is talking to right now: each program's open "
                                       "connections, where they go and who owns the address. Addresses are "
                                       "looked up in the public registries (cached for two weeks).")
        row = QHBoxLayout()
        self.conn_filter = QLineEdit()
        self.conn_filter.setPlaceholderText("Filter by program, owner, address…")
        self.conn_filter.setClearButtonEnabled(True)
        self.conn_filter.textChanged.connect(self.filter_connections)
        self.conn_btn = QPushButton("Refresh")
        self.conn_btn.setObjectName("primary")
        self.conn_btn.clicked.connect(self.refresh_connections)
        self.conn_note = QLabel("")
        self.conn_note.setObjectName("muted")
        row.addWidget(self.conn_filter, 1)
        row.addWidget(self.conn_note)
        row.addWidget(self.conn_btn)
        lay.addLayout(row)
        self.conn_table = _table(["Program", "Remote", "Port", "Owner", "Where", "Conns"], stretch_col=1)
        lay.addWidget(self.conn_table, 1)
        return w

    def refresh_connections(self):
        self.conn_btn.setEnabled(False)
        self.conn_note.setText("Looking up owners…")
        self.worker.run("tk:connections", describe_connections)

    def show_connections(self, rows):
        t = self.conn_table
        t.setSortingEnabled(False)
        t.setRowCount(len(rows))
        for i, r in enumerate(rows):
            remote = f"{r['name']}  ({r['ip']})" if r["name"] else r["ip"]
            port = f"{r['port']}/{r['service']}" if r["service"] else str(r["port"])
            _set_row(t, i, [r["program"], remote, port, r["owner"] or "(refresh to look up)", r["where"], r["count"]],
                     {3: T.MUTED if r["owner"] in ("your network", "") else T.TEXT})
        t.setSortingEnabled(True)
        t.resizeColumnsToContents()
        programs = len({r["program"] for r in rows})
        self.conn_note.setText(f"{sum(r['count'] for r in rows)} connection(s) from {programs} program(s)")
        self.filter_connections()

    def filter_connections(self):
        text = self.conn_filter.text().strip().lower()
        t = self.conn_table
        for r in range(t.rowCount()):
            t.setRowHidden(r, bool(text) and not any(text in (t.item(r, c).text().lower() if t.item(r, c) else "")
                                                     for c in range(t.columnCount())))

    # ---- live traffic ------------------------------------------------------------------

    def build_traffic_panel(self):
        w, lay = _panel("Live traffic", "How fast this computer is downloading and uploading right now, per "
                                        "network interface (includes VPN tunnels).")
        row = QHBoxLayout()
        self.traffic_iface = QComboBox()
        self.traffic_iface.currentIndexChanged.connect(lambda _i: self.traffic_samples_store.clear())
        self.traffic_total = QLabel("")
        self.traffic_total.setObjectName("muted")
        row.addWidget(QLabel("Interface"))
        row.addWidget(self.traffic_iface)
        row.addStretch(1)
        row.addWidget(self.traffic_total)
        lay.addLayout(row)
        self.traffic_chart = TrafficChart(self)
        lay.addWidget(self.traffic_chart, 1)
        self.traffic_samples_store = deque(maxlen=180)
        self.traffic_last = None
        self.traffic_slow = False
        self.traffic_timer = QTimer(self)
        self.traffic_timer.timeout.connect(self.traffic_tick)
        return w

    def traffic_samples(self):
        return list(self.traffic_samples_store)

    def traffic_tick(self):
        t = time.time()
        counters = interface_counters()
        self.traffic_slow = time.time() - t > 0.3  # e.g. PowerShell on Windows: sample less often
        names = sorted(counters, key=lambda n: (-sum(counters[n]), n))
        if [self.traffic_iface.itemText(i) for i in range(self.traffic_iface.count())] != names:
            current = self.traffic_iface.currentText()
            self.traffic_iface.blockSignals(True)
            self.traffic_iface.clear()
            self.traffic_iface.addItems(names)
            self.traffic_iface.setCurrentIndex(max(0, names.index(current) if current in names else 0))
            self.traffic_iface.blockSignals(False)
        name = self.traffic_iface.currentText()
        if name not in counters:
            return
        rx, tx = counters[name]
        if self.traffic_last and self.traffic_last[0] == name:
            _n, last_t, last_rx, last_tx = self.traffic_last
            dt = max(t - last_t, 0.05)
            self.traffic_samples_store.append((t, max(0, rx - last_rx) * 8 / dt / 1e6,
                                               max(0, tx - last_tx) * 8 / dt / 1e6))
        self.traffic_last = (name, t, rx, tx)
        self.traffic_total.setText(f"since boot: {rx / 1e9:.2f} GB down, {tx / 1e9:.2f} GB up")
        self.traffic_chart.update()

    # ---- continuous trace --------------------------------------------------------------

    def build_mtr_panel(self):
        w, lay = _panel("Continuous trace", "Every hop to a destination, pinged continuously: shows where "
                                            "delay or packet loss starts. Loss at a middle hop that doesn't "
                                            "continue to later hops is just that router ignoring pings "
                                            "(common and harmless).")
        row = QHBoxLayout()
        self.mtr_target = QLineEdit("1.1.1.1")
        self.mtr_target.returnPressed.connect(self.toggle_mtr)
        self.mtr_btn = QPushButton("Start")
        self.mtr_btn.setObjectName("primary")
        self.mtr_btn.clicked.connect(self.toggle_mtr)
        self.mtr_note = QLabel("")
        self.mtr_note.setObjectName("muted")
        row.addWidget(self.mtr_target, 1)
        row.addWidget(self.mtr_note)
        row.addWidget(self.mtr_btn)
        lay.addLayout(row)
        self.mtr_table = _table(["Hop", "Address", "Name", "Loss", "Sent", "Last", "Avg", "Best", "Worst"],
                                stretch_col=2)
        lay.addWidget(self.mtr_table, 1)
        self.mtr_hops, self.mtr_stats = [], {}
        self.mtr_pinger = Pinger(workers=32)  # every hop each round, however long the path
        self.mtr_pinger.result.connect(self.mtr_result)
        self.mtr_timer = QTimer(self)
        self.mtr_timer.timeout.connect(lambda: self.mtr_pinger.ping([ip for ip in self.mtr_hops if ip]))
        return w

    def toggle_mtr(self):
        if self.mtr_timer.isActive() or not self.mtr_btn.isEnabled():
            self.mtr_timer.stop()
            self.mtr_btn.setText("Start")
            self.mtr_note.setText("Stopped.")
            return
        target = self.mtr_target.text().strip()
        if not target or target.startswith("-"):
            return
        self.mtr_btn.setEnabled(False)
        self.mtr_note.setText("Finding the route…")
        self.worker.run("tk:hops", find_hops, target)

    def mtr_started(self, res):
        self.mtr_btn.setEnabled(True)
        if isinstance(res, Exception):
            self.mtr_note.setText(f"⚠ {res}")
            return
        target_ip, hops = res
        self.mtr_hops = hops
        self.mtr_stats = {ip: {"sent": 0, "lost": 0, "last": None, "all": []} for ip in hops if ip}
        t = self.mtr_table
        t.setRowCount(len(hops))
        for i, ip in enumerate(hops):
            _set_row(t, i, [i + 1, ip or "no reply", "", "", "", "", "", "", ""],
                     {1: T.MUTED if not ip else T.TEXT})
        self.worker.run("tk:hopnames", lambda: {ip: reverse_name(ip) for ip in hops if ip})
        self.mtr_note.setText(f"{len(hops)} hops to {target_ip}")
        self.mtr_btn.setText("Stop")
        self.mtr_timer.start(1000)

    def mtr_result(self, ip, _when, ms):
        st = self.mtr_stats.get(ip)
        if st is None or not self.mtr_timer.isActive():
            return
        st["sent"] += 1
        st["last"] = ms
        if ms is None:
            st["lost"] += 1
        else:
            st["all"].append(ms)
        loss = 100 * st["lost"] / st["sent"]
        vals = st["all"]
        fmt = lambda v: "—" if v is None else f"{v:.1f} ms"
        for i, hop in enumerate(self.mtr_hops):
            if hop == ip:
                _set_row(self.mtr_table, i, [i + 1, ip, self.mtr_table.item(i, 2).text() if self.mtr_table.item(i, 2)
                                             else "", f"{loss:.0f}%", st["sent"], fmt(ms),
                                             fmt(sum(vals) / len(vals) if vals else None),
                                             fmt(min(vals) if vals else None), fmt(max(vals) if vals else None)],
                         {3: T.AMBER if loss else T.TEXT})

    # ---- LAN speed test ----------------------------------------------------------------

    def build_lan_panel(self):
        w, lay = _panel("LAN speed test", "The real speed between this computer and another one running "
                                          "NetScan: good for finding a slow Wi-Fi link or cable. On the other "
                                          "computer, tick “Allow LAN speed tests”, then enter its address here.")
        self.lan_server = LanSpeedServer(on_event=lambda text: self.worker.done.emit("tk:lanevent", text))
        self.lan_allow = QCheckBox(f"Allow LAN speed tests on this computer (port {LAN_PORT}, your network only, "
                                   "switches off after 15 idle minutes)")
        self.lan_allow.toggled.connect(self.toggle_lan_server)
        self.lan_server_note = QLabel("")
        self.lan_server_note.setObjectName("muted")
        self.lan_server_note.setWordWrap(True)
        self.lan_server_note.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(self.lan_allow)
        lay.addWidget(self.lan_server_note)
        row = QHBoxLayout()
        self.lan_host = QComboBox()
        self.lan_host.setEditable(True)
        self.lan_host.lineEdit().setPlaceholderText("Other computer's IP address")
        self.lan_btn = QPushButton("Test speed")
        self.lan_btn.setObjectName("primary")
        self.lan_btn.clicked.connect(self.run_lan_test)
        row.addWidget(self.lan_host, 1)
        row.addWidget(self.lan_btn)
        lay.addLayout(row)
        tiles = QHBoxLayout()
        self.lan_tiles = {}
        for key, label in (("down", "From it to here"), ("up", "From here to it")):
            frame, value, detail = self.make_tile(label)
            tiles.addWidget(frame)
            self.lan_tiles[key] = (value, detail)
        lay.addLayout(tiles)
        lay.addStretch(1)
        return w

    def toggle_lan_server(self, on):
        if not on:
            self.lan_server.stop()
            self.lan_server_note.setText("")
            return
        try:
            self.lan_server.start()
        except OSError as e:
            self.lan_allow.blockSignals(True)
            self.lan_allow.setChecked(False)
            self.lan_allow.blockSignals(False)
            self.lan_server_note.setText(f"⚠ Couldn't listen on port {LAN_PORT}: {e}")
            return
        me = self.local_ip() or (self.networks[0]["local_ip"] if self.networks else "this computer's IP")
        note = f"Listening. On the other computer, test against {me}."
        if ufw_active():
            lan = str(self.current["network"]) if self.current else "192.168.0.0/16"
            note += (f" Your firewall (ufw) blocks incoming connections; allow them once with: "
                     f"sudo ufw allow proto tcp from {lan} to any port {LAN_PORT}")
        self.lan_server_note.setText(note)

    def run_lan_test(self):
        host = self.lan_host.currentText().strip().split()[0] if self.lan_host.currentText().strip() else ""
        if not host or host.startswith("-"):
            return
        self.lan_btn.setEnabled(False)
        for value, detail in self.lan_tiles.values():
            value.setText("…")
            detail.setText("testing (about 10 seconds)")
        self.worker.run("tk:lan", lan_speed_test, host)

    def lan_hosts_changed(self):
        """Offer scanned devices in the LAN test's address box."""
        current = self.lan_host.currentText()
        self.lan_host.blockSignals(True)
        self.lan_host.clear()
        for ip in sorted((ip for ip in self.hosts if ":" not in ip and ip != self.local_ip()), key=ip_sort_key):
            self.lan_host.addItem(f"{ip}  {self.monitor_label(ip) if self.monitor_label(ip) != ip else ''}".strip())
        self.lan_host.setEditText(current)
        self.lan_host.blockSignals(False)

    # ---- domain toolkit ----------------------------------------------------------------

    def build_domain_panel(self):
        w, lay = _panel("Domain toolkit", "Who a domain is registered with and until when, its name and mail "
                                          "servers, and whether its email is protected against spoofing "
                                          "(SPF, DMARC, DKIM), in plain English.")
        row = QHBoxLayout()
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText("example.com")
        self.domain_edit.returnPressed.connect(self.run_domain)
        self.domain_btn = QPushButton("Check")
        self.domain_btn.setObjectName("primary")
        self.domain_btn.clicked.connect(self.run_domain)
        row.addWidget(self.domain_edit, 1)
        row.addWidget(self.domain_btn)
        lay.addLayout(row)
        self.domain_out = QTextBrowser()
        lay.addWidget(self.domain_out, 1)
        return w

    def run_domain(self):
        name = self.domain_edit.text().strip() or "example.com"
        if not all(c.isalnum() or c in ".-/:" for c in name):
            self.domain_out.setHtml(f'<p style="color:{T.AMBER}">That doesn\'t look like a domain.</p>')
            return
        self.domain_btn.setEnabled(False)
        self.domain_out.setHtml(f'<p style="color:{T.MUTED}">Checking…</p>')
        self.worker.run("tk:domain", domain_report, name)

    def show_domain(self, rep):
        e = html.escape
        parts = [f"<p><b>{e(rep['domain'])}</b></p>"]
        r = rep.get("rdap")
        if r:
            rows = [("Registrar", r["registrar"] or "?"), ("Registered", r["created"] or "?"),
                    ("Expires", r["expires"] or "?"), ("Last changed", r["changed"] or "?"),
                    ("Status", ", ".join(r["status"]) or "?")]
            parts.append(self.html_rows([(f'<span style="color:{T.MUTED}">{k}</span>', e(v)) for k, v in rows]))
        else:
            parts.append(f'<p style="color:{T.MUTED}">Registration details unavailable '
                         f'({e(rep.get("rdap_error", "no answer"))}); some country domains don\'t publish them.</p>')
        dns_rows = [("Name servers", ", ".join(rep["ns"]) or "—"),
                    ("Mail servers", ", ".join(f"{host} ({pref})" for pref, host in rep["mx"]) or "—"),
                    ("SPF", rep["spf"][0] if rep["spf"] else "—"), ("DMARC", rep["dmarc"][0] if rep["dmarc"] else "—")]
        parts.append("<p><b>DNS</b></p>" + self.html_rows([(f'<span style="color:{T.MUTED}">{k}</span>', e(v))
                                                          for k, v in dns_rows]))
        color = {"good": T.GREEN, "warn": T.AMBER, "info": T.MUTED}
        mark = {"good": "✓", "warn": "⚠", "info": "·"}
        parts.append("<p><b>Email security</b></p>" + "".join(
            f'<p style="color:{color[lvl]}">{mark[lvl]} {e(text)}</p>' for lvl, text in email_verdicts(rep)))
        self.domain_out.setHtml("".join(parts))

    # ---- website watch -----------------------------------------------------------------

    def build_webwatch_panel(self):
        w, lay = _panel("Website watch", f"Sites checked every {WEB_WATCH_MINUTES} minutes while NetScan is "
                                         "open. You get a notification when one goes down or comes back, and "
                                         "when its certificate has under 14 days left.")
        row = QHBoxLayout()
        self.web_edit = QLineEdit()
        self.web_edit.setPlaceholderText("https://example.com")
        self.web_edit.returnPressed.connect(self.add_website)
        add = QPushButton("Add")
        add.setObjectName("primary")
        add.clicked.connect(self.add_website)
        check = QPushButton("Check now")
        check.clicked.connect(self.check_websites)
        remove = QPushButton("Remove")
        remove.clicked.connect(self.remove_websites)
        row.addWidget(self.web_edit, 1)
        row.addWidget(add)
        row.addWidget(check)
        row.addWidget(remove)
        lay.addLayout(row)
        self.web_table = _table(["Site", "Status", "Response", "Certificate", "Last checked"], stretch_col=0)
        lay.addWidget(self.web_table, 1)
        self.web_sites = load_watch()   # [{"url", "added"}]
        self.web_state = {}              # url -> last check result
        self.web_timer = QTimer(self)
        self.web_timer.timeout.connect(self.check_websites)
        if self.web_sites:
            self.web_timer.start(WEB_WATCH_MINUTES * 60_000)
            QTimer.singleShot(8000, self.check_websites)
        self.show_websites()
        return w

    def add_website(self):
        url = self.web_edit.text().strip()
        if not url or " " in url:
            return
        if "://" not in url:
            url = "https://" + url
        if url not in [s["url"] for s in self.web_sites]:
            self.web_sites.append({"url": url, "added": time.strftime("%Y-%m-%d")})
            save_watch(self.web_sites)
        self.web_edit.clear()
        if not self.web_timer.isActive():
            self.web_timer.start(WEB_WATCH_MINUTES * 60_000)
        self.show_websites()
        self.check_websites()

    def remove_websites(self):
        rows = sorted({i.row() for i in self.web_table.selectedIndexes()})
        gone = {self.web_table.item(r, 0).text() for r in rows}
        self.web_sites = [s for s in self.web_sites if s["url"] not in gone]
        save_watch(self.web_sites)
        if not self.web_sites:
            self.web_timer.stop()
        self.show_websites()

    def check_websites(self):
        urls = [s["url"] for s in self.web_sites]
        if urls:
            self.worker.run("tk:web", lambda: [check_site(u) for u in urls])

    def websites_checked(self, results):
        for res in results:
            before = self.web_state.get(res["url"])
            self.web_state[res["url"]] = res
            if before is not None and before["ok"] != res["ok"]:
                if res["ok"]:
                    notify(f"{res['url']} is back up", f"HTTP {res['status']}, {res['ms']:.0f} ms")
                else:
                    notify(f"{res['url']} is down", res["error"] or f"HTTP {res['status']}")
            days = res["cert_days"]
            warned = (before or {}).get("cert_warned_day")
            if days is not None and days < 14 and warned != time.strftime("%Y-%m-%d"):
                notify(f"Certificate for {res['url']} expires soon",
                       f"{days} day(s) left" if days >= 0 else f"expired {-days} day(s) ago")
                res["cert_warned_day"] = time.strftime("%Y-%m-%d")
            elif warned:
                res["cert_warned_day"] = warned
        self.show_websites()

    def show_websites(self):
        t = self.web_table
        t.setRowCount(len(self.web_sites))
        for i, site in enumerate(self.web_sites):
            res = self.web_state.get(site["url"])
            if res is None:
                _set_row(t, i, [site["url"], "not checked yet", "", "", ""], {1: T.MUTED})
                continue
            status = (f"up (HTTP {res['status']})" if res["ok"] else
                      f"DOWN: {res['error'] or 'HTTP ' + str(res['status'])}")
            days = res["cert_days"]
            cert = "—" if days is None else (f"expired {-days} days ago" if days < 0 else f"{days} days left")
            _set_row(t, i, [site["url"], status, f"{res['ms']:.0f} ms", cert, res["checked"][11:19]],
                     {1: T.GREEN if res["ok"] else T.RED,
                      3: T.AMBER if days is not None and days < 14 else T.TEXT})
        t.resizeColumnsToContents()

    # ---- DNS speed comparison ----------------------------------------------------------

    def build_dnsbench_panel(self):
        w, lay = _panel("DNS speed", "How fast your DNS server answers compared with big public ones: for "
                                     "sites you visit often (usually remembered) and for names it has never seen. "
                                     "Takes a few seconds; public servers are asked over encrypted DNS.")
        row = QHBoxLayout()
        row.addStretch(1)
        self.dnsbench_btn = QPushButton("Compare")
        self.dnsbench_btn.setObjectName("primary")
        self.dnsbench_btn.clicked.connect(self.run_dnsbench)
        row.addWidget(self.dnsbench_btn)
        lay.addLayout(row)
        self.dnsbench_table = _table(["DNS server", "How", "Sites you visit", "New names", "Failed"], stretch_col=0)
        self.dnsbench_table.setMaximumHeight(34 + 30 * 5)
        lay.addWidget(self.dnsbench_table)
        self.dnsbench_verdict = QLabel("")
        self.dnsbench_verdict.setWordWrap(True)
        lay.addWidget(self.dnsbench_verdict)
        lay.addStretch(1)
        return w

    def run_dnsbench(self):
        self.dnsbench_btn.setEnabled(False)
        self.dnsbench_verdict.setText("Comparing…")
        self.worker.run("tk:dnsbench", dns_benchmark)

    def show_dnsbench(self, res):
        t = self.dnsbench_table
        rows = res["rows"]
        t.setRowCount(len(rows))
        ok = [r for r in rows if r.get("uncached") is not None]
        best_new = min((r["uncached"] for r in ok), default=None)
        fmt = lambda v: "—" if v is None else ("under 1 ms" if v < 1 else f"{v:.0f} ms")
        for i, r in enumerate(rows):
            if r.get("error"):
                _set_row(t, i, [r["name"], r["how"], f"no answer: {r['error']}", "", ""], {2: T.AMBER})
                continue
            _set_row(t, i, [r["name"], r["how"], fmt(r["cached"]), fmt(r["uncached"]), r["failed"] or ""],
                     {3: T.GREEN if r["uncached"] == best_new else T.TEXT})
        t.resizeColumnsToContents()
        self.dnsbench_verdict.setText(res["verdict"])

    # ---- history -----------------------------------------------------------------------

    HISTORY_VIEWS = [("Devices online", "online", "devices", False),
                     ("Latency (Monitor tab)", "latency", "ms", False),
                     ("Packet loss (Monitor tab)", "loss", "%", False),
                     ("Internet latency (Internet tab checks)", "internet_ms", "ms", True),
                     ("Speed tests: download", "down", "Mbit/s", True),
                     ("Speed tests: upload", "up", "Mbit/s", True)]

    def build_history_panel(self):
        w, lay = _panel("History", "What NetScan has recorded over time while it was open (kept 30 days): devices "
                                   "online, latency from the Monitor tab, speed tests, and a timeline of outages, "
                                   "new devices and port changes.")
        row = QHBoxLayout()
        self.hist_view = QComboBox()
        for label, *_rest in self.HISTORY_VIEWS:
            self.hist_view.addItem(label)
        self.hist_range = QComboBox()
        for label, secs in (("Last 24 hours", 86400), ("Last 7 days", 7 * 86400), ("Last 30 days", 30 * 86400)):
            self.hist_range.addItem(label, secs)
        for combo in (self.hist_view, self.hist_range):
            combo.currentIndexChanged.connect(self.show_history)
        row.addWidget(self.hist_view, 1)
        row.addWidget(self.hist_range)
        lay.addLayout(row)
        self.hist_chart = TimeSeriesChart()
        lay.addWidget(self.hist_chart, 2)
        self.hist_events = QTextBrowser()
        lay.addWidget(self.hist_events, 1)
        return w

    def show_history(self):
        label, kind, unit, dots = self.HISTORY_VIEWS[self.hist_view.currentIndex()]
        until = time.time()
        since = until - self.hist_range.currentData()
        if kind == "latency":
            self.history_avg.flush()  # include the minute in progress
        data = history_db.series(kind, since)
        series = [(key, i, points) for i, (key, points) in enumerate(sorted(data.items()))][:8]
        hint = {"latency": "Add devices on the Monitor tab: their latency is recorded here every minute.",
                "loss": "Add devices on the Monitor tab: their packet loss is recorded here every minute.",
                "down": "Run a speed test on the Internet tab to start a history.",
                "up": "Run a speed test on the Internet tab to start a history.",
                "internet_ms": "Press Check now on the Internet tab to start a history."}.get(kind, "Run a scan to start.")
        plan = self.speed_plan() if kind in ("down", "up") else None
        reference = (plan[kind], "your plan") if plan and plan.get(kind) else None
        self.hist_chart.set_data(series, unit, since, until, dots=dots, empty=f"No data for this period yet. {hint}",
                                 reference=reference)
        self.hist_events.setHtml(self.history_events_html(since))

    def history_events_html(self, since):
        """Outages, new devices and port changes from the device list, newest first."""
        e = html.escape
        events = []
        for mac, d in self.devices.devices.items():
            name = d.get("nickname") or d.get("hostname") or d.get("ip") or mac
            for ev in d.get("uptime_log", []):
                events.append((ev["time"], T.AMBER if ev["state"] == "down" else T.GREEN,
                               f"{name} went offline" if ev["state"] == "down" else
                               f"{name} back online" + (f" after {ev['downtime']}" if ev.get("downtime") else "")))
            if d.get("first_seen"):
                events.append((d["first_seen"], T.ACCENT_HI, f"New device: {name} ({d.get('vendor') or mac})"))
            for ch in d.get("port_changes", []):
                bits = [f"+{x}" for x in ch.get("opened", [])] + [f"−{x}" for x in ch.get("closed", [])]
                events.append((ch["time"], T.TEXT, f"{name}: ports {' '.join(bits)}"))
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(since))
        events = sorted((ev for ev in events if ev[0] >= cutoff), reverse=True)[:200]
        if not events:
            return f'<p style="color:{T.MUTED}">No outages, new devices or port changes in this period.</p>'
        return "".join(f'<p><span style="color:{T.MUTED}">{e(t[:16].replace("T", " "))}</span>&nbsp; '
                       f'<span style="color:{c}">{e(text)}</span></p>' for t, c, text in events)

    # ---- known vulnerabilities (opt-in) --------------------------------------------------

    def check_vulns(self, ip):
        ports = self.ports.get(ip) or []
        if not versioned_cpes(ports):
            QMessageBox.information(self, "NetScan", "No software versions known for this device yet. Tick "
                                    "“Detect versions (slower)” and run Scan Ports on it first.")
            return
        if not self.settings.value("vuln_consent", False, type=bool):
            answer = QMessageBox.question(
                self, "Check known vulnerabilities",
                "This sends the software names and versions found on this device (for example “OpenSSH "
                "10.0”) to NIST's National Vulnerability Database. No addresses or device names are sent.\n\n"
                "Allow NetScan to do this when you ask?")
            if answer != QMessageBox.Yes:
                return
            self.settings.setValue("vuln_consent", True)
        self.status.setText(f"Checking known vulnerabilities for {ip} (the public database allows a few "
                            "lookups per 30 seconds)…")
        self.worker.run("tk:vuln", lambda: (ip, host_vulnerabilities(ports)))

    def show_vulns(self, ip, found):
        e = html.escape
        color = {"CRITICAL": T.RED, "HIGH": T.RED, "MEDIUM": T.AMBER, "LOW": T.MUTED}
        total = sum(len(v["vulns"] or []) for v in found.values())
        parts = [f"<p><b>{e(self.monitor_label(ip))}</b> ({e(ip)}): {total} known issue(s) recorded for the "
                 "detected software versions.</p>",
                 f'<p style="color:{T.MUTED}">Matches are by version number only. Linux distributions often fix '
                 "problems without changing the version (e.g. “OpenSSH 10.0p2 Debian 7+deb13u4”), so some of "
                 "these may already be patched on this device. Keeping the device updated is what matters.</p>"]
        for label, info in found.items():
            parts.append(f"<p><b>{e(label)}</b>: {e(info['product'])}"
                         f' <span style="color:{T.MUTED}">({e(info["cpe"])})</span></p>')
            if info["vulns"] is None:
                parts.append(f'<p style="color:{T.AMBER}">Can\'t check: NVD doesn\'t list this product under the '
                             "name nmap reported, so no result here doesn't mean it's safe.</p>")
                continue
            if not info["vulns"]:
                parts.append(f'<p style="color:{T.GREEN}">✓ No known issues recorded in NVD for this version.</p>')
                continue
            rows = []
            for v in info["vulns"][:40]:
                sev = v["severity"] or "?"
                rows.append((f'<a href="https://nvd.nist.gov/vuln/detail/{e(v["id"])}">{e(v["id"])}</a>',
                             f'<span style="color:{color.get(sev, T.TEXT)}">{e(sev.title())} {v["score"] or ""}</span>',
                             e(v["summary"][:180] + ("…" if len(v["summary"]) > 180 else ""))))
            parts.append(self.html_rows(rows, ["Advisory", "Severity", "Summary"]))
            if len(info["vulns"]) > 40:
                parts.append(f'<p style="color:{T.MUTED}">…and {len(info["vulns"]) - 40} more (lower severity).</p>')
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Known vulnerabilities: {ip}")
        dlg.resize(900, 620)
        lay = QVBoxLayout(dlg)
        out = QTextBrowser()
        out.setOpenExternalLinks(True)
        out.setHtml("".join(parts))
        lay.addWidget(out)
        close = QPushButton("Close")
        close.clicked.connect(dlg.accept)
        lay.addWidget(close, 0, Qt.AlignRight)
        dlg.setAttribute(Qt.WA_DeleteOnClose)
        dlg.show()
        self.status.setText(f"{total} known issue(s) for {ip}'s detected software; see the window for details.")

    # ---- results from the background worker --------------------------------------------

    def toolkit_done(self, tag, res):
        if tag == "connections":
            self.conn_btn.setEnabled(True)
            if isinstance(res, Exception):
                self.conn_note.setText(f"⚠ {res}")
            else:
                self.show_connections(res)
        elif tag == "hops":
            self.mtr_started(res)
        elif tag == "hopnames" and not isinstance(res, Exception):
            for i, ip in enumerate(self.mtr_hops):
                if ip and res.get(ip) and self.mtr_table.item(i, 2):
                    self.mtr_table.item(i, 2).setText(res[ip])
            self.mtr_table.resizeColumnsToContents()
        elif tag == "lan":
            self.lan_btn.setEnabled(True)
            if isinstance(res, Exception):
                for value, detail in self.lan_tiles.values():
                    value.setText("—")
                hint = (" Is “Allow LAN speed tests” ticked on it, and its firewall open for port "
                        f"{LAN_PORT}?") if isinstance(res, OSError) else ""
                self.lan_tiles["down"][1].setText(f"failed: {res}.{hint}")
                self.lan_tiles["up"][1].setText("")
            else:
                for key in ("down", "up"):
                    value, detail = self.lan_tiles[key]
                    value.setText(f"{res[key]:.0f} Mbit/s")
                    detail.setText(f"≈ {res[key] / 8:.1f} MB/s with {res['host']}")
        elif tag == "lanevent":
            self.status.setText(str(res))
        elif tag == "domain":
            self.domain_btn.setEnabled(True)
            if isinstance(res, Exception):
                self.domain_out.setHtml(f'<p style="color:{T.AMBER}">⚠ {html.escape(str(res))}</p>')
            else:
                self.show_domain(res)
        elif tag == "web" and not isinstance(res, Exception):
            self.websites_checked(res)
        elif tag == "vuln":
            if isinstance(res, Exception):
                self.status.setText(f"⚠ Vulnerability lookup failed: {getattr(res, 'reason', res)}")
            else:
                self.show_vulns(*res)
        elif tag == "dnsbench":
            self.dnsbench_btn.setEnabled(True)
            if isinstance(res, Exception):
                self.dnsbench_verdict.setText(f"⚠ {res}")
            else:
                self.show_dnsbench(res)
