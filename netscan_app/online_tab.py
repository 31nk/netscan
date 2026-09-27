"""Tools panels that look from the outside in: Gaming & calls, VPN & privacy, What the internet sees,
Services & web pages, and Outages (the connection watch and the ISP report). Engines: online.py, outages.py,
checks.find_services."""

import html
import ipaddress
import os
import time

from PySide6.QtCore import QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextBrowser

from . import history_db
from . import theme as T
from .checks import find_services
from .insights_tab import findings_html, level_color
from .internet import bloat_grade
from .online import exposure_check, exposure_findings, gaming_check, gaming_verdicts, privacy_check, privacy_findings
from .outages import LATENCY_KEY, ROUTER_KEY, WATCH_SECONDS, OutageLog, _fmt_duration, build_isp_report, report_data
from .system import ping_once
from .toolkit_tab import _panel, _set_row, _table
from .widgets import notify


class OnlineMixin:
    """The outside-in panels. Mixed into MainWindow."""

    def build_online_panels(self):
        """[(title, widget)] for the Tools list (tools_tab.TOOL_GROUPS decides where each goes)."""
        return [("Gaming & calls", self.build_gaming_panel()), ("VPN & privacy", self.build_privacy_panel()),
                ("What the internet sees", self.build_exposure_panel()),
                ("Services & web pages", self.build_services_panel()), ("Outages", self.build_outages_panel())]

    def _run_row(self, lay, label, slot, note=""):
        row = QHBoxLayout()
        note_label = QLabel(note)
        note_label.setObjectName("muted")
        note_label.setWordWrap(True)
        btn = QPushButton(label)
        btn.setObjectName("primary")
        btn.clicked.connect(slot)
        row.addWidget(note_label, 1)
        row.addWidget(btn)
        lay.addLayout(row)
        return btn, note_label

    # ---- gaming & calls -------------------------------------------------------------------

    def build_gaming_panel(self):
        w, lay = _panel("Gaming & calls", "How your connection holds up for video calls, online games, cloud gaming "
                                          "and 4K streaming: 15 seconds of latency, jitter and loss, plus the delay to "
                                          "cloud regions games and call services run in. Uses your latest speed test "
                                          "and router check if you've run them.")
        self.game_btn, self.game_note = self._run_row(lay, "Test (15 seconds)", self.run_gaming)
        self.game_head = QLabel("")
        self.game_head.setObjectName("bigName")
        lay.addWidget(self.game_head)
        self.game_table = _table(["Activity", "Verdict", "Why"], stretch_col=2)
        self.game_table.setFixedHeight(40 + 30 * 4)
        lay.addWidget(self.game_table)
        self.region_table = _table(["Region", "Delay", "Jitter", ""], stretch_col=3)
        lay.addWidget(self.region_table, 1)
        self.last_nat_kind = None
        return w

    def run_gaming(self):
        self.game_btn.setEnabled(False)
        self.game_head.setText("")
        self.game_note.setText("Measuring for about 15 seconds; avoid big downloads meanwhile…")
        self.worker.run("on:gaming", gaming_check)

    def latest_speed(self, days=7):
        """The newest speed test in History (within `days`), as {down, up, grade, when} or None."""
        since = time.time() - days * 86400
        downs = history_db.rows("down", since)
        if not downs:
            return None
        ts = downs[-1][0]
        near = lambda kind: next((v for t, _k, v in reversed(history_db.rows(kind, ts - 5)) if abs(t - ts) < 5), None)
        added = near("bloat")
        return {"down": downs[-1][2], "up": near("up"), "grade": bloat_grade(added) if added is not None else None,
                "when": ts}

    def show_gaming(self, res):
        speed = self.latest_speed()
        verdicts, nearest = gaming_verdicts(res, speed, self.last_nat_kind)
        t = self.game_table
        t.setRowCount(len(verdicts))
        for i, (activity, level, verdict, why) in enumerate(verdicts):
            _set_row(t, i, [activity, verdict, why], {1: level_color(level)})
        t.resizeColumnsToContents()
        worst = next((lvl for lvl in ("bad", "warn") if any(v[1] == lvl for v in verdicts)), "good")
        self.game_head.setText({"good": "Ready for calls and games", "warn": "Mostly fine, with some hiccups",
                                "bad": "Expect trouble with some of these"}[worst])
        self.game_head.setStyleSheet(f"color: {level_color(worst)};")
        st = res["stability"]
        rt = self.region_table
        regions = sorted(res["regions"], key=lambda x: (x[1] is None or x[1]["median"] is None,
                                                        (x[1] or {}).get("median") or 0))
        rt.setRowCount(len(regions))
        for i, (name, r) in enumerate(regions):
            if not r or r["median"] is None:
                _set_row(rt, i, [name, "no answer", "", ""], {1: T.MUTED})
                continue
            ms = r["median"]
            _set_row(rt, i, [name, f"{ms:.0f} ms", f"{r['jitter'] or 0:.0f} ms",
                             "nearest" if nearest and name == nearest[0] else
                             "great for games" if ms < 60 else "fine for calls" if ms < 150 else "far away"],
                     {1: T.GREEN if ms < 60 else T.AMBER if ms < 150 else T.MUTED})
        rt.resizeColumnsToContents()
        used = []
        if speed:
            used.append(f"speed test from {time.strftime('%a %H:%M', time.localtime(speed['when']))}")
        if self.last_nat_kind:
            used.append("router check")
        self.game_note.setText(f"Jitter {st['jitter'] or 0:.1f} ms and {st['loss']:.0f}% loss over 40 pings to "
                               f"1.1.1.1 ({st['median'] or 0:.0f} ms typical)."
                               + (f" Also used: {', '.join(used)}." if used else
                                  " Run a speed test (Internet tab) to include bandwidth and bufferbloat."))

    # ---- VPN & privacy ---------------------------------------------------------------------

    def build_privacy_panel(self):
        w, lay = _panel("VPN & privacy", "Whether a VPN is on and working: the address sites see, whether IPv6 "
                                         "slips past the VPN, and which DNS servers really see the sites you visit "
                                         "(a DNS leak test). Contacts Cloudflare, the RDAP registries and bash.ws "
                                         "(the leak test service).")
        self.priv_btn, self.priv_note = self._run_row(lay, "Check", self.run_privacy)
        self.priv_head = QLabel("")
        self.priv_head.setObjectName("bigName")
        lay.addWidget(self.priv_head)
        self.priv_out = QTextBrowser()
        lay.addWidget(self.priv_out, 1)
        return w

    def run_privacy(self):
        self.priv_btn.setEnabled(False)
        self.priv_head.setText("")
        self.priv_out.setHtml(f'<p style="color:{T.MUTED}">Checking (about 5 seconds)…</p>')
        gw = (self.watch_target() or {}).get("gateway")
        self.worker.run("on:privacy", privacy_check, gw)

    def show_privacy(self, m):
        findings, vpn = privacy_findings(m)
        worst = next((lvl for lvl in ("bad", "warn") if any(f[0] == lvl for f in findings)), "good")
        self.priv_head.setText({"bad": "Your VPN is leaking", "warn": "Mostly private, one thing to fix",
                                "good": "VPN working, no leaks found" if vpn else "No VPN in use"}[worst])
        self.priv_head.setStyleSheet(f"color: {level_color(worst if vpn or worst != 'good' else 'info')};")
        e = html.escape
        rows = [("Public IPv4", f"{m.get('v4') or '—'}  {m.get('v4_owner') or ''}  {m.get('country') or ''}"),
                ("Public IPv6", f"{m.get('v6') or 'none'}  {m.get('v6_owner') or ''}"),
                ("This computer asks", ", ".join(m.get("local_dns") or []) or "?"),
                ("Leak test says", m.get("dns_conclusion") or "—")]
        self.priv_out.setHtml(findings_html(findings)
                              + f'<p style="margin-top:16px;color:{T.MUTED}">DETAILS</p>'
                              + self.html_rows([(f'<span style="color:{T.MUTED}">{e(k)}</span>', e(v)) for k, v in rows])
                              + (f'<p style="color:{T.MUTED}">Some checks failed: {e("; ".join(m["errors"]))}</p>'
                                 if m.get("errors") else ""))

    # ---- what the internet sees -------------------------------------------------------------

    def build_exposure_panel(self):
        w, lay = _panel("What the internet sees", "Your public address as the rest of the internet sees it: which "
                                                  "ports are open to everyone (from Shodan's free InternetDB, which "
                                                  "scans the whole internet), known vulnerabilities on them, and "
                                                  "whether the address is on spam blocklists. Sends only your public "
                                                  "IP address to Shodan and the blocklists.")
        self.exp_btn, self.exp_note = self._run_row(lay, "Check", self.run_exposure)
        self.exp_head = QLabel("")
        self.exp_head.setObjectName("bigName")
        lay.addWidget(self.exp_head)
        self.exp_out = QTextBrowser()
        self.exp_out.setOpenExternalLinks(True)
        lay.addWidget(self.exp_out, 1)
        return w

    def run_exposure(self):
        self.exp_btn.setEnabled(False)
        self.exp_head.setText("")
        self.exp_out.setHtml(f'<p style="color:{T.MUTED}">Asking Shodan and the blocklists…</p>')
        self.worker.run("on:exposure", exposure_check, (self.watch_target() or {}).get("gateway"))

    def show_exposure(self, res):
        vpn = res.get("vpn", False)
        forwards = [m for m in (self.upnp or {}).get("mappings", []) if m.get("enabled", True)]
        findings = exposure_findings(res, vpn, forwards)
        ports = (res.get("shodan") or {}).get("ports") or []
        level = "bad" if any(f[0] == "bad" for f in findings) else "warn" if ports else "good"
        self.exp_head.setText(f"{len(ports)} port(s) open to the internet" if ports else
                              "Nothing open to the internet" if res.get("shodan") is not None else "Couldn't check")
        self.exp_head.setStyleSheet(f"color: {level_color(level)};")
        self.exp_note.setText(f"Public address {res['ip'] or '?'}" + (f" ({res['country']})" if res.get("country") else "")
                              + (": your VPN's server, not your home connection. Check with the VPN off to see "
                                 "your home's exposure." if vpn else "."))
        vulns = (res.get("shodan") or {}).get("vulns") or []
        links = ("<p>" + " ".join(f'<a href="https://nvd.nist.gov/vuln/detail/{html.escape(v)}">{html.escape(v)}</a>'
                                  for v in sorted(vulns)[:30]) + "</p>") if vulns else ""
        self.exp_out.setHtml(findings_html(findings) + links)

    # ---- services & web pages ---------------------------------------------------------------

    def build_services_panel(self):
        w, lay = _panel("Services & web pages", "Every web page (router, printer, NAS, Pi-hole, Home Assistant…) and "
                                                "every service devices announce (AirPlay, Chromecast, printers, file "
                                                "shares, HomeKit…) on your network. Double-click a web page to open "
                                                "it. Uses the devices from your scans and the device list.")
        row = QHBoxLayout()
        self.svc_filter = QLineEdit()
        self.svc_filter.setPlaceholderText("Filter…")
        self.svc_filter.setClearButtonEnabled(True)
        self.svc_filter.textChanged.connect(self.filter_services)
        self.svc_note = QLabel("")
        self.svc_note.setObjectName("muted")
        self.svc_btn = QPushButton("Find services")
        self.svc_btn.setObjectName("primary")
        self.svc_btn.clicked.connect(self.run_services)
        row.addWidget(self.svc_filter, 1)
        row.addWidget(self.svc_note)
        row.addWidget(self.svc_btn)
        lay.addLayout(row)
        self.svc_table = _table(["Device", "Service", "Name", "Address", "Details"], stretch_col=4)
        self.svc_table.cellDoubleClicked.connect(self.open_service_row)
        lay.addWidget(self.svc_table, 1)
        self.svc_rows = []
        return w

    def run_services(self):
        net = self.watch_target()
        if not net:
            self.svc_note.setText("No network detected.")
            return
        ips = {ip for ip in self.hosts if ":" not in ip}
        ips |= {d["ip"] for d in self.devices.devices.values()
                if d.get("ip") and ":" not in d["ip"] and self._in_net(d["ip"], net)}
        ips.discard(net["local_ip"])
        known = [(ip, p["port"]) for ip in ips for p in self.ports.get(ip) or [] if p.get("title")]
        self.svc_btn.setEnabled(False)
        self.svc_note.setText(f"Checking {len(ips)} device(s)…")
        self.worker.run("on:services", find_services, net["local_ip"], sorted(ips), known, net["network"])

    @staticmethod
    def _in_net(ip, net):
        try:
            return ipaddress.ip_address(ip) in net["network"]
        except ValueError:
            return False

    def show_services(self, rows):
        self.svc_rows = rows
        t = self.svc_table
        t.setSortingEnabled(False)
        t.setRowCount(len(rows))
        for i, r in enumerate(rows):
            device = self.monitor_label(r["ip"]) if r["ip"] in self.hosts else self.device_name_for(r["ip"]) or r["ip"]
            _set_row(t, i, [device if device != r["ip"] else r["ip"], r["kind"], r["name"], r["url"] or r["ip"],
                            r["detail"]], {3: T.ACCENT_HI if r["url"] else T.TEXT})
        t.resizeColumnsToContents()
        web = sum(1 for r in rows if r["url"])
        self.svc_note.setText(f"{web} web page(s), {len(rows) - web} other service(s)")
        self.filter_services()

    def filter_services(self):
        text = self.svc_filter.text().strip().lower()
        t = self.svc_table
        for r in range(t.rowCount()):
            t.setRowHidden(r, bool(text) and not any(text in (t.item(r, c).text().lower() if t.item(r, c) else "")
                                                     for c in range(t.columnCount())))

    def open_service_row(self, row, _col):
        url = self.svc_table.item(row, 3).text() if self.svc_table.item(row, 3) else ""
        if url.startswith("http"):
            QDesktopServices.openUrl(QUrl(url))

    # ---- outages and the ISP report -------------------------------------------------------------

    def build_outages_panel(self):
        w, lay = _panel("Outages", f"Keeps an eye on your connection while NetScan is open (a ping every "
                                   f"{WATCH_SECONDS} seconds to your router, 1.1.1.1 and 8.8.8.8) and records every "
                                   "outage: whether the internet dropped or your own network did. Save a report to "
                                   "send your internet provider.")
        row = QHBoxLayout()
        self.net_watch_box = QCheckBox("Watch the connection")
        self.net_watch_box.setChecked(self.settings.value("net_watch", False, type=bool))
        self.net_watch_box.toggled.connect(self.toggle_net_watch)
        self.outage_state = QLabel("")
        self.outage_state.setObjectName("muted")
        self.outage_range = QComboBox()
        for label, days in (("Last 24 hours", 1), ("Last 7 days", 7), ("Last 30 days", 30), ("Last 90 days", 90)):
            self.outage_range.addItem(label, days)
        self.outage_range.setCurrentIndex(1)
        self.outage_range.currentIndexChanged.connect(self.show_outages)
        report = QPushButton("Save ISP report…")
        report.clicked.connect(self.save_isp_report)
        row.addWidget(self.net_watch_box)
        row.addWidget(self.outage_state, 1)
        row.addWidget(self.outage_range)
        row.addWidget(report)
        lay.addLayout(row)
        tiles = QHBoxLayout()
        self.outage_tiles = {}
        for key, label in (("uptime", "Internet uptime"), ("count", "Outages"), ("down", "Total downtime"),
                           ("longest", "Longest")):
            frame, value, detail = self.make_tile(label)
            tiles.addWidget(frame)
            self.outage_tiles[key] = (value, detail)
        lay.addLayout(tiles)
        self.outage_table = _table(["Started", "Lasted", "What"], stretch_col=2)
        lay.addWidget(self.outage_table, 1)
        self.outage_log = OutageLog()
        self.outage_log.resume_check()
        self.watch_avg = history_db.MinuteAverager()
        self.net_watch_timer = QTimer(self)
        self.net_watch_timer.timeout.connect(self.net_watch_tick)
        self.net_watch_busy = False
        self.toggle_net_watch(self.net_watch_box.isChecked())
        return w

    def toggle_net_watch(self, on):
        self.settings.setValue("net_watch", on)
        if on:
            self.net_watch_timer.start(WATCH_SECONDS * 1000)
            QTimer.singleShot(3000, self.net_watch_tick)
            self.outage_state.setText("Watching…")
        else:
            self.net_watch_timer.stop()
            self.watch_avg.flush()
            self.outage_state.setText("Off. Tick to start recording outages.")

    def net_watch_tick(self):
        if self.net_watch_busy or not self.net_watch_timer.isActive():
            return
        self.net_watch_busy = True
        gw = (self.watch_target() or {}).get("gateway")

        def check():
            router = ping_once(gw) if gw else None
            internet = ping_once("1.1.1.1")
            if internet is None:
                internet = ping_once("8.8.8.8")
            return gw, router, internet

        self.worker.run("on:netwatch", check)

    def net_watch_result(self, res):
        self.net_watch_busy = False
        gw, router, internet = res
        now = time.time()
        self.last_watch = {"ts": now, "router": router, "internet": internet}  # for the Dashboard
        if gw:
            self.watch_avg.add(ROUTER_KEY, router, now)
        self.watch_avg.add(LATENCY_KEY, internet, now)
        event = self.outage_log.sample(router is not None or not gw, internet is not None, now)
        if event and event[1]["kind"] == "internet":
            kind, o = event
            if kind == "started":
                notify("Internet is down", "Your router answers, but the internet doesn't. NetScan is logging it.")
            else:
                notify("Internet is back", f"It was down for {_fmt_duration(o['end'] - o['start'])}.")
        ongoing = self.outage_log.ongoing
        self.outage_state.setText(
            (f"⚠ {'Internet' if ongoing['kind'] == 'internet' else 'Home network'} down since "
             f"{time.strftime('%H:%M', time.localtime(ongoing['start']))}" if ongoing else
             f"Connection fine at {time.strftime('%H:%M:%S')}"
             + (f" · internet {internet:.0f} ms" if internet is not None else "")))
        if event:
            self.poke_dashboard()
        if event and self.tool_nav.currentItem() and self.tool_nav.currentItem().text() == "Outages":
            self.show_outages()

    def outage_period(self):
        until = time.time()
        return until - self.outage_range.currentData() * 86400, until

    def show_outages(self):
        self.watch_avg.flush()
        since, until = self.outage_period()
        d = report_data(self.outage_log, since, until, self.speed_plan())
        s = d["summary"]
        t = self.outage_tiles
        t["uptime"][0].setText("—" if s["uptime"] is None else f"{s['uptime']:.2f}%")
        watched = s["watched_seconds"]
        t["uptime"][1].setText(("over " + (f"{watched / 3600:.1f} h" if watched >= 3600 else f"{watched // 60:.0f} min")
                                + " watched") if watched else "turn on the watch to measure")
        t["count"][0].setText(str(s["count"]))
        t["count"][1].setText(f"plus {s['home_count']} of your own network" if s["home_count"] else "internet outages")
        t["down"][0].setText(_fmt_duration(s["down_seconds"]))
        t["longest"][0].setText(_fmt_duration(s["longest"]))
        tbl = self.outage_table
        items = list(reversed(d["outages"]))
        tbl.setRowCount(len(items))
        for i, o in enumerate(items):
            lasted = ("still down" if o.get("ongoing") else "unknown (NetScan closed)" if o.get("unknown_end")
                      else _fmt_duration(o["end"] - o["start"]))
            internet = o["kind"] == "internet"
            _set_row(tbl, i, [time.strftime("%a %d %b %H:%M", time.localtime(o["start"])), lasted,
                              "Internet down (router fine)" if internet else "Home network or this computer offline"],
                     {2: T.AMBER if internet else T.MUTED})
        tbl.resizeColumnsToContents()

    def save_isp_report(self):
        since, until = self.outage_period()
        self.watch_avg.flush()
        page = build_isp_report(report_data(self.outage_log, since, until, self.speed_plan()))
        default = os.path.join(os.path.expanduser("~"), f"connection-report-{time.strftime('%Y-%m-%d')}.html")
        path, _ = QFileDialog.getSaveFileName(self, "Save connection report", default, "Web page (*.html)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(page)
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        self.status.setText(f"Saved the connection report to {path}")

    # ---- results from the background worker ------------------------------------------------------

    def online_done(self, tag, res):
        failed = isinstance(res, Exception)
        why = html.escape(str(res)) if failed else ""
        if tag == "gaming":
            self.game_btn.setEnabled(True)
            if failed:
                self.game_note.setText(f"⚠ {res}")
            else:
                self.show_gaming(res)
        elif tag == "privacy":
            self.priv_btn.setEnabled(True)
            if failed:
                self.priv_out.setHtml(f'<p style="color:{T.AMBER}">⚠ {why}</p>')
            else:
                self.show_privacy(res)
        elif tag == "exposure":
            self.exp_btn.setEnabled(True)
            if failed:
                self.exp_out.setHtml(f'<p style="color:{T.AMBER}">⚠ {why}</p>')
            else:
                self.show_exposure(res)
        elif tag == "services":
            self.svc_btn.setEnabled(True)
            if failed:
                self.svc_note.setText(f"⚠ {res}")
            else:
                self.show_services(res)
        elif tag == "netwatch":
            if failed:
                self.net_watch_busy = False
            else:
                self.net_watch_result(res)
