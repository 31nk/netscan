"""The checkup panels in the Tools tab: "Slow internet?", Security checkup, Router check (double NAT and DHCP
servers), Wi-Fi survey and Who's home. Engines live in checks.py."""

import html
import json
import os
import time

from PySide6.QtCore import QProcess, QProcessEnvironment
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QScrollArea, QTextBrowser,
)

from . import theme as T
from .columns import TAB_TOOLS
from .checks import (
    diagnosis, dhcp_args, dhcp_verdict, is_wireless, measure_connection, nat_measure, nat_verdict,
    parse_dhcp_discover, presence_rows, security_checkup, security_measure, survey_reading, survey_verdict,
)
from .devices import data_dir
from .internet import speed_test
from .system import IS_WIN
from .toolkit_tab import _panel, _set_row, _table
from .widgets import PresenceChart

MARKS = {"bad": "✗", "critical": "✗", "high": "✗", "warn": "⚠", "medium": "⚠", "low": "·", "info": "·", "good": "✓"}


def level_color(level):
    return {"bad": T.RED, "critical": T.RED, "high": T.RED, "warn": T.AMBER, "medium": T.AMBER,
            "low": T.TEXT, "info": T.MUTED, "good": T.GREEN}[level]


def findings_html(findings):
    e = html.escape
    return "".join(f'<p style="margin:10px 0 2px 0"><span style="color:{level_color(lvl)}">{MARKS[lvl]}</span>'
                   f"&nbsp; <b>{e(title)}</b></p>"
                   + (f'<p style="margin:0 0 0 18px;color:{T.MUTED}">{e(detail)}</p>' if detail else "")
                   for lvl, title, detail in findings)


def survey_file():
    return os.path.join(data_dir(), "wifi_survey.json")


class InsightsMixin:
    """The checkup panels. Mixed into MainWindow."""

    def build_insight_panels(self):
        """[(title, widget)] for the Tools list (tools_tab.TOOL_GROUPS decides where each goes)."""
        return [("Slow internet?", self.build_diagnose_panel()), ("Security checkup", self.build_security_panel()),
                ("Router check", self.build_router_panel()), ("Wi-Fi survey", self.build_survey_panel()),
                ("Who's home", self.build_presence_panel())]

    def open_tool(self, name):
        for row, tool in self.tool_rows():
            if tool == name:
                self.tabbar.setCurrentIndex(TAB_TOOLS)
                self.tool_nav.setCurrentRow(row)
                return

    def _headline(self):
        label = QLabel("")
        label.setObjectName("bigName")
        label.setWordWrap(True)
        return label

    # ---- slow internet? ------------------------------------------------------------------

    def build_diagnose_panel(self):
        w, lay = _panel("Slow internet?", "Finds where the problem is: this computer's Wi-Fi or cable, the router, "
                                          "your internet provider, DNS, or lag when the line is busy. Takes about "
                                          "5 seconds; pings your router, Cloudflare and Google.")
        row = QHBoxLayout()
        self.diag_speed = QCheckBox("Include a speed test (12 more seconds, uses up to 165 MB)")
        self.diag_btn = QPushButton("Find the problem")
        self.diag_btn.setObjectName("primary")
        self.diag_btn.clicked.connect(self.run_diagnosis)
        row.addWidget(self.diag_speed)
        row.addStretch(1)
        row.addWidget(self.diag_btn)
        lay.addLayout(row)
        self.diag_head = self._headline()
        lay.addWidget(self.diag_head)
        self.diag_out = QTextBrowser()
        lay.addWidget(self.diag_out, 1)
        return w

    def speed_plan(self):
        down, up = (self.settings.value(k, 0, type=int) for k in ("plan_down", "plan_up"))
        return {"down": down, "up": up} if down else None

    def run_diagnosis(self):
        net = self.watch_target()
        speed = self.diag_speed.isChecked()
        provider = self.speed_provider.currentData()
        self.diag_btn.setEnabled(False)
        self.diag_head.setText("")
        self.diag_out.setHtml(f'<p style="color:{T.MUTED}">Measuring… '
                              + ("then running the speed test (about 20 seconds in all)." if speed else "") + "</p>")
        self.worker.run("in:diagnose", lambda: (measure_connection(net), speed_test(provider=provider) if speed else None))

    def show_diagnosis(self, res):
        m, speed = res
        if speed:
            self.speed_finished(speed)  # the Internet tab's tiles and History get it too
        d = diagnosis(m, speed, self.speed_plan())
        self.diag_head.setText(d["headline"])
        self.diag_head.setStyleSheet(f"color: {level_color(d['level'])};")
        parts = [findings_html(d["findings"])]
        rows = []
        if m.get("router"):
            r = m["router"]
            rows.append(("Router", f"{r['avg']:.1f} ms, {r['loss']:.0f}% loss" if r["avg"] is not None else "no reply"))
        for key, name in (("cf", "Cloudflare"), ("google", "Google")):
            r = m.get(key)
            if r:
                rows.append((name, f"{r['avg']:.1f} ms, {r['loss']:.0f}% loss" if r["avg"] is not None else "no reply"))
        if m.get("dns_ms"):
            rows.append(("New DNS lookup", f"{m['dns_ms']:.0f} ms"))
        wifi = m.get("wifi")
        rows.append(("Connection", f"Wi-Fi “{wifi['ssid']}”, {wifi['signal']}% signal, {wifi['band']} channel "
                                   f"{wifi['channel']}" if wifi else "Wi-Fi" if m.get("wireless") else
                     f"cable ({m.get('iface') or '?'})"))
        if speed:
            rows.append(("Speed", f"{speed['down']:.0f} down / {speed['up']:.0f} up Mbit/s, bufferbloat "
                                  f"{speed.get('grade') or '?'}"))
        e = html.escape
        parts.append(f'<p style="margin-top:16px;color:{T.MUTED}">MEASURED</p>'
                     + self.html_rows([(f'<span style="color:{T.MUTED}">{e(k)}</span>', e(v)) for k, v in rows]))
        if m.get("errors"):
            parts.append(f'<p style="color:{T.MUTED}">Some checks failed: {e("; ".join(m["errors"]))}</p>')
        self.diag_out.setHtml("".join(parts))

    # ---- security checkup ---------------------------------------------------------------

    def build_security_panel(self):
        w, lay = _panel("Security checkup", "A grade for your network from what NetScan can see: Wi-Fi protection, "
                                            "ports opened to the internet, risky services, DNS tampering, signs of "
                                            "spoofing and devices you don't know. Uses your latest scan: find "
                                            "hosts with “Also scan top 100 ports” first for the full picture.")
        row = QHBoxLayout()
        self.sec_score = QLabel("")
        self.sec_score.setObjectName("tileValue")
        self.sec_note = QLabel("")
        self.sec_note.setObjectName("muted")
        self.sec_note.setWordWrap(True)
        self.sec_btn = QPushButton("Run checkup")
        self.sec_btn.setObjectName("primary")
        self.sec_btn.clicked.connect(self.run_security)
        row.addWidget(self.sec_score)
        row.addWidget(self.sec_note, 1)
        row.addWidget(self.sec_btn)
        lay.addLayout(row)
        self.sec_out = QTextBrowser()
        lay.addWidget(self.sec_out, 1)
        return w

    def run_security(self):
        self.sec_btn.setEnabled(False)
        self.sec_out.setHtml(f'<p style="color:{T.MUTED}">Checking Wi-Fi, DNS and this computer…</p>')
        self.worker.run("in:security", security_measure)

    def security_context(self, measured):
        gw, me = self.gateway(), self.local_ip()
        hosts = []
        for ip, h in self.hosts.items():
            if ":" in ip:
                continue
            rec = self.devices.get(h)
            hosts.append({"ip": ip, "name": self.monitor_label(ip) if self.monitor_label(ip) != ip else "",
                          "ports": self.network_ports(ip) if ip in self.ports else None,
                          "trusted": bool(rec.get("trusted")) or ip == me, "router": ip == gw, "this": ip == me})
        return {**measured, "hosts": hosts, "upnp": self.upnp, "any_trusted": self.devices.any_trusted(),
                "spoof": self.spoof_warnings}

    def show_security(self, measured):
        res = security_checkup(self.security_context(measured))
        self.last_security = {**res, "when": time.time()}  # for the Dashboard
        self.poke_dashboard()
        color = T.GREEN if res["score"] >= 75 else T.AMBER if res["score"] >= 50 else T.RED
        scanned = sum(1 for ip in self.hosts if ip in self.ports)
        if res["complete"]:
            self.sec_score.setText(f"{res['grade']}  {res['score']}/100")
            self.sec_score.setStyleSheet(f"color: {color};")
            self.sec_note.setText(f"{len(self.hosts)} device(s) from your latest scan, {scanned} with ports scanned"
                                  + (". Router port forwards checked." if self.upnp else
                                     ". Router port forwards not checked (its UPnP didn't answer).")
                                  + f" Checked at {time.strftime('%H:%M')}.")
        else:
            self.sec_score.setText("Incomplete")
            self.sec_score.setStyleSheet(f"color: {T.MUTED};")
            self.sec_note.setText("Only Wi-Fi, DNS and this computer were checked. For a grade, find hosts on the Scan "
                                  "tab with “Also scan top 100 ports” ticked, then run the checkup again.")
        errors = measured.get("errors")
        self.sec_out.setHtml(findings_html(res["findings"])
                             + (f'<p style="color:{T.MUTED}">Couldn\'t check: {html.escape("; ".join(errors))}</p>'
                                if errors else ""))

    # ---- router check: double NAT and DHCP servers -------------------------------------------

    def build_router_panel(self):
        w, lay = _panel("Router check", "Whether your router holds your public address directly, sits behind "
                                        "another router (double NAT), or shares an address with other customers "
                                        "(CGNAT): all three decide whether port forwarding, hosting and "
                                        "“open NAT” for games can work. Also finds every DHCP server handing out "
                                        "addresses: there should be exactly one.")
        row = QHBoxLayout()
        self.nat_btn = QPushButton("Check connection type")
        self.nat_btn.setObjectName("primary")
        self.nat_btn.clicked.connect(self.run_nat_check)
        self.dhcp_btn = QPushButton("Look for DHCP servers")
        self.dhcp_btn.setToolTip("Asks every DHCP server for an offer (without taking an address). Needs raw "
                                 "packets, so it may ask for your password.")
        self.dhcp_btn.clicked.connect(self.run_dhcp_check)
        row.addStretch(1)
        row.addWidget(self.dhcp_btn)
        row.addWidget(self.nat_btn)
        lay.addLayout(row)
        self.router_head = self._headline()
        lay.addWidget(self.router_head)
        self.router_out = QTextBrowser()
        lay.addWidget(self.router_out, 1)
        self.router_sections = {}
        self.dhcp_proc = None
        return w

    def show_router_sections(self):
        e = html.escape
        parts = []
        for key, title in (("nat", "CONNECTION TYPE"), ("dhcp", "DHCP SERVERS")):
            if key in self.router_sections:
                body, extra = self.router_sections[key]
                parts.append(f'<p style="margin-top:14px;color:{T.MUTED}">{title}</p>' + findings_html(body)
                             + (f'<p style="color:{T.MUTED}">{e(extra)}</p>' if extra else ""))
        self.router_out.setHtml("".join(parts))

    def run_nat_check(self):
        self.nat_btn.setEnabled(False)
        self.router_head.setText("")
        self.router_sections["nat"] = ([("info", "Checking…", "")], "")
        self.show_router_sections()
        net, wan = self.watch_target(), (self.upnp or {}).get("public_ip") or None
        self.worker.run("in:nat", nat_measure, net, wan)

    def show_nat(self, m):
        v = nat_verdict(m)
        self.last_nat_kind = v["kind"]  # Gaming & calls mentions strict NAT
        self.router_head.setText(v["headline"])
        self.router_head.setStyleSheet(f"color: {level_color(v['level'])};")
        hops = " → ".join(h or "?" for h in (m.get("hops") or [])[:5])
        extra = " · ".join(x for x in (f"public IP {m['public_ip']}" if m.get("public_ip") else "",
                                        f"router's internet side {m['router_wan']}" if m.get("router_wan") else
                                        "router's UPnP not available", f"route {hops}" if hops else "",
                                        "; ".join(m.get("errors") or [])) if x)
        self.router_sections["nat"] = (v["findings"], extra)
        self.show_router_sections()

    def run_dhcp_check(self):
        if not self.nmap:
            return
        net = self.watch_target()
        if IS_WIN and not self.has_root:
            QMessageBox.information(self, "NetScan", "Looking for DHCP servers needs Npcap (installed with nmap).")
            return
        args = dhcp_args(net["iface"] if net else None)
        prompt = bool(self.root and not self.nmap_caps and not IS_WIN)
        if self.nmap_caps:
            args.insert(0, "--privileged")
        program, argv = (self.root[0], [*self.root[1:], self.nmap, *args]) if prompt else (self.nmap, args)
        self.dhcp_btn.setEnabled(False)
        self.router_sections["dhcp"] = ([("info", "Asking for DHCP offers (about 6 seconds)…"
                                          + (" Authorise in the password prompt." if prompt else ""), "")], "")
        self.show_router_sections()
        self.dhcp_proc = QProcess(self)
        self.dhcp_proc.finished.connect(self.dhcp_done)
        if prompt and self.askpass:
            env = QProcessEnvironment.systemEnvironment()
            env.insert("SUDO_ASKPASS", self.askpass)
            self.dhcp_proc.setProcessEnvironment(env)
        self.dhcp_proc.start(program, argv)

    def dhcp_done(self, code, _status):
        self.dhcp_btn.setEnabled(True)
        out = bytes(self.dhcp_proc.readAllStandardOutput()).decode(errors="replace")
        err = bytes(self.dhcp_proc.readAllStandardError()).decode(errors="replace").strip()
        servers = parse_dhcp_discover(out)
        self.last_dhcp = [s["server"] for s in servers]  # for the site audit
        if code != 0 and not servers:
            why = ("the password prompt was cancelled" if code in (126, 127) else
                   err.splitlines()[-1] if err else f"nmap exited with code {code}")
            self.router_sections["dhcp"] = ([("warn", "Couldn't ask for DHCP offers", why)], "")
        else:
            extra = "; ".join(f"{s['server']} offered {s['offered'] or '?'} (router {s['router'] or '?'}, DNS "
                              f"{s['dns'] or '?'})" for s in servers)
            self.router_sections["dhcp"] = (dhcp_verdict(servers, self.gateway() or
                                                         (self.watch_target() or {}).get("gateway")), extra)
        self.show_router_sections()

    # ---- Wi-Fi survey -----------------------------------------------------------------------

    def build_survey_panel(self):
        w, lay = _panel("Wi-Fi survey", "Carry this laptop around: in each room, type its name and press Measure. "
                                        "You get the signal per room, so dead spots and the best place for a "
                                        "mesh point stand out. Kept until you clear it.")
        row = QHBoxLayout()
        self.survey_room = QLineEdit()
        self.survey_room.setPlaceholderText("Room, e.g. Kitchen")
        self.survey_room.returnPressed.connect(self.run_survey)
        self.survey_btn = QPushButton("Measure here")
        self.survey_btn.setObjectName("primary")
        self.survey_btn.clicked.connect(self.run_survey)
        clear = QPushButton("Clear")
        clear.clicked.connect(self.clear_survey)
        row.addWidget(self.survey_room, 1)
        row.addWidget(self.survey_btn)
        row.addWidget(clear)
        lay.addLayout(row)
        self.survey_note = QLabel("")
        self.survey_note.setObjectName("muted")
        self.survey_note.setWordWrap(True)
        lay.addWidget(self.survey_note)
        self.survey_table = _table(["Room", "Signal", "Verdict", "Band", "Access point", "Measured"], stretch_col=2)
        lay.addWidget(self.survey_table, 1)
        try:
            with open(survey_file(), encoding="utf-8") as f:
                self.survey = json.load(f)
        except (OSError, ValueError):
            self.survey = []
        self.show_survey()
        return w

    def wifi_iface(self):
        return next((n["iface"] for n in self.networks if is_wireless(n["iface"])), None)

    def run_survey(self):
        room = self.survey_room.text().strip() or f"Spot {len(self.survey) + 1}"
        self.survey_btn.setEnabled(False)
        self.survey_note.setText(f"Measuring in {room} (about 5 seconds; keep the laptop where you'd use it)…")
        iface = self.wifi_iface()
        self.worker.run("in:survey", lambda: (room, survey_reading(iface)))

    def survey_done(self, room, reading):
        self.survey = [r for r in self.survey if r["room"] != room] + [{"room": room, **reading}]
        self.save_survey()
        self.survey_room.clear()
        self.survey_note.setText(f"{room}: {reading['signal']}% signal"
                                 + (f" ({reading['dbm']} dBm)" if reading.get("dbm") is not None else "")
                                 + f", {survey_verdict(reading['signal'])[1]}.")
        self.show_survey()

    def save_survey(self):
        tmp = survey_file() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.survey, f, indent=1)
        os.replace(tmp, survey_file())

    def clear_survey(self):
        if self.survey and QMessageBox.question(self, "NetScan", "Clear every room's reading?") == QMessageBox.Yes:
            self.survey = []
            self.save_survey()
            self.show_survey()

    def show_survey(self):
        t = self.survey_table
        rows = sorted(self.survey, key=lambda r: -(r.get("signal") or 0))
        t.setRowCount(len(rows))
        aps = {}
        for r in rows:
            aps.setdefault(r.get("bssid") or "", len(aps) + 1)
        for i, r in enumerate(rows):
            level, text = survey_verdict(r.get("signal"))
            sig = "—" if r.get("signal") is None else f"{r['signal']}%" + (f"  ({r['dbm']} dBm)"
                                                                            if r.get("dbm") is not None else "")
            ap = f"#{aps[r.get('bssid') or '']}  {r.get('bssid') or ''}".strip() if len(aps) > 1 else r.get("bssid", "")
            _set_row(t, i, [r["room"], sig, text, f"{r['band']} ch {r['channel']}", ap,
                            r["when"][5:16].replace("T", " ")], {2: level_color(level)})
        t.resizeColumnsToContents()
        if len(rows) >= 2:
            weak = [r["room"] for r in rows if survey_verdict(r.get("signal"))[0] in ("warn", "bad")]
            self.survey_note.setText(
                (f"Weak spots: {', '.join(weak)}. A mesh point or access point halfway between the router and "
                 "these rooms fixes it best." if weak else "Every room has a good signal.")
                + (" Different access points (#) served different rooms: your mesh is handing you over."
                   if len(aps) > 1 else ""))

    # ---- who's home -------------------------------------------------------------------------

    PRESENCE_FILTERS = [("Phones", "phone"), ("Trusted devices", "trusted"), ("Devices with a nickname", "named"),
                        ("All devices", "all")]

    def build_presence_panel(self):
        w, lay = _panel("Who's home", "When each device was on the network, hour by hour, from your scans and the "
                                      "background watch (Devices tab). Phones are a good stand-in for people.")
        row = QHBoxLayout()
        self.presence_filter = QComboBox()
        for label, _key in self.PRESENCE_FILTERS:
            self.presence_filter.addItem(label)
        self.presence_range = QComboBox()
        for label, hours in (("Last 24 hours", 24), ("Last 7 days", 168)):
            self.presence_range.addItem(label, hours)
        for combo in (self.presence_filter, self.presence_range):
            combo.currentIndexChanged.connect(self.show_presence)
        self.presence_note = QLabel("")
        self.presence_note.setObjectName("muted")
        self.presence_note.setWordWrap(True)
        row.addWidget(self.presence_filter)
        row.addWidget(self.presence_range)
        row.addWidget(self.presence_note, 1)
        lay.addLayout(row)
        self.presence_chart = PresenceChart()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setWidget(self.presence_chart)
        lay.addWidget(scroll, 1)
        return w

    def presence_only(self, key):
        if key == "all":
            return None
        if key == "trusted":
            return lambda _mac, d: d.get("trusted")
        if key == "named":
            return lambda _mac, d: d.get("nickname")
        return lambda mac, d: self.devices.device_type({"mac": mac, "ip": d.get("ip", "")})[0] == "phone"

    def show_presence(self):
        key = self.PRESENCE_FILTERS[self.presence_filter.currentIndex()][1]
        hours = self.presence_range.currentData()
        rows = presence_rows(self.devices.devices, self.devices.checked_hours, hours, only=self.presence_only(key))
        watching = self.watch_timer.isActive()
        self.presence_note.setText(
            f"{sum(r['home_now'] for r in rows)} of {len(rows)} online now. Green = online, grey = checked but not "
            "seen, blank = NetScan wasn't checking."
            + ("" if watching else " Turn on the background watch (Devices tab) for an hour-by-hour picture."))
        label = self.PRESENCE_FILTERS[self.presence_filter.currentIndex()][0].lower()
        self.presence_chart.set_data(rows, hours, f"No {label} seen in this period. "
                                     + ("Try “All devices”." if key != "all" else "Run a scan to start."))

    # ---- results from the background worker ----------------------------------------------------

    def insights_done(self, tag, res):
        failed = isinstance(res, Exception)
        why = html.escape(str(res)) if failed else ""
        if tag == "diagnose":
            self.diag_btn.setEnabled(True)
            if failed:
                self.diag_out.setHtml(f'<p style="color:{T.AMBER}">⚠ {why}</p>')
            else:
                self.show_diagnosis(res)
        elif tag == "security":
            self.sec_btn.setEnabled(True)
            self.show_security({"errors": [str(res)]} if failed else res)
        elif tag == "nat":
            self.nat_btn.setEnabled(True)
            if failed:
                self.router_sections["nat"] = ([("warn", "Check failed", str(res))], "")
                self.show_router_sections()
            else:
                self.show_nat(res)
        elif tag == "survey":
            self.survey_btn.setEnabled(True)
            if failed:
                self.survey_note.setText(f"⚠ {res}")
            else:
                self.survey_done(*res)
