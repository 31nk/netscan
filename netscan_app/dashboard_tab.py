"""The Dashboard tab: one screen with how the network is doing, built only from what NetScan already knows (no
new network traffic): internet, speed, security, devices, outages, what needs attention, and two charts."""

import datetime
import time

from PySide6.QtCore import QSize, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QPushButton, QTextBrowser, QVBoxLayout, QWidget

from . import history_db
from . import theme as T
from .columns import TAB_DASHBOARD, TAB_INTERNET, TAB_SCAN, TAB_TRAFFIC
from .devices import risky
from .insights_tab import findings_html
from .outages import LATENCY_KEY
from .theme import icon_path, make_card
from .widgets import HealthRing, TimeSeriesChart


def health_score(attention, outages_week, down, measured):
    """Overall health 0-100 from the same things "Needs attention" lists, or None before anything's measured.
    Each serious problem costs 10 (at most 40), each warning 3 (at most 15), each internet outage this week 5
    (at most 20); while the internet or the home network is down it's 25 at most."""
    if not measured:
        return None
    bad = sum(1 for lvl, _t, _d in attention if lvl == "bad")
    warn = sum(1 for lvl, _t, _d in attention if lvl == "warn")
    score = 100 - min(40, 10 * bad) - min(15, 3 * warn) - min(20, 5 * outages_week)
    if down:
        score = min(score, 25)
    return max(0, score)


def health_words(score):
    if score is None:
        return "Not enough data yet"
    return "Healthy" if score >= 85 else "Needs a look" if score >= 60 else "Trouble"


class DashboardMixin:
    """The Dashboard tab. Mixed into MainWindow."""

    def build_dashboard_page(self):
        page = QWidget()
        pl = QVBoxLayout(page)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.setSpacing(12)
        top = QHBoxLayout()
        top.setSpacing(12)
        hero, hl, _h = make_card()
        inner = QHBoxLayout()
        inner.setSpacing(18)
        self.dash_ring = HealthRing()
        self.dash_ring.setToolTip("Network health: 100 minus 10 for each serious problem, 3 for each warning and 5 "
                                  "for each internet outage this week (25 at most while offline)")
        words = QVBoxLayout()
        words.setSpacing(4)
        self.dash_headline = QLabel("")
        self.dash_headline.setObjectName("heroTitle")
        self.dash_sub = QLabel("")
        self.dash_sub.setObjectName("muted")
        self.dash_sub.setWordWrap(True)
        self.dash_site = QLabel("")
        self.dash_site.setObjectName("muted")
        self.dash_site.setWordWrap(True)
        words.addStretch(1)
        for w in (self.dash_headline, self.dash_sub, self.dash_site):
            words.addWidget(w)
        words.addStretch(1)
        inner.addWidget(self.dash_ring)
        inner.addLayout(words, 1)
        hl.addLayout(inner)
        grid = QGridLayout()
        grid.setSpacing(10)
        self.dash_tiles = {}
        for i, (key, label) in enumerate((("internet", "Internet"), ("speed", "Speed"), ("security", "Security"),
                                          ("devices", "Devices"), ("outages", "Outages"), ("switch", "Switch port"))):
            frame, value, detail = self.make_tile(label)
            grid.addWidget(frame, i // 3, i % 3)
            self.dash_tiles[key] = (value, detail)
        top.addWidget(hero, 2)
        top.addLayout(grid, 5)
        pl.addLayout(top)

        row = QHBoxLayout()
        row.setSpacing(12)
        attention, al, ah = make_card("Needs attention")
        self.dash_when = QLabel("")
        self.dash_when.setObjectName("muted")
        ah.addStretch(1)
        ah.addWidget(self.dash_when)
        self.dash_attention = QTextBrowser()
        self.dash_attention.setOpenLinks(False)
        al.addWidget(self.dash_attention, 1)
        actions, acl, _h = make_card("Quick actions")
        buttons = QGridLayout()
        buttons.setSpacing(8)
        self.dash_actions = []
        for i, (icon, label, slot) in enumerate((
                ("search", "Find hosts", lambda: (self.tabbar.setCurrentIndex(TAB_SCAN), self.scan_btn.isEnabled() and self.start_scan())),
                ("globe", "Check internet", lambda: (self.tabbar.setCurrentIndex(TAB_INTERNET), self.run_internet_check())),
                ("gauge", "Speed test", lambda: (self.tabbar.setCurrentIndex(TAB_INTERNET), self.speed_btn.isEnabled() and self.run_speed_test())),
                ("pulse", "Slow internet?", lambda: (self.open_tool("Slow internet?"), self.run_diagnosis())),
                ("shield", "Security checkup", lambda: (self.open_tool("Security checkup"), self.run_security())),
                ("doc", "Site audit", lambda: self.open_tool("Site audit")),
                ("port", "Switch port (Traffic)", lambda: self.tabbar.setCurrentIndex(TAB_TRAFFIC)),
                ("copy", "Copy for ticket", self.copy_for_ticket))):
            b = QPushButton(label)
            b.setObjectName("action")
            b.setProperty("icon_name", icon)
            b.setIcon(QIcon(icon_path(icon)))
            b.setIconSize(QSize(16, 16))
            b.clicked.connect(slot)
            buttons.addWidget(b, i // 2, i % 2)
            self.dash_actions.append(b)
        acl.addLayout(buttons)
        acl.addStretch(1)
        row.addWidget(attention, 3)
        row.addWidget(actions, 1)
        pl.addLayout(row, 2)

        charts = QHBoxLayout()
        charts.setSpacing(12)
        lat_card, lcl, _h = make_card("Internet latency, last 24 hours")
        self.dash_latency = TimeSeriesChart()
        self.dash_latency.setMinimumHeight(170)
        lcl.addWidget(self.dash_latency, 1)
        speed_card, scl, _h = make_card("Speed tests, last 30 days")
        self.dash_speed = TimeSeriesChart()
        self.dash_speed.setMinimumHeight(170)
        scl.addWidget(self.dash_speed, 1)
        charts.addWidget(lat_card)
        charts.addWidget(speed_card)
        pl.addLayout(charts, 2)
        self.dash_timer = QTimer(self)
        self.dash_timer.timeout.connect(self.refresh_dashboard)
        return page

    def dashboard_shown(self, visible):
        if visible:
            self.refresh_dashboard()
            self.dash_timer.start(10_000)
        else:
            self.dash_timer.stop()

    def poke_dashboard(self):
        """Something the Dashboard shows just changed: refresh it now if it's on screen (once, however many
        results arrive together)."""
        if self.tabbar.currentIndex() == TAB_DASHBOARD and not getattr(self, "_dash_poked", False):
            self._dash_poked = True
            QTimer.singleShot(0, self._dash_refresh_now)

    def _dash_refresh_now(self):
        self._dash_poked = False
        self.refresh_dashboard()

    def refresh_dashboard(self):
        now = time.time()
        t = self.dash_tiles
        net = self.current or self.watch_target()
        for b in self.dash_actions:  # icons follow the theme
            b.setIcon(QIcon(icon_path(b.property("icon_name"))))

        # Internet: the connection watch is freshest, then the last check.
        watch, check = getattr(self, "last_watch", None), getattr(self, "last_internet", None)
        ongoing = self.outage_log.ongoing
        value, detail = t["internet"]
        if ongoing:
            value.setText("Down" if ongoing["kind"] == "internet" else "Offline")
            value.setStyleSheet(f"color: {T.RED};")
            detail.setText(f"since {time.strftime('%H:%M', time.localtime(ongoing['start']))}")
        elif watch and now - watch["ts"] < 120:
            value.setText("Up" if watch["internet"] is not None else "No reply")
            value.setStyleSheet(f"color: {T.GREEN};" if watch["internet"] is not None else f"color: {T.AMBER};")
            detail.setText(f"{watch['internet']:.0f} ms · watching" if watch["internet"] is not None else "watching")
        elif check:
            cf = (check.get("cf") or (None, None))[0]
            value.setText("Up" if cf is not None else "No reply")
            value.setStyleSheet(f"color: {T.GREEN};" if cf is not None else f"color: {T.AMBER};")
            detail.setText((f"{cf:.0f} ms · " if cf is not None else "") + f"checked {time.strftime('%H:%M', time.localtime(check['ts']))}")
        else:
            value.setText("—")
            value.setStyleSheet("")
            detail.setText("not checked yet")

        speed = self.latest_speed(days=30)
        plan = self.speed_plan()
        value, detail = t["speed"]
        if speed:
            value.setText(f"{speed['down']:.0f} / {speed['up'] or 0:.0f}")
            pct = f" · {100 * speed['down'] / plan['down']:.0f}% of plan" if plan else ""
            detail.setText(f"Mbit/s · {datetime.datetime.fromtimestamp(speed['when']).strftime('%a %H:%M')}{pct}")
        else:
            value.setText("—")
            detail.setText("no speed test yet")

        sec = getattr(self, "last_security", None)
        value, detail = t["security"]
        if sec and sec["complete"]:
            value.setText(f"{sec['grade']}  {sec['score']}")
            value.setStyleSheet(f"color: {T.GREEN if sec['score'] >= 75 else T.AMBER if sec['score'] >= 50 else T.RED};")
            detail.setText(f"checkup at {time.strftime('%H:%M', time.localtime(sec['when']))}")
        else:
            value.setText("—")
            value.setStyleSheet("")
            detail.setText("run the Security checkup")

        known = len(self.devices.devices)
        online = len(self.online_macs) or len(self.hosts)
        t["devices"][0].setText(f"{online} online" if online else f"{known} known")
        new_day = [d for d in self.devices.devices.values()
                   if d.get("first_seen", "") >= datetime.datetime.fromtimestamp(now - 86400).isoformat()]
        t["devices"][1].setText(f"{known} known" + (f" · {len(new_day)} new in 24 h" if new_day else ""))

        week = self.outage_log.between(now - 7 * 86400, now)
        internet = [o for o in week if o["kind"] == "internet"]
        t["outages"][0].setText(str(len(internet)))
        t["outages"][0].setStyleSheet(f"color: {T.AMBER};" if internet else "")
        t["outages"][1].setText("last 7 days" + ("" if self.net_watch_box.isChecked() else " · watch is off"))

        value, detail = t["switch"]
        sw = self.capture.analyzer.snapshot()["switch"] if self.capture else None
        if sw:
            value.setText(f"{sw.get('switch') or 'Switch'}")
            detail.setText(f"port {sw.get('port_desc') or sw.get('port') or '?'}"
                           + (f" · VLAN {sw['vlan']}" if sw.get("vlan") else ""))
        else:
            value.setText("—")
            detail.setText("capturing…" if self.capture and self.capture.running else "start a capture on Traffic")

        attention = self.attention_items(now)
        measured = bool(self.hosts or self.devices.devices or watch or check or speed or sec)
        down = bool(ongoing)
        score = health_score(attention, len(internet), down, measured)
        self.dash_ring.set_score(score, "health")
        self.dash_headline.setText(health_words(score))
        problems = [a for a in attention if a[0] in ("bad", "warn")]
        self.dash_sub.setText("Nothing needs attention." if score is not None and not problems else
                              f"{len(problems)} thing{'s' if len(problems) != 1 else ''} to look at below." if problems
                              else "Find hosts, check the internet or run a speed test to get a score.")
        self.dash_site.setText(f"{self.sites.name()} · " + (f"{net['network']} via {net.get('gateway') or '?'}"
                                                           if net else "no network detected"))
        self.dash_attention.setHtml(findings_html(attention))
        self.dash_when.setText(f"updated {time.strftime('%H:%M:%S')}")
        self.refresh_dashboard_charts(now)

    def attention_items(self, now):
        """[(level, title, detail)]: everything worth a look right now, worst first."""
        f = []
        for severity, text in self.spoof_warnings:
            f.append(("bad" if severity == "high" else "info", "Possible ARP spoofing", text))
        ongoing = self.outage_log.ongoing
        if ongoing:
            f.append(("bad", "The internet is down" if ongoing["kind"] == "internet" else "The home network is down",
                      f"Since {time.strftime('%H:%M', time.localtime(ongoing['start']))}; Outages is logging it."))
        for mac, st in self.uptime_state.items():
            if not st.get("up", True):
                f.append(("bad", f"{self.device_label(mac) or mac} is offline",
                          f"Down since {time.strftime('%H:%M', time.localtime(st['down_since']))}."))
        for url, res in self.web_state.items():
            if not res["ok"]:
                f.append(("bad", f"{url} is down", res["error"] or f"HTTP {res['status']}"))
            elif res["cert_days"] is not None and res["cert_days"] < 14:
                f.append(("warn", f"{url}: certificate expires in {res['cert_days']} days", ""))
        forwards = [m for m in (self.upnp or {}).get("mappings", []) if m.get("enabled", True)]
        if forwards:
            f.append(("warn", f"{len(forwards)} port(s) opened to the internet by devices (UPnP)",
                      ", ".join(f"{m['external_port']}/{m['protocol']} → {m['client']}" for m in forwards[:5])))
        risky_hosts = [ip for ip in self.hosts if risky(self.network_ports(ip))]
        if risky_hosts:
            f.append(("warn", f"Risky services on {len(risky_hosts)} device(s)",
                      ", ".join(self.monitor_label(ip) for ip in risky_hosts[:6]) + ". See the Scan tab."))
        day_ago = datetime.datetime.fromtimestamp(now - 86400).isoformat()
        new, changed = [], []
        for mac, d in self.devices.devices.items():
            name = d.get("nickname") or d.get("hostname") or d.get("ip") or mac
            if d.get("first_seen", "") >= day_ago:
                when = datetime.datetime.fromisoformat(d["first_seen"]).strftime("%a %H:%M")
                new.append((name, f"{d.get('vendor') or mac}, first seen {when}."))
            for ch in d.get("port_changes", []):
                if ch["time"] >= day_ago:
                    changed.append((name, " ".join([f"+{x}" for x in ch.get("opened", [])]
                                                   + [f"−{x}" for x in ch.get("closed", [])])))
        if len(new) > 3:  # e.g. the first scan of a network: one line, not one per device
            f.append(("info", f"{len(new)} new devices in the last 24 hours",
                      ", ".join(n for n, _d in new[:12]) + (" …" if len(new) > 12 else "")))
        else:
            f.extend(("info", f"New device: {n}", detail) for n, detail in new)
        if len(changed) > 3:
            f.append(("info", f"Open ports changed on {len({n for n, _c in changed})} device(s)",
                      "; ".join(f"{n}: {c}" for n, c in changed[:6]) + (" …" if len(changed) > 6 else "")))
        else:
            f.extend(("info", f"{n}: ports changed", c) for n, c in changed)
        sec = getattr(self, "last_security", None)
        if sec and sec["complete"] and sec["score"] < 75:
            f.append(("warn", f"Security grade {sec['grade']} ({sec['score']}/100)", "See Tools → Security checkup."))
        speed, plan = self.latest_speed(days=7), self.speed_plan()
        if speed and plan and speed["down"] < 0.5 * plan["down"]:
            f.append(("warn", f"Last speed test: {speed['down']:.0f} of {plan['down']} Mbit/s",
                      "Under half your plan. Tools → Slow internet? finds out why."))
        if self.capture and self.capture.running:
            for ts, level, text in self.capture.analyzer.snapshot()["events"]:
                if level in ("bad", "warn") and now - ts < 3600:
                    f.append((level, "Traffic: " + text.split(":")[0], text))
        if not self.hosts and not self.devices.devices:
            f.append(("info", "Nothing scanned yet", "Press Find hosts (F5) to see what's on this network."))
        if not f:
            f.append(("good", "All quiet", "No outages, alerts, new devices or risky services to report."))
        order = {"bad": 0, "warn": 1, "info": 2, "good": 3}
        return sorted(f, key=lambda x: order[x[0]])[:40]

    def refresh_dashboard_charts(self, now):
        since = now - 86400
        self.history_avg.flush()
        self.watch_avg.flush()
        lat = history_db.series("latency", since)
        keys = [k for k in (LATENCY_KEY,) if k in lat] or sorted(lat)[:4]
        series = [(k.replace(" (connection watch)", ""), i, lat[k]) for i, k in enumerate(keys)]
        if not series:
            internet = history_db.series("internet_ms", since)
            series = [(k, i, v) for i, (k, v) in enumerate(sorted(internet.items()))][:3]
        self.dash_latency.set_data(series, "ms", since, now,
                                   empty="Turn on Tools → Outages (connection watch) or monitor a device to fill this.")
        month = now - 30 * 86400
        down, up = history_db.series("down", month), history_db.series("up", month)
        merge = lambda data: sorted(p for pts in data.values() for p in pts)
        speeds = [(label, i, pts) for i, (label, pts) in enumerate((("Download", merge(down)), ("Upload", merge(up))))
                  if pts]
        plan = self.speed_plan()
        self.dash_speed.set_data(speeds, "Mbit/s", month, now, dots=True, empty="Run a speed test (Internet tab).",
                                 reference=(plan["down"], "your plan") if plan else None)

