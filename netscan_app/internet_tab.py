"""Internet tab: connection check and speed test."""

import urllib.error
import urllib.parse
import urllib.request

from PySide6.QtCore import (
    Qt,
)
from PySide6.QtWidgets import (
    QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget,
)

from . import theme as T
from .internet import SPEED_DOWN_BYTES, SPEED_PROVIDERS, SPEED_UP_BYTES, internet_check, speed_test
from .theme import make_card
from .widgets import Worker


class InternetMixin:
    """Internet tab: connection check and speed test. Mixed into MainWindow."""

    # ---- internet tab ----------------------------------------------------------

    @staticmethod
    def make_tile(label):
        """A stat tile: small caps label, big value, muted detail line. Returns (frame, value, detail)."""
        frame = QFrame()
        frame.setObjectName("tile")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(14, 10, 14, 12)
        lay.setSpacing(2)
        name = QLabel(label.upper())
        name.setObjectName("tileLabel")
        value = QLabel("—")
        value.setObjectName("tileValue")
        value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        detail = QLabel("")
        detail.setObjectName("muted")
        detail.setWordWrap(True)
        for w in (name, value, detail):
            lay.addWidget(w)
        lay.addStretch(1)
        return frame, value, detail

    def build_internet_page(self):
        self.worker = Worker()
        self.worker.done.connect(self.worker_done)
        self.net_check_btn = QPushButton("Check now")
        self.net_check_btn.setObjectName("primary")
        self.net_check_btn.clicked.connect(self.run_internet_check)
        trace_btn = QPushButton("Trace route to the internet")
        trace_btn.clicked.connect(lambda: self.trace_route("1.1.1.1", "the internet (1.1.1.1)"))
        self.net_when = QLabel("Not checked yet. Contacts Cloudflare (1.1.1.1) only when you press Check now.")
        self.net_when.setObjectName("muted")
        card, cl, head = make_card("Internet connection")
        head.addWidget(self.net_when, 1)
        head.addWidget(trace_btn)
        head.addWidget(self.net_check_btn)
        grid = QGridLayout()
        grid.setSpacing(10)
        self.net_tiles = {}
        for i, (key, label) in enumerate((("ip", "Public IP"), ("route", "Route to the internet"),
                                          ("router", "Router latency"), ("cf", "Internet latency"),
                                          ("dns", "DNS server"), ("dns_ms", "DNS lookup"),
                                          ("google", "Google DNS latency"), ("loss", "Packet loss"))):
            frame, value, detail = self.make_tile(label)
            grid.addWidget(frame, i // 4, i % 4)
            self.net_tiles[key] = (value, detail)
        cl.addLayout(grid)

        self.speed_provider = QComboBox()
        for key, label in SPEED_PROVIDERS:
            self.speed_provider.addItem(label, key)
        self.speed_provider.setToolTip("Automatic uses Cloudflare, and the nearest public LibreSpeed server if "
                                       "Cloudflare is busy or rate-limiting")
        self.speed_btn = QPushButton("Run speed test")
        self.speed_btn.setObjectName("primary")
        self.speed_btn.clicked.connect(self.run_speed_test)
        self.speed_note = QLabel(f"About 12 seconds, using up to "
                                 f"{SPEED_DOWN_BYTES // 1_000_000} MB down and {SPEED_UP_BYTES // 1_000_000} MB up. "
                                 "Through a VPN it measures the VPN's speed.")
        self.speed_note.setObjectName("muted")
        self.speed_note.setWordWrap(True)
        speed, sl, sh = make_card("Speed test")
        sh.addWidget(self.speed_note, 1)
        sh.addWidget(self.speed_provider)
        sh.addWidget(self.speed_btn)
        row = QHBoxLayout()
        row.setSpacing(10)
        self.speed_tiles = {}
        for key, label in (("down", "Download"), ("up", "Upload"), ("bloat", "Bufferbloat")):
            frame, value, detail = self.make_tile(label)
            row.addWidget(frame)
            self.speed_tiles[key] = (value, detail)
        sl.addLayout(row)

        page = QWidget()
        pl = QVBoxLayout(page)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.setSpacing(12)
        pl.addWidget(card)
        pl.addWidget(speed)
        pl.addStretch(1)
        return page

    def run_internet_check(self):
        self.net_check_btn.setEnabled(False)
        self.net_when.setText("Checking…")
        self.worker.run("internet", internet_check, self.watch_target()["gateway"] if self.watch_target() else None)

    def run_speed_test(self):
        self.speed_btn.setEnabled(False)
        for value, detail in self.speed_tiles.values():
            value.setText("…")
            value.setStyleSheet("")
            detail.setText("testing")
        provider = self.speed_provider.currentData()
        self.worker.run("speed", lambda: speed_test(provider=provider))

    def device_name_for(self, ip):
        """'Trading Pi' for an address NetScan knows, else ''."""
        h = self.hosts.get(ip)
        rec = self.devices.get(h) if h else next((d for d in self.devices.devices.values() if d.get("ip") == ip), {})
        return rec.get("nickname") or (h or {}).get("hostname") or rec.get("hostname", "")

    def worker_done(self, tag, res):
        if tag == "uptime":
            if not isinstance(res, Exception):
                self.uptime_result(res)
            return
        if tag.startswith("tool:"):
            self.tool_done(tag[5:], res)
            return
        if tag == "speed":
            self.speed_btn.setEnabled(True)
            if isinstance(res, Exception):
                busy = isinstance(res, urllib.error.HTTPError) and res.code == 429
                for value, detail in self.speed_tiles.values():
                    value.setText("—")
                    detail.setText("Cloudflare's speed test is rate-limiting this connection; choose LibreSpeed or "
                                   "Automatic, or try again later." if busy else f"failed: {res}")
                return
            for key in ("down", "up"):
                value, detail = self.speed_tiles[key]
                value.setText(f"{res[key]:.0f} Mbit/s")
                detail.setText(f"{res['server']} at {res['when']} · ≈ {res[key] / 8:.1f} MB/s · "
                               f"{res['used_mb']:.0f} MB used"
                               + (f"\n{res['note']}" if res.get("note") and key == "down" else ""))
            value, detail = self.speed_tiles["bloat"]
            if res.get("grade"):
                load = res["loaded_ms"]
                value.setText(f"{res['grade']}  (+{res['added_ms']:.0f} ms)")
                value.setStyleSheet(f"color: {T.GREEN if res['grade'] in ('A+', 'A') else T.AMBER if res['grade'] in ('B', 'C') else T.RED};")
                detail.setText(f"latency {res['idle_ms']:.0f} ms idle → "
                               f"{load['down'] or 0:.0f} ms downloading, {load['up'] or 0:.0f} ms uploading. "
                               + ("Calls and games stay smooth while the line is busy." if res["grade"] in ("A+", "A")
                                  else "Lag during downloads/calls; a router with SQM/“smart queue” fixes it."))
            else:
                value.setText("—")
                detail.setText("couldn't ping 1.1.1.1 during the test")
            return
        if tag != "internet":
            return
        self.net_check_btn.setEnabled(True)
        if isinstance(res, Exception):
            self.net_when.setText(f"Check failed: {res}")
            return
        t = self.net_tiles
        self.net_when.setText(f"Checked at {res['when']}." + (" Some checks failed: " + "; ".join(res["errors"])
                                                              if res.get("errors") else ""))
        trace = res.get("trace") or {}
        t["ip"][0].setText(trace.get("ip", "—"))
        t["ip"][1].setText(" · ".join(x for x in (trace.get("loc", ""), f"Cloudflare {trace['colo']}"
                                                 if trace.get("colo") else "") if x) or "no answer from Cloudflare")
        router_ip = (self.upnp or {}).get("public_ip")
        if trace.get("ip") and router_ip:
            via = router_ip != trace["ip"]
            t["route"][0].setText("VPN / proxy" if via else "Direct")
            t["route"][1].setText(f"your router's public IP is {router_ip}" if via else
                                  "the internet sees your router's own IP")
        else:
            t["route"][0].setText("Unknown")
            t["route"][1].setText("needs the router's UPnP (Scan tab) to compare public IPs")
        for key, target in (("router", "your router"), ("cf", "Cloudflare 1.1.1.1"), ("google", "Google 8.8.8.8")):
            ms, loss = res.get(key) or (None, None)
            t[key][0].setText("—" if ms is None else f"{ms:.1f} ms")
            t[key][1].setText(f"median of 5 pings to {target}" if ms is not None else "no reply")
        servers = res.get("dns") or []
        named = [f"{ip} ({self.device_name_for(ip)})" if self.device_name_for(ip) else ip for ip in servers]
        t["dns"][0].setText(servers[0] if servers else "—")
        t["dns"][1].setText(", ".join(named) if named else "couldn't read the DNS settings")
        ms = res.get("dns_ms")
        t["dns_ms"][0].setText("—" if ms is None else f"{ms:.0f} ms")
        t["dns_ms"][1].setText("uncached lookup" + (": slow, sites may feel sluggish to start" if ms and ms > 150
                                                    else ": fine" if ms else ""))
        losses = [res[k][1] for k in ("router", "cf", "google") if res.get(k)]
        worst = max(losses) if losses else None
        t["loss"][0].setText("—" if worst is None else f"{worst:.0f}%")
        t["loss"][1].setText("worst of the three" + (": check Wi-Fi or cables" if worst else ""))
        t["loss"][0].setStyleSheet(f"color: {T.AMBER};" if worst else "")
