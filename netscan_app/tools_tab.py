"""Tools tab: the panels around the engines in tools.py."""

import html
import re
import urllib.error
import urllib.parse
import urllib.request

from PySide6.QtCore import (
    QSize, Qt,
)
from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QPushButton, QStackedWidget,
    QTextBrowser, QVBoxLayout, QWidget,
)

from . import theme as T
from .discovery import cert_note
from .scanning import valid_port_list
from .theme import make_card
from .tools import (
    BLOCKED_ANSWERS, DNS_RCODES, DNS_TYPES, SECURITY_HEADERS, channel_advice, dns_tool,
    http_inspect, ip_info, mac_info, port_check, subnet_info, wifi_scan,
)

# How the Tools list is grouped, in order. Every tool panel must appear here exactly once.
TOOL_GROUPS = [
    ("Checkups", ["Slow internet?", "Security checkup", "Router check", "Gaming & calls"]),
    ("Client work", ["Client sites", "Site audit", "Firewall test", "VoIP readiness", "Domain check (bulk)",
                     "Mail server check", "DNS propagation"]),
    ("Privacy & exposure", ["VPN & privacy", "What the internet sees"]),
    ("DNS", ["DNS lookup", "DNS speed"]),
    ("Websites & domains", ["HTTP inspector", "Domain toolkit", "Website watch"]),
    ("Network & Wi-Fi", ["Services & web pages", "Wi-Fi", "Wi-Fi survey", "Continuous trace", "LAN speed test"]),
    ("Addresses & ports", ["IP info", "Check ports", "Subnet calculator", "MAC lookup"]),
    ("This computer", ["Connections", "Live traffic"]),
    ("Over time", ["Outages", "History", "Who's home"]),
]


class ToolsMixin:
    """Tools tab: the panels around the engines in tools.py. Mixed into MainWindow."""

    # ---- tools tab -----------------------------------------------------------------

    TOOLS = [
        ("dns", "DNS lookup", "Look up a name on your DNS server and on Cloudflare (over HTTPS), and spot blocking "
                              "(e.g. Pi-hole) or DNS hijacking.", "example.com"),
        ("port", "Check ports", "Is a port open on any host, including servers outside your network? "
                                "Ports: a list or ranges, e.g. 22,80,443 or 8000-8100.", "example.com"),
        ("ip", "IP info", "Who owns a public IP address (from the public RDAP registries), and its reverse DNS name.",
         "8.8.8.8"),
        ("http", "HTTP inspector", "A website's redirects, security headers and certificate.", "https://example.com"),
        ("subnet", "Subnet calculator", "Range, netmask, broadcast and host count for a network or address.",
         "192.168.1.0/24"),
        ("mac", "MAC lookup", "The manufacturer of a network card from its MAC address.", "AA:BB:CC:DD:EE:FF"),
        ("wifi", "Wi-Fi", "This computer's Wi-Fi connection and the networks around it, with the least crowded "
                          "channel.", ""),
    ]

    def build_tools_page(self):
        self.tool_nav = QListWidget()
        self.tool_nav.setObjectName("toolNav")
        self.tool_nav.setFixedWidth(190)
        self.tool_nav.setSpacing(1)
        self.tool_stack = QStackedWidget()
        self.tool_widgets = {}
        panels = {}
        for key, title, desc, placeholder in self.TOOLS:
            panel = QWidget()
            lay = QVBoxLayout(panel)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.setSpacing(10)
            head = QLabel(title)
            head.setObjectName("bigName")
            info = QLabel(desc)
            info.setObjectName("muted")
            info.setWordWrap(True)
            info.setProperty("noTicket", True)
            row = QHBoxLayout()
            edit = QLineEdit()
            edit.setPlaceholderText(placeholder)
            extra = None
            if key == "dns":
                extra = QComboBox()
                extra.addItems(list(DNS_TYPES))
            elif key == "port":
                extra = QLineEdit("21,22,23,25,53,80,110,143,443,445,587,993,3306,3389,5432,8080,8443")
                extra.setToolTip("Ports to check")
            run = QPushButton("Scan Wi-Fi" if key == "wifi" else "Run")
            run.setObjectName("primary")
            if key != "wifi":
                row.addWidget(edit, 2)
                edit.returnPressed.connect(lambda k=key: self.run_tool(k))
            if extra is not None:
                row.addWidget(extra, 2 if key == "port" else 0)
            if key == "wifi":
                row.addStretch(1)
            row.addWidget(run)
            run.clicked.connect(lambda _c=False, k=key: self.run_tool(k))
            out = QTextBrowser()
            out.setOpenExternalLinks(False)
            for w in (head, info):
                lay.addWidget(w)
            lay.addLayout(row)
            lay.addWidget(out, 1)
            self.tool_widgets[key] = {"edit": edit, "extra": extra, "run": run, "out": out}
            panels[title] = panel
        panels.update(self.build_toolkit_panels())
        panels.update(self.build_insight_panels())
        panels.update(self.build_online_panels())
        panels.update(self.build_work_panels())
        for group, names in TOOL_GROUPS:
            head = QListWidgetItem(group.upper())
            head.setFlags(Qt.NoItemFlags)  # a heading: not selectable, skipped by the arrow keys
            font = head.font()
            font.setPointSizeF(font.pointSizeF() * 0.8)
            font.setBold(True)
            head.setFont(font)
            head.setSizeHint(QSize(170, 28 if self.tool_nav.count() else 20))
            self.tool_nav.addItem(head)
            for name in names:
                item = QListWidgetItem(name)
                item.setData(Qt.UserRole, self.tool_stack.addWidget(panels.pop(name)))
                item.setSizeHint(QSize(170, 32))  # room for the padding
                self.tool_nav.addItem(item)
        assert not panels, f"tools missing from TOOL_GROUPS: {list(panels)}"
        self.tool_nav.currentRowChanged.connect(self.tool_selected)
        self.tool_nav.setCurrentRow(next(r for r, name in self.tool_rows() if name == "DNS lookup"))
        card, cl, head = make_card("Tools")
        head.addStretch(1)
        copy = QPushButton("Copy for ticket")
        copy.setToolTip("Copy this tool's results as plain text, ready to paste into a ticket (Ctrl+Shift+C)")
        copy.clicked.connect(self.copy_for_ticket)
        head.addWidget(copy)
        body = QHBoxLayout()
        body.setSpacing(16)
        body.addWidget(self.tool_nav)
        body.addWidget(self.tool_stack, 1)
        cl.addLayout(body, 1)
        return card

    def tool_rows(self):
        """[(row, name)] of the tools in the list, leaving out the group headings."""
        nav = self.tool_nav
        return [(r, nav.item(r).text()) for r in range(nav.count()) if nav.item(r).data(Qt.UserRole) is not None]

    def tool_selected(self, row):
        item = self.tool_nav.item(row) if row >= 0 else None
        if item is None or item.data(Qt.UserRole) is None:
            return
        self.tool_stack.setCurrentIndex(item.data(Qt.UserRole))
        self.toolkit_tool_changed(item.text())

    def run_tool(self, key):
        w = self.tool_widgets[key]
        text = w["edit"].text().strip()
        try:
            if key == "subnet":  # instant, no network
                self.tool_done(key, {"rows": subnet_info(text or w["edit"].placeholderText())})
                return
            if key == "mac":
                self.tool_done(key, {"rows": mac_info(text)})
                return
        except ValueError as e:
            self.tool_done(key, e)
            return
        if key != "wifi" and not text:
            text = w["edit"].placeholderText()
            w["edit"].setText(text)
        if key != "wifi" and not re.fullmatch(r"[\w.:/\-%?=&+~#@\[\]]{1,300}", text):
            self.tool_done(key, ValueError("That doesn't look like a valid name, address or URL."))
            return
        w["run"].setEnabled(False)
        w["out"].setHtml(f'<p style="color:{T.MUTED}">Working…</p>')
        jobs = {"dns": lambda: dns_tool(text, w["extra"].currentText()),
                "port": lambda: port_check(text, w["extra"].text().replace(" ", "")),
                "ip": lambda: ip_info(text), "http": lambda: http_inspect(text),
                "wifi": lambda: {"nets": wifi_scan()}}
        if key == "port" and not valid_port_list(w["extra"].text().replace(" ", "")):
            w["run"].setEnabled(True)
            self.tool_done(key, ValueError("Ports must look like 22,80,443 or 8000-8100."))
            return
        self.worker.run("tool:" + key, jobs[key])

    @staticmethod
    def html_rows(rows, headers=None):
        e = html.escape
        head = ("<tr>" + "".join(f'<th align="left" style="color:{T.MUTED};padding:4px 14px 4px 0">{e(h)}</th>'
                                 for h in headers) + "</tr>") if headers else ""
        body = "".join("<tr>" + "".join(f'<td style="padding:3px 14px 3px 0">{c}</td>' for c in r) + "</tr>"
                       for r in rows)
        return f'<table cellspacing="0">{head}{body}</table>'

    def tool_done(self, key, res):
        w = self.tool_widgets[key]
        w["run"].setEnabled(True)
        e = html.escape
        note = lambda text, color=None: f'<p style="color:{color or T.MUTED}">{text}</p>'
        if isinstance(res, Exception):
            msg = str(res.reason) if isinstance(res, urllib.error.URLError) else str(res)
            w["out"].setHtml(note(f"⚠ {e(msg or type(res).__name__)}", T.AMBER))
            return
        if key in ("subnet", "mac"):
            w["out"].setHtml(self.html_rows([(f'<span style="color:{T.MUTED}">{e(k)}</span>', f"<b>{e(v)}</b>")
                                             for k, v in res["rows"]]))
            return
        if key == "dns":
            fmt = lambda v: e(f"{v[0]} {v[1]}" if isinstance(v, tuple) else " ".join(v) if isinstance(v, list) else v)
            rows, answers = [], {}
            for label, (server, rcode, ans, ms, *err) in res["servers"].items():
                answers[label] = {fmt(v) for _t, v in ans if _t == res["type"]}
                status = (f'<span style="color:{T.AMBER}">⚠ {e(err[0])}</span>' if err else
                          e(DNS_RCODES.get(rcode, str(rcode))) + f' <span style="color:{T.MUTED}">({ms:.0f} ms)</span>')
                shown = "<br>".join(fmt(v) for _t, v in ans) or f'<span style="color:{T.MUTED}">no records</span>'
                rows.append([f"<b>{'Your DNS' if label == 'yours' else 'Cloudflare'}</b><br>"
                             f'<span style="color:{T.MUTED}">{e(server)}</span>', status, shown])
            verdicts = []
            mine, theirs = answers.get("yours", set()), answers.get("cloudflare", set())
            if mine & BLOCKED_ANSWERS and theirs and not theirs & BLOCKED_ANSWERS:
                verdicts.append(note("🛡 <b>Blocked by your DNS server</b> (it answers 0.0.0.0): typical of an ad "
                                     "blocker like Pi-hole or AdGuard.", T.GREEN))
            elif mine and theirs and not mine & theirs and res["type"] in ("A", "AAAA"):
                verdicts.append(note("Your DNS gave different addresses from Cloudflare. That's normal for big sites "
                                     "(they serve from many places), but worth a look for a small site or your bank."))
            if res.get("hijack"):
                verdicts.append(note("⚠ <b>Your DNS invents answers for names that don't exist</b> (NXDOMAIN "
                                     "hijacking): usually an ISP sending mistyped addresses to its ad pages.", T.AMBER))
            elif res.get("hijack") is False:
                verdicts.append(note("✓ Your DNS answers “no such name” honestly (no NXDOMAIN hijacking).", T.GREEN))
            w["out"].setHtml(f"<p><b>{e(res['name'])}</b> · {e(res['type'])} records</p>"
                             + self.html_rows(rows, ["Server", "Status", "Answer"]) + "".join(verdicts))
            return
        if key == "port":
            color = {"open": T.GREEN, "closed": T.MUTED, "no answer": T.AMBER}
            rows = [(f"<b>{p}</b>", f'<span style="color:{color[st]}">{st}</span>', e(svc)) for p, st, svc in res["results"]]
            n_open = sum(1 for _p, st, _s in res["results"] if st == "open")
            w["out"].setHtml(f"<p><b>{e(res['host'])}</b> ({e(res['ip'])}): {n_open} of {len(rows)} open</p>"
                             + self.html_rows(rows, ["Port", "State", "Usual service"])
                             + note("“no answer” usually means a firewall silently drops the connection."))
            return
        if key == "ip":
            if res.get("private"):
                w["out"].setHtml(f"<p><b>{e(res['ip'])}</b> is {e(res['private'])}; the public registries "
                                 "don't list these.</p>" + (note(f"Reverse DNS: {e(res['rdns'])}") if res["rdns"] else ""))
                return
            rows = [(k, e(v)) for k, v in (("Address", res["ip"]), ("Reverse DNS", res["rdns"] or "none"),
                                           ("Owner", ", ".join(res["orgs"]) or "?"), ("Network name", res["name"]),
                                           ("Range", res["range"]), ("Handle", res["handle"]),
                                           ("Country", res["country"] or "?"), ("Registry", res["registry"] or "?"))]
            w["out"].setHtml(self.html_rows([(f'<span style="color:{T.MUTED}">{k}</span>', f"<b>{v}</b>") for k, v in rows]))
            return
        if key == "http":
            chain = [(f"<b>{c['status']}</b>", e(c["url"]), f"{c['ms']:.0f} ms") for c in res["chain"]]
            parts = [self.html_rows(chain, ["Status", "URL", "Time"])]
            if "cert_valid" in res:
                good = res["cert_valid"] is True
                cert = cert_note(res["cert"])[0] if res.get("cert") else ""
                parts.append(note(("✓ Certificate trusted by browsers. " if good else
                                   f"⚠ Browsers won't trust this certificate: {e(str(res['cert_valid']))}. ")
                                  + e(cert), T.GREEN if good else T.AMBER))
            hdr = {k.lower(): v for k, v in res["headers"].items()}
            sec = [(("✓" if h not in res["missing"] else "✗") + " " + e(h),
                    f'<span style="color:{T.MUTED}">{e(why)}</span>') for h, why in SECURITY_HEADERS.items()]
            parts.append("<p><b>Security headers</b></p>" + self.html_rows(sec))
            info = [(e(k), e(hdr[k][:120])) for k in ("server", "content-type", "x-powered-by", "cache-control")
                    if k in hdr]
            if info:
                parts.append("<p><b>Other headers</b></p>" + self.html_rows(info))
            w["out"].setHtml("".join(parts))
            return
        if key == "wifi":
            nets = res["nets"]
            if not nets:
                w["out"].setHtml(note("No Wi-Fi information: this computer may have no Wi-Fi, or no tool to read it "
                                      "(Linux needs NetworkManager's nmcli)."))
                return
            parts = []
            mine = next((n for n in nets if n["active"]), None)
            if mine:
                parts.append(f"<p>Connected to <b>{e(mine['ssid'])}</b> on {mine['band']}, channel {mine['channel']}"
                             f" · signal <b>{mine['signal']}%</b>" + (f" · {e(mine.get('rate', ''))}" if mine.get("rate") else "")
                             + "</p>")
            parts.append(note("Channels are set in your router's settings or app. Your own router's extra "
                              "networks aren't counted as competition."))
            for band, a in channel_advice(nets).items():
                counts = ", ".join(f"ch {c}: {n}" for c, n in a["counts"].items()) or "no other routers"
                tip = ""
                if a["yours"] and a["best"] and a["counts"].get(a["yours"], 0) > a["counts"].get(a["best"], 0) + 1:
                    tip = f" → channel <b>{a['best']}</b> is less crowded than yours ({a['yours']})."
                parts.append(note(f"<b>{band}</b>, other routers per channel: {counts}{tip}", T.TEXT))
            bar = lambda sig: f'<span style="color:{T.GREEN if sig >= 60 else T.AMBER if sig >= 35 else T.RED}">'                               + "▮" * max(1, round(sig / 20)) + "</span>" + f" {sig}%"
            rows = [(("<b>" if n["active"] else "") + e(n["ssid"]) + (" ✓</b>" if n["active"] else ""), n["band"],
                     str(n["channel"]), bar(n["signal"] or 0), e(n["security"])) for n in nets]
            parts.append(self.html_rows(rows, ["Network", "Band", "Channel", "Signal", "Security"]))
            w["out"].setHtml("".join(parts))
