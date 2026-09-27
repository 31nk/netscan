"""The Help window (F1 or the ? button): what each tab and tool does, shortcuts, and what goes online."""

import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QPushButton, QTextBrowser, QVBoxLayout

from . import theme as T
from .devices import data_dir
from .tools_tab import TOOL_GROUPS

TABS = [
    ("Scan", "Ctrl+1", "Find hosts on your network (F5), then scan their ports. Right-click a host for Wake-on-LAN, "
     "a nickname, SSH/web links, a traceroute, or a known-vulnerability check. Compare shows what changed since "
     "a saved scan."),
    ("Devices", "Ctrl+2", "Every device NetScan has ever seen: nicknames, trusted flag, Wake-on-LAN, first/last seen, "
     "port changes, background watch and uptime alerts."),
    ("Monitor", "Ctrl+3", "Ping devices over time: latency, jitter and packet loss, with a live chart."),
    ("Internet", "Ctrl+4", "Public IP and VPN check, DNS servers, latency to your router and the internet, and a "
     "speed test with a bufferbloat grade."),
    ("Map", "Ctrl+5", "Everything around your router, grouped by type."),
    ("Tools", "Ctrl+6", "The toolbox below."),
]

TOOLS = dict([
    ("DNS lookup", "Any record type, from your DNS or a public resolver."),
    ("Check ports", "Is a port open on a host (yours or on the internet)?"),
    ("IP info", "Who owns an IP address (RDAP registry data)."),
    ("HTTP inspector", "Status, redirects, headers, TLS certificate and security headers of a website."),
    ("Subnet calculator", "Network, broadcast, host range and mask for any CIDR."),
    ("MAC lookup", "Vendor of a MAC address and whether it's randomised."),
    ("Wi-Fi", "Networks around you and which channel is least crowded."),
    ("Connections", "What this computer is connected to right now, and which program owns each connection."),
    ("Live traffic", "Upload and download speed of each network interface."),
    ("Continuous trace", "Traceroute that keeps running, showing latency and loss per hop."),
    ("LAN speed test", "Speed between two computers running NetScan on the same network."),
    ("Domain toolkit", "Registration, DNS, mail setup (MX/SPF/DMARC/DKIM) and certificate for a domain."),
    ("Website watch", "Get told when a website goes down or its certificate is about to expire."),
    ("DNS speed", "Your DNS against Cloudflare, Google and Quad9, cached and uncached."),
    ("History", "Devices online, latency, loss and speed tests over the last 30 days."),
])

SHORTCUTS = [("F1", "This help"), ("F5", "Find hosts"), ("Ctrl+K", "Jump to anything (tabs, tools, devices, actions)"),
             ("Ctrl+F", "Filter the host list"), ("Ctrl+1 … Ctrl+6", "Switch tabs"),
             ("Delete", "Remove the selected Monitor target")]

ONLINE = [
    ("Internet check", "Cloudflare (1.1.1.1/cdn-cgi/trace) for your public IP; pings to 1.1.1.1 and 8.8.8.8."),
    ("Speed test", "Cloudflare's speed test, or the nearest public LibreSpeed server."),
    ("IP info / Domain toolkit", "RDAP registries (rdap.org and the registry it points to), DNS, the site itself."),
    ("Connections", "RDAP (rdap.org) to name who owns each remote address; cached for two weeks."),
    ("DNS speed", "Queries to Cloudflare and Google (DNS-over-HTTPS) and Quad9 (DNS-over-TLS)."),
    ("Known vulnerabilities", "Only when you ask, and only after you agree once: the software name and version "
     "(never an IP address) are sent to the US National Vulnerability Database (nvd.nist.gov). Cached 7 days."),
    ("Website watch / HTTP inspector", "The websites you enter."),
]


class HelpMixin:
    def show_help(self):
        e = html.escape

        def cells(rows):
            return "".join(f'<tr><td style="padding:3px 14px 3px 0;white-space:nowrap"><b>{e(a)}</b></td>'
                           f'<td style="padding:3px 0">{e(b)}</td></tr>' for a, b in rows)

        def table(rows, head):
            return f'<h3 style="margin-top:14px">{head}</h3><table cellspacing="0">{cells(rows)}</table>'

        tools = "".join(f'<tr><td colspan="2" style="padding:10px 0 2px 0;color:{T.MUTED}">{e(group.upper())}</td></tr>'
                        + cells((name, TOOLS[name]) for name in names) for group, names in TOOL_GROUPS)

        parts = [f'<h2>NetScan</h2><p style="color:{T.MUTED}">A network toolbox built around nmap. Everything '
                 "works on any network; nothing needs a login on other devices.</p>",
                 table([(f"{name}  ({keys})", text) for name, keys, text in TABS], "Tabs"),
                 f'<h3 style="margin-top:14px">Tools</h3><table cellspacing="0">{tools}</table>',
                 table(SHORTCUTS, "Keyboard"),
                 table(ONLINE, "What contacts the internet"),
                 f'<p style="color:{T.MUTED}">Scans, the Devices list, the Monitor and the LAN speed test stay on '
                 "your network. Only Website watch checks the internet on its own, and only for sites you added.</p>",
                 f"<h3 style=\"margin-top:14px\">Your data</h3><p>Devices, history, caches and saved scans live in "
                 f"<code>{e(data_dir())}</code>. Delete that folder to start fresh.</p>",
                 "<h3 style=\"margin-top:14px\">Command line</h3><p><code>netscan.py --scan [--ports] [--json]</code>, "
                 "<code>--internet</code>, <code>--self-test</code>, <code>--help</code>.</p>"]
        dlg = QDialog(self)
        dlg.setWindowTitle("NetScan help")
        dlg.resize(760, 680)
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
