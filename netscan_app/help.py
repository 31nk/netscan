"""The Help window (F1 or the ? button): what each tab and tool does, shortcuts, and what goes online."""

import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QMessageBox, QPushButton, QTextBrowser, QVBoxLayout

from . import theme as T
from .devices import data_dir, make_portable, portable_dir
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
    ("History", "Devices online, latency, loss and speed tests over the last 30 days, with your plan's speed "
                "marked."),
    ("Slow internet?", "Finds where the problem is: Wi-Fi, cable, router, internet provider, DNS or bufferbloat."),
    ("Security checkup", "A grade out of 100 with a fix for each problem found."),
    ("Router check", "Double NAT or a shared provider address (both break port forwarding), and rogue DHCP servers."),
    ("Wi-Fi survey", "Measure the signal room by room to find dead spots."),
    ("Who's home", "Which devices (phones = people) were online, hour by hour."),
    ("Gaming & calls", "Latency, jitter and loss to cloud regions, graded for calls, games, cloud gaming and 4K."),
    ("VPN & privacy", "Whether your VPN leaks: IPv6 bypassing it, and which DNS servers see your lookups."),
    ("What the internet sees", "Ports open on your public address (Shodan), known vulnerabilities, spam blocklists."),
    ("Services & web pages", "Every device's web page and announced service (AirPlay, printers, shares…)."),
    ("Outages", "An optional connection watch that logs outages, and a report to send your provider."),
    ("Client sites", "A separate device list and scans per client network, switched automatically by router."),
    ("Site audit", "A branded report of a client network, plus an inventory CSV for IT Glue, Hudu and similar."),
    ("Firewall test", "Which outgoing ports a network allows (web, mail, remote access, VPN, VoIP), and UDP/NAT."),
    ("VoIP readiness", "Estimated call quality (MOS), SIP reachability, UDP and NAT behaviour."),
    ("Domain check (bulk)", "Many domains at once: email provider, Microsoft 365, SPF, DMARC, DKIM, expiry dates."),
    ("Mail server check", "SMTP, STARTTLS, reverse DNS and 14 spam blocklists for a domain's mail servers or an IP."),
    ("DNS propagation", "A record's answer from 20 public resolvers worldwide and the domain's own name servers."),
])

SHORTCUTS = [("F1", "This help"), ("F5", "Find hosts"), ("Ctrl+K", "Jump to anything (tabs, tools, devices, actions)"),
             ("Ctrl+Shift+C", "Copy what's on screen for a ticket"),
             ("Ctrl+F", "Filter the host list"), ("Ctrl+1 … Ctrl+6", "Switch tabs"),
             ("Delete", "Remove the selected Monitor target")]

ONLINE = [
    ("Internet check", "Cloudflare (1.1.1.1/cdn-cgi/trace) for your public IP; pings to 1.1.1.1 and 8.8.8.8."),
    ("Speed test", "Cloudflare's speed test, or the nearest public LibreSpeed server; also on the schedule you "
                   "pick (off by default)."),
    ("Slow internet? / Router check", "Pings to 1.1.1.1 and 8.8.8.8, a DNS lookup and, for Router check, "
                                      "Cloudflare for your public IP."),
    ("IP info / Domain toolkit", "RDAP registries (rdap.org and the registry it points to), DNS, the site itself."),
    ("Connections", "RDAP (rdap.org) to name who owns each remote address; cached for two weeks."),
    ("DNS speed", "Queries to Cloudflare and Google (DNS-over-HTTPS) and Quad9 (DNS-over-TLS)."),
    ("Known vulnerabilities", "Only when you ask, and only after you agree once: the software name and version "
     "(never an IP address) are sent to the US National Vulnerability Database (nvd.nist.gov). Cached 7 days."),
    ("Website watch / HTTP inspector", "The websites you enter."),
    ("Gaming & calls", "Pings to 1.1.1.1 and connections to Amazon's cloud regions (no data sent)."),
    ("VPN & privacy", "Cloudflare (your IPv4 and IPv6 address), RDAP registries, and bash.ws (DNS leak test)."),
    ("What the internet sees", "Your public IP address, to Shodan's InternetDB and four spam blocklists."),
    ("Outages (if you turn it on)", "A ping every 30 seconds to 1.1.1.1 and, if that fails, 8.8.8.8."),
    ("Firewall test / VoIP readiness", "Connections to portquiz.net on each tested port; STUN to Cloudflare and "
                                       "Google."),
    ("Domain / mail checks", "RDAP, DNS, the domain's website and mail servers, Microsoft's public sign-in lookup "
                             "(getuserrealm), and spam blocklists (by DNS)."),
    ("DNS propagation / Site audit", "20 public DNS resolvers; the audit also uses Cloudflare and RDAP for the "
                                     "public address."),
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
                 "your network. Only Website watch, the Outages connection watch and scheduled speed tests contact the "
                 "internet on their own, and only once you turn them on.</p>",
                 f"<h3 style=\"margin-top:14px\">Your data</h3><p>Devices, history, caches and saved scans live in "
                 f"<code>{e(data_dir())}</code>. Delete that folder to start fresh.</p>"
                 + ("<p>Portable mode is on: settings are in that folder too, so they travel with NetScan.</p>"
                    if portable_dir() else "<p>To carry everything on a USB stick, use Portable mode "
                    "(Ctrl+K → Portable mode, or <code>netscan.py --portable</code>).</p>"),
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

    def show_portable(self):
        folder = portable_dir()
        if folder:
            QMessageBox.information(self, "Portable mode", f"Portable mode is on. Devices, history and settings are "
                                    f"kept in:\n\n{folder}\n\nCopy the whole NetScan folder to take them to another "
                                    "computer. To stop, close NetScan and move or delete that folder.")
            return
        answer = QMessageBox.question(
            self, "Portable mode", "Keep your devices, history and settings in a NetScan-data folder next to "
            "netscan.py instead of this computer's app-data folder? Copy the NetScan folder to a USB stick and they "
            "come with you.\n\nThis computer's data is copied there now; restart NetScan to switch.")
        if answer != QMessageBox.Yes:
            return
        try:
            folder, _created = make_portable()
        except OSError as err:
            QMessageBox.warning(self, "Portable mode", f"Couldn't create the folder: {err}")
            return
        QMessageBox.information(self, "Portable mode", f"Done: {folder}\n\nRestart NetScan to use it.")
