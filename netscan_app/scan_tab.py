"""Scan tab: running nmap, host discovery, the hosts table, port scans, this computer's ports and the right-click menu."""

import codecs
import getpass
import ipaddress
import re
import shutil
import socket
import xml.etree.ElementTree as ET

from PySide6.QtCore import (
    QProcess, QProcessEnvironment, QTimer, QUrl, Qt,
)
from PySide6.QtGui import (
    QColor, QDesktopServices, QFont, QGuiApplication, QIcon,
)
from PySide6.QtWidgets import (
    QApplication, QInputDialog, QMenu, QMessageBox, QTableWidgetItem,
)

from . import history_db
from . import theme as T
from .columns import (
    COLUMNS, COL_CHANGE, COL_HOST, COL_INFO, COL_IP, COL_MAC, COL_NAME, COL_OS, COL_PORTS,
    COL_VENDOR, DISCOVERY_FIELDS,
)
from .devices import DEVICE_TYPES, port_risk, risky, save_history, spoof_check
from .discovery import cert_note, is_tls_port, is_web_port, likely_app, ufw_active
from .router import ROUTER_LEASE_CMD, askpass_helper, parse_dnsmasq_leases
from .scanning import (
    CUSTOM_PROFILE, PORT_PROFILES, UDP_PORTS, WEB_PORTS, mac_vendor, merge_ports, parse_host,
    parse_os, parse_ports, port_label, port_set, summarize_ports, top_tcp_ports, valid_port_list,
    valid_ssh_user,
)
from .system import (
    IS_MAC, IS_WIN, LAN_FAST, find_program, iface_args, local_listeners, local_open_ports,
    neighbour_macs, now_iso, terminal_argv, this_os_name,
)
from .theme import apply_theme, icon_path
from .vulns import versioned_cpes
from .widgets import IPItem, TraceDialog


class ScanMixin:
    """Scan tab: running nmap, host discovery, the hosts table, port scans, this computer's ports and the right-click menu. Mixed into MainWindow."""

    # ---- running nmap ------------------------------------------------------

    def run_nmap(self, args, message, on_host, on_done):
        """Run nmap (as root via pkexec/sudo if requested), streaming results.

        on_host(elem) is called for each <host> element as nmap finishes it;
        on_done(stderr, code) once nmap exits.
        """
        use_root = self.root_box.isChecked() and self.has_root
        # -n: nmap's reverse DNS can hang for minutes behind a VPN that blocks
        # LAN DNS; names are looked up separately by Resolver instead.
        args = ["-n", "-T4", "--stats-every", "1s", "-oX", "-", *args]
        if IS_WIN and not use_root:
            args.insert(0, "--unprivileged")
        # With capabilities, nmap itself can send raw packets: no pkexec, no prompt.
        prompt = bool(use_root and self.root and not self.nmap_caps)
        if use_root and self.nmap_caps:
            args.insert(0, "--privileged")
        program, argv = ((self.root[0], [*self.root[1:], self.nmap, *args]) if prompt
                         else (self.nmap, args))
        self.prompted = prompt

        self.output = ""
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.parser = ET.XMLPullParser(events=("end",))
        self.elapsed = 0
        self.on_host = on_host
        self.on_done = on_done
        self.used_root = use_root
        self.scan_message = message
        self.set_busy(True)
        self.status.setText(message + (" (authorise in the prompt)" if prompt else ""))

        self.proc = QProcess(self)
        self.proc.setProcessChannelMode(QProcess.SeparateChannels)
        self.proc.readyReadStandardOutput.connect(self.read_output)
        self.proc.finished.connect(self.nmap_finished)
        self.proc.errorOccurred.connect(self.nmap_error)
        if use_root and self.askpass:
            env = QProcessEnvironment.systemEnvironment()
            env.insert("SUDO_ASKPASS", self.askpass)
            self.proc.setProcessEnvironment(env)
        self.proc.start(program, argv)
        self.timer.start()

    def is_running(self):
        return self.proc is not None and self.proc.state() != QProcess.NotRunning

    def update_controls(self):
        """Enable/disable controls based on busy state and current choices."""
        busy = self.is_running()
        has_hosts = self.table.rowCount() > 0
        root = self.root_box.isChecked() and self.has_root
        self.scan_btn.setEnabled(not busy and bool(self.nmap))
        self.ports_btn.setEnabled(not busy and has_hosts)
        for w in (self.target, self.refresh_btn, self.profile, self.version_box, self.compare_btn):
            w.setEnabled(not busy)
        self.root_box.setEnabled(not busy and self.has_root)
        self.udp_box.setEnabled(not busy and root)
        self.os_box.setEnabled(not busy and root)
        # OS detection fingerprints open/closed ports, so it forces the port scan on.
        os_on = self.os_box.isChecked() and root
        self.auto_ports_box.setEnabled(not busy and not os_on)
        self.auto_ports_box.setToolTip("Included automatically: OS detection needs a port scan." if os_on
                                       else "Scan each host's top 100 TCP ports while finding hosts.")
        self.udp_box.setToolTip(f"Also scan UDP {UDP_PORTS}" + ("" if root else " (needs root)"))
        self.custom_ports.setVisible(self.profile.currentIndex() == CUSTOM_PROFILE)
        self.custom_ports.setEnabled(not busy)
        self.export_btn.setEnabled(not busy and has_hosts)
        self.compare_btn.setEnabled(not busy and has_hosts)

    def os_toggled(self, on):
        """Tick (and lock) the port scan while Detect OS is on; restore the user's choice after."""
        if on:
            self.auto_before_os = self.auto_ports_box.isChecked()
            self.auto_ports_box.setChecked(True)
        elif self.auto_before_os is not None:
            self.auto_ports_box.setChecked(self.auto_before_os)
            self.auto_before_os = None
        self.update_controls()

    def update_nmap_pill(self):
        self.nmap_pill.setText(
            f'<span style="color:{T.GREEN if self.nmap else T.RED}">●</span>&nbsp; '
            + (f"nmap {self.nmap_version}" if self.nmap_version else
               "nmap ready" if self.nmap else "nmap not found"))

    def retheme(self, mode):
        """Switch theme live: restyle, then repaint everything that was coloured by hand."""
        self.theme_mode = mode
        apply_theme(QApplication.instance(), mode)
        for act in self.theme_group.actions():
            act.setChecked(act.data() == mode)
        self.search_act.setIcon(QIcon(icon_path("search")))
        self.dev_search_act.setIcon(QIcon(icon_path("search")))
        for i in range(1, self.detail_type.count()):
            self.detail_type.setItemIcon(i, QIcon(icon_path("type-" + self.detail_type.itemData(i))))
        for ip in self.hosts:
            self.refresh_row(ip)
        for row in range(self.table.rowCount()):
            text = self.table.item(row, COL_CHANGE).text()
            if text:
                self.set_change(row, text)
        self.update_nmap_pill()
        self.set_dot(T.ACCENT if self.is_running() else T.GREEN)
        self.show_port_details()
        self.refresh_devices()
        self.refresh_monitor()

    def set_dot(self, color):
        self.status_dot.setStyleSheet(f"color: {color};")

    def set_busy(self, busy):
        self.set_dot(T.ACCENT if busy else T.GREEN)
        self.progress.setVisible(busy)
        self.progress.setRange(0, 0)  # indeterminate until nmap reports %
        self.progress.setFormat("%p%")
        self.update_controls()

    def tick(self):
        self.elapsed += 1

    def read_output(self):
        chunk = self.decoder.decode(bytes(self.proc.readAllStandardOutput()))
        self.output += chunk
        if self.parser is None:
            return
        try:
            self.parser.feed(chunk)
            for _event, elem in self.parser.read_events():
                if elem.tag == "host":
                    self.on_host(elem)
                elif elem.tag == "taskprogress":
                    pct = float(elem.get("percent", 0))
                    left = int(elem.get("remaining", 0) or 0)
                    self.progress.setRange(0, 100)
                    self.progress.setValue(int(pct))
                    self.progress.setFormat(f"%p%  ~{left}s left" if left else "%p%")
        except ET.ParseError:
            self.parser = None  # keep what we have; report on finish

    def nmap_error(self, err):
        if err == QProcess.FailedToStart:
            self.timer.stop()
            self.set_busy(False)
            self.set_dot(T.RED)
            self.status.setText("Could not start nmap.")

    def nmap_finished(self, code, _status):
        self.timer.stop()
        self.read_output()
        stderr = bytes(self.proc.readAllStandardError()).decode(errors="replace").strip()
        self.set_busy(False)
        # pkexec: 126 = auth dialog dismissed, 127 = not authorised.
        # sudo -A: password dialog cancelled or wrong, reported as "sudo: ..." with no nmap output.
        declined = ("sudo:" in stderr and "<nmaprun" not in self.output) if IS_MAC \
            else code in (126, 127)
        if declined and self.prompted:
            self.set_dot(T.AMBER)
            self.status.setText("Root access was declined. Untick “Run as root” to scan without it.")
            self.on_done(stderr, code, failed=True)
            return
        if "<nmaprun" not in self.output:
            self.set_dot(T.RED)
            self.status.setText("Scan failed. " + (stderr.splitlines()[-1] if stderr else f"nmap exit {code}"))
            self.on_done(stderr, code, failed=True)
            return
        self.last_xml = self.output
        self.on_done(stderr, code, failed=False)

    # ---- host discovery ----------------------------------------------------

    def start_scan(self):
        targets, net = self.selected_target()
        if not targets or not all(re.fullmatch(r"[0-9A-Za-z.\-/:]+", t) for t in targets):
            QMessageBox.warning(self, "NetScan", "Enter a valid target, e.g. 192.168.1.0/24")
            return
        self.current = net
        self.last_target = " ".join(targets)
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.ip_items = {}
        self.table.setColumnHidden(COL_CHANGE, True)
        self.table.setColumnHidden(COL_OS, True)
        self.table.setColumnHidden(COL_INFO, True)
        self.scan_token += 1
        self.upnp = None
        self.disc_summary = ""
        self.new_devices = set()
        self.hosts = {}
        self.ports = {}
        self.pending = set()
        self.show_port_details()

        # With auto port scan, one nmap run does discovery and then scans each
        # live host (one password prompt instead of two).
        self.auto_ports = self.auto_ports_box.isChecked() or bool(self.os_args())
        if self.auto_ports:
            args = ["--top-ports", "100"] + (["-sV"] if self.version_box.isChecked() else [])
            args += self.os_args()
            message = (f"Finding hosts, scanning top 100 ports{' and detecting OS' if self.os_args() else ''}"
                       f" on {self.last_target}…")
        else:
            args = ["-sn"]
            message = f"Finding hosts on {self.last_target}…"
        if self.auto_ports and net:
            args += LAN_FAST
        if net:
            # Scanning ourselves in the same run throws off nmap's timing for every other host
            # (a full port scan found 1 of the router's 3 open ports); our ports come from the OS.
            args += ["--exclude", net["local_ip"]]
        args += iface_args(net) + targets
        self.run_nmap(args, message, self.host_found, self.hosts_done)

    def host_found(self, elem):
        h = parse_host(elem)
        if h is None:
            return
        net = self.current
        if net and h["ip"] == net["local_ip"]:
            h["mac"] = h["mac"] or net["mac"]
            h["hostname"] = h["hostname"] or socket.gethostname()
            h["vendor"] = h["vendor"] or "(this computer)"
        h["vendor"] = h["vendor"] or mac_vendor(h["mac"])
        self.hosts[h["ip"]] = h
        h["os"] = parse_os(elem)
        if self.auto_ports:
            self.ports[h["ip"]] = parse_ports(elem)
        self.add_row(h)
        if not h["hostname"]:
            self.pending.add(h["ip"])
            self.resolver.lookup([h["ip"]])
        self.status.setText(f"{self.scan_message} {len(self.hosts)} host(s) so far.")

    def hosts_done(self, _stderr, _code, failed):
        # Fill MACs nmap couldn't see (unprivileged scans) from the kernel's ARP cache.
        if self.current:
            macs = neighbour_macs(self.current["iface"])
            for ip, h in self.hosts.items():
                if not h["mac"] and ip in macs:
                    h["mac"] = macs[ip]
                    h["vendor"] = h["vendor"] or mac_vendor(h["mac"])
                    self.refresh_row(ip)
        if not failed:
            self.add_this_computer()
            self.apply_local_ports()
            # Flag devices never seen before, unless this is the first scan ever
            # (then everything would be "new").
            first_run = not self.devices.known_macs()
            with self.devices.batch():
                new = self.devices.record(self.hosts.values(), checked=bool(self.current))
                if self.auto_ports:
                    top = {"tcp": port_set(top_tcp_ports(100)), "udp": set()}
                    for ip, h in self.hosts.items():
                        if h["mac"]:
                            self.devices.update_ports(h["mac"], self.network_ports(ip), top)
            if self.current:
                self.online_macs = {h["mac"] for h in self.hosts.values() if h["mac"]}
                self.run_spoof_check({ip: h["mac"] for ip, h in self.hosts.items()})
                history_db.record("online", str(self.current["network"]), len(self.hosts))
            for ip, h in self.hosts.items():
                rec = self.devices.get(h)
                for key in ("hostname",) + DISCOVERY_FIELDS:  # remembered names, models, services
                    if not h.get(key) and rec.get(key):
                        h[key] = rec[key]
                self.refresh_row(ip)  # MACs, trust and device types are settled now
            self.history_path = save_history(self.scan_record()) if self.hosts else None
            self.refresh_devices()
            if not first_run and self.current:
                self.new_devices = set(new)
                for ip, h in self.hosts.items():
                    if h["mac"] in self.new_devices:
                        self.set_change(self.row_for_ip(ip), "NEW DEVICE")
        self.table.setSortingEnabled(True)
        self.table.sortItems(COL_IP)
        self.table.resizeColumnsToContents()
        self.update_controls()
        if failed:
            return

        n = len(self.hosts)
        self.summary = f"Found {n} host(s) in {max(self.elapsed, 1)}s."
        if n <= 1:
            self.summary += " Few results? If you use a VPN (e.g. Mullvad), enable Local Network Sharing."
            if IS_MAC:
                self.summary += (" Also allow NetScan under System Settings › Privacy & Security"
                                 " › Local Network.")
        if not self.used_root:
            self.summary += " Unprivileged scan: some devices may be missed."
        if self.auto_ports:
            total = sum(len(p) for ip, p in self.ports.items() if ip != self.local_ip())
            self.summary += f" {total} open port(s) in the top 100."
        elif n:
            self.summary += " Select hosts and press Scan Ports to check for services."
        self.summary += self.os_summary(self.hosts)
        self.summary += self.this_computer_summary(self.hosts)
        self.summary += self.risk_summary(self.hosts)
        if self.new_devices:
            self.summary += f" {len(self.new_devices)} device(s) never seen before."
        for severity, text in self.spoof_warnings:
            self.summary += (" ⚠ " if severity == "high" else " Note: ") + text
        self.update_status()
        if self.spoof_warnings and any(sv == "high" for sv, _t in self.spoof_warnings):
            self.set_dot(T.RED)
        if self.current:
            self.start_discovery(names=True, ips=list(self.hosts))

    def update_status(self):
        extra = f" Looking up {len(self.pending)} name(s)…" if self.pending else ""
        if self.discovering:
            extra += " Identifying devices (names, UPnP, IPv6, web pages)…"
        self.status.setText(self.summary + extra)

    # ---- table helpers -----------------------------------------------------

    def add_row(self, h):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.ip_items[h["ip"]] = IPItem(h["ip"])
        self.table.setItem(row, COL_IP, self.ip_items[h["ip"]])
        for col in range(1, len(COLUMNS)):
            self.table.setItem(row, col, QTableWidgetItem(""))
        for col in (COL_IP, COL_MAC):
            self.table.item(row, col).setFont(self.mono)
        bold = QFont()
        bold.setBold(True)
        self.table.item(row, COL_NAME).setFont(bold)
        self.refresh_row(h["ip"], row)

    def refresh_row(self, ip, row=None):
        row = self.row_for_ip(ip) if row is None else row
        if row is None:
            return
        h = self.hosts[ip]
        rec = self.devices.get(h)
        ip_item = self.table.item(row, COL_IP)
        kind, guessed = self.devices.device_type(h, self.ports.get(ip), self.gateway())
        ip_item.setIcon(self.type_icon(kind))
        tips = [DEVICE_TYPES[kind] + (" (guessed)" if guessed else "")]
        untrusted = (bool(h["mac"]) and h["vendor"] != "(this computer)" and not rec.get("trusted")
                     and self.devices.any_trusted())
        if untrusted:
            tips.append("Not marked as trusted")
        ip_item.setForeground(QColor(T.AMBER if untrusted else T.TEXT))
        ip_item.setToolTip("\n".join(tips))
        self.table.item(row, COL_NAME).setText(rec.get("nickname", ""))
        self.table.item(row, COL_HOST).setText(h["hostname"])
        self.table.item(row, COL_OS).setText(h.get("os", ""))
        if h.get("os"):
            self.table.setColumnHidden(COL_OS, False)
        info_text, info_tip = self.identified(h, self.ports.get(ip))
        info = self.table.item(row, COL_INFO)
        info.setText(info_text)
        info.setToolTip(info_tip)
        if info_text:
            self.table.setColumnHidden(COL_INFO, False)
        self.table.item(row, COL_MAC).setText(h["mac"])
        vendor = self.table.item(row, COL_VENDOR)
        vendor.setText(h["vendor"])
        # "(this computer)", "(private/randomised MAC)": notes rather than real vendors
        vendor.setForeground(QColor(T.ACCENT_HI if h["vendor"] == "(this computer)" else
                                    T.MUTED if h["vendor"].startswith("(") else T.TEXT))
        ports = self.table.item(row, COL_PORTS)
        bad = risky(self.ports.get(ip))
        text = summarize_ports(self.ports.get(ip))
        reachable = self.network_ports(ip)
        if ip == self.local_ip() and ip in self.ports:  # reachable vs localhost-only
            local_only = sum(1 for p in self.ports[ip] if p.get("local_only") and not p.get("temporary"))
            text = (summarize_ports(reachable) if reachable else "none reachable from the network") \
                + (f"  · +{local_only} local-only" if local_only else "")
        exposed = h.get("upnp") or []
        if exposed:  # ports a device opened to the internet through the router's UPnP
            text = "open to the internet: " + ", ".join(
                f"{m['external_port']}/{m['protocol']}" for m in exposed) + ("  · " + text if text else "")
        if ":" in ip and ip not in self.ports:
            text = "found over IPv6 only"
        ports.setText(("⚠ " if bad or exposed else "") + text)
        ports.setForeground(QColor(T.AMBER if bad or exposed else T.GREEN if reachable else T.MUTED))
        ports.setToolTip("\n".join(
            [f"Internet port {m['external_port']}/{m['protocol']} → {ip}:{m['internal_port']}"
             f"{' (' + m['description'] + ')' if m['description'] else ''}, opened via UPnP"
             + (f", likely {likely_app(m['protocol'], m['external_port'])}"
                if likely_app(m["protocol"], m["external_port"]) else "") for m in exposed]
            + [f"{port_label(p)}: {port_risk(p)}" for p in bad]))
        self.apply_filter_row(row)

    @staticmethod
    def identified(h, ports=None):
        """(short text, tooltip) of what a device says it is: announced name/model, web page, services."""
        name = (h.get("hostname") or "").lower()
        services = [x for x in h.get("services") or [] if x.lower() != name]
        titles = [f"{p['port']}: {p['title']}" for p in ports or [] if p.get("title")]
        real_titles = [t for t in titles if not re.match(r"\d+: (HTTP )?\d{3}\b", t)]
        model = " ".join(x for x in (h.get("maker"), h.get("model")) if x and x not in (h.get("friendly") or ""))
        text = h.get("friendly") or (services[0] if services else "") or model \
            or (real_titles[0].split(": ", 1)[1] if real_titles else "")
        tip = [line for line in (
            f"Model: {model}" if model else "", f"Announced name: {h['friendly']}" if h.get("friendly") else "",
            "Services: " + ", ".join(services) if services else "",
            "Web pages: " + "; ".join(titles) if titles else "",
            "IPv6: " + ", ".join(h["ipv6"]) if h.get("ipv6") else "") if line]
        return text, "\n".join(tip)

    def start_discovery(self, names, ips, sweep=False):
        """Background, read-only extras: mDNS/SSDP names, IPv6 neighbours, router UPnP, web page titles."""
        net = self.current
        reachable = [(ip, p) for ip in ips if ":" not in ip for p in self.ports.get(ip) or []
                     if not p.get("local_only") and not p.get("temporary")]
        web = [(ip, p["port"]) for ip, p in reachable if is_web_port(p) and not p.get("title")]
        tls = [(ip, p["port"]) for ip, p in reachable if is_tls_port(p) and "cert" not in p]
        if not names and not web and not tls:
            return
        if self.discovering:
            return  # one at a time; the running one reports soon
        gw = self.gateway()
        router = self.hosts.get(gw, {})
        rec = self.devices.get(router) if router else {}
        job = {"token": self.scan_token, "net": net, "gateway": gw if names else None, "web": web, "tls": tls,
               "what": {"names"} if names else set(),
               "upnp_urls": [rec["upnp_url"]] if rec.get("upnp_url") else [],
               "announced": {ip: sorted(urls) for ip, urls in list(self.ssdp_listener.seen.items())},
               "nmap": self.nmap if sweep else None,
               "upnp_ports": list(dict.fromkeys(p["port"] for p in (self.ports.get(gw) or []) + (rec.get("ports") or [])
                                                if p["proto"] == "tcp"))}
        self.discovering = True
        self.update_status()
        self.discovery.start(job)

    def ssdp_announced(self, ip, url):
        """A UPnP device announced itself; if it's our router and we don't know its UPnP yet, check it now."""
        if ip != self.gateway() or self.upnp or self.is_running():
            return
        if self.discovering:
            self.upnp_pending = True  # check once the running discovery finishes
            return
        self.start_discovery(names=True, ips=[])

    def check_upnp(self):
        """Ask the router which ports devices opened to the internet; search its ports if needed."""
        router = self.hosts.get(self.gateway(), {})
        known = self.devices.get(router).get("upnp_url") if router else None
        self.summary = ("Checking the router's UPnP port forwards…" if known else
                        "Searching the router's ports for its UPnP service (about a minute)…")
        self.start_discovery(names=True, ips=[], sweep=True)  # sweeps only if the quick checks fail

    def apply_discovery(self, res):
        if res["token"] != self.scan_token:
            return  # a newer scan has started since
        self.discovering = False
        notes, touched = [], set()
        # Devices first (IPv6 neighbours, mDNS/SSDP responders the scan missed), then what they announce.
        added = self.apply_ipv6(res.get("ipv6", {}))
        for ip in list(res.get("mdns", {})) + list(res.get("upnp_devices", {})):
            added += self.add_found_host(ip)
        if added:
            notes.append(f"{added} more device(s) found by IPv6/mDNS/UPnP that the scan missed.")
        for ip, d in res.get("mdns", {}).items():
            h = self.hosts.get(ip)
            if not h:
                continue
            h["hostname"] = h["hostname"] or d["name"]
            h["services"], h["svc_types"] = d["services"], d["types"]
            h["model"] = h.get("model") or d["model"]
            h["friendly"] = d["friendly"] or h.get("friendly", "")
            touched.add(ip)
        for ip, info in res.get("upnp_devices", {}).items():
            h = self.hosts.get(ip)
            if not h:
                continue
            h["friendly"] = h.get("friendly") or info["friendly"]
            h["model"] = h.get("model") or " ".join(x for x in (info["model"], info["model_number"]) if x)
            h["maker"] = h.get("maker") or info["manufacturer"]
            h["upnp_type"] = info["device_type"]
            touched.add(ip)
        for (ip, port), cert in res.get("certs", {}).items():
            for p in self.ports.get(ip) or []:
                if p["port"] == port and p["proto"] == "tcp":
                    p["cert"] = cert
                    touched.add(ip)
        for (ip, port), title in res.get("titles", {}).items():
            for p in self.ports.get(ip) or []:
                if p["port"] == port and p["proto"] == "tcp":
                    p["title"] = title
                    touched.add(ip)
        if "upnp" in res:
            self.upnp = res["upnp"]
            for h in self.hosts.values():
                h.pop("upnp", None)
            if self.upnp:
                gw = self.gateway()
                if gw in self.hosts:
                    self.devices.update(self.hosts[gw], upnp_url=self.upnp["url"])
                for m in self.upnp["mappings"]:
                    if m["client"] in self.hosts and m["enabled"]:
                        self.hosts[m["client"]].setdefault("upnp", []).append(m)
                        touched.add(m["client"])
                n = sum(1 for m in self.upnp["mappings"] if m["enabled"])
                notes.append(f"Router UPnP: {n} port(s) opened to the internet by devices." if n
                             else "Router UPnP: no ports opened to the internet.")
            else:
                hint = ""
                if not res.get("ssdp") and ufw_active():
                    lan = str(self.current["network"])
                    hint = (" Your firewall (ufw) blocks UPnP discovery replies; to allow them: "
                            f"sudo ufw allow proto udp from {lan} port 1900")
                heard = bool(self.ssdp_listener.seen)
                notes.append("Router UPnP: not found yet. NetScan listens for the router's own announcement "
                             "(usually within a minute) and checks automatically"
                             + ("" if heard else "; or right-click the router → Check internet port forwards")
                             + "." + hint)
        with self.devices.batch():
            for ip in touched:
                h = self.hosts[ip]
                if h["mac"]:
                    self.devices.update(h, **{k: h[k] for k in DISCOVERY_FIELDS + ("hostname",) if h.get(k)})
        for ip in touched:
            self.refresh_row(ip)
        self.table.resizeColumnsToContents()
        self.disc_summary = " ".join(notes)
        if notes:
            # replace an earlier discovery note rather than piling them up
            self.summary = re.sub(r" (\d+ more device\(s\) found|Router UPnP:).*$", "", self.summary.rstrip())
            self.summary += " " + self.disc_summary
        if self.upnp_pending and not self.upnp:
            self.upnp_pending = False
            QTimer.singleShot(0, lambda: self.start_discovery(names=True, ips=[]))
        self.show_port_details()
        self.refresh_devices()
        self.net_map.update()
        self.update_status()

    def add_found_host(self, ip, mac=None, ipv6=None):
        """Add a device another discovery method found on this network (1 if added, else 0)."""
        net = self.current
        if not net or ip in self.hosts or ip == net["local_ip"]:
            return 0
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return 0
        if addr.version == 4 and addr not in net["network"]:
            return 0  # e.g. a device's second interface on another subnet
        if mac is None:
            mac = neighbour_macs(net["iface"]).get(ip, "")
        if mac and any(h["mac"] == mac for h in self.hosts.values()):
            return 0  # already listed under another address
        h = {"ip": ip, "hostname": "", "mac": mac, "vendor": mac_vendor(mac), "os": ""}
        if ipv6:
            h["ipv6"] = ipv6
        rec = self.devices.get(h) if mac else {}
        for key in ("hostname",) + DISCOVERY_FIELDS:
            if not h.get(key) and rec.get(key):
                h[key] = rec[key]
        self.table.setSortingEnabled(False)
        self.hosts[ip] = h
        self.add_row(h)
        self.table.setSortingEnabled(True)
        if mac:
            first_run = not self.devices.known_macs()
            new = self.devices.record([h], checked=False)
            self.online_macs.add(mac)
            if new and not first_run:
                self.new_devices.add(mac)
                self.set_change(self.row_for_ip(ip), "NEW DEVICE")
        return 1

    def apply_ipv6(self, neighbours):
        """Note devices' IPv6 addresses; add devices that only answered over IPv6. Returns how many were added."""
        if not neighbours or not self.current:
            return 0
        net = self.current
        arp = {mac: ip for ip, mac in neighbour_macs(net["iface"]).items()}
        by_mac = {h["mac"]: h for h in self.hosts.values() if h["mac"]}
        added = 0
        for mac, addrs in neighbours.items():
            if mac == net["mac"]:
                continue
            if mac in by_mac:
                by_mac[mac]["ipv6"] = addrs
                continue
            v4 = arp.get(mac)  # it may have an IPv4 address the scan missed
            inside = v4 and ipaddress.ip_address(v4) in net["network"] and v4 not in self.hosts
            added += self.add_found_host(v4 if inside else addrs[0], mac, addrs)
        return added

    def gateway(self):
        return self.current.get("gateway") if self.current else None

    def type_icon(self, kind):
        key = (T.THEME, kind)
        if key not in self._icons:
            self._icons[key] = QIcon(icon_path("type-" + kind))
        return self._icons[key]

    def set_change(self, row, text):
        """Fill the Change column (compare results, new devices) and make sure it's showing."""
        if row is None:
            return
        item = self.table.item(row, COL_CHANGE)
        item.setText(text)
        font = QFont()
        font.setBold(bool(text))
        item.setFont(font)
        item.setForeground(QColor(T.GREEN if text.startswith("NEW") else
                                  T.RED if text.startswith("−") else T.AMBER))
        if text:
            self.table.setColumnHidden(COL_CHANGE, False)
            self.table.resizeColumnToContents(COL_CHANGE)

    def row_for_ip(self, ip):
        item = self.ip_items.get(ip)
        return item.row() if item is not None else None

    def on_resolved(self, ip, name):
        if ip not in self.pending:
            return  # stale result from a previous scan
        self.pending.discard(ip)
        if name and ip in self.hosts:
            self.hosts[ip]["hostname"] = name
            self.devices.update(self.hosts[ip], hostname=name)
            self.refresh_row(ip)
            self.table.resizeColumnToContents(COL_HOST)
        if not self.is_running():
            self.update_status()

    def apply_filter(self):
        for row in range(self.table.rowCount()):
            self.apply_filter_row(row)
        self.update_count()

    def apply_filter_row(self, row):
        text = self.filter_edit.text().strip().lower()
        ip = self.table.item(row, COL_IP).text()
        visible = True
        if text:
            visible = any(text in (self.table.item(row, c).text().lower())
                          for c in range(len(COLUMNS)))
        if visible and self.open_only_box.isChecked():
            visible = bool(self.ports.get(ip))
        self.table.setRowHidden(row, not visible)
        self.count_timer.start()

    def update_count(self):
        total = self.table.rowCount()
        shown = sum(not self.table.isRowHidden(r) for r in range(total))
        self.count_label.setText(f"{shown} of {total} shown" if shown != total else f"{total} host(s)")

    def visible_ips(self):
        return [self.table.item(r, COL_IP).text() for r in range(self.table.rowCount())
                if not self.table.isRowHidden(r)]

    def selected_ips(self):
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        return [self.table.item(r, COL_IP).text() for r in rows if not self.table.isRowHidden(r)]

    # ---- port scanning -----------------------------------------------------

    def port_args(self):
        """nmap args for the chosen port profile, or None if the input is invalid."""
        idx = self.profile.currentIndex()
        if idx == CUSTOM_PROFILE:
            tcp = self.custom_ports.text().replace(" ", "")
            if not valid_port_list(tcp):
                QMessageBox.warning(self, "NetScan",
                                    "Enter ports like 22,80,443 or ranges like 8000-8100.")
                return None
        else:
            tcp = top_tcp_ports(PORT_PROFILES[idx][1])
        self.scanned = {"tcp": port_set(tcp), "udp": set()}
        if self.udp_box.isChecked() and self.udp_box.isEnabled():
            self.scanned["udp"] = port_set(UDP_PORTS)
            return ["-sS", "-sU", "-p", f"T:{tcp},U:{UDP_PORTS}"]
        return ["-p", tcp]

    def start_port_scan(self, ips=None):
        ips = ips or self.selected_ips() or self.visible_ips()
        if not ips:
            return
        args = self.port_args()
        if args is None:
            return
        me = self.local_ip()
        v6_only = [ip for ip in ips if ":" in ip]
        others = [ip for ip in ips if ip != me and ":" not in ip]
        if v6_only and not others and me not in ips:
            self.status.setText("Devices found only over IPv6 can't be port-scanned yet; "
                                "they didn't answer on IPv4.")
            return
        if not others:  # only this computer: read its ports from the OS, no nmap needed
            self.apply_local_ports()
            self.show_port_details()
            self.summary = ("This computer's ports come from its own list of listening sockets."
                            + self.this_computer_summary([me]))
            self.update_status()
            return
        if self.profile.currentIndex() == 2 and len(others) > 3:
            answer = QMessageBox.question(
                self, "NetScan",
                f"Scanning all 65535 ports on {len(others)} hosts can take a long time. Continue?")
            if answer != QMessageBox.Yes:
                return

        self.scan_ips = ips
        self.reported = set()
        for ip in ips:
            row = self.row_for_ip(ip)
            if row is not None:
                self.table.item(row, COL_PORTS).setText("scanning…")
                self.table.item(row, COL_PORTS).setForeground(QColor(T.ACCENT_HI))

        # -Pn: hosts are already known to be up, skip re-pinging them.
        args = ["-Pn", "--open", *args]
        if self.version_box.isChecked():
            args.append("-sV")
        args += self.os_args()
        args += iface_args(self.current) + others
        what = f"{len(others)} host(s)" if len(others) > 1 else others[0]
        label = self.profile.currentText().removesuffix("…").split(" (")[0].lower()
        self.run_nmap(args, f"Scanning {label} on {what}…", self.ports_found, self.ports_done)

    def ports_found(self, elem):
        ip = next((a.get("addr") for a in elem.findall("address")
                   if a.get("addrtype") == "ipv4"), None)
        if ip not in self.hosts:
            return
        self.reported.add(ip)
        self.ports[ip] = merge_ports(self.ports.get(ip), parse_ports(elem), self.scanned)
        os_guess = parse_os(elem)
        if os_guess:
            self.hosts[ip]["os"] = os_guess
            self.devices.update(self.hosts[ip], os=os_guess)
        self.refresh_row(ip)
        if self.selected_ips() == [ip]:
            self.show_port_details()

    def ports_done(self, _stderr, _code, failed):
        for ip in self.scan_ips:
            if ip not in self.reported:
                if failed:
                    self.refresh_row(ip)  # restore previous value
                    continue
                # --open omits hosts without open ports
                self.ports[ip] = merge_ports(self.ports.get(ip), [], self.scanned)
                self.refresh_row(ip)
        self.table.resizeColumnToContents(COL_PORTS)
        self.show_port_details()
        if failed:
            return
        if self.local_ip() in self.scan_ips:
            self.apply_local_ports()
        total = sum(len(self.ports.get(ip, [])) for ip in self.scan_ips if ip != self.local_ip())
        mode = "SYN" if self.used_root else "TCP connect"
        self.summary = (f"Port scan done in {max(self.elapsed, 1)}s ({mode}): "
                        f"{total} open port(s) on {len(self.scan_ips)} host(s).")
        self.summary += self.os_summary({ip: self.hosts[ip] for ip in self.scan_ips if ip in self.hosts})
        self.summary += self.this_computer_summary(self.scan_ips)
        self.summary += self.risk_summary(self.scan_ips)
        with self.devices.batch():
            for ip in self.scan_ips:
                h = self.hosts.get(ip)
                if h and h["mac"]:
                    self.devices.update_ports(h["mac"], self.network_ports(ip), self.scanned)
        for ip in self.scan_ips:
            if ip in self.hosts:
                self.refresh_row(ip)
        if self.history_path:
            save_history(self.scan_record(), self.history_path)
        self.refresh_devices()
        self.update_status()
        if self.current:
            self.start_discovery(names=False, ips=self.scan_ips)

    # ---- this computer ------------------------------------------------------

    def local_ip(self):
        return self.current["local_ip"] if self.current else None

    def network_ports(self, ip):
        """Open ports other machines can reach (drops this computer's localhost-only ones and
        temporary sockets, which change every run)."""
        return [p for p in self.ports.get(ip) or [] if not (p.get("local_only") or p.get("temporary"))]

    def this_computer_summary(self, ips):
        me = self.local_ip()
        if me not in ips or me not in self.ports:
            return ""
        return f" This computer: {len(self.network_ports(me))} port(s) reachable from the network."

    def add_this_computer(self):
        """List this computer even if nmap didn't report it, when its IP is inside the scanned range."""
        ip, net = self.local_ip(), self.current
        if not ip or ip in self.hosts:
            return
        addr = ipaddress.ip_address(ip)
        inside = False
        for t in self.last_target.split():
            try:
                inside = inside or addr in ipaddress.ip_network(t, strict=False)
            except ValueError:
                pass  # ranges like 10.0.0.1-50: leave it to nmap
        if not inside:
            return
        h = {"ip": ip, "hostname": socket.gethostname(), "mac": net["mac"], "vendor": "(this computer)",
             "os": ""}
        self.hosts[ip] = h
        self.add_row(h)

    def apply_local_ports(self):
        """This computer's ports straight from the OS: complete, and including localhost-only ones."""
        ip = self.local_ip()
        if ip not in self.hosts:
            return
        self.ports[ip] = local_open_ports(local_listeners())
        self.hosts[ip]["os"] = self.hosts[ip].get("os") or this_os_name()
        self.refresh_row(ip)

    def run_spoof_check(self, macs, net=None):
        self.spoof_warnings = spoof_check(self.devices, net or self.current, macs)

    def accept_router(self):
        """The router really was replaced: remember its new hardware address."""
        net = self.current
        gw = self.gateway()
        mac = self.hosts.get(gw, {}).get("mac") or neighbour_macs(net["iface"]).get(gw, "")
        if mac:
            self.devices.gateways[f"{net['network']}|{gw}"] = {"mac": mac, "since": now_iso()}
            self.devices.save()
            self.spoof_warnings = [w for w in self.spoof_warnings if "now answers from" not in w[1]]
            self.set_dot(T.GREEN)
            self.status.setText(f"Remembered {mac} as this network's router.")

    def risk_summary(self, ips):
        bad = {ip: risky(self.ports.get(ip)) for ip in ips}
        bad = {ip: r for ip, r in bad.items() if r}
        if not bad:
            return ""
        return f" ⚠ {sum(len(r) for r in bad.values())} risky port(s) on {len(bad)} host(s)."

    def os_args(self):
        if not (self.os_box.isChecked() and self.os_box.isEnabled()):
            return []
        # --osscan-limit: skip hosts without an open and a closed port, where guesses are poor.
        return ["-O", "--osscan-limit"]

    def os_summary(self, hosts):
        if not self.os_args():
            return ""
        guessed = sum(1 for h in hosts.values() if h.get("os"))
        return f" OS identified for {guessed} of {len(hosts)}."

    def show_port_details(self):
        ips = self.selected_ips()
        self.details.setRowCount(0)
        if len(ips) != 1:
            self.details_label.setText("Select a host to see its open ports.")
            return
        ip = ips[0]
        h = self.hosts.get(ip, {})
        kind = self.devices.device_type(h, self.ports.get(ip), self.gateway())[0] if h else "unknown"
        who = " · ".join(x for x in (self.devices.nickname(h) if h else "", ip, DEVICE_TYPES[kind],
                                     h.get("os", ""), self.identified(h, self.ports.get(ip))[0]) if x)
        if ip == self.gateway() and self.upnp and self.upnp.get("public_ip"):
            who += f" · public IP {self.upnp['public_ip']}"
        self.details_label.setToolTip("IPv6: " + ", ".join(h["ipv6"]) if h.get("ipv6") else "")
        for m in h.get("upnp") or []:  # ports this device opened to the internet via UPnP
            row = self.details.rowCount()
            self.details.insertRow(row)
            app = likely_app(m["protocol"], m["external_port"])
            cells = [str(m["internal_port"]), m["protocol"], m["description"] or "(no description)",
                     f"internet port {m['external_port']}" + (f" · likely {app}" if app else ""),
                     "⚠ Opened to the internet by this device via UPnP"]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setForeground(QColor(T.AMBER))
                self.details.setItem(row, col, item)
        if ip not in self.ports:
            self.details_label.setText(f"{who}: " + ("found over IPv6 only; no IPv4 address to scan."
                                                     if ":" in ip else "not port-scanned yet."))
            self.details.resizeColumnsToContents()
            return
        ports = self.ports[ip]
        local = ip == self.local_ip()
        if local:
            reachable = len(self.network_ports(ip))
            temporary = sum(1 for p in ports if p.get("temporary"))
            self.details_label.setText(f"{who}: {reachable} reachable from the network, "
                                       f"{len(ports) - reachable - temporary} local-only, {temporary} temporary "
                                       "(from this computer's own list)")
        else:
            self.details_label.setText(f"{who}: {len(ports)} open port(s)")
        for p in ports:
            row = self.details.rowCount()
            self.details.insertRow(row)
            port_item = QTableWidgetItem()
            port_item.setData(Qt.DisplayRole, p["port"])
            self.details.setItem(row, 0, port_item)
            self.details.setItem(row, 1, QTableWidgetItem(p["proto"]))
            self.details.setItem(row, 2, QTableWidgetItem(p["service"]))
            cert_text, cert_warn = cert_note(p["cert"]) if p.get("cert") else ("", "")
            version = " · ".join(x for x in (p["version"], f"“{p['title']}”" if p.get("title") else "", cert_text) if x)
            self.details.setItem(row, 3, QTableWidgetItem(version))
            if port_risk(p) or cert_warn:
                note = QTableWidgetItem("⚠ " + (port_risk(p) or cert_warn))
                note.setForeground(QColor(T.AMBER))
            elif local:
                note = QTableWidgetItem("Temporary socket for the program's own traffic" if p.get("temporary")
                                        else "Only this computer (localhost)" if p.get("local_only")
                                        else "Reachable from your network")
                note.setForeground(QColor(T.TEXT if not (p.get("local_only") or p.get("temporary")) else T.MUTED))
            else:
                note = QTableWidgetItem("")
            self.details.setItem(row, 4, note)
            if port_risk(p):
                port_item.setForeground(QColor(T.AMBER))
        self.details.resizeColumnsToContents()

    # ---- context menu ------------------------------------------------------

    def show_context_menu(self, pos):
        ips = self.selected_ips()
        if not ips:
            return
        menu = QMenu(self)
        menu.addAction(self.copy_act)
        menu.addAction("Copy IP address" + ("es" if len(ips) > 1 else ""),
                       lambda: QGuiApplication.clipboard().setText("\n".join(ips)))
        menu.addSeparator()
        scan = menu.addAction(f"Scan ports on {'this host' if len(ips) == 1 else f'{len(ips)} hosts'}",
                              lambda: self.start_port_scan(ips))
        scan.setEnabled(not self.is_running())
        v4 = [ip for ip in ips if ":" not in ip]
        if v4:
            menu.addAction("Monitor connection" + (f" ({len(v4)} devices)" if len(v4) > 1 else ""),
                           lambda: self.monitor_hosts(v4))
        if len(ips) == 1:
            ip = ips[0]
            h = self.hosts[ip]
            menu.addAction("Rename…" if self.devices.nickname(h) else "Set nickname…",
                           lambda: self.edit_nickname(ip))
            if h["mac"]:
                trusted = self.devices.get(h).get("trusted")
                menu.addAction("Unmark as trusted" if trusted else "Mark as trusted",
                               lambda: self.set_trusted([h["mac"]], not trusted))
                important = self.devices.get(h).get("important")
                menu.addAction("Stop offline alerts" if important else "Alert when offline",
                               lambda: self.set_important([h["mac"]], not important))
            if h["mac"] and not (self.current and ip == self.current["local_ip"]):
                menu.addAction("Wake-on-LAN", lambda: self.wake(h["mac"], self.devices.nickname(h)
                                                                  or h["hostname"] or ip))
            menu.addSeparator()
            if ":" in ip:  # found only over IPv6: no IPv4 address to open/ssh/ping
                menu.exec(self.table.viewport().mapToGlobal(pos))
                return
            open_ports = {p["port"] for p in self.ports.get(ip, []) if p["proto"] == "tcp"}
            if open_ports & {139, 445}:
                menu.addAction("Open file share (SMB)", lambda: self.open_service("smb", ip))
            if 3389 in open_ports:
                menu.addAction("Remote Desktop (RDP)", lambda: self.open_service("rdp", ip))
            vnc = next((port for port in (5900, 5901, 5902) if port in open_ports), None)
            if vnc:
                menu.addAction("VNC remote desktop", lambda: self.open_service("vnc", ip, vnc))
            if 22 in open_ports:
                menu.addAction("Copy ssh command", lambda: self.copy_ssh(h))
            if ip == self.gateway() and any("now answers from" in t for _s, t in self.spoof_warnings):
                menu.addAction("Accept this router (it was replaced)", self.accept_router)
            if ip == self.gateway():
                chk = menu.addAction("Check internet port forwards (UPnP)", self.check_upnp)
                chk.setEnabled(not self.discovering)
                act = menu.addAction("Get device names from router (SSH)", lambda: self.fetch_router_names(h))
                act.setEnabled(not (self.router_proc and self.router_proc.state() != QProcess.NotRunning))
            web = next(((port, scheme) for port, scheme in WEB_PORTS if port in open_ports), None)
            if web:
                port, scheme = web
                default = 443 if scheme == "https" else 80
                url = f"{scheme}://{ip}" + ("" if port == default else f":{port}")
                menu.addAction(f"Open {url}", lambda: QDesktopServices.openUrl(QUrl(url)))
            else:
                menu.addAction(f"Open http://{ip}",
                               lambda: QDesktopServices.openUrl(QUrl(f"http://{ip}")))
            menu.addAction(f"Trace route to {ip}", lambda: self.trace_route(ip, self.monitor_label(ip)))
            menu.addAction("Check known vulnerabilities…" if versioned_cpes(self.ports.get(ip)) else
                           "Check known vulnerabilities… (needs Detect versions)", lambda: self.check_vulns(ip))
            ping = terminal_argv(["ping", ip])
            if ping:
                if 22 in open_ports or ip not in self.ports:
                    user = self.devices.get(h).get("ssh_user")
                    menu.addAction(f"SSH to {user}@{ip}" if user else f"SSH to {ip}…", lambda: self.ssh_to(h))
                    if user:
                        menu.addAction("Change SSH user…", lambda: self.ssh_target(h, change=True))
                menu.addAction(f"Ping {ip} in terminal",
                               lambda: QProcess.startDetached(ping[0], ping[1:]))
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def ssh_target(self, host, change=False):
        """'user@ip' for this device, asking for (and remembering) the username the first time.

        Without a username ssh uses this computer's login name, which rarely matches the
        account on other machines. Returns None if cancelled.
        """
        user = self.devices.get(host).get("ssh_user", "")
        if not user or change:
            who = self.devices.nickname(host) or host.get("hostname") or host["ip"]
            while True:
                name, ok = QInputDialog.getText(
                    self, "SSH username", f"Username to log in to {who} with:",
                    text=user or getpass.getuser())
                if not ok:
                    return None
                name = name.strip()
                if valid_ssh_user(name):
                    break
                QMessageBox.warning(self, "NetScan", "Usernames can only contain letters, digits, "
                                    "'.', '_' and '-', and can't start with '-'.")
            user = name
            self.devices.set_field(host, "ssh_user", user)
            self.show_device_details()
        return f"{user}@{host['ip']}"

    def fetch_router_names(self, router):
        """Read the router's DHCP lease list over SSH (read-only) and name devices that have no name."""
        ssh = find_program("ssh")
        if not ssh:
            self.status.setText("ssh not found; install OpenSSH to read names from the router.")
            return
        target = self.ssh_target(router)  # asks for the router's username the first time
        if not target:
            return
        env = QProcessEnvironment.systemEnvironment()
        env.insert("SSH_ASKPASS", askpass_helper())
        env.insert("SSH_ASKPASS_REQUIRE", "force")  # always use the dialog, even from a terminal
        self.router_proc = proc = QProcess(self)
        proc.setProcessEnvironment(env)
        proc.setStandardInputFile(QProcess.nullDevice())
        proc.finished.connect(lambda code, _s: self.router_names_done(proc, code))
        self.set_dot(T.ACCENT)
        self.status.setText(f"Reading the device list from the router ({target})… "
                            "Enter the router's password if asked.")
        # StrictHostKeyChecking=yes: only a router whose key you've already accepted in a terminal.
        proc.start(ssh, ["-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
                         "-o", "NumberOfPasswordPrompts=2", target, ROUTER_LEASE_CMD])
        QTimer.singleShot(120_000, lambda: proc.state() != QProcess.NotRunning and proc.kill())

    def router_names_done(self, proc, code):
        out = bytes(proc.readAllStandardOutput()).decode(errors="replace")
        err = bytes(proc.readAllStandardError()).decode(errors="replace")
        leases = parse_dnsmasq_leases(out)
        if code != 0 or not leases:
            self.set_dot(T.AMBER)
            if "Host key verification failed" in err or "No ED25519 host key" in err or "host key" in err.lower():
                msg = ("The router's SSH key isn't known on this computer (or it changed). "
                       f"Connect once from a terminal (ssh {self.ssh_target_text()}) to check and accept it, "
                       "then try again.")
            elif "Permission denied" in err:
                msg = "Router login failed: wrong username or password."
            elif code == 0:
                msg = "Logged in to the router, but it has no dnsmasq lease list (/tmp/dhcp.leases)."
            else:
                last = [l for l in err.splitlines() if l.strip() and not l.startswith("**")]
                msg = "Couldn't read the router's device list: " + (last[-1] if last else f"ssh exit code {code}")
            self.status.setText(msg)
            return
        named = 0
        by_ip = {lease_ip: name for lease_ip, name in leases.values()}
        with self.devices.batch():
            for ip, h in self.hosts.items():
                # Match by MAC; fall back to IP only for hosts whose MAC we don't know.
                name = leases[h["mac"]][1] if h["mac"] in leases else ("" if h["mac"] else by_ip.get(ip, ""))
                if name and not h["hostname"]:
                    h["hostname"] = name
                    self.pending.discard(ip)
                    self.devices.update(h, hostname=name)
                    self.refresh_row(ip)
                    named += 1
            for mac, (_ip, name) in leases.items():  # devices remembered but not in this scan
                rec = self.devices.devices.get(mac)
                if name and rec is not None and not rec.get("hostname"):
                    rec["hostname"] = name
                    self.devices.save()
        self.table.resizeColumnToContents(COL_HOST)
        self.refresh_devices()
        self.set_dot(T.GREEN)
        self.status.setText(f"Router: {len(leases)} device(s) in its DHCP list, "
                            f"{sum(1 for _, n in leases.values() if n)} with names; "
                            f"named {named} device(s) that had no name.")

    def ssh_target_text(self):
        gw = self.gateway()
        h = self.hosts.get(gw, {"ip": gw or "router"})
        user = self.devices.get(h).get("ssh_user") if gw in self.hosts else ""
        return f"{user}@{h['ip']}" if user else h["ip"]

    def ssh_to(self, host):
        target = self.ssh_target(host)
        argv = terminal_argv(["ssh", target]) if target else None
        if argv:
            QProcess.startDetached(argv[0], argv[1:])
            self.status.setText(f"Opened ssh {target} in a terminal.")

    def copy_ssh(self, host):
        target = self.ssh_target(host)
        if target:
            QGuiApplication.clipboard().setText(f"ssh {target}")
            self.status.setText(f"Copied: ssh {target}")

    def trace_route(self, target, label=None):
        dlg = TraceDialog(self, target, label or target)
        dlg.setAttribute(Qt.WA_DeleteOnClose)
        dlg.show()
        return dlg

    def open_service(self, kind, ip, port=None):
        """Open a file share, RDP or VNC session with whatever app this system has for it."""
        argv, url = None, None
        if kind == "smb":
            url = f"smb://{ip}/"
            if IS_WIN:
                argv = ["explorer.exe", f"\\\\{ip}"]
            elif not IS_MAC:
                # Many desktops set no default smb:// handler, so ask a file manager directly.
                fm = next((f for f in ("dolphin", "nautilus", "nemo", "thunar", "caja", "pcmanfm")
                           if shutil.which(f)), None)
                argv = [fm, url] if fm else None
        elif kind == "rdp":
            if IS_WIN:
                argv = ["mstsc.exe", f"/v:{ip}"]
            elif not IS_MAC:
                for prog, args in (("xfreerdp3", [f"/v:{ip}", "/dynamic-resolution"]),
                                   ("xfreerdp", [f"/v:{ip}", "/dynamic-resolution"]),
                                   ("remmina", ["-c", f"rdp://{ip}"]), ("krdc", [f"rdp://{ip}"])):
                    if shutil.which(prog):
                        argv = [prog, *args]
                        break
            url = f"rdp://full%20address=s:{ip}" if IS_MAC else f"rdp://{ip}"
        elif kind == "vnc":
            if not IS_MAC and not IS_WIN:
                for prog, args in (("remmina", ["-c", f"vnc://{ip}:{port}"]), ("krdc", [f"vnc://{ip}:{port}"]),
                                   ("vncviewer", [f"{ip}::{port}"])):
                    if shutil.which(prog):
                        argv = [prog, *args]
                        break
            url = f"vnc://{ip}:{port}"
        ok = QProcess.startDetached(argv[0], argv[1:]) if argv else QDesktopServices.openUrl(QUrl(url))
        if isinstance(ok, tuple):
            ok = ok[0]
        if not ok:
            app = {"smb": "a file manager that supports smb://", "rdp": "Remmina or FreeRDP",
                   "vnc": "Remmina, KRDC or a VNC viewer"}[kind]
            self.set_dot(T.AMBER)
            self.status.setText(f"No app found to open {kind.upper()} on {ip}. Install {app}.")

    def set_trusted(self, macs, trusted):
        with self.devices.batch():
            for mac in macs:
                rec = self.devices.devices.get(mac)
                if rec is not None:
                    self.devices.set_field(rec, "trusted", trusted)
        # Trusting the first device changes how every untrusted row looks.
        for ip in self.hosts:
            self.refresh_row(ip)
        self.refresh_devices()
