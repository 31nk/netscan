"""Watch mode: quiet background checks for new devices and port changes."""

import datetime
import socket
import xml.etree.ElementTree as ET

from PySide6.QtCore import (
    QProcess, QTimer,
)

from . import theme as T
from .columns import WATCH_INTERVALS
from .devices import port_risk
from .scanning import mac_vendor, parse_host, parse_ports, port_label, port_set, top_tcp_ports
from .system import IS_WIN, LAN_FAST, iface_args, neighbour_macs
from .widgets import notify


class WatchMixin:
    """Watch mode: quiet background checks for new devices and port changes. Mixed into MainWindow."""

    # ---- watch mode --------------------------------------------------------

    def set_watch(self, _index=None, first_delay=0):
        minutes = WATCH_INTERVALS[self.watch_combo.currentIndex()][1]
        if not minutes:
            self.watch_timer.stop()
            self.watch_label.setText("Off. Pick an interval to start watching.")
            return
        self.watch_timer.start(minutes * 60_000)
        if first_delay:
            QTimer.singleShot(first_delay, self.watch_scan)  # at startup, let the window settle
        else:
            self.watch_scan()

    def watch_target(self):
        idx = self.target.currentIndex()
        net = self.target.itemData(idx) if idx >= 0 else None
        return net or (self.networks[0] if self.networks else None)

    def watch_scan(self):
        """One quiet, unprivileged check; runs alongside (not instead of) the Scan tab."""
        if not self.nmap or (self.watch_proc is not None
                             and self.watch_proc.state() != QProcess.NotRunning):
            return
        net = self.watch_target()
        if net is None:
            self.watch_label.setText("No local network detected.")
            return
        self.watch_ports = self.watch_ports_box.isChecked()
        scan = ["--top-ports", "100", *LAN_FAST] if self.watch_ports else ["-sn"]
        args = ["-n", "-T4", *scan, "-oX", "-", *iface_args(net), "--exclude", net["local_ip"],
                str(net["network"])]
        if IS_WIN:
            args.insert(0, "--unprivileged")
        elif self.nmap_caps:
            args.insert(0, "--privileged")  # ARP discovery: finds devices that ignore pings
        self.watch_net = net
        self.watch_proc = QProcess(self)
        self.watch_proc.finished.connect(self.watch_done)
        self.watch_label.setText(f"Checking {net['network']}" + (" and its ports" if self.watch_ports else "")
                                 + "…")
        self.watch_proc.start(self.nmap, args)

    def watch_done(self, *_):
        out = bytes(self.watch_proc.readAllStandardOutput()).decode(errors="replace")
        stamp = datetime.datetime.now().strftime("%H:%M")
        try:
            root = ET.fromstring(out[out.index("<nmaprun"):])
        except (ValueError, ET.ParseError):
            self.watch_label.setText(f"Check at {stamp} failed.")
            return
        net = self.watch_net
        macs = neighbour_macs(net["iface"])
        found = []  # (host, ports or None)
        for elem in root.findall("host"):
            h = parse_host(elem)
            if h is None:
                continue
            if h["ip"] == net["local_ip"]:
                h["mac"] = h["mac"] or net["mac"]
                h["vendor"] = h["vendor"] or "(this computer)"
            h["mac"] = h["mac"] or macs.get(h["ip"], "")
            h["vendor"] = h["vendor"] or mac_vendor(h["mac"])
            found.append((h, parse_ports(elem) if self.watch_ports else None))
        if net["mac"] and not any(h["ip"] == net["local_ip"] for h, _ in found):
            found.append(({"ip": net["local_ip"], "hostname": socket.gethostname(), "mac": net["mac"],
                           "vendor": "(this computer)", "os": ""}, None))  # excluded from nmap, but online
        hosts = [h for h, _ in found]
        first_run = not self.devices.known_macs()
        new = self.devices.record(hosts)
        if first_run:
            new = []  # the very first check just learns what's normal
        self.online_macs = {h["mac"] for h in hosts if h["mac"]}
        was = {t for _s, t in self.spoof_warnings}
        self.run_spoof_check({h["ip"]: h["mac"] for h in hosts}, net)
        fresh = [t for sv, t in self.spoof_warnings if sv == "high" and t not in was]
        if fresh:
            notify("Possible ARP spoofing on your network", fresh[0])
            self.set_dot(T.RED)
            self.status.setText("⚠ " + fresh[0])

        changes = []  # (host, opened, closed)
        top = {"tcp": port_set(top_tcp_ports(100)), "udp": set()}
        with self.devices.batch():
            for h, ports in found:
                if not (self.watch_ports and h["mac"]) or ports is None:  # None: this computer
                    continue
                opened, closed = self.devices.update_ports(h["mac"], ports, top)
                if (opened or closed) and h["mac"] not in new:  # new devices just get a baseline
                    changes.append((h, opened, closed))

        self.watch_label.setText(f"Last check {stamp}: {len(hosts)} online"
                                 + (f", {len(new)} new" if new else "")
                                 + (f", port changes on {len(changes)}" if changes else "") + ".")
        what = lambda h: ("Device with a private MAC" if h["vendor"].startswith("(")
                          else h["vendor"] or "Unknown device")
        name = lambda h: self.devices.nickname(h) or h["hostname"] or self.devices.get(h).get("hostname") \
            or f"{what(h)} ({h['ip']})"
        if new:
            joined = [h for h in hosts if h["mac"] in new]
            notify(f"{len(new)} new device(s) on your network",
                   "\n".join(f"{what(h)}  {h['ip']}  {h['mac']}" for h in joined))
            self.set_dot(T.AMBER)
            self.status.setText(f"Watch: {len(new)} new device(s) joined: "
                                + ", ".join(f"{h['ip']} ({what(h)})" for h in joined))
        if changes:
            lines = []
            for h, opened, closed in changes:
                bits = [("⚠ " if port_risk(p) else "") + f"opened {port_label(p)}" for p in opened]
                bits += [f"closed {port_label(p)}" for p in closed]
                lines.append(f"{name(h)}: " + ", ".join(bits))
            notify("Port changes on your network", "\n".join(lines))
            self.set_dot(T.AMBER)
            self.status.setText("Watch: " + "; ".join(lines))
        for ip in self.hosts:
            self.refresh_row(ip)
        self.refresh_devices()
