"""Map tab helpers (the drawing is widgets.NetworkMap)."""

import html

from . import theme as T
from .columns import COL_IP
from .devices import DEVICE_TYPES, port_risk, risky
from .scanning import port_label, summarize_ports


class MapMixin:
    """Map tab helpers (the drawing is widgets.NetworkMap). Mixed into MainWindow."""

    # ---- network map -------------------------------------------------------------

    def map_tooltip(self, ip):
        h = self.hosts.get(ip, {})
        kind, _ = self.devices.device_type(h, self.ports.get(ip), self.gateway()) if h else ("unknown", True)
        ident = self.identified(h, self.ports.get(ip))[0] if h else ""
        ports = self.network_ports(ip)
        lines = [f"<b>{html.escape(self.monitor_label(ip))}</b>", f"{ip} · {DEVICE_TYPES[kind]}"]
        lines += [html.escape(x) for x in (h.get("vendor", ""), ident) if x]
        if ports:
            lines.append("Open: " + html.escape(summarize_ports(ports)))
        for pt in risky(ports):
            lines.append(f'<span style="color:{T.AMBER}">⚠ {html.escape(port_label(pt))}: {html.escape(port_risk(pt))}</span>')
        for mp in h.get("upnp") or []:
            lines.append(f'<span style="color:{T.AMBER}">⚠ opened internet port {mp["external_port"]}/{mp["protocol"]}</span>')
        if h.get("mac") in self.new_devices:
            lines.append("New: first time seen")
        lines.append('<span style="color:gray">Click to show it on the Scan tab</span>')
        return "<br>".join(lines)

    def show_host(self, ip):
        """Jump to a device's row on the Scan tab."""
        row = self.row_for_ip(ip)
        if row is None:
            return
        self.tabbar.setCurrentIndex(0)
        self.filter_edit.clear()
        self.table.selectRow(row)
        self.table.scrollToItem(self.table.item(row, COL_IP))
