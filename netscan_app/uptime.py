"""Uptime alerts for devices marked important."""

import time

from PySide6.QtCore import (
    QTimer,
)

from . import theme as T
from .internet import ping_summary
from .system import now_iso
from .widgets import notify


class UptimeMixin:
    """Uptime alerts for devices marked important. Mixed into MainWindow."""

    # ---- uptime alerts ---------------------------------------------------------------

    UPTIME_EVERY_MS, UPTIME_MISSES = 30_000, 2

    def set_important(self, macs, on):
        with self.devices.batch():
            for mac in macs:
                rec = self.devices.devices.get(mac)
                if rec is not None:
                    self.devices.set_field(rec, "important", on)
                    self.uptime_state.pop(mac, None)
        self.refresh_devices()
        self.uptime_restart()
        self.status.setText(("Watching " if on else "Stopped watching ")
                            + ", ".join(self.device_label(m) or m for m in macs) + " for outages.")

    def uptime_targets(self):
        """{mac: ip} of devices marked important, at their latest known IPv4 address."""
        current = {h["mac"]: ip for ip, h in self.hosts.items() if h["mac"] and ":" not in ip}
        return {mac: current.get(mac) or d.get("ip") for mac, d in self.devices.devices.items()
                if d.get("important") and (current.get(mac) or ":" not in (d.get("ip") or ":"))}

    def uptime_restart(self):
        if self.uptime_targets():
            if not self.uptime_timer.isActive():
                self.uptime_timer.start(self.UPTIME_EVERY_MS)
                QTimer.singleShot(2000, self.uptime_tick)
        else:
            self.uptime_timer.stop()

    def uptime_tick(self):
        targets = self.uptime_targets()
        if not targets:
            self.uptime_timer.stop()
            return
        self.worker.run("uptime", lambda: {mac: ping_summary(ip, count=2)[0] is not None
                                           for mac, ip in targets.items()})

    def uptime_result(self, alive):
        for mac, up in alive.items():
            st = self.uptime_state.setdefault(mac, {"up": True, "misses": 0, "down_since": None})
            rec = self.devices.devices.get(mac)
            if rec is None:
                continue
            name = self.device_label(mac) or rec.get("ip") or mac
            if up:
                st["misses"] = 0
                self.online_macs.add(mac)
                if not st["up"]:
                    st["up"] = True
                    gone = int(time.time() - (st["down_since"] or time.time()))
                    took = f"{gone // 3600} h {gone % 3600 // 60} min" if gone >= 3600 else f"{max(1, gone // 60)} min"
                    self.uptime_log(rec, "up", took)
                    notify(f"{name} is back online", f"It was offline for about {took}.")
                    self.status.setText(f"{name} is back online after about {took}.")
            else:
                st["misses"] += 1
                if st["up"] and st["misses"] >= self.UPTIME_MISSES:
                    st["up"], st["down_since"] = False, time.time()
                    self.online_macs.discard(mac)
                    self.uptime_log(rec, "down")
                    notify(f"{name} went offline", f"{rec.get('ip', '')} stopped answering pings.")
                    self.set_dot(T.AMBER)
                    self.status.setText(f"⚠ {name} ({rec.get('ip', '')}) went offline.")
        if self.tabbar.currentIndex() == 1:
            self.refresh_devices()

    def uptime_log(self, rec, state, downtime=None):
        log = rec.setdefault("uptime_log", [])
        log.append({"time": now_iso(), "state": state, **({"downtime": downtime} if downtime else {})})
        rec["uptime_log"] = log[-50:]
        self.devices.save()
