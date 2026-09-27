"""Client sites: a separate device list and scan history for each network you work on, recognised by the
router's hardware (MAC) address so NetScan switches to the right one when you arrive. The main data folder is
the "Home" site; every other site lives in sites/<id>/ inside it."""

import datetime
import json
import os
import re
import shutil
import uuid

from .devices import data_dir

HOME = "home"


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


class Sites:
    def __init__(self, path=None):
        self.path = path or os.path.join(data_dir(), "sites.json")
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = {}
        self.sites = d.get("sites", {})
        self.current = d.get("current", HOME)
        self.auto = d.get("auto", True)
        if HOME not in self.sites:
            self.sites[HOME] = {"name": "Home", "routers": self._home_routers(), "created": _now()}
        if self.current not in self.sites:
            self.current = HOME

    def _home_routers(self):
        """Routers the main device list already knows (from the ARP-spoofing check), so an existing install
        recognises its own network as Home."""
        try:
            with open(os.path.join(data_dir(), "devices.json"), encoding="utf-8") as f:
                gateways = json.load(f).get("gateways", {})
        except (OSError, ValueError, AttributeError):
            return []
        return sorted({g["mac"] for g in gateways.values() if g.get("mac")})

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"sites": self.sites, "current": self.current, "auto": self.auto}, f, indent=1)
        os.replace(tmp, self.path)

    def folder(self, sid):
        """The site's own folder, or None for Home (the main data folder)."""
        return None if sid == HOME else os.path.join(data_dir(), "sites", sid)

    def name(self, sid=None):
        return self.sites.get(sid or self.current, {}).get("name", "?")

    def find_by_router(self, mac):
        mac = (mac or "").upper()
        return next((sid for sid, s in self.sites.items() if mac and mac in s.get("routers", [])), None)

    def add(self, name, router=None, network=""):
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:30] or "site"
        sid = f"{slug}-{uuid.uuid4().hex[:6]}"
        self.sites[sid] = {"name": name, "routers": [], "networks": [network] if network else [], "created": _now()}
        if router:
            self.assign_router(sid, router)
        self.save()
        return sid

    def assign_router(self, sid, mac):
        """This router belongs to this site (and no other)."""
        mac = mac.upper()
        for s in self.sites.values():
            if mac in s.get("routers", []):
                s["routers"].remove(mac)
        self.sites[sid].setdefault("routers", []).append(mac)
        self.save()

    def rename(self, sid, name):
        self.sites[sid]["name"] = name
        self.save()

    def update(self, sid, **fields):
        self.sites[sid].update(fields)
        self.save()

    def remove(self, sid):
        """Delete a site and its device list and scans (never Home)."""
        if sid == HOME:
            return
        folder = self.folder(sid)
        self.sites.pop(sid, None)
        if self.current == sid:
            self.current = HOME
        self.save()
        if folder and os.path.isdir(folder):
            shutil.rmtree(folder, ignore_errors=True)

    def switch(self, sid):
        """Make sid current; returns its previous visit time (or "")."""
        s = self.sites[sid]
        previous = s.get("last_visit", "")
        s["last_visit"] = _now()
        self.current = sid
        self.save()
        return previous

    def record_scan(self, sid, network, macs):
        """Remember what a finished scan saw; returns the previous scan's {"when", "macs"} (or None)."""
        s = self.sites[sid]
        before = s.get("last_scan")
        s["last_scan"] = {"when": _now(), "macs": sorted(macs)}
        if network and network not in s.setdefault("networks", []):
            s["networks"].append(network)
        self.save()
        return before


def visit_changes(before, now_macs):
    """(new macs, gone macs) between the previous scan's MACs and this one's."""
    old = set((before or {}).get("macs", []))
    now = set(now_macs)
    return sorted(now - old), sorted(old - now)
