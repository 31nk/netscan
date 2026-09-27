"""Reading device names from a dnsmasq router over SSH (read-only)."""

import os
import re
import shlex
import sys

from .devices import data_dir
from .system import IS_WIN


# ---- device names from the router ---------------------------------------------
# Routers running dnsmasq (OpenWrt, OpenSync and many others) keep every DHCP client's
# name in a lease file. NetScan reads it over SSH with one read-only command.
ROUTER_LEASE_CMD = ("cat /tmp/dhcp.leases 2>/dev/null || cat /var/lib/misc/dnsmasq.leases 2>/dev/null"
                    " || cat /tmp/dnsmasq.leases 2>/dev/null")


def parse_dnsmasq_leases(text):
    """dnsmasq leases, '<expiry> <mac> <ip> <hostname|*> <client-id|*>' per line -> {MAC: (ip, name)}."""
    leases = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 4 and re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", f[1]):
            leases[f[1].upper()] = (f[2], "" if f[3] == "*" else f[3][:63])
    return leases


def askpass_helper():
    """Small launcher that ssh runs (SSH_ASKPASS) to ask for a password with NetScan's own dialog.

    The password goes straight from that separate process to ssh; the NetScan window never sees it.
    """
    script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "netscan.py")
    exe = sys.executable
    if IS_WIN:
        path, body = os.path.join(data_dir(), "askpass.cmd"), f'@"{exe}" "{script}" --askpass %*\r\n'
    else:
        path = os.path.join(data_dir(), "askpass")
        body = f'#!/bin/sh\nexec {shlex.quote(exe)} {shlex.quote(script)} --askpass "$@"\n'
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, 0o700)
    return path
