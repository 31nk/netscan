"""Command-line mode and the self-test (no window, no Qt GUI)."""

import ipaddress
import json
import os
import re
import socket
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from .internet import internet_check
from .names import lookup_name
from .scanning import ip_sort_key, mac_vendor, parse_host, parse_ports, summarize_ports
from .system import (
    IS_WIN, LAN_FAST, detect_networks, find_program, iface_args, local_listeners, local_open_ports,
    neighbour_macs, nmap_data_file, nmap_has_caps, npcap_installed, root_prefix, run_text,
)


def self_test():
    """Check the setup without a window: nmap, its data files, network detection, a test scan."""
    ok = True

    def check(label, good, detail=""):
        nonlocal ok
        ok = ok and good
        print(f"[{'OK' if good else 'FAIL'}] {label}" + (f": {detail}" if detail else ""))

    nmap = find_program("nmap")
    check("nmap found", bool(nmap), nmap or "not on PATH or in the usual install folders")
    if nmap:
        version = run_text(nmap, "--version").strip().splitlines()
        check("nmap runs", bool(version), version[0] if version else "no output")
    for name in ("nmap-services", "nmap-mac-prefixes"):
        path = nmap_data_file(name)
        check(f"{name} found", os.path.exists(path), path)
    if IS_WIN:
        check("Npcap installed", npcap_installed(),
              "" if npcap_installed() else "raw scans unavailable; install from https://npcap.com")
    else:
        print(f"[INFO] root helper: {' '.join(root_prefix() or ['none'])}")
        print("[INFO] nmap capabilities: " + ("set, privileged scans need no password" if nmap_has_caps(nmap)
                                             else "not set (run setup-no-password.sh to skip password prompts)"))
    nets = detect_networks()
    check("network detected", bool(nets),
          ", ".join(f"{n['network']} on {n['iface']} (you are {n['local_ip']})" for n in nets)
          or "none; you can still type a target in the app")
    if nmap:
        args = [nmap, "-n", "-sn", "-oX", "-", "127.0.0.1"]
        if IS_WIN and not npcap_installed():
            args.insert(1, "--unprivileged")
        out = run_text(*args)
        up = 'state="up"' in out
        check("test scan of 127.0.0.1", up, "host is up" if up else (out.strip()[-200:] or "no output"))
    print("All checks passed." if ok else "Some checks failed.")
    return 0 if ok else 1


# ---- command-line mode ---------------------------------------------------------
# No window and no Qt: for SSH sessions, a Raspberry Pi, cron jobs or scripts.

CLI_HELP = """NetScan command-line mode

  netscan.py                        open the app
  netscan.py --scan [TARGET]        find hosts (default: this computer's network)
      --ports                       also scan each host's top 100 TCP ports
      --privileged                  use raw packets (needs root, or nmap capabilities)
      --no-names                    skip name lookups (faster)
  netscan.py --internet             public IP, DNS, latency to router and internet
  netscan.py --self-test            check nmap and network detection
  add --json to --scan/--internet for machine-readable output

examples:
  netscan.py --scan --ports
  netscan.py --scan 10.0.0.0/24 --json > hosts.json
"""


def cli_scan(target, ports, privileged, names):
    """Run one scan without the GUI; returns a list of host dicts (like the app's, plus 'ports')."""
    nmap = find_program("nmap")
    if not nmap:
        raise SystemExit("nmap not found.")
    nets = detect_networks()
    net = None
    if target:
        try:
            wanted = ipaddress.ip_network(target, strict=False)
            net = next((n for n in nets if wanted.subnet_of(n["network"])), None)
        except ValueError:
            pass
    else:
        net = nets[0] if nets else None
        if not net:
            raise SystemExit("No network detected; give a target, e.g. --scan 192.168.1.0/24")
        target = str(net["network"])
    args = ["-n", "-T4", "-oX", "-"]
    args += ["--top-ports", "100"] + (LAN_FAST if net else []) if ports else ["-sn"]
    if privileged and not IS_WIN:
        args.insert(0, "--privileged")
    elif IS_WIN and not npcap_installed():
        args.insert(0, "--unprivileged")
    if net:
        args += ["--exclude", net["local_ip"], *iface_args(net)]
    out = run_text(nmap, *args, *target.split(","))
    if "<nmaprun" not in out:
        raise SystemExit("nmap failed: " + (out.strip()[-300:] or "no output"))
    root = ET.fromstring(out[out.index("<nmaprun"):])
    hosts = []
    for elem in root.findall("host"):
        h = parse_host(elem)
        if h:
            h["ports"] = parse_ports(elem) if ports else None
            hosts.append(h)
    if net:
        macs = neighbour_macs(net["iface"])
        for h in hosts:
            h["mac"] = h["mac"] or macs.get(h["ip"], "")
        me = net["local_ip"]
        if ipaddress.ip_address(me) in ipaddress.ip_network(target.split(",")[0], strict=False):
            mine = local_open_ports(local_listeners())
            hosts.append({"ip": me, "hostname": socket.gethostname(), "mac": net["mac"], "vendor": "(this computer)",
                          "ports": [p for p in mine if not p["local_only"] and not p["temporary"]]})
    for h in hosts:
        h["vendor"] = h["vendor"] or mac_vendor(h["mac"])
    if names:
        with ThreadPoolExecutor(max_workers=32) as ex:
            for h, name in zip(hosts, ex.map(lambda h: h["hostname"] or lookup_name(h["ip"]), hosts)):
                h["hostname"] = name
    return sorted(hosts, key=lambda h: ip_sort_key(h["ip"]))


def cli_table(rows, headers):
    widths = [max(len(str(r[i])) for r in rows + [headers]) for i in range(len(headers))]
    line = lambda r: "  ".join(str(c).ljust(w) for c, w in zip(r, widths)).rstrip()
    return "\n".join([line(headers), line(["-" * w for w in widths])] + [line(r) for r in rows])


def cli_main(argv):
    as_json = "--json" in argv
    if "--help" in argv or "-h" in argv:
        print(CLI_HELP)
        return 0
    if "--scan" in argv:
        i = argv.index("--scan")
        target = argv[i + 1] if i + 1 < len(argv) and not argv[i + 1].startswith("-") else None
        if target and not re.fullmatch(r"[0-9A-Za-z.\-/:,]+", target):
            print("Invalid target.", file=sys.stderr)
            return 2
        hosts = cli_scan(target, "--ports" in argv, "--privileged" in argv, "--no-names" not in argv)
        if as_json:
            print(json.dumps(hosts, indent=2))
        else:
            rows = [[h["ip"], h["hostname"] or "-", h["mac"] or "-", h["vendor"] or "-"]
                    + ([summarize_ports(h["ports"]) or "none open"] if "--ports" in argv else []) for h in hosts]
            print(cli_table(rows, ["IP", "HOSTNAME", "MAC", "VENDOR"] + (["OPEN PORTS"] if "--ports" in argv else [])))
            print(f"\n{len(hosts)} host(s).")
        return 0
    if "--internet" in argv:
        nets = detect_networks()
        res = internet_check(nets[0]["gateway"] if nets else None)
        if as_json:
            print(json.dumps(res, indent=2))
            return 0
        trace = res.get("trace") or {}
        fmt = lambda v: "no reply" if not v or v[0] is None else f"{v[0]:.1f} ms, {v[1]:.0f}% loss"
        for label, value in (("Public IP", f"{trace.get('ip', '?')} ({trace.get('loc', '?')}, Cloudflare {trace.get('colo', '?')})"),
                             ("DNS servers", ", ".join(res.get("dns") or []) or "?"),
                             ("DNS lookup", f"{res['dns_ms']:.0f} ms" if res.get("dns_ms") else "?"),
                             ("Router", fmt(res.get("router"))), ("Cloudflare 1.1.1.1", fmt(res.get("cf"))),
                             ("Google 8.8.8.8", fmt(res.get("google")))):
            print(f"{label:20} {value}")
        return 0
    return None  # not a CLI request
