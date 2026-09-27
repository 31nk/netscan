#!/usr/bin/env python3
"""NetScan: a small Qt front end for nmap host discovery and port scanning, grown into a network toolkit.

Auto-detects the LAN subnet from the default route, runs nmap, and lists every
live host with its IP, hostname, MAC address, NIC vendor and open ports.
Results stream in while nmap runs. Scans can be saved as JSON and compared
against a later scan to spot new hosts, missing hosts and port changes.

Root (via pkexec on Linux, sudo with a password dialog on macOS, Npcap on
Windows) gives better discovery, SYN scans and UDP; unprivileged scans fall
back to the kernel neighbour/ARP table for MACs.

Runs on Linux, macOS (nmap from Homebrew) and Windows (nmap + Npcap).
Run with --self-test to check the setup without opening the window, or --help
for command-line mode. The code lives in the netscan_app/ folder next to this file.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netscan_app.app import main  # noqa: E402 - needs the path set up first

if __name__ == "__main__":
    main()
