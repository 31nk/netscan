# NetScan

A network toolbox built around [nmap](https://nmap.org), with a Qt (PySide6) interface. It works on
any network and on Linux, macOS and Windows. Nothing needs a login on other devices.

- **Scan**: find every device on your network (names, vendors, OS guesses, open ports), compare with
  earlier scans, Wake-on-LAN, a traceroute, and an opt-in known-vulnerability check.
- **Devices**: every device ever seen, with nicknames, trusted flags, port-change history, a background
  watch and uptime alerts.
- **Monitor**: latency, jitter and loss over time.
- **Internet**: public IP and VPN check, DNS, latency, and a speed test (Cloudflare or LibreSpeed) with a
  bufferbloat grade.
- **Map**: every device around your router, grouped by type.
- **Tools**: DNS lookup, port check, IP info, HTTP inspector, subnet calculator, MAC lookup, Wi-Fi
  channels, live connections, live traffic, continuous traceroute, LAN speed test, domain toolkit,
  website watch, DNS speed comparison, and 30 days of history.

Press **F1** in the app for the full guide, or **Ctrl+K** to jump to anything.

## Install

Each installer is run from this folder and creates a menu entry or shortcut.

| System  | Command | Notes |
|---------|---------|-------|
| Linux   | `bash install-linux.sh` | Install `nmap` first with your package manager. The app runs from this folder, so `git pull` updates it. `--uninstall` removes the menu entry. |
| macOS   | `bash install-mac.sh` | Install `nmap` and Python first: `brew install nmap python`. The app is copied to `~/Applications/NetScan.app`, so run the installer again after updating. |
| Windows | `powershell -ExecutionPolicy Bypass -File .\install-windows.ps1` | Installs Python, nmap and Npcap if missing (it asks for administrator rights). Run it again after updating. |

To run it without installing: `python3 netscan.py` (needs `pip install PySide6` and nmap).

**Privileged scans** (ARP discovery, SYN/UDP scans, OS detection) need raw sockets. NetScan asks for your
password when it needs them. On Arch Linux, `pkexec ./setup-no-password.sh` gives nmap the capabilities
once so it stops asking (read the script's header for the trade-off; `--undo` reverses it).

## Check that it works

```
python3 netscan.py --self-test
```

This checks nmap and its data files, network detection, and runs a quick test scan of this computer.
It prints OK or FAIL for each step.

## Command line

```
netscan.py --scan [TARGET]        find hosts (default: this computer's network)
    --ports                       also scan each host's top 100 TCP ports
    --privileged                  use raw packets (needs root, or nmap capabilities)
    --no-names                    skip name lookups
netscan.py --internet             public IP, DNS, latency to router and internet
netscan.py --self-test
add --json to --scan/--internet for machine-readable output
```

## What goes online

Scans, the device list, the Monitor and the LAN speed test stay on your network. The internet is
contacted only by the features that need it: the Internet tab (Cloudflare, Google DNS, LibreSpeed),
IP info, Connections and the domain toolkit (RDAP registries), DNS speed (Cloudflare, Google, Quad9),
and the HTTP inspector and website watch (the sites you enter). The vulnerability check asks first,
and sends only software names and versions to the US National Vulnerability Database, never an IP
address.

## Your data

| System  | Folder |
|---------|--------|
| Linux   | `~/.local/share/NetScan/` |
| macOS   | `~/Library/Application Support/NetScan/` |
| Windows | `%APPDATA%\NetScan\` |

It holds `devices.json` (the device list), `history/` (saved scans), `history.db` (30 days of
measurements) and small caches. Delete the folder to start fresh.

## Tests

```
python3 -m unittest discover -s tests -v
```

The tests need PySide6 but not nmap or a network. They use a temporary data folder and run without
a display (`QT_QPA_PLATFORM=offscreen` is set automatically).

## Layout

`netscan.py` starts the app. The `netscan_app/` package has the engine modules (`scanning`, `discovery`,
`internet`, `probes`, `tools`, `vulns`, `history_db`, …) and one module per tab (`scan_tab`, `devices_tab`,
`monitor_tab`, `internet_tab`, `map_tab`, `tools_tab`, `toolkit_tab`), combined in `window.py`.
