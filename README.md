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
- **Traffic**: a live look at the packets this computer's network card sees. Which switch and port you're
  plugged into (LLDP and Cisco CDP: switch name, port, VLAN, voice VLAN, speed), spanning tree, DHCP servers
  (a second one is flagged), DNS lookups, IP address conflicts, broadcast storms, protocols and top talkers.
  It only listens. Save the capture to open it in Wireshark. It needs your password: on Linux a small helper
  (`netscan_app/capture_helper.py`, nothing else) runs as root; macOS uses its built-in tcpdump; Windows uses
  Npcap (installed with nmap).
- **Dashboard**: internet, speed, security grade, devices and outages at a glance, everything that needs
  attention, quick actions and two charts, built only from what NetScan already knows.
- **Checkups**: *Slow internet?* finds whether a problem is your Wi-Fi, cable, router, internet provider,
  DNS or bufferbloat; *Security checkup* grades your network out of 100 with a fix for each problem;
  *Router check* spots double NAT, a shared provider address (CGNAT) and rogue DHCP servers; *Gaming & calls*
  grades your connection for video calls, online games, cloud gaming and 4K from latency to cloud regions.
- **Privacy & exposure**: *VPN & privacy* checks for IPv6 and DNS leaks; *What the internet sees* shows the
  ports open on your public address (Shodan's free InternetDB), known vulnerabilities and spam blocklists.
- **Client work** (for IT / MSP visits): *Client sites* keep each client's devices and scans separate and switch
  automatically by the network's router, with "since your last visit" after each scan; *Site audit* writes a
  branded HTML report of the network plus an inventory CSV for IT Glue, Hudu and similar; *Firewall test* shows
  which outgoing ports a network allows; *VoIP readiness* estimates call quality (MOS); *Domain check (bulk)*,
  *Mail server check* (SMTP, STARTTLS, reverse DNS, 14 blocklists) and *DNS propagation* (20 resolvers).
  **Copy for ticket** (Ctrl+Shift+C) copies any tool's results as plain text.
- **Outages**: an optional connection watch that logs every outage (internet vs. your own network) and saves
  a report to send your internet provider.
- **Tools**: every web page and service on your network (Services & web pages), DNS lookup and speed comparison, HTTP inspector, domain toolkit, website watch, Wi-Fi channels,
  a room-by-room Wi-Fi survey, continuous traceroute, LAN speed test, IP info, port check, subnet
  calculator, MAC lookup, live connections and traffic, 30 days of history (speed tests against your
  plan, with optional scheduled tests) and a who's-home timeline.

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
netscan.py --portable             keep everything in NetScan-data next to netscan.py
add --json to --scan/--internet for machine-readable output
```

## What goes online

Scans, the device list, the Monitor and the LAN speed test stay on your network. The internet is
contacted only by the features that need it: the Internet tab (Cloudflare, Google DNS, LibreSpeed),
IP info, Connections and the domain toolkit (RDAP registries), DNS speed (Cloudflare, Google, Quad9),
Slow internet? and Router check (pings to 1.1.1.1 and 8.8.8.8, Cloudflare for your public IP),
scheduled speed tests and the Outages connection watch if you turn them on (pings to 1.1.1.1/8.8.8.8),
Gaming & calls (connections to Amazon's cloud regions), VPN & privacy (Cloudflare, RDAP, and bash.ws for
the DNS leak test), What the internet sees (your public IP to Shodan's InternetDB and four blocklists), Firewall test and
VoIP readiness (portquiz.net, STUN at Cloudflare and Google), the domain and mail checks (RDAP, DNS, the sites
and mail servers themselves, Microsoft's public sign-in lookup, blocklists), DNS propagation (20 public
resolvers),
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
measurements), `outages.json`, `wifi_survey.json`, `sites.json` and small caches. Each client site's own
device list and saved scans are in `sites/<name>/`; the main folder's are the Home site's. Delete the folder to start fresh.

**Portable mode**: `python3 netscan.py --portable` (or Ctrl+K → Portable mode) copies all of that, plus
your settings, into a `NetScan-data` folder next to `netscan.py`. From then on NetScan uses that folder,
so copying the NetScan folder to a USB stick or another computer brings your devices and history along.
Move or delete `NetScan-data` to go back. To keep the data somewhere else (a synced folder, say), set
the `NETSCAN_DATA` environment variable to that folder.

## Tests

```
python3 -m unittest discover -s tests -v
```

The tests need PySide6 but not nmap or a network. They use a temporary data folder and run without
a display (`QT_QPA_PLATFORM=offscreen` is set automatically).

## Layout

`netscan.py` starts the app. The `netscan_app/` package has the engine modules (`scanning`, `discovery`,
`internet`, `probes`, `tools`, `checks`, `online`, `outages`, `work`, `sites`, `audit`, `vulns`,
`history_db`, …) and one module per tab (`scan_tab`, `devices_tab`, `monitor_tab`, `internet_tab`, `map_tab`,
`tools_tab`, `toolkit_tab`, `insights_tab`, `online_tab`, `work_tab`), combined in `window.py`. `netscan_app/icons/` holds the app icon: `netscan.svg` is the source, and the
PNG (Linux and the window), ICO (Windows) and ICNS (macOS) are rendered from it.
