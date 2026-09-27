"""Table column layouts and small UI constants shared by the window's tabs."""


COLUMNS = ["IP Address", "Name", "Hostname", "MAC Address", "Vendor", "Identified as", "OS", "Open Ports",
           "Change"]
COL_IP, COL_NAME, COL_HOST, COL_MAC, COL_VENDOR, COL_INFO, COL_OS, COL_PORTS, COL_CHANGE = range(9)
# Discovery details kept per device (and remembered in the device list between scans).
DISCOVERY_FIELDS = ("model", "maker", "friendly", "services", "svc_types", "upnp_type", "ipv6")
PORT_COLUMNS = ["Port", "Proto", "Service", "Version", "Note"]
# Devices tab: everything NetScan remembers. The first column is the online dot.
DEV_COLUMNS = ["", "Name", "Type", "Last seen", "Trusted", "Last IP", "Hostname", "MAC Address", "Vendor"]
DEV_STATUS, DEV_NAME, DEV_TYPE, DEV_SEEN, DEV_TRUST, DEV_IP, DEV_HOST, DEV_MAC, DEV_VENDOR = range(9)
# Background watch: (label, minutes between checks; 0 = off).
WATCH_INTERVALS = [("Off", 0), ("Every minute", 1), ("Every 5 minutes", 5),
                   ("Every 15 minutes", 15), ("Every 30 minutes", 30), ("Every hour", 60)]
# The main tabs, in the order they appear.
TAB_NAMES = ["Dashboard", "Scan", "Devices", "Monitor", "Internet", "Map", "Tools", "Traffic"]
TAB_DASHBOARD, TAB_SCAN, TAB_DEVICES, TAB_MONITOR, TAB_INTERNET, TAB_MAP, TAB_TOOLS, TAB_TRAFFIC = range(len(TAB_NAMES))
