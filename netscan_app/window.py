"""The main window: layout, settings, network detection, nicknames and Wake-on-LAN; the tabs come from the mixins."""

import ipaddress
import re

from PySide6.QtCore import (
    QSettings, QTimer, Qt,
)
from PySide6.QtGui import (
    QAction, QActionGroup, QGuiApplication, QIcon, QKeySequence,
)
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFrame, QHBoxLayout, QHeaderView, QInputDialog,
    QLabel, QLineEdit, QMainWindow, QMenu, QProgressBar, QPushButton, QSizePolicy, QSplitter,
    QStackedWidget, QTabBar, QTableWidget, QVBoxLayout, QWidget,
)

from . import theme as T
from .columns import (
    COLUMNS, COL_CHANGE, COL_HOST, COL_INFO, COL_IP, COL_OS, PORT_COLUMNS, WATCH_INTERVALS,
)
from .devices import DeviceStore, devices_file
from .devices_tab import DevicesMixin
from .export import ExportMixin
from .internet_tab import InternetMixin
from .map_tab import MapMixin
from .monitor_tab import MonitorMixin
from .scan_tab import ScanMixin
from .scanning import PORT_PROFILES, UDP_PORTS
from .system import (
    IS_MAC, IS_WIN, detect_networks, find_program, nmap_has_caps, npcap_installed, root_prefix,
    run_text, wake_on_lan, write_askpass,
)
from .theme import THEME_MODES, icon_path, make_card, mono_font
from .tools_tab import ToolsMixin
from .uptime import UptimeMixin
from .watch import WatchMixin
from .widgets import Discovery, NetworkMap, Resolver, SsdpListener, StatusLabel


class MainWindow(ScanMixin, DevicesMixin, MonitorMixin, UptimeMixin, ToolsMixin, MapMixin,
                 InternetMixin, WatchMixin, ExportMixin, QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetScan")
        self.resize(1060, 660)

        self.nmap = find_program("nmap")
        self.root = root_prefix() if not IS_WIN else None
        self.nmap_caps = nmap_has_caps(self.nmap)
        self.prompted = False
        # On Windows nmap needs no password prompt: Npcap gives it raw packet access.
        self.has_root = bool(self.root) or npcap_installed() or self.nmap_caps
        self.askpass = write_askpass() if IS_MAC and self.root else None
        self.settings = QSettings("netscan", "netscan")
        self.proc = None
        self.output = ""
        self.last_xml = ""
        self.parser = None
        self.on_host = None
        self.on_done = None
        self.used_root = False
        self.current = None
        self.last_target = ""
        self.elapsed = 0
        self.pending = set()
        self.summary = ""
        self.hosts = {}   # ip -> host dict
        self.ports = {}   # ip -> list of open-port dicts (absent = not scanned)
        self.scan_ips = []
        self.reported = set()

        self.mono = mono_font()
        self.devices = DeviceStore(devices_file())
        self.new_devices = set()
        self.online_macs = set()  # seen in the latest scan or watch check
        self.history_path = None  # this scan's file in the history folder
        self.router_proc = None
        self.upnp = None          # router's UPnP answer: public IP and port forwards
        self.scan_token = 0       # discovery results from an older scan are ignored
        self.discovering = False
        self.disc_summary = ""
        self.discovery = Discovery()
        self.discovery.done.connect(self.apply_discovery)
        self.ssdp_listener = SsdpListener()
        self.ssdp_listener.found.connect(self.ssdp_announced)
        self.upnp_pending = False
        self.spoof_warnings = []
        self._icons = {}
        self.watch_proc = None
        self.networks = []
        self.ip_items = {}
        self.count_timer = QTimer(self)
        self.count_timer.setSingleShot(True)
        self.count_timer.setInterval(0)
        self.count_timer.timeout.connect(self.update_count)
        self.resolver = Resolver()
        self.resolver.resolved.connect(self.on_resolved)

        # Discover card: target and host discovery
        self.target = QComboBox()
        self.target.setEditable(True)
        self.target.setMinimumWidth(320)
        self.target.lineEdit().setPlaceholderText("Network, e.g. 192.168.1.0/24")
        self.target.setToolTip("Detected networks. You can also type a CIDR, range "
                               "or list, e.g. 10.0.0.0/16 or 10.1.1.1-50,10.1.2.0/24")
        self.refresh_btn = QPushButton("Re-detect")
        self.refresh_btn.setToolTip("Detect local networks again")
        self.refresh_btn.clicked.connect(self.populate_networks)
        self.root_box = QCheckBox("Raw scans (Npcap)" if IS_WIN else "Run as root")
        if IS_WIN:
            self.root_box.setToolTip(
                "Uses Npcap for raw packets: better host discovery, faster SYN port scans, "
                "and needed for UDP." + ("" if self.has_root else " Npcap is not installed."))
        else:
            if self.nmap_caps:
                self.root_box.setText("Privileged scans (no password)")
            self.root_box.setToolTip(("Asks for your Mac password (sudo)." if IS_MAC else
                                      "nmap has raw-packet permission, so no password is needed." if self.nmap_caps
                                      else "Uses pkexec (asks for your password). Run setup-no-password.sh "
                                           "once to stop the prompts.")
                                     + " Better host discovery, faster SYN port scans, and needed for UDP.")
        self.root_box.toggled.connect(self.update_controls)
        self.scan_btn = QPushButton("Find Hosts")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.setDefault(True)
        self.scan_btn.clicked.connect(self.start_scan)
        self.auto_ports_box = QCheckBox("Also scan top 100 ports")
        self.version_box = QCheckBox("Detect versions (slower)")
        self.os_box = QCheckBox("Detect OS")
        self.os_box.setToolTip("Guess each host's operating system while scanning ports "
                               "(needs root). Includes the top 100 port scan, which OS detection needs.")
        self.os_box.toggled.connect(self.os_toggled)
        self.auto_before_os = None

        discover, dl, _ = make_card("Discover")
        row = QHBoxLayout()
        row.addWidget(self.target, 1)
        row.addWidget(self.refresh_btn)
        row.addWidget(self.scan_btn)
        dl.addLayout(row)
        row = QHBoxLayout()
        row.setSpacing(18)
        row.addWidget(self.root_box)
        row.addWidget(self.auto_ports_box)
        row.addWidget(self.version_box)
        row.addWidget(self.os_box)
        row.addStretch(1)
        dl.addLayout(row)

        # Ports card: port scan of selected hosts
        self.profile = QComboBox()
        for label, _ in PORT_PROFILES:
            self.profile.addItem(label)
        self.profile.currentIndexChanged.connect(self.update_controls)
        self.custom_ports = QLineEdit()
        self.custom_ports.setPlaceholderText("22,80,443,8000-8100")
        self.custom_ports.setMinimumWidth(190)
        self.udp_box = QCheckBox("+ common UDP")
        self.udp_box.setToolTip(f"Also scan UDP {UDP_PORTS} (needs root)")
        self.ports_btn = QPushButton("Scan Ports")
        self.ports_btn.setObjectName("primary")
        self.ports_btn.setToolTip("Scans the selected hosts, or every visible host if none are selected.")
        self.ports_btn.clicked.connect(self.start_port_scan)

        ports_card, pl, _ = make_card("Ports")
        row = QHBoxLayout()
        row.addWidget(self.profile, 1)
        row.addWidget(self.ports_btn)
        pl.addLayout(row)
        row = QHBoxLayout()
        row.setSpacing(18)
        row.addWidget(self.custom_ports, 1)
        row.addWidget(self.udp_box)
        row.addStretch(1)
        pl.addLayout(row)

        # Hosts card: filter bar and results table
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by IP, name, MAC, vendor, OS, port…")
        self.filter_edit.setClearButtonEnabled(True)
        self.search_act = self.filter_edit.addAction(QIcon(icon_path("search")), QLineEdit.LeadingPosition)
        self.filter_edit.setMaximumWidth(420)
        self.filter_edit.textChanged.connect(self.apply_filter)
        self.open_only_box = QCheckBox("Only open ports")
        self.open_only_box.setToolTip("Only show hosts with open ports")
        self.open_only_box.toggled.connect(self.apply_filter)
        self.count_label = QLabel("")
        self.count_label.setObjectName("pill")
        self.count_label.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Preferred)  # never clip "13 host(s)"

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels([c.upper() for c in COLUMNS])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setFocusPolicy(Qt.StrongFocus)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(34)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setHighlightSections(False)
        header.setStretchLastSection(True)
        # Show Change (NEW DEVICE, compare results) right after Name, where it's noticed.
        header.moveSection(header.visualIndex(COL_CHANGE), COL_HOST)
        self.table.setColumnHidden(COL_CHANGE, True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.copy_act = QAction("Copy rows", self.table)
        self.copy_act.setShortcut(QKeySequence.Copy)
        self.copy_act.setShortcutContext(Qt.WidgetShortcut)
        self.copy_act.triggered.connect(self.copy_selection)
        self.table.addAction(self.copy_act)
        self.table.itemSelectionChanged.connect(self.show_port_details)
        self.table.itemDoubleClicked.connect(lambda item: self.edit_nickname(
            self.table.item(item.row(), COL_IP).text()))
        rename = QAction("Set nickname…", self.table)
        rename.setShortcut(QKeySequence(Qt.Key_F2))
        rename.setShortcutContext(Qt.WidgetShortcut)
        rename.triggered.connect(self.rename_selected)
        self.table.addAction(rename)
        self.table.setColumnHidden(COL_OS, True)
        self.table.setColumnHidden(COL_INFO, True)

        hosts_card, hl, hh = make_card("Hosts")
        hh.addWidget(self.count_label)
        hh.addStretch(1)
        hh.addWidget(self.open_only_box)
        hh.addSpacing(8)
        hh.addWidget(self.filter_edit, 1)
        hl.addWidget(self.table)

        # Details card: open ports of the selected host
        self.details_label = QLabel("Select a host to see its open ports.")
        self.details_label.setObjectName("muted")
        self.details = QTableWidget(0, len(PORT_COLUMNS))
        self.details.setHorizontalHeaderLabels([c.upper() for c in PORT_COLUMNS])
        self.details.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.details.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.details.setAlternatingRowColors(True)
        self.details.setShowGrid(False)
        self.details.verticalHeader().setVisible(False)
        self.details.verticalHeader().setDefaultSectionSize(32)
        self.details.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.details.horizontalHeader().setHighlightSections(False)
        self.details.horizontalHeader().setStretchLastSection(True)
        details_box, del_, dh = make_card("Open ports")
        dh.addWidget(self.details_label)
        dh.addStretch(1)
        del_.addWidget(self.details)

        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.setHandleWidth(12)
        self.splitter.addWidget(hosts_card)
        self.splitter.addWidget(details_box)
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 2)

        # Status bar
        self.progress = QProgressBar()
        self.progress.setFixedWidth(220)
        self.progress.setTextVisible(True)
        self.progress.hide()
        self.status_dot = QLabel("●")
        self.status = StatusLabel("Ready.")

        self.compare_btn = QPushButton("Compare…")
        self.compare_btn.setToolTip("Compare these results with a saved scan (.json)")
        self.compare_btn.setObjectName("menuButton")
        self.compare_menu = QMenu(self.compare_btn)
        self.compare_menu.aboutToShow.connect(self.build_compare_menu)
        self.compare_btn.setMenu(self.compare_menu)
        self.export_btn = QPushButton("Save / Export")
        self.export_btn.setObjectName("menuButton")
        export_menu = QMenu(self.export_btn)
        export_menu.addAction("Save scan (JSON, for Compare)…", self.save_json)
        export_menu.addAction("Network report (HTML)…", self.export_report)
        export_menu.addAction("Export CSV…", self.export_csv)
        export_menu.addAction("Export last nmap output (XML)…", self.export_xml)
        self.export_btn.setMenu(export_menu)

        statusbar = QFrame()
        statusbar.setObjectName("statusbar")
        bottom = QHBoxLayout(statusbar)
        bottom.setContentsMargins(18, 10, 18, 10)
        bottom.addWidget(self.status_dot)
        bottom.addWidget(self.status, 1)
        bottom.addWidget(self.progress)
        bottom.addSpacing(6)
        bottom.addWidget(self.compare_btn)
        bottom.addWidget(self.export_btn)

        # Title row
        title = QLabel("NetScan")
        title.setObjectName("title")
        subtitle = QLabel("Network discovery and port scanning with nmap")
        subtitle.setObjectName("subtitle")
        titles = QVBoxLayout()
        titles.setSpacing(0)
        titles.addWidget(title)
        titles.addWidget(subtitle)
        self.tabbar = QTabBar()
        self.tabbar.setObjectName("pages")
        self.tabbar.setDrawBase(False)
        self.tabbar.setExpanding(False)
        self.tabbar.addTab("Scan")
        self.tabbar.addTab("Devices")
        self.tabbar.addTab("Monitor")
        self.tabbar.setTabToolTip(2, "Ping devices over time: latency, jitter and packet loss (Ctrl+3)")
        self.tabbar.addTab("Internet")
        self.tabbar.setTabToolTip(3, "Public IP, VPN check, DNS, latency and a speed test (Ctrl+4)")
        self.tabbar.addTab("Map")
        self.tabbar.setTabToolTip(4, "Every device around your router, grouped by type (Ctrl+5)")
        self.tabbar.addTab("Tools")
        self.tabbar.setTabToolTip(5, "DNS lookup, port check, IP info, HTTP inspector, subnet, MAC, Wi-Fi (Ctrl+6)")
        self.tabbar.setTabToolTip(0, "Find hosts and scan ports (Ctrl+1)")
        self.tabbar.setTabToolTip(1, "Every device NetScan has seen: nicknames, Wake-on-LAN, watch, uptime alerts "
                                     "(Ctrl+2)")
        segment = QFrame()
        segment.setObjectName("segment")
        sl = QHBoxLayout(segment)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.addWidget(self.tabbar)
        self.nmap_pill = QLabel()
        self.nmap_pill.setObjectName("pill")
        self.theme_btn = QPushButton("Theme")
        self.theme_btn.setObjectName("menuButton")
        self.theme_btn.setToolTip("Light, dark, or follow your system setting")
        theme_menu = QMenu(self.theme_btn)
        self.theme_group = QActionGroup(self)
        for mode in THEME_MODES:
            act = theme_menu.addAction(mode.capitalize() if mode != "system" else "System (auto)")
            act.setCheckable(True)
            act.setData(mode)
            self.theme_group.addAction(act)
        self.theme_group.triggered.connect(lambda act: self.retheme(act.data()))
        self.theme_btn.setMenu(theme_menu)
        head = QHBoxLayout()
        head.addLayout(titles)
        head.addStretch(1)
        head.addWidget(segment, 0, Qt.AlignVCenter)
        head.addStretch(1)
        head.addWidget(self.theme_btn, 0, Qt.AlignVCenter)
        head.addSpacing(6)
        head.addWidget(self.nmap_pill, 0, Qt.AlignVCenter)

        cards = QHBoxLayout()
        cards.setSpacing(12)
        cards.addWidget(discover, 3)
        cards.addWidget(ports_card, 2)

        body = QVBoxLayout()
        body.setContentsMargins(18, 16, 18, 6)
        body.setSpacing(12)
        scan_page = QWidget()
        sp = QVBoxLayout(scan_page)
        sp.setContentsMargins(0, 0, 0, 0)
        sp.setSpacing(12)
        sp.addLayout(cards)
        sp.addWidget(self.splitter, 1)
        self.pages = QStackedWidget()
        self.pages.addWidget(scan_page)
        self.pages.addWidget(self.build_devices_page())
        self.pages.addWidget(self.build_monitor_page())
        self.pages.addWidget(self.build_internet_page())
        map_card, ml, _ = make_card("Network map")
        self.net_map = NetworkMap(self)
        ml.addWidget(self.net_map, 1)
        self.pages.addWidget(map_card)
        self.pages.addWidget(self.build_tools_page())
        self.tabbar.currentChanged.connect(self.switch_page)

        body.addLayout(head)
        body.addWidget(self.pages, 1)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addLayout(body, 1)
        layout.addWidget(statusbar)
        central = QWidget()
        central.setObjectName("central")
        central.setLayout(layout)
        self.setCentralWidget(central)

        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.tick)
        self.watch_timer = QTimer(self)
        self.watch_timer.timeout.connect(self.watch_scan)
        self.uptime_timer = QTimer(self)
        self.uptime_timer.timeout.connect(self.uptime_tick)
        self.uptime_state = {}  # mac -> {"up", "misses", "down_since"}

        for keys, slot in (("F5", self.shortcut_scan), (QKeySequence.Find, self.focus_filter),
                           ("Ctrl+1", lambda: self.tabbar.setCurrentIndex(0)),
                           ("Ctrl+2", lambda: self.tabbar.setCurrentIndex(1)),
                           ("Ctrl+3", lambda: self.tabbar.setCurrentIndex(2)),
                           ("Ctrl+4", lambda: self.tabbar.setCurrentIndex(3)),
                           ("Ctrl+5", lambda: self.tabbar.setCurrentIndex(4)),
                           ("Ctrl+6", lambda: self.tabbar.setCurrentIndex(5))):
            act = QAction(self)
            act.setShortcut(QKeySequence(keys))
            act.triggered.connect(slot)
            self.addAction(act)

        self.load_settings()
        self.populate_networks()
        self.set_busy(False)
        version = re.search(r"version (\S+)", run_text(self.nmap, "--version")) if self.nmap else None
        self.nmap_version = version.group(1) if version else ""
        self.update_nmap_pill()
        self.theme_mode = self.settings.value("theme", "system", type=str)
        if self.theme_mode not in THEME_MODES:
            self.theme_mode = "system"
        for act in self.theme_group.actions():
            act.setChecked(act.data() == self.theme_mode)
        hints = QGuiApplication.styleHints()
        if hasattr(hints, "colorSchemeChanged"):
            hints.colorSchemeChanged.connect(lambda _s: self.theme_mode == "system" and self.retheme("system"))
        if not self.nmap:
            self.set_dot(T.RED)
            self.status.setText("nmap not found. Install it with: "
                                + ("brew install nmap" if IS_MAC else
                                   "install-windows.ps1 (or choco install nmap)" if IS_WIN else
                                   "sudo pacman -S nmap"))
        self.refresh_devices()
        self.watch_combo.currentIndexChanged.connect(self.set_watch)
        self.set_watch(first_delay=5000)
        self.uptime_restart()

    # ---- settings ----------------------------------------------------------

    def load_settings(self):
        s = self.settings
        b = lambda key, default: s.value(key, default, type=bool)
        self.root_box.setChecked(b("root", True) and self.has_root)
        self.auto_ports_box.setChecked(b("auto_ports", True))
        self.version_box.setChecked(b("versions", False))
        self.os_box.setChecked(b("os", False))
        self.watch_combo.setCurrentIndex(min(s.value("watch", 0, type=int), len(WATCH_INTERVALS) - 1))
        self.watch_ports_box.setChecked(b("watch_ports", False))
        self.mon_interval.setCurrentIndex(min(s.value("monitor_interval", 0, type=int), self.mon_interval.count() - 1))
        self.mon_span.setCurrentIndex(min(s.value("monitor_span", 0, type=int), self.mon_span.count() - 1))
        self.speed_provider.setCurrentIndex(min(s.value("speed_provider", 0, type=int), self.speed_provider.count() - 1))
        if s.contains("dev_split"):
            self.dev_split.restoreState(s.value("dev_split"))
        self.udp_box.setChecked(b("udp", False))
        self.profile.setCurrentIndex(min(s.value("profile", 0, type=int), len(PORT_PROFILES) - 1))
        self.custom_ports.setText(s.value("custom_ports", "", type=str))
        self.open_only_box.setChecked(b("open_only", False))
        if s.contains("geometry"):
            self.restoreGeometry(s.value("geometry"))
        if s.contains("splitter"):
            self.splitter.restoreState(s.value("splitter"))

    def save_settings(self):
        s = self.settings
        s.setValue("root", self.root_box.isChecked())
        # While Detect OS forces the port scan on, save the user's own choice instead.
        s.setValue("auto_ports", self.auto_ports_box.isChecked() if self.auto_before_os is None
                   else self.auto_before_os)
        s.setValue("versions", self.version_box.isChecked())
        s.setValue("os", self.os_box.isChecked())
        s.setValue("watch", self.watch_combo.currentIndex())
        s.setValue("watch_ports", self.watch_ports_box.isChecked())
        s.setValue("monitor_interval", self.mon_interval.currentIndex())
        s.setValue("monitor_span", self.mon_span.currentIndex())
        s.setValue("speed_provider", self.speed_provider.currentIndex())
        s.setValue("theme", self.theme_mode)
        s.setValue("dev_split", self.dev_split.saveState())
        s.setValue("udp", self.udp_box.isChecked())
        s.setValue("profile", self.profile.currentIndex())
        s.setValue("custom_ports", self.custom_ports.text())
        s.setValue("open_only", self.open_only_box.isChecked())
        s.setValue("geometry", self.saveGeometry())
        s.setValue("splitter", self.splitter.saveState())

    # ---- network detection -------------------------------------------------

    def populate_networks(self):
        self.target.clear()
        self.networks = detect_networks()
        if self.networks and hasattr(self, "ssdp_listener"):
            self.ssdp_listener.start(self.networks[0]["local_ip"])
        for n in self.networks:
            self.target.addItem(
                f"{n['network']}  ({n['iface']}, you are {n['local_ip']})", n)
        if not self.networks:
            self.status.setText("No LAN subnet detected. Type a target, e.g. 192.168.1.0/24")

    def selected_target(self):
        """Return (nmap target list, network dict or None)."""
        idx = self.target.currentIndex()
        text = self.target.currentText().strip()
        if idx >= 0 and text == self.target.itemText(idx):
            n = self.target.itemData(idx)
            return [str(n["network"])], n
        # Free-typed: allow comma/space separated targets.
        targets = [t for t in re.split(r"[,\s]+", text) if t]
        match = None
        if len(targets) == 1:
            try:
                net = ipaddress.ip_network(targets[0], strict=False)
                match = next((n for n in self.networks if net.subnet_of(n["network"])), None)
            except ValueError:
                pass
        return targets, match

    # ---- nicknames / wake-on-lan -------------------------------------------

    def shortcut_scan(self):
        if self.tabbar.currentIndex() == 0 and self.scan_btn.isEnabled():
            self.start_scan()

    def rename_selected(self):
        ips = self.selected_ips()
        if len(ips) == 1:
            self.edit_nickname(ips[0])

    def edit_nickname(self, ip):
        h = self.hosts.get(ip)
        if h is None:
            return
        name = self.ask_nickname(h["hostname"] or ip, h["mac"], self.devices.nickname(h))
        if name is None:
            return
        self.devices.set_nickname(h, name)
        self.refresh_row(ip)  # hosts without a MAC are keyed by IP, so refresh this row directly
        self.after_device_change(h["mac"])

    def broadcasts(self):
        return [str(n["network"].broadcast_address) for n in self.networks] + ["255.255.255.255"]

    def wake(self, mac, label=""):
        sent = wake_on_lan(mac, self.broadcasts())
        who = f"{label} ({mac})" if label else mac
        if sent:
            self.set_dot(T.GREEN)
            self.status.setText(f"Sent Wake-on-LAN packet to {who}. It may take a minute to come up.")
        else:
            self.set_dot(T.RED)
            self.status.setText(f"Could not send Wake-on-LAN packet to {who}.")

    def ask_nickname(self, who, mac, current):
        """Nickname prompt; returns the new name ('' removes it) or None if cancelled."""
        name, ok = QInputDialog.getText(
            self, "Nickname", f"Nickname for {who}" + (f"  ({mac})" if mac else "")
            + "\nLeave empty to remove it.", text=current)
        return name.strip() if ok else None

    def switch_page(self, index):
        self.pages.setCurrentIndex(index)
        for w in (self.compare_btn, self.export_btn):
            w.setVisible(index == 0)
        if index == 1:
            self.refresh_devices()
        if index == 2:
            self.refresh_monitor()
        if index == 4:
            self.net_map.update()

    def focus_filter(self):
        edit = self.dev_filter if self.tabbar.currentIndex() == 1 else self.filter_edit
        edit.setFocus()
        edit.selectAll()
