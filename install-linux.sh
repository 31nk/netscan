#!/bin/bash
# Install NetScan on Linux: an app-menu entry, plus a private Python environment with
# PySide6 if the system Python doesn't have it. NetScan runs from this folder, so
# updating it (e.g. git pull) needs no reinstall.
#
# Run from the folder containing netscan.py:  bash install-linux.sh
# Remove the menu entry again:               bash install-linux.sh --uninstall
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
data="${XDG_DATA_HOME:-$HOME/.local/share}"
entry="$data/applications/netscan.desktop"
venv="$data/NetScan/venv"   # next to NetScan's device list and scan history

refresh_menus() {
    if command -v update-desktop-database >/dev/null; then
        update-desktop-database "$data/applications" 2>/dev/null || true
    fi
    # KDE Plasma caches menu entries and keeps launching a stale copy without this.
    for k in kbuildsycoca6 kbuildsycoca5; do
        if command -v "$k" >/dev/null; then "$k" >/dev/null 2>&1 || true; break; fi
    done
}

if [[ "${1:-}" == "--uninstall" ]]; then
    rm -f "$entry"
    rm -rf "$venv"
    refresh_menus
    echo "Removed the NetScan menu entry. Your device list and scan history in $data/NetScan were kept."
    exit 0
fi

[[ -f "$here/netscan.py" && -d "$here/netscan_app" ]] || {
    echo "netscan.py and the netscan_app folder must be next to this script."; exit 1; }

# The install command for a package on this distro: hint <pacman> <apt> <dnf/zypper>
hint() {
    if command -v pacman >/dev/null; then echo "sudo pacman -S $1"
    elif command -v apt >/dev/null; then echo "sudo apt install $2"
    elif command -v dnf >/dev/null; then echo "sudo dnf install $3"
    elif command -v zypper >/dev/null; then echo "sudo zypper install $3"
    else echo "your package manager ($1)"; fi
}
command -v nmap >/dev/null || { echo "nmap not found. Install it with: $(hint nmap nmap nmap)"; exit 1; }
command -v python3 >/dev/null || { echo "python3 not found. Install it with: $(hint python python3 python3)"; exit 1; }

python="$(command -v python3)"
if "$python" -c "import PySide6.QtWidgets" 2>/dev/null; then
    echo "Using $python ($("$python" --version)) with the system's PySide6."
else
    echo "PySide6 (Qt for Python) isn't installed for $python."
    echo "Setting up a private Python environment in $venv"
    echo "(or install it system-wide instead: $(hint pyside6 python3-pyside6 python3-pyside6))"
    if [[ ! -x "$venv/bin/python" ]]; then
        "$python" -m venv "$venv" || {
            echo "Couldn't create the environment. Install venv support with: $(hint python python3-venv python3)"
            exit 1; }
    fi
    echo "Installing PySide6 - this can take a minute..."
    "$venv/bin/pip" install --quiet --upgrade pip PySide6
    python="$venv/bin/python"
fi

# Plasma's Breeze icons have a nicer Ethernet icon; other desktops fall back to the standard one.
icon="network-wired"
[[ "${XDG_CURRENT_DESKTOP:-}" == *KDE* ]] && icon="preferences-system-network-ethernet"

echo "Creating $entry"
mkdir -p "$(dirname "$entry")"
# Written by Python so paths with spaces or quotes get the Desktop Entry escaping right.
"$python" - "$python" "$here/netscan.py" "$entry" "$icon" <<'EOF'
import sys

python, script, entry, icon = sys.argv[1:]


def exec_arg(s):
    """Quote one Exec argument per the Desktop Entry spec."""
    s = s.replace("%", "%%")
    if all(c.isalnum() or c in "/._-+" for c in s):
        return s
    quoted = '"' + "".join("\\" + c if c in '"`$\\' else c for c in s) + '"'
    return quoted.replace("\\", "\\\\")  # the file's own string escaping doubles backslashes


with open(entry, "w", encoding="utf-8") as f:
    f.write(f"""[Desktop Entry]
Type=Application
Name=NetScan
GenericName=Network Scanner
Comment=Scan the local network for devices and open ports (nmap)
Exec={exec_arg(python)} {exec_arg(script)}
Icon={icon}
Terminal=false
StartupNotify=true
Categories=Network;
""")
EOF
chmod 644 "$entry"
refresh_menus

echo
"$python" "$here/netscan.py" --self-test || true
echo
echo "Done. Open NetScan from your app menu (search \"NetScan\")."
if command -v pacman >/dev/null && [[ -f "$here/setup-no-password.sh" ]]; then
    echo "Optional: scan with full features without a password prompt each time:"
    echo "  pkexec \"$here/setup-no-password.sh\""
fi
echo "To update later: pull, or copy the new netscan.py and netscan_app folder into $here (no reinstall needed)."
