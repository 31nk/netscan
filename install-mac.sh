#!/bin/bash
# Install NetScan on macOS: a Python venv with PySide6, plus ~/Applications/NetScan.app.
# Run from the folder containing netscan.py:  bash install-mac.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
support="$HOME/Library/Application Support/NetScan"
app="$HOME/Applications/NetScan.app"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

[[ -f "$here/netscan.py" ]] || { echo "netscan.py not found next to this script."; exit 1; }
command -v nmap >/dev/null || { echo "nmap not found. Install it with: brew install nmap"; exit 1; }

# Prefer Homebrew's Python; Apple's /usr/bin/python3 works too once the Xcode tools are installed.
python="$(command -v python3 || true)"
[[ -n "$python" ]] || { echo "python3 not found. Install it with: brew install python"; exit 1; }
echo "Using $python ($("$python" --version))"

mkdir -p "$support"
cp "$here/netscan.py" "$support/netscan.py"

if [[ ! -x "$support/venv/bin/python" ]]; then
    echo "Creating Python environment..."
    "$python" -m venv "$support/venv"
fi
echo "Installing PySide6 (Qt) - this can take a minute..."
"$support/venv/bin/pip" install --quiet --upgrade pip PySide6

echo "Creating ${app}..."
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cat > "$app/Contents/MacOS/NetScan" <<'EOF'
#!/bin/bash
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
support="$HOME/Library/Application Support/NetScan"
exec "$support/venv/bin/python" "$support/netscan.py" "$@"
EOF
chmod +x "$app/Contents/MacOS/NetScan"
cat > "$app/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>NetScan</string>
    <key>CFBundleDisplayName</key><string>NetScan</string>
    <key>CFBundleIdentifier</key><string>local.netscan</string>
    <key>CFBundleExecutable</key><string>NetScan</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleVersion</key><string>1.0</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSLocalNetworkUsageDescription</key>
    <string>NetScan scans your local network to list devices and open ports.</string>
</dict>
</plist>
EOF

echo
echo "Done. Open NetScan from ~/Applications (or Spotlight: \"NetScan\")."
echo "If macOS asks to let NetScan find devices on your local network, click Allow."
echo "To update later: copy the new netscan.py here and run this script again."
