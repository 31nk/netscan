#!/bin/sh
# Let NetScan do privileged scans (ARP discovery, SYN/UDP, OS detection)
# without asking for a password each time.
#
# Gives /usr/bin/nmap the raw-socket capabilities it needs, instead of running
# it as root through pkexec. Also installs a pacman hook so the capabilities are
# re-applied whenever the nmap package is upgraded (an upgrade replaces the
# binary and drops them).
#
# Trade-off: any program running as any user on this machine can then use nmap
# to send raw packets. Fine for a personal desktop; think twice on a shared box.
#
# Run once:   pkexec /home/d/Projects/netscan/setup-no-password.sh
# Undo:       pkexec /home/d/Projects/netscan/setup-no-password.sh --undo
set -e

NMAP=/usr/bin/nmap
CAPS=cap_net_raw,cap_net_admin,cap_net_bind_service+eip
HOOK=/etc/pacman.d/hooks/nmap-capabilities.hook

if [ "$(id -u)" -ne 0 ]; then
    echo "Needs root: pkexec $0 $*" >&2
    exit 1
fi

if [ "$1" = "--undo" ]; then
    setcap -r "$NMAP" 2>/dev/null || true
    rm -f "$HOOK"
    echo "Removed nmap capabilities and the pacman hook. NetScan will ask for a password again."
    exit 0
fi

setcap "$CAPS" "$NMAP"

mkdir -p "$(dirname "$HOOK")"
cat > "$HOOK" <<EOF
# Installed by NetScan's setup-no-password.sh; remove with its --undo.
[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = nmap

[Action]
Description = Re-applying nmap raw-socket capabilities for NetScan...
When = PostTransaction
Exec = /usr/bin/setcap $CAPS $NMAP
EOF

echo "Done: $(getcap "$NMAP")"
echo "Restart NetScan; the checkbox now reads \"Privileged scans (no password)\"."
