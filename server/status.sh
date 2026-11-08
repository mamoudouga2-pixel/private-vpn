#!/usr/bin/env bash
set -euo pipefail
echo "=== NovaVPN node metadata ==="
cat /var/lib/novavpn/node-info.txt 2>/dev/null || echo "No node metadata found."
echo
echo "=== WireGuard status ==="
wg show wg0 2>/dev/null || { echo "wg0 is not running."; exit 1; }
echo
echo "=== Client profiles on this node ==="
find /root/novavpn-clients -maxdepth 1 -type f -name '*.conf' -printf '%f\n' 2>/dev/null | sort || true
