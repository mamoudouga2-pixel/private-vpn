#!/usr/bin/env bash
# Run on the control server, after install_control_plane.sh.
# Installs WireGuard on each of the five country servers over SSH. You type each server's password once.
# Passwords are never saved. After success the server address is saved in the control plane.
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }
[[ -f /etc/novavpn-control.pub ]] || { echo "Run server/control/install_control_plane.sh first."; exit 1; }
command -v novavpn-admin >/dev/null || { echo "novavpn-admin not found. Run install_control_plane.sh first."; exit 1; }
SERVER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUBKEY="$(cat /etc/novavpn-control.pub)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"; ssh -O exit -o ControlPath="/tmp/novavpn-mux-%C" x 2>/dev/null || true' EXIT
tar czf "$TMP/server.tgz" -C "$(dirname "$SERVER_DIR")" server

declare -A NAMES=([au]=Australia [ar]=Argentina [mx]=Mexico [br]=Brazil [nz]="New Zealand")
# No arguments: the five country servers. Or pass codes, e.g.  deploy_nodes.sh au-sydney  for a city's own server.
CODES=("$@"); [[ ${#CODES[@]} -gt 0 ]] || CODES=(au ar mx br nz)
echo "Enter the public IP of each server. Leave empty to skip."
for CC in "${CODES[@]}"; do
  [[ "$CC" =~ ^[a-z]{2}(-[a-z0-9-]+)?$ ]] || { echo "Bad code: $CC"; continue; }
  echo
  read -rp "${NAMES[$CC]:-$CC} server IP: " IP
  [[ -n "$IP" ]] || { echo "  skipped"; continue; }
  [[ "$IP" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "  invalid address, skipped"; continue; }
  read -rp "  Is this the same machine you are on right now? (y/N): " LOCAL
  if [[ "${LOCAL,,}" == "y" ]]; then
    mkdir -p /root/novavpn && tar xzf "$TMP/server.tgz" -C /root/novavpn
    if [[ -f /etc/wireguard/wg0.conf ]]; then echo "  already installed here, skipping install"; else
      umask 077
      printf 'NODE_COUNTRY=%s\nPUBLIC_ENDPOINT=%s\nCONTROL_PUBKEY=%s\n' "$CC" "$IP" "$PUBKEY" > /root/node.env
      bash /root/novavpn/server/install_node.sh /root/node.env
    fi
    # Local server: ssh to itself is how the control plane reaches it, so root login by key must work here too.
    if ! grep -qF "$PUBKEY" /root/.ssh/authorized_keys 2>/dev/null; then echo "  warning: control key not authorised on this machine"; fi
    novavpn-admin set-server "$CC" "$IP"
    continue
  fi
  MUX=(-o ControlMaster=auto -o ControlPath="/tmp/novavpn-mux-%C" -o ControlPersist=300 -o StrictHostKeyChecking=accept-new)
  echo "  Connecting to $IP — type its root password when asked."
  if ! ssh "${MUX[@]}" "root@$IP" 'echo connected >/dev/null'; then echo "  could not log in to $IP, skipped"; continue; fi
  if ssh "${MUX[@]}" "root@$IP" 'test -f /etc/wireguard/wg0.conf'; then
    echo "  WireGuard already installed on $IP, skipping install."
  else
    scp "${MUX[@]}" -q "$TMP/server.tgz" "root@$IP:/root/novavpn-server.tgz"
    ssh "${MUX[@]}" "root@$IP" "mkdir -p /root/novavpn && tar xzf /root/novavpn-server.tgz -C /root/novavpn && rm -f /root/novavpn-server.tgz && umask 077 && printf 'NODE_COUNTRY=%s\nPUBLIC_ENDPOINT=%s\nCONTROL_PUBKEY=%s\n' '$CC' '$IP' '$PUBKEY' > /root/node.env && bash /root/novavpn/server/install_node.sh /root/node.env" \
      || { echo "  install FAILED on $IP"; continue; }
  fi
  novavpn-admin set-server "$CC" "$IP"
  ssh -O exit "${MUX[@]}" "root@$IP" 2>/dev/null || true
done

echo
echo "Checking all servers from the control plane..."
novavpn-admin servers
