#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo/root."; exit 1; }
ENV_FILE="${1:-/root/node.env}"
[[ -f "$ENV_FILE" ]] || { echo "Missing env file: $ENV_FILE"; exit 1; }
# The environment file must be owned and writable only by root: it is sourced as shell code.
[[ "$(stat -c '%u' "$ENV_FILE")" == "0" ]] || { echo "Environment file must be owned by root."; exit 1; }
# shellcheck disable=SC1090
source "$ENV_FILE"
: "${NODE_COUNTRY:?Set NODE_COUNTRY in env file}"
: "${PUBLIC_ENDPOINT:?Set PUBLIC_ENDPOINT to this VPS public IPv4 or hostname}"
WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_ADDRESS="${WG_ADDRESS:-10.66.66.1/24}"
WG_PORT="${WG_PORT:-51820}"
CLIENT_MTU="${CLIENT_MTU:-1380}"
[[ "$WG_INTERFACE" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || { echo "Invalid WG_INTERFACE."; exit 1; }
[[ "$WG_PORT" =~ ^[0-9]+$ ]] && (( WG_PORT >= 1 && WG_PORT <= 65535 )) || { echo "Invalid WG_PORT."; exit 1; }
[[ "$PUBLIC_ENDPOINT" != "203.0.113.10" ]] || { echo "Replace the example PUBLIC_ENDPOINT with the real VPS address."; exit 1; }
[[ "$PUBLIC_ENDPOINT" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "PUBLIC_ENDPOINT must be an IPv4 address or DNS hostname."; exit 1; }
. /etc/os-release
[[ "${ID:-}" == "ubuntu" || "${ID_LIKE:-}" == *"debian"* ]] || { echo "Supported OS: Ubuntu/Debian."; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y wireguard iptables qrencode curl
umask 077
install -d -m 700 /etc/wireguard /root/novavpn-clients /var/lib/novavpn
CONF_PATH="/etc/wireguard/${WG_INTERFACE}.conf"
if [[ -e "$CONF_PATH" ]]; then
  echo "Existing ${WG_INTERFACE} config found; refusing to overwrite existing peers."
  exit 1
fi
PRIV="/etc/wireguard/${WG_INTERFACE}_private.key"
PUB="/etc/wireguard/${WG_INTERFACE}_public.key"
wg genkey | tee "$PRIV" | wg pubkey > "$PUB"
chmod 600 "$PRIV" "$PUB"
WAN_IF="$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
[[ -n "$WAN_IF" ]] || { echo "Could not detect outbound interface."; exit 1; }
cat > "$CONF_PATH" <<EOF
[Interface]
Address = ${WG_ADDRESS}
ListenPort = ${WG_PORT}
PrivateKey = $(cat "$PRIV")
MTU = ${CLIENT_MTU}
PostUp = iptables -A FORWARD -i ${WG_INTERFACE} -o ${WAN_IF} -j ACCEPT; iptables -A FORWARD -i ${WAN_IF} -o ${WG_INTERFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -o ${WAN_IF} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${WG_INTERFACE} -o ${WAN_IF} -j ACCEPT; iptables -D FORWARD -i ${WAN_IF} -o ${WG_INTERFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -o ${WAN_IF} -j MASQUERADE
EOF
chmod 600 "$CONF_PATH"
cat > /etc/sysctl.d/99-novavpn.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
sysctl --system >/dev/null
systemctl enable --now "wg-quick@${WG_INTERFACE}"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
  ufw allow "${WG_PORT}/udp"
  ufw route allow in on "${WG_INTERFACE}" out on "${WAN_IF}"
fi
cat > /var/lib/novavpn/node-info.txt <<EOF
country=${NODE_COUNTRY}
endpoint=${PUBLIC_ENDPOINT}
port=${WG_PORT}
interface=${WG_INTERFACE}
EOF
chmod 600 /var/lib/novavpn/node-info.txt

# Control-plane automation: install the locked-down wrapper and (optionally) authorise the control-plane key.
install -d -m 755 /usr/local/lib/novavpn
install -m 700 "$SCRIPT_DIR/add_client.sh" "$SCRIPT_DIR/revoke_client.sh" /usr/local/lib/novavpn/
install -m 700 "$SCRIPT_DIR/node_ctl.sh" /usr/local/sbin/novavpn-node-ctl
if [[ -n "${CONTROL_PUBKEY:-}" ]]; then
  [[ "$CONTROL_PUBKEY" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ [A-Za-z0-9@._-]+)?$ ]] || { echo "CONTROL_PUBKEY is not a valid ssh-ed25519 public key."; exit 1; }
  install -d -m 700 /root/.ssh
  touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
  if ! grep -qF "$CONTROL_PUBKEY" /root/.ssh/authorized_keys; then
    printf 'command="/usr/local/sbin/novavpn-node-ctl",restrict %s\n' "$CONTROL_PUBKEY" >> /root/.ssh/authorized_keys
  fi
  echo "Control-plane key authorised (restricted to NovaVPN node commands only)."
else
  echo "No CONTROL_PUBKEY set: automatic profile creation is off for this node."
fi

echo
echo "NovaVPN WireGuard node is active."
echo "Country label: ${NODE_COUNTRY} (confirm actual IP geolocation with your provider)."
echo "Endpoint: ${PUBLIC_ENDPOINT}:${WG_PORT}/UDP"
echo "Server public key: $(cat "$PUB")"
echo "Create a unique profile per user/device: sudo bash server/add_client.sh user001 ${ENV_FILE}"
echo "Provider firewall/security group must allow UDP ${WG_PORT}; keep SSH restricted to trusted administrators."
