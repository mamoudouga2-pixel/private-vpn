#!/usr/bin/env bash
set -Eeuo pipefail
NAME="${1:-}"
ENV_FILE="${2:-/root/node.env}"
[[ $EUID -eq 0 ]] || { echo "Run with sudo/root."; exit 1; }
[[ -f "$ENV_FILE" ]] || { echo "Missing env file: $ENV_FILE"; exit 1; }
[[ "$(stat -c '%u' "$ENV_FILE")" == "0" ]] || { echo "Environment file must be owned by root."; exit 1; }
source "$ENV_FILE"
[[ "$NAME" =~ ^[A-Za-z0-9_-]{3,64}$ ]] || { echo "Client name must be 3-64 letters, digits, _ or -."; exit 1; }
WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_PORT="${WG_PORT:-51820}"
WG_CLIENT_SUBNET="${WG_CLIENT_SUBNET:-10.66.66}"
DNS_SERVERS="${DNS_SERVERS:-1.1.1.1,1.0.0.1}"
CLIENT_MTU="${CLIENT_MTU:-1380}"
CONF="/etc/wireguard/${WG_INTERFACE}.conf"
CLIENT_DIR="/root/novavpn-clients"
[[ -f "$CONF" ]] || { echo "WireGuard node not installed. Run install_node.sh first."; exit 1; }
install -d -m 700 "$CLIENT_DIR"
exec 9>/var/lock/novavpn-peer.lock
flock 9
[[ ! -e "$CLIENT_DIR/${NAME}.conf" ]] || { echo "Client already exists: $NAME"; exit 1; }
OCTET=""
for i in $(seq 2 254); do
  USED=0
  for f in "$CLIENT_DIR"/*.ip; do
    [[ -e "$f" ]] || continue
    if [[ "$(cat "$f")" == "${WG_CLIENT_SUBNET}.${i}/32" ]]; then USED=1; break; fi
  done
  if [[ "$USED" -eq 0 ]]; then OCTET="$i"; break; fi
done
[[ -n "$OCTET" ]] || { echo "VPN client IP pool is full."; exit 1; }
CLIENT_IP="${WG_CLIENT_SUBNET}.${OCTET}/32"
CLIENT_PRIV="$(wg genkey)"
CLIENT_PUB="$(printf '%s' "$CLIENT_PRIV" | wg pubkey)"
PSK="$(wg genpsk)"
SERVER_PUB="$(cat "/etc/wireguard/${WG_INTERFACE}_public.key")"
cat >> "$CONF" <<EOF

# BEGIN PEER ${NAME}
[Peer]
# client-name = ${NAME}
PublicKey = ${CLIENT_PUB}
PresharedKey = ${PSK}
AllowedIPs = ${CLIENT_IP}
# END PEER ${NAME}
EOF
chmod 600 "$CONF"
wg set "$WG_INTERFACE" peer "$CLIENT_PUB" preshared-key <(printf '%s' "$PSK") allowed-ips "$CLIENT_IP"
OUT="$CLIENT_DIR/${NAME}.conf"
cat > "$OUT" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = ${CLIENT_IP}
DNS = ${DNS_SERVERS}
MTU = ${CLIENT_MTU}

[Peer]
PublicKey = ${SERVER_PUB}
PresharedKey = ${PSK}
Endpoint = ${PUBLIC_ENDPOINT}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
printf '%s\n' "$CLIENT_IP" > "$CLIENT_DIR/${NAME}.ip"
printf '%s\n' "$CLIENT_PUB" > "$CLIENT_DIR/${NAME}.pub"
chmod 600 "$OUT" "$CLIENT_DIR/${NAME}.ip" "$CLIENT_DIR/${NAME}.pub"
qrencode -o "$CLIENT_DIR/${NAME}.png" < "$OUT"
chmod 600 "$CLIENT_DIR/${NAME}.png"
echo "Created unique client profile: $OUT"
echo "Private key/config is secret. In the NovaVPN control panel, assign this config to the matching member and country."
