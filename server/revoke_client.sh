#!/usr/bin/env bash
set -Eeuo pipefail
NAME="${1:-}"
ENV_FILE="${2:-/root/node.env}"
[[ $EUID -eq 0 ]] || { echo "Run with sudo/root."; exit 1; }
[[ "$NAME" =~ ^[A-Za-z0-9_-]{3,64}$ ]] || { echo "Invalid client name."; exit 1; }
if [[ -f "$ENV_FILE" ]]; then
  [[ "$(stat -c '%u' "$ENV_FILE")" == "0" ]] || { echo "Environment file must be owned by root."; exit 1; }
  source "$ENV_FILE"
fi
WG_INTERFACE="${WG_INTERFACE:-wg0}"
DIR="/root/novavpn-clients"
PUBFILE="$DIR/${NAME}.pub"
[[ -f "$PUBFILE" ]] || { echo "No client named $NAME"; exit 1; }
PUB="$(cat "$PUBFILE")"
wg set "$WG_INTERFACE" peer "$PUB" remove
CONF="/etc/wireguard/${WG_INTERFACE}.conf"
TMP="$(mktemp)"
awk -v name="$NAME" '
  $0 == "# BEGIN PEER " name {skip=1; next}
  $0 == "# END PEER " name {skip=0; next}
  !skip {print}
' "$CONF" > "$TMP"
cat "$TMP" > "$CONF"
rm -f "$TMP" "$DIR/${NAME}.conf" "$DIR/${NAME}.pub" "$DIR/${NAME}.ip" "$DIR/${NAME}.png"
chmod 600 "$CONF"
echo "Revoked client $NAME on this VPS. Repeat on every country node where this member had a profile."
