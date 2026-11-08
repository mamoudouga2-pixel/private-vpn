#!/usr/bin/env bash
# NovaVPN node control wrapper.
# Runs only as an SSH forced command for the control-plane key. It accepts exactly:
#   add <name>      create (or re-read) a client profile and print the .conf to stdout
#   revoke <name>   remove a client (safe to repeat)
#   status          print a few health lines
# Anything else is refused, so a leaked control-plane key cannot open a shell on the node.
set -Eeuo pipefail

LIB_DIR="${NOVAVPN_LIB_DIR:-/usr/local/lib/novavpn}"
CLIENT_DIR="${NOVAVPN_CLIENT_DIR:-/root/novavpn-clients}"
ENV_FILE="${NOVAVPN_NODE_ENV:-/root/node.env}"
WG_BIN="${NOVAVPN_WG_BIN:-wg}"

CMD="${SSH_ORIGINAL_COMMAND:-}"
read -r ACTION NAME EXTRA <<<"$CMD" || true
[[ -z "${EXTRA:-}" ]] || { echo "refused" >&2; exit 2; }

valid_name() { [[ "${1:-}" =~ ^[A-Za-z0-9_-]{3,64}$ ]]; }

case "${ACTION:-}" in
  add)
    valid_name "${NAME:-}" || { echo "bad name" >&2; exit 2; }
    if [[ ! -f "$CLIENT_DIR/${NAME}.conf" ]]; then
      bash "$LIB_DIR/add_client.sh" "$NAME" "$ENV_FILE" >&2
    fi
    cat "$CLIENT_DIR/${NAME}.conf"
    ;;
  revoke)
    valid_name "${NAME:-}" || { echo "bad name" >&2; exit 2; }
    if [[ -f "$CLIENT_DIR/${NAME}.pub" ]]; then
      bash "$LIB_DIR/revoke_client.sh" "$NAME" "$ENV_FILE" >&2
    else
      echo "already absent" >&2
    fi
    echo "revoked"
    ;;
  status)
    DUMP="$("$WG_BIN" show wg0 latest-handshakes 2>/dev/null)" || { echo "wg=down"; exit 0; }
    PEERS=0; LAST=0
    while IFS=$'\t' read -r _key ts; do
      [[ -n "${_key:-}" ]] || continue
      PEERS=$((PEERS+1))
      (( ${ts:-0} > LAST )) && LAST="$ts"
    done <<<"$DUMP"
    echo "wg=up"
    echo "peers=$PEERS"
    echo "last_handshake=$LAST"
    ;;
  *)
    echo "refused" >&2
    exit 2
    ;;
esac
