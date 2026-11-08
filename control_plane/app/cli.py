"""novavpn-admin: operator commands (run on the control server). No web admin panel exists."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _load_env() -> None:
    path = Path(os.environ.get("NOVAVPN_ENV_FILE", "/etc/novavpn-control.env"))
    if path.is_file():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


_load_env()
from . import core  # noqa: E402  (needs the env loaded first)

COUNTRY_NAMES = {c["code"]: c["name"] for c in core.COUNTRIES} | {l["code"]: l["name"] + " (own server)" for l in core.LOCATIONS}


def _show_results(label: str, results: list[dict]) -> None:
    for r in results:
        extra = f" — {r['detail']}" if r.get("detail") else ""
        print(f"  {label} {COUNTRY_NAMES.get(r['country'], r['country'])}: {r['status']}{extra}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="novavpn-admin", description="NovaVPN operator tool")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add-user", help="create a member and make their VPN keys on all servers")
    a.add_argument("username"); a.add_argument("email"); a.add_argument("--no-provision", action="store_true")
    sub.add_parser("list-users", help="list members")
    for name in ("disable", "enable", "provision", "reset-password"):
        s = sub.add_parser(name); s.add_argument("username")
    d = sub.add_parser("delete", help="delete a member and revoke their keys"); d.add_argument("username"); d.add_argument("--yes", action="store_true")
    n = sub.add_parser("set-server", help="save a server address: set-server au 1.2.3.4  (or a city: set-server au-sydney 1.2.3.4)"); n.add_argument("country"); n.add_argument("host"); n.add_argument("--port", type=int, default=22)
    sub.add_parser("servers", help="check the servers")
    sub.add_parser("locations", help="show the 20 locations and which server each one uses")
    sub.add_parser("provision-all", help="give every active member keys on any server they are missing (run after adding a server)")
    sub.add_parser("retry-revocations", help="retry key removals that failed earlier")
    sub.add_parser("summary", help="counts")
    args = p.parse_args(argv)

    core.init_db()
    try:
        if args.cmd == "add-user":
            r = core.create_user(args.username, args.email, auto_provision=not args.no_provision)
            print(f"Member created: {r['username']}\nTemporary password (give it to the member, shown only now):\n  {r['temporary_password']}")
            if "provisioning" in r:
                _show_results("VPN keys", r["provisioning"])
                if not r["provisioning"]:
                    print("  (No server address saved yet; run set-server first, then: novavpn-admin provision USERNAME)")
        elif args.cmd == "list-users":
            for u in core.list_users():
                print(f"{u['username']:<20} {'ACTIVE ' if u['active'] else 'DISABLED'}  {u['email']:<28} {','.join(u['countries']) or '-'}")
        elif args.cmd == "disable":
            r = core.set_active(core.user_id_of(args.username), False); print("Member disabled."); _show_results("revoke", r["revocation"])
        elif args.cmd == "enable":
            r = core.set_active(core.user_id_of(args.username), True); print("Member enabled."); _show_results("VPN keys", r["provisioning"])
        elif args.cmd == "provision":
            _show_results("VPN keys", core.provision_user(core.user_id_of(args.username)))
        elif args.cmd == "reset-password":
            print("New temporary password (shown only now):\n  " + core.reset_password(core.user_id_of(args.username)))
        elif args.cmd == "delete":
            if not args.yes and input(f"Delete {args.username} and revoke all their keys? type yes: ").strip() != "yes":
                print("Cancelled."); return 1
            r = core.delete_user(core.user_id_of(args.username)); print("Member deleted."); _show_results("revoke", r["revocation"])
        elif args.cmd == "set-server":
            core.set_node(args.country, args.host, args.port); print(f"Saved {args.country.lower()} = {args.host}")
        elif args.cmd == "servers":
            for s in core.nodes_health():
                state = "OK" if s["ok"] else "PROBLEM"
                extra = f"peers={s['peers']}" if s["ok"] else s.get("detail", "")
                print(f"{s['name']:<12} {s['host'] or '-':<18} {state:<8} {extra}")
        elif args.cmd == "locations":
            for l in core.location_table():
                print(f"{l['code']:<28} {l['name']:<28} {l['server']}")
        elif args.cmd == "provision-all":
            for user, res in core.provision_all().items():
                print(user); _show_results("VPN keys", res)
        elif args.cmd == "retry-revocations":
            print(core.retry_revocations())
        elif args.cmd == "summary":
            for k, v in core.summary().items():
                print(f"{k}: {v}")
    except core.CoreError as exc:
        print("Error:", exc.message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
