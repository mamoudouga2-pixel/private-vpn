"""Automatic peer provisioning on country nodes over SSH.

The control plane never gets a shell on a node: the node authorises its key with a forced command
(novavpn-node-ctl) that only understands: add <name>, revoke <name>, status.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

SSH_DIR = Path(os.environ.get("NOVAVPN_SSH_DIR", "/var/lib/novavpn-control/ssh"))
SSH_BIN = os.environ.get("NOVAVPN_SSH_BIN", "ssh")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")


class NodeError(Exception):
    pass


def peer_name(user_id: int, country_code: str) -> str:
    return f"u{int(user_id):05d}_{country_code.lower()}"


def valid_host(host: str) -> bool:
    return bool(HOST_RE.match(host or ""))


def _run(host: str, port: int, remote: str, timeout: int = 40) -> str:
    if not valid_host(host):
        raise NodeError("Node address is not set or invalid.")
    if not (1 <= int(port) <= 65535):
        raise NodeError("Invalid SSH port.")
    key = SSH_DIR / "id_ed25519"
    args = [
        SSH_BIN, "-i", str(key), "-p", str(int(port)),
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={SSH_DIR / 'known_hosts'}",
        "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3",
        f"root@{host}", remote,
    ]
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise NodeError("Node did not answer in time.") from exc
    except FileNotFoundError as exc:
        raise NodeError("ssh is not installed on the control-plane server.") from exc
    if done.returncode != 0:
        # Do not return stderr verbatim to API clients; it can contain host details.
        raise NodeError(f"Node command failed (exit {done.returncode}).")
    return done.stdout


def create_peer(host: str, port: int, name: str) -> str:
    if not NAME_RE.match(name):
        raise NodeError("Invalid peer name.")
    config = _run(host, port, f"add {name}")
    if "[Interface]" not in config or "PrivateKey" not in config:
        raise NodeError("Node returned an unexpected profile.")
    return config.strip()


def revoke_peer(host: str, port: int, name: str) -> None:
    if not NAME_RE.match(name):
        raise NodeError("Invalid peer name.")
    out = _run(host, port, f"revoke {name}")
    if "revoked" not in out:
        raise NodeError("Node did not confirm revoke.")


def node_status(host: str, port: int) -> dict[str, int | str]:
    out = _run(host, port, "status", timeout=20)
    info: dict[str, int | str] = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = int(v) if v.strip().isdigit() else v.strip()
    if info.get("wg") != "up":
        raise NodeError("WireGuard is not running on the node.")
    return info
