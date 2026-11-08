"""NovaVPN control-plane logic (no web framework in here, so it can be tested and driven from the CLI)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from . import provision

DB_PATH = Path(os.environ.get("NOVAVPN_DB", "/var/lib/novavpn-control/control.sqlite3"))
JWT_SECRET = os.environ.get("NOVAVPN_JWT_SECRET", "")
FERNET_KEY = os.environ.get("NOVAVPN_FERNET_KEY", "")
TOKEN_TTL = int(os.environ.get("NOVAVPN_TOKEN_TTL", "28800"))

# Five real VPN servers (one per country).
COUNTRIES = [
    {"code": "au", "name": "Australia", "flag": "🇦🇺", "region": "Oceania"},
    {"code": "ar", "name": "Argentina", "flag": "🇦🇷", "region": "South America"},
    {"code": "mx", "name": "Mexico", "flag": "🇲🇽", "region": "North America"},
    {"code": "br", "name": "Brazil", "flag": "🇧🇷", "region": "South America"},
    {"code": "nz", "name": "New Zealand", "flag": "🇳🇿", "region": "Oceania"},
]

# Twenty selectable labels. Each one is served by its country's server (labels, not separate servers).
_CITIES = {
    "au": ["Sydney", "Adelaide", "Brisbane", "Perth"],
    "ar": ["Avenida 9 de Julio", "Avenida Corrientes", "Caminito", "Avenida de Mayo"],
    "mx": ["Mexico City", "Paseo de la Reforma", "Avenida Juárez", "Avenida de los Insurgentes"],
    "br": ["São Paulo", "Rio de Janeiro", "Brasília", "Fortaleza"],
    "nz": ["Wellington", "Auckland", "Christchurch", "Other Major Centers"],
}


def _slug(text: str) -> str:
    import unicodedata
    plain = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return "-".join("".join(c.lower() if c.isalnum() else " " for c in plain).split())


LOCATIONS = [
    {"code": f"{c['code']}-{_slug(city)}", "name": city, "country": c["code"]}
    for c in COUNTRIES for city in _CITIES[c["code"]]
]
COUNTRY_BY_CODE = {c["code"]: c for c in COUNTRIES}
LOCATION_TO_COUNTRY = {loc["code"]: loc["country"] for loc in LOCATIONS}


class CoreError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------- passwords, tokens, encryption ----------
def password_hash(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1, dklen=64, maxmem=128 * 1024 * 1024)
    return base64.urlsafe_b64encode(salt).decode(), base64.urlsafe_b64encode(digest).decode()


def password_ok(password: str, salt_text: str, digest_text: str) -> bool:
    try:
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
        actual = hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1, dklen=64, maxmem=128 * 1024 * 1024)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_token(user_id: int, username: str, token_version: int = 0) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps({"sub": str(user_id), "username": username, "iat": int(time.time()),
                                  "exp": int(time.time()) + TOKEN_TTL, "jti": secrets.token_urlsafe(12),
                                  "ver": token_version}, separators=(",", ":")).encode())
    sig = _b64url(hmac.new(JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def decode_token(token: str) -> dict[str, Any]:
    try:
        header, payload, signature = token.split(".")
        expected = _b64url(hmac.new(JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        claims = json.loads(base64.urlsafe_b64decode((payload + "=" * (-len(payload) % 4)).encode()))
        if int(claims.get("exp", 0)) < int(time.time()):
            raise ValueError("expired")
        return claims
    except Exception as exc:
        raise CoreError("Session expired or invalid. Please sign in again.", 401) from exc


def encrypt_config(config: str) -> str:
    return Fernet(FERNET_KEY.encode()).encrypt(config.encode()).decode()


def decrypt_config(ciphertext: str) -> str:
    try:
        return Fernet(FERNET_KEY.encode()).decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise CoreError("Profile decryption failed; check the server encryption key.", 500) from exc


# ---------- database ----------
def init_db() -> None:
    if len(JWT_SECRET) < 40 or not FERNET_KEY:
        raise RuntimeError("NOVAVPN_JWT_SECRET and NOVAVPN_FERNET_KEY must be configured before startup.")
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            active INTEGER NOT NULL DEFAULT 1,
            must_change_password INTEGER NOT NULL DEFAULT 1,
            token_version INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS nodes (
            code TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            flag TEXT NOT NULL,
            region TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            host TEXT NOT NULL DEFAULT '',
            ssh_port INTEGER NOT NULL DEFAULT 22
        );
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            country_code TEXT NOT NULL REFERENCES nodes(code),
            config_ciphertext TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, country_code)
        );
        CREATE INDEX IF NOT EXISTS idx_profiles_user ON profiles(user_id);
        CREATE TABLE IF NOT EXISTS pending_revocations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            country_code TEXT NOT NULL,
            peer_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_error TEXT NOT NULL DEFAULT '',
            UNIQUE(country_code, peer_name)
        );
        """)
        for c in COUNTRIES:
            conn.execute("INSERT OR IGNORE INTO nodes(code,name,flag,region,active) VALUES(?,?,?,?,1)",
                         (c["code"], c["name"], c["flag"], c["region"]))
        # City slots stay empty (no address) until a city gets its own server; until then its country server is used.
        for loc in LOCATIONS:
            c = COUNTRY_BY_CODE[loc["country"]]
            conn.execute("INSERT OR IGNORE INTO nodes(code,name,flag,region,active) VALUES(?,?,?,?,1)",
                         (loc["code"], loc["name"], c["flag"], c["name"]))


def validate_wireguard_config(config: str) -> None:
    text = config.strip()
    missing = [k for k in ["[Interface]", "[Peer]", "PrivateKey", "PublicKey", "Endpoint", "AllowedIPs"] if k not in text]
    if missing:
        raise CoreError("Incomplete WireGuard profile. Missing: " + ", ".join(missing), 422)
    if "0.0.0.0/0" not in text and "::/0" not in text:
        raise CoreError("The profile must route default traffic through the VPN (AllowedIPs).", 422)


# ---------- customer side ----------
_failures: dict[str, list[float]] = {}
_MAX_FAILS, _WINDOW = 8, 600


def _throttled(key: str) -> bool:
    now = time.time()
    recent = [t for t in _failures.get(key, []) if now - t < _WINDOW]
    _failures[key] = recent
    return len(recent) >= _MAX_FAILS


def authenticate(username: str, password: str) -> dict[str, Any]:
    key = username.strip().lower()
    if _throttled(key):
        raise CoreError("Too many attempts. Please wait ten minutes and try again.", 429)
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=? OR email=?", (username, username)).fetchone()
    if not row or not row["active"] or not password_ok(password, row["password_salt"], row["password_hash"]):
        _failures.setdefault(key, []).append(time.time())
        raise CoreError("Incorrect sign-in details or inactive account.", 401)
    _failures.pop(key, None)
    return {"access_token": make_token(row["id"], row["username"], row["token_version"]), "token_type": "bearer",
            "expires_in": TOKEN_TTL, "username": row["username"], "role": "user",
            "must_change_password": bool(row["must_change_password"])}


def user_from_token(token: str) -> dict[str, Any]:
    claims = decode_token(token)
    with db() as conn:
        row = conn.execute("SELECT id,username,email,active,must_change_password,token_version FROM users WHERE id=?",
                           (claims["sub"],)).fetchone()
    if not row or not row["active"] or int(claims.get("ver", 0)) != int(row["token_version"]):
        raise CoreError("This account is disabled. Contact your provider.", 401)
    return dict(row)


def change_password(user_id: int, current: str, new: str) -> None:
    if len(new) < 12:
        raise CoreError("New password must be at least 12 characters.", 422)
    with db() as conn:
        row = conn.execute("SELECT password_salt,password_hash FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or not password_ok(current, row["password_salt"], row["password_hash"]):
            raise CoreError("Current password is incorrect.", 400)
        salt, digest = password_hash(new)
        conn.execute("UPDATE users SET password_salt=?,password_hash=?,must_change_password=0 WHERE id=?", (salt, digest, user_id))


def list_locations(user_id: int) -> list[dict[str, Any]]:
    """A city uses its own server once one is set up and the member has keys there; otherwise its country server."""
    with db() as conn:
        have = {r["country_code"]: bool(r["active"]) for r in conn.execute(
            "SELECT p.country_code,n.active FROM profiles p JOIN nodes n ON n.code=p.country_code WHERE p.user_id=?", (user_id,)).fetchall()}
    out = []
    for loc in LOCATIONS:
        c = COUNTRY_BY_CODE[loc["country"]]
        out.append({"code": loc["code"], "name": loc["name"], "flag": c["flag"], "region": c["name"],
                    "available": bool(have.get(loc["code"]) or have.get(loc["country"]))})
    return out


def get_profile(user_id: int, location_code: str) -> dict[str, str]:
    code = location_code.lower()
    country = LOCATION_TO_COUNTRY.get(code) or (code if code in COUNTRY_BY_CODE else None)
    if not country:
        raise CoreError("Unknown location.", 404)
    with db() as conn:
        for node_code in ([code] if code != country else []) + [country]:
            row = conn.execute("""SELECT p.config_ciphertext FROM profiles p JOIN nodes n ON n.code=p.country_code
                WHERE p.user_id=? AND p.country_code=? AND n.active=1""", (user_id, node_code)).fetchone()
            if row:
                return {"country_code": country, "country": COUNTRY_BY_CODE[country]["name"],
                        "config": decrypt_config(row["config_ciphertext"])}
    raise CoreError("No active VPN profile is assigned for this location.", 404)


# ---------- provisioning on the five servers ----------
def provision_user(user_id: int) -> list[dict[str, str]]:
    """Create a unique WireGuard peer on every active, connected country server the user does not have yet."""
    with db() as conn:
        nodes = conn.execute("SELECT code,name,host,ssh_port FROM nodes WHERE active=1 AND host<>'' ORDER BY name").fetchall()
        have = {r[0] for r in conn.execute("SELECT country_code FROM profiles WHERE user_id=?", (user_id,)).fetchall()}
    results: list[dict[str, str]] = [{"country": n["code"], "status": "exists"} for n in nodes if n["code"] in have]
    todo = [n for n in nodes if n["code"] not in have]

    def make(n: sqlite3.Row) -> tuple[str, str | None, str]:
        try:
            config = provision.create_peer(n["host"], n["ssh_port"], provision.peer_name(user_id, n["code"]))
            validate_wireguard_config(config)
            return n["code"], config, ""
        except (provision.NodeError, CoreError) as exc:
            return n["code"], None, getattr(exc, "message", str(exc))

    if todo:
        with ThreadPoolExecutor(max_workers=min(5, len(todo))) as pool:
            made = list(pool.map(make, todo))
        with db() as conn:
            for code, config, error in made:
                if config is None:
                    results.append({"country": code, "status": "failed", "detail": error})
                    continue
                conn.execute("""INSERT INTO profiles(user_id,country_code,config_ciphertext,updated_at) VALUES(?,?,?,?)
                    ON CONFLICT(user_id,country_code) DO UPDATE SET config_ciphertext=excluded.config_ciphertext,updated_at=excluded.updated_at""",
                             (user_id, code, encrypt_config(config), utc_now()))
                results.append({"country": code, "status": "created"})
    return results


def revoke_profiles(user_id: int, only_country: str | None = None) -> list[dict[str, str]]:
    """Revoke the user's peers on the servers and drop stored profiles. Unreachable servers are queued for retry."""
    with db() as conn:
        sql = "SELECT p.country_code,n.host,n.ssh_port FROM profiles p JOIN nodes n ON n.code=p.country_code WHERE p.user_id=?"
        args: list[Any] = [user_id]
        if only_country:
            sql += " AND p.country_code=?"
            args.append(only_country)
        rows = conn.execute(sql, args).fetchall()
    results: list[dict[str, str]] = []
    for r in rows:
        name = provision.peer_name(user_id, r["country_code"])
        try:
            if not r["host"]:
                raise provision.NodeError("Server address not set; revoke this peer on the VPS by hand.")
            provision.revoke_peer(r["host"], r["ssh_port"], name)
            results.append({"country": r["country_code"], "status": "revoked"})
        except provision.NodeError as exc:
            with db() as conn:
                conn.execute("INSERT OR IGNORE INTO pending_revocations(country_code,peer_name,created_at,last_error) VALUES(?,?,?,?)",
                             (r["country_code"], name, utc_now(), str(exc)))
            results.append({"country": r["country_code"], "status": "queued", "detail": str(exc)})
    with db() as conn:
        if only_country:
            conn.execute("DELETE FROM profiles WHERE user_id=? AND country_code=?", (user_id, only_country))
        else:
            conn.execute("DELETE FROM profiles WHERE user_id=?", (user_id,))
    return results


# ---------- operator actions (used by the novavpn-admin command line tool) ----------
def user_id_of(username: str) -> int:
    with db() as conn:
        row = conn.execute("SELECT id FROM users WHERE username=? OR email=?", (username, username)).fetchone()
    if not row:
        raise CoreError(f"No member named {username}.", 404)
    return int(row["id"])


def create_user(username: str, email: str, password: str | None = None, auto_provision: bool = True) -> dict[str, Any]:
    import re
    if not re.fullmatch(r"[A-Za-z0-9_.@+-]{3,64}", username):
        raise CoreError("Username: 3-64 letters, digits or _ . @ + -", 422)
    if "@" not in email or "." not in email.split("@")[-1]:
        raise CoreError("Enter a valid email address.", 422)
    if password is not None and len(password) < 12:
        raise CoreError("Password must be at least 12 characters.", 422)
    password = password or secrets.token_urlsafe(15)
    salt, digest = password_hash(password)
    try:
        with db() as conn:
            cur = conn.execute("INSERT INTO users(username,email,password_salt,password_hash,role,active,must_change_password,created_at) VALUES(?,?,?,?,'user',1,1,?)",
                               (username, email, salt, digest, utc_now()))
            uid = int(cur.lastrowid)
    except sqlite3.IntegrityError as exc:
        raise CoreError("Username or email already exists.", 409) from exc
    out: dict[str, Any] = {"id": uid, "username": username, "email": email, "temporary_password": password}
    if auto_provision:
        out["provisioning"] = provision_user(uid)
    return out


def list_users() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("""SELECT u.id,u.username,u.email,u.active,u.created_at,GROUP_CONCAT(p.country_code, ',') AS countries
            FROM users u LEFT JOIN profiles p ON p.user_id=u.id GROUP BY u.id ORDER BY u.created_at""").fetchall()
    return [{"id": r["id"], "username": r["username"], "email": r["email"], "active": bool(r["active"]),
             "created_at": r["created_at"], "countries": sorted((r["countries"] or "").split(",")) if r["countries"] else []} for r in rows]


def set_active(user_id: int, active: bool) -> dict[str, Any]:
    with db() as conn:
        cur = conn.execute("UPDATE users SET active=?,token_version=token_version+1 WHERE id=?", (1 if active else 0, user_id))
    if cur.rowcount == 0:
        raise CoreError("User not found.", 404)
    if active:
        return {"active": True, "provisioning": provision_user(user_id)}
    return {"active": False, "revocation": revoke_profiles(user_id)}


def delete_user(user_id: int) -> dict[str, Any]:
    with db() as conn:
        if not conn.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone():
            raise CoreError("User not found.", 404)
    results = revoke_profiles(user_id)
    with db() as conn:
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    return {"deleted": True, "revocation": results}


def reset_password(user_id: int) -> str:
    temp = secrets.token_urlsafe(16)
    salt, digest = password_hash(temp)
    with db() as conn:
        cur = conn.execute("UPDATE users SET password_salt=?,password_hash=?,must_change_password=1,token_version=token_version+1 WHERE id=?",
                           (salt, digest, user_id))
    if cur.rowcount == 0:
        raise CoreError("User not found.", 404)
    return temp


def set_node(code: str, host: str, port: int = 22) -> None:
    code = code.lower()
    if code not in COUNTRY_BY_CODE and code not in LOCATION_TO_COUNTRY:
        raise CoreError("Unknown code. Use a country (" + ", ".join(COUNTRY_BY_CODE) + ") or a city code from: novavpn-admin locations", 404)
    if not provision.valid_host(host):
        raise CoreError("Server address must be an IP address or hostname.", 422)
    with db() as conn:
        conn.execute("UPDATE nodes SET host=?,ssh_port=? WHERE code=?", (host, int(port), code))


def set_node_active(code: str, active: bool) -> None:
    with db() as conn:
        cur = conn.execute("UPDATE nodes SET active=? WHERE code=?", (1 if active else 0, code.lower()))
    if cur.rowcount == 0:
        raise CoreError("Unknown code.", 404)


def nodes_health() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("SELECT code,name,host,ssh_port,active FROM nodes WHERE host<>'' OR length(code)=2 ORDER BY code").fetchall()

    def check(r: sqlite3.Row) -> dict[str, Any]:
        base = {"code": r["code"], "name": r["name"], "host": r["host"], "enabled": bool(r["active"])}
        if not r["host"]:
            return base | {"ok": False, "detail": "Server address not set."}
        try:
            info = provision.node_status(r["host"], r["ssh_port"])
            last = int(info.get("last_handshake", 0) or 0)
            return base | {"ok": True, "peers": int(info.get("peers", 0) or 0),
                           "seconds_since_last_handshake": (int(time.time()) - last) if last else None}
        except provision.NodeError as exc:
            return base | {"ok": False, "detail": str(exc)}

    with ThreadPoolExecutor(max_workers=5) as pool:
        return list(pool.map(check, rows))


def retry_revocations() -> dict[str, int]:
    with db() as conn:
        rows = conn.execute("""SELECT r.id,r.peer_name,n.host,n.ssh_port FROM pending_revocations r
            LEFT JOIN nodes n ON n.code=r.country_code""").fetchall()
    done = 0
    for r in rows:
        try:
            if not r["host"]:
                raise provision.NodeError("Server address not set.")
            provision.revoke_peer(r["host"], r["ssh_port"], r["peer_name"])
            with db() as conn:
                conn.execute("DELETE FROM pending_revocations WHERE id=?", (r["id"],))
            done += 1
        except provision.NodeError as exc:
            with db() as conn:
                conn.execute("UPDATE pending_revocations SET last_error=? WHERE id=?", (str(exc), r["id"]))
    return {"revoked": done, "still_pending": len(rows) - done}


def provision_all() -> dict[str, list[dict[str, str]]]:
    """Give every active member keys on any server they do not have yet (run after adding a server)."""
    with db() as conn:
        users = conn.execute("SELECT id,username FROM users WHERE active=1 ORDER BY id").fetchall()
    return {u["username"]: provision_user(u["id"]) for u in users}


def location_table() -> list[dict[str, str]]:
    with db() as conn:
        hosts = {r["code"]: r["host"] for r in conn.execute("SELECT code,host FROM nodes").fetchall()}
    return [{"code": l["code"], "name": l["name"], "country": l["country"],
             "server": ("own: " + hosts[l["code"]]) if hosts.get(l["code"]) else ("country: " + (hosts.get(l["country"]) or "not set"))}
            for l in LOCATIONS]


def summary() -> dict[str, int]:
    with db() as conn:
        return {
            "active_members": conn.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0],
            "total_members": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "profiles": conn.execute("SELECT COUNT(*) FROM profiles").fetchone()[0],
            "servers_with_address": conn.execute("SELECT COUNT(*) FROM nodes WHERE host<>''").fetchone()[0],
            "pending_revocations": conn.execute("SELECT COUNT(*) FROM pending_revocations").fetchone()[0],
        }
