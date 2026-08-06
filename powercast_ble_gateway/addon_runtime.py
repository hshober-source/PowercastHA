from __future__ import annotations

import json
import os
import re
import secrets
import signal
import subprocess
import threading
import time
from copy import deepcopy
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

from ha_bridge import HomeAssistantBridge


APP_DIR = Path(os.getenv("ADDON_APP_DIR", "/app"))
DATA_DIR = Path(os.getenv("ADDON_DATA_DIR", "/data"))
OPTIONS_PATH = DATA_DIR / "options.json"
BLE_CONFIG_PATH = DATA_DIR / "ble-hub.yml"
ADOPTED_TAGS_PATH = DATA_DIR / "adopted-tags.json"
SEEN_TAGS_PATH = DATA_DIR / "seen-tags.json"
INDEX_PATH = APP_DIR / "ui" / "index.html"
BLE_HUB_SCRIPT = APP_DIR / "vendor" / "python_ble_hub" / "ble_mqtt_hub.py"
BLE_HUB_SOURCE_PATH = APP_DIR / "vendor" / "python_ble_hub" / "SOURCE.json"
SENSOR_TYPE_REGISTRY_PATH = APP_DIR / "vendor" / "python_ble_hub" / "sensor_types.json"
HOST = "0.0.0.0"
PORT = int(os.getenv("POWERCAST_BLE_ADDON_PORT", "8091"))
SESSION_SECRET = os.getenv("POWERCAST_BLE_ADDON_SESSION_SECRET") or secrets.token_hex(32)
COOKIE_NAME = "powercast_ble_addon"

DEFAULT_OPTIONS: dict[str, Any] = {
    "gateway_mac": "",
    "mqtt_host": "core-mosquitto",
    "mqtt_port": 1883,
    "mqtt_username": "",
    "mqtt_password": "",
    "mqtt_topic": "/sensors/observations/{gateway_mac}",
    "mqtt_client_id": "ha-powercast-ble-hub",
    "mqtt_subscribe_topic": "/sensors/observations/#",
    "ha_discovery_prefix": "homeassistant",
    "ha_state_topic_base": "blet/homeassistant/ble",
    "scanning_mode": "active",
    "publish_interval_seconds": 0,
    "name_allowlist": ["BLET", "PCBLE", "STBLE"],
    "start_scanner_on_boot": True,
}

DEFAULT_TAG: dict[str, Any] = {
    "ble_mac": "",
    "display_name": "",
    "location": "",
    "sensor_type": "",
    "notes": "",
    "is_stationary": False,
    "key_hex": "",
    "claimed": True,
}

SCANNER_PROCESS: subprocess.Popen[str] | None = None
# Scanner lifecycle methods return a status snapshot while the lifecycle lock is
# held, so this must be re-entrant to avoid self-deadlocking during startup.
SCANNER_LOCK = threading.RLock()
STARTED_AT = time.time()
BRIDGE: HomeAssistantBridge | None = None
SEEN_TAGS_LAST_WRITE: dict[str, float] = {}


def canonical_mac(value: Any) -> str:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    if len(cleaned) != 12:
        raise ValueError("ble_mac must contain exactly 12 hex characters")
    return cleaned.upper()


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def ensure_data_files() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not OPTIONS_PATH.exists():
        OPTIONS_PATH.write_text(json.dumps(DEFAULT_OPTIONS, indent=2), encoding="utf-8")
    if not ADOPTED_TAGS_PATH.exists():
        ADOPTED_TAGS_PATH.write_text("[]\n", encoding="utf-8")
    if not SEEN_TAGS_PATH.exists():
        SEEN_TAGS_PATH.write_text("[]\n", encoding="utf-8")
    os.chmod(OPTIONS_PATH, 0o600)
    os.chmod(ADOPTED_TAGS_PATH, 0o600)
    os.chmod(SEEN_TAGS_PATH, 0o600)


def load_options() -> dict[str, Any]:
    ensure_data_files()
    try:
        payload = json.loads(OPTIONS_PATH.read_text(encoding="utf-8") or "{}")
    except json.JSONDecodeError:
        payload = {}
    merged = deep_merge(DEFAULT_OPTIONS, payload if isinstance(payload, dict) else {})
    merged["name_allowlist"] = normalize_text_list(merged.get("name_allowlist"))
    return merged


def save_options(payload: dict[str, Any]) -> dict[str, Any]:
    current = load_options()
    merged = deep_merge(current, payload)
    merged["name_allowlist"] = normalize_text_list(merged.get("name_allowlist")) or ["BLET", "PCBLE", "STBLE"]
    OPTIONS_PATH.write_text(json.dumps(merged, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(OPTIONS_PATH, 0o600)
    write_ble_config(merged)
    if BRIDGE is not None:
        BRIDGE.restart()
    return merged


def public_options() -> dict[str, Any]:
    """Return settings without exposing the MQTT password through the web API."""
    options = load_options()
    options["mqtt_password_configured"] = bool(options.get("mqtt_password"))
    options["mqtt_password"] = ""
    return options


def load_tags() -> list[dict[str, Any]]:
    ensure_data_files()
    try:
        payload = json.loads(ADOPTED_TAGS_PATH.read_text(encoding="utf-8") or "[]")
    except json.JSONDecodeError:
        payload = []
    rows: list[dict[str, Any]] = []
    for item in payload if isinstance(payload, list) else []:
        if not isinstance(item, dict):
            continue
        row = deepcopy(DEFAULT_TAG)
        row.update(item)
        try:
            row["ble_mac"] = canonical_mac(row.get("ble_mac"))
        except ValueError:
            continue
        row["claimed"] = bool(row.get("claimed", True))
        row["is_stationary"] = bool(row.get("is_stationary", False))
        rows.append(row)
    return sorted(rows, key=lambda item: item["ble_mac"])


def save_tags(rows: list[dict[str, Any]]) -> None:
    ADOPTED_TAGS_PATH.write_text(json.dumps(rows, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(ADOPTED_TAGS_PATH, 0o600)


def upsert_tag(payload: dict[str, Any]) -> dict[str, Any]:
    row = deepcopy(DEFAULT_TAG)
    row.update(payload)
    row["ble_mac"] = canonical_mac(row.get("ble_mac"))
    existing = next((item for item in load_tags() if item["ble_mac"] == row["ble_mac"]), None)
    row["display_name"] = str(row.get("display_name") or "").strip()
    row["location"] = str(row.get("location") or "").strip()
    row["sensor_type"] = str(row.get("sensor_type") or "").strip()
    row["notes"] = str(row.get("notes") or "").strip()
    row["key_hex"] = str(row.get("key_hex") or "").strip().upper()
    if not row["key_hex"] and existing is not None:
        row["key_hex"] = str(existing.get("key_hex") or "")
    if row["key_hex"] and (not re.fullmatch(r"[0-9A-F]{32}", row["key_hex"])):
        raise ValueError("key_hex must be exactly 32 hexadecimal characters")
    row["claimed"] = bool(row.get("claimed", True))
    row["is_stationary"] = bool(row.get("is_stationary", False))
    rows = [item for item in load_tags() if item["ble_mac"] != row["ble_mac"]]
    rows.append(row)
    rows.sort(key=lambda item: item["ble_mac"])
    save_tags(rows)
    return row


def load_seen_tags() -> list[dict[str, Any]]:
    ensure_data_files()
    try:
        payload = json.loads(SEEN_TAGS_PATH.read_text(encoding="utf-8") or "[]")
    except json.JSONDecodeError:
        payload = []
    rows = [dict(item) for item in payload if isinstance(item, dict) and str(item.get("ble_mac") or "")]
    claimed = {row["ble_mac"] for row in load_tags() if bool(row.get("claimed", True))}
    for row in rows:
        row["adopted"] = row.get("ble_mac") in claimed
    return sorted(rows, key=lambda row: str(row.get("last_seen") or ""), reverse=True)


def record_seen_tag(payload: dict[str, Any]) -> None:
    """Persist a bounded discovery list without blocking HTTP status reads."""
    try:
        mac = canonical_mac(payload.get("ble_mac"))
    except ValueError:
        return
    now = time.monotonic()
    if now - SEEN_TAGS_LAST_WRITE.get(mac, 0) < 5:
        return
    SEEN_TAGS_LAST_WRITE[mac] = now
    try:
        rows = json.loads(SEEN_TAGS_PATH.read_text(encoding="utf-8") or "[]")
    except (OSError, json.JSONDecodeError):
        rows = []
    rows = [dict(row) for row in rows if isinstance(row, dict)]
    existing = next((row for row in rows if row.get("ble_mac") == mac), None)
    if existing is None:
        existing = {"ble_mac": mac, "first_seen": str(payload.get("last_seen") or "")}
        rows.append(existing)
    for key in ("ble_name", "sensor_type_hint", "last_rssi", "last_gateway_mac", "last_seen"):
        value = payload.get(key)
        if value not in (None, ""):
            existing[key] = value
    existing["observations"] = int(existing.get("observations") or 0) + 1
    rows.sort(key=lambda row: str(row.get("last_seen") or ""), reverse=True)
    temporary = SEEN_TAGS_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(rows[:5000], indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(SEEN_TAGS_PATH)


def public_tag(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result.pop("key_hex", None)
    result["has_key"] = bool(row.get("key_hex"))
    return result


def delete_tag(ble_mac: str) -> bool:
    mac = canonical_mac(ble_mac)
    rows = load_tags()
    filtered = [item for item in rows if item["ble_mac"] != mac]
    if len(filtered) == len(rows):
        return False
    save_tags(filtered)
    return True


def normalize_text_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def write_ble_config(options: dict[str, Any] | None = None) -> None:
    options = options or load_options()
    gateway_mac = str(options.get("gateway_mac") or "").strip().upper() or "HA0000000001"
    payload = {
        "hub": {
            "gateway_mac": gateway_mac,
            "publish_interval_seconds": int(options.get("publish_interval_seconds", 0) or 0),
        },
        "mqtt": {
            "host": str(options.get("mqtt_host") or "core-mosquitto"),
            "port": int(options.get("mqtt_port") or 1883),
            "username": str(options.get("mqtt_username") or "") or None,
            "password": str(options.get("mqtt_password") or "") or None,
            "topic": str(options.get("mqtt_topic") or "/sensors/observations/{gateway_mac}"),
            "client_id": str(options.get("mqtt_client_id") or "ha-powercast-ble-hub"),
        },
        "ble": {
            "scanning_mode": str(options.get("scanning_mode") or "active"),
            "name_allowlist": normalize_text_list(options.get("name_allowlist")) or ["BLET", "PCBLE", "STBLE"],
            "mac_allowlist": [],
        },
    }
    BLE_CONFIG_PATH.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=False), encoding="utf-8")


def scanner_command() -> list[str]:
    return [
        "python",
        str(BLE_HUB_SCRIPT),
        "--config",
        str(BLE_CONFIG_PATH),
    ]


def scanner_source_identity() -> dict[str, Any]:
    try:
        payload = json.loads(BLE_HUB_SOURCE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"canonical_source": "unknown", "verified": False}
    if not isinstance(payload, dict):
        return {"canonical_source": "unknown", "verified": False}
    return {
        "canonical_source": str(payload.get("canonical_source") or "unknown"),
        "git_revision": payload.get("git_revision"),
        "generated_at": payload.get("generated_at"),
        "verified": bool(payload.get("files")),
    }


def sensor_type_registry() -> list[dict[str, Any]]:
    try:
        payload = json.loads(SENSOR_TYPE_REGISTRY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    rows = payload.get("types") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def scanner_status() -> dict[str, Any]:
    with SCANNER_LOCK:
        process = SCANNER_PROCESS
        running = process is not None and process.poll() is None
        return {
            "running": running,
            "pid": process.pid if running and process else None,
            "returncode": None if running or process is None else process.poll(),
            "command": scanner_command(),
            "source": scanner_source_identity(),
        }


def bridge_status() -> dict[str, Any]:
    return BRIDGE.status() if BRIDGE is not None else {"running": False, "connected": False}


def start_scanner() -> dict[str, Any]:
    global SCANNER_PROCESS
    with SCANNER_LOCK:
        if SCANNER_PROCESS is not None and SCANNER_PROCESS.poll() is None:
            return scanner_status()
        write_ble_config()
        SCANNER_PROCESS = subprocess.Popen(
            scanner_command(),
            cwd=str(APP_DIR / "vendor" / "python_ble_hub"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return scanner_status()


def stop_scanner() -> dict[str, Any]:
    global SCANNER_PROCESS
    with SCANNER_LOCK:
        if SCANNER_PROCESS is None or SCANNER_PROCESS.poll() is not None:
            SCANNER_PROCESS = None
            return scanner_status()
        SCANNER_PROCESS.terminate()
        try:
            SCANNER_PROCESS.wait(timeout=10)
        except subprocess.TimeoutExpired:
            SCANNER_PROCESS.kill()
            SCANNER_PROCESS.wait(timeout=5)
        SCANNER_PROCESS = None
        return scanner_status()


def restart_scanner() -> dict[str, Any]:
    stop_scanner()
    return start_scanner()


def read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        return {}
    payload = handler.rfile.read(length)
    return json.loads(payload.decode("utf-8"))


def render_index() -> str:
    return INDEX_PATH.read_text(encoding="utf-8")


def session_cookie() -> str:
    issued_at = str(int(time.time()))
    digest = secrets.token_hex(16)
    token = json.dumps({"iat": issued_at, "nonce": digest}, separators=(",", ":"))
    return token


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str, status: int = 200) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in {"/", "/app"}:
            self.send_html(render_index())
            return
        if self.path == "/health":
            self.send_json({"ok": True, "uptime_seconds": int(time.time() - STARTED_AT)})
            return
        if self.path == "/api/status":
            self.send_json(
                {
                    "scanner": scanner_status(),
                    "bridge": bridge_status(),
                    "options": public_options(),
                    "adopted_tags": [public_tag(row) for row in load_tags()],
                    "sensor_types": sensor_type_registry(),
                    "registry_path": str(ADOPTED_TAGS_PATH),
                    "config_path": str(BLE_CONFIG_PATH),
                }
            )
            return
        if self.path == "/api/options":
            self.send_json(public_options())
            return
        if self.path == "/api/tags":
            rows = load_tags()
            self.send_json({"items": [public_tag(row) for row in rows], "count": len(rows)})
            return
        if self.path == "/api/seen-tags":
            rows = load_seen_tags()
            self.send_json({"items": rows, "count": len(rows)})
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.path == "/api/options":
            try:
                updated = save_options(read_json(self))
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
                return
            self.send_json(updated)
            return
        if self.path == "/api/tags":
            try:
                row = upsert_tag(read_json(self))
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
                return
            self.send_json({"status": "saved", "item": public_tag(row)})
            return
        if self.path == "/api/scanner":
            payload = read_json(self)
            action = str(payload.get("action") or "").strip().lower()
            try:
                if action == "start":
                    status = start_scanner()
                elif action == "stop":
                    status = stop_scanner()
                elif action == "restart":
                    status = restart_scanner()
                else:
                    raise ValueError("action must be start, stop, or restart")
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
                return
            self.send_json({"status": status})
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        if self.path.startswith("/api/tags/"):
            ble_mac = self.path.rsplit("/", 1)[-1]
            try:
                deleted = delete_tag(ble_mac)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
                return
            if not deleted:
                self.send_json({"error": "not found"}, status=404)
                return
            self.send_json({"status": "deleted", "ble_mac": canonical_mac(ble_mac)})
            return
        self.send_error(HTTPStatus.NOT_FOUND)


def main() -> None:
    global BRIDGE
    ensure_data_files()
    write_ble_config()
    BRIDGE = HomeAssistantBridge(load_options, load_tags, sensor_type_registry, record_seen_tag)
    BRIDGE.start()
    if load_options().get("start_scanner_on_boot", True):
        start_scanner()

    def shutdown_handler(signum: int, _frame: Any) -> None:
        stop_scanner()
        if BRIDGE is not None:
            BRIDGE.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Powercast BLE HA add-on listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
