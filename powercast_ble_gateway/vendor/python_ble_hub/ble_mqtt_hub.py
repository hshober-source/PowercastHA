from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG = {
    "hub": {
        "gateway_mac": None,
        "publish_interval_seconds": 10,
        "min_rssi": None,
        # Re-create the BLE scanner periodically. BlueZ adapters can remain
        # connected while silently ceasing to deliver advertisement callbacks.
        "scanner_restart_seconds": 1800,
        "scanner_retry_seconds": 15,
        "scanner_recovery_command_timeout_seconds": 20,
    },
    "mqtt": {
        "host": "core-mosquitto",
        "port": 1883,
        "topic": "/sensors/observations/{gateway_mac}",
        "client_id": "python-ble-hub-01",
        "username": None,
        "password": None,
        "tls": False,
    },
    "ble": {
        "scanning_mode": "active",
        "mac_allowlist": [],
        "name_allowlist": ["BLET", "PCBLE", "STBLE", "W7RF"],
    },
}


@dataclass
class Observation:
    timestamp_ms: int
    mac: str
    rssi: int | None
    adv_data: str
    name: str | None


DEFAULT_ALLOWED_NAMES = {"BLET", "PCBLE", "STBLE", "W7RF"}
POWERCAST_COMPANY_ID = 0x02D3
W7RF_COMPANY_ID = 0xFFFF
W7RF_MAGIC = b"W7"


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return DEFAULT_CONFIG
    with path.open("r", encoding="utf-8") as config_file:
        return deep_merge(DEFAULT_CONFIG, yaml.safe_load(config_file) or {})


def canonical_mac(value: str | int | None) -> str:
    if value is None:
        value = uuid.getnode()
    if isinstance(value, int):
        return f"{value:012X}"
    return "".join(ch for ch in str(value).upper() if ch in "0123456789ABCDEF")


def log_now(message: str) -> None:
    print(f"{datetime.now(UTC).isoformat()} {message}")


def ad_structure(field_type: int, payload: bytes) -> bytes:
    if not payload:
        return b""
    length = len(payload) + 1
    if length > 255:
        payload = payload[:254]
        length = 255
    return bytes([length, field_type]) + payload


def reconstruct_adv_data(name: str | None, manufacturer_data: dict[int, bytes]) -> str:
    """Build BLE AD structures from fields exposed by Bleak.

    Bleak does not expose the exact raw advertisement packet on every platform.
    For Powercast BLET packets, local name + manufacturer data reconstructs the
    byte layout used by the ingester decoder.
    """
    payload = bytearray()
    if name:
        payload.extend(ad_structure(0x09, name.encode("utf-8", errors="ignore")))
    for company_id, data in sorted(manufacturer_data.items()):
        payload.extend(ad_structure(0xFF, int(company_id).to_bytes(2, "little") + bytes(data)))
    return payload.hex()


def is_allowed_name(name: str | None, allowed_names: set[str]) -> bool:
    return name in allowed_names


def is_w7rf_manufacturer_data(manufacturer_data: dict[int, bytes]) -> bool:
    data = manufacturer_data.get(W7RF_COMPANY_ID)
    return bool(data and len(data) >= 10 and bytes(data[:2]) == W7RF_MAGIC)


def is_powercast_encrypted_source(manufacturer_data: dict[int, bytes]) -> bool:
    """Recognize the approved 000A encrypted body independent of local name."""
    data = manufacturer_data.get(POWERCAST_COMPANY_ID)
    return bool(data and len(data) == 13)


def is_powercast_encrypted_adv_data(adv_data: str) -> bool:
    """Recognize the same approved source after reconstructing BLE AD fields."""
    try:
        payload = bytes.fromhex(adv_data)
    except (TypeError, ValueError):
        return False
    index = 0
    while index < len(payload):
        length = payload[index]
        if length == 0:
            break
        end = index + 1 + length
        if end > len(payload) or length < 3:
            return False
        if payload[index + 1] == 0xFF:
            value = payload[index + 2:end]
            if value[:2] == POWERCAST_COMPANY_ID.to_bytes(2, "little") and len(value[2:]) == 13:
                return True
        index = end
    return False


def resolved_advertisement_name(name: str | None, manufacturer_data: dict[int, bytes]) -> str | None:
    if is_w7rf_manufacturer_data(manufacturer_data):
        return "W7RF"
    if is_powercast_encrypted_source(manufacturer_data) and name not in {"PCBLE", "STBLE"}:
        return "PCBLE"
    return name


def allowed_observations(observations: list[Observation], allowed_names: set[str]) -> list[Observation]:
    return [
        observation
        for observation in observations
        if observation.adv_data
        and (is_allowed_name(observation.name, allowed_names) or is_powercast_encrypted_adv_data(observation.adv_data))
    ]


def make_mqtt_client(config: dict[str, Any]) -> mqtt.Client:
    import paho.mqtt.client as mqtt

    mqtt_config = config["mqtt"]
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=mqtt_config["client_id"])
    if mqtt_config.get("username"):
        client.username_pw_set(mqtt_config["username"], mqtt_config.get("password"))
    if mqtt_config.get("tls"):
        client.tls_set(cert_reqs=ssl.CERT_REQUIRED)
    client.connect(mqtt_config["host"], int(mqtt_config["port"]), keepalive=60)
    client.loop_start()
    return client


def make_payload(config: dict[str, Any], observations: list[Observation], msg_id: int) -> dict[str, Any]:
    gateway_mac = canonical_mac(config["hub"].get("gateway_mac"))
    allowed_names = configured_allowed_names(config)
    filtered_observations = allowed_observations(observations, allowed_names)
    return {
        "msg_id": msg_id,
        "device_info": {"mac": gateway_mac},
        "data": [
            {
                "timestamp": observation.timestamp_ms,
                "adv_data": observation.adv_data,
                "rssi": observation.rssi,
                "mac": observation.mac,
                "type": "python-ble",
                "ble_name": observation.name,
            }
            for observation in filtered_observations
        ],
    }


def fake_observations() -> list[Observation]:
    now_ms = int(time.time() * 1000)
    return [
        Observation(
            timestamp_ms=now_ms,
            mac="D029D3B4CC1A",
            rssi=-64,
            adv_data="0509424c455409ffd30261df0a625211",
            name="BLET",
        )
    ]


def configured_allowed_names(config: dict[str, Any]) -> set[str]:
    names = {str(name) for name in config["ble"].get("name_allowlist", []) if str(name)}
    return names or set(DEFAULT_ALLOWED_NAMES)


def publish_topic(config: dict[str, Any]) -> str:
    gateway_mac = canonical_mac(config["hub"].get("gateway_mac"))
    topic_template = str(config["mqtt"].get("topic") or "/sensors/observations/{gateway_mac}")
    if "{gateway_mac}" in topic_template:
        return topic_template.format(gateway_mac=gateway_mac)
    return topic_template.rstrip("/") + f"/{gateway_mac}"


async def run_hub(config: dict[str, Any], dry_run: bool = False, fake_once: bool = False) -> None:
    topic = publish_topic(config)
    publish_interval = int(config["hub"]["publish_interval_seconds"])
    min_rssi = config["hub"].get("min_rssi")
    mac_allowlist = {canonical_mac(mac) for mac in config["ble"].get("mac_allowlist", [])}
    allowed_names = configured_allowed_names(config)
    observations: dict[str, Observation] = {}
    msg_id = 0

    client = None if dry_run else make_mqtt_client(config)

    def seen(device: Any, advertisement_data: Any) -> None:
        mac = canonical_mac(getattr(device, "address", None))
        name = advertisement_data.local_name or getattr(device, "name", None)
        rssi = advertisement_data.rssi
        if mac_allowlist and mac not in mac_allowlist:
            return
        manufacturer_data = advertisement_data.manufacturer_data or {}
        is_w7rf = is_w7rf_manufacturer_data(manufacturer_data)
        is_powercast_encrypted = is_powercast_encrypted_source(manufacturer_data)
        if not is_allowed_name(name, allowed_names) and not is_w7rf and not is_powercast_encrypted:
            return
        if min_rssi is not None and rssi is not None and rssi < int(min_rssi):
            return

        adv_name = resolved_advertisement_name(name, manufacturer_data)
        adv_data = reconstruct_adv_data(adv_name, manufacturer_data)
        if not adv_data:
            return
        observations[mac] = Observation(
            timestamp_ms=int(time.time() * 1000),
            mac=mac,
            rssi=rssi,
            adv_data=adv_data,
            name=adv_name,
        )

    if fake_once:
        payload = make_payload(config, fake_observations(), msg_id)
        print(json.dumps(payload, indent=2))
        if client:
            client.publish(topic, json.dumps(payload, separators=(",", ":")), qos=1)
        return

    print(f"Scanning as gateway {canonical_mac(config['hub'].get('gateway_mac'))}")
    print(f"Publishing to mqtt://{config['mqtt']['host']}:{config['mqtt']['port']}{topic}")
    from bleak import BleakScanner

    scanner_restart_seconds = max(0, int(config["hub"].get("scanner_restart_seconds", 1800)))
    scanner_retry_seconds = max(1, int(config["hub"].get("scanner_retry_seconds", 15)))
    scanner_recovery_timeout = max(5, int(config["hub"].get("scanner_recovery_command_timeout_seconds", 20)))

    async def run_recovery_command(*args: str) -> None:
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=scanner_recovery_timeout)
        except asyncio.TimeoutError:
            log_now(f"scanner recovery command timed out: {' '.join(args)}")
            return
        except FileNotFoundError:
            log_now(f"scanner recovery command missing: {' '.join(args)}")
            return
        output = (stdout or b"").decode(errors="ignore").strip()
        error_output = (stderr or b"").decode(errors="ignore").strip()
        if process.returncode != 0:
            detail = error_output or output or f"exit {process.returncode}"
            log_now(f"scanner recovery command failed: {' '.join(args)} :: {detail}")
        elif output:
            log_now(f"scanner recovery command output: {' '.join(args)} :: {output}")

    async def stop_scanner(scanner: Any) -> None:
        try:
            await scanner.stop()
        except Exception as error:
            log_now(f"BLE scanner stop ignored during recovery: {error!r}")

    async def start_scanner() -> Any:
        scanner = BleakScanner(seen, scanning_mode=config["ble"].get("scanning_mode", "active"))
        await scanner.start()
        return scanner

    async def bounce_bluetooth_stack() -> None:
        log_now("BLE scanner entering hard recovery: cycling bluetooth adapter")
        await run_recovery_command("/usr/bin/pkill", "-f", "bluetoothctl")
        await run_recovery_command("/usr/bin/bluetoothctl", "power", "off")
        await asyncio.sleep(1)
        await run_recovery_command("/usr/sbin/rfkill", "block", "bluetooth")
        await asyncio.sleep(1)
        await run_recovery_command("/usr/sbin/rfkill", "unblock", "bluetooth")
        await asyncio.sleep(2)
        await run_recovery_command("/usr/bin/bluetoothctl", "power", "on")
        await asyncio.sleep(3)
        await run_recovery_command("/usr/bin/hciconfig", "hci0", "reset")
        await asyncio.sleep(2)

    async def recover_scanner(scanner: Any, reason: str) -> tuple[Any, float]:
        log_now(f"recovering BLE scanner: {reason}")
        await stop_scanner(scanner)
        await asyncio.sleep(1)
        try:
            scanner = await start_scanner()
            log_now("BLE scanner soft recovery succeeded")
            return scanner, time.monotonic()
        except Exception as soft_error:
            log_now(f"BLE scanner soft recovery failed: {soft_error!r}")
        await bounce_bluetooth_stack()
        scanner = await start_scanner()
        log_now("BLE scanner hard recovery succeeded")
        return scanner, time.monotonic()

    try:
        while True:
            scanner = await start_scanner()
            scanner_started_at = time.monotonic()
            try:
                while True:
                    await asyncio.sleep(publish_interval)
                    msg_id += 1
                    batch = list(observations.values())
                    observations.clear()
                    payload = make_payload(config, batch, msg_id)
                    if dry_run:
                        print(json.dumps(payload, separators=(",", ":")))
                    elif client:
                        result = client.publish(topic, json.dumps(payload, separators=(",", ":")), qos=1)
                        if result.rc != 0:
                            print(f"{datetime.now(UTC).isoformat()} MQTT publish unavailable (rc={result.rc}); Paho will reconnect")
                        else:
                            print(f"{datetime.now(UTC).isoformat()} published {len(payload['data'])} packet(s)")

                    if scanner_restart_seconds and time.monotonic() - scanner_started_at >= scanner_restart_seconds:
                        scanner, scanner_started_at = await recover_scanner(
                            scanner,
                            f"scheduled scanner refresh after {scanner_restart_seconds}s",
                        )
            except asyncio.CancelledError:
                raise
            except Exception as error:
                log_now(f"BLE scanner failure: {error!r}; retrying in {scanner_retry_seconds}s")
                await asyncio.sleep(scanner_retry_seconds)
                try:
                    scanner, scanner_started_at = await recover_scanner(scanner, str(error))
                except Exception as recovery_error:
                    log_now(f"BLE scanner recovery failed: {recovery_error!r}")
            finally:
                await stop_scanner(scanner)
    finally:
        if client:
            client.loop_stop()
            client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description="BLE scanner that publishes gateway-compatible MQTT payloads.")
    parser.add_argument("--config", default="config.yml", type=Path)
    parser.add_argument("--dry-run", action="store_true", help="Print MQTT payloads instead of publishing.")
    parser.add_argument("--fake-once", action="store_true", help="Emit one known-good BLET test payload and exit.")
    args = parser.parse_args()
    asyncio.run(run_hub(load_config(args.config), dry_run=args.dry_run, fake_once=args.fake_once))


if __name__ == "__main__":
    main()
