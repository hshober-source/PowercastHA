from __future__ import annotations

import json
import logging
import re
import threading
import time
from datetime import UTC, datetime
from typing import Any, Callable

import paho.mqtt.client as mqtt

from vendor import hub_ingester as decoder

LOG = logging.getLogger("powercast_ble.ha_bridge")


def canonical_mac(value: Any) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", value.lower()).strip("_") or "value"


class HomeAssistantBridge:
    """Decode adopted BLE packets locally and publish MQTT Discovery/state."""

    def __init__(self, options_provider: Callable[[], dict[str, Any]], tags_provider: Callable[[], list[dict[str, Any]]], sensor_types_provider: Callable[[], list[dict[str, Any]]], seen_tag_recorder: Callable[[dict[str, Any]], None]) -> None:
        self.options_provider = options_provider
        self.tags_provider = tags_provider
        self.sensor_types_provider = sensor_types_provider
        self.seen_tag_recorder = seen_tag_recorder
        self.client: mqtt.Client | None = None
        self._lock = threading.RLock()
        self._running = False
        self._connected = False
        self._started_at: float | None = None
        self._last_error: str | None = None
        self._last_packet_at: str | None = None
        self._last_decoded_at: str | None = None
        self._packets_seen = self._decoded = self._ignored = self._errors = 0
        self._published_entities: set[str] = set()

    def status(self) -> dict[str, Any]:
        # A status snapshot must never contend with a busy MQTT callback. These
        # scalar reads are safe under CPython's GIL and can be momentarily stale.
        return {"running": self._running, "connected": self._connected, "started_at": self._started_at, "last_error": self._last_error, "last_packet_at": self._last_packet_at, "last_decoded_at": self._last_decoded_at, "packets_seen": self._packets_seen, "decoded": self._decoded, "ignored": self._ignored, "errors": self._errors, "published_entities": len(self._published_entities)}

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self._running:
                return self.status()
            options = self.options_provider()
            client_id = str(options.get("mqtt_client_id") or "ha-powercast-ble").strip() + "-bridge"
            self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, protocol=mqtt.MQTTv311)
            self.client.on_connect = self._on_connect
            self.client.on_disconnect = self._on_disconnect
            self.client.on_message = self._on_message
            try:
                username = str(options.get("mqtt_username") or "").strip()
                if username:
                    self.client.username_pw_set(username, str(options.get("mqtt_password") or ""))
                self.client.connect_async(str(options.get("mqtt_host") or "core-mosquitto"), int(options.get("mqtt_port") or 1883), 45)
                self.client.loop_start()
                self._running, self._started_at, self._last_error = True, time.time(), None
            except Exception as exc:
                self._errors += 1
                self._last_error = f"connect_failed:{exc.__class__.__name__}"
                LOG.exception("Unable to start MQTT bridge")
            return self.status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            client, self.client = self.client, None
            self._running = self._connected = False
        if client is not None:
            try:
                client.disconnect()
                client.loop_stop()
            except Exception:
                LOG.debug("MQTT bridge shutdown encountered an error", exc_info=True)
        return self.status()

    def restart(self) -> dict[str, Any]:
        self.stop()
        return self.start()

    def _on_connect(self, client: mqtt.Client, _userdata: Any, _flags: Any, reason_code: Any, _properties: Any = None) -> None:
        if getattr(reason_code, "is_failure", False):
            with self._lock:
                self._connected = False
                self._last_error = f"mqtt_connect_failed:{reason_code}"
            return
        topic = str(self.options_provider().get("mqtt_subscribe_topic") or "/sensors/observations/#")
        client.subscribe(topic, qos=0)
        with self._lock:
            self._connected, self._last_error = True, None
        LOG.info("Subscribed to raw BLE MQTT topic %s", topic)

    def _on_disconnect(self, _client: mqtt.Client, _userdata: Any, _disconnect_flags: Any, _reason_code: Any, _properties: Any = None) -> None:
        with self._lock:
            self._connected = False

    def _decoder_registry(self) -> dict[str, dict[str, Any]]:
        return {str(row.get("custom_device_id") or "").upper(): row for row in self.sensor_types_provider() if str(row.get("custom_device_id") or "").strip()}

    def _tag_for(self, mac: str) -> dict[str, Any] | None:
        return next((tag for tag in self.tags_provider() if bool(tag.get("claimed", True)) and canonical_mac(tag.get("ble_mac")) == mac), None)

    def _key_for(self, mac: str) -> tuple[list[tuple[str, bytes]], str | None]:
        key_hex = str((self._tag_for(mac) or {}).get("key_hex") or "").strip()
        if not key_hex:
            return [], "tag_key_not_configured"
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            return [], "invalid_tag_key_hex"
        return ([(mac, key)], None) if len(key) == 16 else ([], "invalid_tag_key_length")

    def _decode(self, packet: dict[str, Any], tag: dict[str, Any]) -> dict[str, Any]:
        decoder.sensor_registry = self._decoder_registry
        decoder.pcble_aes_keys = self._key_for
        decoder.decrypt_location = lambda: "edge_server"
        result = decoder.decode_beacon(packet)
        selected, actual = str(tag.get("sensor_type") or "").upper(), str(result.get("custom_device_id") or "").upper()
        if selected and actual and selected != actual:
            raise ValueError("decoded_sensor_type_does_not_match_adopted_type")
        if selected and not actual and selected != "0000":
            raise ValueError("encrypted_packet_was_not_authenticated")
        return result

    @staticmethod
    def _decoded_object(row: dict[str, Any]) -> dict[str, Any]:
        payload = row.get("decoded")
        if isinstance(payload, dict): return payload
        if isinstance(payload, str):
            try:
                value = json.loads(payload)
                return value if isinstance(value, dict) else {}
            except json.JSONDecodeError: pass
        return {}

    def _measurements(self, row: dict[str, Any], tag: dict[str, Any]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        raw = self._decoded_object(row).get("characteristics")
        if isinstance(raw, dict):
            for key, value in raw.items():
                value = value.get("value") if isinstance(value, dict) else value
                if isinstance(value, (int, float, bool)): output[str(key)] = value
        for key in ("temperature_f", "temperature_c", "humidity_percent"):
            if isinstance(row.get(key), (int, float)): output.setdefault(key, round(row[key], 2))
        if not output and str(tag.get("sensor_type") or "").upper() == "0002": output["heartbeat"] = True
        return output

    @staticmethod
    def _unit_for(key: str, registry: dict[str, Any]) -> str | None:
        for item in registry.get("characteristics") or []:
            if str(item.get("characteristic_key") or "") == key: return item.get("unit")
        return {"temperature_f": "degF", "temperature_c": "degC", "humidity_percent": "%", "rssi": "dBm"}.get(key)

    def _publish_discovery(self, mac: str, tag: dict[str, Any], row: dict[str, Any], fields: dict[str, Any]) -> None:
        if self.client is None: return
        options = self.options_provider()
        prefix, state_base = str(options.get("ha_discovery_prefix") or "homeassistant").strip("/"), str(options.get("ha_state_topic_base") or "blet/homeassistant/ble").strip("/")
        state_topic, device_id, friendly = f"{state_base}/{mac}/state", f"powercast_ble_{mac.lower()}", str(tag.get("display_name") or mac)
        registry = self._decoder_registry().get(str(row.get("custom_device_id") or tag.get("sensor_type") or "").upper(), {})
        device = {"identifiers": [device_id], "name": friendly, "manufacturer": "Powercast", "model": str(registry.get("display_name") or row.get("sensor_type") or "BLE tag"), "via_device": str(options.get("gateway_mac") or "powercast_ble_gateway")}
        for key, value in {**fields, "rssi": 0}.items():
            entity_key = f"{mac}_{slug(key)}"
            if entity_key in self._published_entities: continue
            binary, component = isinstance(value, bool), "binary_sensor" if isinstance(value, bool) else "sensor"
            config: dict[str, Any] = {"name": f"{friendly} {key.replace('_', ' ').title()}", "unique_id": f"{device_id}_{slug(key)}", "state_topic": state_topic, "value_template": "{{ value_json.rssi }}" if key == "rssi" else f"{{{{ value_json.measurements.{key} }}}}", "device": device}
            if binary: config.update({"payload_on": True, "payload_off": False})
            else:
                unit = self._unit_for(key, registry)
                if unit: config["unit_of_measurement"] = unit
                if key.startswith("temperature"): config.update({"device_class": "temperature", "state_class": "measurement"})
                elif key == "humidity_percent": config.update({"device_class": "humidity", "state_class": "measurement"})
                elif key == "rssi": config.update({"device_class": "signal_strength", "state_class": "measurement"})
            self.client.publish(f"{prefix}/{component}/{device_id}/{slug(key)}/config", json.dumps(config, separators=(",", ":")), qos=1, retain=True)
            self._published_entities.add(entity_key)

    def _publish_state(self, mac: str, tag: dict[str, Any], packet: dict[str, Any], row: dict[str, Any], fields: dict[str, Any]) -> None:
        if self.client is None: return
        base = str(self.options_provider().get("ha_state_topic_base") or "blet/homeassistant/ble").strip("/")
        state = {"timestamp": packet.get("TimeStamp") or datetime.now(UTC).isoformat(), "ble_mac": mac, "display_name": str(tag.get("display_name") or mac), "sensor_type": row.get("sensor_type") or tag.get("sensor_type"), "custom_device_id": row.get("custom_device_id") or tag.get("sensor_type"), "rssi": packet.get("RSSI"), "gateway_mac": canonical_mac(packet.get("GatewayMAC")), "measurements": fields}
        self.client.publish(f"{base}/{mac}/state", json.dumps(state, separators=(",", ":")), qos=1, retain=True)

    def _record_seen_tag(self, packet: dict[str, Any], mac: str) -> None:
        name = str(packet.get("BLEName") or "").upper().strip()
        allowed = {str(value).upper() for value in self.options_provider().get("name_allowlist") or []}
        if name not in allowed:
            return
        hinted_type = "0000" if name == "BLET" else str(decoder.service_device_id(packet.get("RawData")) or "").upper()
        self.seen_tag_recorder({
            "ble_mac": mac,
            "ble_name": name,
            "sensor_type_hint": hinted_type,
            "last_rssi": packet.get("RSSI"),
            "last_gateway_mac": canonical_mac(packet.get("GatewayMAC")),
            "last_seen": packet.get("TimeStamp") or datetime.now(UTC).isoformat(),
        })

    def _on_message(self, _client: mqtt.Client, _userdata: Any, message: mqtt.MQTTMessage) -> None:
        try: packets = decoder.expand_payload(json.loads(message.payload.decode("utf-8")), message.topic)
        except Exception:
            with self._lock: self._errors += 1; self._last_error = "invalid_mqtt_payload"
            return
        for packet in packets:
            mac = canonical_mac(packet.get("BLEMAC"))
            if not mac: continue
            with self._lock: self._packets_seen += 1; self._last_packet_at = datetime.now(UTC).isoformat()
            self._record_seen_tag(packet, mac)
            tag = self._tag_for(mac)
            if tag is None:
                with self._lock: self._ignored += 1
                continue
            try:
                row, fields = self._decode(packet, tag), None
                fields = self._measurements(row, tag)
                if not fields: raise ValueError("no_valid_measurements")
                self._publish_discovery(mac, tag, row, fields)
                self._publish_state(mac, tag, packet, row, fields)
                with self._lock: self._decoded += 1; self._last_decoded_at = datetime.now(UTC).isoformat(); self._last_error = None
            except Exception as exc:
                LOG.debug("Ignored tag %s: %s", mac, exc)
                with self._lock: self._ignored += 1; self._last_error = str(exc)
