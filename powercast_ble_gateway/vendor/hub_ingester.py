import json
import os
import re
import threading
import time
import ast
import math
import operator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import paho.mqtt.client as mqtt
import psycopg
import yaml
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover - optional until encrypted tags are enabled
    AES = None


CONFIG_PATH = os.getenv("CONFIG_PATH", "/config/settings.yml")
SECRETS_PATH = os.getenv("SECRETS_PATH", "/config/secrets.yml")


def load_config() -> dict[str, Any]:
    config: dict[str, Any] = {}
    for path in (CONFIG_PATH, SECRETS_PATH):
        try:
            with open(path, "r", encoding="utf-8") as config_file:
                config = deep_merge(config, yaml.safe_load(config_file) or {})
        except FileNotFoundError:
            continue
    return config


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


CONFIG = load_config()
CONFIG_RELOAD_LOCK = threading.Lock()


def config_value(path: str, default: Any) -> Any:
    value: Any = CONFIG
    return config_value_from(value, path, default)


def reload_config_or_cached() -> dict[str, Any]:
    global CONFIG
    with CONFIG_RELOAD_LOCK:
        try:
            CONFIG = load_config()
        except OSError as exc:
            print(f"Config reload failed; using cached config: {exc}")
        return CONFIG


def config_value_from(config: dict[str, Any], path: str, default: Any) -> Any:
    value: Any = config
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def env_or_config(env_name: str, path: str, default: Any) -> Any:
    return os.getenv(env_name, str(config_value(path, default)))


def bool_setting(env_name: str, path: str, default: bool) -> bool:
    value = env_or_config(env_name, path, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def sql_interval(value: str) -> str:
    if not re.fullmatch(r"[0-9]+ [A-Za-z]+", value):
        raise ValueError(f"Unsafe SQL interval value: {value}")
    return value


MQTT_HOST = env_or_config("MQTT_HOST", "mqtt.host", "mosquitto")
MQTT_PORT = int(env_or_config("MQTT_PORT", "mqtt.port", 1883))
DATABASE_URL = env_or_config("DATABASE_URL", "common.database_url", "postgresql://sensors:sensors@timescaledb:5432/sensors")
MIN_READING_INTERVAL_SECONDS = int(env_or_config("MIN_READING_INTERVAL_SECONDS", "ingestion.min_reading_interval_seconds", 0))
COMPACT_DECODED_READINGS = bool_setting("COMPACT_DECODED_READINGS", "ingestion.compact_decoded_readings", True)
COMPACT_BUCKET_SECONDS = int(env_or_config("COMPACT_BUCKET_SECONDS", "ingestion.compact_bucket_seconds", 60))
TEMPERATURE_F_MIN = float(env_or_config("TEMPERATURE_F_MIN", "ingestion.measurement_sanity.temperature_f_min", -40))
TEMPERATURE_F_MAX = float(env_or_config("TEMPERATURE_F_MAX", "ingestion.measurement_sanity.temperature_f_max", 185))
TEMPERATURE_C_MIN = float(env_or_config("TEMPERATURE_C_MIN", "ingestion.measurement_sanity.temperature_c_min", -40))
TEMPERATURE_C_MAX = float(env_or_config("TEMPERATURE_C_MAX", "ingestion.measurement_sanity.temperature_c_max", 85))
HUMIDITY_PERCENT_MIN = float(env_or_config("HUMIDITY_PERCENT_MIN", "ingestion.measurement_sanity.humidity_percent_min", 0))
HUMIDITY_PERCENT_MAX = float(env_or_config("HUMIDITY_PERCENT_MAX", "ingestion.measurement_sanity.humidity_percent_max", 100))
COMPACT_MAX_TEMPERATURE_DELTA_F = float(env_or_config("COMPACT_MAX_TEMPERATURE_DELTA_F", "ingestion.measurement_sanity.compact_max_temperature_delta_f", 8))
COMPACT_MAX_HUMIDITY_DELTA_PERCENT = float(env_or_config("COMPACT_MAX_HUMIDITY_DELTA_PERCENT", "ingestion.measurement_sanity.compact_max_humidity_delta_percent", 25))
W7RF_MAX_PLAUSIBLE_DELTA = int(env_or_config("W7RF_MAX_PLAUSIBLE_DELTA", "ingestion.w7rf_max_plausible_delta", 5000))
W7RF_PRESENCE_KEEPALIVE_SECONDS = int(env_or_config("W7RF_PRESENCE_KEEPALIVE_SECONDS", "ingestion.w7rf_presence_keepalive_seconds", 10))
W7RF_LAST_READ_COUNT: dict[tuple[str | None, str | None, str | None], int] = {}
W7RF_LAST_EMIT_TIME: dict[tuple[str | None, str | None, str | None], datetime] = {}
INGEST_BATCH_MESSAGES = int(env_or_config("INGEST_BATCH_MESSAGES", "ingestion.batch_messages", 100))
INGEST_BATCH_FLUSH_SECONDS = float(env_or_config("INGEST_BATCH_FLUSH_SECONDS", "ingestion.batch_flush_seconds", 2))
RAW_COMPRESSION_AFTER = sql_interval(env_or_config("RAW_COMPRESSION_AFTER", "database.raw_compression_after", "7 days"))
RAW_RETENTION_AFTER = sql_interval(env_or_config("RAW_RETENTION_AFTER", "database.raw_retention_after", "30 days"))
FORECAST_RETENTION_AFTER = sql_interval(env_or_config("FORECAST_RETENTION_AFTER", "database.forecast_retention_after", "7 days"))
TAG_KEY_CACHE_SECONDS = int(env_or_config("TAG_KEY_CACHE_SECONDS", "encryption.tag_key_cache_seconds", 30))
MESSAGE_BUFFER: list[tuple[str, bytes]] = []
MESSAGE_BUFFER_LOCK = threading.Lock()
MESSAGE_BUFFER_EVENT = threading.Event()
DEFAULT_SENSOR_REGISTRY = {
    "0001": {
        "custom_device_id": "0001",
        "sensor_type": "encrypted_temperature_humidity",
        "display_name": "Encrypted temperature and humidity",
        "decoder_function": "PCBLE_registry_decoder",
        "has_temperature": True,
        "has_humidity": True,
        "is_location_only": False,
        "characteristics": [
            {"characteristic_key": "temperature_f", "byte_offset": 0, "byte_length": 2, "byte_order": "big", "crc_offset": 2, "crc_length": 1, "crc_algorithm": "sensirion_crc8"},
            {"characteristic_key": "humidity_percent", "byte_offset": 3, "byte_length": 2, "byte_order": "big", "crc_offset": 5, "crc_length": 1, "crc_algorithm": "sensirion_crc8"},
        ],
    },
    "0002": {
        "custom_device_id": "0002",
        "sensor_type": "heartbeat_location",
        "display_name": "Heartbeat / asset tracking",
        "decoder_function": "heartbeat",
        "has_temperature": False,
        "has_humidity": False,
        "is_location_only": True,
    },
}
SENSOR_REGISTRY_CACHE: tuple[float, dict[str, dict[str, Any]]] | None = None


def decrypt_location() -> str:
    configured = str(env_or_config("BLET_DECRYPT_LOCATION", "encryption.decrypt_location", "edge_server")).strip().lower()
    if configured in {"hub", "local"}:
        return "hub"
    return "edge_server"


def mqtt_topics() -> list[str]:
    topics: list[str] = []
    configured = config_value("mqtt.topics", None)
    if isinstance(configured, list):
        topics.extend(str(item).strip() for item in configured if str(item).strip())
    else:
        legacy_topic = str(env_or_config("MQTT_TOPIC", "mqtt.topic", "/sensors/observations/#")).strip()
        if legacy_topic:
            topics.append(legacy_topic)
        additional = config_value("mqtt.additional_topics", [])
        if isinstance(additional, list):
            topics.extend(str(item).strip() for item in additional if str(item).strip())
    if not topics:
        topics.append("/sensors/observations/#")
    deduped: list[str] = []
    seen: set[str] = set()
    for topic in topics:
        if topic not in seen:
            deduped.append(topic)
            seen.add(topic)
    return deduped


MQTT_TOPICS = mqtt_topics()


SCHEMA_SQL = f"""
CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS raw_ble_packets (
    time timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    first_seen_at timestamptz,
    last_seen_at timestamptz,
    topic text NOT NULL,
    gateway_mac text,
    gateway_macs jsonb,
    gateway_rssi text,
    gateway_rssi_counts jsonb,
    format text,
    ble_mac text,
    ble_name text,
    rssi integer,
    adv_type text,
    pri_phy text,
    sec_phy text,
    raw_data text,
    beacon_type text,
    custom_device_id text,
    sensor_type text,
    decoder_version text,
    temperature_raw integer,
    temperature_c double precision,
    temperature_f double precision,
    temperature_crc integer,
    humidity_raw integer,
    humidity_percent double precision,
    humidity_crc integer,
    decoded jsonb,
    sample_count integer NOT NULL DEFAULT 1,
    payload jsonb NOT NULL
);

ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS first_seen_at timestamptz;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS last_seen_at timestamptz;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS gateway_macs jsonb;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS gateway_rssi text;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS gateway_rssi_counts jsonb;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS beacon_type text;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS custom_device_id text;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS sensor_type text;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS decoder_version text;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS temperature_raw integer;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS temperature_c double precision;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS temperature_f double precision;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS temperature_crc integer;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS humidity_raw integer;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS humidity_percent double precision;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS humidity_crc integer;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS decoded jsonb;
ALTER TABLE raw_ble_packets ADD COLUMN IF NOT EXISTS sample_count integer NOT NULL DEFAULT 1;

SELECT create_hypertable('raw_ble_packets', 'time', if_not_exists => TRUE, chunk_time_interval => INTERVAL '1 day');
CREATE INDEX IF NOT EXISTS raw_ble_packets_ble_mac_time_idx ON raw_ble_packets (ble_mac, time DESC);
CREATE INDEX IF NOT EXISTS raw_ble_packets_gateway_time_idx ON raw_ble_packets (gateway_mac, time DESC);
CREATE INDEX IF NOT EXISTS raw_ble_packets_format_time_idx ON raw_ble_packets (format, time DESC);
CREATE INDEX IF NOT EXISTS raw_ble_packets_beacon_type_time_idx ON raw_ble_packets (beacon_type, time DESC);
CREATE INDEX IF NOT EXISTS raw_ble_packets_custom_device_id_time_idx ON raw_ble_packets (custom_device_id, time DESC);
CREATE INDEX IF NOT EXISTS raw_ble_packets_sensor_type_time_idx ON raw_ble_packets (sensor_type, time DESC);

CREATE TABLE IF NOT EXISTS raw_rfid_packets (
    time timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    topic text NOT NULL,
    gateway_mac text,
    format text,
    rfid_value_type text,
    epc text,
    tid text,
    rssi integer,
    reader_timestamp bigint,
    note text,
    value_json jsonb,
    payload jsonb NOT NULL
);

SELECT create_hypertable('raw_rfid_packets', 'time', if_not_exists => TRUE, chunk_time_interval => INTERVAL '1 day');
CREATE INDEX IF NOT EXISTS raw_rfid_packets_gateway_time_idx ON raw_rfid_packets (gateway_mac, time DESC);
CREATE INDEX IF NOT EXISTS raw_rfid_packets_epc_time_idx ON raw_rfid_packets (epc, time DESC);
CREATE INDEX IF NOT EXISTS raw_rfid_packets_tid_time_idx ON raw_rfid_packets (tid, time DESC);
CREATE INDEX IF NOT EXISTS raw_rfid_packets_value_type_time_idx ON raw_rfid_packets (rfid_value_type, time DESC);

CREATE TABLE IF NOT EXISTS ble_observations_1m (
    time timestamptz NOT NULL,
    ble_mac text NOT NULL,
    sensor_type text NOT NULL,
    beacon_type text,
    custom_device_id text,
    gateway_mac text,
    gateway_macs jsonb,
    gateway_rssi text,
    gateway_rssi_counts jsonb,
    sample_count bigint NOT NULL DEFAULT 0,
    avg_rssi double precision,
    temperature_c double precision,
    temperature_f double precision,
    humidity_percent double precision,
    first_seen_at timestamptz,
    last_seen_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (time, ble_mac, sensor_type)
);

ALTER TABLE ble_observations_1m ADD COLUMN IF NOT EXISTS beacon_type text;
ALTER TABLE ble_observations_1m ADD COLUMN IF NOT EXISTS custom_device_id text;
ALTER TABLE ble_observations_1m ADD COLUMN IF NOT EXISTS gateway_macs jsonb;
ALTER TABLE ble_observations_1m ADD COLUMN IF NOT EXISTS gateway_rssi text;
ALTER TABLE ble_observations_1m ADD COLUMN IF NOT EXISTS gateway_rssi_counts jsonb;
ALTER TABLE ble_observations_1m ADD COLUMN IF NOT EXISTS avg_rssi double precision;
ALTER TABLE ble_observations_1m ADD COLUMN IF NOT EXISTS temperature_c double precision;
ALTER TABLE ble_observations_1m ADD COLUMN IF NOT EXISTS temperature_f double precision;
ALTER TABLE ble_observations_1m ADD COLUMN IF NOT EXISTS humidity_percent double precision;
ALTER TABLE ble_observations_1m ADD COLUMN IF NOT EXISTS first_seen_at timestamptz;
ALTER TABLE ble_observations_1m ADD COLUMN IF NOT EXISTS last_seen_at timestamptz;
ALTER TABLE ble_observations_1m ADD COLUMN IF NOT EXISTS updated_at timestamptz;
ALTER TABLE ble_observations_1m ALTER COLUMN updated_at SET DEFAULT now();
UPDATE ble_observations_1m SET updated_at = now() WHERE updated_at IS NULL;

SELECT create_hypertable('ble_observations_1m', 'time', if_not_exists => TRUE, chunk_time_interval => INTERVAL '7 days');
CREATE INDEX IF NOT EXISTS ble_observations_1m_mac_time_idx ON ble_observations_1m (ble_mac, time DESC);
CREATE INDEX IF NOT EXISTS ble_observations_1m_gateway_time_idx ON ble_observations_1m (gateway_mac, time DESC);
CREATE INDEX IF NOT EXISTS ble_observations_1m_beacon_time_idx ON ble_observations_1m (beacon_type, time DESC);
CREATE INDEX IF NOT EXISTS ble_observations_1m_custom_device_id_time_idx ON ble_observations_1m (custom_device_id, time DESC);

CREATE TABLE IF NOT EXISTS ble_tag_current_state (
    ble_mac text PRIMARY KEY,
    sensor_type text,
    beacon_type text,
    custom_device_id text,
    last_seen_at timestamptz,
    gateway_mac text,
    gateway_macs jsonb,
    gateway_rssi text,
    gateway_rssi_counts jsonb,
    sample_count bigint NOT NULL DEFAULT 0,
    last_rssi integer,
    temperature_c double precision,
    temperature_f double precision,
    humidity_percent double precision,
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE ble_tag_current_state ADD COLUMN IF NOT EXISTS custom_device_id text;
CREATE INDEX IF NOT EXISTS ble_tag_current_state_last_seen_idx ON ble_tag_current_state (last_seen_at DESC);
CREATE INDEX IF NOT EXISTS ble_tag_current_state_gateway_idx ON ble_tag_current_state (gateway_mac);
CREATE INDEX IF NOT EXISTS ble_tag_current_state_custom_device_id_idx ON ble_tag_current_state (custom_device_id);

CREATE TABLE IF NOT EXISTS ble_sensor_type_registry (
    custom_device_id text PRIMARY KEY,
    sensor_type text NOT NULL,
    display_name text NOT NULL,
    decoder_function text NOT NULL DEFAULT 'heartbeat',
    has_temperature boolean NOT NULL DEFAULT false,
    has_humidity boolean NOT NULL DEFAULT false,
    is_location_only boolean NOT NULL DEFAULT true,
    notes text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ble_sensor_type_characteristics (
    custom_device_id text NOT NULL REFERENCES ble_sensor_type_registry(custom_device_id) ON DELETE CASCADE,
    characteristic_key text NOT NULL,
    display_name text NOT NULL,
    value_type text NOT NULL DEFAULT 'boolean',
    byte_offset integer,
    byte_length integer,
    byte_order text NOT NULL DEFAULT 'big',
    is_signed boolean NOT NULL DEFAULT false,
    crc_offset integer,
    crc_length integer,
    crc_algorithm text NOT NULL DEFAULT 'none',
    scale double precision,
    value_offset double precision,
    formula text,
    unit text,
    notes text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (custom_device_id, characteristic_key)
);

CREATE TABLE IF NOT EXISTS ble_characteristic_registry (
    characteristic_key text PRIMARY KEY,
    display_name text NOT NULL,
    value_type text NOT NULL DEFAULT 'number',
    unit text,
    notes text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE ble_sensor_type_characteristics ADD COLUMN IF NOT EXISTS byte_offset integer;
ALTER TABLE ble_sensor_type_characteristics ADD COLUMN IF NOT EXISTS byte_length integer;
ALTER TABLE ble_sensor_type_characteristics ADD COLUMN IF NOT EXISTS byte_order text NOT NULL DEFAULT 'big';
ALTER TABLE ble_sensor_type_characteristics ADD COLUMN IF NOT EXISTS is_signed boolean NOT NULL DEFAULT false;
ALTER TABLE ble_sensor_type_characteristics ADD COLUMN IF NOT EXISTS crc_offset integer;
ALTER TABLE ble_sensor_type_characteristics ADD COLUMN IF NOT EXISTS crc_length integer;
ALTER TABLE ble_sensor_type_characteristics ADD COLUMN IF NOT EXISTS crc_algorithm text NOT NULL DEFAULT 'none';
ALTER TABLE ble_sensor_type_characteristics ADD COLUMN IF NOT EXISTS scale double precision;
ALTER TABLE ble_sensor_type_characteristics ADD COLUMN IF NOT EXISTS value_offset double precision;
ALTER TABLE ble_sensor_type_characteristics ADD COLUMN IF NOT EXISTS formula text;

CREATE INDEX IF NOT EXISTS ble_sensor_type_characteristics_device_idx ON ble_sensor_type_characteristics (custom_device_id);

INSERT INTO ble_characteristic_registry (
    characteristic_key,
    display_name,
    value_type,
    unit,
    notes
) VALUES
    ('temperature_f', 'Temperature', 'number', 'degF', 'Temperature in Fahrenheit.'),
    ('humidity_percent', 'Humidity', 'number', '%', 'Relative humidity percent.'),
    ('heartbeat', 'Heartbeat', 'boolean', NULL, 'Presence/asset tracking heartbeat.'),
    ('motion_detected', 'Motion Detected', 'boolean', NULL, 'Motion detected state.')
ON CONFLICT (characteristic_key) DO NOTHING;

INSERT INTO ble_sensor_type_registry (
    custom_device_id,
    sensor_type,
    display_name,
    decoder_function,
    has_temperature,
    has_humidity,
    is_location_only,
    notes
) VALUES
    ('0001', 'encrypted_temperature_humidity', 'Encrypted temperature and humidity', 'PCBLE_registry_decoder', true, true, false, 'PCBLE encrypted temperature/humidity payload. First two decrypted bytes are custom device ID 0001, followed by 6 bytes of sensor data.'),
    ('0002', 'heartbeat_location', 'Heartbeat / asset tracking', 'PCBLE_registry_decoder', false, false, true, 'PCBLE heartbeat-only payload used for asset and location tracking.')
ON CONFLICT (custom_device_id) DO NOTHING;

INSERT INTO ble_sensor_type_characteristics (
    custom_device_id,
    characteristic_key,
    display_name,
    value_type,
    byte_offset,
    byte_length,
    byte_order,
    is_signed,
    crc_offset,
    crc_length,
    crc_algorithm,
    scale,
    value_offset,
    formula,
    unit,
    notes
) VALUES
    ('0001', 'temperature_f', 'Temperature', 'number', 0, 2, 'big', false, 2, 1, 'sensirion_crc8', NULL, NULL, '-49 + 315 * (raw / 65535)', 'degF', 'Temperature raw value in the decrypted sensor payload.'),
    ('0001', 'humidity_percent', 'Humidity', 'number', 3, 2, 'big', false, 5, 1, 'sensirion_crc8', NULL, NULL, '100 * (raw / 65535)', '%', 'Humidity raw value in the decrypted sensor payload.'),
    ('0002', 'heartbeat', 'Heartbeat', 'boolean', NULL, NULL, 'big', false, NULL, NULL, 'none', NULL, NULL, NULL, NULL, 'Presence/asset-tracking heartbeat without a decoded measurement payload.')
ON CONFLICT (custom_device_id, characteristic_key) DO NOTHING;

UPDATE ble_sensor_type_characteristics
SET scale = NULL,
    value_offset = NULL,
    crc_offset = 2,
    crc_length = 1,
    crc_algorithm = 'sensirion_crc8',
    formula = '-49 + 315 * (raw / 65535)',
    notes = 'Temperature raw value in the decrypted sensor payload.'
WHERE custom_device_id = '0001'
  AND characteristic_key = 'temperature_f';

UPDATE ble_sensor_type_characteristics
SET scale = NULL,
    value_offset = NULL,
    crc_offset = 5,
    crc_length = 1,
    crc_algorithm = 'sensirion_crc8',
    formula = '100 * (raw / 65535)',
    notes = 'Humidity raw value in the decrypted sensor payload.'
WHERE custom_device_id = '0001'
  AND characteristic_key = 'humidity_percent';

INSERT INTO ble_characteristic_registry (
    characteristic_key,
    display_name,
    value_type,
    unit,
    notes,
    updated_at
)
SELECT DISTINCT ON (characteristic_key)
    characteristic_key,
    display_name,
    value_type,
    unit,
    notes,
    now()
FROM ble_sensor_type_characteristics
WHERE characteristic_key IS NOT NULL
ORDER BY characteristic_key, updated_at DESC NULLS LAST, display_name
ON CONFLICT (characteristic_key) DO UPDATE SET
    display_name = COALESCE(ble_characteristic_registry.display_name, EXCLUDED.display_name),
    value_type = COALESCE(ble_characteristic_registry.value_type, EXCLUDED.value_type),
    unit = COALESCE(ble_characteristic_registry.unit, EXCLUDED.unit),
    notes = COALESCE(ble_characteristic_registry.notes, EXCLUDED.notes),
    updated_at = now();

CREATE TABLE IF NOT EXISTS ble_tag_security (
    ble_mac text PRIMARY KEY,
    key_id text NOT NULL,
    encrypted_key_hex text NOT NULL,
    key_nonce_hex text NOT NULL,
    key_fingerprint text NOT NULL,
    key_algorithm text NOT NULL DEFAULT 'AES-128-EAX',
    key_wrap_algorithm text NOT NULL DEFAULT 'AES-256-GCM',
    claimed_by text,
    claimed_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ble_tag_security_claimed_at_idx ON ble_tag_security (claimed_at DESC);

CREATE OR REPLACE FUNCTION format_gateway_rssi(rssi_values jsonb)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE
        WHEN count(*) = 0 THEN NULL
        ELSE '[' || string_agg(key || ':' || round((value->>'avg')::numeric)::text, ', ' ORDER BY key) || ']'
    END
    FROM jsonb_each(rssi_values)
    WHERE value->>'avg' IS NOT NULL;
$$;

DO $migration$
DECLARE
    gateway_rssi_type text;
BEGIN
    SELECT data_type
    INTO gateway_rssi_type
    FROM information_schema.columns
    WHERE table_name = 'raw_ble_packets'
      AND column_name = 'gateway_rssi';

    IF gateway_rssi_type = 'jsonb' THEN
        UPDATE raw_ble_packets
        SET gateway_rssi_counts = gateway_rssi
        WHERE gateway_rssi_counts IS NULL
          AND gateway_rssi IS NOT NULL;

        ALTER TABLE raw_ble_packets
        ALTER COLUMN gateway_rssi TYPE text
        USING format_gateway_rssi(gateway_rssi);
    END IF;
END;
$migration$;

CREATE OR REPLACE FUNCTION merge_gateway_rssi_counts(existing jsonb, incoming jsonb)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    result jsonb := COALESCE(existing, '{{}}'::jsonb);
    gateway text;
    incoming_value jsonb;
    existing_value jsonb;
    existing_count integer;
    incoming_count integer;
    merged_count integer;
    existing_avg numeric;
    incoming_avg numeric;
    merged_avg numeric;
BEGIN
    IF incoming IS NULL OR incoming = '{{}}'::jsonb THEN
        RETURN NULLIF(result, '{{}}'::jsonb);
    END IF;

    FOR gateway, incoming_value IN SELECT key, value FROM jsonb_each(incoming)
    LOOP
        IF incoming_value IS NULL OR incoming_value->>'avg' IS NULL THEN
            CONTINUE;
        END IF;

        incoming_avg := (incoming_value->>'avg')::numeric;
        incoming_count := GREATEST(COALESCE((incoming_value->>'sample_count')::integer, 1), 1);
        existing_value := result->gateway;

        IF existing_value IS NULL OR existing_value->>'avg' IS NULL THEN
            result := jsonb_set(
                result,
                ARRAY[gateway],
                jsonb_build_object('avg', incoming_avg, 'sample_count', incoming_count),
                true
            );
        ELSE
            existing_avg := (existing_value->>'avg')::numeric;
            existing_count := GREATEST(COALESCE((existing_value->>'sample_count')::integer, 1), 1);
            merged_count := existing_count + incoming_count;
            merged_avg := ((existing_avg * existing_count) + (incoming_avg * incoming_count)) / merged_count;
            result := jsonb_set(
                result,
                ARRAY[gateway],
                jsonb_build_object('avg', merged_avg, 'sample_count', merged_count),
                true
            );
        END IF;
    END LOOP;

    RETURN NULLIF(result, '{{}}'::jsonb);
END;
$$;

CREATE OR REPLACE FUNCTION best_gateway_mac_by_rssi(rssi_values jsonb)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT key
    FROM jsonb_each(rssi_values)
    WHERE value->>'avg' IS NOT NULL
    ORDER BY abs((value->>'avg')::numeric), key
    LIMIT 1;
$$;

SELECT remove_compression_policy('raw_ble_packets', if_exists => TRUE);
ALTER TABLE raw_ble_packets SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'ble_mac,beacon_type,sensor_type',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('raw_ble_packets', INTERVAL '{RAW_COMPRESSION_AFTER}', if_not_exists => TRUE);
SELECT remove_retention_policy('raw_ble_packets', if_exists => TRUE);
SELECT add_retention_policy('raw_ble_packets', INTERVAL '{RAW_RETENTION_AFTER}', if_not_exists => TRUE);

SELECT remove_compression_policy('raw_rfid_packets', if_exists => TRUE);
ALTER TABLE raw_rfid_packets SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'gateway_mac,rfid_value_type',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('raw_rfid_packets', INTERVAL '{RAW_COMPRESSION_AFTER}', if_not_exists => TRUE);
SELECT remove_retention_policy('raw_rfid_packets', if_exists => TRUE);
SELECT add_retention_policy('raw_rfid_packets', INTERVAL '{RAW_RETENTION_AFTER}', if_not_exists => TRUE);

SELECT remove_compression_policy('ble_observations_1m', if_exists => TRUE);
ALTER TABLE ble_observations_1m SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'ble_mac,beacon_type,sensor_type',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('ble_observations_1m', INTERVAL '{RAW_COMPRESSION_AFTER}', if_not_exists => TRUE);

CREATE TABLE IF NOT EXISTS ble_forecasts (
    time timestamptz NOT NULL,
    generated_at timestamptz NOT NULL,
    ble_mac text NOT NULL,
    metric text NOT NULL,
    horizon_step integer NOT NULL,
    forecast_value double precision NOT NULL,
    lower_value double precision,
    upper_value double precision,
    context_points integer NOT NULL,
    bucket_interval text NOT NULL,
    model_name text NOT NULL,
    model_version text,
    source text NOT NULL,
    payload jsonb
);

SELECT create_hypertable('ble_forecasts', 'time', if_not_exists => TRUE, chunk_time_interval => INTERVAL '7 days');
CREATE INDEX IF NOT EXISTS ble_forecasts_mac_metric_time_idx ON ble_forecasts (ble_mac, metric, time DESC);
CREATE INDEX IF NOT EXISTS ble_forecasts_generated_idx ON ble_forecasts (generated_at DESC);
CREATE INDEX IF NOT EXISTS ble_forecasts_bucket_metric_generated_idx ON ble_forecasts (bucket_interval, metric, generated_at DESC);
SELECT remove_retention_policy('ble_forecasts', if_exists => TRUE);
SELECT add_retention_policy('ble_forecasts', INTERVAL '{FORECAST_RETENTION_AFTER}', if_not_exists => TRUE);
"""


INSERT_SQL = """
INSERT INTO raw_ble_packets (
    time,
    received_at,
    first_seen_at,
    last_seen_at,
    topic,
    gateway_mac,
    gateway_macs,
    gateway_rssi,
    gateway_rssi_counts,
    format,
    ble_mac,
    ble_name,
    rssi,
    adv_type,
    pri_phy,
    sec_phy,
    raw_data,
    beacon_type,
    custom_device_id,
    sensor_type,
    decoder_version,
    temperature_raw,
    temperature_c,
    temperature_f,
    temperature_crc,
    humidity_raw,
    humidity_percent,
    humidity_crc,
    decoded,
    sample_count,
    payload
) VALUES (
    %(time)s,
    %(received_at)s,
    %(first_seen_at)s,
    %(last_seen_at)s,
    %(topic)s,
    %(gateway_mac)s,
    %(gateway_macs)s,
    %(gateway_rssi)s,
    %(gateway_rssi_counts)s,
    %(format)s,
    %(ble_mac)s,
    %(ble_name)s,
    %(rssi)s,
    %(adv_type)s,
    %(pri_phy)s,
    %(sec_phy)s,
    %(raw_data)s,
    %(beacon_type)s,
    %(custom_device_id)s,
    %(sensor_type)s,
    %(decoder_version)s,
    %(temperature_raw)s,
    %(temperature_c)s,
    %(temperature_f)s,
    %(temperature_crc)s,
    %(humidity_raw)s,
    %(humidity_percent)s,
    %(humidity_crc)s,
    %(decoded)s,
    %(sample_count)s,
    %(payload)s
);
"""


RFID_INSERT_SQL = """
INSERT INTO raw_rfid_packets (
    time,
    received_at,
    topic,
    gateway_mac,
    format,
    rfid_value_type,
    epc,
    tid,
    rssi,
    reader_timestamp,
    note,
    value_json,
    payload
) VALUES (
    %(time)s,
    %(received_at)s,
    %(topic)s,
    %(gateway_mac)s,
    %(format)s,
    %(rfid_value_type)s,
    %(epc)s,
    %(tid)s,
    %(rssi)s,
    %(reader_timestamp)s,
    %(note)s,
    %(value_json)s,
    %(payload)s
);
"""


RFID_HUB_UPSERT_SQL = """
INSERT INTO ble_seen_hubs (
    hub_mac,
    source_types,
    supports_ble,
    supports_rfid,
    first_seen_at,
    last_seen_at,
    sample_count,
    updated_at
) VALUES (
    %(gateway_mac)s,
    'RFID Hub',
    false,
    true,
    %(time)s,
    %(time)s,
    1,
    now()
)
ON CONFLICT (hub_mac) DO UPDATE SET
    source_types = CASE
        WHEN ble_seen_hubs.source_types ILIKE '%%RFID%%' THEN ble_seen_hubs.source_types
        WHEN ble_seen_hubs.source_types ILIKE '%%BLE%%' THEN 'BLE Hub + RFID Hub'
        ELSE 'RFID Hub'
    END,
    supports_rfid = true,
    first_seen_at = LEAST(COALESCE(ble_seen_hubs.first_seen_at, EXCLUDED.first_seen_at), EXCLUDED.first_seen_at),
    last_seen_at = GREATEST(COALESCE(ble_seen_hubs.last_seen_at, EXCLUDED.last_seen_at), EXCLUDED.last_seen_at),
    sample_count = ble_seen_hubs.sample_count + 1,
    updated_at = now();
"""


COMPACT_UPDATE_SQL = f"""
UPDATE raw_ble_packets
SET
    received_at = GREATEST(received_at, %(received_at)s),
    first_seen_at = LEAST(COALESCE(first_seen_at, time), %(first_seen_at)s),
    last_seen_at = GREATEST(COALESCE(last_seen_at, time), %(last_seen_at)s),
    gateway_mac = COALESCE(
        best_gateway_mac_by_rssi(merge_gateway_rssi_counts(gateway_rssi_counts, %(gateway_rssi_counts)s::jsonb)),
        best_gateway_mac_by_rssi(gateway_rssi_counts),
        %(gateway_mac)s,
        gateway_mac
    ),
    gateway_macs = (
        SELECT jsonb_agg(DISTINCT value ORDER BY value)
        FROM jsonb_array_elements_text(COALESCE(gateway_macs, '[]'::jsonb) || %(gateway_macs)s::jsonb)
    ),
    gateway_rssi = format_gateway_rssi(merge_gateway_rssi_counts(gateway_rssi_counts, %(gateway_rssi_counts)s::jsonb)),
    gateway_rssi_counts = merge_gateway_rssi_counts(gateway_rssi_counts, %(gateway_rssi_counts)s::jsonb),
    ble_name = CASE
        WHEN beacon_type = 'powercast_blet' OR %(beacon_type)s = 'powercast_blet'
            THEN COALESCE(%(ble_name)s, 'BLET')
        WHEN beacon_type = 'powercast_pcble_encrypted' OR %(beacon_type)s = 'powercast_pcble_encrypted'
            THEN COALESCE(%(ble_name)s, 'PCBLE')
        ELSE COALESCE(NULLIF(ble_name, ''), %(ble_name)s)
    END,
    rssi = CASE
        WHEN rssi IS NULL THEN %(rssi)s::integer
        WHEN %(rssi)s::integer IS NULL THEN rssi
        ELSE round(((rssi::numeric * sample_count) + (%(rssi)s::numeric * %(sample_count)s::integer)) / (sample_count + %(sample_count)s::integer))::integer
    END,
    raw_data = COALESCE(%(raw_data)s, raw_data),
    custom_device_id = COALESCE(%(custom_device_id)s, custom_device_id),
    temperature_raw = COALESCE(%(temperature_raw)s::integer, temperature_raw),
    temperature_c = CASE
        WHEN %(temperature_c)s::double precision IS NULL THEN temperature_c
        WHEN %(temperature_c)s::double precision < {TEMPERATURE_C_MIN} OR %(temperature_c)s::double precision > {TEMPERATURE_C_MAX} THEN temperature_c
        WHEN temperature_c IS NULL THEN %(temperature_c)s::double precision
        WHEN temperature_c < {TEMPERATURE_C_MIN} OR temperature_c > {TEMPERATURE_C_MAX} THEN %(temperature_c)s::double precision
        WHEN abs(temperature_c - %(temperature_c)s::double precision) > {COMPACT_MAX_TEMPERATURE_DELTA_F * 5 / 9} THEN temperature_c
        ELSE ((temperature_c * sample_count) + (%(temperature_c)s::double precision * %(sample_count)s::integer)) / (sample_count + %(sample_count)s::integer)
    END,
    temperature_f = CASE
        WHEN %(temperature_f)s::double precision IS NULL THEN temperature_f
        WHEN %(temperature_f)s::double precision < {TEMPERATURE_F_MIN} OR %(temperature_f)s::double precision > {TEMPERATURE_F_MAX} THEN temperature_f
        WHEN temperature_f IS NULL THEN %(temperature_f)s::double precision
        WHEN temperature_f < {TEMPERATURE_F_MIN} OR temperature_f > {TEMPERATURE_F_MAX} THEN %(temperature_f)s::double precision
        WHEN abs(temperature_f - %(temperature_f)s::double precision) > {COMPACT_MAX_TEMPERATURE_DELTA_F} THEN temperature_f
        ELSE ((temperature_f * sample_count) + (%(temperature_f)s::double precision * %(sample_count)s::integer)) / (sample_count + %(sample_count)s::integer)
    END,
    temperature_crc = COALESCE(%(temperature_crc)s::integer, temperature_crc),
    humidity_raw = COALESCE(%(humidity_raw)s::integer, humidity_raw),
    humidity_percent = CASE
        WHEN %(humidity_percent)s::double precision IS NULL THEN humidity_percent
        WHEN %(humidity_percent)s::double precision < {HUMIDITY_PERCENT_MIN} OR %(humidity_percent)s::double precision > {HUMIDITY_PERCENT_MAX} THEN humidity_percent
        WHEN humidity_percent IS NULL THEN %(humidity_percent)s::double precision
        WHEN humidity_percent < {HUMIDITY_PERCENT_MIN} OR humidity_percent > {HUMIDITY_PERCENT_MAX} THEN %(humidity_percent)s::double precision
        WHEN abs(humidity_percent - %(humidity_percent)s::double precision) > {COMPACT_MAX_HUMIDITY_DELTA_PERCENT} THEN humidity_percent
        ELSE ((humidity_percent * sample_count) + (%(humidity_percent)s::double precision * %(sample_count)s::integer)) / (sample_count + %(sample_count)s::integer)
    END,
    humidity_crc = COALESCE(%(humidity_crc)s::integer, humidity_crc),
    decoded = COALESCE(%(decoded)s, decoded),
    sample_count = sample_count + %(sample_count)s::integer,
    payload = %(payload)s
WHERE time = %(time)s
  AND ble_mac = %(ble_mac)s
  AND sensor_type = %(sensor_type)s;
"""


OBSERVATION_UPSERT_SQL = f"""
INSERT INTO ble_observations_1m (
    time,
    ble_mac,
    sensor_type,
    beacon_type,
    custom_device_id,
    gateway_mac,
    gateway_macs,
    gateway_rssi,
    gateway_rssi_counts,
    sample_count,
    avg_rssi,
    temperature_c,
    temperature_f,
    humidity_percent,
    first_seen_at,
    last_seen_at,
    updated_at
) VALUES (
    %(time)s,
    %(ble_mac)s,
    %(sensor_type)s,
    %(beacon_type)s,
    %(custom_device_id)s,
    %(gateway_mac)s,
    %(gateway_macs)s,
    %(gateway_rssi)s,
    %(gateway_rssi_counts)s,
    %(sample_count)s,
    %(rssi)s,
    %(temperature_c)s,
    %(temperature_f)s,
    %(humidity_percent)s,
    %(first_seen_at)s,
    %(last_seen_at)s,
    now()
)
ON CONFLICT (time, ble_mac, sensor_type) DO UPDATE SET
    beacon_type = COALESCE(EXCLUDED.beacon_type, ble_observations_1m.beacon_type),
    custom_device_id = COALESCE(EXCLUDED.custom_device_id, ble_observations_1m.custom_device_id),
    gateway_mac = COALESCE(
        best_gateway_mac_by_rssi(merge_gateway_rssi_counts(ble_observations_1m.gateway_rssi_counts, EXCLUDED.gateway_rssi_counts)),
        best_gateway_mac_by_rssi(ble_observations_1m.gateway_rssi_counts),
        EXCLUDED.gateway_mac,
        ble_observations_1m.gateway_mac
    ),
    gateway_macs = (
        SELECT jsonb_agg(DISTINCT value ORDER BY value)
        FROM jsonb_array_elements_text(COALESCE(ble_observations_1m.gateway_macs, '[]'::jsonb) || EXCLUDED.gateway_macs)
    ),
    gateway_rssi_counts = merge_gateway_rssi_counts(ble_observations_1m.gateway_rssi_counts, EXCLUDED.gateway_rssi_counts),
    gateway_rssi = format_gateway_rssi(merge_gateway_rssi_counts(ble_observations_1m.gateway_rssi_counts, EXCLUDED.gateway_rssi_counts)),
    avg_rssi = CASE
        WHEN ble_observations_1m.avg_rssi IS NULL THEN EXCLUDED.avg_rssi
        WHEN EXCLUDED.avg_rssi IS NULL THEN ble_observations_1m.avg_rssi
        ELSE ((ble_observations_1m.avg_rssi * ble_observations_1m.sample_count) + (EXCLUDED.avg_rssi * EXCLUDED.sample_count)) / NULLIF(ble_observations_1m.sample_count + EXCLUDED.sample_count, 0)
    END,
    temperature_c = CASE
        WHEN EXCLUDED.temperature_c IS NULL THEN ble_observations_1m.temperature_c
        WHEN EXCLUDED.temperature_c < {TEMPERATURE_C_MIN} OR EXCLUDED.temperature_c > {TEMPERATURE_C_MAX} THEN ble_observations_1m.temperature_c
        WHEN ble_observations_1m.temperature_c IS NULL THEN EXCLUDED.temperature_c
        WHEN ble_observations_1m.temperature_c < {TEMPERATURE_C_MIN} OR ble_observations_1m.temperature_c > {TEMPERATURE_C_MAX} THEN EXCLUDED.temperature_c
        WHEN abs(ble_observations_1m.temperature_c - EXCLUDED.temperature_c) > {COMPACT_MAX_TEMPERATURE_DELTA_F * 5 / 9} THEN ble_observations_1m.temperature_c
        ELSE ((ble_observations_1m.temperature_c * ble_observations_1m.sample_count) + (EXCLUDED.temperature_c * EXCLUDED.sample_count)) / NULLIF(ble_observations_1m.sample_count + EXCLUDED.sample_count, 0)
    END,
    temperature_f = CASE
        WHEN EXCLUDED.temperature_f IS NULL THEN ble_observations_1m.temperature_f
        WHEN EXCLUDED.temperature_f < {TEMPERATURE_F_MIN} OR EXCLUDED.temperature_f > {TEMPERATURE_F_MAX} THEN ble_observations_1m.temperature_f
        WHEN ble_observations_1m.temperature_f IS NULL THEN EXCLUDED.temperature_f
        WHEN ble_observations_1m.temperature_f < {TEMPERATURE_F_MIN} OR ble_observations_1m.temperature_f > {TEMPERATURE_F_MAX} THEN EXCLUDED.temperature_f
        WHEN abs(ble_observations_1m.temperature_f - EXCLUDED.temperature_f) > {COMPACT_MAX_TEMPERATURE_DELTA_F} THEN ble_observations_1m.temperature_f
        ELSE ((ble_observations_1m.temperature_f * ble_observations_1m.sample_count) + (EXCLUDED.temperature_f * EXCLUDED.sample_count)) / NULLIF(ble_observations_1m.sample_count + EXCLUDED.sample_count, 0)
    END,
    humidity_percent = CASE
        WHEN EXCLUDED.humidity_percent IS NULL THEN ble_observations_1m.humidity_percent
        WHEN EXCLUDED.humidity_percent < {HUMIDITY_PERCENT_MIN} OR EXCLUDED.humidity_percent > {HUMIDITY_PERCENT_MAX} THEN ble_observations_1m.humidity_percent
        WHEN ble_observations_1m.humidity_percent IS NULL THEN EXCLUDED.humidity_percent
        WHEN ble_observations_1m.humidity_percent < {HUMIDITY_PERCENT_MIN} OR ble_observations_1m.humidity_percent > {HUMIDITY_PERCENT_MAX} THEN EXCLUDED.humidity_percent
        WHEN abs(ble_observations_1m.humidity_percent - EXCLUDED.humidity_percent) > {COMPACT_MAX_HUMIDITY_DELTA_PERCENT} THEN ble_observations_1m.humidity_percent
        ELSE ((ble_observations_1m.humidity_percent * ble_observations_1m.sample_count) + (EXCLUDED.humidity_percent * EXCLUDED.sample_count)) / NULLIF(ble_observations_1m.sample_count + EXCLUDED.sample_count, 0)
    END,
    sample_count = ble_observations_1m.sample_count + EXCLUDED.sample_count,
    first_seen_at = LEAST(COALESCE(ble_observations_1m.first_seen_at, EXCLUDED.first_seen_at), COALESCE(EXCLUDED.first_seen_at, ble_observations_1m.first_seen_at)),
    last_seen_at = GREATEST(COALESCE(ble_observations_1m.last_seen_at, EXCLUDED.last_seen_at), COALESCE(EXCLUDED.last_seen_at, ble_observations_1m.last_seen_at)),
    updated_at = now();
"""


CURRENT_STATE_UPSERT_SQL = """
INSERT INTO ble_tag_current_state (
    ble_mac,
    sensor_type,
    beacon_type,
    custom_device_id,
    last_seen_at,
    gateway_mac,
    gateway_macs,
    gateway_rssi,
    gateway_rssi_counts,
    sample_count,
    last_rssi,
    temperature_c,
    temperature_f,
    humidity_percent,
    updated_at
) VALUES (
    %(ble_mac)s,
    %(sensor_type)s,
    %(beacon_type)s,
    %(custom_device_id)s,
    %(last_seen_at)s,
    %(gateway_mac)s,
    %(gateway_macs)s,
    %(gateway_rssi)s,
    %(gateway_rssi_counts)s,
    %(sample_count)s,
    %(rssi)s,
    %(temperature_c)s,
    %(temperature_f)s,
    %(humidity_percent)s,
    now()
)
ON CONFLICT (ble_mac) DO UPDATE SET
    sensor_type = CASE WHEN EXCLUDED.last_seen_at >= COALESCE(ble_tag_current_state.last_seen_at, '-infinity'::timestamptz) THEN EXCLUDED.sensor_type ELSE ble_tag_current_state.sensor_type END,
    beacon_type = CASE WHEN EXCLUDED.last_seen_at >= COALESCE(ble_tag_current_state.last_seen_at, '-infinity'::timestamptz) THEN EXCLUDED.beacon_type ELSE ble_tag_current_state.beacon_type END,
    custom_device_id = CASE WHEN EXCLUDED.last_seen_at >= COALESCE(ble_tag_current_state.last_seen_at, '-infinity'::timestamptz) THEN EXCLUDED.custom_device_id ELSE ble_tag_current_state.custom_device_id END,
    last_seen_at = GREATEST(COALESCE(ble_tag_current_state.last_seen_at, EXCLUDED.last_seen_at), COALESCE(EXCLUDED.last_seen_at, ble_tag_current_state.last_seen_at)),
    gateway_mac = CASE WHEN EXCLUDED.last_seen_at >= COALESCE(ble_tag_current_state.last_seen_at, '-infinity'::timestamptz) THEN EXCLUDED.gateway_mac ELSE ble_tag_current_state.gateway_mac END,
    gateway_macs = CASE WHEN EXCLUDED.last_seen_at >= COALESCE(ble_tag_current_state.last_seen_at, '-infinity'::timestamptz) THEN EXCLUDED.gateway_macs ELSE ble_tag_current_state.gateway_macs END,
    gateway_rssi = CASE WHEN EXCLUDED.last_seen_at >= COALESCE(ble_tag_current_state.last_seen_at, '-infinity'::timestamptz) THEN EXCLUDED.gateway_rssi ELSE ble_tag_current_state.gateway_rssi END,
    gateway_rssi_counts = CASE WHEN EXCLUDED.last_seen_at >= COALESCE(ble_tag_current_state.last_seen_at, '-infinity'::timestamptz) THEN EXCLUDED.gateway_rssi_counts ELSE ble_tag_current_state.gateway_rssi_counts END,
    sample_count = ble_tag_current_state.sample_count + EXCLUDED.sample_count,
    last_rssi = CASE WHEN EXCLUDED.last_seen_at >= COALESCE(ble_tag_current_state.last_seen_at, '-infinity'::timestamptz) THEN EXCLUDED.last_rssi ELSE ble_tag_current_state.last_rssi END,
    temperature_c = CASE WHEN EXCLUDED.last_seen_at >= COALESCE(ble_tag_current_state.last_seen_at, '-infinity'::timestamptz) THEN EXCLUDED.temperature_c ELSE ble_tag_current_state.temperature_c END,
    temperature_f = CASE WHEN EXCLUDED.last_seen_at >= COALESCE(ble_tag_current_state.last_seen_at, '-infinity'::timestamptz) THEN EXCLUDED.temperature_f ELSE ble_tag_current_state.temperature_f END,
    humidity_percent = CASE WHEN EXCLUDED.last_seen_at >= COALESCE(ble_tag_current_state.last_seen_at, '-infinity'::timestamptz) THEN EXCLUDED.humidity_percent ELSE ble_tag_current_state.humidity_percent END,
    updated_at = now();
"""


POWERCAST_BLET_PREFIX = bytes.fromhex("0509424C455409FFD302")
POWERCAST_PCBLE_NAME_PREFIX = bytes.fromhex("06095043424C45")
POWERCAST_STBLE_NAME_PREFIX = bytes.fromhex("06095354424C45")
POWERCAST_COMPANY_ID = bytes.fromhex("D302")
WINE7_RFID_COMPANY_ID = bytes.fromhex("FFFF")
WINE7_RFID_MAGIC = bytes.fromhex("5737")
UINT16_MAX = 65535
TAG_KEY_CACHE: dict[str, tuple[float, list[tuple[str, bytes]], str | None]] = {}
FORMULA_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}
FORMULA_FUNCTIONS = {
    "abs": abs,
    "min": min,
    "max": max,
    "round": round,
    "pow": pow,
    "sqrt": math.sqrt,
    "ln": math.log,
    "log": math.log,
    "log10": math.log10,
    "exp": math.exp,
}
FORMULA_CONSTANTS = {
    "UINT16_MAX": UINT16_MAX,
    "uint16_max": UINT16_MAX,
    "pi": math.pi,
    "e": math.e,
}


@dataclass(frozen=True)
class DecodedBeacon:
    beacon_type: str | None = None
    custom_device_id: str | None = None
    sensor_type: str | None = None
    decoder_version: str | None = None
    temperature_raw: int | None = None
    temperature_c: float | None = None
    temperature_f: float | None = None
    temperature_crc: int | None = None
    humidity_raw: int | None = None
    humidity_percent: float | None = None
    humidity_crc: int | None = None
    decoded: dict[str, Any] | None = None

    def as_row(self) -> dict[str, Any]:
        return {
            "beacon_type": self.beacon_type,
            "custom_device_id": self.custom_device_id,
            "sensor_type": self.sensor_type,
            "decoder_version": self.decoder_version,
            "temperature_raw": self.temperature_raw,
            "temperature_c": self.temperature_c,
            "temperature_f": self.temperature_f,
            "temperature_crc": self.temperature_crc,
            "humidity_raw": self.humidity_raw,
            "humidity_percent": self.humidity_percent,
            "humidity_crc": self.humidity_crc,
            "decoded": json.dumps(self.decoded, separators=(",", ":")) if self.decoded is not None else None,
        }


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, int | float):
        seconds = value / 1000 if value > 10_000_000_000 else value
        try:
            return datetime.fromtimestamp(seconds, UTC)
        except (OSError, OverflowError, ValueError):
            return datetime.now(UTC)

    if not isinstance(value, str):
        return datetime.now(UTC)
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return datetime.now(UTC)


def bucket_timestamp(value: datetime, seconds: int) -> datetime:
    if seconds <= 1:
        return value
    timestamp = int(value.timestamp())
    return datetime.fromtimestamp(timestamp - (timestamp % seconds), UTC)


def parse_hex_payload(value: Any) -> bytes | None:
    if not isinstance(value, str):
        return None

    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def parse_ble_local_name(raw_data: Any) -> str | None:
    payload = parse_hex_payload(raw_data)
    if not payload:
        return None

    index = 0
    while index < len(payload):
        length = payload[index]
        if length == 0:
            break

        field_end = index + 1 + length
        if field_end > len(payload):
            break

        field_type = payload[index + 1]
        field_value = payload[index + 2:field_end]
        if field_type in {0x08, 0x09}:
            try:
                return field_value.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                return None

        index = field_end

    return None


def parse_ad_structures(raw_data: Any) -> list[tuple[int, bytes]]:
    payload = parse_hex_payload(raw_data)
    if payload is None:
        return []

    structures: list[tuple[int, bytes]] = []
    index = 0
    while index < len(payload):
        length = payload[index]
        if length == 0:
            break
        field_end = index + 1 + length
        if field_end > len(payload) or length < 1:
            break
        structures.append((payload[index + 1], payload[index + 2:field_end]))
        index = field_end
    return structures


def powercast_manufacturer_body(raw_data: Any) -> tuple[bytes, int] | None:
    payload = parse_hex_payload(raw_data)
    if payload is None:
        return None

    index = 0
    while index < len(payload):
        length = payload[index]
        if length == 0:
            break
        field_end = index + 1 + length
        if field_end > len(payload) or length < 3:
            return None
        field_type = payload[index + 1]
        field_value = payload[index + 2:field_end]
        if field_type == 0xFF and field_value[:2] == POWERCAST_COMPANY_ID:
            return field_value[2:], length
        index = field_end
    return None


def service_device_id(raw_data: Any) -> str | None:
    for field_type, field_value in parse_ad_structures(raw_data):
        if field_type in {0x02, 0x03} and len(field_value) >= 2:
            # Preserve the documented Custom Device ID text. The workbook's
            # wire bytes 00 0A represent registry ID 000A.
            return field_value[:2].hex().upper()
    return None




def wine7_rfid_manufacturer_body(raw_data: Any) -> bytes | None:
    payload = parse_hex_payload(raw_data)
    if payload is None:
        return None

    index = 0
    while index < len(payload):
        length = payload[index]
        if length == 0:
            break

        field_end = index + 1 + length
        if field_end > len(payload):
            return None

        field_type = payload[index + 1]
        field_value = payload[index + 2:field_end]
        if field_type == 0xFF and len(field_value) >= 11 and field_value[:2] == WINE7_RFID_COMPANY_ID:
            body = field_value[2:]
            if body[:2] == WINE7_RFID_MAGIC:
                return body

        index = field_end

    return None


def canonical_mac(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None

    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value)
    return cleaned.upper() if cleaned else None


def decode_powercast_blet(raw_data: Any) -> DecodedBeacon | None:
    payload = parse_hex_payload(raw_data)
    if payload is None or len(payload) < 16 or not payload.startswith(POWERCAST_BLET_PREFIX):
        return None

    return decode_temperature_humidity_payload(
        payload,
        offset=10,
        beacon_type="powercast_blet",
        sensor_type="temperature_humidity",
        decoder_version="powercast_blet_v1",
        decoded_extra=None,
    )


def decode_temperature_humidity_payload(
    payload: bytes,
    offset: int,
    beacon_type: str,
    sensor_type: str,
    decoder_version: str,
    custom_device_id: str | None = None,
    decoded_extra: dict[str, Any] | None = None,
    temperature_offset: int = 0,
    temperature_length: int = 2,
    temperature_byte_order: str = "big",
    temperature_crc_offset: int | None = 2,
    temperature_crc_length: int | None = 1,
    humidity_offset: int = 3,
    humidity_length: int = 2,
    humidity_byte_order: str = "big",
    humidity_crc_offset: int | None = 5,
    humidity_crc_length: int | None = 1,
    temperature_crc_algorithm: str = "sensirion_crc8",
    humidity_crc_algorithm: str = "sensirion_crc8",
) -> DecodedBeacon:
    temperature_start = offset + temperature_offset
    humidity_start = offset + humidity_offset
    temperature_raw = int.from_bytes(
        payload[temperature_start : temperature_start + temperature_length],
        byteorder=temperature_byte_order if temperature_byte_order in {"big", "little"} else "big",
    )
    humidity_raw = int.from_bytes(
        payload[humidity_start : humidity_start + humidity_length],
        byteorder=humidity_byte_order if humidity_byte_order in {"big", "little"} else "big",
    )
    temperature_crc = read_check_value(payload, offset, temperature_crc_offset, temperature_crc_length)
    humidity_crc = read_check_value(payload, offset, humidity_crc_offset, humidity_crc_length)
    temperature_crc_valid = validate_check_value(
        payload,
        temperature_start,
        temperature_length,
        offset,
        temperature_crc_offset,
        temperature_crc_length,
        temperature_crc_algorithm,
    )
    humidity_crc_valid = validate_check_value(
        payload,
        humidity_start,
        humidity_length,
        offset,
        humidity_crc_offset,
        humidity_crc_length,
        humidity_crc_algorithm,
    )
    temperature_valid = temperature_crc_valid is not False
    humidity_valid = humidity_crc_valid is not False
    temperature_c = -45 + 175 * (temperature_raw / UINT16_MAX) if temperature_valid else None
    temperature_f = -49 + 315 * (temperature_raw / UINT16_MAX) if temperature_valid else None
    humidity_percent = 100 * (humidity_raw / UINT16_MAX) if humidity_valid else None
    decoded = {
        "temperature": {
            "raw": temperature_raw,
            "c": temperature_c,
            "f": temperature_f,
            "crc": temperature_crc,
            "crc_valid": temperature_crc_valid,
        },
        "humidity": {
            "raw": humidity_raw,
            "percent": humidity_percent,
            "crc": humidity_crc,
            "crc_valid": humidity_crc_valid,
        },
    }
    if decoded_extra:
        decoded.update(decoded_extra)

    return DecodedBeacon(
        beacon_type=beacon_type,
        custom_device_id=custom_device_id,
        sensor_type=sensor_type,
        decoder_version=decoder_version,
        temperature_raw=temperature_raw if temperature_valid else None,
        temperature_c=temperature_c,
        temperature_f=temperature_f,
        temperature_crc=temperature_crc,
        humidity_raw=humidity_raw if humidity_valid else None,
        humidity_percent=humidity_percent,
        humidity_crc=humidity_crc,
        decoded=decoded,
    )


def read_check_value(payload: bytes, base_offset: int, check_offset: int | None, check_length: int | None) -> int | None:
    if check_offset is None or check_length is None or check_length <= 0:
        return None
    start = base_offset + check_offset
    end = start + check_length
    if start < 0 or end > len(payload):
        return None
    return int.from_bytes(payload[start:end], byteorder="big")


def read_check_bytes(payload: bytes, base_offset: int, check_offset: int | None, check_length: int | None) -> bytes | None:
    if check_offset is None or check_length is None or check_length <= 0:
        return None
    start = base_offset + check_offset
    end = start + check_length
    if start < 0 or end > len(payload):
        return None
    return payload[start:end]


def sensirion_crc8(data: bytes) -> int:
    crc = 0xFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x31) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


def validate_check_value(
    payload: bytes,
    data_start: int,
    data_length: int,
    base_offset: int,
    check_offset: int | None,
    check_length: int | None,
    algorithm: str,
) -> bool | None:
    algorithm = (algorithm or "none").strip().lower()
    if algorithm in {"none", "raw_byte"}:
        return None
    check_bytes = read_check_bytes(payload, base_offset, check_offset, check_length)
    data = payload[data_start : data_start + data_length]
    if check_bytes is None or len(data) != data_length:
        return False
    if algorithm == "sensirion_crc8":
        return len(check_bytes) == 1 and sensirion_crc8(data) == check_bytes[0]
    return None


def payload_number(payload: bytes, offset: int | float, length: int | float = 1, byte_order: str = "big", signed: bool = False) -> int:
    start = int(offset)
    size = int(length)
    if start < 0 or size <= 0 or start + size > len(payload):
        raise ValueError("payload byte range is outside decrypted payload")
    order = byte_order if byte_order in {"big", "little"} else "big"
    return int.from_bytes(payload[start : start + size], byteorder=order, signed=bool(signed))


def evaluate_formula(formula: Any, raw: int | float, payload: bytes | None = None) -> float | int:
    if not isinstance(formula, str) or not formula.strip():
        return raw

    def evaluate(node: ast.AST) -> float | int:
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int | float):
            return node.value
        if isinstance(node, ast.Name):
            if node.id == "raw":
                return raw
            if node.id in FORMULA_CONSTANTS:
                return FORMULA_CONSTANTS[node.id]
            raise ValueError(f"Unsupported formula name: {node.id}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            function_name = node.func.id
            args = [evaluate(argument) for argument in node.args]
            kwargs = {}
            for keyword in node.keywords:
                if keyword.arg is None:
                    raise ValueError("Formula splat arguments are not supported")
                if isinstance(keyword.value, ast.Constant):
                    kwargs[keyword.arg] = keyword.value.value
                else:
                    kwargs[keyword.arg] = evaluate(keyword.value)
            if function_name in {"payload", "payload_uint", "payload_int"}:
                if payload is None:
                    raise ValueError("Payload byte helpers require a decrypted payload")
                if len(args) not in {1, 2}:
                    raise ValueError("Payload byte helpers require offset and optional length")
                signed = function_name == "payload_int" or bool(kwargs.pop("signed", False))
                byte_order = str(kwargs.pop("byte_order", kwargs.pop("order", "big")))
                if kwargs:
                    raise ValueError("Unsupported payload helper keyword")
                return payload_number(payload, args[0], args[1] if len(args) == 2 else 1, byte_order, signed)
            if function_name in FORMULA_FUNCTIONS:
                return FORMULA_FUNCTIONS[function_name](*args, **kwargs)
            raise ValueError(f"Unsupported formula function: {function_name}")
        if isinstance(node, ast.BinOp) and type(node.op) in FORMULA_OPERATORS:
            return FORMULA_OPERATORS[type(node.op)](evaluate(node.left), evaluate(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in FORMULA_OPERATORS:
            return FORMULA_OPERATORS[type(node.op)](evaluate(node.operand))
        raise ValueError("Unsupported formula expression")

    parsed = ast.parse(formula, mode="eval")
    return evaluate(parsed)


STANDARD_MEASUREMENT_LIMITS: dict[str, tuple[float, float]] = {
    "temperature_f": (-100.0, 300.0),
    "temperature_c": (-75.0, 150.0),
    "humidity_percent": (0.0, 100.0),
}


def normalize_standard_measurement_value(
    key: str,
    value: float | int | bool | None,
    formula: Any,
    value_type: str,
) -> tuple[float | int | bool | None, str | None]:
    if value is None or key not in STANDARD_MEASUREMENT_LIMITS:
        return value, None
    if value_type != "number":
        return value, None
    if not isinstance(formula, str) or not formula.strip():
        return None, "missing_formula"
    if not isinstance(value, int | float) or not math.isfinite(float(value)):
        return None, "invalid_number"

    minimum, maximum = STANDARD_MEASUREMENT_LIMITS[key]
    numeric_value = float(value)
    if numeric_value < minimum or numeric_value > maximum:
        return None, "out_of_range"
    return value, None


def characteristic_required_length(characteristics: list[dict[str, Any]]) -> int:
    required = 0
    for characteristic in characteristics:
        offset = int_metadata(characteristic, "byte_offset")
        length = int_metadata(characteristic, "byte_length")
        if offset is not None and length is not None:
            required = max(required, offset + length)
        crc_offset, crc_length, _algorithm = crc_metadata(characteristic, None, None, "none")
        if crc_offset is not None and crc_length is not None:
            required = max(required, crc_offset + crc_length)
    return required


def decode_registry_characteristics(
    payload: bytes,
    sensor: dict[str, Any],
    beacon_type: str,
    custom_device_id: str | None,
    sensor_type: str,
    decoder_version: str,
    decoded_extra: dict[str, Any],
) -> DecodedBeacon:
    decoded_characteristics: dict[str, dict[str, Any]] = {}
    temperature_raw: int | None = None
    temperature_c: float | None = None
    temperature_f: float | None = None
    temperature_crc: int | None = None
    humidity_raw: int | None = None
    humidity_percent: float | None = None
    humidity_crc: int | None = None

    for characteristic in sensor.get("characteristics") or []:
        key = str(characteristic.get("characteristic_key") or "").strip()
        if not key:
            continue

        value_type = text_metadata(characteristic, "value_type", "number")
        byte_offset = int_metadata(characteristic, "byte_offset")
        byte_length = int_metadata(characteristic, "byte_length")
        byte_order = text_metadata(characteristic, "byte_order", "big")
        is_signed = bool(characteristic.get("is_signed"))
        crc_offset, crc_length, crc_algorithm = crc_metadata(characteristic, None, None, "none")
        value: float | int | bool | None = None
        raw: int | None = None
        crc = read_check_value(payload, 0, crc_offset, crc_length)
        crc_valid: bool | None = None
        error: str | None = None

        if byte_offset is None or byte_length is None:
            if value_type == "boolean":
                value = True
        elif byte_offset < 0 or byte_length <= 0 or byte_offset + byte_length > len(payload):
            error = "payload_too_short"
        else:
            raw_bytes = payload[byte_offset : byte_offset + byte_length]
            raw = int.from_bytes(
                raw_bytes,
                byteorder=byte_order if byte_order in {"big", "little"} else "big",
                signed=is_signed,
            )
            crc_valid = validate_check_value(payload, byte_offset, byte_length, 0, crc_offset, crc_length, crc_algorithm)
            if crc_valid is not False:
                try:
                    value = evaluate_formula(characteristic.get("formula"), raw, payload)
                except (ArithmeticError, SyntaxError, ValueError) as exc:
                    error = f"formula_error:{exc.__class__.__name__}"
                    value = None
                if value_type == "boolean" and value is not None:
                    value = bool(value)
                value, validation_error = normalize_standard_measurement_value(
                    key,
                    value,
                    characteristic.get("formula"),
                    value_type,
                )
                if validation_error is not None:
                    error = validation_error if error is None else f"{error};{validation_error}"

        decoded_characteristics[key] = {
            "raw": raw,
            "value": value,
            "crc": crc,
            "crc_valid": crc_valid,
            "unit": characteristic.get("unit"),
            "value_type": value_type,
            "formula": characteristic.get("formula"),
            "byte_offset": byte_offset,
            "byte_length": byte_length,
            "error": error,
        }

        if key == "temperature_f":
            temperature_raw = raw if crc_valid is not False else None
            temperature_f = float(value) if value is not None and crc_valid is not False else None
            temperature_c = (temperature_f - 32) * 5 / 9 if temperature_f is not None else None
            temperature_crc = crc
        elif key == "temperature_c":
            temperature_raw = raw if crc_valid is not False else None
            temperature_c = float(value) if value is not None and crc_valid is not False else None
            temperature_f = (temperature_c * 9 / 5) + 32 if temperature_c is not None else None
            temperature_crc = crc
        elif key == "humidity_percent":
            humidity_raw = raw if crc_valid is not False else None
            humidity_percent = float(value) if value is not None and crc_valid is not False else None
            humidity_crc = crc

    decoded = dict(decoded_extra)
    decoded["characteristics"] = decoded_characteristics
    if "temperature_f" in decoded_characteristics:
        temp = decoded_characteristics["temperature_f"]
        decoded["temperature"] = {
            "raw": temp.get("raw"),
            "f": temp.get("value"),
            "c": temperature_c,
            "crc": temp.get("crc"),
            "crc_valid": temp.get("crc_valid"),
            "formula": temp.get("formula"),
        }
    if "humidity_percent" in decoded_characteristics:
        humidity = decoded_characteristics["humidity_percent"]
        decoded["humidity"] = {
            "raw": humidity.get("raw"),
            "percent": humidity.get("value"),
            "crc": humidity.get("crc"),
            "crc_valid": humidity.get("crc_valid"),
            "formula": humidity.get("formula"),
        }
    return DecodedBeacon(
        beacon_type=beacon_type,
        custom_device_id=custom_device_id,
        sensor_type=sensor_type,
        decoder_version=decoder_version,
        temperature_raw=temperature_raw,
        temperature_c=temperature_c,
        temperature_f=temperature_f,
        temperature_crc=temperature_crc,
        humidity_raw=humidity_raw,
        humidity_percent=humidity_percent,
        humidity_crc=humidity_crc,
        decoded=decoded,
    )


def hex_bytes(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return bytes.fromhex(value.strip())
    except ValueError:
        return None


def sensor_registry() -> dict[str, dict[str, Any]]:
    global SENSOR_REGISTRY_CACHE
    now = time.monotonic()
    if SENSOR_REGISTRY_CACHE is not None and now - SENSOR_REGISTRY_CACHE[0] < 30:
        return SENSOR_REGISTRY_CACHE[1]

    registry = {key: dict(value) for key, value in DEFAULT_SENSOR_REGISTRY.items()}
    try:
        with psycopg.connect(DATABASE_URL, row_factory=dict_row) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT custom_device_id, sensor_type, display_name, decoder_function,
                           has_temperature, has_humidity, is_location_only, notes
                    FROM ble_sensor_type_registry;
                    """
                )
                for row in cursor.fetchall():
                    custom_device_id = str(row["custom_device_id"]).upper()
                    registry[custom_device_id] = dict(row)
                cursor.execute(
                    """
                    SELECT custom_device_id, characteristic_key, display_name, value_type,
                           byte_offset, byte_length, byte_order, is_signed,
                           crc_offset, crc_length, crc_algorithm,
                           formula, unit, notes
                    FROM ble_sensor_type_characteristics
                    ORDER BY custom_device_id, characteristic_key;
                    """
                )
                for row in cursor.fetchall():
                    custom_device_id = str(row["custom_device_id"]).upper()
                    registry.setdefault(custom_device_id, {"custom_device_id": custom_device_id})
                    registry[custom_device_id].setdefault("characteristics", []).append(dict(row))
    except Exception:
        pass

    SENSOR_REGISTRY_CACHE = (now, registry)
    return registry


def registry_entry(custom_device_id: str | None) -> dict[str, Any]:
    if not custom_device_id:
        return {
            "custom_device_id": None,
            "sensor_type": "encrypted_unknown",
            "display_name": "Unknown encrypted sensor",
            "decoder_function": "unknown",
            "has_temperature": False,
            "has_humidity": False,
            "is_location_only": False,
        }

    return sensor_registry().get(
        custom_device_id,
        {
            "custom_device_id": custom_device_id,
            "sensor_type": f"pcble_custom_{custom_device_id.lower()}",
            "display_name": f"PCBLE custom device {custom_device_id}",
            "decoder_function": "unknown",
            "has_temperature": False,
            "has_humidity": False,
            "is_location_only": False,
        },
    )


def int_metadata(row: dict[str, Any], key: str, default: int | None = None) -> int | None:
    value = row.get(key)
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def text_metadata(row: dict[str, Any], key: str, default: str) -> str:
    value = str(row.get(key) or default).strip().lower()
    return value or default


def crc_metadata(row: dict[str, Any], offset_default: int | None, length_default: int | None, algorithm_default: str = "sensirion_crc8") -> tuple[int | None, int | None, str]:
    algorithm = text_metadata(row, "crc_algorithm", algorithm_default)
    if algorithm == "none":
        return None, None, algorithm
    return int_metadata(row, "crc_offset", offset_default), int_metadata(row, "crc_length", length_default), algorithm


def key_wrap_key() -> bytes | None:
    key_hex = os.getenv("BLET_KEY_WRAP_KEY_HEX") or str(config_value_from(reload_config_or_cached(), "encryption.key_wrap_key_hex", "")).strip()
    key = hex_bytes(key_hex)
    return key if key is not None and len(key) == 32 else None


def unwrap_tag_key(row: dict[str, Any]) -> bytes:
    if AES is None:
        raise ValueError("pycryptodome_not_installed")
    wrap_key = key_wrap_key()
    if wrap_key is None:
        raise ValueError("key_wrap_key_not_configured")

    nonce = hex_bytes(row.get("key_nonce_hex"))
    encrypted = hex_bytes(row.get("encrypted_key_hex"))
    if nonce is None or encrypted is None or len(nonce) != 12 or len(encrypted) <= 16:
        raise ValueError("invalid_wrapped_key")

    ciphertext = encrypted[:-16]
    auth_tag = encrypted[-16:]
    cipher = AES.new(wrap_key, AES.MODE_GCM, nonce=nonce)
    tag_key = cipher.decrypt_and_verify(ciphertext, auth_tag)
    if len(tag_key) != 16:
        raise ValueError("invalid_tag_key_length")
    return tag_key


def pcble_aes_keys(ble_mac: str | None) -> tuple[list[tuple[str, bytes]], str | None]:
    if not ble_mac:
        return [], "missing_ble_mac"

    now = time.monotonic()
    cached = TAG_KEY_CACHE.get(ble_mac)
    if cached is not None and now - cached[0] < TAG_KEY_CACHE_SECONDS:
        return cached[1], cached[2]

    if AES is None:
        return [], "pycryptodome_not_installed"
    if key_wrap_key() is None:
        reason = "key_wrap_key_not_configured"
        TAG_KEY_CACHE[ble_mac] = (now, [], reason)
        return [], reason

    try:
        with psycopg.connect(DATABASE_URL, row_factory=dict_row) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT key_id, encrypted_key_hex, key_nonce_hex, key_fingerprint
                    FROM ble_tag_security
                    WHERE ble_mac = %s;
                    """,
                    (ble_mac,),
                )
                row = cursor.fetchone()
    except Exception as exc:
        reason = f"key_lookup_failed:{exc.__class__.__name__}"
        TAG_KEY_CACHE[ble_mac] = (now, [], reason)
        return [], reason

    if row is None:
        reason = "tag_not_claimed"
        TAG_KEY_CACHE[ble_mac] = (now, [], reason)
        return [], reason

    try:
        tag_key = unwrap_tag_key(row)
    except ValueError as exc:
        TAG_KEY_CACHE[ble_mac] = (now, [], str(exc))
        return [], str(exc)

    key_id = str(row.get("key_id") or row.get("key_fingerprint") or ble_mac)
    keys = [(key_id, tag_key)]
    TAG_KEY_CACHE[ble_mac] = (now, keys, None)
    return keys, None


def decrypt_pcble_payload(ble_mac: str | None, nonce: bytes, ciphertext: bytes, tag: bytes) -> dict[str, Any]:
    if not ciphertext:
        return {"status": "not_decrypted", "reason": "missing_ciphertext"}

    keys, reason = pcble_aes_keys(ble_mac)
    if not keys:
        return {"status": "not_decrypted", "reason": reason or "no_keys_configured"}
    if AES is None:
        return {"status": "not_decrypted", "reason": "pycryptodome_not_installed"}

    for key_id, key in keys:
        try:
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=len(tag))
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError):
            continue
        custom_device_id_bytes = plaintext[:2] if len(plaintext) >= 2 else b""
        i2c_payload = plaintext[2:] if len(plaintext) > 2 else b""
        custom_device_id_hex = custom_device_id_bytes.hex().upper()
        return {
            "status": "decrypted",
            "key_id": key_id,
            "ble_mac": ble_mac,
            "plaintext_hex": plaintext.hex().upper(),
            "custom_device_id_hex": custom_device_id_hex,
            "product_id_hex": custom_device_id_hex,
            "customer_id_hex": custom_device_id_hex,
            "custom_device_id_little": int.from_bytes(custom_device_id_bytes, "little") if custom_device_id_bytes else None,
            "custom_device_id_big": int.from_bytes(custom_device_id_bytes, "big") if custom_device_id_bytes else None,
            "i2c_payload_hex": i2c_payload.hex().upper(),
        }

    return {"status": "not_decrypted", "reason": "authentication_failed"}


def decrypt_stble_payload(
    ble_mac: str | None,
    salt: bytes,
    ciphertext: bytes,
    tag: bytes,
    custom_device_id: str | None = None,
) -> dict[str, Any]:
    if len(salt) != 8:
        return {"status": "not_decrypted", "reason": "invalid_salt_length"}
    if not ciphertext:
        return {"status": "not_decrypted", "reason": "missing_ciphertext"}
    if len(tag) != 4:
        return {"status": "not_decrypted", "reason": "invalid_authentication_tag_length"}

    keys, reason = pcble_aes_keys(ble_mac)
    if not keys:
        return {"status": "not_decrypted", "reason": reason or "no_keys_configured"}
    if AES is None:
        return {"status": "not_decrypted", "reason": "pycryptodome_not_installed"}

    nonce = salt + bytes(5)
    for key_id, key in keys:
        try:
            cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
            cipher.update(POWERCAST_COMPANY_ID)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError):
            continue

        device_id = custom_device_id or "000A"
        return {
            "status": "decrypted",
            "key_id": key_id,
            "ble_mac": ble_mac,
            "crypto": "aes_ccm",
            "plaintext_hex": plaintext.hex().upper(),
            "custom_device_id_hex": device_id,
            "product_id_hex": device_id,
            "customer_id_hex": device_id,
            "custom_device_id_little": int(device_id, 16),
            "custom_device_id_big": int(device_id, 16),
            "i2c_payload_hex": plaintext.hex().upper(),
        }

    return {"status": "not_decrypted", "reason": "authentication_failed"}




def normalize_hub_decryption(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def decode_stble_from_decryption(raw_data: Any, ble_mac: str | None, decryption: dict[str, Any]) -> DecodedBeacon | None:
    payload = parse_hex_payload(raw_data)
    manufacturer = powercast_manufacturer_body(raw_data)
    if payload is None or manufacturer is None:
        return None

    manufacturer_body, manufacturer_length = manufacturer
    if len(manufacturer_body) < 13:
        return None

    local_name = parse_ble_local_name(raw_data) or "STBLE"
    service_id = service_device_id(raw_data)
    custom_device_id = (
        decryption.get("custom_device_id_hex")
        if decryption.get("status") == "decrypted"
        else service_id
    )
    sensor = registry_entry(custom_device_id)
    salt = manufacturer_body[:8]
    ciphertext = manufacturer_body[8:-4]
    tag = manufacturer_body[-4:]
    nonce = salt + bytes(5)
    decoded_extra = {
        "local_name": local_name,
        "ble_mac": ble_mac,
        "manufacturer_company_id": "02D3",
        "service_device_id": service_id,
        "salt_hex": salt.hex().upper(),
        "nonce_hex": nonce.hex().upper(),
        "ciphertext_hex": ciphertext.hex().upper(),
        "tag_hex": tag.hex().upper(),
        "manufacturer_length": manufacturer_length,
        "decryption": decryption,
    }
    decoded_extra["custom_device_id"] = sensor.get("custom_device_id")
    decoded_extra["sensor_registry"] = {
        "sensor_type": sensor.get("sensor_type"),
        "display_name": sensor.get("display_name"),
        "decoder_function": sensor.get("decoder_function"),
        "has_temperature": sensor.get("has_temperature"),
        "has_humidity": sensor.get("has_humidity"),
        "is_location_only": sensor.get("is_location_only"),
    }

    decrypted_payload = hex_bytes(decryption.get("i2c_payload_hex"))
    characteristics = sensor.get("characteristics") or []
    required_payload_length = characteristic_required_length(characteristics)
    decoder_function = str(sensor.get("decoder_function") or "").strip().casefold()
    if (
        decryption.get("status") == "decrypted"
        and decoder_function in {"registry_characteristics", "stble_registry_decoder", "pcble_registry_decoder"}
        and decrypted_payload is not None
        and len(decrypted_payload) >= required_payload_length
        and characteristics
    ):
        return decode_registry_characteristics(
            decrypted_payload,
            sensor,
            beacon_type="powercast_pcble_encrypted",
            custom_device_id=custom_device_id,
            sensor_type=str(sensor.get("sensor_type") or "stble_encrypted_unknown"),
            decoder_version="powercast_stble_aes_ccm_registry_v1",
            decoded_extra=decoded_extra,
        )

    return DecodedBeacon(
        beacon_type="powercast_pcble_encrypted",
        custom_device_id=custom_device_id,
        sensor_type=str(sensor.get("sensor_type") or "encrypted_unknown"),
        decoder_version="powercast_stble_aes_ccm_v1",
        decoded=decoded_extra,
    )




def decode_powercast_pcble_from_decryption(raw_data: Any, ble_mac: str | None, decryption: dict[str, Any]) -> DecodedBeacon | None:
    payload = parse_hex_payload(raw_data)
    if payload is None or len(payload) < 21 or not payload.startswith(POWERCAST_PCBLE_NAME_PREFIX):
        return None

    manufacturer_length = payload[7]
    manufacturer_end = 8 + manufacturer_length
    if manufacturer_end > len(payload) or payload[8] != 0xFF or payload[9:11] != POWERCAST_COMPANY_ID:
        return None

    adv_count_bytes = payload[11:15]
    salt = payload[15:17]
    tag = payload[manufacturer_end - 2:manufacturer_end]
    ciphertext = payload[17:manufacturer_end - 2]
    nonce = bytes.fromhex("56789ABC") + salt
    decoded_extra = {
        "local_name": "PCBLE",
        "ble_mac": ble_mac,
        "manufacturer_company_id": "02D3",
        "advertising_count": int.from_bytes(adv_count_bytes, "little"),
        "nonce_counter_hex": "56789ABC",
        "nonce_salt_hex": salt.hex().upper(),
        "nonce_hex": nonce.hex().upper(),
        "ciphertext_hex": ciphertext.hex().upper(),
        "tag_hex": tag.hex().upper(),
        "manufacturer_length": manufacturer_length,
        "decryption": decryption,
    }

    custom_device_id = decryption.get("custom_device_id_hex") if decryption.get("status") == "decrypted" else None
    sensor = registry_entry(custom_device_id)
    decoded_extra["custom_device_id"] = sensor.get("custom_device_id")
    decoded_extra["sensor_registry"] = {
        "sensor_type": sensor.get("sensor_type"),
        "display_name": sensor.get("display_name"),
        "decoder_function": sensor.get("decoder_function"),
        "has_temperature": sensor.get("has_temperature"),
        "has_humidity": sensor.get("has_humidity"),
        "is_location_only": sensor.get("is_location_only"),
    }

    i2c_payload = hex_bytes(decryption.get("i2c_payload_hex"))
    characteristics = sensor.get("characteristics") or []
    required_payload_length = characteristic_required_length(characteristics)
    decoder_function = str(sensor.get("decoder_function") or "").strip().casefold()
    if (
        decryption.get("status") == "decrypted"
        and decoder_function in {"registry_characteristics", "temperature_humidity_v1", "pcble_registry_decoder"}
        and i2c_payload is not None
        and len(i2c_payload) >= required_payload_length
        and characteristics
    ):
        return decode_registry_characteristics(
            i2c_payload,
            sensor,
            beacon_type="powercast_pcble_encrypted",
            custom_device_id=custom_device_id,
            sensor_type=str(sensor.get("sensor_type") or "encrypted_temperature_humidity"),
            decoder_version="powercast_pcble_registry_decoder_v1",
            decoded_extra=decoded_extra,
        )

    return DecodedBeacon(
        beacon_type="powercast_pcble_encrypted",
        custom_device_id=custom_device_id,
        sensor_type=str(sensor.get("sensor_type") or "encrypted_unknown"),
        decoder_version="powercast_pcble_aes_eax_v1",
        decoded=decoded_extra,
    )


def decode_powercast_pcble(raw_data: Any, ble_mac: str | None = None, provided_decryption: Any = None) -> DecodedBeacon | None:
    payload = parse_hex_payload(raw_data)
    manufacturer = powercast_manufacturer_body(raw_data)
    local_name = (parse_ble_local_name(raw_data) or "").upper()
    custom_device_id_hint = service_device_id(raw_data)
    if payload is None or manufacturer is None:
        return None

    manufacturer_body, _manufacturer_length = manufacturer
    if local_name not in {"PCBLE", "STBLE"} or len(manufacturer_body) < 4:
        return None

    # 000A uses the STBLE AES-CCM payload layout. Some scanner firmware reports
    # that local name as PCBLE and may omit the separate service-data field, so
    # authenticated format detection is used before the legacy EAX fallback.
    stble_candidate = local_name == "STBLE" or custom_device_id_hint == "000A" or len(manufacturer_body) == 13
    normalized_provided = normalize_hub_decryption(provided_decryption)
    if normalized_provided and normalized_provided.get("status") == "decrypted":
        if normalized_provided.get("crypto") == "aes_ccm" or stble_candidate:
            return decode_stble_from_decryption(raw_data, ble_mac, normalized_provided)
        return decode_powercast_pcble_from_decryption(raw_data, ble_mac, normalized_provided)

    configured_location = decrypt_location()
    if configured_location == "hub":
        decryption = normalized_provided or {"status": "not_decrypted", "reason": "hub_decryption_missing"}
        if stble_candidate:
            return decode_stble_from_decryption(raw_data, ble_mac, decryption)
        return decode_powercast_pcble_from_decryption(raw_data, ble_mac, decryption)

    stble_decryption: dict[str, Any] | None = None
    if stble_candidate and len(manufacturer_body) >= 13:
        salt = manufacturer_body[:8]
        ciphertext = manufacturer_body[8:-4]
        tag = manufacturer_body[-4:]
        stble_decryption = decrypt_stble_payload(ble_mac, salt, ciphertext, tag, custom_device_id_hint)
        if stble_decryption.get("status") == "decrypted":
            return decode_stble_from_decryption(raw_data, ble_mac, stble_decryption)

    # Legacy PCBLE AES-EAX packets retain the original fixed counter and the
    # short salt/tag layout. Authentication must succeed before any plaintext
    # is used; a failed STBLE attempt is never treated as decoded data.
    if len(payload) >= 21 and payload.startswith(POWERCAST_PCBLE_NAME_PREFIX):
        manufacturer_length = payload[7]
        manufacturer_end = 8 + manufacturer_length
        if manufacturer_end <= len(payload) and payload[8] == 0xFF and payload[9:11] == POWERCAST_COMPANY_ID:
            salt = payload[15:17]
            tag = payload[manufacturer_end - 2:manufacturer_end]
            ciphertext = payload[17:manufacturer_end - 2]
            nonce = bytes.fromhex("56789ABC") + salt
            decryption = decrypt_pcble_payload(ble_mac, nonce, ciphertext, tag)
            if decryption.get("status") == "decrypted" or stble_decryption is None:
                return decode_powercast_pcble_from_decryption(raw_data, ble_mac, decryption)

    return decode_stble_from_decryption(raw_data, ble_mac, stble_decryption or {"status": "not_decrypted", "reason": "authentication_failed"})


def decode_wine7_rfid(raw_data: Any) -> dict[str, Any] | None:
    body = wine7_rfid_manufacturer_body(raw_data)
    if body is None:
        return None
    if len(body) < 9 or body[:2] != WINE7_RFID_MAGIC:
        return None

    version = body[2]
    sequence = int.from_bytes(body[3:5], "little")
    flags = body[5]
    pc = int.from_bytes(body[6:8], "big")
    epc_len = body[8]
    epc_prefix = body[9:]
    advertised_epc_len = min(epc_len, len(epc_prefix))
    epc_hex = epc_prefix[:advertised_epc_len].hex().upper()
    truncated = bool(flags & 0x01) or epc_len > advertised_epc_len

    return {
        "local_name": "W7RF",
        "manufacturer_company_id": "FFFF",
        "version": version,
        "sequence": sequence,
        "flags": flags,
        "pc_hex": f"{pc:04X}",
        "pc": pc,
        "epc_len": epc_len,
        "epc_hex": epc_hex,
        "truncated": truncated,
    }


def decode_beacon(packet: dict[str, Any]) -> dict[str, Any]:
    raw_data = packet.get("RawData")
    decoded = decode_powercast_blet(raw_data)
    if decoded is not None:
        return decoded.as_row()

    decoded = decode_powercast_pcble(raw_data, canonical_mac(packet.get("BLEMAC")), packet.get("PCBLEDecryption"))
    if decoded is not None:
        return decoded.as_row()

    return DecodedBeacon().as_row()


def normalize_modern_gateway_envelope(payload: dict[str, Any]) -> list[dict[str, Any]]:
    gateway_mac = canonical_mac(payload.get("device_info", {}).get("mac"))
    msg_id = payload.get("msg_id")
    data = payload.get("data")
    records = data if isinstance(data, list) else [data]
    packets: list[dict[str, Any]] = []

    for record in records:
        if not isinstance(record, dict):
            continue

        if "adv_data" in record:
            packets.append(
                {
                    "TimeStamp": record.get("timestamp"),
                    "Format": "RawData",
                    "GatewayMAC": gateway_mac,
                    "BLEMAC": canonical_mac(record.get("mac")),
                    "RSSI": record.get("rssi"),
                    "AdvType": record.get("type"),
                    "BLEName": record.get("ble_name") or parse_ble_local_name(record.get("adv_data")),
                    "RawData": str(record.get("adv_data", "")).upper(),
                    "PCBLEDecryption": record.get("pcble_decryption"),
                    "payload": {
                        "msg_id": msg_id,
                        "device_info": payload.get("device_info"),
                        "data": record,
                    },
                }
            )
            continue

        packets.append(
            {
                "TimeStamp": record.get("timestamp"),
                "Format": "GatewayStatus",
                "GatewayMAC": gateway_mac,
                "payload": {
                    "msg_id": msg_id,
                    "device_info": payload.get("device_info"),
                    "data": record,
                },
            }
        )

    return packets


def normalize_rfid_gateway_envelope(payload: dict[str, Any]) -> list[dict[str, Any]]:
    device_info = payload.get("device_info")
    data = payload.get("data")
    if not isinstance(device_info, dict):
        return []
    records = data if isinstance(data, list) else [data]
    gateway_mac = canonical_mac(device_info.get("mac"))
    msg_id = payload.get("msg_id")
    packets: list[dict[str, Any]] = []

    for record in records:
        if not isinstance(record, dict):
            continue
        packets.append(
            {
                "TimeStamp": record.get("timestamp"),
                "Format": "RFIDEvent",
                "GatewayMAC": gateway_mac,
                "RSSI": record.get("rssi"),
                "RFIDValueType": record.get("value_type"),
                "RFIDEPC": record.get("epc"),
                "RFIDTID": record.get("tid"),
                "RFIDReaderTimestamp": record.get("reader_timestamp"),
                "RFIDNote": record.get("note"),
                "RFIDValue": record.get("value"),
                "payload": {
                    "msg_id": msg_id,
                    "device_info": device_info,
                    "data": record,
                },
            }
        )

    return packets


def expand_payload(data: Any, topic: str | None = None) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [packet for packet in data if isinstance(packet, dict)]

    if isinstance(data, dict) and "device_info" in data and "data" in data:
        protocol = str(data.get("device_info", {}).get("protocol") or "").strip().lower()
        if protocol in {"pct-er-2025-05-json", "rfid_json_reader_v1"}:
            return normalize_rfid_gateway_envelope(data)
        records = data.get("data")
        if isinstance(records, list) and any(isinstance(record, dict) and "value_type" in record for record in records):
            return normalize_rfid_gateway_envelope(data)
        if isinstance(topic, str) and topic.startswith("/rfid/observations/"):
            return normalize_rfid_gateway_envelope(data)
        return normalize_modern_gateway_envelope(data)

    if isinstance(data, dict):
        return [data]

    return []


def normalize_packet(
    topic: str,
    packet: dict[str, Any],
    received_at: datetime,
    gateway_mac: str | None = None,
) -> dict[str, Any]:
    w7rf = decode_wine7_rfid(packet.get("RawData"))
    if w7rf is not None:
        received_by_gateway_mac = canonical_mac(packet.get("GatewayMAC")) or gateway_mac
        rfid_hub_mac = canonical_mac(packet.get("BLEMAC")) or received_by_gateway_mac
        value = Jsonb({
            **w7rf,
            "transport": "ble_advertisement",
            "received_by_gateway_mac": received_by_gateway_mac,
            "source_ble_mac": canonical_mac(packet.get("BLEMAC")),
        })
        note = "WINE7 RFID Hub via BLE advertisement"
        if w7rf.get("truncated"):
            note += " (truncated EPC)"
        return {
            "row_kind": "rfid",
            "time": parse_timestamp(packet.get("TimeStamp")),
            "received_at": received_at,
            "topic": topic,
            "gateway_mac": rfid_hub_mac,
            "format": "RFIDEvent",
            "rfid_value_type": "epc",
            "epc": canonical_mac(w7rf.get("epc_hex")),
            "tid": None,
            "rssi": packet.get("RSSI"),
            "reader_timestamp": w7rf.get("sequence"),
            "note": note,
            "value_json": value,
            "payload": json.dumps(packet.get("payload", packet), separators=(",", ":")),
        }

    if packet.get("Format") == "RFIDEvent":
        value = packet.get("RFIDValue")
        if value is not None and not isinstance(value, Jsonb):
            value = Jsonb(value)
        return {
            "row_kind": "rfid",
            "time": parse_timestamp(packet.get("TimeStamp")),
            "received_at": received_at,
            "topic": topic,
            "gateway_mac": canonical_mac(packet.get("GatewayMAC")) or gateway_mac,
            "format": packet.get("Format"),
            "rfid_value_type": packet.get("RFIDValueType"),
            "epc": canonical_mac(packet.get("RFIDEPC")),
            "tid": canonical_mac(packet.get("RFIDTID")),
            "rssi": packet.get("RSSI"),
            "reader_timestamp": packet.get("RFIDReaderTimestamp"),
            "note": packet.get("RFIDNote"),
            "value_json": value,
            "payload": json.dumps(packet.get("payload", packet), separators=(",", ":")),
        }

    decoded = decode_beacon(packet)
    row = {
        "row_kind": "ble",
        "time": parse_timestamp(packet.get("TimeStamp")),
        "received_at": received_at,
        "first_seen_at": None,
        "last_seen_at": None,
        "topic": topic,
        "gateway_mac": canonical_mac(packet.get("GatewayMAC")) or gateway_mac,
        "gateway_macs": None,
        "gateway_rssi": None,
        "gateway_rssi_counts": None,
        "format": packet.get("Format"),
        "ble_mac": canonical_mac(packet.get("BLEMAC")),
        "ble_name": packet.get("BLEName") or parse_ble_local_name(packet.get("RawData")),
        "rssi": packet.get("RSSI"),
        "adv_type": packet.get("AdvType"),
        "pri_phy": packet.get("PriPHY"),
        "sec_phy": packet.get("SecPHY"),
        "raw_data": packet.get("RawData"),
        "sample_count": 1,
        "payload": json.dumps(packet.get("payload", packet), separators=(",", ":")),
    }
    row["first_seen_at"] = row["time"]
    row["last_seen_at"] = row["time"]
    row["gateway_macs"] = Jsonb([row["gateway_mac"]] if row["gateway_mac"] else [])
    row["gateway_rssi_counts"] = Jsonb(
        {row["gateway_mac"]: {"avg": row["rssi"], "sample_count": 1}} if row["gateway_mac"] and row["rssi"] is not None else {}
    )
    row["gateway_rssi"] = format_gateway_rssi_value(row["gateway_rssi_counts"])
    row.update(decoded)
    if row.get("beacon_type") == "powercast_blet":
        row["ble_name"] = parse_ble_local_name(row.get("raw_data")) or "BLET"
    elif row.get("beacon_type") == "powercast_pcble_encrypted":
        row["ble_name"] = parse_ble_local_name(row.get("raw_data")) or "PCBLE"
    if row.get("decoded") is not None and not isinstance(row["decoded"], Jsonb):
        row["decoded"] = Jsonb(json.loads(row["decoded"]))
    return sanitize_decoded_measurements(row)


def expand_w7rf_read_count(row: dict[str, Any]) -> list[dict[str, Any]]:
    value = jsonb_obj(row.get("value_json"))
    if value.get("local_name") != "W7RF":
        return [row]

    try:
        current_count = int(row.get("reader_timestamp")) & 0xFFFF
    except (TypeError, ValueError):
        return [row]

    key = (row.get("gateway_mac"), row.get("epc"), value.get("source_ble_mac"))
    previous_count = W7RF_LAST_READ_COUNT.get(key)
    previous_emit_time = W7RF_LAST_EMIT_TIME.get(key)
    W7RF_LAST_READ_COUNT[key] = current_count

    if previous_count is None:
        delta = 1
        first_count = current_count
    elif current_count == previous_count:
        row_time = row.get("time")
        if (
            not isinstance(row_time, datetime)
            or previous_emit_time is not None
            and (row_time - previous_emit_time).total_seconds() < W7RF_PRESENCE_KEEPALIVE_SECONDS
        ):
            return []
        delta = 1
        first_count = current_count
    elif current_count > previous_count:
        delta = current_count - previous_count
        first_count = previous_count + 1
    else:
        wrapped_delta = current_count + 0x10000 - previous_count
        if wrapped_delta > W7RF_MAX_PLAUSIBLE_DELTA:
            delta = 1
            first_count = current_count
        else:
            delta = wrapped_delta
            first_count = previous_count + 1

    expanded: list[dict[str, Any]] = []
    for index in range(max(delta, 1)):
        expanded_row = row.copy()
        expanded_row["reader_timestamp"] = (first_count + index) & 0xFFFF
        expanded_row["value_json"] = Jsonb({
            **value,
            "read_count": current_count,
            "read_count_delta": delta,
            "expanded_read_index": index + 1,
            "presence_keepalive": current_count == previous_count,
        })
        expanded.append(expanded_row)
    if expanded and isinstance(row.get("time"), datetime):
        W7RF_LAST_EMIT_TIME[key] = row["time"]
    return expanded


def filter_rows_by_min_interval(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if MIN_READING_INTERVAL_SECONDS <= 0:
        return rows

    filtered: list[dict[str, Any]] = []
    latest_by_mac: dict[str, datetime] = {}
    candidate_macs = sorted(
        {
            row["ble_mac"]
            for row in rows
            if row.get("ble_mac") and row.get("sensor_type")
        }
    )

    if candidate_macs:
        with psycopg.connect(DATABASE_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT ble_mac, max(time)
                    FROM raw_ble_packets
                    WHERE ble_mac = ANY(%s)
                      AND sensor_type IS NOT NULL
                    GROUP BY ble_mac;
                    """,
                    (candidate_macs,),
                )
                latest_by_mac = {ble_mac: latest_time for ble_mac, latest_time in cursor.fetchall()}

    for row in sorted(rows, key=lambda item: item["time"]):
        ble_mac = row.get("ble_mac")
        sensor_type = row.get("sensor_type")
        if not ble_mac or not sensor_type:
            filtered.append(row)
            continue

        latest_time = latest_by_mac.get(ble_mac)
        if latest_time is not None and (row["time"] - latest_time).total_seconds() < MIN_READING_INTERVAL_SECONDS:
            continue

        filtered.append(row)
        latest_by_mac[ble_mac] = row["time"]

    return filtered


def filter_supported_sensor_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for row in rows:
        if row.get("row_kind") == "rfid":
            filtered.append(row)
            continue
        if row.get("beacon_type") in {"powercast_blet", "powercast_pcble_encrypted"}:
            filtered.append(row)
    return filtered


def jsonb_list(value: Any) -> list[str]:
    if isinstance(value, Jsonb):
        value = value.obj
    if not isinstance(value, list):
        return []
    return sorted({str(item) for item in value if item})


def jsonb_obj(value: Any) -> dict[str, Any]:
    if isinstance(value, Jsonb):
        value = value.obj
    return value if isinstance(value, dict) else {}


def value_in_range(value: Any, minimum: float, maximum: float) -> bool:
    if value is None:
        return False
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return False
    return math.isfinite(numeric) and minimum <= numeric <= maximum


def standard_measurement_limit(field: str) -> tuple[float, float] | None:
    if field == "temperature_f":
        return (TEMPERATURE_F_MIN, TEMPERATURE_F_MAX)
    if field == "temperature_c":
        return (TEMPERATURE_C_MIN, TEMPERATURE_C_MAX)
    if field == "humidity_percent":
        return (HUMIDITY_PERCENT_MIN, HUMIDITY_PERCENT_MAX)
    return None


def sanitize_measurement_value(field: str, value: Any) -> Any:
    limits = standard_measurement_limit(field)
    if limits is None or value is None:
        return value
    return value if value_in_range(value, limits[0], limits[1]) else None


def sanitize_decoded_measurements(row: dict[str, Any]) -> dict[str, Any]:
    for field in ("temperature_c", "temperature_f", "humidity_percent"):
        if row.get(field) is not None and sanitize_measurement_value(field, row.get(field)) is None:
            row[field] = None
            if field.startswith("temperature"):
                row["temperature_raw"] = None
            elif field == "humidity_percent":
                row["humidity_raw"] = None
    return row


def average_value(current: Any, current_count: int, incoming: Any, incoming_count: int) -> Any:
    if current is None:
        return incoming
    if incoming is None:
        return current
    return ((float(current) * current_count) + (float(incoming) * incoming_count)) / (current_count + incoming_count)


def average_measurement_value(field: str, current: Any, current_count: int, incoming: Any, incoming_count: int) -> Any:
    incoming = sanitize_measurement_value(field, incoming)
    current = sanitize_measurement_value(field, current)
    if current is None:
        return incoming
    if incoming is None:
        return current
    if field == "temperature_f" and abs(float(current) - float(incoming)) > COMPACT_MAX_TEMPERATURE_DELTA_F:
        return current
    if field == "temperature_c" and abs(float(current) - float(incoming)) > (COMPACT_MAX_TEMPERATURE_DELTA_F * 5 / 9):
        return current
    if field == "humidity_percent" and abs(float(current) - float(incoming)) > COMPACT_MAX_HUMIDITY_DELTA_PERCENT:
        return current
    return average_value(current, current_count, incoming, incoming_count)


def format_gateway_rssi_value(gateway_rssi_counts: Any) -> str | None:
    parts: list[str] = []
    for gateway, value in sorted(jsonb_obj(gateway_rssi_counts).items()):
        if not isinstance(value, dict) or value.get("avg") is None:
            continue
        parts.append(f"{gateway}:{round(float(value['avg']))}")
    return f"[{', '.join(parts)}]" if parts else None


def merge_gateway_rssi_counts_values(current: Any, incoming: Any) -> Jsonb:
    merged: dict[str, dict[str, float | int]] = {}

    for source in (jsonb_obj(current), jsonb_obj(incoming)):
        for gateway, value in source.items():
            if not isinstance(value, dict) or value.get("avg") is None:
                continue

            incoming_avg = float(value["avg"])
            incoming_count = max(int(value.get("sample_count") or 1), 1)
            if gateway not in merged:
                merged[gateway] = {"avg": incoming_avg, "sample_count": incoming_count}
                continue

            existing = merged[gateway]
            existing_count = int(existing["sample_count"])
            merged_count = existing_count + incoming_count
            existing["avg"] = ((float(existing["avg"]) * existing_count) + (incoming_avg * incoming_count)) / merged_count
            existing["sample_count"] = merged_count

    return Jsonb(merged)


def best_gateway_mac_by_rssi_value(gateway_rssi_counts: Any, fallback: str | None = None) -> str | None:
    candidates: list[tuple[float, str]] = []
    for gateway, value in jsonb_obj(gateway_rssi_counts).items():
        if not isinstance(value, dict) or value.get("avg") is None:
            continue
        candidates.append((abs(float(value["avg"])), gateway))

    if not candidates:
        return fallback

    return sorted(candidates)[0][1]


def merge_compact_row(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    current_count = int(target["sample_count"])
    incoming_count = int(incoming["sample_count"])

    target["received_at"] = max(target["received_at"], incoming["received_at"])
    target["first_seen_at"] = min(target["first_seen_at"], incoming["first_seen_at"])
    target["last_seen_at"] = max(target["last_seen_at"], incoming["last_seen_at"])
    target["gateway_macs"] = Jsonb(sorted(set(jsonb_list(target["gateway_macs"]) + jsonb_list(incoming["gateway_macs"]))))
    target["gateway_rssi_counts"] = merge_gateway_rssi_counts_values(target["gateway_rssi_counts"], incoming["gateway_rssi_counts"])
    target["gateway_rssi"] = format_gateway_rssi_value(target["gateway_rssi_counts"])
    target["gateway_mac"] = best_gateway_mac_by_rssi_value(target["gateway_rssi_counts"], target["gateway_mac"])

    target["rssi"] = None if average_value(target["rssi"], current_count, incoming["rssi"], incoming_count) is None else round(average_value(target["rssi"], current_count, incoming["rssi"], incoming_count))
    for field in ("temperature_c", "temperature_f", "humidity_percent"):
        target[field] = average_measurement_value(field, target[field], current_count, incoming[field], incoming_count)

    for field in ("raw_data", "custom_device_id", "temperature_raw", "temperature_crc", "humidity_raw", "humidity_crc", "decoded", "payload"):
        if incoming.get(field) is not None:
            target[field] = incoming[field]

    target["sample_count"] = current_count + incoming_count


def compact_decoded_rows(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    passthrough: list[dict[str, Any]] = []
    compacted: dict[tuple[datetime, str, str], dict[str, Any]] = {}

    for row in rows:
        if not COMPACT_DECODED_READINGS or not row.get("ble_mac") or not row.get("sensor_type"):
            passthrough.append(row)
            continue

        row = row.copy()
        row["time"] = bucket_timestamp(row["time"], COMPACT_BUCKET_SECONDS)
        key = (row["time"], row["ble_mac"], row["sensor_type"])
        if key not in compacted:
            compacted[key] = row
            continue

        merge_compact_row(compacted[key], row)

    return passthrough, list(compacted.values())


def merge_rows_by_key(rows: list[dict[str, Any]], key_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    merged: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        key = tuple(row.get(field) for field in key_fields)
        if key not in merged:
            merged[key] = row
            continue
        merge_compact_row(merged[key], row)
    return list(merged.values())


def latest_rows_by_mac(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        ble_mac = row.get("ble_mac")
        if not ble_mac:
            continue
        existing = latest.get(ble_mac)
        if existing is None or row.get("last_seen_at") >= existing.get("last_seen_at"):
            latest[ble_mac] = row
    return list(latest.values())


def ensure_schema() -> None:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(SCHEMA_SQL)


def rows_from_payload(topic: str, payload: bytes, received_at: datetime) -> list[dict[str, Any]]:
    data = json.loads(payload.decode("utf-8", errors="replace"))
    packets = expand_payload(data, topic)
    rows: list[dict[str, Any]] = []
    current_gateway_mac: str | None = None

    for packet in packets:
        if not isinstance(packet, dict):
            continue

        packet_gateway_mac = canonical_mac(packet.get("GatewayMAC"))
        if packet_gateway_mac:
            current_gateway_mac = packet_gateway_mac

        rows.extend(expand_w7rf_read_count(normalize_packet(topic, packet, received_at, current_gateway_mac)))

    rows = filter_supported_sensor_rows(rows)
    return rows if COMPACT_DECODED_READINGS else filter_rows_by_min_interval(rows)


def insert_rows(rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0

    rfid_rows = [row for row in rows if row.get("row_kind") == "rfid"]
    ble_rows = [row for row in rows if row.get("row_kind") != "rfid"]
    passthrough_rows, compact_rows = compact_decoded_rows(ble_rows)
    observation_rows = merge_rows_by_key(
        [row for row in compact_rows if row.get("ble_mac") and row.get("sensor_type")],
        ("time", "ble_mac", "sensor_type"),
    )
    current_state_rows = latest_rows_by_mac(observation_rows)
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            if rfid_rows:
                cursor.executemany(RFID_INSERT_SQL, rfid_rows)
                cursor.executemany(
                    RFID_HUB_UPSERT_SQL,
                    [row for row in rfid_rows if row.get("gateway_mac")],
                )
            if passthrough_rows:
                cursor.executemany(INSERT_SQL, passthrough_rows)
            for row in compact_rows:
                cursor.execute(COMPACT_UPDATE_SQL, row)
                if cursor.rowcount == 0:
                    cursor.execute(INSERT_SQL, row)
            for row in observation_rows:
                cursor.execute(OBSERVATION_UPSERT_SQL, row)
            for row in current_state_rows:
                cursor.execute(CURRENT_STATE_UPSERT_SQL, row)
    return len(rfid_rows) + len(passthrough_rows) + len(compact_rows)


def insert_message_batch(messages: list[tuple[str, bytes]]) -> int:
    received_at = datetime.now(UTC)
    rows: list[dict[str, Any]] = []
    for topic, payload in messages:
        try:
            rows.extend(rows_from_payload(topic, payload, received_at))
        except json.JSONDecodeError as exc:
            print(f"Dropped invalid JSON MQTT payload from {topic}: {exc}")
    return insert_rows(rows)


def flush_message_buffer() -> int:
    with MESSAGE_BUFFER_LOCK:
        if not MESSAGE_BUFFER:
            return 0
        messages = list(MESSAGE_BUFFER)
        MESSAGE_BUFFER.clear()

    try:
        count = insert_message_batch(messages)
    except Exception:
        with MESSAGE_BUFFER_LOCK:
            MESSAGE_BUFFER[:0] = messages
        raise
    print(f"Stored {count} packet row(s) from {len(messages)} MQTT message(s)")
    return count


def ingest_buffer_worker() -> None:
    while True:
        MESSAGE_BUFFER_EVENT.wait(INGEST_BATCH_FLUSH_SECONDS)
        MESSAGE_BUFFER_EVENT.clear()
        try:
            flush_message_buffer()
        except Exception as exc:
            print(f"Failed to flush MQTT batch: {exc}")


def on_connect(client: mqtt.Client, _userdata: Any, _flags: dict[str, Any], reason_code: int, _properties: Any) -> None:
    if reason_code == 0:
        for topic in MQTT_TOPICS:
            client.subscribe(topic, qos=1)
        print(f"Subscribed to {', '.join(MQTT_TOPICS)}")
    else:
        print(f"MQTT connection failed with reason code {reason_code}")


def on_message(_client: mqtt.Client, _userdata: Any, message: mqtt.MQTTMessage) -> None:
    with MESSAGE_BUFFER_LOCK:
        MESSAGE_BUFFER.append((message.topic, bytes(message.payload)))
        should_flush = len(MESSAGE_BUFFER) >= INGEST_BATCH_MESSAGES
    if should_flush:
        MESSAGE_BUFFER_EVENT.set()


def main() -> None:
    threading.Thread(target=ingest_buffer_worker, daemon=True).start()
    while True:
        try:
            ensure_schema()
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="hub-native-ingester")
            client.on_connect = on_connect
            client.on_message = on_message
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
            client.loop_forever()
        except Exception as exc:
            print(f"Hub ingester error: {exc}; retrying in 5s")
            time.sleep(5)


if __name__ == "__main__":
    main()
