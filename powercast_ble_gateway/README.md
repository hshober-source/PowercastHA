# Powercast BLE Gateway App

This Home Assistant app is a standalone local deployment:

`Powercast BLE tags -> local BLE adapter -> local Mosquitto -> Home Assistant`

It does not send sensor packets, decoded readings, or tag keys to Powercast
servers, an edge server, or a cloud service. The default broker is Home
Assistant's local `core-mosquitto` app.

## Features

- Active or passive BLE scanning for `BLET`, `PCBLE`, and `STBLE` advertisements.
- A local Seen Tags and Adopted Tags workflow.
- Local authenticated decryption for adopted encrypted tags.
- Sensirion CRC-8 validation for each legacy BLET temperature and humidity word;
  failed fields are not sent to Home Assistant.
- Home Assistant MQTT Discovery entities for valid measurements and RSSI.
- A bundled key-free sensor type registry, including current device IDs through
  `000E`.

## Security Model

Tag AES keys are entered only during local adoption and are stored in the
add-on data volume with owner-only permissions. The app does not return keys
through its web API and never includes them in MQTT discovery or state payloads.
Use an authenticated Mosquitto account for this app; do not enable anonymous
MQTT access merely to connect the gateway.

## Maintaining Sensor Types

`registry/sensor_types.json` is the public source of truth for published sensor
type definitions. Update it whenever a new type is approved, then run:

```bash
python scripts/sync_registry.py
python scripts/check_registry.py
```

The validation workflow prevents a release when the bundled runtime registry is
out of sync with the public registry.
