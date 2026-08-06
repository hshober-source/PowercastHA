# Powercast Home Assistant Add-ons

This repository publishes the standalone **Powercast BLE Gateway** app for
Home Assistant OS and Home Assistant Supervised installations.

The supported independent deployment path is:

```text
Powercast BLE tags -> Powercast BLE Gateway app -> local Mosquitto -> Home Assistant
```

The app scans Bluetooth advertisements on the Home Assistant host, keeps its
own local adoption/key registry, decrypts only adopted encrypted tags, and
publishes Home Assistant MQTT Discovery entities through the local broker. No
Powercast edge server, cloud account, external MQTT broker, or Internet
connection is needed for normal operation after installation.

## Install

1. In Home Assistant, open **Settings -> Apps -> App store**.
2. Open the menu, choose **Repositories**, then **Add repository**.
3. Enter `https://github.com/hshober-source/PowercastHA`.
4. Install **Powercast BLE Gateway**.
5. Install and start the official **Mosquitto broker** app if it is not already
   present. Create a dedicated MQTT login for the gateway.
6. Configure and start **Powercast BLE Gateway**, then adopt tags from its
   **Seen Tags** page.

The default MQTT host is `core-mosquitto`, which is the local Home Assistant
broker. Use an external MQTT host only when deliberately integrating another
system.

## Sensor Types

The public, key-free registry is at [registry/sensor_types.json](registry/sensor_types.json).
It currently includes legacy BLET, encrypted PCBLE, STBLE boolean, and the
current LoRa SHT40 type definitions. Tag AES keys are never stored in this
repository.

## Development

Run the registry checks before publishing a change:

```bash
python scripts/sync_registry.py
python scripts/check_registry.py
```

The GitHub Actions workflow enforces this invariant for pull requests and
pushes to `main`.
