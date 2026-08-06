# Powercast BLE Gateway

Install this app on Home Assistant OS or a Supervised installation to scan Powercast BLE tags, maintain a local adopted-tag registry, decrypt adopted PCBLE/STBLE tags locally, and create MQTT Discovery entities in Home Assistant.

## Installation

1. In Home Assistant, open **Settings -> Apps -> App store**.
2. Open the repository menu, choose **Add repository**, and enter the repository URL.
3. Locate **Powercast BLE Gateway**, install it, and start it.
4. Open the app panel, set the gateway MAC and MQTT connection, then adopt tags from **Seen Tags**.

Use this public repository:

```text
https://github.com/hshober-source/PowercastHA
```

## Security

Only adopted tags publish Home Assistant entities. Encrypted packets must authenticate successfully and match the adopted device type. The app stores the local key file owner-only and never exposes keys through its web API, MQTT discovery, or entity state.

## Bluetooth access

The app requests host D-Bus access for BlueZ. Do not run another BLE scanner against the same adapter at the same time. In a migration, stop the old scanner only after its MQTT destinations have been reproduced in the app settings.
