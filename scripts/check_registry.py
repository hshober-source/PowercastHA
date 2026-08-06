from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "registry" / "sensor_types.json"
TARGET = ROOT / "powercast_ble_gateway" / "vendor" / "python_ble_hub" / "sensor_types.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    if not SOURCE.is_file() or not TARGET.is_file():
        raise SystemExit("Sensor type registry source or bundled runtime registry is missing")
    if digest(SOURCE) != digest(TARGET):
        raise SystemExit("Bundled registry is stale. Run: python scripts/sync_registry.py")
    print("Sensor type registry is synchronized")


if __name__ == "__main__":
    main()
