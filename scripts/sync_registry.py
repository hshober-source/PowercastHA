from __future__ import annotations

import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "registry" / "sensor_types.json"
TARGET = ROOT / "powercast_ble_gateway" / "vendor" / "python_ble_hub" / "sensor_types.json"


def main() -> None:
    if not SOURCE.is_file():
        raise SystemExit(f"Missing source registry: {SOURCE}")
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SOURCE, TARGET)
    print(f"Synchronized {TARGET.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
