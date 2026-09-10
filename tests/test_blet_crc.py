import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DECODER = ROOT / "powercast_ble_gateway" / "vendor" / "hub_ingester.py"
SPEC = importlib.util.spec_from_file_location("powercast_hub_ingester", DECODER)
assert SPEC is not None and SPEC.loader is not None
hub_ingester = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hub_ingester)


class BletCrcTests(unittest.TestCase):
    def decode(self, raw_data: str) -> tuple[dict, dict]:
        beacon = hub_ingester.decode_powercast_blet(raw_data)
        self.assertIsNotNone(beacon)
        row = beacon.as_row()
        return row, json.loads(row["decoded"])

    def test_known_good_blet_packet_decodes(self) -> None:
        row, decoded = self.decode("0509424c455409ffd30261df0a625211")
        self.assertIsNotNone(row["temperature_f"])
        self.assertIsNotNone(row["humidity_percent"])
        self.assertTrue(decoded["temperature"]["crc_valid"])
        self.assertTrue(decoded["humidity"]["crc_valid"])

    def test_invalid_sensor_check_bytes_do_not_produce_measurements(self) -> None:
        row, decoded = self.decode("0509424c455409ffd302000000000000")
        self.assertIsNone(row["temperature_f"])
        self.assertIsNone(row["humidity_percent"])
        self.assertFalse(decoded["temperature"]["crc_valid"])
        self.assertFalse(decoded["humidity"]["crc_valid"])


if __name__ == "__main__":
    unittest.main()
