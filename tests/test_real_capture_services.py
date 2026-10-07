from __future__ import annotations

import ipaddress
import unittest
from pathlib import Path

from scapy.all import rdpcap  # type: ignore

from asset_probe.passive import analyze_packets
from asset_probe.protocol_detector import detect_opcua_payload, parse_service_type_id


ROOT = Path(__file__).resolve().parents[1]
LOCAL_NETS = [ipaddress.IPv4Network("192.168.0.0/16")]


def _operation_hints(path: Path) -> dict[str, int]:
    hints: dict[str, int] = {}
    for asset in analyze_packets(rdpcap(str(path)), LOCAL_NETS):
        for operation, count in asset.protocol_metadata.opcua.get("operation_hints", {}).items():
            hints[operation] = hints.get(operation, 0) + count
    return hints


def _msg_with_type_id(encoded_type_id: bytes) -> bytes:
    body = bytearray(32)
    body[:4] = b"MSGF"
    body[4:8] = len(body).to_bytes(4, "little")
    body[24 : 24 + len(encoded_type_id)] = encoded_type_id
    return bytes(body)


class ServiceTypeIdEncodingTests(unittest.TestCase):
    def test_decodes_all_numeric_nodeid_encodings(self) -> None:
        self.assertEqual(parse_service_type_id(_msg_with_type_id(b"\x00\x2a")), 42)
        self.assertEqual(parse_service_type_id(_msg_with_type_id(b"\x01\x00\x77\x02")), 631)
        self.assertEqual(parse_service_type_id(_msg_with_type_id(b"\x02\x00\x00\x77\x02\x00\x00")), 631)

    def test_non_zero_namespace_is_not_a_standard_service(self) -> None:
        self.assertIsNone(parse_service_type_id(_msg_with_type_id(b"\x01\x02\x77\x02")))

    def test_plain_uint32_service_id_is_not_accepted(self) -> None:
        detection = detect_opcua_payload(_msg_with_type_id((631).to_bytes(4, "little")))
        self.assertTrue(detection.detected)
        self.assertIsNone(detection.service_id)


class RealCaptureServiceTests(unittest.TestCase):
    def test_icsmaster_capture_reports_session_establishment(self) -> None:
        hints = _operation_hints(ROOT / "release_pcaps" / "opcua_icsmaster_method.pcap")
        self.assertEqual(set(hints), {"get_endpoints", "create_session", "activate_session"})

    def test_umati_capture_reports_probe_services(self) -> None:
        path = ROOT / "umati_active_probe_4840.pcapng"
        if not path.exists():
            self.skipTest("umati capture not present")
        hints = _operation_hints(path)
        for operation in ("get_endpoints", "create_session", "activate_session", "browse", "read", "close_session"):
            with self.subTest(operation=operation):
                self.assertGreater(hints.get(operation, 0), 0)


if __name__ == "__main__":
    unittest.main()
