from __future__ import annotations

import unittest

from scapy.layers.dns import DNS, DNSQR, DNSRR  # type: ignore

from asset_probe.protocol_detector import detect_opcua_payload


def _ua_tcp_message(message_type: bytes = b"MSG", service_id: int = 631) -> bytes:
    body = bytearray(28)
    body[:3] = message_type
    body[3:4] = b"F"
    body[4:8] = (len(body)).to_bytes(4, "little")
    body[24:28] = b"\x01\x00" + service_id.to_bytes(2, "little")
    return bytes(body)


class ProtocolDetectorTests(unittest.TestCase):
    def test_ordinary_tcp_is_not_opcua(self) -> None:
        result = detect_opcua_payload(
            b"GET / HTTP/1.1\r\n", src_port=51000, dst_port=80
        )
        self.assertFalse(result.detected)

    def test_ordinary_udp_is_not_opcua(self) -> None:
        result = detect_opcua_payload(b"ordinary datagram", transport="udp", dst_port=9999)
        self.assertFalse(result.detected)

    def test_ua_tcp_is_detected_on_standard_and_nonstandard_ports(self) -> None:
        payload = _ua_tcp_message()
        for port in (4840, 12001, 51210):
            with self.subTest(port=port):
                result = detect_opcua_payload(payload, src_port=51000, dst_port=port)
                self.assertTrue(result.detected)
                self.assertGreaterEqual(result.confidence, 0.9)
                self.assertIn("ua_tcp_message_type:MSG", result.evidence)
                self.assertIn("known_service_id:631", result.evidence)

    def test_port_4840_alone_is_only_a_candidate(self) -> None:
        result = detect_opcua_payload(b"ordinary tcp payload", src_port=51000, dst_port=4840)
        self.assertFalse(result.detected)
        self.assertTrue(result.candidate)
        self.assertEqual(result.evidence, ("tcp_port_4840_candidate_only",))

    def test_bare_opcua_mdns_service_text_is_not_a_valid_announcement(self) -> None:
        result = detect_opcua_payload(
            b"_opcua-tcp._tcp.local", transport="udp", src_port=5353
        )
        self.assertFalse(result.detected)

    def test_valid_opcua_mdns_ptr_announcement_is_detected(self) -> None:
        payload = bytes(
            DNS(
                id=0,
                qr=1,
                aa=1,
                qd=DNSQR(qname="_opcua-tcp._tcp.local", qtype="PTR"),
                an=DNSRR(
                    rrname="_opcua-tcp._tcp.local",
                    type="PTR",
                    rdata="DemoNode._opcua-tcp._tcp.local",
                ),
            )
        )
        result = detect_opcua_payload(payload, transport="udp", src_port=5353)
        self.assertTrue(result.detected)
        self.assertIn("mdns_ptr_announcement:_opcua-tcp._tcp", result.evidence)


if __name__ == "__main__":
    unittest.main()