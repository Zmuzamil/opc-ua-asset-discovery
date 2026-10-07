from __future__ import annotations

import ipaddress
import unittest

from scapy.all import Ether, IP, Raw, TCP  # type: ignore

from asset_probe.cli import _summarize_capture
from asset_probe.passive import analyze_packets
from asset_probe.tcp_reassembly import reassemble_tcp_messages


def _ua_message(service_id: int = 631, request_id: int = 1) -> bytes:
    body = b"".join(
        [
            (1).to_bytes(4, "little"),
            (0).to_bytes(4, "little"),
            (1).to_bytes(4, "little"),
            request_id.to_bytes(4, "little"),
            b"\x01\x00" + service_id.to_bytes(2, "little"),
            b"\x00\x00\x00\x00",
        ]
    )
    return b"MSGF" + (8 + len(body)).to_bytes(4, "little") + body


def _tcp_packet(payload: bytes, sequence: int, *, stamp: float = 1.0):
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="192.0.2.20")
        / TCP(sport=51000, dport=12001, seq=sequence, flags="PA")
    )
    if payload:
        packet = packet / Raw(load=payload)
    packet.time = stamp
    return packet


class TcpReassemblyTests(unittest.TestCase):
    def test_split_message_is_detected_with_stream_provenance(self) -> None:
        message = _ua_message()
        split_at = 13
        packets = [
            _tcp_packet(message[:split_at], 1000),
            _tcp_packet(message[split_at:], 1000 + split_at, stamp=2.0),
        ]

        reassembled = reassemble_tcp_messages(packets)
        self.assertEqual(len(reassembled), 1)
        self.assertEqual(reassembled[0].payload, message)
        self.assertEqual(reassembled[0].packet_indices, (1, 2))

        assets = analyze_packets(packets, [ipaddress.IPv4Network("192.0.2.0/24")])
        server = next(asset for asset in assets if asset.mac == "02:00:00:00:00:02")
        self.assertIn("OPCUA", server.discovered_protocols)
        self.assertIn(
            "passive_observed: tcp_reassembled",
            server.protocol_metadata.opcua["detection"]["provenance"],
        )
        stream_record = server.protocol_metadata.opcua["tcp_reassembled_messages"][0]
        self.assertEqual(stream_record["packet_indices"], [1, 2])

        capture = _summarize_capture(packets)
        event = capture["packet_events"][0]
        self.assertEqual(event["contributing_packet_indices"], [1, 2])
        self.assertEqual(event["provenance"]["stream"], "passive_observed: tcp_reassembled")

    def test_out_of_order_segments_are_reordered_by_sequence(self) -> None:
        message = _ua_message()
        split_at = 17
        packets = [
            _tcp_packet(message[split_at:], 2000 + split_at),
            _tcp_packet(message[:split_at], 2000, stamp=2.0),
        ]

        reassembled = reassemble_tcp_messages(packets)
        self.assertEqual(len(reassembled), 1)
        self.assertEqual(reassembled[0].payload, message)
        self.assertEqual(reassembled[0].packet_indices, (1, 2))

    def test_sequence_wraparound_is_reassembled(self) -> None:
        message = _ua_message()
        split_at = 12
        initial_sequence = 0xFFFFFFFA
        packets = [
            _tcp_packet(message[:split_at], initial_sequence),
            _tcp_packet(message[split_at:], (initial_sequence + split_at) & 0xFFFFFFFF, stamp=2.0),
        ]

        reassembled = reassemble_tcp_messages(packets)
        self.assertEqual(len(reassembled), 1)
        self.assertEqual(reassembled[0].payload, message)

    def test_retransmitted_segment_does_not_duplicate_message(self) -> None:
        message = _ua_message()
        split_at = 11
        packets = [
            _tcp_packet(message[:split_at], 3000),
            _tcp_packet(message[:split_at], 3000, stamp=2.0),
            _tcp_packet(message[split_at:], 3000 + split_at, stamp=3.0),
        ]

        reassembled = reassemble_tcp_messages(packets)
        self.assertEqual(len(reassembled), 1)
        self.assertEqual(reassembled[0].payload, message)
        self.assertEqual(reassembled[0].packet_indices, (1, 2, 3))

        assets = analyze_packets(packets, [ipaddress.IPv4Network("192.0.2.0/24")])
        server = next(asset for asset in assets if asset.mac == "02:00:00:00:00:02")
        self.assertEqual(server.protocol_metadata.opcua["detection"]["packet_count"], 1)

    def test_multiple_messages_in_one_tcp_payload_are_extracted(self) -> None:
        first = _ua_message(631, 1)
        second = _ua_message(527, 2)
        packets = [_tcp_packet(first + second, 4000)]

        reassembled = reassemble_tcp_messages(packets)
        self.assertEqual([item.payload for item in reassembled], [first, second])
        self.assertEqual([item.detection.service_id for item in reassembled], [631, 527])

        assets = analyze_packets(packets, [ipaddress.IPv4Network("192.0.2.0/24")])
        server = next(asset for asset in assets if asset.mac == "02:00:00:00:00:02")
        self.assertEqual(server.protocol_metadata.opcua["message_types"]["MSG"], 2)
        self.assertEqual(server.protocol_metadata.opcua["detection"]["packet_count"], 2)

    def test_incomplete_or_gapped_message_is_not_detected(self) -> None:
        message = _ua_message()
        incomplete = [_tcp_packet(message[:20], 5000)]
        gapped = [
            _tcp_packet(message[:10], 6000),
            _tcp_packet(message[15:], 6000 + 15, stamp=2.0),
        ]

        self.assertEqual(reassemble_tcp_messages(incomplete), [])
        self.assertEqual(reassemble_tcp_messages(gapped), [])
        for packets in (incomplete, gapped):
            assets = analyze_packets(packets, [ipaddress.IPv4Network("192.0.2.0/24")])
            self.assertTrue(all("OPCUA" not in asset.discovered_protocols for asset in assets))


if __name__ == "__main__":
    unittest.main()