from __future__ import annotations

import ipaddress
import unittest

from scapy.all import Ether, IP, Raw, TCP, UDP  # type: ignore

from asset_probe.cli import _assemble_inventory, _summarize_capture
from asset_probe.passive import analyze_packets


SERVICE_IDS = [428, 461, 467, 631, 527, 673, 473]
EXPECTED_OPS = {
    "get_endpoints",
    "create_session",
    "activate_session",
    "read",
    "browse",
    "write",
    "close_session",
}


def _binary_msg(service_id: int, req_id: int) -> bytes:
    header = b"MSGF"
    body = b"".join(
        [
            (1).to_bytes(4, "little"),
            (0).to_bytes(4, "little"),
            (1).to_bytes(4, "little"),
            req_id.to_bytes(4, "little"),
            b"\x01\x00" + service_id.to_bytes(2, "little"),
            b"\x00\x00\x00\x00",
        ]
    )
    return header + (8 + len(body)).to_bytes(4, "little") + body


class PassiveParserTests(unittest.TestCase):
    def test_extracts_expected_operation_hints(self) -> None:
        packets = []
        for idx, sid in enumerate(SERVICE_IDS, start=1):
            pkt = (
                Ether(src="02:42:ac:11:00:02", dst="02:42:ac:11:00:01")
                / IP(src="10.10.0.2", dst="10.10.0.10", ttl=64)
                / TCP(sport=50000, dport=4840, flags="PA")
                / Raw(load=_binary_msg(sid, idx))
            )
            pkt.time = float(idx)
            packets.append(pkt)

        assets = analyze_packets(packets, [ipaddress.IPv4Network("10.10.0.0/24")])
        self.assertGreaterEqual(len(assets), 1)

        hints_union = set()
        for asset in assets:
            hints = asset.protocol_metadata.opcua.get("operation_hints", {})
            hints_union.update(hints.keys())

        self.assertTrue(EXPECTED_OPS.issubset(hints_union))

    def test_non_opcua_payload_not_misclassified(self) -> None:
        pkt = (
            Ether(src="02:42:ac:11:00:12", dst="02:42:ac:11:00:13")
            / IP(src="10.20.0.12", dst="10.20.0.13", ttl=58)
            / TCP(sport=51001, dport=80, flags="PA")
            / Raw(load=b"GET / HTTP/1.1\r\nHost: example.local\r\n\r\n")
        )
        pkt.time = 1.0

        assets = analyze_packets([pkt], [ipaddress.IPv4Network("10.20.0.0/24")])
        detected = set()
        for asset in assets:
            detected.update(asset.discovered_protocols)

        self.assertNotIn("OPCUA", detected)

    def test_detects_nonstandard_port_when_payload_is_opcua(self) -> None:
        pkt = (
            Ether(src="02:42:ac:11:00:22", dst="02:42:ac:11:00:23")
            / IP(src="10.30.0.2", dst="10.30.0.10", ttl=64)
            / TCP(sport=50001, dport=12001, flags="PA")
            / Raw(load=_binary_msg(631, 1))
        )
        pkt.time = 1.0

        assets = analyze_packets([pkt], [ipaddress.IPv4Network("10.30.0.0/24")])
        detected = set()
        for asset in assets:
            detected.update(asset.discovered_protocols)

        self.assertIn("OPCUA", detected)

    def test_port_4840_without_opcua_framing_is_not_parsed_as_opcua(self) -> None:
        pkt = (
            Ether(src="02:42:ac:11:00:32", dst="02:42:ac:11:00:33")
            / IP(src="10.40.0.2", dst="10.40.0.10", ttl=64)
            / TCP(sport=50002, dport=4840, flags="PA")
            / Raw(load=b"ordinary tcp payload")
        )
        pkt.time = 1.0

        assets = analyze_packets([pkt], [ipaddress.IPv4Network("10.40.0.0/24")])
        self.assertTrue(assets)
        self.assertTrue(all("OPCUA" not in asset.discovered_protocols for asset in assets))
        self.assertTrue(all(not asset.protocol_metadata.opcua for asset in assets))

    def test_mixed_tcp_udp_and_opcua_only_parse_detected_traffic(self) -> None:
        ua_packet = (
            Ether(src="02:42:ac:11:00:42", dst="02:42:ac:11:00:43")
            / IP(src="10.50.0.2", dst="10.50.0.10", ttl=64)
            / TCP(sport=50003, dport=51210, flags="PA")
            / Raw(load=_binary_msg(631, 1))
        )
        ordinary_tcp = (
            Ether(src="02:42:ac:11:00:52", dst="02:42:ac:11:00:53")
            / IP(src="10.50.0.20", dst="10.50.0.30", ttl=64)
            / TCP(sport=50004, dport=80, flags="PA")
            / Raw(load=b"GET / HTTP/1.1\r\n")
        )
        ordinary_udp = (
            Ether(src="02:42:ac:11:00:62", dst="02:42:ac:11:00:63")
            / IP(src="10.50.0.40", dst="10.50.0.50", ttl=64)
            / UDP(sport=50005, dport=9999)
            / Raw(load=b"ordinary datagram")
        )
        assets = analyze_packets(
            [ordinary_tcp, ua_packet, ordinary_udp],
            [ipaddress.IPv4Network("10.50.0.0/24")],
        )

        by_mac = {asset.mac: asset for asset in assets}
        ua_asset = by_mac["02:42:ac:11:00:43"]
        self.assertIn("OPCUA", ua_asset.discovered_protocols)
        self.assertTrue(ua_asset.protocol_metadata.opcua["detection"]["detected"])
        self.assertEqual(ua_asset.protocol_metadata.opcua["detection"]["packet_count"], 1)
        for mac in ("02:42:ac:11:00:53", "02:42:ac:11:00:63"):
            self.assertNotIn("OPCUA", by_mac[mac].discovered_protocols)
            self.assertFalse(by_mac[mac].protocol_metadata.opcua)

    def test_known_nonstandard_ports_12001_and_51210(self) -> None:
        for port in (12001, 51210):
            with self.subTest(port=port):
                pkt = (
                    Ether(src="02:42:ac:11:00:72", dst="02:42:ac:11:00:73")
                    / IP(src="10.60.0.2", dst="10.60.0.10", ttl=64)
                    / TCP(sport=50006, dport=port, flags="PA")
                    / Raw(load=_binary_msg(631, 1))
                )
                pkt.time = 1.0
                assets = analyze_packets([pkt], [ipaddress.IPv4Network("10.60.0.0/24")])
                self.assertTrue(any("OPCUA" in asset.discovered_protocols for asset in assets))

    def test_capture_summary_separates_opcua_from_other_packets(self) -> None:
        ua_packet = (
            Ether(src="02:42:ac:11:00:82", dst="02:42:ac:11:00:83")
            / IP(src="10.70.0.2", dst="10.70.0.10", ttl=64)
            / TCP(sport=50007, dport=12001, flags="PA")
            / Raw(load=_binary_msg(631, 1))
        )
        ordinary_packet = (
            Ether(src="02:42:ac:11:00:92", dst="02:42:ac:11:00:93")
            / IP(src="10.70.0.20", dst="10.70.0.30", ttl=64)
            / UDP(sport=50008, dport=9999)
            / Raw(load=b"ordinary datagram")
        )
        ua_packet.time = 2.0
        ordinary_packet.time = 1.0

        summary = _summarize_capture([ordinary_packet, ua_packet])

        self.assertEqual(summary["total_packets_observed"], 2)
        self.assertEqual(summary["opcua_packets"], 1)
        self.assertEqual(summary["non_opc_packets"], 1)
        self.assertEqual(summary["unique_opcua_client_ips"], ["10.70.0.2"])
        self.assertEqual(summary["unique_opcua_server_ips"], ["10.70.0.10"])
        self.assertEqual(len(summary["opcua_sessions"]), 1)

    def test_capture_summary_counts_payloads_and_keeps_samples_metadata_only(self) -> None:
        tcp_with_payload = (
            Ether(src="02:42:ac:11:01:01", dst="02:42:ac:11:01:02")
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / TCP(sport=51000, dport=4840, flags="PA")
            / Raw(load=b"sensitive application data")
        )
        tcp_without_payload = (
            Ether(src="02:42:ac:11:01:03", dst="02:42:ac:11:01:04")
            / IP(src="192.0.2.3", dst="192.0.2.4")
            / TCP(sport=51001, dport=443, flags="S")
        )
        udp_packet = (
            Ether(src="02:42:ac:11:01:05", dst="02:42:ac:11:01:06")
            / IP(src="192.0.2.5", dst="192.0.2.6")
            / UDP(sport=53000, dport=5353)
            / Raw(load=b"ordinary datagram")
        )

        summary = _summarize_capture([tcp_with_payload, tcp_without_payload, udp_packet])

        self.assertEqual(summary["total_packets_observed"], 3)
        self.assertEqual(summary["tcp_packets"], 2)
        self.assertEqual(summary["tcp_packets_with_payload"], 1)
        self.assertEqual(summary["udp_packets"], 1)
        self.assertEqual(summary["detector_invocation_count"], 3)
        self.assertEqual(summary["port_4840_candidates"], 1)
        self.assertEqual(len(summary["tcp_payload_samples"]), 1)
        self.assertEqual(summary["tcp_payload_samples"][0]["tcp_payload_bytes"], len(b"sensitive application data"))
        self.assertNotIn("payload", summary["tcp_payload_samples"][0])
        self.assertNotIn("sensitive application data", str(summary["tcp_payload_samples"]))

    def test_inventory_json_separates_endpoint_identity_and_active_enrichment(self) -> None:
        packet = (
            Ether(src="02:42:ac:11:00:a2", dst="02:42:ac:11:00:a3")
            / IP(src="192.0.2.10", dst="198.51.100.20", ttl=64)
            / TCP(sport=52000, dport=12001, flags="PA")
            / Raw(load=b"HELF" + (8).to_bytes(4, "little"))
        )
        packet.time = 1.0
        capture = _summarize_capture([packet])
        active = [{"target_ip": "198.51.100.20", "target_port": 12001, "provenance": "active_observed"}]

        result = _assemble_inventory(
            mode="runtime",
            iface="test-nic",
            duration=1,
            packet_count=0,
            bpf="",
            assets=[],
            capture=capture,
            active=active,
            local_nets=[],
        )

        self.assertEqual(set(result), {"runtime_summary", "passive", "active", "warnings"})
        server = next(asset for asset in result["passive"]["assets"] if asset["role"] == "Server")
        self.assertEqual(server["identity"], {
            "ip": "198.51.100.20",
            "transport_protocol": "tcp",
            "port": 12001,
            "provenance": "passive_observed",
        })
        self.assertEqual(server["observed_ethernet_peers"][0]["provenance"], "passive_observed")
        self.assertIn("next-hop gateway", server["observed_ethernet_peers"][0]["endpoint_relationship_provenance"])
        self.assertNotIn("mac", server)
        self.assertNotIn("active_probe", server["protocol_metadata"]["opcua"])
        self.assertEqual(result["active"], active)

    def test_hello_and_ack_set_endpoint_roles_from_ua_direction(self) -> None:
        client_mac = "02:42:ac:11:00:a2"
        server_mac = "02:42:ac:11:00:a3"
        hello = (
            Ether(src=client_mac, dst=server_mac)
            / IP(src="10.80.0.2", dst="10.80.0.10", ttl=64)
            / TCP(sport=50009, dport=51210, flags="PA")
            / Raw(load=b"HELF" + (8).to_bytes(4, "little"))
        )
        ack = (
            Ether(src=server_mac, dst=client_mac)
            / IP(src="10.80.0.10", dst="10.80.0.2", ttl=64)
            / TCP(sport=51210, dport=50009, flags="PA")
            / Raw(load=b"ACKF" + (8).to_bytes(4, "little"))
        )
        hello.time = 1.0
        ack.time = 2.0

        assets = analyze_packets([hello, ack], [ipaddress.IPv4Network("10.80.0.0/24")])
        by_mac = {asset.mac: asset for asset in assets}

        self.assertEqual(by_mac[client_mac].role, "Client")
        self.assertEqual(by_mac[server_mac].role, "Server")

    def test_packet_events_preserve_message_types_hints_direction_and_evidence(self) -> None:
        client_mac = "02:42:ac:11:01:02"
        server_mac = "02:42:ac:11:01:03"
        client_ip = "10.81.0.2"
        server_ip = "10.81.0.10"

        def packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, message, stamp):
            pkt = (
                Ether(src=src_mac, dst=dst_mac)
                / IP(src=src_ip, dst=dst_ip, ttl=64)
                / TCP(sport=src_port, dport=dst_port, flags="PA")
                / Raw(load=message)
            )
            pkt.time = stamp
            return pkt

        packets = [
            packet(client_mac, server_mac, client_ip, server_ip, 51010, 51210, b"HELF" + (8).to_bytes(4, "little"), 1),
            packet(server_mac, client_mac, server_ip, client_ip, 51210, 51010, b"ACKF" + (8).to_bytes(4, "little"), 2),
            packet(client_mac, server_mac, client_ip, server_ip, 51010, 51210, b"OPNF" + (8).to_bytes(4, "little"), 3),
            packet(client_mac, server_mac, client_ip, server_ip, 51010, 51210, _binary_msg(631, 1), 4),
            packet(client_mac, server_mac, client_ip, server_ip, 51010, 51210, _binary_msg(9999, 2), 5),
            packet(client_mac, server_mac, client_ip, server_ip, 51010, 51210, b"CLOF" + (8).to_bytes(4, "little"), 6),
            packet(server_mac, client_mac, server_ip, client_ip, 51210, 51010, b"ERRF" + (8).to_bytes(4, "little"), 7),
        ]

        summary = _summarize_capture(packets)
        events = summary["packet_events"]
        by_type = {event["opcua_message_type"]: event for event in events if event["opcua_message_type"] != "MSG"}
        read_event = next(event for event in events if event["opcua_service_hint"] == "read")

        self.assertEqual(summary["message_type_counts"], {"HEL": 1, "ACK": 1, "OPN": 1, "MSG": 2, "CLO": 1, "ERR": 1})
        self.assertEqual(by_type["HEL"]["direction"], "client_to_server")
        self.assertEqual(by_type["ACK"]["direction"], "server_to_client")
        self.assertEqual(by_type["OPN"]["direction"], "client_to_server")
        self.assertIn("ua_tcp_message_type:MSG", read_event["detection_evidence"])
        self.assertEqual(by_type["HEL"]["source_mac"], client_mac)
        self.assertEqual(by_type["HEL"]["destination_mac"], server_mac)
        self.assertEqual(read_event["provenance"]["packet_fields"], "passive_observed")
        self.assertTrue(all(event["limitations"] for event in events))
        self.assertEqual(summary["opcua_sessions"][0]["packet_indices"], list(range(1, 8)))

    def test_final_inventory_keeps_passive_and_active_top_level_sections_separate(self) -> None:
        client_mac = "02:42:ac:11:02:03"
        server_mac = "02:42:ac:11:02:04"
        packets = [
            Ether(src=client_mac, dst=server_mac)
            / IP(src="10.82.0.20", dst="10.82.0.10")
            / TCP(sport=51000, dport=4840)
            / Raw(load=b"HELF" + (8).to_bytes(4, "little")),
            Ether(src=server_mac, dst=client_mac)
            / IP(src="10.82.0.10", dst="10.82.0.20")
            / TCP(sport=4840, dport=51000)
            / Raw(load=b"ACKF" + (8).to_bytes(4, "little")),
        ]
        packets[0].time = 1
        packets[1].time = 2
        capture = _summarize_capture(packets)
        active_record = {
            "target_ip": "10.82.0.10",
            "target_port": 4840,
            "status": "ok",
            "provenance": "active_observed",
        }
        inventory = _assemble_inventory(
            mode="runtime",
            iface="Ethernet",
            duration=15,
            packet_count=len(packets),
            bpf="",
            assets=[{"mac": client_mac, "protocol_metadata": {"opcua": {"detection": {"detected": True}}}}],
            capture=capture,
            active=[active_record],
            local_nets=[ipaddress.IPv4Network("10.82.0.0/24")],
        )

        self.assertEqual(set(inventory), {"runtime_summary", "passive", "active", "warnings"})
        self.assertNotIn("active", inventory["passive"])
        passive_assets = inventory["passive"]["assets"]
        server_asset = next(asset for asset in passive_assets if asset["role"] == "Server")
        self.assertEqual(server_asset["identity"]["ip"], "10.82.0.10")
        self.assertEqual(server_asset["identity"]["port"], 4840)
        self.assertEqual(
            server_asset["protocol_metadata"]["opcua"]["detection"]["packet_indices"],
            [1, 2],
        )
        self.assertNotIn("active_probe", server_asset["protocol_metadata"]["opcua"])
        self.assertEqual(len(inventory["passive"]["link_layer_observations"]), 2)
        session = inventory["passive"]["sessions"][0]
        self.assertEqual(session["client_endpoint"], {"ip": "10.82.0.20", "port": 51000})
        self.assertEqual(session["server_endpoint"], {"ip": "10.82.0.10", "port": 4840})
        self.assertEqual(inventory["active"][0]["provenance"], "active_observed")
        self.assertTrue(any("TCP segment" in warning for warning in inventory["warnings"]))
        self.assertTrue(any("next-hop" in warning for warning in inventory["warnings"]))


if __name__ == "__main__":
    unittest.main()
