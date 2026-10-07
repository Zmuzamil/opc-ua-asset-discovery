from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import socket
from pathlib import Path
from typing import Iterable

from scapy.all import sniff, rdpcap, get_if_addr, get_if_list, Ether, IP, TCP, UDP  # type: ignore

from .opcua_probe import OpcUaProbeConfig, probe_opcua_server
from .passive import analyze_packets
from .protocol_detector import OPCUA_REQUEST_SERVICES, ProtocolDetection, detect_opcua_payload
from .tcp_reassembly import ReassembledTcpMessage, reassemble_tcp_messages


def get_if_netmask(iface: str) -> str:
    """Return an interface netmask with compatibility for Scapy 2.7."""
    try:
        from scapy.all import conf

        dev = conf.ifaces.dev_from_name(iface)
        mask = getattr(dev, "netmask", None)
        if mask:
            return str(mask)
    except Exception:
        pass
    return "255.255.255.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Protocol-first OT asset discovery and inventory")
    parser.add_argument("--mode", choices=["runtime", "offline"], required=True)
    parser.add_argument("--iface", default=None, help="Network interface for runtime packet capture")
    parser.add_argument("--pcap", default=None, help="Path to pcap file for offline mode")
    parser.add_argument("--duration", type=int, default=30, help="Runtime sniff duration in seconds")
    parser.add_argument("--packet-count", type=int, default=0, help="Stop after N packets (0 means unlimited)")
    parser.add_argument("--bpf", default="", help="Optional capture filter; may exclude traffic needed for identification")
    parser.add_argument("--local-cidr", action="append", default=[], help="Extra local CIDR ranges")
    parser.add_argument("--output", default="asset_inventory.json", help="Output JSON file")
    parser.add_argument("--benchmark-dir", default="", help="Folder of .pcap/.pcapng files for offline benchmark")
    parser.add_argument("--benchmark-output", default="", help="Optional benchmark report JSON path")
    parser.add_argument("--diagnostics", action="store_true", help="Include safe runtime capture diagnostics in output")

    parser.add_argument("--enable-active", action="store_true", help="Opt in to active probing; off by default, passive capture never connects to targets")
    parser.add_argument("--active-opcua", action="store_true", help="With --enable-active, probe server endpoints observed in UA-TCP HEL/ACK or known request-service traffic")
    parser.add_argument("--opcua-timeout", type=float, default=4.0)
    parser.add_argument("--active-max-targets", type=int, default=25, help="Safety cap for active target count")
    parser.add_argument("--active-delay-ms", type=int, default=75, help="Delay between active target probes")
    parser.add_argument("--active-allowlist", default="", help="File with allowed target IPs, one per line; required for active probing in runtime mode")

    args = parser.parse_args()
    if args.active_opcua and not args.enable_active:
        parser.error("--active-opcua requires --enable-active")
    if args.mode == "runtime" and args.enable_active and not args.active_allowlist:
        parser.error("active probing in runtime mode requires --active-allowlist")
    return args


def _infer_local_networks(iface: str | None, extra_cidrs: Iterable[str]) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []

    if iface:
        try:
            ip = get_if_addr(iface)
            mask = get_if_netmask(iface)
            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            nets.append(net)
        except Exception:
            pass

    for cidr in extra_cidrs:
        try:
            nets.append(ipaddress.IPv4Network(cidr, strict=False))
        except Exception:
            continue

    if not nets:
        # Last-resort fallback for runtime mode.
        try:
            host = socket.gethostbyname(socket.gethostname())
            nets.append(ipaddress.IPv4Network(f"{host}/24", strict=False))
        except Exception:
            pass

    return nets


def _load_packets(args: argparse.Namespace, resolved_iface: str | None = None):
    if args.mode == "offline":
        if not args.pcap:
            raise ValueError("--pcap is required in offline mode")
        return rdpcap(args.pcap)

    iface = resolved_iface if resolved_iface is not None else _resolve_capture_interface(args.iface)

    kwargs = {
        "iface": iface,
        "timeout": args.duration,
        "store": True,
        "started_callback": lambda: print(
            f"Capture active on {iface or 'default interface'}", flush=True
        ),
    }
    if args.packet_count > 0:
        kwargs["count"] = args.packet_count
    if args.bpf:
        kwargs["filter"] = args.bpf

    return sniff(**kwargs)


def _resolve_capture_interface(iface: str | None) -> str | None:
    if not iface:
        return None
    available = get_if_list()
    if iface in available:
        return iface
    try:
        from scapy.all import conf

        device = conf.ifaces.dev_from_name(iface)
        network_name = getattr(device, "network_name", None)
        if network_name and network_name in available:
            return str(network_name)
    except Exception:
        pass
    raise ValueError(f"Unknown interface: {iface}")


def _summarize_capture(packets) -> dict:
    summary = {
        "total_packets_observed": len(packets),
        "tcp_packets": 0,
        "tcp_packets_with_payload": 0,
        "udp_packets": 0,
        "detector_invocation_count": 0,
        "tcp_payload_samples": [],
        "tcp_reassembled_detector_invocations": 0,
        "opcua_detected": False,
        "opcua_packets": 0,
        "non_opc_packets": 0,
        "port_4840_candidates": 0,
        "unique_opcua_ip_addresses": set(),
        "unique_opcua_client_ips": set(),
        "unique_opcua_server_ips": set(),
        "opcua_sessions": [],
        "source_destination_pairs": {},
        "message_type_counts": {},
        "opcua_packet_bytes": 0,
        "opcua_payload_bytes": 0,
        "first_seen": None,
        "last_seen": None,
        "capture_first_seen": None,
        "capture_last_seen": None,
        "packet_events": [],
        "flows": {},
    }
    sessions = {}
    session_directions = {}
    detected_tcp_messages: set[tuple] = set()

    for packet_index, packet in enumerate(packets, start=1):
        timestamp = float(getattr(packet, "time", 0.0))
        summary["capture_first_seen"] = timestamp if summary["capture_first_seen"] is None else min(summary["capture_first_seen"], timestamp)
        summary["capture_last_seen"] = timestamp if summary["capture_last_seen"] is None else max(summary["capture_last_seen"], timestamp)
        src_ip = str(packet[IP].src) if IP in packet else ""
        dst_ip = str(packet[IP].dst) if IP in packet else ""
        transport = ""
        src_port = dst_port = None
        payload = b""
        if TCP in packet:
            transport = "tcp"
            summary["tcp_packets"] += 1
            src_port, dst_port = int(packet[TCP].sport), int(packet[TCP].dport)
            payload = bytes(packet[TCP].payload)
            if payload:
                summary["tcp_packets_with_payload"] += 1
                if len(summary["tcp_payload_samples"]) < 5:
                    summary["tcp_payload_samples"].append(
                        {
                            "packet_index": packet_index,
                            "timestamp": timestamp,
                            "source_ip": src_ip or None,
                            "source_port": src_port,
                            "destination_ip": dst_ip or None,
                            "destination_port": dst_port,
                            "tcp_flags": str(packet[TCP].flags),
                            "packet_bytes": int(len(packet)),
                            "tcp_payload_bytes": len(payload),
                        }
                    )
        elif UDP in packet:
            transport = "udp"
            summary["udp_packets"] += 1
            src_port, dst_port = int(packet[UDP].sport), int(packet[UDP].dport)
            payload = bytes(packet[UDP].payload)
        else:
            transport = f"ip_protocol_{int(packet[IP].proto)}" if IP in packet else "non_transport"

        src_mac = str(packet[Ether].src) if Ether in packet else None
        dst_mac = str(packet[Ether].dst) if Ether in packet else None
        flow_key = (src_ip, src_port, dst_ip, dst_port, transport, src_mac, dst_mac)
        flow = summary["flows"].setdefault(
            flow_key,
            {
                "source_ip": src_ip or None,
                "destination_ip": dst_ip or None,
                "source_mac": src_mac,
                "destination_mac": dst_mac,
                "source_port": src_port,
                "destination_port": dst_port,
                "transport_protocol": transport,
                "packet_count": 0,
                "byte_count": 0,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "provenance": "passive_observed",
            },
        )
        flow["packet_count"] += 1
        flow["byte_count"] += int(len(packet))
        flow["last_seen"] = timestamp

        summary["detector_invocation_count"] += 1
        detection = detect_opcua_payload(
            payload,
            transport=transport,
            src_port=src_port,
            dst_port=dst_port,
        )
        summary["port_4840_candidates"] += int(detection.candidate)
        if transport == "tcp":
            if detection.detected:
                declared_size = int.from_bytes(payload[4:8], "little") if len(payload) >= 8 else 0
                if declared_size > len(payload):
                    detection = ProtocolDetection(
                        detected=False,
                        confidence=0.0,
                        candidate=detection.candidate,
                        evidence=detection.evidence,
                    )
                else:
                    fingerprint = (src_ip, src_port, dst_ip, dst_port, int(packet[TCP].seq), payload[:declared_size])
                    if fingerprint in detected_tcp_messages:
                        detection = ProtocolDetection(detected=False, confidence=0.0)
                    else:
                        detected_tcp_messages.add(fingerprint)
        if not detection.detected:
            summary["non_opc_packets"] += 1
            continue

        summary["opcua_detected"] = True
        summary["opcua_packets"] += 1
        summary["opcua_packet_bytes"] += int(len(packet))
        summary["opcua_payload_bytes"] += len(payload)
        summary["first_seen"] = timestamp if summary["first_seen"] is None else min(summary["first_seen"], timestamp)
        summary["last_seen"] = timestamp if summary["last_seen"] is None else max(summary["last_seen"], timestamp)
        if src_ip:
            summary["unique_opcua_ip_addresses"].add(src_ip)
        if dst_ip:
            summary["unique_opcua_ip_addresses"].add(dst_ip)
        if detection.message_type == "HEL" and src_ip and dst_ip:
            summary["unique_opcua_client_ips"].add(src_ip)
            summary["unique_opcua_server_ips"].add(dst_ip)
        elif detection.message_type == "ACK" and src_ip and dst_ip:
            summary["unique_opcua_server_ips"].add(src_ip)
            summary["unique_opcua_client_ips"].add(dst_ip)
        elif detection.service_id is not None and src_ip and dst_ip:
            summary["unique_opcua_client_ips"].add(src_ip)
            summary["unique_opcua_server_ips"].add(dst_ip)
        if detection.message_type:
            counts = summary["message_type_counts"]
            counts[detection.message_type] = counts.get(detection.message_type, 0) + 1

        if detection.message_type == "HEL":
            direction = "client_to_server"
            direction_provenance = "passive_inferred: UA-TCP HEL source is client"
        elif detection.message_type == "ACK":
            direction = "server_to_client"
            direction_provenance = "passive_inferred: UA-TCP ACK source is server"
        elif detection.service_id is not None:
            direction = "client_to_server"
            direction_provenance = "passive_inferred: known request service in UA-TCP MSG"
        else:
            endpoint_key = tuple(sorted(((src_ip, src_port), (dst_ip, dst_port))))
            client_endpoint = session_directions.get(endpoint_key)
            if client_endpoint and (src_ip, src_port) == client_endpoint:
                direction = "client_to_server"
                direction_provenance = "passive_inferred: direction from UA-TCP HEL/ACK session exchange"
            elif client_endpoint and (dst_ip, dst_port) == client_endpoint:
                direction = "server_to_client"
                direction_provenance = "passive_inferred: direction from UA-TCP HEL/ACK session exchange"
            else:
                direction = "unknown"
                direction_provenance = "passive_inferred: no direction evidence in this packet"
        message_size = int.from_bytes(payload[4:8], "little") if transport == "tcp" and len(payload) >= 8 else None
        limitations = []
        if transport == "tcp":
            limitations.append("TCP streams are sequence-reassembled per bidirectional IPv4 flow; TCP segment loss or capture gaps can still leave a UA-TCP message incomplete.")
            if message_size is not None and message_size > len(payload):
                limitations.append("Captured TCP payload is shorter than the declared UA-TCP message size; message completeness is unknown.")
        event = {
                "packet_index": packet_index,
                "timestamp": timestamp,
                "source_ip": src_ip or None,
                "destination_ip": dst_ip or None,
                "source_mac": src_mac,
                "destination_mac": dst_mac,
                "source_port": src_port,
                "destination_port": dst_port,
                "transport_protocol": transport,
                "packet_length": int(len(packet)),
                "opcua_message_type": detection.message_type,
                "opcua_service_hint": OPCUA_REQUEST_SERVICES.get(detection.service_id),
                "service_id": detection.service_id,
                "direction": direction,
                "detection_confidence": detection.confidence,
                "detection_evidence": list(detection.evidence),
                "provenance": {
                    "packet_fields": "passive_observed",
                    "direction": direction_provenance,
                    "service_hint": "passive_observed" if detection.service_id is not None else "not_available",
                },
                "message_size_declared": message_size,
                "captured_payload_bytes": len(payload),
                "limitations": limitations,
            }
        summary["packet_events"].append(event)

        if src_ip and dst_ip:
            pair_key = (src_ip, src_port, dst_ip, dst_port, transport)
            pair = summary["source_destination_pairs"].setdefault(
                pair_key,
                {
                    "source_ip": src_ip,
                    "source_port": src_port,
                    "destination_ip": dst_ip,
                    "destination_port": dst_port,
                    "transport": transport,
                    "packet_count": 0,
                    "bytes": 0,
                },
            )
            pair["packet_count"] += 1
            pair["bytes"] += int(len(packet))
            if transport == "tcp":
                endpoints = tuple(sorted(((src_ip, src_port), (dst_ip, dst_port))))
                if detection.message_type == "HEL":
                    session_directions[endpoints] = (src_ip, src_port)
                elif detection.message_type == "ACK":
                    session_directions[endpoints] = (dst_ip, dst_port)
                session = sessions.setdefault(
                    endpoints,
                    {
                        "endpoint_a": {"ip": endpoints[0][0], "port": endpoints[0][1]},
                        "endpoint_b": {"ip": endpoints[1][0], "port": endpoints[1][1]},
                        "packet_count": 0,
                        "bytes": 0,
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                        "packet_indices": [],
                        "provenance": "passive_inferred: packets grouped by TCP endpoint tuple",
                    },
                )
                session["packet_count"] += 1
                session["bytes"] += int(len(packet))
                session["first_seen"] = min(session["first_seen"], timestamp)
                session["last_seen"] = max(session["last_seen"], timestamp)
                if detection.detected:
                    session["packet_indices"].append(packet_index)

    for reassembled in reassemble_tcp_messages(packets):
        summary["tcp_reassembled_detector_invocations"] += 1
        if not _reassembled_message_seen_in_packet(reassembled, packets):
            _append_reassembled_capture_event(summary, reassembled, packets)

    for key in (
        "unique_opcua_ip_addresses",
        "unique_opcua_client_ips",
        "unique_opcua_server_ips",
    ):
        summary[key] = sorted(summary[key])
    for endpoints, session in sessions.items():
        client_endpoint = session_directions.get(endpoints)
        if client_endpoint:
            server_endpoint = endpoints[1] if client_endpoint == endpoints[0] else endpoints[0]
            session["client_endpoint"] = {"ip": client_endpoint[0], "port": client_endpoint[1]}
            session["server_endpoint"] = {"ip": server_endpoint[0], "port": server_endpoint[1]}
            session["role_provenance"] = "passive_inferred: UA-TCP HEL/ACK direction"
        else:
            session["role_provenance"] = "passive_inferred: client/server role unavailable"
    summary["opcua_sessions"] = list(sessions.values())
    summary["source_destination_pairs"] = list(summary["source_destination_pairs"].values())
    summary["flows"] = list(summary["flows"].values())
    return summary


def _reassembled_message_seen_in_packet(message: ReassembledTcpMessage, packets) -> bool:
    for packet_index in message.packet_indices:
        packet = packets[packet_index - 1]
        payload = bytes(packet[TCP].payload)
        if not payload.startswith(message.payload):
            continue
        direct = detect_opcua_payload(
            payload,
            src_port=int(packet[TCP].sport),
            dst_port=int(packet[TCP].dport),
        )
        if direct.detected and direct.message_type == message.detection.message_type:
            if int.from_bytes(payload[4:8], "little") <= len(payload):
                return True
    return False


def _append_reassembled_capture_event(summary: dict, message: ReassembledTcpMessage, packets) -> None:
    detection = message.detection
    packet = packets[message.packet_indices[0] - 1]
    src_mac = str(packet[Ether].src) if Ether in packet else None
    dst_mac = str(packet[Ether].dst) if Ether in packet else None
    if detection.message_type == "HEL":
        direction = "client_to_server"
        direction_provenance = "passive_inferred: UA-TCP HEL source is client"
    elif detection.message_type == "ACK":
        direction = "server_to_client"
        direction_provenance = "passive_inferred: UA-TCP ACK source is server"
    elif detection.service_id is not None:
        direction = "client_to_server"
        direction_provenance = "passive_inferred: known request service in reassembled UA-TCP MSG"
    else:
        direction = "unknown"
        direction_provenance = "passive_inferred: no direction evidence in this reassembled message"

    packet_bytes = sum(int(len(packets[index - 1])) for index in message.packet_indices)
    event = {
        "packet_index": message.packet_indices[0],
        "contributing_packet_indices": list(message.packet_indices),
        "timestamp": message.first_seen,
        "source_ip": message.source_ip,
        "destination_ip": message.destination_ip,
        "source_mac": src_mac,
        "destination_mac": dst_mac,
        "source_port": message.source_port,
        "destination_port": message.destination_port,
        "transport_protocol": "tcp",
        "packet_length": packet_bytes,
        "opcua_message_type": detection.message_type,
        "opcua_service_hint": OPCUA_REQUEST_SERVICES.get(detection.service_id),
        "service_id": detection.service_id,
        "direction": direction,
        "detection_confidence": detection.confidence,
        "detection_evidence": list(detection.evidence),
        "provenance": {
            "packet_fields": "passive_observed",
            "stream": "passive_observed: tcp_reassembled",
            "contributing_packets": "passive_observed",
            "direction": direction_provenance,
            "service_hint": "passive_observed" if detection.service_id is not None else "not_available",
        },
        "message_size_declared": len(message.payload),
        "captured_payload_bytes": len(message.payload),
        "limitations": [],
    }
    summary["packet_events"].append(event)
    summary["opcua_detected"] = True
    summary["opcua_packets"] += 1
    summary["opcua_packet_bytes"] += packet_bytes
    summary["opcua_payload_bytes"] += len(message.payload)
    summary["first_seen"] = message.first_seen if summary["first_seen"] is None else min(summary["first_seen"], message.first_seen)
    summary["last_seen"] = message.last_seen if summary["last_seen"] is None else max(summary["last_seen"], message.last_seen)
    summary["unique_opcua_ip_addresses"].update((message.source_ip, message.destination_ip))
    if detection.message_type == "HEL":
        summary["unique_opcua_client_ips"].add(message.source_ip)
        summary["unique_opcua_server_ips"].add(message.destination_ip)
    elif detection.message_type == "ACK":
        summary["unique_opcua_server_ips"].add(message.source_ip)
        summary["unique_opcua_client_ips"].add(message.destination_ip)
    elif detection.service_id is not None:
        summary["unique_opcua_client_ips"].add(message.source_ip)
        summary["unique_opcua_server_ips"].add(message.destination_ip)
    if detection.message_type:
        counts = summary["message_type_counts"]
        counts[detection.message_type] = counts.get(detection.message_type, 0) + 1

    pair_key = (message.source_ip, message.source_port, message.destination_ip, message.destination_port, "tcp")
    pair = summary["source_destination_pairs"].setdefault(
        pair_key,
        {
            "source_ip": message.source_ip,
            "source_port": message.source_port,
            "destination_ip": message.destination_ip,
            "destination_port": message.destination_port,
            "transport": "tcp",
            "packet_count": 0,
            "bytes": 0,
        },
    )
    pair["packet_count"] += len(message.packet_indices)
    pair["bytes"] += packet_bytes

    endpoints = tuple(sorted(((message.source_ip, message.source_port), (message.destination_ip, message.destination_port))))
    session = next(
        (
            item
            for item in summary["opcua_sessions"]
            if item["endpoint_a"] == {"ip": endpoints[0][0], "port": endpoints[0][1]}
            and item["endpoint_b"] == {"ip": endpoints[1][0], "port": endpoints[1][1]}
        ),
        None,
    )
    if session is None:
        session = {
            "endpoint_a": {"ip": endpoints[0][0], "port": endpoints[0][1]},
            "endpoint_b": {"ip": endpoints[1][0], "port": endpoints[1][1]},
            "packet_count": 0,
            "bytes": 0,
            "first_seen": message.first_seen,
            "last_seen": message.last_seen,
            "packet_indices": [],
            "provenance": "passive_inferred: packets grouped by TCP endpoint tuple",
        }
        summary["opcua_sessions"].append(session)
    session["packet_count"] += len(message.packet_indices)
    session["bytes"] += packet_bytes
    session["first_seen"] = min(session["first_seen"], message.first_seen)
    session["last_seen"] = max(session["last_seen"], message.last_seen)
    session["packet_indices"] = sorted(set(session["packet_indices"]).union(message.packet_indices))
    session["detected_message_packet_indices"] = sorted(
        set(session.get("detected_message_packet_indices", [])).union(message.packet_indices)
    )


def _load_allowlist(path: str) -> set[str]:
    if not path:
        return set()
    p = Path(path)
    if not p.exists():
        raise ValueError(f"active allowlist file not found: {path}")
    out = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        t = line.strip()
        if not t or t.startswith("#"):
            continue
        out.add(t)
    return out


def _build_passive_endpoint_assets(packet_events: list[dict]) -> list[dict]:
    endpoints: dict[tuple[str, str, int], dict] = {}

    for event in packet_events:
        transport = event.get("transport_protocol")
        if transport != "tcp":
            continue
        source = (event.get("source_ip"), event.get("source_port"))
        destination = (event.get("destination_ip"), event.get("destination_port"))
        if not source[0] or not destination[0]:
            continue

        message_type = event.get("opcua_message_type")
        service_id = event.get("service_id")
        if message_type == "HEL" or service_id is not None:
            client_endpoint, server_endpoint = source, destination
        elif message_type == "ACK":
            server_endpoint, client_endpoint = source, destination
        else:
            client_endpoint = server_endpoint = None

        for endpoint, role, mac_field in (
            (source, "Client" if client_endpoint == source else "Server" if server_endpoint == source else "Unknown", "source_mac"),
            (destination, "Client" if client_endpoint == destination else "Server" if server_endpoint == destination else "Unknown", "destination_mac"),
        ):
            ip, port = endpoint
            key = (ip, transport, port)
            asset = endpoints.setdefault(
                key,
                {
                    "identity": {
                        "ip": ip,
                        "transport_protocol": transport,
                        "port": port,
                        "provenance": "passive_observed",
                    },
                    "role": role,
                    "role_provenance": "passive_inferred: UA-TCP message direction" if role != "Unknown" else "not_available",
                    "protocol_metadata": {
                        "opcua": {
                            "detection": {"detected": True, "confidence": 0.0, "evidence": [], "packet_indices": []},
                            "message_types": {},
                            "service_ids": [],
                        }
                    },
                    "observed_ethernet_peers": {},
                    "provenance": "passive_observed",
                },
            )
            if asset["role"] == "Unknown" and role != "Unknown":
                asset["role"] = role
                asset["role_provenance"] = "passive_inferred: UA-TCP message direction"

            opcua = asset["protocol_metadata"]["opcua"]
            detection = opcua["detection"]
            detection["confidence"] = max(detection["confidence"], event.get("detection_confidence") or 0.0)
            detection["packet_indices"].append(event["packet_index"])
            for evidence in event.get("detection_evidence", []):
                if evidence not in detection["evidence"]:
                    detection["evidence"].append(evidence)
            if message_type:
                types = opcua["message_types"]
                types[message_type] = types.get(message_type, 0) + 1
            if service_id is not None and service_id not in opcua["service_ids"]:
                opcua["service_ids"].append(service_id)

            mac = event.get(mac_field)
            if mac:
                peer = asset["observed_ethernet_peers"].setdefault(
                    mac,
                    {
                        "mac": mac,
                        "provenance": "passive_observed",
                        "endpoint_relationship_provenance": "passive_inferred: observed in the same packet; may be a next-hop gateway",
                        "packet_indices": [],
                    },
                )
                if event["packet_index"] not in peer["packet_indices"]:
                    peer["packet_indices"].append(event["packet_index"])

    result = list(endpoints.values())
    for asset in result:
        asset["protocol_metadata"]["opcua"]["detection"]["packet_indices"].sort()
        asset["protocol_metadata"]["opcua"]["detection"]["evidence"].sort()
        asset["protocol_metadata"]["opcua"]["service_ids"].sort()
        asset["observed_ethernet_peers"] = list(asset["observed_ethernet_peers"].values())
    return result


def _build_link_layer_observations(flows: list[dict]) -> list[dict]:
    observations: dict[str, dict] = {}
    for flow in flows:
        for mac_field in ("source_mac", "destination_mac"):
            mac = flow.get(mac_field)
            if not mac:
                continue
            observation = observations.setdefault(
                mac,
                {"observed_ethernet_mac": mac, "packet_count": 0, "provenance": "passive_observed"},
            )
            observation["packet_count"] += flow["packet_count"]
    return list(observations.values())


def _strict_opcua_assets(assets: list[dict]) -> int:
    keys = {
        "message_types",
        "application_uris",
        "security_mode_hints",
        "operation_hints",
        "binary_service_hints",
        "mdns_announcements",
        "transfer_stats",
        "payload_samples",
    }
    count = 0
    for asset in assets:
        opcua = asset.get("protocol_metadata", {}).get("opcua", {})
        if isinstance(opcua, dict) and keys.intersection(opcua):
            count += 1
    return count


def _score_inventory_result(result: dict) -> dict:
    assets = result.get("assets", [])
    total_assets = int(result.get("asset_count", len(assets)))
    strict_opcua = _strict_opcua_assets(assets)

    has_message_types = 0
    has_transfer_stats = 0
    has_binary_hints = 0
    for asset in assets:
        opcua = asset.get("protocol_metadata", {}).get("opcua", {})
        if not isinstance(opcua, dict):
            continue
        has_message_types += int(bool(opcua.get("message_types")))
        has_transfer_stats += int(bool(opcua.get("transfer_stats")))
        has_binary_hints += int(bool(opcua.get("binary_service_hints")))

    score = 0.0
    if total_assets > 0:
        score += 20.0
    if strict_opcua > 0:
        score += 20.0
    score += min(20.0, has_message_types * 2.0)
    score += min(15.0, has_transfer_stats * 1.5)
    score += min(10.0, has_binary_hints * 2.0)
    return {
        "score_0_100": round(min(score, 100.0), 2),
        "asset_count": total_assets,
        "opcua_assets_strict": strict_opcua,
        "assets_with_message_types": has_message_types,
        "assets_with_transfer_stats": has_transfer_stats,
        "assets_with_binary_hints": has_binary_hints,
    }


def _load_benchmark_labels(bench_dir: Path) -> dict:
    labels_path = bench_dir / "ground_truth_labels.json"
    if not labels_path.exists():
        return {}
    try:
        data = json.loads(labels_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _collect_detected_operation_hints(assets: list[dict]) -> set[str]:
    hints: set[str] = set()
    for asset in assets:
        opcua = asset.get("protocol_metadata", {}).get("opcua", {})
        if not isinstance(opcua, dict):
            continue
        ops = opcua.get("operation_hints", {})
        if isinstance(ops, dict):
            hints.update(str(k) for k in ops.keys())
    return hints


def _compute_binary_metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    total = tp + fp + fn + tn
    accuracy = ((tp + tn) / total) if total else 0.0
    precision = (tp / (tp + fp)) if (tp + fp) else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "counts": {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "total": total},
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _run_benchmark(args: argparse.Namespace, local_nets: list[ipaddress.IPv4Network]) -> dict:
    bench_dir = Path(args.benchmark_dir)
    if not bench_dir.exists() or not bench_dir.is_dir():
        raise ValueError("--benchmark-dir must be an existing directory")

    pcaps = sorted(
        [
            p
            for p in bench_dir.iterdir()
            if p.is_file() and p.suffix.lower() in {".pcap", ".pcapng", ".cap"}
        ]
    )

    if not pcaps:
        raise ValueError("No .pcap/.pcapng/.cap files found in benchmark directory")

    report = {
        "benchmark_dir": str(bench_dir),
        "count": len(pcaps),
        "files": [],
    }

    labels = _load_benchmark_labels(bench_dir)
    has_labels = bool(labels.get("files")) if isinstance(labels, dict) else False

    cls_tp = cls_fp = cls_fn = cls_tn = 0
    op_tp = op_fp = op_fn = 0

    for pcap in pcaps:
        packets = rdpcap(str(pcap))
        analyzed = analyze_packets(packets, local_nets)
        assets = [a.to_dict() for a in analyzed]
        result = {
            "mode": "offline",
            "pcap": str(pcap),
            "asset_count": len(assets),
            "assets": assets,
        }
        _enrich_evidence_and_confidence(result["assets"])
        score = _score_inventory_result(result)
        row = {
            "pcap": str(pcap),
            "asset_count": result["asset_count"],
            "score": score,
        }

        if has_labels:
            expected_file = labels.get("files", {}).get(pcap.name, {})
            expected_has_opcua = bool(expected_file.get("has_opcua"))
            predicted_has_opcua = bool(score.get("opcua_assets_strict", 0) > 0)

            if expected_has_opcua and predicted_has_opcua:
                cls_tp += 1
            elif (not expected_has_opcua) and predicted_has_opcua:
                cls_fp += 1
            elif expected_has_opcua and (not predicted_has_opcua):
                cls_fn += 1
            else:
                cls_tn += 1

            expected_ops = set(expected_file.get("expected_operation_hints", []))
            predicted_ops = _collect_detected_operation_hints(result["assets"])
            op_tp += len(expected_ops.intersection(predicted_ops))
            op_fp += len(predicted_ops - expected_ops)
            op_fn += len(expected_ops - predicted_ops)

            row["ground_truth"] = {
                "has_opcua": expected_has_opcua,
                "predicted_has_opcua": predicted_has_opcua,
                "expected_operation_hints": sorted(expected_ops),
                "predicted_operation_hints": sorted(predicted_ops),
            }

        report["files"].append(row)

    if report["files"]:
        report["summary"] = {
            "avg_score": round(
                sum(row["score"]["score_0_100"] for row in report["files"]) / len(report["files"]),
                2,
            ),
            "best_score": max(row["score"]["score_0_100"] for row in report["files"]),
            "worst_score": min(row["score"]["score_0_100"] for row in report["files"]),
        }

    if has_labels:
        op_precision = (op_tp / (op_tp + op_fp)) if (op_tp + op_fp) else 0.0
        op_recall = (op_tp / (op_tp + op_fn)) if (op_tp + op_fn) else 0.0
        op_f1 = (2 * op_precision * op_recall / (op_precision + op_recall)) if (op_precision + op_recall) else 0.0
        report["classification_metrics"] = _compute_binary_metrics(cls_tp, cls_fp, cls_fn, cls_tn)
        report["operation_hint_metrics"] = {
            "counts": {"tp": op_tp, "fp": op_fp, "fn": op_fn},
            "precision": round(op_precision, 4),
            "recall": round(op_recall, 4),
            "f1": round(op_f1, 4),
        }

    return report


def _enrich_evidence_and_confidence(assets: list[dict]) -> None:
    for asset in assets:
        evidence = []
        score = 0.0
        opcua = asset.get("protocol_metadata", {}).get("opcua", {})
        detection = opcua.get("detection", {})

        if asset.get("mac"):
            evidence.append({"field": "mac", "source": "Ethernet", "confidence": 1.0})
            score += 0.2

        if asset.get("oui_vendor"):
            evidence.append({"field": "oui_vendor", "source": "OUI mapping", "confidence": 0.9})
            score += 0.15

        ips = asset.get("ips", [])
        if ips:
            evidence.append({"field": "ips", "source": "IPv4 packet headers", "confidence": 0.95})
            score += 0.2

        if asset.get("role") and asset.get("role") != "Unknown":
            evidence.append(
                {
                    "field": "role",
                    "source": "UA-TCP message/service direction" if opcua.get("observed_roles") else "TCP SYN directionality",
                    "confidence": 0.8,
                }
            )
            score += 0.1

        if asset.get("station_function") and asset.get("station_function") != "Unknown":
            evidence.append(
                {
                    "field": "station_function",
                    "source": "Role + protocol heuristic",
                    "confidence": 0.75,
                }
            )
            score += 0.08

        discovered_protocols = asset.get("discovered_protocols", [])
        if "OPCUA" in discovered_protocols:
            evidence.append(
                {
                    "field": "discovered_protocols",
                    "source": "UA-TCP framing or explicit OPC UA mDNS service marker",
                    "confidence": detection.get("confidence", 0.9),
                }
            )
            score += 0.07

        if detection.get("detected"):
            evidence.append(
                {
                    "field": "protocol_metadata.opcua.detection",
                    "source": ", ".join(detection.get("evidence", [])),
                    "confidence": detection.get("confidence", 0.0),
                }
            )
            score += 0.1

        if opcua.get("message_types"):
            evidence.append(
                {
                    "field": "protocol_metadata.opcua.message_types",
                    "source": "OPC UA TCP headers",
                    "confidence": 0.9,
                }
            )
            score += 0.15

        l2 = asset.get("protocol_metadata", {}).get("l2", {})
        if l2.get("arp") or l2.get("lldp"):
            evidence.append(
                {
                    "field": "protocol_metadata.l2",
                    "source": "ARP/LLDP passive observation",
                    "confidence": 0.8,
                }
            )
            score += 0.05

        asset["evidence"] = evidence
        asset["confidence_score"] = round(min(score, 1.0), 3)


async def _run_active_probe(assets: list[dict], args: argparse.Namespace) -> list[dict]:
    if not args.enable_active:
        return []

    opcua_cfg = OpcUaProbeConfig(
        enabled=args.active_opcua,
        timeout_s=args.opcua_timeout,
    )

    allowlist = _load_allowlist(args.active_allowlist)

    opcua_targets: set[tuple[str, int]] = set()

    for asset in assets:
        detection = asset.get("protocol_metadata", {}).get("opcua", {}).get("detection", {})
        if not detection.get("detected"):
            continue
        for endpoint in detection.get("server_endpoints", []):
            ip = endpoint.get("ip")
            port = endpoint.get("port")
            if ip and isinstance(port, int):
                opcua_targets.add((ip, port))

    if allowlist:
        opcua_targets = {target for target in opcua_targets if target[0] in allowlist}

    if len(opcua_targets) > args.active_max_targets:
        raise ValueError(
            f"Active target count {len(opcua_targets)} exceeds safety cap {args.active_max_targets}. "
            "Use --active-max-targets or --active-allowlist."
        )

    tasks = []
    task_keys = []
    if opcua_cfg.enabled:
        for ip, port in opcua_targets:
            tasks.append(probe_opcua_server(ip=ip, port=port, cfg=opcua_cfg))
            task_keys.append((ip, port))
            if args.active_delay_ms > 0:
                await asyncio.sleep(args.active_delay_ms / 1000.0)

    opcua_results = await asyncio.gather(*tasks, return_exceptions=True) if tasks else []
    active_results = []

    for task_result, (ip, port) in zip(opcua_results, task_keys):
        if isinstance(task_result, Exception):
            probe_result = {
                "status": "probe_failed",
                "target": f"opc.tcp://{ip}:{port}",
                "errors": [str(task_result)],
                "warnings": [],
                "endpoints": [],
                "endpoint_count": 0,
                "find_servers": [],
                "find_servers_on_network": [],
            }
        else:
            probe_result = task_result

        endpoints = probe_result.get("endpoints", [])
        first_endpoint = endpoints[0] if endpoints else {}
        active_record = {
            "target_ip": ip,
            "target_port": port,
            "endpoint_url": probe_result.get("target", f"opc.tcp://{ip}:{port}"),
            "endpoint_count": probe_result.get("endpoint_count", len(endpoints)),
            "endpoint_descriptions": endpoints,
            "applications": [
                {
                    "application_name": endpoint.get("application_name"),
                    "application_uri": endpoint.get("application_uri"),
                    "product_uri": endpoint.get("product_uri"),
                    "application_type": endpoint.get("application_type"),
                }
                for endpoint in endpoints
            ],
            "application_name": first_endpoint.get("application_name"),
            "application_uri": first_endpoint.get("application_uri"),
            "product_uri": first_endpoint.get("product_uri"),
            "application_type": first_endpoint.get("application_type"),
            "security_mode": first_endpoint.get("security_mode"),
            "security_policy": first_endpoint.get("security_policy"),
            "transport_profile": first_endpoint.get("transport_profile_uri"),
            "server_certificates": [
                endpoint.get("certificate") for endpoint in endpoints if endpoint.get("certificate")
            ],
            "get_endpoints": {
                "status": probe_result.get("get_endpoints_status", probe_result.get("status", "unknown")),
                "endpoint_count": probe_result.get("endpoint_count", len(endpoints)),
                "endpoint_descriptions": endpoints,
            },
            "find_servers": {
                "status": probe_result.get("find_servers_status", "unknown"),
                "results": probe_result.get("find_servers", []),
            },
            "find_servers_on_network": {
                "status": probe_result.get("find_servers_on_network_status", "unknown"),
                "results": probe_result.get("find_servers_on_network", []),
            },
            "namespace_array": probe_result.get("namespace_array"),
            "build_info": probe_result.get("build_info"),
            "server_status": probe_result.get("server_status"),
            "field_status": {
                "namespace_array": probe_result.get("namespace_array_status", "unknown"),
                "build_info": probe_result.get("build_info_status", "unknown"),
                "server_status": probe_result.get("server_status_status", "unknown"),
            },
            "address_space_hints": probe_result.get("address_space_hints", []),
            "device": probe_result.get("device"),
            "trust_fingerprint": probe_result.get("trust_fingerprint"),
            "status": probe_result.get("status", "unknown"),
            "errors": probe_result.get("errors", []),
            "warnings": probe_result.get("warnings", []),
            "provenance": "active_observed",
            "passive_server_endpoint_reference": {
                "ip": ip,
                "transport_protocol": "tcp",
                "port": port,
                "provenance": "passive_observed",
            },
        }
        active_results.append(active_record)

    return active_results


def _assemble_inventory(
    *,
    mode: str,
    iface: str | None,
    duration: int,
    packet_count: int,
    bpf: str,
    assets: list[dict],
    capture: dict,
    active: list[dict],
    local_nets: list[ipaddress.IPv4Network],
    diagnostics: dict | None = None,
) -> dict:
    passive_assets = _build_passive_endpoint_assets(capture["packet_events"])

    warnings = [
        "TCP streams are sequence-reassembled per bidirectional IPv4 flow; TCP segment loss or capture gaps can still leave a UA-TCP message incomplete.",
    ]
    warnings.append(
        "For routed traffic, the observed Ethernet MAC may identify the next-hop gateway rather than the remote host; use the IP and port endpoint evidence."
    )
    if not capture["opcua_detected"]:
        warnings.append(
            "No OPC UA framing or valid OPC UA DNS-SD PTR evidence was observed; this does not prove OPC UA is absent from the network."
        )
    for active_result in active:
        warnings.extend(active_result.get("warnings", []))

    summary_fields = {
        "total_packets_observed",
        "opcua_detected",
        "opcua_packets",
        "non_opc_packets",
        "port_4840_candidates",
        "unique_opcua_ip_addresses",
        "unique_opcua_client_ips",
        "unique_opcua_server_ips",
        "message_type_counts",
        "opcua_packet_bytes",
        "opcua_payload_bytes",
        "first_seen",
        "last_seen",
        "capture_first_seen",
        "capture_last_seen",
    }
    runtime_summary = {
            "capture_mode": mode,
            "interface": iface if mode == "runtime" else None,
            "duration_seconds": duration if mode == "runtime" else None,
            "packet_limit": (packet_count or None) if mode == "runtime" else None,
            "asset_count": len(passive_assets),
            "provenance": "passive_observed",
            **{key: capture[key] for key in summary_fields},
        }
    if diagnostics is not None:
        runtime_summary["capture_diagnostics"] = diagnostics

    return {
        "runtime_summary": runtime_summary,
        "passive": {
            "assets": passive_assets,
            "link_layer_observations": _build_link_layer_observations(capture["flows"]),
            "flows": capture["flows"],
            "sessions": capture["opcua_sessions"],
            "source_destination_pairs": capture["source_destination_pairs"],
            "opcua_packet_events": capture["packet_events"],
            "provenance": "passive_observed",
            "inference_provenance": "passive_inferred",
            "local_networks": [str(network) for network in local_nets],
            "capture": {
                "interface": iface if mode == "runtime" else None,
                "bpf_filter": bpf or None,
                "layer2_addressing_note": "MAC addresses are observed Ethernet peers; on routed traffic, the destination MAC may be a next-hop gateway rather than the remote IP host.",
            },
            "warnings": [
                "TCP streams are sequence-reassembled per bidirectional IPv4 flow; TCP segment loss or capture gaps can still leave a UA-TCP message incomplete.",
                "Encrypted SecureChannel payloads may hide service and application metadata; only fields positively visible in the capture are recorded.",
                "Routed Ethernet MAC addresses may identify a next-hop gateway rather than the remote IP host.",
            ],
        },
        "active": active,
        "warnings": sorted(set(warnings)),
    }


def main() -> int:
    args = parse_args()
    resolved_iface = _resolve_capture_interface(args.iface) if args.mode == "runtime" else None
    local_nets = _infer_local_networks(resolved_iface or args.iface, args.local_cidr)

    if args.benchmark_dir:
        report = _run_benchmark(args, local_nets)
        out_path = Path(args.benchmark_output or args.output)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Wrote benchmark report for {report['count']} files to {out_path}")
        return 0

    if args.mode == "runtime":
        print(f"Starting live capture on {args.iface or 'default interface'}...", flush=True)
    packets = _load_packets(args, resolved_iface)
    analyzed = analyze_packets(packets, local_nets)
    assets = [a.to_dict() for a in analyzed]

    for asset in assets:
        asset["provenance"] = {
            "observed": [
                "mac",
                "ips",
                "ttl_values",
                "port_profile",
                "conversations",
                "protocol_metadata.opcua.detection.evidence",
                "protocol_metadata.opcua.message_types",
                "protocol_metadata.opcua.operation_hints",
            ],
            "inferred": ["role", "station_function", "topology_placement"],
            "labels": {"observed": "passive_observed", "inferred": "passive_inferred"},
        }

    capture = _summarize_capture(packets)
    capture_diagnostics = None
    if args.diagnostics and args.mode == "runtime":
        from scapy.all import conf

        diagnostic_iface = resolved_iface or str(conf.iface)
        try:
            device = conf.ifaces.dev_from_name(args.iface or diagnostic_iface)
            interface_description = getattr(device, "description", None)
        except Exception:
            interface_description = None
        local_ip = get_if_addr(diagnostic_iface)
        capture_diagnostics = {
            "requested_interface": args.iface,
            "resolved_interface_name": str(diagnostic_iface),
            "interface_description": interface_description,
            "local_ip": local_ip if local_ip != "0.0.0.0" else None,
            "local_networks": [str(network) for network in local_nets],
            "bpf_filter": args.bpf or None,
            "bpf_filter_applied": bool(args.bpf),
            "total_packets_captured": capture["total_packets_observed"],
            "tcp_packets": capture["tcp_packets"],
            "tcp_packets_with_payload": capture["tcp_packets_with_payload"],
            "udp_packets": capture["udp_packets"],
            "packets_where_opcua_detector_was_invoked": capture["detector_invocation_count"],
            "packets_detected_as_opcua": capture["opcua_packets"],
            "port_4840_candidates": capture["port_4840_candidates"],
            "tcp_payload_samples": capture["tcp_payload_samples"],
        }
    _enrich_evidence_and_confidence(assets)
    active = asyncio.run(_run_active_probe(assets, args))

    result = _assemble_inventory(
        mode=args.mode,
        iface=args.iface,
        duration=args.duration,
        packet_count=args.packet_count,
        bpf=args.bpf,
        assets=assets,
        capture=capture,
        active=active,
        local_nets=local_nets,
        diagnostics=capture_diagnostics,
    )

    out_path = Path(args.output)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Wrote {len(result['passive']['assets'])} assets to {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

