from __future__ import annotations

import ipaddress
from typing import Iterable

from scapy.all import ARP, Ether, IP, TCP, UDP  # type: ignore

from .models import AssetRecord, ConversationStats
from .oui import is_virtualization_vendor, lookup_oui_vendor
from .protocol_detector import OPCUA_REQUEST_SERVICES, ProtocolDetection, detect_opcua_payload
from .tcp_reassembly import ReassembledTcpMessage, reassemble_tcp_messages

OPCUA_PORT = 4840


def _ensure_asset(assets: dict[str, AssetRecord], mac: str) -> AssetRecord:
    if mac not in assets:
        assets[mac] = AssetRecord(mac=mac, oui_vendor=lookup_oui_vendor(mac))
    return assets[mac]


def _is_local_ip(ip: str, local_nets: Iterable[ipaddress.IPv4Network]) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in local_nets)
    except Exception:
        return False


def _infer_role(asset: AssetRecord) -> str:
    observed_roles = asset.protocol_metadata.opcua.get("observed_roles", [])
    if len(observed_roles) > 1:
        return "Both"
    if observed_roles:
        return observed_roles[0]

    has_server = bool(asset.port_profile.tcp_server_ports)
    has_client = asset.port_profile.tcp_client_initiations > 0
    if has_server and has_client:
        return "Both"
    if has_server:
        return "Server"
    if has_client:
        return "Client"
    return "Unknown"


def _infer_station_function(asset: AssetRecord) -> str:
    if "OPCUA" in asset.discovered_protocols:
        if asset.role == "Server":
            return "OPC UA Server"
        if asset.role == "Client":
            return "OPC UA Client"
        if asset.role == "Both":
            return "OPC UA Client/Server"
    if len(asset.ips) > 1 and asset.role in {"Both", "Server"}:
        return "Gateway/Router"
    return "Unknown"


def _update_interarrival(asset: AssetRecord) -> None:
    for conv in asset.conversations.values():
        if conv.first_seen is not None and conv.last_seen is not None and conv.packets > 1:
            dt = conv.last_seen - conv.first_seen
            conv.avg_interarrival_s = max(dt, 0.0) / float(conv.packets - 1)


def _record_detection(
    asset: AssetRecord,
    detection: ProtocolDetection,
    packet_length: int,
    payload_length: int,
    timestamp: float,
    provenance: str = "passive_observed",
) -> None:
    opcua = asset.protocol_metadata.opcua
    asset.discovered_protocols.add("OPCUA")
    state = opcua.setdefault(
        "detection",
        {
            "detected": True,
            "confidence": 0.0,
            "evidence": [],
            "packet_count": 0,
            "packet_bytes": 0,
            "payload_bytes": 0,
            "first_seen": timestamp,
            "last_seen": timestamp,
            "server_endpoints": [],
            "provenance": [],
        },
    )
    state["confidence"] = max(float(state["confidence"]), detection.confidence)
    state["packet_count"] += 1
    state["packet_bytes"] += packet_length
    state["payload_bytes"] += payload_length
    state["first_seen"] = min(float(state["first_seen"]), timestamp)
    state["last_seen"] = max(float(state["last_seen"]), timestamp)
    for evidence in detection.evidence:
        if evidence not in state["evidence"]:
            state["evidence"].append(evidence)
    if provenance not in state["provenance"]:
        state["provenance"].append(provenance)



def _record_role(asset: AssetRecord, role: str) -> None:
    roles = asset.protocol_metadata.opcua.setdefault("observed_roles", [])
    if role not in roles:
        roles.append(role)


def _record_reassembled_detection(
    assets: dict[str, AssetRecord],
    message: ReassembledTcpMessage,
    packets,
) -> None:
    packet = packets[message.packet_indices[0] - 1]
    src_mac = str(packet["Ether"].src)
    dst_mac = str(packet["Ether"].dst)
    src_asset = _ensure_asset(assets, src_mac)
    dst_asset = _ensure_asset(assets, dst_mac)
    detection = message.detection
    server_asset = src_asset if detection.message_type == "ACK" else dst_asset
    server_ip = message.source_ip if detection.message_type == "ACK" else message.destination_ip
    server_port = message.source_port if detection.message_type == "ACK" else message.destination_port
    packet_bytes = sum(int(len(packets[index - 1])) for index in message.packet_indices)

    _record_detection(
        server_asset,
        detection,
        packet_bytes,
        len(message.payload),
        message.first_seen,
        provenance="passive_observed: tcp_reassembled",
    )
    if src_asset is not server_asset:
        _record_detection(
            src_asset,
            detection,
            packet_bytes,
            len(message.payload),
            message.first_seen,
            provenance="passive_observed: tcp_reassembled",
        )

    if detection.message_type == "HEL":
        _record_role(src_asset, "Client")
        _record_role(server_asset, "Server")
        role_inference = "UA-TCP HEL destination"
    elif detection.message_type == "ACK":
        _record_role(src_asset, "Server")
        _record_role(dst_asset, "Client")
        role_inference = "UA-TCP ACK source"
    elif detection.service_id is not None:
        _record_role(src_asset, "Client")
        _record_role(server_asset, "Server")
        role_inference = "known UA-TCP request service destination"
    else:
        role_inference = None

    opcua = server_asset.protocol_metadata.opcua
    if detection.message_type:
        types = opcua.setdefault("message_types", {})
        types[detection.message_type] = int(types.get(detection.message_type, 0)) + 1
        transfer = opcua.setdefault(
            "transfer_stats",
            {
                "payload_bytes": 0,
                "packet_count": 0,
                "first_seen": message.first_seen,
                "last_seen": message.last_seen,
            },
        )
        transfer["payload_bytes"] += len(message.payload)
        transfer["packet_count"] += 1
        transfer["last_seen"] = max(float(transfer["last_seen"]), message.last_seen)
        printable = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in message.payload[:96])
        samples = opcua.setdefault("payload_samples", [])
        if printable and printable not in samples and len(samples) < 5:
            samples.append(printable)

    if role_inference and server_ip:
        endpoints = opcua["detection"]["server_endpoints"]
        endpoint = next(
            (item for item in endpoints if item["ip"] == server_ip and item["port"] == server_port),
            None,
        )
        if endpoint is None:
            endpoints.append({"ip": server_ip, "port": server_port, "role_inferences": [role_inference]})
        elif role_inference not in endpoint["role_inferences"]:
            endpoint["role_inferences"].append(role_inference)

    if detection.service_id is not None:
        operation = OPCUA_REQUEST_SERVICES[detection.service_id]
        hints = opcua.setdefault("operation_hints", {})
        hints[operation] = int(hints.get(operation, 0)) + 1
        binary_hints = opcua.setdefault("binary_service_hints", {})
        key = f"{operation}_request"
        binary_hints[key] = int(binary_hints.get(key, 0)) + 1

    stream_record = {
        "message_type": detection.message_type,
        "service_id": detection.service_id,
        "sequence_start": message.sequence_start,
        "message_size": len(message.payload),
        "packet_indices": list(message.packet_indices),
        "provenance": "passive_observed: tcp_reassembled",
    }
    for asset in {src_asset.mac: src_asset, server_asset.mac: server_asset}.values():
        stream_messages = asset.protocol_metadata.opcua.setdefault("tcp_reassembled_messages", [])
        if stream_record not in stream_messages:
            stream_messages.append(stream_record)


def _message_was_detected_in_packet(message: ReassembledTcpMessage, packets) -> bool:
    for packet_index in message.packet_indices:
        packet = packets[packet_index - 1]
        payload = bytes(packet["TCP"].payload)
        if not payload.startswith(message.payload):
            continue
        detection = detect_opcua_payload(
            payload,
            src_port=int(packet["TCP"].sport),
            dst_port=int(packet["TCP"].dport),
        )
        if detection.detected and detection.message_type == message.detection.message_type:
            declared_size = int.from_bytes(payload[4:8], "little")
            if declared_size <= len(payload):
                return True
    return False


def analyze_packets(packets, local_nets: list[ipaddress.IPv4Network]) -> list[AssetRecord]:
    packets = list(packets)
    assets: dict[str, AssetRecord] = {}
    detected_tcp_messages: set[tuple] = set()

    for pkt in packets:
        if Ether not in pkt:
            continue

        src_mac = str(pkt[Ether].src)
        dst_mac = str(pkt[Ether].dst)
        src_asset = _ensure_asset(assets, src_mac)
        dst_asset = _ensure_asset(assets, dst_mac)
        timestamp = float(getattr(pkt, "time", 0.0))
        packet_length = int(len(pkt))

        if ARP in pkt:
            src_asset.protocol_metadata.l2.setdefault("arp", {"packets": 0})
            src_asset.protocol_metadata.l2["arp"]["packets"] += 1

        if IP in pkt:
            src_ip = str(pkt[IP].src)
            dst_ip = str(pkt[IP].dst)
            src_asset.ips.add(src_ip)
            dst_asset.ips.add(dst_ip)
            src_asset.ttl_values.append(int(pkt[IP].ttl))

            conv = src_asset.conversations.get(dst_ip)
            if conv is None:
                conv = ConversationStats(
                    peer_ip=dst_ip,
                    packets=0,
                    bytes=0,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
                src_asset.conversations[dst_ip] = conv
            conv.packets += 1
            conv.bytes += packet_length
            conv.last_seen = timestamp

        if TCP in pkt:
            tcp = pkt[TCP]
            src_asset.port_profile.tcp_client_initiations += int(
                bool(tcp.flags & 0x02 and not (tcp.flags & 0x10))
            )
            dst_asset.port_profile.tcp_server_ports.add(int(tcp.dport))
            payload = bytes(tcp.payload)
            detection = detect_opcua_payload(
                payload,
                src_port=int(tcp.sport),
                dst_port=int(tcp.dport),
            )
            if detection.detected:
                declared_size = int.from_bytes(payload[4:8], "little") if len(payload) >= 8 else 0
                if declared_size > len(payload):
                    detection = ProtocolDetection(detected=False, confidence=0.0)
                else:
                    fingerprint = (
                        str(pkt[IP].src) if IP in pkt else "",
                        int(tcp.sport),
                        str(pkt[IP].dst) if IP in pkt else "",
                        int(tcp.dport),
                        int(tcp.seq),
                        payload[:declared_size],
                    )
                    if fingerprint in detected_tcp_messages:
                        detection = ProtocolDetection(detected=False, confidence=0.0)
                    else:
                        detected_tcp_messages.add(fingerprint)

            if detection.detected:
                if detection.message_type == "ACK":
                    server_asset = src_asset
                    server_ip = str(pkt[IP].src) if IP in pkt else ""
                    server_port = int(tcp.sport)
                else:
                    server_asset = dst_asset
                    server_ip = str(pkt[IP].dst) if IP in pkt else ""
                    server_port = int(tcp.dport)

                _record_detection(server_asset, detection, packet_length, len(payload), timestamp)
                if src_asset is not server_asset:
                    _record_detection(src_asset, detection, packet_length, len(payload), timestamp)
                opcua = server_asset.protocol_metadata.opcua
                if detection.message_type == "HEL":
                    _record_role(src_asset, "Client")
                    _record_role(server_asset, "Server")
                elif detection.message_type == "ACK":
                    _record_role(src_asset, "Server")
                    _record_role(dst_asset, "Client")
                elif detection.service_id is not None:
                    _record_role(src_asset, "Client")
                    _record_role(server_asset, "Server")

                if detection.message_type:
                    opcua.setdefault("message_types", {})
                    types = opcua["message_types"]
                    types[detection.message_type] = int(types.get(detection.message_type, 0)) + 1
                    opcua.setdefault(
                        "transfer_stats",
                        {
                            "payload_bytes": 0,
                            "packet_count": 0,
                            "first_seen": timestamp,
                            "last_seen": timestamp,
                        },
                    )
                    transfer = opcua["transfer_stats"]
                    transfer["payload_bytes"] += len(payload)
                    transfer["packet_count"] += 1
                    transfer["last_seen"] = timestamp

                    sample = payload[:96]
                    printable = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in sample)
                    opcua.setdefault("payload_samples", [])
                    if printable and printable not in opcua["payload_samples"] and len(opcua["payload_samples"]) < 5:
                        opcua["payload_samples"].append(printable)

                if (detection.message_type in {"HEL", "ACK"} or detection.service_id is not None) and server_ip:
                    if detection.message_type == "ACK":
                        role_inference = "UA-TCP ACK source"
                    elif detection.message_type == "HEL":
                        role_inference = "UA-TCP HEL destination"
                    else:
                        role_inference = "known UA-TCP request service destination"
                    endpoints = opcua["detection"]["server_endpoints"]
                    endpoint = next(
                        (
                            item
                            for item in endpoints
                            if item["ip"] == server_ip and item["port"] == server_port
                        ),
                        None,
                    )
                    if endpoint is None:
                        endpoints.append(
                            {
                                "ip": server_ip,
                                "port": server_port,
                                "role_inferences": [role_inference],
                            }
                        )
                    elif role_inference not in endpoint["role_inferences"]:
                        endpoint["role_inferences"].append(role_inference)

                if detection.service_id is not None:
                    operation = OPCUA_REQUEST_SERVICES[detection.service_id]
                    opcua.setdefault("operation_hints", {})
                    hints = opcua["operation_hints"]
                    hints[operation] = int(hints.get(operation, 0)) + 1
                    opcua.setdefault("binary_service_hints", {})
                    binary_hints = opcua["binary_service_hints"]
                    binary_key = f"{operation}_request"
                    binary_hints[binary_key] = int(binary_hints.get(binary_key, 0)) + 1

        if UDP in pkt:
            udp = pkt[UDP]
            src_asset.port_profile.udp_ports.add(int(udp.sport))
            dst_asset.port_profile.udp_ports.add(int(udp.dport))
            payload = bytes(udp.payload)
            detection = detect_opcua_payload(
                payload,
                transport="udp",
                src_port=int(udp.sport),
                dst_port=int(udp.dport),
            )
            if detection.detected:
                _record_detection(src_asset, detection, packet_length, len(payload), timestamp)
                opcua = src_asset.protocol_metadata.opcua
                opcua.setdefault("mdns_announcements", {"count": 0, "last_seen": timestamp})
                opcua["mdns_announcements"]["count"] += 1
                opcua["mdns_announcements"]["last_seen"] = timestamp

    for reassembled in reassemble_tcp_messages(packets):
        if not _message_was_detected_in_packet(reassembled, packets):
            _record_reassembled_detection(assets, reassembled, packets)

    out = list(assets.values())
    for asset in out:
        if asset.ips:
            if is_virtualization_vendor(asset.oui_vendor):
                asset.topology_placement = "Virtual"
            elif any(_is_local_ip(ip, local_nets) for ip in asset.ips):
                asset.topology_placement = "Local"
            else:
                asset.topology_placement = "Remote"

        asset.role = _infer_role(asset)
        asset.station_function = _infer_station_function(asset)
        _update_interarrival(asset)
        if "detection" in asset.protocol_metadata.opcua:
            asset.protocol_metadata.opcua["detection"]["evidence"].sort()

    out.sort(key=lambda asset: (0 if asset.protocol_metadata.opcua else 1, asset.mac))
    return out
