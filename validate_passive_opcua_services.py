from __future__ import annotations

import ipaddress
import json
import struct

from scapy.all import Ether, IP, TCP, Raw  # type: ignore

from asset_probe.passive import analyze_packets


SERVICE_IDS = {
    "get_endpoints": 428,
    "create_session": 461,
    "activate_session": 467,
    "read": 631,
    "browse": 527,
    "write": 673,
    "close_session": 473,
}

EXPECTED_BINARY_HINTS = {
    "get_endpoints_request",
    "create_session_request",
    "activate_session_request",
    "read_request",
    "browse_request",
    "write_request",
    "close_session_request",
}


def _binary_opcua_msg(service_id: int, channel_id: int = 1, request_id: int = 1) -> bytes:
    # UA TCP message header: MessageType(3), ChunkType(1), MessageSize(4, le)
    ua_header = b"MSGF"
    # Minimal SecureConversation scaffolding + FourByte NodeId (0x01, ns 0, uint16 id) service type.
    body = b"".join(
        [
            struct.pack("<I", channel_id),
            struct.pack("<I", 0),  # token id placeholder
            struct.pack("<I", 1),  # sequence number
            struct.pack("<I", request_id),
            b"\x01\x00" + struct.pack("<H", service_id),
            b"\x00\x00\x00\x00",
        ]
    )
    size = 8 + len(body)
    return ua_header + struct.pack("<I", size) + body


def _pkt(service_id: int, t: float):
    payload = _binary_opcua_msg(service_id=service_id, request_id=int(t))
    pkt = (
        Ether(src="02:42:ac:11:00:02", dst="02:42:ac:11:00:01")
        / IP(src="10.10.0.2", dst="10.10.0.10", ttl=64)
        / TCP(sport=51000, dport=4840, flags="PA")
        / Raw(load=payload)
    )
    pkt.time = t
    return pkt


def main() -> int:
    packets = [_pkt(service_id, i + 1.0) for i, service_id in enumerate(SERVICE_IDS.values())]

    assets = [a.to_dict() for a in analyze_packets(packets, [ipaddress.IPv4Network("10.10.0.0/24")])]
    out = {
        "asset_count": len(assets),
        "services_expected": [
            "get_endpoints",
            "create_session",
            "activate_session",
            "read",
            "browse",
            "write",
            "close_session",
        ],
        "assets": assets,
    }

    with open("passive_opcua_service_validation.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    if not assets:
        print("No assets parsed")
        return 1

    opcua = assets[0].get("protocol_metadata", {}).get("opcua", {})
    hints = set((opcua.get("operation_hints") or {}).keys())
    binary_hints = set((opcua.get("binary_service_hints") or {}).keys())
    required = set(out["services_expected"])
    missing = sorted(required - hints)
    missing_binary = sorted(EXPECTED_BINARY_HINTS - binary_hints)

    print("Parsed operation hints:", sorted(hints))
    print("Parsed binary service hints:", sorted(binary_hints))
    if missing or missing_binary:
        print("Missing:", missing)
        print("Missing binary:", missing_binary)
        return 2

    print("Passive service extraction validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
