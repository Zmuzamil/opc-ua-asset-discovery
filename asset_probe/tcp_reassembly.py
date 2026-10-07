from __future__ import annotations

from dataclasses import dataclass

from .protocol_detector import ProtocolDetection, detect_opcua_payload

_TCP_SEQUENCE_MODULUS = 1 << 32
_TCP_SEQUENCE_HALF = 1 << 31
_MAX_UA_TCP_MESSAGE_SIZE = 16 * 1024 * 1024


@dataclass(frozen=True)
class ReassembledTcpMessage:
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    payload: bytes
    packet_indices: tuple[int, ...]
    first_seen: float
    last_seen: float
    sequence_start: int
    detection: ProtocolDetection


def _sequence_offset(sequence: int, anchor: int) -> int:
    return ((sequence - anchor + _TCP_SEQUENCE_HALF) % _TCP_SEQUENCE_MODULUS) - _TCP_SEQUENCE_HALF


def _contiguous_runs(segments: list[dict], anchor: int) -> list[tuple[int, bytes]]:
    positioned = sorted(
        [
            (
            _sequence_offset(segment["sequence"], anchor),
            segment["payload"],
            segment,
            )
            for segment in segments
            if segment["payload"]
        ],
        key=lambda item: (item[0], len(item[1]), item[2]["packet_index"]),
    )
    runs: list[tuple[int, bytes]] = []
    run_start: int | None = None
    run_bytes = bytearray()
    run_end = 0

    def finish_run() -> None:
        if run_start is not None:
            runs.append((run_start, bytes(run_bytes)))

    for start, payload, _segment in positioned:
        end = start + len(payload)
        if run_start is None or start > run_end:
            finish_run()
            run_start = start
            run_bytes = bytearray(payload)
            run_end = end
            continue

        if end > run_end:
            overlap = max(0, run_end - start)
            run_bytes.extend(payload[overlap:])
            run_end = end

    finish_run()
    return runs


def _extract_messages(
    direction: tuple[str, int, str, int],
    segments: list[dict],
    anchor: int,
) -> list[ReassembledTcpMessage]:
    output: list[ReassembledTcpMessage] = []
    positioned_segments = [
        (
            _sequence_offset(segment["sequence"], anchor),
            _sequence_offset(segment["sequence"], anchor) + len(segment["payload"]),
            segment,
        )
        for segment in segments
        if segment["payload"]
    ]

    for run_start, stream in _contiguous_runs(segments, anchor):
        offset = 0
        while offset + 8 <= len(stream):
            message_size = int.from_bytes(stream[offset + 4 : offset + 8], "little")
            if message_size < 8 or message_size > _MAX_UA_TCP_MESSAGE_SIZE:
                offset += 1
                continue
            message_end = offset + message_size
            if message_end > len(stream):
                break

            message = stream[offset:message_end]
            detection = detect_opcua_payload(message, transport="tcp")
            if detection.detected:
                absolute_start = run_start + offset
                absolute_end = run_start + message_end
                contributors = [
                    segment
                    for segment_start, segment_end, segment in positioned_segments
                    if segment_start < absolute_end and segment_end > absolute_start
                ]
                if contributors:
                    output.append(
                        ReassembledTcpMessage(
                            source_ip=direction[0],
                            source_port=direction[1],
                            destination_ip=direction[2],
                            destination_port=direction[3],
                            payload=message,
                            packet_indices=tuple(sorted({item["packet_index"] for item in contributors})),
                            first_seen=min(item["timestamp"] for item in contributors),
                            last_seen=max(item["timestamp"] for item in contributors),
                            sequence_start=absolute_start,
                            detection=detection,
                        )
                    )
            offset = message_end

    return output


def reassemble_tcp_messages(packets) -> list[ReassembledTcpMessage]:
    """Return detector-positive UA-TCP messages reconstructed from complete TCP streams."""
    flows: dict[tuple, dict[tuple[str, int, str, int], dict]] = {}

    for packet_index, packet in enumerate(packets, start=1):
        if "IP" not in packet or "TCP" not in packet:
            continue
        tcp = packet["TCP"]
        source_ip = str(packet["IP"].src)
        destination_ip = str(packet["IP"].dst)
        source_port = int(tcp.sport)
        destination_port = int(tcp.dport)
        direction = (source_ip, source_port, destination_ip, destination_port)
        endpoints = tuple(sorted(((source_ip, source_port), (destination_ip, destination_port))))
        flow = flows.setdefault(endpoints, {})
        state = flow.setdefault(direction, {"segments": [], "syn_sequences": []})
        sequence = int(tcp.seq) & 0xFFFFFFFF
        syn = bool(int(tcp.flags) & 0x02)
        if syn:
            state["syn_sequences"].append((sequence + 1) & 0xFFFFFFFF)
        payload = bytes(tcp.payload)
        if payload:
            payload_sequence = (sequence + int(syn)) & 0xFFFFFFFF
            state["segments"].append(
                {
                    "sequence": payload_sequence,
                    "payload": payload,
                    "packet_index": packet_index,
                    "timestamp": float(getattr(packet, "time", 0.0)),
                }
            )

    messages: list[ReassembledTcpMessage] = []
    for flow in flows.values():
        for direction, state in flow.items():
            segments = state["segments"]
            if not segments:
                continue
            anchors = state["syn_sequences"]
            anchor = anchors[0] if anchors else segments[0]["sequence"]
            messages.extend(_extract_messages(direction, segments, anchor))

    return sorted(messages, key=lambda item: (item.first_seen, item.source_ip, item.source_port, item.sequence_start))