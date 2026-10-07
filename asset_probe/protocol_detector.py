from __future__ import annotations

from dataclasses import asdict, dataclass

from scapy.layers.dns import DNS, DNSRR  # type: ignore


OPCUA_PORT = 4840
_OPCUA_MESSAGE_TYPES = {"HEL", "ACK", "ERR", "OPN", "MSG", "CLO"}
_OPCUA_CHUNK_TYPES = {"F", "C", "A"}
# Namespace-0 DefaultBinary encoding ids of request services (OPC 10000-6 NodeIds.csv).
OPCUA_REQUEST_SERVICES = {
    428: "get_endpoints",
    461: "create_session",
    467: "activate_session",
    473: "close_session",
    527: "browse",
    631: "read",
    673: "write",
}
# MSG chunk: header(8) + SecureChannelId(4) + TokenId(4) + SequenceNumber(4) + RequestId(4).
_MSG_TYPE_ID_OFFSET = 24


def parse_service_type_id(payload: bytes) -> int | None:
    """Decode the namespace-0 numeric TypeId NodeId that starts a UA-TCP MSG body.

    Readable only on SecurityPolicy None channels; encrypted bodies decode as noise
    and almost never match a known request id.
    """
    if payload[:3] != b"MSG" or len(payload) < _MSG_TYPE_ID_OFFSET + 2:
        return None
    body = payload[_MSG_TYPE_ID_OFFSET:]
    encoding = body[0]
    if encoding == 0x00:  # TwoByte: id(1), namespace 0
        return body[1]
    if encoding == 0x01 and len(body) >= 4:  # FourByte: namespace(1), id(2)
        return int.from_bytes(body[2:4], "little") if body[1] == 0 else None
    if encoding == 0x02 and len(body) >= 7:  # Numeric: namespace(2), id(4)
        namespace = int.from_bytes(body[1:3], "little")
        return int.from_bytes(body[3:7], "little") if namespace == 0 else None
    return None


def _is_opcua_mdns_ptr_announcement(payload: bytes) -> bool:
    try:
        message = DNS(payload)
    except Exception:
        return False
    if not int(message.qr) or not int(message.ancount):
        return False

    for record in message.an:
        if not isinstance(record, DNSRR):
            continue
        if int(record.type) == 12:
            record_data = (record.rrname, record.rdata)
            for value in record_data:
                if isinstance(value, str):
                    encoded = value.encode("ascii", errors="ignore")
                else:
                    encoded = bytes(value)
                if b"_opcua-tcp._tcp" in encoded.lower():
                    return True
    return False


@dataclass(frozen=True)
class ProtocolDetection:
    detected: bool
    confidence: float
    evidence: tuple[str, ...] = ()
    message_type: str | None = None
    service_id: int | None = None
    candidate: bool = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def detect_opcua_payload(
    payload: bytes,
    *,
    transport: str = "tcp",
    src_port: int | None = None,
    dst_port: int | None = None,
) -> ProtocolDetection:
    """Identify OPC UA from observed UA-TCP framing or its mDNS service marker."""
    normalized_transport = transport.lower()

    if normalized_transport == "tcp" and len(payload) >= 8:
        message_type = payload[:3].decode("ascii", errors="ignore")
        chunk_type = payload[3:4].decode("ascii", errors="ignore")
        message_size = int.from_bytes(payload[4:8], "little", signed=False)

        if (
            message_type in _OPCUA_MESSAGE_TYPES
            and chunk_type in _OPCUA_CHUNK_TYPES
            and message_size >= 8
        ):
            evidence = [
                f"ua_tcp_message_type:{message_type}",
                f"ua_tcp_chunk_type:{chunk_type}",
                f"ua_tcp_message_size:{message_size}",
            ]
            service_id = parse_service_type_id(payload)
            if service_id in OPCUA_REQUEST_SERVICES:
                evidence.append(f"known_service_id:{service_id}")
            else:
                service_id = None

            return ProtocolDetection(
                detected=True,
                confidence=0.99 if service_id is not None else 0.95,
                evidence=tuple(evidence),
                message_type=message_type,
                service_id=service_id,
            )

    if normalized_transport == "udp" and (src_port == 5353 or dst_port == 5353):
        if _is_opcua_mdns_ptr_announcement(payload):
            return ProtocolDetection(
                detected=True,
                confidence=0.9,
                evidence=("mdns_ptr_announcement:_opcua-tcp._tcp",),
            )

    if normalized_transport == "tcp" and OPCUA_PORT in {src_port, dst_port}:
        return ProtocolDetection(
            detected=False,
            confidence=0.2,
            evidence=("tcp_port_4840_candidate_only",),
            candidate=True,
        )

    return ProtocolDetection(detected=False, confidence=0.0)