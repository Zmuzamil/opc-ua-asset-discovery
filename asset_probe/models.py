from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class ConversationStats:
    peer_ip: str
    packets: int = 0
    bytes: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    avg_interarrival_s: float | None = None


@dataclass
class PortProfile:
    tcp_client_initiations: int = 0
    tcp_server_ports: set[int] = field(default_factory=set)
    udp_ports: set[int] = field(default_factory=set)


@dataclass
class ProtocolMetadata:
    l2: dict[str, Any] = field(default_factory=dict)
    opcua: dict[str, Any] = field(default_factory=dict)


@dataclass
class AssetRecord:
    mac: str
    oui_vendor: str | None = None
    ips: set[str] = field(default_factory=set)
    topology_placement: str = "Unknown"
    role: str = "Unknown"
    station_function: str = "Unknown"
    port_profile: PortProfile = field(default_factory=PortProfile)
    conversations: dict[str, ConversationStats] = field(default_factory=dict)
    protocol_metadata: ProtocolMetadata = field(default_factory=ProtocolMetadata)
    discovered_protocols: set[str] = field(default_factory=set)
    ttl_values: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        base = asdict(self)
        base["ips"] = sorted(self.ips)
        base["discovered_protocols"] = sorted(self.discovered_protocols)
        base["port_profile"]["tcp_server_ports"] = sorted(self.port_profile.tcp_server_ports)
        base["port_profile"]["udp_ports"] = sorted(self.port_profile.udp_ports)
        return base
