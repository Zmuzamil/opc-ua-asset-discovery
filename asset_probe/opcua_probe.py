from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import timezone
from typing import Any

from asyncua import Client
from asyncua.ua import NodeId

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except Exception:  # pragma: no cover
    x509 = None
    serialization = None


@dataclass
class OpcUaProbeConfig:
    enabled: bool = False
    timeout_s: float = 4.0
    max_browse_nodes: int = 200


def _classify_probe_error(message: str) -> dict[str, str]:
    m = (message or "").lower()
    if "badtoomanysessions" in m or "maximum number of sessions" in m:
        return {
            "status": "server_session_limit",
            "hint": "Target server is reachable but temporarily rejects new sessions. Retry later.",
        }
    if "connection is closed" in m:
        return {
            "status": "connection_closed",
            "hint": "Server closed the OPC UA channel. Endpoint URL path or server policy may require adjustment.",
        }
    if "timed out" in m or "timeout" in m:
        return {
            "status": "timeout",
            "hint": "Target did not complete OPC UA handshake in time. Increase timeout or retry.",
        }
    return {
        "status": "probe_failed",
        "hint": "Probe failed due to target/server behavior or policy. Check warnings and retry.",
    }


def _servers_from_endpoints(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Derive coarse server inventory from endpoint metadata as a fallback."""
    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    for ep in endpoints:
        app_uri = str(ep.get("application_uri") or "")
        product_uri = str(ep.get("product_uri") or "")
        app_name = str(ep.get("application_name") or "")
        key = (app_uri, product_uri, app_name)
        if key not in out:
            out[key] = {
                "application_uri": app_uri,
                "product_uri": product_uri,
                "application_type": "Unknown",
                "application_name": app_name,
                "source": "endpoint_fallback",
            }
    return list(out.values())


def _derive_device_identity(result: dict[str, Any]) -> dict[str, Any]:
    device = {
        "Manufacturer": None,
        "Model": None,
        "SerialNumber": None,
        "HardwareRevision": None,
        "SoftwareRevision": None,
    }

    exact_hits: dict[str, str] = {}

    hints = result.get("address_space_hints", [])
    if isinstance(hints, list):
        for item in hints:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", ""))
            lower_name = name.lower()
            value = item.get("value")
            if value is None:
                continue

            if "|" in name:
                browse_name = name.split("|", 1)[0]
                if ":" in browse_name:
                    browse_name = browse_name.split(":", 1)[1]
                key = browse_name.strip()
                if key in {"Manufacturer", "Model", "SerialNumber", "HardwareRevision", "SoftwareRevision"}:
                    exact_hits[key] = str(value)

            if device["Model"] is None and "model" in lower_name:
                device["Model"] = str(value)
            elif device["SerialNumber"] is None and "serial" in lower_name:
                device["SerialNumber"] = str(value)
            elif device["HardwareRevision"] is None and (
                "hardware" in lower_name or "hwrevision" in lower_name or "revision" in lower_name
            ):
                device["HardwareRevision"] = str(value)
            elif device["SoftwareRevision"] is None and (
                "software" in lower_name or "swrevision" in lower_name or "firmware" in lower_name
            ):
                device["SoftwareRevision"] = str(value)
            elif device["Manufacturer"] is None and "manufacturer" in lower_name:
                device["Manufacturer"] = str(value)

    build_info = result.get("build_info", {})
    if isinstance(build_info, dict):
        if not device["Manufacturer"]:
            device["Manufacturer"] = build_info.get("manufacturer_name")
        if not device["SoftwareRevision"]:
            device["SoftwareRevision"] = build_info.get("software_version")

    for key, value in exact_hits.items():
        device[key] = value

    return device


def _parse_certificate(cert_bytes: bytes) -> dict[str, Any]:
    if not cert_bytes:
        return {}

    parsed: dict[str, Any] = {
        "sha256": hashlib.sha256(cert_bytes).hexdigest(),
        "length": len(cert_bytes),
    }

    if x509 is None:
        parsed["note"] = "Install cryptography for full certificate parsing"
        return parsed

    try:
        cert = x509.load_der_x509_certificate(cert_bytes)
        parsed["subject"] = cert.subject.rfc4514_string()
        parsed["issuer"] = cert.issuer.rfc4514_string()
        parsed["serial_number"] = str(cert.serial_number)
        parsed["not_before"] = cert.not_valid_before_utc.astimezone(timezone.utc).isoformat()
        parsed["not_after"] = cert.not_valid_after_utc.astimezone(timezone.utc).isoformat()
        parsed["signature_hash"] = getattr(cert.signature_hash_algorithm, "name", None)
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            parsed["san_application_uris"] = list(san.get_values_for_type(x509.UniformResourceIdentifier))
            parsed["san_dns_names"] = list(san.get_values_for_type(x509.DNSName))
            parsed["san_ip_addresses"] = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
        except Exception:
            parsed["san_application_uris"] = []
            parsed["san_dns_names"] = []
            parsed["san_ip_addresses"] = []
        if serialization is not None:
            parsed["public_key_type"] = cert.public_key().__class__.__name__
    except Exception as ex:
        parsed["parse_error"] = str(ex)

    return parsed


async def probe_opcua_server(ip: str, port: int, cfg: OpcUaProbeConfig, endpoint_url: str | None = None) -> dict[str, Any]:
    if not cfg.enabled:
        return {}

    target_url = endpoint_url or f"opc.tcp://{ip}:{port}"

    result: dict[str, Any] = {
        "target": target_url,
        "errors": [],
        "warnings": [],
        "find_servers": [],
        "find_servers_on_network": [],
        "status": "unknown",
    }

    url = target_url
    client = Client(url=url, timeout=cfg.timeout_s)

    try:
        await asyncio.wait_for(client.connect(), timeout=cfg.timeout_s)

        endpoints = await asyncio.wait_for(client.get_endpoints(), timeout=cfg.timeout_s)
        result["endpoints"] = []
        for ep in endpoints:
            cert_info = _parse_certificate(ep.ServerCertificate or b"")
            app_uri = ep.Server.ApplicationUri
            cert_app_uris = cert_info.get("san_application_uris", [])
            uri_match = None
            if isinstance(cert_app_uris, list) and cert_app_uris:
                uri_match = app_uri in cert_app_uris
            result["endpoints"].append(
                {
                    "endpoint_url": ep.EndpointUrl,
                    "security_mode": str(ep.SecurityMode),
                    "security_policy": ep.SecurityPolicyUri,
                    "transport_profile_uri": ep.TransportProfileUri,
                    "application_type": str(ep.Server.ApplicationType),
                    "application_uri": app_uri,
                    "product_uri": ep.Server.ProductUri,
                    "application_name": str(ep.Server.ApplicationName.Text),
                    "application_uri_matches_certificate_san": uri_match,
                    "certificate": cert_info,
                }
            )
            result["get_endpoints_status"] = "ok"
            result["endpoint_count"] = len(result["endpoints"])

        cert_fingerprints = []
        for ep in result["endpoints"]:
            cert = ep.get("certificate", {})
            fp = cert.get("sha256")
            if fp:
                cert_fingerprints.append(fp)
        result["trust_fingerprint"] = {
            "cert_sha256_unique": sorted(set(cert_fingerprints)),
            "endpoint_count": len(result["endpoints"]),
        }

        try:
            servers = await asyncio.wait_for(client.find_servers(), timeout=cfg.timeout_s)
            result["find_servers"] = [
                {
                    "application_uri": s.ApplicationUri,
                    "product_uri": s.ProductUri,
                    "application_type": str(s.ApplicationType),
                    "application_name": str(s.ApplicationName.Text),
                    "source": "find_servers",
                }
                for s in servers
            ]
            if not result["find_servers"]:
                result["find_servers"] = _servers_from_endpoints(result.get("endpoints", []))
                if result["find_servers"]:
                    result["warnings"].append("FindServers returned no rows; used endpoint-based fallback server list")
            result["find_servers_status"] = "ok" if result["find_servers"] else "empty"
        except Exception as ex:
            result["warnings"].append(f"FindServers failed: {ex}; using endpoint-based fallback server list")
            result["find_servers"] = _servers_from_endpoints(result.get("endpoints", []))
            result["find_servers_status"] = "failed_with_endpoint_fallback" if result["find_servers"] else "failed"

        try:
            servers_on_net = await asyncio.wait_for(client.find_servers_on_network(), timeout=cfg.timeout_s)
            result["find_servers_on_network"] = [
                {
                    "record_id": s.RecordId,
                    "server_name": s.ServerName,
                    "discovery_url": s.DiscoveryUrl,
                    "capabilities": list(s.ServerCapabilities),
                }
                for s in servers_on_net
            ]
            result["find_servers_on_network_status"] = "ok"
        except Exception as ex:
            result["warnings"].append(f"FindServersOnNetwork not available or restricted: {ex}")
            result["find_servers_on_network_status"] = "unavailable_or_restricted"

        ns_node = client.get_node(NodeId(2255, 0))
        ns_array = await asyncio.wait_for(ns_node.read_value(), timeout=cfg.timeout_s)
        result["namespace_array"] = list(ns_array) if isinstance(ns_array, (list, tuple)) else [str(ns_array)]
        result["namespace_array_status"] = "ok"

        build_info_node = client.get_node(NodeId(2260, 0))
        try:
            build_info = await asyncio.wait_for(build_info_node.read_value(), timeout=cfg.timeout_s)
            result["build_info"] = {
                "product_name": getattr(build_info, "ProductName", None),
                "software_version": getattr(build_info, "SoftwareVersion", None),
                "build_number": getattr(build_info, "BuildNumber", None),
                "manufacturer_name": getattr(build_info, "ManufacturerName", None),
            }
            result["build_info_status"] = "ok"
        except Exception as ex:
            result["warnings"].append(f"BuildInfo read failed: {ex}")
            result["build_info_status"] = "failed"

        server_status_node = client.get_node(NodeId(2256, 0))
        try:
            server_status = await asyncio.wait_for(server_status_node.read_value(), timeout=cfg.timeout_s)
            server_status_build = getattr(server_status, "BuildInfo", None)
            result["server_status"] = {
                "start_time": str(getattr(server_status, "StartTime", "")) or None,
                "current_time": str(getattr(server_status, "CurrentTime", "")) or None,
                "state": str(getattr(server_status, "State", "")) or None,
                "seconds_till_shutdown": getattr(server_status, "SecondsTillShutdown", None),
                "shutdown_reason": str(getattr(getattr(server_status, "ShutdownReason", None), "Text", "")) or None,
                "build_info": {
                    "product_name": getattr(server_status_build, "ProductName", None),
                    "software_version": getattr(server_status_build, "SoftwareVersion", None),
                    "build_number": getattr(server_status_build, "BuildNumber", None),
                    "manufacturer_name": getattr(server_status_build, "ManufacturerName", None),
                } if server_status_build is not None else None,
            }
            result["server_status_status"] = "ok"
        except Exception as ex:
            result["server_status_status"] = "failed"
            result["warnings"].append(f"ServerStatus read failed: {ex}")

        # Lightweight bounded browse from Objects folder looking for device traits.
        objects = client.nodes.objects
        q = [objects]
        visited = set()
        found = []

        while q and len(visited) < cfg.max_browse_nodes:
            node = q.pop(0)
            nid = str(node.nodeid)
            if nid in visited:
                continue
            visited.add(nid)

            try:
                bname = await asyncio.wait_for(node.read_browse_name(), timeout=cfg.timeout_s)
                display = await asyncio.wait_for(node.read_display_name(), timeout=cfg.timeout_s)
                name = f"{bname.Name}|{display.Text}"
            except Exception:
                name = nid

            lower = name.lower()
            if any(token in lower for token in ["serial", "model", "revision", "firmware", "device", "manufacturer", "software", "hardware"]):
                try:
                    value = await asyncio.wait_for(node.read_value(), timeout=cfg.timeout_s)
                except Exception:
                    value = None
                found.append({"node": nid, "name": name, "value": str(value) if value is not None else None})

            try:
                children = await asyncio.wait_for(node.get_children(), timeout=cfg.timeout_s)
                q.extend(children[:10])
            except Exception:
                continue

        result["address_space_hints"] = found
        result["device"] = _derive_device_identity(result)
        result["status"] = "ok"

    except Exception as ex:
        emsg = str(ex)
        info = _classify_probe_error(emsg)
        result["status"] = info["status"]
        result["errors"].append(f"Probe failed: {emsg}")
        result["warnings"].append(info["hint"])
    finally:
        try:
            await asyncio.wait_for(client.disconnect(), timeout=cfg.timeout_s)
        except Exception:
            pass

    return result
