from __future__ import annotations

import asyncio
import json
from contextlib import suppress

from asyncua import Server

from asset_probe.opcua_probe import OpcUaProbeConfig, probe_opcua_server

GROUND_TRUTH = {
    "Manufacturer": "GroundTruth Industries",
    "Model": "GT-OPCUA-1000",
    "SerialNumber": "GT-2026-0001",
    "HardwareRevision": "HW-1.2",
    "SoftwareRevision": "SW-3.4.5",
}


async def _run_validation() -> tuple[dict, list[str]]:
    server = Server()
    await server.init()
    server.set_endpoint("opc.tcp://0.0.0.0:4840/groundtruth")
    server.set_server_name("GroundTruth OPC UA Reference Server")

    idx = await server.register_namespace("urn:groundtruth:opcua")
    device = await server.nodes.objects.add_object(idx, "Device")
    await device.add_variable(idx, "Manufacturer", GROUND_TRUTH["Manufacturer"])
    await device.add_variable(idx, "Model", GROUND_TRUTH["Model"])
    await device.add_variable(idx, "SerialNumber", GROUND_TRUTH["SerialNumber"])
    await device.add_variable(idx, "HardwareRevision", GROUND_TRUTH["HardwareRevision"])
    await device.add_variable(idx, "SoftwareRevision", GROUND_TRUTH["SoftwareRevision"])

    errors: list[str] = []

    async with server:
        await asyncio.sleep(1.0)
        result = await probe_opcua_server("127.0.0.1", 4840, OpcUaProbeConfig(enabled=True, timeout_s=6.0))
        found = result.get("device", {})
        for key, expected in GROUND_TRUTH.items():
            actual = found.get(key)
            if actual != expected:
                errors.append(f"{key}: expected={expected!r} actual={actual!r}")

    return result, errors


def main() -> int:
    result, errors = asyncio.run(_run_validation())
    report = {
        "ground_truth": GROUND_TRUTH,
        "probe_result": result,
        "validation_errors": errors,
        "passed": len(errors) == 0,
    }
    with open("ground_truth_opcua_validation.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("wrote ground_truth_opcua_validation.json")
    print("passed:", report["passed"])
    if errors:
        print("validation_errors:")
        for e in errors:
            print("-", e)

    return 0 if report["passed"] else 2


if __name__ == "__main__":
    with suppress(KeyboardInterrupt):
        raise SystemExit(main())
