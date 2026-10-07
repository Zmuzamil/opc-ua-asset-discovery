from __future__ import annotations

import sys
import tempfile
from argparse import Namespace
from pathlib import Path
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, patch

from asset_probe.cli import _run_active_probe, parse_args


def _active_args() -> Namespace:
    return Namespace(
        enable_active=True,
        active_opcua=True,
        opcua_timeout=1.0,
        active_allowlist="",
        active_max_targets=5,
        active_delay_ms=0,
    )


class ActiveProbeGatingTests(IsolatedAsyncioTestCase):
    async def test_port_without_positive_detection_is_not_probed(self) -> None:
        assets = [
            {
                "mac": "02:42:ac:11:00:b2",
                "ips": ["192.0.2.10"],
                "port_profile": {"tcp_server_ports": [4840]},
                "protocol_metadata": {"opcua": {"detection": {"detected": False}}},
            }
        ]

        with patch("asset_probe.cli.probe_opcua_server", new_callable=AsyncMock) as probe:
            active = await _run_active_probe(assets, _active_args())

        probe.assert_not_awaited()
        self.assertEqual(active, [])

    async def test_detected_nonstandard_endpoint_is_probed(self) -> None:
        assets = [
            {
                "mac": "02:42:ac:11:00:c2",
                "ips": ["192.0.2.20"],
                "protocol_metadata": {
                    "opcua": {
                        "detection": {
                            "detected": True,
                            "server_endpoints": [{"ip": "192.0.2.20", "port": 51210}],
                        }
                    }
                },
            }
        ]

        with patch(
            "asset_probe.cli.probe_opcua_server",
            new_callable=AsyncMock,
            return_value={"status": "ok"},
        ) as probe:
            active = await _run_active_probe(assets, _active_args())

        probe.assert_awaited_once()
        self.assertEqual(probe.await_args.kwargs["ip"], "192.0.2.20")
        self.assertEqual(probe.await_args.kwargs["port"], 51210)
        self.assertEqual(active[0]["status"], "ok")
        self.assertEqual(active[0]["provenance"], "active_observed")
        self.assertNotIn("active_probe", assets[0]["protocol_metadata"]["opcua"])

    async def test_detected_endpoint_is_not_probed_without_opt_in(self) -> None:
        assets = [
            {
                "mac": "02:42:ac:11:00:d2",
                "ips": ["192.0.2.30"],
                "protocol_metadata": {
                    "opcua": {
                        "detection": {
                            "detected": True,
                            "server_endpoints": [{"ip": "192.0.2.30", "port": 12001}],
                        }
                    }
                },
            }
        ]
        args = _active_args()
        args.enable_active = False
        args.active_opcua = False

        with patch("asset_probe.cli.probe_opcua_server", new_callable=AsyncMock) as probe:
            active = await _run_active_probe(assets, args)

        probe.assert_not_awaited()
        self.assertEqual(active, [])

    async def test_allowlist_excludes_unlisted_detected_endpoints(self) -> None:
        assets = [
            {
                "mac": "02:42:ac:11:00:f2",
                "ips": ["192.0.2.50", "192.0.2.51"],
                "protocol_metadata": {
                    "opcua": {
                        "detection": {
                            "detected": True,
                            "server_endpoints": [
                                {"ip": "192.0.2.50", "port": 4840},
                                {"ip": "192.0.2.51", "port": 4840},
                            ],
                        }
                    }
                },
            }
        ]
        with tempfile.TemporaryDirectory() as folder:
            allowlist = Path(folder) / "allow.txt"
            allowlist.write_text("# lab server\n192.0.2.51\n", encoding="utf-8")
            args = _active_args()
            args.active_allowlist = str(allowlist)

            with patch(
                "asset_probe.cli.probe_opcua_server",
                new_callable=AsyncMock,
                return_value={"status": "ok"},
            ) as probe:
                active = await _run_active_probe(assets, args)

        probe.assert_awaited_once()
        self.assertEqual(probe.await_args.kwargs["ip"], "192.0.2.51")
        self.assertEqual([record["target_ip"] for record in active], ["192.0.2.51"])

    async def test_active_record_preserves_enrichment_fields_separately(self) -> None:
        assets = [
            {
                "mac": "02:42:ac:11:00:e2",
                "ips": ["192.0.2.40"],
                "protocol_metadata": {
                    "opcua": {
                        "detection": {
                            "detected": True,
                            "server_endpoints": [{"ip": "192.0.2.40", "port": 12001}],
                        }
                    }
                },
            }
        ]
        probe_result = {
            "status": "ok",
            "target": "opc.tcp://192.0.2.40:12001",
            "endpoints": [
                {
                    "endpoint_url": "opc.tcp://192.0.2.40:12001",
                    "application_name": "Demo Server",
                    "application_uri": "urn:demo:server",
                    "product_uri": "urn:demo:product",
                    "application_type": "Server",
                    "security_mode": "SignAndEncrypt",
                    "security_policy": "Basic256Sha256",
                    "transport_profile_uri": "opc.tcp",
                    "certificate": {"sha256": "abc123"},
                }
            ],
            "get_endpoints_status": "ok",
            "find_servers_status": "ok",
            "find_servers": [{"application_name": "Demo Server"}],
            "find_servers_on_network_status": "unavailable_or_restricted",
            "find_servers_on_network": [],
            "namespace_array": ["http://opcfoundation.org/UA/"],
            "build_info": {"manufacturer_name": "Example", "software_version": "1.2"},
            "server_status": {"state": "Running"},
            "errors": [],
            "warnings": ["FindServersOnNetwork unavailable"],
        }

        with patch(
            "asset_probe.cli.probe_opcua_server",
            new_callable=AsyncMock,
            return_value=probe_result,
        ):
            active = await _run_active_probe(assets, _active_args())

        record = active[0]
        self.assertEqual((record["target_ip"], record["target_port"]), ("192.0.2.40", 12001))
        self.assertEqual(record["application_name"], "Demo Server")
        self.assertEqual(record["security_mode"], "SignAndEncrypt")
        self.assertEqual(record["security_policy"], "Basic256Sha256")
        self.assertEqual(record["transport_profile"], "opc.tcp")
        self.assertEqual(record["server_certificates"], [{"sha256": "abc123"}])
        self.assertEqual(record["namespace_array"], probe_result["namespace_array"])
        self.assertEqual(record["build_info"], probe_result["build_info"])
        self.assertEqual(record["server_status"], probe_result["server_status"])
        self.assertEqual(record["find_servers"]["results"], probe_result["find_servers"])
        self.assertEqual(
            record["find_servers_on_network"]["status"],
            "unavailable_or_restricted",
        )
        self.assertEqual(record["provenance"], "active_observed")
        self.assertNotIn("active_probe", assets[0]["protocol_metadata"]["opcua"])



class ActiveProbeArgumentTests(TestCase):
    def _parse(self, *argv: str):
        with patch.object(sys, "argv", ["run_probe.py", *argv]):
            return parse_args()

    def test_active_probing_is_off_by_default(self) -> None:
        args = self._parse("--mode", "runtime")
        self.assertFalse(args.enable_active)
        self.assertFalse(args.active_opcua)

    def test_runtime_active_probing_requires_allowlist(self) -> None:
        with patch("sys.stderr"), self.assertRaises(SystemExit):
            self._parse("--mode", "runtime", "--enable-active", "--active-opcua")

    def test_active_opcua_requires_enable_active(self) -> None:
        with patch("sys.stderr"), self.assertRaises(SystemExit):
            self._parse("--mode", "offline", "--pcap", "x.pcap", "--active-opcua")

    def test_runtime_active_probing_with_allowlist_is_accepted(self) -> None:
        args = self._parse(
            "--mode", "runtime", "--enable-active", "--active-opcua", "--active-allowlist", "allow.txt"
        )
        self.assertTrue(args.enable_active)
        self.assertEqual(args.active_allowlist, "allow.txt")


if __name__ == "__main__":
    import unittest

    unittest.main()