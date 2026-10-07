# OPC UA Asset Discovery Research Prototype

## Purpose

Discover OPC UA endpoints from live NIC traffic using packet-level evidence, then enrich positively identified servers with controlled OPC UA queries.

## Architecture

Passive capture observes packets and records protocol evidence, endpoint roles, flows, and sessions. By default the tool is passive only and never connects to a target. Active enrichment is opt-in (`--enable-active --active-opcua`), is limited to endpoints identified as servers from positive OPC UA evidence, and in runtime mode additionally requires an `--active-allowlist`. Active results remain separate from passive observations.

Service hints come from the TypeId NodeId at the start of a UA-TCP MSG body (namespace 0 request encoding ids, e.g. 428 GetEndpoints, 631 Read). They are readable only on SecurityPolicy None channels.

## Installation

Use Python 3.10 or newer and install the pinned project dependencies in a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Dependencies

- Scapy for NIC capture and packet parsing
- asyncua for OPC UA client enrichment
- cryptography for optional certificate parsing

On Windows, live capture requires Npcap and sufficient capture permissions.

## Run

Start a live capture without supplying a target address:

```powershell
python run_probe.py --mode runtime --duration 60 --output inventory.json
```

Select an interface by its Scapy interface name:

```powershell
python run_probe.py --mode runtime --iface "Wi-Fi" --duration 60 --output inventory.json
```

To also enrich discovered servers, opt in and list the IPs you are authorized to query, one per line:

```powershell
python run_probe.py --mode runtime --iface "Wi-Fi" --duration 60 --enable-active --active-opcua --active-allowlist allowed_ips.txt --output inventory.json
```

Use `python run_probe.py --help` to see capture duration, packet limit, BPF filter, local network, and active-probe safety options. A restrictive BPF filter can hide OPC UA traffic on nonstandard ports.

For repeatable offline checks, analyze a capture or run the labeled fixture benchmark:

```powershell
python run_probe.py --mode offline --pcap release_pcaps\opcua_positive_nonstandard_port.pcap --output inventory.json
python run_probe.py --mode offline --benchmark-dir release_pcaps --benchmark-output benchmark.json
```

## View Results in a Browser

In VS Code, select **Live OPC UA Demo** from Run and Debug and press the play button. It performs a 120-second passive capture on `Wi-Fi` with no BPF or target filter, opens one OPC UA session to the configured controlled test endpoint during capture, enables active enrichment with an allowlist containing only that endpoint (`results/demo_active_allowlist.txt`), writes timestamped JSON and self-contained graphical HTML reports, updates `results/OPEN_LATEST_RESULT.html`, and opens the timestamped dashboard in the default browser when complete.

Select **Open Latest OPC UA Results** to open the stable latest dashboard directly in the default browser. The report HTML embeds its matching JSON, so browser viewing does not depend on opening the JSON separately or on `file://` fetch behavior.

The launch configurations are in `.vscode/launch.json`. The controlled demo endpoint is set in `run_live_demo.py`; passive discovery does not receive that endpoint as a target or filter.

## JSON Output

Runtime and offline inventory output has exactly four root sections: `runtime_summary`, `passive`, `active`, and `warnings`.

- `runtime_summary`: capture mode, interface/duration, packet counts, OPC UA statistics, and message-type counts.
- `passive`: endpoint-keyed assets, link-layer observations, flows, sessions, packet events, evidence, and provenance.
- `active`: endpoint descriptions and successfully retrieved application, certificate, namespace, BuildInfo, and server-status data with `active_observed` provenance.
- `warnings`: capture, decoding, encryption, and attribution limitations.

Passive endpoint identity uses observed IP, transport, and port. Ethernet MAC addresses are recorded as link-layer observations and may represent a gateway/next hop, not a remote server.

## Tests

```powershell
python -m unittest discover -s tests -p "test_*.py"
python validate_passive_opcua_services.py
python validate_ground_truth_opcua.py
```

## Limitations

- UA-TCP messages are reconstructed from sequence-contiguous TCP segments; missing segments or capture gaps can leave messages incomplete.
- Encrypted SecureChannel payloads can hide service and application metadata; the analyzer does not infer hidden services.
- A TCP port, including 4840, is not protocol proof. Positive UA-TCP framing or an OPC UA DNS-SD PTR announcement is required.
- Role inference uses HEL/ACK and recognized request-service direction; otherwise the role is unknown.
- Routed Ethernet MAC addresses identify observed local link peers and are not definitive remote-device MAC addresses.
- Active enrichment requires a positively discovered server endpoint and may be limited by network policy or server session limits.
