# OPC UA Asset Discovery

An experimental, evidence-first research prototype for identifying OPC UA communication in live network traffic and controlled packet captures. Passive packet evidence establishes candidate assets and endpoint roles; optional active OPC UA enrichment is kept separate and is available only after positive passive server-endpoint discovery.

The current experiment demonstrates controlled validation on selected interfaces, endpoints, and labeled packet-capture fixtures. It is not universal or autonomous network discovery and does not establish that a network is free of OPC UA when no traffic is observed.

## Research Motivation

Operational technology asset inventories are often incomplete, while port-based identification can confuse services that share ports or run on nonstandard ports. This prototype investigates a conservative alternative: use captured protocol framing and explicit service evidence for passive identification, retain where each observation came from, and only then allow controlled OPC UA requests to positively discovered servers.

## Pipeline

```text
NIC / live traffic
	-> packet acquisition
	-> L2-L4 extraction
	-> OPC UA protocol identification
	-> passive endpoint discovery
	-> client/server role inference
	-> controlled active enrichment (opt-in)
	-> JSON inventory and graphical HTML report
```

Active enrichment is disabled unless enabled with the CLI options. When enabled, targets are drawn from detected server endpoints in passive evidence, not from a target-first scan. The VS Code live demo supplies an allowlist for its configured controlled test endpoint.

## Implemented Features

- Live packet capture using Scapy, with selectable interface, duration, packet limit, optional BPF filter, and local CIDR context.
- IPv4, TCP, UDP, Ethernet, ARP, and DNS-SD packet-field extraction.
- Sequence-aware TCP payload reassembly per bidirectional IPv4 flow, including out-of-order segments, retransmissions, and declared-size UA-TCP message reconstruction.
- OPC UA identification from UA-TCP message framing or a valid OPC UA DNS-SD PTR marker. TCP port 4840 alone is recorded only as a candidate, not protocol proof.
- Passive endpoint identity based on observed IP, transport, and port; HEL/ACK and recognized request-service direction can inform client/server roles.
- Separate passive observations, inferred fields, and active enrichment results with packet and stream provenance.
- Optional active retrieval of endpoint descriptions and selected application/server metadata after positive passive server discovery.
- JSON inventory output, diagnostic counters, and a graphical, self-contained HTML dashboard generated from the matching JSON report.
- Labeled offline fixtures for OPC UA traffic, nonstandard-port traffic, and mixed non-OPC-UA traffic.

## Requirements

- Python 3.10 or newer
- Scapy 2.7.0
- asyncua 2.0.1
- cryptography 50.0.1
- On Windows, Npcap and appropriate capture permissions for live NIC capture

Pinned Python dependencies are listed in [`requirements.txt`](requirements.txt).

## Installation

From the project directory in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run

### VS Code Live Demo

Open **Run and Debug**, select **Live OPC UA Demo**, and press the play button. The existing launcher captures 120 seconds on the configured `Wi-Fi` interface without a BPF or passive target filter. During capture it makes one OPC UA client connection to the controlled endpoint configured in [`run_live_demo.py`](run_live_demo.py); the same configured host is used for the optional active allowlist. After capture it writes timestamped JSON and graphical HTML reports, updates `results/OPEN_LATEST_RESULT.html`, and opens the dashboard in the default browser.

The demo requires authorization and network reachability to its configured controlled test endpoint. It is a validation workflow, not a general-purpose scan.

Choose **Open Latest OPC UA Results** in Run and Debug to open the stable latest dashboard in the default browser. The HTML embeds its corresponding JSON so it can be viewed directly without manually opening JSON or relying on browser `file://` fetch behavior. Both configurations are in [`.vscode/launch.json`](.vscode/launch.json).

Generated reports and local capture outputs are ignored by Git and remain on the local machine.

### CLI Capture

Passive runtime capture without a supplied target:

```powershell
.\.venv\Scripts\python.exe .\run_probe.py --mode runtime --iface "Wi-Fi" --duration 60 --output .\inventory.json
```

Add `--diagnostics` to include interface resolution, BPF state, packet counts, detector invocation counts, and metadata-only TCP payload samples. A restrictive BPF filter can hide OPC UA traffic, especially when it runs on nonstandard ports.

Active enrichment can be explicitly enabled for positively discovered servers. In production or shared networks, use an allowlist containing only authorized IP addresses:

```powershell
.\.venv\Scripts\python.exe .\run_probe.py --mode runtime --iface "Wi-Fi" --duration 60 --enable-active --active-opcua --active-allowlist .\allowed_ips.txt --output .\inventory.json
```

For CLI options, run the project interpreter with `--help`:

```powershell
.\.venv\Scripts\python.exe .\run_probe.py --help
```

### Offline Fixtures

Analyze one included capture or run the labeled fixture benchmark:

```powershell
.\.venv\Scripts\python.exe .\run_probe.py --mode offline --pcap .\release_pcaps\opcua_positive_nonstandard_port.pcap --output .\inventory.json
.\.venv\Scripts\python.exe .\run_probe.py --mode offline --benchmark-dir .\release_pcaps --benchmark-output .\benchmark.json
```

The benchmark compares predictions with the labels in `release_pcaps/ground_truth_labels.json`. Its classification accuracy, precision, recall, and F1 are fixture-benchmark metrics only; they are not live-network performance claims. Detector confidence is a separate evidence score and is not accuracy.

## Output

Inventory JSON has four root sections:

- `runtime_summary`: capture mode, interface and duration, packet totals, OPC UA counts, and message-type counts.
- `passive`: endpoint-keyed assets, link-layer observations, flows, sessions, packet events, evidence, and provenance.
- `active`: separately recorded results from permitted OPC UA enrichment, with `active_observed` provenance.
- `warnings`: capture, decoding, encryption, and attribution limitations.

The HTML report presents the JSON as a graphical dashboard, including capture summary, passive assets, packet events, flows, active metadata, warnings, and the embedded raw source record.

## Project Structure

```text
asset_probe/             Capture analysis, models, protocol detection, OPC UA client probe
release_pcaps/           Labeled offline benchmark fixtures
tests/                   Unit tests for detection, parsing, reassembly, and probe gating
.vscode/launch.json       Browser and live-demo launch configurations
run_probe.py              CLI entry point
run_live_demo.py          Controlled live-capture and report workflow
generate_dashboard_report.py  Self-contained HTML report generator
open_latest_result.py     Opens the stable latest report in the default browser
run_final_validation.ps1  Unit, service, ground-truth, and offline fixture validations
requirements.txt          Pinned Python dependencies
opcua_asset_discovery_dashboard.html  Graphical dashboard template
```

The local `umati_active_probe_4840.pcapng` capture and generated `results/` files are excluded from Git because they may contain local or network-specific observations. The small labeled fixtures in `release_pcaps/` are the intentional offline test corpus.

## Experimental Validation

The repository includes unit tests for protocol evidence, packet parsing, reassembly, active-probe gating, and report generation. The release benchmark contains three labeled PCAP fixtures: two OPC UA captures, including nonstandard-port traffic, and one mixed-traffic negative fixture. The benchmark runner calculates classification metrics and operation-hint metrics against those labels. This small, selected fixture set supports repeatable regression checks; it does not establish general detection rates or broad deployment performance.

Run unit tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s .\tests -p "test_*.py"
```

Run the full existing validation script:

```powershell
.\run_final_validation.ps1
```

The full script includes active ground-truth validation against its configured test server, so run it only where that test is authorized and reachable. It also runs the offline release-PCAP benchmark.

## Limitations

- Live discovery depends on traffic visible on the selected interface during the capture window; no observed OPC UA traffic does not prove that no OPC UA service exists.
- TCP reassembly is sequence-aware per bidirectional IPv4 flow. Missing segments or capture gaps can leave a UA-TCP message incomplete; general TCP stream normalization is outside the prototype's scope.
- Encrypted SecureChannel payloads can hide service and application metadata. The analyzer does not infer hidden services.
- Port 4840 is not protocol proof. Positive UA-TCP framing or a valid OPC UA DNS-SD PTR announcement is required.
- Role inference uses HEL/ACK and recognized request-service direction; otherwise a role can remain unknown.
- On routed traffic, an observed Ethernet MAC may belong to a next-hop gateway rather than the remote IP endpoint.
- Active enrichment can be limited by server policy, connectivity, or session limits and must only be used against authorized endpoints.

## Research Positioning

This is an experimental research prototype for controlled validation of passive-first OPC UA identification and endpoint enrichment. Results are specific to the selected interface, observed traffic, implementation, and labeled fixtures. They should not be interpreted as universal autonomous OT asset discovery, a security audit, or a guarantee of network completeness.

## Citation

No associated paper, DOI, formal author metadata, or release identifier is currently included. For reproducibility, cite the repository URL and the exact Git commit or release tag used:

```text
OPC UA Asset Discovery research prototype. https://github.com/Zmuzamil/opc-ua-asset-discovery
Specify the exact commit or release tag and access date when citing a particular version.
```

No `LICENSE` file is included because no reuse license has been specified. Public availability on GitHub does not by itself grant permission to reuse or redistribute the code.
