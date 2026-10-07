# OPC UA Asset Discovery

**Experimental research prototype**

An evidence-first prototype for identifying OPC UA communication from passive network traffic and optionally enriching positively discovered server endpoints through controlled active OPC UA requests.

## Repository Status

Experimental research prototype.

## Research Motivation

Operational technology (OT) asset inventories may be incomplete, and port-based identification can confuse services sharing a port or miss services on nonstandard ports. This project examines evidence-based OPC UA identification from observed traffic while retaining evidence provenance and separating passive analysis from any active enrichment.

## Research Problem

Given traffic visible to a selected capture interface, identify evidence of OPC UA communication, associate observations with candidate endpoints, and infer endpoint roles where protocol direction provides sufficient evidence. The prototype also explores how controlled active enrichment can be performed after passive discovery without turning the workflow into a target-first scan.

## Architecture

The architecture is passive-first. Active enrichment is optional and cannot establish an endpoint as a passive discovery; it is a separate follow-on observation for positively discovered server endpoints.

```text
NIC / Live Traffic
	-> Packet Acquisition
	-> L2-L4 Extraction
	-> OPC UA Protocol Identification
	-> Passive Endpoint Discovery
	-> Client/Server Role Inference
	-> Controlled Active Enrichment
	-> JSON Inventory
	-> Graphical Report
```

The inventory keeps the following concepts distinct:

- **Passive observation:** packet-derived facts, including protocol messages, addresses, ports, packet indices, and stream provenance.
- **Passive inference:** derived endpoint identity and client/server role, based on observed protocol evidence and direction. An inference is not itself a directly observed packet field.
- **Active observation:** results returned by an explicitly enabled OPC UA client request, stored separately from passive evidence and labeled with active provenance.
- **Detector confidence:** an evidence score associated with a detector result. It is not a probability of correctness and is not benchmark accuracy.
- **Benchmark metrics:** classification and operation-hint comparisons against labels for the included offline fixtures only; these do not measure detector confidence or establish live-network performance.

## Features

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

## Usage

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

**Security / Authorization:** Active enrichment must only be used against authorized endpoints. It can be explicitly enabled for positively discovered servers. In production or shared networks, use an allowlist containing only authorized IP addresses:

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

The benchmark compares predictions with the labels in `release_pcaps/ground_truth_labels.json`. Any classification accuracy, precision, recall, or F1 produced by the runner are fixture-benchmark metrics only; they are not live-network performance claims. Detector confidence remains a separate evidence score and is not accuracy.

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

## Testing

The current offline unit-test run completed **39 tests successfully**. The tests cover protocol evidence, packet parsing, reassembly, active-probe gating, and report generation.

Run the unit suite:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s .\tests -p "test_*.py"
```

## Benchmark

The included fixture set is defined by `release_pcaps/ground_truth_labels.json` and contains the repository's labeled positive and negative examples. The offline runner calculates classification metrics and operation-hint metrics against these labels. These are fixture-specific benchmark results; no broader dataset coverage or deployment performance is claimed here.

Run the offline fixture benchmark:

```powershell
.\.venv\Scripts\python.exe .\run_probe.py --mode offline --benchmark-dir .\release_pcaps --benchmark-output .\benchmark.json
```

## Experimental Validation

The repository's full validation script runs the unit suite, passive-service validation, a local active ground-truth OPC UA server check, and the offline fixture benchmark:

```powershell
.\run_final_validation.ps1
```

The current validation status reported here is the offline unit suite only: 39 tests passed. The full script was not rerun for this documentation update. Its active ground-truth check starts a local OPC UA server and should be run only in an environment where that activity is authorized and permitted.

## Reproducibility

From a fresh checkout, another researcher can:

1. Install the pinned dependencies in a virtual environment using the [installation](#installation) commands above.
2. Run offline analysis on the included labeled captures using the [offline fixture](#offline-fixtures) or [benchmark](#benchmark) commands.
3. Run the unit suite using the command in [Testing](#testing).
4. Run **Live OPC UA Demo** from VS Code in an authorized environment with the configured controlled endpoint reachable. This performs a 120-second capture and makes a client connection to that endpoint; it is not required for offline reproduction.

Capture results depend on interface selection, traffic visibility, permissions, and the test endpoint. Generated reports and inventories are local outputs and are not included as experimental fixtures.

## Limitations

- Live discovery depends on traffic visible on the selected interface during the capture window; no observed OPC UA traffic does not prove that no OPC UA service exists.
- TCP reassembly is sequence-aware per bidirectional IPv4 flow. Missing segments or capture gaps can leave a UA-TCP message incomplete; general TCP stream normalization is outside the prototype's scope.
- Encrypted SecureChannel payloads can hide service and application metadata. The analyzer does not infer hidden services.
- Port 4840 is not protocol proof. Positive UA-TCP framing or a valid OPC UA DNS-SD PTR announcement is required.
- Role inference uses HEL/ACK and recognized request-service direction; otherwise a role can remain unknown.
- On routed traffic, an observed Ethernet MAC may belong to a next-hop gateway rather than the remote IP endpoint.
- Active enrichment can be limited by server policy, connectivity, or session limits and must only be used against authorized endpoints.

This is a controlled experimental research prototype and does not claim universal autonomous OT asset discovery or complete network visibility.

## Research Positioning

This is an experimental research prototype for controlled validation of passive-first OPC UA identification and endpoint enrichment. Results are specific to the selected interface, observed traffic, implementation, and labeled fixtures. They should not be interpreted as universal autonomous OT asset discovery, a security audit, or a guarantee of network completeness.

## Citation

The associated paper is in preparation. No publication, DOI, funding, or affiliation information is asserted here. For software identification, cite the repository URL and the exact Git commit or release tag used:

```text
OPC UA Asset Discovery research prototype. https://github.com/Zmuzamil/opc-ua-asset-discovery
Specify the exact commit or release tag and access date when citing a particular version.
```

No `LICENSE` file is included because no reuse license has been selected. Public availability on GitHub does not by itself grant permission to reuse or redistribute the code.
