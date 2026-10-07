from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from asyncua import Client

from generate_dashboard_report import generate_report


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
CAPTURE_INTERFACE = "Wi-Fi"
CAPTURE_DURATION_SECONDS = 120
CONTROLLED_TEST_ENDPOINT = "opc.tcp://78.47.71.152:4840"


def _start_controlled_session() -> None:
    async def connect_and_disconnect() -> None:
        client = Client(CONTROLLED_TEST_ENDPOINT, timeout=8)
        connected = False
        try:
            await client.connect()
            connected = True
            print(f"Controlled OPC UA session established: {CONTROLLED_TEST_ENDPOINT}", flush=True)
        except Exception as exc:
            print(f"Controlled OPC UA session failed: {type(exc).__name__}: {exc}", flush=True)
        finally:
            if connected:
                try:
                    await client.disconnect()
                    print("Controlled OPC UA session disconnected", flush=True)
                except Exception as exc:
                    print(f"OPC UA disconnect warning: {type(exc).__name__}: {exc}", flush=True)

    asyncio.run(connect_and_disconnect())


def _open_default_browser(path: Path) -> None:
    resolved_path = path.resolve()
    if os.name == "nt":
        os.startfile(str(resolved_path))
    else:
        webbrowser.open(resolved_path.as_uri())


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    report_stem = f"live_nic_{stamp}"
    json_report = RESULTS / f"{report_stem}.json"
    html_report = RESULTS / f"{report_stem}.html"
    latest_report = RESULTS / "OPEN_LATEST_RESULT.html"
    # Active enrichment is opt-in; allow only the controlled endpoint this demo connects to.
    allowlist = RESULTS / "demo_active_allowlist.txt"
    allowlist.write_text(f"{urlparse(CONTROLLED_TEST_ENDPOINT).hostname}\n", encoding="utf-8")

    command = [
        sys.executable,
        str(ROOT / "run_probe.py"),
        "--mode",
        "runtime",
        "--iface",
        CAPTURE_INTERFACE,
        "--duration",
        str(CAPTURE_DURATION_SECONDS),
        "--diagnostics",
        "--enable-active",
        "--active-opcua",
        "--active-allowlist",
        str(allowlist),
        "--output",
        str(json_report),
    ]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT) + os.pathsep + environment.get("PYTHONPATH", "")
    print("Starting passive OPC UA capture with no BPF filter or target input.", flush=True)
    print(f"Interface: {CAPTURE_INTERFACE}; duration: {CAPTURE_DURATION_SECONDS} seconds", flush=True)
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    capture_ready = threading.Event()
    output_finished = threading.Event()

    def forward_output() -> None:
        try:
            assert process.stdout is not None
            for line in process.stdout:
                print(line, end="", flush=True)
                if "Capture active on " in line:
                    capture_ready.set()
        finally:
            output_finished.set()

    output_thread = threading.Thread(target=forward_output, daemon=True)
    output_thread.start()
    while not capture_ready.wait(0.2) and not output_finished.is_set():
        if process.poll() is not None:
            break

    if capture_ready.is_set():
        _start_controlled_session()
    else:
        print("Capture did not report readiness; no client session was started.", flush=True)

    return_code = process.wait()
    output_thread.join()
    if return_code != 0:
        print(f"Live capture failed with exit code {return_code}; no report was opened.", flush=True)
        return return_code
    if not json_report.exists():
        print("Live capture completed without producing its JSON report.", flush=True)
        return 1

    generate_report(json_report, html_report, latest_report)
    _open_default_browser(html_report)
    print(f"Opened graphical report: {html_report}", flush=True)
    print(f"Latest report link: {latest_report}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
