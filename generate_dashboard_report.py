from __future__ import annotations

import base64
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DASHBOARD_TEMPLATE = ROOT / "opcua_asset_discovery_dashboard.html"
REPORT_MARKER = "__OPCUA_REPORT_BASE64__"


def generate_report(json_path: Path, html_path: Path, latest_path: Path) -> None:
    raw_json = json_path.read_bytes()
    template = DASHBOARD_TEMPLATE.read_text(encoding="utf-8")
    if REPORT_MARKER not in template:
        raise RuntimeError("Dashboard template is missing its embedded report marker")
    encoded_json = base64.b64encode(raw_json).decode("ascii")
    rendered = template.replace(REPORT_MARKER, encoded_json)

    html_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_latest = latest_path.with_suffix(latest_path.suffix + ".tmp")
    html_path.write_text(rendered, encoding="utf-8")
    shutil.copyfile(html_path, temporary_latest)
    temporary_latest.replace(latest_path)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate a self-contained OPC UA results dashboard")
    parser.add_argument("json_report", type=Path)
    parser.add_argument("html_report", type=Path)
    parser.add_argument(
        "--latest",
        type=Path,
        default=ROOT / "results" / "OPEN_LATEST_RESULT.html",
    )
    arguments = parser.parse_args()
    generate_report(arguments.json_report, arguments.html_report, arguments.latest)
    print(f"Wrote dashboard: {arguments.html_report}")
    print(f"Updated latest dashboard: {arguments.latest}")
