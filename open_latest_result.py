from __future__ import annotations

import os
import sys
import webbrowser
from pathlib import Path


LATEST_REPORT = Path(__file__).resolve().parent / "results" / "OPEN_LATEST_RESULT.html"


def main() -> int:
    if not LATEST_REPORT.is_file():
        print(f"Latest report does not exist yet: {LATEST_REPORT}", file=sys.stderr)
        print("Run the Live OPC UA Demo launch configuration first.", file=sys.stderr)
        return 1

    report_path = LATEST_REPORT.resolve()
    if os.name == "nt":
        os.startfile(str(report_path))
    else:
        webbrowser.open(report_path.as_uri())
    print(f"Opened latest OPC UA results: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
