from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_junit(path: Path) -> dict:
    tree = ET.parse(path)
    suite = tree.getroot().find("testsuite")
    tests = int(suite.attrib.get("tests", "0"))
    failures = int(suite.attrib.get("failures", "0"))
    errors = int(suite.attrib.get("errors", "0"))
    return {"tests": tests, "failures": failures, "errors": errors,
            "status": "PASS" if failures == 0 and errors == 0 else "FAIL"}


if __name__ == "__main__":
    summary = parse_junit(Path("reports/junit/bluestrix-tests.xml"))
    print(json.dumps(summary, indent=2))
