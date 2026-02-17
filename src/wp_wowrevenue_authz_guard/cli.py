from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .scanner import scan_plugin_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wowrevenue-authz-guard",
        description="Scan a WordPress plugin directory for WowRevenue <= 2.1.3 authz risk patterns.",
    )
    parser.add_argument("plugin_dir", type=Path, help="Path to plugin source directory")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    result = scan_plugin_dir(args.plugin_dir)

    payload = {
        "high_risk": result.is_high_risk,
        "vulnerable_version": result.vulnerable_version,
        "found_install_activation_flow": result.found_install_activation_flow,
        "missing_admin_capability": result.missing_admin_capability,
        "reasons": result.reasons,
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        status = "HIGH RISK" if result.is_high_risk else "LOWER RISK"
        print(f"Scan result: {status}")
        for reason in result.reasons:
            print(f"- {reason}")

    return 2 if result.is_high_risk else 0


if __name__ == "__main__":
    sys.exit(main())

