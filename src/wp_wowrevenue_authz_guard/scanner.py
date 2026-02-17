from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


@dataclass
class ScanResult:
    vulnerable_version: bool
    found_install_activation_flow: bool
    missing_admin_capability: bool
    reasons: list[str]

    @property
    def is_high_risk(self) -> bool:
        return (
            self.vulnerable_version
            and self.found_install_activation_flow
            and self.missing_admin_capability
        )


VULNERABLE_MAX_VERSION = (2, 1, 3)
PLUGIN_HEADER_VERSION_RE = re.compile(r"^\s*\*\s*Version:\s*([0-9.]+)\s*$", re.MULTILINE)
AJAX_HOOK_RE = re.compile(r"add_action\(\s*['\"]wp_ajax_([^'\"]+)['\"]")
INSTALLATION_FN_RE = re.compile(
    r"(Plugin_Upgrader|install_plugin_install_status|activate_plugin|plugins_api)\s*\(",
    re.IGNORECASE,
)


def _parse_version_tuple(version: str) -> tuple[int, ...]:
    parts = [int(p) for p in version.split(".") if p.isdigit()]
    return tuple(parts) if parts else (0,)


def _extract_plugin_version(plugin_main_php: str) -> tuple[int, ...]:
    match = PLUGIN_HEADER_VERSION_RE.search(plugin_main_php)
    if not match:
        return (0,)
    return _parse_version_tuple(match.group(1))


def scan_plugin_dir(path: str | Path) -> ScanResult:
    plugin_dir = Path(path)
    php_files = sorted(plugin_dir.rglob("*.php"))
    if not php_files:
        return ScanResult(False, False, False, ["No PHP files found."])

    reasons: list[str] = []
    plugin_main_content = ""
    for file in php_files:
        text = file.read_text(encoding="utf-8", errors="ignore")
        if "Plugin Name:" in text and not plugin_main_content:
            plugin_main_content = text
            break

    version_tuple = _extract_plugin_version(plugin_main_content)
    vulnerable_version = version_tuple <= VULNERABLE_MAX_VERSION
    if vulnerable_version:
        reasons.append("Detected plugin version <= 2.1.3.")
    else:
        reasons.append("Plugin version appears above 2.1.3 or unavailable.")

    found_install_activation_flow = False
    missing_admin_capability = False

    for file in php_files:
        text = file.read_text(encoding="utf-8", errors="ignore")
        has_ajax = bool(AJAX_HOOK_RE.search(text))
        has_install_flow = bool(INSTALLATION_FN_RE.search(text))
        if has_ajax and has_install_flow:
            found_install_activation_flow = True
            reasons.append(
                f"Potential install/activation flow reachable from AJAX handler in {file.name}."
            )
            has_capability_guard = (
                "current_user_can('activate_plugins'" in text
                or 'current_user_can("activate_plugins"' in text
                or "current_user_can('install_plugins'" in text
                or 'current_user_can("install_plugins"' in text
                or "manage_options" in text
            )
            if not has_capability_guard:
                missing_admin_capability = True
                reasons.append(
                    f"Missing strong capability checks in {file.name} for install/activation path."
                )

    if not found_install_activation_flow:
        reasons.append("No install/activation flow tied to AJAX handlers detected.")

    return ScanResult(
        vulnerable_version=vulnerable_version,
        found_install_activation_flow=found_install_activation_flow,
        missing_admin_capability=missing_admin_capability,
        reasons=reasons,
    )

