# wp-wowrevenue-authz-guard

`wp-wowrevenue-authz-guard` is a small scanner that identifies the risk pattern behind **WowRevenue <= 2.1.3 missing authorization for authenticated users (Subscriber+) to trigger plugin installation/activation flows**.

## Why this exists

Before writing custom code, we checked maintained ecosystem options:

- Maintained vulnerability feeds/scanners exist (WPScan, WPVulnerability API, Wordfence intelligence), and they are recommended for broad monitoring.
- A focused maintained plugin/tool dedicated to this exact WowRevenue authz anti-pattern was not found.

Because of that gap, this project provides a targeted local scanner that teams can run in CI or release checks.

## What it checks

The scanner marks **high risk** when all are true:

1. Plugin version is `<= 2.1.3`.
2. AJAX handlers (`wp_ajax_*`) appear tied to plugin installation/activation APIs.
3. Strong capability checks (`install_plugins`, `activate_plugins`, or equivalent admin guard) are missing.

## Install and run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
wowrevenue-authz-guard /path/to/plugin
wowrevenue-authz-guard /path/to/plugin --json
```

Exit code `2` means high risk; exit code `0` means not high risk.

## Actionable migration guidance (deprecation workflow)

If your code still uses subscriber-reachable AJAX actions for privileged operations, treat that pattern as deprecated:

- Deprecated pattern:
  - `wp_ajax_*` handlers that can call install/activation functions without strict capability checks.
- Replacement:
  - Gate privileged handlers with `current_user_can('install_plugins')` or `current_user_can('activate_plugins')`.
  - Keep nonce validation, but do not rely on nonce as authorization.
  - Split low-privilege AJAX endpoints from admin-only endpoints.
- Migration:
  - Inventory all `wp_ajax_*` hooks.
  - Flag handlers that invoke `Plugin_Upgrader`, `activate_plugin`, `plugins_api`, or install helpers.
  - Add capability checks at function entry; return explicit forbidden responses when unauthorized.
  - Re-test flows with subscriber role to verify denial.

## Tests

```bash
pip install -e ".[dev]"
ruff check .
pytest -q
```

