from pathlib import Path

from wp_wowrevenue_authz_guard.scanner import scan_plugin_dir


def _write_plugin(tmp_path: Path, version: str, body: str) -> Path:
    plugin_dir = tmp_path / "wowrevenue"
    plugin_dir.mkdir()
    php = plugin_dir / "wowrevenue.php"
    php.write_text(
        f"""<?php
/*
 * Plugin Name: WowRevenue
 * Version: {version}
 */
{body}
""",
        encoding="utf-8",
    )
    return plugin_dir


def test_detects_high_risk_path(tmp_path: Path) -> None:
    plugin = _write_plugin(
        tmp_path,
        "2.1.3",
        """
add_action('wp_ajax_wr_install_plugin', 'wr_install');
function wr_install() {
    $upgrader = new Plugin_Upgrader();
    activate_plugin('hello-dolly/hello.php');
}
""",
    )
    result = scan_plugin_dir(plugin)
    assert result.is_high_risk is True
    assert result.missing_admin_capability is True


def test_not_high_risk_when_capability_guard_present(tmp_path: Path) -> None:
    plugin = _write_plugin(
        tmp_path,
        "2.1.3",
        """
add_action('wp_ajax_wr_install_plugin', 'wr_install');
function wr_install() {
    if (!current_user_can('install_plugins')) {
        wp_die('forbidden');
    }
    $upgrader = new Plugin_Upgrader();
    activate_plugin('hello-dolly/hello.php');
}
""",
    )
    result = scan_plugin_dir(plugin)
    assert result.is_high_risk is False
    assert result.found_install_activation_flow is True

