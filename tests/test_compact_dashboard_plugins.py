from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = (ROOT / 'templates' / 'index.html').read_text()
CONNECTIONS = (ROOT / 'templates' / 'connections.html').read_text()
PLUGINS = (ROOT / 'templates' / 'plugins.html').read_text()
STYLES = (ROOT / 'static' / 'style.css').read_text()


def test_dashboard_and_connections_use_shared_compact_kpi_hooks():
    assert 'dashboard-shell compact-operations-shell' in DASHBOARD
    assert 'dashboard-metric-grid compact-kpi-grid' in DASHBOARD
    assert DASHBOARD.count('compact-kpi-heading') == 8
    assert 'dashboard-shell compact-operations-shell connections-shell' in CONNECTIONS
    assert 'dashboard-metric-grid compact-kpi-grid' in CONNECTIONS
    assert CONNECTIONS.count('compact-kpi-heading') == 6
    assert 'class="dashboard-panel connection-session-boundary" data-responsive-disclosure' in CONNECTIONS
    assert '<summary><h2 class="connection-session-heading h5 mb-0"><i class="bi bi-lock"' in CONNECTIONS
    assert 'This page does not infer identities' in CONNECTIONS


def test_plugin_strip_keeps_all_status_fields_and_safe_full_values():
    assert 'plugin-status-grid compact-kpi-grid compact-kpi-strip' in PLUGINS
    assert PLUGINS.count('compact-kpi-small') == 6
    for label in (
        'Bundled executable',
        'Configured source',
        'Restart state',
        'Ban projection publication',
        'Recent telemetry',
        'Ban records',
    ):
        assert label in PLUGINS
    assert 'title="{{ bundled_path }}"' in PLUGINS
    assert PLUGINS.count('compact-kpi-detail') == 6
    assert 'not proof of active enforcement' in PLUGINS
    assert 'The GUI cannot inspect the running process configuration.' in PLUGINS


def test_plugin_wot_disclosure_opens_for_active_modes_and_errors():
    open_condition = (
        "wot_policy.mode in ['monitor', 'enforce'] or wot_form.errors "
        'or wot_state.last_error'
    )
    assert f'class="plugin-wot-disclosure" data-responsive-disclosure{{% if {open_condition} %}} open' in PLUGINS
    assert 'Off, Monitor, and Enforce describe the published policy artifact.' in PLUGINS
    assert 'Confirmation is required whenever the resulting mode is Enforce.' in PLUGINS
    assert 'class="dashboard-panel plugin-panel">' in PLUGINS
    assert PLUGINS.index('Write-policy configuration') < PLUGINS.index('plugin-wot-disclosure')


def test_compact_kpi_density_is_desktop_only_with_mobile_safeguards():
    desktop_start = STYLES.index('@media (min-width: 992px)')
    mobile = STYLES[:desktop_start]
    desktop = STYLES[desktop_start:]

    assert '.compact-kpi-heading' in mobile
    assert '.compact-operations-shell .compact-kpi' in desktop
    assert 'min-height: 112px' in desktop
    assert '.plugins-shell .compact-kpi-small' in desktop
    assert 'min-height: 82px' in desktop
    assert '.plugins-shell .compact-kpi-strip' in desktop
    assert 'grid-template-columns: repeat(6, minmax(0, 1fr))' in desktop
    assert 'text-overflow: ellipsis' in desktop
    assert '@media (max-width: 991px)' in mobile
    assert '.connection-session-boundary > summary { min-height: 42px; }' in mobile
    assert '.dashboard-metric { min-height: 155px; }' in mobile
    assert '.dashboard-metric-grid { grid-template-columns: 1fr; }' in mobile
