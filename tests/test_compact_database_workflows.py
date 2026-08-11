from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATABASE = (ROOT / 'templates' / 'db.html').read_text()
IMPORT_EXPORT = (ROOT / 'templates' / 'import_export.html').read_text()
CONFIGURATION = (ROOT / 'templates' / 'config.html').read_text()
STYLES = (ROOT / 'static' / 'style.css').read_text()
CONNECTIONS = (ROOT / 'templates' / 'connections.html').read_text()
EVENTS_DELETE = (ROOT / 'templates' / 'events_delete.html').read_text()


def test_database_disclosures_keep_inventory_visible_and_secondary_output_compact():
    assert 'class="workflow-disclosure" data-responsive-disclosure open' in DATABASE
    assert 'class="workflow-disclosure workflow-subdisclosure mt-3" data-responsive-disclosure{% if negentropy_add_form.errors %} open{% endif %}' in DATABASE
    assert 'class="workflow-disclosure dictionary-output-disclosure" data-responsive-disclosure' in DATABASE
    assert DATABASE.index('{% if dict_error %}') < DATABASE.index('dictionary-output-disclosure')
    assert 'dict_output is not none' in DATABASE


def test_compaction_summary_preserves_status_and_both_confirmations():
    assert 'class="dashboard-panel operations-danger-zone compaction-disclosure" data-responsive-disclosure' in DATABASE
    assert 'Relay must be stopped' in DATABASE
    assert 'Last outcome:' in DATABASE
    assert 'name="confirm_compact" value="yes" required' in DATABASE
    assert "confirm('Confirm the relay is stopped and start database compaction?')" in DATABASE


def test_import_export_opens_the_relevant_workflow_and_keeps_reference_disclosed():
    assert "export_active = request.method == 'POST' and 'export_submit' in request.form" in IMPORT_EXPORT
    assert "import_active = request.method == 'POST' and not export_active and 'import_submit' in request.form" in IMPORT_EXPORT
    assert 'data-responsive-disclosure{% if not import_active %} open{% endif %}' in IMPORT_EXPORT
    assert 'data-responsive-disclosure{% if import_active %} open{% endif %}' in IMPORT_EXPORT
    assert '<h2 class="workflow-summary-heading h5 mb-0" id="exportEventsTitle">' in IMPORT_EXPORT
    assert '<h2 class="workflow-summary-heading h5 mb-0" id="importEventsTitle">' in IMPORT_EXPORT
    assert 'JSONL format reference' in IMPORT_EXPORT
    assert IMPORT_EXPORT.count('rows="8"') == 2


def test_no_verify_warning_is_progressive_but_server_confirmation_remains():
    assert "import_form.no_verify.data == 'true'" in IMPORT_EXPORT
    assert "verificationControls.classList.toggle('is-no-verify', verificationSelect.value === 'true')" in IMPORT_EXPORT
    assert 'import_form.confirm_no_verify' in IMPORT_EXPORT
    assert 'No verification skips strfry' in IMPORT_EXPORT


def test_configuration_stays_open_and_compact_without_losing_guidance():
    assert CONFIGURATION.count('<form method="post"') == 2
    assert 'rows="3"' in CONFIGURATION
    assert 'A process restart may be required.' in CONFIGURATION
    assert 'The configuration is unavailable.' in CONFIGURATION


def test_workflow_density_is_desktop_only_and_mobile_controls_remain_comfortable():
    desktop_start = STYLES.index('@media (min-width: 992px)')
    mobile = STYLES[:desktop_start]
    desktop = STYLES[desktop_start:]

    assert '.workflow-disclosure > summary' in mobile
    assert '.verification-risk' in mobile
    assert '.compact-workflow-shell .dashboard-header' in desktop
    assert '.workflow-textarea' in desktop
    assert 'resize: vertical' in desktop
    assert '.workflow-panel-disclosure > summary' in mobile
    assert 'min-height: 42px' in mobile


def test_connections_and_danger_workflows_remain_visible_on_mobile():
    assert 'connection-session-boundary" data-responsive-disclosure' in CONNECTIONS
    assert '<h2 class="connection-session-heading h5 mb-0">' in CONNECTIONS
    assert 'Per-connection details are not exposed by strfry yet' in CONNECTIONS
    assert 'event-delete-shell compact-danger-shell' in EVENTS_DELETE
    assert 'confirm_delete' in EVENTS_DELETE
    assert 'This command acts directly on the relay database.' in EVENTS_DELETE
    assert '.compact-danger-shell .dashboard-panel' in STYLES[STYLES.index('@media (min-width: 992px)'):]
    assert '<details>\n            <summary class="dashboard-section-label">JSONL format reference</summary>' in IMPORT_EXPORT
