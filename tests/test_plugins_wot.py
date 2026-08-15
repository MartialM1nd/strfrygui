import importlib
import json
import time
from datetime import timedelta

from config import Config
from models import ModerationReport, User, WoTBuildState, WoTPolicy, db, utcnow
from utils import moderation_reports
from utils.configuration import load_configuration
from utils.wot import DEFAULT_ROOT_NPUBS, policy_fingerprint


def test_plugins_page_manages_and_publishes_wot_policy(monkeypatch, tmp_path):
    runtime_dir = tmp_path / 'runtime'
    runtime_dir.mkdir()
    bundled_plugin = tmp_path / 'blocklist_plugin.py'
    bundled_plugin.write_text('#!/bin/sh\nexit 0\n')
    bundled_plugin.chmod(0o755)
    strfry_config = tmp_path / 'strfry.conf'
    strfry_config.write_text(
        'relay {\n'
        '    writePolicy {\n'
        f'        plugin = "{bundled_plugin}"\n'
        '        timeoutSeconds = "10"\n'
        '        lookbackSeconds = "0"\n'
        '    }\n'
        '}\n'
    )
    monkeypatch.setattr(
        Config,
        'SQLALCHEMY_DATABASE_URI',
        f'sqlite:///{tmp_path / "routes.db"}',
    )
    monkeypatch.setattr(Config, 'STRFRY_BINARY', '/bin/true')
    monkeypatch.setattr(Config, 'STRFRY_CONFIG', str(strfry_config))
    monkeypatch.setattr(Config, 'BLOCKLIST_PLUGIN_PATH', str(bundled_plugin))
    monkeypatch.setattr(Config, 'BANNED_PUBKEYS_FILE', str(runtime_dir / 'blocklist.json'))
    monkeypatch.setattr(Config, 'TRUST_POLICY_FILE', str(runtime_dir / 'trust_policy.json'))
    monkeypatch.setattr(Config, 'LEGACY_TRUST_POLICY_FILE', str(tmp_path / 'trust_policy.json'))
    monkeypatch.setattr(
        Config,
        'TRUST_POLICY_STATS_FILE',
        str(runtime_dir / 'trust_policy_stats.json'),
    )
    decision_log_path = runtime_dir / 'write_policy_events.jsonl'
    monkeypatch.setattr(
        Config,
        'WRITE_POLICY_EVENT_LOG',
        str(decision_log_path),
    )

    app_module = importlib.import_module('app')
    assert app_module._bundled_plugin_available() is True
    bundled_plugin.chmod(0o775)
    assert app_module._bundled_plugin_available() is False
    bundled_plugin.chmod(0o755)
    plugin_symlink = tmp_path / 'plugin-symlink'
    plugin_symlink.symlink_to(bundled_plugin)
    monkeypatch.setattr(Config, 'BLOCKLIST_PLUGIN_PATH', str(plugin_symlink))
    assert app_module._bundled_plugin_available() is False
    monkeypatch.setattr(Config, 'BLOCKLIST_PLUGIN_PATH', str(bundled_plugin))
    monkeypatch.setattr(app_module, 'queue_wot_rebuild', lambda: False)
    monkeypatch.setattr(app_module, '_collect_dashboard_sample', lambda: None)
    monkeypatch.setattr(app_module, 'sync_moderation_reports', lambda: None)
    flask_app = app_module.app
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    with flask_app.app_context():
        admin = User(username='wot-admin', role='admin', must_change_password=False)
        admin.set_password('not-used')
        moderator = User(
            username='wot-moderator',
            role='moderator',
            must_change_password=False,
        )
        moderator.set_password('not-used')
        viewer = User(username='wot-viewer', role='viewer', must_change_password=False)
        viewer.set_password('not-used')
        db.session.add_all([admin, moderator, viewer])
        db.session.commit()
        admin_id = admin.id
        moderator_id = moderator.id
        viewer_id = viewer.id

    client = flask_app.test_client()
    with client.session_transaction() as session:
        session['_user_id'] = str(admin_id)
        session['_fresh'] = True
        session['_nostr_auth_version'] = 1

    (runtime_dir / 'trust_policy_stats.json').write_text(json.dumps({
        'updated_at': int(time.time()),
        'counters': {'accepted_monitor': 4},
    }))
    page = client.get('/plugins')
    assert b'class="dashboard-shell plugins-shell"' in page.data
    assert b'<details class="plugin-wot-disclosure" data-responsive-disclosure>' in page.data
    assert b'Bundled executable' in page.data
    assert b'Configured source' in page.data
    assert b'Ban projection publication' in page.data
    assert b'Recent telemetry' in page.data
    assert b'not proof of active enforcement' in page.data
    assert b'action="/plugins/write-policy"' in page.data
    with flask_app.app_context():
        policy_revision = policy_fingerprint(db.session.get(WoTPolicy, 1))
    response = client.post('/plugins/wot', data={
        'policy_revision': policy_revision,
        'mode': 'monitor',
        'root_npubs': '\n'.join(DEFAULT_ROOT_NPUBS),
        'trust_threshold': '55',
        'pow_difficulty': '22',
        'require_pow_commitment': 'y',
        'refresh_interval_minutes': '45',
        'rate_limit_per_minute': '20',
        'rate_limit_burst': '8',
    })

    assert page.status_code == 200
    assert b'Web of Trust and Proof of Work' in page.data
    assert response.status_code == 303
    with flask_app.app_context():
        policy = db.session.get(WoTPolicy, 1)
        assert (policy.mode, policy.trust_threshold, policy.pow_difficulty) == (
            'monitor',
            55,
            22,
        )
        policy_revision = policy_fingerprint(policy)
    with open(Config.TRUST_POLICY_FILE) as policy_file:
        published = json.load(policy_file)
    assert published['mode'] == 'monitor'
    assert published['trust_threshold'] == 55
    assert published['pow_difficulty'] == 22

    unconfirmed_enforce = client.post('/plugins/wot', data={
        'policy_revision': policy_revision,
        'mode': 'enforce',
        'root_npubs': '\n'.join(DEFAULT_ROOT_NPUBS),
        'trust_threshold': '55',
        'pow_difficulty': '22',
        'refresh_interval_minutes': '45',
        'rate_limit_per_minute': '20',
        'rate_limit_burst': '8',
    })
    assert unconfirmed_enforce.status_code == 422
    assert b'<details class="plugin-wot-disclosure" data-responsive-disclosure open>' in unconfirmed_enforce.data
    assert b'Confirm Enforce mode' in unconfirmed_enforce.data
    assert b'<option selected value="enforce">' in unconfirmed_enforce.data
    with flask_app.app_context():
        policy = db.session.get(WoTPolicy, 1)
        assert policy.mode == 'monitor'
        policy.pow_difficulty = 23
        db.session.commit()

    stale_wot = client.post('/plugins/wot', data={
        'policy_revision': policy_revision,
        'mode': 'monitor',
        'root_npubs': '\n'.join(DEFAULT_ROOT_NPUBS),
        'trust_threshold': '55',
        'pow_difficulty': '22',
        'refresh_interval_minutes': '45',
        'rate_limit_per_minute': '20',
        'rate_limit_burst': '8',
    })
    assert stale_wot.status_code == 422
    assert b'Policy changed. Reload before saving.' in stale_wot.data
    with flask_app.app_context():
        policy_revision = policy_fingerprint(db.session.get(WoTPolicy, 1))

    zero_response = client.post('/plugins/wot', data={
        'policy_revision': policy_revision,
        'mode': 'off',
        'root_npubs': '\n'.join(DEFAULT_ROOT_NPUBS),
        'trust_threshold': '0',
        'pow_difficulty': '0',
        'refresh_interval_minutes': '45',
        'rate_limit_per_minute': '0',
        'rate_limit_burst': '0',
    })
    assert zero_response.status_code == 303
    with flask_app.app_context():
        policy = db.session.get(WoTPolicy, 1)
        assert (
            policy.trust_threshold,
            policy.pow_difficulty,
            policy.rate_limit_per_minute,
            policy.rate_limit_burst,
        ) == (0, 0, 0, 0)

        policy.mode = 'monitor'
        policy.refresh_interval_minutes = 30
        state = db.session.get(WoTBuildState, 1)
        state.status = 'idle'
        state.generated_at = utcnow()
        assert app_module._wot_refresh_due(policy, state) is False
        state.generated_at = utcnow() - timedelta(minutes=31)
        assert app_module._wot_refresh_due(policy, state) is True

    assert client.post('/plugins', data={}).status_code == 405
    config_revision = load_configuration(strfry_config).revision
    invalid_path = client.post('/plugins/write-policy', data={
        'config_revision': config_revision,
        'plugin_path': 'relative-plugin',
        'timeout': '10',
        'lookback': '0',
    })
    assert invalid_path.status_code == 422
    assert b'Select the bundled write-policy plugin or disable it' in invalid_path.data
    invalid_timeout = client.post('/plugins/write-policy', data={
        'config_revision': config_revision,
        'plugin_path': str(bundled_plugin),
        'timeout': '61',
        'lookback': '0',
    })
    assert invalid_timeout.status_code == 422
    assert b'Number must be between 1 and 60' in invalid_timeout.data

    custom_plugin = tmp_path / 'custom-policy'
    custom_plugin.write_text('#!/bin/sh\nexit 0\n')
    custom_plugin.chmod(0o755)
    rejected_custom_path = client.post('/plugins/write-policy', data={
        'config_revision': config_revision,
        'plugin_path': str(custom_plugin),
        'timeout': '10',
        'lookback': '0',
        'confirm_plugin_change': 'y',
    })
    assert rejected_custom_path.status_code == 422
    assert load_configuration(strfry_config).values['relay']['writePolicy']['plugin'] == str(bundled_plugin)

    strfry_config.write_text(
        strfry_config.read_text().replace(str(bundled_plugin), str(custom_plugin))
    )
    unsupported_page = client.get('/plugins')
    assert b'Unsupported' in unsupported_page.data
    assert str(custom_plugin).encode() in unsupported_page.data
    migrated_path = client.post('/plugins/write-policy', data={
        'config_revision': load_configuration(strfry_config).revision,
        'plugin_path': str(bundled_plugin),
        'timeout': '10',
        'lookback': '0',
        'confirm_plugin_change': 'y',
    })
    assert migrated_path.status_code == 303
    assert load_configuration(strfry_config).values['relay']['writePolicy']['plugin'] == str(bundled_plugin)

    timeout_only = client.post('/plugins/write-policy', data={
        'config_revision': load_configuration(strfry_config).revision,
        'plugin_path': str(bundled_plugin),
        'timeout': '11',
        'lookback': '0',
    })
    assert timeout_only.status_code == 303
    assert load_configuration(strfry_config).values['relay']['writePolicy']['timeoutSeconds'] == 11

    stale_config_revision = load_configuration(strfry_config).revision
    strfry_config.write_text(strfry_config.read_text() + '# external update\n')
    externally_updated = strfry_config.read_bytes()
    stale_config = client.post('/plugins/write-policy', data={
        'config_revision': stale_config_revision,
        'plugin_path': str(bundled_plugin),
        'timeout': '12',
        'lookback': '0',
    })
    assert stale_config.status_code == 422
    assert b'Configuration changed. Reload before saving.' in stale_config.data
    assert strfry_config.read_bytes() == externally_updated

    disable_response = client.post('/plugins/write-policy', data={
        'config_revision': load_configuration(strfry_config).revision,
        'plugin_path': '',
        'timeout': '10',
        'lookback': '0',
        'confirm_plugin_change': 'y',
    })
    assert disable_response.status_code == 303
    assert 'plugin = ""' in strfry_config.read_text()

    decision_log_path.write_text(json.dumps({
        'timestamp_ms': 1_700_000_000_000,
        'action': 'reject',
        'reason': 'banned',
        'event_id': 'event-id',
        'pubkey': 'pubkey',
        'kind': 1,
        'source_ip': '192.0.2.1',
        'source_type': 'IP4',
        'policy_mode': 'enforce',
    }) + '\n')

    policy_log_page = client.get('/policy-log')
    assert policy_log_page.status_code == 200
    assert b'id="eventIdFilter"' in policy_log_page.data
    assert b'id="pubkeyFilter"' in policy_log_page.data
    assert b'/static/policy_log.js' in policy_log_page.data
    assert b'<table' not in policy_log_page.data
    policy_log_script = client.get('/static/policy_log.js')
    assert b'Actual reason' in policy_log_script.data
    assert b'Monitor reason' in policy_log_script.data
    api_response = client.get('/api/write-policy-events?limit=99999')
    assert api_response.status_code == 200
    assert api_response.headers['Cache-Control'] == 'no-store, max-age=0'
    assert api_response.get_json()['events'][0]['source_ip'] == '192.0.2.1'

    dashboard_page = client.get('/')
    dashboard_api = client.get('/api/dashboard')
    assert dashboard_page.status_code == 200
    assert b'RELAY CONTROL' in dashboard_page.data
    assert b'aria-current="page"' in dashboard_page.data
    assert b'aria-label="Toggle color theme"' in dashboard_page.data
    assert b'href="#mainContent"' in dashboard_page.data
    assert b'Admission outcomes' in dashboard_page.data
    assert dashboard_api.status_code == 200
    assert 'moderation' in dashboard_api.get_json()
    connections_page = client.get('/connections')
    connections_api = client.get('/api/connections')
    assert connections_page.status_code == 200
    assert b'Connection Operations' in connections_page.data
    assert connections_api.status_code == 200
    assert connections_api.headers['Cache-Control'] == 'no-store, max-age=0'
    assert 'current' in connections_api.get_json()
    assert 'sessions' not in connections_api.get_json()

    moderator_client = flask_app.test_client()
    with moderator_client.session_transaction() as session:
        session['_user_id'] = str(moderator_id)
        session['_fresh'] = True
        session['_nostr_auth_version'] = 1

    def fail_request_sync(*args, **kwargs):
        raise AssertionError('moderation page must not synchronize reports')

    monkeypatch.setattr(app_module, 'sync_moderation_reports', fail_request_sync)
    monkeypatch.setattr(app_module, 'scan_events', fail_request_sync)
    monkeypatch.setattr(moderation_reports, 'scan_events', fail_request_sync)
    with flask_app.app_context():
        open_report = ModerationReport(
            event_id='ux-open-report',
            reporter_pubkey='reporter',
            reported_pubkey='reported',
            report_type='spam',
            content='Repeated promotional posts',
            created_at=utcnow(),
        )
        reviewed_report = ModerationReport(
            event_id='ux-reviewed-report',
            report_type='other',
            reviewed=True,
            created_at=utcnow() - timedelta(days=2),
        )
        db.session.add_all([open_report, reviewed_report])
        db.session.commit()
        open_report_id = open_report.id

    flask_app.config['WTF_CSRF_ENABLED'] = True
    moderation_page = moderator_client.get('/moderation')
    assert moderation_page.status_code == 200
    assert moderation_page.data.index(b'Report queue') < moderation_page.data.index(b'Event purge operations')
    assert moderation_page.data.index(b'Event purge operations') < moderation_page.data.index(b'Domain ban operations')
    assert b'id="openReportCount">1<' in moderation_page.data
    assert b'id="newReportCount">1<' in moderation_page.data
    assert b'Load more reports' in moderation_page.data
    assert b'innerHTML' not in moderation_page.data
    assert b'location.reload' not in moderation_page.data
    assert client.post('/api/metadata-relays', json={'url': 'wss://relay.example'}).status_code == 400
    flask_app.config['WTF_CSRF_ENABLED'] = False
    assert moderator_client.get('/api/moderation-reports?offset=nope&limit=9999').status_code == 200

    with flask_app.app_context():
        cursor_reports = [
            ModerationReport(
                event_id=f'cursor-report-{index}',
                report_type='spam',
                created_at=utcnow() + timedelta(minutes=index),
            )
            for index in range(4)
        ]
        db.session.add_all(cursor_reports)
        db.session.commit()
        ordered_cursor_ids = [report.id for report in reversed(cursor_reports)]
    first_page = moderator_client.get('/api/moderation-reports?limit=2').get_json()
    assert [report['id'] for report in first_page['reports']] == ordered_cursor_ids[:2]
    with flask_app.app_context():
        db.session.get(ModerationReport, ordered_cursor_ids[0]).reviewed = True
        db.session.commit()
    second_page = moderator_client.get('/api/moderation-reports', query_string={
        'limit': 2,
        'cursor_created_at': first_page['next_cursor']['created_at'],
        'cursor_id': first_page['next_cursor']['id'],
    }).get_json()
    assert second_page['reports'][0]['id'] == ordered_cursor_ids[2]

    with flask_app.app_context():
        duplicate_time = utcnow() + timedelta(hours=1)
        nullable_reports = [
            ModerationReport(
                event_id=f'nullable-report-{index}',
                reporter_pubkey='nullable-page',
                report_type='spam',
                created_at=duplicate_time,
            )
            for index in range(4)
        ]
        db.session.add_all(nullable_reports)
        db.session.commit()
        nullable_reports[0].created_at = None
        nullable_reports[1].created_at = None
        db.session.commit()
        expected_nullable_ids = [
            nullable_reports[3].id,
            nullable_reports[2].id,
            nullable_reports[1].id,
            nullable_reports[0].id,
        ]
    paged_ids = []
    cursor = None
    while True:
        query = {'limit': 1, 'reporter': 'nullable-page'}
        if cursor:
            query['cursor_id'] = cursor['id']
            if cursor['created_at']:
                query['cursor_created_at'] = cursor['created_at']
            else:
                query['cursor_null'] = '1'
        page = moderator_client.get('/api/moderation-reports', query_string=query).get_json()
        paged_ids.extend(report['id'] for report in page['reports'])
        cursor = page['next_cursor']
        if not cursor:
            break
    assert paged_ids == expected_nullable_ids

    ascending_ids = []
    cursor = None
    while True:
        query = {'limit': 1, 'reporter': 'nullable-page', 'sort': 'asc'}
        if cursor:
            query['cursor_id'] = cursor['id']
            if cursor['created_at']:
                query['cursor_created_at'] = cursor['created_at']
            else:
                query['cursor_null'] = '1'
        page = moderator_client.get('/api/moderation-reports', query_string=query).get_json()
        ascending_ids.extend(report['id'] for report in page['reports'])
        cursor = page['next_cursor']
        if not cursor:
            break
    assert ascending_ids == list(reversed(expected_nullable_ids))

    preserved = moderator_client.post(
        f'/moderation/report/{open_report_id}/review',
        data={'next': '/moderation?report_type=spam'},
    )
    assert preserved.headers['Location'].endswith('/moderation?report_type=spam')
    rejected = moderator_client.post(
        f'/moderation/report/{open_report_id}/review',
        data={'next': 'https://example.com/'},
    )
    assert rejected.headers['Location'].endswith('/moderation')
    assert moderator_client.get('/policy-log').status_code == 200
    assert moderator_client.get('/api/write-policy-events').status_code == 200

    imported = []
    monkeypatch.setattr(
        app_module,
        'import_events',
        lambda data, verify=True: imported.append((data, verify)),
    )
    unconfirmed_import = client.post('/import_export', data={
        'import_submit': '1',
        'file': '{"id":"event"}',
        'no_verify': 'true',
    })
    assert unconfirmed_import.status_code == 200
    assert b'class="dashboard-panel workflow-panel-disclosure mb-4" data-responsive-disclosure>' in unconfirmed_import.data
    assert unconfirmed_import.data.count(b'class="dashboard-panel workflow-panel-disclosure mb-4" data-responsive-disclosure open>') == 1
    assert unconfirmed_import.data.index(b'id="importEventsTitle"') > unconfirmed_import.data.index(b'data-responsive-disclosure open>')
    assert b'Confirm that you understand the risk' in unconfirmed_import.data
    assert imported == []

    confirmed_import = client.post('/import_export', data={
        'import_submit': '1',
        'file': '{"id":"event"}',
        'no_verify': 'true',
        'confirm_no_verify': 'y',
    })
    assert confirmed_import.status_code == 200
    assert confirmed_import.headers['Cache-Control'] == 'no-store'
    assert imported == [('{"id":"event"}', False)]

    initial_import_export = client.get('/import_export')
    monkeypatch.setattr(app_module, 'export_events', lambda **_kwargs: '{}\n')
    successful_export = client.post('/import_export', data={'export_submit': '1'})
    invalid_export = client.post('/import_export', data={
        'export_submit': '1',
        'since': 'not-a-timestamp',
    })
    for response in (initial_import_export, successful_export, invalid_export):
        assert response.data.count(b'class="dashboard-panel workflow-panel-disclosure mb-4" data-responsive-disclosure open>') == 1
        assert response.data.index(b'data-responsive-disclosure open>') < response.data.index(b'id="exportEventsTitle"')

    assert client.post('/db', data={
        'negentropy_build': '1',
        'tree_id': '../unsafe',
    }).status_code == 400
    assert client.post('/db', data={
        'negentropy_delete': '1',
        'tree_id': 'safe-tree',
    }).status_code == 400
    assert client.post('/db', data={
        'refresh_negentropy': '1',
        'refresh_dict': '1',
    }).status_code == 400

    monkeypatch.setattr(
        app_module,
        'get_strfry_process_info',
        lambda: {'process_count': 1, 'uptime_seconds': 30},
    )
    compaction_blocked = client.post('/db', data={
        'compact': '1',
        'confirm_compact': 'yes',
    }, follow_redirects=True)
    assert b'Stop all strfry processes before compacting' in compaction_blocked.data

    viewer_client = flask_app.test_client()
    with viewer_client.session_transaction() as session:
        session['_user_id'] = str(viewer_id)
        session['_fresh'] = True
        session['_nostr_auth_version'] = 1
    assert viewer_client.get('/policy-log').status_code == 302
    assert viewer_client.get('/api/write-policy-events').status_code == 302
    viewer_dashboard = viewer_client.get('/api/dashboard')
    assert viewer_dashboard.status_code == 200
    assert 'moderation' not in viewer_dashboard.get_json()
    assert viewer_client.get('/connections').status_code == 200
    assert viewer_client.get('/api/connections').status_code == 200
    assert viewer_client.post('/events', data={
        'delete_selected': '1',
        'selected_events': 'event-id',
    }).status_code == 403

    monkeypatch.setattr(app_module, 'scan_events', lambda *args, **kwargs: [{
        'id': 'a' * 64,
        'pubkey': 'b' * 64,
        'created_at': 1_700_000_000,
        'kind': 1,
        'tags': [],
        'content': '<script>alert("event-xss")</script>',
        'sig': 'c' * 128,
    }])
    event_page = moderator_client.post('/events', data={
        'search': '1',
        'search_type': 'all',
        'limit': '25',
    })
    assert event_page.status_code == 200
    assert b'Event explorer' in event_page.data
    assert b'&lt;script&gt;alert' in event_page.data
    assert b'<script>alert("event-xss")</script>' not in event_page.data
    assert moderator_client.post('/events', data={
        'delete_selected': '1',
        'event_ids': 'a',
    }).status_code == 400

    empty_delete = moderator_client.post('/events/delete', data={
        'filter_json': '{}',
        'confirm_delete': 'DELETE',
    })
    assert empty_delete.status_code == 200
    assert b'Empty filters are not allowed' in empty_delete.data
