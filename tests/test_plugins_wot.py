import importlib
import json
from datetime import timedelta

from config import Config
from models import ModerationReport, User, WoTBuildState, WoTPolicy, db, utcnow
from utils import moderation_reports
from utils.wot import DEFAULT_ROOT_NPUBS


def test_plugins_page_manages_and_publishes_wot_policy(monkeypatch, tmp_path):
    runtime_dir = tmp_path / 'runtime'
    runtime_dir.mkdir()
    strfry_config = tmp_path / 'strfry.conf'
    strfry_config.write_text(
        'relay {\n'
        '    writePolicy {\n'
        '        plugin = "/opt/strfrygui/utils/blocklist_plugin.py"\n'
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

    page = client.get('/plugins')
    response = client.post('/plugins/wot', data={
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
    assert response.status_code == 302
    with flask_app.app_context():
        policy = db.session.get(WoTPolicy, 1)
        assert (policy.mode, policy.trust_threshold, policy.pow_difficulty) == (
            'monitor',
            55,
            22,
        )
    with open(Config.TRUST_POLICY_FILE) as policy_file:
        published = json.load(policy_file)
    assert published['mode'] == 'monitor'
    assert published['trust_threshold'] == 55
    assert published['pow_difficulty'] == 22

    zero_response = client.post('/plugins/wot', data={
        'mode': 'off',
        'root_npubs': '\n'.join(DEFAULT_ROOT_NPUBS),
        'trust_threshold': '0',
        'pow_difficulty': '0',
        'refresh_interval_minutes': '45',
        'rate_limit_per_minute': '0',
        'rate_limit_burst': '0',
    })
    assert zero_response.status_code == 302
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

    disable_response = client.post('/plugins', data={
        'plugin_path': '',
        'timeout': '10',
        'lookback': '0',
    })
    assert disable_response.status_code == 200
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
    assert b'Actual reason' in policy_log_page.data
    assert b'Monitor reason' in policy_log_page.data
    assert b"document.hidden" in policy_log_page.data
    assert b"eventSearchLine('e', record.event_id, 'event_id', 'event_id')" in policy_log_page.data
    assert b"eventSearchLine('p', record.pubkey, 'pubkey', 'pubkey')" in policy_log_page.data
    assert b"link.textContent = value" in policy_log_page.data
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

    viewer_client = flask_app.test_client()
    with viewer_client.session_transaction() as session:
        session['_user_id'] = str(viewer_id)
        session['_fresh'] = True
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
