import importlib
import json
from datetime import timedelta

from config import Config
from models import User, WoTBuildState, WoTPolicy, db, utcnow
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
    monkeypatch.setattr(app_module, '_sync_reports_if_due', lambda: None)
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
