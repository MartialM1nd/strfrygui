import importlib
import json
from datetime import timedelta

from config import Config
from models import User, WoTBuildState, WoTPolicy, db, utcnow
from utils.wot import DEFAULT_ROOT_NPUBS


def test_plugins_page_manages_and_publishes_wot_policy(monkeypatch, tmp_path):
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
    monkeypatch.setattr(Config, 'BANNED_PUBKEYS_FILE', str(tmp_path / 'blocklist.json'))
    monkeypatch.setattr(Config, 'TRUST_POLICY_FILE', str(tmp_path / 'trust_policy.json'))
    monkeypatch.setattr(
        Config,
        'TRUST_POLICY_STATS_FILE',
        str(tmp_path / 'trust_policy_stats.json'),
    )

    app_module = importlib.import_module('app')
    monkeypatch.setattr(app_module, 'queue_wot_rebuild', lambda: False)
    flask_app = app_module.app
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    with flask_app.app_context():
        admin = User(username='wot-admin', role='admin', must_change_password=False)
        admin.set_password('not-used')
        db.session.add(admin)
        db.session.commit()
        admin_id = admin.id

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
