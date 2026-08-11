import importlib
import sys

import pytest

from config import Config
from models import AuditLog, User, db
from utils.configuration import load_configuration
from utils.strfry import hex_to_npub


CONFIG = '''relay {
    info {
        name = "Route Relay"
        description = "Original description"
        pubkey = ""
        contact = "mailto:old@example.com"
    }
    bind = "127.0.0.1"
    port = 7777
}
'''


@pytest.fixture(scope='module', autouse=True)
def unload_route_app_after_module():
    yield
    sys.modules.pop('app', None)


@pytest.fixture
def route_app(monkeypatch, tmp_path):
    config_path = tmp_path / 'strfry.conf'
    config_path.write_text(CONFIG)
    runtime_dir = tmp_path / 'runtime'
    runtime_dir.mkdir()
    monkeypatch.setattr(Config, 'STRFRY_CONFIG', str(config_path))
    monkeypatch.setattr(Config, 'STRFRY_BINARY', '/bin/true')
    monkeypatch.setattr(Config, 'SQLALCHEMY_DATABASE_URI', f'sqlite:///{tmp_path / "routes.db"}')
    monkeypatch.setattr(Config, 'BANNED_PUBKEYS_FILE', str(runtime_dir / 'blocklist.json'))
    monkeypatch.setattr(Config, 'TRUST_POLICY_FILE', str(runtime_dir / 'trust_policy.json'))
    monkeypatch.setattr(Config, 'LEGACY_TRUST_POLICY_FILE', str(tmp_path / 'trust_policy.json'))
    monkeypatch.setattr(Config, 'TRUST_POLICY_STATS_FILE', str(runtime_dir / 'trust_stats.json'))
    monkeypatch.setattr(Config, 'WRITE_POLICY_EVENT_LOG', str(runtime_dir / 'events.jsonl'))

    app_module = importlib.import_module('app')
    flask_app = app_module.app
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    monkeypatch.setattr(app_module, 'dashboard_summary', lambda role: {})

    with flask_app.app_context():
        db.create_all()
        suffix = tmp_path.name
        users = {}
        for role in ('admin', 'moderator', 'viewer'):
            user = User(
                username=f'config-{role}-{suffix}',
                role=role,
                must_change_password=False,
            )
            user.set_password('not-used')
            db.session.add(user)
            users[role] = user
        db.session.commit()
        user_ids = {role: user.id for role, user in users.items()}

    yield app_module, flask_app, config_path, user_ids

    with flask_app.app_context():
        AuditLog.query.filter(AuditLog.user_id.in_(user_ids.values())).delete(
            synchronize_session=False
        )
        User.query.filter(User.id.in_(user_ids.values())).delete(synchronize_session=False)
        db.session.commit()


def client_for(flask_app, user_id=None):
    client = flask_app.test_client()
    if user_id is not None:
        with client.session_transaction() as session:
            session['_user_id'] = str(user_id)
            session['_fresh'] = True
    return client


def revision(config_path):
    return load_configuration(config_path).revision


def info_data(config_path, **overrides):
    data = {
        'config_revision': revision(config_path),
        'relay_name': 'Route Relay',
        'relay_description': 'Original description',
        'relay_pubkey': '',
        'relay_contact': 'mailto:old@example.com',
    }
    data.update(overrides)
    return data


def test_configuration_routes_require_admin_role(route_app):
    _module, flask_app, _path, users = route_app

    assert client_for(flask_app).get('/config').status_code == 302
    assert client_for(flask_app, users['viewer']).get('/config').status_code == 302
    assert client_for(flask_app, users['moderator']).post('/config/network').status_code == 302
    assert client_for(flask_app, users['admin']).get('/config').status_code == 200
    assert client_for(flask_app, users['admin']).post('/config').status_code == 405


def test_get_shows_separate_writable_forms_revision_and_collapsed_config(route_app):
    _module, flask_app, _path, users = route_app

    response = client_for(flask_app, users['admin']).get('/config')

    assert response.status_code == 200
    assert b'action="/config/relay-info"' in response.data
    assert b'action="/config/network"' in response.data
    assert b'name="config_revision"' in response.data
    assert b'Writable' in response.data
    assert b'<details' in response.data


def test_relay_info_normalizes_npub_clears_values_and_uses_prg(route_app):
    _module, flask_app, config_path, users = route_app
    pubkey = 'ab' * 32
    client = client_for(flask_app, users['admin'])

    response = client.post('/config/relay-info', data=info_data(
        config_path,
        relay_name='',
        relay_description='',
        relay_pubkey=hex_to_npub(pubkey),
        relay_contact='',
    ))

    assert response.status_code == 303
    assert response.headers['Location'].endswith('/config')
    values = load_configuration(config_path).values['relay']['info']
    assert values == {
        'name': '',
        'description': '',
        'pubkey': pubkey,
        'contact': '',
    }
    follow = client.get(response.headers['Location'])
    assert b'Configuration updated' in follow.data
    with flask_app.app_context():
        actions = [
            log.action
            for log in AuditLog.query.filter_by(user_id=users['admin']).order_by(AuditLog.id)
        ]
        assert actions[-2:] == ['config_update_requested', 'config_update_completed']


@pytest.mark.parametrize(
    'endpoint,data,error_value',
    [
        ('/config/relay-info', {'relay_name': 'x' * 101}, 'x' * 101),
        ('/config/relay-info', {'relay_contact': 'mail\nheader'}, 'mail\nheader'),
        ('/config/relay-info', {'relay_pubkey': 'not-a-pubkey'}, 'not-a-pubkey'),
        ('/config/relay-info', {'relay_pubkey': 'nPuB1mixedcase'}, 'nPuB1mixedcase'),
        ('/config/network', {'relay_bind': 'not-an-ip', 'relay_port': '7777'}, 'not-an-ip'),
        ('/config/network', {'relay_bind': '0.0.0.0', 'relay_port': '65536'}, '65536'),
    ],
)
def test_invalid_values_are_preserved_with_422(route_app, endpoint, data, error_value):
    _module, flask_app, config_path, users = route_app
    before = config_path.read_bytes()
    submitted = info_data(config_path, **data) if endpoint.endswith('relay-info') else {
        'config_revision': revision(config_path),
        **data,
    }

    response = client_for(flask_app, users['admin']).post(endpoint, data=submitted)

    assert response.status_code == 422
    assert error_value.encode() in response.data
    assert config_path.read_bytes() == before


def test_network_accepts_common_addresses_and_empty_bind(route_app):
    _module, flask_app, config_path, users = route_app
    client = client_for(flask_app, users['admin'])

    response = client.post('/config/network', data={
        'config_revision': revision(config_path),
        'relay_bind': '0.0.0.0',
        'relay_port': '65535',
    })
    assert response.status_code == 303
    response = client.post('/config/network', data={
        'config_revision': revision(config_path),
        'relay_bind': '',
        'relay_port': '1',
    })

    assert response.status_code == 303
    relay = load_configuration(config_path).values['relay']
    assert relay['bind'] == ''
    assert relay['port'] == 1


def test_stale_revision_returns_conflict_without_writing(route_app):
    _module, flask_app, config_path, users = route_app
    stale_revision = revision(config_path)
    config_path.write_text(CONFIG.replace('Route Relay', 'Changed elsewhere'))
    before = config_path.read_bytes()

    response = client_for(flask_app, users['admin']).post('/config/relay-info', data={
        **info_data(config_path, relay_name='Our value'),
        'config_revision': stale_revision,
    })

    assert response.status_code == 422
    assert b'Configuration changed' in response.data
    assert config_path.read_bytes() == before
    with flask_app.app_context():
        actions = [
            log.action
            for log in AuditLog.query.filter_by(user_id=users['admin']).order_by(AuditLog.id)
        ]
        assert actions[-2:] == ['config_update_requested', 'config_update_conflict']


def test_read_only_snapshot_disables_writes_without_exposing_diagnostics(route_app):
    _module, flask_app, config_path, users = route_app
    config_path.write_text('relay {\n    port = nope\n}\n')
    client = client_for(flask_app, users['admin'])

    page = client.get('/config')
    response = client.post('/config/network', data={
        'config_revision': revision(config_path),
        'relay_bind': '127.0.0.1',
        'relay_port': '7777',
    })

    assert page.status_code == 200
    assert b'Read-only' in page.data
    assert b'must be an integer' not in page.data
    assert response.status_code == 422
    assert b'could not be saved safely' in response.data


def test_audit_records_outcomes_and_field_names_without_values(route_app):
    _module, flask_app, config_path, users = route_app
    secret_value = 'raw-value-must-not-be-audited'

    response = client_for(flask_app, users['admin']).post('/config/relay-info', data=info_data(
        config_path,
        relay_name=secret_value,
        relay_pubkey='invalid',
    ))

    assert response.status_code == 422
    with flask_app.app_context():
        logs = AuditLog.query.filter_by(user_id=users['admin']).order_by(AuditLog.id).all()
        assert [log.action for log in logs[-2:]] == [
            'config_update_requested',
            'config_update_failed',
        ]
        assert all('relay.info.name' in log.details for log in logs[-2:])
        assert all(secret_value not in (log.details or '') for log in logs)
        assert all('invalid' not in (log.details or '') for log in logs)


def test_global_relay_name_is_nested_and_unavailable_config_does_not_break_page(route_app, monkeypatch):
    _module, flask_app, config_path, users = route_app
    client = client_for(flask_app, users['admin'])

    page = client.get('/config')
    assert b'Configuration - Route Relay - StrfryGUI' in page.data

    monkeypatch.setattr(Config, 'STRFRY_CONFIG', str(config_path.parent / 'missing.conf'))
    unavailable = client.get('/config')
    assert unavailable.status_code == 200
    assert b'Unavailable' in unavailable.data
    assert b'configuration unavailable:' not in unavailable.data
