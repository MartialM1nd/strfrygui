import importlib
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError

from config import Config
from models import (
    AuditLog,
    BannedDomain,
    BannedPubkey,
    MetadataRelay,
    PubkeyBanSource,
    User,
    db,
)
from utils.relay import RelayError


PASSWORD = 'StrongPassword123456!'
PUBKEYS = {
    'admin': '1' * 64,
    'moderator': '2' * 64,
    'viewer': '3' * 64,
    'inactive': '4' * 64,
}
CONFIG = '''relay {
    info {
        name = "Admin Test Relay"
    }
    bind = "127.0.0.1"
    port = 7777
}
'''


@pytest.fixture(scope='module')
def admin_app(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp('admin-routes')
    runtime_dir = tmp_path / 'runtime'
    runtime_dir.mkdir()
    config_path = tmp_path / 'strfry.conf'
    config_path.write_text(CONFIG)
    settings = {
        'STRFRY_CONFIG': str(config_path),
        'STRFRY_BINARY': '/bin/true',
        'SQLALCHEMY_DATABASE_URI': f'sqlite:///{tmp_path / "admin.db"}',
        'BANNED_PUBKEYS_FILE': str(runtime_dir / 'blocklist.json'),
        'TRUST_POLICY_FILE': str(runtime_dir / 'trust_policy.json'),
        'LEGACY_TRUST_POLICY_FILE': str(tmp_path / 'trust_policy.json'),
        'TRUST_POLICY_STATS_FILE': str(runtime_dir / 'trust_stats.json'),
        'WRITE_POLICY_EVENT_LOG': str(runtime_dir / 'events.jsonl'),
    }
    old_settings = {name: getattr(Config, name) for name in settings}
    for name, value in settings.items():
        setattr(Config, name, value)

    app_module = importlib.import_module('app')
    flask_app = app_module.app
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
        admin = _make_user('admin-test', 'admin', pubkey=PUBKEYS['admin'])
        moderator = _make_user('moderator-test', 'moderator', pubkey=PUBKEYS['moderator'])
        viewer = _make_user('viewer-test', 'viewer', pubkey=PUBKEYS['viewer'])
        inactive = _make_user('inactive-test', 'admin', is_active=False, pubkey=PUBKEYS['inactive'])
        db.session.commit()
        user_ids = {
            'admin': admin.id,
            'moderator': moderator.id,
            'viewer': viewer.id,
            'inactive': inactive.id,
        }

    yield app_module, flask_app, user_ids

    with flask_app.app_context():
        db.session.remove()
        db.drop_all()
    for name, value in old_settings.items():
        setattr(Config, name, value)
    sys.modules.pop('app', None)


@pytest.fixture(autouse=True)
def clean_admin_data(admin_app):
    _module, flask_app, user_ids = admin_app
    with flask_app.app_context():
        AuditLog.query.delete()
        PubkeyBanSource.query.delete()
        BannedPubkey.query.delete()
        BannedDomain.query.delete()
        MetadataRelay.query.delete()
        User.query.filter(~User.id.in_(user_ids.values())).delete(synchronize_session=False)
        admin = db.session.get(User, user_ids['admin'])
        admin.username = 'admin-test'
        admin.role = 'admin'
        admin.is_active = True
        admin.nostr_pubkey = PUBKEYS['admin']
        admin.auth_version = 1
        admin.must_change_password = False
        for role in ('moderator', 'viewer'):
            user = db.session.get(User, user_ids[role])
            user.role = role
            user.is_active = True
            user.nostr_pubkey = PUBKEYS[role]
            user.auth_version = 1
        inactive = db.session.get(User, user_ids['inactive'])
        inactive.is_active = False
        inactive.nostr_pubkey = PUBKEYS['inactive']
        inactive.auth_version = 1
        db.session.commit()
    yield


def _make_user(username, role, is_active=True, pubkey=None):
    user = User(
        username=username,
        role=role,
        is_active=is_active,
        nostr_pubkey=pubkey,
        must_change_password=False,
    )
    user.set_password(PASSWORD)
    db.session.add(user)
    return user


def _client_for(flask_app, user_id=None):
    client = flask_app.test_client()
    if user_id is not None:
        with client.session_transaction() as session:
            session['_user_id'] = str(user_id)
            session['_fresh'] = True
            session['_nostr_auth_version'] = 1
    return client


def _edit_data(role='admin', is_active='true', nostr_pubkey=PUBKEYS['admin']):
    return {'role': role, 'is_active': is_active, 'nostr_pubkey': nostr_pubkey}


def test_admin_is_get_only_redirect_to_operators(admin_app):
    _module, flask_app, users = admin_app
    client = _client_for(flask_app, users['admin'])

    response = client.get('/admin')

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/admin/operators')
    assert client.post('/admin').status_code == 405


def test_admin_pages_require_active_admin_and_navigation_is_active(admin_app):
    _module, flask_app, users = admin_app

    assert _client_for(flask_app).get('/admin/operators').status_code == 302
    assert _client_for(flask_app, users['viewer']).get('/admin/audit').status_code == 302
    inactive_response = _client_for(flask_app, users['inactive']).get('/admin/operators')
    assert inactive_response.status_code == 302
    assert inactive_response.headers['Location'].endswith('/login')

    client = _client_for(flask_app, users['admin'])
    for path, label in (
        ('/admin/operators', b'Operators'),
        ('/admin/audit', b'Audit log'),
        ('/admin/relays', b'Metadata relays'),
        ('/admin/bans', b'Ban registry'),
    ):
        response = client.get(path)
        assert response.status_code == 200
        assert label in response.data
        assert b'aria-current="page"' in response.data


def test_focused_pages_do_not_render_old_combined_admin(admin_app):
    _module, flask_app, users = admin_app
    client = _client_for(flask_app, users['admin'])
    with flask_app.app_context():
        db.session.add(AuditLog(action='secret_audit_marker', details='audit-only'))
        db.session.commit()

    operators = client.get('/admin/operators')
    audit = client.get('/admin/audit')

    assert b'secret_audit_marker' not in operators.data
    assert b'Create operator' in operators.data
    assert b'Create operator' not in audit.data
    assert b'secret_audit_marker' in audit.data


def test_create_and_edit_duplicate_pubkeys_roll_back_mutation_and_audit(admin_app):
    _module, flask_app, users = admin_app
    client = _client_for(flask_app, users['admin'])

    create = client.post('/admin/user', data={
        'nostr_pubkey': PUBKEYS['viewer'],
        'role': 'viewer',
    })
    edit = client.post(
        f'/admin/user/{users["moderator"]}/edit',
        data=_edit_data(role='moderator'),
    )

    assert create.status_code == 302
    assert edit.status_code == 302
    assert create.headers['Location'].endswith('/admin/operators')
    assert edit.headers['Location'].endswith('/admin/operators')
    with flask_app.app_context():
        assert db.session.get(User, users['moderator']).username == 'moderator-test'
        assert AuditLog.query.filter(AuditLog.action.in_(['user_create', 'user_edit'])).count() == 0


def test_operator_uses_profile_name_and_commits_audit_together(admin_app, monkeypatch):
    app_module, flask_app, users = admin_app
    client = _client_for(flask_app, users['admin'])
    monkeypatch.setattr(app_module, 'get_pubkey_metadata', lambda pubkey, refresh=False: {'name': 'created_operator'})

    response = client.post('/admin/user', data={
        'nostr_pubkey': '5' * 64,
        'role': 'moderator',
    })

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/admin/operators')
    with flask_app.app_context():
        created = User.query.filter_by(username='created_operator').one()
        audit = AuditLog.query.filter_by(action='user_create').one()
        assert created.nostr_pubkey == '5' * 64
        assert created.must_change_password is False
        assert audit.user_id == users['admin']


def test_self_delete_demote_and_deactivate_are_forbidden(admin_app):
    _module, flask_app, users = admin_app
    client = _client_for(flask_app, users['admin'])
    admin_id = users['admin']

    demote = client.post(
        f'/admin/user/{admin_id}/edit',
        data=_edit_data(role='moderator'),
    )
    deactivate = client.post(
        f'/admin/user/{admin_id}/edit',
        data=_edit_data(is_active='false'),
    )
    delete = client.post(
        f'/admin/user/{admin_id}/delete',
        data={'confirm_user_id': str(admin_id)},
    )

    assert {demote.status_code, deactivate.status_code, delete.status_code} == {302}
    with flask_app.app_context():
        admin = db.session.get(User, admin_id)
        assert admin.role == 'admin'
        assert admin.is_active is True
        assert AuditLog.query.count() == 0


def test_delete_confirmation_is_bound_to_target(admin_app):
    _module, flask_app, users = admin_app
    client = _client_for(flask_app, users['admin'])
    target_id = users['viewer']

    assert client.post(
        f'/admin/user/{target_id}/delete',
        data={'confirm_user_id': str(users['moderator'])},
    ).status_code == 400
    with flask_app.app_context():
        assert db.session.get(User, target_id) is not None

    response = client.post(
        f'/admin/user/{target_id}/delete',
        data={'confirm_user_id': str(target_id)},
    )
    assert response.status_code == 302
    assert response.headers['Location'].endswith('/admin/operators')
    with flask_app.app_context():
        assert db.session.get(User, target_id) is None
        assert AuditLog.query.filter_by(action='user_delete').one()
        replacement = _make_user('viewer-test', 'viewer', pubkey=PUBKEYS['viewer'])
        replacement.id = target_id
        db.session.commit()


def test_password_change_route_is_removed_and_operator_page_has_no_password_controls(admin_app):
    _module, flask_app, users = admin_app
    client = _client_for(flask_app, users['admin'])
    assert client.post(f'/change-password/{users["moderator"]}').status_code == 404
    operators = client.get('/admin/operators')
    assert b'Set password' not in operators.data
    assert b'Nostr pubkey' in operators.data
    assert b'name="username"' not in operators.data


def test_admin_pubkey_replacement_updates_name_and_revokes_sessions(admin_app, monkeypatch):
    app_module, flask_app, users = admin_app
    admin_client = _client_for(flask_app, users['admin'])
    viewer_client = _client_for(flask_app, users['viewer'])
    monkeypatch.setattr(app_module, 'get_pubkey_metadata', lambda pubkey, refresh=False: {'name': 'viewer_profile'})

    response = admin_client.post(
        f'/admin/user/{users["viewer"]}/edit',
        data=_edit_data(
            role='viewer',
            nostr_pubkey='6' * 64,
        ),
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b'User viewer_profile updated.' in response.data
    with flask_app.app_context():
        viewer = db.session.get(User, users['viewer'])
        assert viewer.auth_version == 2
        assert viewer.username == 'viewer_profile'
    assert viewer_client.get('/').headers['Location'].endswith('/login')


def test_audit_api_filters_orders_and_uses_cursor(admin_app):
    _module, flask_app, users = admin_app
    timestamp = datetime(2026, 8, 10, 12, 0, 0)
    with flask_app.app_context():
        db.session.add_all([
            AuditLog(user_id=users['admin'], action='user_edit', details='alpha', timestamp=timestamp),
            AuditLog(user_id=users['admin'], action='user_edit', details='beta', timestamp=timestamp),
            AuditLog(action='system_sync', details='<script>alert(1)</script>', timestamp=timestamp - timedelta(days=1)),
            AuditLog(user_id=users['moderator'], action='login', details='outside', timestamp=timestamp - timedelta(days=2)),
        ])
        db.session.commit()

    client = _client_for(flask_app, users['admin'])
    first = client.get('/api/audit-logs', query_string={
        'action': 'user_',
        'operator': 'admin-test',
        'system': 'exclude',
        'date_from': '2026-08-10',
        'date_to': '2026-08-10',
        'limit': 1,
    })
    payload = first.get_json()

    assert first.status_code == 200
    assert first.headers['Cache-Control'].startswith('no-store')
    assert first.headers['X-Content-Type-Options'] == 'nosniff'
    assert first.content_type == 'application/json'
    assert payload['total_count'] == 2
    assert payload['has_more'] is True
    assert payload['logs'][0]['details'] == 'beta'

    second = client.get('/api/audit-logs', query_string={
        'action': 'user_',
        'operator': 'admin-test',
        'system': 'exclude',
        'date_from': '2026-08-10',
        'date_to': '2026-08-10',
        'limit': 1,
        'cursor': json.dumps(payload['next_cursor']),
    }).get_json()
    assert [entry['details'] for entry in second['logs']] == ['alpha']
    assert second['has_more'] is False

    system = client.get('/api/audit-logs?system=only&text=script').get_json()
    assert [entry['username'] for entry in system['logs']] == ['system']
    assert system['logs'][0]['details'] == '<script>alert(1)</script>'


def test_audit_bounds_invalid_legacy_values_and_html_security(admin_app):
    _module, flask_app, users = admin_app
    with flask_app.app_context():
        for number in range(105):
            db.session.add(AuditLog(action=f'action-{number}'))
        db.session.commit()
    client = _client_for(flask_app, users['admin'])

    maximum = client.get('/api/audit-logs?limit=1000&offset=not-a-number')
    minimum = client.get('/api/audit-logs?limit=0&offset=-20')
    capped_offset = client.get('/api/audit-logs?offset=999999')
    malformed_cursor = client.get('/api/audit-logs?cursor=not-json&limit=2')
    page = client.get('/admin/audit?limit=2')

    assert len(maximum.get_json()['logs']) == 100
    assert len(minimum.get_json()['logs']) == 1
    assert capped_offset.get_json()['logs'] == []
    assert len(malformed_cursor.get_json()['logs']) == 2
    assert page.status_code == 200
    assert page.headers['Cache-Control'].startswith('no-store')
    assert page.headers['X-Content-Type-Options'] == 'nosniff'
    assert b'data-next-cursor=' in page.data


def test_audit_filter_disclosure_tracks_active_filters(admin_app):
    _module, flask_app, users = admin_app
    client = _client_for(flask_app, users['admin'])

    default_page = client.get('/admin/audit')
    filtered_page = client.get('/admin/audit?action=user&system=exclude')

    disclosure = b'class="dashboard-panel admin-filter-disclosure compact-panel mb-4" data-responsive-disclosure'
    assert disclosure + b'>' in default_page.data
    assert b'No active filters' in default_page.data
    assert disclosure + b' open>' in filtered_page.data
    assert b'2 active' in filtered_page.data
    assert b'Action, System records' in filtered_page.data


def test_relay_api_rejects_malformed_json_and_canonical_duplicates(admin_app):
    _module, flask_app, users = admin_app
    client = _client_for(flask_app, users['admin'])

    assert client.post('/api/metadata-relays', data='["not-an-object"]', content_type='application/json').status_code == 400
    assert client.post('/api/metadata-relays', data='{', content_type='application/json').status_code == 400

    created = client.post('/api/metadata-relays', json={'url': ' WSS://Relay.Example:443 '})
    duplicate = client.post('/api/metadata-relays', json={'url': 'wss://relay.example/'})

    assert created.status_code == 200
    assert created.get_json()['url'] == 'wss://relay.example/'
    assert duplicate.status_code == 409
    with flask_app.app_context():
        assert MetadataRelay.query.count() == 1
        assert AuditLog.query.filter_by(action='metadata_relay_added').count() == 1


def test_relay_api_compares_canonical_equivalents_in_legacy_rows(admin_app):
    _module, flask_app, users = admin_app
    with flask_app.app_context():
        db.session.add(MetadataRelay(url='WSS://Relay.Example:443'))
        db.session.commit()

    response = _client_for(flask_app, users['admin']).post(
        '/api/metadata-relays',
        json={'url': 'wss://relay.example/'},
    )

    assert response.status_code == 409


def test_relay_api_enforces_enabled_lookup_limit(admin_app, monkeypatch):
    app_module, flask_app, users = admin_app
    monkeypatch.setattr(app_module, 'MAX_RELAYS', 1)
    with flask_app.app_context():
        MetadataRelay.query.delete()
        db.session.add(MetadataRelay(url='wss://one.example/', enabled=True))
        db.session.add(MetadataRelay(url='wss://two.example/', enabled=False))
        db.session.commit()
        disabled_id = MetadataRelay.query.filter_by(enabled=False).one().id
    client = _client_for(flask_app, users['admin'])

    added = client.post('/api/metadata-relays', json={'url': 'wss://three.example/'})
    enabled = client.post(f'/api/metadata-relays/{disabled_id}/toggle', json={})

    assert added.status_code == 409
    assert enabled.status_code == 409
    assert b'At most 1 metadata relays may be enabled' in added.data


def test_relay_frontend_ignores_obsolete_loads():
    source = Path('static/admin_relays.js').read_text()

    assert 'loadGeneration' in source
    assert 'generation !== loadGeneration' in source


def test_relay_integrity_race_rolls_back_mutation_and_audit(admin_app, monkeypatch):
    _module, flask_app, users = admin_app

    def race():
        raise IntegrityError('INSERT', {}, RuntimeError('simulated race'))

    monkeypatch.setattr(db.session, 'commit', race)
    response = _client_for(flask_app, users['admin']).post(
        '/api/metadata-relays',
        json={'url': 'wss://race.example'},
    )

    assert response.status_code == 409
    with flask_app.app_context():
        assert MetadataRelay.query.count() == 0
        assert AuditLog.query.filter_by(action='metadata_relay_added').count() == 0


def test_relay_delete_requires_exact_stored_url_and_audits_atomically(admin_app):
    _module, flask_app, users = admin_app
    with flask_app.app_context():
        relay = MetadataRelay(url='WSS://Relay.Example:443')
        db.session.add(relay)
        db.session.commit()
        relay_id = relay.id
    client = _client_for(flask_app, users['admin'])

    wrong = client.delete(
        f'/api/metadata-relays/{relay_id}',
        json={'confirm_url': 'wss://relay.example/'},
    )
    deleted = client.delete(
        f'/api/metadata-relays/{relay_id}',
        json={'confirm_url': 'WSS://Relay.Example:443'},
    )

    assert wrong.status_code == 400
    assert deleted.status_code == 200
    with flask_app.app_context():
        assert db.session.get(MetadataRelay, relay_id) is None
        assert AuditLog.query.filter_by(action='metadata_relay_deleted').count() == 1


def test_relay_test_uses_safe_public_tester_and_bounds_client_error(admin_app, monkeypatch, caplog):
    app_module, flask_app, users = admin_app
    with flask_app.app_context():
        relay = MetadataRelay(url='wss://relay.example/')
        db.session.add(relay)
        db.session.commit()
        relay_id = relay.id
    calls = []

    def fail_safely(url, timeout):
        calls.append((url, timeout))
        raise RelayError('private diagnostic detail')

    monkeypatch.setattr(app_module, 'test_relay', fail_safely)
    response = _client_for(flask_app, users['admin']).post(
        f'/api/metadata-relays/{relay_id}/test',
        json={},
    )

    assert response.status_code == 502
    assert calls == [('wss://relay.example/', 5)]
    assert response.get_json() == {'status': 'failed', 'message': 'Relay test failed'}
    assert b'private diagnostic detail' not in response.data
    assert 'private diagnostic detail' in caplog.text
    with flask_app.app_context():
        assert db.session.get(MetadataRelay, relay_id).last_status == 'failed'
        assert AuditLog.query.filter_by(action='metadata_relay_tested').count() == 1


def test_external_metadata_lookup_uses_safe_latest_kind0(admin_app, monkeypatch):
    app_module, _flask_app, _users = admin_app
    calls = []
    event = {'content': json.dumps({'name': 'Latest profile'})}

    def lookup(pubkey, relays, timeout):
        calls.append((pubkey, relays, timeout))
        return event

    monkeypatch.setattr(app_module, 'safe_lookup_kind0', lookup)
    metadata = app_module.fetch_from_external_relays(
        'a' * 64,
        ['WSS://Relay.Example:443', 'wss://relay.example/'],
    )

    assert metadata == {'name': 'Latest profile'}
    assert calls == [('a' * 64, ['wss://relay.example/'], 5)]


def test_ban_removals_require_exact_targets_and_preserve_service_calls(admin_app, monkeypatch):
    app_module, flask_app, users = admin_app
    pubkey = 'a' * 64
    with flask_app.app_context():
        ban = BannedPubkey(pubkey=pubkey)
        domain = BannedDomain(domain='example.com')
        db.session.add_all([ban, domain])
        db.session.commit()
        ban_id = ban.id
        domain_id = domain.id
    calls = []

    class Decisions:
        def unban(self, target_id):
            calls.append(('pubkey', target_id))
            return type('Outcome', (), {'active_set_changed': True, 'warnings': []})()

        def unban_domain(self, target_id):
            calls.append(('domain', target_id))
            return type('Outcome', (), {
                'removed_sources': 0,
                'unbanned_pubkeys': 0,
                'remaining_bans': 0,
                'warnings': [],
            })()

    monkeypatch.setattr(app_module, 'moderation_decisions', lambda: Decisions())
    client = _client_for(flask_app, users['admin'])

    assert client.post(f'/admin/banned/{ban_id}/unban', data={'confirm_pubkey': 'b' * 64}).status_code == 400
    assert client.post(f'/admin/banned-domain/{domain_id}/delete', data={'confirm_domain': 'other.example'}).status_code == 400
    assert calls == []

    unban = client.post(f'/admin/banned/{ban_id}/unban', data={'confirm_pubkey': pubkey})
    undomain = client.post(f'/admin/banned-domain/{domain_id}/delete', data={'confirm_domain': 'example.com'})
    assert unban.status_code == 302 and unban.headers['Location'].endswith('/admin/bans')
    assert undomain.status_code == 302 and undomain.headers['Location'].endswith('/admin/bans')
    assert calls == [('pubkey', ban_id), ('domain', domain_id)]
