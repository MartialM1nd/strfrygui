import importlib
import re
import sys

import pytest
from types import SimpleNamespace

from config import Config
from models import AuditLog, User, db
from utils.strfry import hex_to_npub


PASSWORD = 'StrongPassword123456!'


@pytest.fixture(scope='module')
def legacy_app(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp('legacy-pages')
    old_database_uri = Config.SQLALCHEMY_DATABASE_URI
    old_proxy_count = Config.TRUSTED_PROXY_COUNT
    Config.SQLALCHEMY_DATABASE_URI = f'sqlite:///{tmp_path / "legacy.db"}'
    Config.TRUSTED_PROXY_COUNT = 1
    app_module = importlib.import_module('app')
    flask_app = app_module.app
    old_token = Config.REGISTRATION_TOKEN
    flask_app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
    )
    Config.REGISTRATION_TOKEN = 'private-registration-token'
    app_module.limiter.reset()
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
    yield app_module, flask_app
    with flask_app.app_context():
        db.session.remove()
        db.drop_all()
    Config.REGISTRATION_TOKEN = old_token
    Config.TRUSTED_PROXY_COUNT = old_proxy_count
    Config.SQLALCHEMY_DATABASE_URI = old_database_uri
    sys.modules.pop('app', None)


@pytest.fixture(autouse=True)
def clean_legacy_database(legacy_app):
    _app_module, flask_app = legacy_app
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
    yield


def add_user(flask_app, username='operator', role='admin', must_change=False):
    with flask_app.app_context():
        user = User(
            username=username,
            role=role,
            must_change_password=must_change,
        )
        user.set_password(PASSWORD)
        db.session.add(user)
        db.session.commit()
        return user.id


def login(client, username='operator', next_url=None):
    path = '/login'
    if next_url is not None:
        path += f'?next={next_url}'
    return client.post(path, data={'username': username, 'password': PASSWORD})


def test_auth_pages_render_nostr_only_controls_and_masked_token(legacy_app):
    _app_module, flask_app = legacy_app
    client = flask_app.test_client()

    register_page = client.get('/register')
    login_page = client.get('/login')

    assert b'id="setupRegistrationToken"' in register_page.data
    assert b'id="setupUsername"' not in register_page.data
    assert b'type="password"' in register_page.data
    assert b'Sign and configure administrator' in register_page.data
    assert b'Sign in with Nostr' in login_page.data
    assert b'name="password"' not in login_page.data
    csp = login_page.headers['Content-Security-Policy']
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    assert f'nonce="{nonce}"'.encode() in login_page.data
    assert "frame-ancestors 'none'" in csp
    assert login_page.headers['X-Frame-Options'] == 'DENY'
    assert login_page.headers['X-Content-Type-Options'] == 'nosniff'
    assert login_page.headers['Cache-Control'].startswith('no-store')


def test_vendored_static_assets_are_cacheable_without_external_execution(legacy_app):
    _app_module, flask_app = legacy_app
    response = flask_app.test_client().get(
        '/static/vendor/bootstrap-5.3.2/bootstrap.min.css'
    )

    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'public, max-age=31536000, immutable'


@pytest.mark.parametrize('next_url', [
    'https://attacker.example/steal',
    '//attacker.example/steal',
    '/\\attacker.example/steal',
])
def test_login_page_does_not_embed_unsafe_next_as_redirect_logic(legacy_app, next_url):
    _app_module, flask_app = legacy_app
    response = flask_app.test_client().get(f'/login?next={next_url}')
    assert response.status_code == 200
    assert b'data-nostr-auth="login"' in response.data


def test_login_page_preserves_local_next_for_challenge_request(legacy_app):
    _app_module, flask_app = legacy_app
    local = flask_app.test_client().get('/login?next=/events?limit=25')
    assert b'data-next="/events?limit=25"' in local.data


def test_password_login_and_change_routes_are_removed(legacy_app):
    _app_module, flask_app = legacy_app
    client = flask_app.test_client()
    assert client.post('/login', data={'username': 'operator', 'password': PASSWORD}).status_code == 405
    assert client.post('/change-password/1').status_code == 404


def test_protected_api_returns_json_when_session_is_missing(legacy_app):
    _app_module, flask_app = legacy_app
    response = flask_app.test_client().get('/api/dashboard')

    assert response.status_code == 401
    assert response.is_json
    assert response.get_json() == {'error': 'Authentication required.'}


def test_missing_api_route_returns_json(legacy_app):
    _app_module, flask_app = legacy_app
    response = flask_app.test_client().get('/api/not-a-route')

    assert response.status_code == 404
    assert response.is_json
    assert response.get_json() == {'error': 'The requested API endpoint does not exist.'}


def test_protected_api_returns_json_when_role_is_insufficient(legacy_app):
    _app_module, flask_app = legacy_app
    user_id = add_user(flask_app, role='viewer')
    client = flask_app.test_client()
    with client.session_transaction() as auth_session:
        auth_session['_user_id'] = str(user_id)
        auth_session['_fresh'] = True
        auth_session['_nostr_auth_version'] = 1

    response = client.get('/api/audit-logs')

    assert response.status_code == 403
    assert response.is_json
    assert response.get_json() == {'error': 'Permission denied.'}


def test_unhandled_api_error_returns_json(legacy_app, monkeypatch):
    app_module, flask_app = legacy_app
    user_id = add_user(flask_app)
    client = flask_app.test_client()
    with client.session_transaction() as auth_session:
        auth_session['_user_id'] = str(user_id)
        auth_session['_fresh'] = True
        auth_session['_nostr_auth_version'] = 1

    def fail_dashboard(**kwargs):
        raise RuntimeError('private detail')

    monkeypatch.setattr(app_module, 'dashboard_summary', fail_dashboard)
    old_propagate = flask_app.config.get('PROPAGATE_EXCEPTIONS')
    flask_app.config['PROPAGATE_EXCEPTIONS'] = False
    try:
        response = client.get('/api/dashboard')
    finally:
        flask_app.config['PROPAGATE_EXCEPTIONS'] = old_propagate

    assert response.status_code == 500
    assert response.is_json
    assert response.get_json() == {'error': 'The request could not be completed.'}
    assert b'private detail' not in response.data


def test_trusted_proxy_identity_is_shared_by_audit_and_rate_limit(legacy_app, monkeypatch):
    app_module, flask_app = legacy_app
    app_module.limiter.reset()
    monkeypatch.setattr(
        app_module,
        '_verified_auth',
        lambda action: SimpleNamespace(pubkey='f' * 64, redirect_to=None, payload={}),
    )
    client = flask_app.test_client()

    failed_login = client.post(
        '/api/auth/verify',
        headers={'X-Forwarded-For': '198.51.100.10'},
        environ_base={'REMOTE_ADDR': '127.0.0.1'},
    )
    with flask_app.app_context():
        audit = AuditLog.query.filter_by(action='login_failed').one()
    for _ in range(5):
        client.post(
            '/api/auth/challenge',
            json={'action': 'login'},
            headers={'X-Forwarded-For': '198.51.100.20'},
            environ_base={'REMOTE_ADDR': '127.0.0.1'},
        )
    limited = client.post(
        '/api/auth/challenge',
        json={'action': 'login'},
        headers={'X-Forwarded-For': '198.51.100.20'},
        environ_base={'REMOTE_ADDR': '127.0.0.1'},
    )
    independent = client.post(
        '/api/auth/challenge',
        json={'action': 'login'},
        headers={'X-Forwarded-For': '198.51.100.21'},
        environ_base={'REMOTE_ADDR': '127.0.0.1'},
    )

    assert failed_login.status_code == 401
    assert audit.ip_address == '198.51.100.10'
    assert limited.status_code == 429
    assert limited.is_json
    assert limited.get_json() == {'error': 'Too many requests. Please try again later.'}
    assert independent.status_code == 200


def test_oversized_api_body_is_rejected_before_json_parsing(legacy_app):
    _app_module, flask_app = legacy_app
    original_limit = flask_app.config['REQUEST_MAX_BYTES']
    flask_app.config['REQUEST_MAX_BYTES'] = 64
    try:
        response = flask_app.test_client().post(
            '/api/auth/challenge',
            json={'action': 'login', 'padding': 'x' * 100},
        )
    finally:
        flask_app.config['REQUEST_MAX_BYTES'] = original_limit

    assert response.status_code == 413
    assert response.get_json() == {'error': 'Request body is too large.'}


def test_protected_api_csrf_rejection_is_json(legacy_app):
    app_module, flask_app = legacy_app
    app_module.limiter.reset()
    user_id = add_user(flask_app)
    client = flask_app.test_client()
    with client.session_transaction() as auth_session:
        auth_session['_user_id'] = str(user_id)
        auth_session['_fresh'] = True
        auth_session['_nostr_auth_version'] = 1
    flask_app.config['WTF_CSRF_ENABLED'] = True
    try:
        response = client.post(
            '/api/metadata-relays',
            json={'url': 'wss://relay.example'},
        )
    finally:
        flask_app.config['WTF_CSRF_ENABLED'] = False

    assert response.status_code == 400
    assert response.is_json
    assert response.get_json() == {'error': 'Request validation failed.'}


def test_nostr_login_endpoints_do_not_require_redundant_csrf_token(legacy_app):
    app_module, flask_app = legacy_app
    app_module.limiter.reset()
    flask_app.config['WTF_CSRF_ENABLED'] = True
    client = flask_app.test_client()
    try:
        challenge_response = client.post(
            '/api/auth/challenge',
            json={'action': 'login'},
        )
        verify_response = client.post('/api/auth/verify')
    finally:
        flask_app.config['WTF_CSRF_ENABLED'] = False

    assert challenge_response.status_code == 200
    assert challenge_response.is_json
    assert 'event' in challenge_response.get_json()
    assert verify_response.status_code == 401
    assert verify_response.get_json() == {'error': 'Nostr authentication failed.'}


def test_auth_api_accepts_csrf_token_from_login_page(legacy_app):
    app_module, flask_app = legacy_app
    app_module.limiter.reset()
    flask_app.config['WTF_CSRF_ENABLED'] = True
    client = flask_app.test_client()
    try:
        login_page = client.get('/login')
        token = re.search(
            rb'<meta name="csrf-token" content="([^"]+)">',
            login_page.data,
        ).group(1).decode()
        response = client.post(
            '/api/auth/challenge',
            json={'action': 'login'},
            headers={'X-CSRFToken': token},
        )
    finally:
        flask_app.config['WTF_CSRF_ENABLED'] = False

    assert response.status_code == 200
    assert response.is_json
    assert 'event' in response.get_json()


def test_oversized_body_is_rejected_even_when_route_does_not_read_it(legacy_app):
    _app_module, flask_app = legacy_app
    original_limit = flask_app.config['REQUEST_MAX_BYTES']
    flask_app.config['REQUEST_MAX_BYTES'] = 64
    try:
        response = flask_app.test_client().get('/login', data='x' * 100)
    finally:
        flask_app.config['REQUEST_MAX_BYTES'] = original_limit

    assert response.status_code == 413


def test_nostr_login_maps_verified_pubkey_to_existing_user(legacy_app, monkeypatch):
    app_module, flask_app = legacy_app
    pubkey = 'a' * 64
    with flask_app.app_context():
        user = User(username='nostr-admin', role='admin', nostr_pubkey=pubkey, must_change_password=False)
        user.disable_password()
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    monkeypatch.setattr(
        app_module,
        '_verified_auth',
        lambda action: SimpleNamespace(pubkey=pubkey, redirect_to='/events', payload={}),
    )
    monkeypatch.setattr(app_module, 'get_pubkey_metadata', lambda value, refresh=False: {'name': 'updated-profile'})

    response = flask_app.test_client().post('/api/auth/verify')

    assert response.status_code == 200
    assert response.get_json()['redirect'] == '/events'
    with flask_app.app_context():
        user = db.session.get(User, user_id)
        assert user.last_login is not None
        assert user.username == 'updated-profile'


def test_nostr_bootstrap_binds_existing_admin_and_closes_setup(legacy_app, monkeypatch):
    app_module, flask_app = legacy_app
    user_id = add_user(flask_app, username='existing_admin')
    pubkey = 'b' * 64
    monkeypatch.setattr(
        app_module,
        '_verified_auth',
        lambda action: SimpleNamespace(
            pubkey=pubkey,
            redirect_to=None,
            payload={'registration_token': 'private-registration-token'},
        ),
    )
    monkeypatch.setattr(app_module, 'get_pubkey_metadata', lambda value, refresh=False: {'name': 'profile-admin'})

    response = flask_app.test_client().post('/api/auth/bootstrap')

    assert response.status_code == 200
    with flask_app.app_context():
        user = db.session.get(User, user_id)
        assert user.nostr_pubkey == pubkey
        assert user.username == 'profile-admin'
        assert app_module._nostr_setup_available() is False


def test_nostr_bootstrap_creates_fresh_admin_from_profile(legacy_app, monkeypatch):
    app_module, flask_app = legacy_app
    pubkey = '9' * 64
    monkeypatch.setattr(
        app_module,
        '_verified_auth',
        lambda action: SimpleNamespace(
            pubkey=pubkey,
            redirect_to=None,
            payload={'registration_token': 'private-registration-token'},
        ),
    )
    monkeypatch.setattr(app_module, 'get_pubkey_metadata', lambda value, refresh=False: {'name': 'fresh-admin'})

    response = flask_app.test_client().post('/api/auth/bootstrap')

    assert response.status_code == 200
    with flask_app.app_context():
        user = User.query.one()
        assert user.username == 'fresh-admin'
        assert user.nostr_pubkey == pubkey
        assert user.role == 'admin'


def test_nostr_bootstrap_requires_exactly_one_unbound_admin(legacy_app, monkeypatch):
    app_module, flask_app = legacy_app
    add_user(flask_app, username='first_admin')
    add_user(flask_app, username='second_admin')
    monkeypatch.setattr(
        app_module,
        '_verified_auth',
        lambda action: SimpleNamespace(
            pubkey='c' * 64,
            redirect_to=None,
            payload={'registration_token': 'private-registration-token'},
        ),
    )

    response = flask_app.test_client().post('/api/auth/bootstrap')

    assert response.status_code == 400
    assert b'exactly one active, unbound administrator' in response.data


def test_profile_username_uses_unique_short_npub_fallback(legacy_app, monkeypatch):
    app_module, flask_app = legacy_app
    pubkey = 'd' * 64
    monkeypatch.setattr(app_module, 'get_pubkey_metadata', lambda value, refresh=False: {'name': 'taken'})
    add_user(flask_app, username='taken')

    with flask_app.app_context():
        username = app_module._profile_username(pubkey)

    assert username == hex_to_npub(pubkey)[:17]


def test_key_rotation_updates_profile_username(legacy_app, monkeypatch):
    app_module, flask_app = legacy_app
    old_pubkey = 'e' * 64
    new_pubkey = 'f' * 64
    user_id = add_user(flask_app, username='old-name', role='viewer')
    with flask_app.app_context():
        user = db.session.get(User, user_id)
        user.nostr_pubkey = old_pubkey
        db.session.commit()

    client = flask_app.test_client()
    with client.session_transaction() as auth_session:
        auth_session['_user_id'] = str(user_id)
        auth_session['_fresh'] = True
        auth_session['_nostr_auth_version'] = 1
        auth_session['_nostr_rotation'] = {
            'user_id': user_id,
            'auth_version': 1,
            'expires_at': int(app_module.time.time()) + 60,
        }
    monkeypatch.setattr(
        app_module,
        '_verified_auth',
        lambda action: SimpleNamespace(pubkey=new_pubkey, redirect_to=None, payload={}),
    )
    monkeypatch.setattr(app_module, 'get_pubkey_metadata', lambda value, refresh=False: {'name': 'new-profile'})

    response = client.post('/api/auth/rotate-key')

    assert response.status_code == 200
    with flask_app.app_context():
        user = db.session.get(User, user_id)
        assert user.nostr_pubkey == new_pubkey
        assert user.username == 'new-profile'


def test_error_pages_have_safe_context_status_and_recovery(legacy_app):
    app_module, flask_app = legacy_app
    client = flask_app.test_client()

    missing = client.get('/does-not-exist')
    assert missing.status_code == 404
    assert b'Page not found' in missing.data
    assert b'href="/login"' in missing.data

    with flask_app.test_request_context('/failure'):
        body, status = app_module.internal_error(RuntimeError('private detail'))
    assert status == 500
    assert b'Internal server error' in body.encode()
    assert b'private detail' not in body.encode()
