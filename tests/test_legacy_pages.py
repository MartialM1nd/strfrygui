import importlib
import sys

import pytest
from types import SimpleNamespace

from config import Config
from models import User, db


PASSWORD = 'StrongPassword123456!'


@pytest.fixture(scope='module')
def legacy_app(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp('legacy-pages')
    old_database_uri = Config.SQLALCHEMY_DATABASE_URI
    Config.SQLALCHEMY_DATABASE_URI = f'sqlite:///{tmp_path / "legacy.db"}'
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
    assert b'type="password"' in register_page.data
    assert b'Sign and configure administrator' in register_page.data
    assert b'Sign in with Nostr' in login_page.data
    assert b'name="password"' not in login_page.data


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

    response = flask_app.test_client().post('/api/auth/verify')

    assert response.status_code == 200
    assert response.get_json()['redirect'] == '/events'
    with flask_app.app_context():
        user = db.session.get(User, user_id)
        assert user.last_login is not None


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
            payload={'username': 'existing_admin', 'registration_token': 'private-registration-token'},
        ),
    )

    response = flask_app.test_client().post('/api/auth/bootstrap')

    assert response.status_code == 200
    with flask_app.app_context():
        user = db.session.get(User, user_id)
        assert user.nostr_pubkey == pubkey
        assert app_module._nostr_setup_available() is False


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
