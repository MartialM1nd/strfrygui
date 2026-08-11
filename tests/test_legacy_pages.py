import importlib
import sys

import pytest

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


def test_auth_forms_render_accessible_validation_and_masked_token(legacy_app):
    _app_module, flask_app = legacy_app
    client = flask_app.test_client()

    register_page = client.get('/register')
    invalid = client.post('/register', data={
        'username': 'x',
        'password': 'short',
        'confirm_password': 'different',
        'role': 'admin',
        'registration_token': 'wrong',
    })
    bad_token = client.post('/register', data={
        'username': 'first_admin',
        'password': PASSWORD,
        'confirm_password': PASSWORD,
        'role': 'admin',
        'registration_token': 'visible-secret',
    })

    assert b'name="registration_token"' in register_page.data
    assert b'type="password"' in register_page.data
    assert b'autocomplete="new-password"' in register_page.data
    assert b'is-invalid' in invalid.data
    assert b'aria-describedby="username-errors"' in invalid.data
    assert b'id="username-errors"' in invalid.data
    assert b'aria-describedby="registration_token-errors"' in bad_token.data
    assert b'visible-secret' not in bad_token.data


@pytest.mark.parametrize('next_url', [
    'https://attacker.example/steal',
    '//attacker.example/steal',
    '/\\attacker.example/steal',
])
def test_login_rejects_unsafe_next_redirects(legacy_app, next_url):
    _app_module, flask_app = legacy_app
    add_user(flask_app)

    response = login(flask_app.test_client(), next_url=next_url)

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/')
    assert 'attacker.example' not in response.headers['Location']


def test_login_accepts_local_next_and_preserves_forced_password_change(legacy_app):
    _app_module, flask_app = legacy_app
    add_user(flask_app)
    local = login(flask_app.test_client(), next_url='/events?limit=25')
    assert local.headers['Location'].endswith('/events?limit=25')

    forced_id = add_user(flask_app, username='forced', role='viewer', must_change=True)
    forced = login(flask_app.test_client(), username='forced', next_url='/events')
    assert forced.headers['Location'].endswith(f'/change-password/{forced_id}')


def test_registration_and_password_change_behavior_remains_intact(legacy_app):
    _app_module, flask_app = legacy_app
    client = flask_app.test_client()
    created = client.post('/register', data={
        'username': 'first_admin',
        'password': PASSWORD,
        'confirm_password': PASSWORD,
        'role': 'admin',
        'registration_token': 'private-registration-token',
    })
    assert created.status_code == 302
    assert created.headers['Location'].endswith('/login')

    login(client, username='first_admin')
    with flask_app.app_context():
        user_id = User.query.filter_by(username='first_admin').one().id
    invalid = client.post(
        f'/change-password/{user_id}',
        data={'password': 'short', 'confirm_password': 'short'},
    )
    assert invalid.status_code == 200
    assert b'aria-describedby="password-help password-errors"' in invalid.data


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
