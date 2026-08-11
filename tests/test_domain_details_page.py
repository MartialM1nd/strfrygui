import importlib
import sys

import pytest

from models import BannedDomain, BannedPubkey, PubkeyBanSource, User, db
from config import Config


PASSWORD = 'StrongPassword123456!'
PUBKEY_A = 'a' * 64
PUBKEY_B = 'b' * 64


@pytest.fixture(scope='module')
def domain_page_app(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp('domain-details-page')
    old_database_uri = Config.SQLALCHEMY_DATABASE_URI
    Config.SQLALCHEMY_DATABASE_URI = f'sqlite:///{tmp_path / "domain-page.db"}'
    app_module = importlib.import_module('app')
    flask_app = app_module.app
    flask_app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
    )
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
        users = {}
        for role in ('admin', 'moderator', 'viewer'):
            user = User(username=f'{role}-domain', role=role, must_change_password=False)
            user.set_password(PASSWORD)
            db.session.add(user)
            db.session.flush()
            users[role] = user.id
        domain = BannedDomain(
            domain='example.com',
            reason='test domain',
            banned_by=users['moderator'],
            scan_status='idle',
            last_scan_new_bans=1,
            last_scan_details='{"unresolved": 1, "unresolved_entries": [{"name": "<script>alert(1)</script>", "pubkey": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "error": "<img src=x onerror=alert(1)>"}]}',
        )
        db.session.add(domain)
        db.session.flush()
        ban = BannedPubkey(pubkey=PUBKEY_A, reason='domain', banned_by=users['moderator'])
        db.session.add(ban)
        db.session.flush()
        db.session.add(PubkeyBanSource(
            banned_pubkey_id=ban.id,
            source_type='domain',
            banned_domain_id=domain.id,
            local_name='<svg onload=alert(1)>',
            reason='domain',
            banned_by=users['moderator'],
        ))
        db.session.commit()
        domain_id = domain.id
    yield app_module, flask_app, users, domain_id
    with flask_app.app_context():
        db.session.remove()
        db.drop_all()
    Config.SQLALCHEMY_DATABASE_URI = old_database_uri
    sys.modules.pop('app', None)


def client_for(flask_app, user_id=None):
    client = flask_app.test_client()
    if user_id is not None:
        with client.session_transaction() as session:
            session['_user_id'] = str(user_id)
            session['_fresh'] = True
    return client


def test_domain_details_requires_moderator_and_renders_operations_states(domain_page_app):
    _module, flask_app, users, domain_id = domain_page_app
    assert client_for(flask_app).get(f'/moderation/domain/{domain_id}').status_code == 302
    assert client_for(flask_app, users['viewer']).get(f'/moderation/domain/{domain_id}').status_code == 302

    response = client_for(flask_app, users['moderator']).get(f'/moderation/domain/{domain_id}')
    assert response.status_code == 200
    assert b'Domain ban operations' in response.data
    assert b'data-status="idle"' in response.data
    assert b'<caption class="visually-hidden">' in response.data
    assert b'scope="col"' in response.data
    assert b'aria-live="polite"' in response.data
    assert b'class="domain-summary-grid domain-kpi-strip mb-4"' in response.data
    assert b'domain-results-toolbar compact-toolbar' in response.data
    assert b'class="domain-copy-cell"' in response.data
    assert b'class="btn btn-sm btn-link copy-value"' in response.data
    assert b'title="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' in response.data
    assert b'innerHTML' not in response.data


def test_domain_details_preserves_filters_two_paginations_and_export(domain_page_app):
    _module, flask_app, users, domain_id = domain_page_app
    client = client_for(flask_app, users['admin'])
    query = '<script>' + ('x' * 300)

    response = client.get(
        f'/moderation/domain/{domain_id}',
        query_string={'q': query, 'page': 2, 'unresolved_page': 2, 'per_page': 1},
    )
    export = client.get(f'/moderation/domain/{domain_id}/export.csv')

    assert response.status_code == 200
    assert b'maxlength="256"' in response.data
    assert b'page=1' in response.data
    assert b'unresolved_page=1' in response.data
    assert export.status_code == 200
    assert export.mimetype == 'text/csv'
    assert b'nip05,npub,hex_pubkey' in export.data


def test_domain_details_escapes_database_and_search_values(domain_page_app):
    _module, flask_app, users, domain_id = domain_page_app
    response = client_for(flask_app, users['moderator']).get(
        f'/moderation/domain/{domain_id}',
        query_string={'q': '<script>alert(9)</script>'},
    )

    assert b'<script>alert(9)</script>' not in response.data
    assert b'&lt;script&gt;alert(9)&lt;/script&gt;' in response.data
    assert b'<img src=x onerror=alert(1)>' not in response.data
