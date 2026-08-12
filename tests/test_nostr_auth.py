import base64
import json
from datetime import timedelta

import pytest
from flask import Flask

from models import NostrAuthChallenge, db, utcnow
from utils import nostr_auth
from utils.nostr_auth import NostrAuthError, canonical_payload, issue_challenge, normalize_pubkey, verify_request
from utils.strfry import hex_to_npub


PUBKEY = 'a' * 64
VERIFY_URL = 'https://relay-admin.example/api/auth/verify'


@pytest.fixture
def auth_app(tmp_path):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY='test-secret',
        SQLALCHEMY_DATABASE_URI=f'sqlite:///{tmp_path / "auth.db"}',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    db.init_app(app)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def signed_event(template, pubkey=PUBKEY):
    event = {**template, 'id': 'b' * 64, 'pubkey': pubkey, 'sig': 'c' * 128}
    return event


def authorization(event):
    return 'Nostr ' + base64.b64encode(json.dumps(event).encode()).decode()


def test_normalize_pubkey_accepts_hex_and_npub():
    assert normalize_pubkey(PUBKEY.upper()) == PUBKEY
    assert normalize_pubkey(hex_to_npub(PUBKEY)) == PUBKEY
    with pytest.raises(NostrAuthError):
        normalize_pubkey('not-a-pubkey')


def test_challenge_is_hashed_bound_and_consumed_once(auth_app, monkeypatch):
    monkeypatch.setattr(nostr_auth, 'validate_nostr_event', lambda event: event)
    with auth_app.test_request_context('/'):
        result = issue_challenge('login', 'browser-a', VERIFY_URL, 60, redirect_to='/events')
        nonce = next(tag[1] for tag in result['event']['tags'] if tag[0] == 'challenge')
        stored = NostrAuthChallenge.query.one()
        assert stored.nonce_hash != nonce

        verified = verify_request(
            authorization(signed_event(result['event'])),
            'login',
            'browser-a',
            VERIFY_URL,
            60,
        )
        assert verified.pubkey == PUBKEY
        assert verified.redirect_to == '/events'

        with pytest.raises(NostrAuthError, match='invalid or expired'):
            verify_request(
                authorization(signed_event(result['event'])),
                'login',
                'browser-a',
                VERIFY_URL,
                60,
            )


def test_challenge_rejects_other_session_and_wrong_url(auth_app, monkeypatch):
    monkeypatch.setattr(nostr_auth, 'validate_nostr_event', lambda event: event)
    with auth_app.app_context():
        result = issue_challenge('login', 'browser-a', VERIFY_URL, 60)
        event = signed_event(result['event'])
        with pytest.raises(NostrAuthError, match='invalid or expired'):
            verify_request(authorization(event), 'login', 'browser-b', VERIFY_URL, 60)

        event['tags'][0][1] = 'https://attacker.example/api/auth/verify'
        with pytest.raises(NostrAuthError, match='does not match'):
            verify_request(authorization(event), 'login', 'browser-a', VERIFY_URL, 60)


def test_bootstrap_payload_is_canonical_and_bound(auth_app, monkeypatch):
    monkeypatch.setattr(nostr_auth, 'validate_nostr_event', lambda event: event)
    payload = {'username': 'admin', 'registration_token': 'secret'}
    with auth_app.app_context():
        result = issue_challenge('bootstrap', 'browser-a', VERIFY_URL, 60, payload=payload)
        assert result['payload'] == canonical_payload(payload).decode()
        verified = verify_request(
            authorization(signed_event(result['event'])),
            'bootstrap',
            'browser-a',
            VERIFY_URL,
            60,
            body=result['payload'].encode(),
        )
        assert verified.payload == payload


def test_expired_challenge_is_rejected(auth_app, monkeypatch):
    monkeypatch.setattr(nostr_auth, 'validate_nostr_event', lambda event: event)
    with auth_app.app_context():
        result = issue_challenge('login', 'browser-a', VERIFY_URL, 60)
        challenge = NostrAuthChallenge.query.one()
        challenge.expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()
        with pytest.raises(NostrAuthError, match='invalid or expired'):
            verify_request(
                authorization(signed_event(result['event'])),
                'login',
                'browser-a',
                VERIFY_URL,
                60,
            )


def test_challenge_rejects_altered_issued_timestamp(auth_app, monkeypatch):
    monkeypatch.setattr(nostr_auth, 'validate_nostr_event', lambda event: event)
    with auth_app.app_context():
        result = issue_challenge('login', 'browser-a', VERIFY_URL, 60)
        event = signed_event(result['event'])
        event['created_at'] += 1
        with pytest.raises(NostrAuthError, match='invalid or expired'):
            verify_request(
                authorization(event),
                'login',
                'browser-a',
                VERIFY_URL,
                60,
            )


def test_rotation_challenge_is_bound_to_user(auth_app, monkeypatch):
    monkeypatch.setattr(nostr_auth, 'validate_nostr_event', lambda event: event)
    with auth_app.app_context():
        result = issue_challenge(
            'rotate-current',
            'browser-a',
            VERIFY_URL,
            60,
            user_id=10,
        )
        with pytest.raises(NostrAuthError, match='invalid or expired'):
            verify_request(
                authorization(signed_event(result['event'])),
                'rotate-current',
                'browser-a',
                VERIFY_URL,
                60,
                user_id=11,
            )


def test_authorization_header_is_bounded_and_well_formed(auth_app):
    with auth_app.app_context():
        with pytest.raises(NostrAuthError, match='required'):
            verify_request(None, 'login', 'browser-a', VERIFY_URL, 60)
        with pytest.raises(NostrAuthError, match='Invalid authorization'):
            verify_request('Nostr !!!', 'login', 'browser-a', VERIFY_URL, 60)
