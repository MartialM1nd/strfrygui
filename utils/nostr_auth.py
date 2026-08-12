import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, or_, update

from models import NostrAuthChallenge, db, utcnow
from utils.nip05 import InvalidNostrEvent, validate_nostr_event
from utils.strfry import npub_to_hex


PUBKEY_PATTERN = re.compile(r'^[0-9a-f]{64}$')
ALLOWED_ACTIONS = {'login', 'bootstrap', 'rotate-current', 'rotate-key'}


class NostrAuthError(ValueError):
    """Raised when a Nostr authentication request is invalid."""


@dataclass(frozen=True)
class VerifiedAuth:
    pubkey: str
    redirect_to: str | None
    payload: dict


def normalize_pubkey(value):
    if not isinstance(value, str):
        raise NostrAuthError('Enter a valid npub or 64-character hex pubkey.')
    normalized = value.strip()
    if normalized.lower().startswith('npub1'):
        try:
            normalized = npub_to_hex(normalized.lower())
        except ValueError as exc:
            raise NostrAuthError('Enter a valid npub or 64-character hex pubkey.') from exc
    normalized = normalized.lower()
    if PUBKEY_PATTERN.fullmatch(normalized) is None:
        raise NostrAuthError('Enter a valid npub or 64-character hex pubkey.')
    return normalized


def canonical_payload(payload):
    if not payload:
        return b''
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')


def issue_challenge(
    action,
    session_token,
    verify_url,
    ttl,
    payload=None,
    redirect_to=None,
    user_id=None,
):
    if action not in ALLOWED_ACTIONS:
        raise NostrAuthError('Invalid authentication action.')
    nonce = secrets.token_urlsafe(32)
    payload_bytes = canonical_payload(payload)
    now = utcnow()
    cleanup_before = now - timedelta(days=1)
    db.session.execute(delete(NostrAuthChallenge).where(or_(
        NostrAuthChallenge.expires_at < cleanup_before,
        NostrAuthChallenge.consumed_at < cleanup_before,
    )))
    challenge = NostrAuthChallenge(
        nonce_hash=_sha256(nonce.encode('utf-8')),
        session_hash=_sha256(session_token.encode('utf-8')),
        action=action,
        user_id=user_id,
        expected_created_at=int(now.timestamp()),
        payload_hash=_sha256(payload_bytes) if payload_bytes else None,
        redirect_to=redirect_to,
        created_at=now,
        expires_at=now + timedelta(seconds=ttl),
    )
    db.session.add(challenge)
    db.session.commit()
    tags = [['u', verify_url], ['method', 'POST'], ['challenge', nonce]]
    if payload_bytes:
        tags.append(['payload', challenge.payload_hash])
    return {
        'event': {
            'kind': 27235,
            'created_at': int(now.timestamp()),
            'content': '',
            'tags': tags,
        },
        'payload': payload_bytes.decode('utf-8') if payload_bytes else '',
    }


def verify_request(
    authorization,
    action,
    session_token,
    verify_url,
    tolerance,
    body=b'',
    user_id=None,
):
    event = _decode_authorization(authorization)
    try:
        validate_nostr_event(event)
    except InvalidNostrEvent as exc:
        raise NostrAuthError('Invalid authentication event.') from exc
    if event['kind'] != 27235 or event['content'] != '':
        raise NostrAuthError('Invalid authentication event.')
    now = utcnow()
    if abs(int(now.timestamp()) - event['created_at']) > tolerance:
        raise NostrAuthError('Authentication event has expired.')
    if _single_tag(event, 'u') != verify_url or _single_tag(event, 'method') != 'POST':
        raise NostrAuthError('Authentication event does not match this request.')
    nonce = _single_tag(event, 'challenge')
    challenge = NostrAuthChallenge.query.filter_by(nonce_hash=_sha256(nonce.encode('utf-8'))).first()
    if not challenge or challenge.action != action:
        raise NostrAuthError('Authentication challenge is invalid or expired.')
    if not hmac.compare_digest(challenge.session_hash, _sha256(session_token.encode('utf-8'))):
        raise NostrAuthError('Authentication challenge is invalid or expired.')
    if challenge.expires_at <= now or challenge.consumed_at is not None:
        raise NostrAuthError('Authentication challenge is invalid or expired.')
    if challenge.user_id != user_id or event['created_at'] != challenge.expected_created_at:
        raise NostrAuthError('Authentication challenge is invalid or expired.')
    payload_hash = _sha256(body) if body else None
    if challenge.payload_hash != payload_hash:
        raise NostrAuthError('Authentication payload does not match the challenge.')
    event_payload = _optional_single_tag(event, 'payload')
    if event_payload != challenge.payload_hash:
        raise NostrAuthError('Authentication payload does not match the event.')
    consumed = db.session.execute(
        update(NostrAuthChallenge)
        .where(
            NostrAuthChallenge.id == challenge.id,
            NostrAuthChallenge.consumed_at.is_(None),
            NostrAuthChallenge.expires_at > now,
        )
        .values(consumed_at=now)
    )
    if consumed.rowcount != 1:
        db.session.rollback()
        raise NostrAuthError('Authentication challenge is invalid or expired.')
    db.session.commit()
    try:
        payload = json.loads(body) if body else {}
    except json.JSONDecodeError as exc:
        raise NostrAuthError('Authentication payload is invalid.') from exc
    return VerifiedAuth(event['pubkey'], challenge.redirect_to, payload)


def _decode_authorization(value):
    if not isinstance(value, str) or not value.startswith('Nostr '):
        raise NostrAuthError('Nostr authorization is required.')
    token = value[6:].strip()
    if not token or len(token) > 16384:
        raise NostrAuthError('Invalid authorization header.')
    try:
        raw = base64.b64decode(token, validate=True)
        event = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NostrAuthError('Invalid authorization header.') from exc
    return event


def _single_tag(event, name):
    values = [tag[1] for tag in event['tags'] if len(tag) == 2 and tag[0] == name]
    if len(values) != 1:
        raise NostrAuthError(f'Authentication event requires one {name} tag.')
    return values[0]


def _optional_single_tag(event, name):
    values = [tag[1] for tag in event['tags'] if len(tag) == 2 and tag[0] == name]
    if len(values) > 1:
        raise NostrAuthError(f'Authentication event allows at most one {name} tag.')
    return values[0] if values else None


def _sha256(value):
    return hashlib.sha256(value).hexdigest()
