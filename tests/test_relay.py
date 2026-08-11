import json
from types import SimpleNamespace

import pytest

import utils.relay as relay
from utils.nip05 import InvalidNostrEvent, Nip05VerificationError
from utils.relay import RelayError, lookup_kind0, normalize_relay_url


PUBKEY = 'a' * 64


@pytest.mark.parametrize(
    ('value', 'expected'),
    [
        (' WSS://Example.COM. ', 'wss://example.com/'),
        ('ws://example.com:80/path?q=One', 'ws://example.com/path?q=One'),
        ('wss://bücher.example:443/a%20b?x=%2F', 'wss://xn--bcher-kva.example/a%20b?x=%2F'),
        ('wss://[2606:4700:4700::1111]:443', 'wss://[2606:4700:4700::1111]/'),
        ('ws://8.8.8.8', 'ws://8.8.8.8/'),
    ],
)
def test_normalize_relay_url_canonicalizes_without_losing_path_or_query(value, expected):
    assert normalize_relay_url(value) == expected


@pytest.mark.parametrize(
    'value',
    [
        None,
        '',
        'https://example.com',
        'wss://',
        'wss://user@example.com',
        'wss://example.com/#fragment',
        'wss://example.com\\@evil.test',
        'wss://example.com/\npath',
        'wss://example.com:0',
        'wss://example.com:65536',
        'wss://example.com/bad%escape',
        'wss://bad_label.example',
        'wss://127.0.0.1',
        'ws://[::1]',
        'wss://' + ('a' * 250) + '.com',
    ],
)
def test_normalize_relay_url_rejects_unsafe_or_malformed_values(value):
    with pytest.raises(RelayError):
        normalize_relay_url(value)


def test_open_public_websocket_pins_address_and_preserves_tls_hostname(monkeypatch):
    calls = {}

    class RawSocket:
        def close(self):
            calls['raw_closed'] = True

    class TlsSocket:
        def close(self):
            calls['tls_closed'] = True

    class Context:
        def wrap_socket(self, raw_socket, server_hostname):
            calls['tls'] = (raw_socket, server_hostname)
            return TlsSocket()

    class FrameBuffer:
        length = None

        def recv_length(self):
            pass

    connection = SimpleNamespace(frame_buffer=FrameBuffer())
    raw_socket = RawSocket()
    monkeypatch.setattr(
        relay,
        'resolve_public_addresses',
        lambda hostname, timeout, port: calls.setdefault('dns', (hostname, port)) and ['8.8.8.8'],
    )
    monkeypatch.setattr(
        relay.socket,
        'create_connection',
        lambda address, timeout: calls.setdefault('socket', address) and raw_socket,
    )
    monkeypatch.setattr(relay.ssl, 'create_default_context', lambda: Context())

    def create_connection(url, **kwargs):
        calls['websocket'] = (url, kwargs)
        return connection

    monkeypatch.setattr(relay.websocket, 'create_connection', create_connection)

    assert relay.open_public_websocket('wss://Example.com:8443/path', 2) is connection
    assert calls['dns'] == ('example.com', 8443)
    assert calls['socket'] == ('8.8.8.8', 8443)
    assert calls['tls'][1] == 'example.com'
    assert calls['websocket'][0] == 'wss://example.com:8443/path'
    assert calls['websocket'][1]['socket'].__class__ is TlsSocket
    assert calls['websocket'][1]['redirect_limit'] == 0
    assert calls['websocket'][1]['suppress_origin'] is True


def test_open_public_websocket_rejects_private_dns_answer_before_socket(monkeypatch):
    monkeypatch.setattr(
        relay,
        'resolve_public_addresses',
        lambda *args, **kwargs: (_ for _ in ()).throw(
            Nip05VerificationError('Non-public address returned for example.com')
        ),
    )
    monkeypatch.setattr(
        relay.socket,
        'create_connection',
        lambda *args, **kwargs: pytest.fail('socket connection must not be attempted'),
    )

    with pytest.raises(RelayError, match='Non-public address'):
        relay.open_public_websocket('wss://example.com', 1)


class Connection:
    def __init__(self, messages):
        self.messages = list(messages)
        self.sent = []
        self.closed = False

    def send(self, message):
        self.sent.append(json.loads(message))

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv_frame(self):
        message = self.messages.pop(0)
        if callable(message):
            message = message(self.sent[0][1])
        return SimpleNamespace(
            opcode=relay.websocket.ABNF.OPCODE_TEXT,
            fin=True,
            data=json.dumps(message).encode('utf-8'),
        )

    def close(self):
        self.closed = True


def test_relay_requires_matching_eose_and_closes_subscription():
    connection = Connection([lambda sub: ['EOSE', sub]])

    assert relay.test_relay(
        'wss://relay.example',
        websocket_opener=lambda url, timeout: connection,
    )
    assert connection.sent[0][0] == 'REQ'
    assert connection.sent[-1] == ['CLOSE', connection.sent[0][1]]
    assert connection.closed


def test_relay_rejects_response_without_eose_and_still_closes():
    connection = Connection([['NOTICE', 'hello'], ['CLOSED', 'other', 'done']])
    connection.messages.extend([['NOTICE', 'noise']] * (relay.MAX_MESSAGES - 2))

    with pytest.raises(RelayError, match='EOSE'):
        relay.test_relay(
            'wss://relay.example',
            websocket_opener=lambda url, timeout: connection,
        )
    assert connection.closed


def test_lookup_kind0_validates_events_and_selects_latest_deterministically(monkeypatch):
    older = event('c' * 64, 10)
    later_high_id = event('f' * 64, 20)
    later_low_id = event('b' * 64, 20)
    forged = event('0' * 64, 30)
    connections = [
        Connection([
            lambda sub: ['EVENT', sub, older],
            lambda sub: ['EVENT', sub, later_high_id],
            lambda sub: ['EOSE', sub],
        ]),
        Connection([
            lambda sub: ['EVENT', sub, forged],
            lambda sub: ['EVENT', sub, later_low_id],
            lambda sub: ['EOSE', sub],
        ]),
    ]

    def validate(candidate):
        if candidate['id'] == forged['id']:
            raise InvalidNostrEvent('forged')
        return candidate

    monkeypatch.setattr(relay, 'validate_nostr_event', validate)

    result = lookup_kind0(
        PUBKEY,
        ['wss://one.example', 'wss://two.example'],
        websocket_opener=lambda url, timeout: connections.pop(0),
    )

    assert result == later_low_id


def test_lookup_kind0_rejects_event_that_fails_real_cryptographic_validation():
    forged = event('0' * 64, 30)
    connection = Connection([
        lambda sub: ['EVENT', sub, forged],
        lambda sub: ['EOSE', sub],
    ])

    assert lookup_kind0(
        PUBKEY,
        'wss://relay.example',
        websocket_opener=lambda url, timeout: connection,
    ) is None


def test_lookup_kind0_does_not_use_events_from_incomplete_subscription(monkeypatch):
    candidate = event('b' * 64, 20)
    connection = Connection([lambda sub: ['EVENT', sub, candidate]])
    connection.messages.extend([['NOTICE', 'noise']] * (relay.MAX_MESSAGES - 1))
    monkeypatch.setattr(relay, 'validate_nostr_event', lambda candidate: candidate)

    assert lookup_kind0(
        PUBKEY,
        'wss://relay.example',
        websocket_opener=lambda url, timeout: connection,
    ) is None


def test_lookup_kind0_rejects_invalid_pubkey_without_network_access():
    with pytest.raises(RelayError, match='Pubkey'):
        lookup_kind0('not-a-pubkey', ['wss://relay.example'])


@pytest.mark.parametrize('timeout', [0, -1, float('inf'), float('nan')])
def test_relay_rejects_unbounded_timeout_values(timeout):
    with pytest.raises(RelayError, match='timeout'):
        relay.test_relay('wss://relay.example', timeout=timeout)


def event(event_id, created_at):
    return {
        'id': event_id,
        'pubkey': PUBKEY,
        'created_at': created_at,
        'kind': 0,
        'tags': [],
        'content': '{}',
        'sig': '1' * 128,
    }
