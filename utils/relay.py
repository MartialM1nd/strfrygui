import ipaddress
import json
import math
import re
import secrets
import socket
import ssl
import time
from urllib.parse import urlsplit, urlunsplit

import websocket

from utils.nip05 import (
    InvalidNostrEvent,
    Nip05VerificationError,
    resolve_public_addresses,
    validate_nostr_event,
)


MAX_RELAY_URL_LENGTH = 256
MAX_RELAYS = 8
MAX_MESSAGES = 64
MAX_FRAME_BYTES = 262144
MAX_TIMEOUT = 30.0
_HOST_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
_PUBKEY = re.compile(r'^[0-9a-f]{64}$')
_INVALID_PERCENT_ESCAPE = re.compile(r'%(?![0-9a-fA-F]{2})')


class RelayError(ValueError):
    """Raised when a relay URL or protocol exchange is unsafe or invalid."""


def normalize_relay_url(value):
    """Return a canonical ws/wss URL after strict validation."""
    if not isinstance(value, str):
        raise RelayError('Relay URL is required')
    value = value.strip()
    if not value:
        raise RelayError('Relay URL is required')
    if len(value) > MAX_RELAY_URL_LENGTH:
        raise RelayError('Relay URL is too long')
    if '\\' in value or '#' in value or any(
        character.isspace() or ord(character) == 127 for character in value
    ):
        raise RelayError('Relay URL contains invalid characters')

    try:
        parsed = urlsplit(value)
        port = parsed.port
        hostname = parsed.hostname
    except (TypeError, ValueError) as exc:
        raise RelayError('Relay URL is malformed') from exc
    scheme = parsed.scheme.lower()
    if scheme not in {'ws', 'wss'}:
        raise RelayError('Relay URL must use ws or wss')
    if not parsed.netloc or not hostname:
        raise RelayError('Relay URL must include a host')
    if parsed.username is not None or parsed.password is not None:
        raise RelayError('Relay URL must not include credentials')
    if port is not None and not 1 <= port <= 65535:
        raise RelayError('Relay URL has an invalid port')
    if _INVALID_PERCENT_ESCAPE.search(parsed.path) or _INVALID_PERCENT_ESCAPE.search(parsed.query):
        raise RelayError('Relay URL has an invalid percent escape')

    hostname = hostname.rstrip('.')
    if not hostname or '%' in hostname:
        raise RelayError('Relay URL has an invalid host')
    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            hostname = hostname.encode('idna').decode('ascii').lower()
        except UnicodeError as exc:
            raise RelayError('Relay URL has an invalid host') from exc
        if len(hostname) > 253 or any(
            _HOST_LABEL.fullmatch(label) is None for label in hostname.split('.')
        ):
            raise RelayError('Relay URL has an invalid host')
        display_host = hostname
    else:
        if not literal_ip.is_global:
            raise RelayError('Relay IP address must be public')
        hostname = literal_ip.compressed.lower()
        display_host = f'[{hostname}]' if literal_ip.version == 6 else hostname

    default_port = 443 if scheme == 'wss' else 80
    netloc = display_host if port is None or port == default_port else f'{display_host}:{port}'
    normalized = urlunsplit((scheme, netloc, parsed.path or '/', parsed.query, ''))
    if len(normalized) > MAX_RELAY_URL_LENGTH:
        raise RelayError('Relay URL is too long')
    return normalized


def open_public_websocket(relay_url, timeout):
    """Connect to a pre-resolved public address while retaining TLS hostname checks."""
    relay_url = normalize_relay_url(relay_url)
    parsed = urlsplit(relay_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'wss' else 80)
    timeout = _bounded_timeout(timeout)
    deadline = time.monotonic() + timeout
    try:
        addresses = resolve_public_addresses(hostname, timeout=timeout, port=port)
    except Nip05VerificationError as exc:
        raise RelayError(str(exc)) from exc

    last_error = None
    for address in addresses:
        raw_socket = None
        connected_socket = None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            raw_socket = socket.create_connection((address, port), timeout=remaining)
            if parsed.scheme == 'wss':
                connected_socket = ssl.create_default_context().wrap_socket(
                    raw_socket,
                    server_hostname=hostname,
                )
            else:
                connected_socket = raw_socket
            connection = websocket.create_connection(
                relay_url,
                socket=connected_socket,
                timeout=max(0.1, deadline - time.monotonic()),
                suppress_origin=True,
                redirect_limit=0,
            )
            _limit_websocket_frames(connection)
            return connection
        except (OSError, ssl.SSLError, websocket.WebSocketException, RelayError) as exc:
            last_error = exc
            try:
                if connected_socket is not None:
                    connected_socket.close()
                elif raw_socket is not None:
                    raw_socket.close()
            except OSError:
                pass
    detail = f': {last_error}' if last_error else ''
    raise RelayError(f'Unable to connect to relay {relay_url}{detail}')


def test_relay(relay_url, timeout=5, websocket_opener=None):
    """Require a complete, bounded Nostr subscription response from a relay."""
    normalized = normalize_relay_url(relay_url)
    _query_relay(normalized, None, _bounded_timeout(timeout), websocket_opener)
    return True


def lookup_kind0(pubkey, relay_urls, timeout=5, websocket_opener=None):
    """Return the deterministic latest cryptographically valid kind-0 event."""
    if not isinstance(pubkey, str) or _PUBKEY.fullmatch(pubkey) is None:
        raise RelayError('Pubkey must be 64 lowercase hexadecimal characters')
    if isinstance(relay_urls, str):
        relay_urls = [relay_urls]
    try:
        relay_urls = list(relay_urls)
    except TypeError as exc:
        raise RelayError('Relay URLs must be an iterable') from exc
    if not relay_urls:
        return None
    if len(relay_urls) > MAX_RELAYS:
        raise RelayError(f'At most {MAX_RELAYS} relays may be queried')

    normalized_urls = []
    for relay_url in relay_urls:
        normalized = normalize_relay_url(relay_url)
        if normalized not in normalized_urls:
            normalized_urls.append(normalized)

    deadline = time.monotonic() + _bounded_timeout(timeout)
    events = []
    for relay_url in normalized_urls:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            events.extend(_query_relay(relay_url, pubkey, remaining, websocket_opener))
        except RelayError:
            continue
    if not events:
        return None
    return min(events, key=lambda event: (-event['created_at'], event['id']))


def _query_relay(relay_url, pubkey, timeout, websocket_opener):
    opener = websocket_opener or open_public_websocket
    subscription_id = secrets.token_hex(8)
    event_filter = {'kinds': [0], 'limit': 1}
    if pubkey is not None:
        event_filter['authors'] = [pubkey]
    connection = None
    completed = False
    events = []
    deadline = time.monotonic() + _bounded_timeout(timeout)
    try:
        connection = opener(relay_url, timeout=max(0.1, deadline - time.monotonic()))
        connection.send(json.dumps(['REQ', subscription_id, event_filter], separators=(',', ':')))
        for _ in range(MAX_MESSAGES):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RelayError('Relay response timed out')
            connection.settimeout(max(0.1, remaining))
            frame = connection.recv_frame()
            if frame.opcode == websocket.ABNF.OPCODE_PING:
                connection.pong(frame.data)
                continue
            if frame.opcode == websocket.ABNF.OPCODE_CLOSE:
                break
            if frame.opcode != websocket.ABNF.OPCODE_TEXT or not frame.fin:
                raise RelayError('Relay sent an unsupported WebSocket frame')
            data = frame.data.encode('utf-8') if isinstance(frame.data, str) else frame.data
            if not isinstance(data, bytes) or len(data) > MAX_FRAME_BYTES:
                raise RelayError('Relay WebSocket frame is too large')
            try:
                payload = json.loads(data.decode('utf-8'))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RelayError('Relay sent an invalid JSON message') from exc
            if not isinstance(payload, list) or not payload:
                continue
            if payload[0] == 'EOSE' and len(payload) == 2 and payload[1] == subscription_id:
                completed = True
                break
            if (
                pubkey is not None
                and payload[0] == 'EVENT'
                and len(payload) == 3
                and payload[1] == subscription_id
                and isinstance(payload[2], dict)
                and payload[2].get('kind') == 0
                and payload[2].get('pubkey') == pubkey
            ):
                try:
                    validate_nostr_event(payload[2])
                except InvalidNostrEvent:
                    continue
                events.append(payload[2])
        if not completed:
            raise RelayError('Relay did not complete the subscription with EOSE')
        return events
    except (OSError, socket.timeout, websocket.WebSocketException) as exc:
        raise RelayError(f'Relay connection failed: {exc}') from exc
    finally:
        if connection is not None:
            try:
                connection.send(json.dumps(['CLOSE', subscription_id], separators=(',', ':')))
            except (OSError, websocket.WebSocketException):
                pass
            try:
                connection.close()
            except (OSError, websocket.WebSocketException):
                pass


def _limit_websocket_frames(connection):
    frame_buffer = getattr(connection, 'frame_buffer', None)
    if frame_buffer is None or not callable(getattr(frame_buffer, 'recv_length', None)):
        raise RelayError('WebSocket client cannot enforce the frame-size limit')
    original_recv_length = frame_buffer.recv_length

    def recv_length():
        original_recv_length()
        if frame_buffer.length is not None and frame_buffer.length > MAX_FRAME_BYTES:
            raise RelayError('Relay WebSocket frame is too large')

    frame_buffer.recv_length = recv_length


def _bounded_timeout(timeout):
    try:
        timeout = float(timeout)
    except (TypeError, ValueError) as exc:
        raise RelayError('Relay timeout must be a number') from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise RelayError('Relay timeout must be positive')
    return min(timeout, MAX_TIMEOUT)
