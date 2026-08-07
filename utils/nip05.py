import hashlib
import hmac
import ipaddress
import json
import queue
import re
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlencode
from urllib.parse import urlparse

import urllib3
import websocket

from config import Config


LOCAL_NAME_PATTERN = re.compile(r'^[a-z0-9._-]+$')
PUBKEY_PATTERN = re.compile(r'^[0-9a-f]{64}$')
DOMAIN_LABEL_PATTERN = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
_dns_slots = threading.BoundedSemaphore(4)
_http_slots = threading.BoundedSemaphore(4)


class Nip05VerificationError(Exception):
    """Raised when a NIP-05 endpoint cannot be queried safely."""


class InvalidNostrEvent(ValueError):
    """Raised when an event fails NIP-01 structure, ID, or signature validation."""


@dataclass(frozen=True)
class Nip05Directory:
    names: dict[str, str]
    relays: dict[str, tuple[str, ...]]
    invalid_entries: int = 0


@dataclass(frozen=True)
class ProfileClaimResult:
    verified: bool
    source: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class RelayLookupResult:
    events: tuple[tuple[dict, str], ...]
    errors: tuple[str, ...] = ()


def normalize_domain(value):
    """Return a canonical ASCII hostname suitable for a domain ban."""
    if not isinstance(value, str):
        raise ValueError('Domain is required')
    domain = value.strip().rstrip('.')
    if not domain or any(character in domain for character in '/:@?#'):
        raise ValueError('Enter a domain without a scheme, path, port, or user')

    try:
        domain = domain.encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise ValueError('Invalid domain') from exc

    if len(domain) > 253:
        raise ValueError('Domain is too long')
    labels = domain.split('.')
    if any(not DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels):
        raise ValueError('Invalid domain')
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError('IP addresses cannot be banned as NIP-05 domains')


def domain_matches(candidate, blocked_domain):
    return candidate == blocked_domain or candidate.endswith('.' + blocked_domain)


def find_domain_candidates(events, blocked_domain):
    """Find NIP-05 claims from each pubkey's latest scanned kind-0 event."""
    latest_by_pubkey = {}
    for event in events:
        if event.get('kind') != 0:
            continue
        pubkey = event.get('pubkey')
        if not isinstance(pubkey, str) or not PUBKEY_PATTERN.fullmatch(pubkey):
            continue
        current = latest_by_pubkey.get(pubkey)
        event_created_at = _created_at(event)
        current_created_at = _created_at(current) if current else None
        if (
            current is None
            or event_created_at > current_created_at
            or (
                event_created_at == current_created_at
                and _event_id(event) < _event_id(current)
            )
        ):
            latest_by_pubkey[pubkey] = event

    candidates = []
    for pubkey, event in latest_by_pubkey.items():
        try:
            content = json.loads(event.get('content', ''))
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(content, dict):
            continue
        identifier = content.get('nip05')
        if not isinstance(identifier, str) or identifier.count('@') != 1:
            continue
        local_name, claimed_domain = identifier.split('@')
        if not LOCAL_NAME_PATTERN.fullmatch(local_name):
            continue
        try:
            claimed_domain = normalize_domain(claimed_domain)
        except ValueError:
            continue
        if domain_matches(claimed_domain, blocked_domain):
            candidates.append((local_name, claimed_domain, pubkey))

    return sorted(candidates)


def _event_id(event):
    event_id = event.get('id')
    return event_id if isinstance(event_id, str) and PUBKEY_PATTERN.fullmatch(event_id) else 'f' * 64


def _created_at(event):
    created_at = event.get('created_at', 0)
    return created_at if isinstance(created_at, int) else 0


def resolve_public_addresses(hostname, resolver=None, timeout=None, port=443):
    """Resolve a hostname while rejecting any non-public result."""
    try:
        if resolver is None:
            dns_timeout = timeout if timeout is not None else Config.NIP05_HTTP_TIMEOUT
            results = _run_bounded(
                lambda: socket.getaddrinfo(
                    hostname,
                    port,
                    type=socket.SOCK_STREAM,
                ),
                max(0.1, min(dns_timeout, 30)),
                _dns_slots,
                f'Timed out resolving {hostname}',
            )
        else:
            results = resolver(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise Nip05VerificationError(f'Unable to resolve {hostname}') from exc

    addresses = []
    for result in results:
        address = result[4][0].split('%', 1)[0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise Nip05VerificationError(f'Invalid address returned for {hostname}') from exc
        if not parsed.is_global:
            raise Nip05VerificationError(f'Non-public address returned for {hostname}')
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise Nip05VerificationError(f'No addresses returned for {hostname}')
    address_limit = max(1, min(Config.NIP05_MAX_ADDRESSES, 16))
    return addresses[:address_limit]


def fetch_nip05_document(hostname, local_name=None, deadline=None):
    """Fetch a NIP-05 document using only pre-resolved public addresses."""
    http_timeout = max(0.1, min(Config.NIP05_HTTP_TIMEOUT, 30))
    if deadline is None:
        deadline = time.monotonic() + http_timeout
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    return _run_bounded(
        lambda: _fetch_nip05_document(hostname, local_name, deadline, http_timeout),
        remaining,
        _http_slots,
        f'Timed out fetching NIP-05 document from {hostname}',
    )


def _fetch_nip05_document(hostname, local_name, deadline, http_timeout):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    addresses = resolve_public_addresses(hostname, timeout=min(http_timeout, remaining))
    path = '/.well-known/nostr.json'
    if local_name is not None:
        path += '?' + urlencode({'name': local_name})
    response_limit = max(1024, min(Config.NIP05_MAX_RESPONSE_BYTES, 1048576))

    for address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        response = None
        try:
            attempt_timeout = min(http_timeout, remaining)
            pool = urllib3.HTTPSConnectionPool(
                address,
                port=443,
                assert_hostname=hostname,
                server_hostname=hostname,
                cert_reqs='CERT_REQUIRED',
                timeout=urllib3.Timeout(
                    total=remaining,
                    connect=attempt_timeout,
                    read=attempt_timeout,
                ),
                retries=False,
            )
            response = pool.request(
                'GET',
                path,
                headers={
                    'Host': hostname,
                    'Accept': 'application/json',
                    'User-Agent': 'StrfryGUI/1.0',
                },
                redirect=False,
                preload_content=False,
            )
            if response.status != 200:
                raise Nip05VerificationError(
                    f'NIP-05 endpoint returned HTTP {response.status}'
                )
            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) > response_limit:
                raise Nip05VerificationError('NIP-05 response is too large')
            body = response.read(response_limit + 1)
            if len(body) > response_limit:
                raise Nip05VerificationError('NIP-05 response is too large')
            document = json.loads(body.decode('utf-8'))
            return document if isinstance(document, dict) else None
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError, urllib3.exceptions.HTTPError):
            continue
        finally:
            if response is not None:
                response.release_conn()
    return None


def parse_nip05_directory(document, max_names=None):
    if not isinstance(document, dict) or not isinstance(document.get('names'), dict):
        raise Nip05VerificationError('NIP-05 endpoint did not return a names map')
    if not document['names']:
        raise Nip05VerificationError(
            'NIP-05 endpoint does not expose an enumerable names directory'
        )
    max_names = max_names or getattr(Config, 'NIP05_MAX_NAMES', 1000)
    max_names = max(1, min(max_names, 10000))
    if len(document['names']) > max_names:
        raise Nip05VerificationError(
            f'NIP-05 directory exceeds the {max_names}-name safety limit'
        )
    names = {}
    invalid_entries = 0
    for local_name, pubkey in document['names'].items():
        if (
            not isinstance(local_name, str)
            or LOCAL_NAME_PATTERN.fullmatch(local_name) is None
            or not isinstance(pubkey, str)
            or PUBKEY_PATTERN.fullmatch(pubkey) is None
        ):
            invalid_entries += 1
            continue
        names[local_name] = pubkey

    relays = {}
    relay_map = document.get('relays', {})
    if isinstance(relay_map, dict):
        max_relays = max(1, min(getattr(Config, 'NIP05_MAX_RELAYS', 8), 32))
        for pubkey in set(names.values()):
            urls = relay_map.get(pubkey)
            if not isinstance(urls, list):
                continue
            valid_urls = []
            for url in urls:
                if _valid_wss_url(url) and url not in valid_urls:
                    valid_urls.append(url)
                if len(valid_urls) >= max_relays:
                    break
            if valid_urls:
                relays[pubkey] = tuple(valid_urls)
    if not names:
        raise Nip05VerificationError('NIP-05 directory contains no valid name entries')
    return Nip05Directory(names=names, relays=relays, invalid_entries=invalid_entries)


def fetch_nip05_directory(hostname, deadline=None):
    document = fetch_nip05_document(hostname, deadline=deadline)
    if document is None:
        raise Nip05VerificationError('NIP-05 endpoint returned no document')
    return parse_nip05_directory(document)


def _valid_wss_url(value):
    return _valid_websocket_url(value, allow_ws=False)


def _valid_websocket_url(value, allow_ws=False):
    if not isinstance(value, str):
        return False
    try:
        parsed = urlparse(value)
        parsed_port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme in ({'ws', 'wss'} if allow_ws else {'wss'})
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
        and (parsed_port is None or 1 <= parsed_port <= 65535)
    )


def event_claims_nip05(event, local_name, domain, pubkey):
    if event.get('kind') != 0 or event.get('pubkey') != pubkey:
        return False
    try:
        content = json.loads(event.get('content', ''))
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(content, dict):
        return False
    return content.get('nip05') == f'{local_name}@{domain}'


def validate_nostr_event(event, schnorr_verifier=None):
    if not isinstance(event, dict):
        raise InvalidNostrEvent('Event must be an object')
    event_id = event.get('id')
    pubkey = event.get('pubkey')
    signature = event.get('sig')
    created_at = event.get('created_at')
    kind = event.get('kind')
    tags = event.get('tags')
    content = event.get('content')
    if not isinstance(event_id, str) or PUBKEY_PATTERN.fullmatch(event_id) is None:
        raise InvalidNostrEvent('Invalid event ID')
    if not isinstance(pubkey, str) or PUBKEY_PATTERN.fullmatch(pubkey) is None:
        raise InvalidNostrEvent('Invalid event pubkey')
    if not isinstance(signature, str) or re.fullmatch(r'[0-9a-f]{128}', signature) is None:
        raise InvalidNostrEvent('Invalid event signature')
    if not isinstance(created_at, int) or isinstance(created_at, bool):
        raise InvalidNostrEvent('Invalid event timestamp')
    if not isinstance(kind, int) or isinstance(kind, bool) or not 0 <= kind <= 65535:
        raise InvalidNostrEvent('Invalid event kind')
    if not isinstance(content, str):
        raise InvalidNostrEvent('Invalid event content')
    if not isinstance(tags, list) or any(
        not isinstance(tag, list) or any(not isinstance(value, str) for value in tag)
        for tag in tags
    ):
        raise InvalidNostrEvent('Invalid event tags')

    serialized = json.dumps(
        [0, pubkey, created_at, kind, tags, content],
        ensure_ascii=False,
        separators=(',', ':'),
    ).encode('utf-8')
    digest = hashlib.sha256(serialized).digest()
    if not hmac.compare_digest(event_id, digest.hex()):
        raise InvalidNostrEvent('Event ID does not match content')
    verifier = schnorr_verifier or _verify_schnorr
    if not verifier(pubkey, signature, digest):
        raise InvalidNostrEvent('Invalid event signature')
    return event


def _verify_schnorr(pubkey, signature, digest):
    try:
        public_key = bytes.fromhex(pubkey)
        signature_bytes = bytes.fromhex(signature)
        r = int.from_bytes(signature_bytes[:32], 'big')
        s = int.from_bytes(signature_bytes[32:], 'big')
        if r >= _SECP256K1_P or s >= _SECP256K1_N:
            return False
        point = _lift_x(int.from_bytes(public_key, 'big'))
        challenge = int.from_bytes(
            _tagged_hash('BIP0340/challenge', signature_bytes[:32] + public_key + digest),
            'big',
        ) % _SECP256K1_N
        result = _point_add(
            _point_multiply(s, _SECP256K1_G),
            _point_multiply(_SECP256K1_N - challenge, point),
        )
        return result is not None and result[1] % 2 == 0 and result[0] == r
    except (TypeError, ValueError):
        return False


_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _tagged_hash(tag, message):
    tag_hash = hashlib.sha256(tag.encode('ascii')).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def _lift_x(x):
    if x >= _SECP256K1_P:
        raise ValueError('Invalid x-only public key')
    y_squared = (pow(x, 3, _SECP256K1_P) + 7) % _SECP256K1_P
    y = pow(y_squared, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
    if pow(y, 2, _SECP256K1_P) != y_squared:
        raise ValueError('Invalid x-only public key')
    return x, y if y % 2 == 0 else _SECP256K1_P - y


def _point_add(first, second):
    if first is None:
        return second
    if second is None:
        return first
    x1, y1 = first
    x2, y2 = second
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return None
    if first == second:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, _SECP256K1_P)
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, _SECP256K1_P)
    slope %= _SECP256K1_P
    x3 = (slope * slope - x1 - x2) % _SECP256K1_P
    return x3, (slope * (x1 - x3) - y1) % _SECP256K1_P


def _point_multiply(scalar, point):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def lookup_profile_claim(
    local_name,
    domain,
    pubkey,
    relay_hints,
    configured_relays,
    deadline,
    scanner=None,
    relay_lookup=None,
):
    """Find the latest signed kind-0 profile and verify its exact NIP-05 claim."""
    if scanner is None:
        from utils.strfry import StrfryError, scan_events

        scanner = scan_events
        scanner_errors = (StrfryError, ValueError, OSError)
    else:
        scanner_errors = (ValueError, OSError)
    try:
        local_events = scanner(
            {'kinds': [0], 'authors': [pubkey]},
            limit=10,
            timeout=max(1, int(deadline - time.monotonic())),
        )
    except scanner_errors as exc:
        local_events = []
        local_error = str(exc)
    else:
        local_error = None

    candidates = [
        (event, 'local')
        for event in local_events
        if event.get('kind') == 0
        and event.get('pubkey') == pubkey
        and _event_is_valid(event)
    ]
    relay_urls = []
    configured = [
        url for url in configured_relays if _valid_websocket_url(url, allow_ws=True)
    ]
    hinted = [url for url in relay_hints if _valid_wss_url(url)]
    max_relays = max(1, min(getattr(Config, 'NIP05_MAX_RELAYS', 8), 32))
    for index in range(max(len(configured), len(hinted))):
        for candidates_list in (configured, hinted):
            if index < len(candidates_list):
                relay_url = candidates_list[index]
                if relay_url not in relay_urls:
                    relay_urls.append(relay_url)
            if len(relay_urls) >= max_relays:
                break
        if len(relay_urls) >= max_relays:
            break
    relay_lookup = relay_lookup or lookup_external_kind0
    relay_errors = ()
    if relay_urls and time.monotonic() < deadline:
        relay_result = relay_lookup(pubkey, relay_urls, deadline)
        if isinstance(relay_result, RelayLookupResult):
            external_events = relay_result.events
            relay_errors = relay_result.errors
        else:
            external_events = relay_result
        candidates.extend(external_events)

    if not candidates:
        error = 'No kind-0 profile found'
        source_errors = ([local_error] if local_error else []) + list(relay_errors)
        if source_errors:
            error += ': ' + '; '.join(source_errors[:5])
        return ProfileClaimResult(False, error=error)
    event, source = max(
        candidates,
        key=lambda item: (_created_at(item[0]), _reverse_sort_id(_event_id(item[0]))),
    )
    if event_claims_nip05(event, local_name, domain, pubkey):
        return ProfileClaimResult(True, source=source)
    error = 'Latest profile does not claim this NIP-05'
    source_errors = ([local_error] if local_error else []) + list(relay_errors)
    if source_errors:
        error += '; source errors: ' + '; '.join(source_errors[:5])
    return ProfileClaimResult(False, source=source, error=error)


def lookup_external_kind0(pubkey, relay_urls, deadline, websocket_opener=None):
    websocket_opener = websocket_opener or open_public_websocket
    events = []
    errors = []
    max_message_bytes = max(
        1024,
        min(getattr(Config, 'NIP05_MAX_WS_MESSAGE_BYTES', 262144), 1048576),
    )
    for relay_url in relay_urls:
        relay_timeout = max(0.1, min(getattr(Config, 'NIP05_RELAY_TIMEOUT', 3), 30))
        relay_deadline = min(deadline, time.monotonic() + relay_timeout)
        remaining = relay_deadline - time.monotonic()
        if remaining <= 0:
            break
        connection = None
        subscription_id = secrets.token_hex(8)
        try:
            connection = websocket_opener(relay_url, timeout=remaining)
            _limit_websocket_frames(connection, max_message_bytes)
            connection.send(json.dumps([
                'REQ',
                subscription_id,
                {'kinds': [0], 'authors': [pubkey], 'limit': 1},
            ]))
            while time.monotonic() < relay_deadline:
                connection.settimeout(max(0.1, relay_deadline - time.monotonic()))
                frame = connection.recv_frame()
                if frame.opcode == websocket.ABNF.OPCODE_PING:
                    connection.pong(frame.data)
                    continue
                if frame.opcode == websocket.ABNF.OPCODE_CLOSE:
                    break
                if frame.opcode != websocket.ABNF.OPCODE_TEXT or not frame.fin:
                    raise Nip05VerificationError('Relay sent an unsupported WebSocket frame')
                if len(frame.data) > max_message_bytes:
                    break
                message = (
                    frame.data
                    if isinstance(frame.data, str)
                    else frame.data.decode('utf-8')
                )
                payload = json.loads(message)
                if not isinstance(payload, list) or not payload:
                    continue
                if payload[0] == 'EOSE' and len(payload) > 1 and payload[1] == subscription_id:
                    break
                if (
                    payload[0] != 'EVENT'
                    or len(payload) < 3
                    or payload[1] != subscription_id
                    or not isinstance(payload[2], dict)
                ):
                    continue
                event = payload[2]
                if event.get('kind') != 0 or event.get('pubkey') != pubkey:
                    continue
                try:
                    validate_nostr_event(event)
                except InvalidNostrEvent as exc:
                    errors.append(f'{relay_url}: invalid event ({exc})')
                    continue
                events.append((event, relay_url))
        except (
            Nip05VerificationError,
            OSError,
            ValueError,
            json.JSONDecodeError,
            websocket.WebSocketException,
        ) as exc:
            errors.append(f'{relay_url}: {exc}')
            continue
        finally:
            if connection is not None:
                try:
                    connection.send(json.dumps(['CLOSE', subscription_id]))
                except (OSError, websocket.WebSocketException):
                    pass
                try:
                    connection.close()
                except (OSError, websocket.WebSocketException):
                    pass
    return RelayLookupResult(tuple(events), tuple(errors))


def _limit_websocket_frames(connection, max_bytes):
    frame_buffer = getattr(connection, 'frame_buffer', None)
    if frame_buffer is None:
        raise Nip05VerificationError('WebSocket client cannot enforce the frame-size limit')
    original_recv_length = frame_buffer.recv_length

    def recv_length():
        original_recv_length()
        if frame_buffer.length is not None and frame_buffer.length > max_bytes:
            raise Nip05VerificationError('Relay WebSocket frame is too large')

    frame_buffer.recv_length = recv_length


def _event_is_valid(event):
    try:
        validate_nostr_event(event)
        return True
    except InvalidNostrEvent:
        return False


def open_public_websocket(relay_url, timeout):
    parsed = urlparse(relay_url)
    if not _valid_websocket_url(relay_url, allow_ws=True):
        raise Nip05VerificationError('Relay must be a valid ws or wss URL')
    hostname = normalize_domain(parsed.hostname)
    port = parsed.port or (443 if parsed.scheme == 'wss' else 80)
    addresses = resolve_public_addresses(hostname, timeout=timeout, port=port)
    last_error = None
    for address in addresses:
        raw_socket = None
        tls_socket = None
        try:
            raw_socket = socket.create_connection((address, port), timeout=timeout)
            if parsed.scheme == 'wss':
                tls_socket = ssl.create_default_context().wrap_socket(
                    raw_socket,
                    server_hostname=hostname,
                )
            else:
                tls_socket = raw_socket
            return websocket.create_connection(
                relay_url,
                socket=tls_socket,
                timeout=timeout,
                suppress_origin=True,
                redirect_limit=0,
            )
        except (OSError, ssl.SSLError, websocket.WebSocketException) as exc:
            last_error = exc
            if tls_socket is not None:
                tls_socket.close()
            elif raw_socket is not None:
                raw_socket.close()
    raise Nip05VerificationError(f'Unable to connect to relay {relay_url}: {last_error}')


def _reverse_sort_id(event_id):
    return ''.join(chr(255 - ord(character)) for character in event_id)


def _run_bounded(operation, timeout, slots, timeout_message):
    deadline = time.monotonic() + timeout
    if not slots.acquire(timeout=timeout):
        raise Nip05VerificationError(timeout_message)
    result_queue = queue.Queue(maxsize=1)

    def run():
        try:
            result_queue.put((True, operation()))
        except Exception as exc:
            result_queue.put((False, exc))
        finally:
            slots.release()

    threading.Thread(target=run, daemon=True, name='nip05-network').start()
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise queue.Empty
        succeeded, result = result_queue.get(timeout=remaining)
    except queue.Empty as exc:
        raise Nip05VerificationError(timeout_message) from exc
    if succeeded:
        return result
    raise result


def verify_nip05(local_name, domain, pubkey, fetcher=None, deadline=None):
    """Verify that a profile claim maps back to the same pubkey."""
    if not LOCAL_NAME_PATTERN.fullmatch(local_name):
        return False
    if not PUBKEY_PATTERN.fullmatch(pubkey):
        return False
    document = (
        fetcher(domain, local_name)
        if fetcher is not None
        else fetch_nip05_document(domain, local_name, deadline=deadline)
    )
    if not isinstance(document, dict) or not isinstance(document.get('names'), dict):
        return False
    mapped_pubkey = document['names'].get(local_name)
    return (
        isinstance(mapped_pubkey, str)
        and PUBKEY_PATTERN.fullmatch(mapped_pubkey) is not None
        and mapped_pubkey == pubkey
    )
