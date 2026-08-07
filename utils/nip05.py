import ipaddress
import json
import queue
import re
import socket
import threading
import time
from urllib.parse import urlencode

import urllib3

from config import Config


LOCAL_NAME_PATTERN = re.compile(r'^[a-z0-9._-]+$')
PUBKEY_PATTERN = re.compile(r'^[0-9a-f]{64}$')
DOMAIN_LABEL_PATTERN = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
_dns_slots = threading.BoundedSemaphore(4)
_http_slots = threading.BoundedSemaphore(4)


class Nip05VerificationError(Exception):
    """Raised when a NIP-05 endpoint cannot be queried safely."""


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


def resolve_public_addresses(hostname, resolver=None, timeout=None):
    """Resolve a hostname while rejecting any non-public result."""
    try:
        if resolver is None:
            dns_timeout = timeout if timeout is not None else Config.NIP05_HTTP_TIMEOUT
            results = _run_bounded(
                lambda: socket.getaddrinfo(
                    hostname,
                    443,
                    type=socket.SOCK_STREAM,
                ),
                max(0.1, min(dns_timeout, 30)),
                _dns_slots,
                f'Timed out resolving {hostname}',
            )
        else:
            results = resolver(hostname, 443, type=socket.SOCK_STREAM)
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


def fetch_nip05_document(hostname, local_name, deadline=None):
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
    path = '/.well-known/nostr.json?' + urlencode({'name': local_name})
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
                headers={'Host': hostname, 'Accept': 'application/json'},
                redirect=False,
                preload_content=False,
            )
            if response.status != 200:
                continue
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
