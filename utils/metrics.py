import ipaddress
import queue
import socket
import threading
import time
from collections import deque
from urllib.parse import urlsplit

import urllib3

from config import Config
from utils.strfry import get_strfry_uptime


class MetricsError(Exception):
    pass


MAX_HISTORY = 60

client_histories = {}
relay_histories = {}
events_histories = {}

previous_client = {}
previous_relay = {}
previous_events = {}

history_initialized = False
_dns_slots = threading.BoundedSemaphore(4)


def fetch_metrics():
    """Fetch metrics from a pinned loopback address with a bounded response."""
    try:
        parsed = urlsplit(Config.STRFRY_METRICS_URL)
        port = parsed.port
    except ValueError as exc:
        raise MetricsError('Metrics URL is invalid') from exc
    if (
        parsed.scheme not in {'http', 'https'}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise MetricsError('Metrics URL is invalid')
    hostname = parsed.hostname
    port = port or (443 if parsed.scheme == 'https' else 80)
    authority_host = f'[{hostname}]' if ':' in hostname else hostname
    default_port = 443 if parsed.scheme == 'https' else 80
    authority = authority_host if port == default_port else f'{authority_host}:{port}'
    deadline = time.monotonic() + Config.STRFRY_METRICS_TIMEOUT
    addresses = _resolve_loopback_addresses(hostname, port, deadline)
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query

    for address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        response = None
        try:
            timeout = urllib3.Timeout(total=remaining, connect=remaining, read=remaining)
            if parsed.scheme == 'https':
                pool = urllib3.HTTPSConnectionPool(
                    address,
                    port=port,
                    assert_hostname=hostname,
                    server_hostname=hostname,
                    cert_reqs='CERT_REQUIRED',
                    timeout=timeout,
                    retries=False,
                )
            else:
                pool = urllib3.HTTPConnectionPool(
                    address,
                    port=port,
                    timeout=timeout,
                    retries=False,
                )
            response = pool.request(
                'GET',
                path,
                headers={
                    'Host': authority,
                    'Accept': 'text/plain',
                    'Accept-Encoding': 'identity',
                    'User-Agent': 'StrfryGUI/1.0',
                },
                redirect=False,
                preload_content=False,
            )
            if response.status != 200:
                raise MetricsError(f'Metrics endpoint returned HTTP {response.status}')
            encoding = response.headers.get('Content-Encoding', 'identity').lower()
            if encoding not in {'', 'identity'}:
                raise MetricsError('Metrics endpoint returned unsupported encoding')
            content_length = response.headers.get('Content-Length')
            if (
                content_length is not None
                and int(content_length) > Config.STRFRY_METRICS_MAX_RESPONSE_BYTES
            ):
                raise MetricsError('Metrics response is too large')
            body = response.read(Config.STRFRY_METRICS_MAX_RESPONSE_BYTES + 1)
            if len(body) > Config.STRFRY_METRICS_MAX_RESPONSE_BYTES:
                raise MetricsError('Metrics response is too large')
            return body.decode('utf-8')
        except MetricsError:
            raise
        except (OSError, ValueError, UnicodeError, urllib3.exceptions.HTTPError):
            continue
        finally:
            if response is not None:
                response.release_conn()
    raise MetricsError('Failed to fetch metrics')


def _resolve_loopback_addresses(hostname, port, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not _dns_slots.acquire(timeout=remaining):
        raise MetricsError('Metrics hostname resolution timed out')
    results = queue.Queue(maxsize=1)

    def resolve():
        try:
            results.put((True, socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)))
        except OSError as exc:
            results.put((False, exc))
        finally:
            _dns_slots.release()

    threading.Thread(target=resolve, daemon=True, name='metrics-dns').start()
    try:
        succeeded, resolved = results.get(timeout=max(0.1, deadline - time.monotonic()))
    except queue.Empty as exc:
        raise MetricsError('Metrics hostname resolution timed out') from exc
    if not succeeded:
        raise MetricsError('Metrics hostname could not be resolved') from resolved
    addresses = []
    for result in resolved:
        address = result[4][0]
        if not ipaddress.ip_address(address).is_loopback:
            raise MetricsError('Metrics endpoint must resolve only to loopback addresses')
        if address not in addresses:
            addresses.append(address)
        if len(addresses) > Config.STRFRY_METRICS_MAX_ADDRESSES:
            raise MetricsError('Metrics hostname resolves to too many addresses')
    if not addresses:
        raise MetricsError('Metrics hostname could not be resolved')
    return addresses


def parse_metrics(raw_metrics):
    metrics = {
        'client_messages': {},
        'relay_messages': {},
        'events_by_kind': {},
        'counters': {},
        'gauges': {},
    }

    scalar_counters = {
        'strfry_write_events_total',
        'strfry_write_rejected_total',
        'strfry_write_dups_total',
        'strfry_write_time_microseconds_total',
        'strfry_slow_client_terminations_total',
        'strfry_auth_challenges_sent_total',
        'strfry_auth_success_total',
        'strfry_auth_failure_total',
    }
    scalar_gauges = {
        'strfry_write_batch_size',
        'strfry_connections_current',
        'strfry_authenticated_connections_current',
    }
    
    for line in raw_metrics.split('\n'):
        line = line.strip()
        
        if not line or line.startswith('#'):
            continue
        
        if '{' in line and '}' in line:
            metric_name = line.split('{')[0]
            labels = {}
            label_str = line.split('{')[1].split('}')[0]
            for label in label_str.split(','):
                if '=' in label:
                    key, value = label.split('=', 1)
                    labels[key.strip()] = value.strip().strip('"')
            
            value = line.split('}')[1].strip().split()[0]
            
            if 'nostr_client_messages_total' in metric_name:
                verb = labels.get('verb', 'unknown')
                metrics['client_messages'][verb] = int(float(value))
            elif 'nostr_relay_messages_total' in metric_name:
                verb = labels.get('verb', 'unknown')
                metrics['relay_messages'][verb] = int(float(value))
            elif 'nostr_events_total' in metric_name:
                kind = labels.get('kind', 'unknown')
                metrics['events_by_kind'][kind] = int(float(value))
        else:
            parts = line.split()
            if len(parts) >= 2:
                metric_name = parts[0]
                value = parts[1]

                if 'nostr_client_messages_total' in metric_name:
                    metrics['client_messages']['total'] = int(float(value))
                elif 'nostr_relay_messages_total' in metric_name:
                    metrics['relay_messages']['total'] = int(float(value))
                elif 'nostr_events_total' in metric_name:
                    metrics['events_by_kind']['total'] = int(float(value))
                elif metric_name in scalar_counters:
                    metrics['counters'][metric_name] = int(float(value))
                elif metric_name in scalar_gauges:
                    metrics['gauges'][metric_name] = float(value)
    
    return metrics


def get_metrics():
    raw = fetch_metrics()
    try:
        return parse_metrics(raw)
    except (IndexError, TypeError, ValueError) as exc:
        raise MetricsError(f"Failed to parse metrics: {exc}") from exc


def get_summary():
    global history_initialized, client_histories, relay_histories, events_histories
    global previous_client, previous_relay, previous_events
    
    metrics = get_metrics()
    
    total_client = sum(metrics['client_messages'].values())
    total_relay = sum(metrics['relay_messages'].values())
    total_events = sum(metrics['events_by_kind'].values())
    
    current_time = int(time.time())
    
    for verb, count in metrics['client_messages'].items():
        if verb == 'total':
            continue
        if verb not in client_histories:
            client_histories[verb] = deque(maxlen=MAX_HISTORY)
        rate = 0
        if verb in previous_client:
            rate = max(0, count - previous_client[verb])
        client_histories[verb].append((current_time, rate))
        previous_client[verb] = count
    
    for verb, count in metrics['relay_messages'].items():
        if verb == 'total':
            continue
        if verb not in relay_histories:
            relay_histories[verb] = deque(maxlen=MAX_HISTORY)
        rate = 0
        if verb in previous_relay:
            rate = max(0, count - previous_relay[verb])
        relay_histories[verb].append((current_time, rate))
        previous_relay[verb] = count
    
    for kind, count in metrics['events_by_kind'].items():
        if kind not in events_histories:
            events_histories[kind] = deque(maxlen=MAX_HISTORY)
        rate = 0
        if kind in previous_events:
            rate = max(0, count - previous_events[kind])
        events_histories[kind].append((current_time, rate))
        previous_events[kind] = count
    
    history_initialized = True
    
    return {
        'total_client_messages': total_client,
        'total_relay_messages': total_relay,
        'total_events': total_events,
        'strfry_uptime_seconds': get_strfry_uptime(),
        'client_messages_breakdown': metrics['client_messages'],
        'relay_messages_breakdown': metrics['relay_messages'],
        'top_event_kinds': sorted(metrics['events_by_kind'].items(), key=lambda x: x[1], reverse=True),
        'client_rate_history': {verb: list(h) for verb, h in client_histories.items()},
        'relay_rate_history': {verb: list(h) for verb, h in relay_histories.items()},
        'events_rate_history': {kind: list(h) for kind, h in events_histories.items()}
    }
