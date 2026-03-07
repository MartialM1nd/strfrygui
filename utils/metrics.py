import requests
import time
from collections import deque
from config import Config


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


def fetch_metrics():
    try:
        response = requests.get(
            Config.STRFRY_METRICS_URL,
            timeout=5,
            headers={"Accept": "text/plain"}
        )
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise MetricsError(f"Failed to fetch metrics: {e}")


def parse_metrics(raw_metrics):
    metrics = {
        'client_messages': {},
        'relay_messages': {},
        'events_by_kind': {},
        'connection_info': {}
    }
    
    current_metric = None
    
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
            
            value = line.split('}')[1].strip()
            
            if 'nostr_client_messages_total' in metric_name:
                verb = labels.get('verb', 'unknown')
                metrics['client_messages'][verb] = int(value)
            elif 'nostr_relay_messages_total' in metric_name:
                verb = labels.get('verb', 'unknown')
                metrics['relay_messages'][verb] = int(value)
            elif 'nostr_events_total' in metric_name:
                kind = labels.get('kind', 'unknown')
                metrics['events_by_kind'][kind] = int(value)
        elif line.startswith('nostr_'):
            parts = line.split()
            if len(parts) >= 2:
                metric_name = parts[0]
                value = parts[1]
                
                if 'nostr_client_messages_total' in metric_name:
                    metrics['client_messages']['total'] = int(value)
                elif 'nostr_relay_messages_total' in metric_name:
                    metrics['relay_messages']['total'] = int(value)
                elif 'nostr_events_total' in metric_name:
                    metrics['events_by_kind']['total'] = int(value)
    
    return metrics


def get_metrics():
    raw = fetch_metrics()
    return parse_metrics(raw)


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
        'client_messages_breakdown': metrics['client_messages'],
        'relay_messages_breakdown': metrics['relay_messages'],
        'top_event_kinds': sorted(metrics['events_by_kind'].items(), key=lambda x: x[1], reverse=True),
        'client_rate_history': {verb: list(h) for verb, h in client_histories.items()},
        'relay_rate_history': {verb: list(h) for verb, h in relay_histories.items()},
        'events_rate_history': {kind: list(h) for kind, h in events_histories.items()}
    }
