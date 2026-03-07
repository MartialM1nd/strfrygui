import requests
import time
from collections import deque
from config import Config


class MetricsError(Exception):
    pass


events_history = deque(maxlen=20)
client_history = deque(maxlen=20)
relay_history = deque(maxlen=20)
previous_total_events = None
previous_total_client = None
previous_total_relay = None
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
    global previous_total_events, previous_total_client, previous_total_relay, history_initialized
    
    metrics = get_metrics()
    
    total_client = sum(metrics['client_messages'].values())
    total_relay = sum(metrics['relay_messages'].values())
    total_events = sum(metrics['events_by_kind'].values())
    
    current_time = int(time.time())
    events_rate = 0
    client_rate = 0
    relay_rate = 0
    
    if previous_total_events is not None:
        events_rate = max(0, total_events - previous_total_events)
    if previous_total_client is not None:
        client_rate = max(0, total_client - previous_total_client)
    if previous_total_relay is not None:
        relay_rate = max(0, total_relay - previous_total_relay)
    
    events_history.append((current_time, events_rate))
    client_history.append((current_time, client_rate))
    relay_history.append((current_time, relay_rate))
    
    previous_total_events = total_events
    previous_total_client = total_client
    previous_total_relay = total_relay
    history_initialized = True
    
    top_kinds = sorted(
        metrics['events_by_kind'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]
    
    return {
        'total_client_messages': total_client,
        'total_relay_messages': total_relay,
        'total_events': total_events,
        'client_messages_breakdown': metrics['client_messages'],
        'relay_messages_breakdown': metrics['relay_messages'],
        'top_event_kinds': top_kinds,
        'events_rate_history': list(events_history),
        'client_rate_history': list(client_history),
        'relay_rate_history': list(relay_history)
    }
