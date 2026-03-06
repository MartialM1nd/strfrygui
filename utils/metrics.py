import requests
from config import Config


class MetricsError(Exception):
    pass


def fetch_metrics():
    try:
        response = requests.get(Config.STRFRY_METRICS_URL, timeout=5)
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
    metrics = get_metrics()
    
    total_client = sum(metrics['client_messages'].values())
    total_relay = sum(metrics['relay_messages'].values())
    total_events = sum(metrics['events_by_kind'].values())
    
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
        'top_event_kinds': top_kinds
    }
