import json
import os
from datetime import timedelta

from sqlalchemy.exc import IntegrityError

from config import Config, bundled_plugin_available
from models import (
    BannedDomain,
    BannedPubkey,
    DashboardSample,
    EventPurge,
    ModerationReport,
    WoTBuildState,
    WoTPolicy,
    WritePolicyProjection,
    db,
    utcnow,
)
from utils.metrics import MetricsError, get_metrics
from utils.configuration import load_configuration
from utils.strfry import get_strfry_process_info


ACCEPT_COUNTERS = {
    'accepted_off',
    'accepted_monitor',
    'accepted_trusted',
    'accepted_pow',
}
# Non-network bypasses are imports/syncs, not client publish attempts.
REJECT_COUNTERS = {'malformed', 'blocked', 'rate_limited', 'pow_rejected'}
POLICY_REASON_COUNTERS = {
    'blocked': 'Banned pubkey',
    'rate_limited': 'Rate limited',
    'pow_rejected': 'Proof of work',
    'malformed': 'Malformed',
}
SAMPLE_RETENTION_DAYS = 30


def _json_dict(path):
    try:
        with open(path, encoding='utf-8') as input_file:
            value = json.load(input_file)
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _policy_counters(path):
    document = _json_dict(path)
    counters = document.get('counters')
    if not isinstance(counters, dict):
        return False, {}
    return True, {
        key: value
        for key, value in counters.items()
        if isinstance(key, str) and isinstance(value, int) and value >= 0
    }


def database_storage(path):
    """Return allocated database bytes and filesystem capacity without following links."""
    allocated = 0
    pending = [path]
    while pending:
        current = pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    pending.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    file_stat = entry.stat(follow_symlinks=False)
                    allocated += getattr(file_stat, 'st_blocks', 0) * 512
    filesystem = os.statvfs(path)
    return {
        'database_size_bytes': allocated,
        'disk_total_bytes': filesystem.f_blocks * filesystem.f_frsize,
        'disk_free_bytes': filesystem.f_bavail * filesystem.f_frsize,
    }


def _flatten_counters(metrics):
    counters = dict(metrics.get('counters', {}))
    for verb, value in metrics.get('client_messages', {}).items():
        counters[f'client:{verb}'] = value
    for verb, value in metrics.get('relay_messages', {}).items():
        counters[f'relay:{verb}'] = value
    for kind, value in metrics.get('events_by_kind', {}).items():
        counters[f'kind:{kind}'] = value
    return counters


def collect_sample(now=None):
    now = now or utcnow()
    bucket = now.replace(second=0, microsecond=0)
    sample = DashboardSample.query.filter_by(sampled_at=bucket).first()
    if sample is None:
        sample = DashboardSample(sampled_at=bucket)
        db.session.add(sample)
    sample.collected_at = now

    try:
        metrics = get_metrics()
        sample.metrics_available = True
        sample.metrics_error = None
        sample.counters_json = json.dumps(_flatten_counters(metrics), sort_keys=True)
        sample.gauges_json = json.dumps(metrics.get('gauges', {}), sort_keys=True)
    except MetricsError as exc:
        sample.metrics_available = False
        sample.metrics_error = str(exc)

    process_info = get_strfry_process_info()
    sample.uptime_seconds = process_info['uptime_seconds']
    sample.process_count = process_info['process_count']
    try:
        storage = database_storage(Config.STRFRY_DB_PATH)
    except OSError:
        storage = {
            'database_size_bytes': None,
            'disk_total_bytes': None,
            'disk_free_bytes': None,
        }
    for key, value in storage.items():
        setattr(sample, key, value)
    sample.policy_available, policy_counters = _policy_counters(
        Config.TRUST_POLICY_STATS_FILE
    )
    sample.policy_counters_json = json.dumps(policy_counters, sort_keys=True)

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return DashboardSample.query.filter_by(sampled_at=bucket).first()

    cutoff = now - timedelta(days=SAMPLE_RETENTION_DAYS)
    DashboardSample.query.filter(DashboardSample.sampled_at < cutoff).delete(
        synchronize_session=False
    )
    db.session.commit()
    return sample


def _counter_delta(samples, getter, names):
    total = 0
    previous = None
    for sample in samples:
        values = getter(sample)
        current = sum(values.get(name, 0) for name in names)
        if previous is not None:
            total += current - previous if current >= previous else current
        previous = current
    return total


def _optional_counter_delta(samples, getter, names):
    relevant_samples = [
        sample
        for sample in samples
        if any(name in getter(sample) for name in names)
    ]
    if not relevant_samples:
        return None
    return _counter_delta(relevant_samples, getter, names)


def _counter_breakdown(samples, prefix):
    names = sorted({
        name
        for sample in samples
        for name in sample.counters
        if name.startswith(prefix)
    })
    return {
        name.removeprefix(prefix): _optional_counter_delta(
            samples, lambda item: item.counters, {name}
        )
        for name in names
    }


def _hourly_series(samples, now):
    buckets = {}
    start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
    for index in range(24):
        timestamp = start + timedelta(hours=index)
        buckets[timestamp] = {
            'timestamp': int(timestamp.timestamp()),
            'accepted': None,
            'rejected': None,
            'connections_sum': 0,
            'connections_count': 0,
            'connections_peak': None,
        }

    previous_policy = None
    for sample in samples:
        hour = sample.sampled_at.replace(minute=0, second=0, microsecond=0)
        if sample.policy_available:
            current_accepted = sum(
                sample.policy_counters.get(name, 0) for name in ACCEPT_COUNTERS
            )
            current_rejected = sum(
                sample.policy_counters.get(name, 0) for name in REJECT_COUNTERS
            )
            if previous_policy is not None and hour in buckets:
                accepted_delta = (
                    current_accepted - previous_policy[0]
                    if current_accepted >= previous_policy[0]
                    else current_accepted
                )
                rejected_delta = (
                    current_rejected - previous_policy[1]
                    if current_rejected >= previous_policy[1]
                    else current_rejected
                )
                buckets[hour]['accepted'] = (buckets[hour]['accepted'] or 0) + accepted_delta
                buckets[hour]['rejected'] = (buckets[hour]['rejected'] or 0) + rejected_delta
            previous_policy = (current_accepted, current_rejected)
        else:
            previous_policy = None

        connections = sample.gauges.get('strfry_connections_current')
        if hour in buckets and isinstance(connections, (int, float)):
            buckets[hour]['connections_sum'] += connections
            buckets[hour]['connections_count'] += 1
            peak = buckets[hour]['connections_peak']
            buckets[hour]['connections_peak'] = connections if peak is None else max(peak, connections)

    output = []
    for bucket in buckets.values():
        count = bucket.pop('connections_count')
        total = bucket.pop('connections_sum')
        bucket['connections_average'] = round(total / count, 1) if count else None
        output.append(bucket)
    return output


def _attention_items(latest, now, role):
    items = []
    if latest is None or not latest.metrics_available:
        items.append({'severity': 'danger', 'label': 'Relay metrics unavailable', 'url': '/connections'})
    elif now - latest.collected_at > timedelta(minutes=2):
        items.append({'severity': 'warning', 'label': 'Relay metrics are stale', 'url': '/connections'})

    if role == 'admin' and latest and latest.disk_total_bytes and latest.disk_free_bytes is not None:
        free_ratio = latest.disk_free_bytes / latest.disk_total_bytes
        if free_ratio < 0.05:
            items.append({'severity': 'danger', 'label': 'Database disk is critically low', 'url': '/db'})
        elif free_ratio < 0.15:
            items.append({'severity': 'warning', 'label': 'Database disk is running low', 'url': '/db'})

    if role in ('admin', 'moderator'):
        if latest and not latest.policy_available:
            items.append({
                'severity': 'warning',
                'label': 'Write-policy telemetry unavailable',
                'url': '/plugins' if role == 'admin' else '/policy-log',
            })
        projection = db.session.get(WritePolicyProjection, 1)
        if projection and projection.status == 'pending':
            items.append({
                'severity': 'danger',
                'label': 'Ban projection publication is pending',
                'url': '/moderation',
            })
        failed_purges = EventPurge.query.filter(
            EventPurge.status == 'pending',
            EventPurge.attempts > 0,
        ).count()
        if failed_purges:
            items.append({'severity': 'warning', 'label': f'{failed_purges} event purges need attention', 'url': '/moderation'})
        failed_domains = BannedDomain.query.filter(
            BannedDomain.scan_status == 'idle',
            BannedDomain.last_scan_error.isnot(None),
        ).count()
        if failed_domains:
            items.append({'severity': 'warning', 'label': f'{failed_domains} domain scans need review', 'url': '/moderation'})
    if role == 'admin':
        snapshot = load_configuration(Config.STRFRY_CONFIG)
        configured_path = (
            snapshot.values.get('relay', {}).get('writePolicy', {}).get('plugin', '')
        )
        if snapshot.revision is None:
            items.append({
                'severity': 'warning',
                'label': 'Write-policy configuration is unavailable',
                'url': '/plugins',
            })
        elif not configured_path:
            items.append({
                'severity': 'warning',
                'label': 'Write-policy plugin is disabled',
                'url': '/plugins',
            })
        elif (
            not isinstance(configured_path, str)
            or configured_path != Config.BLOCKLIST_PLUGIN_PATH
            or not bundled_plugin_available(Config.BLOCKLIST_PLUGIN_PATH)
        ):
            items.append({
                'severity': 'danger',
                'label': 'Configured write-policy plugin is unsupported or unsafe',
                'url': '/plugins',
            })
        wot_state = db.session.get(WoTBuildState, 1)
        if wot_state and wot_state.status == 'failed':
            items.append({'severity': 'warning', 'label': 'Web-of-trust build failed', 'url': '/plugins'})
        wot_policy = db.session.get(WoTPolicy, 1)
        if (
            wot_policy
            and wot_policy.mode == 'enforce'
            and wot_state
            and wot_state.generated_at
            and now - wot_state.generated_at > timedelta(
                minutes=max(60, wot_policy.refresh_interval_minutes * 3)
            )
        ):
            items.append({'severity': 'danger', 'label': 'Enforced trust policy is stale', 'url': '/plugins'})
    return items


def _recent_samples(now):
    cutoff = now - timedelta(hours=24)
    baseline = DashboardSample.query.filter(
        DashboardSample.sampled_at < cutoff,
        DashboardSample.sampled_at >= cutoff - timedelta(minutes=5),
    ).order_by(DashboardSample.sampled_at.desc()).first()
    samples = DashboardSample.query.filter(
        DashboardSample.sampled_at >= cutoff
    ).order_by(DashboardSample.sampled_at).all()
    if baseline is not None:
        samples.insert(0, baseline)
    return cutoff, samples


def connection_summary(now=None):
    now = now or utcnow()
    cutoff, samples = _recent_samples(now)
    latest = samples[-1] if samples else None
    metric_samples = [sample for sample in samples if sample.metrics_available]
    stale = bool(latest and now - latest.collected_at > timedelta(minutes=2))
    current_total = (
        latest.gauges.get('strfry_connections_current')
        if latest and latest.metrics_available
        else None
    )
    current_authenticated = (
        latest.gauges.get('strfry_authenticated_connections_current')
        if latest and latest.metrics_available
        else None
    )
    current_anonymous = (
        max(0, current_total - current_authenticated)
        if current_total is not None and current_authenticated is not None
        else None
    )
    connection_values = [
        sample.gauges['strfry_connections_current']
        for sample in metric_samples
        if sample.sampled_at >= cutoff
        and isinstance(sample.gauges.get('strfry_connections_current'), (int, float))
    ]
    coverage_hours = (
        min(24, round((now - metric_samples[0].sampled_at).total_seconds() / 3600, 1))
        if metric_samples else 0
    )
    def counter(name):
        return _optional_counter_delta(
            metric_samples, lambda item: item.counters, {name}
        )
    hourly = _hourly_series(samples, now)
    status = (
        'unavailable' if latest is None or not latest.metrics_available
        else 'stale' if stale
        else 'limited' if current_total is None
        else 'live'
    )
    return {
        'collected_at': latest.collected_at.isoformat() + 'Z' if latest else None,
        'available': bool(latest and latest.metrics_available),
        'status': status,
        'error': latest.metrics_error if latest else 'No telemetry samples available',
        'coverage_hours': coverage_hours,
        'current': {
            'total': current_total,
            'authenticated': current_authenticated,
            'anonymous': current_anonymous,
        },
        'average_24h': (
            round(sum(connection_values) / len(connection_values), 1)
            if connection_values else None
        ),
        'peak_24h': max(connection_values) if connection_values else None,
        'authentication_24h': {
            'challenges': counter('strfry_auth_challenges_sent_total'),
            'successes': counter('strfry_auth_success_total'),
            'failures': counter('strfry_auth_failure_total'),
        },
        'slow_client_terminations_24h': counter(
            'strfry_slow_client_terminations_total'
        ),
        'incoming_24h': _counter_breakdown(metric_samples, 'client:'),
        'outgoing_24h': _counter_breakdown(metric_samples, 'relay:'),
        'history': [
            {
                'timestamp': point['timestamp'],
                'average': point['connections_average'],
                'peak': point['connections_peak'],
            }
            for point in hourly
        ],
    }


def dashboard_summary(now=None, role='viewer'):
    now = now or utcnow()
    cutoff, samples = _recent_samples(now)
    latest = samples[-1] if samples else None

    policy_samples = [sample for sample in samples if sample.policy_available]
    metric_samples = [sample for sample in samples if sample.metrics_available]
    policy_available = bool(policy_samples)
    policy_coverage_hours = (
        min(24, round((now - policy_samples[0].sampled_at).total_seconds() / 3600, 1))
        if policy_samples else 0
    )
    metric_coverage_hours = (
        min(24, round((now - metric_samples[0].sampled_at).total_seconds() / 3600, 1))
        if metric_samples else 0
    )
    accepted = _counter_delta(policy_samples, lambda item: item.policy_counters, ACCEPT_COUNTERS) if policy_available else None
    rejected = _counter_delta(policy_samples, lambda item: item.policy_counters, REJECT_COUNTERS) if policy_available else None
    decisions = (accepted + rejected) if policy_available else 0
    current_connections = latest.gauges.get('strfry_connections_current') if latest else None
    connection_values = [
        item.gauges.get('strfry_connections_current')
        for item in metric_samples
        if item.sampled_at >= cutoff
        if isinstance(item.gauges.get('strfry_connections_current'), (int, float))
    ]
    storage_baseline = next(
        (
            item.database_size_bytes
            for item in samples
            if item.database_size_bytes is not None
            and item.sampled_at <= cutoff + timedelta(minutes=5)
        ),
        None,
    )
    disk_used_percent = None
    if latest and latest.disk_total_bytes and latest.disk_free_bytes is not None:
        disk_used_percent = round(
            (latest.disk_total_bytes - latest.disk_free_bytes) * 100 / latest.disk_total_bytes,
            1,
        )

    summary = {
        'collected_at': latest.collected_at.isoformat() + 'Z' if latest else None,
        'relay': {
            'status': (
                'offline' if latest is None or (
                    not latest.metrics_available and latest.process_count == 0
                )
                else 'degraded' if not latest.metrics_available
                else 'stale' if now - latest.collected_at > timedelta(minutes=2)
                else 'healthy'
            ),
            'error': latest.metrics_error if latest else 'No telemetry samples available',
            'uptime_seconds': latest.uptime_seconds if latest else None,
            'process_count': latest.process_count if latest else None,
        },
        'storage': {
            'database_size_bytes': latest.database_size_bytes if latest else None,
            'growth_bytes_24h': (
                latest.database_size_bytes - storage_baseline
                if latest and latest.database_size_bytes is not None and storage_baseline is not None
                else None
            ),
            'disk_free_bytes': latest.disk_free_bytes if latest else None,
            'disk_total_bytes': latest.disk_total_bytes if latest else None,
            'disk_used_percent': disk_used_percent,
        },
        'connections': {
            'current': current_connections,
            'peak_24h': max(connection_values) if connection_values else None,
        },
        'admission': {
            'available': policy_available,
            'coverage_hours': policy_coverage_hours,
            'accepted_24h': accepted,
            'rejected_24h': rejected,
            'accepted_percent': round(accepted * 100 / decisions, 1) if decisions else None,
            'reasons': {
                label: _counter_delta(policy_samples, lambda item: item.policy_counters, {name})
                for name, label in POLICY_REASON_COUNTERS.items()
            } if policy_available else {},
        },
        'activity': {
            'coverage_hours': metric_coverage_hours,
            'publish_attempts_24h': _optional_counter_delta(metric_samples, lambda item: item.counters, {'client:EVENT'}),
            'subscriptions_24h': _optional_counter_delta(metric_samples, lambda item: item.counters, {'client:REQ'}),
            'persisted_24h': _optional_counter_delta(metric_samples, lambda item: item.counters, {'strfry_write_events_total'}),
        },
        'history': _hourly_series(samples, now),
    }

    if role in ('admin', 'moderator'):
        summary['moderation'] = {
            'unreviewed_reports': ModerationReport.query.filter_by(reviewed=False).count(),
            'new_reports_24h': ModerationReport.query.filter(ModerationReport.created_at >= cutoff).count(),
            'banned_pubkeys': BannedPubkey.query.count(),
            'banned_domains': BannedDomain.query.count(),
            'new_pubkey_bans_24h': BannedPubkey.query.filter(BannedPubkey.banned_at >= cutoff).count(),
        }
        summary['attention'] = _attention_items(latest, now, role)
    else:
        summary['attention'] = _attention_items(latest, now, role)
    return summary
