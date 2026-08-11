import json
from datetime import timedelta

from config import Config
from models import BannedPubkey, DashboardSample, ModerationReport, db, utcnow
from utils.dashboard import connection_summary, dashboard_summary, database_storage
from utils.metrics import parse_metrics


def add_sample(sampled_at, policy=None, counters=None, gauges=None, db_size=100):
    sample = DashboardSample(
        sampled_at=sampled_at,
        collected_at=sampled_at,
        metrics_available=True,
        policy_available=True,
        database_size_bytes=db_size,
        disk_total_bytes=1000,
        disk_free_bytes=400,
        counters_json=json.dumps(counters or {}),
        gauges_json=json.dumps(gauges or {}),
        policy_counters_json=json.dumps(policy or {}),
    )
    db.session.add(sample)
    return sample


def test_database_storage_uses_allocated_bytes(tmp_path):
    nested = tmp_path / 'nested'
    nested.mkdir()
    (tmp_path / 'data.mdb').write_bytes(b'x' * 8192)
    (nested / 'lock.mdb').write_bytes(b'x' * 100)

    result = database_storage(str(tmp_path))

    assert result['database_size_bytes'] >= 8192
    assert result['disk_total_bytes'] > result['disk_free_bytes']


def test_parse_metrics_supports_current_strfry_operational_metrics():
    metrics = parse_metrics('''
nostr_client_messages_total{verb="EVENT"} 42
nostr_events_total{kind="1"} 30
strfry_write_events_total 30
strfry_write_rejected_total 4
strfry_connections_current 7
strfry_authenticated_connections_current 2
''')

    assert metrics['client_messages'] == {'EVENT': 42}
    assert metrics['events_by_kind'] == {'1': 30}
    assert metrics['counters']['strfry_write_events_total'] == 30
    assert metrics['counters']['strfry_write_rejected_total'] == 4
    assert metrics['gauges']['strfry_connections_current'] == 7


def test_dashboard_summary_handles_counter_resets_and_moderation(app):
    now = utcnow().replace(second=0, microsecond=0)
    with app.app_context():
        add_sample(
            now - timedelta(hours=24),
            policy={'accepted_off': 90, 'blocked': 10},
            counters={'client:EVENT': 180, 'client:REQ': 30},
            gauges={'strfry_connections_current': 4},
            db_size=100,
        )
        add_sample(
            now - timedelta(hours=12),
            policy={'accepted_off': 100, 'blocked': 12},
            counters={'client:EVENT': 200, 'client:REQ': 40},
            gauges={'strfry_connections_current': 9},
            db_size=140,
        )
        add_sample(
            now,
            policy={'accepted_off': 5, 'blocked': 1},
            counters={'client:EVENT': 8, 'client:REQ': 3},
            gauges={'strfry_connections_current': 6},
            db_size=150,
        )
        db.session.add(ModerationReport(event_id='a', reviewed=False, created_at=now))
        db.session.add(BannedPubkey(pubkey='b' * 64, banned_at=now))
        db.session.commit()

        summary = dashboard_summary(now, role='admin')

    assert summary['admission'] == {
        'available': True,
        'coverage_hours': 24,
        'accepted_24h': 15,
        'rejected_24h': 3,
        'accepted_percent': 83.3,
        'reasons': {
            'Banned pubkey': 3,
            'Rate limited': 0,
            'Proof of work': 0,
            'Malformed': 0,
        },
    }
    assert summary['connections'] == {'current': 6, 'peak_24h': 9}
    assert summary['storage']['growth_bytes_24h'] == 50
    assert summary['activity']['publish_attempts_24h'] == 28
    assert summary['moderation']['unreviewed_reports'] == 1
    assert summary['moderation']['banned_pubkeys'] == 1


def test_dashboard_summary_does_not_expose_moderation_to_viewers(app):
    now = utcnow().replace(second=0, microsecond=0)
    with app.app_context():
        add_sample(now, gauges={'strfry_connections_current': 1})
        db.session.commit()

        summary = dashboard_summary(now, role='viewer')

    assert 'moderation' not in summary
    assert all(item['url'] == '/connections' for item in summary['attention'])


def test_dashboard_summary_skips_unavailable_counter_gaps(app):
    now = utcnow().replace(second=0, microsecond=0)
    with app.app_context():
        add_sample(now - timedelta(minutes=2), policy={'accepted_off': 100})
        gap = add_sample(now - timedelta(minutes=1))
        gap.metrics_available = False
        gap.policy_available = False
        add_sample(now, policy={'accepted_off': 110})
        db.session.commit()

        summary = dashboard_summary(now)

    assert summary['admission']['accepted_24h'] == 10


def test_dashboard_summary_marks_policy_telemetry_unavailable(app):
    now = utcnow().replace(second=0, microsecond=0)
    with app.app_context():
        sample = add_sample(now)
        sample.policy_available = False
        db.session.commit()

        summary = dashboard_summary(now)

    assert summary['admission']['available'] is False
    assert summary['admission']['coverage_hours'] == 0
    assert summary['admission']['accepted_24h'] is None
    assert summary['admission']['rejected_24h'] is None
    assert summary['admission']['reasons'] == {}


def test_dashboard_attention_reports_configured_plugin_state(monkeypatch, tmp_path, app):
    now = utcnow().replace(second=0, microsecond=0)
    plugin = tmp_path / 'custom-policy'
    plugin.write_text('#!/bin/sh\nexit 0\n')
    plugin.chmod(0o755)
    config_path = tmp_path / 'strfry.conf'
    config_path.write_text(
        'relay {\n'
        '    writePolicy {\n'
        f'        plugin = "{plugin}"\n'
        '    }\n'
        '}\n'
    )
    monkeypatch.setattr(Config, 'STRFRY_CONFIG', str(config_path))

    with app.app_context():
        add_sample(now)
        db.session.commit()
        configured = dashboard_summary(now, role='admin')
        config_path.write_text(config_path.read_text().replace(str(plugin), ''))
        disabled = dashboard_summary(now, role='admin')

    assert not any('plugin is not executable' in item['label'] for item in configured['attention'])
    assert any(item['label'] == 'Write-policy plugin is disabled' for item in disabled['attention'])


def test_dashboard_admission_excludes_non_network_bypasses(app):
    now = utcnow().replace(second=0, microsecond=0)
    with app.app_context():
        add_sample(
            now - timedelta(hours=2),
            policy={'accepted_off': 10, 'bypassed': 100},
        )
        add_sample(now, policy={'accepted_off': 13, 'bypassed': 150})
        db.session.commit()

        summary = dashboard_summary(now)

    assert summary['admission']['accepted_24h'] == 3
    assert summary['admission']['coverage_hours'] == 2


def test_connection_summary_reports_gauges_and_restart_aware_activity(app):
    now = utcnow().replace(second=0, microsecond=0)
    with app.app_context():
        add_sample(
            now - timedelta(hours=24),
            counters={
                'client:EVENT': 100,
                'client:REQ': 40,
                'relay:EVENT': 400,
                'strfry_auth_challenges_sent_total': 10,
                'strfry_auth_success_total': 8,
                'strfry_auth_failure_total': 2,
                'strfry_slow_client_terminations_total': 1,
            },
            gauges={
                'strfry_connections_current': 4,
                'strfry_authenticated_connections_current': 1,
            },
        )
        add_sample(
            now,
            counters={
                'client:EVENT': 130,
                'client:REQ': 52,
                'relay:EVENT': 490,
                'strfry_auth_challenges_sent_total': 16,
                'strfry_auth_success_total': 13,
                'strfry_auth_failure_total': 3,
                'strfry_slow_client_terminations_total': 3,
            },
            gauges={
                'strfry_connections_current': 7,
                'strfry_authenticated_connections_current': 2,
            },
        )
        db.session.commit()

        summary = connection_summary(now)

    assert summary['current'] == {
        'total': 7,
        'authenticated': 2,
        'anonymous': 5,
    }
    assert summary['status'] == 'live'
    assert summary['average_24h'] == 5.5
    assert summary['peak_24h'] == 7
    assert summary['authentication_24h'] == {
        'challenges': 6,
        'successes': 5,
        'failures': 1,
    }
    assert summary['slow_client_terminations_24h'] == 2
    assert summary['incoming_24h'] == {'EVENT': 30, 'REQ': 12}
    assert summary['outgoing_24h'] == {'EVENT': 90}


def test_connection_summary_marks_unsupported_gauges_unavailable(app):
    now = utcnow().replace(second=0, microsecond=0)
    with app.app_context():
        add_sample(now, counters={'client:EVENT': 1})
        db.session.commit()

        summary = connection_summary(now)

    assert summary['available'] is True
    assert summary['status'] == 'limited'
    assert summary['current'] == {
        'total': None,
        'authenticated': None,
        'anonymous': None,
    }


def test_connection_summary_marks_old_samples_stale(app):
    now = utcnow().replace(second=0, microsecond=0)
    with app.app_context():
        add_sample(
            now - timedelta(minutes=3),
            gauges={'strfry_connections_current': 4},
        )
        db.session.commit()

        summary = connection_summary(now)

    assert summary['status'] == 'stale'
    assert summary['current']['total'] == 4


def test_connection_summary_skips_missing_and_new_counter_baselines(app):
    now = utcnow().replace(second=0, microsecond=0)
    with app.app_context():
        add_sample(
            now - timedelta(minutes=2),
            counters={'client:EVENT': 100, 'strfry_auth_success_total': 20},
        )
        add_sample(now - timedelta(minutes=1), counters={})
        add_sample(
            now,
            counters={
                'client:EVENT': 105,
                'client:REQ': 50,
                'strfry_auth_success_total': 3,
            },
        )
        db.session.commit()

        summary = connection_summary(now)

    assert summary['incoming_24h'] == {'EVENT': 5, 'REQ': 0}
    assert summary['authentication_24h']['successes'] == 3
