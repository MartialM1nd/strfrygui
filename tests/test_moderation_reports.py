from datetime import UTC, datetime
import hashlib
import json

import pytest
from sqlalchemy import event, text

from config import Config
from models import ModerationReport, db, ensure_moderation_report_indexes
from utils import moderation_reports
from utils import nip05
from utils.strfry import StrfryError


STRICT_PARSE_REPORT = moderation_reports._parse_report


def sign_schnorr(private_key, message):
    public_point = nip05._point_multiply(private_key, nip05._SECP256K1_G)
    secret = private_key if public_point[1] % 2 == 0 else nip05._SECP256K1_N - private_key
    public_key = public_point[0].to_bytes(32, 'big')
    nonce = int.from_bytes(nip05._tagged_hash(
        'BIP0340/nonce', secret.to_bytes(32, 'big') + public_key + message
    ), 'big') % nip05._SECP256K1_N
    nonce_point = nip05._point_multiply(nonce, nip05._SECP256K1_G)
    if nonce_point[1] % 2:
        nonce = nip05._SECP256K1_N - nonce
        nonce_point = nip05._point_multiply(nonce, nip05._SECP256K1_G)
    r = nonce_point[0].to_bytes(32, 'big')
    challenge = int.from_bytes(nip05._tagged_hash(
        'BIP0340/challenge', r + public_key + message
    ), 'big') % nip05._SECP256K1_N
    return r + ((nonce + challenge * secret) % nip05._SECP256K1_N).to_bytes(32, 'big')


@pytest.fixture(autouse=True)
def preserve_legacy_sync_fixtures(monkeypatch):
    def parse(report):
        p_tag = next((tag for tag in report.get('tags', []) if tag[0] == 'p'), None)
        e_tag = next((tag for tag in report.get('tags', []) if tag[0] == 'e'), None)
        return (
            p_tag[1] if p_tag else None,
            e_tag[1] if e_tag else None,
            p_tag[2] if p_tag else None,
            datetime.fromtimestamp(report.get('created_at', 0), UTC).replace(tzinfo=None),
        )

    monkeypatch.setattr(moderation_reports, '_parse_report', parse)
    monkeypatch.setattr(
        moderation_reports,
        '_target_exists',
        lambda events, pubkey, event_id=None: bool(events),
    )


def report_event(event_id, reported_pubkey=None, reported_event_id=None):
    tags = []
    if reported_pubkey:
        tags.append(['p', reported_pubkey, 'spam'])
    if reported_event_id:
        tags.append(['e', reported_event_id, 'spam'])
    return {
        'id': event_id,
        'pubkey': 'reporter',
        'created_at': 1_700_000_000,
        'content': 'Spam report',
        'tags': tags,
    }


def test_sync_bulk_checks_existing_reports(app, monkeypatch):
    db.session.add_all([
        ModerationReport(event_id=f'existing-{index}')
        for index in range(50)
    ])
    db.session.commit()
    calls = []

    def scan(filter_json, limit, timeout):
        calls.append((filter_json, limit, timeout))
        return [report_event(f'existing-{index}') for index in range(50)]

    monkeypatch.setattr(moderation_reports, 'scan_events', scan)
    report_queries = []

    def count_report_queries(conn, cursor, statement, parameters, context, executemany):
        if 'FROM moderation_reports' in statement:
            report_queries.append(statement)

    event.listen(db.engine, 'before_cursor_execute', count_report_queries)
    try:
        result = moderation_reports.sync_moderation_reports()
    finally:
        event.remove(db.engine, 'before_cursor_execute', count_report_queries)

    assert result == 0
    assert len(report_queries) == 3
    assert calls == [
        ({'kinds': [1984], 'limit': 200}, 200, Config.MODERATION_REPORT_SYNC_TIMEOUT)
    ]


def test_sync_temporarily_suppresses_rejected_reports(app, monkeypatch):
    calls = []
    sync_count = 0

    def scan(filter_json, limit, timeout):
        nonlocal sync_count
        calls.append(filter_json)
        if 'kinds' in filter_json:
            sync_count += 1
            return [report_event(
                f'fake-report-{sync_count}',
                reported_pubkey='missing-pubkey',
            )]
        return []

    monkeypatch.setattr(moderation_reports, 'scan_events', scan)
    moderation_reports.clear_rejection_cache()

    assert moderation_reports.sync_moderation_reports() == 0
    assert moderation_reports.sync_moderation_reports() == 0
    assert calls == [
        {'kinds': [1984], 'limit': 200},
        {'authors': ['missing-pubkey'], 'limit': 1},
        {'kinds': [1984], 'limit': 200},
    ]


def test_sync_reuses_target_validation_within_batch(app, monkeypatch):
    calls = []

    def scan(filter_json, limit, timeout):
        calls.append(filter_json)
        if 'kinds' in filter_json:
            return [
                report_event('report-1', reported_pubkey='same-pubkey'),
                report_event('report-2', reported_pubkey='same-pubkey'),
            ]
        return [report_event('target-event')]

    monkeypatch.setattr(moderation_reports, 'scan_events', scan)
    moderation_reports.clear_rejection_cache()

    assert moderation_reports.sync_moderation_reports() == 2
    assert calls.count({'authors': ['same-pubkey'], 'limit': 1}) == 1
    assert ModerationReport.query.count() == 2


def test_sync_does_not_cache_scan_failures_as_rejections(app, monkeypatch):
    calls = []

    def scan(filter_json, limit, timeout):
        calls.append(filter_json)
        if 'kinds' in filter_json:
            return [report_event('report', reported_pubkey='unknown')]
        raise StrfryError('scan unavailable')

    monkeypatch.setattr(moderation_reports, 'scan_events', scan)
    moderation_reports.clear_rejection_cache()

    assert moderation_reports.sync_moderation_reports() is None
    assert moderation_reports.sync_moderation_reports() is None
    assert calls.count({'authors': ['unknown'], 'limit': 1}) == 2


def test_sync_bounds_target_validations_per_cycle(app, monkeypatch):
    calls = []

    def scan(filter_json, limit, timeout):
        calls.append(filter_json)
        if 'kinds' in filter_json:
            return [
                report_event(f'report-{index}', reported_pubkey=f'pubkey-{index}')
                for index in range(3)
            ]
        return [report_event('target')]

    monkeypatch.setattr(moderation_reports, 'scan_events', scan)
    monkeypatch.setattr(Config, 'MODERATION_REPORT_VALIDATION_LIMIT', 1)
    moderation_reports.clear_rejection_cache()

    assert moderation_reports.sync_moderation_reports() == 1
    assert len([call for call in calls if 'authors' in call]) == 1


def test_sync_carries_deferred_reports_into_next_cycle(app, monkeypatch):
    scan_count = 0

    def scan(filter_json, limit, timeout):
        nonlocal scan_count
        if 'kinds' in filter_json:
            scan_count += 1
            if scan_count > 1:
                return []
            return [
                report_event('report-1', reported_pubkey='pubkey-1'),
                report_event('report-2', reported_pubkey='pubkey-2'),
            ]
        return [report_event('target')]

    monkeypatch.setattr(moderation_reports, 'scan_events', scan)
    monkeypatch.setattr(Config, 'MODERATION_REPORT_VALIDATION_LIMIT', 1)
    moderation_reports.clear_rejection_cache()

    assert moderation_reports.sync_moderation_reports() == 1
    assert moderation_reports.sync_moderation_reports() == 1
    assert ModerationReport.query.count() == 2


def test_sync_stops_validation_when_total_deadline_expires(app, monkeypatch):
    calls = []
    clock = iter([0, 0, Config.MODERATION_REPORT_SYNC_TIMEOUT + 1])

    def scan(filter_json, limit, timeout):
        calls.append(filter_json)
        return [report_event('report', reported_pubkey='pubkey')]

    monkeypatch.setattr(moderation_reports, 'scan_events', scan)
    monkeypatch.setattr(moderation_reports.time, 'monotonic', lambda: next(clock))
    moderation_reports.clear_rejection_cache()

    assert moderation_reports.sync_moderation_reports() == 0
    assert calls == [{'kinds': [1984], 'limit': 200}]


def test_default_report_query_uses_reviewed_date_index(app):
    plan = db.session.execute(text(
        'EXPLAIN QUERY PLAN '
        'SELECT * FROM moderation_reports '
        'WHERE reviewed = 0 '
        'ORDER BY created_at DESC, id DESC LIMIT 25'
    )).all()

    assert any(
        'ix_moderation_reports_reviewed_created_id' in row[3]
        for row in plan
    )


def test_existing_database_migration_creates_report_indexes(app):
    index_names = {
        'ix_moderation_reports_reviewed_created_id',
        'ix_moderation_reports_report_type',
        'ix_moderation_reports_reporter_pubkey',
        'ix_moderation_reports_reported_pubkey',
        'ix_moderation_reports_reported_event_id',
        'ix_moderation_reports_created_at',
        'ix_moderation_reports_reporter_received',
        'ix_moderation_reports_reviewed_received_id',
    }
    with db.engine.begin() as connection:
        for index_name in index_names:
            connection.execute(text(f'DROP INDEX IF EXISTS {index_name}'))
        ensure_moderation_report_indexes(connection)
        actual_names = {
            row[1]
            for row in connection.execute(text(
                "PRAGMA index_list('moderation_reports')"
            ))
        }

    assert index_names <= actual_names


def test_strict_report_parser_requires_signed_unambiguous_targets(monkeypatch):
    now = int(datetime.now(UTC).timestamp())
    report = {
        'id': '1' * 64,
        'pubkey': '2' * 64,
        'sig': '3' * 128,
        'kind': 1984,
        'created_at': now,
        'content': 'Spam report',
        'tags': [['p', '4' * 64, 'spam']],
    }
    calls = []
    monkeypatch.setattr(
        moderation_reports,
        'validate_nostr_event',
        lambda event: calls.append(event),
    )

    parsed = STRICT_PARSE_REPORT(report)

    assert parsed[:3] == ('4' * 64, None, 'spam')
    assert calls == [report]
    report['tags'] = [
        ['e', '5' * 64, 'spam'],
        ['p', '4' * 64],
    ]
    assert STRICT_PARSE_REPORT(report)[:3] == ('4' * 64, '5' * 64, 'spam')
    report['tags'].append(['p', '5' * 64, 'spam'])
    with pytest.raises(ValueError, match='ambiguous'):
        STRICT_PARSE_REPORT(report)


def test_strict_report_parser_accepts_canonical_signed_note_report():
    private_key = 7
    public_point = nip05._point_multiply(private_key, nip05._SECP256K1_G)
    pubkey = public_point[0].to_bytes(32, 'big').hex()
    created_at = int(datetime.now(UTC).timestamp())
    tags = [['e', '5' * 64, 'spam'], ['p', '4' * 64]]
    serialized = json.dumps(
        [0, pubkey, created_at, 1984, tags, 'Spam report'],
        ensure_ascii=False,
        separators=(',', ':'),
    ).encode()
    digest = hashlib.sha256(serialized).digest()
    report = {
        'id': digest.hex(),
        'pubkey': pubkey,
        'sig': sign_schnorr(private_key, digest).hex(),
        'kind': 1984,
        'created_at': created_at,
        'content': 'Spam report',
        'tags': tags,
    }

    assert STRICT_PARSE_REPORT(report)[:3] == ('4' * 64, '5' * 64, 'spam')
