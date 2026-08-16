import json
import os

from utils import decision_log
from utils.decision_log import read_decision_log


def record(index, action='accept'):
    return {
        'timestamp_ms': 1_700_000_000_000 + index,
        'action': action,
        'reason': 'trusted' if action == 'accept' else 'banned',
        'event_id': f'event-{index}',
        'pubkey': f'pubkey-{index}',
        'kind': index,
        'source_ip': '192.0.2.1',
        'source_type': 'IP4',
        'policy_mode': 'enforce',
    }


def append(path, *records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('ab') as output:
        for value in records:
            output.write(json.dumps(value).encode() + b'\n')


def test_decision_log_reader_does_not_follow_symlinks(tmp_path):
    victim = tmp_path / 'victim.jsonl'
    append(victim, record(1))
    path = tmp_path / 'events.jsonl'
    path.symlink_to(victim)

    batch = read_decision_log(str(path))

    assert batch.available is False
    assert batch.events == []


def test_initial_read_returns_latest_records_from_rotated_and_current(tmp_path):
    path = tmp_path / 'events.jsonl'
    append(tmp_path / 'events.jsonl.1', record(1), record(2))
    append(path, record(3), record(4, 'reject'))

    batch = read_decision_log(str(path), limit=3)

    assert [event['event_id'] for event in batch.events] == [
        'event-2',
        'event-3',
        'event-4',
    ]
    assert batch.available is True
    assert batch.cursor
    assert batch.reset is False


def test_cursor_reads_only_appended_records_and_reports_backlog(tmp_path):
    path = tmp_path / 'events.jsonl'
    append(path, record(1))
    initial = read_decision_log(str(path))
    append(path, record(2), record(3))

    first = read_decision_log(str(path), cursor=initial.cursor, limit=1)
    second = read_decision_log(str(path), cursor=first.cursor, limit=10)

    assert [event['event_id'] for event in first.events] == ['event-2']
    assert first.has_more is True
    assert [event['event_id'] for event in second.events] == ['event-3']
    assert second.has_more is False


def test_cursor_continues_across_rotation(tmp_path):
    path = tmp_path / 'events.jsonl'
    append(path, record(1))
    initial = read_decision_log(str(path))
    append(path, record(2))
    os.replace(path, tmp_path / 'events.jsonl.1')
    append(path, record(3))

    batch = read_decision_log(str(path), cursor=initial.cursor, limit=10)

    assert [event['event_id'] for event in batch.events] == ['event-2', 'event-3']
    assert batch.reset is False


def test_initial_read_retries_when_rotation_changes_snapshot(monkeypatch, tmp_path):
    path = tmp_path / 'events.jsonl'
    append(path, record(1))
    original = decision_log._read_latest
    rotated = False

    def rotate_during_read(files, limit):
        nonlocal rotated
        batch = original(files, limit)
        if not rotated:
            rotated = True
            append(path, record(2))
            os.replace(path, tmp_path / 'events.jsonl.1')
            append(path, record(3))
        return batch

    monkeypatch.setattr(decision_log, '_read_latest', rotate_during_read)

    batch = read_decision_log(str(path), limit=10)

    assert [event['event_id'] for event in batch.events] == [
        'event-1',
        'event-2',
        'event-3',
    ]


def test_initial_read_requests_retry_after_repeated_generation_changes(monkeypatch):
    generation = 0

    def changing_files(path):
        nonlocal generation
        generation += 1
        return [decision_log.LogFile(path, 1, generation, 0, generation)]

    monkeypatch.setattr(decision_log, '_log_files', changing_files)

    batch = decision_log._read_consistent_latest('/missing/events.jsonl', 10)

    assert batch.events == []
    assert batch.cursor is None
    assert batch.reset is True
    assert batch.has_more is True


def test_invalid_or_expired_cursor_resets_to_latest_window(tmp_path):
    path = tmp_path / 'events.jsonl'
    append(path, record(1), record(2))

    batch = read_decision_log(str(path), cursor='not-a-cursor', limit=1)

    assert batch.reset is True
    assert [event['event_id'] for event in batch.events] == ['event-2']


def test_reader_skips_malformed_partial_oversized_and_invalid_records(tmp_path):
    path = tmp_path / 'events.jsonl'
    path.write_bytes(
        b'not-json\n'
        + json.dumps({'timestamp_ms': 1, 'action': 'invalid'}).encode()
        + b'\n'
        + b'x' * 5000
        + b'\n'
        + json.dumps(record(1)).encode()
        + b'\n'
        + json.dumps(record(2)).encode()
    )

    batch = read_decision_log(str(path), limit=10)

    assert [event['event_id'] for event in batch.events] == ['event-1']


def test_missing_log_is_reported_without_error(tmp_path):
    batch = read_decision_log(str(tmp_path / 'missing.jsonl'), cursor='expired')

    assert batch.available is False
    assert batch.events == []
    assert batch.cursor is None
    assert batch.reset is True
