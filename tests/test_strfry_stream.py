import pytest

from config import Config
from utils.strfry import (
    StrfryError,
    database_maintenance_lock,
    delete_events,
    export_events,
    iter_scan_events,
    validate_jsonl,
)


def executable(tmp_path, body):
    path = tmp_path / 'strfry'
    path.write_text('#!/bin/sh\n' + body)
    path.chmod(0o755)
    return path


def test_iter_scan_events_streams_jsonl_and_skips_malformed_lines(monkeypatch, tmp_path):
    binary = executable(
        tmp_path,
        "printf '%s\\n' '{\"id\":\"one\"}' 'not-json' '{\"id\":\"two\"}'\n",
    )
    monkeypatch.setattr(Config, 'STRFRY_BINARY', str(binary))
    monkeypatch.setattr(Config, 'STRFRY_CONFIG', '')

    events = list(iter_scan_events({}, limit=2, timeout=2))

    assert events == [{'id': 'one'}, {'id': 'two'}]


def test_iter_scan_events_reports_command_failure(monkeypatch, tmp_path):
    binary = executable(tmp_path, "printf 'scan failed' >&2\nexit 1\n")
    monkeypatch.setattr(Config, 'STRFRY_BINARY', str(binary))
    monkeypatch.setattr(Config, 'STRFRY_CONFIG', '')

    with pytest.raises(StrfryError, match='scan failed'):
        list(iter_scan_events({}, limit=1, timeout=2))


def test_validate_jsonl_requires_bounded_objects(monkeypatch):
    monkeypatch.setattr(Config, 'IMPORT_MAX_BYTES', 100)
    monkeypatch.setattr(Config, 'IMPORT_MAX_EVENTS', 1)

    assert validate_jsonl('{"id":"one"}') is True
    with pytest.raises(StrfryError, match='JSON object'):
        validate_jsonl('["not", "an", "object"]')
    with pytest.raises(StrfryError, match='1-event safety limit'):
        validate_jsonl('{"id":"one"}\n{"id":"two"}')
    with pytest.raises(StrfryError, match='100-byte safety limit'):
        validate_jsonl('{"content":"' + ('x' * 100) + '"}')


def test_export_events_rejects_output_over_limit(monkeypatch, tmp_path):
    binary = executable(tmp_path, "printf '1234567890'\n")
    monkeypatch.setattr(Config, 'STRFRY_BINARY', str(binary))
    monkeypatch.setattr(Config, 'STRFRY_CONFIG', '')
    monkeypatch.setattr(Config, 'EXPORT_MAX_BYTES', 5)

    with pytest.raises(StrfryError, match='5-byte safety limit'):
        export_events()


def test_export_events_preserves_zero_timestamp_bounds(monkeypatch, tmp_path):
    args_file = tmp_path / 'args'
    binary = executable(tmp_path, f"printf '%s' \"$*\" > '{args_file}'\n")
    monkeypatch.setattr(Config, 'STRFRY_BINARY', str(binary))
    monkeypatch.setattr(Config, 'STRFRY_CONFIG', '')
    monkeypatch.setattr(Config, 'EXPORT_MAX_BYTES', 100)

    export_events(since=0, until=0)

    assert args_file.read_text() == 'export --since 0 --until 0'


def test_database_maintenance_lock_rejects_overlap(monkeypatch, tmp_path):
    monkeypatch.setattr(
        Config,
        'DATABASE_MAINTENANCE_LOCK',
        str(tmp_path / 'maintenance.lock'),
    )

    with database_maintenance_lock():
        with pytest.raises(StrfryError, match='maintenance operation is in progress'):
            with database_maintenance_lock():
                pass
        with pytest.raises(StrfryError, match='maintenance operation is in progress'):
            delete_events({'ids': ['event-id']})
