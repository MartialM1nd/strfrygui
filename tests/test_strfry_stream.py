import pytest

from config import Config
from utils.strfry import StrfryError, iter_scan_events


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
