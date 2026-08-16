import base64
import json
import os
import stat
from dataclasses import dataclass


MAX_LINE_BYTES = 4096
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_BATCH_BYTES = 2 * 1024 * 1024
MAX_BATCH_RECORDS = 500


@dataclass(frozen=True)
class LogFile:
    path: str
    device: int
    inode: int
    size: int
    modified_ms: int


@dataclass(frozen=True)
class LogBatch:
    events: list[dict]
    cursor: str | None
    reset: bool
    has_more: bool
    available: bool
    updated_at: int | None


def _log_files(path):
    files = []
    for candidate in (path + '.1', path):
        try:
            file_stat = os.lstat(candidate)
        except OSError:
            continue
        if not stat.S_ISREG(file_stat.st_mode):
            continue
        files.append(LogFile(
            path=candidate,
            device=file_stat.st_dev,
            inode=file_stat.st_ino,
            size=file_stat.st_size,
            modified_ms=int(file_stat.st_mtime * 1000),
        ))
    return files


def _open_log(path):
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0),
    )
    file_stat = os.fstat(descriptor)
    if not stat.S_ISREG(file_stat.st_mode):
        os.close(descriptor)
        raise OSError('Decision log path is not a regular file')
    return os.fdopen(descriptor, 'rb')


def _encode_cursor(log_file, offset):
    raw = f'{log_file.device}:{log_file.inode}:{offset}'.encode('ascii')
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


def _decode_cursor(value):
    if not isinstance(value, str) or not value or len(value) > 128:
        return None
    try:
        padding = '=' * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(value + padding).decode('ascii')
        device, inode, offset = (int(part) for part in decoded.split(':'))
    except (UnicodeDecodeError, ValueError):
        return None
    if min(device, inode, offset) < 0:
        return None
    return device, inode, offset


def _bounded_string(value, maximum):
    return value if isinstance(value, str) and len(value) <= maximum else None


def _parse_record(line):
    if len(line) > MAX_LINE_BYTES:
        return None
    try:
        record = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(record, dict):
        return None
    timestamp = record.get('timestamp_ms')
    action = record.get('action')
    if (
        not isinstance(timestamp, int)
        or isinstance(timestamp, bool)
        or action not in ('accept', 'reject')
    ):
        return None
    simulated_action = record.get('simulated_action')
    if simulated_action not in (None, 'accept', 'reject'):
        return None
    return {
        'timestamp_ms': timestamp,
        'action': action,
        'reason': _bounded_string(record.get('reason'), 64),
        'simulated_action': simulated_action,
        'simulated_reason': _bounded_string(record.get('simulated_reason'), 64),
        'event_id': _bounded_string(record.get('event_id'), 128),
        'pubkey': _bounded_string(record.get('pubkey'), 128),
        'kind': (
            record.get('kind')
            if isinstance(record.get('kind'), int)
            and not isinstance(record.get('kind'), bool)
            else None
        ),
        'source_ip': _bounded_string(record.get('source_ip'), 64),
        'source_type': _bounded_string(record.get('source_type'), 32),
        'policy_mode': _bounded_string(record.get('policy_mode'), 16),
    }


def _read_latest(files, limit):
    events = []
    actual_files = []
    for log_file in files:
        try:
            with _open_log(log_file.path) as input_file:
                file_stat = os.fstat(input_file.fileno())
                start = max(0, file_stat.st_size - MAX_FILE_BYTES)
                input_file.seek(start)
                if start:
                    input_file.readline(MAX_LINE_BYTES + 1)
                for line in input_file:
                    if not line.endswith(b'\n'):
                        input_file.seek(-len(line), os.SEEK_CUR)
                        break
                    record = _parse_record(line)
                    if record is not None:
                        events.append(record)
                final_stat = os.fstat(input_file.fileno())
                actual = LogFile(
                    log_file.path,
                    final_stat.st_dev,
                    final_stat.st_ino,
                    input_file.tell(),
                    int(final_stat.st_mtime * 1000),
                )
                actual_files.append(actual)
        except OSError:
            continue
    events = events[-limit:]
    if not actual_files:
        return LogBatch([], None, False, False, False, None)
    latest = actual_files[-1]
    return LogBatch(
        events,
        _encode_cursor(latest, latest.size),
        False,
        False,
        True,
        max(log_file.modified_ms for log_file in actual_files),
    )


def _file_fingerprint(files):
    return tuple(
        (log_file.device, log_file.inode)
        for log_file in files
    )


def _read_consistent_latest(path, limit):
    """Retry an initial tail if rotation or appends changed its file snapshot."""
    batch = LogBatch([], None, False, False, False, None)
    for _ in range(3):
        before = _log_files(path)
        batch = _read_latest(before, limit)
        after = _log_files(path)
        if _file_fingerprint(before) == _file_fingerprint(after):
            return batch
    files = _log_files(path)
    return LogBatch(
        [],
        None,
        True,
        True,
        bool(files),
        max((log_file.modified_ms for log_file in files), default=None),
    )


def _read_file(log_file, offset, limit, byte_budget):
    events = []
    consumed = 0
    try:
        with _open_log(log_file.path) as input_file:
            file_stat = os.fstat(input_file.fileno())
            if (file_stat.st_dev, file_stat.st_ino) != (
                log_file.device,
                log_file.inode,
            ):
                return events, offset, consumed, True
            if offset > file_stat.st_size:
                return events, offset, consumed, True
            input_file.seek(offset)
            while len(events) < limit and consumed < byte_budget:
                line_start = input_file.tell()
                line = input_file.readline(
                    min(MAX_LINE_BYTES + 1, byte_budget - consumed)
                )
                if not line:
                    break
                consumed += len(line)
                if not line.endswith(b'\n'):
                    if len(line) <= MAX_LINE_BYTES:
                        input_file.seek(line_start)
                        break
                    while consumed < byte_budget:
                        discarded = input_file.readline(byte_budget - consumed)
                        consumed += len(discarded)
                        if not discarded or discarded.endswith(b'\n'):
                            break
                    continue
                record = _parse_record(line)
                if record is not None:
                    events.append(record)
            return events, input_file.tell(), consumed, False
    except OSError:
        return events, offset, consumed, True


def read_decision_log(path, cursor=None, limit=200):
    """Read a bounded initial tail or continue from a validated file cursor."""
    limit = max(1, min(int(limit), MAX_BATCH_RECORDS))
    files = _log_files(path)
    if not files:
        return LogBatch([], None, bool(cursor), False, False, None)
    decoded = _decode_cursor(cursor) if cursor else None
    if decoded is None:
        batch = _read_consistent_latest(path, limit)
        if cursor:
            return LogBatch(
                batch.events,
                batch.cursor,
                True,
                batch.has_more,
                batch.available,
                batch.updated_at,
            )
        return batch

    device, inode, offset = decoded
    start_index = next(
        (
            index
            for index, log_file in enumerate(files)
            if (log_file.device, log_file.inode) == (device, inode)
        ),
        None,
    )
    if start_index is None:
        latest = _read_consistent_latest(path, limit)
        return LogBatch(
            latest.events,
            latest.cursor,
            True,
            latest.has_more,
            latest.available,
            latest.updated_at,
        )

    events = []
    bytes_read = 0
    current_offset = offset
    current_file = files[start_index]
    for index in range(start_index, len(files)):
        current_file = files[index]
        if index != start_index:
            current_offset = 0
        new_events, current_offset, consumed, changed = _read_file(
            current_file,
            current_offset,
            limit - len(events),
            MAX_BATCH_BYTES - bytes_read,
        )
        if changed:
            latest = _read_consistent_latest(path, limit)
            return LogBatch(
                latest.events,
                latest.cursor,
                True,
                latest.has_more,
                latest.available,
                latest.updated_at,
            )
        events.extend(new_events)
        bytes_read += consumed
        if len(events) >= limit or bytes_read >= MAX_BATCH_BYTES:
            break

    has_later_file = current_file != files[-1]
    has_more = current_offset < current_file.size or has_later_file
    return LogBatch(
        events,
        _encode_cursor(current_file, current_offset),
        False,
        has_more,
        True,
        max(log_file.modified_ms for log_file in files),
    )
