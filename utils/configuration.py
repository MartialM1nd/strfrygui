"""Conservative, source-preserving access to the strfry configuration file."""

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


EDITABLE_SCHEMA = {
    "relay.info.name": str,
    "relay.info.description": str,
    "relay.info.pubkey": str,
    "relay.info.contact": str,
    "relay.bind": str,
    "relay.port": int,
    "relay.writePolicy.plugin": str,
    "relay.writePolicy.timeoutSeconds": int,
    "relay.writePolicy.lookbackSeconds": int,
}

_NAME = r"[A-Za-z_][A-Za-z0-9_-]*"
_SECTION_RE = re.compile(rf"^(?P<indent>\s*)(?P<name>{_NAME})\s*\{{\s*(?:#.*)?$")
_CLOSE_RE = re.compile(r"^\s*}\s*(?:#.*)?$")
_ASSIGN_RE = re.compile(rf"^(?P<prefix>\s*(?P<name>{_NAME})\s*=\s*)(?P<rest>.*)$")
_INTEGER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)$")

_thread_locks_guard = threading.Lock()
_thread_locks: dict[str, threading.Lock] = {}


class ConfigurationError(ValueError):
    """Raised when a configuration cannot safely be interpreted or changed."""


class RevisionConflict(ConfigurationError):
    """Raised when the file changed after it was presented to the caller."""


class ConfigurationBusy(ConfigurationError):
    """Raised when another process is updating the configuration."""


@dataclass(frozen=True)
class _Assignment:
    line: int
    value_start: int
    value_end: int


@dataclass
class _Section:
    line: int
    indent: str
    close_line: int | None = None
    child_indent: str | None = None


@dataclass(frozen=True)
class ConfigSnapshot:
    """A point-in-time configuration view and its safe-write capability."""

    values: dict[str, Any]
    revision: str | None
    path: str
    writable: bool
    diagnostics: tuple[str, ...] = ()
    _target_path: str | None = field(default=None, repr=False, compare=False)

    @property
    def can_write(self) -> bool:
        return self.writable

    @property
    def write_capability(self) -> bool:
        return self.writable

    def write(
        self,
        updates: dict[str, Any],
        expected_revision: str | None = None,
    ) -> "ConfigSnapshot":
        """Apply updates if this snapshot is still current."""
        if not self.writable or self.revision is None:
            detail = "; ".join(self.diagnostics) or "configuration is read-only"
            raise ConfigurationError(detail)
        return update_configuration(
            self.path,
            updates,
            expected_revision=self.revision if expected_revision is None else expected_revision,
        )


def _nested_set(values: dict[str, Any], path: tuple[str, ...], value: Any) -> bool:
    target = values
    for part in path[:-1]:
        existing = target.get(part)
        if existing is None:
            existing = {}
            target[part] = existing
        elif not isinstance(existing, dict):
            return False
        target = existing
    if path[-1] in target:
        return False
    target[path[-1]] = value
    return True


def _split_value(rest: str) -> tuple[str, int]:
    """Return the value token and its end offset within rest."""
    if not rest:
        raise ConfigurationError("missing assignment value")
    if rest[0] == '"':
        escaped = False
        for index in range(1, len(rest)):
            char = rest[index]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                end = index + 1
                suffix = rest[end:]
                if suffix.strip() and not suffix.lstrip().startswith("#"):
                    raise ConfigurationError("unexpected text after quoted value")
                return rest[:end], end
        raise ConfigurationError("unterminated quoted value")

    comment = rest.find("#")
    end = len(rest) if comment < 0 else comment
    token = rest[:end].rstrip()
    if not token or any(char.isspace() for char in token):
        raise ConfigurationError("unquoted values must be a single token")
    return token, len(token)


def _decode_value(token: str) -> Any:
    if token.startswith('"'):
        try:
            value = json.loads(token)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ConfigurationError("invalid quoted string") from exc
        if not isinstance(value, str):
            raise ConfigurationError("quoted value is not a string")
        return value
    return token


def _parse(
    source: str,
) -> tuple[
    dict[str, Any],
    dict[str, _Assignment],
    dict[tuple[str, ...], _Section],
    list[str],
]:
    values: dict[str, Any] = {}
    assignments: dict[str, _Assignment] = {}
    diagnostics: list[str] = []
    sections: list[str] = []
    section_paths: set[tuple[str, ...]] = set()
    section_records: dict[tuple[str, ...], _Section] = {}

    for line_number, full_line in enumerate(source.splitlines(keepends=True)):
        line = full_line.rstrip("\r\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        match = _SECTION_RE.fullmatch(line)
        if match:
            path = (*sections, match.group("name"))
            parent = tuple(sections)
            if parent in section_records and section_records[parent].child_indent is None:
                section_records[parent].child_indent = match.group("indent")
            if path in section_paths:
                diagnostics.append(f"line {line_number + 1}: duplicate section {'.'.join(path)}")
            section_paths.add(path)
            section_records.setdefault(
                path, _Section(line=line_number, indent=match.group("indent"))
            )
            sections.append(match.group("name"))
            continue
        if _CLOSE_RE.fullmatch(line):
            if not sections:
                diagnostics.append(f"line {line_number + 1}: unmatched closing brace")
            else:
                section_records[tuple(sections)].close_line = line_number
                sections.pop()
            continue

        match = _ASSIGN_RE.fullmatch(line)
        if not match:
            diagnostics.append(f"line {line_number + 1}: unsupported or malformed syntax")
            continue
        try:
            token, token_end = _split_value(match.group("rest"))
            value = _decode_value(token)
        except ConfigurationError as exc:
            diagnostics.append(f"line {line_number + 1}: {exc}")
            continue

        path = (*sections, match.group("name"))
        dotted = ".".join(path)
        current_section = tuple(sections)
        if current_section in section_records and section_records[current_section].child_indent is None:
            section_records[current_section].child_indent = line[: len(line) - len(line.lstrip())]
        expected_type = EDITABLE_SCHEMA.get(dotted)
        if expected_type is int:
            if not isinstance(value, str) or not _INTEGER_RE.fullmatch(value):
                diagnostics.append(f"line {line_number + 1}: {dotted} must be an integer")
                continue
            value = int(value)
        elif expected_type is str and not token.startswith('"'):
            diagnostics.append(f"line {line_number + 1}: {dotted} must be a quoted string")
            continue

        if dotted in assignments or not _nested_set(values, path, value):
            diagnostics.append(f"line {line_number + 1}: ambiguous duplicate {dotted}")
            continue
        value_start = match.start("rest")
        assignments[dotted] = _Assignment(line_number, value_start, value_start + token_end)

    if sections:
        diagnostics.append(f"end of file: unclosed section {'.'.join(sections)}")
    return values, assignments, section_records, diagnostics


def _resolve_target(path: str) -> tuple[str | None, list[str]]:
    requested = Path(path)
    try:
        target = requested.resolve(strict=True)
        target_stat = target.stat()
    except (OSError, RuntimeError, ValueError) as exc:
        return None, [f"configuration unavailable: {exc}"]
    if not stat.S_ISREG(target_stat.st_mode):
        return None, ["configuration target is not a regular file"]
    return str(target), []


def _can_preserve_group(group_id: int) -> bool:
    return (
        os.geteuid() == 0
        or group_id == os.getegid()
        or group_id in os.getgroups()
    )


def load_configuration(path: str | os.PathLike[str]) -> ConfigSnapshot:
    """Read a configuration without turning unsafe conditions into write access."""
    requested = os.fspath(path)
    target, diagnostics = _resolve_target(requested)
    if target is None:
        return ConfigSnapshot({}, None, requested, False, tuple(diagnostics))

    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags)
        with os.fdopen(descriptor, "rb") as config_file:
            source_bytes = config_file.read()
        source = source_bytes.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        return ConfigSnapshot(
            {}, None, requested, False, (f"configuration unreadable: {exc}",), target
        )

    values, _assignments, _sections, parse_diagnostics = _parse(source)
    diagnostics.extend(parse_diagnostics)
    parent = os.path.dirname(target) or "."
    target_stat = os.stat(target)
    if not os.access(target, os.W_OK):
        diagnostics.append("configuration file is not writable")
    if not os.access(parent, os.W_OK):
        diagnostics.append("configuration directory is not writable")
    if not _can_preserve_group(target_stat.st_gid):
        diagnostics.append("configuration group cannot be preserved")
    revision = hashlib.sha256(source_bytes).hexdigest()
    return ConfigSnapshot(
        values, revision, requested, not diagnostics, tuple(diagnostics), target
    )


# Short aliases make the module convenient without weakening the explicit API.
read_configuration = load_configuration
read_config = load_configuration
load_config = load_configuration
get_config_snapshot = load_configuration


def _validate_updates(updates: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(updates, dict) or not updates:
        raise ConfigurationError("updates must be a non-empty mapping")
    validated = {}
    for key, value in updates.items():
        expected_type = EDITABLE_SCHEMA.get(key)
        if expected_type is None:
            raise KeyError(f"Key '{key}' is not editable")
        if expected_type is int:
            if isinstance(value, bool):
                raise ConfigurationError(f"{key} must be an integer")
            if isinstance(value, str) and _INTEGER_RE.fullmatch(value):
                value = int(value)
            if not isinstance(value, int):
                raise ConfigurationError(f"{key} must be an integer")
            if key == "relay.port" and not 1 <= value <= 65535:
                raise ConfigurationError("relay.port must be between 1 and 65535")
            if key == "relay.writePolicy.timeoutSeconds" and not 1 <= value <= 60:
                raise ConfigurationError(
                    "relay.writePolicy.timeoutSeconds must be between 1 and 60"
                )
            if key == "relay.writePolicy.lookbackSeconds" and not 0 <= value <= 3600:
                raise ConfigurationError(
                    "relay.writePolicy.lookbackSeconds must be between 0 and 3600"
                )
        else:
            if not isinstance(value, str):
                raise ConfigurationError(f"{key} must be a string")
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise ConfigurationError(f"{key} contains a control character")
        validated[key] = value
    return validated


def _serialize(value: Any) -> str:
    return str(value) if isinstance(value, int) else json.dumps(value, ensure_ascii=True)


def _in_process_lock(target: str) -> threading.Lock:
    with _thread_locks_guard:
        return _thread_locks.setdefault(target, threading.Lock())


@contextmanager
def _configuration_lock(target: str):
    thread_lock = _in_process_lock(target)
    if not thread_lock.acquire(blocking=False):
        raise ConfigurationBusy("another configuration update is in progress")

    lock_fd = None
    flock_acquired = False
    try:
        lock_path = target + ".lock"
        lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        lock_fd = os.open(lock_path, lock_flags, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            flock_acquired = True
        except BlockingIOError as exc:
            raise ConfigurationBusy(
                "another configuration update is in progress"
            ) from exc
        yield
    finally:
        if lock_fd is not None:
            if flock_acquired:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        thread_lock.release()


def _child_indent(section: _Section, parent: _Section | None = None) -> str:
    if section.child_indent is not None:
        return section.child_indent
    if parent is not None and section.indent.startswith(parent.indent):
        unit = section.indent[len(parent.indent):]
        if unit:
            return section.indent + unit
    return section.indent + "    "


def _updated_source(
    source: str,
    updates: dict[str, Any],
    assignments: dict[str, _Assignment],
    sections: dict[tuple[str, ...], _Section],
) -> str:
    relay_path = ("relay",)
    relay = sections.get(relay_path)
    if relay is None or relay.close_line is None:
        raise KeyError("Section 'relay' not found in config")

    lines = source.splitlines(keepends=True)
    newline_match = re.search(r"\r\n|\n|\r", source)
    newline = newline_match.group(0) if newline_match else os.linesep
    insertions: dict[int, list[str]] = {}
    missing_sections: dict[tuple[str, ...], list[tuple[str, Any]]] = {}

    for key, value in updates.items():
        assignment = assignments.get(key)
        if assignment is not None:
            line = lines[assignment.line]
            lines[assignment.line] = (
                line[:assignment.value_start]
                + _serialize(value)
                + line[assignment.value_end:]
            )
            continue

        parts = tuple(key.split("."))
        parent_path = parts[:-1]
        parent = sections.get(parent_path)
        if parent is not None and parent.close_line is not None:
            grandparent = sections.get(parent_path[:-1])
            indent = _child_indent(parent, grandparent)
            insertions.setdefault(parent.close_line, []).append(
                f"{indent}{parts[-1]} = {_serialize(value)}{newline}"
            )
        elif parent_path in {("relay", "info"), ("relay", "writePolicy")}:
            missing_sections.setdefault(parent_path, []).append((parts[-1], value))
        else:
            raise KeyError(f"Section '{'.'.join(parent_path)}' not found in config")

    relay_indent = _child_indent(relay)
    indent_unit = relay_indent[len(relay.indent):] or "    "
    for section_path, fields in missing_sections.items():
        section_lines = [f"{relay_indent}{section_path[-1]} {{{newline}"]
        field_indent = relay_indent + indent_unit
        section_lines.extend(
            f"{field_indent}{name} = {_serialize(value)}{newline}"
            for name, value in fields
        )
        section_lines.append(f"{relay_indent}}}{newline}")
        insertions.setdefault(relay.close_line, []).extend(section_lines)

    output = []
    for line_number, line in enumerate(lines):
        output.extend(insertions.get(line_number, ()))
        output.append(line)
    return "".join(output)


def _atomic_replace(target: str, source: str, source_stat: os.stat_result) -> None:
    directory = os.path.dirname(target) or "."
    descriptor, temporary = tempfile.mkstemp(prefix=".strfry.conf.", dir=directory)
    try:
        os.fchmod(descriptor, stat.S_IMODE(source_stat.st_mode))
        try:
            os.fchown(descriptor, source_stat.st_uid, source_stat.st_gid)
        except PermissionError:
            try:
                os.fchown(descriptor, -1, source_stat.st_gid)
            except PermissionError:
                pass
        if os.fstat(descriptor).st_gid != source_stat.st_gid:
            raise ConfigurationError(
                "atomic replacement cannot preserve the configuration group"
            )
        with os.fdopen(descriptor, "wb") as config_file:
            config_file.write(source.encode("utf-8"))
            config_file.flush()
            os.fsync(config_file.fileno())
        os.replace(temporary, target)
        temporary = ""
        directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def update_configuration(
    path: str | os.PathLike[str],
    updates: dict[str, Any],
    expected_revision: str,
) -> ConfigSnapshot:
    """Safely update known fields when the expected SHA256 revision matches."""
    requested = os.fspath(path)
    if not isinstance(expected_revision, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_revision):
        raise ConfigurationError("expected_revision must be a SHA256 hex digest")
    validated = _validate_updates(updates)
    target, diagnostics = _resolve_target(requested)
    if target is None:
        raise ConfigurationError("; ".join(diagnostics))

    with _configuration_lock(target):
        resolved_again, resolve_diagnostics = _resolve_target(requested)
        if resolved_again != target:
            raise ConfigurationError(
                "; ".join(resolve_diagnostics) or "configuration target changed"
            )
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        source_fd = os.open(target, flags)
        try:
            source_stat = os.fstat(source_fd)
            with os.fdopen(source_fd, "rb", closefd=False) as config_file:
                source_bytes = config_file.read()
        finally:
            os.close(source_fd)
        revision = hashlib.sha256(source_bytes).hexdigest()
        if revision != expected_revision:
            raise RevisionConflict("configuration changed; reload before saving")
        try:
            source = source_bytes.decode("utf-8")
        except UnicodeError as exc:
            raise ConfigurationError("configuration is not valid UTF-8") from exc
        _values, assignments, sections, parse_diagnostics = _parse(source)
        if parse_diagnostics:
            raise ConfigurationError("; ".join(parse_diagnostics))
        updated_source = _updated_source(source, validated, assignments, sections)
        _atomic_replace(target, updated_source, source_stat)
    return load_configuration(requested)


write_config = update_configuration
