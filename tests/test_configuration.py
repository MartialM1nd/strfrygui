import fcntl
import hashlib
import os
import stat

import pytest

from config import Config
from utils.configuration import (
    ConfigurationBusy,
    ConfigurationError,
    RevisionConflict,
    _can_preserve_group,
    load_configuration,
    update_configuration,
)
from utils.strfry import get_config, update_config


CONFIG = '''# retained header
relay { # relay comment
    info {
        name = "old name" # retained inline comment
        description = ""
        pubkey = "abc"
        contact = "mailto:test@example.com"
    }
    bind = "127.0.0.1"
    port = 7777
    writePolicy {
        plugin = "/old/plugin"
        timeoutSeconds = 10
        lookbackSeconds = 0
    }
    unrelated = "leave me alone"
}
'''


def config_file(tmp_path, content=CONFIG):
    path = tmp_path / "strfry.conf"
    path.write_text(content)
    return path


def test_snapshot_has_typed_values_revision_and_capability(tmp_path):
    path = config_file(tmp_path)

    snapshot = load_configuration(path)

    assert snapshot.writable is True
    assert snapshot.can_write is True
    assert snapshot.path == str(path)
    assert snapshot.diagnostics == ()
    assert snapshot.values["relay"]["info"]["description"] == ""
    assert snapshot.values["relay"]["port"] == 7777
    assert snapshot.revision == hashlib.sha256(path.read_bytes()).hexdigest()


def test_write_changes_only_value_tokens_and_serializes_types(tmp_path):
    path = config_file(tmp_path)
    before = path.read_text()
    snapshot = load_configuration(path)

    result = snapshot.write(
        {
            "relay.info.name": 'new "name"',
            "relay.info.description": "",
            "relay.port": 8888,
            "relay.writePolicy.lookbackSeconds": "42",
        }
    )

    expected = before.replace('"old name"', '"new \\"name\\""')
    expected = expected.replace("port = 7777", "port = 8888")
    expected = expected.replace("lookbackSeconds = 0", "lookbackSeconds = 42")
    assert path.read_text() == expected
    assert result.values["relay"]["port"] == 8888
    assert "# retained inline comment" in path.read_text()


@pytest.mark.parametrize("value", ["line\nbreak", "carriage\rreturn", "nul\0byte", "delete\x7f"])
def test_rejects_control_character_injection_without_writing(tmp_path, value):
    path = config_file(tmp_path)
    before = path.read_bytes()

    with pytest.raises(ConfigurationError, match="control character"):
        load_configuration(path).write({"relay.info.name": value})

    assert path.read_bytes() == before


def test_rejects_unknown_fields_and_wrong_types(tmp_path):
    snapshot = load_configuration(config_file(tmp_path))

    with pytest.raises(KeyError, match="not editable"):
        snapshot.write({"relay.unrelated": "changed"})
    with pytest.raises(ConfigurationError, match="must be an integer"):
        snapshot.write({"relay.port": "not-a-number"})
    with pytest.raises(ConfigurationError, match="between 1 and 65535"):
        snapshot.write({"relay.port": 0})


def test_expected_revision_prevents_lost_update(tmp_path):
    path = config_file(tmp_path)
    snapshot = load_configuration(path)
    path.write_text(path.read_text().replace("old name", "someone else"))

    with pytest.raises(RevisionConflict, match="changed"):
        snapshot.write({"relay.info.name": "ours"})

    assert "someone else" in path.read_text()


@pytest.mark.parametrize(
    "content, message",
    [
        ('relay {\n name = "one"\n name = "two"\n}\n', "ambiguous duplicate"),
        ('relay {\n info {\n name = "unterminated\n}\n}\n', "unterminated"),
        ('relay {\n port = "seven"\n}\n', "must be an integer"),
        ('relay {\n bind = 127.0.0.1\n}\n', "must be a quoted string"),
        ('relay {\n ???\n}\n', "malformed syntax"),
        ('relay {\n port = 7777\n', "unclosed section"),
    ],
)
def test_malformed_or_ambiguous_files_are_read_only(tmp_path, content, message):
    snapshot = load_configuration(config_file(tmp_path, content))

    assert snapshot.writable is False
    assert any(message in diagnostic for diagnostic in snapshot.diagnostics)
    with pytest.raises(ConfigurationError):
        snapshot.write({"relay.port": 8888})


def test_missing_and_non_regular_targets_return_diagnostics(tmp_path):
    missing = load_configuration(tmp_path / "missing.conf")
    directory = load_configuration(tmp_path)

    assert missing.revision is None and not missing.writable
    assert directory.revision is None and not directory.writable
    assert missing.diagnostics
    assert "not a regular file" in directory.diagnostics[0]


def test_group_preservation_capability_requires_root_or_membership(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(os, "getegid", lambda: 1000)
    monkeypatch.setattr(os, "getgroups", lambda: [1001, 1002])

    assert _can_preserve_group(1002) is True
    assert _can_preserve_group(2000) is False


def test_symlink_updates_target_without_replacing_link_and_preserves_mode(tmp_path):
    target = config_file(tmp_path)
    target.chmod(0o640)
    original_group = target.stat().st_gid
    link = tmp_path / "configured.conf"
    link.symlink_to(target.name)
    snapshot = load_configuration(link)

    snapshot.write({"relay.info.contact": "new@example.com"})

    assert link.is_symlink()
    assert "new@example.com" in target.read_text()
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert target.stat().st_gid == original_group


def test_atomic_write_failure_never_falls_back_to_direct_write(monkeypatch, tmp_path):
    path = config_file(tmp_path)
    before = path.read_bytes()
    snapshot = load_configuration(path)

    def fail_replace(source, destination):
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        snapshot.write({"relay.info.name": "new"})

    assert path.read_bytes() == before


def test_compatibility_functions_use_safe_configuration(monkeypatch, tmp_path):
    path = config_file(tmp_path)
    monkeypatch.setattr(Config, "STRFRY_CONFIG", str(path))

    assert get_config()["relay"]["port"] == "7777"
    assert update_config({"relay.writePolicy.timeoutSeconds": "15"}) is True
    assert get_config()["relay"]["writePolicy"]["timeoutSeconds"] == "15"


def test_update_function_requires_sha256_revision(tmp_path):
    path = config_file(tmp_path)

    with pytest.raises(ConfigurationError, match="SHA256"):
        update_configuration(path, {"relay.port": 8888}, "not-a-revision")


def test_quoted_decimal_integers_are_compatible_and_normalized_on_edit(tmp_path):
    path = config_file(
        tmp_path,
        CONFIG.replace("port = 7777", 'port = "7777"').replace(
            "timeoutSeconds = 10", 'timeoutSeconds = "10"'
        ),
    )
    snapshot = load_configuration(path)

    assert snapshot.writable
    assert snapshot.values["relay"]["port"] == 7777
    assert snapshot.values["relay"]["writePolicy"]["timeoutSeconds"] == 10

    snapshot.write({"relay.port": 8888, "relay.writePolicy.timeoutSeconds": 20})

    assert "port = 8888" in path.read_text()
    assert "timeoutSeconds = 20" in path.read_text()


def test_inserts_missing_info_and_write_policy_into_existing_relay(tmp_path):
    path = config_file(
        tmp_path,
        '# header\nrelay {\n    bind = "127.0.0.1"\n    port = 7777\n}\n',
    )

    result = load_configuration(path).write(
        {
            "relay.info.name": "Inserted Relay",
            "relay.info.description": "",
            "relay.writePolicy.plugin": "/plugin",
            "relay.writePolicy.timeoutSeconds": 15,
            "relay.writePolicy.lookbackSeconds": 30,
        }
    )

    content = path.read_text()
    assert content.count("relay {") == 1
    assert content.count("info {") == 1
    assert content.count("writePolicy {") == 1
    assert '# header\nrelay {\n    bind = "127.0.0.1"\n    port = 7777\n' in content
    assert result.values["relay"]["info"]["name"] == "Inserted Relay"
    assert result.values["relay"]["writePolicy"]["timeoutSeconds"] == 15


def test_inserts_missing_keys_into_existing_known_sections(tmp_path):
    path = config_file(
        tmp_path,
        'relay {\n    info {\n        name = "existing"\n    }\n'
        '    writePolicy {\n        plugin = "/plugin"\n    }\n}\n',
    )

    load_configuration(path).write(
        {
            "relay.info.contact": "admin@example.com",
            "relay.writePolicy.lookbackSeconds": 60,
        }
    )

    content = path.read_text()
    assert '        contact = "admin@example.com"\n    }' in content
    assert "        lookbackSeconds = 60\n    }" in content


def test_busy_flock_fails_without_waiting(tmp_path):
    path = config_file(tmp_path)
    snapshot = load_configuration(path)
    lock_fd = os.open(str(path.resolve()) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ConfigurationBusy, match="in progress"):
            snapshot.write({"relay.port": 8888})
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


@pytest.mark.parametrize(
    "key,value,message",
    [
        ("relay.writePolicy.timeoutSeconds", 0, "between 1 and 60"),
        ("relay.writePolicy.timeoutSeconds", 61, "between 1 and 60"),
        ("relay.writePolicy.lookbackSeconds", -1, "between 0 and 3600"),
        ("relay.writePolicy.lookbackSeconds", 3601, "between 0 and 3600"),
    ],
)
def test_write_policy_integer_bounds(tmp_path, key, value, message):
    snapshot = load_configuration(config_file(tmp_path))

    with pytest.raises(ConfigurationError, match=message):
        snapshot.write({key: value})
