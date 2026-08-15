import fcntl
import io
import json
import os
import stat
import threading
import time

from utils import blocklist_plugin as plugin


EVENT_ID = "0" * 4 + "f" * 60
_DEFAULT_ARTIFACT = object()


def policy_data(**updates):
    data = {
        "version": 1,
        "mode": "enforce",
        "roots": ["root"],
        "scores": {"trusted": 80, "root": 1},
        "trust_threshold": 70,
        "pow_difficulty": 16,
        "require_pow_commitment": False,
        "generated_at": 100,
        "expires_at": 1000,
    }
    data.update(updates)
    return data


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="ascii")


def request(pubkey="unknown", event_id=EVENT_ID, tags=None, **updates):
    value = {
        "type": "new",
        "sourceType": "IP4",
        "sourceInfo": "192.0.2.10:4321",
        "event": {"id": event_id, "pubkey": pubkey, "tags": tags or []},
    }
    value.update(updates)
    return value


def runtime(tmp_path, policy=_DEFAULT_ARTIFACT, blocklist=_DEFAULT_ARTIFACT):
    tmp_path.mkdir(parents=True, exist_ok=True)
    blocklist_path = tmp_path / "blocklist.json"
    policy_path = tmp_path / "trust_policy.json"
    if policy is _DEFAULT_ARTIFACT:
        policy = policy_data(mode="off")
    if blocklist is _DEFAULT_ARTIFACT:
        blocklist = []
    if blocklist is not None:
        write_json(blocklist_path, blocklist)
    if policy is not None:
        write_json(policy_path, policy)
    return plugin.WritePolicyRuntime(
        str(blocklist_path),
        str(policy_path),
        str(tmp_path / "trust_policy_stats.json"),
    )


def test_missing_policy_rejects_network_writes_but_loaded_bans_win(tmp_path):
    subject = runtime(tmp_path, policy=None, blocklist=["banned"])

    unavailable = subject.process(request("unknown"), now=200)
    assert unavailable == {
        "id": EVENT_ID,
        "action": "reject",
        "msg": "blocked: write-policy artifacts are unavailable",
    }
    assert subject.process(request("banned"), now=200) == {
        "id": EVENT_ID,
        "action": "reject",
        "msg": "blocked: pubkey is banned",
    }


def test_runtime_recovers_after_initial_artifacts_are_published(tmp_path):
    subject = runtime(tmp_path, policy=None, blocklist=None)
    assert subject.process(request(), now=200)["action"] == "reject"
    assert subject.process(
        request(sourceType="Import"), now=200
    )["action"] == "accept"

    write_json(tmp_path / "blocklist.json", [])
    write_json(tmp_path / "trust_policy.json", policy_data(mode="off"))

    assert subject.process(request(), now=200)["action"] == "accept"
    assert subject.counters["unavailable_blocklist"] == 1
    assert subject.counters["unavailable_trust_policy"] == 1
    assert subject.counters["policy_recovered"] == 1


def test_off_and_monitor_accept_but_bans_always_win(tmp_path):
    off = runtime(tmp_path / "off", policy_data(mode="off"), ["banned"])
    monitor = runtime(tmp_path / "monitor", policy_data(mode="monitor"), ["banned"])

    assert off.process(request(), now=200)["action"] == "accept"
    assert monitor.process(request(event_id="f" * 64), now=200)["action"] == "accept"
    assert monitor.counters["monitor_pow_failed"] == 1
    assert monitor.counters["monitor_low_trust"] == 1
    assert monitor.process(request("trusted"), now=200)["action"] == "accept"
    assert monitor.counters["monitor_trusted"] == 1
    assert monitor.process(request("banned"), now=200)["action"] == "reject"


def test_enforce_accepts_roots_scores_and_valid_pow(tmp_path):
    subject = runtime(tmp_path, policy_data())

    assert subject.process(request("root"), now=200)["action"] == "accept"
    assert subject.process(request("trusted"), now=200)["action"] == "accept"
    assert subject.process(request(), now=200)["action"] == "accept"
    rejected = subject.process(request(event_id="00" + "f" * 62), now=200)
    assert rejected["action"] == "reject"
    assert rejected["msg"].startswith("pow:")


def test_stale_policy_only_trusts_roots_and_requires_pow_for_scores(tmp_path):
    subject = runtime(tmp_path, policy_data(pow_difficulty=20))

    assert subject.process(request("root", event_id="f" * 64), now=1001)["action"] == "accept"
    result = subject.process(request("trusted", event_id=EVENT_ID), now=1001)
    assert result["action"] == "reject"
    assert result["msg"].startswith("pow:")


def test_stale_policy_requires_pow_even_with_zero_threshold(tmp_path):
    subject = runtime(tmp_path, policy_data(trust_threshold=0, pow_difficulty=20))

    result = subject.process(request(event_id=EVENT_ID), now=1001)
    assert result["action"] == "reject"
    assert result["msg"].startswith("pow:")


def test_leading_zero_bits_counts_partial_bytes_and_rejects_invalid_ids():
    assert plugin.leading_zero_bits("0001" + "ff" * 30) == 15
    assert plugin.leading_zero_bits("08" + "ff" * 31) == 4
    assert plugin.leading_zero_bits("0" * 64) == 256
    assert plugin.leading_zero_bits("not-hex") == -1


def test_nonce_commitment_is_required_at_policy_difficulty(tmp_path):
    subject = runtime(tmp_path, policy_data(require_pow_commitment=True))

    missing = subject.process(request(), now=200)
    low = subject.process(request(tags=[["nonce", "1", "15"]]), now=200)
    valid = subject.process(request(tags=[["nonce", "1", "16"]]), now=200)

    assert missing["msg"] == "pow: missing nonce difficulty commitment"
    assert low["action"] == "reject"
    assert valid["action"] == "accept"
    assert not plugin.has_nonce_commitment([["nonce", "1", 16.5]], 16)


def test_zero_difficulty_does_not_require_a_nonce_tag(tmp_path):
    subject = runtime(
        tmp_path,
        policy_data(pow_difficulty=0, require_pow_commitment=True),
    )

    assert subject.process(request(event_id="f" * 64), now=200)["action"] == "accept"


def test_non_network_sources_bypass_trust_and_pow_but_not_bans(tmp_path):
    subject = runtime(tmp_path, policy_data(pow_difficulty=64), ["banned"])

    for source_type in ("Import", "Stream", "Sync", "Stored"):
        assert subject.process(
            request(event_id="f" * 64, sourceType=source_type), now=200
        )["action"] == "accept"
    assert subject.process(
        request("banned", sourceType="Stored"), now=200
    )["action"] == "reject"


def test_rate_limit_applies_to_low_network_authors_and_is_bounded(tmp_path):
    subject = runtime(
        tmp_path,
        policy_data(
            rate_limit_per_minute=1,
            rate_limit_burst=1,
            max_tracked_ips=2,
        ),
    )

    assert subject.process(request(), now=200, monotonic_now=0)["action"] == "accept"
    limited = subject.process(request(), now=200, monotonic_now=0)
    assert limited["msg"].startswith("rate-limited:")
    assert subject.process(request("trusted"), now=200, monotonic_now=0)["action"] == "accept"
    subject.process(request(sourceInfo="192.0.2.11:1"), now=200, monotonic_now=0)
    subject.process(request(sourceInfo="[2001:db8::1]:2"), now=200, monotonic_now=0)
    assert len(subject.rate_limiter._buckets) == 2


def test_monitor_rate_limit_evaluates_without_rejecting(tmp_path):
    subject = runtime(
        tmp_path,
        policy_data(mode="monitor", rate_limit_per_minute=1, rate_limit_burst=1),
    )

    subject.process(request(), now=200, monotonic_now=0)
    assert subject.process(request(), now=200, monotonic_now=0)["action"] == "accept"
    assert subject.counters["monitor_rate_limited"] == 1


def test_policy_reloader_retains_valid_policy_when_malformed_or_missing(tmp_path):
    policy_path = tmp_path / "trust_policy.json"
    write_json(policy_path, policy_data())
    reloader = plugin.PolicyReloader(str(policy_path))
    original = reloader.policy

    policy_path.write_text("{broken", encoding="ascii")
    os.utime(policy_path, ns=(2_000_000_000, 2_000_000_000))
    assert reloader.reload() is original
    policy_path.unlink()
    assert reloader.reload() is original


def test_blocklist_reloads_by_mtime(tmp_path):
    blocklist_path = tmp_path / "blocklist.json"
    write_json(blocklist_path, [])
    subject = plugin.BlocklistReloader(str(blocklist_path))
    write_json(blocklist_path, ["new-ban"])
    os.utime(blocklist_path, ns=(2_000_000_000, 2_000_000_000))

    assert subject.reload() == {"new-ban"}


def test_blocklist_reloader_retains_last_valid_bans(tmp_path):
    blocklist_path = tmp_path / "blocklist.json"
    write_json(blocklist_path, ["active-ban"])
    subject = plugin.BlocklistReloader(str(blocklist_path))
    blocklist_path.write_text("{broken", encoding="ascii")
    os.utime(blocklist_path, ns=(2_000_000_000, 2_000_000_000))

    assert subject.reload() == {"active-ban"}


def test_reloaders_use_legacy_files_until_runtime_files_exist(tmp_path):
    runtime_blocklist = tmp_path / "runtime-blocklist.json"
    legacy_blocklist = tmp_path / "legacy-blocklist.json"
    runtime_policy = tmp_path / "runtime-policy.json"
    legacy_policy = tmp_path / "legacy-policy.json"
    write_json(legacy_blocklist, ["legacy-ban"])
    write_json(legacy_policy, policy_data(mode="monitor"))
    blocklists = plugin.BlocklistReloader(
        str(runtime_blocklist), str(legacy_blocklist)
    )
    policies = plugin.PolicyReloader(str(runtime_policy), str(legacy_policy))

    assert blocklists.reload() == {"legacy-ban"}
    assert policies.reload().mode == "monitor"

    write_json(runtime_blocklist, [])
    write_json(runtime_policy, policy_data(mode="enforce"))

    assert blocklists.reload() == set()
    assert policies.reload().mode == "enforce"

    runtime_blocklist.unlink()
    runtime_policy.unlink()
    write_json(legacy_blocklist, ["stale-legacy-ban"])
    write_json(legacy_policy, policy_data(mode="off"))

    assert blocklists.reload() == set()
    assert policies.reload().mode == "enforce"


def test_reloaders_do_not_fail_open_when_initial_runtime_files_are_invalid(tmp_path):
    runtime_blocklist = tmp_path / "runtime-blocklist.json"
    legacy_blocklist = tmp_path / "legacy-blocklist.json"
    runtime_policy = tmp_path / "runtime-policy.json"
    legacy_policy = tmp_path / "legacy-policy.json"
    runtime_blocklist.write_text("{broken", encoding="ascii")
    runtime_policy.write_text("{broken", encoding="ascii")
    write_json(legacy_blocklist, ["legacy-ban"])
    write_json(legacy_policy, policy_data(mode="enforce"))

    blocklists = plugin.BlocklistReloader(
        str(runtime_blocklist), str(legacy_blocklist)
    )
    policies = plugin.PolicyReloader(str(runtime_policy), str(legacy_policy))

    assert blocklists.reload() == {"legacy-ban"}
    assert policies.reload().mode == "enforce"


def test_runtime_flushes_aggregate_stats_atomically(tmp_path):
    stats_path = tmp_path / "trust_policy_stats.json"
    write_json(tmp_path / "blocklist.json", [])
    write_json(tmp_path / "trust_policy.json", policy_data(mode="off"))
    subject = plugin.WritePolicyRuntime(
        str(tmp_path / "blocklist.json"),
        str(tmp_path / "trust_policy.json"),
        str(stats_path),
    )
    subject.process(request())

    subject.flush_stats(now=100, force=True)

    assert json.loads(stats_path.read_text()) == {
        "updated_at": 100,
        "counters": {"accepted_off": 1},
    }
    assert stat.S_IMODE(stats_path.stat().st_mode) == 0o640


def test_ip_normalization_handles_ipv4_ipv6_dicts_and_bad_input():
    assert plugin.normalize_source_ip("192.0.2.1:7777") == "192.0.2.1"
    assert plugin.normalize_source_ip("[2001:0db8::1]:7777") == "2001:db8::1"
    assert plugin.normalize_source_ip("2001:db8::2") == "2001:db8::2"
    assert plugin.normalize_source_ip({"ip": "198.51.100.4"}) == "198.51.100.4"
    assert plugin.normalize_source_ip("hostname:10") is None
    assert plugin.normalize_source_ip(None) is None


def test_malformed_new_request_with_event_id_is_rejected(tmp_path):
    subject = runtime(tmp_path)

    response = subject.process({"type": "new", "event": {"id": "abc"}})
    assert response["action"] == "reject"
    assert response["msg"].startswith("blocked:")
    assert subject.process({"type": "notice", "event": {"id": "abc"}}) is None


def test_main_is_jsonl_and_ignores_unknown_messages(monkeypatch, tmp_path):
    subject = runtime(tmp_path)
    monkeypatch.setattr(plugin, "WritePolicyRuntime", lambda: subject)
    stdin = io.StringIO(
        "not json\n"
        + json.dumps({"type": "notice"})
        + "\n"
        + json.dumps(request())
        + "\n"
    )
    stdout = io.StringIO()

    plugin.main(
        stdin,
        stdout,
        plugin.DecisionLog(str(tmp_path / "write_policy_events.jsonl")),
    )

    assert json.loads(stdout.getvalue()) == {"id": EVENT_ID, "action": "accept"}


def run_main(subject, log_path, requests, monkeypatch, stdout=None):
    monkeypatch.setattr(plugin, "WritePolicyRuntime", lambda: subject)
    stdin = io.StringIO("".join(json.dumps(value) + "\n" for value in requests))
    stdout = io.StringIO() if stdout is None else stdout
    plugin.main(stdin, stdout, plugin.DecisionLog(str(log_path)))
    records = [json.loads(line) for line in log_path.read_text().splitlines()]
    return stdout, records


def test_main_logs_accept_reject_and_monitor_decisions_without_sensitive_data(
    monkeypatch, tmp_path
):
    enforce = runtime(
        tmp_path / "enforce",
        policy_data(pow_difficulty=20),
        ["banned"],
    )
    sensitive_request = request(
        "root",
        sourceInfo={"ip": "[2001:0db8::1]:7777", "secret": "raw-source-secret"},
    )
    sensitive_request["event"].update(
        content="content-secret",
        sig="signature-secret",
        tags=[["secret-tag"]],
        kind=1,
    )
    monitor = runtime(
        tmp_path / "monitor-log",
        policy_data(mode="monitor", pow_difficulty=20),
    )
    _, accepted = run_main(
        enforce,
        tmp_path / "accepted.jsonl",
        [sensitive_request],
        monkeypatch,
    )

    rejected_request = request(event_id="f" * 64, kind="not-an-integer")
    _, rejected = run_main(
        enforce,
        tmp_path / "rejected.jsonl",
        [rejected_request],
        monkeypatch,
    )

    _, monitored = run_main(
        monitor,
        tmp_path / "monitored.jsonl",
        [request(event_id="f" * 64)],
        monkeypatch,
    )

    timestamp_ms = accepted[0].pop("timestamp_ms")
    assert isinstance(timestamp_ms, int)
    assert timestamp_ms > 1_000_000_000_000
    assert accepted[0] == {
        "action": "accept",
        "reason": "trusted",
        "event_id": EVENT_ID,
        "pubkey": "root",
        "kind": 1,
        "source_ip": "2001:db8::1",
        "source_type": "IP4",
        "policy_mode": "enforce",
    }
    serialized = json.dumps(accepted[0])
    assert "content-secret" not in serialized
    assert "signature-secret" not in serialized
    assert "secret-tag" not in serialized
    assert "raw-source-secret" not in serialized
    assert rejected[0]["action"] == "reject"
    assert rejected[0]["reason"] == "insufficient_pow"
    assert rejected[0]["kind"] is None
    assert monitored[0]["action"] == "accept"
    assert monitored[0]["reason"] == "monitor"
    assert monitored[0]["simulated_action"] == "reject"
    assert monitored[0]["simulated_reason"] == "insufficient_pow"


def test_main_flushes_response_before_logging(monkeypatch, tmp_path):
    events = []

    class TrackingOutput(io.StringIO):
        def flush(self):
            events.append("flush")
            super().flush()

    class TrackingLog:
        def write(self, record):
            events.append("log")

    subject = runtime(tmp_path)
    monkeypatch.setattr(plugin, "WritePolicyRuntime", lambda: subject)

    plugin.main(
        io.StringIO(json.dumps(request()) + "\n"), TrackingOutput(), TrackingLog()
    )

    assert events == ["flush", "log"]


def test_decision_log_rotates_with_one_bounded_backup_and_mode_0640(tmp_path):
    path = tmp_path / "events.jsonl"
    subject = plugin.DecisionLog(str(path), max_bytes=180)

    for sequence in range(30):
        subject.write({"sequence": sequence, "value": "x" * 30})

    backup = tmp_path / "events.jsonl.1"
    assert 0 < path.stat().st_size <= 180
    assert 0 < backup.stat().st_size <= 180
    assert not (tmp_path / "events.jsonl.2").exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert stat.S_IMODE(backup.stat().st_mode) == 0o640
    assert stat.S_IMODE((tmp_path / "events.jsonl.lock").stat().st_mode) == 0o640


def test_decision_log_contention_and_failure_do_not_change_response(
    monkeypatch, tmp_path
):
    subject = runtime(tmp_path / "runtime")
    monkeypatch.setattr(plugin, "WritePolicyRuntime", lambda: subject)
    log_path = tmp_path / "events.jsonl"
    decision_log = plugin.DecisionLog(str(log_path))
    lock_descriptor = os.open(
        decision_log.lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640
    )
    fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    stdout = io.StringIO()
    try:
        plugin.main(
            io.StringIO(json.dumps(request()) + "\n"), stdout, decision_log
        )
    finally:
        os.close(lock_descriptor)

    assert json.loads(stdout.getvalue())["action"] == "accept"
    assert not log_path.exists()

    class FailingLog:
        def write(self, record):
            raise OSError("unwritable")

    stdout = io.StringIO()
    plugin.main(io.StringIO(json.dumps(request()) + "\n"), stdout, FailingLog())
    assert json.loads(stdout.getvalue())["action"] == "accept"


def test_decision_log_corrects_existing_file_permissions(tmp_path):
    path = tmp_path / "events.jsonl"
    lock_path = tmp_path / "events.jsonl.lock"
    path.write_text("")
    lock_path.write_text("")
    path.chmod(0o666)
    lock_path.chmod(0o666)

    plugin.DecisionLog(str(path)).write({"action": "accept"})

    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o640


def test_async_decision_log_drops_when_queue_is_full_without_blocking():
    started = threading.Event()
    release = threading.Event()

    class SlowLog:
        def write(self, record):
            started.set()
            release.wait(1)

    subject = plugin.AsyncDecisionLog(SlowLog(), max_pending=1)
    assert subject.write({"sequence": 1}) is True
    assert started.wait(1)
    assert subject.write({"sequence": 2}) is True

    before = time.monotonic()
    assert subject.write({"sequence": 3}) is False
    assert time.monotonic() - before < 0.1
    release.set()
    subject.pending.join()
    subject.close()


def test_decision_log_bounds_untrusted_identifier_fields(tmp_path):
    subject = runtime(tmp_path)
    oversized = request(
        pubkey="p" * 1000,
        event_id="e" * 10000,
        sourceType="source" * 100,
    )

    record = subject.process_with_details(oversized).log_record(timestamp_ms=1)
    serialized = json.dumps(record)

    assert record["event_id"] is None
    assert record["pubkey"] is None
    assert record["source_type"] is None
    assert len(serialized) < plugin.DECISION_LOG_MAX_RECORD_BYTES


def test_decision_log_drops_record_when_runtime_directory_is_missing(tmp_path):
    path = tmp_path / "missing" / "events.jsonl"

    plugin.DecisionLog(str(path)).write({"action": "accept"})

    assert not path.exists()
