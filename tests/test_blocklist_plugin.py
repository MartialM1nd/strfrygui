import io
import json
import os

from utils import blocklist_plugin as plugin


EVENT_ID = "0" * 4 + "f" * 60


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


def runtime(tmp_path, policy=None, blocklist=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    blocklist_path = tmp_path / "blocklist.json"
    policy_path = tmp_path / "trust_policy.json"
    if blocklist is not None:
        write_json(blocklist_path, blocklist)
    if policy is not None:
        write_json(policy_path, policy)
    return plugin.WritePolicyRuntime(
        str(blocklist_path),
        str(policy_path),
        str(tmp_path / "trust_policy_stats.json"),
    )


def test_missing_policy_defaults_to_blocklist_only_off(tmp_path):
    subject = runtime(tmp_path, blocklist=["banned"])

    assert subject.process(request("unknown"), now=200)["action"] == "accept"
    assert subject.process(request("banned"), now=200) == {
        "id": EVENT_ID,
        "action": "reject",
        "msg": "blocked: pubkey is banned",
    }


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


def test_runtime_flushes_aggregate_stats_atomically(tmp_path):
    stats_path = tmp_path / "trust_policy_stats.json"
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

    plugin.main(stdin, stdout)

    assert json.loads(stdout.getvalue()) == {"id": EVENT_ID, "action": "accept"}
