#!/usr/bin/env python3
"""strfry write-policy plugin for bans, trust scores, PoW, and rate limits."""

import ipaddress
import json
import math
import os
import sys
import time
from collections import Counter, OrderedDict
from dataclasses import dataclass, field


BASE_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
BLOCKLIST_FILE = os.path.join(BASE_DIR, "blocklist.json")
TRUST_POLICY_FILE = os.path.join(BASE_DIR, "trust_policy.json")
TRUST_POLICY_STATS_FILE = os.path.join(BASE_DIR, "trust_policy_stats.json")
NON_NETWORK_SOURCE_TYPES = frozenset({"import", "stream", "sync", "stored"})


def _file_mtime(path):
    try:
        return os.stat(path).st_mtime_ns
    except OSError:
        return None


def load_blocklist(path=BLOCKLIST_FILE):
    """Load the legacy JSON pubkey list, returning an empty set on failure."""
    try:
        with open(path, encoding="utf-8") as blocklist_file:
            data = json.load(blocklist_file)
    except (json.JSONDecodeError, OSError):
        return set()
    if not isinstance(data, list):
        return set()
    try:
        return set(data)
    except TypeError:
        return set()


def _load_valid_blocklist(path):
    try:
        with open(path, encoding="utf-8") as blocklist_file:
            data = json.load(blocklist_file)
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, list) or not all(isinstance(value, str) for value in data):
        return None
    return set(data)


@dataclass(frozen=True)
class TrustPolicy:
    version: int = 1
    mode: str = "off"
    roots: frozenset = field(default_factory=frozenset)
    scores: dict = field(default_factory=dict)
    trust_threshold: int = 0
    pow_difficulty: int = 0
    require_pow_commitment: bool = False
    generated_at: int = 0
    expires_at: int = 0
    rate_limit_per_minute: float = 0
    rate_limit_burst: int = 0
    max_tracked_ips: int = 10000

    @classmethod
    def from_dict(cls, data):
        """Validate and construct a version 1 policy."""
        if not isinstance(data, dict):
            raise ValueError("policy must be an object")

        required = {
            "version",
            "mode",
            "roots",
            "scores",
            "trust_threshold",
            "pow_difficulty",
            "require_pow_commitment",
            "generated_at",
            "expires_at",
        }
        if not required.issubset(data):
            raise ValueError("policy is missing required fields")
        if data["version"] != 1 or isinstance(data["version"], bool):
            raise ValueError("unsupported policy version")
        if data["mode"] not in {"off", "monitor", "enforce"}:
            raise ValueError("invalid policy mode")
        if not isinstance(data["roots"], list) or not all(
            isinstance(root, str) for root in data["roots"]
        ):
            raise ValueError("roots must be a list of strings")
        if not isinstance(data["scores"], dict) or not all(
            isinstance(pubkey, str) and _is_bounded_int(score, 0, 100)
            for pubkey, score in data["scores"].items()
        ):
            raise ValueError("scores must map strings to integers from 0 to 100")
        if not _is_bounded_int(data["trust_threshold"], 0, 100):
            raise ValueError("invalid trust threshold")
        if not _is_bounded_int(data["pow_difficulty"], 0, 64):
            raise ValueError("invalid PoW difficulty")
        if not isinstance(data["require_pow_commitment"], bool):
            raise ValueError("invalid PoW commitment flag")
        if not _is_int(data["generated_at"]) or not _is_int(data["expires_at"]):
            raise ValueError("policy timestamps must be integers")

        rate = data.get("rate_limit_per_minute", 0)
        burst = data.get("rate_limit_burst", 0)
        max_ips = data.get("max_tracked_ips", 10000)
        if (
            isinstance(rate, bool)
            or not isinstance(rate, (int, float))
            or not math.isfinite(rate)
            or rate < 0
        ):
            raise ValueError("invalid rate limit")
        if not _is_bounded_int(burst, 0, 1000000):
            raise ValueError("invalid rate limit burst")
        if not _is_bounded_int(max_ips, 1, 1000000):
            raise ValueError("invalid tracked IP limit")

        return cls(
            version=1,
            mode=data["mode"],
            roots=frozenset(data["roots"]),
            scores=dict(data["scores"]),
            trust_threshold=data["trust_threshold"],
            pow_difficulty=data["pow_difficulty"],
            require_pow_commitment=data["require_pow_commitment"],
            generated_at=data["generated_at"],
            expires_at=data["expires_at"],
            rate_limit_per_minute=float(rate),
            rate_limit_burst=burst,
            max_tracked_ips=max_ips,
        )


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_bounded_int(value, minimum, maximum):
    return _is_int(value) and minimum <= value <= maximum


class PolicyReloader:
    """Reload a policy by mtime while retaining the last valid value."""

    def __init__(self, path):
        self.path = path
        self.policy = TrustPolicy()
        self._mtime = object()
        self.reload()

    def reload(self):
        current_mtime = _file_mtime(self.path)
        if current_mtime == self._mtime:
            return self.policy
        self._mtime = current_mtime
        if current_mtime is None:
            return self.policy
        try:
            with open(self.path, encoding="utf-8") as policy_file:
                candidate = TrustPolicy.from_dict(json.load(policy_file))
        except (json.JSONDecodeError, OSError, ValueError, TypeError):
            return self.policy
        self.policy = candidate
        return self.policy


class BlocklistReloader:
    """Preserve the legacy blocklist reload-by-mtime behavior."""

    def __init__(self, path):
        self.path = path
        self.blocklist = load_blocklist(path)
        self._mtime = _file_mtime(path)

    def reload(self):
        current_mtime = _file_mtime(self.path)
        if current_mtime != self._mtime:
            candidate = _load_valid_blocklist(self.path)
            if candidate is not None:
                self.blocklist = candidate
            self._mtime = current_mtime
        return self.blocklist


def leading_zero_bits(event_id):
    """Return the number of actual leading zero bits in a 32-byte event id."""
    if not isinstance(event_id, str) or len(event_id) != 64:
        return -1
    try:
        raw_id = bytes.fromhex(event_id)
    except ValueError:
        return -1
    count = 0
    for byte in raw_id:
        if byte == 0:
            count += 8
            continue
        count += 8 - byte.bit_length()
        break
    return count


def has_nonce_commitment(tags, difficulty):
    """Check for a NIP-13 nonce tag committing to at least difficulty bits."""
    if not isinstance(tags, list):
        return False
    for tag in tags:
        if not isinstance(tag, list) or len(tag) < 3 or tag[0] != "nonce":
            continue
        value = tag[2]
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            committed = value
        elif isinstance(value, str) and value.isdigit():
            committed = int(value)
        else:
            continue
        if committed >= difficulty:
            return True
    return False


def normalize_source_ip(source_info):
    """Extract a canonical IP from common strfry sourceInfo representations."""
    if isinstance(source_info, dict):
        source_info = next(
            (
                source_info[key]
                for key in ("ip", "address", "host")
                if isinstance(source_info.get(key), str)
            ),
            None,
        )
    if not isinstance(source_info, str):
        return None
    value = source_info.strip()
    if not value:
        return None
    if value.startswith("["):
        closing = value.find("]")
        if closing == -1:
            return None
        host = value[1:closing]
        suffix = value[closing + 1 :]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
            return None
    else:
        host = value
        if value.count(":") == 1:
            possible_host, port = value.rsplit(":", 1)
            if port.isdigit():
                host = possible_host
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


class TokenBucket:
    """Bounded LRU collection of process-local token buckets."""

    def __init__(self):
        self._buckets = OrderedDict()

    def allow(self, key, rate_per_minute, burst, max_entries, now=None):
        if rate_per_minute <= 0 or burst <= 0:
            return True
        now = time.monotonic() if now is None else now
        key = key or "<unknown>"
        bucket = self._buckets.pop(key, None)
        if bucket is None:
            tokens, updated_at = float(burst), now
        else:
            tokens, updated_at = bucket
            tokens = min(float(burst), tokens + max(0, now - updated_at) * rate_per_minute / 60)
        allowed = tokens >= 1
        if allowed:
            tokens -= 1
        self._buckets[key] = (tokens, now)
        while len(self._buckets) > max_entries:
            self._buckets.popitem(last=False)
        return allowed


class WritePolicyRuntime:
    """Stateful, testable write-policy decision runtime."""

    def __init__(
        self,
        blocklist_path=BLOCKLIST_FILE,
        policy_path=TRUST_POLICY_FILE,
        stats_path=TRUST_POLICY_STATS_FILE,
    ):
        self.blocklists = BlocklistReloader(blocklist_path)
        self.policies = PolicyReloader(policy_path)
        self.stats_path = stats_path
        self.rate_limiter = TokenBucket()
        self.counters = Counter()
        self._stats_flushed_at = 0

    def flush_stats(self, now=None, force=False):
        """Publish aggregate counters at most once every ten seconds."""
        now = time.time() if now is None else now
        if not force and now - self._stats_flushed_at < 10:
            return
        temporary_path = self.stats_path + ".tmp"
        try:
            with open(temporary_path, "w", encoding="utf-8") as stats_file:
                json.dump(
                    {"updated_at": int(now), "counters": dict(self.counters)},
                    stats_file,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                stats_file.flush()
                os.fsync(stats_file.fileno())
            os.chmod(temporary_path, 0o644)
            os.replace(temporary_path, self.stats_path)
            self._stats_flushed_at = now
        except OSError:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass

    def process(self, request, now=None, monotonic_now=None):
        """Return a strfry response, or None for ignorable messages."""
        if not isinstance(request, dict):
            return None
        if request.get("type") != "new":
            return None

        event = request.get("event")
        event_id = event.get("id") if isinstance(event, dict) else None
        if not isinstance(event_id, str) or not event_id:
            return None
        if not isinstance(event, dict) or not isinstance(event.get("pubkey"), str):
            self.counters["malformed"] += 1
            return _reject(event_id, "blocked: malformed write-policy request")

        blocklist = self.blocklists.reload()
        policy = self.policies.reload()
        pubkey = event["pubkey"]
        if pubkey in blocklist:
            self.counters["blocked"] += 1
            return _reject(event_id, "blocked: pubkey is banned")

        source_type = request.get("sourceType")
        if isinstance(source_type, str) and source_type.lower() in NON_NETWORK_SOURCE_TYPES:
            self.counters["bypassed"] += 1
            return _accept(event_id)
        if policy.mode == "off":
            self.counters["accepted_off"] += 1
            return _accept(event_id)

        now = int(time.time()) if now is None else now
        stale = now > policy.expires_at
        score = 100 if pubkey in policy.roots else policy.scores.get(pubkey, 0)
        if stale and pubkey not in policy.roots:
            score = 0
        trusted = score >= policy.trust_threshold
        if stale and pubkey not in policy.roots:
            trusted = False

        rate_allowed = True
        if not trusted:
            rate_allowed = self.rate_limiter.allow(
                normalize_source_ip(request.get("sourceInfo")),
                policy.rate_limit_per_minute,
                policy.rate_limit_burst,
                policy.max_tracked_ips,
                monotonic_now,
            )

        pow_bits = leading_zero_bits(event_id)
        pow_valid = pow_bits >= policy.pow_difficulty
        commitment_valid = (
            policy.pow_difficulty == 0
            or not policy.require_pow_commitment
            or has_nonce_commitment(event.get("tags"), policy.pow_difficulty)
        )

        if policy.mode == "monitor":
            if trusted:
                self.counters["monitor_trusted"] += 1
            else:
                self.counters["monitor_low_trust"] += 1
                if not rate_allowed:
                    self.counters["monitor_rate_limited"] += 1
                if pow_valid and commitment_valid:
                    self.counters["monitor_pow_valid"] += 1
                else:
                    self.counters["monitor_pow_failed"] += 1
            self.counters["accepted_monitor"] += 1
            return _accept(event_id)
        if trusted:
            self.counters["accepted_trusted"] += 1
            return _accept(event_id)
        if not rate_allowed:
            self.counters["rate_limited"] += 1
            return _reject(event_id, "rate-limited: too many events from source")
        if not pow_valid:
            self.counters["pow_rejected"] += 1
            return _reject(event_id, "pow: insufficient leading-zero bits")
        if not commitment_valid:
            self.counters["pow_rejected"] += 1
            return _reject(event_id, "pow: missing nonce difficulty commitment")
        self.counters["accepted_pow"] += 1
        return _accept(event_id)


def _accept(event_id):
    return {"id": event_id, "action": "accept"}


def _reject(event_id, message):
    return {"id": event_id, "action": "reject", "msg": message}


def main(stdin=None, stdout=None):
    """Run the strfry JSONL plugin protocol loop."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    runtime = WritePolicyRuntime()
    for line in stdin:
        try:
            request = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        response = runtime.process(request)
        if response is not None:
            print(json.dumps(response, separators=(",", ":")), file=stdout, flush=True)
            runtime.flush_stats()


if __name__ == "__main__":
    main()
