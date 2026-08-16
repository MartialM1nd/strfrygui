import hashlib
import json
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, timedelta

from sqlalchemy.exc import SQLAlchemyError

from config import Config
from models import WoTBuildState, WoTPolicy, db, utcnow
from utils.nip05 import InvalidNostrEvent, validate_nostr_event
from utils.strfry import StrfryError, iter_scan_events, npub_to_hex
from utils.runtime_files import atomic_write, file_lock, read_bounded


DEFAULT_ROOT_NPUBS = (
    'npub12ay99qrgh9vdk0eneu8t7ccfd7x8srt3ngvdajh5mufw5dpp590su28yuc',
    'npub18ams6ewn5aj2n3wt2qawzglx9mr4nzksxhvrdc4gzrecw7n5tvjqctp424',
)
MAX_DIRECT_IDENTITIES = 5000
MAX_IDENTITIES = 100000
MAX_EDGES = 500000
MAX_FOLLOWS_PER_LIST = 2000
AUTHOR_CHUNK_SIZE = 250
BUILD_TIMEOUT_SECONDS = 300
_publication_thread_lock = threading.Lock()


class WoTError(Exception):
    """Raised when a web-of-trust policy cannot be built or published."""


@contextmanager
def _publication_lock():
    with _publication_thread_lock:
        with file_lock(Config.TRUST_POLICY_FILE + '.lock'):
            yield


@dataclass(frozen=True)
class WoTSnapshot:
    scores: dict[str, int]
    root_count: int
    direct_count: int
    edge_count: int
    truncated: bool


def policy_fingerprint(policy):
    """Return a stable concurrency token for operator-controlled policy fields."""
    document = {
        'mode': policy.mode,
        'roots': policy.roots,
        'trust_threshold': policy.trust_threshold,
        'pow_difficulty': policy.pow_difficulty,
        'require_pow_commitment': bool(policy.require_pow_commitment),
        'refresh_interval_minutes': policy.refresh_interval_minutes,
        'rate_limit_per_minute': policy.rate_limit_per_minute,
        'rate_limit_burst': policy.rate_limit_burst,
    }
    encoded = json.dumps(document, separators=(',', ':'), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def initialize_wot():
    with _publication_lock():
        policy = db.session.get(WoTPolicy, 1)
        if policy is None:
            policy = WoTPolicy(id=1, root_npubs=json.dumps(DEFAULT_ROOT_NPUBS))
            db.session.add(policy)
        state = db.session.get(WoTBuildState, 1)
        if state is None:
            state = WoTBuildState(id=1)
            db.session.add(state)
        db.session.commit()
    return policy, state


def normalize_roots(values):
    roots = []
    seen = set()
    for value in values:
        npub = value.strip().lower()
        if not npub or npub in seen:
            continue
        try:
            npub_to_hex(npub)
        except ValueError as exc:
            raise WoTError(f'Invalid root npub: {value.strip()}') from exc
        roots.append(npub)
        seen.add(npub)
    if not roots:
        raise WoTError('At least one trusted root npub is required')
    if len(roots) > 20:
        raise WoTError('At most 20 trusted roots are allowed')
    return roots


def root_pubkeys(policy):
    try:
        return [npub_to_hex(npub) for npub in normalize_roots(policy.roots)]
    except ValueError as exc:
        raise WoTError(str(exc)) from exc


def _newer_event(candidate, current):
    if current is None:
        return True
    candidate_time = candidate.get('created_at', 0)
    current_time = current.get('created_at', 0)
    return candidate_time > current_time or (
        candidate_time == current_time
        and candidate.get('id', '') < current.get('id', '')
    )


def _latest_follow_lists(authors, scanner, validator, deadline):
    latest = {}
    authors = sorted(set(authors))
    for offset in range(0, len(authors), AUTHOR_CHUNK_SIZE):
        if time.monotonic() >= deadline:
            raise WoTError('WoT build deadline reached')
        chunk = authors[offset:offset + AUTHOR_CHUNK_SIZE]
        timeout = max(1, int(deadline - time.monotonic()))
        try:
            events = scanner(
                {'kinds': [3], 'authors': chunk},
                # strfry retains one replaceable kind-3 per author; extra room
                # tolerates legacy databases that still contain older versions.
                limit=min(1000, len(chunk) * 4),
                timeout=timeout,
            )
            for event in events:
                if event.get('kind') != 3 or event.get('pubkey') not in chunk:
                    continue
                try:
                    validator(event)
                except (InvalidNostrEvent, ValueError, TypeError):
                    continue
                pubkey = event['pubkey']
                if _newer_event(event, latest.get(pubkey)):
                    latest[pubkey] = event
        except (StrfryError, OSError, ValueError) as exc:
            raise WoTError(str(exc)) from exc
    return latest


def _followed_pubkeys(event):
    followed = []
    seen = set()
    for tag in event.get('tags', []):
        if not isinstance(tag, list) or len(tag) < 2 or tag[0] != 'p':
            continue
        pubkey = tag[1]
        if (
            not isinstance(pubkey, str)
            or len(pubkey) != 64
            or pubkey in seen
        ):
            continue
        try:
            bytes.fromhex(pubkey)
        except ValueError:
            continue
        followed.append(pubkey.lower())
        seen.add(pubkey)
        if len(followed) > MAX_FOLLOWS_PER_LIST:
            return None
    return followed


def build_snapshot(policy, scanner=None, validator=None, now=None):
    """Build a bounded two-hop trust graph from local kind-3 events."""
    scanner = scanner or iter_scan_events
    validator = validator or validate_nostr_event
    now = now or utcnow()
    deadline = time.monotonic() + BUILD_TIMEOUT_SECONDS
    roots = root_pubkeys(policy)
    root_set = set(roots)
    scores = {pubkey: 100 for pubkey in roots}
    edge_count = 0
    truncated = False

    root_events = _latest_follow_lists(roots, scanner, validator, deadline)
    direct = set()
    for root in roots:
        follows = _followed_pubkeys(root_events.get(root, {}))
        if follows is None:
            truncated = True
            continue
        for pubkey in follows:
            if edge_count >= MAX_EDGES:
                truncated = True
                break
            edge_count += 1
            if pubkey not in root_set:
                direct.add(pubkey)

    if len(direct) > MAX_DIRECT_IDENTITIES:
        direct = set(sorted(direct)[:MAX_DIRECT_IDENTITIES])
        truncated = True
    for pubkey in direct:
        scores[pubkey] = 80

    direct_events = _latest_follow_lists(direct, scanner, validator, deadline)
    endorsements = {}
    stop = False
    for endorser in sorted(direct):
        follows = _followed_pubkeys(direct_events.get(endorser, {}))
        if follows is None:
            truncated = True
            continue
        for pubkey in follows:
            if edge_count >= MAX_EDGES:
                truncated = True
                stop = True
                break
            edge_count += 1
            if pubkey in scores:
                continue
            if pubkey not in endorsements and len(scores) + len(endorsements) >= MAX_IDENTITIES:
                truncated = True
                stop = True
                break
            endorsements.setdefault(pubkey, set()).add(endorser)
        if stop:
            break

    for pubkey, endorsers in endorsements.items():
        scores[pubkey] = min(100, 40 + 5 * len(endorsers))

    return WoTSnapshot(
        scores=scores,
        root_count=len(roots),
        direct_count=len(direct),
        edge_count=edge_count,
        truncated=truncated,
    )


def _atomic_json_write(path, data):
    atomic_write(
        path,
        json.dumps(data, separators=(',', ':'), sort_keys=True).encode('utf-8'),
    )


def publish_policy(policy, snapshot=None, generated_at=None):
    roots = root_pubkeys(policy)
    generated_at = generated_at or utcnow()
    scores = snapshot.scores if snapshot is not None else {root: 100 for root in roots}
    expires_at = generated_at + timedelta(
        minutes=max(60, policy.refresh_interval_minutes * 3)
    )
    generated_timestamp = int(generated_at.replace(tzinfo=UTC).timestamp())
    expires_timestamp = int(expires_at.replace(tzinfo=UTC).timestamp())
    data = {
        'version': 1,
        'mode': policy.mode,
        'roots': roots,
        'scores': scores,
        'trust_threshold': policy.trust_threshold,
        'pow_difficulty': policy.pow_difficulty,
        'require_pow_commitment': bool(policy.require_pow_commitment),
        'rate_limit_per_minute': policy.rate_limit_per_minute,
        'rate_limit_burst': policy.rate_limit_burst,
        'max_tracked_ips': 10000,
        'generated_at': generated_timestamp,
        'expires_at': expires_timestamp,
    }
    try:
        _atomic_json_write(Config.TRUST_POLICY_FILE, data)
    except OSError as exc:
        raise WoTError(f'Could not publish trust policy: {exc}') from exc
    return data


def republish_policy_settings(policy):
    """Apply operator settings immediately while retaining a compatible graph."""
    roots = root_pubkeys(policy)
    current = None
    for source_path in (
        Config.TRUST_POLICY_FILE,
        Config.LEGACY_TRUST_POLICY_FILE,
    ):
        try:
            candidate = json.loads(read_bounded(source_path, 5 * 1024 * 1024))
        except (OSError, json.JSONDecodeError, TypeError):
            continue
        if _compatible_policy_snapshot(candidate, roots):
            current = candidate
            break
    if current is None:
        return publish_policy(policy)

    current.update({
        'mode': policy.mode,
        'trust_threshold': policy.trust_threshold,
        'pow_difficulty': policy.pow_difficulty,
        'require_pow_commitment': bool(policy.require_pow_commitment),
        'rate_limit_per_minute': policy.rate_limit_per_minute,
        'rate_limit_burst': policy.rate_limit_burst,
        'max_tracked_ips': 10000,
    })
    try:
        _atomic_json_write(Config.TRUST_POLICY_FILE, current)
    except OSError as exc:
        raise WoTError(f'Could not publish trust policy: {exc}') from exc
    return current


def _compatible_policy_snapshot(candidate, roots):
    if (
        not isinstance(candidate, dict)
        or candidate.get('version') != 1
        or candidate.get('roots') != roots
        or candidate.get('mode') not in ('off', 'monitor', 'enforce')
        or not isinstance(candidate.get('scores'), dict)
        or not isinstance(candidate.get('require_pow_commitment'), bool)
    ):
        return False
    integer_fields = (
        ('trust_threshold', 0, 100),
        ('pow_difficulty', 0, 64),
        ('generated_at', 0, None),
        ('expires_at', 0, None),
    )
    for name, minimum, maximum in integer_fields:
        value = candidate.get(name)
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < minimum
            or (maximum is not None and value > maximum)
        ):
            return False
    return all(
        isinstance(pubkey, str)
        and isinstance(score, int)
        and not isinstance(score, bool)
        and 0 <= score <= 100
        for pubkey, score in candidate['scores'].items()
    )


def commit_policy_settings(policy, expected_revision=None, settings=None):
    """Publish and commit settings as one compensated application transition."""
    candidate = settings or {
        'mode': policy.mode,
        'root_npubs': policy.root_npubs,
        'trust_threshold': policy.trust_threshold,
        'pow_difficulty': policy.pow_difficulty,
        'require_pow_commitment': policy.require_pow_commitment,
        'refresh_interval_minutes': policy.refresh_interval_minutes,
        'rate_limit_per_minute': policy.rate_limit_per_minute,
        'rate_limit_burst': policy.rate_limit_burst,
    }
    with _publication_lock():
        db.session.expire(policy)
        current = db.session.get(WoTPolicy, 1)
        if current is None:
            db.session.rollback()
            raise WoTError('Web-of-trust policy is unavailable')
        if expected_revision is not None and policy_fingerprint(current) != expected_revision:
            db.session.rollback()
            raise WoTError('Policy changed. Reload before saving.')
        for name, value in candidate.items():
            setattr(current, name, value)
        try:
            published = republish_policy_settings(current)
        except WoTError:
            db.session.rollback()
            raise
        try:
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            previous = db.session.get(WoTPolicy, 1)
            republish_policy_settings(previous)
            raise
    return published


def rebuild_policy(scanner=None, validator=None):
    policy, state = initialize_wot()
    build_roots = root_pubkeys(policy)
    state.status = 'running'
    state.started_at = utcnow()
    state.last_error = None
    db.session.commit()
    try:
        snapshot = build_snapshot(policy, scanner=scanner, validator=validator)
        with _publication_lock():
            db.session.expire_all()
            policy = db.session.get(WoTPolicy, 1)
            if root_pubkeys(policy) != build_roots:
                publish_policy(policy)
                raise WoTError('Trusted roots changed during build; rebuilding with new roots')
            generated_at = utcnow()
            publish_policy(policy, snapshot, generated_at)
        state.status = 'idle'
        state.revision += 1
        state.finished_at = generated_at
        state.generated_at = generated_at
        state.root_count = snapshot.root_count
        state.direct_count = snapshot.direct_count
        state.identity_count = len(snapshot.scores)
        state.edge_count = snapshot.edge_count
        state.truncated = snapshot.truncated
        state.last_error = None
    except (WoTError, OSError, TypeError, ValueError) as exc:
        state.status = 'failed'
        state.finished_at = utcnow()
        state.last_error = str(exc)
    db.session.commit()
    return state
