import json
import os
import stat
from datetime import datetime

import pytest
from sqlalchemy.exc import SQLAlchemyError

from config import Config
from models import WoTBuildState, WoTPolicy, db
from utils import wot
from utils.strfry import npub_to_hex
from utils.wot import (
    DEFAULT_ROOT_NPUBS,
    WoTError,
    build_snapshot,
    commit_policy_settings,
    initialize_wot,
    normalize_roots,
    policy_fingerprint,
    publish_policy,
    republish_policy_settings,
    rebuild_policy,
)


def follow_event(author, follows, created_at=1):
    return {
        'id': author,
        'pubkey': author,
        'created_at': created_at,
        'kind': 3,
        'tags': [['p', pubkey] for pubkey in follows],
        'content': '',
        'sig': '0' * 128,
    }


def local_scanner(events):
    def scan(filter_json, limit, timeout):
        authors = set(filter_json['authors'])
        return [event for event in events if event['pubkey'] in authors][:limit]

    return scan


def test_initialize_wot_uses_configured_default_roots(app):
    policy, state = initialize_wot()

    assert policy.roots == list(DEFAULT_ROOT_NPUBS)
    assert policy.mode == 'off'
    assert state.status == 'idle'


def test_normalize_roots_validates_deduplicates_and_requires_a_root(app):
    root = DEFAULT_ROOT_NPUBS[0]

    assert normalize_roots([root.upper(), root]) == [root]
    try:
        normalize_roots([])
    except WoTError as exc:
        assert str(exc) == 'At least one trusted root npub is required'
    else:
        raise AssertionError('Expected an empty root set to fail')


def test_build_snapshot_scores_only_bounded_rooted_two_hop_graph(app):
    policy, _ = initialize_wot()
    roots = [npub_to_hex(npub) for npub in DEFAULT_ROOT_NPUBS]
    direct_a = 'a' * 64
    direct_b = 'b' * 64
    endorsed_twice = 'c' * 64
    endorsed_once = 'd' * 64
    disconnected = 'e' * 64
    events = [
        follow_event(roots[0], [direct_a]),
        follow_event(roots[1], [direct_b]),
        follow_event(direct_a, [endorsed_twice, endorsed_once]),
        follow_event(direct_b, [endorsed_twice]),
        follow_event(disconnected, [endorsed_once]),
    ]

    snapshot = build_snapshot(
        policy,
        scanner=local_scanner(events),
        validator=lambda event: None,
    )

    assert snapshot.scores[roots[0]] == 100
    assert snapshot.scores[direct_a] == 80
    assert snapshot.scores[endorsed_twice] == 50
    assert snapshot.scores[endorsed_once] == 45
    assert disconnected not in snapshot.scores
    assert snapshot.direct_count == 2
    assert snapshot.edge_count == 5


def test_publish_policy_writes_operator_controls_and_scores_atomically(app):
    policy, _ = initialize_wot()
    policy.mode = 'enforce'
    policy.trust_threshold = 55
    policy.pow_difficulty = 22
    policy.require_pow_commitment = False
    db.session.commit()
    snapshot = build_snapshot(
        policy,
        scanner=local_scanner([]),
        validator=lambda event: None,
    )

    publish_policy(policy, snapshot, datetime(2026, 1, 1))

    with open(Config.TRUST_POLICY_FILE) as policy_file:
        data = json.load(policy_file)
    assert data['mode'] == 'enforce'
    assert data['trust_threshold'] == 55
    assert data['pow_difficulty'] == 22
    assert data['require_pow_commitment'] is False
    assert set(data['roots']) == set(snapshot.scores)
    assert data['expires_at'] > data['generated_at']
    assert stat.S_IMODE(os.stat(Config.TRUST_POLICY_FILE).st_mode) == 0o640
    assert stat.S_IMODE(os.stat(Config.TRUST_POLICY_FILE + '.lock').st_mode) == 0o640


def test_first_runtime_publication_preserves_compatible_legacy_scores(app):
    policy, _ = initialize_wot()
    roots = [npub_to_hex(npub) for npub in policy.roots]
    legacy = {
        'version': 1,
        'mode': 'enforce',
        'roots': roots,
        'scores': {**{root: 100 for root in roots}, 'a' * 64: 45},
        'trust_threshold': 50,
        'pow_difficulty': 20,
        'require_pow_commitment': True,
        'rate_limit_per_minute': 30,
        'rate_limit_burst': 10,
        'max_tracked_ips': 10000,
        'generated_at': 1,
        'expires_at': 2,
    }
    with open(Config.LEGACY_TRUST_POLICY_FILE, 'w') as legacy_file:
        json.dump(legacy, legacy_file)
    with open(Config.TRUST_POLICY_FILE, 'w') as runtime_file:
        runtime_file.write('{broken')

    republish_policy_settings(policy)

    with open(Config.TRUST_POLICY_FILE) as policy_file:
        published = json.load(policy_file)
    assert published['scores']['a' * 64] == 45


def test_policy_fingerprint_changes_with_operator_settings(app):
    policy, _ = initialize_wot()
    original = policy_fingerprint(policy)

    policy.rate_limit_burst = 0

    assert policy_fingerprint(policy) != original
    assert len(policy_fingerprint(policy)) == 64


def test_commit_policy_settings_restores_publication_after_database_failure(monkeypatch, app):
    policy, _ = initialize_wot()
    publish_policy(policy)
    with open(Config.TRUST_POLICY_FILE) as policy_file:
        original = json.load(policy_file)
    policy.mode = 'monitor'
    original_commit = db.session.commit
    calls = 0

    def fail_once():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise SQLAlchemyError('commit failed')
        return original_commit()

    monkeypatch.setattr(db.session, 'commit', fail_once)

    with pytest.raises(SQLAlchemyError):
        commit_policy_settings(policy)

    with open(Config.TRUST_POLICY_FILE) as policy_file:
        restored = json.load(policy_file)
    assert restored['mode'] == original['mode']
    assert db.session.get(WoTPolicy, 1).mode == original['mode']


def test_rebuild_policy_records_success_and_publishes_snapshot(app):
    policy, _ = initialize_wot()
    roots = [npub_to_hex(npub) for npub in policy.roots]
    direct = 'a' * 64

    state = rebuild_policy(
        scanner=local_scanner([follow_event(roots[0], [direct])]),
        validator=lambda event: None,
    )

    assert state.status == 'idle'
    assert state.revision == 1
    assert state.identity_count == 3
    assert state.direct_count == 1
    assert state.generated_at is not None


def test_rebuild_policy_retains_previous_file_after_build_failure(app):
    policy, _ = initialize_wot()
    publish_policy(policy)
    original = open(Config.TRUST_POLICY_FILE).read()

    def fail_scan(filter_json, limit, timeout):
        raise OSError('local scan failed')

    state = rebuild_policy(scanner=fail_scan, validator=lambda event: None)

    assert state.status == 'failed'
    assert state.last_error == 'local scan failed'
    assert open(Config.TRUST_POLICY_FILE).read() == original
    assert WoTBuildState.query.one().revision == 0


def test_oversized_follow_list_is_ignored(monkeypatch, app):
    policy, _ = initialize_wot()
    roots = [npub_to_hex(npub) for npub in policy.roots]
    monkeypatch.setattr(wot, 'MAX_FOLLOWS_PER_LIST', 1)

    snapshot = build_snapshot(
        policy,
        scanner=local_scanner([
            follow_event(roots[0], ['a' * 64, 'b' * 64]),
        ]),
        validator=lambda event: None,
    )

    assert snapshot.direct_count == 0
    assert snapshot.truncated is True


def test_graph_stops_at_direct_and_edge_bounds(monkeypatch, app):
    policy, _ = initialize_wot()
    roots = [npub_to_hex(npub) for npub in policy.roots]
    monkeypatch.setattr(wot, 'MAX_DIRECT_IDENTITIES', 1)
    monkeypatch.setattr(wot, 'MAX_EDGES', 2)

    snapshot = build_snapshot(
        policy,
        scanner=local_scanner([
            follow_event(roots[0], ['a' * 64, 'b' * 64]),
            follow_event('a' * 64, ['c' * 64]),
        ]),
        validator=lambda event: None,
    )

    assert snapshot.direct_count == 1
    assert snapshot.edge_count == 2
    assert snapshot.truncated is True


def test_graph_stops_at_identity_bound(monkeypatch, app):
    policy, _ = initialize_wot()
    roots = [npub_to_hex(npub) for npub in policy.roots]
    monkeypatch.setattr(wot, 'MAX_IDENTITIES', 4)
    direct = 'a' * 64

    snapshot = build_snapshot(
        policy,
        scanner=local_scanner([
            follow_event(roots[0], [direct]),
            follow_event(direct, ['b' * 64, 'c' * 64]),
        ]),
        validator=lambda event: None,
    )

    assert len(snapshot.scores) == 4
    assert snapshot.truncated is True


def test_two_hop_scores_accumulate_distinct_endorsements(app):
    policy, _ = initialize_wot()
    roots = [npub_to_hex(npub) for npub in policy.roots]
    endorsers = [f'{index:064x}' for index in range(1, 13)]
    target = 'f' * 64
    events = [follow_event(roots[0], endorsers)]
    events.extend(follow_event(endorser, [target]) for endorser in endorsers)

    snapshot = build_snapshot(
        policy,
        scanner=local_scanner(events),
        validator=lambda event: None,
    )

    assert snapshot.scores[target] == 100


def test_rebuild_uses_operator_settings_saved_during_scan(app):
    policy, _ = initialize_wot()
    changed = False

    def scanner(filter_json, limit, timeout):
        nonlocal changed
        if not changed:
            changed = True
            current = db.session.get(type(policy), 1)
            current.mode = 'enforce'
            current.pow_difficulty = 24
            db.session.commit()
        return []

    state = rebuild_policy(scanner=scanner, validator=lambda event: None)

    assert state.status == 'idle'
    with open(Config.TRUST_POLICY_FILE) as policy_file:
        published = json.load(policy_file)
    assert published['mode'] == 'enforce'
    assert published['pow_difficulty'] == 24


def test_rebuild_rejects_graph_when_roots_change_during_scan(app):
    policy, _ = initialize_wot()
    changed = False

    def scanner(filter_json, limit, timeout):
        nonlocal changed
        if not changed:
            changed = True
            current = db.session.get(type(policy), 1)
            current.root_npubs = json.dumps([DEFAULT_ROOT_NPUBS[0]])
            db.session.commit()
        return []

    state = rebuild_policy(scanner=scanner, validator=lambda event: None)

    assert state.status == 'failed'
    assert state.last_error == 'Trusted roots changed during build; rebuilding with new roots'
    with open(Config.TRUST_POLICY_FILE) as policy_file:
        published = json.load(policy_file)
    assert published['roots'] == [npub_to_hex(DEFAULT_ROOT_NPUBS[0])]
