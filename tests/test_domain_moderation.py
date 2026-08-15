import json
from datetime import timedelta

import pytest

import utils.moderation as moderation_module
from config import Config
from models import (
    AuditLog,
    BannedDomain,
    BannedPubkey,
    EventPurge,
    PubkeyBanSource,
    WritePolicyProjection,
)
from utils.moderation import ModerationDecisions
from utils.nip05 import Nip05Directory, Nip05VerificationError, ProfileClaimResult


PUBKEY_A = "a" * 64
PUBKEY_B = "b" * 64
PUBKEY_C = "c" * 64


def directory(names):
    return Nip05Directory(names=names, relays={}, invalid_entries=0)


def verified_profile(name, domain, pubkey, relay_hints, configured_relays, deadline):
    return ProfileClaimResult(verified=True, source="local")


@pytest.mark.parametrize("details", ["null", "[]", '"status"', "invalid"])
def test_domain_scan_details_normalizes_non_objects(details):
    assert BannedDomain(last_scan_details=details).scan_details == {}


def test_domain_reconciliation_enumerates_verifies_bans_and_purges(app):
    decisions = ModerationDecisions(
        actor_id=7,
        directory_fetcher=lambda domain, deadline: directory({
            "alice": PUBKEY_A,
            "bob": PUBKEY_B,
            "carol": PUBKEY_C,
        }),
        profile_lookup=lambda name, domain, pubkey, relay_hints, configured_relays, deadline: (
            ProfileClaimResult(verified=pubkey != PUBKEY_C, source="local")
        ),
    )

    domain, outcome = decisions.ban_domain("Example.COM", "Coordinated abuse")

    assert domain.domain == "example.com"
    assert (outcome.names, outcome.verified, outcome.unresolved) == (3, 2, 1)
    assert (outcome.new_sources, outcome.new_bans) == (2, 2)
    assert (outcome.purge_completed, outcome.purge_pending) == (0, 2)
    assert outcome.enforcement_status == "published"

    bans = BannedPubkey.query.order_by(BannedPubkey.pubkey).all()
    assert [ban.pubkey for ban in bans] == [PUBKEY_A, PUBKEY_B]
    assert PubkeyBanSource.query.filter_by(source_type="domain").count() == 2
    assert EventPurge.query.filter_by(status="pending").count() == 2
    projection = WritePolicyProjection.query.one()
    assert projection.desired_revision == projection.published_revision == 1
    assert domain.last_scan_new_bans == 2
    assert domain.scan_details["unresolved"] == 1

    with open(app.config["BANNED_PUBKEYS_FILE"]) as blocklist_file:
        assert json.load(blocklist_file) == [PUBKEY_A, PUBKEY_B]


def test_domain_source_overlaps_direct_ban_without_duplicate_purge(app):
    decisions = ModerationDecisions(
        actor_id=7,
        directory_fetcher=lambda domain, deadline: directory({"alice": PUBKEY_A}),
        profile_lookup=verified_profile,
    )
    decisions.ban_pubkey(PUBKEY_A, "Direct ban")
    revision = WritePolicyProjection.query.one().desired_revision

    domain, outcome = decisions.ban_domain("example.com", "Domain abuse")

    ban = BannedPubkey.query.filter_by(pubkey=PUBKEY_A).one()
    assert {source.source_type for source in ban.sources} == {"direct", "domain"}
    assert outcome.new_sources == 1
    assert outcome.new_bans == 0
    assert EventPurge.query.filter_by(target=PUBKEY_A).count() == 1
    assert WritePolicyProjection.query.one().desired_revision == revision
    assert domain.last_scan_new_bans == 0

    unban = decisions.unban(ban.id)

    assert unban.active_set_changed is False
    assert BannedPubkey.query.filter_by(pubkey=PUBKEY_A).one()
    assert [source.source_type for source in ban.sources] == ["domain"]


def test_domain_reconciliation_is_additive_when_name_disappears(app):
    snapshots = [directory({"alice": PUBKEY_A}), directory({})]
    decisions = ModerationDecisions(
        actor_id=7,
        directory_fetcher=lambda domain, deadline: snapshots.pop(0),
        profile_lookup=verified_profile,
    )
    domain, _ = decisions.ban_domain("example.com", "Spam")

    second = decisions.reconcile_domain(domain.id)

    assert second.new_sources == 0
    assert BannedPubkey.query.filter_by(pubkey=PUBKEY_A).one()
    assert PubkeyBanSource.query.filter_by(banned_domain_id=domain.id).count() == 1


def test_reconciliation_refreshes_existing_source_name(app):
    snapshots = [directory({"alice": PUBKEY_A}), directory({"alice-renamed": PUBKEY_A})]
    decisions = ModerationDecisions(
        actor_id=7,
        directory_fetcher=lambda domain, deadline: snapshots.pop(0),
        profile_lookup=verified_profile,
    )
    domain, _ = decisions.ban_domain("example.com", "Spam")

    decisions.reconcile_domain(domain.id)

    source = PubkeyBanSource.query.filter_by(banned_domain_id=domain.id).one()
    assert source.local_name == "alice-renamed"


def test_reconciliation_handles_multiple_verified_aliases_for_new_pubkey(app):
    decisions = ModerationDecisions(
        actor_id=7,
        directory_fetcher=lambda domain, deadline: directory({
            "alice": PUBKEY_A,
            "alice-alias": PUBKEY_A,
        }),
        profile_lookup=verified_profile,
    )

    domain, outcome = decisions.ban_domain("example.com", "Spam")

    assert outcome.new_bans == 1
    assert PubkeyBanSource.query.filter_by(banned_domain_id=domain.id).count() == 1


def test_reconciliation_tries_bounded_aliases_until_claim_verifies(app):
    looked_up = []
    decisions = ModerationDecisions(
        actor_id=7,
        directory_fetcher=lambda domain, deadline: directory({
            "invalid-alias": PUBKEY_A,
            "valid-alias": PUBKEY_A,
        }),
        profile_lookup=lambda name, domain, pubkey, relay_hints, configured_relays, deadline: (
            looked_up.append(name)
            or ProfileClaimResult(verified=name == "valid-alias", source="local")
        ),
    )

    domain, outcome = decisions.ban_domain("example.com", "Spam")

    assert looked_up == ["invalid-alias", "valid-alias"]
    assert outcome.new_bans == 1
    source = PubkeyBanSource.query.filter_by(banned_domain_id=domain.id).one()
    assert source.local_name == "valid-alias"


def test_domain_reconciliation_caps_unique_candidates_before_lookup(app, monkeypatch):
    monkeypatch.setattr(Config, "DOMAIN_SCAN_CANDIDATE_LIMIT", 2)
    names = {
        f"user-{index}": f"{index:064x}"
        for index in range(10)
    }
    looked_up = []
    decisions = ModerationDecisions(
        actor_id=7,
        directory_fetcher=lambda domain, deadline: directory(names),
        profile_lookup=lambda name, domain, pubkey, relay_hints, configured_relays, deadline: (
            looked_up.append((name, pubkey))
            or ProfileClaimResult(verified=True, source="local")
        ),
    )

    domain, outcome = decisions.ban_domain("example.com", "Spam")

    assert looked_up == sorted(names.items())[:2]
    assert outcome.new_bans == 2
    assert outcome.purge_pending == 2
    assert domain.last_scan_candidates == 2
    assert domain.scan_details["truncated_candidates"] == 8


def test_pending_purge_processing_is_bounded(app, monkeypatch):
    decisions = ModerationDecisions(
        actor_id=7,
        directory_fetcher=lambda domain, deadline: directory({
            "alice": PUBKEY_A,
            "bob": PUBKEY_B,
            "carol": PUBKEY_C,
        }),
        profile_lookup=verified_profile,
    )
    decisions.ban_domain("example.com", "Spam")
    deleted = []
    monkeypatch.setattr(
        moderation_module,
        "delete_events",
        lambda event_filter, timeout: deleted.append(event_filter),
    )

    processed = ModerationDecisions.process_pending_purges(limit=2)

    assert len(processed) == 2
    assert len(deleted) == 2
    assert EventPurge.query.filter_by(status="completed").count() == 2
    assert EventPurge.query.filter_by(status="pending").count() == 1


def test_failed_purge_uses_exponential_retry_delay(app, monkeypatch):
    monkeypatch.setattr(Config, "STRFRY_BINARY", "/bin/false")
    monkeypatch.setattr(Config, "MODERATION_PURGE_RETRY_SECONDS", 10)
    monkeypatch.setattr(Config, "MODERATION_PURGE_RETRY_MAX_SECONDS", 100)
    decisions = ModerationDecisions(
        actor_id=7,
        directory_fetcher=lambda domain, deadline: directory({"alice": PUBKEY_A}),
        profile_lookup=verified_profile,
    )
    decisions.ban_domain("example.com", "Spam")

    first = ModerationDecisions.process_pending_purges(limit=1)
    purge = EventPurge.query.one()
    purge.attempted_at = moderation_module.utcnow() - timedelta(seconds=11)
    moderation_module.db.session.commit()
    second = ModerationDecisions.process_pending_purges(limit=1)
    purge = EventPurge.query.one()
    purge.attempted_at = moderation_module.utcnow() - timedelta(seconds=11)
    moderation_module.db.session.commit()
    too_soon = ModerationDecisions.process_pending_purges(limit=1)

    assert len(first) == len(second) == 1
    assert too_soon == []
    assert purge.attempts == 2


def test_stale_purge_claim_is_recovered_after_restart(app, monkeypatch):
    decisions = ModerationDecisions(
        actor_id=7,
        directory_fetcher=lambda domain, deadline: directory({"alice": PUBKEY_A}),
        profile_lookup=verified_profile,
    )
    decisions.ban_domain("example.com", "Spam")
    purge = EventPurge.query.one()
    purge.claimed_at = moderation_module.utcnow() - timedelta(
        seconds=Config.MODERATION_PURGE_TIMEOUT + 61
    )
    moderation_module.db.session.commit()
    deleted = []
    monkeypatch.setattr(
        moderation_module,
        "delete_events",
        lambda event_filter, timeout: deleted.append(event_filter),
    )

    processed = ModerationDecisions.process_pending_purges(limit=1)

    assert len(processed) == 1
    assert deleted == [{"authors": [PUBKEY_A]}]
    assert EventPurge.query.one().status == "completed"


def test_domain_unban_removes_only_domain_sourced_active_bans(app):
    decisions = ModerationDecisions(
        actor_id=7,
        directory_fetcher=lambda domain, deadline: directory({
            "alice": PUBKEY_A,
            "bob": PUBKEY_B,
        }),
        profile_lookup=verified_profile,
    )
    decisions.ban_pubkey(PUBKEY_B, "Direct ban")
    domain, _ = decisions.ban_domain("example.com", "Spam")
    purges_before = EventPurge.query.count()

    outcome = decisions.unban_domain(domain.id)

    assert BannedDomain.query.count() == 0
    assert BannedPubkey.query.filter_by(pubkey=PUBKEY_A).first() is None
    assert BannedPubkey.query.filter_by(pubkey=PUBKEY_B).one()
    assert PubkeyBanSource.query.filter_by(source_type="domain").count() == 0
    assert EventPurge.query.count() == purges_before
    assert (outcome.removed_sources, outcome.unbanned_pubkeys, outcome.remaining_bans) == (2, 1, 1)
    assert AuditLog.query.filter_by(action="domain_unbanned").one()


def test_domain_endpoint_error_is_persisted_for_feedback(app):
    def fail(domain, deadline):
        raise Nip05VerificationError("NIP-05 endpoint returned HTTP 404")

    decisions = ModerationDecisions(actor_id=7, directory_fetcher=fail)
    domain = decisions.create_domain("example.com", "Spam")

    outcome = decisions.reconcile_domain(domain.id)

    assert outcome.scan_error == "NIP-05 endpoint returned HTTP 404"
    assert domain.last_scan_error == outcome.scan_error
    assert domain.scan_status == "idle"
    assert BannedPubkey.query.count() == 0


def test_domain_unban_prevents_pending_purge_from_deleting_events(app, monkeypatch):
    Config.STRFRY_BINARY = "/bin/false"
    decisions = ModerationDecisions(
        actor_id=7,
        directory_fetcher=lambda domain, deadline: directory({"alice": PUBKEY_A}),
        profile_lookup=verified_profile,
    )
    domain, _ = decisions.ban_domain("example.com", "Spam")
    purge = EventPurge.query.filter_by(target=PUBKEY_A).one()
    assert purge.status == "pending"
    decisions.unban_domain(domain.id)
    monkeypatch.setattr(
        moderation_module,
        "delete_events",
        lambda event_filter, timeout: pytest.fail("unbanned events must not be purged"),
    )

    retried = decisions.retry_purge(purge.id)

    assert retried.status == "completed"
    assert retried.was_cancelled is True
