import json

from config import Config
from models import AuditLog, BannedDomain, BannedPubkey, EventPurge, WritePolicyProjection
from utils.moderation import ModerationDecisions


PUBKEY_A = "a" * 64
PUBKEY_B = "b" * 64
PUBKEY_C = "c" * 64


def profile(pubkey, nip05, created_at=1):
    content = {"nip05": nip05} if nip05 else {}
    return {
        "kind": 0,
        "pubkey": pubkey,
        "created_at": created_at,
        "content": json.dumps(content),
    }


def test_domain_reconciliation_batches_verified_pubkey_bans(app):
    scans = []
    events = [
        profile(PUBKEY_A, "alice@example.com"),
        profile(PUBKEY_B, "bob@profiles.example.com"),
        profile(PUBKEY_C, "carol@other.test"),
    ]

    def scanner(event_filter, limit, timeout):
        scans.append((event_filter, limit, timeout))
        return events

    decisions = ModerationDecisions(
        actor_id=7,
        event_scanner=scanner,
        nip05_verifier=lambda name, domain, pubkey: name != "nobody",
    )

    domain, outcome = decisions.ban_domain("Example.COM", "Coordinated abuse")

    assert domain.domain == "example.com"
    assert scans == [({"kinds": [0]}, 500, 30)]
    assert (outcome.scanned_events, outcome.candidates, outcome.verified) == (3, 2, 2)
    assert (outcome.new_bans, outcome.queued_purges) == (2, 2)
    assert outcome.enforcement_status == "published"

    bans = BannedPubkey.query.order_by(BannedPubkey.pubkey).all()
    assert [ban.pubkey for ban in bans] == [PUBKEY_A, PUBKEY_B]
    assert all("example.com" in ban.reason for ban in bans)
    assert EventPurge.query.filter_by(status="pending").count() == 2
    projection = WritePolicyProjection.query.one()
    assert projection.desired_revision == projection.published_revision == 1
    assert domain.last_scan_new_bans == 2
    assert domain.last_scan_error is None
    assert domain.scan_status == "idle"

    with open(app.config["BANNED_PUBKEYS_FILE"]) as blocklist_file:
        assert json.load(blocklist_file) == [PUBKEY_A, PUBKEY_B]


def test_repeated_domain_reconciliation_does_not_duplicate_work(app):
    events = [profile(PUBKEY_A, "alice@example.com")]
    decisions = ModerationDecisions(
        actor_id=7,
        event_scanner=lambda event_filter, limit, timeout: events,
        nip05_verifier=lambda name, domain, pubkey: True,
    )
    domain, first = decisions.ban_domain("example.com", "Spam")

    second = decisions.reconcile_domain(domain.id)

    assert (first.new_bans, second.new_bans) == (1, 0)
    assert BannedPubkey.query.count() == 1
    assert EventPurge.query.count() == 1
    projection = WritePolicyProjection.query.one()
    assert projection.desired_revision == projection.published_revision == 1


def test_deleting_domain_preserves_materialized_pubkey_bans(app):
    decisions = ModerationDecisions(
        actor_id=7,
        event_scanner=lambda event_filter, limit, timeout: [
            profile(PUBKEY_A, "alice@example.com")
        ],
        nip05_verifier=lambda name, domain, pubkey: True,
    )
    domain, _ = decisions.ban_domain("example.com", "Spam")
    revision = WritePolicyProjection.query.one().desired_revision

    decisions.delete_domain(domain.id)

    assert BannedDomain.query.count() == 0
    assert BannedPubkey.query.filter_by(pubkey=PUBKEY_A).one()
    assert EventPurge.query.filter_by(target=PUBKEY_A).one()
    assert WritePolicyProjection.query.one().desired_revision == revision
    assert AuditLog.query.filter_by(action="banned_domain_deleted").one()


def test_reconciliation_rotates_past_failed_candidates(app):
    Config.DOMAIN_SCAN_CANDIDATE_LIMIT = 1
    events = [
        profile(PUBKEY_A, "alice@example.com"),
        profile(PUBKEY_B, "bob@example.com"),
    ]
    decisions = ModerationDecisions(
        actor_id=7,
        event_scanner=lambda event_filter, limit, timeout: events,
        nip05_verifier=lambda name, domain, pubkey: pubkey == PUBKEY_B,
    )

    domain, first = decisions.ban_domain("example.com", "Spam")
    second = decisions.reconcile_domain(domain.id)

    assert first.new_bans == 0
    assert second.new_bans == 1
    assert BannedPubkey.query.filter_by(pubkey=PUBKEY_B).one()
