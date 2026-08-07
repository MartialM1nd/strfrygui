import json
import os
import stat

from config import Config
from models import (
    AuditLog,
    BannedDomain,
    BannedPubkey,
    EventPurge,
    ModerationReport,
    PubkeyBanSource,
    WritePolicyProjection,
    db,
)
from utils.moderation import ModerationDecisions


def make_report():
    report = ModerationReport(
        event_id="report-event",
        reporter_pubkey="reporter",
        reported_pubkey="bad-pubkey",
        report_type="spam",
    )
    db.session.add(report)
    db.session.commit()
    return report


def test_ban_report_records_decision_enforces_and_purges(app):
    report = make_report()

    outcome = ModerationDecisions(actor_id=7, ip_address="192.0.2.1").ban_report(
        report.id, "Repeated spam"
    )

    assert outcome.committed is True
    assert outcome.enforcement_status == "published"
    assert outcome.purge_status == "completed"

    ban = BannedPubkey.query.one()
    assert (ban.pubkey, ban.reason, ban.banned_by) == (
        "bad-pubkey",
        "Repeated spam",
        7,
    )
    assert (report.reviewed, report.banned) == (True, True)

    audit = AuditLog.query.one()
    assert audit.action == "pubkey_banned"
    assert audit.ip_address == "192.0.2.1"

    purge = EventPurge.query.one()
    assert (purge.target_type, purge.target, purge.status, purge.attempts) == (
        "pubkey",
        "bad-pubkey",
        "completed",
        1,
    )

    projection = WritePolicyProjection.query.one()
    assert projection.published_revision == projection.desired_revision == 1
    with open(app.config["BANNED_PUBKEYS_FILE"]) as blocklist_file:
        assert json.load(blocklist_file) == ["bad-pubkey"]
    assert stat.S_IMODE(os.stat(app.config["BANNED_PUBKEYS_FILE"]).st_mode) == 0o644


def test_reconciliation_publishes_an_empty_initial_projection(app):
    projection = ModerationDecisions.reconcile_write_policy()

    assert projection.status == "published"
    with open(app.config["BANNED_PUBKEYS_FILE"]) as blocklist_file:
        assert json.load(blocklist_file) == []


def test_ban_commits_when_purge_fails_and_purge_can_be_retried(app):
    report = make_report()
    Config.STRFRY_BINARY = "/bin/false"

    outcome = ModerationDecisions(actor_id=7).ban_report(report.id, "Spam")

    assert outcome.committed is True
    assert outcome.enforcement_status == "published"
    assert outcome.purge_status == "pending"
    assert outcome.warnings == ["Event purge pending: Command failed with code 1"]
    assert BannedPubkey.query.filter_by(pubkey="bad-pubkey").one()
    assert (report.reviewed, report.banned) == (True, True)

    purge = EventPurge.query.one()
    Config.STRFRY_BINARY = "/bin/true"
    retried = ModerationDecisions(actor_id=7).retry_purge(purge.id)

    assert (retried.status, retried.attempts, retried.last_error) == (
        "completed",
        2,
        None,
    )


def test_ban_reports_non_executable_strfry_as_pending_purge(app, tmp_path):
    report = make_report()
    binary = tmp_path / "strfry"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o644)
    Config.STRFRY_BINARY = str(binary)

    outcome = ModerationDecisions(actor_id=7).ban_report(report.id, "Spam")

    assert outcome.committed is True
    assert outcome.purge_status == "pending"
    assert "Failed to execute strfry" in outcome.purge_error


def test_ban_commits_when_enforcement_fails_and_projection_can_be_retried(app, tmp_path):
    report = make_report()
    blocklist_path = tmp_path / "missing" / "blocklist.json"
    app.config["BANNED_PUBKEYS_FILE"] = str(blocklist_path)
    Config.BANNED_PUBKEYS_FILE = str(blocklist_path)

    outcome = ModerationDecisions(actor_id=7).ban_report(report.id, "Spam")

    assert outcome.committed is True
    assert outcome.enforcement_status == "pending"
    assert outcome.purge_status == "completed"
    projection = WritePolicyProjection.query.one()
    assert projection.published_revision == 0
    assert projection.desired_revision == 1
    assert projection.last_error

    (tmp_path / "missing").mkdir()
    retried = ModerationDecisions.reconcile_write_policy()

    assert retried.status == "published"
    assert retried.published_revision == retried.desired_revision == 1


def test_ban_enforcement_stays_pending_without_write_policy_plugin(app, tmp_path):
    report = make_report()
    Config.BLOCKLIST_PLUGIN_PATH = str(tmp_path / "missing-plugin.py")

    outcome = ModerationDecisions(actor_id=7).ban_report(report.id, "Spam")

    assert outcome.committed is True
    assert outcome.enforcement_status == "pending"
    assert "Write-policy plugin not found" in outcome.enforcement_error


def test_repeated_ban_preserves_provenance_and_resolves_new_report(app):
    first_report = make_report()
    first = ModerationDecisions(actor_id=7).ban_report(first_report.id, "First reason")
    second_report = ModerationReport(
        event_id="second-report",
        reporter_pubkey="another-reporter",
        reported_pubkey="bad-pubkey",
        report_type="illegal",
    )
    db.session.add(second_report)
    db.session.commit()

    second = ModerationDecisions(actor_id=9).ban_report(second_report.id, "Later reason")

    assert first.committed and second.committed
    ban = BannedPubkey.query.one()
    assert (ban.reason, ban.banned_by) == ("First reason", 7)
    assert (second_report.reviewed, second_report.banned) == (True, True)
    assert AuditLog.query.filter_by(action="pubkey_banned").count() == 2
    assert EventPurge.query.filter_by(target="bad-pubkey").count() == 2
    projection = WritePolicyProjection.query.one()
    assert projection.desired_revision == projection.published_revision == 1


def test_repeated_ban_retries_existing_pending_purge(app):
    first_report = make_report()
    Config.STRFRY_BINARY = "/bin/false"
    ModerationDecisions(actor_id=7).ban_report(first_report.id, "First reason")
    second_report = ModerationReport(
        event_id="second-report",
        reporter_pubkey="another-reporter",
        reported_pubkey="bad-pubkey",
        report_type="spam",
    )
    db.session.add(second_report)
    db.session.commit()
    Config.STRFRY_BINARY = "/bin/true"

    outcome = ModerationDecisions(actor_id=9).ban_report(second_report.id, "Later reason")

    assert outcome.purge_status == "completed"
    purge = EventPurge.query.one()
    assert purge.attempts == 2
    assert (second_report.reviewed, second_report.banned) == (True, True)


def test_forced_reconciliation_replaces_stale_projection(app):
    db.session.add(BannedPubkey(pubkey="active-ban", reason="Spam", banned_by=7))
    db.session.add(WritePolicyProjection(
        id=1,
        desired_revision=1,
        published_revision=1,
        status="published",
    ))
    db.session.commit()
    with open(app.config["BANNED_PUBKEYS_FILE"], "w") as blocklist_file:
        json.dump([], blocklist_file)

    ModerationDecisions.reconcile_write_policy(force=True)

    with open(app.config["BANNED_PUBKEYS_FILE"]) as blocklist_file:
        assert json.load(blocklist_file) == ["active-ban"]


def test_direct_ban_and_unban_change_active_set_and_projection(app):
    decisions = ModerationDecisions(actor_id=7, ip_address="192.0.2.1")

    banned = decisions.ban_pubkey("direct-pubkey", "Manual moderation")
    ban = BannedPubkey.query.filter_by(pubkey="direct-pubkey").one()
    ban_id = ban.id
    assert ban.reason == "Manual moderation"
    unbanned = decisions.unban(ban_id)

    assert banned.committed and unbanned.committed
    assert unbanned.enforcement_status == "published"
    assert BannedPubkey.query.filter_by(pubkey="direct-pubkey").first() is None
    assert [entry.action for entry in AuditLog.query.order_by(AuditLog.id)] == [
        "pubkey_banned",
        "user_unbanned",
    ]
    projection = WritePolicyProjection.query.one()
    assert projection.desired_revision == projection.published_revision == 2
    with open(app.config["BANNED_PUBKEYS_FILE"]) as blocklist_file:
        assert json.load(blocklist_file) == []


def test_projection_does_not_modify_non_writable_plugin(app):
    plugin_path = app.config["BLOCKLIST_PLUGIN_PATH"]
    os.chmod(plugin_path, 0o555)
    plugin_mtime = os.stat(plugin_path).st_mtime_ns

    outcome = ModerationDecisions(actor_id=7).ban_pubkey("direct-pubkey", "Spam")

    assert outcome.enforcement_status == "published"
    assert os.stat(plugin_path).st_mtime_ns == plugin_mtime


def test_backfill_marks_legacy_bans_as_direct_sources(app):
    ban = BannedPubkey(pubkey="legacy-pubkey", reason="Legacy", banned_by=7)
    db.session.add(ban)
    db.session.commit()

    created = ModerationDecisions.backfill_ban_sources()
    repeated = ModerationDecisions.backfill_ban_sources()

    assert (created, repeated) == (1, 0)
    source = PubkeyBanSource.query.one()
    assert (source.banned_pubkey_id, source.source_type) == (ban.id, "direct")


def test_backfill_recovers_legacy_domain_sources(app):
    domain = BannedDomain(domain="example.com", reason="Spam", banned_by=7)
    ban = BannedPubkey(
        pubkey="legacy-domain-pubkey",
        reason="Verified NIP-05 domain example.com: Spam",
        banned_by=7,
    )
    db.session.add_all([domain, ban])
    db.session.commit()

    ModerationDecisions.backfill_ban_sources()

    sources = PubkeyBanSource.query.order_by(PubkeyBanSource.source_type).all()
    assert [(source.source_type, source.banned_domain_id) for source in sources] == [
        ("direct", None),
        ("domain", domain.id),
    ]


def test_delete_reported_event_resolves_report_when_purge_is_pending(app):
    report = make_report()
    report.reported_event_id = "reported-event"
    db.session.commit()
    Config.STRFRY_BINARY = "/bin/false"

    outcome = ModerationDecisions(actor_id=7).delete_reported_event(report.id)

    assert outcome.committed is True
    assert outcome.purge_status == "pending"
    assert report.reviewed is True
    purge = EventPurge.query.one()
    assert (purge.target_type, purge.target) == ("event", "reported-event")
    assert AuditLog.query.one().action == "moderation_event_purge_requested"


def test_review_and_report_deletion_are_audited_decisions(app):
    report = make_report()
    decisions = ModerationDecisions(actor_id=7)

    reviewed = decisions.review_report(report.id)
    deleted = decisions.delete_report(report.id)

    assert reviewed.committed and deleted.committed
    assert db.session.get(ModerationReport, report.id) is None
    assert [entry.action for entry in AuditLog.query.order_by(AuditLog.id)] == [
        "moderation_review",
        "moderation_report_deleted",
    ]
