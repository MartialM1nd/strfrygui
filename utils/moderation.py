import json
import os
import tempfile
import threading
from dataclasses import dataclass

from sqlalchemy import update
from sqlalchemy.exc import SQLAlchemyError

from config import Config
from models import (
    AuditLog,
    BannedPubkey,
    EventPurge,
    ModerationReport,
    WritePolicyProjection,
    db,
    utcnow,
)
from utils.strfry import StrfryError, delete_events


_projection_lock = threading.Lock()


class ModerationError(Exception):
    """Raised when a moderation decision cannot be recorded."""


@dataclass(frozen=True)
class DecisionOutcome:
    committed: bool
    enforcement_status: str | None = None
    purge_status: str | None = None
    enforcement_error: str | None = None
    purge_error: str | None = None

    @property
    def warnings(self):
        warnings = []
        if self.enforcement_status == 'pending':
            warnings.append(f'Ban enforcement pending: {self.enforcement_error}')
        if self.purge_status == 'pending':
            warnings.append(f'Event purge pending: {self.purge_error}')
        return warnings


class ModerationDecisions:
    """Record operator decisions and coordinate their follow-up effects."""

    def __init__(self, actor_id, ip_address=None):
        self.actor_id = actor_id
        self.ip_address = ip_address

    def ban_report(self, report_id, reason):
        report = db.session.get(ModerationReport, report_id)
        if report is None:
            raise ModerationError('Moderation report not found')
        if not report.reported_pubkey:
            raise ModerationError('Moderation report has no reported pubkey')

        return self._ban_pubkey(report.reported_pubkey, reason, report)

    def ban_pubkey(self, pubkey, reason):
        if not pubkey:
            raise ModerationError('Pubkey is required')
        return self._ban_pubkey(pubkey, reason)

    def _ban_pubkey(self, pubkey, reason, report=None):
        """Commit a Ban decision, then attempt enforcement and purge effects."""
        now = utcnow()
        ban = BannedPubkey.query.filter_by(pubkey=pubkey).first()
        ban_created = ban is None
        if ban_created:
            db.session.add(BannedPubkey(
                pubkey=pubkey,
                reason=reason,
                banned_by=self.actor_id,
                banned_at=now,
            ))

        if report is not None:
            report.reviewed = True
            report.reviewed_by = self.actor_id
            report.reviewed_at = now
            report.banned = True
            report.banned_by = self.actor_id
            report.banned_at = now

        if ban_created:
            self._mark_projection_pending()

        purge = self._pending_purge(
            'pubkey',
            pubkey,
            report.id if report is not None else None,
        )
        self._add_audit('pubkey_banned', f'Banned pubkey {pubkey} - {reason}')

        self._commit()

        enforcement = self.reconcile_write_policy()
        purge = self._attempt_purge(purge.id)
        return DecisionOutcome(
            committed=True,
            enforcement_status=enforcement.status,
            purge_status=purge.status,
            enforcement_error=enforcement.last_error,
            purge_error=purge.last_error,
        )

    def unban(self, ban_id):
        ban = db.session.get(BannedPubkey, ban_id)
        if ban is None:
            raise ModerationError('Ban not found')

        pubkey = ban.pubkey
        db.session.delete(ban)
        self._mark_projection_pending()
        self._add_audit('user_unbanned', f'Unbanned pubkey {pubkey}')
        self._commit()

        enforcement = self.reconcile_write_policy()
        return DecisionOutcome(
            committed=True,
            enforcement_status=enforcement.status,
            enforcement_error=enforcement.last_error,
        )

    def review_report(self, report_id):
        report = db.session.get(ModerationReport, report_id)
        if report is None:
            raise ModerationError('Moderation report not found')

        report.reviewed = True
        report.reviewed_by = self.actor_id
        report.reviewed_at = utcnow()
        self._add_audit(
            'moderation_review',
            f'Reviewed report {report.id} (type: {report.report_type})',
        )
        self._commit()
        return DecisionOutcome(committed=True)

    def retry_write_policy(self):
        projection = self._projection_state()
        self._add_audit(
            'ban_enforcement_retried',
            f'Retried write-policy projection revision {projection.desired_revision}',
        )
        self._commit()
        projection = self.reconcile_write_policy()
        return DecisionOutcome(
            committed=True,
            enforcement_status=projection.status,
            enforcement_error=projection.last_error,
        )

    def delete_report(self, report_id):
        report = db.session.get(ModerationReport, report_id)
        if report is None:
            raise ModerationError('Moderation report not found')

        db.session.delete(report)
        self._add_audit('moderation_report_deleted', f'Deleted report {report_id}')
        self._commit()
        return DecisionOutcome(committed=True)

    def delete_reported_event(self, report_id):
        report = db.session.get(ModerationReport, report_id)
        if report is None:
            raise ModerationError('Moderation report not found')
        if not report.reported_event_id:
            raise ModerationError('Moderation report has no reported event')

        now = utcnow()
        report.reviewed = True
        report.reviewed_by = self.actor_id
        report.reviewed_at = now
        purge = self._pending_purge('event', report.reported_event_id, report.id)
        self._add_audit(
            'moderation_event_purge_requested',
            f'Requested purge of event {report.reported_event_id} from report {report_id}',
        )
        self._commit()

        purge = self._attempt_purge(purge.id)
        return DecisionOutcome(
            committed=True,
            purge_status=purge.status,
            purge_error=purge.last_error,
        )

    def _add_audit(self, action, details):
        db.session.add(AuditLog(
            user_id=self.actor_id,
            action=action,
            details=details,
            ip_address=self.ip_address,
        ))

    def _pending_purge(self, target_type, target, report_id):
        purge = EventPurge.query.filter_by(
            target_type=target_type,
            target=target,
            status='pending',
        ).order_by(EventPurge.created_at).first()
        if purge is None:
            purge = EventPurge(
                target_type=target_type,
                target=target,
                requested_by=self.actor_id,
                report_id=report_id,
            )
            db.session.add(purge)
        return purge

    @staticmethod
    def _commit():
        try:
            db.session.commit()
        except SQLAlchemyError as exc:
            db.session.rollback()
            raise ModerationError(f'Failed to record moderation decision: {exc}') from exc

    @staticmethod
    def _projection_state():
        projection = db.session.get(WritePolicyProjection, 1)
        if projection is None:
            projection = WritePolicyProjection(
                id=1,
                desired_revision=0,
                published_revision=0,
                status='published',
                attempts=0,
            )
            db.session.add(projection)
        return projection

    @classmethod
    def _mark_projection_pending(cls):
        projection = cls._projection_state()
        projection.desired_revision += 1
        projection.status = 'pending'
        projection.last_error = None
        return projection

    @classmethod
    def initialize_projection(cls):
        projection = db.session.get(WritePolicyProjection, 1)
        if projection is None:
            has_bans = BannedPubkey.query.first() is not None
            projection = WritePolicyProjection(
                id=1,
                desired_revision=1 if has_bans else 0,
                published_revision=0,
                status='pending' if has_bans else 'published',
            )
            db.session.add(projection)
            cls._commit()
        return projection

    @classmethod
    def request_republication(cls):
        cls.initialize_projection()
        cls._mark_projection_pending()
        cls._commit()
        return cls.reconcile_write_policy()

    @classmethod
    def reconcile_write_policy(cls, force=False):
        """Atomically publish the complete active Ban set when needed."""
        with _projection_lock:
            projection = cls.initialize_projection()
            if (
                not force
                and projection.status == 'published'
                and projection.published_revision == projection.desired_revision
                and os.path.exists(Config.BANNED_PUBKEYS_FILE)
            ):
                return projection

            try:
                # An explicit write serializes projection snapshots across SQLite processes.
                db.session.execute(
                    update(WritePolicyProjection)
                    .where(WritePolicyProjection.id == projection.id)
                    .values(attempts=WritePolicyProjection.attempts + 1)
                )
                db.session.refresh(projection)
                attempts = projection.attempts
                desired_revision = projection.desired_revision
                cls._publish_blocklist()
                db.session.refresh(projection)
                projection.attempts = attempts
                projection.published_revision = desired_revision
                if projection.desired_revision == desired_revision:
                    projection.status = 'published'
                    projection.last_error = None
                    projection.published_at = utcnow()
                else:
                    projection.status = 'pending'
                    projection.last_error = 'A newer write-policy revision is pending'
            except OSError as exc:
                projection.status = 'pending'
                projection.last_error = str(exc)
            projection.updated_at = utcnow()
            cls._commit()
            return projection

    @staticmethod
    def _publish_blocklist():
        """Replace the blocklist file atomically and notify the plugin."""
        blocklist_path = Config.BANNED_PUBKEYS_FILE
        plugin_path = Config.BLOCKLIST_PLUGIN_PATH
        pubkeys = [ban.pubkey for ban in BannedPubkey.query.order_by(BannedPubkey.pubkey)]

        directory = os.path.dirname(blocklist_path) or '.'
        fd, temporary_path = tempfile.mkstemp(prefix='.blocklist-', dir=directory, text=True)
        try:
            with os.fdopen(fd, 'w') as blocklist_file:
                json.dump(pubkeys, blocklist_file)
                blocklist_file.flush()
                os.fsync(blocklist_file.fileno())
            os.chmod(temporary_path, 0o644)
            os.replace(temporary_path, blocklist_path)
        except OSError:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)
            raise

        if not os.path.exists(plugin_path):
            raise FileNotFoundError(f'Write-policy plugin not found: {plugin_path}')
        if not os.access(plugin_path, os.X_OK):
            os.chmod(plugin_path, 0o755)
        os.utime(plugin_path, None)

    def retry_purge(self, purge_id):
        purge = db.session.get(EventPurge, purge_id)
        if purge is None:
            raise ModerationError('Event purge not found')
        self._add_audit(
            'event_purge_retried',
            f'Retried {purge.target_type} purge for {purge.target}',
        )
        self._commit()
        return self._attempt_purge(purge_id)

    @staticmethod
    def _attempt_purge(purge_id):
        """Run one bounded purge attempt and persist its observable outcome."""
        purge = db.session.get(EventPurge, purge_id)
        if purge is None:
            raise ModerationError('Event purge not found')
        if purge.status == 'completed':
            return purge

        purge.attempts += 1
        purge.attempted_at = utcnow()
        if purge.target_type == 'pubkey':
            event_filter = {'authors': [purge.target]}
        elif purge.target_type == 'event':
            event_filter = {'ids': [purge.target]}
        else:
            raise ModerationError(f'Unsupported purge target type: {purge.target_type}')
        try:
            delete_events(
                event_filter,
                timeout=Config.MODERATION_PURGE_TIMEOUT,
            )
            purge.status = 'completed'
            purge.last_error = None
            purge.completed_at = utcnow()
        except (ValueError, StrfryError) as exc:
            purge.status = 'pending'
            purge.last_error = str(exc)
        ModerationDecisions._commit()
        return purge
