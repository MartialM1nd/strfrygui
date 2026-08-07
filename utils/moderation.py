import json
import os
import tempfile
import threading
import time
from dataclasses import dataclass

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from config import Config
from models import (
    AuditLog,
    BannedDomain,
    BannedPubkey,
    EventPurge,
    ModerationReport,
    WritePolicyProjection,
    db,
    utcnow,
)
from utils.nip05 import (
    Nip05VerificationError,
    find_domain_candidates,
    normalize_domain,
    verify_nip05,
)
from utils.strfry import StrfryError, delete_events, scan_events


_projection_lock = threading.Lock()
_domain_scan_lock = threading.Lock()


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


@dataclass(frozen=True)
class DomainScanOutcome:
    scanned_events: int
    candidates: int
    verified: int
    new_bans: int
    queued_purges: int
    enforcement_status: str | None = None
    enforcement_error: str | None = None
    scan_error: str | None = None

    @property
    def warnings(self):
        warnings = []
        if self.scan_error:
            warnings.append(f'Domain scan failed: {self.scan_error}')
        if self.enforcement_status == 'pending':
            warnings.append(f'Ban enforcement pending: {self.enforcement_error}')
        return warnings


class ModerationDecisions:
    """Record operator decisions and coordinate their follow-up effects."""

    def __init__(self, actor_id, ip_address=None, event_scanner=None, nip05_verifier=None):
        self.actor_id = actor_id
        self.ip_address = ip_address
        self.event_scanner = event_scanner or scan_events
        self.nip05_verifier = nip05_verifier or verify_nip05
        self.uses_default_nip05_verifier = nip05_verifier is None

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

    def ban_domain(self, domain, reason):
        banned_domain = self.create_domain(domain, reason)
        return banned_domain, self.reconcile_domain(banned_domain.id)

    def create_domain(self, domain, reason):
        try:
            domain = normalize_domain(domain)
        except ValueError as exc:
            raise ModerationError(str(exc)) from exc
        if BannedDomain.query.filter_by(domain=domain).first() is not None:
            raise ModerationError(f'Domain {domain} is already banned')

        reason = reason.strip() if isinstance(reason, str) else ''
        banned_domain = BannedDomain(
            domain=domain,
            reason=reason or None,
            banned_by=self.actor_id,
        )
        db.session.add(banned_domain)
        self._add_audit(
            'domain_banned',
            f'Banned NIP-05 domain {domain} and its subdomains - {reason or "No reason provided"}',
        )
        self._commit()
        return banned_domain

    def reconcile_domain(self, domain_id):
        """Discover verified local NIP-05 profiles and batch their pubkey bans."""
        with _domain_scan_lock:
            banned_domain = db.session.get(BannedDomain, domain_id)
            if banned_domain is None:
                raise ModerationError('Banned domain not found')
            banned_domain.scan_status = 'running'
            banned_domain.scan_started_at = utcnow()
            domain = banned_domain.domain
            domain_reason = banned_domain.reason
            scan_cursor = banned_domain.last_scan_cursor or 0
            self._commit()

            scan_limit = max(1, min(Config.DOMAIN_SCAN_EVENT_LIMIT, 5000))
            scan_timeout = max(1, min(Config.DOMAIN_SCAN_TIMEOUT, 300))
            try:
                events = self.event_scanner(
                    {'kinds': [0]},
                    limit=scan_limit,
                    timeout=scan_timeout,
                )
            except (StrfryError, ValueError) as exc:
                banned_domain = db.session.get(BannedDomain, domain_id)
                if banned_domain is None:
                    raise ModerationError('Banned domain not found') from exc
                banned_domain.scan_status = 'idle'
                banned_domain.scan_started_at = None
                banned_domain.last_scanned_at = utcnow()
                banned_domain.last_scan_error = str(exc)
                self._add_audit(
                    'banned_domain_reconciled',
                    f'Failed to scan NIP-05 domain {domain}: {exc}',
                )
                self._commit()
                return DomainScanOutcome(0, 0, 0, 0, 0, scan_error=str(exc))

            candidates = find_domain_candidates(events, domain)
            candidate_pubkeys = {pubkey for _, _, pubkey in candidates}
            existing_pubkeys = set()
            if candidate_pubkeys:
                existing_pubkeys = {
                    ban.pubkey
                    for ban in BannedPubkey.query.filter(
                        BannedPubkey.pubkey.in_(candidate_pubkeys)
                    )
                }
            db.session.rollback()

            candidate_limit = max(1, min(Config.DOMAIN_SCAN_CANDIDATE_LIMIT, 500))
            total_timeout = max(1, min(Config.DOMAIN_SCAN_TOTAL_TIMEOUT, 300))
            deadline = time.monotonic() + total_timeout
            verified_pubkeys = set()
            unchecked_candidates = [
                candidate for candidate in candidates if candidate[2] not in existing_pubkeys
            ]
            if unchecked_candidates:
                start = scan_cursor % len(unchecked_candidates)
                ordered_candidates = unchecked_candidates[start:] + unchecked_candidates[:start]
            else:
                start = 0
                ordered_candidates = []
            attempted_candidates = 0
            for local_name, claimed_domain, pubkey in ordered_candidates[:candidate_limit]:
                if time.monotonic() >= deadline:
                    break
                attempted_candidates += 1
                try:
                    if self.uses_default_nip05_verifier:
                        verified = self.nip05_verifier(
                            local_name,
                            claimed_domain,
                            pubkey,
                            deadline=deadline,
                        )
                    else:
                        verified = self.nip05_verifier(local_name, claimed_domain, pubkey)
                    if verified:
                        verified_pubkeys.add(pubkey)
                except (Nip05VerificationError, OSError, ValueError):
                    continue

            banned_domain = db.session.get(BannedDomain, domain_id)
            if banned_domain is None:
                raise ModerationError('Banned domain not found')
            new_pubkeys = []
            purge_ids = []
            reason = f'Verified NIP-05 domain {domain}'
            if domain_reason:
                reason += f': {domain_reason}'

            for pubkey in sorted(verified_pubkeys):
                try:
                    with db.session.begin_nested():
                        db.session.add(BannedPubkey(
                            pubkey=pubkey,
                            reason=reason,
                            banned_by=self.actor_id,
                            banned_at=utcnow(),
                        ))
                        db.session.flush()
                except IntegrityError:
                    continue
                new_pubkeys.append(pubkey)
                purge = self._pending_purge('pubkey', pubkey, None)
                db.session.flush()
                purge_ids.append(purge.id)

            if new_pubkeys:
                self._mark_projection_pending()

            banned_domain.last_scanned_at = utcnow()
            banned_domain.scan_status = 'idle'
            banned_domain.scan_started_at = None
            banned_domain.last_scan_events = len(events)
            banned_domain.last_scan_candidates = len(candidates)
            banned_domain.last_scan_verified = len(verified_pubkeys)
            banned_domain.last_scan_new_bans = len(new_pubkeys)
            banned_domain.last_scan_cursor = (
                (start + attempted_candidates) % len(unchecked_candidates)
                if unchecked_candidates
                else 0
            )
            banned_domain.last_scan_error = None
            self._add_audit(
                'banned_domain_reconciled',
                f'Reconciled NIP-05 domain {domain}: '
                f'{len(events)} events, {len(candidates)} candidates, '
                f'{len(verified_pubkeys)} verified, {len(new_pubkeys)} new bans',
            )
            self._commit()

            projection = (
                self.reconcile_write_policy()
                if new_pubkeys
                else self.initialize_projection()
            )
            return DomainScanOutcome(
                scanned_events=len(events),
                candidates=len(candidates),
                verified=len(verified_pubkeys),
                new_bans=len(new_pubkeys),
                queued_purges=len(purge_ids),
                enforcement_status=projection.status,
                enforcement_error=projection.last_error,
            )

    def delete_domain(self, domain_id):
        banned_domain = db.session.get(BannedDomain, domain_id)
        if banned_domain is None:
            raise ModerationError('Banned domain not found')
        domain = banned_domain.domain
        db.session.delete(banned_domain)
        self._add_audit(
            'banned_domain_deleted',
            f'Deleted NIP-05 domain rule {domain}; existing pubkey bans were preserved',
        )
        self._commit()
        return DecisionOutcome(committed=True)

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
