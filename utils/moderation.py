import json
import os
import tempfile
import threading
import time
from dataclasses import dataclass

from sqlalchemy import update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError

from config import Config
from models import (
    AuditLog,
    BannedDomain,
    BannedPubkey,
    EventPurge,
    MetadataRelay,
    ModerationReport,
    PubkeyBanSource,
    User,
    WritePolicyProjection,
    db,
    utcnow,
)
from utils.nip05 import (
    ProfileClaimResult,
    Nip05VerificationError,
    fetch_nip05_directory,
    lookup_profile_claim,
    normalize_domain,
)
from utils.strfry import StrfryError, delete_events


_projection_lock = threading.Lock()
_domain_scan_lock = threading.Lock()
_purge_lock = threading.Lock()


class ModerationError(Exception):
    """Raised when a moderation decision cannot be recorded."""


@dataclass(frozen=True)
class DecisionOutcome:
    committed: bool
    enforcement_status: str | None = None
    purge_status: str | None = None
    enforcement_error: str | None = None
    purge_error: str | None = None
    active_set_changed: bool = True

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
    names: int
    verified: int
    unresolved: int
    invalid_entries: int
    new_sources: int
    new_bans: int
    purge_completed: int
    purge_pending: int
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


@dataclass(frozen=True)
class DomainUnbanOutcome:
    removed_sources: int
    unbanned_pubkeys: int
    remaining_bans: int
    enforcement_status: str | None = None
    enforcement_error: str | None = None

    @property
    def warnings(self):
        if self.enforcement_status == 'pending':
            return [f'Ban enforcement pending: {self.enforcement_error}']
        return []


class ModerationDecisions:
    """Record operator decisions and coordinate their follow-up effects."""

    def __init__(
        self,
        actor_id,
        ip_address=None,
        directory_fetcher=None,
        profile_lookup=None,
    ):
        self.actor_id = actor_id
        self.ip_address = ip_address
        self.directory_fetcher = directory_fetcher or fetch_nip05_directory
        self.profile_lookup = profile_lookup or lookup_profile_claim

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
            f'Banned NIP-05 domain {domain} - {reason or "No reason provided"}',
        )
        self._commit()
        return banned_domain

    def reconcile_domain(self, domain_id):
        """Enumerate a NIP-05 directory and materialize verified profile claims."""
        with _domain_scan_lock:
            banned_domain = db.session.get(BannedDomain, domain_id)
            if banned_domain is None:
                raise ModerationError('Banned domain not found')
            banned_domain.scan_status = 'running'
            banned_domain.scan_started_at = utcnow()
            domain = banned_domain.domain
            domain_reason = banned_domain.reason
            self._commit()

            total_timeout = max(1, min(Config.DOMAIN_SCAN_TOTAL_TIMEOUT, 300))
            deadline = time.monotonic() + total_timeout
            try:
                directory = self.directory_fetcher(domain, deadline)
            except (Nip05VerificationError, OSError, ValueError) as exc:
                return self._record_domain_error(domain_id, domain, str(exc))

            configured_relays = tuple(
                relay.url
                for relay in MetadataRelay.query.filter_by(enabled=True).order_by(MetadataRelay.id)
            )
            existing_sources = {
                source.banned_pubkey.pubkey: source
                for source in PubkeyBanSource.query.filter_by(
                    source_type='domain',
                    banned_domain_id=domain_id,
                )
            }
            verified = []
            unresolved = []
            known_verified = 0
            for local_name, pubkey in directory.names.items():
                if pubkey in existing_sources:
                    existing_sources[pubkey].last_seen_at = utcnow()
                    known_verified += 1
                    continue
                if time.monotonic() >= deadline:
                    unresolved.append({'name': local_name, 'pubkey': pubkey, 'error': 'Scan deadline reached'})
                    continue
                try:
                    profile_timeout = max(
                        0.1,
                        min(getattr(Config, 'NIP05_PROFILE_TIMEOUT', 10), 60),
                    )
                    profile_deadline = min(deadline, time.monotonic() + profile_timeout)
                    result = self.profile_lookup(
                        local_name,
                        domain,
                        pubkey,
                        directory.relays.get(pubkey, ()),
                        configured_relays,
                        profile_deadline,
                    )
                except (Nip05VerificationError, OSError, ValueError) as exc:
                    result = ProfileClaimResult(False, error=str(exc))
                if result.verified:
                    verified.append((local_name, pubkey, result.source))
                else:
                    unresolved.append({
                        'name': local_name,
                        'pubkey': pubkey,
                        'error': result.error or 'Profile claim could not be verified',
                    })

            verified_pubkeys = {pubkey for _, pubkey, _ in verified}
            unresolved = [
                entry for entry in unresolved if entry['pubkey'] not in verified_pubkeys
            ]

            banned_domain = db.session.get(BannedDomain, domain_id)
            if banned_domain is None:
                raise ModerationError('Banned domain not found')
            new_bans = []
            new_sources = 0
            purge_ids = []
            reason = f'Verified NIP-05 directory {domain}'
            if domain_reason:
                reason += f': {domain_reason}'

            sourced_pubkeys = set(existing_sources)
            for local_name, pubkey, source_name in verified:
                if pubkey in sourced_pubkeys:
                    continue
                ban = BannedPubkey.query.filter_by(pubkey=pubkey).first()
                ban_created = ban is None
                if ban_created:
                    ban = BannedPubkey(
                        pubkey=pubkey,
                        reason=reason,
                        banned_by=self.actor_id,
                        banned_at=utcnow(),
                    )
                    db.session.add(ban)
                    db.session.flush()
                    new_bans.append(pubkey)
                db.session.add(PubkeyBanSource(
                    banned_pubkey_id=ban.id,
                    source_type='domain',
                    banned_domain_id=domain_id,
                    local_name=local_name,
                    reason=reason,
                    banned_by=self.actor_id,
                ))
                new_sources += 1
                sourced_pubkeys.add(pubkey)
                if ban_created:
                    purge = self._pending_purge('pubkey', pubkey, None)
                    db.session.flush()
                    purge_ids.append(purge.id)

            if new_bans:
                self._mark_projection_pending()

            banned_domain.last_scanned_at = utcnow()
            banned_domain.scan_status = 'idle'
            banned_domain.scan_started_at = None
            banned_domain.last_scan_events = len(directory.names)
            banned_domain.last_scan_candidates = len(directory.names)
            verified_count = known_verified + len(verified)
            banned_domain.last_scan_verified = verified_count
            banned_domain.last_scan_new_bans = len(new_bans)
            banned_domain.last_scan_error = None
            details = {
                'invalid_entries': directory.invalid_entries,
                'unresolved': len(unresolved),
                'unresolved_entries': unresolved[:50],
                'new_sources': new_sources,
                'purge_completed': 0,
                'purge_pending': len(purge_ids),
            }
            banned_domain.last_scan_details = json.dumps(details)
            self._add_audit(
                'banned_domain_reconciled',
                f'Reconciled NIP-05 directory {domain}: {len(directory.names)} names, '
                f'{verified_count} verified, {len(unresolved)} unresolved, '
                f'{new_sources} new sources, {len(new_bans)} new bans',
            )
            self._commit()

            projection = (
                self.reconcile_write_policy()
                if new_bans
                else self.initialize_projection()
            )
            purge_completed = 0
            purge_pending = 0
            for purge_id in purge_ids:
                purge = self._attempt_purge(purge_id)
                if purge.status == 'completed':
                    purge_completed += 1
                else:
                    purge_pending += 1
            banned_domain = db.session.get(BannedDomain, domain_id)
            if banned_domain is not None:
                details['purge_completed'] = purge_completed
                details['purge_pending'] = purge_pending
                banned_domain.last_scan_details = json.dumps(details)
                self._commit()
            return DomainScanOutcome(
                names=len(directory.names),
                verified=verified_count,
                unresolved=len(unresolved),
                invalid_entries=directory.invalid_entries,
                new_sources=new_sources,
                new_bans=len(new_bans),
                purge_completed=purge_completed,
                purge_pending=purge_pending,
                enforcement_status=projection.status,
                enforcement_error=projection.last_error,
            )

    def _record_domain_error(self, domain_id, domain, error):
        banned_domain = db.session.get(BannedDomain, domain_id)
        if banned_domain is None:
            raise ModerationError('Banned domain not found')
        banned_domain.scan_status = 'idle'
        banned_domain.scan_started_at = None
        banned_domain.last_scanned_at = utcnow()
        banned_domain.last_scan_error = error
        banned_domain.last_scan_details = json.dumps({'error': error})
        self._add_audit(
            'banned_domain_reconciled',
            f'Failed to reconcile NIP-05 directory {domain}: {error}',
        )
        self._commit()
        return DomainScanOutcome(0, 0, 0, 0, 0, 0, 0, 0, scan_error=error)

    def unban_domain(self, domain_id):
        with _domain_scan_lock, _purge_lock:
            return self._unban_domain(domain_id)

    def _unban_domain(self, domain_id):
        banned_domain = db.session.get(BannedDomain, domain_id)
        if banned_domain is None:
            raise ModerationError('Banned domain not found')
        domain = banned_domain.domain
        sources = PubkeyBanSource.query.filter_by(
            source_type='domain',
            banned_domain_id=domain_id,
        ).all()
        affected_bans = {source.banned_pubkey_id: source.banned_pubkey for source in sources}
        for source in sources:
            db.session.delete(source)
        db.session.flush()
        unbanned_pubkeys = 0
        remaining_bans = 0
        for ban in affected_bans.values():
            if PubkeyBanSource.query.filter_by(banned_pubkey_id=ban.id).count() == 0:
                db.session.delete(ban)
                unbanned_pubkeys += 1
            else:
                remaining_bans += 1
        db.session.delete(banned_domain)
        if unbanned_pubkeys:
            self._mark_projection_pending()
        self._add_audit(
            'domain_unbanned',
            f'Unbanned NIP-05 domain {domain}: removed {len(sources)} sources, '
            f'unbanned {unbanned_pubkeys} pubkeys, preserved {remaining_bans} overlapping bans',
        )
        self._commit()
        projection = (
            self.reconcile_write_policy()
            if unbanned_pubkeys
            else self.initialize_projection()
        )
        return DomainUnbanOutcome(
            removed_sources=len(sources),
            unbanned_pubkeys=unbanned_pubkeys,
            remaining_bans=remaining_bans,
            enforcement_status=projection.status,
            enforcement_error=projection.last_error,
        )

    def _ban_pubkey(self, pubkey, reason, report=None):
        """Commit a Ban decision, then attempt enforcement and purge effects."""
        now = utcnow()
        ban = BannedPubkey.query.filter_by(pubkey=pubkey).first()
        ban_created = ban is None
        if ban_created:
            ban = BannedPubkey(
                pubkey=pubkey,
                reason=reason,
                banned_by=self.actor_id,
                banned_at=now,
            )
            db.session.add(ban)
            db.session.flush()

        direct_source = PubkeyBanSource.query.filter_by(
            banned_pubkey_id=ban.id,
            source_type='direct',
        ).first()
        if direct_source is None:
            db.session.add(PubkeyBanSource(
                banned_pubkey_id=ban.id,
                source_type='direct',
                reason=reason,
                banned_by=self.actor_id,
                banned_at=now,
                last_seen_at=now,
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
        with _purge_lock:
            return self._unban(ban_id)

    def _unban(self, ban_id):
        ban = db.session.get(BannedPubkey, ban_id)
        if ban is None:
            raise ModerationError('Ban not found')

        pubkey = ban.pubkey
        direct_source = PubkeyBanSource.query.filter_by(
            banned_pubkey_id=ban.id,
            source_type='direct',
        ).first()
        if direct_source is None and ban.sources:
            raise ModerationError('Pubkey is banned only by a domain rule')
        if direct_source is not None:
            db.session.delete(direct_source)
            db.session.flush()
        active_set_changed = PubkeyBanSource.query.filter_by(
            banned_pubkey_id=ban.id,
        ).count() == 0
        if active_set_changed:
            db.session.delete(ban)
            self._mark_projection_pending()
        self._add_audit(
            'user_unbanned',
            f'Removed direct ban for pubkey {pubkey}'
            + ('' if active_set_changed else '; domain ban remains active'),
        )
        self._commit()

        enforcement = (
            self.reconcile_write_policy()
            if active_set_changed
            else self.initialize_projection()
        )
        return DecisionOutcome(
            committed=True,
            enforcement_status=enforcement.status,
            enforcement_error=enforcement.last_error,
            active_set_changed=active_set_changed,
        )

    @classmethod
    def backfill_ban_sources(cls):
        created = 0
        domains = BannedDomain.query.all()
        valid_user_ids = {user_id for user_id, in db.session.query(User.id)}
        sourced_ban_ids = {
            ban_id for ban_id, in db.session.query(PubkeyBanSource.banned_pubkey_id)
        }
        for ban in BannedPubkey.query:
            if ban.id not in sourced_ban_ids:
                matched_domain = next((
                    domain
                    for domain in domains
                    if ban.reason
                    and (
                        ban.reason == f'Verified NIP-05 domain {domain.domain}'
                        or ban.reason.startswith(f'Verified NIP-05 domain {domain.domain}:')
                        or ban.reason == f'Verified NIP-05 directory {domain.domain}'
                        or ban.reason.startswith(f'Verified NIP-05 directory {domain.domain}:')
                    )
                ), None)
                direct_result = db.session.execute(sqlite_insert(PubkeyBanSource).values(
                    banned_pubkey_id=ban.id,
                    source_type='direct',
                    banned_domain_id=None,
                    reason=ban.reason,
                    banned_by=ban.banned_by if ban.banned_by in valid_user_ids else None,
                    banned_at=ban.banned_at or utcnow(),
                    last_seen_at=ban.banned_at or utcnow(),
                ).on_conflict_do_nothing())
                created += direct_result.rowcount
                if matched_domain:
                    domain_result = db.session.execute(sqlite_insert(PubkeyBanSource).values(
                        banned_pubkey_id=ban.id,
                        source_type='domain',
                        banned_domain_id=matched_domain.id,
                        reason=ban.reason,
                        banned_by=(
                            ban.banned_by if ban.banned_by in valid_user_ids else None
                        ),
                        banned_at=ban.banned_at or utcnow(),
                        last_seen_at=ban.banned_at or utcnow(),
                    ).on_conflict_do_nothing())
                    created += domain_result.rowcount
        if created:
            cls._commit()
        return created

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
        """Replace the blocklist file atomically for the polling plugin."""
        blocklist_path = Config.BANNED_PUBKEYS_FILE
        plugin_path = Config.BLOCKLIST_PLUGIN_PATH
        pubkeys = [ban.pubkey for ban in BannedPubkey.query.order_by(BannedPubkey.pubkey)]

        if not os.path.exists(plugin_path):
            raise FileNotFoundError(f'Write-policy plugin not found: {plugin_path}')
        if not os.access(plugin_path, os.X_OK):
            raise PermissionError(f'Write-policy plugin is not executable: {plugin_path}')

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
        with _purge_lock:
            return ModerationDecisions._attempt_purge_locked(purge_id)

    @staticmethod
    def _attempt_purge_locked(purge_id):
        """Run one bounded purge attempt and persist its observable outcome."""
        purge = db.session.get(EventPurge, purge_id)
        if purge is None:
            raise ModerationError('Event purge not found')
        if purge.status == 'completed':
            return purge

        purge.attempts += 1
        purge.attempted_at = utcnow()
        if purge.target_type == 'pubkey':
            if BannedPubkey.query.filter_by(pubkey=purge.target).first() is None:
                purge.status = 'completed'
                purge.last_error = 'Cancelled: pubkey is no longer banned'
                purge.completed_at = utcnow()
                ModerationDecisions._commit()
                return purge
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
