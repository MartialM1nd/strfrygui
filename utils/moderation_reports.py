import logging
import json
import os
import re
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy.exc import SQLAlchemyError

from config import Config
from models import EventPurge, ModerationReport, db, utcnow
from utils.nip05 import InvalidNostrEvent, validate_nostr_event
from utils.strfry import StrfryError, scan_events
from utils.runtime_files import file_lock


logger = logging.getLogger(__name__)
_rejection_cache = {}
_target_cache = {}
_pending_reports = {}
_HEX_64 = re.compile(r'^[0-9a-f]{64}$')
_REPORT_TYPES = {'nudity', 'malware', 'profanity', 'illegal', 'spam', 'impersonation', 'other'}


def clear_rejection_cache():
    _rejection_cache.clear()
    _target_cache.clear()
    _pending_reports.clear()


def _prune_rejection_cache(now):
    expired = [event_id for event_id, expires_at in _rejection_cache.items() if expires_at <= now]
    for event_id in expired:
        del _rejection_cache[event_id]
    while len(_rejection_cache) > Config.MODERATION_REPORT_REJECTION_CACHE_SIZE:
        del _rejection_cache[next(iter(_rejection_cache))]
    expired_targets = [
        target for target, (_, expires_at) in _target_cache.items()
        if expires_at <= now
    ]
    for target in expired_targets:
        del _target_cache[target]
    while len(_target_cache) > Config.MODERATION_REPORT_REJECTION_CACHE_SIZE:
        del _target_cache[next(iter(_target_cache))]


def _defer_reports(reports):
    for report in reports:
        event_id = report.get('id')
        if event_id:
            _pending_reports[event_id] = report
    while len(_pending_reports) > Config.MODERATION_REPORT_PENDING_LIMIT:
        del _pending_reports[next(iter(_pending_reports))]


def _parse_report(report):
    encoded = json.dumps(report, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(encoded) > Config.MODERATION_REPORT_MAX_EVENT_BYTES:
        raise ValueError('report event is too large')
    validate_nostr_event(report)
    if report['kind'] != 1984:
        raise ValueError('event is not a moderation report')
    if len(report['content'].encode('utf-8')) > Config.MODERATION_REPORT_MAX_CONTENT_BYTES:
        raise ValueError('report content is too large')
    if len(report['tags']) > Config.MODERATION_REPORT_MAX_TAGS:
        raise ValueError('report has too many tags')
    p_tags = [tag for tag in report['tags'] if tag and tag[0] == 'p']
    e_tags = [tag for tag in report['tags'] if tag and tag[0] == 'e']
    if len(p_tags) != 1 or len(e_tags) > 1:
        raise ValueError('report target tags are ambiguous')
    p_tag = p_tags[0]
    e_tag = e_tags[0] if e_tags else None
    if len(p_tag) not in {2, 3} or (e_tag is not None and len(e_tag) != 3):
        raise ValueError('report target tags are ambiguous')
    reported_pubkey = p_tag[1]
    report_type = e_tag[2] if e_tag is not None else (p_tag[2] if len(p_tag) == 3 else None)
    if _HEX_64.fullmatch(reported_pubkey) is None or report_type not in _REPORT_TYPES:
        raise ValueError('report pubkey target is invalid')
    if e_tag is not None and len(p_tag) == 3 and p_tag[2] != report_type:
        raise ValueError('report target types do not match')
    reported_event_id = e_tag[1] if e_tag is not None else None
    if e_tag is not None and _HEX_64.fullmatch(reported_event_id) is None:
        raise ValueError('report event target is invalid')
    created_at = datetime.fromtimestamp(report['created_at'], UTC).replace(tzinfo=None)
    now = utcnow()
    if created_at < now - timedelta(days=Config.MODERATION_REPORT_MAX_AGE_DAYS):
        raise ValueError('report is too old')
    if created_at > now + timedelta(minutes=5):
        raise ValueError('report timestamp is in the future')
    return reported_pubkey, reported_event_id, report_type, created_at


def _delete_expired_reviewed_reports():
    cutoff = utcnow() - timedelta(days=Config.MODERATION_REPORT_REVIEWED_RETENTION_DAYS)
    report_ids = [
        report_id
        for report_id, in db.session.query(ModerationReport.id).filter(
            ModerationReport.reviewed.is_(True),
            ModerationReport.received_at < cutoff,
        ).order_by(ModerationReport.id).limit(Config.MODERATION_REPORT_RETENTION_BATCH_SIZE)
    ]
    if report_ids:
        EventPurge.query.filter(EventPurge.report_id.in_(report_ids)).update(
            {'report_id': None}, synchronize_session=False
        )
        ModerationReport.query.filter(ModerationReport.id.in_(report_ids)).delete(
            synchronize_session=False
        )
        db.session.commit()


def _target_exists(events, pubkey, event_id=None):
    for event in events:
        try:
            validate_nostr_event(event)
        except InvalidNostrEvent:
            continue
        if event.get('pubkey') != pubkey:
            continue
        if event_id is not None and event.get('id') != event_id:
            continue
        return True
    return False


def sync_moderation_reports():
    lock_path = os.path.join(Config.LOCK_DIR, 'moderation-report-sync.lock')
    try:
        with file_lock(lock_path, blocking=False):
            return _sync_moderation_reports()
    except BlockingIOError:
        return 0


def _sync_moderation_reports():
    """Import and validate recent kind-1984 reports from the relay."""
    reports = []
    try:
        started_at = time.monotonic()
        timeout = Config.MODERATION_REPORT_SYNC_TIMEOUT
        deadline = started_at + timeout
        _delete_expired_reviewed_reports()
        scanned_reports = scan_events(
            {'kinds': [1984], 'limit': 200},
            limit=200,
            timeout=timeout,
        )
        reports_by_id = dict(_pending_reports)
        _pending_reports.clear()
        for report in scanned_reports:
            if report.get('id'):
                reports_by_id[report['id']] = report
        reports = list(reports_by_id.values())
        event_ids = [report.get('id') for report in reports if report.get('id')]
        existing_ids = set()
        if event_ids:
            existing_ids = {
                event_id
                for event_id, in db.session.query(ModerationReport.event_id).filter(
                    ModerationReport.event_id.in_(event_ids)
                )
            }

        now = time.monotonic()
        _prune_rejection_cache(now)
        author_exists = {}
        event_exists = {}
        validations = 0
        added = 0
        stored_count = ModerationReport.query.count()
        reporter_cutoff = utcnow() - timedelta(days=1)
        accepted_by_reporter = {}

        for report_index, report in enumerate(reports):
            event_id = report.get('id')
            if (
                not event_id
                or event_id in existing_ids
                or _rejection_cache.get(('report', event_id), 0) > now
            ):
                continue
            try:
                reported_pubkey, reported_event_id, report_type, created_at = _parse_report(report)
            except (InvalidNostrEvent, KeyError, TypeError, ValueError, OverflowError):
                _rejection_cache[('report', event_id)] = now + Config.MODERATION_REPORT_REJECTION_TTL
                continue
            if added >= Config.MODERATION_REPORT_ACCEPT_LIMIT or stored_count + added >= Config.MODERATION_REPORT_MAX_STORED:
                break
            reporter_count = ModerationReport.query.filter(
                ModerationReport.reporter_pubkey == report['pubkey'],
                ModerationReport.received_at >= reporter_cutoff,
            ).count()
            reporter_count += accepted_by_reporter.get(report['pubkey'], 0)
            if reporter_count >= Config.MODERATION_REPORT_REPORTER_LIMIT:
                _rejection_cache[('report', event_id)] = now + Config.MODERATION_REPORT_REJECTION_TTL
                continue

            if reported_pubkey:
                author_key = ('author', reported_pubkey)
                cached_author = _target_cache.get(author_key)
                if cached_author:
                    author_exists[reported_pubkey] = cached_author[0]
                elif reported_pubkey not in author_exists:
                    remaining = deadline - time.monotonic()
                    if validations >= Config.MODERATION_REPORT_VALIDATION_LIMIT or remaining <= 0:
                        _defer_reports(reports[report_index:])
                        break
                    validations += 1
                    author_events = scan_events(
                        {'authors': [reported_pubkey], 'limit': 1},
                        limit=1,
                        timeout=remaining,
                    )
                    author_exists[reported_pubkey] = _target_exists(
                        author_events, reported_pubkey
                    )
                    _target_cache[author_key] = (
                        author_exists[reported_pubkey],
                        now + Config.MODERATION_REPORT_REJECTION_TTL,
                    )
                if not author_exists[reported_pubkey]:
                    _rejection_cache[('report', event_id)] = (
                        now + Config.MODERATION_REPORT_REJECTION_TTL
                    )
                    continue

            if reported_event_id:
                target_key = ('event', reported_event_id, reported_pubkey)
                event_identity = (reported_event_id, reported_pubkey)
                cached_event = _target_cache.get(target_key)
                if cached_event:
                    event_exists[event_identity] = cached_event[0]
                elif event_identity not in event_exists:
                    remaining = deadline - time.monotonic()
                    if validations >= Config.MODERATION_REPORT_VALIDATION_LIMIT or remaining <= 0:
                        _defer_reports(reports[report_index:])
                        break
                    validations += 1
                    target_events = scan_events(
                        {'ids': [reported_event_id], 'limit': 1},
                        limit=1,
                        timeout=remaining,
                    )
                    event_exists[event_identity] = _target_exists(
                        target_events,
                        reported_pubkey,
                        event_id=reported_event_id,
                    )
                    _target_cache[target_key] = (
                        event_exists[event_identity],
                        now + Config.MODERATION_REPORT_REJECTION_TTL,
                    )
                if not event_exists[event_identity]:
                    _rejection_cache[('report', event_id)] = (
                        now + Config.MODERATION_REPORT_REJECTION_TTL
                    )
                    continue

            db.session.add(ModerationReport(
                event_id=event_id,
                reporter_pubkey=report.get('pubkey'),
                reported_pubkey=reported_pubkey,
                reported_event_id=reported_event_id,
                report_type=report_type,
                content=report.get('content', ''),
                created_at=created_at,
                received_at=utcnow(),
            ))
            existing_ids.add(event_id)
            accepted_by_reporter[report['pubkey']] = accepted_by_reporter.get(report['pubkey'], 0) + 1
            added += 1

        db.session.commit()
        _prune_rejection_cache(now)
        return added
    except (IndexError, TypeError, ValueError, StrfryError, SQLAlchemyError):
        db.session.rollback()
        _defer_reports(reports)
        logger.exception('Could not synchronize moderation reports')
        return None
