import logging
import time
from datetime import UTC, datetime

from sqlalchemy.exc import SQLAlchemyError

from config import Config
from models import ModerationReport, db
from utils.strfry import StrfryError, scan_events


logger = logging.getLogger(__name__)
_rejection_cache = {}
_target_cache = {}
_pending_reports = {}


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


def sync_moderation_reports():
    """Import and validate recent kind-1984 reports from the relay."""
    reports = []
    try:
        started_at = time.monotonic()
        timeout = Config.MODERATION_REPORT_SYNC_TIMEOUT
        deadline = started_at + timeout
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

        for report_index, report in enumerate(reports):
            event_id = report.get('id')
            if (
                not event_id
                or event_id in existing_ids
                or _rejection_cache.get(('report', event_id), 0) > now
            ):
                continue

            report_type = None
            reported_pubkey = None
            reported_event_id = None
            for tag in report.get('tags', []):
                if not isinstance(tag, list) or not tag:
                    continue
                if tag[0] == 'p' and len(tag) >= 3:
                    reported_pubkey = tag[1]
                    report_type = tag[2]
                elif tag[0] == 'e' and len(tag) >= 3:
                    reported_event_id = tag[1]

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
                    author_exists[reported_pubkey] = bool(scan_events(
                        {'authors': [reported_pubkey], 'limit': 1},
                        limit=1,
                        timeout=remaining,
                    ))
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
                target_key = ('event', reported_event_id)
                cached_event = _target_cache.get(target_key)
                if cached_event:
                    event_exists[reported_event_id] = cached_event[0]
                elif reported_event_id not in event_exists:
                    remaining = deadline - time.monotonic()
                    if validations >= Config.MODERATION_REPORT_VALIDATION_LIMIT or remaining <= 0:
                        _defer_reports(reports[report_index:])
                        break
                    validations += 1
                    event_exists[reported_event_id] = bool(scan_events(
                        {'ids': [reported_event_id], 'limit': 1},
                        limit=1,
                        timeout=remaining,
                    ))
                    _target_cache[target_key] = (
                        event_exists[reported_event_id],
                        now + Config.MODERATION_REPORT_REJECTION_TTL,
                    )
                if not event_exists[reported_event_id]:
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
                created_at=datetime.fromtimestamp(
                    report.get('created_at', 0), UTC
                ).replace(tzinfo=None),
            ))
            existing_ids.add(event_id)
            added += 1

        db.session.commit()
        _prune_rejection_cache(now)
        return added
    except (IndexError, TypeError, ValueError, StrfryError, SQLAlchemyError):
        db.session.rollback()
        _defer_reports(reports)
        logger.exception('Could not synchronize moderation reports')
        return None
