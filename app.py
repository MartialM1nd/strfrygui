import csv
import hmac
import ipaddress
import json
import os
import queue
import re
import secrets
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime, time as datetime_time, timedelta
from urllib.parse import urlsplit
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort, make_response, g, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import CSRFProtect, FlaskForm
from flask_wtf.csrf import CSRFError
from wtforms import BooleanField, StringField, SelectField, TextAreaField, IntegerField, HiddenField
from wtforms.validators import DataRequired, InputRequired, Length, NumberRange, Optional, Regexp, ValidationError
from flask_limiter import Limiter
from sqlalchemy import and_, func, or_
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from sqlalchemy.orm import joinedload
from io import StringIO
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config, bundled_plugin_available
from models import (
    db, User, AuditLog, ModerationReport, BannedPubkey, BannedDomain, MetadataRelay,
    EventPurge, PubkeyBanSource, WoTBuildState, ensure_audit_log_indexes,
    ensure_moderation_report_indexes, utcnow,
)
from utils.strfry import (
    scan_events, delete_events, export_events, import_events,
    negentropy_list, negentropy_add, negentropy_build,
    negentropy_delete, dict_list, StrfryError,
    validate_filter_json, hex_to_npub, npub_to_hex,
)
from utils.metrics import get_summary, MetricsError
from utils.auth import admin_required, moderator_required, viewer_or_higher, permission_required
from utils.nostr_auth import NostrAuthError, issue_challenge, normalize_pubkey, verify_request
from utils.moderation import ModerationDecisions, ModerationError
from utils.moderation_reports import sync_moderation_reports
from utils.nip05 import (
    InvalidNostrEvent,
    LOCAL_NAME_PATTERN,
    PUBKEY_PATTERN,
    Nip05VerificationError,
    fetch_nip05_document,
    normalize_domain,
    validate_nostr_event,
)
from utils.domain_view import domain_identity_page, unresolved_identity_page
from utils.decision_log import read_decision_log
from utils.dashboard import collect_sample, connection_summary, dashboard_summary
from utils.configuration import (
    ConfigurationBusy,
    ConfigurationError,
    RevisionConflict,
    load_configuration,
)
from utils.wot import (
    WoTError,
    commit_policy_settings,
    initialize_wot,
    normalize_roots,
    policy_fingerprint,
    rebuild_policy,
    republish_policy_settings,
)
from utils.relay import (
    MAX_RELAYS,
    RelayError,
    lookup_kind0 as safe_lookup_kind0,
    normalize_relay_url,
    test_relay,
)
from utils.runtime_files import file_lock, read_bounded

_domain_scan_queue = queue.Queue(maxsize=1)
_wot_build_queue = queue.Queue(maxsize=1)
_purge_wakeup = queue.Queue(maxsize=1)
_dashboard_sample_lock = threading.Lock()
_operator_thread_lock = threading.Lock()
_metadata_relay_thread_lock = threading.Lock()


@contextmanager
def _operator_mutation_lock():
    """Serialize active-admin invariant checks across web workers."""
    lock_path = os.path.join(Config.LOCK_DIR, 'operator-mutations.lock')
    with _operator_thread_lock, file_lock(lock_path):
        yield


@contextmanager
def _metadata_relay_mutation_lock():
    """Serialize metadata-relay capacity checks and mutations across workers."""
    lock_path = os.path.join(Config.LOCK_DIR, 'metadata-relay-mutations.lock')
    with _metadata_relay_thread_lock, file_lock(lock_path):
        yield


class PubkeyMetadataCache:
    def __init__(self, max_size, ttl_seconds, negative_ttl_seconds):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.negative_ttl_seconds = negative_ttl_seconds
        self.lock = threading.RLock()
        self.generation = 0

    def get(self, pubkey):
        with self.lock:
            entry = self.cache.get(pubkey)
            if entry is None:
                return False, None
            metadata, expires_at = entry
            if time.monotonic() >= expires_at:
                del self.cache[pubkey]
                return False, None
            self.cache.move_to_end(pubkey)
            return True, metadata

    def set(self, pubkey, metadata, expected_generation=None):
        ttl = self.ttl_seconds if metadata else self.negative_ttl_seconds
        with self.lock:
            if (
                expected_generation is not None
                and expected_generation != self.generation
            ):
                return False
            self.cache[pubkey] = (metadata, time.monotonic() + ttl)
            self.cache.move_to_end(pubkey)
            while len(self.cache) > self.max_size:
                self.cache.popitem(last=False)
            return True

    def current_generation(self):
        with self.lock:
            return self.generation

    def clear(self):
        with self.lock:
            self.cache.clear()
            self.generation += 1


class MetadataLookupBusy(RuntimeError):
    """Raised when bounded external metadata lookup capacity is exhausted."""


pubkey_metadata_cache = PubkeyMetadataCache(
    Config.METADATA_CACHE_MAX_ENTRIES,
    Config.METADATA_CACHE_TTL_SECONDS,
    Config.METADATA_NEGATIVE_CACHE_TTL_SECONDS,
)
_metadata_lookup_slots = threading.BoundedSemaphore(Config.METADATA_LOOKUP_CONCURRENCY)
_metadata_inflight = set()
_metadata_inflight_lock = threading.Lock()


def fetch_from_external_relays(pubkey, relays_list=None):
    """Fetch bounded, signed kind-0 metadata from configured public relays."""
    if not isinstance(pubkey, str) or PUBKEY_PATTERN.fullmatch(pubkey) is None:
        raise ValueError('Pubkey must be 64 lowercase hexadecimal characters.')
    if relays_list is None:
        enabled_relays = MetadataRelay.query.filter_by(enabled=True).order_by(MetadataRelay.id).all()
        relays_list = [r.url for r in enabled_relays]

    normalized_relays = []
    for relay_url in relays_list:
        try:
            normalized = normalize_relay_url(relay_url)
        except RelayError:
            continue
        if normalized not in normalized_relays:
            normalized_relays.append(normalized)
        if len(normalized_relays) == Config.METADATA_LOOKUP_MAX_RELAYS:
            break

    try:
        event = safe_lookup_kind0(
            pubkey,
            normalized_relays,
            timeout=Config.METADATA_LOOKUP_TIMEOUT,
        )
    except RelayError as exc:
        app.logger.warning('External metadata lookup rejected: %s', exc)
        return None
    if event is None:
        return None
    try:
        if len(event['content'].encode('utf-8')) > Config.METADATA_MAX_CONTENT_BYTES:
            return None
        metadata = json.loads(event['content'])
    except (KeyError, TypeError, json.JSONDecodeError):
        return None
    if isinstance(metadata, dict):
        return metadata
    return None


def get_pubkey_metadata(pubkey, refresh=False):
    if not isinstance(pubkey, str) or PUBKEY_PATTERN.fullmatch(pubkey) is None:
        raise ValueError('Pubkey must be 64 lowercase hexadecimal characters.')
    cache_hit, cached = (False, None) if refresh else pubkey_metadata_cache.get(pubkey)
    if cache_hit:
        return cached
    if not _metadata_lookup_slots.acquire(blocking=False):
        raise MetadataLookupBusy('Metadata lookup capacity is exhausted.')
    with _metadata_inflight_lock:
        if pubkey in _metadata_inflight:
            _metadata_lookup_slots.release()
            raise MetadataLookupBusy('Metadata lookup is already in progress.')
        _metadata_inflight.add(pubkey)
    try:
        if not refresh:
            cache_hit, cached = pubkey_metadata_cache.get(pubkey)
            if cache_hit:
                return cached
        generation = pubkey_metadata_cache.current_generation()
        try:
            events = scan_events({
                'kinds': [0],
                'authors': [pubkey]
            }, limit=1, timeout=Config.METADATA_LOOKUP_TIMEOUT)
            if events:
                validate_nostr_event(events[0])
                if events[0].get('pubkey') != pubkey or events[0].get('kind') != 0:
                    raise ValueError('Unexpected profile event')
                if len(events[0]['content'].encode('utf-8')) > Config.METADATA_MAX_CONTENT_BYTES:
                    raise ValueError('Profile metadata is too large')
                content = json.loads(events[0]['content'])
                if isinstance(content, dict):
                    pubkey_metadata_cache.set(
                        pubkey, content, expected_generation=generation
                    )
                    return content
        except (InvalidNostrEvent, StrfryError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            pass

        metadata = fetch_from_external_relays(pubkey)
        if metadata:
            pubkey_metadata_cache.set(
                pubkey, metadata, expected_generation=generation
            )
            return metadata

        pubkey_metadata_cache.set(pubkey, {}, expected_generation=generation)
        return {}
    finally:
        with _metadata_inflight_lock:
            _metadata_inflight.discard(pubkey)
        _metadata_lookup_slots.release()


def _profile_username(pubkey, user_id=None):
    """Return a unique operator name from signed profile metadata or the npub."""
    try:
        metadata = get_pubkey_metadata(pubkey, refresh=True)
    except (MetadataLookupBusy, ValueError):
        metadata = {}
    profile_name = metadata.get('name') if isinstance(metadata, dict) else None
    if isinstance(profile_name, str):
        profile_name = ' '.join(profile_name.split())
        if (
            profile_name
            and len(profile_name) <= 80
            and all(character.isprintable() for character in profile_name)
            and not _username_in_use(profile_name, user_id)
        ):
            return profile_name

    npub = hex_to_npub(pubkey)
    for length in range(17, len(npub) + 1):
        candidate = npub[:length]
        if not _username_in_use(candidate, user_id):
            return candidate
    suffix = 2
    while _username_in_use(f'{npub}_{suffix}', user_id):
        suffix += 1
    return f'{npub}_{suffix}'


def _username_in_use(username, user_id=None):
    query = User.query.filter_by(username=username)
    if user_id is not None:
        query = query.filter(User.id != user_id)
    return query.first() is not None


app = Flask(__name__)
app.config.from_object(Config)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=app.config['TRUSTED_PROXY_COUNT'])

db.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

limiter = Limiter(
    app=app,
    key_func=lambda: get_client_ip(),
    default_limits=[Config.RATELIMIT_DEFAULT],
)


@app.before_request
def apply_request_limits():
    g.csp_nonce = secrets.token_urlsafe(24)
    is_import = request.endpoint == 'import_export'
    maximum = app.config[
        'IMPORT_REQUEST_MAX_BYTES' if is_import else 'REQUEST_MAX_BYTES'
    ]
    request.max_content_length = maximum
    request.max_form_memory_size = (
        app.config['IMPORT_MAX_BYTES'] + 65536
        if is_import
        else min(app.config['REQUEST_MAX_BYTES'], 256 * 1024)
    )
    request.max_form_parts = app.config['MAX_FORM_PARTS']
    if request.content_length is not None and request.content_length > maximum:
        raise RequestEntityTooLarge()
    if request.content_length is None and request.environ.get('HTTP_TRANSFER_ENCODING'):
        request.get_data(cache=True)


@app.after_request
def apply_security_headers(response):
    nonce = getattr(g, 'csp_nonce', '')
    response.headers['Content-Security-Policy'] = '; '.join((
        "default-src 'none'",
        "base-uri 'none'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        f"script-src 'self' 'nonce-{nonce}'",
        "script-src-attr 'none'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "worker-src 'none'",
    ))
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = (
        'accelerometer=(), camera=(), geolocation=(), gyroscope=(), '
        'magnetometer=(), microphone=(), payment=(), usb=()'
    )
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    response.headers['X-XSS-Protection'] = '0'
    if request.endpoint == 'static':
        if '/vendor/' in request.path:
            response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        else:
            response.headers['Cache-Control'] = 'public, max-age=0, must-revalidate'
    else:
        response.headers['Cache-Control'] = 'no-store, max-age=0, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    session_version = session.get('_nostr_auth_version')
    if user and session_version != user.auth_version:
        return None
    return user


class AdminCreateUserForm(FlaskForm):
    nostr_pubkey = StringField('Nostr Pubkey', validators=[DataRequired(), Length(max=128)])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('moderator', 'Moderator'), ('viewer', 'Viewer')], validators=[DataRequired()])

    def validate_nostr_pubkey(self, field):
        try:
            field.data = normalize_pubkey(field.data)
        except NostrAuthError as exc:
            raise ValidationError(str(exc)) from exc


class UserEditForm(FlaskForm):
    role = SelectField('Role', choices=[('admin', 'Admin'), ('moderator', 'Moderator'), ('viewer', 'Viewer')], validators=[DataRequired()])
    is_active = SelectField('Active', choices=[('true', 'Yes'), ('false', 'No')], validators=[DataRequired()])
    nostr_pubkey = StringField('Nostr Pubkey', validators=[DataRequired(), Length(max=128)])

    def validate_nostr_pubkey(self, field):
        try:
            field.data = normalize_pubkey(field.data)
        except NostrAuthError as exc:
            raise ValidationError(str(exc)) from exc


class DeleteForm(FlaskForm):
    filter_json = TextAreaField('Nostr Filter (JSON)', validators=[DataRequired()])
    confirm_delete = StringField('Type DELETE to confirm', validators=[DataRequired()])


class EmptyForm(FlaskForm):
    pass


class BannedDomainForm(FlaskForm):
    domain = StringField('NIP-05 Domain', validators=[DataRequired(), Length(max=253)])
    reason = TextAreaField('Reason', validators=[Optional(), Length(max=1000)])

    def validate_domain(self, field):
        try:
            field.data = normalize_domain(field.data)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc


class EventSearchForm(FlaskForm):
    search_type = SelectField('Search Type', choices=[
        ('all', 'All Events'),
        ('keyword', 'By Keyword'),
        ('nip05', 'By NIP-05'),
        ('pubkey', 'By Pubkey'),
        ('event_id', 'By Event ID'),
        ('kind', 'By Kind'),
        ('timerange', 'By Time Range'),
        ('tag', 'By Tag'),
        ('advanced', 'Advanced (JSON)')
    ])
    keyword = StringField('Keyword', validators=[Optional()])
    nip05 = StringField('NIP-05 (e.g., user@domain.com)', validators=[Optional()])
    pubkey = StringField('Pubkey', validators=[Optional()])
    event_id = StringField('Event ID', validators=[Optional()])
    kind = StringField('Kind', validators=[Optional()])
    since = StringField('Since', validators=[Optional()])
    until = StringField('Until', validators=[Optional()])
    tag_name = StringField('Tag Name (e.g., p, e)', validators=[Optional()])
    tag_value = StringField('Tag Value', validators=[Optional()])
    filter_json = TextAreaField('Custom Filter (JSON)', validators=[Optional()])
    limit = IntegerField('Limit', default=25, validators=[NumberRange(min=1, max=1000)])


class ExportForm(FlaskForm):
    since = IntegerField('Since (timestamp)', validators=[Optional(), NumberRange(min=0)])
    until = IntegerField('Until (timestamp)', validators=[Optional(), NumberRange(min=0)])
    reverse = SelectField('Order', choices=[('false', 'Ascending (oldest first)'), ('reverse', 'Descending (newest first)')])
    fried = SelectField('Fried Export', choices=[('false', 'No'), ('true', 'Yes (faster re-import)')])

    def validate_until(self, field):
        if self.since.data is not None and field.data is not None and field.data < self.since.data:
            raise ValidationError('Until must be greater than or equal to since.')


class ImportForm(FlaskForm):
    file = TextAreaField('JSONL Data', validators=[
        DataRequired(),
        Length(max=Config.IMPORT_MAX_BYTES),
    ])
    no_verify = SelectField('Skip Verification', choices=[('false', 'Verify signatures'), ('true', 'No verification (faster)')])
    confirm_no_verify = BooleanField('I understand that signature verification will be skipped')

    def validate_confirm_no_verify(self, field):
        if self.no_verify.data == 'true' and not field.data:
            raise ValidationError('Confirm that you understand the risk of skipping verification.')


def control_safe(form, field):
    if field.data and any(ord(char) < 32 or ord(char) == 127 for char in field.data):
        raise ValidationError('Control characters are not allowed.')


class ConfigurationRevisionForm(FlaskForm):
    config_revision = HiddenField(validators=[
        InputRequired(),
        Regexp(r'^[0-9a-f]{64}$', message='Reload the page before saving.'),
    ])


class RelayInfoForm(ConfigurationRevisionForm):
    relay_name = StringField('Relay Name', validators=[Optional(), Length(max=100), control_safe])
    relay_description = TextAreaField('Description', validators=[Optional(), Length(max=1000), control_safe])
    relay_pubkey = StringField('Operator Pubkey', validators=[Optional(), Length(max=128), control_safe])
    relay_contact = StringField('Contact', validators=[Optional(), Length(max=320), control_safe])

    def validate_relay_pubkey(self, field):
        value = (field.data or '').strip()
        if not value:
            field.data = ''
            return
        if re.fullmatch(r'[0-9a-fA-F]{64}', value):
            field.data = value.lower()
            return
        if value.startswith('NPUB1'):
            value = value.lower()
        if value.startswith('npub1'):
            try:
                field.data = npub_to_hex(value)
                return
            except ValueError as exc:
                raise ValidationError('Enter a valid npub or 64-character hex pubkey.') from exc
        raise ValidationError('Enter a valid npub or 64-character hex pubkey.')


class RelayNetworkForm(ConfigurationRevisionForm):
    relay_bind = StringField('Bind Address', validators=[Optional(), Length(max=45), control_safe])
    relay_port = IntegerField('Port', validators=[InputRequired(), NumberRange(min=1, max=65535)])

    def validate_relay_bind(self, field):
        value = (field.data or '').strip()
        if not value:
            field.data = ''
            return
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValidationError('Enter a valid IPv4 or IPv6 address.') from exc
        field.data = value


def _bundled_plugin_available():
    return bundled_plugin_available(Config.BLOCKLIST_PLUGIN_PATH)


def _supported_plugin_path(value):
    return value == '' or (
        value == Config.BLOCKLIST_PLUGIN_PATH and _bundled_plugin_available()
    )


class PluginForm(ConfigurationRevisionForm):
    plugin_path = SelectField('Write-policy plugin', choices=[])
    timeout = IntegerField('Timeout (seconds)', validators=[
        InputRequired(), NumberRange(min=1, max=60),
    ])
    lookback = IntegerField('Lookback (seconds)', validators=[
        InputRequired(), NumberRange(min=0, max=3600),
    ])
    confirm_plugin_change = BooleanField('I understand this changes or disables the configured executable')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.plugin_path.choices = [
            ('', 'Disabled'),
            (Config.BLOCKLIST_PLUGIN_PATH, 'Bundled plugin'),
        ]

    def validate_plugin_path(self, field):
        field.data = (field.data or '').strip()
        if not _supported_plugin_path(field.data):
            raise ValidationError('Select the bundled write-policy plugin or disable it.')


class WoTPolicyForm(FlaskForm):
    policy_revision = HiddenField(validators=[
        InputRequired(),
        Regexp(r'^[0-9a-f]{64}$', message='Reload the page before saving.'),
    ])
    mode = SelectField('Protection Mode', choices=[
        ('off', 'Off - blocklist only'),
        ('monitor', 'Monitor - score without rejecting'),
        ('enforce', 'Enforce - require PoW below threshold'),
    ], validators=[DataRequired()])
    root_npubs = TextAreaField('Trusted Root npubs', validators=[DataRequired()])
    trust_threshold = IntegerField('Trust Score to Bypass PoW', validators=[
        InputRequired(), NumberRange(min=0, max=100),
    ])
    pow_difficulty = IntegerField('Required PoW Difficulty', validators=[
        InputRequired(), NumberRange(min=0, max=64),
    ])
    require_pow_commitment = BooleanField('Require NIP-13 difficulty commitment')
    refresh_interval_minutes = IntegerField('Refresh Interval (minutes)', validators=[
        DataRequired(), NumberRange(min=5, max=1440),
    ])
    rate_limit_per_minute = IntegerField('Low-Trust Events per Minute', validators=[
        InputRequired(), NumberRange(min=0, max=100000),
    ])
    rate_limit_burst = IntegerField('Low-Trust Burst', validators=[
        InputRequired(), NumberRange(min=0, max=10000),
    ])
    confirm_enforce = BooleanField('I understand Enforce mode can reject publish attempts')


@app.context_processor
def inject_user():
    return dict(User=User)


@app.context_processor
def inject_relay_name():
    return dict(relay_name=_relay_name())


@app.template_filter('datetime')
def datetime_filter(ts):
    from datetime import datetime
    if not ts:
        return ''
    try:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except (OSError, OverflowError, TypeError, ValueError):
        return str(ts)


@app.template_filter('is_nsfw')
def is_nsfw_filter(tags):
    """Check if event has NSFW content-warning tag (NIP-36)."""
    if not tags:
        return False
    for tag in tags:
        if isinstance(tag, list) and len(tag) >= 1:
            if tag[0] == 'content-warning':
                return True
            if len(tag) >= 2 and tag[0] == 'l' and 'nsfw' in str(tag[1]).lower():
                return True
            if len(tag) >= 1 and tag[0] == 'L' and 'content-warning' in str(tag[1]).lower():
                return True
    return False


@app.template_filter('human_size')
def human_size_filter(size):
    if not size:
        return '0 B'
    try:
        size = int(size)
    except (ValueError, TypeError):
        return str(size)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if size < 1024:
            return f'{size:.1f} {unit}' if unit != 'B' else f'{size} B'
        size /= 1024
    return f'{size:.1f} PB'


@app.template_filter('format_uptime')
def format_uptime_filter(seconds):
    if seconds is None:
        return 'N/A'
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    parts = []
    if days:
        parts.append(f'{days}d')
    if hours:
        parts.append(f'{hours}h')
    if mins or not parts:
        parts.append(f'{mins}m')
    return ' '.join(parts)


def get_client_ip():
    try:
        return str(ipaddress.ip_address(request.remote_addr))
    except (TypeError, ValueError):
        return 'unknown'


def moderation_decisions():
    return ModerationDecisions(
        current_user.id,
        get_client_ip(),
        purge_notifier=queue_purge_processing,
    )


def _run_domain_reconciliation(domain_id, actor_id, ip_address):
    with app.app_context():
        try:
            ModerationDecisions(
                actor_id,
                ip_address,
                purge_notifier=queue_purge_processing,
            ).reconcile_domain(domain_id)
        except Exception as exc:
            app.logger.exception('NIP-05 domain reconciliation failed')
            db.session.rollback()
            banned_domain = db.session.get(BannedDomain, domain_id)
            if banned_domain is not None:
                banned_domain.scan_status = 'idle'
                banned_domain.scan_started_at = None
                banned_domain.last_scanned_at = utcnow()
                banned_domain.last_scan_error = str(exc)
                db.session.commit()


def _domain_reconciliation_worker():
    while True:
        domain_id, actor_id, ip_address = _domain_scan_queue.get()
        try:
            _run_domain_reconciliation(domain_id, actor_id, ip_address)
        except Exception:
            app.logger.exception('NIP-05 domain worker failed to recover cleanly')
        finally:
            _domain_scan_queue.task_done()


threading.Thread(
    target=_domain_reconciliation_worker,
    daemon=True,
    name='nip05-domain-worker',
).start()


def queue_domain_reconciliation(domain_id, actor_id, ip_address):
    stale_before = utcnow() - timedelta(seconds=_domain_scan_lease_seconds())
    claimed = BannedDomain.query.filter(
        BannedDomain.id == domain_id,
        or_(
            BannedDomain.scan_status.notin_(['queued', 'running']),
            BannedDomain.scan_started_at.is_(None),
            BannedDomain.scan_started_at < stale_before,
        ),
    ).update({
        'scan_status': 'queued',
        'scan_started_at': utcnow(),
    }, synchronize_session=False)
    db.session.commit()
    if not claimed:
        return False
    try:
        _domain_scan_queue.put_nowait((domain_id, actor_id, ip_address))
    except queue.Full:
        BannedDomain.query.filter_by(id=domain_id, scan_status='queued').update({
            'scan_status': 'idle',
            'scan_started_at': None,
        })
        db.session.commit()
        return False
    return True


def queue_purge_processing():
    """Wake the durable purge worker without accumulating in-memory jobs."""
    try:
        _purge_wakeup.put_nowait(True)
    except queue.Full:
        pass


def _purge_worker():
    while True:
        signaled = False
        try:
            _purge_wakeup.get(timeout=Config.MODERATION_PURGE_WORKER_INTERVAL)
            signaled = True
        except queue.Empty:
            pass
        try:
            with app.app_context():
                ModerationDecisions.process_pending_purges()
        except Exception:
            app.logger.exception('Durable event purge worker failed')
        finally:
            if signaled:
                _purge_wakeup.task_done()


def _domain_scan_lease_seconds():
    scan_timeout = max(1, min(Config.DOMAIN_SCAN_TIMEOUT, 300))
    verification_timeout = max(1, min(Config.DOMAIN_SCAN_TOTAL_TIMEOUT, 300))
    return scan_timeout + verification_timeout + 60


def _run_wot_rebuild():
    with app.app_context():
        state = rebuild_policy()
        if state.last_error == 'Trusted roots changed during build; rebuilding with new roots':
            queue_wot_rebuild()


def _wot_build_worker():
    while True:
        _wot_build_queue.get()
        try:
            _run_wot_rebuild()
        except Exception as exc:
            app.logger.exception('Web-of-trust build failed unexpectedly')
            try:
                with app.app_context():
                    db.session.rollback()
                    state = db.session.get(WoTBuildState, 1)
                    if state is not None:
                        state.status = 'failed'
                        state.finished_at = utcnow()
                        state.last_error = str(exc)
                        db.session.commit()
            except SQLAlchemyError:
                app.logger.exception('Could not record web-of-trust worker failure')
        finally:
            _wot_build_queue.task_done()


threading.Thread(
    target=_wot_build_worker,
    daemon=True,
    name='wot-build-worker',
).start()


def queue_wot_rebuild():
    initialize_wot()
    stale_before = utcnow() - timedelta(seconds=360)
    claimed = WoTBuildState.query.filter(
        WoTBuildState.id == 1,
        or_(
            WoTBuildState.status.notin_(['queued', 'running']),
            WoTBuildState.started_at.is_(None),
            WoTBuildState.started_at < stale_before,
        ),
    ).update({
        'status': 'queued',
        'started_at': utcnow(),
        'last_error': None,
    }, synchronize_session=False)
    db.session.commit()
    if not claimed:
        return False
    try:
        _wot_build_queue.put_nowait(True)
    except queue.Full:
        state = db.session.get(WoTBuildState, 1)
        state.status = 'idle'
        state.started_at = None
        db.session.commit()
        return False
    return True


def _wot_refresh_due(policy, state):
    if policy.mode == 'off':
        return False
    if state.status in ('queued', 'running'):
        stale_before = utcnow() - timedelta(seconds=360)
        return state.started_at is None or state.started_at < stale_before
    if state.generated_at is None:
        return True
    return utcnow() - state.generated_at >= timedelta(
        minutes=policy.refresh_interval_minutes
    )


def _wot_refresh_scheduler():
    while True:
        time.sleep(60)
        with app.app_context():
            try:
                policy, state = initialize_wot()
                if _wot_refresh_due(policy, state):
                    queue_wot_rebuild()
            except Exception:
                app.logger.exception('Could not schedule web-of-trust refresh')


def _dashboard_sampler():
    while True:
        started_at = time.monotonic()
        with app.app_context():
            _collect_dashboard_sample()
        elapsed = time.monotonic() - started_at
        time.sleep(max(1, Config.DASHBOARD_SAMPLE_INTERVAL - elapsed))


def _report_sync_scheduler():
    while True:
        started_at = time.monotonic()
        with app.app_context():
            sync_moderation_reports()
        elapsed = time.monotonic() - started_at
        time.sleep(max(1, 300 - elapsed))


def flash_moderation_outcome(outcome, success_message):
    flash(success_message, 'success')
    for warning in outcome.warnings:
        flash(warning, 'warning')


def log_audit(action, details=None, user_id=None, commit=True):
    if user_id is None:
        user_id = current_user.id if current_user.is_authenticated else None
    log = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=get_client_ip()
    )
    db.session.add(log)
    if commit:
        db.session.commit()
    return log


def _safe_config_snapshot():
    if 'strfry_config_snapshot' not in g:
        g.strfry_config_snapshot = load_configuration(Config.STRFRY_CONFIG)
    return g.strfry_config_snapshot


def _relay_name():
    return _safe_config_snapshot().values.get('relay', {}).get('info', {}).get('name', '')


def _collect_dashboard_sample():
    if not _dashboard_sample_lock.acquire(blocking=False):
        return
    try:
        collect_sample()
    except (OSError, SQLAlchemyError, ValueError):
        db.session.rollback()
        app.logger.exception('Could not collect dashboard telemetry')
    finally:
        _dashboard_sample_lock.release()


@app.route('/')
@viewer_or_higher
def index():
    dashboard = dashboard_summary(role=current_user.role)
    return render_template('index.html', dashboard=dashboard, relay_name=_relay_name())


@app.route('/api/dashboard')
@viewer_or_higher
def api_dashboard():
    response = jsonify(dashboard_summary(role=current_user.role))
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    return response


@app.route('/api/metrics')
@viewer_or_higher
def api_metrics():
    try:
        metrics = get_summary()
        return jsonify(metrics)
    except MetricsError as e:
        return jsonify({'error': str(e)}), 500


@app.route('/policy-log')
@moderator_required
def policy_log():
    return render_template('policy_log.html')


@app.route('/api/write-policy-events')
@limiter.limit("600 per minute")
@moderator_required
def api_write_policy_events():
    cursor = request.args.get('cursor')
    try:
        limit = int(request.args.get('limit', 200))
    except ValueError:
        limit = 200
    batch = read_decision_log(
        app.config['WRITE_POLICY_EVENT_LOG'],
        cursor=cursor,
        limit=limit,
    )
    response = jsonify({
        'events': batch.events,
        'cursor': batch.cursor,
        'reset': batch.reset,
        'has_more': batch.has_more,
        'available': batch.available,
        'updated_at': batch.updated_at,
    })
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@app.route('/api/pubkey-metadata/<pubkey>')
@viewer_or_higher
@limiter.limit(Config.RATELIMIT_METADATA)
def api_pubkey_metadata(pubkey):
    try:
        metadata = get_pubkey_metadata(pubkey)
        return jsonify(metadata)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except MetadataLookupBusy:
        return jsonify({'error': 'Metadata lookup is temporarily unavailable.'}), 503
    except Exception:
        app.logger.exception('Metadata lookup failed')
        return jsonify({'error': 'Metadata lookup failed.'}), 500


@app.route('/api/event/<event_id>')
@moderator_required
def api_get_event(event_id):
    try:
        events = scan_events({'ids': [event_id]}, limit=1)
        if events:
            e = events[0]
            return jsonify({
                'id': e.get('id'),
                'pubkey': e.get('pubkey'),
                'kind': e.get('kind'),
                'content': e.get('content'),
                'tags': e.get('tags'),
                'created_at': e.get('created_at')
            })
        return jsonify({'error': 'Event not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/metadata-relays', methods=['GET'])
@admin_required
def api_metadata_relays_list():
    try:
        relays = MetadataRelay.query.order_by(MetadataRelay.id).all()
        return jsonify([relay.to_dict() for relay in relays])
    except SQLAlchemyError:
        app.logger.exception('Could not load metadata relays')
        return jsonify({'error': 'Metadata relays could not be loaded'}), 500


@app.route('/api/metadata-relays', methods=['POST'])
@admin_required
@_metadata_relay_mutation_lock()
def api_metadata_relays_add():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({'error': 'A JSON object is required'}), 400
    try:
        url = normalize_relay_url(payload.get('url'))
    except RelayError as exc:
        return jsonify({'error': str(exc)}), 400

    if _find_equivalent_metadata_relay(url) is not None:
        return jsonify({'error': 'Relay already exists'}), 409
    if MetadataRelay.query.filter_by(enabled=True).count() >= MAX_RELAYS:
        return jsonify({'error': f'At most {MAX_RELAYS} metadata relays may be enabled'}), 409

    relay = MetadataRelay(url=url, enabled=True)
    db.session.add(relay)
    log_audit('metadata_relay_added', f'Added metadata relay: {url}', commit=False)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Relay already exists'}), 409
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception('Could not add metadata relay %s', url)
        return jsonify({'error': 'Relay could not be added'}), 500
    pubkey_metadata_cache.clear()
    return jsonify(relay.to_dict())


@app.route('/api/metadata-relays/<int:relay_id>', methods=['DELETE'])
@admin_required
@_metadata_relay_mutation_lock()
def api_metadata_relays_delete(relay_id):
    relay = MetadataRelay.query.get_or_404(relay_id)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({'error': 'A JSON object is required'}), 400
    if payload.get('confirm_url') != relay.url:
        return jsonify({'error': 'Relay URL confirmation does not match'}), 400
    url = relay.url
    db.session.delete(relay)
    log_audit('metadata_relay_deleted', f'Deleted metadata relay: {url}', commit=False)
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception('Could not delete metadata relay %s', url)
        return jsonify({'error': 'Relay could not be deleted'}), 500
    pubkey_metadata_cache.clear()
    return jsonify({'success': True})


@app.route('/api/metadata-relays/<int:relay_id>/toggle', methods=['POST'])
@admin_required
@_metadata_relay_mutation_lock()
def api_metadata_relays_toggle(relay_id):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({'error': 'A JSON object is required'}), 400
    relay = MetadataRelay.query.get_or_404(relay_id)
    if not relay.enabled and MetadataRelay.query.filter_by(enabled=True).count() >= MAX_RELAYS:
        return jsonify({'error': f'At most {MAX_RELAYS} metadata relays may be enabled'}), 409
    url = relay.url
    relay.enabled = not relay.enabled
    log_audit(
        'metadata_relay_toggled',
        f'Toggled metadata relay: {relay.url} ({relay.enabled})',
        commit=False,
    )
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception('Could not toggle metadata relay %s', url)
        return jsonify({'error': 'Relay could not be updated'}), 500
    pubkey_metadata_cache.clear()
    return jsonify(relay.to_dict())


@app.route('/api/metadata-relays/<int:relay_id>/test', methods=['POST'])
@admin_required
def api_metadata_relays_test(relay_id):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({'error': 'A JSON object is required'}), 400
    relay = MetadataRelay.query.get_or_404(relay_id)
    url = relay.url
    status_code = 200
    try:
        test_relay(relay.url, timeout=5)
        relay.last_status = 'success'
        message = 'Relay is working'
    except RelayError as exc:
        app.logger.warning('Metadata relay test failed for %s: %s', relay.url, exc)
        relay.last_status = 'failed'
        message = 'Relay test failed'
        status_code = 502
    relay.last_tested = utcnow()
    log_audit(
        'metadata_relay_tested',
        f'Tested metadata relay: {relay.url} ({relay.last_status})',
        commit=False,
    )
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception('Could not record metadata relay test for %s', url)
        return jsonify({'error': 'Relay test result could not be recorded'}), 500
    return jsonify({'status': relay.last_status, 'message': message}), status_code


def _find_equivalent_metadata_relay(normalized_url):
    """Match canonical equivalents without requiring legacy rows to be migrated first."""
    for relay in MetadataRelay.query.all():
        try:
            if normalize_relay_url(relay.url) == normalized_url:
                return relay
        except RelayError:
            continue
    return None


@app.route('/api/moderation-reports')
@moderator_required
def api_moderation_reports():
    report_type_filter = request.args.get('report_type', '')
    reporter_filter = request.args.get('reporter', '')
    reported_filter = request.args.get('reported', '')
    event_id_filter = request.args.get('event_id', '')
    show_reviewed = request.args.get('show_reviewed', 'false') == 'true'
    sort_order = 'asc' if request.args.get('sort') == 'asc' else 'desc'
    offset = max(0, request.args.get('offset', default=0, type=int))
    limit = min(100, max(1, request.args.get('limit', default=25, type=int)))
    
    query = ModerationReport.query
    
    if report_type_filter:
        query = query.filter(ModerationReport.report_type == report_type_filter)
    if reporter_filter:
        query = query.filter(ModerationReport.reporter_pubkey == reporter_filter)
    if reported_filter:
        query = query.filter(ModerationReport.reported_pubkey == reported_filter)
    if event_id_filter:
        query = query.filter(ModerationReport.reported_event_id == event_id_filter)
    if not show_reviewed:
        query = query.filter(ModerationReport.reviewed.is_(False))

    total_count = query.count()
    cursor_created_at = request.args.get('cursor_created_at', '')
    cursor_id = request.args.get('cursor_id', type=int)
    cursor_is_null = request.args.get('cursor_null') == '1'
    try:
        cursor_datetime = datetime.fromisoformat(cursor_created_at) if cursor_created_at else None
    except ValueError:
        cursor_datetime = None
    cursor_active = cursor_id is not None and (cursor_datetime is not None or cursor_is_null)
    if cursor_active:
        if sort_order == 'desc':
            if cursor_is_null:
                query = query.filter(
                    ModerationReport.created_at.is_(None),
                    ModerationReport.id < cursor_id,
                )
            else:
                query = query.filter(or_(
                    ModerationReport.created_at < cursor_datetime,
                    ModerationReport.created_at.is_(None),
                    and_(
                        ModerationReport.created_at == cursor_datetime,
                        ModerationReport.id < cursor_id,
                    ),
                ))
        else:
            if cursor_is_null:
                query = query.filter(or_(
                    and_(
                        ModerationReport.created_at.is_(None),
                        ModerationReport.id > cursor_id,
                    ),
                    ModerationReport.created_at.is_not(None),
                ))
            else:
                query = query.filter(or_(
                    ModerationReport.created_at > cursor_datetime,
                    and_(
                        ModerationReport.created_at == cursor_datetime,
                        ModerationReport.id > cursor_id,
                    ),
                ))
    if sort_order == 'desc':
        sort_columns = (ModerationReport.created_at.desc(), ModerationReport.id.desc())
    else:
        sort_columns = (ModerationReport.created_at.asc(), ModerationReport.id.asc())
    page_query = query.order_by(*sort_columns)
    if not cursor_active:
        page_query = page_query.offset(offset)
    page = page_query.limit(limit + 1).all()
    has_more = len(page) > limit
    reports = page[:limit]
    next_cursor = None
    if reports and has_more:
        next_cursor = {
            'created_at': reports[-1].created_at.isoformat() if reports[-1].created_at else None,
            'id': reports[-1].id,
        }
    
    reports_data = []
    for r in reports:
        reports_data.append({
            'id': r.id,
            'report_type': r.report_type,
            'created_at': r.created_at.isoformat() if r.created_at else None,
            'reporter_pubkey': r.reporter_pubkey,
            'reported_pubkey': r.reported_pubkey,
            'reported_event_id': r.reported_event_id,
            'content': r.content,
            'reviewed': r.reviewed,
            'banned': r.banned,
            'event_id': r.event_id,
            'reviewed_by': r.reviewed_by,
            'reviewed_at': r.reviewed_at.isoformat() if r.reviewed_at else None,
            'banned_by': r.banned_by,
            'banned_at': r.banned_at.isoformat() if r.banned_at else None,
        })
    
    return jsonify({
        'reports': reports_data,
        'has_more': has_more,
        'total_count': total_count,
        'next_cursor': next_cursor,
    })


def _bounded_query_int(args, name, default, minimum, maximum):
    try:
        value = int(args.get(name, default))
    except (TypeError, ValueError):
        value = default
    return min(maximum, max(minimum, value))


def _parse_audit_date(value, end=False):
    if not value:
        return None
    try:
        parsed = datetime.strptime(value, '%Y-%m-%d').date()
    except (TypeError, ValueError):
        return None
    return datetime.combine(parsed, datetime_time.max if end else datetime_time.min)


def _parse_audit_cursor(value):
    if not value:
        return None
    try:
        cursor = json.loads(value)
        timestamp = datetime.fromisoformat(cursor['timestamp'])
        identifier = int(cursor['id'])
        if identifier < 1:
            return None
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return timestamp, identifier


def _audit_page(args):
    limit = _bounded_query_int(args, 'limit', 25, 1, 100)
    offset = _bounded_query_int(args, 'offset', 0, 0, 10000)
    action = (args.get('action') or '').strip()[:100]
    operator = (args.get('operator') or '').strip()[:80]
    text_filter = (args.get('text') or args.get('q') or '').strip()[:200]
    system = (args.get('system') or 'include').lower()
    if system in ('true', '1'):
        system = 'only'
    elif system in ('false', '0'):
        system = 'exclude'
    if system not in ('include', 'only', 'exclude'):
        system = 'include'
    date_from_value = args.get('date_from') or args.get('start_date') or ''
    date_to_value = args.get('date_to') or args.get('end_date') or ''
    date_from = _parse_audit_date(date_from_value)
    date_to = _parse_audit_date(date_to_value, end=True)
    cursor = _parse_audit_cursor(args.get('cursor'))

    query = AuditLog.query.outerjoin(User, AuditLog.user_id == User.id)
    if action:
        query = query.filter(AuditLog.action.contains(action, autoescape=True))
    if operator.lower() == 'system':
        query = query.filter(AuditLog.user_id.is_(None))
    elif operator:
        query = query.filter(User.username.contains(operator, autoescape=True))
    if system == 'only':
        query = query.filter(AuditLog.user_id.is_(None))
    elif system == 'exclude':
        query = query.filter(AuditLog.user_id.is_not(None))
    if text_filter:
        query = query.filter(or_(
            AuditLog.action.contains(text_filter, autoescape=True),
            AuditLog.details.contains(text_filter, autoescape=True),
            AuditLog.ip_address.contains(text_filter, autoescape=True),
            User.username.contains(text_filter, autoescape=True),
        ))
    if date_from:
        query = query.filter(AuditLog.timestamp >= date_from)
    if date_to:
        query = query.filter(AuditLog.timestamp <= date_to)

    total_count = query.count()
    if cursor:
        cursor_timestamp, cursor_id = cursor
        query = query.filter(or_(
            AuditLog.timestamp < cursor_timestamp,
            and_(AuditLog.timestamp == cursor_timestamp, AuditLog.id < cursor_id),
        ))
    query = query.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
    if not cursor:
        query = query.offset(offset)
    results = query.limit(limit + 1).all()
    has_more = len(results) > limit
    logs = results[:limit]
    next_cursor = None
    if has_more and logs and logs[-1].timestamp:
        next_cursor = {
            'timestamp': logs[-1].timestamp.isoformat(),
            'id': logs[-1].id,
        }
    return {
        'logs': logs,
        'has_more': has_more and next_cursor is not None,
        'total_count': total_count,
        'next_cursor': next_cursor,
        'offset': offset,
        'limit': limit,
        'filters': {
            'action': action,
            'operator': operator,
            'text': text_filter,
            'system': system,
            'date_from': date_from_value if date_from else '',
            'date_to': date_to_value if date_to else '',
        },
    }


def _secure_audit_response(response):
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@app.route('/api/audit-logs')
@admin_required
def api_audit_logs():
    page = _audit_page(request.args)
    response = jsonify({
        'logs': [log.to_dict() for log in page['logs']],
        'has_more': page['has_more'],
        'total_count': page['total_count'],
        'next_cursor': page['next_cursor'],
    })
    return _secure_audit_response(response)


@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template('login.html', setup_available=_nostr_setup_available())


def _safe_login_next(candidate):
    """Return a local absolute-path redirect target, or None when unsafe."""
    if not candidate or not candidate.startswith('/') or candidate.startswith('//'):
        return None
    if '\\' in candidate or any(ord(character) < 32 for character in candidate):
        return None
    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc:
        return None
    return candidate


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    log_audit('logout', 'User logged out')
    logout_user()
    session.pop('_nostr_rotation', None)
    session.pop('_nostr_auth_version', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/register')
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if not _nostr_setup_available():
        flash('Initial setup is closed.', 'warning')
        return redirect(url_for('login'))
    return render_template('register.html', existing_install=User.query.count() > 0)


def _nostr_setup_available():
    return User.query.filter_by(role='admin', is_active=True).filter(User.nostr_pubkey.isnot(None)).count() == 0


def _auth_session_token():
    token = session.get('_nostr_auth_browser')
    if not token:
        import secrets

        token = secrets.token_urlsafe(32)
        session['_nostr_auth_browser'] = token
    return token


def _auth_verify_url(action):
    endpoints = {
        'login': '/api/auth/verify',
        'bootstrap': '/api/auth/bootstrap',
        'rotate-current': '/api/auth/rotate-current',
        'rotate-key': '/api/auth/rotate-key',
    }
    if action not in endpoints:
        raise NostrAuthError('Invalid authentication action.')
    return f'{Config.PUBLIC_BASE_URL}{endpoints[action]}'


@app.route('/api/auth/challenge', methods=['POST'])
@csrf.exempt
@limiter.limit(Config.RATELIMIT_LOGIN)
def auth_challenge():
    data = request.get_json(silent=True) or {}
    action = data.get('action', 'login')
    if action == 'bootstrap' and not _nostr_setup_available():
        return jsonify({'error': 'Initial setup is closed.'}), 403
    if action in {'rotate-current', 'rotate-key'} and not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required.'}), 401
    if action == 'rotate-key':
        rotation = session.get('_nostr_rotation') or {}
        if (
            rotation.get('user_id') != current_user.id
            or rotation.get('auth_version') != current_user.auth_version
            or rotation.get('expires_at', 0) < int(time.time())
        ):
            session.pop('_nostr_rotation', None)
            return jsonify({'error': 'Reauthenticate with your current Nostr key first.'}), 403
    payload = None
    if action == 'bootstrap':
        payload = {
            'registration_token': data.get('registration_token', ''),
        }
    try:
        result = issue_challenge(
            action,
            _auth_session_token(),
            _auth_verify_url(action),
            Config.NOSTR_AUTH_CHALLENGE_TTL,
            payload=payload,
            redirect_to=_safe_login_next(data.get('next')),
            user_id=current_user.id if action in {'rotate-current', 'rotate-key'} else None,
        )
    except NostrAuthError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify(result)


def _verified_auth(action):
    return verify_request(
        request.headers.get('Authorization'),
        action,
        _auth_session_token(),
        _auth_verify_url(action),
        Config.NOSTR_AUTH_TIMESTAMP_TOLERANCE,
        body=request.get_data(cache=True),
        user_id=current_user.id if action in {'rotate-current', 'rotate-key'} else None,
    )


@app.route('/api/auth/verify', methods=['POST'])
@csrf.exempt
@limiter.limit(Config.RATELIMIT_LOGIN)
def auth_verify():
    try:
        verified = _verified_auth('login')
    except NostrAuthError:
        return jsonify({'error': 'Nostr authentication failed.'}), 401
    user = User.query.filter_by(nostr_pubkey=verified.pubkey, is_active=True).first()
    if not user:
        log_audit('login_failed', 'Failed Nostr login for an unknown or inactive pubkey')
        return jsonify({'error': 'This Nostr identity is not authorized.'}), 401
    with _operator_mutation_lock():
        user.username = _profile_username(verified.pubkey, user.id)
        user.update_login()
        log_audit('login', 'User logged in with Nostr', commit=False)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'Could not assign a unique operator name.'}), 409
    session.pop('_user_id', None)
    session.pop('_fresh', None)
    login_user(user, fresh=True)
    session['_nostr_auth_version'] = user.auth_version
    return jsonify({'redirect': verified.redirect_to or url_for('index')})


@app.route('/api/auth/bootstrap', methods=['POST'])
@csrf.exempt
@limiter.limit(Config.RATELIMIT_LOGIN)
@_operator_mutation_lock()
def auth_bootstrap():
    if not _nostr_setup_available():
        return jsonify({'error': 'Initial setup is closed.'}), 403
    try:
        verified = _verified_auth('bootstrap')
    except NostrAuthError:
        return jsonify({'error': 'Nostr setup verification failed.'}), 401
    expected_token = Config.REGISTRATION_TOKEN or ''
    supplied_token = verified.payload.get('registration_token', '')
    if not expected_token or not hmac.compare_digest(supplied_token, expected_token):
        log_audit('register_failed', 'Invalid registration token during Nostr setup')
        return jsonify({'error': 'Invalid registration token.'}), 403
    if User.query.filter_by(nostr_pubkey=verified.pubkey).first():
        return jsonify({'error': 'This Nostr pubkey is already assigned.'}), 409
    if User.query.count() > 0:
        eligible_admins = User.query.filter_by(
            role='admin',
            is_active=True,
            nostr_pubkey=None,
        ).all()
        if len(eligible_admins) != 1:
            return jsonify({'error': 'Existing setup requires exactly one active, unbound administrator.'}), 400
        user = eligible_admins[0]
        user.username = _profile_username(verified.pubkey, user.id)
        user.nostr_pubkey = verified.pubkey
        action = 'user_nostr_bootstrap'
    else:
        username = _profile_username(verified.pubkey)
        user = User(username=username, nostr_pubkey=verified.pubkey, role='admin', must_change_password=False)
        user.disable_password()
        db.session.add(user)
        action = 'register'
    db.session.flush()
    log_audit(action, f'Nostr administrator configured for {user.username}', commit=False)
    db.session.commit()
    return jsonify({'redirect': url_for('login')})


@app.route('/events', methods=['GET', 'POST'])
@viewer_or_higher
def events():
    if request.method == 'GET' and request.args:
        form = EventSearchForm(formdata=request.args)
    else:
        form = EventSearchForm()
    events_list = []
    error = None
    current_filter = {}

    if request.method == 'POST' and 'delete_selected' in request.form:
        if current_user.role not in ('admin', 'moderator'):
            abort(403)
        event_ids = list(dict.fromkeys(request.form.getlist('event_ids')))
        if any(PUBKEY_PATTERN.fullmatch(event_id) is None for event_id in event_ids):
            abort(400, description='Event IDs must be exact 64-character hex values')
        if event_ids:
            try:
                id_filter = {'ids': event_ids}
                delete_events(id_filter)
                flash(f'Deleted {len(event_ids)} event(s) successfully', 'success')
                log_audit('event_delete', f'Deleted {len(event_ids)} events via UI')
            except (ValueError, StrfryError) as e:
                flash(f'Failed to delete events: {e}', 'danger')
        params = {'search_type': request.form.get('search_type', 'all')}
        for name in (
            'pubkey', 'kind', 'event_id', 'since', 'until', 'keyword', 'nip05',
            'tag_name', 'tag_value', 'filter_json',
        ):
            if request.form.get(name):
                params[name] = request.form.get(name)
        params['limit'] = request.form.get('limit', 25)
        return redirect(url_for('events', **params))

    search_requested = (
        request.method == 'POST' and 'search' in request.form
    ) or (
        request.method == 'GET' and 'search_type' in request.args
    )
    if search_requested:
        if request.method == 'POST' and not form.validate():
            error = ' '.join(
                message for messages in form.errors.values() for message in messages
            )
        else:
            error = validate_event_search(form)
        if not error:
            try:
                if form.search_type.data == 'nip05':
                    pubkey = resolve_nip05(form.nip05.data)
                    if not pubkey:
                        raise ValueError(
                            'Could not resolve NIP-05 address. Check the address and try again.'
                        )
                    current_filter = {'authors': [pubkey]}
                else:
                    current_filter = build_filter_from_form(form)

                since_ts = parse_timestamp(form.since.data) if form.since.data else None
                until_ts = parse_timestamp(form.until.data) if form.until.data else None
                if since_ts is not None:
                    current_filter['since'] = since_ts
                if until_ts is not None:
                    current_filter['until'] = until_ts

                if form.search_type.data == 'keyword':
                    keyword = form.keyword.data.lower()
                    filter_obj = {k: v for k, v in current_filter.items() if k != 'limit'}
                    all_events = scan_events(filter_obj, limit=1000)
                    events_list = [
                        event for event in all_events
                        if keyword in event.get('content', '').lower()
                    ][:form.limit.data]
                else:
                    events_list = scan_events(current_filter, limit=form.limit.data)
            except (ValueError, StrfryError) as e:
                error = str(e)

    event_pubkeys = {event.get('pubkey') for event in events_list if event.get('pubkey')}
    banned_pubkeys = set()
    if event_pubkeys:
        banned_pubkeys = {
            ban.pubkey for ban in BannedPubkey.query.filter(
                BannedPubkey.pubkey.in_(event_pubkeys)
            )
        }

    return render_template(
        'events.html',
        form=form,
        events=events_list,
        error=error,
        current_filter=current_filter,
        banned_pubkeys=banned_pubkeys,
        search_performed=search_requested,
    )


def parse_timestamp(value):
    if not value:
        return None
    value = value.strip()
    try:
        return int(value)
    except ValueError:
        pass
    from datetime import datetime
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M',
        '%Y-%m-%d',
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            return int(dt.timestamp())
        except ValueError:
            continue
    return None


def validate_event_search(form):
    search_type = form.search_type.data or 'all'
    allowed_types = {
        'all', 'keyword', 'nip05', 'pubkey', 'event_id', 'kind', 'timerange',
        'tag', 'advanced',
    }
    if search_type not in allowed_types:
        return 'Unsupported search type.'
    required_fields = {
        'keyword': (form.keyword.data, 'Enter a keyword to search for.'),
        'nip05': (form.nip05.data, 'Enter a NIP-05 address.'),
        'pubkey': (form.pubkey.data, 'Enter a pubkey or npub.'),
        'event_id': (form.event_id.data, 'Enter an event ID.'),
        'kind': (form.kind.data, 'Enter an event kind.'),
        'tag': (
            form.tag_name.data and form.tag_value.data,
            'Enter both a tag name and value.',
        ),
        'advanced': (form.filter_json.data, 'Enter a JSON filter.'),
    }
    if search_type in required_fields and not required_fields[search_type][0]:
        return required_fields[search_type][1]
    if not form.limit.data or not 1 <= form.limit.data <= 1000:
        return 'Limit must be between 1 and 1000.'
    if search_type == 'kind':
        try:
            int(form.kind.data)
        except (TypeError, ValueError):
            return 'Kind must be a valid number.'
    if search_type == 'pubkey':
        value = form.pubkey.data.strip()
        if value.startswith('npub'):
            try:
                npub_to_hex(value)
            except ValueError:
                return 'Pubkey must be a valid npub or 64-character hex value.'
        else:
            try:
                if len(value) != 64:
                    raise ValueError
                bytes.fromhex(value)
            except ValueError:
                return 'Pubkey must be a valid npub or 64-character hex value.'
    if search_type == 'event_id':
        value = form.event_id.data.strip()
        try:
            if len(value) != 64:
                raise ValueError
            bytes.fromhex(value)
        except ValueError:
            return 'Event ID must be 64 hexadecimal characters.'
    if search_type == 'tag' and len(form.tag_name.data.strip()) != 1:
        return 'Tag name must be one character.'
    if search_type in ('keyword', 'timerange'):
        since_ts = parse_timestamp(form.since.data) if form.since.data else None
        until_ts = parse_timestamp(form.until.data) if form.until.data else None
        if form.since.data and since_ts is None:
            return 'Since must be a timestamp or valid date.'
        if form.until.data and until_ts is None:
            return 'Until must be a timestamp or valid date.'
        if since_ts is not None and until_ts is not None and since_ts > until_ts:
            return 'Since must be earlier than Until.'
    return None


def resolve_nip05(nip05_address):
    """Resolve a NIP-05 address to a pubkey."""
    try:
        local_part, _, domain = nip05_address.strip().partition('@')
        if not local_part or not domain or LOCAL_NAME_PATTERN.fullmatch(local_part) is None:
            return None
        domain = normalize_domain(domain)
        deadline = time.monotonic() + Config.NIP05_PROFILE_TIMEOUT
        document = fetch_nip05_document(domain, local_name=local_part, deadline=deadline)
        names = document.get('names') if isinstance(document, dict) else None
        pubkey = names.get(local_part) if isinstance(names, dict) else None
        return pubkey if isinstance(pubkey, str) and PUBKEY_PATTERN.fullmatch(pubkey) else None
    except (ValueError, Nip05VerificationError):
        return None


def build_filter_from_form(form):
    filter_obj = {}
    
    search_type = form.search_type.data
    
    if search_type == 'all':
        pass
    elif search_type == 'keyword' and form.keyword.data:
        filter_obj['kinds'] = [1]
        filter_obj['limit'] = 1000
        since_ts = parse_timestamp(form.since.data) if form.since.data else None
        until_ts = parse_timestamp(form.until.data) if form.until.data else None
        if since_ts is not None:
            filter_obj['since'] = since_ts
        if until_ts is not None:
            filter_obj['until'] = until_ts
    elif search_type == 'nip05' and form.nip05.data:
        pubkey = resolve_nip05(form.nip05.data)
        if pubkey:
            filter_obj['authors'] = [pubkey]
    elif search_type == 'pubkey' and form.pubkey.data:
        pubkey_input = form.pubkey.data.strip()
        try:
            pubkey_hex = npub_to_hex(pubkey_input)
        except ValueError:
            pubkey_hex = pubkey_input
        filter_obj['authors'] = [pubkey_hex]
    elif search_type == 'event_id' and form.event_id.data:
        filter_obj['ids'] = [form.event_id.data.strip()]
    elif search_type == 'kind' and form.kind.data:
        try:
            filter_obj['kinds'] = [int(form.kind.data.strip())]
        except ValueError:
            raise ValueError('Kind must be a valid number')
    elif search_type == 'timerange':
        since_ts = parse_timestamp(form.since.data) if form.since.data else None
        until_ts = parse_timestamp(form.until.data) if form.until.data else None
        if since_ts is not None:
            filter_obj['since'] = since_ts
        if until_ts is not None:
            filter_obj['until'] = until_ts
    elif search_type == 'tag' and form.tag_name.data and form.tag_value.data:
        tag_name = form.tag_name.data.strip()
        if tag_name:
            filter_obj['#' + tag_name[0]] = [form.tag_value.data.strip()]
    elif search_type == 'advanced' and form.filter_json.data:
        filter_obj = validate_filter_json(form.filter_json.data)
    
    return filter_obj


@app.route('/events/delete', methods=['GET', 'POST'])
@moderator_required
def events_delete():
    form = DeleteForm()
    error = None
    success = None
    
    if request.method == 'POST' and form.validate_on_submit():
        if form.confirm_delete.data != 'DELETE':
            error = 'You must type DELETE to confirm'
        else:
            try:
                filter_obj = validate_filter_json(form.filter_json.data)
                if not filter_obj:
                    raise ValueError('Empty filters are not allowed for deletion.')
                delete_events(filter_obj)
                success = 'Events deleted successfully'
                log_audit('event_delete', f'Deleted events matching: {form.filter_json.data}')
            except (ValueError, StrfryError) as e:
                error = str(e)
    
    return render_template('events_delete.html', form=form, error=error, success=success)


@app.route('/import_export', methods=['GET', 'POST'])
@permission_required('import_export')
def import_export():
    export_form = ExportForm()
    import_form = ImportForm()
    export_error = None
    export_success = None
    import_error = None
    import_success = None
    export_data = None
    
    if request.method == 'POST':
        if 'export_submit' in request.form and export_form.validate():
            try:
                kwargs = {}
                if export_form.since.data is not None:
                    kwargs['since'] = export_form.since.data
                if export_form.until.data is not None:
                    kwargs['until'] = export_form.until.data
                if export_form.reverse.data == 'reverse':
                    kwargs['reverse'] = True
                if export_form.fried.data == 'true':
                    kwargs['fried'] = True
                
                export_data = export_events(**kwargs)
                export_size = len(export_data.encode('utf-8')) if export_data else 0
                export_success = f'Exported events (size: {export_size} bytes)'
                log_audit('export', f'Exported events with params: {kwargs}')
            except StrfryError as e:
                export_error = str(e)
        
        elif 'import_submit' in request.form and import_form.validate():
            try:
                verify = import_form.no_verify.data != 'true'
                import_events(import_form.file.data, verify=verify)
                import_success = 'Events imported successfully'
                log_audit('import', f'Imported events (verify={verify})')
            except StrfryError as e:
                import_error = str(e)
    
    response = make_response(render_template(
        'import_export.html',
        export_form=export_form,
        import_form=import_form,
        export_error=export_error,
        export_success=export_success,
        import_error=import_error,
        import_success=import_success,
        export_data=export_data
    ))
    response.headers['Cache-Control'] = 'no-store'
    return response


def _valid_tree_id(tree_id):
    return bool(
        tree_id
        and len(tree_id) <= 128
        and all(character.isalnum() or character in '._-' for character in tree_id)
    )


@app.route('/db', methods=['GET', 'POST'])
@permission_required('db_manage')
def db_management():
    negentropy_error = None
    negentropy_success = None
    dict_error = None
    
    trees = []
    dict_output = None
    negentropy_add_form = EventSearchForm()
    negentropy_add_form.limit.data = 0

    if request.method == 'GET' and request.args:
        refresh_actions = ('refresh_negentropy', 'refresh_dict')
        if sum(action in request.args for action in refresh_actions) != 1:
            abort(400, description='Request exactly one database refresh')
        if 'refresh_negentropy' in request.args:
            try:
                trees = negentropy_list()
            except StrfryError as e:
                negentropy_error = str(e)
        else:
            try:
                dict_output = dict_list()
            except StrfryError as e:
                dict_error = str(e)
    elif request.method == 'POST':
        actions = (
            'negentropy_add', 'negentropy_build', 'negentropy_delete', 'compact',
            'refresh_negentropy', 'refresh_dict',
        )
        if sum(action in request.form for action in actions) != 1:
            abort(400, description='Submit exactly one database action')

        if 'negentropy_add' in request.form:
            try:
                filter_obj = validate_filter_json(negentropy_add_form.filter_json.data)
                result = negentropy_add(filter_obj)
                flash(f'Created negentropy tree: {result}')
                log_audit('negentropy_add', f'Added tree: {filter_obj}')
            except (ValueError, StrfryError) as e:
                flash(str(e), 'danger')
            return redirect(url_for('db_management'))
        
        elif 'negentropy_build' in request.form:
            tree_id = request.form.get('tree_id')
            if not _valid_tree_id(tree_id):
                abort(400, description='Invalid negentropy tree ID')
            try:
                result = negentropy_build(tree_id)
                flash(f'Built tree {tree_id}')
                log_audit('negentropy_build', f'Built tree: {tree_id}')
            except StrfryError as e:
                flash(str(e), 'danger')
            return redirect(url_for('db_management'))
        
        elif 'negentropy_delete' in request.form:
            tree_id = request.form.get('tree_id')
            if not _valid_tree_id(tree_id):
                abort(400, description='Invalid negentropy tree ID')
            if request.form.get('confirm_tree_delete') != tree_id:
                abort(400, description='Confirm the negentropy tree deletion')
            try:
                result = negentropy_delete(tree_id)
                flash(f'Deleted tree {tree_id}')
                log_audit('negentropy_delete', f'Deleted tree: {tree_id}')
            except StrfryError as e:
                flash(str(e), 'danger')
            return redirect(url_for('db_management'))
        
        elif 'compact' in request.form:
            abort(410, description='Web compaction is disabled; stop strfry and compact offline.')
        
        elif 'refresh_negentropy' in request.form:
            try:
                trees = negentropy_list()
            except StrfryError as e:
                negentropy_error = str(e)
        
        elif 'refresh_dict' in request.form:
            try:
                dict_output = dict_list()
            except StrfryError as e:
                dict_error = str(e)
    
    return render_template(
        'db.html',
        trees=trees,
        negentropy_add_form=negentropy_add_form,
        negentropy_error=negentropy_error,
        negentropy_success=negentropy_success,
        dict_output=dict_output,
        dict_error=dict_error,
    )


def _redacted_configuration(value, key=''):
    sensitive_markers = ('password', 'secret', 'token', 'credential', 'private')
    if any(marker in key.lower() for marker in sensitive_markers):
        return '[redacted]'
    if isinstance(value, dict):
        return {item_key: _redacted_configuration(item, item_key) for item_key, item in value.items()}
    return value


def _configuration_page(info_form, network_form, status_code=200):
    snapshot = _safe_config_snapshot()
    if snapshot.revision is None:
        config_status = 'error'
    elif snapshot.writable:
        config_status = 'writable'
    else:
        config_status = 'read-only'
    return render_template(
        'config.html',
        info_form=info_form,
        network_form=network_form,
        config_status=config_status,
        current_config=_redacted_configuration(snapshot.values),
    ), status_code


def _audit_config_update(outcome, section, fields):
    details = f"section={section}; fields={','.join(sorted(fields))}"
    log_audit(f'config_update_{outcome}', details)


def _configuration_forms():
    snapshot = _safe_config_snapshot()
    relay = snapshot.values.get('relay', {})
    relay_info = relay.get('info', {})
    return (
        RelayInfoForm(formdata=None, data={
            'config_revision': snapshot.revision or '',
            'relay_name': relay_info.get('name', ''),
            'relay_description': relay_info.get('description', ''),
            'relay_pubkey': relay_info.get('pubkey', ''),
            'relay_contact': relay_info.get('contact', ''),
        }),
        RelayNetworkForm(formdata=None, data={
            'config_revision': snapshot.revision or '',
            'relay_bind': relay.get('bind', ''),
            'relay_port': relay.get('port'),
        }),
    )


@app.route('/config', methods=['GET'])
@permission_required('config')
def config_view():
    info_form, network_form = _configuration_forms()
    return _configuration_page(info_form, network_form)


def _configuration_update(form, section, fields, make_updates):
    _audit_config_update('requested', section, fields)
    if not form.validate_on_submit():
        _audit_config_update('failed', section, fields)
        return False, 422
    try:
        _safe_config_snapshot().write(
            make_updates(),
            expected_revision=form.config_revision.data,
        )
    except RevisionConflict:
        _audit_config_update('conflict', section, fields)
        form.config_revision.errors.append('Configuration changed. Reload before saving.')
        return False, 422
    except ConfigurationBusy:
        _audit_config_update('failed', section, fields)
        form.config_revision.errors.append('Configuration is busy. Try again shortly.')
        return False, 422
    except (ConfigurationError, KeyError, OSError):
        _audit_config_update('failed', section, fields)
        form.config_revision.errors.append('Configuration could not be saved safely.')
        return False, 422
    _audit_config_update('completed', section, fields)
    flash('Configuration updated. Some changes may require a strfry restart.', 'success')
    return True, 303


@app.route('/config/relay-info', methods=['POST'])
@permission_required('config')
def update_relay_info():
    form = RelayInfoForm()
    fields = (
        'relay.info.name',
        'relay.info.description',
        'relay.info.pubkey',
        'relay.info.contact',
    )
    success, status_code = _configuration_update(form, 'relay-info', fields, lambda: {
        'relay.info.name': form.relay_name.data or '',
        'relay.info.description': form.relay_description.data or '',
        'relay.info.pubkey': form.relay_pubkey.data or '',
        'relay.info.contact': form.relay_contact.data or '',
    })
    if success:
        return redirect(url_for('config_view'), code=status_code)
    _info_form, network_form = _configuration_forms()
    return _configuration_page(form, network_form, status_code)


@app.route('/config/network', methods=['POST'])
@permission_required('config')
def update_relay_network():
    form = RelayNetworkForm()
    fields = ('relay.bind', 'relay.port')
    success, status_code = _configuration_update(form, 'network', fields, lambda: {
        'relay.bind': form.relay_bind.data or '',
        'relay.port': form.relay_port.data,
    })
    if success:
        return redirect(url_for('config_view'), code=status_code)
    info_form, _network_form = _configuration_forms()
    return _configuration_page(info_form, form, status_code)


def _write_policy_updates(plugin_path, timeout, lookback):
    """Validate write-policy values independently of the HTTP form."""
    if not _supported_plugin_path(plugin_path):
        raise ConfigurationError(
            'relay.writePolicy.plugin must be empty or the bundled plugin path'
        )
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 60:
        raise ConfigurationError('relay.writePolicy.timeoutSeconds must be between 1 and 60')
    if isinstance(lookback, bool) or not isinstance(lookback, int) or not 0 <= lookback <= 3600:
        raise ConfigurationError('relay.writePolicy.lookbackSeconds must be between 0 and 3600')
    return {
        'relay.writePolicy.plugin': plugin_path,
        'relay.writePolicy.timeoutSeconds': timeout,
        'relay.writePolicy.lookbackSeconds': lookback,
    }


def _plugins_page(plugin_form=None, wot_form=None, status_code=200):
    snapshot = _safe_config_snapshot()
    write_policy = snapshot.values.get('relay', {}).get('writePolicy', {})
    configured_path = write_policy.get('plugin', '')
    if not isinstance(configured_path, str):
        configured_path = ''
    bundled_path = app.config['BLOCKLIST_PLUGIN_PATH']
    bundled_installed = _bundled_plugin_available()
    configured_executable = configured_path == bundled_path and bundled_installed
    configuration_kind = (
        'disabled' if not configured_path
        else 'bundled' if configured_path == bundled_path
        else 'unsupported'
    )

    blocklist_count = BannedPubkey.query.count()
    projection = ModerationDecisions.initialize_projection()
    wot_policy, wot_state = initialize_wot()
    try:
        wot_stats = json.loads(read_bounded(
            app.config['TRUST_POLICY_STATS_FILE'],
            1024 * 1024,
        ))
        if not isinstance(wot_stats, dict):
            wot_stats = {}
    except (OSError, json.JSONDecodeError):
        wot_stats = {}
    stats_updated_at = wot_stats.get('updated_at')
    telemetry_recent = (
        isinstance(stats_updated_at, (int, float))
        and not isinstance(stats_updated_at, bool)
        and 0 <= time.time() - stats_updated_at <= 120
    )

    if plugin_form is None:
        plugin_form = PluginForm(formdata=None, data={
            'config_revision': snapshot.revision or '',
            'plugin_path': (
                configured_path
                if configured_path in {'', bundled_path}
                else bundled_path
            ),
            'timeout': write_policy.get('timeoutSeconds', 10),
            'lookback': write_policy.get('lookbackSeconds', 0),
        })
    if wot_form is None:
        wot_form = WoTPolicyForm(formdata=None, data={
            'policy_revision': policy_fingerprint(wot_policy),
            'mode': wot_policy.mode,
            'root_npubs': '\n'.join(wot_policy.roots),
            'trust_threshold': wot_policy.trust_threshold,
            'pow_difficulty': wot_policy.pow_difficulty,
            'require_pow_commitment': wot_policy.require_pow_commitment,
            'refresh_interval_minutes': wot_policy.refresh_interval_minutes,
            'rate_limit_per_minute': wot_policy.rate_limit_per_minute,
            'rate_limit_burst': wot_policy.rate_limit_burst,
        })

    attention = []
    if not snapshot.writable:
        attention.append('The strfry configuration is read-only or unavailable.')
    if configured_path and not configured_executable:
        attention.append(
            'The configured plugin is unsupported. Select the bundled plugin or disable it.'
        )
    if projection.status == 'pending':
        attention.append('The latest ban projection has not been published.')
    if wot_state.status == 'failed':
        attention.append('The latest web-of-trust graph build failed.')
    if not telemetry_recent:
        attention.append('Recent write-policy telemetry is unavailable or stale.')

    return render_template(
        'plugins.html',
        form=plugin_form,
        config_snapshot=snapshot,
        configured_path=configured_path,
        configured_executable=configured_executable,
        configuration_kind=configuration_kind,
        bundled_path=bundled_path,
        bundled_installed=bundled_installed,
        restart_status='unknown',
        blocklist_count=blocklist_count,
        projection=projection,
        wot_form=wot_form,
        wot_policy=wot_policy,
        wot_state=wot_state,
        wot_stats=wot_stats,
        telemetry_recent=telemetry_recent,
        attention=attention,
    ), status_code


@app.route('/plugins', methods=['GET'])
@admin_required
def plugins():
    return _plugins_page()


@app.route('/plugins/write-policy', methods=['POST'])
@admin_required
def update_write_policy():
    form = PluginForm()
    snapshot = _safe_config_snapshot()
    write_policy = snapshot.values.get('relay', {}).get('writePolicy', {})
    old_path = write_policy.get('plugin', '')
    if not isinstance(old_path, str):
        old_path = ''

    valid = form.validate_on_submit()
    path_changed = valid and form.plugin_path.data != old_path
    if path_changed and not form.confirm_plugin_change.data:
        form.confirm_plugin_change.errors.append(
            'Confirm this plugin path change before saving.'
        )
        valid = False
    if not valid:
        return _plugins_page(plugin_form=form, status_code=422)

    fields = (
        'relay.writePolicy.plugin',
        'relay.writePolicy.timeoutSeconds',
        'relay.writePolicy.lookbackSeconds',
    )
    _audit_config_update('requested', 'write-policy', fields)
    try:
        updates = _write_policy_updates(
            form.plugin_path.data,
            form.timeout.data,
            form.lookback.data,
        )
        snapshot.write(updates, expected_revision=form.config_revision.data)
    except RevisionConflict:
        _audit_config_update('conflict', 'write-policy', fields)
        form.config_revision.errors.append('Configuration changed. Reload before saving.')
        return _plugins_page(plugin_form=form, status_code=422)
    except ConfigurationBusy:
        _audit_config_update('failed', 'write-policy', fields)
        form.config_revision.errors.append('Configuration is busy. Try again shortly.')
        return _plugins_page(plugin_form=form, status_code=422)
    except (ConfigurationError, KeyError, OSError):
        _audit_config_update('failed', 'write-policy', fields)
        form.config_revision.errors.append('Configuration could not be saved safely.')
        return _plugins_page(plugin_form=form, status_code=422)

    _audit_config_update('completed', 'write-policy', fields)
    try:
        ModerationDecisions.request_republication()
    except ModerationError:
        flash('Configuration saved, but the ban projection could not be republished.', 'warning')
    if path_changed:
        flash('Write-policy configuration saved. Restart required to apply the plugin path change.', 'success')
    else:
        flash('Write-policy configuration saved. Runtime application status is unknown.', 'success')
    return redirect(url_for('plugins'), code=303)


@app.route('/plugins/wot', methods=['POST'])
@admin_required
def update_wot_policy():
    form = WoTPolicyForm()
    if not form.validate_on_submit():
        return _plugins_page(wot_form=form, status_code=422)

    try:
        raw_roots = form.root_npubs.data.replace(',', '\n').splitlines()
        roots = normalize_roots(raw_roots)
        policy, _ = initialize_wot()
        if form.mode.data == 'enforce' and not form.confirm_enforce.data:
            form.confirm_enforce.errors.append(
                'Confirm Enforce mode before publishing a policy that can reject events.'
            )
            return _plugins_page(wot_form=form, status_code=422)
        roots_changed = policy.roots != roots
        settings = {
            'mode': form.mode.data,
            'root_npubs': json.dumps(roots),
            'trust_threshold': form.trust_threshold.data,
            'pow_difficulty': form.pow_difficulty.data,
            'require_pow_commitment': form.require_pow_commitment.data,
            'refresh_interval_minutes': form.refresh_interval_minutes.data,
            'rate_limit_per_minute': form.rate_limit_per_minute.data,
            'rate_limit_burst': form.rate_limit_burst.data,
        }
        log_audit(
            'wot_policy_updated',
            f'Updated WoT policy mode={settings["mode"]}, threshold={settings["trust_threshold"]}, '
            f'pow={settings["pow_difficulty"]}, roots={len(roots)}',
            commit=False,
        )
        commit_policy_settings(
            policy,
            expected_revision=form.policy_revision.data,
            settings=settings,
        )
    except (OSError, SQLAlchemyError, WoTError, ValueError) as exc:
        db.session.rollback()
        form.root_npubs.errors.append(str(exc))
        return _plugins_page(wot_form=form, status_code=422)

    queued = False
    if settings['mode'] != 'off':
        try:
            queued = queue_wot_rebuild()
        except SQLAlchemyError:
            db.session.rollback()
            flash('Policy saved, but the local graph rebuild could not be queued.', 'warning')

    message = 'Web-of-trust policy artifact published. This does not prove active enforcement.'
    if queued:
        message += ' Local graph rebuild queued.'
    elif roots_changed:
        message += ' Roots changed; use Rebuild now after the active build finishes.'
    flash(message, 'success')
    return redirect(url_for('plugins'), code=303)


@app.route('/plugins/wot/rebuild', methods=['POST'])
@admin_required
def rebuild_wot_policy():
    form = EmptyForm()
    if not form.validate_on_submit():
        abort(400)
    if queue_wot_rebuild():
        log_audit('wot_rebuild_queued', 'Queued local web-of-trust rebuild')
        flash('Local web-of-trust rebuild queued.', 'success')
    else:
        flash('A web-of-trust rebuild is already queued or running.', 'warning')
    return redirect(url_for('plugins'))


@app.route('/connections')
@viewer_or_higher
def connections():
    return render_template(
        'connections.html',
        connections=connection_summary(),
        relay_name=_relay_name(),
    )


@app.route('/api/connections')
@viewer_or_higher
def api_connections():
    response = jsonify(connection_summary())
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    return response


@app.route('/admin')
@admin_required
def admin():
    return redirect(url_for('admin_operators'))


@app.route('/admin/operators')
@admin_required
def admin_operators():
    users = User.query.order_by(User.username, User.id).all()
    return render_template(
        'admin_operators.html',
        users=users,
        create_user_form=AdminCreateUserForm(),
    )


@app.route('/admin/audit')
@admin_required
def admin_audit():
    page = _audit_page(request.args)
    response = make_response(render_template(
        'admin_audit.html',
        audit_logs=page['logs'],
        audit_offset=page['offset'],
        audit_limit=page['limit'],
        audit_has_more=page['has_more'],
        audit_total=page['total_count'],
        next_cursor=page['next_cursor'],
        audit_filters=page['filters'],
    ))
    return _secure_audit_response(response)


@app.route('/admin/relays')
@admin_required
def admin_relays():
    return render_template('admin_relays.html')


@app.route('/admin/bans')
@admin_required
def admin_bans():
    banned_pubkeys = (
        BannedPubkey.query.options(
            joinedload(BannedPubkey.sources).joinedload(PubkeyBanSource.banned_domain)
        )
        .order_by(BannedPubkey.banned_at.desc())
        .all()
    )
    banned_domains = BannedDomain.query.order_by(BannedDomain.banned_at.desc()).all()
    _attach_domain_source_counts(banned_domains)
    return render_template(
        'admin_bans.html',
        banned_pubkeys=banned_pubkeys,
        banned_domains=banned_domains,
    )


@app.route('/moderation', methods=['GET', 'POST'])
@moderator_required
def moderation():
    report_type_filter = request.args.get('report_type', '')
    reporter_filter = request.args.get('reporter', '')
    reported_filter = request.args.get('reported', '')
    event_id_filter = request.args.get('event_id', '')
    show_reviewed = request.args.get('show_reviewed', 'false') == 'true'
    sort_order = 'asc' if request.args.get('sort') == 'asc' else 'desc'
    offset = max(0, request.args.get('offset', default=0, type=int))
    limit = min(100, max(1, request.args.get('limit', default=25, type=int)))
    
    query = ModerationReport.query
    
    if report_type_filter:
        query = query.filter(ModerationReport.report_type == report_type_filter)
    if reporter_filter:
        query = query.filter(ModerationReport.reporter_pubkey == reporter_filter)
    if reported_filter:
        query = query.filter(ModerationReport.reported_pubkey == reported_filter)
    if event_id_filter:
        query = query.filter(ModerationReport.reported_event_id == event_id_filter)
    if not show_reviewed:
        query = query.filter(ModerationReport.reviewed.is_(False))
    
    form = EmptyForm()
    domain_form = BannedDomainForm()
    
    if sort_order == 'desc':
        sort_columns = (ModerationReport.created_at.desc(), ModerationReport.id.desc())
    else:
        sort_columns = (ModerationReport.created_at.asc(), ModerationReport.id.asc())
    reports = query.order_by(*sort_columns).offset(offset).limit(limit).all()
    total_count = query.count()
    has_more = (offset + len(reports)) < total_count
    report_cursor = None
    if reports and has_more:
        report_cursor = {
            'created_at': reports[-1].created_at.isoformat() if reports[-1].created_at else None,
            'id': reports[-1].id,
        }
    open_report_count = ModerationReport.query.filter_by(reviewed=False).count()
    new_report_count = ModerationReport.query.filter(
        func.coalesce(ModerationReport.received_at, ModerationReport.created_at)
        >= utcnow() - timedelta(hours=24)
    ).count()
    pending_purges = EventPurge.query.filter_by(status='pending').order_by(EventPurge.created_at.desc()).all()
    completed_purges = EventPurge.query.filter_by(status='completed').order_by(
        EventPurge.created_at.desc()
    ).limit(25).all()
    projection = ModerationDecisions.initialize_projection()
    banned_domains = BannedDomain.query.order_by(BannedDomain.banned_at.desc()).all()
    _attach_domain_source_counts(banned_domains)
    active_domain_count = sum(
        domain.scan_status in ('queued', 'running') for domain in banned_domains
    )
    
    return render_template('moderation.html', reports=reports, 
                           report_type_filter=report_type_filter,
                           reporter_filter=reporter_filter,
                           reported_filter=reported_filter,
                           event_id_filter=event_id_filter,
                           show_reviewed=show_reviewed,
                           sort_order=sort_order,
                           offset=offset,
                           limit=limit,
                           has_more=has_more,
                           report_cursor=report_cursor,
                           total_count=total_count,
                           open_report_count=open_report_count,
                           new_report_count=new_report_count,
                           pending_purges=pending_purges,
                           completed_purges=completed_purges,
                           projection=projection,
                           banned_domains=banned_domains,
                           active_domain_count=active_domain_count,
                           domain_form=domain_form,
                           form=form)


def _moderation_return_url():
    candidate = request.form.get('next', '')
    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc or parsed.path != url_for('moderation'):
        return url_for('moderation')
    return candidate


@app.route('/moderation/report/<int:report_id>/review', methods=['POST'])
@moderator_required
def moderation_review(report_id):
    try:
        outcome = moderation_decisions().review_report(report_id)
        flash_moderation_outcome(outcome, 'Report marked as reviewed.')
    except ModerationError as e:
        flash(str(e), 'danger')
    
    return redirect(_moderation_return_url())


@app.route('/moderation/report/<int:report_id>/ban', methods=['POST'])
@moderator_required
def moderation_ban(report_id):
    reason = request.form.get('reason', 'Banned via moderation report')
    try:
        outcome = moderation_decisions().ban_report(report_id, reason)
        flash_moderation_outcome(outcome, 'Ban recorded.')
    except ModerationError as e:
        flash(f'Failed to ban user: {e}', 'danger')
    return redirect(_moderation_return_url())


@app.route('/moderation/report/<int:report_id>/delete', methods=['POST'])
@moderator_required
def moderation_delete_report(report_id):
    try:
        outcome = moderation_decisions().delete_report(report_id)
        flash_moderation_outcome(outcome, 'Report deleted.')
    except ModerationError as e:
        flash(str(e), 'danger')
    
    return redirect(_moderation_return_url())


@app.route('/moderation/report/<int:report_id>/delete-event', methods=['POST'])
@moderator_required
def moderation_delete_event(report_id):
    try:
        outcome = moderation_decisions().delete_reported_event(report_id)
        flash_moderation_outcome(outcome, 'Event purge recorded.')
    except ModerationError as e:
        flash(f'Failed to delete event: {e}', 'danger')
    
    return redirect(_moderation_return_url())


@app.route('/moderation/purge/<int:purge_id>/retry', methods=['POST'])
@moderator_required
def moderation_retry_purge(purge_id):
    try:
        purge = moderation_decisions().retry_purge(purge_id)
        if purge.was_cancelled:
            flash('Event purge cancelled because the pubkey is no longer banned.', 'info')
        elif purge.status == 'completed':
            flash('Event purge completed.', 'success')
        else:
            flash(f'Event purge remains pending: {purge.last_error}', 'warning')
    except ModerationError as e:
        flash(str(e), 'danger')
    return redirect(_moderation_return_url())


@app.route('/moderation/enforcement/retry', methods=['POST'])
@moderator_required
def moderation_retry_enforcement():
    outcome = moderation_decisions().retry_write_policy()
    if outcome.enforcement_status == 'published':
        flash('Ban enforcement published.', 'success')
    else:
        flash(f'Ban enforcement remains pending: {outcome.enforcement_error}', 'warning')
    next_endpoint = request.form.get('next', 'moderation')
    if next_endpoint not in {'moderation', 'plugins'}:
        next_endpoint = 'moderation'
    return redirect(url_for(next_endpoint))


@app.route('/moderation/ban-by-pubkey', methods=['POST'])
@moderator_required
def ban_by_pubkey():
    pubkey = request.form.get('pubkey')
    reason = request.form.get('reason', '').strip() or 'Banned from events page'
    
    if not pubkey:
        return 'No pubkey provided', 400
    
    try:
        outcome = moderation_decisions().ban_pubkey(pubkey, reason)
        flash_moderation_outcome(outcome, 'Ban recorded.')
        message = 'Ban recorded.'
        if outcome.warnings:
            message += ' ' + ' '.join(outcome.warnings)
        return message, 200
    except ModerationError as e:
        return f'Failed to ban user: {e}', 500


@app.route('/moderation/domain', methods=['POST'])
@moderator_required
def moderation_ban_domain():
    form = BannedDomainForm()
    if not form.validate_on_submit():
        errors = [message for messages in form.errors.values() for message in messages]
        flash(errors[0] if errors else 'Invalid domain ban.', 'danger')
        return redirect(url_for('moderation'))
    try:
        actor_id = current_user.id
        ip_address = get_client_ip()
        banned_domain = ModerationDecisions(actor_id, ip_address).create_domain(
            form.domain.data,
            form.reason.data or '',
        )
        if queue_domain_reconciliation(banned_domain.id, actor_id, ip_address):
            flash(f'Domain {banned_domain.domain} banned. Reconciliation started.', 'success')
        else:
            flash(
                f'Domain {banned_domain.domain} banned, but the reconciliation queue is busy. '
                'Use Reconcile to try again.',
                'warning',
            )
    except ModerationError as e:
        flash(str(e), 'danger')
    return redirect(url_for('moderation'))


@app.route('/moderation/domain/<int:domain_id>/reconcile', methods=['POST'])
@moderator_required
def moderation_reconcile_domain(domain_id):
    if not EmptyForm().validate_on_submit():
        abort(400)
    banned_domain = db.session.get(BannedDomain, domain_id)
    if banned_domain is None:
        flash('Banned domain not found', 'danger')
    elif queue_domain_reconciliation(domain_id, current_user.id, get_client_ip()):
        flash(f'Reconciliation started for {banned_domain.domain}.', 'success')
    else:
        flash(
            f'Could not queue reconciliation for {banned_domain.domain}; another scan may '
            'already be queued or running.',
            'warning',
        )
    return redirect(url_for('moderation'))


@app.route('/moderation/domain/<int:domain_id>')
@moderator_required
def moderation_domain_details(domain_id):
    banned_domain = db.session.get(BannedDomain, domain_id)
    if banned_domain is None:
        abort(404)
    search = request.args.get('q', '').strip()[:256]
    page = max(1, request.args.get('page', 1, type=int) or 1)
    unresolved_page_number = max(
        1,
        request.args.get('unresolved_page', 1, type=int) or 1,
    )
    per_page = min(100, max(1, request.args.get('per_page', 50, type=int) or 50))
    identities = domain_identity_page(
        domain_id,
        search,
        offset=(page - 1) * per_page,
        limit=per_page,
    )
    unresolved = unresolved_identity_page(
        banned_domain,
        search,
        offset=(unresolved_page_number - 1) * per_page,
        limit=per_page,
    )
    return render_template(
        'moderation_domain_details.html',
        domain_ban=banned_domain,
        identities=identities,
        unresolved=unresolved,
        search=search,
        page=page,
        unresolved_page=unresolved_page_number,
        per_page=per_page,
    )


@app.route('/moderation/domain/<int:domain_id>/export.csv')
@moderator_required
def moderation_domain_export(domain_id):
    banned_domain = db.session.get(BannedDomain, domain_id)
    if banned_domain is None:
        abort(404)
    search = request.args.get('q', '').strip()[:256]
    identities = domain_identity_page(domain_id, search, limit=None)
    output = StringIO(newline='')
    writer = csv.writer(output)
    writer.writerow([
        'nip05',
        'npub',
        'hex_pubkey',
        'discovered_at',
        'last_seen_at',
        'other_sources',
        'purge_status',
        'purge_attempts',
        'purge_error',
    ])
    for row in identities.rows:
        source = row.source
        purge = row.purge
        if purge is None:
            purge_status = 'not recorded'
        elif purge.was_cancelled:
            purge_status = 'cancelled'
        else:
            purge_status = purge.status
        writer.writerow([
            _csv_safe(
                f'{source.local_name}@{banned_domain.domain}'
                if source.local_name
                else ''
            ),
            row.npub,
            source.banned_pubkey.pubkey,
            source.banned_at.isoformat() if source.banned_at else '',
            source.last_seen_at.isoformat() if source.last_seen_at else '',
            _csv_safe(', '.join(row.other_sources)),
            purge_status,
            purge.attempts if purge else 0,
            _csv_safe(purge.last_error if purge and purge.last_error else ''),
        ])
    filename = f'banned-{banned_domain.domain}.csv'
    return app.response_class(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


def _csv_safe(value):
    value = str(value)
    normalized = value.lstrip(' \t\r\n')
    return "'" + value if normalized.startswith(('=', '+', '-', '@')) else value


def _attach_domain_source_counts(domains):
    domain_ids = [domain.id for domain in domains]
    if not domain_ids:
        return
    counts = dict(
        db.session.query(PubkeyBanSource.banned_domain_id, func.count(PubkeyBanSource.id))
        .filter(PubkeyBanSource.banned_domain_id.in_(domain_ids))
        .group_by(PubkeyBanSource.banned_domain_id)
    )
    for domain in domains:
        domain.source_count = counts.get(domain.id, 0)


def is_pubkey_banned(pubkey):
    if not pubkey:
        return False
    return BannedPubkey.query.filter_by(pubkey=pubkey).first() is not None


@app.route('/admin/user/<int:user_id>/edit', methods=['POST'])
@admin_required
@_operator_mutation_lock()
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserEditForm()
    
    if form.validate_on_submit():
        requested_active = form.is_active.data == 'true'
        if user.id == current_user.id and form.nostr_pubkey.data != user.nostr_pubkey:
            flash('Use signed key rotation to change your own Nostr pubkey.', 'danger')
            return redirect(url_for('admin_operators'))
        if user.id == current_user.id and (
            form.role.data != 'admin' or not requested_active
        ):
            flash('You cannot demote or deactivate your own account.', 'danger')
            return redirect(url_for('admin_operators'))
        removes_active_admin = (
            user.role == 'admin'
            and user.is_active
            and (form.role.data != 'admin' or not requested_active)
        )
        if removes_active_admin and User.query.filter_by(role='admin', is_active=True).count() <= 1:
            flash('At least one active admin account is required.', 'danger')
            return redirect(url_for('admin_operators'))
        pubkey_changed = form.nostr_pubkey.data != user.nostr_pubkey
        if pubkey_changed:
            user.username = _profile_username(form.nostr_pubkey.data, user.id)
        user.nostr_pubkey = form.nostr_pubkey.data
        if pubkey_changed:
            user.auth_version += 1
        user.role = form.role.data
        user.is_active = requested_active
        log_audit(
            'user_edit',
            f'Edited user {user_id}: username={user.username}, role={user.role}, active={user.is_active}',
            commit=False,
        )
        try:
            db.session.commit()
            flash(f'User {user.username} updated.', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('Nostr pubkey or profile-derived username already exists.', 'danger')
    else:
        flash('Failed to update user.', 'danger')
    
    return redirect(url_for('admin_operators'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
@_operator_mutation_lock()
def delete_user(user_id):
    if user_id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_operators'))
    
    user = User.query.get_or_404(user_id)
    if request.form.get('confirm_user_id') != str(user.id):
        abort(400)
    if (
        user.role == 'admin'
        and user.is_active
        and User.query.filter_by(role='admin', is_active=True).count() <= 1
    ):
        flash('At least one active admin account is required.', 'danger')
        return redirect(url_for('admin_operators'))
    username = user.username
    db.session.delete(user)
    log_audit('user_delete', f'Deleted user {username}', commit=False)
    db.session.commit()
    flash(f'User {username} deleted.', 'success')
    
    return redirect(url_for('admin_operators'))


@app.route('/admin/banned/<int:ban_id>/unban', methods=['POST'])
@admin_required
def unban_pubkey(ban_id):
    ban = BannedPubkey.query.get_or_404(ban_id)
    if not EmptyForm().validate_on_submit():
        abort(400)
    if request.form.get('confirm_pubkey') != ban.pubkey:
        abort(400)
    try:
        outcome = moderation_decisions().unban(ban_id)
        message = (
            'Pubkey unbanned.'
            if outcome.active_set_changed
            else 'Direct ban removed; the pubkey remains banned by a domain rule.'
        )
        flash_moderation_outcome(outcome, message)
    except ModerationError as e:
        flash(str(e), 'danger')
    
    return redirect(url_for('admin_bans'))


@app.route('/admin/banned-domain/<int:domain_id>/delete', methods=['POST'])
@admin_required
def delete_banned_domain(domain_id):
    banned_domain = BannedDomain.query.get_or_404(domain_id)
    if not EmptyForm().validate_on_submit():
        abort(400)
    if request.form.get('confirm_domain') != banned_domain.domain:
        abort(400)
    try:
        outcome = moderation_decisions().unban_domain(domain_id)
        flash(
            f'Domain unbanned: removed {outcome.removed_sources} sources and '
            f'unbanned {outcome.unbanned_pubkeys} pubkeys. '
            f'{outcome.remaining_bans} remain banned by other sources. '
            'Previously purged notes cannot be restored.',
            'success',
        )
        for warning in outcome.warnings:
            flash(warning, 'warning')
    except ModerationError as e:
        flash(str(e), 'danger')
    return redirect(url_for('admin_bans'))


@app.route('/admin/user', methods=['POST'])
@admin_required
@_operator_mutation_lock()
def create_user():
    form = AdminCreateUserForm()
    if form.validate_on_submit():
        user = User(
            nostr_pubkey=form.nostr_pubkey.data,
            role=form.role.data,
            must_change_password=False,
        )
        user.username = _profile_username(user.nostr_pubkey)
        user.disable_password()
        
        db.session.add(user)
        log_audit(
            'user_create',
            f'Created user {user.username} as {user.role}',
            commit=False,
        )
        try:
            db.session.commit()
            flash(f'User {user.username} created.', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('Nostr pubkey or profile-derived username already exists.', 'danger')
    else:
        flash('Failed to create user. Check the pubkey and role.', 'danger')
    
    return redirect(url_for('admin_operators'))


@app.route('/api/auth/rotate-current', methods=['POST'])
@csrf.exempt
@viewer_or_higher
@limiter.limit(Config.RATELIMIT_LOGIN)
def authorize_nostr_key_rotation():
    try:
        verified = _verified_auth('rotate-current')
    except NostrAuthError:
        return jsonify({'error': 'Current Nostr key verification failed.'}), 401
    if verified.pubkey != current_user.nostr_pubkey:
        return jsonify({'error': 'Sign with your currently assigned Nostr key.'}), 403
    session['_nostr_rotation'] = {
        'user_id': current_user.id,
        'auth_version': current_user.auth_version,
        'expires_at': int(time.time()) + Config.NOSTR_AUTH_CHALLENGE_TTL,
    }
    return jsonify({'authorized': True})


@app.route('/api/auth/rotate-key', methods=['POST'])
@csrf.exempt
@viewer_or_higher
@limiter.limit(Config.RATELIMIT_LOGIN)
@_operator_mutation_lock()
def rotate_nostr_key():
    rotation = session.pop('_nostr_rotation', None) or {}
    if (
        rotation.get('user_id') != current_user.id
        or rotation.get('auth_version') != current_user.auth_version
        or rotation.get('expires_at', 0) < int(time.time())
    ):
        return jsonify({'error': 'Reauthenticate with your current Nostr key first.'}), 403
    try:
        verified = _verified_auth('rotate-key')
    except NostrAuthError:
        return jsonify({'error': 'Nostr key rotation failed.'}), 401
    if User.query.filter(User.nostr_pubkey == verified.pubkey, User.id != current_user.id).first():
        return jsonify({'error': 'This Nostr pubkey is already assigned.'}), 409
    old_pubkey = current_user.nostr_pubkey
    current_user.username = _profile_username(verified.pubkey, current_user.id)
    current_user.nostr_pubkey = verified.pubkey
    current_user.auth_version += 1
    log_audit(
        'user_nostr_key_change',
        f'Changed own Nostr pubkey from {(old_pubkey or "unbound")[:12]} to {verified.pubkey[:12]}',
        commit=False,
    )
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'This Nostr pubkey is already assigned.'}), 409
    logout_user()
    return jsonify({'redirect': url_for('login')})


@app.errorhandler(CSRFError)
def csrf_error(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Request validation failed.'}), 400
    return _error_response(
        400,
        'Request validation failed',
        'Reload the page and try again.',
    )


@app.errorhandler(404)
def not_found_error(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'The requested API endpoint does not exist.'}), 404
    return _error_response(
        404,
        'Page not found',
        'The requested page does not exist or may have moved.',
    )


@app.errorhandler(RequestEntityTooLarge)
def request_too_large(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Request body is too large.'}), 413
    return _error_response(
        413,
        'Request too large',
        'The submitted request exceeds the allowed size.',
    )


@app.errorhandler(429)
def rate_limit_exceeded(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Too many requests. Please try again later.'}), 429
    return _error_response(
        429,
        'Too many requests',
        'Please wait before trying again.',
    )


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if request.path.startswith('/api/'):
        return jsonify({'error': 'The request could not be completed.'}), 500
    return _error_response(
        500,
        'Internal server error',
        'The request could not be completed. Please try again.',
    )


def _error_response(status_code, title, message):
    authenticated = current_user.is_authenticated
    recovery_url = url_for('index') if authenticated else url_for('login')
    recovery_label = 'Return to dashboard' if authenticated else 'Go to login'
    return render_template(
        'error.html',
        status_code=status_code,
        error_title=title,
        error_message=message,
        recovery_url=recovery_url,
        recovery_label=recovery_label,
    ), status_code


def init_db():
    with app.app_context():
        db.create_all()
        
        from sqlalchemy import text
        with db.engine.connect() as conn:
            user_columns = {
                row[1]
                for row in conn.execute(text("PRAGMA table_info('users')"))
            }
            if 'nostr_pubkey' not in user_columns:
                conn.execute(text('ALTER TABLE users ADD COLUMN nostr_pubkey VARCHAR(64)'))
                conn.commit()
            if 'auth_version' not in user_columns:
                conn.execute(text('ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 1'))
                conn.commit()
            conn.execute(text(
                'CREATE UNIQUE INDEX IF NOT EXISTS ix_users_nostr_pubkey '
                'ON users (nostr_pubkey) WHERE nostr_pubkey IS NOT NULL'
            ))
            result = conn.execute(text(
                "SELECT name FROM pragma_table_info('users') WHERE name='must_change_password'"
            ))
            if not result.fetchone():
                conn.execute(text(
                    "ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT 1"
                ))
                conn.commit()

            domain_columns = {
                row[1]
                for row in conn.execute(text("PRAGMA table_info('banned_domains')"))
            }
            if 'last_scan_details' not in domain_columns:
                try:
                    conn.execute(text(
                        'ALTER TABLE banned_domains ADD COLUMN last_scan_details TEXT'
                    ))
                    conn.commit()
                except OperationalError as exc:
                    if 'duplicate column name' not in str(exc).lower():
                        raise
            purge_columns = {
                row[1]
                for row in conn.execute(text("PRAGMA table_info('event_purges')"))
            }
            if 'claimed_at' not in purge_columns:
                try:
                    conn.execute(text(
                        'ALTER TABLE event_purges ADD COLUMN claimed_at DATETIME'
                    ))
                    conn.commit()
                except OperationalError as exc:
                    if 'duplicate column name' not in str(exc).lower():
                        raise
            report_columns = {
                row[1]
                for row in conn.execute(text("PRAGMA table_info('moderation_reports')"))
            }
            if 'received_at' not in report_columns:
                try:
                    conn.execute(text(
                        'ALTER TABLE moderation_reports ADD COLUMN received_at DATETIME'
                    ))
                    conn.execute(text(
                        'UPDATE moderation_reports SET received_at = CURRENT_TIMESTAMP '
                        'WHERE received_at IS NULL'
                    ))
                    conn.commit()
                except OperationalError as exc:
                    if 'duplicate column name' not in str(exc).lower():
                        raise
            conn.execute(text(
                'CREATE INDEX IF NOT EXISTS ix_pubkey_ban_source_domain_id '
                'ON pubkey_ban_sources (banned_domain_id, id)'
            ))
            ensure_moderation_report_indexes(conn)
            ensure_audit_log_indexes(conn)
            conn.commit()

        if MetadataRelay.query.count() == 0:
            default_relays = [
                'wss://relay.damus.io',
                'wss://nos.lol',
                'wss://relay.nostr.band'
            ]
            for url in default_relays:
                relay = MetadataRelay(url=url, enabled=True, is_default=True)
                db.session.add(relay)
            db.session.commit()

        stale_before = utcnow() - timedelta(seconds=_domain_scan_lease_seconds())
        interrupted_domains = BannedDomain.query.filter(
            BannedDomain.scan_status.in_(['queued', 'running']),
            or_(
                BannedDomain.scan_started_at.is_(None),
                BannedDomain.scan_started_at < stale_before,
            ),
        ).all()
        for banned_domain in interrupted_domains:
            banned_domain.scan_status = 'idle'
            banned_domain.scan_started_at = None
            banned_domain.last_scan_error = 'Reconciliation resumed after application restart'
        db.session.commit()

        ModerationDecisions.backfill_ban_sources()
        for banned_domain in interrupted_domains:
            if not queue_domain_reconciliation(banned_domain.id, banned_domain.banned_by, None):
                banned_domain = db.session.get(BannedDomain, banned_domain.id)
                banned_domain.last_scan_error = (
                    'Reconciliation interrupted by application restart; use Reconcile to retry'
                )
                db.session.commit()
        
        ModerationDecisions.initialize_projection()
        projection = ModerationDecisions.reconcile_write_policy(force=True)
        if projection.status != 'published':
            raise RuntimeError(
                f'Could not publish initial blocklist: {projection.last_error or "unknown error"}'
            )
        wot_policy, wot_state = initialize_wot()
        stale_wot_before = utcnow() - timedelta(seconds=360)
        if (
            wot_state.status in ('queued', 'running')
            and (
                wot_state.started_at is None
                or wot_state.started_at < stale_wot_before
            )
        ):
            wot_state.status = 'failed'
            wot_state.last_error = 'Build interrupted by application restart'
            wot_state.started_at = None
            db.session.commit()
        republish_policy_settings(wot_policy)
        if _wot_refresh_due(wot_policy, wot_state):
            queue_wot_rebuild()


init_db()

threading.Thread(
    target=_purge_worker,
    daemon=True,
    name='event-purge-worker',
).start()
queue_purge_processing()

threading.Thread(
    target=_wot_refresh_scheduler,
    daemon=True,
    name='wot-refresh-scheduler',
).start()

threading.Thread(
    target=_dashboard_sampler,
    daemon=True,
    name='dashboard-telemetry-sampler',
).start()

threading.Thread(
    target=_report_sync_scheduler,
    daemon=True,
    name='moderation-report-sync',
).start()


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
