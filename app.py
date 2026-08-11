import csv
import json
import os
import queue
import threading
import time
from datetime import datetime, timedelta
from urllib.parse import urlsplit
from flask import Flask, render_template, redirect, url_for, flash, request, send_file, jsonify, abort, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import BooleanField, StringField, PasswordField, SelectField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, InputRequired, Length, EqualTo, NumberRange, Optional, Regexp, ValidationError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import and_, func, or_
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from io import StringIO, BytesIO
import tempfile

from config import Config, Security
from models import (
    db, User, AuditLog, ModerationReport, BannedPubkey, BannedDomain, MetadataRelay,
    EventPurge, PubkeyBanSource, WoTBuildState, ensure_moderation_report_indexes,
    utcnow,
)
from utils.strfry import (
    scan_events, delete_events, export_events, import_events,
    compact_database, negentropy_list, negentropy_add, negentropy_build,
    negentropy_delete, dict_list, get_config, update_config, StrfryError,
    validate_filter_json, npub_to_hex, get_strfry_process_info,
    acquire_database_maintenance_lock, release_database_maintenance_lock,
)
from utils.metrics import get_summary, MetricsError
from utils.auth import admin_required, moderator_required, viewer_or_higher, permission_required
from utils.moderation import ModerationDecisions, ModerationError
from utils.moderation_reports import sync_moderation_reports
from utils.nip05 import (
    LOCAL_NAME_PATTERN,
    PUBKEY_PATTERN,
    Nip05VerificationError,
    fetch_nip05_document,
    normalize_domain,
)
from utils.domain_view import domain_identity_page, unresolved_identity_page
from utils.decision_log import read_decision_log
from utils.dashboard import collect_sample, connection_summary, dashboard_summary
from utils.wot import (
    WoTError,
    commit_policy_settings,
    initialize_wot,
    normalize_roots,
    rebuild_policy,
    republish_policy_settings,
)

_compaction = {
    'running': False,
    'started_at': None,
    'finished_at': None,
    'error': None,
    'thread': None,
}
_domain_scan_queue = queue.Queue(maxsize=1)
_wot_build_queue = queue.Queue(maxsize=1)
_dashboard_sample_lock = threading.Lock()


def _run_compaction(lock_file):
    try:
        compact_database(lock_file=lock_file)
    except StrfryError as e:
        _compaction['error'] = str(e)
    finally:
        release_database_maintenance_lock(lock_file)
        _compaction['finished_at'] = datetime.now()
        _compaction['running'] = False


class PubkeyMetadataCache:
    def __init__(self, max_size=50000, ttl_days=7):
        self.cache = {}
        self.max_size = max_size
        self.ttl_seconds = ttl_days * 86400
        self.access_order = []
    
    def get(self, pubkey):
        if pubkey in self.cache:
            metadata, timestamp = self.cache[pubkey]
            import time
            if time.time() - timestamp > self.ttl_seconds:
                del self.cache[pubkey]
                self.access_order.remove(pubkey)
                return None
            if pubkey in self.access_order:
                self.access_order.remove(pubkey)
            self.access_order.append(pubkey)
            return metadata
        return None
    
    def set(self, pubkey, metadata):
        import time
        current_time = time.time()
        
        if len(self.cache) > 0 and len(self.cache) % 100 == 0:
            self._cleanup_expired()
        
        if pubkey in self.cache:
            if pubkey in self.access_order:
                self.access_order.remove(pubkey)
        else:
            if len(self.cache) >= self.max_size:
                oldest = self.access_order.pop(0)
                del self.cache[oldest]
        
        self.cache[pubkey] = (metadata, current_time)
        self.access_order.append(pubkey)
    
    def _cleanup_expired(self):
        import time
        now = time.time()
        expired = [
            k for k, v in self.cache.items() 
            if now - v[1] > self.ttl_seconds
        ]
        for k in expired:
            del self.cache[k]
            if k in self.access_order:
                self.access_order.remove(k)


pubkey_metadata_cache = PubkeyMetadataCache()


def fetch_from_external_relays(pubkey, relays_list=None):
    """Fetch kind 0 metadata from external relays."""
    from models import MetadataRelay
    import json
    
    if relays_list is None:
        enabled_relays = MetadataRelay.query.filter_by(enabled=True).all()
        relays_list = [r.url for r in enabled_relays]
    
    for relay_url in relays_list:
        try:
            subscription = json.dumps({
                "kinds": [0],
                "authors": [pubkey],
                "limit": 1
            })
            ws_url = relay_url.replace('wss://', 'wss://').replace('ws://', 'ws://')
            
            import websocket
            ws = websocket.create_connection(ws_url, timeout=5)
            ws.send(json.dumps(["REQ", "metadata", subscription]))
            
            while True:
                try:
                    response = ws.recv()
                    if not response:
                        break
                    msg = json.loads(response)
                    if msg[0] == "EVENT" and msg[2].get('kind') == 0:
                        ws.close()
                        return json.loads(msg[2].get('content', '{}'))
                except:
                    break
            
            ws.close()
        except Exception:
            continue
    
    return None


def get_pubkey_metadata(pubkey):
    cached = pubkey_metadata_cache.get(pubkey)
    if cached:
        return cached
    
    try:
        events = scan_events({
            'kinds': [0],
            'authors': [pubkey]
        }, limit=1)
        if events:
            import json
            content = json.loads(events[0]['content'])
            pubkey_metadata_cache.set(pubkey, content)
            return content
    except Exception:
        pass
    
    metadata = fetch_from_external_relays(pubkey)
    if metadata:
        pubkey_metadata_cache.set(pubkey, metadata)
        return metadata
    
    pubkey_metadata_cache.set(pubkey, {})
    return {}


app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"]
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=80),
        Regexp(r'^[a-zA-Z0-9_]+$', message='Username must be alphanumeric with underscores only')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=21),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
               message='Password must have: 21+ chars, uppercase, lowercase, digit, special char')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('moderator', 'Moderator'), ('viewer', 'Viewer')], validators=[DataRequired()])
    registration_token = StringField('Registration Token', validators=[DataRequired()])


class AdminCreateUserForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=80),
        Regexp(r'^[a-zA-Z0-9_]+$', message='Username must be alphanumeric with underscores only')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, max=128)
    ])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('moderator', 'Moderator'), ('viewer', 'Viewer')], validators=[DataRequired()])


class UserEditForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=80),
        Regexp(r'^[a-zA-Z0-9_]+$', message='Username must be alphanumeric with underscores only')
    ])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('moderator', 'Moderator'), ('viewer', 'Viewer')], validators=[DataRequired()])
    is_active = SelectField('Active', choices=[('true', 'Yes'), ('false', 'No')], validators=[DataRequired()])


class ChangePasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=21),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
               message='Password must have: 21+ chars, uppercase, lowercase, digit, special char')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])


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


class ConfigForm(FlaskForm):
    relay_name = StringField('Relay Name', validators=[Optional()])
    relay_description = StringField('Description', validators=[Optional()])
    relay_pubkey = StringField('Pubkey', validators=[Optional()])
    relay_contact = StringField('Contact', validators=[Optional()])
    relay_bind = StringField('Bind Address', validators=[Optional()])
    relay_port = StringField('Port', validators=[Optional()])


class PluginForm(FlaskForm):
    plugin_path = StringField('Plugin Path', validators=[Optional()])
    timeout = IntegerField('Timeout (seconds)', default=10, validators=[Optional()])
    lookback = IntegerField('Lookback (seconds)', default=0, validators=[Optional()])


class WoTPolicyForm(FlaskForm):
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


@app.context_processor
def inject_user():
    return dict(User=User)


@app.context_processor
def inject_relay_name():
    config = get_config()
    relay_name = config.get('info', {}).get('name', '') if config else ''
    return dict(relay_name=relay_name)


@app.template_filter('datetime')
def datetime_filter(ts):
    from datetime import datetime
    if not ts:
        return ''
    try:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except:
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
    if days: parts.append(f'{days}d')
    if hours: parts.append(f'{hours}h')
    if mins or not parts: parts.append(f'{mins}m')
    return ' '.join(parts)


def get_client_ip():
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr


def moderation_decisions():
    return ModerationDecisions(current_user.id, get_client_ip())


def _run_domain_reconciliation(domain_id, actor_id, ip_address):
    with app.app_context():
        try:
            ModerationDecisions(actor_id, ip_address).reconcile_domain(domain_id)
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


def log_audit(action, details=None, user_id=None):
    user_id = user_id or (current_user.id if current_user.is_authenticated else None)
    log = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=get_client_ip()
    )
    db.session.add(log)
    db.session.commit()


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
    config = get_config()
    relay_name = config.get('info', {}).get('name', '') if config else ''

    return render_template('index.html', dashboard=dashboard, relay_name=relay_name)


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
def api_pubkey_metadata(pubkey):
    try:
        metadata = get_pubkey_metadata(pubkey)
        return jsonify(metadata)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
    relays = MetadataRelay.query.all()
    return jsonify([r.to_dict() for r in relays])


@app.route('/api/metadata-relays', methods=['POST'])
@admin_required
def api_metadata_relays_add():
    url = request.json.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if not url.startswith('wss://') and not url.startswith('ws://'):
        return jsonify({'error': 'URL must start with wss:// or ws://'}), 400
    
    existing = MetadataRelay.query.filter_by(url=url).first()
    if existing:
        return jsonify({'error': 'Relay already exists'}), 400
    
    relay = MetadataRelay(url=url, enabled=True)
    db.session.add(relay)
    db.session.commit()
    
    log_audit('metadata_relay_added', f'Added metadata relay: {url}')
    return jsonify(relay.to_dict())


@app.route('/api/metadata-relays/<int:relay_id>', methods=['DELETE'])
@admin_required
def api_metadata_relays_delete(relay_id):
    relay = MetadataRelay.query.get_or_404(relay_id)
    url = relay.url
    db.session.delete(relay)
    db.session.commit()
    
    log_audit('metadata_relay_deleted', f'Deleted metadata relay: {url}')
    return jsonify({'success': True})


@app.route('/api/metadata-relays/<int:relay_id>/toggle', methods=['POST'])
@admin_required
def api_metadata_relays_toggle(relay_id):
    relay = MetadataRelay.query.get_or_404(relay_id)
    relay.enabled = not relay.enabled
    db.session.commit()
    
    log_audit('metadata_relay_toggled', f'Toggled metadata relay: {relay.url} ({relay.enabled})')
    return jsonify(relay.to_dict())


@app.route('/api/metadata-relays/<int:relay_id>/test', methods=['POST'])
@admin_required
def api_metadata_relays_test(relay_id):
    import json
    import websocket
    from datetime import datetime
    
    relay = MetadataRelay.query.get_or_404(relay_id)
    
    try:
        ws_url = relay.url.replace('wss://', 'wss://').replace('ws://', 'ws://')
        ws = websocket.create_connection(ws_url, timeout=5)
        ws.send(json.dumps(["REQ", "test", {"kinds": [0], "limit": 1}]))
        
        response = ws.recv()
        ws.close()
        
        relay.last_status = 'success'
        relay.last_tested = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Relay is working'})
    except Exception as e:
        relay.last_status = 'failed'
        relay.last_tested = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'status': 'failed', 'message': str(e)})


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
        query = query.filter(ModerationReport.reviewed == False)

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


@app.route('/api/audit-logs')
@admin_required
def api_audit_logs():
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 25))
    
    query = AuditLog.query.order_by(AuditLog.timestamp.desc())
    total_count = query.count()
    logs = query.offset(offset).limit(limit).all()
    has_more = (offset + len(logs)) < total_count
    
    logs_data = []
    for log in logs:
        logs_data.append({
            'id': log.id,
            'action': log.action,
            'details': log.details,
            'user_id': log.user_id,
            'username': log.user.username if log.user else 'system',
            'ip_address': log.ip_address,
            'timestamp': log.timestamp.isoformat() if log.timestamp else None
        })
    
    return jsonify({
        'logs': logs_data,
        'has_more': has_more,
        'total_count': total_count
    })


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user:
            if user.lockout_until and user.lockout_until > datetime.utcnow():
                flash('Account temporarily locked. Try again later.', 'danger')
                return render_template('login.html', form=form)
            
            if user.check_password(form.password.data):
                if not user.is_active:
                    flash('Your account has been deactivated.', 'danger')
                    return render_template('login.html', form=form)
                
                user.failed_login_attempts = 0
                user.lockout_until = None
                login_user(user)
                user.update_login()
                db.session.commit()
                
                log_audit('login', f'User logged in')
                
                if user.must_change_password:
                    flash('Please change your password.', 'warning')
                    return redirect(url_for('change_password_route', user_id=user.id))
                
                next_page = request.args.get('next')
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(next_page) if next_page else redirect(url_for('index'))
        
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.lockout_until = datetime.utcnow() + timedelta(minutes=15)
                flash('Too many failed attempts. Account locked for 15 minutes.', 'danger')
                log_audit('login_failed', f'Account locked after 5 failed attempts for {user.username}')
            else:
                flash('Invalid username or password.', 'danger')
                log_audit('login_failed', f'Failed login attempt for {user.username}')
            db.session.commit()
        else:
            flash('Invalid username or password.', 'danger')
            log_audit('login_failed', f'Failed login attempt for unknown user {form.username.data}')
    
    return render_template('login.html', form=form)


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    log_audit('logout', f'User logged out')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if User.query.count() > 0:
        flash('Registration is closed. Please contact an administrator.', 'warning')
        return redirect(url_for('login'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        if Config.REGISTRATION_TOKEN and form.registration_token.data != Config.REGISTRATION_TOKEN:
            flash('Invalid registration token.', 'danger')
            log_audit('register_failed', f'Invalid token attempt for user {form.username.data}')
            return render_template('register.html', form=form)
        
        user = User(
            username=form.username.data,
            role=form.role.data,
            must_change_password=False
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        log_audit('register', f'User {user.username} registered as {user.role}')
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)


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
                result = delete_events(filter_obj)
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
                result = import_events(import_form.file.data, verify=verify)
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
    
    if request.method == 'POST':
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
            if _compaction['running']:
                flash('Compaction is already in progress.', 'warning')
            elif request.form.get('confirm_compact') != 'yes':
                flash('Confirm that the relay is stopped before compacting.', 'danger')
            else:
                process_count = get_strfry_process_info()['process_count']
                if process_count is None:
                    flash('Cannot confirm that the relay is stopped; compaction was not started.', 'danger')
                elif process_count > 0:
                    flash('Stop all strfry processes before compacting the database.', 'danger')
                else:
                    try:
                        lock_file = acquire_database_maintenance_lock()
                    except StrfryError as e:
                        flash(str(e), 'danger')
                    else:
                        _compaction['running'] = True
                        _compaction['started_at'] = datetime.now()
                        _compaction['finished_at'] = None
                        _compaction['error'] = None
                        t = threading.Thread(target=_run_compaction, args=(lock_file,), daemon=True)
                        _compaction['thread'] = t
                        t.start()
                        flash('Database compaction started in background.', 'info')
                        log_audit('compact', 'Database compaction initiated')
            return redirect(url_for('db_management'))
        
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
    
    compaction_status = {
        'running': _compaction['running'],
        'started_at': _compaction.get('started_at'),
        'finished_at': _compaction.get('finished_at'),
        'error': _compaction.get('error'),
    }
    return render_template(
        'db.html',
        trees=trees,
        negentropy_add_form=negentropy_add_form,
        negentropy_error=negentropy_error,
        negentropy_success=negentropy_success,
        dict_output=dict_output,
        dict_error=dict_error,
        compaction_status=compaction_status,
    )


@app.route('/config', methods=['GET', 'POST'])
@permission_required('config')
def config_view():
    form = ConfigForm()
    error = None
    success = None
    
    current_config = get_config()
    
    if request.method == 'POST':
        updates = {}
        
        if form.relay_name.data:
            updates['relay.info.name'] = form.relay_name.data
        if form.relay_description.data:
            updates['relay.info.description'] = form.relay_description.data
        if form.relay_pubkey.data:
            updates['relay.info.pubkey'] = form.relay_pubkey.data
        if form.relay_contact.data:
            updates['relay.info.contact'] = form.relay_contact.data
        if form.relay_bind.data:
            updates['relay.bind'] = form.relay_bind.data
        if form.relay_port.data:
            updates['relay.port'] = form.relay_port.data
        
        if updates:
            try:
                update_config(updates)
                success = 'Configuration updated successfully. Some changes may require strfry restart.'
                log_audit('config_update', f'Updated config: {list(updates.keys())}')
                current_config = get_config()
            except Exception as e:
                error = str(e)
    
    if current_config:
        if 'relay' in current_config and 'info' in current_config['relay']:
            relay_info = current_config['relay'].get('info', {})
            form.relay_name.data = relay_info.get('name', '')
            form.relay_description.data = relay_info.get('description', '')
            form.relay_pubkey.data = relay_info.get('pubkey', '')
            form.relay_contact.data = relay_info.get('contact', '')
        
        if 'relay' in current_config:
            relay_config = current_config['relay']
            form.relay_bind.data = relay_config.get('bind', '')
            form.relay_port.data = relay_config.get('port', '')
    
    return render_template('config.html', form=form, current_config=current_config, error=error, success=success)


@app.route('/plugins', methods=['GET', 'POST'])
@admin_required
def plugins():
    form = PluginForm()
    wot_form = WoTPolicyForm()
    error = None
    success = None

    current_config = get_config()
    write_policy = current_config.get('relay', {}).get('writePolicy', {}) if current_config else {}

    plugin_path = app.config['BLOCKLIST_PLUGIN_PATH']
    plugin_installed = os.path.exists(plugin_path) and os.access(plugin_path, os.X_OK)
    blocklist_count = BannedPubkey.query.count()
    projection = ModerationDecisions.initialize_projection()
    wot_policy, wot_state = initialize_wot()
    try:
        with open(app.config['TRUST_POLICY_STATS_FILE']) as stats_file:
            wot_stats = json.load(stats_file)
        if not isinstance(wot_stats, dict):
            wot_stats = {}
    except (OSError, json.JSONDecodeError):
        wot_stats = {}

    if request.method == 'POST':
        if form.validate():
            updates = {}
            updates['relay.writePolicy.plugin'] = form.plugin_path.data or ''
            if form.timeout.data is not None:
                updates['relay.writePolicy.timeoutSeconds'] = str(form.timeout.data)
            if form.lookback.data is not None:
                updates['relay.writePolicy.lookbackSeconds'] = str(form.lookback.data)

            if updates:
                try:
                    update_config(updates)
                    projection = ModerationDecisions.request_republication()
                    success = 'Plugin configuration updated. Restart strfry to apply changes.'
                    log_audit('plugin_update', f'Updated plugin config: {updates}')
                    current_config = get_config()
                    write_policy = current_config.get('relay', {}).get('writePolicy', {}) if current_config else {}
                except (KeyError, OSError, ModerationError) as e:
                    error = str(e)

    if write_policy:
        form.plugin_path.data = write_policy.get('plugin', '')
        form.timeout.data = write_policy.get('timeoutSeconds', 10)
        form.lookback.data = write_policy.get('lookbackSeconds', 0)
    else:
        form.plugin_path.data = plugin_path if plugin_installed else ''
        form.timeout.data = 10
        form.lookback.data = 0

    wot_form.mode.data = wot_policy.mode
    wot_form.root_npubs.data = '\n'.join(wot_policy.roots)
    wot_form.trust_threshold.data = wot_policy.trust_threshold
    wot_form.pow_difficulty.data = wot_policy.pow_difficulty
    wot_form.require_pow_commitment.data = wot_policy.require_pow_commitment
    wot_form.refresh_interval_minutes.data = wot_policy.refresh_interval_minutes
    wot_form.rate_limit_per_minute.data = wot_policy.rate_limit_per_minute
    wot_form.rate_limit_burst.data = wot_policy.rate_limit_burst

    return render_template('plugins.html', form=form, error=error, success=success,
                           plugin_installed=plugin_installed, blocklist_count=blocklist_count,
                           plugin_path=plugin_path, projection=projection,
                           wot_form=wot_form, wot_policy=wot_policy, wot_state=wot_state,
                           wot_stats=wot_stats)


@app.route('/plugins/wot', methods=['POST'])
@admin_required
def update_wot_policy():
    form = WoTPolicyForm()
    if not form.validate_on_submit():
        for errors in form.errors.values():
            for message in errors:
                flash(message, 'danger')
        return redirect(url_for('plugins'))

    try:
        raw_roots = form.root_npubs.data.replace(',', '\n').splitlines()
        roots = normalize_roots(raw_roots)
        policy, _ = initialize_wot()
        roots_changed = policy.roots != roots
        policy.mode = form.mode.data
        policy.root_npubs = json.dumps(roots)
        policy.trust_threshold = form.trust_threshold.data
        policy.pow_difficulty = form.pow_difficulty.data
        policy.require_pow_commitment = form.require_pow_commitment.data
        policy.refresh_interval_minutes = form.refresh_interval_minutes.data
        policy.rate_limit_per_minute = form.rate_limit_per_minute.data
        policy.rate_limit_burst = form.rate_limit_burst.data
        commit_policy_settings(policy)
        queued = queue_wot_rebuild() if policy.mode != 'off' else False
        log_audit(
            'wot_policy_updated',
            f'Updated WoT policy mode={policy.mode}, threshold={policy.trust_threshold}, '
            f'pow={policy.pow_difficulty}, roots={len(roots)}',
        )
    except (OSError, SQLAlchemyError, WoTError, ValueError) as exc:
        db.session.rollback()
        flash(str(exc), 'danger')
        return redirect(url_for('plugins'))

    message = 'Web-of-trust policy published.'
    if queued:
        message += ' Local graph rebuild queued.'
    elif roots_changed:
        message += ' Roots changed; use Rebuild now after the active build finishes.'
    flash(message, 'success')
    return redirect(url_for('plugins'))


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
    config = get_config()
    relay_name = (
        config.get('relay', {}).get('info', {}).get('name', '')
        if config else ''
    )
    return render_template(
        'connections.html',
        connections=connection_summary(),
        relay_name=relay_name,
    )


@app.route('/api/connections')
@viewer_or_higher
def api_connections():
    response = jsonify(connection_summary())
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    return response


@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    users = User.query.all()
    audit_offset = int(request.args.get('audit_offset', 0))
    audit_limit = int(request.args.get('audit_limit', 10))
    
    audit_query = AuditLog.query.order_by(AuditLog.timestamp.desc())
    audit_logs = audit_query.offset(audit_offset).limit(audit_limit).all()
    total_logs = audit_query.count()
    audit_has_more = (audit_offset + len(audit_logs)) < total_logs
    
    banned_pubkeys = BannedPubkey.query.order_by(BannedPubkey.banned_at.desc()).all()
    banned_domains = BannedDomain.query.order_by(BannedDomain.banned_at.desc()).all()
    _attach_domain_source_counts(banned_domains)
    
    edit_forms = {}
    for user in users:
        edit_forms[user.id] = UserEditForm(
            username=user.username,
            role=user.role,
            is_active='true' if user.is_active else 'false'
        )
    
    create_user_form = AdminCreateUserForm()
    change_password_form = ChangePasswordForm()
    
    return render_template('admin.html', users=users, audit_logs=audit_logs, edit_forms=edit_forms, create_user_form=create_user_form, change_password_form=change_password_form, banned_pubkeys=banned_pubkeys, banned_domains=banned_domains, audit_offset=audit_offset, audit_limit=audit_limit, audit_has_more=audit_has_more, audit_total=total_logs)


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
        query = query.filter(ModerationReport.reviewed == False)
    
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
        ModerationReport.created_at >= utcnow() - timedelta(hours=24)
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
    search = request.args.get('q', '').strip()
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
    search = request.args.get('q', '').strip()
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
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserEditForm()
    
    if form.validate_on_submit():
        user.username = form.username.data
        user.role = form.role.data
        user.is_active = form.is_active.data == 'true'
        db.session.commit()
        
        log_audit('user_edit', f'Edited user {user_id}: username={user.username}, role={user.role}, active={user.is_active}')
        flash(f'User {user.username} updated.', 'success')
    else:
        flash('Failed to update user.', 'danger')
    
    return redirect(url_for('admin'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin'))
    
    user = User.query.get_or_404(user_id)
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    log_audit('user_delete', f'Deleted user {username}')
    flash(f'User {username} deleted.', 'success')
    
    return redirect(url_for('admin'))


@app.route('/admin/banned/<int:ban_id>/unban', methods=['POST'])
@admin_required
def unban_pubkey(ban_id):
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
    
    return redirect(url_for('admin'))


@app.route('/admin/banned-domain/<int:domain_id>/delete', methods=['POST'])
@admin_required
def delete_banned_domain(domain_id):
    if not EmptyForm().validate_on_submit():
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
    return redirect(url_for('admin'))


@app.route('/admin/user', methods=['POST'])
@admin_required
def create_user():
    form = AdminCreateUserForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            role=form.role.data,
            must_change_password=True
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        try:
            db.session.commit()
            log_audit('user_create', f'Created user {user.username} as {user.role}')
            flash(f'User {user.username} created.', 'success')
        except Exception as e:
            db.session.rollback()
            if 'UNIQUE constraint' in str(e) or 'duplicate' in str(e).lower():
                flash('Username already exists.', 'danger')
            else:
                flash('Failed to create user.', 'danger')
    else:
        flash('Failed to create user. Check username and password requirements.', 'danger')
    
    return redirect(url_for('admin'))


@app.route('/change-password/<int:user_id>', methods=['GET', 'POST'])
@login_required
def change_password_route(user_id):
    if current_user.id != user_id and current_user.role != 'admin':
        abort(403)
    
    user = User.query.get_or_404(user_id)
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.must_change_password = False
        db.session.commit()
        log_audit('password_change', f'Password changed for {user.username}')
        
        if current_user.id == user_id:
            flash('Password changed successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash(f'Password for {user.username} changed.', 'success')
            return redirect(url_for('admin'))
    
    return render_template('change_password.html', form=form, user=user)


@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error='404 - Page Not Found'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error='500 - Internal Server Error'), 500


def init_db():
    with app.app_context():
        from models import (
            ModerationReport,
            BannedPubkey,
            BannedDomain,
            MetadataRelay,
            PubkeyBanSource,
        )
        db.create_all()
        
        from sqlalchemy import text
        with db.engine.connect() as conn:
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
            conn.execute(text(
                'CREATE INDEX IF NOT EXISTS ix_pubkey_ban_source_domain_id '
                'ON pubkey_ban_sources (banned_domain_id, id)'
            ))
            ensure_moderation_report_indexes(conn)
            conn.commit()
            
            try:
                conn.execute(text("SELECT 1 FROM metadata_relays LIMIT 1"))
            except:
                conn.execute(text("CREATE TABLE IF NOT EXISTS metadata_relays (id INTEGER PRIMARY KEY, url TEXT UNIQUE NOT NULL, enabled BOOLEAN DEFAULT 1, is_default BOOLEAN DEFAULT 0, last_status TEXT DEFAULT 'unknown', last_tested TIMESTAMP)"))
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
        ModerationDecisions.reconcile_write_policy(force=True)
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
