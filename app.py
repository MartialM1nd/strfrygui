import os
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, flash, request, send_file, jsonify, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, Optional, Regexp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from io import StringIO, BytesIO
import tempfile

from config import Config, Security
from models import db, User, AuditLog, ModerationReport, BannedPubkey, MetadataRelay
from utils.strfry import (
    scan_events, delete_events, export_events, import_events,
    compact_database, negentropy_list, negentropy_add, negentropy_build,
    negentropy_delete, dict_list, get_config, update_config, StrfryError,
    validate_filter_json, npub_to_hex
)
from utils.metrics import get_summary, MetricsError
from utils.auth import admin_required, moderator_required, viewer_or_higher, permission_required

APP_DIR = os.path.dirname(os.path.abspath(__file__))
BANNED_PUBKEYS_FILE = os.path.join(APP_DIR, "blocklist.json")
BLOCKLIST_PLUGIN_PATH = os.path.join(APP_DIR, "utils", "blocklist_plugin.py")


def sync_blocklist():
    """Write blocklist.json and trigger strfry plugin auto-reload."""
    try:
        from models import BannedPubkey
        banned = [b.pubkey for b in BannedPubkey.query.all()]
        with open(BANNED_PUBKEYS_FILE, 'w') as f:
            json.dump(banned, f)
        if os.path.exists(BLOCKLIST_PLUGIN_PATH):
            if not os.access(BLOCKLIST_PLUGIN_PATH, os.X_OK):
                os.chmod(BLOCKLIST_PLUGIN_PATH, 0o755)
            os.utime(BLOCKLIST_PLUGIN_PATH, None)
    except Exception:
        pass


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
    limit = IntegerField('Limit', default=25)


class ExportForm(FlaskForm):
    since = IntegerField('Since (timestamp)', validators=[Optional()])
    until = IntegerField('Until (timestamp)', validators=[Optional()])
    reverse = SelectField('Order', choices=[('false', 'Ascending (oldest first)'), ('reverse', 'Descending (newest first)')])
    fried = SelectField('Fried Export', choices=[('false', 'No'), ('true', 'Yes (faster re-import)')])


class ImportForm(FlaskForm):
    file = TextAreaField('JSONL Data', validators=[DataRequired()])
    no_verify = SelectField('Skip Verification', choices=[('false', 'Verify signatures'), ('true', 'No verification (faster)')])


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


@app.template_filter('render_images')
def render_images_filter(content):
    """Convert image URLs in content to img tags."""
    if not content:
        return ''
    import re
    image_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.bmp')
    url_pattern = r'https?://[^\s<>"\']+'
    def replace_url(match):
        url = match.group(0)
        if any(url.lower().endswith(ext) for ext in image_extensions):
            return f'<a href="{url}" target="_blank"><img src="{url}" class="event-image" loading="lazy" alt="Image"></a>'
        return url
    return re.sub(url_pattern, replace_url, content)


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


def get_client_ip():
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr


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


@app.route('/')
@viewer_or_higher
def index():
    try:
        metrics = get_summary()
    except MetricsError as e:
        metrics = {'error': str(e)}
    
    config = get_config()
    relay_name = config.get('info', {}).get('name', '') if config else ''
    
    return render_template('index.html', metrics=metrics, relay_name=relay_name)


@app.route('/api/metrics')
@viewer_or_higher
def api_metrics():
    try:
        metrics = get_summary()
        return jsonify(metrics)
    except MetricsError as e:
        return jsonify({'error': str(e)}), 500


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
    sort_order = request.args.get('sort', 'desc')
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 25))
    
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
    sort_column = ModerationReport.created_at.desc() if sort_order == 'desc' else ModerationReport.created_at.asc()
    reports = query.order_by(sort_column).offset(offset).limit(limit).all()
    has_more = (offset + len(reports)) < total_count
    
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
        'total_count': total_count
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


@app.route('/logout')
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
    form = EventSearchForm()
    events_list = []
    error = None
    current_filter = {}
    
    if request.method == 'GET':
        search_type = request.args.get('search_type', 'all')
        form.search_type.data = search_type
        
        if search_type == 'pubkey' and request.args.get('pubkey'):
            form.pubkey.data = request.args.get('pubkey')
            try:
                current_filter = {'authors': [form.pubkey.data]}
                events_list = scan_events(current_filter, limit=form.limit.data or 25)
            except (ValueError, StrfryError) as e:
                error = str(e)
        elif search_type == 'event_id' and request.args.get('event_id'):
            form.event_id.data = request.args.get('event_id')
            try:
                current_filter = {'ids': [form.event_id.data]}
                events_list = scan_events(current_filter, limit=form.limit.data or 25)
            except (ValueError, StrfryError) as e:
                error = str(e)
    elif request.method == 'POST':
        if 'delete_selected' in request.form:
            event_ids = request.form.getlist('event_ids')
            if event_ids:
                try:
                    id_filter = {'ids': event_ids}
                    delete_events(id_filter)
                    flash(f'Deleted {len(event_ids)} event(s) successfully', 'success')
                    log_audit('event_delete', f'Deleted {len(event_ids)} events via UI')
                except (ValueError, StrfryError) as e:
                    flash(f'Failed to delete events: {e}', 'danger')
            params = {'search_type': request.form.get('search_type', 'all')}
            if request.form.get('pubkey'):
                params['pubkey'] = request.form.get('pubkey')
            if request.form.get('kind'):
                params['kind'] = request.form.get('kind')
            if request.form.get('event_id'):
                params['event_id'] = request.form.get('event_id')
            if request.form.get('since'):
                params['since'] = request.form.get('since')
            if request.form.get('until'):
                params['until'] = request.form.get('until')
            if request.form.get('keyword'):
                params['keyword'] = request.form.get('keyword')
            if request.form.get('nip05'):
                params['nip05'] = request.form.get('nip05')
            if request.form.get('tag_name'):
                params['tag_name'] = request.form.get('tag_name')
            if request.form.get('tag_value'):
                params['tag_value'] = request.form.get('tag_value')
            if request.form.get('filter_json'):
                params['filter_json'] = request.form.get('filter_json')
            params['limit'] = request.form.get('limit', 25)
            return redirect(url_for('events', **params))
        
        if 'search' in request.form and form.validate():
            try:
                if form.search_type.data == 'nip05' and form.nip05.data:
                    pubkey = resolve_nip05(form.nip05.data)
                    if not pubkey:
                        error = "Could not resolve NIP-05 address. Check the format (user@domain.com) and try again."
                    else:
                        current_filter = {'authors': [pubkey]}
                else:
                    current_filter = build_filter_from_form(form)
                
                if form.search_type.data == 'keyword' and form.keyword.data:
                    keyword = form.keyword.data.lower()
                    filter_obj = {k: v for k, v in current_filter.items() if k != 'limit'}
                    filter_obj['limit'] = 1000
                    all_events = scan_events(filter_obj, limit=1000)
                    events_list = [e for e in all_events if keyword in e.get('content', '').lower()]
                    events_list = events_list[:form.limit.data or 25]
                else:
                    events_list = scan_events(current_filter, limit=form.limit.data or 25)
            except (ValueError, StrfryError) as e:
                error = str(e)
    
    banned_pubkeys = [b.pubkey for b in BannedPubkey.query.all()]
    
    return render_template('events.html', form=form, events=events_list, error=error, current_filter=current_filter, banned_pubkeys=banned_pubkeys)


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


def resolve_nip05(nip05_address):
    """Resolve a NIP-05 address to a pubkey."""
    try:
        import requests
        local_part, _, domain = nip05_address.strip().partition('@')
        if not local_part or not domain:
            return None
        
        url = f"https://{domain}/.well-known/nostr.json?name={local_part}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        pubkey = data.get('names', {}).get(local_part)
        return pubkey
    except Exception:
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
        if since_ts:
            filter_obj['since'] = since_ts
        if until_ts:
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
            return {'error': 'Kind must be a valid number'}
    elif search_type == 'timerange':
        since_ts = parse_timestamp(form.since.data) if form.since.data else None
        until_ts = parse_timestamp(form.until.data) if form.until.data else None
        if since_ts:
            filter_obj['since'] = since_ts
        if until_ts:
            filter_obj['until'] = until_ts
    elif search_type == 'tag' and form.tag_name.data and form.tag_value.data:
        tag_name = form.tag_name.data.strip()
        if tag_name:
            filter_obj['#' + tag_name[0]] = [form.tag_value.data.strip()]
    elif search_type == 'advanced' and form.filter_json.data:
        return validate_filter_json(form.filter_json.data)
    
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
                if export_form.since.data:
                    kwargs['since'] = export_form.since.data
                if export_form.until.data:
                    kwargs['until'] = export_form.until.data
                if export_form.reverse.data == 'reverse':
                    kwargs['reverse'] = True
                if export_form.fried.data == 'true':
                    kwargs['fried'] = True
                
                export_data = export_events(**kwargs)
                export_success = f'Exported events (size: {len(export_data) if export_data else 0} bytes)'
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
    
    return render_template(
        'import_export.html',
        export_form=export_form,
        import_form=import_form,
        export_error=export_error,
        export_success=export_success,
        import_error=import_error,
        import_success=import_success,
        export_data=export_data
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
            try:
                result = negentropy_build(tree_id)
                flash(f'Built tree {tree_id}')
                log_audit('negentropy_build', f'Built tree: {tree_id}')
            except StrfryError as e:
                flash(str(e), 'danger')
            return redirect(url_for('db_management'))
        
        elif 'negentropy_delete' in request.form:
            tree_id = request.form.get('tree_id')
            try:
                result = negentropy_delete(tree_id)
                flash(f'Deleted tree {tree_id}')
                log_audit('negentropy_delete', f'Deleted tree: {tree_id}')
            except StrfryError as e:
                flash(str(e), 'danger')
            return redirect(url_for('db_management'))
        
        elif 'compact' in request.form:
            try:
                result = compact_database()
                flash('Database compaction initiated. Check strfry logs for progress.', 'info')
                log_audit('compact', 'Database compaction initiated')
            except StrfryError as e:
                flash(str(e), 'danger')
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
    
    return render_template(
        'db.html',
        trees=trees,
        negentropy_add_form=negentropy_add_form,
        negentropy_error=negentropy_error,
        negentropy_success=negentropy_success,
        dict_output=dict_output,
        dict_error=dict_error
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
    error = None
    success = None

    current_config = get_config()
    write_policy = current_config.get('relay', {}).get('writePolicy', {}) if current_config else {}

    plugin_installed = os.path.exists(BLOCKLIST_PLUGIN_PATH) and os.access(BLOCKLIST_PLUGIN_PATH, os.X_OK)
    blocklist_count = 0
    if os.path.exists(BANNED_PUBKEYS_FILE):
        try:
            with open(BANNED_PUBKEYS_FILE) as f:
                blocklist_count = len(json.load(f))
        except (json.JSONDecodeError, OSError):
            pass

    if request.method == 'POST':
        if form.validate():
            updates = {}
            if form.plugin_path.data:
                updates['relay.writePolicy.plugin'] = form.plugin_path.data
            if form.timeout.data is not None:
                updates['relay.writePolicy.timeoutSeconds'] = str(form.timeout.data)
            if form.lookback.data is not None:
                updates['relay.writePolicy.lookbackSeconds'] = str(form.lookback.data)

            if updates:
                try:
                    update_config(updates)
                    sync_blocklist()
                    success = 'Plugin configuration updated. Restart strfry to apply changes.'
                    log_audit('plugin_update', f'Updated plugin config: {updates}')
                    current_config = get_config()
                    write_policy = current_config.get('relay', {}).get('writePolicy', {}) if current_config else {}
                except Exception as e:
                    error = str(e)

    if write_policy:
        form.plugin_path.data = write_policy.get('plugin', '')
        form.timeout.data = write_policy.get('timeoutSeconds', 10)
        form.lookback.data = write_policy.get('lookbackSeconds', 0)
    else:
        form.plugin_path.data = BLOCKLIST_PLUGIN_PATH if plugin_installed else ''
        form.timeout.data = 10
        form.lookback.data = 0

    return render_template('plugins.html', form=form, error=error, success=success,
                           plugin_installed=plugin_installed, blocklist_count=blocklist_count,
                           plugin_path=BLOCKLIST_PLUGIN_PATH)


@app.route('/connections')
@viewer_or_higher
def connections():
    try:
        metrics = get_summary()
    except MetricsError as e:
        metrics = {'error': str(e)}
    
    return render_template('connections.html', metrics=metrics)


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
    
    edit_forms = {}
    for user in users:
        edit_forms[user.id] = UserEditForm(
            username=user.username,
            role=user.role,
            is_active='true' if user.is_active else 'false'
        )
    
    create_user_form = AdminCreateUserForm()
    change_password_form = ChangePasswordForm()
    
    return render_template('admin.html', users=users, audit_logs=audit_logs, edit_forms=edit_forms, create_user_form=create_user_form, change_password_form=change_password_form, banned_pubkeys=banned_pubkeys, audit_offset=audit_offset, audit_limit=audit_limit, audit_has_more=audit_has_more, audit_total=total_logs)


def sync_moderation_reports():
    """Fetch reports from strfry and sync to database."""
    try:
        reports = scan_events({'kinds': [1984], 'limit': 200}, limit=200)
        
        for report in reports:
            event_id = report.get('id')
            existing = ModerationReport.query.filter_by(event_id=event_id).first()
            
            if existing:
                continue
            
            tags = report.get('tags', [])
            report_type = None
            reported_pubkey = None
            reported_event_id = None
            
            for tag in tags:
                if tag[0] == 'p' and len(tag) >= 3:
                    reported_pubkey = tag[1]
                    report_type = tag[2] if len(tag) > 2 else 'other'
                elif tag[0] == 'e' and len(tag) >= 3:
                    reported_event_id = tag[1]
            
            if reported_pubkey:
                existing = scan_events({'authors': [reported_pubkey], 'limit': 1}, limit=1)
                if not existing:
                    continue
            
            if reported_event_id:
                existing = scan_events({'ids': [reported_event_id], 'limit': 1}, limit=1)
                if not existing:
                    continue
            
            new_report = ModerationReport(
                event_id=event_id,
                reporter_pubkey=report.get('pubkey'),
                reported_pubkey=reported_pubkey,
                reported_event_id=reported_event_id,
                report_type=report_type,
                content=report.get('content', ''),
                created_at=datetime.fromtimestamp(report.get('created_at', 0))
            )
            db.session.add(new_report)
        
        db.session.commit()
    except Exception as e:
        pass


@app.route('/moderation', methods=['GET', 'POST'])
@moderator_required
def moderation():
    sync_moderation_reports()
    
    report_type_filter = request.args.get('report_type', '')
    reporter_filter = request.args.get('reporter', '')
    reported_filter = request.args.get('reported', '')
    event_id_filter = request.args.get('event_id', '')
    show_reviewed = request.args.get('show_reviewed', 'false') == 'true'
    sort_order = request.args.get('sort', 'desc')
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 25))
    
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
    
    from flask_wtf import FlaskForm
    class EmptyForm(FlaskForm):
        pass
    form = EmptyForm()
    
    sort_column = ModerationReport.created_at.desc() if sort_order == 'desc' else ModerationReport.created_at.asc()
    reports = query.order_by(sort_column).offset(offset).limit(limit).all()
    total_count = query.count()
    has_more = (offset + len(reports)) < total_count
    
    return render_template('moderation.html', reports=reports, 
                           report_type_filter=report_type_filter,
                           reporter_filter=reporter_filter,
                           reported_filter=reported_filter,
                           show_reviewed=show_reviewed,
                           sort_order=sort_order,
                           offset=offset,
                           limit=limit,
                           has_more=has_more,
                           total_count=total_count,
                           form=form)


@app.route('/moderation/report/<int:report_id>/review', methods=['POST'])
@moderator_required
def moderation_review(report_id):
    report = ModerationReport.query.get_or_404(report_id)
    report.reviewed = True
    report.reviewed_by = current_user.id
    report.reviewed_at = datetime.utcnow()
    db.session.commit()
    
    log_audit('moderation_review', f'Reviewed report {report.id} (type: {report.report_type})')
    flash('Report marked as reviewed.', 'success')
    
    return redirect(url_for('moderation'))


@app.route('/moderation/report/<int:report_id>/ban', methods=['POST'])
@moderator_required
def moderation_ban(report_id):
    report = ModerationReport.query.get_or_404(report_id)
    reason = request.form.get('reason', f'Report type: {report.report_type}')
    
    try:
        if report.reported_pubkey:
            delete_events({'authors': [report.reported_pubkey]})
        
        existing_ban = BannedPubkey.query.filter_by(pubkey=report.reported_pubkey).first()
        if not existing_ban:
            ban = BannedPubkey(
                pubkey=report.reported_pubkey,
                reason=reason,
                banned_by=current_user.id
            )
            db.session.add(ban)
        
        report.banned = True
        report.banned_by = current_user.id
        report.banned_at = datetime.utcnow()
        report.reviewed = True
        report.reviewed_by = current_user.id
        report.reviewed_at = datetime.utcnow()
        
        log_audit('pubkey_banned', f'Banned pubkey {report.reported_pubkey} - {reason}')
        flash('User banned and all events deleted.', 'success')
    except (ValueError, StrfryError) as e:
        flash(f'Failed to ban user: {e}', 'danger')
    
    db.session.commit()
    sync_blocklist()
    return redirect(url_for('moderation'))


@app.route('/moderation/report/<int:report_id>/delete', methods=['POST'])
@moderator_required
def moderation_delete_report(report_id):
    report = ModerationReport.query.get_or_404(report_id)
    db.session.delete(report)
    db.session.commit()
    
    log_audit('moderation_report_deleted', f'Deleted report {report_id}')
    flash('Report deleted.', 'success')
    
    return redirect(url_for('moderation'))


@app.route('/moderation/report/<int:report_id>/delete-event', methods=['POST'])
@moderator_required
def moderation_delete_event(report_id):
    report = ModerationReport.query.get_or_404(report_id)
    
    if not report.reported_event_id:
        flash('No event ID associated with this report.', 'danger')
        return redirect(url_for('moderation'))
    
    try:
        delete_events({'ids': [report.reported_event_id]})
        log_audit('moderation_event_deleted', f'Deleted event {report.reported_event_id} from report {report_id}')
        flash('Event deleted.', 'success')
    except (ValueError, StrfryError) as e:
        flash(f'Failed to delete event: {e}', 'danger')
        return redirect(url_for('moderation'))
    
    report.reviewed = True
    report.reviewed_by = current_user.id
    report.reviewed_at = datetime.utcnow()
    db.session.commit()
    
    return redirect(url_for('moderation'))


@app.route('/moderation/ban-by-pubkey', methods=['POST'])
@moderator_required
def ban_by_pubkey():
    pubkey = request.form.get('pubkey')
    reason = request.form.get('reason', 'Banned via events page')
    
    if not pubkey:
        return 'No pubkey provided', 400
    
    try:
        delete_events({'authors': [pubkey]})
        
        existing_ban = BannedPubkey.query.filter_by(pubkey=pubkey).first()
        if not existing_ban:
            ban = BannedPubkey(pubkey=pubkey, reason=reason, banned_by=current_user.id)
            db.session.add(ban)
        
        log_audit('pubkey_banned', f'Banned pubkey {pubkey} - {reason}')
        db.session.commit()
        sync_blocklist()
        return 'OK', 200
    except (ValueError, StrfryError) as e:
        return f'Failed to ban user: {e}', 500


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
    ban = BannedPubkey.query.get_or_404(ban_id)
    pubkey = ban.pubkey
    db.session.delete(ban)
    db.session.commit()
    
    log_audit('user_unbanned', f'Unbanned pubkey {pubkey}')
    db.session.commit()
    sync_blocklist()
    flash(f'Pubkey unbanned.', 'success')
    
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
        from models import ModerationReport, BannedPubkey, MetadataRelay
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
        
        if not os.path.exists(BANNED_PUBKEYS_FILE):
            with open(BANNED_PUBKEYS_FILE, 'w') as f:
                json.dump([], f)
        if os.path.exists(BLOCKLIST_PLUGIN_PATH):
            if not os.access(BLOCKLIST_PLUGIN_PATH, os.X_OK):
                os.chmod(BLOCKLIST_PLUGIN_PATH, 0o755)


init_db()


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
