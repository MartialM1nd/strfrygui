import os
from flask import Flask, render_template, redirect, url_for, flash, request, send_file, jsonify, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, Optional
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from io import StringIO, BytesIO
import tempfile

from config import Config, Security
from models import db, User, AuditLog
from utils.strfry import (
    scan_events, delete_events, export_events, import_events,
    compact_database, negentropy_list, negentropy_add, negentropy_build,
    negentropy_delete, dict_list, get_config, update_config, StrfryError,
    validate_filter_json, npub_to_hex
)
from utils.metrics import get_summary, MetricsError
from utils.auth import admin_required, moderator_required, viewer_or_higher, permission_required

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
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('moderator', 'Moderator'), ('viewer', 'Viewer')], validators=[DataRequired()])


class UserEditForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('moderator', 'Moderator'), ('viewer', 'Viewer')], validators=[DataRequired()])
    is_active = SelectField('Active', choices=[('true', 'Yes'), ('false', 'No')], validators=[DataRequired()])


class DeleteForm(FlaskForm):
    filter_json = TextAreaField('Nostr Filter (JSON)', validators=[DataRequired()])
    confirm_delete = StringField('Type DELETE to confirm', validators=[DataRequired()])


class EventSearchForm(FlaskForm):
    search_type = SelectField('Search Type', choices=[
        ('all', 'All Events'),
        ('pubkey', 'By Pubkey'),
        ('kind', 'By Kind'),
        ('timerange', 'By Time Range'),
        ('tag', 'By Tag'),
        ('advanced', 'Advanced (JSON)')
    ])
    pubkey = StringField('Pubkey', validators=[Optional()])
    kind = SelectField('Kind', choices=[
        ('', 'Select Kind...'),
        ('0', 'Metadata (kind 0)'),
        ('1', 'Text Note (kind 1)'),
        ('2', 'Recommend Relay (kind 2)'),
        ('3', 'Contacts (kind 3)'),
        ('4', 'Encrypted DM (kind 4)'),
        ('5', 'Event Deletion (kind 5)'),
        ('6', 'Repost (kind 6)'),
        ('7', 'Reaction (kind 7)'),
        ('10000', 'Mute List (kind 10000)'),
        ('10001', 'Pin List (kind 10001)'),
        ('30000', 'NIP-51 Mute List'),
        ('30001', 'NIP-51 Pin List'),
    ], validators=[Optional()])
    since = StringField('Since (Unix timestamp)', validators=[Optional()])
    until = StringField('Until (Unix timestamp)', validators=[Optional()])
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


@app.context_processor
def inject_user():
    return dict(User=User)


@app.template_filter('datetime')
def datetime_filter(ts):
    from datetime import datetime
    if not ts:
        return ''
    try:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(ts)


def log_audit(action, details=None):
    if current_user.is_authenticated:
        log = AuditLog(
            user_id=current_user.id,
            action=action,
            details=details,
            ip_address=request.remote_addr
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
    
    return render_template('index.html', metrics=metrics)


@app.route('/api/metrics')
@viewer_or_higher
def api_metrics():
    try:
        metrics = get_summary()
        return jsonify(metrics)
    except MetricsError as e:
        return jsonify({'error': str(e)}), 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash('Your account has been deactivated.', 'danger')
                return render_template('login.html', form=form)
            
            login_user(user)
            user.update_login()
            db.session.commit()
            
            log_audit('login', f'User logged in')
            
            next_page = request.args.get('next')
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    
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
        user = User(
            username=form.username.data,
            role=form.role.data
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        log_audit('register', f'User {user.username} registered as {user.role}')
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)


@app.route('/events', methods=['GET', 'POST'])
@moderator_required
def events():
    form = EventSearchForm()
    events_list = []
    error = None
    current_filter = {}
    
    if request.method == 'POST':
        if 'search' in request.form and form.validate():
            try:
                current_filter = build_filter_from_form(form)
                events_list = scan_events(current_filter, limit=form.limit.data or 25)
            except (ValueError, StrfryError) as e:
                error = str(e)
        elif 'delete_selected' in request.form:
            event_ids = request.form.getlist('event_ids')
            if event_ids:
                try:
                    id_filter = {'ids': event_ids}
                    delete_events(id_filter)
                    flash(f'Deleted {len(event_ids)} event(s) successfully', 'success')
                    log_audit('event_delete', f'Deleted {len(event_ids)} events via UI')
                    if form.validate():
                        try:
                            current_filter = build_filter_from_form(form)
                            events_list = scan_events(current_filter, limit=form.limit.data or 25)
                        except:
                            pass
                except (ValueError, StrfryError) as e:
                    error = str(e)
    
    return render_template('events.html', form=form, events=events_list, error=error, current_filter=current_filter)


def build_filter_from_form(form):
    filter_obj = {}
    
    search_type = form.search_type.data
    
    if search_type == 'all':
        pass
    elif search_type == 'pubkey' and form.pubkey.data:
        pubkey_input = form.pubkey.data.strip()
        try:
            pubkey_hex = npub_to_hex(pubkey_input)
        except ValueError:
            pubkey_hex = pubkey_input
        filter_obj['authors'] = [pubkey_hex]
    elif search_type == 'kind' and form.kind.data:
        filter_obj['kinds'] = [int(form.kind.data)]
    elif search_type == 'timerange':
        if form.since.data:
            try:
                filter_obj['since'] = int(form.since.data)
            except ValueError:
                pass
        if form.until.data:
            try:
                filter_obj['until'] = int(form.until.data)
            except ValueError:
                pass
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
    try:
        trees = negentropy_list()
    except StrfryError as e:
        negentropy_error = str(e)
    
    negentropy_add_form = EventSearchForm()
    negentropy_add_form.limit.data = 0
    
    if request.method == 'POST':
        if 'negentropy_add' in request.form:
            try:
                filter_obj = validate_filter_json(negentropy_add_form.filter_json.data)
                result = negentropy_add(filter_obj)
                negentropy_success = f'Created negentropy tree: {result}'
                log_audit('negentropy_add', f'Added tree: {filter_obj}')
                trees = negentropy_list()
            except (ValueError, StrfryError) as e:
                negentropy_error = str(e)
        
        elif 'negentropy_build' in request.form:
            tree_id = request.form.get('tree_id')
            try:
                result = negentropy_build(tree_id)
                negentropy_success = f'Built tree {tree_id}'
                log_audit('negentropy_build', f'Built tree: {tree_id}')
                trees = negentropy_list()
            except StrfryError as e:
                negentropy_error = str(e)
        
        elif 'negentropy_delete' in request.form:
            tree_id = request.form.get('tree_id')
            try:
                result = negentropy_delete(tree_id)
                negentropy_success = f'Deleted tree {tree_id}'
                log_audit('negentropy_delete', f'Deleted tree: {tree_id}')
                trees = negentropy_list()
            except StrfryError as e:
                negentropy_error = str(e)
        
        elif 'compact' in request.form:
            try:
                result = compact_database()
                flash('Database compaction initiated. Check strfry logs for progress.', 'info')
                log_audit('compact', 'Database compaction initiated')
            except StrfryError as e:
                dict_error = str(e)
    
    dict_output = None
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
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    
    edit_forms = {}
    for user in users:
        edit_forms[user.id] = UserEditForm(
            username=user.username,
            role=user.role,
            is_active='true' if user.is_active else 'false'
        )
    
    return render_template('admin.html', users=users, audit_logs=audit_logs, edit_forms=edit_forms)


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


@app.route('/admin/user', methods=['POST'])
@admin_required
def create_user():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            role=form.role.data
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        log_audit('user_create', f'Created user {user.username} as {user.role}')
        flash(f'User {user.username} created.', 'success')
    else:
        flash('Failed to create user.', 'danger')
    
    return redirect(url_for('admin'))


@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error='404 - Page Not Found'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error='500 - Internal Server Error'), 500


_db_initialized = False

def init_db():
    global _db_initialized
    if not _db_initialized:
        with app.app_context():
            db.create_all()
            _db_initialized = True
            if User.query.count() == 0:
                print("No users found. Please register at /register")


init_db()


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
