import json
from datetime import UTC, datetime

import bcrypt
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

db = SQLAlchemy()

MODERATION_REPORT_INDEXES = (
    'CREATE INDEX IF NOT EXISTS ix_moderation_reports_reviewed_created_id '
    'ON moderation_reports (reviewed, created_at, id)',
    'CREATE INDEX IF NOT EXISTS ix_moderation_reports_report_type '
    'ON moderation_reports (report_type)',
    'CREATE INDEX IF NOT EXISTS ix_moderation_reports_reporter_pubkey '
    'ON moderation_reports (reporter_pubkey)',
    'CREATE INDEX IF NOT EXISTS ix_moderation_reports_reported_pubkey '
    'ON moderation_reports (reported_pubkey)',
    'CREATE INDEX IF NOT EXISTS ix_moderation_reports_reported_event_id '
    'ON moderation_reports (reported_event_id)',
    'CREATE INDEX IF NOT EXISTS ix_moderation_reports_created_at '
    'ON moderation_reports (created_at)',
)

AUDIT_LOG_INDEXES = (
    'CREATE INDEX IF NOT EXISTS ix_audit_log_timestamp_id '
    'ON audit_log (timestamp, id)',
    'CREATE INDEX IF NOT EXISTS ix_audit_log_action_timestamp_id '
    'ON audit_log (action, timestamp, id)',
    'CREATE INDEX IF NOT EXISTS ix_audit_log_user_timestamp_id '
    'ON audit_log (user_id, timestamp, id)',
)


def ensure_moderation_report_indexes(connection):
    """Create moderation report indexes for databases predating the models."""
    for statement in MODERATION_REPORT_INDEXES:
        connection.execute(text(statement))


def ensure_audit_log_indexes(connection):
    """Create audit indexes for databases predating the focused admin pages."""
    for statement in AUDIT_LOG_INDEXES:
        connection.execute(text(statement))


def utcnow():
    return datetime.now(UTC).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime)
    must_change_password = db.Column(db.Boolean, default=True)
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def update_login(self):
        self.last_login = utcnow()
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    __table_args__ = (
        db.Index('ix_audit_log_timestamp_id', 'timestamp', 'id'),
        db.Index('ix_audit_log_action_timestamp_id', 'action', 'timestamp', 'id'),
        db.Index('ix_audit_log_user_timestamp_id', 'user_id', 'timestamp', 'id'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)
    
    user = db.relationship('User', backref='audit_logs')
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else 'system',
            'action': self.action,
            'details': self.details,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


class ModerationReport(db.Model):
    __tablename__ = 'moderation_reports'
    __table_args__ = (
        db.Index(
            'ix_moderation_reports_reviewed_created_id',
            'reviewed',
            'created_at',
            'id',
        ),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(64), unique=True)
    reporter_pubkey = db.Column(db.String(64), index=True)
    reported_pubkey = db.Column(db.String(64), index=True)
    reported_event_id = db.Column(db.String(64), index=True)
    report_type = db.Column(db.String(20), index=True)
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    reviewed = db.Column(db.Boolean, default=False)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    reviewed_at = db.Column(db.DateTime)
    banned = db.Column(db.Boolean, default=False)
    banned_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    banned_at = db.Column(db.DateTime)
    
    reviewer = db.relationship('User', foreign_keys=[reviewed_by], backref='reviews')
    banner = db.relationship('User', foreign_keys=[banned_by], backref='bans')


class BannedPubkey(db.Model):
    __tablename__ = 'banned_pubkeys'
    
    id = db.Column(db.Integer, primary_key=True)
    pubkey = db.Column(db.String(64), unique=True, nullable=False, index=True)
    reason = db.Column(db.Text)
    banned_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    banned_at = db.Column(db.DateTime, default=utcnow)
    
    banner = db.relationship('User', backref='banned_pubkeys')
    sources = db.relationship(
        'PubkeyBanSource',
        back_populates='banned_pubkey',
        cascade='all, delete-orphan',
    )

    @property
    def has_direct_source(self):
        return any(source.source_type == 'direct' for source in self.sources) or not self.sources

    @property
    def active_source(self):
        if not self.sources:
            return None
        return next(
            (source for source in self.sources if source.source_type == 'direct'),
            self.sources[0],
        )

    @property
    def active_reason(self):
        return self.active_source.reason if self.active_source else self.reason

    @property
    def active_banned_by(self):
        return self.active_source.banned_by if self.active_source else self.banned_by

    @property
    def active_banned_at(self):
        return self.active_source.banned_at if self.active_source else self.banned_at


class BannedDomain(db.Model):
    __tablename__ = 'banned_domains'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(253), unique=True, nullable=False, index=True)
    reason = db.Column(db.Text)
    banned_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    banned_at = db.Column(db.DateTime, default=utcnow)
    scan_status = db.Column(db.String(20), nullable=False, default='idle', index=True)
    scan_started_at = db.Column(db.DateTime)
    last_scanned_at = db.Column(db.DateTime)
    last_scan_events = db.Column(db.Integer, nullable=False, default=0)
    last_scan_candidates = db.Column(db.Integer, nullable=False, default=0)
    last_scan_verified = db.Column(db.Integer, nullable=False, default=0)
    last_scan_new_bans = db.Column(db.Integer, nullable=False, default=0)
    last_scan_cursor = db.Column(db.Integer, nullable=False, default=0)
    last_scan_error = db.Column(db.Text)
    last_scan_details = db.Column(db.Text)

    banner = db.relationship('User', backref='banned_domains')
    pubkey_sources = db.relationship(
        'PubkeyBanSource',
        back_populates='banned_domain',
    )

    @property
    def scan_details(self):
        try:
            details = json.loads(self.last_scan_details or '{}')
            return details if isinstance(details, dict) else {}
        except json.JSONDecodeError:
            return {}


class PubkeyBanSource(db.Model):
    __tablename__ = 'pubkey_ban_sources'
    __table_args__ = (
        db.CheckConstraint(
            "(source_type = 'direct' AND banned_domain_id IS NULL) OR "
            "(source_type = 'domain' AND banned_domain_id IS NOT NULL)",
            name='ck_pubkey_ban_source_shape',
        ),
        db.UniqueConstraint(
            'banned_pubkey_id',
            'banned_domain_id',
            name='uq_pubkey_ban_source_domain',
        ),
        db.Index(
            'uq_pubkey_ban_source_direct',
            'banned_pubkey_id',
            unique=True,
            sqlite_where=text("source_type = 'direct'"),
        ),
        db.Index(
            'ix_pubkey_ban_source_domain_id',
            'banned_domain_id',
            'id',
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    banned_pubkey_id = db.Column(
        db.Integer,
        db.ForeignKey('banned_pubkeys.id', ondelete='CASCADE'),
        nullable=False,
    )
    source_type = db.Column(db.String(20), nullable=False, index=True)
    banned_domain_id = db.Column(
        db.Integer,
        db.ForeignKey('banned_domains.id', ondelete='CASCADE'),
    )
    local_name = db.Column(db.String(128))
    reason = db.Column(db.Text)
    banned_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    banned_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_seen_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    banned_pubkey = db.relationship('BannedPubkey', back_populates='sources')
    banned_domain = db.relationship('BannedDomain', back_populates='pubkey_sources')
    banner = db.relationship('User')


class WritePolicyProjection(db.Model):
    __tablename__ = 'write_policy_projection'
    __table_args__ = (
        db.CheckConstraint("status IN ('pending', 'published')", name='ck_projection_status'),
    )

    id = db.Column(db.Integer, primary_key=True)
    desired_revision = db.Column(db.Integer, nullable=False, default=0)
    published_revision = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(20), nullable=False, default='published', index=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    last_error = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    published_at = db.Column(db.DateTime)


class WoTPolicy(db.Model):
    __tablename__ = 'wot_policy'
    __table_args__ = (
        db.CheckConstraint(
            "mode IN ('off', 'monitor', 'enforce')",
            name='ck_wot_policy_mode',
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    mode = db.Column(db.String(20), nullable=False, default='off')
    root_npubs = db.Column(db.Text, nullable=False, default='[]')
    trust_threshold = db.Column(db.Integer, nullable=False, default=50)
    pow_difficulty = db.Column(db.Integer, nullable=False, default=20)
    require_pow_commitment = db.Column(db.Boolean, nullable=False, default=True)
    refresh_interval_minutes = db.Column(db.Integer, nullable=False, default=30)
    rate_limit_per_minute = db.Column(db.Integer, nullable=False, default=30)
    rate_limit_burst = db.Column(db.Integer, nullable=False, default=10)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    @property
    def roots(self):
        try:
            roots = json.loads(self.root_npubs)
        except (TypeError, json.JSONDecodeError):
            return []
        return roots if isinstance(roots, list) else []


class WoTBuildState(db.Model):
    __tablename__ = 'wot_build_state'
    __table_args__ = (
        db.CheckConstraint(
            "status IN ('idle', 'queued', 'running', 'failed')",
            name='ck_wot_build_status',
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(20), nullable=False, default='idle', index=True)
    revision = db.Column(db.Integer, nullable=False, default=0)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    generated_at = db.Column(db.DateTime)
    root_count = db.Column(db.Integer, nullable=False, default=0)
    direct_count = db.Column(db.Integer, nullable=False, default=0)
    identity_count = db.Column(db.Integer, nullable=False, default=0)
    edge_count = db.Column(db.Integer, nullable=False, default=0)
    truncated = db.Column(db.Boolean, nullable=False, default=False)
    last_error = db.Column(db.Text)


class DashboardSample(db.Model):
    __tablename__ = 'dashboard_samples'

    id = db.Column(db.Integer, primary_key=True)
    sampled_at = db.Column(db.DateTime, unique=True, nullable=False, index=True)
    collected_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    metrics_available = db.Column(db.Boolean, nullable=False, default=False)
    policy_available = db.Column(db.Boolean, nullable=False, default=False)
    metrics_error = db.Column(db.Text)
    uptime_seconds = db.Column(db.Integer)
    process_count = db.Column(db.Integer)
    database_size_bytes = db.Column(db.Integer)
    disk_total_bytes = db.Column(db.Integer)
    disk_free_bytes = db.Column(db.Integer)
    counters_json = db.Column(db.Text, nullable=False, default='{}')
    gauges_json = db.Column(db.Text, nullable=False, default='{}')
    policy_counters_json = db.Column(db.Text, nullable=False, default='{}')

    @staticmethod
    def _values(raw):
        try:
            values = json.loads(raw or '{}')
        except (TypeError, json.JSONDecodeError):
            return {}
        return values if isinstance(values, dict) else {}

    @property
    def counters(self):
        return self._values(self.counters_json)

    @property
    def gauges(self):
        return self._values(self.gauges_json)

    @property
    def policy_counters(self):
        return self._values(self.policy_counters_json)


class EventPurge(db.Model):
    __tablename__ = 'event_purges'
    __table_args__ = (
        db.CheckConstraint("target_type IN ('pubkey', 'event')", name='ck_purge_target_type'),
        db.CheckConstraint("status IN ('pending', 'completed')", name='ck_purge_status'),
    )

    id = db.Column(db.Integer, primary_key=True)
    target_type = db.Column(db.String(20), nullable=False)
    target = db.Column(db.String(64), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default='pending', index=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    last_error = db.Column(db.Text)
    requested_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    report_id = db.Column(
        db.Integer,
        db.ForeignKey('moderation_reports.id', ondelete='SET NULL'),
        nullable=True,
    )
    created_at = db.Column(db.DateTime, default=utcnow)
    attempted_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)

    @property
    def was_cancelled(self):
        return self.status == 'completed' and bool(
            self.last_error and self.last_error.startswith('Cancelled:')
        )


class MetadataRelay(db.Model):
    __tablename__ = 'metadata_relays'
    
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(256), unique=True, nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    is_default = db.Column(db.Boolean, default=False)
    last_status = db.Column(db.String(20), default='unknown')
    last_tested = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'enabled': self.enabled,
            'is_default': self.is_default,
            'last_status': self.last_status,
            'last_tested': self.last_tested.isoformat() if self.last_tested else None
        }
