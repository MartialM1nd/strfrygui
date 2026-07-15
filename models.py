from datetime import UTC, datetime

import bcrypt
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


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
            'username': self.user.username if self.user else 'system',
            'action': self.action,
            'details': self.details,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


class ModerationReport(db.Model):
    __tablename__ = 'moderation_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(64), unique=True)
    reporter_pubkey = db.Column(db.String(64))
    reported_pubkey = db.Column(db.String(64))
    reported_event_id = db.Column(db.String(64))
    report_type = db.Column(db.String(20))
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=utcnow)
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
