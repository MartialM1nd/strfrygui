import os
from dotenv import load_dotenv

load_dotenv()

APP_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY must be set in environment")
    
    REGISTRATION_TOKEN = os.getenv('REGISTRATION_TOKEN')
    
    STRFRY_BINARY = os.getenv('STRFRY_BINARY', '/usr/local/bin/strfry')
    STRFRY_CONFIG = os.getenv('STRFRY_CONFIG', '/etc/strfry.conf')
    STRFRY_DB_PATH = os.getenv('STRFRY_DB_PATH', '/var/lib/strfry')
    STRFRY_METRICS_URL = os.getenv('STRFRY_METRICS_URL', 'http://localhost:7777/metrics')
    BANNED_PUBKEYS_FILE = os.path.join(APP_DIR, 'blocklist.json')
    BLOCKLIST_PLUGIN_PATH = os.path.join(APP_DIR, 'utils', 'blocklist_plugin.py')
    MODERATION_PURGE_TIMEOUT = int(os.getenv('MODERATION_PURGE_TIMEOUT', '30'))
    
    EXTERNAL_RELAYS = os.getenv('EXTERNAL_RELAYS', 'wss://relay.damus.io\nwss://nos.lol').split('\n')
    EXTERNAL_RELAYS = [r.strip() for r in EXTERNAL_RELAYS if r.strip()]
    
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///strfrygui.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    PERMANENT_SESSION_LIFETIME = 86400
    
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
    
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = "100 per minute"
    RATELIMIT_LOGIN = "5 per minute"


class Security:
    ALLOWED_ROLES = ['admin', 'moderator', 'viewer']
    ROLE_PERMISSIONS = {
        'admin': ['read', 'write', 'delete', 'config', 'users', 'import_export', 'db_manage', 'moderation'],
        'moderator': ['read', 'write', 'delete', 'moderation'],
        'viewer': ['read']
    }
    
    @classmethod
    def has_permission(cls, role, permission):
        return permission in cls.ROLE_PERMISSIONS.get(role, [])
