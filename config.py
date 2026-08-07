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
    DOMAIN_SCAN_EVENT_LIMIT = int(os.getenv('DOMAIN_SCAN_EVENT_LIMIT', '500'))
    DOMAIN_SCAN_TIMEOUT = int(os.getenv('DOMAIN_SCAN_TIMEOUT', '30'))
    DOMAIN_SCAN_CANDIDATE_LIMIT = int(os.getenv('DOMAIN_SCAN_CANDIDATE_LIMIT', '50'))
    DOMAIN_SCAN_TOTAL_TIMEOUT = int(os.getenv('DOMAIN_SCAN_TOTAL_TIMEOUT', '120'))
    NIP05_HTTP_TIMEOUT = float(os.getenv('NIP05_HTTP_TIMEOUT', '5'))
    NIP05_MAX_RESPONSE_BYTES = int(os.getenv('NIP05_MAX_RESPONSE_BYTES', '262144'))
    NIP05_MAX_ADDRESSES = int(os.getenv('NIP05_MAX_ADDRESSES', '4'))
    NIP05_MAX_NAMES = int(os.getenv('NIP05_MAX_NAMES', '1000'))
    NIP05_MAX_RELAYS = int(os.getenv('NIP05_MAX_RELAYS', '8'))
    NIP05_PROFILE_TIMEOUT = float(os.getenv('NIP05_PROFILE_TIMEOUT', '10'))
    NIP05_RELAY_TIMEOUT = float(os.getenv('NIP05_RELAY_TIMEOUT', '3'))
    NIP05_MAX_WS_MESSAGE_BYTES = int(os.getenv('NIP05_MAX_WS_MESSAGE_BYTES', '262144'))
    
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
