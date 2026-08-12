import os
from urllib.parse import urlsplit
from dotenv import load_dotenv

load_dotenv()

APP_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY must be set in environment")
    
    REGISTRATION_TOKEN = os.getenv('REGISTRATION_TOKEN')
    PUBLIC_BASE_URL = os.getenv('PUBLIC_BASE_URL', 'https://localhost').rstrip('/')
    _PUBLIC_URL = urlsplit(PUBLIC_BASE_URL)
    try:
        _PUBLIC_PORT = _PUBLIC_URL.port
    except ValueError as exc:
        raise ValueError('PUBLIC_BASE_URL contains an invalid port') from exc
    if (
        _PUBLIC_URL.scheme != 'https'
        or not _PUBLIC_URL.hostname
        or _PUBLIC_URL.username is not None
        or _PUBLIC_URL.password is not None
        or _PUBLIC_URL.path
        or _PUBLIC_URL.query
        or _PUBLIC_URL.fragment
    ):
        raise ValueError('PUBLIC_BASE_URL must be an HTTPS origin without a path, query, or fragment')
    _PUBLIC_HOST = _PUBLIC_URL.hostname.lower()
    if ':' in _PUBLIC_HOST:
        _PUBLIC_HOST = f'[{_PUBLIC_HOST}]'
    PUBLIC_BASE_URL = f'https://{_PUBLIC_HOST}'
    if _PUBLIC_PORT not in (None, 443):
        PUBLIC_BASE_URL += f':{_PUBLIC_PORT}'
    NOSTR_AUTH_CHALLENGE_TTL = max(10, int(os.getenv('NOSTR_AUTH_CHALLENGE_TTL', '60')))
    NOSTR_AUTH_TIMESTAMP_TOLERANCE = max(10, int(os.getenv('NOSTR_AUTH_TIMESTAMP_TOLERANCE', '60')))
    
    STRFRY_BINARY = os.getenv('STRFRY_BINARY', '/usr/local/bin/strfry')
    STRFRY_CONFIG = os.getenv('STRFRY_CONFIG', '/etc/strfry.conf')
    STRFRY_DB_PATH = os.getenv('STRFRY_DB_PATH', '/var/lib/strfry')
    STRFRY_METRICS_URL = os.getenv('STRFRY_METRICS_URL', 'http://localhost:7777/metrics')
    RUNTIME_DIR = os.path.join(APP_DIR, 'runtime')
    LEGACY_TRUST_POLICY_FILE = os.path.join(APP_DIR, 'trust_policy.json')
    BANNED_PUBKEYS_FILE = os.path.join(RUNTIME_DIR, 'blocklist.json')
    TRUST_POLICY_FILE = os.path.join(RUNTIME_DIR, 'trust_policy.json')
    TRUST_POLICY_STATS_FILE = os.path.join(RUNTIME_DIR, 'trust_policy_stats.json')
    WRITE_POLICY_EVENT_LOG = os.path.join(RUNTIME_DIR, 'write_policy_events.jsonl')
    BLOCKLIST_PLUGIN_PATH = os.path.join(APP_DIR, 'utils', 'blocklist_plugin.py')
    DASHBOARD_SAMPLE_INTERVAL = max(60, int(os.getenv('DASHBOARD_SAMPLE_INTERVAL', '60')))
    MODERATION_PURGE_TIMEOUT = int(os.getenv('MODERATION_PURGE_TIMEOUT', '30'))
    MODERATION_REPORT_SYNC_TIMEOUT = max(1, int(os.getenv('MODERATION_REPORT_SYNC_TIMEOUT', '30')))
    MODERATION_REPORT_VALIDATION_LIMIT = max(1, int(os.getenv('MODERATION_REPORT_VALIDATION_LIMIT', '20')))
    MODERATION_REPORT_REJECTION_TTL = max(0, int(os.getenv('MODERATION_REPORT_REJECTION_TTL', '3600')))
    MODERATION_REPORT_REJECTION_CACHE_SIZE = max(1, int(os.getenv('MODERATION_REPORT_REJECTION_CACHE_SIZE', '2000')))
    MODERATION_REPORT_PENDING_LIMIT = max(200, int(os.getenv('MODERATION_REPORT_PENDING_LIMIT', '1000')))
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
    IMPORT_MAX_BYTES = max(1, int(os.getenv('IMPORT_MAX_BYTES', str(5 * 1024 * 1024))))
    IMPORT_MAX_EVENTS = max(1, int(os.getenv('IMPORT_MAX_EVENTS', '10000')))
    EXPORT_MAX_BYTES = max(1, int(os.getenv('EXPORT_MAX_BYTES', str(5 * 1024 * 1024))))
    DATABASE_MAINTENANCE_LOCK = os.path.join(RUNTIME_DIR, 'database-maintenance.lock')
    
    EXTERNAL_RELAYS = os.getenv('EXTERNAL_RELAYS', 'wss://relay.damus.io\nwss://nos.lol').split('\n')
    EXTERNAL_RELAYS = [r.strip() for r in EXTERNAL_RELAYS if r.strip()]
    
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///strfrygui.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    TRUSTED_PROXY_COUNT = max(0, int(os.getenv('TRUSTED_PROXY_COUNT', '0')))
    
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
