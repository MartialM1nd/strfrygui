import os
import stat
from urllib.parse import urlsplit

from dotenv import load_dotenv

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DOTENV_PATH = os.path.join(APP_DIR, '.env')


def _open_validated_dotenv(path):
    """Open a dotenv file once, rejecting unsafe ownership and permissions."""
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError('.env must be a regular file, not a symlink') from exc
    try:
        file_stat = os.fstat(descriptor)
        mode = stat.S_IMODE(file_stat.st_mode)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError('.env must be a regular file, not a symlink')
        if file_stat.st_uid not in {0, os.geteuid()}:
            raise ValueError('.env must be owned by root or the service user')
        if mode & 0o027:
            raise ValueError('.env must not be group-writable or accessible by other users')
        trusted_groups = {os.getegid(), *os.getgroups()}
        if mode & 0o040 and file_stat.st_gid not in trusted_groups:
            raise ValueError('.env group access must be limited to the service group')
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _validate_dotenv(path):
    descriptor = _open_validated_dotenv(path)
    if descriptor is not None:
        os.close(descriptor)


def _validate_secret(name, value, required=True):
    if not value:
        if required:
            raise ValueError(f'{name} must be set in environment')
        return None
    if len(value) < 32:
        raise ValueError(f'{name} must contain at least 32 characters')
    return value


def bundled_plugin_available(path):
    """Return whether path is the deployment-controlled bundled executable."""
    try:
        plugin_stat = os.lstat(path)
        source_owner = os.stat(APP_DIR).st_uid
    except OSError:
        return False
    return (
        os.path.isabs(path)
        and stat.S_ISREG(plugin_stat.st_mode)
        and plugin_stat.st_uid in {0, source_owner}
        and os.access(path, os.X_OK)
        and plugin_stat.st_mode & 0o022 == 0
    )


_dotenv_descriptor = _open_validated_dotenv(DOTENV_PATH)
if _dotenv_descriptor is not None:
    with os.fdopen(_dotenv_descriptor, encoding='utf-8') as _dotenv_file:
        load_dotenv(stream=_dotenv_file)


class Config:
    SECRET_KEY = _validate_secret('SECRET_KEY', os.getenv('SECRET_KEY'))
    REGISTRATION_TOKEN = _validate_secret(
        'REGISTRATION_TOKEN', os.getenv('REGISTRATION_TOKEN'), required=False
    )
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
    MODERATION_PURGE_BATCH_SIZE = max(1, int(os.getenv('MODERATION_PURGE_BATCH_SIZE', '5')))
    MODERATION_PURGE_RETRY_SECONDS = max(1, int(os.getenv('MODERATION_PURGE_RETRY_SECONDS', '300')))
    MODERATION_PURGE_RETRY_MAX_SECONDS = max(
        MODERATION_PURGE_RETRY_SECONDS,
        int(os.getenv('MODERATION_PURGE_RETRY_MAX_SECONDS', '3600')),
    )
    MODERATION_PURGE_WORKER_INTERVAL = max(1, int(os.getenv('MODERATION_PURGE_WORKER_INTERVAL', '30')))
    MODERATION_REPORT_SYNC_TIMEOUT = max(1, int(os.getenv('MODERATION_REPORT_SYNC_TIMEOUT', '30')))
    MODERATION_REPORT_VALIDATION_LIMIT = max(1, int(os.getenv('MODERATION_REPORT_VALIDATION_LIMIT', '20')))
    MODERATION_REPORT_REJECTION_TTL = max(0, int(os.getenv('MODERATION_REPORT_REJECTION_TTL', '3600')))
    MODERATION_REPORT_REJECTION_CACHE_SIZE = max(1, int(os.getenv('MODERATION_REPORT_REJECTION_CACHE_SIZE', '2000')))
    MODERATION_REPORT_PENDING_LIMIT = max(200, int(os.getenv('MODERATION_REPORT_PENDING_LIMIT', '1000')))
    DOMAIN_SCAN_TIMEOUT = int(os.getenv('DOMAIN_SCAN_TIMEOUT', '30'))
    DOMAIN_SCAN_CANDIDATE_LIMIT = int(os.getenv('DOMAIN_SCAN_CANDIDATE_LIMIT', '50'))
    DOMAIN_SCAN_ALIASES_PER_PUBKEY = max(
        1, int(os.getenv('DOMAIN_SCAN_ALIASES_PER_PUBKEY', '3'))
    )
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
