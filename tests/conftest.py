import os
import sys
from pathlib import Path

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("SECRET_KEY", "test-secret")

from config import Config
from models import db


@pytest.fixture
def app(tmp_path):
    app = Flask(__name__)
    blocklist_path = tmp_path / "blocklist.json"
    trust_policy_path = tmp_path / "trust_policy.json"
    trust_stats_path = tmp_path / "trust_policy_stats.json"
    decision_log_path = tmp_path / "runtime" / "write_policy_events.jsonl"
    plugin_path = tmp_path / "blocklist_plugin.py"
    plugin_path.write_text("#!/bin/sh\nexit 0\n")
    plugin_path.chmod(0o755)
    app.config.update(
        SQLALCHEMY_DATABASE_URI="sqlite://",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        BANNED_PUBKEYS_FILE=str(blocklist_path),
        TRUST_POLICY_FILE=str(trust_policy_path),
        TRUST_POLICY_STATS_FILE=str(trust_stats_path),
        WRITE_POLICY_EVENT_LOG=str(decision_log_path),
        BLOCKLIST_PLUGIN_PATH=str(plugin_path),
        MODERATION_PURGE_TIMEOUT=1,
    )
    db.init_app(app)

    old_binary = Config.STRFRY_BINARY
    old_config = Config.STRFRY_CONFIG
    old_blocklist = Config.BANNED_PUBKEYS_FILE
    old_plugin = Config.BLOCKLIST_PLUGIN_PATH
    old_trust_policy = Config.TRUST_POLICY_FILE
    old_trust_stats = Config.TRUST_POLICY_STATS_FILE
    old_decision_log = Config.WRITE_POLICY_EVENT_LOG
    old_timeout = Config.MODERATION_PURGE_TIMEOUT
    old_scan_limit = Config.DOMAIN_SCAN_EVENT_LIMIT
    old_scan_timeout = Config.DOMAIN_SCAN_TIMEOUT
    old_candidate_limit = Config.DOMAIN_SCAN_CANDIDATE_LIMIT
    old_total_timeout = Config.DOMAIN_SCAN_TOTAL_TIMEOUT
    old_max_names = Config.NIP05_MAX_NAMES
    old_max_relays = Config.NIP05_MAX_RELAYS
    Config.STRFRY_BINARY = "/bin/true"
    Config.STRFRY_CONFIG = ""
    Config.BANNED_PUBKEYS_FILE = str(blocklist_path)
    Config.BLOCKLIST_PLUGIN_PATH = str(plugin_path)
    Config.TRUST_POLICY_FILE = str(trust_policy_path)
    Config.TRUST_POLICY_STATS_FILE = str(trust_stats_path)
    Config.WRITE_POLICY_EVENT_LOG = str(decision_log_path)
    Config.MODERATION_PURGE_TIMEOUT = 1
    Config.DOMAIN_SCAN_EVENT_LIMIT = 500
    Config.DOMAIN_SCAN_TIMEOUT = 30
    Config.DOMAIN_SCAN_CANDIDATE_LIMIT = 50
    Config.DOMAIN_SCAN_TOTAL_TIMEOUT = 30
    Config.NIP05_MAX_NAMES = 1000
    Config.NIP05_MAX_RELAYS = 8

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

    Config.STRFRY_BINARY = old_binary
    Config.STRFRY_CONFIG = old_config
    Config.BANNED_PUBKEYS_FILE = old_blocklist
    Config.BLOCKLIST_PLUGIN_PATH = old_plugin
    Config.TRUST_POLICY_FILE = old_trust_policy
    Config.TRUST_POLICY_STATS_FILE = old_trust_stats
    Config.WRITE_POLICY_EVENT_LOG = old_decision_log
    Config.MODERATION_PURGE_TIMEOUT = old_timeout
    Config.DOMAIN_SCAN_EVENT_LIMIT = old_scan_limit
    Config.DOMAIN_SCAN_TIMEOUT = old_scan_timeout
    Config.DOMAIN_SCAN_CANDIDATE_LIMIT = old_candidate_limit
    Config.DOMAIN_SCAN_TOTAL_TIMEOUT = old_total_timeout
    Config.NIP05_MAX_NAMES = old_max_names
    Config.NIP05_MAX_RELAYS = old_max_relays
