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
    plugin_path = tmp_path / "blocklist_plugin.py"
    plugin_path.write_text("#!/bin/sh\nexit 0\n")
    plugin_path.chmod(0o755)
    app.config.update(
        SQLALCHEMY_DATABASE_URI="sqlite://",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        BANNED_PUBKEYS_FILE=str(blocklist_path),
        BLOCKLIST_PLUGIN_PATH=str(plugin_path),
        MODERATION_PURGE_TIMEOUT=1,
    )
    db.init_app(app)

    old_binary = Config.STRFRY_BINARY
    old_config = Config.STRFRY_CONFIG
    old_blocklist = Config.BANNED_PUBKEYS_FILE
    old_plugin = Config.BLOCKLIST_PLUGIN_PATH
    old_timeout = Config.MODERATION_PURGE_TIMEOUT
    old_scan_limit = Config.DOMAIN_SCAN_EVENT_LIMIT
    old_scan_timeout = Config.DOMAIN_SCAN_TIMEOUT
    old_candidate_limit = Config.DOMAIN_SCAN_CANDIDATE_LIMIT
    old_total_timeout = Config.DOMAIN_SCAN_TOTAL_TIMEOUT
    Config.STRFRY_BINARY = "/bin/true"
    Config.STRFRY_CONFIG = ""
    Config.BANNED_PUBKEYS_FILE = str(blocklist_path)
    Config.BLOCKLIST_PLUGIN_PATH = str(plugin_path)
    Config.MODERATION_PURGE_TIMEOUT = 1
    Config.DOMAIN_SCAN_EVENT_LIMIT = 500
    Config.DOMAIN_SCAN_TIMEOUT = 30
    Config.DOMAIN_SCAN_CANDIDATE_LIMIT = 50
    Config.DOMAIN_SCAN_TOTAL_TIMEOUT = 30

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

    Config.STRFRY_BINARY = old_binary
    Config.STRFRY_CONFIG = old_config
    Config.BANNED_PUBKEYS_FILE = old_blocklist
    Config.BLOCKLIST_PLUGIN_PATH = old_plugin
    Config.MODERATION_PURGE_TIMEOUT = old_timeout
    Config.DOMAIN_SCAN_EVENT_LIMIT = old_scan_limit
    Config.DOMAIN_SCAN_TIMEOUT = old_scan_timeout
    Config.DOMAIN_SCAN_CANDIDATE_LIMIT = old_candidate_limit
    Config.DOMAIN_SCAN_TOTAL_TIMEOUT = old_total_timeout
