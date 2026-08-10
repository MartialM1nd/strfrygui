import os

from config import Config
from utils import blocklist_plugin


def test_generated_write_policy_files_live_under_runtime_directory():
    expected = {
        os.path.join(Config.RUNTIME_DIR, 'blocklist.json'),
        os.path.join(Config.RUNTIME_DIR, 'trust_policy.json'),
        os.path.join(Config.RUNTIME_DIR, 'trust_policy_stats.json'),
        os.path.join(Config.RUNTIME_DIR, 'write_policy_events.jsonl'),
    }

    assert {
        Config.BANNED_PUBKEYS_FILE,
        Config.TRUST_POLICY_FILE,
        Config.TRUST_POLICY_STATS_FILE,
        Config.WRITE_POLICY_EVENT_LOG,
    } == expected
    assert {
        blocklist_plugin.BLOCKLIST_FILE,
        blocklist_plugin.TRUST_POLICY_FILE,
        blocklist_plugin.TRUST_POLICY_STATS_FILE,
        blocklist_plugin.DECISION_LOG_FILE,
    } == expected
