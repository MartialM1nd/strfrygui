#!/usr/bin/env python3
"""strfry write-policy plugin: blocks banned pubkeys.

Install in strfry.conf:
    relay {
        writePolicy {
            plugin = "/path/to/utils/blocklist_plugin.py"
            timeoutSeconds = 10
        }
    }

Make executable: chmod 755 utils/blocklist_plugin.py
Restart strfry once, then bans update in real-time via mtime detection.
"""
import sys
import json
import os

BLOCKLIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "blocklist.json")
BLOCKLIST_FILE = os.path.normpath(BLOCKLIST_FILE)


def load_blocklist():
    if not os.path.exists(BLOCKLIST_FILE):
        return set()
    try:
        with open(BLOCKLIST_FILE) as f:
            data = json.load(f)
            return set(data) if isinstance(data, list) else set()
    except (json.JSONDecodeError, OSError):
        return set()


blocklist = load_blocklist()
blocklist_mtime = os.path.getmtime(BLOCKLIST_FILE) if os.path.exists(BLOCKLIST_FILE) else 0
prev_id = None

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue

    try:
        request = json.loads(line)
    except json.JSONDecodeError:
        continue

    if request.get("type") != "new":
        continue

    event = request.get("event", {})
    event_id = event.get("id", "")
    pubkey = event.get("pubkey", "")

    current_mtime = os.path.getmtime(BLOCKLIST_FILE) if os.path.exists(BLOCKLIST_FILE) else 0
    if current_mtime != blocklist_mtime:
        blocklist = load_blocklist()
        blocklist_mtime = current_mtime

    if pubkey in blocklist:
        print(json.dumps({"id": event_id, "action": "reject", "msg": "blocked: pubkey is banned"}, separators=(",", ":")), flush=True)
    else:
        print(json.dumps({"id": event_id, "action": "accept"}, separators=(",", ":")), flush=True)
