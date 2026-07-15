import subprocess
import json
import os
import re
import time
from config import Config


_cache = {}


def _cache_get(key, ttl=30):
    entry = _cache.get(key)
    if entry and time.time() - entry['time'] < ttl:
        return entry['value']
    return None


def _cache_set(key, value):
    _cache[key] = {'value': value, 'time': time.time()}


class StrfryError(Exception):
    pass


def npub_to_hex(npub):
    try:
        import bech32
        hrp, data = bech32.bech32_decode(npub)
        if hrp != 'npub':
            raise ValueError(f"Invalid npub prefix: {hrp}")
        if not data:
            raise ValueError("Empty npub data")
        converted = bech32.convertbits(data, 5, 8, False)
        if converted is None:
            raise ValueError("Failed to convert bits")
        return ''.join(f'{b:02x}' for b in converted)
    except Exception as e:
        raise ValueError(f"Invalid npub: {e}")


def validate_filter_json(filter_str):
    try:
        obj = json.loads(filter_str)
        if not isinstance(obj, dict):
            raise ValueError("Filter must be a JSON object")
        return obj
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")


def run_strfry_command(args, input_data=None, capture_output=True, timeout=300):
    binary = Config.STRFRY_BINARY
    
    if not os.path.exists(binary):
        raise StrfryError(f"strfry binary not found at {binary}")
    
    cmd = [binary]
    if Config.STRFRY_CONFIG:
        cmd.extend(['--config', Config.STRFRY_CONFIG])
    cmd.extend(args)
    
    try:
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=capture_output,
            text=True,
            timeout=timeout
        )
        if result.returncode != 0:
            raise StrfryError(result.stderr.strip() or f"Command failed with code {result.returncode}")
        return result.stdout.strip() if capture_output else None
    except subprocess.TimeoutExpired:
        raise StrfryError("Command timed out")
    except FileNotFoundError:
        raise StrfryError(f"strfry binary not found at {binary}")
    except OSError as e:
        raise StrfryError(f"Failed to execute strfry: {e}")


def scan_events(filter_json, limit=100):
    filter_with_limit = {**filter_json, 'limit': limit}
    filter_str = json.dumps(filter_with_limit)
    cmd = ['scan', filter_str]
    output = run_strfry_command(cmd)
    
    events = []
    if not output:
        return events
    for line in output.split('\n'):
        if line.strip():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def count_events(filter_json):
    filter_str = json.dumps(filter_json)
    cmd = ['scan', filter_str]
    output = run_strfry_command(cmd)
    
    count = 0
    if not output:
        return count
    for line in output.split('\n'):
        if line.strip():
            count += 1
    return count


def delete_events(filter_json, timeout=300):
    filter_str = json.dumps(filter_json)
    cmd = ['delete', '--filter', filter_str]
    output = run_strfry_command(cmd, timeout=timeout)
    return output


def export_events(since=None, until=None, reverse=False, fried=False):
    cmd = ['export']
    if since:
        cmd.extend(['--since', str(since)])
    if until:
        cmd.extend(['--until', str(until)])
    if reverse:
        cmd.append('--reverse')
    if fried:
        cmd.append('--fried')
    
    return run_strfry_command(cmd)


def import_events(jsonl_data, verify=True):
    validate_jsonl(jsonl_data)
    
    cmd = ['import']
    if not verify:
        cmd.append('--no-verify')
    
    return run_strfry_command(cmd, input_data=jsonl_data)


def validate_jsonl(jsonl_data):
    """Validate file contains valid JSONL before passing to strfry"""
    for line_num, line in enumerate(jsonl_data.split('\n')):
        if line.strip():
            try:
                json.loads(line)
            except json.JSONDecodeError as e:
                raise StrfryError(f"Invalid JSON at line {line_num + 1}: {e}")
    return True


def compact_database():
    cmd = ['compact', '-']
    output = run_strfry_command(cmd)
    return output


def get_strfry_uptime():
    """Return strfry process uptime in seconds, or None if not found."""
    try:
        import subprocess
        result = subprocess.run(
            ['pgrep', '-x', 'strfry'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        pid = result.stdout.strip().split()[0]

        with open(f'/proc/{pid}/stat') as f:
            stat = f.read().split()
        starttime = int(stat[21])
        clk_tck = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
        with open('/proc/uptime') as f:
            system_uptime = float(f.read().split()[0])
        uptime = system_uptime - (starttime / clk_tck)
        return max(0, int(uptime))
    except (FileNotFoundError, IndexError, ValueError, subprocess.TimeoutExpired):
        return None


def negentropy_list():
    cached = _cache_get('negentropy_list')
    if cached is not None:
        return cached

    cmd = ['negentropy', 'list']
    output = run_strfry_command(cmd, timeout=120)
    
    trees = []
    current_tree = {}
    if output:
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('tree '):
                if current_tree:
                    trees.append(current_tree)
                current_tree = {'id': line.split()[1].rstrip(':')}
            elif line.startswith('filter:'):
                current_tree['filter'] = line.split(':', 1)[1].strip()
            elif line.startswith('size:'):
                current_tree['size'] = line.split(':', 1)[1].strip()
            elif line.startswith('fingerprint:'):
                current_tree['fingerprint'] = line.split(':', 1)[1].strip()
        
        if current_tree:
            trees.append(current_tree)
    
    _cache_set('negentropy_list', trees)
    return trees


def _clear_negentropy_cache():
    _cache.pop('negentropy_list', None)


def negentropy_add(filter_json):
    filter_str = json.dumps(filter_json)
    cmd = ['negentropy', 'add', filter_str]
    output = run_strfry_command(cmd)
    _clear_negentropy_cache()
    return output


def negentropy_build(tree_id):
    cmd = ['negentropy', 'build', str(tree_id)]
    output = run_strfry_command(cmd)
    _clear_negentropy_cache()
    return output


def negentropy_delete(tree_id):
    cmd = ['negentropy', 'delete', str(tree_id)]
    output = run_strfry_command(cmd)
    _clear_negentropy_cache()
    return output


def dict_list():
    cached = _cache_get('dict_list')
    if cached is not None:
        return cached

    cmd = ['dict', 'stats']
    output = run_strfry_command(cmd, timeout=120)
    _cache_set('dict_list', output)
    return output


def dict_train(filter_json, output_file):
    filter_str = json.dumps(filter_json)
    cmd = ['dict', 'train', '--output', output_file, filter_str]
    return run_strfry_command(cmd)


def dict_compress(filter_json, dict_file):
    filter_str = json.dumps(filter_json)
    cmd = ['dict', 'compress', '--dict', dict_file, filter_str]
    return run_strfry_command(cmd)


def dict_decompress(filter_json):
    filter_str = json.dumps(filter_json)
    cmd = ['dict', 'decompress', filter_str]
    return run_strfry_command(cmd)


def get_config():
    config_path = Config.STRFRY_CONFIG
    if not os.path.exists(config_path):
        return None
    
    with open(config_path, 'r') as f:
        content = f.read()
    
    config = {}
    section_stack = []
    
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        if line.endswith('{'):
            section_stack.append(line[:-1].strip())
        elif line == '}':
            if section_stack:
                section_stack.pop()
        elif '=' in line:
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"')
            
            target = config
            for section in section_stack:
                if section not in target:
                    target[section] = {}
                target = target[section]
            target[key] = value
    
    return config


def update_config(updates):
    config_path = Config.STRFRY_CONFIG
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, 'r') as f:
        lines = f.readlines()

    for dotted_key, new_value in updates.items():
        parts = dotted_key.split('.')
        target_key = parts[-1]
        target_sections = parts[:-1]

        section_stack = []
        found = False

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            if stripped.endswith('{'):
                section_stack.append(stripped[:-1].strip())
            elif stripped == '}':
                if section_stack:
                    section_stack.pop()
            elif '=' in stripped and not stripped.startswith('#'):
                key = stripped.split('=', 1)[0].strip()
                if key == target_key and section_stack == target_sections:
                    indent = line[:len(line) - len(line.lstrip())]
                    lines[i] = f'{indent}{key} = "{new_value}"\n'
                    found = True
                    break

        if not found:
            raise KeyError(f"Key '{dotted_key}' not found in config")

    with open(config_path, 'w') as f:
        f.writelines(lines)

    return True
