import subprocess
import json
import os
import re
from config import Config


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


def run_strfry_command(args, input_data=None, capture_output=True):
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
            timeout=300
        )
        if result.returncode != 0:
            raise StrfryError(result.stderr.strip() or f"Command failed with code {result.returncode}")
        return result.stdout.strip() if capture_output else None
    except subprocess.TimeoutExpired:
        raise StrfryError("Command timed out")
    except FileNotFoundError:
        raise StrfryError(f"strfry binary not found at {binary}")


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


def delete_events(filter_json):
    filter_str = json.dumps(filter_json)
    cmd = ['delete', '--filter', filter_str]
    output = run_strfry_command(cmd)
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


def negentropy_list():
    cmd = ['negentropy', 'list']
    output = run_strfry_command(cmd)
    
    trees = []
    current_tree = {}
    if not output:
        return trees
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
    
    return trees


def negentropy_add(filter_json):
    filter_str = json.dumps(filter_json)
    cmd = ['negentropy', 'add', filter_str]
    output = run_strfry_command(cmd)
    return output


def negentropy_build(tree_id):
    cmd = ['negentropy', 'build', str(tree_id)]
    output = run_strfry_command(cmd)
    return output


def negentropy_delete(tree_id):
    cmd = ['negentropy', 'delete', str(tree_id)]
    output = run_strfry_command(cmd)
    return output


def dict_list():
    cmd = ['dict', 'stats']
    output = run_strfry_command(cmd)
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
    current_section = 'root'
    
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        if line.endswith('{'):
            current_section = line[:-1].strip()
            if current_section not in config:
                config[current_section] = {}
        elif '=' in line:
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"')
            
            if current_section == 'root':
                config[key] = value
            else:
                if current_section in config:
                    config[current_section][key] = value
    
    return config


def update_config(updates):
    config_path = Config.STRFRY_CONFIG
    
    current_config = {}
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            content = f.read()
            current_config = parse_toml_like(content)
    
    for key, value in updates.items():
        current_config[key] = value
    
    with open(config_path, 'w') as f:
        for key, value in current_config.items():
            if isinstance(value, dict):
                f.write(f"{key} {{\n")
                for k, v in value.items():
                    f.write(f'    {k} = "{v}"\n')
                f.write("}\n\n")
            else:
                f.write(f'{key} = "{value}"\n')
    
    return True


def parse_toml_like(content):
    config = {}
    current_section = 'root'
    
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        if line.endswith('{'):
            current_section = line[:-1].strip()
            if current_section not in config:
                config[current_section] = {}
        elif '}' in line:
            current_section = 'root'
        elif '=' in line:
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"')
            
            if current_section == 'root':
                config[key] = value
            else:
                if current_section not in config:
                    config[current_section] = {}
                config[current_section][key] = value
    
    return config
