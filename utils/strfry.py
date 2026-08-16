import subprocess
import json
import os
import selectors
import signal
import tempfile
import time
from contextlib import contextmanager
from config import Config
from utils.runtime_files import file_lock


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
        if converted is None or len(converted) != 32:
            raise ValueError("Failed to convert bits")
        return ''.join(f'{b:02x}' for b in converted)
    except Exception as e:
        raise ValueError(f"Invalid npub: {e}")


def hex_to_npub(pubkey):
    try:
        import bech32

        if not isinstance(pubkey, str) or len(pubkey) != 64:
            raise ValueError("Pubkey must be 64 hexadecimal characters")
        raw_pubkey = bytes.fromhex(pubkey)
        data = bech32.convertbits(raw_pubkey, 8, 5, True)
        if data is None:
            raise ValueError("Failed to convert bits")
        return bech32.bech32_encode('npub', data)
    except (TypeError, ValueError) as e:
        raise ValueError(f"Invalid hex pubkey: {e}") from e


def validate_filter_json(filter_str):
    try:
        obj = json.loads(filter_str)
        if not isinstance(obj, dict):
            raise ValueError("Filter must be a JSON object")
        return obj
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")


def _strfry_command(args):
    binary = Config.STRFRY_BINARY

    if not os.path.exists(binary):
        raise StrfryError(f"strfry binary not found at {binary}")

    cmd = [binary]
    if Config.STRFRY_CONFIG:
        cmd.extend(['--config', Config.STRFRY_CONFIG])
    cmd.extend(args)
    return cmd


def run_strfry_command(args, input_data=None, capture_output=True, timeout=300):
    cmd = _strfry_command(args)
    output = _run_bounded_process(
        cmd,
        input_data=input_data,
        timeout=timeout,
        max_stdout=(Config.STRFRY_COMMAND_MAX_STDOUT_BYTES if capture_output else 0),
        max_stderr=Config.STRFRY_COMMAND_MAX_STDERR_BYTES,
    )
    return output.strip() if capture_output else None


def run_strfry_command_limited(args, max_output_bytes, timeout=300):
    """Run a read-only command while bounding captured stdout in memory and on disk."""
    return _run_bounded_process(
        _strfry_command(args),
        timeout=timeout,
        max_stdout=max_output_bytes,
        max_stderr=Config.STRFRY_COMMAND_MAX_STDERR_BYTES,
    ).strip()


def _run_bounded_process(cmd, input_data=None, timeout=300, max_stdout=None, max_stderr=None):
    """Run one command with bounded output, deadline, and process-group cleanup."""
    max_stdout = Config.STRFRY_COMMAND_MAX_STDOUT_BYTES if max_stdout is None else max_stdout
    max_stderr = Config.STRFRY_COMMAND_MAX_STDERR_BYTES if max_stderr is None else max_stderr
    input_file = None
    if input_data is not None:
        input_file = tempfile.TemporaryFile()
        input_file.write(input_data.encode('utf-8') if isinstance(input_data, str) else input_data)
        input_file.seek(0)
    try:
        process = subprocess.Popen(
            cmd,
            stdin=input_file,
            stdout=subprocess.PIPE if max_stdout else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except (FileNotFoundError, OSError) as exc:
        if input_file is not None:
            input_file.close()
        raise StrfryError(f"Failed to execute strfry: {exc}") from exc

    streams = {}
    selector = selectors.DefaultSelector()
    if process.stdout is not None:
        selector.register(process.stdout, selectors.EVENT_READ)
        streams[process.stdout.fileno()] = ('stdout', bytearray(), max_stdout)
    selector.register(process.stderr, selectors.EVENT_READ)
    streams[process.stderr.fileno()] = ('stderr', bytearray(), max_stderr)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StrfryError('Command timed out')
            events = selector.select(remaining)
            if not events:
                raise StrfryError('Command timed out')
            for key, _mask in events:
                name, output, limit = streams[key.fd]
                chunk = os.read(key.fd, min(65536, limit + 1 - len(output)))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output) > limit:
                    raise StrfryError(
                        f'Command {name} exceeds the {limit}-byte safety limit'
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise StrfryError('Command timed out')
        return_code = process.wait(timeout=remaining)
        stdout = next((bytes(value[1]) for value in streams.values() if value[0] == 'stdout'), b'')
        stderr = next((bytes(value[1]) for value in streams.values() if value[0] == 'stderr'), b'')
        if return_code != 0:
            message = stderr.decode('utf-8', errors='replace').strip()
            raise StrfryError(message or f'Command failed with code {return_code}')
        return stdout.decode('utf-8', errors='strict')
    except (subprocess.TimeoutExpired, UnicodeDecodeError) as exc:
        raise StrfryError('Command timed out' if isinstance(exc, subprocess.TimeoutExpired) else 'Command output is not UTF-8') from exc
    finally:
        selector.close()
        group_signaled = False
        try:
            os.killpg(process.pid, signal.SIGTERM)
            group_signaled = True
        except ProcessLookupError:
            pass
        if process.poll() is None:
            try:
                process.wait(timeout=Config.STRFRY_TERMINATE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
        elif group_signaled:
            time.sleep(Config.STRFRY_TERMINATE_GRACE_SECONDS)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.stdout is not None:
            process.stdout.close()
        process.stderr.close()
        if input_file is not None:
            input_file.close()


def scan_events(filter_json, limit=100, timeout=300):
    filter_with_limit = {**filter_json, 'limit': limit}
    filter_str = json.dumps(filter_with_limit)
    cmd = ['scan', filter_str]
    output = run_strfry_command_limited(cmd, Config.STRFRY_SCAN_MAX_BYTES, timeout=timeout)
    
    events = []
    if not output:
        return events
    for line in output.split('\n'):
        if line.strip():
            if len(line.encode('utf-8')) > Config.STRFRY_SCAN_MAX_LINE_BYTES:
                raise StrfryError('Scan event exceeds the line-size safety limit')
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def iter_scan_events(filter_json, limit=100, timeout=300):
    """Stream events from a bounded local strfry scan."""
    for event in scan_events(filter_json, limit=limit, timeout=timeout):
        yield event


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
    with database_maintenance_lock():
        return run_strfry_command(cmd, timeout=timeout)


def export_events(since=None, until=None, reverse=False, fried=False):
    cmd = ['export']
    if since is not None:
        cmd.extend(['--since', str(since)])
    if until is not None:
        cmd.extend(['--until', str(until)])
    if reverse:
        cmd.append('--reverse')
    if fried:
        cmd.append('--fried')
    
    return run_strfry_command_limited(cmd, Config.EXPORT_MAX_BYTES)


def import_events(jsonl_data, verify=True):
    validate_jsonl(jsonl_data)
    
    cmd = ['import']
    if not verify:
        cmd.append('--no-verify')
    
    with database_maintenance_lock():
        return run_strfry_command(cmd, input_data=jsonl_data)


def validate_jsonl(jsonl_data):
    """Validate bounded JSONL event objects before passing them to strfry."""
    if len(jsonl_data.encode('utf-8')) > Config.IMPORT_MAX_BYTES:
        raise StrfryError(
            f"Import exceeds the {Config.IMPORT_MAX_BYTES}-byte safety limit"
        )

    event_count = 0
    for line_num, line in enumerate(jsonl_data.split('\n')):
        if line.strip():
            event_count += 1
            if event_count > Config.IMPORT_MAX_EVENTS:
                raise StrfryError(
                    f"Import exceeds the {Config.IMPORT_MAX_EVENTS}-event safety limit"
                )
            try:
                event = json.loads(line)
            except json.JSONDecodeError as e:
                raise StrfryError(f"Invalid JSON at line {line_num + 1}: {e}")
            if not isinstance(event, dict):
                raise StrfryError(f"Line {line_num + 1} must contain a JSON object")
    if event_count == 0:
        raise StrfryError("Import must contain at least one JSON event object")
    return True


@contextmanager
def database_maintenance_lock():
    """Prevent overlapping GUI database writes across worker processes."""
    try:
        with file_lock(Config.DATABASE_MAINTENANCE_LOCK, blocking=False):
            yield
    except BlockingIOError as exc:
        raise StrfryError("Another database maintenance operation is in progress") from exc


def compact_database(lock_file=None):
    cmd = ['compact', '-']
    if lock_file is not None:
        return run_strfry_command(cmd)
    with database_maintenance_lock():
        return run_strfry_command(cmd)


def get_strfry_uptime():
    """Return strfry process uptime in seconds, or None if not found."""
    return get_strfry_process_info()['uptime_seconds']


def get_strfry_process_info():
    """Return the oldest visible strfry process uptime and process count."""
    try:
        import subprocess
        result = subprocess.run(
            ['pgrep', '-x', 'strfry'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {
                'uptime_seconds': None,
                'process_count': 0 if result.returncode == 1 else None,
            }
        pids = result.stdout.strip().split()
        clk_tck = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
        with open('/proc/uptime') as f:
            system_uptime = float(f.read().split()[0])
        uptimes = []
        for pid in pids:
            try:
                with open(f'/proc/{pid}/stat') as process_stat:
                    stat = process_stat.read().split()
                starttime = int(stat[21])
                uptimes.append(max(0, int(system_uptime - (starttime / clk_tck))))
            except (OSError, IndexError, ValueError):
                continue
        return {
            'uptime_seconds': max(uptimes) if uptimes else None,
            'process_count': len(uptimes) if uptimes else None,
        }
    except (OSError, IndexError, ValueError, subprocess.TimeoutExpired):
        return {'uptime_seconds': None, 'process_count': None}


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
    with database_maintenance_lock():
        output = run_strfry_command(cmd)
    _clear_negentropy_cache()
    return output


def negentropy_build(tree_id):
    cmd = ['negentropy', 'build', str(tree_id)]
    with database_maintenance_lock():
        output = run_strfry_command(cmd)
    _clear_negentropy_cache()
    return output


def negentropy_delete(tree_id):
    cmd = ['negentropy', 'delete', str(tree_id)]
    with database_maintenance_lock():
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
    from utils.configuration import load_configuration

    snapshot = load_configuration(Config.STRFRY_CONFIG)
    if snapshot.revision is None:
        return None

    def legacy_values(value):
        if isinstance(value, dict):
            return {key: legacy_values(item) for key, item in value.items()}
        return str(value)

    return legacy_values(snapshot.values)


def update_config(updates, expected_revision=None):
    from utils.configuration import ConfigurationError, load_configuration

    snapshot = load_configuration(Config.STRFRY_CONFIG)
    if snapshot.revision is None:
        if not os.path.exists(Config.STRFRY_CONFIG):
            raise FileNotFoundError(f"Config file not found: {Config.STRFRY_CONFIG}")
        raise ConfigurationError('; '.join(snapshot.diagnostics))
    snapshot.write(updates, expected_revision=expected_revision)
    return True
