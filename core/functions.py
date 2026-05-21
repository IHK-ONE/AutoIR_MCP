import json
import re
import time
from datetime import datetime
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / 'config.json'
_safeline_server = ''
_safeline_config_mtime = None


def is_safe_path(base_dir, candidate):
    try:
        Path(candidate).resolve().relative_to(Path(base_dir).resolve())
        return True
    except (OSError, ValueError):
        return False


def is_safe_tar_member(destination, member, max_member_size=20 * 1024 * 1024):
    if member.issym() or member.islnk() or member.isdev() or member.size > max_member_size:
        return False
    if Path(member.name).is_absolute() or ".." in Path(member.name).parts:
        return False
    return is_safe_path(destination, Path(destination) / member.name)


def truncate_text(value, max_chars=4000):
    value = value or ""
    if len(value) <= max_chars:
        return value, False
    return value[:max_chars] + "\n[TRUNCATED] output exceeded limit", True


def format_tool_output(tool, content, empty_message="未发现明显异常"):
    if content is None:
        content = ""
    if isinstance(content, str):
        stripped = content.strip()
        return stripped or f"[EMPTY] {tool}: {empty_message}"
    return content


def append_limited(chunks, current_size, data, max_bytes):
    if current_size >= max_bytes:
        return current_size, True
    remaining = max_bytes - current_size
    chunks.append(data[:remaining])
    return current_size + min(len(data), remaining), len(data) > remaining


def decode_limited(chunks, truncated):
    output = b''.join(chunks).decode(errors='ignore').strip()
    if truncated:
        output += '\n[TRUNCATED] command output exceeded max_bytes'
    return output


def exec_command(client, command, timeout=10, max_bytes=1_000_000):
    result = {
        'status': False,
        'result': '',
        'stdout': '',
        'stderr': '',
        'exit_status': None,
        'error': '',
        'command': command,
        'timeout': False,
        'truncated': False,
    }
    started = time.monotonic()
    channel = None
    try:
        timeout = max(1, int(timeout))
        max_bytes = max(1024, int(max_bytes))
        channel = client.get_transport().open_session()
        channel.settimeout(1)
        channel.exec_command(command)
        stdout_chunks = []
        stderr_chunks = []
        stdout_size = stderr_size = 0
        stdout_truncated = stderr_truncated = False
        while True:
            if time.monotonic() - started > timeout:
                raise TimeoutError(f'{timeout}s')
            if channel.recv_ready():
                stdout_size, truncated = append_limited(stdout_chunks, stdout_size, channel.recv(32768), max_bytes)
                stdout_truncated = stdout_truncated or truncated
            if channel.recv_stderr_ready():
                stderr_size, truncated = append_limited(stderr_chunks, stderr_size, channel.recv_stderr(32768), max_bytes)
                stderr_truncated = stderr_truncated or truncated
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            time.sleep(0.05)
        exit_status = channel.recv_exit_status()
        stdout_output = decode_limited(stdout_chunks, stdout_truncated)
        stderr_output = decode_limited(stderr_chunks, stderr_truncated)
        result.update({
            'status': exit_status == 0,
            'result': stdout_output or stderr_output,
            'stdout': stdout_output,
            'stderr': stderr_output,
            'exit_status': exit_status,
            'truncated': stdout_truncated or stderr_truncated,
        })
    except TimeoutError as error:
        if channel is not None:
            channel.close()
        result.update({
            'result': f'命令超时: {error}',
            'error': str(error),
            'timeout': True,
        })
    except Exception as error:
        if channel is not None:
            channel.close()
        result.update({
            'result': str(error),
            'error': str(error),
        })
    return result


def command_ok(result):
    return bool(result and result.get('status') and result.get('result'))


def first_success(client, commands, timeout=10, max_bytes=1_000_000):
    last_result = {'status': False, 'result': '', 'stderr': '', 'exit_status': None, 'error': 'no command executed'}
    for command in commands:
        last_result = exec_command(client, command, timeout=timeout, max_bytes=max_bytes)
        if command_ok(last_result):
            return last_result
    return last_result


def sftp_download(client, origin_path, download_path):
    sftp = None
    try:
        sftp = client.open_sftp()
        sftp.get(origin_path, download_path)
        return {'status': True, 'result': download_path, 'error': ''}
    except Exception as error:
        return {'status': False, 'result': '', 'error': str(error)}
    finally:
        if sftp:
            sftp.close()


def sftp_upload(client, local_path, server_path):
    sftp = None
    try:
        sftp = client.open_sftp()
        sftp.put(local_path, server_path)
        return {'status': True, 'result': server_path, 'error': ''}
    except Exception as error:
        return {'status': False, 'result': '', 'error': str(error)}
    finally:
        if sftp:
            sftp.close()


def get_file_list(files):
    file_list = {}
    for i, file in enumerate(files.splitlines()[1:]):
        parts = re.split(r'\s+', file.strip())
        if len(parts) < 9:
            continue
        perm = parts[0].strip('.').strip('+')
        link = parts[1]
        owner = parts[2]
        group = parts[3]
        size = parts[4]
        timestamp = get_time(parts[5:8])
        filename = ' '.join(parts[8:])
        if filename not in ['.', '..']:
            file_list[i] = {'perm': perm, 'link': link, 'owner': owner, 'group': group, 'size': size, 'time': timestamp, 'filename': filename}
    return file_list


def get_time(parts):
    month_map = {
        'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
        'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
        'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
    }
    if len(parts) < 3:
        return ''
    month = month_map.get(parts[0], parts[0])
    day = parts[1]
    if ':' in parts[2]:
        return f'{datetime.now().year}年{month}月{day}日 {parts[2]}'
    return f'{parts[2]}年{month}月{day}日'


def get_time_path():
    return datetime.now().strftime('%Y_%m_%d_%H_%M_%S')


MALICIOUS_PATTERN = re.compile(
    r'bash\s+-i|/dev/tcp/|\bnc\s+|\btelnet\s+|\bcurl\s+.*\|\s*(sh|bash|python|perl)|'
    r'\bwget\s+.*\|\s*(sh|bash|python|perl)|exec\s+.*socket|base64\s+-d|'
    r'exec\(base64\.b64decode|\.decode\([\'\"]base64[\'\"]\)|php\s+-r|'
    r'python\s+-c\s+.*socket|perl\s+-e\s+.*socket',
    re.IGNORECASE,
)


def check_safe_local(content):
    try:
        return content if MALICIOUS_PATTERN.search(content) else ''
    except Exception:
        return ''


def get_safeline_server():
    global _safeline_config_mtime, _safeline_server
    try:
        mtime = CONFIG_PATH.stat().st_mtime
        if mtime == _safeline_config_mtime:
            return _safeline_server
        with open(CONFIG_PATH, encoding='utf-8') as file:
            _safeline_server = json.load(file).get('SafeLineWAF', {}).get('Server', '').strip()
        _safeline_config_mtime = mtime
        return _safeline_server
    except (OSError, json.JSONDecodeError, AttributeError):
        _safeline_server = ''
        _safeline_config_mtime = None
        return ''


def check_safe_safeline(content):
    server = get_safeline_server()
    if not server:
        return ''
    try:
        response = requests.get(server, params={'input': content}, timeout=5)
        return content if response.status_code == 403 else ''
    except requests.RequestException:
        return ''
