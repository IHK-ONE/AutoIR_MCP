import json
import re
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / 'config.json'
_safeline_server = ''
_safeline_config_mtime = None
_safeline_session = requests.Session()
_safeline_cache = {}
_safeline_cache_lock = threading.Lock()
_safeline_rate_lock = threading.Lock()
_safeline_request_times = []
SAFELINE_CACHE_TTL = 300
SAFELINE_UNAVAILABLE_TTL = 30
SAFELINE_CACHE_MAX = 512
SAFELINE_MAX_QUERIES_PER_MINUTE = 120
COMMAND_CONCURRENCY = 8
_command_semaphore = threading.BoundedSemaphore(COMMAND_CONCURRENCY)


def is_safe_path(base_dir, candidate):
    try:
        Path(candidate).resolve().relative_to(Path(base_dir).resolve())
        return True
    except (OSError, ValueError):
        return False


def is_safe_tar_member(destination, member, max_member_size=20 * 1024 * 1024):
    if member.issym() or member.islnk() or member.isdev() or member.isfifo() or member.size > max_member_size:
        return False
    # Normalize Windows separators so "..\\evil" cannot slip through Path.parts.
    name = member.name.replace("\\", "/")
    if not name or name.startswith("/") or ".." in Path(name).parts:
        return False
    return is_safe_path(destination, Path(destination) / name)


def get_run_id():
    """Return a collision-resistant identifier for one tool run."""
    return datetime.now().strftime('%Y_%m_%d_%H_%M_%S_%f') + '_' + uuid.uuid4().hex[:8]


def truncate_text(value, max_chars=4000):
    value = value or ""
    if len(value) <= max_chars:
        return value, False
    return value[:max_chars] + "\n[TRUNCATED] output exceeded limit", True


FAILURE_KEYWORDS = (
    '错误', '失败', '[ERROR]', '[FAILED]', '[PERMISSION]', '[NOT_FOUND]',
    '命令超时', '权限不足', 'Traceback', 'exception',
)
SUSPICIOUS_KEYWORDS = ('[!]', '可疑', '异常', '后门', 'webshell', 'WebShell', 'deleted exe', '反弹', '挖矿', 'SUID', 'authorized_keys')
HIGH_RISK_KEYWORDS = ('root 标识用户', '空口令', 'ld.so.preload', 'SSH wrapper', '隐藏 PID')


def value_to_text(value):
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except TypeError:
        return str(value)


def is_failure_text(text):
    text = text or ''
    if '未发现明显异常' in text:
        return False
    return any(keyword in text for keyword in FAILURE_KEYWORDS)


def infer_risk_level(text):
    text = text or ''
    if not text or '未发现明显异常' in text or text.startswith('[EMPTY]'):
        return '未发现明显异常'
    if any(keyword in text for keyword in HIGH_RISK_KEYWORDS):
        return '高'
    if any(keyword in text for keyword in SUSPICIOUS_KEYWORDS):
        return '中'
    if is_failure_text(text) or '[TRUNCATED]' in text:
        return '低'
    return '信息'


def classify_remote_error_text(text):
    """Classify a remote error message without guessing from empty output."""
    text = (text or '').lower()
    if 'command not found' in text:
        return 'error'
    permission_markers = (
        'permission denied', 'operation not permitted', 'access denied',
        '权限不足', '没有权限',
    )
    if any(marker in text for marker in permission_markers):
        return 'permission_denied'
    missing_markers = (
        'no such file', 'not found', 'cannot stat', "can't open",
        'does not exist', '找不到', '不存在',
    )
    if any(marker in text for marker in missing_markers):
        return 'not_found'
    return 'error'


def classify_remote_result(result):
    """Return ok / not_found / permission_denied / timeout / error."""
    if not isinstance(result, dict):
        return 'error'
    if result.get('status'):
        return 'ok'
    if result.get('timeout'):
        return 'timeout'
    detail = ' '.join(str(result.get(key) or '') for key in ('stderr', 'result', 'error'))
    return classify_remote_error_text(detail)


def remote_result_issue(result, target, action='读取', include_missing=False):
    """Build an explicit, non-empty issue for a failed remote read."""
    kind = classify_remote_result(result)
    if kind == 'not_found':
        return f'[NOT_FOUND] {action} {target}: 文件或路径不存在' if include_missing else ''
    if kind == 'permission_denied':
        return f'[PERMISSION] {action} {target}: 权限不足'
    if kind == 'timeout':
        return f'[FAILED] {action} {target}: 命令超时'
    detail = result.get('error') or result.get('stderr') or result.get('result') or '无错误详情'
    detail = str(detail).strip().splitlines()[0][:300] if str(detail).strip() else '无错误详情'
    return f'[FAILED] {action} {target}: {detail}'


def remote_error_issue(kind, target, detail='', action='读取'):
    if kind == 'not_found':
        return ''
    if kind == 'permission_denied':
        return f'[PERMISSION] {action} {target}: 权限不足'
    if kind == 'timeout':
        return f'[FAILED] {action} {target}: 命令超时'
    detail = (detail or '').strip().splitlines()[0][:300] if (detail or '').strip() else '无错误详情'
    return f'[FAILED] {action} {target}: {detail}'


def normalize_tool_result(tool, value, empty_message="未发现明显异常"):
    data = None
    error = ''
    kind = type(value).__name__ if value is not None else 'none'
    explicit_status = None

    if isinstance(value, dict):
        explicit_status = value.get('status')
        status = bool(explicit_status) if explicit_status is not None else True
        result = value_to_text(value.get('result', ''))
        explicit_data = value.get('data') if 'data' in value else None
        data = explicit_data if explicit_data is not None else {key: item for key, item in value.items() if key not in {'status', 'result', 'error', 'meta', 'data'}} or None
        error = value_to_text(value.get('error', ''))
        truncated = bool(value.get('truncated', False))
        if not result and data is not None:
            result = value_to_text(data)
    elif isinstance(value, (list, tuple)):
        result = value_to_text(value)
        status = True
        data = list(value)
        truncated = False
    else:
        result = value_to_text(value).strip()
        status = not is_failure_text(result)
        truncated = '[TRUNCATED]' in result

    if not result:
        result = f'[EMPTY] {tool}: {empty_message}'
    risk = infer_risk_level(result)
    if explicit_status is None:
        if risk == '未发现明显异常':
            status = True
        elif is_failure_text(result):
            status = False
            error = error or result
    elif not status:
        # Never turn an explicitly reported failure into a success just because
        # the failure result happened to be empty.
        error = error or result

    return {
        'status': status,
        'result': result,
        'data': data,
        'error': error,
        'meta': {
            'tool': tool,
            'risk': risk,
            'empty': result.startswith('[EMPTY]'),
            'truncated': truncated,
            'kind': kind,
        },
    }


def unique_limited(values, limit=100):
    result = []
    seen = set()
    for value in values:
        value = str(value).strip().strip('.,;:()[]{}<>"\'`')
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
        if len(result) >= limit:
            break
    return result


IPV4_PATTERN = re.compile(
    r'(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])'
)
URL_PATTERN = re.compile(r'https?://[^\s<>"\'`]+', re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b')
PATH_PATTERN = re.compile(r'(?<![\w.:/-])/(?:[\w.@%+=:,~-]+/)*[\w.@%+=:,~-]+')
PORT_PATTERNS = (
    re.compile(r'(?i)\b(?:port|端口)\s*[:=]?\s*([1-9]\d{0,4})\b'),
    re.compile(r'\b(?:\d{1,3}(?:\.\d{1,3}){3}|localhost|[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)[:：]([1-9]\d{0,4})\b'),
)
HASH_PATTERN = re.compile(r'\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b')
USER_AGENT_PATTERN = re.compile(r'(?i)\b(?:user[-_ ]?agent|ua)\s*[:=：]\s*["\']?([^\r\n"\']+?)(?=\s+(?:user[-_ ]?agent|ua|user|username|account|ip|path|url|domain|port|md5|sha1|sha256|用户|账号|账户|路径|端口|哈希)\s*[:=：]|["\']|$)')
COMBINED_LOG_USER_AGENT_PATTERN = re.compile(r'"[^"\r\n]*"\s+"([^"\r\n]+)"\s*$')
USER_PATTERNS = (
    re.compile(r'(?i)\b(?:user|username|account|用户|账号|账户)\s*[:=：]\s*([A-Za-z0-9_][\w.-]{0,63})'),
    re.compile(r'(?i)\binvalid\s+user\s+([A-Za-z0-9_][\w.-]{0,63})\b'),
    re.compile(r'(?i)\b(?:Accepted|Failed)\s+password\s+for\s+(?:invalid\s+user\s+)?([A-Za-z0-9_][\w.-]{0,63})\b'),
)
NOISE_DOMAIN_SUFFIXES = {
    'php', 'jsp', 'jspx', 'asp', 'aspx', 'sh', 'py', 'pl', 'txt', 'log', 'conf', 'ini',
    'gz', 'tgz', 'zip', 'tar', 'rar', '7z', 'bz2', 'xz', 'db', 'sql', 'json', 'xml',
    'html', 'htm', 'css', 'js', 'map', 'md', 'csv', 'png', 'jpg', 'jpeg', 'gif',
    'svg', 'ico', 'woff', 'woff2', 'ttf', 'eot', 'so', 'dll', 'exe', 'bin',
}


def valid_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return False
    return 1 <= port <= 65535


def extract_ioc_values(text, limit=100):
    text = text or ''
    try:
        limit = max(1, min(int(limit), 5000))
    except (TypeError, ValueError):
        limit = 100
    urls = unique_limited(URL_PATTERN.findall(text), limit)
    url_hosts = []
    for url in urls:
        try:
            host = urlparse(url).hostname or ''
            if host:
                url_hosts.append(host)
        except ValueError:
            pass
    ips = unique_limited(
        (
            ip for ip in IPV4_PATTERN.findall(text)
            if not ip.startswith('127.') and ip not in {'0.0.0.0', '255.255.255.255'}
        ),
        limit,
    )
    domains = unique_limited(
        (
            domain.lower() for domain in DOMAIN_PATTERN.findall(text)
            if domain.lower() not in {'localhost'}
            and not IPV4_PATTERN.fullmatch(domain)
            and domain.rsplit('.', 1)[-1].lower() not in NOISE_DOMAIN_SUFFIXES
        ),
        limit,
    )
    path_text = URL_PATTERN.sub(' ', text)
    paths = unique_limited(
        (
            path for path in PATH_PATTERN.findall(path_text)
            if not path.startswith('//') and not path.startswith('/dev/null')
        ),
        limit,
    )
    ports = []
    for pattern in PORT_PATTERNS:
        ports.extend(match for match in pattern.findall(text) if valid_port(match))
    users = []
    for pattern in USER_PATTERNS:
        users.extend(pattern.findall(text))
    user_agents = USER_AGENT_PATTERN.findall(text)
    user_agents.extend(agent for agent in COMBINED_LOG_USER_AGENT_PATTERN.findall(text) if agent != '-')
    return {
        'ips': ips,
        'domains': unique_limited(url_hosts + domains, limit),
        'urls': urls,
        'paths': paths,
        'ports': unique_limited(ports, limit),
        'hashes': unique_limited(HASH_PATTERN.findall(text), limit),
        'users': unique_limited(users, limit),
        'user_agents': unique_limited(user_agents, limit),
    }


TIMELINE_PATTERNS = (
    re.compile(r'\b\d{4}[-/]\d{1,2}[-/]\d{1,2}[ T]\d{1,2}:\d{2}(?::\d{2})?\b'),
    re.compile(r'\b\d{4}年\d{1,2}月\d{1,2}日\s+\d{1,2}:\d{2}(?::\d{2})?\b'),
    re.compile(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}\b'),
    re.compile(r'\b\d{1,2}/[A-Za-z]{3}/\d{4}:\d{1,2}:\d{2}:\d{2}\s+[+-]\d{4}\b'),
)


def extract_timeline_events(text, limit=100):
    events = []
    seen = set()
    source = 'input'
    try:
        limit = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        limit = 100
    for raw_line in (text or '').splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith('## '):
            source = line[3:].strip() or source
            continue
        for pattern in TIMELINE_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            timestamp = match.group(0)
            event = line.replace(timestamp, '', 1).strip(' -\t[]') or line
            event = event[:240]
            key = (timestamp, event, source)
            if key in seen:
                break
            seen.add(key)
            events.append({'time': timestamp, 'event': event, 'source': source, 'raw': line[:300]})
            break
        if len(events) >= limit:
            break
    return events


ATTACK_FLOW_RULES = (
    ('初始访问', ('Accepted password', 'Failed password', 'Invalid user', '成功登录', '失败登录', '爆破', 'GET /', 'POST /')),
    ('执行与落地', ('疑似 WebShell', 'WebShell', '近期变更文件', '/tmp/', '/dev/shm/', 'curl ', 'wget ', 'bash -i', 'base64', 'php -r')),
    ('权限提升', ('root 标识用户', '特权用户', 'SUID', 'sudo', '空口令', 'setuid')),
    ('持久化', ('cron', 'crontab', 'systemd', 'timer', 'ExecStart', 'authorized_keys', 'profile', 'rc.local', 'ld.so.preload', '可疑任务')),
    ('防御规避', ('check_deleted_exe', 'check_pid', 'check_mount', 'check_ssh_wrapper', '环境变量劫持', 'deleted exe', '隐藏', 'wrapper')),
    ('命令控制/外联', ('check_network', 'check_listening_ports', 'check_dns_config', 'check_hosts', '/dev/tcp/', 'remote :', 'http://', 'https://')),
    ('影响动作', ('check_mine', '挖矿', '高 CPU', 'miner', 'coin', 'container', 'webshell')),
)


def collect_attack_evidence(text, rules, limit=3):
    evidence = {stage: [] for stage, _ in rules}
    lowered_rules = [(stage, tuple(keyword.lower() for keyword in keywords)) for stage, keywords in rules]
    for raw_line in (text or '').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('## '):
            continue
        line_lower = line.lower()
        for stage, keywords in lowered_rules:
            if len(evidence[stage]) >= limit:
                continue
            if any(keyword in line_lower for keyword in keywords):
                evidence[stage].append(line.replace('|', '/')[:180])
        if all(len(items) >= limit for items in evidence.values()):
            break
    return evidence


def infer_attack_flow(text, iocs=None, timeline_events=None, max_items=8, evidence_limit=3, include_unobserved=True):
    text = text or ''
    try:
        max_items = max(1, min(int(max_items), len(ATTACK_FLOW_RULES)))
    except (TypeError, ValueError):
        max_items = 8
    try:
        evidence_limit = max(1, min(int(evidence_limit), 10))
    except (TypeError, ValueError):
        evidence_limit = 3

    iocs = iocs or extract_ioc_values(text)
    if timeline_events is None:
        timeline_events = extract_timeline_events(text, limit=20)
    rules = ATTACK_FLOW_RULES[:max_items]
    evidence_by_stage = collect_attack_evidence(text, rules, limit=evidence_limit)
    stages = []
    for stage, _ in rules:
        evidence = list(evidence_by_stage.get(stage, []))
        if stage == '命令控制/外联':
            suspicious_ports = [port for port in (iocs.get('ports') or []) if valid_port(port) and int(port) > 1024]
            if any(iocs.get(key) for key in ('ips', 'domains', 'urls')) or suspicious_ports:
                ioc_summary = ', '.join((iocs.get('ips') or [])[:3] + (iocs.get('domains') or [])[:3] + (iocs.get('urls') or [])[:2] + suspicious_ports[:3])
                if ioc_summary:
                    evidence.insert(0, f'IOC: {ioc_summary}')
        status = '发现线索' if evidence else '未发现明显线索'
        if include_unobserved or evidence:
            stages.append({'stage': stage, 'status': status, 'evidence': evidence[:evidence_limit]})

    observed = [stage for stage in stages if stage['status'] == '发现线索']
    if observed:
        summary = ' → '.join(stage['stage'] for stage in observed[:6])
        summary = f'基于现有证据，疑似攻击链条包含：{summary}。证据仍需结合原始日志人工复核。'
    else:
        summary = '当前材料不足以还原明确攻击流程，缺少可支撑阶段判断的工具证据。'
    if timeline_events:
        first_event = timeline_events[0]
        summary += f' 首个时间线线索：{first_event.get("time", "-")} {first_event.get("event", "")}。'

    rows = ['| 阶段 | 判断 | 关键依据 |', '|---|---|---|']
    for stage in stages:
        evidence = '<br>'.join(stage['evidence']) if stage['evidence'] else '未发现明显线索'
        rows.append(f'| {stage["stage"]} | {stage["status"]} | {evidence} |')
    return {'stages': stages, 'summary': summary, 'markdown': '\n'.join(rows)}


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
    # Bound the number of concurrent channels so a burst of parallel tool
    # calls cannot overwhelm the target's sshd.
    with _command_semaphore:
        try:
            timeout = max(1, int(timeout))
            max_bytes = max(1024, int(max_bytes))
            transport = client.get_transport()
            if transport is None or (hasattr(transport, 'is_active') and not transport.is_active()):
                raise RuntimeError('SSH 连接已断开')
            channel = transport.open_session()
            channel.settimeout(1)
            channel.exec_command(command)
            stdout_chunks = []
            stderr_chunks = []
            stdout_size = stderr_size = 0
            stdout_truncated = stderr_truncated = False
            while True:
                progressed = False
                # Drain every chunk currently buffered instead of one chunk per
                # sleep interval; large command output is no longer throttled.
                while channel.recv_ready():
                    if time.monotonic() - started > timeout:
                        raise TimeoutError(f'{timeout}s')
                    stdout_size, truncated = append_limited(stdout_chunks, stdout_size, channel.recv(65536), max_bytes)
                    stdout_truncated = stdout_truncated or truncated
                    progressed = True
                while channel.recv_stderr_ready():
                    if time.monotonic() - started > timeout:
                        raise TimeoutError(f'{timeout}s')
                    stderr_size, truncated = append_limited(stderr_chunks, stderr_size, channel.recv_stderr(65536), max_bytes)
                    stderr_truncated = stderr_truncated or truncated
                    progressed = True
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                if time.monotonic() - started > timeout:
                    raise TimeoutError(f'{timeout}s')
                if not progressed:
                    time.sleep(0.02)
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
            result.update({
                'result': f'命令超时: {error}',
                'error': str(error),
                'timeout': True,
            })
        except Exception as error:
            result.update({
                'result': str(error),
                'error': str(error),
            })
        finally:
            if channel is not None:
                try:
                    channel.close()
                except Exception:
                    pass
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


def sftp_download(client, origin_path, download_path, timeout=120, max_bytes=None):
    """Download with an idle timeout and an optional hard size limit.

    paramiko's SFTPClient.get() has no timeout or size guard of its own, so a
    stalled transfer or a file that grows after the initial stat could hang the
    whole investigation.
    """
    sftp = None
    total = 0
    try:
        sftp = client.open_sftp()
        channel = sftp.get_channel() if hasattr(sftp, 'get_channel') else None
        if channel is not None and timeout:
            channel.settimeout(timeout)
        with sftp.open(origin_path, 'rb') as remote_file:
            if hasattr(remote_file, 'prefetch'):
                remote_file.prefetch()
            with open(download_path, 'wb') as local_file:
                while True:
                    chunk = remote_file.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if max_bytes is not None and total > max_bytes:
                        raise ValueError(f'文件超过下载大小限制 {max_bytes} bytes')
                    local_file.write(chunk)
        return {'status': True, 'result': download_path, 'error': '', 'bytes': total}
    except Exception as error:
        try:
            Path(download_path).unlink()
        except OSError:
            pass
        return {'status': False, 'result': '', 'error': str(error), 'bytes': total}
    finally:
        if sftp:
            try:
                sftp.close()
            except Exception:
                pass


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


MALICIOUS_PATTERN = re.compile(
    r'bash\s+-i|/dev/tcp/|\bnc\s+|\btelnet\s+|\bcurl\s+.*\|\s*(sh|bash|python|perl)|'
    r'\bwget\s+.*\|\s*(sh|bash|python|perl)|exec\s+.*socket|base64\s+-d|'
    r'exec\(base64\.b64decode|\.decode\([\'\"]base64[\'\"]\)|php\s+-r|'
    r'python\s+-c\s+.*socket|perl\s+-e\s+.*socket|powershell|cmd\.exe',
    re.IGNORECASE,
)

# Only content that looks command-like or webshell-like is worth a remote
# SafeLine lookup; this avoids one HTTP request per line of process/strings
# output while keeping the local regex as the first-pass filter.
SAFELINE_HINT_PATTERN = re.compile(
    r'(?i)(?:<\?|eval\s*\(|assert\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|'
    r'base64|/dev/tcp|\bsocket\b|subprocess|os\.system|popen|'
    r'\b(?:bash|sh|curl|wget|nc|ncat|socat|python|perl|php|powershell|chmod)\b)',
)
SAFELINE_MAX_INPUT = 8192


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
            server = json.load(file).get('SafeLineWAF', {}).get('Server', '')
        server = str(server or '').strip()
        new_server = server if urlparse(server).scheme in ('http', 'https') else ''
        if new_server != _safeline_server:
            with _safeline_cache_lock:
                _safeline_cache.clear()
        _safeline_server = new_server
        _safeline_config_mtime = mtime
        return _safeline_server
    except (OSError, json.JSONDecodeError, AttributeError):
        _safeline_server = ''
        _safeline_config_mtime = None
        return ''


def check_safe_safeline_result(content, use_cache=True):
    """Query SafeLine and preserve why a verdict could not be obtained.

    Returns {'status': hit|clean|unavailable|disabled, 'content': ...,
             'error': ..., 'http_status': ...}.
    """
    result = {'status': 'disabled', 'content': '', 'error': '', 'http_status': None}
    server = get_safeline_server()
    content = str(content or '')
    if not server or not content:
        result['error'] = 'SafeLine 未配置或内容为空'
        return result
    if len(content) > SAFELINE_MAX_INPUT:
        content = content[:SAFELINE_MAX_INPUT]

    now = time.monotonic()
    if use_cache:
        with _safeline_cache_lock:
            cached = _safeline_cache.get(content)
            if cached and now - cached[0] < cached[1]:
                return dict(cached[2])

    with _safeline_rate_lock:
        cutoff = now - 60
        while _safeline_request_times and _safeline_request_times[0] < cutoff:
            _safeline_request_times.pop(0)
        if len(_safeline_request_times) >= SAFELINE_MAX_QUERIES_PER_MINUTE:
            result = {
                'status': 'unavailable',
                'content': '',
                'error': 'SafeLine 查询频率超过限制，部分内容未检测',
                'http_status': None,
            }
            return result
        _safeline_request_times.append(now)

    try:
        response = _safeline_session.get(server, params={'input': content}, timeout=(3, 5))
        if response.status_code == 403:
            result = {'status': 'hit', 'content': content, 'error': '', 'http_status': 403}
        elif 200 <= response.status_code < 400:
            result = {'status': 'clean', 'content': '', 'error': '', 'http_status': response.status_code}
        else:
            result = {
                'status': 'unavailable',
                'content': '',
                'error': f'SafeLine 返回 HTTP {response.status_code}',
                'http_status': response.status_code,
            }
    except requests.RequestException as error:
        result = {
            'status': 'unavailable',
            'content': '',
            'error': f'SafeLine 请求失败: {error}',
            'http_status': None,
        }

    if use_cache:
        ttl = SAFELINE_CACHE_TTL if result['status'] in ('hit', 'clean') else SAFELINE_UNAVAILABLE_TTL
        with _safeline_cache_lock:
            if len(_safeline_cache) >= SAFELINE_CACHE_MAX:
                _safeline_cache.pop(next(iter(_safeline_cache)))
            _safeline_cache[content] = (now, ttl, dict(result))
    return result


def check_safe_safeline(content):
    result = check_safe_safeline_result(content)
    return result['content'] if result['status'] == 'hit' else ''
