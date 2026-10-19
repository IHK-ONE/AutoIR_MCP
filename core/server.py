from fastmcp import FastMCP
from .functions import (
    PROJECT_ROOT,
    SAFELINE_HINT_PATTERN,
    check_safe_local,
    check_safe_safeline_result,
    classify_remote_error_text,
    classify_remote_result,
    remote_result_issue,
    remote_error_issue,
    exec_command,
    extract_ioc_values,
    extract_timeline_events,
    infer_attack_flow,
    infer_risk_level,
    first_success,
    IPV4_PATTERN,
    normalize_tool_result,
    get_file_list,
    get_run_id,
    get_safeline_server,
    is_safe_path,
    is_safe_tar_member,
    sftp_download,
    sftp_upload,
    truncate_text,
)
from .prompts import AUTOIR_MCP_BANNER, MCP_INSTRUCTIONS, TOOL_CATEGORIES
from .session import SSHSession
import paramiko
import csv
import json
import os
import shutil
import tarfile
import hashlib
import subprocess
import collections
import ipaddress
import re
import shlex
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

base_dir = str(PROJECT_ROOT)
INTERNAL_IOC_LIMIT = 5000
SESSION_ERROR = "错误：SSH连接未建立或已断开，请先调用 get_ssh_client 建立连接"
NO_PRESET_NEXT_TOOLS = 'MCP 服务不预设后续工具、排查路径或固定顺序；由 AI 客户端根据用户目标、现场上下文和工具证据自行编排。'
VALID_REPORT_RISKS = {'高', '中', '低', '信息', '未发现明显异常'}
REPORT_OUTPUT_MODES = {'inline', 'preview', 'file', 'both'}

mcp = FastMCP("AutoIR_MCP", instructions=MCP_INSTRUCTIONS)


ssh_session = SSHSession(None)
session_lock = threading.RLock()
state_lock = threading.RLock()
webshell_lock = threading.RLock()


def _close_client(client):
    if client is None:
        return
    try:
        client.close()
    except Exception:
        pass


def append_warnings(output, warnings):
    unique = list(dict.fromkeys(
        item for item in (warnings or []) if item and item not in output
    ))
    if not unique:
        return output
    return (output + '\n' if output else '') + '\n'.join(unique)


def check_session(probe=False):
    with session_lock:
        session = ssh_session
        client = session.client if session else None
    if client is None:
        return False
    try:
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            return False
        if hasattr(transport, 'is_authenticated') and not transport.is_authenticated():
            return False
        if not probe:
            return True
        result = exec_command(client, 'true', timeout=5, max_bytes=1000)
        return bool(result.get('status'))
    except Exception:
        return False


@mcp.tool()
def get_ssh_client(ip, port=22, username='root', password='', verify_host_key=False, known_hosts='', key_file='', passphrase=''):
    """
    建立 SSH 会话并缓存连接，是用户提供 IP、端口、账号密码、靶机信息或应急响应题目时必须优先调用的入口工具。
    调用：看到目标 IP/账号密码/CTF 题目/应急排查任务时，不得直接根据题面回答，必须先调用本工具连接目标；所有远程检测工具前也必须先调用。
    后续：连接成功后，按用户目标调用专用 check_* / discover_* / profile_* 工具采证；交付结论、结束调查或用户要求总结前必须调用 generate_report 汇总证据。
    输出：返回连接状态和失败原因；连接失败必须在最终报告中标注检测失败或需人工复核。
    verify_host_key=True 时启用 known_hosts 主机密钥校验；known_hosts 可指定自定义文件。
    key_file/passphrase 用于私钥登录；未指定时 paramiko 会尝试本机默认密钥和 SSH agent。
    """

    global ssh_session

    if not ip or not isinstance(ip, str) or not ip.strip():
        return {"status": False, "result": "IP地址不能为空且必须为字符串"}

    try:
        port = int(port)
    except (TypeError, ValueError):
        return {"status": False, "result": "端口必须为1-65535之间的整数"}
    if not 1 <= port <= 65535:
        return {"status": False, "result": "端口必须为1-65535之间的整数"}

    if not username or not isinstance(username, str) or not username.strip():
        return {"status": False, "result": "用户名不能为空且必须为字符串"}
    if password is None:
        password = ''
    if not isinstance(password, str):
        return {"status": False, "result": "password 必须为字符串"}
    if passphrase is None:
        passphrase = ''
    if key_file and not os.path.isfile(str(key_file)):
        return {"status": False, "result": f"私钥文件不存在或不可读: {key_file}"}

    ip = ip.strip()
    username = username.strip()
    client = paramiko.SSHClient()

    try:
        if verify_host_key:
            if known_hosts:
                client.load_system_host_keys(str(known_hosts))
            else:
                client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs = {'port': port, 'username': username, 'password': password, 'timeout': 30}
        if key_file:
            connect_kwargs['key_filename'] = str(key_file)
            connect_kwargs['passphrase'] = passphrase
        client.connect(ip, **connect_kwargs)
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(30)
        with session_lock:
            old_client = ssh_session.client if ssh_session and ssh_session.client else None
            ssh_session = SSHSession(client)
        _close_client(old_client)
        result_text = "SSH 连接成功"
        if not verify_host_key:
            result_text += "；警告：未校验主机密钥，存在中间人风险，实战环境建议 verify_host_key=True"
        return {"status": True, "result": result_text}

    except paramiko.BadHostKeyException:
        _close_client(client)
        return {"status": False, "result": "SSH 主机密钥校验失败：目标主机密钥与 known_hosts 不匹配"}
    except paramiko.AuthenticationException:
        _close_client(client)
        return {"status": False, "result": "SSH 认证失败：请检查用户名、密码，或私钥/key_file、SSH agent 配置"}
    except paramiko.SSHException as e:
        _close_client(client)
        return {"status": False, "result": f"SSH 连接错误: {str(e)}"}
    except Exception as e:
        _close_client(client)
        return {"status": False, "result": f"SSH 连接失败: {str(e)}"}


@mcp.tool()
def check_ssh_session():
    """
    检查当前 SSH 会话状态。
    调用：需要确认是否已连接目标主机、连接是否仍可用时使用。
    输出：返回 connected 状态和说明。
    """
    connected = check_session(probe=True)
    return {
        "status": connected,
        "connected": connected,
        "result": "SSH 会话可用" if connected else "SSH 会话未建立或已断开",
    }


@mcp.tool()
def close_ssh_client():
    """
    关闭当前 SSH 会话。
    调用：完成排查或需要释放连接时使用。
    输出：返回关闭状态。
    """
    global ssh_session
    try:
        with session_lock:
            old_client = ssh_session.client if ssh_session else None
            ssh_session = SSHSession(None)
        _close_client(old_client)
    except Exception as error:
        with session_lock:
            ssh_session = SSHSession(None)
        return {"status": False, "result": f"SSH 会话关闭异常: {error}"}
    return {"status": True, "result": "SSH 会话已关闭"}


@mcp.tool()
def reset_session(close_connection=True):
    """
    重置当前 MCP 会话状态。
    调用：需要清空缓存的用户、进程、网络等状态时使用；默认同时关闭 SSH 连接。
    输出：返回重置状态。
    """
    global ssh_session
    with session_lock:
        old_client = ssh_session.client if ssh_session else None
    if close_connection and old_client:
        _close_client(old_client)
        with session_lock:
            ssh_session = SSHSession(None)
        return {"status": True, "result": "会话状态已重置，SSH 连接已关闭"}
    with session_lock:
        if ssh_session is None:
            ssh_session = SSHSession(old_client)
        else:
            ssh_session.client = old_client
            ssh_session.reset_analysis_state()
    return {"status": True, "result": "会话状态已重置，SSH 连接保持不变"}


@mcp.tool()
def shell(command, timeout=10, max_bytes=200000):
    """
    在已连接的 SSH 目标主机上执行 shell 命令。
    调用：需要 AI 直接通过 MCP 对目标机执行命令时使用，不使用本地 Bash；必须先调用 get_ssh_client。
    输出：返回 exec_command 的统一执行结果。
    """
    if not check_session():
        return {"status": False, "result": SESSION_ERROR}
    if not isinstance(command, str) or not command.strip():
        return {"status": False, "result": "command 不能为空"}
    try:
        timeout = max(1, min(int(timeout), 600))
    except (TypeError, ValueError):
        timeout = 10
    try:
        max_bytes = max(1024, min(int(max_bytes), 5_000_000))
    except (TypeError, ValueError):
        max_bytes = 200000

    return exec_command(ssh_session.client, command.strip(), timeout=timeout, max_bytes=max_bytes)



@mcp.tool()
def check_safeline():
    """
    检测 SafeLine WAF 可用性。
    调用：SSH 连接成功后优先调用一次，用于后续恶意命令/请求辅助判断。
    输出：返回 WAF 存活状态。
    """
    result = check_safe_safeline_result('bash -i')
    with session_lock:
        ssh_session.safeline_available = result['status'] in ('hit', 'clean')
        ssh_session.safeline_checked_at = time.monotonic()
        ssh_session.safeline_error = result.get('error', '')
    insecure_http = str(get_safeline_server() or '').lower().startswith('http://')
    transport_note = '；警告：当前使用明文 HTTP，发送的命令/文件片段可能在传输中泄露，建议尽快启用 HTTPS' if insecure_http else ''
    if result['status'] == 'hit':
        return {"status": True, "result": f"雷池 WAF 服务存活并检出测试命令{transport_note}"}
    if result['status'] == 'clean':
        return {"status": True, "result": f"雷池 WAF 服务可达，但未拦截测试命令{transport_note}"}
    if result['status'] == 'unavailable':
        return {"status": False, "result": f"雷池 WAF 不可用: {result.get('error') or '未知错误'}"}
    return {"status": False, "result": "雷池 WAF 未配置或配置无效"}


@mcp.tool()
def get_tool_inventory():
    """
    获取 MCP 工具清单。
    调用：需要了解可用纯工具和工具分组时使用；不返回任何预设排查路径。
    输出：返回工具分类。
    """
    return {
        "categories": TOOL_CATEGORIES,
    }


def ioc_source_text(text=''):
    return str(text or '')


def clamp_int(value, default, minimum=1, maximum=500):
    try:
        return max(minimum, min(int(value), maximum))
    except (TypeError, ValueError):
        return default


def trim_iocs(iocs, limit):
    limit = clamp_int(limit, 50, minimum=1, maximum=500)
    return {key: (values or [])[:limit] for key, values in (iocs or {}).items()}


def iocs_truncated(iocs, limit, extraction_limit=None):
    limit = clamp_int(limit, 50, minimum=1, maximum=500)
    extraction_limit = clamp_int(extraction_limit, 0, minimum=0, maximum=INTERNAL_IOC_LIMIT) if extraction_limit else None
    return any(
        len(values or []) > limit or (extraction_limit and len(values or []) >= extraction_limit)
        for values in (iocs or {}).values()
    )


def format_ioc_lines(iocs, limit=50, extraction_limit=None):
    lines = []
    labels = {
        'ips': 'IP',
        'domains': '域名',
        'urls': 'URL',
        'paths': '路径',
        'ports': '端口',
        'hashes': '哈希',
        'users': '用户',
        'user_agents': 'User-Agent',
    }
    limit = clamp_int(limit, 50, minimum=1, maximum=500)
    extraction_limit = clamp_int(extraction_limit, 0, minimum=0, maximum=INTERNAL_IOC_LIMIT) if extraction_limit else None
    for key, label in labels.items():
        all_values = iocs.get(key) or []
        values = all_values[:limit]
        hidden = len(all_values) - limit
        if hidden > 0 and extraction_limit and len(all_values) >= extraction_limit:
            suffix = f'（另有 {hidden} 条已提取未展示；提取达到上限，实际数量可能更多）'
        elif hidden > 0:
            suffix = f'（另有 {hidden} 条未展示）'
        else:
            suffix = ''
        lines.append(f'- {label}: {", ".join(values) + suffix if values else "未提取到"}')
    return '\n'.join(lines)


def format_timeline_lines(events, limit=10):
    if not events:
        return '未提取到常见时间格式的事件线索'
    limit = clamp_int(limit, 10, minimum=1, maximum=100)
    rows = ['| 时间 | 事件 | 来源 |', '|---|---|---|']
    for item in events[:limit]:
        event = item['event'].replace('|', '/')
        source_name = item['source'].replace('|', '/')
        rows.append(f'| {item["time"]} | {event} | {source_name} |')
    if len(events) > limit:
        rows.append(f'| ... | 另有 {len(events) - limit} 条时间线线索未展示 | ... |')
    return '\n'.join(rows)


def summarize_input_sections(content, max_sections=12):
    rows = []
    current = ''
    body = []
    for line in content.splitlines():
        if line.startswith('## '):
            if current:
                rows.append((current, body))
            current = line[3:].strip()
            body = []
        elif current and line.strip():
            body.append(line.strip())
    if current:
        rows.append((current, body))

    findings = []
    for name, lines in rows[:max_sections]:
        section_text = '\n'.join(lines) if lines else '无输出'
        text = next((line for line in lines if not line.startswith('[status=')), section_text)
        risk = infer_risk_level(section_text)
        evidence, _ = truncate_text(text, max_chars=160)
        findings.append(f'| {name} | {evidence.replace("|", "/")} | {risk} | 最近输入材料 |')
    if not findings:
        findings.append('| 输入材料 | 暂无可结构化的工具输出 | 信息 | 证据不足 |')
    return '\n'.join(findings)


def parse_json_like(value, default):
    if value is None or value == '':
        return default
    parsed = value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return default
    if isinstance(parsed, type(default)):
        return parsed
    if isinstance(default, list) and isinstance(parsed, dict):
        return [parsed] if parsed else []
    return default


def sanitize_report_cell(value, max_chars=240):
    text = ' '.join(('' if value is None else str(value)).split())
    text = text.replace('|', '/')
    text, truncated = truncate_text(text, max_chars=max_chars)
    return text.replace('\n[TRUNCATED] output exceeded limit', '…') if truncated else text


def normalize_report_risk(value):
    risk = str(value or '信息').strip()
    aliases = {'高危': '高', '严重': '高', 'high': '高', 'critical': '高', '中危': '中', 'medium': '中', '低危': '低', 'low': '低', 'info': '信息', 'informational': '信息'}
    risk = aliases.get(risk, aliases.get(risk.lower(), risk))
    return risk if risk in VALID_REPORT_RISKS else '信息'


def normalize_evidence(value, evidence_limit=3):
    if value is None:
        items = []
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        items = [value]
    evidence = [sanitize_report_cell(item, max_chars=320) for item in items if item is not None and str(item).strip()]
    return evidence[:evidence_limit] or ['证据不足，需人工复核']


def first_present(mapping, keys):
    for key in keys:
        value = mapping.get(key)
        if value is not None and str(value).strip():
            return value
    return None


def normalize_findings(findings, evidence_limit=3, max_findings=12):
    raw = parse_json_like(findings, {})
    if isinstance(raw, dict) and isinstance(raw.get('findings'), list):
        source = raw['findings']
    elif isinstance(raw, dict) and isinstance(raw.get('data'), list):
        source = raw['data']
    elif isinstance(raw, dict) and any(key in raw for key in ('status', 'result', 'data', 'error', 'meta')):
        source = []
    else:
        source = parse_json_like(findings, [])
    normalized = []
    for index, item in enumerate(source[:max_findings], start=1):
        if not isinstance(item, dict):
            item = {'item': f'检测项 {index}', 'finding': item}
        name = first_present(item, ['item', 'name', 'title', '检测项', '检查项', '项目']) or f'检测项 {index}'
        path = first_present(item, ['path', 'file', '路径', '文件'])
        finding = first_present(item, ['finding', 'summary', 'result', 'description', 'event', '关键发现', '发现', '结果', '描述', '事件'])
        evidence_value = first_present(item, ['evidence', 'evidences', 'basis', 'proof', '依据', '证据', '证明'])
        risk_value = first_present(item, ['risk', '风险', '风险等级'])
        risk = normalize_report_risk(risk_value)
        if finding is None:
            if risk == '未发现明显异常':
                finding = '未发现明显异常'
            else:
                finding = f'发现{name}' if risk_value is not None or path is not None or evidence_value is not None else '待检测，需人工复核'
        if path is not None:
            finding = f'{finding}（路径：{path}）'
        evidence = normalize_evidence(evidence_value, evidence_limit=evidence_limit)
        if path is not None and all(str(path) not in entry for entry in evidence):
            evidence = [sanitize_report_cell(path, max_chars=320)] + evidence[:max(0, evidence_limit - 1)]
        normalized.append({
            'item': sanitize_report_cell(name, max_chars=120),
            'finding': sanitize_report_cell(finding, max_chars=240),
            'risk': risk,
            'evidence': evidence,
        })
    return normalized


def format_findings_rows(findings):
    if not findings:
        return '| 检测状态 | 暂无结构化检测结果 | 信息 | 需补充 findings 列表或人工复核 |'
    rows = []
    for finding in findings:
        evidence = '<br>'.join(finding['evidence'])
        rows.append(f'| {finding["item"]} | {finding["finding"]} | {finding["risk"]} | {evidence} |')
    return '\n'.join(rows)


def normalize_report_timeline(timeline, max_events=50):
    raw = parse_json_like(timeline, {})
    if isinstance(raw.get('data'), dict) and isinstance(raw['data'].get('events'), list):
        source = raw['data']['events']
    elif isinstance(raw.get('data'), dict) and isinstance(raw['data'].get('timeline_events'), list):
        source = raw['data']['timeline_events']
    elif isinstance(raw.get('data'), list):
        source = raw['data']
    elif isinstance(raw.get('events'), list):
        source = raw['events']
    elif isinstance(raw.get('timeline_events'), list):
        source = raw['timeline_events']
    elif any(key in raw for key in ('status', 'result', 'data', 'error', 'meta')):
        source = []
    else:
        source = parse_json_like(timeline, [])
    events = []
    for index, item in enumerate(source[:max_events], start=1):
        if not isinstance(item, dict):
            item = {'event': item}
        event = first_present(item, ['event', 'description', 'desc', 'meaning', '事件', '描述', '含义']) or '事件待复核'
        events.append({
            'time': sanitize_report_cell(first_present(item, ['time', 'timestamp', 'date', '时间', '日期']) or '未知时间', max_chars=80),
            'event': sanitize_report_cell(event, max_chars=240),
            'source': sanitize_report_cell(first_present(item, ['source', 'tool', 'src_ip', '来源', '工具', '源IP']) or f'时间线 {index}', max_chars=120),
        })
    return events


def normalize_report_iocs(iocs, max_iocs_per_type=50):
    source = parse_json_like(iocs, {})
    if isinstance(source.get('iocs'), dict):
        source = source['iocs']
    elif isinstance(source.get('data'), dict) and isinstance(source['data'].get('iocs'), dict):
        source = source['data']['iocs']
    elif isinstance(source.get('data'), dict):
        source = source['data']
    aliases = {
        'ips': ('ips', 'ip', 'IP', '地址'),
        'domains': ('domains', 'domain', '域名'),
        'urls': ('urls', 'url', 'URL', '链接'),
        'paths': ('paths', 'path', 'files', 'file', '路径', '文件'),
        'ports': ('ports', 'port', '端口'),
        'hashes': ('hashes', 'hash', 'md5', 'sha1', 'sha256', '哈希'),
        'users': ('users', 'user', 'account', 'accounts', '用户', '账号', '账户'),
        'user_agents': ('user_agents', 'user_agent', 'ua', 'User-Agent', 'UA'),
    }
    normalized = {}
    limit = clamp_int(max_iocs_per_type, 50, minimum=1, maximum=INTERNAL_IOC_LIMIT)
    for key, names in aliases.items():
        values = []
        for name in names:
            raw = source.get(name) if isinstance(source, dict) else None
            if raw is None:
                continue
            if isinstance(raw, (list, tuple, set)):
                values.extend(raw)
            else:
                values.append(raw)
        seen = set()
        limited = []
        for value in values:
            text = sanitize_report_cell(value, max_chars=240)
            if not text or text in seen:
                continue
            seen.add(text)
            limited.append(text)
            if len(limited) >= limit:
                break
        normalized[key] = limited
    return normalized


def merge_report_iocs(primary, secondary, limit=INTERNAL_IOC_LIMIT):
    merged = {}
    keys = list(dict.fromkeys(list((primary or {}).keys()) + list((secondary or {}).keys())))
    limit = clamp_int(limit, INTERNAL_IOC_LIMIT, minimum=1, maximum=INTERNAL_IOC_LIMIT)
    for key in keys:
        seen = set()
        values = []
        for source in (primary or {}, secondary or {}):
            for value in source.get(key) or []:
                text = sanitize_report_cell(value, max_chars=240)
                if not text or text in seen:
                    continue
                seen.add(text)
                values.append(text)
                if len(values) >= limit:
                    break
            if len(values) >= limit:
                break
        merged[key] = values
    return merged


def merge_report_timeline(primary, secondary, max_events=50):
    merged = []
    seen = set()
    max_events = clamp_int(max_events, 50, minimum=1, maximum=200)
    for event in list(primary or []) + list(secondary or []):
        item = {
            'time': sanitize_report_cell(event.get('time') or event.get('timestamp') or event.get('date') or '未知时间', max_chars=80),
            'event': sanitize_report_cell(event.get('event') or event.get('description') or event.get('desc') or '事件待复核', max_chars=240),
            'source': sanitize_report_cell(event.get('source') or event.get('tool') or event.get('src_ip') or 'input', max_chars=120),
        }
        key = (item['time'], item['event'], item['source'])
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
        if len(merged) >= max_events:
            break
    return merged


def first_text_match(text, patterns):
    for pattern in patterns:
        match = re.search(pattern, text or '', re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ''


def normalize_case_context(case, legacy_content=''):
    data = parse_json_like(case, {})
    if not isinstance(data, dict):
        data = {}
    return {
        'title': sanitize_report_cell(data.get('title') or data.get('case') or data.get('name') or data.get('案件名称') or first_text_match(legacy_content, [r'(?:案件名称|案件标题|title|case)\s*[:=：]\s*([^\r\n]+)']) or '', max_chars=160),
        'target': sanitize_report_cell(data.get('target') or data.get('ip') or data.get('目标') or first_text_match(legacy_content, [r'(?:目标信息|目标|target|ip)\s*[:=：]\s*([^\r\n]+)']) or '', max_chars=240),
        'system': sanitize_report_cell(data.get('system') or data.get('os') or data.get('系统') or first_text_match(legacy_content, [r'(?:系统信息|操作系统|系统|system|os)\s*[:=：]\s*([^\r\n]+)']) or '', max_chars=160),
        'webroot': sanitize_report_cell(data.get('webroot') or data.get('web_root') or data.get('Web根目录') or data.get('web根目录') or first_text_match(legacy_content, [r'(?:Web根目录|webroot|web_root)\s*[:=：]\s*([^\r\n]+)']) or '', max_chars=240),
    }


def normalize_answers(answers):
    data = parse_json_like(answers, {})
    if isinstance(data, dict) and isinstance(data.get('answers'), dict):
        return data['answers']
    if isinstance(data, dict) and isinstance(data.get('data'), dict):
        return data['data']
    if isinstance(data, dict) and any(key in data for key in ('status', 'result', 'data', 'error', 'meta')):
        items = data.get('data') if isinstance(data.get('data'), list) else []
    elif data:
        return data
    else:
        items = parse_json_like(answers, [])
    normalized = {}
    for index, item in enumerate(items, start=1):
        if isinstance(item, dict):
            key = first_present(item, ['question', 'item', 'name', 'title', '问题', '题目', '检测项']) or f'答案 {index}'
            value = first_present(item, ['answer', 'value', 'result', 'finding', 'description', '答案', '结果', '关键发现', '描述']) or ''
        else:
            key = f'答案 {index}'
            value = item
        if str(key or '').strip() or str(value or '').strip():
            normalized[str(key or f'答案 {index}')] = value
    return normalized


def format_answers_lines(answers):
    data = normalize_answers(answers)
    if not data:
        return '- 未提供结构化答案。'
    lines = []
    for key, value in data.items():
        lines.append(f'- {sanitize_report_cell(key, max_chars=80)}：{sanitize_report_cell(value, max_chars=240)}')
    return '\n'.join(lines)


def build_answers_tail(answers):
    return f'## 答案\n\n{format_answers_lines(answers)}'


def build_delivery_preview(case_context, legacy_summary, source_note, evidence_status, findings_rows, ioc_text, timeline_text, answers, report_path):
    title = case_context.get('title') or '未提供'
    target = case_context.get('target') or '未提供'
    system = case_context.get('system') or '未提供'
    webroot = case_context.get('webroot') or '未提供'
    return f'''## 案件背景

- 案件标题：{title}
- 目标信息：{target}
- 系统信息：{system}
- Web 根目录：{webroot}
- 证据状态：{evidence_status}

## 摘要

- 材料来源：{source_note}

```text
{legacy_summary}
```

## 检测结果表

| 检测项 | 关键发现 | 风险 | 依据 |
|---|---|---|---|
{findings_rows}

## IOC 摘要

{ioc_text}

## 时间线摘要

{timeline_text}

## 完整报告

报告已生成：{report_path}

{build_answers_tail(answers)}
'''


def build_attack_source(findings, timeline_events, iocs):
    lines = ['## findings']
    for item in findings:
        if item.get('risk') not in {'高', '中', '低'}:
            continue
        lines.append(f'{item["item"]} {item["finding"]} {item["risk"]} {" ".join(item["evidence"])}')
    lines.append('## timeline')
    for event in timeline_events:
        lines.append(f'{event["time"]} {event["event"]} {event["source"]}')
    lines.append('## iocs')
    for key, values in iocs.items():
        if values:
            lines.append(f'{key}: {", ".join(values)}')
    return '\n'.join(lines)


def build_structured_summary(findings, timeline_events, iocs):
    lines = []
    for item in findings[:5]:
        lines.append(f'- {item["item"]}: {item["finding"]}（{item["risk"]}）')
    for event in timeline_events[:5]:
        lines.append(f'- {event["time"]}: {event["event"]}')
    for key, values in iocs.items():
        if values:
            lines.append(f'- {key}: {", ".join(values[:10])}')
    return '\n'.join(lines) or '已提供结构化输入，但未形成可展示摘要。'


def has_public_network_ioc(iocs):
    for ip in iocs.get('ips') or []:
        try:
            address = ipaddress.ip_address(str(ip))
        except ValueError:
            continue
        if not (address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified):
            return True
    return any(iocs.get(key) for key in ('domains', 'urls'))


def write_report_file(report):
    report_dir = safe_local_subdir('downloads/reports') / get_run_id()
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / 'report.md'
    index = 2
    while report_path.exists():
        report_path = report_dir / f'report_{index}.md'
        index += 1
    report_path.write_text(report, encoding='utf-8')
    return str(report_path)


@mcp.tool()
def extract_iocs(text='', limit=100):
    """
    从输入文本或最近一次输入材料提取 IOC。
    调用：需要从日志、进程、WebShell 或其他工具输出中汇总 IP、域名、URL、路径和端口时使用。
    输出：返回去重后的 IOC 字段，不做外部情报查询；limit 控制每类 IOC 最大数量。
    """
    source = ioc_source_text(text)
    if not source.strip():
        return normalize_tool_result('extract_iocs', {"status": False, "result": "没有可提取 IOC 的文本；请传入 text 或已有工具输出"})
    limit = clamp_int(limit, 100, minimum=1, maximum=500)
    iocs = extract_ioc_values(source, limit=INTERNAL_IOC_LIMIT)
    visible_iocs = trim_iocs(iocs, limit)
    truncated = iocs_truncated(iocs, limit, extraction_limit=INTERNAL_IOC_LIMIT)
    result = format_ioc_lines(iocs, limit=limit, extraction_limit=INTERNAL_IOC_LIMIT)
    return {
        "status": True,
        "result": result,
        "iocs": visible_iocs,
        "data": {"iocs": visible_iocs},
        "error": "",
        "meta": {"tool": "extract_iocs", "risk": "信息", "empty": not any(iocs.values()), "truncated": truncated, "kind": "dict"},
    }


@mcp.tool()
def generate_timeline(text='', max_events=100):
    """
    从输入文本或最近输入材料生成事件时间线。
    调用：需要复盘入侵过程、梳理日志/文件/登录事件先后顺序时使用。
    输出：返回按原始材料出现顺序整理的 markdown 时间线表。
    """
    source = ioc_source_text(text)
    if not source.strip():
        return normalize_tool_result('generate_timeline', {'status': False, 'result': '没有可提取时间线的文本；请传入 text，或先提供已有工具输出'})
    max_events = clamp_int(max_events, 100, minimum=1, maximum=500)
    events = extract_timeline_events(source, limit=max_events)
    if not events:
        return normalize_tool_result('generate_timeline', '未提取到常见时间格式的事件线索')
    rows = ['| 时间 | 事件 | 来源 |', '|---|---|---|']
    for item in events:
        event = item['event'].replace('|', '/')
        source_name = item['source'].replace('|', '/')
        rows.append(f'| {item["time"]} | {event} | {source_name} |')
    result = '\n'.join(rows)
    normalized = normalize_tool_result('generate_timeline', result)
    normalized['data'] = {'events': events}
    return normalized


@mcp.tool()
def analyze_attack_chain(text='', max_stages=8, evidence_limit=3, include_unobserved=True, max_timeline_events=30, max_iocs_per_type=50):
    """
    基于输入文本或最近输入材料分析攻击链阶段。
    调用：需要让 AI 客户端复盘初始访问、落地执行、提权、持久化、外联和影响动作时使用。
    输出：返回攻击阶段表、路径判断、IOC 和时间线数据；max_iocs_per_type 控制 IOC 展示数量。
    """
    source = ioc_source_text(text)
    if not source.strip():
        return normalize_tool_result('analyze_attack_chain', {'status': False, 'result': '没有可分析攻击链的文本；请传入 text，或先提供已有工具输出'})
    max_stages = clamp_int(max_stages, 8, minimum=1, maximum=8)
    evidence_limit = clamp_int(evidence_limit, 3, minimum=1, maximum=10)
    max_timeline_events = clamp_int(max_timeline_events, 30, minimum=1, maximum=200)
    max_iocs_per_type = clamp_int(max_iocs_per_type, 50, minimum=1, maximum=500)
    ioc_extract_limit = INTERNAL_IOC_LIMIT
    iocs = extract_ioc_values(source, limit=ioc_extract_limit)
    timeline_events = extract_timeline_events(source, limit=max_timeline_events)
    attack_flow = infer_attack_flow(
        source,
        iocs=iocs,
        timeline_events=timeline_events,
        max_items=max_stages,
        evidence_limit=evidence_limit,
        include_unobserved=include_unobserved,
    )
    result = f'''## 攻击路径判断

{attack_flow['summary']}

## 攻击阶段表

{attack_flow['markdown']}

## IOC 摘要

{format_ioc_lines(iocs, limit=max_iocs_per_type, extraction_limit=ioc_extract_limit)}

## 时间线摘要

{format_timeline_lines(timeline_events, limit=min(max_timeline_events, 20))}
'''
    has_evidence = any(stage['status'] == '发现线索' for stage in attack_flow['stages'])
    has_network_iocs = any(iocs.get(key) for key in ('ips', 'domains', 'urls'))
    truncated = iocs_truncated(iocs, max_iocs_per_type, extraction_limit=ioc_extract_limit)
    return {
        'status': True,
        'result': result,
        'data': {
            'iocs': trim_iocs(iocs, max_iocs_per_type),
            'timeline_events': timeline_events,
            'attack_flow': attack_flow,
        },
        'error': '',
        'meta': {
            'tool': 'analyze_attack_chain',
            'risk': '中' if has_evidence or has_network_iocs else '信息' if any(iocs.values()) or timeline_events else '未发现明显异常',
            'empty': not has_evidence and not any(iocs.values()) and not timeline_events,
            'truncated': truncated,
            'kind': 'dict',
        },
    }


@mcp.tool()
def generate_report(extra_context='', case=None, findings=None, timeline=None, iocs=None, answers=None, output_mode='both', include_iocs=True, report_profile='standard', focus='', max_summary_chars=1200, max_findings=12, max_timeline_events=50, max_iocs_per_type=50, evidence_limit=3, include_timeline=True, include_next_tools=False):
    """
    调查结束前必须调用的最终汇总工具，优先基于 AI 按模板整理好的 case/findings/timeline/iocs/answers 渲染规范化结论报告。
    调用：交付结论、结束调查或用户要求总结前必须调用；AI 客户端应先过滤长日志并按模板填充结构化字段，不要把长日志直接塞入 extra_context。
    推荐模板：case={案件名称/目标/系统/Web根目录}；findings=[{检测项,关键发现,风险,依据}]；timeline=[{时间,事件,来源}]；iocs={IP,域名,URL,路径,端口,哈希,用户,User-Agent}；answers={题号:答案}。
    输出：默认 output_mode=both，同时返回完整 markdown 并写入报告文件；output_mode=file 仅写入报告文件并返回短预览和 report_path。
    要求：检测结果表字段固定为 | 检测项 | 关键发现 | 风险 | 依据 |；风险等级只能使用 高 / 中 / 低 / 信息 / 未发现明显异常；证据不足时标注 待检测 或 需人工复核，不得编造完整攻击链。
    """
    legacy_content = ioc_source_text(extra_context)
    has_legacy_content = bool(legacy_content.strip())
    profiles = {
        'standard': '标准应急报告',
        'executive': '管理层摘要，突出影响、风险和处置优先级',
        'technical': '技术复盘，突出证据、IOC、时间线和工具依据',
        'handoff': '交接报告，突出已做检查、未决问题和证据缺口',
    }
    report_profile = str(report_profile or 'standard').strip().lower()
    if report_profile not in profiles:
        report_profile = 'standard'
    output_mode = str(output_mode or 'both').strip().lower()
    if output_mode not in REPORT_OUTPUT_MODES:
        output_mode = 'both'
    max_summary_chars = clamp_int(max_summary_chars, 1200, minimum=300, maximum=10000)
    max_findings = clamp_int(max_findings, 12, minimum=1, maximum=50)
    max_timeline_events = clamp_int(max_timeline_events, 50, minimum=1, maximum=200)
    max_iocs_per_type = clamp_int(max_iocs_per_type, 50, minimum=1, maximum=500)
    evidence_limit = clamp_int(evidence_limit, 3, minimum=1, maximum=10)

    case_context = normalize_case_context(case, legacy_content)
    normalized_findings = normalize_findings(findings, evidence_limit=evidence_limit, max_findings=max_findings)
    timeline_events = normalize_report_timeline(timeline, max_events=max_timeline_events)
    normalized_iocs = normalize_report_iocs(iocs, max_iocs_per_type=INTERNAL_IOC_LIMIT)
    normalized_answers = normalize_answers(answers)
    has_case_context = any(case_context.values())
    has_structured_evidence = any((normalized_findings, timeline_events, any(normalized_iocs.values())))
    has_structured_input = any((has_case_context, has_structured_evidence, normalized_answers))
    structured_summary = build_structured_summary(normalized_findings, timeline_events, normalized_iocs) if has_structured_input else ''
    if has_legacy_content and structured_summary:
        legacy_summary_source = legacy_content + '\n' + structured_summary
    elif has_legacy_content:
        legacy_summary_source = legacy_content
    elif structured_summary:
        legacy_summary_source = structured_summary
    else:
        legacy_summary_source = '未提供 extra_context 或结构化证据；尚未执行检测或当前上下文没有可汇总证据。'
    legacy_summary, summary_truncated = truncate_text(legacy_summary_source, max_chars=max_summary_chars)

    legacy_findings_rows = ''
    legacy_findings_for_attack = []
    if has_legacy_content:
        remaining_findings = max_findings - len(normalized_findings)
        if remaining_findings > 0:
            legacy_findings_rows = summarize_input_sections(legacy_content, max_sections=remaining_findings)
        legacy_findings_for_attack = normalize_findings([
            {'item': '兼容输入摘要', 'finding': '从 extra_context 生成的兼容检测行', 'risk': infer_risk_level(legacy_content), 'evidence': [legacy_summary]}
        ], evidence_limit=evidence_limit, max_findings=1)
    structured_findings_rows = format_findings_rows(normalized_findings) if normalized_findings else ''
    if structured_findings_rows and legacy_findings_rows:
        findings_rows = structured_findings_rows + '\n' + legacy_findings_rows
    elif structured_findings_rows:
        findings_rows = structured_findings_rows
    elif legacy_findings_rows:
        findings_rows = legacy_findings_rows
    else:
        findings_rows = format_findings_rows([])
    findings_for_attack = normalized_findings + legacy_findings_for_attack

    if has_legacy_content:
        legacy_iocs = extract_ioc_values(legacy_content, limit=INTERNAL_IOC_LIMIT)
        normalized_iocs = merge_report_iocs(normalized_iocs, legacy_iocs, limit=INTERNAL_IOC_LIMIT)
        legacy_timeline_events = extract_timeline_events(legacy_content, limit=max_timeline_events)
        timeline_events = merge_report_timeline(timeline_events, legacy_timeline_events, max_events=max_timeline_events)

    attack_parts = [legacy_content, build_attack_source(findings_for_attack, timeline_events, normalized_iocs)]
    attack_source = '\n'.join(part for part in attack_parts if part)
    attack_flow = infer_attack_flow(attack_source, iocs=normalized_iocs, timeline_events=timeline_events, evidence_limit=evidence_limit)
    ioc_text = format_ioc_lines(normalized_iocs, limit=max_iocs_per_type, extraction_limit=INTERNAL_IOC_LIMIT) if include_iocs else '未启用 IOC 摘要展示'
    timeline_text = format_timeline_lines(timeline_events, limit=min(max_timeline_events, 15)) if include_timeline else '未启用时间线摘要'
    focus_line = f'- 关注方向：{focus}' if str(focus or '').strip() else '- 关注方向：未指定，按通用 Linux 应急响应组织。'
    title_line = f'- 案件标题：{case_context["title"]}' if case_context['title'] else '- 案件标题：未提供。'
    target_line = f'- 目标信息：{case_context["target"]}' if case_context['target'] else '- 目标信息：未提供。'
    system_line = f'- 系统信息：{case_context["system"]}' if case_context['system'] else '- 系统信息：未提供。'
    webroot_line = f'- Web 根目录：{case_context["webroot"]}' if case_context['webroot'] else '- Web 根目录：未提供。'
    if has_structured_evidence:
        evidence_status = '已提供结构化证据，报告按 findings/timeline/iocs 渲染。'
        source_note = '结构化输入'
    elif has_structured_input:
        evidence_status = '待检测：已提供结构化案件或答案信息，但未提供 findings/timeline/iocs 工具证据。'
        source_note = '结构化案件背景'
    elif has_legacy_content:
        evidence_status = '未提供完整结构化证据，已使用 extra_context 兼容摘要；建议后续改为 findings/timeline/iocs。'
        source_note = 'extra_context 兼容摘要'
    else:
        evidence_status = '待检测：未提供 extra_context 或结构化证据。'
        source_note = '无输入材料'
    suspicious_findings = any(item['risk'] in {'高', '中'} for item in findings_for_attack)
    suspicious_attack_flow = any(
        stage['status'] == '发现线索' and any(not evidence.startswith('IOC: ') for evidence in stage.get('evidence', []))
        for stage in attack_flow['stages']
    )
    if not has_structured_evidence and not has_legacy_content:
        risk_note = '未提供可汇总的工具证据，不能判断是否存在入侵、WebShell、持久化或影响动作；所有结论均应标注为待检测或需人工复核。'
    elif suspicious_findings or suspicious_attack_flow or has_public_network_ioc(normalized_iocs) or '[!]' in legacy_content:
        risk_note = '发现可疑线索，需结合原始日志和业务上下文人工复核。'
    else:
        risk_note = '当前结构化摘要未见明确高危线索，仍需结合工具失败、权限不足和截断情况复核。'
    truncated_note = '；摘要已截断，完整原始材料未写入报告正文' if summary_truncated else ''
    next_tools = NO_PRESET_NEXT_TOOLS

    report = f'''```text
{AUTOIR_MCP_BANNER}
```

## 案件背景

{title_line}
{target_line}
{system_line}
{webroot_line}
{focus_line}
- 报告画像：{report_profile}（{profiles[report_profile]}）
- 证据状态：{evidence_status}

## 摘要

- 材料来源：{source_note}{truncated_note}
- 关键摘要：

```text
{legacy_summary}
```

## 检测结果表

| 检测项 | 关键发现 | 风险 | 依据 |
|---|---|---|---|
{findings_rows}

## 检测状态说明

- 未发现明显异常：仅表示当前材料未见明确异常，不代表目标绝对安全。
- 检测失败 / 权限不足 / 输出截断：必须按工具原始结果呈现，不能归类为无异常。
- 待检测 / 需人工复核：表示当前证据不足，不能编造结论。
- 结构化输入优先：长日志应先过滤、切片并整理为 findings/timeline/iocs 后再生成报告。

## IOC 摘要

{ioc_text}

## 时间线摘要

{timeline_text}

## 结构化答案

{format_answers_lines(normalized_answers)}

## 攻击流程分析

{attack_flow['markdown']}

### 攻击路径判断

{attack_flow['summary']}

## 风险分析

{risk_note}

## 处置原则

- 仅将工具输出作为证据来源，不能把单条线索直接写成已确认失陷。
- 风险定性必须结合原始日志、业务上下文、权限边界和时间线交叉验证。
- 报告中标注“需人工复核”的阶段必须回看原始证据后再定性。

## AI 编排说明

{next_tools}
'''
    preview, preview_truncated = truncate_text(report, max_chars=max_summary_chars)
    if output_mode == 'inline':
        return report
    if output_mode == 'preview':
        return {'status': True, 'result': preview, 'report_path': '', 'truncated': preview_truncated}
    report_path = write_report_file(report)
    delivery = build_delivery_preview(
        case_context,
        legacy_summary,
        source_note,
        evidence_status,
        findings_rows,
        ioc_text,
        timeline_text,
        answers,
        report_path,
    )
    if output_mode == 'both':
        return {'status': True, 'result': report, 'preview': delivery, 'report_path': report_path, 'truncated': preview_truncated}
    return {'status': True, 'result': delivery, 'report_path': report_path, 'truncated': preview_truncated}


def command_format(check, command):
    return 'env -i /usr/bin/' + command if check else command


def quote_remote_path(path):
    return shlex.quote(str(path))


def detect_malicious_text(content, use_safeline=True, warnings=None):
    content = str(content or '')
    malicious_local = check_safe_local(content)
    if malicious_local:
        return malicious_local
    if not use_safeline:
        return ''
    with session_lock:
        available = bool(
            ssh_session.safeline_available
            and time.monotonic() - ssh_session.safeline_checked_at < 300
        )
    if not available:
        return ''
    # Remote WAF lookups are expensive; only send command/webshell-like input.
    if len(content) > 8192 or not SAFELINE_HINT_PATTERN.search(content):
        return ''
    result = check_safe_safeline_result(content)
    if result['status'] == 'unavailable':
        with session_lock:
            ssh_session.safeline_error = result.get('error', '')
        if warnings is not None and not any('SafeLine' in item for item in warnings):
            warnings.append(f"[WARN] SafeLine 查询失败，部分内容未经过 WAF 检测: {result.get('error') or '未知错误'}")
        return ''
    return result['content'] if result['status'] == 'hit' else ''


def file_md5(path):
    digest = hashlib.md5()
    with open(path, 'rb') as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def empty_result(message='未发现明显异常'):
    return message


def command_failure(result, action='命令执行失败'):
    detail = result.get('error') or result.get('stderr') or result.get('result') or '无错误详情'
    return f'{action}: {detail}'


def count_ips_from_lines(lines):
    counts = {}
    for line in lines:
        ip_match = IPV4_PATTERN.search(line)
        if ip_match:
            ip = ip_match.group()
            counts[ip] = counts.get(ip, 0) + 1
    return counts


def brute_force_success_ips(failed_counts, accepted_counts, threshold=5, limit=20):
    """Return IPs with repeated failures followed by at least one success."""
    correlated = [
        (ip, int(failures), int(accepted_counts.get(ip, 0)))
        for ip, failures in failed_counts.items()
        if failures >= threshold and accepted_counts.get(ip, 0) > 0
    ]
    correlated.sort(key=lambda item: (-item[1], item[0]))
    return correlated[:limit]


def invalid_user_counts(lines, limit=20):
    counts = collections.Counter()
    for line in lines:
        for match in re.finditer(r'Invalid user\s+(\S+)', line, re.I):
            counts[match.group(1)] += 1
    return counts.most_common(limit)


def format_ip_counts(counts, label, limit=50):
    if not counts:
        return ''
    ordered = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    lines = [f'ip: {ip}\tcount: {count}\t[!] {label}' for ip, count in ordered[:limit]]
    if len(ordered) > limit:
        lines.append(f'[TRUNCATED] 共 {len(ordered)} 个来源 IP，仅展示前 {limit} 个')
    return '\n'.join(lines)


HIJACK_VARIABLES = (
    'LD_PRELOAD', 'LD_AOUT_PRELOAD', 'LD_ELF_PRELOAD', 'LD_LIBRARY_PATH',
    'PROMPT_COMMAND', 'BASH_ENV', 'ENV', 'PS4',
)


def check_export(filename, data):
    seen = set()
    for raw_line in (data or '').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        match = re.match(r'(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)', line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        finding = None
        if key == 'PATH':
            # Normal PATH assignments are common; only writable/relative
            # entries are worth escalating during incident response.
            parts = value.strip('"\'').split(':')
            if any(part in ('', '.') or part in ('/tmp', '/var/tmp', '/dev/shm') or part.startswith(('/tmp/', '/var/tmp/', '/dev/shm/')) for part in parts):
                finding = f'[!] PATH 包含可疑目录: {value[:200]}'
        elif key in HIJACK_VARIABLES:
            finding = f'[!] 环境变量劫持: {key}={value[:200]}'
        if finding and finding not in seen:
            seen.add(finding)
            ssh_session.hijack_output.append(f'filename: {filename}\t{finding}')


def process_files(file_list, base_path='', warnings=None):
    for file in dict.fromkeys(file_list):
        path = f'{base_path}{file}' if base_path else file
        command = command_format(ssh_session.hijack, f'cat {quote_remote_path(path)}')
        result = exec_command(ssh_session.client, command)

        if result['status'] and result['result']:
            check_export(path, result['result'])
        elif warnings is not None:
            kind = classify_remote_result(result)
            if kind not in ('ok', 'not_found'):
                issue = remote_result_issue(result, path, '读取')
                if issue:
                    warnings.append(issue)


@mcp.tool()
def check_hijack():
    """
    检查 shell 初始化文件中的环境变量劫持。
    调用：怀疑 PATH、LD_PRELOAD、PROMPT_COMMAND 等被篡改时使用。
    输出：返回可疑文件、变量和值。
    """

    if not check_session():
        return SESSION_ERROR

    ssh_session.hijack = False
    ssh_session.hijack_output = []
    warnings = []

    common_files = [
        '/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc',
        '/etc/bashrc', '/etc/bash.bashrc', '/etc/profile', '/etc/environment',
        '/etc/csh.login', '/etc/csh.cshrc', '/etc/zshrc', '/etc/zsh/zshrc', '/etc/zsh/zshenv',
    ]
    home_files = ['.bashrc', '.bash_profile', '.tcshrc', '.cshrc', '.profile', '.zshrc', '.zshenv', '.pam_environment']

    result = exec_command(ssh_session.client, 'ls -al .')
    if result['status'] and result['result'][:5] != 'total':
        result = exec_command(ssh_session.client, 'env -i /usr/bin/ls -al .')
        if result['status'] and result['result'][:5] == 'total':
            ssh_session.hijack = True

    process_files(common_files, warnings=warnings)

    profile_d_files = []
    profile_d_command = command_format(ssh_session.hijack, 'ls -al /etc/profile.d/')
    profile_d_result = exec_command(ssh_session.client, profile_d_command)
    if profile_d_result['status'] and profile_d_result['result']:
        profile_d_files = [file['filename'] for file in get_file_list(profile_d_result['result']).values()]
    process_files(profile_d_files, '/etc/profile.d/', warnings=warnings)

    home_dir_command = command_format(ssh_session.hijack, 'ls -al /home')
    home_dir_result = exec_command(ssh_session.client, home_dir_command)
    if home_dir_result['status'] and home_dir_result['result']:
        ssh_session.user_list = [file['filename'] for file in get_file_list(home_dir_result['result']).values()]
        process_files([f'/home/{user}/{f}' for user in ssh_session.user_list for f in home_files], warnings=warnings)

    return append_warnings('\n'.join(ssh_session.hijack_output) or empty_result(), warnings)


def extract_users_from_output(output):
    return [line.strip().split()[-1] for line in output.splitlines() if line.strip()]


def get_group():
    result = exec_command(ssh_session.client, 'cat /etc/group')
    if result['status'] and result['result']:
        for line in result['result'].splitlines():
            parts = line.strip().split(':')
            if len(parts) >= 4:
                group_name, _, _, users = parts
                ssh_session.group_list[group_name] = [user.strip() for user in users.split(',') if user.strip()]


def load_home_users(force=False, warnings=None):
    with state_lock:
        if ssh_session.user_list and not force:
            return list(ssh_session.user_list)
    result = exec_command(ssh_session.client, 'ls -al /home')
    kind = classify_remote_result(result)
    users = []
    if kind == 'ok':
        users = [file['filename'] for file in get_file_list(result['result']).values()]
    elif kind != 'not_found' and warnings is not None:
        warnings.append(remote_result_issue(result, '/home', '列出用户目录'))
    with state_lock:
        if users:
            ssh_session.user_list = users
        ssh_session.user_list_time = time.monotonic()
        return list(ssh_session.user_list)


@mcp.tool()
def check_home():
    """
    枚举 /home 用户目录。
    调用：用户排查的基础步骤，可为 history、ssh key、rc 文件检测提供用户列表。
    输出：返回发现的用户目录名。
    """

    if not check_session():
        return SESSION_ERROR

    warnings = []
    users = load_home_users(warnings=warnings)
    return append_warnings('\n'.join(users) or empty_result('未发现 /home 用户目录'), warnings)


HISTORY_SUSPICIOUS_PATTERNS = (
    (re.compile(r'(?:curl|wget)[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b', re.I), '下载内容直接交给 shell 执行'),
    (re.compile(r'\b(?:nc|ncat)\b[^\n]*(?:\s-e\s|--exec\b)|/dev/tcp/', re.I), '可能的反弹 shell'),
    (re.compile(r'\b(?:bash|sh)\s+-i\b', re.I), '交互式 shell'),
    (re.compile(r'\bsocat\b[^\n]*\bexec:', re.I), '可能的反弹 shell'),
    (re.compile(r'\bbase64\b[^\n]*(?:-d|--decode)|(?:xxd|openssl)\b[^\n]*(?:\s-r\b|base64)', re.I), '编码载荷解码'),
    (re.compile(r'\b(?:useradd|adduser)\b|\bpasswd\s+root\b', re.I), '账户变更'),
    (re.compile(r'authorized_keys', re.I), 'SSH 免密配置变更'),
    (re.compile(r'\b(?:chmod|chown)\b[^\n]*(?:/etc/|/bin/|/usr/bin/|/tmp/|/dev/shm/)', re.I), '敏感路径权限变更'),
    (re.compile(r'\bchmod\b[^\n]*(?:\+s\b|[24][0-7]{3}\b)', re.I), 'SUID/SGID 权限变更'),
    (re.compile(r'\bcrontab\b|\bat\s+\d|\bsystemctl\s+enable\b', re.I), '持久化配置'),
    (re.compile(r'\bhistory\s+-c\b|\brm\b[^\n]*\.bash_history|\bln\s+-sf\s+/dev/null[^\n]*history', re.I), '历史记录清理'),
    (re.compile(r'\b(?:iptables|nft)\b[^\n]*\s-[DFX]\b', re.I), '防火墙规则删除'),
    (re.compile(r'\b(?:insmod|modprobe)\b', re.I), '内核模块加载'),
    (re.compile(r'\b(?:setcap|capsh)\b', re.I), 'Linux capability 变更'),
)


LOW_SIGNAL_HISTORY_REASONS = {
    '账户变更', '持久化配置', 'Linux capability 变更', '内核模块加载', 'SSH 免密配置变更',
}


def history_suspicious_reason(line):
    for pattern, reason in HISTORY_SUSPICIOUS_PATTERNS:
        if pattern.search(line):
            return reason
    return None


@mcp.tool()
def check_history():
    """
    检查 root 与普通用户的 bash_history 是否存在，并扫描高危命令特征。
    调用：发现可疑用户或需追踪操作痕迹时使用。
    输出：返回历史文件路径、行数和命中特征；历史记录可被清空或篡改，需结合其他证据复核。
    """

    if not check_session():
        return SESSION_ERROR
    warnings = []
    output = []
    users = load_home_users(warnings=warnings)
    paths = ['/root/.bash_history'] + [f'/home/{user}/.bash_history' for user in users]

    for entry in read_remote_files(paths, warnings=warnings):
        if entry['status'] != 'ok':
            continue
        lines = [line.strip() for line in entry['content'].splitlines() if line.strip()]
        if not lines:
            output.append(f'[i] bash_history 为空: {entry["path"]}')
            continue
        output.append(f'[!] 存在 bash_history: {entry["path"]}\t行数: {len(lines)}')
        hits = []
        for line in lines[-500:]:
            reason = history_suspicious_reason(line)
            if reason:
                hits.append((line, reason))
        for line, reason in hits[:10]:
            tag = '[i]' if reason in LOW_SIGNAL_HISTORY_REASONS else '[!]'
            output.append(f'  {line[:200]}\t{tag} {reason}，需结合上下文复核')
        if len(hits) > 10:
            output.append(f'  [TRUNCATED] 另有 {len(hits) - 10} 条特征命中未展示')

    return append_warnings('\n'.join(output) or empty_result(), warnings)


@mcp.tool()
def check_passwd():
    """
    分析 /etc/passwd 中可登录、UID/GID 异常的账户。
    调用：排查恶意用户、隐藏特权账户或异常 shell 权限时使用。
    输出：返回用户、shell 和异常原因。
    """

    if not check_session():
        return SESSION_ERROR

    result = exec_command(ssh_session.client, 'cat /etc/passwd')
    output = []
    kind = classify_remote_result(result)
    if kind != 'ok':
        issue = remote_result_issue(result, '/etc/passwd', '读取', include_missing=True)
        return issue or command_failure(result, '/etc/passwd 读取失败')

    if result['result']:
        for line in result['result'].splitlines():
            parts = line.strip().split(':')
            if len(parts) >= 7:
                user_name, _, user_uid, user_gid, _, _, user_shell = parts

                issues = []
                if ('nologin' not in user_shell) and (user_name != 'root'):
                    if "sh" in user_shell:
                        issues.append('拥有 shell 权限 [拥有系统 shell]')
                    else:
                        issues.append('拥有 shell 权限 [请检测 shell]')
                if user_uid == '0' and user_name != 'root':
                    issues.append('root 标识用户')
                if user_gid == '0' and user_name != 'root':
                    issues.append('特权用户')

                if issues:
                    output.append(f'user: {user_name}\tshell: {user_shell}\t[!] {"、".join(issues)}')

    return '\n'.join(output) or empty_result()


@mcp.tool()
def check_ssh_keys():
    """
    检查 root 与普通用户的 authorized_keys，以及 SSH 登录命令触发配置。
    调用：排查 SSH 免密后门、sshrc/rc 命令执行或 ProxyCommand 持久化时使用；必要时先调用 check_home。
    输出：返回密钥文件路径、key 注释用户，以及 sshrc/rc/config 中的可疑命令。
    """

    if not check_session():
        return SESSION_ERROR

    warnings = []
    output = []
    users = load_home_users(warnings=warnings)
    dirs = ['/root/.ssh'] + [f'/home/{user}/.ssh' for user in users]
    key_paths = []
    for directory in dirs:
        key_paths.extend([f'{directory}/authorized_keys', f'{directory}/authorized_keys2'])

    for entry in read_remote_files(key_paths, warnings=warnings):
        if entry['status'] != 'ok':
            continue
        key_users = ', '.join(extract_users_from_output(entry['content'])) or '无注释'
        restricted = any(token in entry['content'] for token in ('command=', 'environment=', 'permitopen='))
        tag = '[i] authorized_keys 含强制命令/环境限制，需重点核对' if restricted else '[i] 存在 authorized_keys，需核对公钥来源'
        output.append(f'{entry["path"]}\tuser list: {key_users}\t{tag}')

    # ~/.ssh/rc and /etc/ssh/sshrc execute on login; ProxyCommand/LocalCommand
    # in ~/.ssh/config can provide command execution or tunnelling persistence.
    trigger_paths = ['/etc/ssh/sshrc']
    for directory in dirs:
        trigger_paths.extend([f'{directory}/rc', f'{directory}/config'])
    for entry in read_remote_files(trigger_paths, warnings=warnings):
        if entry['status'] != 'ok':
            continue
        hits = []
        is_config = Path(entry['path']).name == 'config'
        for raw_line in entry['content'].splitlines():
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue
            lower = line.lower()
            if is_config:
                if any(token in lower for token in ('proxycommand', 'localcommand', 'match exec', 'permitlocalcommand')):
                    hits.append(line)
            else:
                hits.append(line)
        if hits:
            output.append(f'{entry["path"]}\t[!] SSH 登录命令触发配置，需重点复核')
            for line in hits[:5]:
                output.append(f'  {line[:200]}')
            if len(hits) > 5:
                output.append(f'  [TRUNCATED] 另有 {len(hits) - 5} 行未展示')

    # List other files so private keys, config edits and dropped files are
    # visible without mislabelling every file as authorized_keys.
    quoted_dirs = ' '.join(shlex.quote(directory) for directory in dirs)
    command = f'for d in {quoted_dirs}; do [ -d "$d" ] && find "$d" -maxdepth 1 -type f -print; done; true'
    result = exec_command(ssh_session.client, command, timeout=20, max_bytes=200000)
    if result.get('stderr'):
        kind = classify_remote_error_text(result['stderr'])
        issue = remote_error_issue(kind, 'SSH 目录', result['stderr'], '列出')
        if issue:
            warnings.append(issue)
    known_keys = {'authorized_keys', 'authorized_keys2'}
    for line in (result.get('stdout') or '').splitlines():
        path = line.strip()
        if not path.startswith('/'):
            continue
        if Path(path).name in known_keys:
            continue
        output.append(f'{path}\t[i] SSH 目录文件，需复核')

    return append_warnings('\n'.join(output) or empty_result(), warnings)


@mcp.tool()
def check_shadow():
    """
    检查 /etc/shadow 空口令账户。
    调用：排查弱口令、无密码登录或异常账户时使用。
    输出：返回空口令用户名。
    """

    if not check_session():
        return SESSION_ERROR

    result = exec_command(ssh_session.client, 'cat /etc/shadow')
    output = []
    kind = classify_remote_result(result)
    if kind != 'ok':
        issue = remote_result_issue(result, '/etc/shadow', '读取', include_missing=True)
        return issue or command_failure(result, '/etc/shadow 读取失败')

    if result['result']:
        for line in result['result'].splitlines():
            parts = line.strip().split(':')
            if len(parts) >= 2:
                user_name, hashcode = parts[0], parts[1]
                if not hashcode:
                    output.append(f'user: {user_name}\t[!] 空口令账户')

    return '\n'.join(output) or empty_result()


@mcp.tool()
def check_sudoers():
    """
    检查 sudoers 中高权限用户和组。
    调用：排查提权风险、异常 sudo 授权或管理员组滥用时使用。
    输出：返回可 sudo 的用户/组及组成员。
    """

    if not check_session():
        return SESSION_ERROR

    output = []
    warnings = []

    paths = ['/etc/sudoers']
    for file in get_files('/etc/sudoers.d', warnings=warnings):
        paths.append(f'/etc/sudoers.d/{file}')

    entries = read_remote_files(paths, warnings=warnings)
    readable = [entry for entry in entries if entry['status'] == 'ok']
    if not readable:
        for entry in entries:
            if entry['status'] != 'not_found':
                issue = remote_error_issue(entry['status'], entry['path'], entry['content'], '读取')
                return append_warnings(issue or empty_result(), warnings)
        return append_warnings(empty_result(), warnings)

    get_group()
    for entry in readable:
        for line in entry['content'].splitlines():
            line = line.strip()
            if ('ALL=(ALL)' in line or 'ALL=(root)' in line) and not line.startswith('#'):
                parts = line.split()
                if len(parts) > 0:
                    user_or_group = parts[0]
                    tag = (
                        '[!] sudo 免密授权（NOPASSWD），需重点核对'
                        if 'NOPASSWD' in line
                        else '[i] sudo 授权，需核对是否符合预期'
                    )

                    if user_or_group.startswith('%'):
                        group_name = user_or_group[1:]
                        users_in_group = ssh_session.group_list.get(group_name, [])
                        tmp = f'group: {group_name}\tuser: {", ".join(users_in_group)}'
                        output.append(f'{tmp}\t{tag}')
                    else:
                        tmp = f'{"user: " + user_or_group}'
                        output.append(f'{tmp}\t{tag}')

    return append_warnings('\n'.join(output) or empty_result(), warnings)


PAM_EXEC_MODULES = {
    'pam_exec.so': '[!] PAM 外部命令执行模块，需重点复核',
    'pam_python.so': '[!] PAM Python 模块，需重点复核',
    'pam_script.so': '[!] PAM 脚本模块，需重点复核',
}


def pam_line_finding(line):
    """Return a review finding for dangerous PAM configuration lines."""
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        return None
    tokens = re.split(r'\s+', stripped)
    controls = {token.lower() for token in tokens[:2]}
    module = next((token for token in tokens if token.endswith('.so')), '')
    if module in PAM_EXEC_MODULES:
        return PAM_EXEC_MODULES[module]
    if module == 'pam_permit.so' and 'auth' in controls:
        return '[!] PAM 认证无条件放行模块，需重点复核'
    if module == 'pam_unix.so' and 'nullok' in tokens:
        return '[!] PAM 允许空口令（nullok），需重点复核'
    include_target = tokens[-1] if tokens else ''
    include_directive = tokens[0] == '@include' or 'include' in tokens[:2]
    if include_directive and include_target.startswith('/'):
        if not include_target.startswith('/etc/pam.d/'):
            return f'[!] PAM 引用 /etc/pam.d 之外的配置文件: {include_target}'
    return None


@mcp.tool()
def check_pam():
    """
    检查 PAM 配置中的外部命令模块和弱认证配置。
    调用：排查 PAM 后门、登录命令执行、空口令放行或认证绕过时使用。
    输出：返回 pam.d/pam.conf 中的命中行、文件和风险说明。
    """

    if not check_session():
        return SESSION_ERROR

    warnings = []
    paths = ['/etc/pam.conf']
    for file in get_files('/etc/pam.d', warnings=warnings):
        paths.append(f'/etc/pam.d/{file}')

    output = []
    for entry in read_remote_files(paths, warnings=warnings):
        if entry['status'] != 'ok':
            continue
        for line_number, raw_line in enumerate(entry['content'].splitlines(), 1):
            finding = pam_line_finding(raw_line)
            if finding:
                output.append(f'{entry["path"]}:{line_number}\t{raw_line.strip()[:200]}\t{finding}')

    return append_warnings('\n'.join(output) or empty_result(), warnings)


def sshd_config_finding(line):
    """Return a review finding for dangerous sshd_config directives."""
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        return None
    parts = stripped.split(None, 1)
    directive = parts[0].lower()
    value = parts[1].strip() if len(parts) > 1 else ''
    lower_value = value.lower()

    if directive == 'authorizedkeyscommand' and lower_value not in ('', 'none'):
        return '[!] sshd 配置 AuthorizedKeysCommand，认证时会执行外部命令，需重点复核'
    if directive == 'forcecommand' and lower_value not in ('', 'none'):
        return '[!] sshd 配置 ForceCommand，登录后会强制执行命令，需重点复核'
    if directive == 'permituserenvironment' and lower_value == 'yes':
        return '[!] PermitUserEnvironment=yes，允许注入用户环境变量，需重点复核'
    if directive == 'authorizedkeysfile':
        if any(token in lower_value for token in ('/tmp', '/dev/shm', '/var/tmp')):
            return f'[!] AuthorizedKeysFile 指向临时目录: {value}'
        if lower_value not in ('', 'none') and not lower_value.endswith(('authorized_keys', 'authorized_keys2')):
            return f'[i] AuthorizedKeysFile 使用自定义路径，需复核: {value}'
    if directive == 'subsystem' and 'sftp' in lower_value:
        tokens = value.split()
        server = tokens[1] if len(tokens) > 1 else ''
        if server and server not in ('internal-sftp', '/usr/lib/openssh/sftp-server', '/usr/libexec/openssh/sftp-server'):
            return f'[!] SFTP 子系统使用非标准程序: {server}'
    if directive == 'hostkey' and value.startswith('/') and not value.startswith('/etc/ssh/'):
        return f'[!] HostKey 位于非标准路径: {value}'
    if directive == 'include' and value.startswith('/') and not value.startswith('/etc/ssh/'):
        return f'[!] sshd Include 指向非标准路径: {value}'
    if directive == 'permitrootlogin' and lower_value == 'yes':
        return '[i] PermitRootLogin=yes，需核对管理要求'
    if directive == 'permittunnel' and lower_value in ('yes', 'point-to-point', 'ethernet'):
        return '[i] 允许 SSH 隧道，需复核'
    if directive == 'port' and value not in ('', '22'):
        return f'[i] 非标准 SSH 端口: {value}'
    return None


@mcp.tool()
def check_sshd_config():
    """
    检查 sshd 配置中的命令执行、认证绕过和持久化指令。
    调用：排查 SSH 后门、AuthorizedKeysCommand、ForceCommand、自定义 SFTP/HostKey 时使用。
    输出：返回 sshd_config 及 sshd_config.d 中的可疑指令和风险说明。
    """

    if not check_session():
        return SESSION_ERROR

    warnings = []
    paths = ['/etc/ssh/sshd_config']
    for file in get_files('/etc/ssh/sshd_config.d', warnings=warnings):
        paths.append(f'/etc/ssh/sshd_config.d/{file}')

    output = []
    readable = 0
    for entry in read_remote_files(paths, warnings=warnings):
        if entry['status'] != 'ok':
            continue
        readable += 1
        for line_number, raw_line in enumerate(entry['content'].splitlines(), 1):
            finding = sshd_config_finding(raw_line)
            if finding:
                output.append(f'{entry["path"]}:{line_number}\t{raw_line.strip()[:200]}\t{finding}')

    if readable == 0 and not output:
        return append_warnings(empty_result('未读取到 sshd 配置，需人工复核'), warnings)
    return append_warnings('\n'.join(output) or empty_result(), warnings)


ROOTKIT_MODULE_NAMES = {
    'diamorphine', 'reptile', 'azazel', 'suterusu', 'bdvl', 'knark', 'adore', 'adore-ng',
    'rootkit', 'rkit', 'enyelkm', 'mokes', 'beurk',
}


def decode_kernel_taint(value):
    """Decode Linux kernel taint bits that matter during incident response."""
    try:
        taint = int(str(value).strip())
    except (TypeError, ValueError):
        return []
    reasons = []
    if taint & (1 << 1):
        reasons.append('[!] 内核存在强制加载模块标记（taint bit 1）')
    if taint & (1 << 3):
        reasons.append('[!] 内核存在强制卸载模块标记（taint bit 3）')
    if taint & (1 << 7):
        reasons.append('[i] 内核曾发生 die/oops（taint bit 7），需结合日志复核')
    if taint & (1 << 9):
        reasons.append('[i] 内核曾产生 warning（taint bit 9）')
    if taint & (1 << 12):
        reasons.append('[i] 已加载树外模块（taint bit 12），需核对来源')
    if taint & (1 << 13):
        reasons.append('[!] 已加载未签名模块（taint bit 13），需重点复核')
    return reasons


def kernel_module_tag(name, path, intree):
    if name in ROOTKIT_MODULE_NAMES:
        return '[!] 已知 rootkit 模块名，需重点复核'
    if path and not path.startswith(('/lib/modules/', '/usr/lib/modules/')):
        return '[!] 模块文件路径异常，需重点复核'
    if intree == 'N':
        return '[i] 树外模块，需核对来源'
    return '[i] 已加载模块'


@mcp.tool()
def check_kernel_modules():
    """
    检查已加载内核模块、模块文件路径和内核 taint 标记。
    调用：排查内核 rootkit、强制加载模块、未签名/树外模块或内核异常时使用。
    输出：返回 lsmod 模块、modinfo 路径、intree 标记、taint 位解析和已知 rootkit 模块名。
    """

    if not check_session():
        return SESSION_ERROR

    nonce = get_run_id()
    taint_mark = f'@@AUTOIR_KMOD:{nonce}:TAINT@@'
    lsmod_mark = f'@@AUTOIR_KMOD:{nonce}:LSMOD@@'
    paths_mark = f'@@AUTOIR_KMOD:{nonce}:PATHS@@'
    command = (
        f"printf '{taint_mark}\\n'; cat /proc/sys/kernel/tainted 2>&1; "
        f"printf '\\n{lsmod_mark}\\n'; lsmod 2>&1 | head -n 300; "
        f"printf '\\n{paths_mark}\\n'; "
        'if command -v modinfo >/dev/null 2>&1; then '
        "lsmod 2>/dev/null | awk 'NR>1 {print $1}' | head -n 300 | while read -r m; do "
        'f=$(modinfo -F filename "$m" 2>/dev/null); i=$(modinfo -F intree "$m" 2>/dev/null); '
        "printf '%s\\t%s\\t%s\\n' \"$m\" \"$f\" \"$i\"; done; "
        'else printf "modinfo unavailable\\n"; fi'
    )
    result = exec_command(ssh_session.client, command, timeout=60, max_bytes=300000)
    text = result.get('result') or ''
    if not text:
        return command_failure(result, '内核模块检查失败')

    warnings = []
    if result.get('truncated'):
        warnings.append('[TRUNCATED] 内核模块输出超过采集上限，结果可能不完整')

    _, _, rest = text.partition(taint_mark)
    taint_text, _, rest = rest.partition(lsmod_mark)
    lsmod_text, _, paths_text = rest.partition(paths_mark)
    taint_value = taint_text.strip().splitlines()[0].strip() if taint_text.strip() else ''

    output = []
    if taint_value.isdigit():
        output.append(f'kernel taint: {taint_value}')
        for finding in decode_kernel_taint(taint_value):
            output.append(f'\t{finding}')
    elif taint_value:
        warnings.append(f'[WARN] 内核 taint 读取失败: {truncate_text(taint_value, 200)}')
    if any(token in lsmod_text.lower() for token in ('command not found', 'not found')):
        return append_warnings('[FAILED] lsmod 不可用，无法枚举内核模块，需人工复核', warnings)

    module_paths = {}
    intree_map = {}
    for line in paths_text.splitlines():
        parts = line.strip().split('\t')
        if len(parts) >= 2 and parts[1]:
            module_paths[parts[0]] = parts[1]
            intree_map[parts[0]] = parts[2] if len(parts) > 2 else ''
    modinfo_missing = 'modinfo unavailable' in paths_text
    if modinfo_missing:
        warnings.append('[WARN] modinfo 不可用，无法校验模块文件路径，需人工复核')

    module_rows = [line for line in lsmod_text.splitlines()[1:] if line.strip()]
    if not module_rows:
        warnings.append('[WARN] lsmod 未返回模块列表，可能需要 root 权限或内核未启用模块')
    for row in module_rows[:300]:
        parts = re.split(r'\s+', row.strip())
        name = parts[0]
        size = parts[1] if len(parts) > 1 else '-'
        used = parts[2] if len(parts) > 2 else '-'
        path = module_paths.get(name, '')
        tag = kernel_module_tag(name, path, intree_map.get(name, ''))
        output.append(f'module: {name}\tsize: {size}\tused: {used}\tpath: {path or "-"}\t{tag}')

    return append_warnings('\n'.join(output) or empty_result('未发现已加载内核模块'), warnings)


privilege_escalation = ['aa-exec', 'aoss', 'apt-get', 'apt', 'ash', 'at', 'awk',
                        'aws', 'bash', 'batcat', 'bconsole', 'bundle', 'bundler', 'busctl', 'busybox', 'byebug', 'c89',
                        'c99', 'cabal', 'capsh', 'cdist', 'certbot', 'check_by_ssh', 'choom', 'cobc', 'composer',
                        'cowsay', 'cowthink', 'cpan', 'cpio', 'cpulimit', 'crash', 'csh', 'csvtool', 'dash', 'dc',
                        'debugfs', 'distcc', 'dmesg', 'docker', 'dotnet', 'dpkg', 'dstat', 'dvips', 'easy_install',
                        'eb', 'ed', 'elvish', 'emacs', 'enscript', 'env', 'ex', 'expect', 'facter', 'find', 'fish',
                        'flock', 'ftp', 'gawk', 'gcc', 'gcloud', 'gdb', 'gem', 'genie', 'ghc', 'ghci', 'gimp', 'ginsh',
                        'git', 'grc', 'gtester', 'hping3', 'iftop', 'ionice', 'irb', 'ispell', 'jjs', 'joe',
                        'journalctl', 'jrunscript', 'jtag', 'julia', 'knife', 'ksh', 'latex', 'latexmk', 'ld.so',
                        'less', 'lftp', 'loginctl', 'logsave', 'ltrace', 'lua', 'lualatex', 'luatex', 'mail', 'make',
                        'man', 'mawk', 'minicom', 'more', 'msfconsole', 'msgfilter', 'multitime', 'mysql', 'nano',
                        'nawk', 'ncdu', 'ncftp', 'neofetch', 'nice', 'nmap', 'node', 'nohup', 'npm', 'nroff', 'nsenter',
                        'octave', 'openvpn', 'pandoc', 'pdb', 'pdflatex', 'pdftex', 'perf', 'perl', 'perlbug', 'pexec',
                        'pg', 'php', 'pic', 'pico', 'pip', 'posh', 'pry', 'psftp', 'psql', 'puppet', 'pwsh', 'python',
                        'rake', 'rc', 'rlwrap', 'rpm', 'rpmdb', 'rpmquery', 'rpmverify', 'rsync', 'rtorrent', 'ruby',
                        'run-mailcap', 'run-parts', 'runscript', 'rview', 'rvim', 'sash', 'scanmem', 'scp', 'screen',
                        'script', 'scrot', 'sed', 'service', 'setarch', 'setlock', 'sftp', 'sg', 'slsh', 'smbclient',
                        'socat', 'softlimit', 'split', 'sqlite3', 'sqlmap', 'ssh-agent', 'ssh', 'sshpass',
                        'start-stop-daemon', 'stdbuf', 'strace', 'tar', 'task', 'taskset', 'tasksh', 'tclsh', 'tdbtool',
                        'telnet', 'tex', 'time', 'timedatectl', 'timeout', 'tmate', 'tmux', 'top', 'torify', 'torsocks',
                        'tshark', 'unshare', 'vagrant', 'valgrind', 'vi', 'view', 'vim', 'vimdiff', 'volatility',
                        'watch', 'wget', 'wish', 'xargs', 'xdg-user-dir', 'xdotool', 'xelatex', 'xetex', 'yarn', 'yash',
                        'zathura', 'zip', 'zsh', 'zypper']


def parse_ps_output(output):
    processes = {}
    for line in output.splitlines()[1:]:
        try:
            parts = re.split(r'\s+', line.strip())
            if len(parts) < 11:
                continue

            pid = int(parts[1])
            command = ' '.join(parts[10:])
            exe = command.split()[0] if command.strip() else ''
            if exe.startswith('[') and exe.endswith(']'):
                exe = exe[1:-1]
            elif ':' in exe and '/' not in exe:
                exe = exe.split(':')[0]
            elif '/' in exe:
                exe = Path(exe).name
            elif '(' in exe:
                exe = exe[1:-1]

            processes[pid] = {
                'user': parts[0],
                'cpu': float(parts[2]),
                'mem': float(parts[3]),
                'tty': parts[6],
                'time': parts[9],
                'command': command,
                'exe': exe}
        except (IndexError, ValueError):
            continue
    return processes


def parse_ps_ef_output(output):
    """Parse the portable `ps -ef` layout used when BSD-style ps is missing.

    CPU/MEM are unavailable in this format; they are set to 0 so resource
    checks do not invent values. The process list is still useful for
    hidden-PID and process-mismatch comparisons.
    """
    processes = {}
    for line in output.splitlines()[1:]:
        parts = re.split(r'\s+', line.strip())
        if len(parts) < 8:
            continue
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        command = ' '.join(parts[7:])
        exe = command.split()[0] if command.strip() else ''
        if exe.startswith('[') and exe.endswith(']'):
            exe = exe[1:-1]
        elif '/' in exe:
            exe = Path(exe).name
        processes[pid] = {
            'user': parts[0],
            'cpu': 0.0,
            'mem': 0.0,
            'tty': parts[5],
            'time': parts[6],
            'command': command,
            'exe': exe,
        }
    return processes


PROCESS_SNAPSHOT_TTL = 60


def load_processes():
    processes = {}
    for command in ('ps -aux', 'ps auxww', 'ps -ef'):
        result = exec_command(ssh_session.client, command)
        if not result['status'] or not result['result']:
            continue
        processes = parse_ps_output(result['result'])
        if not processes:
            processes = parse_ps_ef_output(result['result'])
        if processes:
            break
    with state_lock:
        ssh_session.ps = processes
        ssh_session.ps_time = time.monotonic() if processes else 0.0
        return len(processes)


def ensure_processes(max_age=PROCESS_SNAPSHOT_TTL):
    with state_lock:
        fresh = bool(ssh_session.ps) and time.monotonic() - ssh_session.ps_time <= max_age
        count = len(ssh_session.ps)
    if fresh:
        return count
    return load_processes()


@mcp.tool()
def get_ps(force=False):
    """
    采集进程快照。
    调用：进程类检测前优先调用；后续 check_mine、check_exec、check_pid、check_exe 复用该快照，超过 60 秒自动刷新。
    输出：返回采集到的进程数量；采集失败时返回明确失败原因。
    """

    if not check_session():
        return SESSION_ERROR

    count = load_processes() if force or not ssh_session.ps else ensure_processes()
    if not count:
        return command_failure({'error': '进程快照为空'}, '进程快照获取失败')
    return f"已获取 {count} 个进程信息"


@mcp.tool()
def check_mine():
    """
    检测高 CPU/内存占用进程。
    调用：怀疑挖矿、资源异常或主机卡顿时使用；会自动补采进程快照。
    输出：返回超过阈值的 PID、资源占用和命令。
    """

    if not check_session():
        return SESSION_ERROR

    ensure_processes()
    with state_lock:
        processes = dict(ssh_session.ps)
    if not processes:
        return command_failure({'error': '进程快照为空，无法检测资源占用'}, '进程快照获取失败')

    output = ''
    for pid, proc in processes.items():
        cpu, mem, command = proc['cpu'], proc['mem'], proc['command']
        if cpu > 50.0 or mem > 50.0:
            output += (
                f'PID: {pid}\tCPU: {cpu}\tMEM: {mem}\tCOMMAND: {command}'
                '\t[!] CPU/内存占用超过 50%，需结合命令行、父进程和启动时间复核\n'
            )
    return output or empty_result()


@mcp.tool()
def check_exec():
    """
    检测可疑命令执行进程。
    调用：排查反弹 shell、相对路径执行、root 可提权命令或 WAF 命中特征时使用。
    输出：返回 PID、TTY、命令和可疑原因。
    """

    if not check_session():
        return SESSION_ERROR

    ensure_processes()
    with state_lock:
        processes = dict(ssh_session.ps)
    if not processes:
        return command_failure({'error': '进程快照为空，无法检测可疑命令执行'}, '进程快照获取失败')

    output = ''
    root_command = []

    for pid, proc in processes.items():
        user, tty, command, exe = proc['user'], proc['tty'], proc['command'], proc['exe']
        reasons = []

        if 'ttyS' not in tty and tty != '?':
            reasons.append('tty 虚拟终端执行命令')
        if './' in command:
            reasons.append('通过相对路径运行命令')
        if user == 'root' and exe not in root_command:
            root_command.append(exe)
        if detect_malicious_text(command):
            reasons.append('疑似命令执行')
        if reasons:
            output += f'PID: {pid}\tTTY: {tty}\tCOMMAND: {command}\t[!] {", ".join(reasons)}\n'

    for command in root_command:
        if command.startswith('[') or command.endswith(']'):
            continue
        for check in privilege_escalation:
            if check == command:
                output += f'"command: " {command}\t[!] 疑似可 root 提权\n'
                break

    return output or empty_result()


@mcp.tool()
def check_pid():
    """
    检测疑似隐藏 PID。
    调用：怀疑 rootkit、进程隐藏或 ps 输出不可信时使用。
    输出：返回 /proc 存在但进程快照缺失的 PID。
    """

    if not check_session():
        return SESSION_ERROR

    ensure_processes()
    with state_lock:
        processes = dict(ssh_session.ps)
    if not processes:
        return command_failure({'error': '进程快照为空，无法比对隐藏 PID'}, '进程快照获取失败')

    output = ''

    result_pid = exec_command(ssh_session.client, 'ls /proc')
    result_self = exec_command(ssh_session.client, 'ls -al /proc/self')
    if not result_pid['status'] or not result_self['status']:
        failed = result_pid if not result_pid['status'] else result_self
        return command_failure(failed, '/proc 枚举失败')

    try:
        current_pid = re.findall(r'(\d+)', result_pid['result'])  # 确定所有 pid
        self_match = re.search(r'-> (\d+)', result_self['result'])
        if not self_match:
            return command_failure(result_self, '/proc/self 解析失败')
        self_pid = self_match.group(1)  # 匹配 self 的 pid

        for pid in current_pid:
            if int(pid) not in processes and (int(pid) not in range(int(self_pid) - 2, int(self_pid) + 2)):
                output += f'PID: {pid}\t path:/proc/{pid}\t[!] 隐藏 pid\n'
    except (AttributeError, ValueError):
        return command_failure({'error': '/proc 输出解析失败'}, '隐藏 PID 检测失败')

    return output or empty_result()


@mcp.tool()
def check_exe():
    """
    检测进程名与真实可执行文件不一致。
    调用：怀疑进程伪装、命令替换或二进制劫持时使用。
    输出：返回 PID、真实 exe 和 ps 中显示的 exe。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''
    ensure_processes()
    with state_lock:
        processes = dict(ssh_session.ps)

    result = exec_command(ssh_session.client, 'ls -al /proc/*/exe 2>&1')
    if not result['status'] and not result['result']:
        return command_failure(result, '/proc exe 读取失败')
    warnings = []
    text = result['result'] or ''
    if 'Permission denied' in text or '权限' in text:
        warnings.append('[PERMISSION] 部分 /proc/<pid>/exe 不可读，比对结果可能不完整，需人工复核')
    matched = 0
    try:
        group = re.findall(r'.*/proc/(\d+)/exe -> (.*)', text)
        matched = len(group)
        for item in group:
            pid = item[0]
            true_exe = Path(item[1]).name  # exe 真实指向命令
            if int(pid) in processes:
                exe = processes[int(pid)]['exe']

                if true_exe != exe:
                    output += f'PID: {pid}\ttrue_exe: {true_exe}\texe: {exe}\t[!] 进程名与真实可执行文件不一致，需结合上下文复核\n'
    except ValueError:
        pass

    if not output and not processes:
        return command_failure({'error': '进程快照为空，无法比对可执行文件'}, '/proc exe 比对失败')
    if not output and not matched:
        return append_warnings(
            '[FAILED] 未解析到任何 /proc/<pid>/exe 记录，无法完成比对，需人工复核',
            warnings,
        )
    return append_warnings(output or empty_result(), warnings)


@mcp.tool()
def check_mount():
    """
    检查 /proc 挂载异常。
    调用：怀疑通过 mount 隐藏进程或伪装文件系统时使用。
    输出：返回可疑 /proc/<pid> 挂载项。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''

    result = exec_command(ssh_session.client, 'cat /proc/mounts')
    if not result['status']:
        return command_failure(result, '挂载信息读取失败')
    if not result['result']:
        return empty_result()

    try:
        for pid in re.findall(r'/proc/(\d+)', result['result']):
            output += f'path: /proc/{pid}\t[i] /proc/<pid> 相关挂载，需人工复核\n'
    except re.error:
        pass

    return output or empty_result()


@mcp.tool()
def get_localhost():
    """
    采集本机 IPv4 地址。
    调用：网络连接分析前使用，用于区分本地地址和远程外联。
    输出：返回本地 IP 列表。
    """

    if not check_session():
        return SESSION_ERROR

    ip_list = ["127.0.0.1", "localhost", "0.0.0.0"]
    with state_lock:
        ssh_session.ip_list_time = 0.0
    result = first_success(ssh_session.client, ['ip -4 addr show', 'hostname -I'])

    if not result['status']:
        return command_failure(result, '本地 IP 获取失败')
    if not result['result']:
        with state_lock:
            ssh_session.ip_list = list(ip_list)
            ssh_session.ip_list_time = time.monotonic()
        return f"本地IP列表: {', '.join(ip_list)}"

    for line in result['result'].splitlines():
        line = line.strip()
        if "inet" in line:
            try:
                ip = re.split(r'\s+', line)[1].split('/')[0]
                if ip not in ip_list:
                    ip_list.append(ip)
            except (IndexError, ValueError):
                pass
        else:
            for ip in line.split():
                if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', ip) and ip not in ip_list:
                    ip_list.append(ip)

    with state_lock:
        ssh_session.ip_list = list(ip_list)
        ssh_session.ip_list_time = time.monotonic()
    return f"本地IP列表: {', '.join(ip_list)}"


def ensure_local_ips(warnings=None, max_age=60):
    """Refresh local IPv4 addresses when the cache is empty or stale."""
    with state_lock:
        fresh = (
            len(ssh_session.ip_list) > 3
            and time.monotonic() - ssh_session.ip_list_time <= max_age
        )
    if fresh:
        return True
    result = get_localhost()
    if isinstance(result, str) and '获取失败' in result:
        if warnings is not None:
            warnings.append('[WARN] 本机 IP 自动采集失败，远程连接判断可能不准确，需人工复核')
        return False
    return True


def parse_socket_line(line):
    line = line.strip()
    if not line or line.lower().startswith(('netid', 'proto', 'active')):
        return None
    parts = re.split(r'\s+', line)
    if len(parts) < 5 or parts[0] not in ('tcp', 'udp', 'tcp6', 'udp6'):
        return None
    if len(parts) >= 6 and parts[1].upper() in {'LISTEN', 'UNCONN', 'ESTAB', 'ESTABLISHED', 'TIME-WAIT'}:
        state = parts[1]
        local = parts[4]
        remote = parts[5]
    else:
        state = next((part for part in parts if part.upper() in {'LISTEN', 'UNCONN', 'ESTABLISHED'}), '')
        local = parts[3]
        remote = parts[4]
    process = parts[-1] if '/' in parts[-1] or 'users:' in parts[-1] else ''
    return {
        'proto': parts[0],
        'local': local,
        'remote': remote,
        'state': state,
        'process': process,
    }


@mcp.tool()
def check_network():
    """
    分析 ss -anutp 网络连接。
    调用：排查异常外联、监听端口或后门通信时使用；可结合已采集的本机地址判断远程连接。
    输出：返回本地地址、远程地址、进程和连接类型。
    """
    if not check_session():
        return SESSION_ERROR

    output = []
    warnings = []

    ensure_local_ips(warnings)

    with state_lock:
        local_ips = set(ssh_session.ip_list)
    if len(local_ips) <= 3:
        warnings.append('[WARN] 未采集到有效 IPv4 地址，远程连接判断可能不准确，需人工复核')

    result = first_success(ssh_session.client, ['ss -anutp', 'netstat -anutp 2>/dev/null'])
    if not result.get('status'):
        return command_failure(result, '网络连接获取失败')
    if not result.get('result'):
        return append_warnings(empty_result(), warnings)

    missing_process = 0
    connection_count = 0
    for line in result['result'].splitlines()[1:]:
        try:
            socket = parse_socket_line(line)
            if not socket:
                continue
            connection_count += 1
            if not socket['process']:
                missing_process += 1
            local = socket['local']
            remote = socket['remote']
            process = socket['process'] or '-'
            local_addr, local_port = local.rsplit(':', 1)
            remote_addr, remote_port = remote.rsplit(':', 1)

            if remote_addr not in local_ips and remote_port != "*":
                output.append(f'local :{local}\tremote :{remote}\tpid :{process}\t[!] 发现远程连接')
            elif local_port and local_port != "*":
                output.append(f'local :{local}\tremote :{remote}\tpid :{process}\t[!] 发现开启端口')
        except (IndexError, ValueError):
            pass

    if missing_process:
        warnings.append(
            f'[WARN] {missing_process}/{connection_count} 条连接缺少进程信息'
            '（非 root、hidepid 或内核限制），需人工复核'
        )
    return append_warnings('\n'.join(output) or empty_result(), warnings)


@mcp.tool()
def check_listening_ports():
    """
    汇总监听端口。
    调用：需要快速确认目标主机暴露服务、监听地址和关联进程时使用。
    输出：返回协议、本地监听地址、状态和进程线索。
    """
    if not check_session():
        return SESSION_ERROR

    result = first_success(ssh_session.client, ['ss -lntup', 'netstat -lntup 2>/dev/null'])
    if not result.get('status'):
        return command_failure(result, '监听端口获取失败')
    if not result.get('result'):
        return empty_result('未发现监听端口')

    output = []
    for line in result['result'].splitlines():
        socket = parse_socket_line(line)
        if not socket:
            continue
        output.append(
            f'proto: {socket["proto"]}\tlocal: {socket["local"]}\tstate: {socket["state"] or "-"}'
            f'\tprocess: {socket["process"] or "-"}\t[i] 监听端口'
        )

    return '\n'.join(output) or empty_result('未发现监听端口')


@mcp.tool()
def check_eth():
    """
    枚举网卡设备。
    调用：排查异常网卡、虚拟网卡或多网段资产时使用。
    输出：返回网卡名称列表。
    """

    if not check_session():
        return SESSION_ERROR

    result = exec_command(ssh_session.client, 'ls /sys/class/net')
    if not result.get('status'):
        return command_failure(result, '网卡枚举失败')

    output = [f'网卡: {line.strip()}\t[i] 网卡检测' for line in result['result'].splitlines() if line.strip()]
    return '\n'.join(output) or empty_result('未发现网卡')


@mcp.tool()
def check_hosts():
    """
    检查 /etc/hosts 非本机解析项。
    调用：排查 hosts 劫持、恶意域名解析或异常内网映射时使用。
    输出：返回可疑 IP 与域名。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''
    warnings = []
    standard_hosts = {'127.0.0.1', '127.0.1.1', '::1', 'ff02::1', 'ff02::2'}
    ensure_local_ips(warnings)
    with state_lock:
        local_ips = set(ssh_session.ip_list)

    result = exec_command(ssh_session.client, 'cat /etc/hosts')
    if not result['status']:
        return command_failure(result, 'hosts 读取失败')
    if not result['result']:
        return empty_result()

    for line in result['result'].splitlines():
        line = line.strip()
        try:
            parts = re.split(r'\s+', line.strip())
            if parts and not parts[0].startswith('#'):
                ip, *domains = parts
                if ip in standard_hosts or not domains:
                    continue
                if ip and ip not in local_ips:
                    output += f'ip: {ip}\tdomain: {"、".join(domains)}\t[!] 非本机 hosts 解析\n'
                else:
                    output += f'ip: {ip}\tdomain: {"、".join(domains)}\t[i] 本机地址映射，需复核\n'
        except (IndexError, ValueError):
            pass

    return append_warnings(output or empty_result(), warnings)


@mcp.tool()
def check_bin(path=''):
    """
    采集系统命令目录关键文件线索。
    调用：怀疑系统命令被替换、权限异常、新增可疑命令或 /usr/local 落地后门时使用。
    输出：返回近期修改、非 root 属主、异常权限和软链信息，供结合上下文复核。
    默认扫描 /usr/bin、/usr/sbin、/usr/local/bin、/usr/local/sbin；可传 path 只扫描指定目录。
    """

    if not check_session():
        return SESSION_ERROR

    directories = [path] if path else ['/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin']
    warnings = []
    output = []

    for directory in directories:
        result = exec_command(ssh_session.client, f'ls -alt {quote_remote_path(directory)} 2>&1')
        kind = classify_remote_result(result)
        if kind == 'not_found':
            if path:
                return remote_result_issue(result, directory, '读取', include_missing=True) or f'{directory} 不存在'
            continue
        if kind != 'ok':
            issue = remote_result_issue(result, directory, '读取')
            if issue:
                warnings.append(issue)
            continue
        if not result['result']:
            continue

        files = list(get_file_list(result['result']).values())
        recent_files = []
        suspicious_files = []
        symlink_files = []

        for file in files:
            filename = file['filename']
            owner = file['owner']
            group = file['group']
            perm = file['perm']
            time = file['time']
            link = ''

            if ' -> ' in filename:
                filename, link = filename.split(' -> ', 1)

            full_path = f'{directory.rstrip("/")}/{filename}'
            if len(recent_files) < 10:
                recent_files.append(f'file: {full_path}\ttime: {time}\t[i] {directory} 近期修改文件')

            reasons = []
            if owner != 'root' or group != 'root':
                reasons.append('非 root 属主/属组')
            if len(perm) > 8 and perm[8] == 'w':
                reasons.append('other 可写权限')
            if len(perm) > 3 and perm[3] in {'s', 'S'}:
                reasons.append('setuid 权限')
            if len(perm) > 6 and perm[6] in {'s', 'S'}:
                reasons.append('setgid 权限')

            if reasons:
                suspicious_files.append(
                    f'file: {full_path}\tperm: {perm}\towner: {owner}\tgroup: {group}\t[!] {", ".join(reasons)}，需结合上下文复核'
                )
            if link:
                symlink_files.append(f'file: {full_path}\tlink: {link}\t[i] {directory} 软链条目')

        output.extend(recent_files)
        output.extend(suspicious_files[:50])
        if len(suspicious_files) > 50:
            output.append(f'[i] {directory} 还有 {len(suspicious_files) - 50} 条权限/属主线索未展示')
        output.extend(symlink_files[:30])
        if len(symlink_files) > 30:
            output.append(f'[i] {directory} 还有 {len(symlink_files) - 30} 条软链线索未展示')

    return append_warnings('\n'.join(output) or empty_result(), warnings)


def package_integrity_tag(line, manager):
    """Classify an rpm/dpkg/apk integrity mismatch line for review priority."""
    stripped = line.strip()
    if not stripped:
        return None
    system_path = any(
        token in stripped
        for token in ('/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/lib/', '/lib64/', '/usr/lib/', '/usr/lib64/')
    )
    if manager == 'rpm' and stripped.lower().startswith('missing'):
        return '[!] 软件包文件缺失，需重点复核'
    if manager == 'apk':
        # apk audit --system prints "<reason-code> <path>" for changed files.
        match = re.match(r'^([A-Za-z])\s+(/\S.*)$', stripped)
        if match:
            code = match.group(1)
            reason = {
                'A': '新增文件', 'D': '文件缺失', 'U': '文件变更',
                'M': '权限/元数据变更', 'C': '配置文件变更',
            }.get(code.upper(), '文件系统审计差异')
        elif stripped.startswith('/'):
            reason = '文件系统审计差异'
        else:
            return None
        if system_path:
            return f'[!] 系统路径{reason}，需重点复核'
        return f'[i] {reason}，需人工复核'
    # rpm/dpkg verification lines begin with 9 attribute characters followed by
    # whitespace. Skip database errors and other diagnostic text.
    if not re.match(r'^[\w?.]{9}\s', stripped):
        return None
    # Binaries and shared libraries are the highest-value tampering targets.
    if system_path:
        return '[!] 系统可执行文件/库与软件包记录不一致，需重点复核'
    return '[i] 文件与软件包记录不一致，需人工复核'


@mcp.tool()
def check_package_integrity(max_lines=200):
    """
    校验已安装软件包的文件完整性，发现被替换或缺失的系统文件。
    调用：怀疑系统命令被替换、二进制后门或 rootkit 时使用；需要 root 权限，rpm 全量校验可能较慢。
    输出：返回 rpm/dpkg/apk 校验差异，系统可执行文件和库不一致会重点标注。
    """

    if not check_session():
        return SESSION_ERROR
    try:
        max_lines = max(1, min(int(max_lines), 1000))
    except (TypeError, ValueError):
        max_lines = 200

    nonce = get_run_id()
    mgr_mark = f'@@AUTOIR_PKG:{nonce}:MGR@@'
    lines_mark = f'@@AUTOIR_PKG:{nonce}:LINES@@'
    err_mark = f'@@AUTOIR_PKG:{nonce}:ERR@@'
    rc_mark = f'@@AUTOIR_PKG:{nonce}:RC@@'

    command = (
        'err=$(mktemp 2>/dev/null || echo /tmp/autoir_pkg_$$.err); '
        'out=$(mktemp 2>/dev/null || echo /tmp/autoir_pkg_$$.out); '
        'if command -v rpm >/dev/null 2>&1; then '
        'mgr=rpm; rpm -Va --noscripts >"$out" 2>"$err"; rc=$?; '
        'elif command -v dpkg >/dev/null 2>&1; then '
        'mgr=dpkg; dpkg --verify >"$out" 2>"$err"; rc=$?; '
        'elif command -v apk >/dev/null 2>&1; then '
        'mgr=apk; apk audit --system >"$out" 2>"$err"; rc=$?; '
        'else mgr=none; : >"$out"; printf "rpm/dpkg/apk not found\\n" >"$err"; rc=127; fi; '
        f'printf "{mgr_mark}%s\\n" "$mgr"; '
        f'head -n {max_lines} "$out"; '
        f'printf "\\n{lines_mark}\\n"; '
        'wc -l <"$out"; '
        f'printf "{err_mark}\\n"; '
        'head -n 5 "$err"; '
        f'printf "\\n{rc_mark}%s\\n" "$rc"; '
        'rm -f "$out" "$err"'
    )
    result = exec_command(ssh_session.client, command, timeout=180, max_bytes=400000)
    text = result.get('result') or ''
    if not text:
        return command_failure(result, '软件包完整性校验失败')

    warnings = []
    if result.get('truncated'):
        warnings.append('[TRUNCATED] 软件包校验输出超过上限，结果可能不完整')

    _, _, rest = text.partition(mgr_mark)
    manager = rest.split('\n', 1)[0].strip() if rest else ''
    after_manager = rest.split('\n', 1)[1] if '\n' in rest else ''
    body, _, tail = after_manager.partition(lines_mark)
    total_text, _, err_part = tail.partition(err_mark)
    errors, _, rc_part = err_part.partition(rc_mark)
    try:
        total = int(total_text.strip().splitlines()[-1].strip())
    except (ValueError, IndexError):
        total = None
    try:
        return_code = int(rc_part.strip().splitlines()[0].strip()) if rc_part.strip() else None
    except (ValueError, IndexError):
        return_code = None

    if manager in ('', 'none'):
        return append_warnings('[INFO] 未检测到 rpm/dpkg/apk，无法校验软件包完整性，需人工复核', warnings)

    lines = []
    for raw_line in body.splitlines():
        tag = package_integrity_tag(raw_line, manager)
        if tag:
            lines.append(f'{raw_line.strip()}\t{tag}')

    error_text = errors.strip()
    if error_text:
        error_kind = classify_remote_error_text(error_text)
        if error_kind == 'permission_denied':
            warnings.append(f'[PERMISSION] 软件包校验权限不足，结果可能不完整: {error_text.splitlines()[0][:200]}')
        elif not lines:
            warnings.append(f'[WARN] {manager} 校验提示: {error_text.splitlines()[0][:200]}')
    if return_code not in (None, 0) and not lines and not error_text:
        warnings.append(f'[WARN] {manager} 校验退出码 {return_code}，未返回差异明细')

    if not lines:
        if total:
            return append_warnings(f'[WARN] 软件包校验共有 {total} 条差异，但未能解析明细，需人工复核', warnings)
        return append_warnings(f'[i] {manager} 校验未发现文件差异', warnings)

    header = f'manager: {manager}\t差异文件数: {total if total is not None else len(lines)}'
    if total is not None and total > len(lines):
        warnings.append(f'[TRUNCATED] 共 {total} 条差异，仅展示前 {len(lines)} 条')
    return append_warnings('\n'.join([header] + lines), warnings)


@mcp.tool()
def check_tmp():
    """
    列举常见临时目录（/tmp、/var/tmp、/dev/shm、/run/shm）下的文件。
    调用：排查临时目录落地文件、脚本、内存盘驻留样本或恶意文件时使用。
    输出：返回可疑临时文件路径、属主、权限和时间。
    """

    if not check_session():
        return SESSION_ERROR

    # Malware frequently runs from /dev/shm to avoid disk forensics; /var/tmp
    # survives reboots more often than /tmp. Scan all common locations.
    command = (
        'dirs=""; '
        'for d in /tmp /var/tmp /dev/shm /run/shm; do [ -d "$d" ] && dirs="$dirs $d"; done; '
        'err=$(mktemp 2>/dev/null || echo /tmp/autoir_tmp_$$.err); '
        'out=$(mktemp 2>/dev/null || echo /tmp/autoir_tmp_$$.out); '
        'if [ -n "$dirs" ]; then '
        "find $dirs -xdev -type f -printf '%p\\t%u:%g\\t%m\\t%s bytes\\t%TY-%Tm-%Td %TH:%TM\\n' "
        '>"$out" 2>"$err"; rc=$?; '
        'if [ "$rc" -ne 0 ] && [ ! -s "$out" ]; then '
        'find $dirs -xdev -type f >"$out" 2>>"$err"; fi; '
        'else printf "no temp directory found\\n" >"$err"; fi; '
        'head -n 1000 "$out"; '
        f"printf '\\n{FIND_STDERR_MARK}\\n'; "
        'head -n 5 "$err"; rm -f "$out" "$err"'
    )
    result = exec_command(ssh_session.client, command, timeout=30, max_bytes=300000)
    if not result['status'] and not result['result']:
        return command_failure(result, '临时目录文件扫描失败')
    data, errors = split_find_output(result['result'])
    warnings = []
    if errors:
        if find_printf_fallback_error(errors):
            warnings.append('[INFO] 目标 find 不支持 -printf，已回退到路径列表')
        elif classify_remote_error_text(errors) == 'permission_denied':
            warnings.append(f'[PERMISSION] 临时目录扫描权限不足，结果可能不完整: {errors.splitlines()[0][:200]}')
        else:
            warnings.append(f'[WARN] 临时目录扫描部分失败: {errors.splitlines()[0][:200]}')
    if not data:
        return append_warnings(empty_result(), warnings)

    temp_dirs = ('/dev/shm', '/run/shm', '/var/tmp', '/tmp')
    output = []
    for item in data.splitlines():
        line = item.strip()
        if not line:
            continue
        parts = line.split('\t')
        file_path = parts[0]
        location = next(
            (root for root in temp_dirs if file_path == root or file_path.startswith(root + '/')),
            file_path,
        )
        tag = f'[i] {location} 文件，需复核'
        if len(parts) >= 3 and re.fullmatch(r'[0-7]{3,4}', parts[2].strip()):
            try:
                if int(parts[2].strip(), 8) & 0o111:
                    tag = f'[!] {location} 可执行文件，需优先复核'
            except ValueError:
                pass
        if Path(file_path).name.startswith('.'):
            tag = f'[!] {location} 隐藏文件，需优先复核'
        output.append(f'file path: {file_path}\t{tag}')
    return append_warnings('\n'.join(output) or empty_result(), warnings)


FIND_STDERR_MARK = '@@AUTOIR_FIND_STDERR@@'


def portable_recent_find(paths, days, printf_format, stat_format, max_results):
    """Build a recent-file find command that never hides failures.

    GNU find uses -printf; busybox or restricted find builds fall back to stat
    when the first pass fails without output. stderr is returned after a marker
    so permission and missing-path errors stay visible to the caller instead of
    becoming a false "no changes" result.
    """
    quoted_paths = ' '.join(quote_remote_path(item) for item in paths)
    return (
        'err=$(mktemp 2>/dev/null || echo /tmp/autoir_find_$$.err); '
        'out=$(mktemp 2>/dev/null || echo /tmp/autoir_find_$$.out); '
        f"find {quoted_paths} -type f -mtime -{days} -printf '{printf_format}' >\"$out\" 2>\"$err\"; rc=$?; "
        f'if [ "$rc" -ne 0 ] && [ ! -s "$out" ]; then '
        f"find {quoted_paths} -type f -mtime -{days} -exec stat -c '{stat_format}' {{}} + "
        '>"$out" 2>>"$err"; fi; '
        f'head -n {max_results} "$out"; '
        f"printf '\\n{FIND_STDERR_MARK}\\n'; "
        'head -n 10 "$err"; rm -f "$out" "$err"'
    )


def split_find_output(output):
    data, separator, errors = str(output or '').partition(FIND_STDERR_MARK)
    if not separator:
        return data.strip('\n'), ''
    return data.strip('\n'), errors.strip()


def find_printf_fallback_error(errors):
    lowered = (errors or '').lower()
    return any(token in lowered for token in ('-printf', 'unrecognized option', 'invalid option'))


@mcp.tool()
def check_recent_files(path='/tmp', days=7, max_results=200):
    """
    检查指定目录近期变更文件。
    调用：排查 /tmp、webroot、用户目录中近期落地的脚本、样本、隐藏 shell、免杀马或异常文件时使用。
    输出：返回文件路径、属主、权限、大小和修改时间；find 失败或权限不足会明确标注。
    """
    if not check_session():
        return SESSION_ERROR

    if not isinstance(path, str) or not path.strip() or not path.strip().startswith('/'):
        return "path 必须是目标主机上的绝对路径"
    try:
        days = max(1, min(int(days), 365))
    except (TypeError, ValueError):
        days = 7
    try:
        max_results = max(1, min(int(max_results), 1000))
    except (TypeError, ValueError):
        max_results = 200
    path = path.strip()

    command = portable_recent_find(
        [path],
        days,
        '%TY-%Tm-%Td %TH:%TM\\t%u:%g\\t%m\\t%s bytes\\t%p\\n',
        '%y\\t%U:%G\\t%A\\t%s bytes\\t%n',
        max_results,
    )
    result = exec_command(ssh_session.client, command, timeout=60, max_bytes=300000)
    if not result['status'] and not result['result']:
        return command_failure(result, '近期文件扫描失败')

    data, errors = split_find_output(result['result'])
    warnings = []
    if errors:
        kind = classify_remote_error_text(errors)
        first = errors.splitlines()[0][:200]
        if find_printf_fallback_error(errors):
            warnings.append('[INFO] 目标 find 不支持 -printf，已回退到 stat 输出')
        elif kind == 'permission_denied':
            warnings.append(f'[PERMISSION] 近期文件扫描权限不足，结果可能不完整，需人工复核: {first}')
        elif kind == 'not_found':
            return f'[NOT_FOUND] 路径不存在: {path}\n{first}'
        else:
            warnings.append(f'[WARN] find 扫描部分失败: {first}')

    if not data:
        return append_warnings(empty_result(f'最近 {days} 天未发现变更文件'), warnings)
    output = '\n'.join(f'{line}\t[i] 近期变更文件' for line in data.splitlines())
    return append_warnings(output, warnings)


@mcp.tool()
def discover_webroots(max_results=50):
    """
    自动发现常见 Web 根目录。
    调用：用户要求 WebShell 查杀、Web 入侵排查、隐藏 shell 路径、免杀马路径或不知道站点目录时使用，后续可接 check_webshell 或 check_recent_files。
    输出：返回 webroot 路径、来源、存在状态和浅层文件数量。
    """
    if not check_session():
        return SESSION_ERROR
    try:
        max_results = max(1, min(int(max_results), 200))
    except (TypeError, ValueError):
        max_results = 50

    command = r'''for p in /var/www/html /usr/share/nginx/html /www/wwwroot /home/wwwroot /data/wwwroot /srv/www /opt/lampp/htdocs; do [ -d "$p" ] && printf 'common\t%s\n' "$p"; done
for f in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/apache2/sites-enabled/* /etc/apache2/sites-available/* /etc/httpd/conf/*.conf /etc/httpd/conf.d/*.conf /www/server/panel/vhost/nginx/*.conf /www/server/panel/vhost/apache/*.conf; do
  [ -f "$f" ] || continue
  awk '
    $1 == "root" {gsub(";", "", $2); gsub("\"", "", $2); if ($2 ~ /^\//) printf "config:%s\t%s\n", FILENAME, $2}
    $1 == "DocumentRoot" {gsub("\"", "", $2); if ($2 ~ /^\//) printf "config:%s\t%s\n", FILENAME, $2}
  ' "$f" 2>/dev/null
done'''
    result = exec_command(ssh_session.client, command, timeout=30, max_bytes=200000)
    if not result['status'] and not result['result']:
        return command_failure(result, 'Web 目录发现失败')

    roots = []
    seen = set()
    for line in result.get('result', '').splitlines():
        parts = line.split('\t', 1)
        if len(parts) != 2:
            continue
        source, path = parts[0].strip(), parts[1].strip().rstrip(';')
        if not path.startswith('/') or path in seen:
            continue
        seen.add(path)
        roots.append((source, path))
        if len(roots) >= max_results:
            break

    if not roots:
        return empty_result('未发现常见 Web 根目录')

    output = []
    for source, path in roots:
        quoted = quote_remote_path(path)
        info = exec_command(
            ssh_session.client,
            f"if [ -d {quoted} ]; then count=$(find {quoted} -maxdepth 2 -type f 2>/dev/null | head -n 1001 | wc -l); stat -c '%U:%G\t%A\t%s bytes\t%y' {quoted} 2>/dev/null | sed \"s/^/$count files(max depth 2)\t/\"; else echo 'missing'; fi",
            timeout=15,
            max_bytes=4000,
        )
        detail = info.get('result', '').strip() if info.get('status') else '状态获取失败'
        output.append(f'source: {source}\tpath: {path}\t{detail}\t[i] Web 根目录候选')
    return '\n'.join(output)


WEBROOT_RUN_PATTERN = re.compile(r'^\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}_\d{6}_[0-9a-f]{8}$')


def prune_stale_webshell_runs(max_age_days=None):
    """Remove crash-leftover webroot run directories when retention is set.

    Normal scans always delete their temporary extraction directory. This is
    only a safety net for interrupted runs, disabled by default (0) because an
    extracted webroot can be evidence. Set AUTOIR_WEBSHELL_RETENTION_DAYS to a
    positive value to enable it.
    """
    if max_age_days is None:
        try:
            max_age_days = int(os.environ.get('AUTOIR_WEBSHELL_RETENTION_DAYS', '0'))
        except ValueError:
            max_age_days = 0
    if max_age_days <= 0:
        return
    cutoff = time.time() - max_age_days * 86400
    downloads = Path(base_dir) / 'downloads'
    try:
        entries = list(downloads.iterdir())
    except OSError:
        return
    for entry in entries:
        if not entry.is_dir() or not WEBROOT_RUN_PATTERN.match(entry.name):
            continue
        try:
            if entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry, ignore_errors=True)
        except OSError:
            continue


WEBSHELL_REMOTE_GREP = (
    r'(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)'
    r'|(base64_decode|gzinflate|gzuncompress|str_rot13)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)'
    r'|(call_user_func|array_map)[[:space:]]*\([[:space:]]*\$_(POST|GET)'
    r'|preg_replace[[:space:]]*\([^;]{0,80}/e'
    r'|\$_(POST|GET|REQUEST|COOKIE)[[:space:]]*\[[^]]*\][[:space:]]*\('
    r'|Runtime[.]getRuntime[[:space:]]*\([[:space:]]*\)[.]exec'
    r'|CreateObject[[:space:]]*\([[:space:]]*["]?WScript[.]Shell'
    r'|eval[[:space:]]*\([[:space:]]*String[.]fromCharCode'
)
WEBSHELL_CODE_EXTENSIONS = ('*.php', '*.php3', '*.php4', '*.php5', '*.php7', '*.php8',
                            '*.phtml', '*.phar', '*.jsp', '*.jspx', '*.asp', '*.aspx')
WEB_SHELL_FILENAMES = {
    'shell.php', 'cmd.php', 'backdoor.php', 'webshell.php', 'xiaoma.php',
    'hack.php', 'c99.php', 'r57.php', '1.php', '2.php',
}


def webshell_line_finding(content):
    lower = (content or '').lower()
    if re.search(r'\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(post|get|request|cookie)', lower):
        return '[!] 请求参数直接传入代码执行函数'
    if re.search(r'\b(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*\$_(post|get|request|cookie)', lower):
        return '[!] 请求参数用于解码/解压执行'
    if re.search(r'\b(call_user_func|array_map)\s*\(\s*\$_(post|get)', lower):
        return '[!] 动态函数调用请求参数'
    if re.search(r'preg_replace\s*\([^;]{0,80}/e', lower):
        return '[!] preg_replace /e 代码执行'
    if re.search(r'\$_(post|get|request|cookie)\s*\[[^]]*\]\s*\(', lower):
        return '[!] 请求参数作为函数调用'
    if re.search(r'runtime\.getruntime\s*\(\s*\)\.exec', lower):
        return '[!] JSP Runtime.exec 命令执行'
    if re.search(r'createobject\s*\(\s*["]?wscript\.shell', lower):
        return '[!] ASP WScript.Shell 命令执行'
    if re.search(r'eval\s*\(\s*string\.fromcharcode', lower):
        return '[!] JS 编码代码执行'
    return None


def suspicious_web_filename(file_path):
    normalized = (file_path or '').replace('\\', '/')
    basename = normalized.rsplit('/', 1)[-1]
    lower = basename.lower()
    code_extension = r'\.(?:php\d?|phtml|phar|jsp|jspx|asp|aspx)$'
    if lower in WEB_SHELL_FILENAMES:
        return '[!] 命中常见 WebShell 文件名，需重点复核'
    if lower.startswith('.') and re.search(code_extension, lower):
        return '[!] 隐藏的 Web 脚本文件，需重点复核'
    if re.search(r'(?:php\d?|phtml|phar|jsp|jspx|asp|aspx)\.(?:jpg|jpeg|png|gif|txt|zip|bak|old|tmp|ico)$', lower):
        return '[!] Web 脚本伪装为其他扩展名，需重点复核'
    if re.search(r'/(?:uploads?|wp-content/uploads)/', normalized, re.I) and re.search(code_extension, lower):
        return '[!] 上传目录中的可执行 Web 脚本，需重点复核'
    return None


def remote_web_code_scan(path, max_files=5000):
    """Heuristic remote scan used in addition to (or instead of) HeMa."""
    nonce = get_run_id()
    code_mark = f'@@AUTOIR_WEBSCAN:{nonce}:CODE@@'
    name_mark = f'@@AUTOIR_WEBSCAN:{nonce}:NAME@@'
    quoted_path = quote_remote_path(path)
    name_expression = ' -o '.join(f"-name '{name}'" for name in WEBSHELL_CODE_EXTENSIONS)
    command = (
        'err=$(mktemp 2>/dev/null || echo /tmp/autoir_webscan_$$.err); '
        'list=$(mktemp 2>/dev/null || echo /tmp/autoir_webscan_$$.list); '
        f"printf '{code_mark}\\n'; "
        f'find {quoted_path} -maxdepth 8 -type f -size -5M \\( {name_expression} \\) '
        '-print0 2>>"$err" > "$list"; '
        'if [ -s "$list" ]; then '
        f"xargs -0 grep -nHE -e '{WEBSHELL_REMOTE_GREP}' < \"$list\" 2>>\"$err\" | head -n 100; "
        'fi; '
        f"printf '\\n{name_mark}\\n'; "
        f'tr \'\\0\' \'\\n\' < "$list" | head -n {int(max_files)}; '
        f"printf '\\n{FIND_STDERR_MARK}\\n'; head -n 5 \"$err\"; rm -f \"$list\" \"$err\""
    )
    result = exec_command(ssh_session.client, command, timeout=180, max_bytes=600000)
    text = result.get('result') or ''
    if not text:
        return [], [command_failure(result, '远程 Web 代码启发式扫描失败')]

    warnings = []
    if result.get('truncated'):
        warnings.append('[TRUNCATED] 远程 Web 代码扫描输出超过采集上限，结果可能不完整')
    _, _, rest = text.partition(code_mark)
    code_text, _, rest = rest.partition(name_mark)
    name_text, _, error_text = rest.partition(FIND_STDERR_MARK)
    errors = error_text.strip()
    if 'broken pipe' in errors.lower() or 'write error' in errors.lower():
        # head intentionally closes the pipe after enough hits.
        errors = ''
    if errors:
        kind = classify_remote_error_text(errors)
        first = errors.splitlines()[0][:200]
        if kind == 'permission_denied':
            warnings.append(f'[PERMISSION] 远程 Web 代码扫描权限不足，结果可能不完整: {first}')
        elif kind != 'not_found':
            warnings.append(f'[WARN] 远程 Web 代码扫描部分失败: {first}')

    output = []
    for line in code_text.splitlines():
        parts = line.split(':', 2)
        if len(parts) != 3 or not parts[0].startswith('/'):
            continue
        file_path, lineno, content = parts
        finding = webshell_line_finding(content) or '[!] 远程启发式命中可疑 Web 代码'
        output.append(
            f'file: {file_path}\tline: {lineno}'
            f'\tcontent: {truncate_text(content.strip(), 200)}\t{finding}'
        )
        if len(output) >= 100:
            output.append('[TRUNCATED] 远程启发式命中过多，仅展示前 100 条')
            break

    seen_names = set()
    for file_path in name_text.splitlines():
        file_path = file_path.strip()
        if not file_path.startswith('/') or file_path in seen_names:
            continue
        seen_names.add(file_path)
        finding = suspicious_web_filename(file_path)
        if finding:
            output.append(f'file: {file_path}\t{finding}')
    return output, warnings


@mcp.tool()
def check_webshell(path='/var/www/html', max_files=20000):
    """
    扫描 webroot 中的疑似 WebShell。
    调用：用户要求 WebShell 查杀、Web 入侵排查、查找黑客 shell、隐藏 shell 或免杀马时使用；传入站点目录，工具会打包下载并调用本地扫描器分析。
    输出：返回疑似文件路径、MD5 或扫描器错误。
    """

    if not check_session():
        return SESSION_ERROR

    prune_stale_webshell_runs()

    output = ''
    if not isinstance(path, str) or not path.strip() or not path.strip().startswith('/'):
        return "path 必须是目标主机上的绝对路径"
    try:
        max_files = max(1, min(int(max_files), 100000))
    except (TypeError, ValueError):
        max_files = 20000
    path = path.strip()
    quoted_path = quote_remote_path(path)

    # Keep find's stderr: redirecting it to /dev/null makes permission errors
    # and missing paths look like an empty webroot.
    count_result = exec_command(
        ssh_session.client,
        f"err=$(mktemp); find {quoted_path} -type f 2>\"$err\" | head -n {max_files + 1} | wc -l; "
        f"head -n 5 \"$err\"; rm -f \"$err\"",
        timeout=30,
        max_bytes=2000,
    )
    if not count_result['status'] and not count_result['result']:
        return command_failure(count_result, 'webroot 文件计数失败')
    lines = count_result['result'].splitlines()
    try:
        file_count = int(lines[0].strip())
    except (IndexError, ValueError):
        return command_failure(count_result, 'webroot 文件计数失败')

    find_errors = '\n'.join(lines[1:]).strip()
    if find_errors:
        kind = classify_remote_error_text(find_errors)
        if kind == 'not_found':
            return f'[NOT_FOUND] webroot 路径不存在: {path}'
        if kind == 'permission_denied':
            output += '[PERMISSION] webroot 文件枚举权限不足，扫描范围可能不完整，需人工复核\n'
        elif kind == 'error':
            return remote_result_issue(
                {'status': False, 'result': find_errors}, path, '枚举 webroot', include_missing=True
            ) or command_failure(count_result, 'webroot 文件枚举失败')

    if file_count == 0:
        return output or empty_result('webroot 目录未发现文件')
    if file_count > max_files:
        return f'webroot 文件数量超过限制 {max_files}，请缩小扫描目录或提高 max_files'

    if file_count:
        size_result = exec_command(ssh_session.client, f"du -sb {quoted_path} 2>/dev/null | awk '{{print $1}}'", timeout=20, max_bytes=1000)
        if size_result['status'] and size_result['result']:
            try:
                if int(size_result['result'].splitlines()[0]) > 500 * 1024 * 1024:
                    return output + 'webroot 总大小超过 500MB，未执行打包扫描；请缩小扫描目录'
            except (IndexError, ValueError):
                pass

        heuristic_lines, heuristic_warnings = remote_web_code_scan(path, max_files)
        for line in heuristic_lines:
            output += line + '\n'
        for warning in heuristic_warnings:
            output += warning + '\n'

        run_id = get_run_id()
        remote_archive = f'/tmp/autoir_webroot_{run_id}.tar.gz'
        quoted_remote_archive = quote_remote_path(remote_archive)
        local_path = Path(base_dir) / 'downloads' / run_id
        archive_path = local_path / 'webroot.tar.gz'
        download_result = {'status': False, 'error': ''}
        try:
            # Packaging a large webroot routinely takes minutes; the default
            # 10s command timeout made this tool fail on realistic sites.
            tar_result = exec_command(
                ssh_session.client,
                f'tar -zcf {quoted_remote_archive} -C {quoted_path} .',
                timeout=300,
                max_bytes=20000,
            )
            if not tar_result['status']:
                return output + command_failure(tar_result, 'webroot 打包失败')
            local_path.mkdir(parents=True, exist_ok=True)
            download_result = sftp_download(
                ssh_session.client,
                remote_archive,
                str(archive_path),
                timeout=300,
                max_bytes=512 * 1024 * 1024,
            )
        finally:
            exec_command(ssh_session.client, f'rm -f {quoted_remote_archive}', timeout=5, max_bytes=1000)
        if not download_result.get('status') or not archive_path.exists():
            return output + f'webroot 下载失败：{download_result.get("error") or "未生成本地压缩包"}'

        try:
            extracted_bytes = 0
            max_extract_bytes = 2 * 1024 * 1024 * 1024
            with tarfile.open(archive_path, 'r:gz') as tar:
                member_count = 0
                for member in tar:
                    member_count += 1
                    if member_count > max_files:
                        return output + f'压缩包成员数量超过限制 {max_files}，已停止解压'
                    if not is_safe_tar_member(local_path, member):
                        server_path = path.rstrip('/') + '/' + member.name.replace('\\', '/')
                        output += f'file path: {server_path}\t[!] 路径/类型/大小异常已拦截\n'
                        continue
                    extracted_bytes += max(member.size, 0)
                    if extracted_bytes > max_extract_bytes:
                        return output + '解压后总大小超过限制 2GB，已停止解压'
                    try:
                        tar.extract(member, local_path, filter='data')
                    except TypeError:
                        # Python < 3.12 has no extraction filter; manual checks above
                        # already reject links, devices, FIFOs and traversal.
                        tar.extract(member, local_path)

            scanner_dir = Path(base_dir) / 'extensions' / 'HeMa'
            scanner_names = ('hm.exe', 'hm') if os.name == 'nt' else ('hm', 'hm.exe')
            scanner_path = next(
                (scanner_dir / candidate for candidate in scanner_names
                 if (scanner_dir / candidate).is_file()),
                None,
            )
            if scanner_path is None:
                return (
                    output
                    + f'扫描器不存在: {scanner_dir / scanner_names[0]}'
                    + '（未执行 HeMa 扫描；已完成远程启发式扫描，仍建议人工复核）'
                )
            result_path = scanner_dir / 'result.csv'
            rows = []
            # HeMa writes a shared result.csv; serialize scans so concurrent calls
            # cannot mix each other's findings.
            with webshell_lock:
                try:
                    result_path.unlink()
                except OSError:
                    pass
                try:
                    result = subprocess.run(
                        [str(scanner_path), 'scan', str(local_path)],
                        capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=300,
                    )
                except subprocess.TimeoutExpired:
                    return output + '扫描器执行超时'
                except OSError as error:
                    return output + f'扫描器执行失败: {error}'

                count = 0
                summary_found = False
                for line in result.stdout.splitlines():
                    if "总计" in line:
                        summary_found = True
                        try:
                            count = int(line.replace(' ', '').split('|')[-2])
                        except (IndexError, ValueError):
                            count = 0

                if result.returncode != 0:
                    if not result_path.exists():
                        detail = (result.stderr or result.stdout).strip()
                        return output + (
                            f'扫描器执行失败 (exit {result.returncode}): '
                            f'{truncate_text(detail, 500) or "无输出"}'
                        )
                    output += f'[WARN] 扫描器退出码为 {result.returncode}，已尝试解析现有 result.csv，需人工复核\n'
                if count and not result_path.exists():
                    return output + f'扫描器报告疑似 {count} 个文件，但未生成 result.csv'
                if not summary_found and not result_path.exists():
                    detail = (result.stderr or result.stdout).strip()
                    return output + f'扫描器输出无法解析，检测结果未知: {truncate_text(detail, 500) or "无输出"}'

                # Parse any result.csv even when the summary line is missing or
                # unparsable; missing findings are worse than extra findings.
                if result_path.exists():
                    try:
                        csvfile = open(result_path, 'r', encoding='utf-8', errors='ignore')
                    except OSError as error:
                        return output + f'扫描器结果读取失败: {error}'
                    with csvfile:
                        csv_reader = csv.reader(csvfile, delimiter=',')
                        next(csv_reader, None)  # 跳过表头
                        rows = [row for row in csv_reader if len(row) >= 3]

            for row in rows:
                raw_path = Path(row[2])
                file_path = raw_path if raw_path.is_absolute() else local_path / raw_path
                if not file_path.is_file():
                    output += f'file path: {row[2]}\t[!] 扫描器报告文件未能定位，需人工复核\n'
                    continue
                try:
                    md5 = file_md5(file_path)
                except OSError:
                    md5 = '读取失败'
                try:
                    relative = file_path.relative_to(local_path).as_posix()
                except ValueError:
                    relative = row[2].replace('\\', '/')
                server_path = path.rstrip('/') + '/' + relative
                output += f'file path: {server_path}\tmd5: {md5}\t[!] 疑似 webshell 文件\n'
        finally:
            # Extracted webroots can reach 2GB; keep them only while the scan
            # needs them so repeated investigations cannot fill the disk.
            shutil.rmtree(local_path, ignore_errors=True)
    return output or empty_result('未发现疑似 webshell')


# Printable markers survive exec_command's output stripping; the per-call
# nonce keeps attacker-controlled file content from forging them.
BATCH_FILE_MARK = '@@AUTOIR_FILE:'
BATCH_STATUS_MARK = '@@AUTOIR_STATUS:'
BATCH_FILE_CHUNK = 40


def get_files(directory, warnings=None):
    file_list = []
    result = exec_command(ssh_session.client, f'ls -al {quote_remote_path(directory)}')
    kind = classify_remote_result(result)
    if kind == 'ok':
        for file in get_file_list(result['result']).values():
            filename = file['filename']
            if '->' in filename:
                filename = filename.split(' -> ')[0]
            file_list.append(filename)
    elif kind != 'not_found' and warnings is not None:
        warnings.append(remote_result_issue(result, directory, '列出目录'))
    return file_list


def parse_batched_file_output(output):
    """Parse markers emitted by read_remote_files()."""
    entries = []
    current = None
    for line in (output or '').split('\n'):
        line = line.rstrip('\r')
        if line.startswith(BATCH_FILE_MARK):
            if current is not None:
                entries.append(current)
            payload = line[len(BATCH_FILE_MARK):]
            # Batches prefix a per-call nonce so attacker-controlled file
            # content cannot forge markers; accept legacy paths starting with /.
            path = payload if payload.startswith('/') else payload.split(':', 1)[-1]
            current = {'path': path, 'lines': [], 'code': None}
        elif line.startswith(BATCH_STATUS_MARK):
            if current is not None:
                payload = line[len(BATCH_STATUS_MARK):]
                try:
                    current['code'] = int(payload.split(':', 1)[-1])
                except ValueError:
                    current['code'] = 1
                entries.append(current)
                current = None
        elif current is not None:
            current['lines'].append(line)
    if current is not None:
        entries.append(current)
    return [
        {
            'path': entry['path'],
            'content': '\n'.join(entry['lines']),
            'code': entry['code'] if entry['code'] is not None else 1,
        }
        for entry in entries
    ]


def read_remote_files(paths, warnings=None, timeout=30, max_bytes=500000):
    """Read many remote files in few SSH round trips.

    Files are read in chunks of BATCH_FILE_CHUNK with one shell command per
    chunk. Each file gets an explicit exit code so permission failures are not
    silently reported as clean.
    """
    unique_paths = list(dict.fromkeys(path for path in paths if path))
    results = []
    for offset in range(0, len(unique_paths), BATCH_FILE_CHUNK):
        chunk = unique_paths[offset:offset + BATCH_FILE_CHUNK]
        nonce = get_run_id()
        script = []
        for path in chunk:
            quoted = quote_remote_path(path)
            script.append(
                f"printf '@@AUTOIR_FILE:{nonce}:%s\\n' {quoted}\n"
                f"cat {quoted} 2>&1\n"
                f"printf '\\n@@AUTOIR_STATUS:{nonce}:%s\\n' \"$?\""
            )
        result = exec_command(
            ssh_session.client,
            '\n'.join(script),
            timeout=timeout,
            max_bytes=max_bytes,
        )
        if result.get('truncated') and warnings is not None:
            warnings.append('[TRUNCATED] 批量文件读取输出超过上限，部分文件内容可能不完整')
        parsed = parse_batched_file_output(result.get('result', ''))
        if not parsed:
            kind = classify_remote_result(result)
            if kind != 'not_found' and warnings is not None:
                issue = remote_result_issue(result, f'{len(chunk)} 个文件', '批量读取')
                if issue:
                    warnings.append(issue)
            for path in chunk:
                results.append({
                    'path': path,
                    'content': '',
                    'status': kind if kind != 'ok' else 'error',
                    'exists': False,
                })
            continue
        for entry in parsed:
            if entry['code'] == 0:
                status, exists = 'ok', True
            else:
                status = classify_remote_error_text(entry['content'])
                exists = False
                issue = remote_error_issue(status, entry['path'], entry['content'], '读取')
                if issue and warnings is not None:
                    warnings.append(issue)
            results.append({
                'path': entry['path'],
                'content': entry['content'],
                'status': status,
                'exists': exists,
            })

        # A large file can consume the chunk's byte budget and cut off markers
        # for later files. Never silently drop those paths.
        returned = {entry['path'] for entry in parsed}
        missing = [path for path in chunk if path not in returned]
        if missing and warnings is not None:
            preview = ', '.join(missing[:5]) + ('...' if len(missing) > 5 else '')
            warnings.append(
                f'[TRUNCATED] 批量读取未返回 {len(missing)} 个文件（输出可能被截断）: {preview}'
            )
        for path in missing:
            results.append({
                'path': path,
                'content': '',
                'status': 'error',
                'exists': False,
            })
    return results


def check_malicious_content_batch(paths, warnings=None):
    output = ''
    for entry in read_remote_files(paths, warnings=warnings):
        if entry['status'] != 'ok':
            continue
        for line in entry['content'].splitlines():
            if line.startswith('#'):
                continue
            malicious = detect_malicious_text(line.strip(), warnings=warnings)
            if malicious:
                output += f'file: {entry["path"]}\tcontent: {malicious}\t[!] 恶意命令执行\n'
    return output


def check_malicious_content(file_path, warnings=None):
    return check_malicious_content_batch([file_path], warnings=warnings)


@mcp.tool()
def check_ld_so_preload():
    """
    检查 /etc/ld.so.preload 后门。
    调用：怀疑动态库预加载、命令劫持或持久化时使用。
    输出：返回非注释预加载库路径。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''
    warnings = []

    for entry in read_remote_files(['/etc/ld.so.preload'], warnings=warnings):
        if entry['status'] == 'ok':
            for line in entry['content'].splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    output += f'{line}\t[!] ld.so.preload 后门！\n'
        elif entry['status'] != 'not_found':
            issue = remote_error_issue(entry['status'], entry['path'], entry['content'], '读取')
            return append_warnings(issue or empty_result(), warnings)

    return append_warnings(output or empty_result(), warnings)


@mcp.tool()
def check_cron():
    """
    扫描 cron 计划任务中的可疑命令。
    调用：排查定时持久化、反弹任务或恶意下载执行时使用。
    输出：返回可疑任务文件和命中内容。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''
    warnings = []

    cron_dirs = ['/var/spool/cron', '/etc/cron.d', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.hourly', '/etc/cron.monthly']
    cron_files = ['/etc/crontab']

    for cron_dir in cron_dirs:
        for file in get_files(cron_dir, warnings=warnings):
            cron_files.append(f'{cron_dir}/{file}')

    output = check_malicious_content_batch(cron_files, warnings=warnings)
    return append_warnings(output or empty_result(), warnings)


@mcp.tool()
def check_ssh():
    """
    检查 /usr/sbin/sshd 是否被软链接劫持。
    调用：怀疑 SSH 后门、sshd 被替换或异常端口服务时使用。
    输出：返回 sshd 链接信息和风险提示。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''

    result = exec_command(ssh_session.client, 'ls -al /usr/sbin/sshd 2>&1')
    kind = classify_remote_result(result)
    if kind == 'not_found':
        return '[NOT_FOUND] /usr/sbin/sshd 不存在，需人工确认 SSH 服务实际路径'
    if kind == 'permission_denied':
        return remote_result_issue(result, '/usr/sbin/sshd', '读取', include_missing=True) or command_failure(
            result, '/usr/sbin/sshd 检查失败'
        )
    if kind != 'ok':
        return command_failure(result, '/usr/sbin/sshd 检查失败')
    if result['result']:
        text = result['result'].strip()
        if ' -> ' in text:
            target = text.split(' -> ', 1)[1].strip()
            # A symlink is unusual for sshd but also a legitimate packaging
            # choice on some systems; require manual confirmation instead of
            # declaring a hijack from ls output alone.
            output += f'content: {text}\t[i] /usr/sbin/sshd 是软链接 -> {target}，需人工复核\n'

    return output or empty_result()


@mcp.tool()
def check_ssh_wrapper():
    """
    检查 sshd 二进制中的可疑字符串。
    调用：怀疑 SSH wrapper 后门或 sshd 被脚本/恶意逻辑包装时使用。
    输出：返回命中的可疑内容。
    """

    if not check_session():
        return SESSION_ERROR

    output = ''
    warnings = []

    result = exec_command(ssh_session.client, 'strings -a /usr/sbin/sshd 2>/dev/null', timeout=30, max_bytes=1_000_000)
    if not result['status'] and not result['result']:
        return command_failure(result, 'sshd strings 提取失败')
    if result.get('truncated'):
        warnings.append('[TRUNCATED] sshd strings 输出超过 max_bytes，结果可能不完整')
    if result['result']:
        for line in result['result'].splitlines():
            malicious = detect_malicious_text(line.strip(), warnings=warnings)
            if malicious:
                if '\033' in malicious:
                    output += f'file: {"/usr/sbin/sshd"}\tcontent: {malicious}\t[!] 恶意 shell 命令\n'
                else:
                    output += f'file: {"/usr/sbin/sshd"}\tcontent: {malicious}\t[!] ssh wrapper 劫持\n'

    return append_warnings(output or empty_result(), warnings)


@mcp.tool()
def check_inetd():
    """
    检查 /etc/inetd.conf 中的可疑后门配置。
    调用：排查 inetd 持久化或网络服务触发命令执行时使用。
    输出：返回可疑配置内容。
    """

    if not check_session():
        return SESSION_ERROR

    warnings = []
    output = check_malicious_content('/etc/inetd.conf', warnings=warnings)
    return append_warnings(output or empty_result(), warnings)


@mcp.tool()
def check_xinetd():
    """
    检查 xinetd 配置中的可疑后门。
    调用：排查 xinetd 服务持久化、反弹 shell 或异常执行路径时使用。
    输出：返回可疑配置文件和命中内容。
    """

    if not check_session():
        return SESSION_ERROR

    warnings = []

    # /etc/xinetd.conf is a file; service definitions live in /etc/xinetd.d/.
    xinetd_files = ['/etc/xinetd.conf']
    for file in get_files('/etc/xinetd.d', warnings=warnings):
        xinetd_files.append(f'/etc/xinetd.d/{file}')

    output = check_malicious_content_batch(xinetd_files, warnings=warnings)
    return append_warnings(output or empty_result(), warnings)


def _php_directive_value(line, directive):
    match = re.search(
        rf'\b{re.escape(directive)}\s*(?:=|\s)\s*["\']?([^"\'\s;]+)',
        line,
        re.I,
    )
    return match.group(1) if match else ''


def web_persistence_finding(filename, line):
    """Detect PHP/Apache persistence directives in web or PHP config files."""
    stripped = line.strip()
    if not stripped or stripped.startswith(('#', ';', '//')):
        return None
    basename = filename.replace('\\', '/').rsplit('/', 1)[-1].lower()

    prepend = _php_directive_value(stripped, 'auto_prepend_file') or _php_directive_value(stripped, 'auto_append_file')
    if prepend and prepend.lower() not in ('none', 'off', '0', '""', "''"):
        directive = 'auto_prepend_file' if 'auto_prepend_file' in stripped.lower() else 'auto_append_file'
        return f'[!] {directive} 自动包含外部文件: {prepend}'

    if basename in ('php.ini', '.php.ini') or basename.endswith('.ini'):
        if re.match(r'^\s*allow_url_include\s*=\s*(?:on|1|true|yes)\b', stripped, re.I):
            return '[!] allow_url_include 开启，允许远程包含代码'
        extension_dir = _php_directive_value(stripped, 'extension_dir')
        if extension_dir and extension_dir.startswith(('/tmp/', '/var/tmp/', '/dev/shm/')):
            return f'[!] PHP extension_dir 指向临时目录: {extension_dir}'
        extension_match = re.match(r'^\s*extension\s*=\s*["\']?(/[^"\'\s;]+)', stripped, re.I)
        if extension_match:
            extension_path = extension_match.group(1)
            if not extension_path.startswith((
                '/usr/lib/php', '/usr/lib64/php', '/usr/local/lib/php',
                '/usr/local/php/lib/php',
            )):
                return f'[!] PHP 从非标准路径加载扩展: {extension_path}'

    if basename.startswith('.htaccess'):
        if re.search(r'\bphp_(?:admin_)?value\s+auto_(?:prepend|append)_file\b', stripped, re.I):
            return f'[!] .htaccess 配置 PHP 自动包含: {truncate_text(stripped, 200)}'
        if re.match(r'^\s*(?:AddHandler|AddType|SetHandler)\b', stripped, re.I) and re.search(
            r'application/x-httpd-php|php[0-9]?\b', stripped, re.I
        ):
            return f'[!] .htaccess 修改 PHP 处理器，上传文件可能被执行: {truncate_text(stripped, 200)}'
        if re.match(r'^\s*php_(?:admin_)?flag\s+engine\s+on\b', stripped, re.I):
            return '[i] .htaccess 强制开启 PHP 引擎，需结合上传目录复核'
        if 'ExecCGI' in stripped:
            return '[i] .htaccess 开启 ExecCGI，需结合目录用途复核'
    return None


@mcp.tool()
def check_web_persistence(path='/var/www'):
    """
    检查 PHP/Web 配置文件中的自动包含与处理器持久化。
    调用：排查 .user.ini、.htaccess、php.ini 中 auto_prepend_file、allow_url_include、PHP handler 等持久化时使用。
    输出：返回文件、行号、命中内容和风险标记。
    """

    if not check_session():
        return SESSION_ERROR
    if not isinstance(path, str) or not path.strip().startswith('/'):
        return 'path 必须是目标主机上的绝对路径'
    path = path.strip()
    quoted_path = quote_remote_path(path)

    command = (
        'err=$(mktemp 2>/dev/null || echo /tmp/autoir_webpersist_$$.err); '
        '{ for f in /etc/php.ini /etc/php/*/cli/php.ini /etc/php/*/apache2/php.ini '
        '/etc/php/*/fpm/php.ini /etc/php/*/cgi/php.ini /etc/php/*/conf.d/*.ini '
        '/etc/php/*/mods-available/*.ini /etc/php.d/*.ini '
        '/usr/local/php/etc/php.ini /usr/local/etc/php/php.ini; do '
        '[ -f "$f" ] && printf \'%s\\n\' "$f"; done; '
        f'find {quoted_path} -maxdepth 8 -type f \\( -name \'.user.ini\' -o -name \'.htaccess\' '
        "-o -name '.htaccess.*' -o -name 'php.ini' -o -name '.php.ini' \\) "
        '-print 2>>"$err"; } | sort -u | head -n 300; '
        f"printf '\\n{FIND_STDERR_MARK}\\n'; head -n 5 \"$err\"; rm -f \"$err\""
    )
    result = exec_command(ssh_session.client, command, timeout=60, max_bytes=120000)
    if not result['status'] and not result['result']:
        return command_failure(result, 'Web/PHP 配置枚举失败')

    data, errors = split_find_output(result['result'])
    warnings = []
    if errors:
        kind = classify_remote_error_text(errors)
        first = errors.splitlines()[0][:200]
        if kind == 'permission_denied':
            warnings.append(f'[PERMISSION] Web/PHP 配置枚举权限不足，结果可能不完整: {first}')
        elif kind == 'not_found':
            warnings.append(f'[NOT_FOUND] 站点目录不存在或不可读: {first}')
        else:
            warnings.append(f'[WARN] Web/PHP 配置枚举部分失败: {first}')

    paths = [line.strip() for line in data.splitlines() if line.strip().startswith('/')]
    paths = list(dict.fromkeys(paths))[:300]
    if not paths:
        return append_warnings(
            empty_result('未发现 .user.ini、.htaccess 或 php.ini 配置'),
            warnings,
        )

    output = []
    readable = 0
    for entry in read_remote_files(paths, warnings=warnings, timeout=60, max_bytes=600000):
        if entry['status'] != 'ok':
            continue
        readable += 1
        for lineno, line in enumerate(entry['content'].splitlines(), 1):
            finding = web_persistence_finding(entry['path'], line)
            if finding:
                output.append(
                    f'file: {entry["path"]}\tline: {lineno}'
                    f'\tcontent: {truncate_text(line.strip(), 300)}\t{finding}'
                )
    if not readable:
        return append_warnings('[FAILED] Web/PHP 配置文件均无法读取，需人工复核', warnings)
    if not output:
        return append_warnings(
            empty_result(f'已检查 {readable} 个 Web/PHP 配置文件，未发现持久化特征'),
            warnings,
        )
    return append_warnings('\n'.join(output), warnings)


COMMON_SUID_SGID_PATHS = {
    '/bin/at', '/bin/chage', '/bin/expiry', '/bin/gpasswd', '/bin/mount',
    '/bin/newgrp', '/bin/passwd', '/bin/ping', '/bin/ping6', '/bin/su',
    '/bin/umount', '/sbin/mount.cifs', '/sbin/mount.nfs', '/usr/bin/at',
    '/usr/bin/chfn', '/usr/bin/chsh', '/usr/bin/crontab', '/usr/bin/expiry',
    '/usr/bin/fusermount', '/usr/bin/fusermount3', '/usr/bin/gpasswd',
    '/usr/bin/mount', '/usr/bin/newgrp', '/usr/bin/nsenter',
    '/usr/bin/passwd', '/usr/bin/ping', '/usr/bin/ping6', '/usr/bin/pkexec',
    '/usr/bin/rcp', '/usr/bin/rlogin', '/usr/bin/rsh', '/usr/bin/su',
    '/usr/bin/sudo', '/usr/bin/umount', '/usr/bin/wall', '/usr/bin/write',
    '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',
    '/usr/lib/openssh/ssh-keysign', '/usr/lib/policykit-1/polkit-agent-helper-1',
    '/usr/lib/pt_chown', '/usr/lib/snapd/snap-confine',
    '/usr/lib/utempter/utempter', '/usr/libexec/openssh/ssh-keysign',
    '/usr/sbin/mount.cifs', '/usr/sbin/mount.nfs',
}


@mcp.tool()
def check_setuid():
    """
    查找 SUID/SGID 文件。
    调用：排查本地提权后门或异常 SUID 程序时使用。
    输出：返回发现的 SUID/SGID 文件、属主和模式；常见系统程序标记为需校验，非典型路径标记为需人工复核；覆盖所有本地挂载点。
    """

    if not check_session():
        return SESSION_ERROR

    output = []
    warnings = []

    command = (
        'err=$(mktemp 2>/dev/null || echo /tmp/autoir_suid_$$.err); '
        'out=$(mktemp 2>/dev/null || echo /tmp/autoir_suid_$$.out); '
        'dirs=$(df -P -l 2>/dev/null | awk \'NR>1 {print $6}\' | sort -u); '
        '[ -n "$dirs" ] || dirs=/; '
        'for d in $dirs; do '
        'case "$d" in /proc*|/sys*|/mnt*|/media*) continue;; esac; '
        'find "$d" -xdev -type f \\( -perm -4000 -o -perm -2000 \\) '
        '-exec stat -c \'%A %U:%G %n\' {} + >>"$out" 2>>"$err"; '
        'done; '
        'sort -u "$out" | head -n 2000; '
        f"printf '\\n{FIND_STDERR_MARK}\\n'; "
        'head -n 10 "$err"; rm -f "$out" "$err"'
    )
    result = exec_command(ssh_session.client, command, timeout=120, max_bytes=500000)
    if not result['status'] and not result['result']:
        return command_failure(result, 'SUID/SGID 文件扫描失败')

    data, errors = split_find_output(result['result'])
    if errors:
        kind = classify_remote_error_text(errors)
        first = errors.splitlines()[0][:200]
        if kind == 'permission_denied':
            warnings.append(f'[PERMISSION] SUID/SGID 扫描权限不足，结果可能不完整，需人工复核: {first}')
        else:
            warnings.append(f'[WARN] SUID/SGID 扫描部分失败: {first}')

    for line in data.splitlines():
        parts = line.split(' ', 2)
        if len(parts) < 3:
            continue
        mode, owner, file_path = parts
        if not file_path.startswith('/'):
            continue
        flags = []
        if len(mode) >= 4 and mode[3] in 'sS':
            flags.append('SUID')
        if len(mode) >= 7 and mode[6] in 'sS':
            flags.append('SGID')
        if not flags:
            continue
        label = '/'.join(flags)
        if owner.split(':', 1)[0] != 'root':
            output.append(
                f'{file_path}\tmode: {mode}\towner: {owner}\t[!] {label} 属主非 root，需人工复核'
            )
        elif file_path in COMMON_SUID_SGID_PATHS:
            output.append(
                f'{file_path}\tmode: {mode}\towner: {owner}\t[i] 常见 {label} 程序，建议核对包完整性'
            )
        else:
            output.append(
                f'{file_path}\tmode: {mode}\towner: {owner}\t[!] 非典型 {label}，需人工复核'
            )

    if not output:
        return append_warnings(empty_result('未发现 SUID/SGID 文件'), warnings)
    return append_warnings('\n'.join(output), warnings)


@mcp.tool()
def check_startup():
    """
    扫描系统启动项中的可疑命令。
    调用：排查 init、rc.local、systemd 等启动持久化时使用。
    输出：返回可疑启动项文件和命中内容。
    """

    if not check_session():
        return SESSION_ERROR

    warnings = []

    init_paths = ['/etc/init.d', '/etc/rc.d', '/etc/systemd/system', '/usr/local/etc/rc.d']
    init_files = ['/etc/rc.local', '/usr/local/etc/rc.local', '/etc/conf.d/local.start', '/etc/inittab']

    files = []
    for path in init_paths:
        for file in get_files(path, warnings=warnings):
            files.append(f'{path}/{file}')
    files.extend(init_files)

    output = check_malicious_content_batch(files, warnings=warnings)
    return append_warnings(output or empty_result(), warnings)


@mcp.tool()
def check_profile():
    """
    扫描 /etc/profile.d 脚本。
    调用：排查登录即触发的持久化、环境变量注入或命令劫持时使用。
    输出：返回可疑脚本和命中内容。
    """

    if not check_session():
        return SESSION_ERROR

    warnings = []

    files = [f'/etc/profile.d/{file}' for file in get_files('/etc/profile.d', warnings=warnings)]
    output = check_malicious_content_batch(files, warnings=warnings)
    return append_warnings(output or empty_result(), warnings)


@mcp.tool()
def check_rc():
    """
    扫描系统与用户 shell 初始化脚本。
    调用：排查 .bashrc、profile、cshrc 等登录持久化或环境劫持时使用。
    输出：返回可疑脚本和命中内容。
    """

    if not check_session():
        return SESSION_ERROR

    warnings = []

    init_paths = ['/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/etc/bashrc',
                  '/etc/profile', '/etc/csh.login', '/etc/csh.cshrc']
    init_files = ['.bashrc', '.bash_profile', '.tcshrc', '.cshrc']

    files = list(init_paths)
    for user in load_home_users(warnings=warnings):
        for file in init_files:
            files.append(f'/home/{user}/{file}')

    output = check_malicious_content_batch(files, warnings=warnings)
    return append_warnings(output or empty_result(), warnings)


pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
    r'(?P<status>\d{3}) (?P<size>\d+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)

WEB_ATTACK_PATTERNS = (
    (re.compile(r'(?:\.\./|%2e%2e%2f|/etc/(?:passwd|shadow)|(?:^|\s)/proc/self/)', re.I),
     '[!] 路径穿越/敏感文件探测'),
    (re.compile(r'(?:union(?:\s|%20|\+)+select|information_schema|extractvalue\s*\(|updatexml\s*\()', re.I),
     '[!] SQL 注入特征'),
    (re.compile(r'\bsleep\s*\(\s*\d|\bbenchmark\s*\(', re.I),
     '[!] SQL 注入/延时探测特征'),
    (re.compile(r'(?:php://(?:input|filter)|data://|expect://|phar://)', re.I),
     '[!] PHP 伪协议/代码执行特征'),
    (re.compile(r'(?:;\s*|\|\s*|\$\(\s*|`\s*)(?:cat|ls|id|whoami|uname|wget|curl|bash|sh|nc|python|perl)\b', re.I),
     '[!] 命令注入特征'),
    (re.compile(r'(?:^|/)(?:shell|cmd|backdoor|webshell|xiaoma|hack|1)\.(?:php\d?|phtml|jsp|jspx|asp|aspx)\b', re.I),
     '[!] 疑似 WebShell 路径访问'),
    (re.compile(r'(?:^|/)(?:uploads?|wp-content/uploads)/[^?\s]*\.(?:php\d?|phtml|jsp|jspx|asp|aspx)\b', re.I),
     '[!] 上传目录中的 Web 脚本访问'),
    (re.compile(r'(?:^|/)(?:\.git/|\.env\b|wp-config\.php|phpmyadmin\b|manager/html|actuator\b|solr/|console/)', re.I),
     '[i] 敏感路径探测'),
)
SCANNER_USER_AGENT = re.compile(
    r'(?:sqlmap|nikto|nmap|masscan|dirsearch|gobuster|ffuf|wpscan|acunetix|nessus|zgrab|nuclei|xray|fscan|whatweb)',
    re.I,
)


def web_attack_reason(text):
    for regex, reason in WEB_ATTACK_PATTERNS:
        if regex.search(text or ''):
            return reason
    if SCANNER_USER_AGENT.search(text or ''):
        return '[i] 扫描器/自动化工具特征'
    return None


@mcp.tool()
def check_log(path='/var/log/apache2/access.log', max_lines=5000):
    """
    分析 Apache access.log。
    调用：排查 Web 攻击、恶意 URI、异常状态码和 User-Agent 时使用；path 可指定日志路径。
    输出：返回恶意请求和访问统计。
    """

    if not check_session():
        return SESSION_ERROR

    try:
        max_lines = max(1, min(int(max_lines), 50000))
    except (TypeError, ValueError):
        max_lines = 5000

    output = [f'仅分析最近 {max_lines} 行日志']

    result = exec_command(ssh_session.client, f'tail -n {int(max_lines)} {quote_remote_path(path)}', timeout=20)
    if not result['status']:
        issue = remote_result_issue(result, path, '读取', include_missing=True)
        return issue or command_failure(result, '日志读取失败')
    if result.get('truncated'):
        output.append('[TRUNCATED] 日志输出超过采集上限，统计和特征匹配可能不完整')
    if not result['result']:
        return empty_result('日志为空或无可读内容')

    checked_lines = set()
    for line in result['result'].splitlines():
        stripped = line.strip()
        if stripped in checked_lines:
            continue
        checked_lines.add(stripped)
        if detect_malicious_text(stripped, use_safeline=False):
            output.append(f'url: {urllib.parse.unquote(stripped)}\t[!] 恶意请求')

    request_success = []
    request_jump = []
    request_others = []
    all_requests = []
    user_agents = set()
    for match in pattern.finditer(result['result']):
        request = match.groupdict()
        all_requests.append(request)
        status = request['status']
        user_agents.add(request['user_agent'])
        if status == '200' and len(request['path']) != 1:
            request_success.append(request)
        elif status == '302':
            request_jump.append(request)
        else:
            request_others.append(request)

    def add_ip_counts(title, requests):
        counts = collections.Counter(request['ip'] for request in requests).most_common()
        output.append(title)
        output.extend(f'\tip: {ip}\tcount: {count}' for ip, count in counts[:50])
        if len(counts) > 50:
            output.append(f'\t[TRUNCATED] 共 {len(counts)} 个来源 IP，仅展示前 50 个')

    add_ip_counts('成功访问 IP 统计', request_success)
    add_ip_counts('\n跳转访问 IP 统计', request_jump)
    add_ip_counts('\n失败访问 IP 统计', request_others)

    output.append('\n访问 User-Agent 统计')
    top_agents = collections.Counter(user_agents).most_common(50)
    output.extend(f'\tUser-Agent: {user_agent}\tcount: {count}' for user_agent, count in top_agents)
    if len(user_agents) > 50:
        output.append(f'\t[TRUNCATED] 共 {len(user_agents)} 个 User-Agent，仅展示前 50 个')

    def add_requests(title, requests):
        output.append(title)
        output.extend(
            f'\tip: {request["ip"]}\turi: {request["path"]}\tuser agent: {request["user_agent"]}'
            for request in requests[:100]
        )
        if len(requests) > 100:
            output.append(f'\t[TRUNCATED] 共 {len(requests)} 条请求，仅展示前 100 条')

    add_requests('\n成功访问 请求统计', request_success)
    add_requests('\n跳转访问 请求统计', request_jump)

    attack_stats = {}
    for request in all_requests:
        reason = web_attack_reason(f'{request["path"]} {request["user_agent"]}')
        if not reason:
            continue
        key = (request['ip'], reason)
        entry = attack_stats.setdefault(key, {'count': 0, 'success': 0, 'uri': request['path']})
        entry['count'] += 1
        if request['status'].startswith(('2', '3')):
            entry['success'] += 1
    if attack_stats:
        output.append('\nWeb 攻击特征统计')
        ordered = sorted(attack_stats.items(), key=lambda item: (-item[1]['count'], item[0][0]))[:50]
        for (ip, reason), entry in ordered:
            output.append(
                f'\tip: {ip}\tcount: {entry["count"]}\tsuccess: {entry["success"]}'
                f'\turi: {truncate_text(entry["uri"], 200)}\t{reason}'
            )
        if len(attack_stats) > 50:
            output.append(f'\t[TRUNCATED] 共 {len(attack_stats)} 组攻击特征，仅展示前 50 组')

    return '\n'.join(output)


@mcp.tool()
def check_login_success():
    """
    统计成功登录来源。
    调用：排查异常 SSH 登录、凭证泄露或未知远程登录时使用。
    输出：返回登录 IP 和次数。
    """

    if not check_session():
        return SESSION_ERROR

    result = first_success(ssh_session.client, [
        # grep exits 1 when there are simply no matches; only exit >=2 is an error.
        "grep -h 'Accepted' /var/log/auth.log /var/log/secure; [ $? -le 1 ]",
        "journalctl -n 5000 --no-pager 2>/dev/null | grep -h 'Accepted '",
        'last',
    ], timeout=30)

    if not result['status']:
        return command_failure(result, '成功登录日志读取失败')
    if not result['result']:
        return empty_result('未发现成功登录 IP')

    output = format_ip_counts(count_ips_from_lines(result['result'].splitlines()), '成功登入 IP')
    return output or empty_result('未发现成功登录 IP')


@mcp.tool()
def check_login_fail():
    """
    统计失败登录来源。
    调用：排查爆破、撞库或异常登录尝试时使用。
    输出：返回失败登录 IP 和次数。
    """

    if not check_session():
        return SESSION_ERROR

    result = first_success(ssh_session.client, [
        "grep -h -E 'Failed password|authentication failure|Invalid user' /var/log/auth.log /var/log/secure; [ $? -le 1 ]",
        "journalctl -n 5000 --no-pager 2>/dev/null | grep -h -E 'Failed password|authentication failure|Invalid user'",
        'lastb',
    ], timeout=30)

    if not result['status']:
        return command_failure(result, '失败登录日志读取失败')
    if not result['result']:
        return empty_result('未发现失败登录 IP')

    output = format_ip_counts(count_ips_from_lines(result['result'].splitlines()), '爆破登入 IP')
    return output or empty_result('未发现失败登录 IP')


SSHD_PROCESS_PATTERN = re.compile(
    r'^\s*(\d+)\s+(\d+)\s+(\S+)\s+\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4}\s+(.*)$'
)


def sshd_session_finding(ppid, args):
    """Flag sshd processes whose shape does not match a normal session."""
    args = (args or '').strip()
    if 'sshd:' not in args and 'sshd ' not in args:
        return None
    if re.search(r'\bnotty\b', args):
        return '[i] 非交互 SSH 会话（notty），需结合登录来源与操作时间线复核'
    if ppid in ('0', '1') and re.search(r'sshd:\s+\S+@', args):
        return '[!] sshd 会话进程父进程为 1，可能为独立后门 sshd，需重点复核'
    return None


@mcp.tool()
def check_login_sessions():
    """
    关联当前登录会话、历史登录、sshd 进程和已建立 SSH 连接。
    调用：需要判断是否存在异常在线会话、隐藏登录或非交互 SSH 时使用。
    输出：返回 who/last 会话、sshd 进程启动时间与父子关系、established SSH 连接；MCP 自身连接也会出现在结果中。
    """

    if not check_session():
        return SESSION_ERROR

    nonce = get_run_id()
    who_mark = f'@@AUTOIR_SESS:{nonce}:WHO@@'
    last_mark = f'@@AUTOIR_SESS:{nonce}:LAST@@'
    ps_mark = f'@@AUTOIR_SESS:{nonce}:PS@@'
    net_mark = f'@@AUTOIR_SESS:{nonce}:NET@@'
    command = (
        f"printf '{who_mark}\\n'; who -u 2>&1; "
        f"printf '\\n{last_mark}\\n'; (last -Fai 2>/dev/null || last -f /var/log/wtmp 2>/dev/null) | head -n 40; "
        f"printf '\\n{ps_mark}\\n'; ps -eo pid,ppid,user,lstart,args 2>/dev/null | grep '[s]shd'; "
        f"printf '\\n{net_mark}\\n'; "
        "(ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null) | grep -E 'ESTAB|ESTABLISHED' | head -n 100"
    )
    result = exec_command(ssh_session.client, command, timeout=30, max_bytes=200000)
    text = result.get('result') or ''
    if not text:
        return command_failure(result, '登录会话信息获取失败')

    warnings = []
    if result.get('truncated'):
        warnings.append('[TRUNCATED] 登录会话输出超过采集上限，结果可能不完整')

    _, _, rest = text.partition(who_mark)
    who_text, _, rest = rest.partition(last_mark)
    last_text, _, rest = rest.partition(ps_mark)
    ps_text, _, net_text = rest.partition(net_mark)

    output = []
    who_lines = [line for line in who_text.strip().splitlines() if line.strip()]
    if who_lines:
        output.append('当前登录会话（who -u）')
        output.extend(f'\t{line}' for line in who_lines[:50])
    else:
        output.append('[i] who -u 未返回当前登录会话')

    last_lines = [line for line in last_text.strip().splitlines() if line.strip()]
    if last_lines:
        output.append('\n近期登录记录（last -Fai）')
        output.extend(f'\t{line}' for line in last_lines[:40])
    else:
        output.append('[i] last 未返回登录记录，可能 wtmp 不可用或已轮转')

    sshd_lines = []
    for line in ps_text.splitlines():
        match = SSHD_PROCESS_PATTERN.match(line)
        if not match:
            continue
        pid, ppid, user, args = match.groups()
        finding = sshd_session_finding(ppid, args)
        sshd_lines.append(
            f'\tpid: {pid}\tppid: {ppid}\tuser: {user}\targs: {args.strip()}'
            + (f'\t{finding}' if finding else '')
        )
    if sshd_lines:
        output.append('\nsshd 进程')
        output.extend(sshd_lines[:50])
    else:
        output.append('[i] 未发现 sshd 进程，若目标非 SSH 管理方式需人工复核')

    connection_lines = []
    for line in net_text.splitlines():
        socket = parse_socket_line(line)
        if not socket:
            continue
        local, remote = socket['local'], socket['remote']
        if not re.search(r':(?:22|2222|22022)$', local) and 'sshd' not in line.lower():
            continue
        connection_lines.append(
            f'\tlocal: {local}\tremote: {remote}\tstate: {socket["state"] or "-"}'
            f'\tprocess: {socket["process"] or "-"}'
            f'\t[i] 已建立 SSH 连接（包含 MCP 自身连接，需结合时间线复核）'
        )
    if connection_lines:
        output.append('\n已建立 SSH 连接')
        output.extend(connection_lines[:50])
    else:
        output.append('[i] 未发现目标端口已建立的 SSH 连接（ss/netstat 可能不可用或无权限）')

    lower_net = net_text.lower()
    if 'permission denied' in lower_net:
        warnings.append('[PERMISSION] 连接进程信息读取权限不足，需人工复核')
    if 'command not found' in lower_net or 'not found' in lower_net:
        warnings.append('[WARN] ss/netstat 不可用，无法关联已建立 SSH 连接，需人工复核')
    return append_warnings('\n'.join(output), warnings)


def _rootkit_upload_impl(install=False):
    if not check_session():
        return SESSION_ERROR

    local_rkhunter = Path(base_dir) / 'extensions' / 'rkhunter.gz'
    remote_archive = f'/tmp/autoir_rkhunter_{get_run_id()}.tar.gz'
    quoted_archive = quote_remote_path(remote_archive)
    upload_result = sftp_upload(ssh_session.client, str(local_rkhunter), remote_archive)
    if not upload_result.get('status'):
        return f'上传失败: {upload_result.get("error") or "本地 rkhunter.gz 不存在或 SFTP 失败"}'

    install_command = f'cd /tmp && tar -xf {quoted_archive} && cd /tmp/rkhunter-1.4.6 && bash installer.sh --install'
    if not install:
        return {
            "status": True,
            "result": "rkhunter 已上传，默认未安装；如需修改目标系统，请人工确认后执行安装命令或调用 install=True",
            "remote_archive": remote_archive,
            "manual_install_command": install_command,
        }

    result = exec_command(ssh_session.client, install_command, timeout=120, max_bytes=120000)

    if result['status'] and result['result']:
        if "complete" in result['result'].lower():
            return '[success] rkhunter rootkit 检测工具上传安装成功，需要用户手动执行命令 rkhunter --check'

    return command_failure(result, 'rkhunter 安装失败')


@mcp.tool()
def RootkitUpload(install=False):
    """
    上传 rkhunter；默认不安装。
    调用：需要 rootkit 深度检测时使用；只有明确 install=True 时才会在目标机执行安装脚本。
    输出：返回上传状态、人工安装命令或显式安装结果。
    """
    return _rootkit_upload_impl(install)


@mcp.tool(name='RookitUpload', description='兼容旧工具名，已弃用；请改用 RootkitUpload。')
def RookitUploadAlias(install=False):
    return _rootkit_upload_impl(install)


@mcp.tool()
def get_system_info():
    """
    采集基础系统信息。
    调用：SSH 连接成功后优先调用，用于报告目标主机上下文。
    输出：返回 hostname、系统版本、内核、时间和运行时长。
    """
    if not check_session():
        return SESSION_ERROR

    command = "printf 'hostname: '; hostname; printf 'kernel: '; uname -a; printf 'date: '; date; printf 'uptime: '; uptime; printf 'os-release:\n'; cat /etc/os-release 2>/dev/null"
    result = exec_command(ssh_session.client, command, timeout=10, max_bytes=20000)
    if not result['status']:
        return command_failure(result, '系统信息采集失败')
    return result['result'] or empty_result('系统信息为空')


@mcp.tool()
def check_alias():
    """
    扫描 alias 后门。
    调用：怀疑 shell 命令被 alias 劫持或登录持久化时使用。
    输出：返回可疑 alias 定义和来源文件。
    """
    if not check_session():
        return SESSION_ERROR

    paths = ['/root/.bashrc', '/root/.bash_profile', '/root/.profile', '/etc/bashrc', '/etc/profile']
    for user in load_home_users():
        paths.extend([f'/home/{user}/.bashrc', f'/home/{user}/.bash_profile', f'/home/{user}/.profile'])

    output = []
    dangerous = re.compile(r'\b(curl|wget|nc|ncat|socat|bash\s+-i|/dev/tcp|python\s+-c|perl\s+-e|chmod\s+\+s|ssh|scp)\b', re.I)
    for path in paths:
        result = exec_command(ssh_session.client, f"grep -nE '^alias[[:space:]]+' {quote_remote_path(path)} 2>/dev/null")
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                if dangerous.search(line):
                    output.append(f'file: {path}\tcontent: {line}\t[!] 可疑 alias 后门')
                else:
                    output.append(f'file: {path}\tcontent: {line}\t[i] alias 定义需复核')
    return '\n'.join(output) or empty_result()


@mcp.tool()
def check_env_preload():
    """
    检查环境变量预加载和命令注入。
    调用：排查 LD_PRELOAD、LD_LIBRARY_PATH、PROMPT_COMMAND 等登录持久化或劫持。
    输出：返回变量来源、变量名和值。
    """
    if not check_session():
        return SESSION_ERROR

    names = 'LD_PRELOAD|LD_AOUT_PRELOAD|LD_ELF_PRELOAD|LD_LIBRARY_PATH|PROMPT_COMMAND|BASH_ENV|ENV'
    paths = ['/root/.bashrc', '/root/.bash_profile', '/root/.profile', '/etc/bashrc', '/etc/profile', '/etc/environment']
    for file in get_files('/etc/profile.d'):
        paths.append(f'/etc/profile.d/{file}')
    for user in load_home_users():
        paths.extend([f'/home/{user}/.bashrc', f'/home/{user}/.bash_profile', f'/home/{user}/.profile'])

    output = []
    for path in paths:
        result = exec_command(ssh_session.client, f"grep -nE '({names})' {quote_remote_path(path)} 2>/dev/null")
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                if line.strip().startswith('#'):
                    continue
                output.append(f'file: {path}\tcontent: {line}\t[!] 环境变量持久化/劫持')
    return '\n'.join(output) or empty_result()


@mcp.tool()
def check_fstab():
    """
    检查 /etc/fstab 异常挂载项。
    调用：排查启动挂载持久化、远程挂载或伪装文件系统时使用。
    输出：返回可疑挂载项。
    """
    if not check_session():
        return SESSION_ERROR

    result = exec_command(ssh_session.client, 'cat /etc/fstab 2>&1')
    if not result['status']:
        issue = remote_result_issue(result, '/etc/fstab', '读取', include_missing=True)
        return issue or command_failure(result, 'fstab 读取失败')
    output = []
    high = re.compile(r'(curl|wget|/dev/tcp|sshfs|nfs|cifs)', re.I)
    review = re.compile(r'(tmpfs|fuse|overlay|auto|x-systemd)', re.I)
    for line in result['result'].splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if high.search(stripped):
            output.append(f'file: /etc/fstab\tcontent: {stripped}\t[!] 网络/命令执行类挂载项，需重点复核')
        elif review.search(stripped):
            output.append(f'file: /etc/fstab\tcontent: {stripped}\t[i] 特殊文件系统挂载项，需结合环境复核')
    return '\n'.join(output) or empty_result()


@mcp.tool()
def check_systemd_timers():
    """
    检查 systemd timer 持久化。
    调用：排查定时任务持久化或异常服务触发器时使用。
    输出：返回 timer 列表和可疑文件内容。
    """
    if not check_session():
        return SESSION_ERROR

    result = first_success(ssh_session.client, [
        "systemctl list-timers --all --no-pager 2>/dev/null",
        "find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -name '*.timer' -type f 2>/dev/null",
    ], timeout=20, max_bytes=80000)
    if not result['status']:
        return command_failure(result, 'systemd timer 检查失败')
    return result['result'] or empty_result()


@mcp.tool()
def check_service_execstart():
    """
    检查 systemd 服务 ExecStart 高危命令。
    调用：排查 systemd 服务持久化、反弹 shell 或下载执行时使用。
    输出：返回可疑服务文件和 ExecStart 内容。
    """
    if not check_session():
        return SESSION_ERROR

    command = r"grep -RInE 'Exec(Start|StartPre|StartPost)=.*(bash -i|/dev/tcp|curl|wget|nc |ncat|socat|python -c|perl -e|chmod \+s)' /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system 2>/dev/null"
    result = exec_command(ssh_session.client, command, timeout=30, max_bytes=120000)
    if result['result']:
        # grep exits 2 when one of the fixed systemd paths is missing, but it
        # still prints valid matches from the paths that exist.
        output = '\n'.join(
            f'{line}\t[!] systemd 高危启动命令' for line in result['result'].splitlines()
        )
        if not result['status']:
            output += '\n[WARN] 部分 systemd 目录不可读或不存在，结果可能不完整'
        return output
    if result.get('exit_status') in (0, 1):
        return empty_result()
    return command_failure(result, 'systemd 服务检查失败')


@mcp.tool()
def check_deleted_exe():
    """
    检查已删除但仍在运行的可执行文件。
    调用：排查无文件落地进程、进程隐藏或恶意进程自删除时使用。
    输出：返回 PID 和 deleted exe 指向。
    """
    if not check_session():
        return SESSION_ERROR

    marker = '@@AUTOIR_EXE_ERR@@'
    command = (
        'out=$(mktemp 2>/dev/null || echo /tmp/autoir_exe_$$.out); '
        'err=$(mktemp 2>/dev/null || echo /tmp/autoir_exe_$$.err); '
        'ls -al /proc/*/exe >"$out" 2>"$err"; rc=$?; '
        'grep "deleted" "$out" || true; '
        f"printf '\\n{marker}%s\\n' \"$rc\"; "
        'head -n 10 "$err"; rm -f "$out" "$err"'
    )
    result = exec_command(ssh_session.client, command, timeout=20)
    if not result['status'] and not result['result']:
        return command_failure(result, 'deleted exe 检查失败')

    data, separator, tail = result['result'].partition(marker)
    errors = ''
    exit_status = None
    if separator:
        first, _, errors = tail.partition('\n')
        try:
            exit_status = int(first.strip())
        except ValueError:
            exit_status = None
        errors = errors.strip()
    else:
        # Without our marker the output is likely exec_command's stderr
        # fallback, not a process list; never present it as findings.
        errors = result['result'].strip()

    warnings = []
    if errors:
        kind = classify_remote_error_text(errors)
        first = errors.splitlines()[0][:200]
        if kind == 'permission_denied':
            warnings.append(f'[PERMISSION] 部分 /proc/<pid>/exe 不可读，结果可能不完整: {first}')
        elif kind == 'not_found':
            warnings.append('[NOT_FOUND] /proc 不可用或当前环境不支持 /proc/<pid>/exe')
        else:
            warnings.append(f'[WARN] deleted exe 检查部分失败: {first}')

    output = '\n'.join(
        f'{line.strip()}\t[!] deleted exe 进程' for line in data.splitlines() if line.strip()
    )
    if output:
        return append_warnings(output, warnings)
    if warnings:
        return '\n'.join(warnings)
    if exit_status in (0, 1, None):
        return empty_result()
    return command_failure({'stderr': errors, 'result': errors}, 'deleted exe 检查失败')


@mcp.tool()
def check_dns_config():
    """
    检查 DNS 配置。
    调用：排查 DNS 劫持、异常解析或未知 nameserver 时使用。
    输出：返回 resolv.conf 内容和可疑 nameserver。
    """
    if not check_session():
        return SESSION_ERROR

    result = exec_command(ssh_session.client, 'cat /etc/resolv.conf 2>&1')
    if not result['status']:
        issue = remote_result_issue(result, '/etc/resolv.conf', '读取', include_missing=True)
        return issue or command_failure(result, 'DNS 配置读取失败')
    output = []
    for line in result['result'].splitlines():
        stripped = line.strip()
        if not stripped.startswith('nameserver'):
            continue
        ip = stripped.split()[-1]
        try:
            address = ipaddress.ip_address(ip)
            is_local = address.is_private or address.is_loopback or address.is_link_local
        except ValueError:
            is_local = False
            output.append(f'file: /etc/resolv.conf\tcontent: {stripped}\t[!] nameserver 不是合法 IP，需人工复核')
            continue
        if is_local:
            output.append(f'file: /etc/resolv.conf\tcontent: {stripped}\t[i] 内网/本机 DNS，需结合网络环境复核')
        else:
            output.append(f'file: /etc/resolv.conf\tcontent: {stripped}\t[i] 公共/外部 DNS，需结合企业规范复核')
    return '\n'.join(output) or empty_result()


@mcp.tool()
def check_auth_log(max_lines=5000):
    """
    分析 SSH/auth 日志。
    调用：排查暴力破解、成功登录、无效用户和认证异常时使用。
    输出：返回关键认证事件统计。
    """
    if not check_session():
        return SESSION_ERROR

    try:
        max_lines = max(1, min(int(max_lines), 50000))
    except (TypeError, ValueError):
        max_lines = 5000
    command = (
        'if [ -r /var/log/auth.log ] || [ -r /var/log/secure ]; then '
        f'tail -q -n {max_lines} /var/log/auth.log /var/log/secure; '
        'elif command -v journalctl >/dev/null 2>&1; then '
        f"journalctl -n {max_lines} --no-pager 2>/dev/null | grep -Ei 'sshd|Failed password|Accepted |Invalid user|authentication failure' || true; "
        'else '
        'printf "no auth log or journalctl available\\n" >&2; exit 1; '
        'fi'
    )
    result = exec_command(ssh_session.client, command, timeout=30, max_bytes=200000)
    warnings = []
    if not result['status']:
        # tail exits non-zero when one of the two paths is missing even though
        # it still prints useful lines from the other one.
        if not result.get('stdout'):
            detail = result.get('stderr') or result.get('error') or result.get('result') or ''
            kind = classify_remote_error_text(detail)
            if kind == 'permission_denied':
                first = detail.strip().splitlines()[0][:200] if detail.strip() else '无错误详情'
                return f'[PERMISSION] auth 日志读取权限不足: {first}'
            if kind == 'not_found' or 'no auth log' in detail:
                return '[NOT_FOUND] /var/log/auth.log、/var/log/secure 和 journalctl 均不可用，需人工确认日志配置'
            return command_failure(result, 'auth 日志读取失败')
        detail = (result.get('stderr') or '').strip().splitlines()
        warnings.append(f'[WARN] auth 日志部分读取失败: {detail[0][:200] if detail else "未知错误"}')
    lines = (result.get('stdout') or result.get('result') or '').splitlines()
    failed = [line for line in lines if re.search(r'Failed password|authentication failure|Invalid user', line, re.I)]
    accepted = [line for line in lines if re.search(r'Accepted (password|publickey)', line, re.I)]
    output = []
    failed_counts = count_ips_from_lines(failed)
    accepted_counts = count_ips_from_lines(accepted)
    if failed_counts:
        output.append('失败登录统计\n' + format_ip_counts(failed_counts, '失败登录来源'))
    if accepted_counts:
        output.append('成功登录统计\n' + format_ip_counts(accepted_counts, '成功登录来源'))
    correlated = brute_force_success_ips(failed_counts, accepted_counts)
    if correlated:
        output.append('疑似暴力破解后成功登录')
        output.extend(
            f'\tip: {ip}\tfailed: {failures}\taccepted: {accepted}'
            f'\t[!] 同一来源大量失败后成功登录，需重点复核'
            for ip, failures, accepted in correlated
        )
    invalid_users = invalid_user_counts(failed)
    if invalid_users:
        output.append('无效用户名统计')
        output.extend(f'\tuser: {user}\tcount: {count}\t[i] 无效用户尝试' for user, count in invalid_users)
    for line in failed[:20] + accepted[:20]:
        output.append(f'event: {line}')
    return append_warnings('\n'.join(output) or empty_result('未发现认证异常事件'), warnings)


@mcp.tool()
def check_web_logs_auto(max_lines=3000):
    """
    自动发现并分析常见 Web 访问日志。
    调用：不知道 Apache/Nginx/httpd 日志路径时使用。
    输出：返回已发现日志路径和分析摘要。
    """
    if not check_session():
        return SESSION_ERROR

    result = exec_command(ssh_session.client, "find /var/log -maxdepth 3 -type f \\( -name 'access.log' -o -name '*access*.log' -o -name 'access_log' \\) 2>/dev/null", timeout=20)
    if not result['status']:
        return command_failure(result, 'Web 日志发现失败')
    paths = [line.strip() for line in result['result'].splitlines() if line.strip()][:5]
    if not paths:
        return empty_result('未发现常见 Web access 日志')
    output = [f'发现日志: {path}' for path in paths]
    for path in paths:
        output.append(f'--- {path} ---')
        output.append(check_log(path=path, max_lines=max_lines))
    return '\n'.join(output)


def safe_local_subdir(relative_dir):
    base = Path(base_dir) / 'downloads'
    target = (Path(base_dir) / relative_dir).resolve()
    if not is_safe_path(base, target):
        target = base / 'evidence'
    target.mkdir(parents=True, exist_ok=True)
    return target


def is_allowed_upload_source(path):
    allowed_roots = (Path(base_dir) / 'extensions', Path(base_dir) / 'downloads')
    return any(is_safe_path(root, path) for root in allowed_roots)


@mcp.tool()
def stat_file(path):
    """
    获取目标主机文件元数据。
    调用：取证前确认文件权限、大小、时间和类型时使用。
    输出：返回 stat 信息，失败时 fallback 到 ls -al。
    """
    if not check_session():
        return SESSION_ERROR
    if not isinstance(path, str) or not path.strip():
        return "path 不能为空"
    quoted = quote_remote_path(path.strip())
    result = first_success(ssh_session.client, [
        f"stat {quoted} 2>/dev/null",
        f"ls -al {quoted} 2>/dev/null",
    ])
    if not result['status']:
        return command_failure(result, '文件元数据读取失败')
    return result['result'] or empty_result('文件不存在或无可读元数据')


@mcp.tool()
def hash_file(path, algorithm='sha256'):
    """
    计算目标主机文件哈希。
    调用：文件取证、样本确认或完整性校验时使用。
    输出：返回 md5/sha1/sha256 哈希。
    """
    if not check_session():
        return SESSION_ERROR
    if not isinstance(path, str) or not path.strip():
        return "path 不能为空"
    algorithms = {'sha256': 'sha256sum', 'sha1': 'sha1sum', 'md5': 'md5sum'}
    algorithm = str(algorithm).lower().strip()
    if algorithm not in algorithms:
        return "algorithm 仅支持 sha256、sha1、md5"
    quoted = quote_remote_path(path.strip())
    result = exec_command(ssh_session.client, f"{algorithms[algorithm]} {quoted} 2>/dev/null")
    if not result['status']:
        return command_failure(result, '文件哈希计算失败')
    return result['result'] or empty_result('文件哈希为空')


@mcp.tool()
def profile_suspicious_file(path, max_preview_lines=40, max_strings=80):
    """
    快速画像目标主机上的可疑文件。
    调用：需要对单个文件做 stat、hash、类型、预览和字符串片段分析时使用。
    输出：返回文件元数据、sha256、file 类型、头部预览、strings 片段和风险提示。
    """
    if not check_session():
        return {"status": False, "result": SESSION_ERROR}
    if not isinstance(path, str) or not path.strip():
        return {"status": False, "result": "path 不能为空"}
    try:
        max_preview_lines = max(1, min(int(max_preview_lines), 200))
    except (TypeError, ValueError):
        max_preview_lines = 40
    try:
        max_strings = max(1, min(int(max_strings), 300))
    except (TypeError, ValueError):
        max_strings = 80

    path = path.strip()
    quoted = quote_remote_path(path)
    stat_result = exec_command(
        ssh_session.client,
        f"stat -c '%F\t%A\t%a\t%U:%G\t%s\t%y\t%n' {quoted} 2>&1",
        timeout=10,
        max_bytes=8000,
    )
    if not stat_result['status']:
        issue = remote_result_issue(stat_result, path, '读取', include_missing=True)
        return {"status": False, "path": path, "result": issue or command_failure(stat_result, '文件元数据读取失败')}

    fields = stat_result.get('result', '').split('\t')
    file_type = fields[0] if len(fields) > 0 else ''
    permissions = fields[1] if len(fields) > 1 else ''
    mode = fields[2] if len(fields) > 2 else ''
    owner = fields[3] if len(fields) > 3 else ''
    size = fields[4] if len(fields) > 4 else ''
    mtime = fields[5] if len(fields) > 5 else ''

    sha256_result = exec_command(ssh_session.client, f"sha256sum {quoted} 2>/dev/null", timeout=20, max_bytes=4000)
    type_result = exec_command(ssh_session.client, f"file -b {quoted} 2>/dev/null", timeout=10, max_bytes=4000)
    preview_result = exec_command(ssh_session.client, f"head -n {max_preview_lines} {quoted} 2>/dev/null", timeout=10, max_bytes=12000)
    strings_result = exec_command(ssh_session.client, f"strings -a {quoted} 2>/dev/null | head -n {max_strings}", timeout=20, max_bytes=20000)

    lower_path = path.lower()
    reasons = []
    if 'directory' in file_type.lower():
        reasons.append('目标是目录')
    if permissions and any(flag in permissions for flag in ('x', 's', 'S')):
        reasons.append('包含执行权限或 SUID/SGID 标记')
    if permissions and permissions.endswith('w'):
        reasons.append('other 可写')
    if lower_path.endswith(('.php', '.jsp', '.jspx', '.asp', '.aspx', '.war', '.py', '.pl', '.sh')):
        reasons.append('脚本或 Web 可执行扩展')
    if any(token in lower_path for token in ('/tmp/', '/dev/shm/', '/var/tmp/', '/uploads/', '/upload/')):
        reasons.append('位于高频落地目录')
    if size == '0':
        reasons.append('空文件')

    sha256 = sha256_result.get('result', '').split()[0] if sha256_result.get('status') and sha256_result.get('result') else ''
    preview, preview_truncated = truncate_text(preview_result.get('result', ''), max_chars=4000)
    string_snippets, strings_truncated = truncate_text(strings_result.get('result', ''), max_chars=8000)

    return {
        "status": True,
        "path": path,
        "metadata": {
            "type": file_type,
            "permissions": permissions,
            "mode": mode,
            "owner": owner,
            "size": size,
            "mtime": mtime,
        },
        "sha256": sha256,
        "file": type_result.get('result', '') if type_result.get('status') else 'file 命令不可用或失败',
        "preview": preview,
        "strings": string_snippets,
        "risk_notes": reasons or ['未发现明显文件画像风险点，仍需结合上下文复核'],
        "truncated": preview_truncated or strings_truncated,
    }


@mcp.tool()
def download_file(remote_path, local_dir='downloads/evidence', max_bytes=100 * 1024 * 1024):
    """
    下载目标主机文件到本地取证目录。
    调用：需要保存可疑文件、日志或配置用于后续分析时使用；默认拒绝超过 max_bytes 的文件。
    输出：返回本地路径、远程路径和下载状态。
    """
    if not check_session():
        return {"status": False, "result": SESSION_ERROR}
    if not isinstance(remote_path, str) or not remote_path.strip():
        return {"status": False, "result": "remote_path 不能为空"}
    try:
        max_bytes = max(1024, min(int(max_bytes), 2 * 1024 * 1024 * 1024))
    except (TypeError, ValueError):
        max_bytes = 100 * 1024 * 1024
    if not isinstance(local_dir, str) or not local_dir.strip():
        local_dir = 'downloads/evidence'
    remote_path = remote_path.strip()
    quoted_remote = quote_remote_path(remote_path)
    stat_result = exec_command(ssh_session.client, f"stat -c '%s\t%n\t%s bytes\t%U:%G\t%A\t%y' {quoted_remote} 2>&1", timeout=10, max_bytes=4000)
    if not stat_result.get('status'):
        issue = remote_result_issue(stat_result, remote_path, '读取', include_missing=True)
        return {"status": False, "remote_path": remote_path, "result": issue or command_failure(stat_result, '远程文件元数据读取失败')}
    try:
        remote_size = int(stat_result.get('result', '').split('\t', 1)[0])
    except (IndexError, ValueError):
        return {"status": False, "remote_path": remote_path, "result": "远程文件大小解析失败"}
    if remote_size > max_bytes:
        return {"status": False, "remote_path": remote_path, "size": remote_size, "max_bytes": max_bytes, "result": "远程文件超过下载大小限制"}
    filename = Path(remote_path.rstrip('/')).name
    if not filename:
        return {"status": False, "remote_path": remote_path, "result": "remote_path 必须指向文件而不是目录"}
    target_dir = safe_local_subdir(local_dir) / get_run_id()
    target_dir.mkdir(parents=True, exist_ok=True)
    local_path = target_dir / filename
    if local_path.exists():
        stem, suffix = local_path.stem, local_path.suffix
        index = 2
        while local_path.exists():
            local_path = target_dir / f'{stem}_{index}{suffix}'
            index += 1
    result = sftp_download(ssh_session.client, remote_path, str(local_path), max_bytes=max_bytes)
    return {
        "status": result.get('status'),
        "remote_path": remote_path,
        "local_path": str(local_path) if result.get('status') else "",
        "stat": stat_result.get('result', ''),
        "error": result.get('error', ''),
    }


@mcp.tool()
def upload_file(local_path, remote_path):
    """
    上传本地文件到目标主机。
    调用：需要传输取证工具或用户明确要求上传文件时使用。
    输出：返回上传状态和错误原因。
    """
    if not check_session():
        return {"status": False, "result": SESSION_ERROR}
    if not isinstance(local_path, str) or not local_path.strip():
        return {"status": False, "result": "local_path 不能为空"}
    local = Path(local_path).expanduser().resolve()
    if not local.is_file():
        return {"status": False, "result": f"本地文件不存在: {local}"}
    if not is_allowed_upload_source(local):
        return {"status": False, "result": "local_path 仅允许位于项目 extensions/ 或 downloads/ 目录内"}
    if not isinstance(remote_path, str) or not remote_path.strip():
        return {"status": False, "result": "remote_path 不能为空"}
    result = sftp_upload(ssh_session.client, str(local), remote_path.strip())
    return {
        "status": result.get('status'),
        "local_path": str(local),
        "remote_path": remote_path.strip(),
        "error": result.get('error', ''),
    }


@mcp.tool()
def collect_evidence_bundle(include_logs=True, include_files=False):
    """
    采集本地证据快照目录。
    调用：需要保存系统、用户、进程、网络、服务、计划任务和关键日志摘要用于复盘时使用。
    输出：返回本地 bundle 目录和生成的文件列表。
    """
    if not check_session():
        return {"status": False, "result": SESSION_ERROR}
    bundle_dir = Path(base_dir) / 'downloads' / 'evidence_bundle' / get_run_id()
    bundle_dir.mkdir(parents=True, exist_ok=True)
    commands = {
        'system.txt': "hostname; uname -a; date; uptime; cat /etc/os-release 2>/dev/null",
        'users.txt': "cat /etc/passwd; printf '\n--- sudoers ---\n'; cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null",
        'processes.txt': "ps auxww; printf '\\n--- deleted exe ---\\n'; ls -al /proc/*/exe 2>&1 | grep -E 'deleted|Permission denied' || true",
        'network.txt': "ip addr; ss -anutp 2>/dev/null || netstat -anutp 2>/dev/null; cat /etc/hosts; cat /etc/resolv.conf 2>/dev/null",
        'services.txt': "systemctl list-units --type=service --all --no-pager 2>/dev/null; systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null",
        'scheduled.txt': "crontab -l 2>/dev/null; ls -al /var/spool/cron /var/spool/cron/crontabs 2>/dev/null; atq 2>/dev/null",
        'startup.txt': "find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -maxdepth 2 -type f 2>/dev/null | head -500; cat /etc/rc.local /etc/profile 2>/dev/null",
    }
    if include_logs:
        # Iterate explicitly: multi-file tail adds headers and hides missing or
        # unreadable logs behind redirection.
        commands['logs.txt'] = (
            "for f in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages; do "
            "if [ -r \"$f\" ]; then printf '## %s\\n' \"$f\"; tail -n 1000 \"$f\"; "
            "elif [ -e \"$f\" ]; then printf '## %s [PERMISSION]\\n' \"$f\"; fi; done; "
            "if command -v journalctl >/dev/null 2>&1; then "
            "printf '## journalctl (last 1000)\\n'; journalctl -n 1000 --no-pager 2>&1 | head -n 1000; fi"
        )
    if include_files:
        commands['tmp_files.txt'] = (
            "for d in /tmp /var/tmp /dev/shm /run/shm; do "
            "[ -d \"$d\" ] || continue; printf '## %s\\n' \"$d\"; "
            "find \"$d\" -xdev -type f -exec stat -c '%y\\t%U:%G\\t%A\\t%s bytes\\t%n' {} + 2>&1 | head -n 500; "
            "done"
        )
    client = ssh_session.client

    def collect(item):
        filename, command = item
        result = exec_command(client, command, timeout=30, max_bytes=500000)
        return filename, command, result

    # Collect in parallel; map() preserves dict order so output stays deterministic.
    with ThreadPoolExecutor(max_workers=4) as pool:
        collected = list(pool.map(collect, commands.items()))

    written = []
    for filename, command, result in collected:
        path = bundle_dir / filename
        header = (
            f'# command: {command}\n'
            f'# status: {result.get("status")} exit_status: {result.get("exit_status")} '
            f'truncated: {result.get("truncated")} timeout: {result.get("timeout")}\n\n'
        )
        body = result.get('result', '') or result.get('error', '')
        path.write_text(header + body, encoding='utf-8', errors='ignore')
        written.append(str(path))
    return {"status": True, "bundle_dir": str(bundle_dir), "files": written}


@mcp.tool()
def list_services():
    """
    枚举系统服务。
    调用：排查异常服务、未知服务或服务状态时使用。
    输出：返回 service 列表。
    """
    if not check_session():
        return SESSION_ERROR
    result = first_success(ssh_session.client, [
        'systemctl list-units --type=service --all --no-pager 2>/dev/null',
        'command -v rc-status >/dev/null 2>&1 && rc-status -a 2>/dev/null',
        'command -v rc-update >/dev/null 2>&1 && rc-update show 2>/dev/null',
        'command -v chkconfig >/dev/null 2>&1 && chkconfig --list 2>/dev/null',
        'command -v service >/dev/null 2>&1 && service --status-all 2>&1',
    ], timeout=20, max_bytes=200000)
    if not result['status']:
        return command_failure(result, '服务列表获取失败')
    return result['result'] or empty_result('未发现服务列表')


@mcp.tool()
def check_enabled_services():
    """
    检查开机自启服务。
    调用：排查持久化服务或异常 enabled 服务时使用。
    输出：返回 enabled service 列表。
    """
    if not check_session():
        return SESSION_ERROR
    result = first_success(ssh_session.client, [
        'systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null',
        'command -v rc-update >/dev/null 2>&1 && rc-update show 2>/dev/null',
        'command -v chkconfig >/dev/null 2>&1 && chkconfig --list 2>/dev/null '
        '| grep -E "[[:space:]]3:on|[[:space:]]on$"',
    ], timeout=20, max_bytes=200000)
    if not result['status'] and not result.get('result'):
        return command_failure(result, '开机自启服务获取失败')
    return result['result'] or empty_result('未发现 enabled 服务')


@mcp.tool()
def check_recent_systemd_changes(days=7):
    """
    检查近期变更的 systemd 单元文件。
    调用：排查近期新增或修改的服务、timer、socket 持久化时使用。
    输出：返回最近修改的 systemd 文件。
    """
    if not check_session():
        return SESSION_ERROR
    try:
        days = max(1, min(int(days), 365))
    except (TypeError, ValueError):
        days = 7
    paths = ['/etc/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system']
    command = portable_recent_find(
        paths,
        days,
        '%TY-%Tm-%Td %TH:%TM\\t%p\\n',
        '%y\\t%n',
        2000,
    )
    result = exec_command(ssh_session.client, command, timeout=60, max_bytes=200000)
    if not result['status'] and not result['result']:
        return command_failure(result, 'systemd 近期变更检查失败')

    data, errors = split_find_output(result['result'])
    warnings = []
    if errors:
        if find_printf_fallback_error(errors):
            warnings.append('[INFO] 目标 find 不支持 -printf，已回退到 stat 输出')
        elif classify_remote_error_text(errors) == 'permission_denied':
            first = errors.splitlines()[0][:200]
            warnings.append(f'[PERMISSION] systemd 目录扫描权限不足，结果可能不完整: {first}')
        elif not data:
            return f'[NOT_FOUND] systemd 单元目录不可读或不存在: {errors.splitlines()[0][:200]}'
        else:
            warnings.append(f'[WARN] systemd 近期变更检查部分失败: {errors.splitlines()[0][:200]}')

    if not data:
        return append_warnings(empty_result(f'最近 {days} 天未发现 systemd 文件变更'), warnings)
    return append_warnings(data, warnings)


def container_runtime():
    result = first_success(ssh_session.client, ['command -v docker', 'command -v podman'])
    if result['status'] and result['result']:
        path = result['result'].splitlines()[0].strip()
        return 'podman' if path.endswith('podman') else 'docker'
    return ''


def container_ids(runtime):
    result = exec_command(ssh_session.client, f"{runtime} ps -aq --no-trunc 2>&1", timeout=20)
    if not result['status']:
        detail = (result.get('result') or result.get('stderr') or '').strip()
        return [], detail or '容器列表获取失败，可能无权限或 daemon 不可访问'
    ids = [line.strip() for line in (result.get('result') or '').splitlines() if line.strip()]
    return ids, ''


@mcp.tool()
def check_docker_containers():
    """
    检查 Docker/Podman 容器列表。
    调用：排查容器中隐藏的恶意服务、进程或异常镜像时使用。
    输出：返回容器列表或不可用原因。
    """
    if not check_session():
        return SESSION_ERROR
    runtime = container_runtime()
    if not runtime:
        return empty_result('未发现 docker/podman 命令')
    result = exec_command(ssh_session.client, f'{runtime} ps -a --no-trunc 2>&1', timeout=30, max_bytes=200000)
    if not result['status']:
        return command_failure(result, f'{runtime} 容器列表获取失败，可能无权限或 daemon 不可访问')
    return result['result'] or empty_result('未发现容器')


@mcp.tool()
def check_container_mounts():
    """
    检查容器挂载。
    调用：排查宿主机敏感目录挂载、逃逸风险或恶意持久化时使用。
    输出：返回容器挂载摘要。
    """
    if not check_session():
        return SESSION_ERROR
    runtime = container_runtime()
    if not runtime:
        return empty_result('未发现 docker/podman 命令')
    ids, error = container_ids(runtime)
    if error:
        return f'[FAILED] {runtime} 容器枚举失败: {truncate_text(error, 300)}'
    if not ids:
        return empty_result('未发现容器')
    quoted_ids = ' '.join(shlex.quote(cid) for cid in ids[:50])
    result = exec_command(
        ssh_session.client,
        f"{runtime} inspect --format '{{{{.Name}}}} {{{{json .Mounts}}}}' {quoted_ids} 2>&1",
        timeout=30,
        max_bytes=500000,
    )
    if result['status'] and result['result']:
        return result['result']
    return command_failure(result, '容器挂载信息获取失败')


@mcp.tool()
def check_container_processes():
    """
    检查容器内进程。
    调用：排查容器内挖矿、反弹 shell 或异常服务时使用。
    输出：返回容器 top 进程摘要。
    """
    if not check_session():
        return SESSION_ERROR
    runtime = container_runtime()
    if not runtime:
        return empty_result('未发现 docker/podman 命令')
    ids, error = container_ids(runtime)
    if error:
        return f'[FAILED] {runtime} 容器枚举失败: {truncate_text(error, 300)}'
    if not ids:
        return empty_result('未发现容器')
    quoted_ids = ' '.join(shlex.quote(cid) for cid in ids[:50])
    command = f'for cid in {quoted_ids}; do echo "## $cid"; {runtime} top "$cid" 2>&1; done'
    result = exec_command(ssh_session.client, command, timeout=60, max_bytes=500000)
    if result['status'] and result['result']:
        return result['result']
    return command_failure(result, '容器进程信息获取失败')


@mcp.tool()
def check_user_crontabs():
    """
    检查用户级 crontab。
    调用：排查用户级计划任务、反弹 shell 或定时下载执行时使用。
    输出：返回每个用户的 crontab 和 spool 文件线索。
    """
    if not check_session():
        return SESSION_ERROR
    marker = '@@AUTOIR_CRON_ERR@@'
    command = (
        'err=$(mktemp 2>/dev/null || echo /tmp/autoir_cron_$$.err); '
        "awk -F: '$7 !~ /(nologin|false)$/ {print $1}' /etc/passwd | head -n 200 | "
        'while IFS= read -r user; do '
        'crontab=$(crontab -l -u "$user" 2>>"$err"); '
        "if [ -n \"$crontab\" ]; then printf '## user: %s\\n%s\\n\\n' \"$user\" \"$crontab\"; fi; "
        'done; '
        f"printf '\\n{marker}\\n'; "
        "grep -v 'no crontab' \"$err\" | head -n 10; rm -f \"$err\""
    )
    result = exec_command(ssh_session.client, command, timeout=60, max_bytes=300000)
    if not result['status'] and not result['result']:
        return command_failure(result, '用户级 crontab 读取失败')
    data, _, errors = result['result'].partition(marker)
    data, errors = data.strip(), errors.strip()
    warnings = []
    if errors:
        kind = classify_remote_error_text(errors)
        first = errors.splitlines()[0][:200]
        if kind == 'permission_denied':
            warnings.append(f'[PERMISSION] 用户级 crontab 读取权限不足，结果可能不完整: {first}')
        else:
            warnings.append(f'[WARN] 用户级 crontab 部分读取失败: {first}')
    spool = exec_command(
        ssh_session.client,
        "find /var/spool/cron /var/spool/cron/crontabs -maxdepth 2 -type f "
        "-exec stat -c '%n\\t%U:%G\\t%A\\t%s bytes' {} + 2>&1",
        timeout=20,
    )
    spool_lines = []
    spool_errors = []
    for line in (spool.get('result') or '').splitlines():
        if '\t' in line:
            spool_lines.append(line)
        elif line.strip():
            spool_errors.append(line.strip())
    if spool_errors:
        combined_spool_errors = '\n'.join(spool_errors)
        if classify_remote_error_text(combined_spool_errors) == 'permission_denied':
            warnings.append('[PERMISSION] cron spool 目录读取权限不足，结果可能不完整')
        else:
            warnings.append(f'[WARN] cron spool 部分读取失败: {spool_errors[0][:200]}')
    output = []
    if data:
        output.append(data)
    if spool_lines:
        output.append('## cron spool files\n' + '\n'.join(spool_lines))
    return append_warnings('\n\n'.join(output) or empty_result('未发现用户级 crontab'), warnings)


@mcp.tool()
def check_at_jobs():
    """
    检查 at 计划任务。
    调用：排查一次性定时执行任务或隐藏持久化时使用。
    输出：返回 atq 列表和任务内容。
    """
    if not check_session():
        return SESSION_ERROR
    result = exec_command(ssh_session.client, 'atq 2>/dev/null', timeout=10)
    if not result['status'] or not result['result']:
        if result.get('exit_status') in (0, 1, None):
            return empty_result('未发现 at 任务或 at 不可用')
        return command_failure(result, 'atq 查询失败')
    output = ['## atq', result['result']]
    job_ids = []
    for line in result['result'].splitlines()[:50]:
        fields = line.split()
        if fields and fields[0].isdigit():
            job_ids.append(fields[0])

    if job_ids:
        # Fetch all job bodies in one round trip; per-job exec_command made a
        # large at queue take tens of seconds and risked transport timeouts.
        script = '\n'.join(
            f'printf "\\n## at job %s\\n" {shlex.quote(job_id)}; at -c {shlex.quote(job_id)} 2>&1'
            for job_id in job_ids
        )
        jobs = exec_command(ssh_session.client, script, timeout=30, max_bytes=200000)
        if jobs['status'] or jobs['result']:
            output.append(jobs['result'])
        else:
            output.append(command_failure(jobs, 'at 任务内容读取失败'))
    return '\n\n'.join(output)



if __name__ == "__main__":
    mcp.run()
